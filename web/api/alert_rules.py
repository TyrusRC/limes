"""REST for alert rules and the per-project integration settings (limes.alerts.rules / channels).
A rule or integration id from another project is a 404. A saved secret is never returned: only set / not set and its
last four characters."""
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import HasPermission
from dashboard.models import Project
from limes import identity
from limes.alerts import channels, events, outbound, rule_tasks, rules
from limes.definitions import PERM_MODIFY_SCAN_CONFIGURATIONS
from startScan.alert_models import CHANNELS
from startScan.models import AlertIntegration, AlertRule

MAX_SECRET = 2000


def _fail(message, status=400):
    return Response({'status': False, 'message': message}, status=status)


def _project(request):
    data = request.data if isinstance(request.data, dict) else {}
    slug = request.query_params.get('project') or data.get('project')
    return Project.objects.filter(slug=slug).first() if isinstance(slug, str) else None


def rule_json(r):
    return {'id': r.id, 'name': r.name, 'enabled': r.enabled, 'kinds': r.kinds, 'min_severity': r.min_severity, 'tags': r.tags,
            'score_drop_points': r.score_drop_points, 'score_window_days': r.score_window_days, 'channels': r.channels,
            'email_to': r.email_to, 'created_at': r.created_at, 'last_sent': r.last_sent, 'last_error': r.last_error,
            'last_error_at': r.last_error_at}


def integration_json(i):
    if i is None:
        i = AlertIntegration()
    return {'webhook_url': channels.mask(i.webhook_url_enc), 'webhook_secret': channels.mask(i.webhook_secret_enc),
            'slack_url': channels.mask(i.slack_url_enc), 'jira_base_url': i.jira_base_url, 'jira_email': i.jira_email,
            'jira_token': channels.mask(i.jira_token_enc), 'jira_project_key': i.jira_project_key,
            'jira_issue_type': i.jira_issue_type, 'jira_labels': i.jira_labels}


class _Base(APIView):
    permission_classes = [IsAuthenticated, HasPermission]
    permission_required = PERM_MODIFY_SCAN_CONFIGURATIONS


class RuleList(_Base):
    def get(self, request):
        project = _project(request)
        if not project:
            return _fail('project not found', 404)
        from django.conf import settings
        return Response({'results': [rule_json(r) for r in AlertRule.objects.filter(project=project).order_by('name', 'id')],
                         'meta': {'kinds': list(events.KINDS), 'channels': list(CHANNELS),
                                  'email_configured': bool(settings.EMAIL_HOST)}})

    def post(self, request):
        project = _project(request)
        if not project:
            return _fail('project not found', 404)
        try:
            fields = rules.clean_rule(request.data)
        except rules.RuleError as e:
            return _fail(str(e))
        try:
            with transaction.atomic():
                if AlertRule.objects.filter(project=project).count() >= rules.MAX_RULES:
                    return _fail('at most %d rules per project' % rules.MAX_RULES)
                rule = AlertRule.objects.create(project=project, created_by=request.user, **fields)
        except IntegrityError:
            return _fail('a rule with this name exists')
        return Response(rule_json(rule), status=201)


class RuleDetail(_Base):
    def _rule(self, request, pk):
        project = _project(request)
        return AlertRule.objects.filter(pk=pk, project=project).first() if project else None

    def get(self, request, pk):
        rule = self._rule(request, pk)
        return Response(rule_json(rule)) if rule else _fail('rule not found', 404)

    def patch(self, request, pk):
        rule = self._rule(request, pk)
        if not rule:
            return _fail('rule not found', 404)
        try:
            fields = rules.clean_rule(request.data, partial_of=rule)
        except rules.RuleError as e:
            return _fail(str(e))
        try:
            with transaction.atomic():
                for k, v in fields.items():
                    setattr(rule, k, v)
                rule.save()
        except IntegrityError:
            return _fail('a rule with this name exists')
        return Response(rule_json(rule))

    def delete(self, request, pk):
        rule = self._rule(request, pk)
        if not rule:
            return _fail('rule not found', 404)
        rule.delete()
        return Response(status=204)


class RuleTest(_Base):
    """Send a test message through the rule's channels now (one attempt, no retry); the outcome is also kept on the rule."""

    def post(self, request, pk):
        project = _project(request)
        rule = AlertRule.objects.filter(pk=pk, project=project).select_related('project').first() if project else None
        if not rule:
            return _fail('rule not found', 404)
        msg, results = channels.test_message(rule), {}
        for ch in rule.channels:
            if ch == 'jira':
                results[ch] = 'skipped: use "Test create issue" in the integration settings'
                continue
            try:
                err = rule_tasks.run_channel(project, ch, [rule], msg)
            except outbound.OutboundError as e:
                err = str(e)
            except Exception as e:  # never the exception text: it can carry a URL
                err = 'unexpected error (%s)' % type(e).__name__
            results[ch] = err or 'ok'
            rule_tasks.record_result([rule], ch, err)
        rule.refresh_from_db()
        return Response({'results': results, 'rule': rule_json(rule)})


SECRET_FIELDS = {'webhook_url': 'webhook_url_enc', 'webhook_secret': 'webhook_secret_enc', 'slack_url': 'slack_url_enc',
                 'jira_token': 'jira_token_enc'}
URL_FIELDS = ('webhook_url', 'slack_url')


def _text(data, field, cap):
    v = data.get(field)
    if v is None:
        return None
    if not isinstance(v, str) or len(v.strip()) > cap or any(ord(c) < 32 for c in v):
        raise rules.RuleError(f'{field} is not valid')
    return v.strip()


def clean_integration(data):
    """{column: value} for the fields present in `data`: a secret is encrypted, '' clears. Raises RuleError."""
    out = {}
    for field, col in SECRET_FIELDS.items():
        v = data.get(field)
        if v is None:
            continue
        if not isinstance(v, str) or len(v) > MAX_SECRET or any(ord(c) < 32 for c in v):
            raise rules.RuleError(f'{field} is not valid')
        v = v.strip()
        if v and field in URL_FIELDS and outbound.validate_url(v):
            raise rules.RuleError(f'{field}: {outbound.validate_url(v)}')
        if v and field == 'webhook_secret' and len(v) < 8:
            raise rules.RuleError('webhook_secret must be at least 8 characters')
        out[col] = identity.encrypt(v) if v else ''
    base = _text(data, 'jira_base_url', outbound.MAX_URL)
    if base is not None:
        if base and outbound.validate_url(base):
            raise rules.RuleError('jira_base_url: ' + outbound.validate_url(base))
        out['jira_base_url'] = base.rstrip('/')
    email = _text(data, 'jira_email', 200)
    if email is not None:
        try:
            if email:
                validate_email(email)
        except ValidationError:
            raise rules.RuleError('jira_email is not valid')
        out['jira_email'] = email
    key = _text(data, 'jira_project_key', 20)
    if key is not None:
        key = key.upper()
        if key and not channels.PROJECT_KEY_RE.fullmatch(key):
            raise rules.RuleError('jira_project_key looks like ABC')
        out['jira_project_key'] = key
    itype = _text(data, 'jira_issue_type', 60)
    if itype is not None:
        out['jira_issue_type'] = itype
    if data.get('jira_labels') is not None:
        labels = data['jira_labels']
        if not isinstance(labels, list) or len(labels) > channels.MAX_LABELS or not all(isinstance(l, str) and 0 < len(l) <= 50 for l in labels):
            raise rules.RuleError('jira_labels is up to %d labels of up to 50 characters' % channels.MAX_LABELS)
        out['jira_labels'] = sorted({channels.LABEL_RE.sub('-', l) for l in labels})
    return out


class Integration(_Base):
    def get(self, request):
        project = _project(request)
        if not project:
            return _fail('project not found', 404)
        return Response(integration_json(channels.integration(project)))

    def put(self, request):
        project = _project(request)
        if not project:
            return _fail('project not found', 404)
        try:
            fields = clean_integration(request.data)
        except rules.RuleError as e:
            return _fail(str(e))
        integ, _ = AlertIntegration.objects.update_or_create(project=project, defaults=fields)
        return Response(integration_json(integ))


class JiraTest(_Base):
    """Create a real issue to prove the settings work, and report its key."""

    def post(self, request):
        project = _project(request)
        if not project:
            return _fail('project not found', 404)
        try:
            key = channels.create_jira_issue(channels.integration(project), 'Limes test issue',
                                             ['Created by the Limes "Test create issue" button. You can close it.'])
        except channels.NotConfigured as e:
            return _fail(str(e))
        except outbound.OutboundError as e:
            return _fail(str(e))
        return Response({'status': True, 'key': key})
