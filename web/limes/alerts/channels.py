"""The channels an alert rule can send to. Each sender raises NotConfigured or outbound.OutboundError and logs nothing
itself; limes.alerts.rule_tasks records the outcome on the rule. Every text that came from a scan (titles, hostnames)
is untrusted: it is flattened to one capped line, and escaped for the chat it goes to."""
import json
import re
import smtplib

from django.conf import settings
from django.core.mail import send_mail

from limes import identity
from limes.alerts import deliver, outbound
from startScan.models import AlertIntegration, TrackedIssue

JIRA_KEY_RE = re.compile(r'[A-Z][A-Z0-9_]{1,19}-\d{1,9}')
PROJECT_KEY_RE = re.compile(r'[A-Z][A-Z0-9_]{1,19}')
LABEL_RE = re.compile(r'[^A-Za-z0-9_.:-]')
MAX_LABELS = 10
SUMMARY_MAX = 200
LINE_MAX = 300


SEVERITY_WORDS = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}


class NotConfigured(Exception):
    pass


def clean(text, cap=LINE_MAX):
    """One printable line, at most `cap` characters."""
    text = ''.join(' ' if (c.isspace() or ord(c) < 32 or ord(c) == 127) else c for c in str(text or ''))
    return re.sub(r' +', ' ', text).strip()[:cap]


def slack_escape(text):
    """Slack mrkdwn: & < > are the only characters that start a link, mention or channel ping."""
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def secret(enc):
    """Plaintext of an *_enc column; '' when unset or when the key changed since it was saved."""
    try:
        return identity.decrypt(enc) if enc else ''
    except Exception:
        return ''


def mask(enc):
    """What the API may say about a stored secret: whether it is set and its last four characters."""
    plain = secret(enc)
    if not enc:
        return {'set': False, 'last4': None}
    return {'set': True, 'last4': ('••••' + plain[-4:]) if len(plain) >= 8 else None}


def integration(project):
    return AlertIntegration.objects.filter(project=project).first()


def message(event):
    """The channel-neutral view of a ChangeEvent."""
    return {'kind': event.kind, 'title': event.title, 'severity': event.severity, 'event_id': event.id,
            'asset': event.asset.value if event.asset_id else None, 'payload': deliver.payload(event),
            'project': event.project.name, 'key': (event.detail or {}).get('key'), 'asset_id': event.asset_id}


def test_message(rule):
    title = 'Limes test alert for rule %s' % clean(rule.name, 100)
    return {'kind': 'test', 'title': title, 'severity': None, 'event_id': None, 'asset': None, 'key': None, 'asset_id': None,
            'project': rule.project.name, 'payload': {'event': 'test', 'project': rule.project.slug, 'title': title}}


def send_in_app(project, rules, msg, **kw):
    from limes.common_func import create_inappnotification
    from django.urls import reverse
    from limes.definitions import PROJECT_LEVEL_NOTIFICATION
    sev = msg['severity'] or 0
    create_inappnotification(
        title=clean(msg['title'], 300), description=clean('Alert rule: ' + ', '.join(r.name for r in rules), 500),
        notification_type=PROJECT_LEVEL_NOTIFICATION, project_slug=project.slug, icon='mdi-alert-circle-outline',
        status='error' if sev >= 3 else 'warning', redirect_link=reverse('dashboardIndex', kwargs={'slug': project.slug}))


def send_email(project, rules, msg, **kw):
    if not settings.EMAIL_HOST:
        raise NotConfigured('email is not configured on this server (set LIMES_EMAIL_HOST)')
    to = sorted({a for r in rules for a in r.email_to})
    if not to:
        raise NotConfigured('no email recipients')
    body = '\n'.join([clean(msg['title'], 300), '', 'Project: ' + clean(msg['project'], 100),
                      'Asset: ' + clean(msg['asset'] or '-', 255), 'Event: ' + clean(msg['kind'], 40),
                      'Rule: ' + ', '.join(clean(r.name, 100) for r in rules)])
    try:
        send_mail('[Limes] ' + clean(msg['title'], 150), body, settings.DEFAULT_FROM_EMAIL, to, fail_silently=False)
    except (smtplib.SMTPException, OSError) as exc:
        raise outbound.OutboundError('the mail server refused or did not answer (%s)' % type(exc).__name__, transient=True)


def send_webhook(project, rules, msg, **kw):
    integ = integration(project)
    url, key = (secret(integ.webhook_url_enc), secret(integ.webhook_secret_enc)) if integ else ('', '')
    if not url or not key:
        raise NotConfigured('the webhook URL and signing secret are not set')
    body = json.dumps(msg['payload'], sort_keys=True).encode()
    outbound.request('post', url, data=body, headers={'Content-Type': 'application/json',
                                                      'X-Limes-Signature': deliver.sign(body, key)}, **kw)


def send_slack(project, rules, msg, **kw):
    integ = integration(project)
    url = secret(integ.slack_url_enc) if integ else ''
    text = slack_escape(clean(msg['title'], 250))
    if not url:  # no per-project hook: the install-wide chat setting, as the default alerts use
        from limes.common_func import send_slack_message
        from scanEngine.models import Notification
        n = Notification.objects.first()
        if not (n and n.send_to_slack and n.slack_hook_url):
            raise NotConfigured('no Slack webhook is set')
        send_slack_message(text)
        return
    outbound.request('post', url, data=json.dumps({'text': text}).encode(), headers={'Content-Type': 'application/json'}, **kw)


def jira_ready(integ):
    return bool(integ and integ.jira_base_url and integ.jira_email and secret(integ.jira_token_enc)
                and PROJECT_KEY_RE.fullmatch(integ.jira_project_key or ''))


def create_jira_issue(integ, summary, lines, **kw):
    """Create one issue and return its key. Summary and description are plain text: the description is ADF text nodes."""
    if not jira_ready(integ):
        raise NotConfigured('Jira is not fully set up')
    import base64
    auth = base64.b64encode(('%s:%s' % (integ.jira_email, secret(integ.jira_token_enc))).encode()).decode()
    labels = [LABEL_RE.sub('-', l)[:50] for l in (integ.jira_labels or [])][:MAX_LABELS]
    fields = {'project': {'key': integ.jira_project_key}, 'issuetype': {'name': clean(integ.jira_issue_type or 'Task', 60)},
              'summary': clean(summary, SUMMARY_MAX), 'labels': [l for l in labels if l],
              'description': {'type': 'doc', 'version': 1, 'content': [
                  {'type': 'paragraph', 'content': [{'type': 'text', 'text': clean(l, LINE_MAX)}]} for l in lines if clean(l)]}}
    resp = outbound.request('post', integ.jira_base_url.rstrip('/') + '/rest/api/3/issue', data=json.dumps({'fields': fields}).encode(),
                            headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                                     'Authorization': 'Basic ' + auth}, **kw)
    try:
        key = str(resp.json().get('key', ''))
    except ValueError:
        key = ''
    if not JIRA_KEY_RE.fullmatch(key):
        raise outbound.OutboundError('Jira answered without an issue key')
    return key


def send_jira(project, rules, msg, **kw):
    """One Jira issue per new issue, whatever fires: the key is claimed on the TrackedIssue before the call, so a
    re-fire (a retry, a second rule, a severity bump) finds it set. NOTE: a worker killed between claim and answer leaves
    'pending' and no issue is ever made for that one; upgrade path is a claim timestamp."""
    if msg['kind'] != 'issue_new':
        return
    integ = integration(project)
    if not jira_ready(integ):
        raise NotConfigured('Jira is not fully set up')
    ti = TrackedIssue.objects.filter(project=project, asset_id=msg['asset_id'], key=msg['key']).first() if msg['asset_id'] and msg['key'] else None
    if ti is None or not TrackedIssue.objects.filter(pk=ti.pk, jira_key='').update(jira_key='pending'):
        return
    try:
        sev = SEVERITY_WORDS.get(msg['severity'], 'unrated')
        key = create_jira_issue(integ, '[Limes] %s' % msg['title'],
                                [msg['title'], 'Asset: %s' % (msg['asset'] or '-'), 'Severity: %s' % sev,
                                 'Check: %s' % msg['key'], 'Project: %s' % msg['project']], **kw)
    except BaseException:
        TrackedIssue.objects.filter(pk=ti.pk, jira_key='pending').update(jira_key='')
        raise
    TrackedIssue.objects.filter(pk=ti.pk).update(jira_key=key)


SENDERS = {'in_app': send_in_app, 'email': send_email, 'webhook': send_webhook, 'slack': send_slack, 'jira': send_jira}
