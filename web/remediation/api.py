"""REST for remediation requests and the Waivers page. Project-scoped: every id is looked up inside the project named
in the request, so an id from another project is a 404. Reads are login-only (like the sibling read endpoints);
writes need PERM_MODIFY_TARGETS and carry the session CSRF check."""
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_date
from rest_framework.response import Response
from rest_framework.views import APIView
from rolepermissions.checkers import has_permission

from api.permissions import HasPermission
from dashboard.models import Project
from limes import scoring, waivers
from limes.checks.catalogue import CHECKS
from limes.definitions import PERM_MODIFY_TARGETS
from remediation import service
from remediation.models import RemediationRequest
from startScan.models import IssueWaiver

LIST_CAP = 200
THREAD_CAP = 200
MEMBER_CAP = 200
WAIVER_CAP = 200


def _project(data):
    slug = data.get('project') if hasattr(data, 'get') else None
    return Project.objects.filter(slug=slug).first() if isinstance(slug, str) else None


def _id(value):
    if isinstance(value, str) and value.isascii() and value.isdigit():
        value = int(value)
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2 ** 63 else None


def _missing(what='not found'):
    return Response({'status': False, 'message': what}, status=404)


def _bad(message):
    return Response({'status': False, 'message': message}, status=400)


def _load(data, key='id'):
    """(project, request) or (None, None): the request must belong to the named project."""
    project, pk = _project(data), _id(data.get(key) if hasattr(data, 'get') else None)
    if project is None or pk is None:
        return None, None
    return project, RemediationRequest.objects.filter(pk=pk, project=project).select_related('project', 'created_by', 'assignee').first()


def _name(user):
    return user.username if user else None


def request_json(row):
    r = row['req']
    return {'id': r.id, 'title': r.title, 'message': r.message, 'status': r.status, 'due_date': r.due_date,
            'created_by': _name(r.created_by), 'assignee': _name(r.assignee), 'external_emails': r.external_emails,
            'email_status': r.email_status, 'created_at': r.created_at, 'updated_at': r.updated_at,
            'completed_at': r.completed_at, 'open_issues': row['open'], 'total_issues': row['total'],
            'impacted_assets': row['assets'], 'categories': row['categories'], 'overdue': row['overdue']}


class RemediationList(APIView):
    def get(self, request):
        project = _project(request.query_params)
        if project is None:
            return _missing('project not found')
        status = request.query_params.get('status') or 'active'
        if status not in ('active', 'completed', 'archived'):
            return _bad('status must be active, completed or archived')
        rows = list(RemediationRequest.objects.filter(project=project, status=status).select_related('created_by', 'assignee')
                    .order_by('-updated_at', '-id')[:LIST_CAP])
        return Response([request_json(r) for r in service.summaries(rows)])


class Writer(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_MODIFY_TARGETS


class RemediationCreate(Writer):
    def post(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        project = _project(data)
        if project is None:
            return _missing('project not found')
        due = data.get('due_date')
        if due in (None, ''):
            due = None
        else:
            try:
                due = parse_date(due) if isinstance(due, str) else None
            except ValueError:
                due = None
            if due is None:
                return _bad('due_date must be YYYY-MM-DD')
        assignee = None
        if data.get('assignee') not in (None, ''):
            assignee = User.objects.filter(username=data['assignee']).first() if isinstance(data['assignee'], str) else None
            if assignee is None:
                return _bad('the assignee must be a member of this project')
        try:
            req = service.create_request(project, request.user, data.get('title'), data.get('message'), due, data.get('issues'),
                                         assignee, data.get('emails'))
        except service.RemediationError as e:
            return _bad(str(e))
        return Response({'status': True, 'id': req.id, 'email_status': req.email_status})


class RemediationDetail(APIView):
    def get(self, request):
        project, req = _load(request.query_params)
        if req is None:
            return _missing()
        summary = service.summaries([req])[0]
        items = [{'issue_id': i.issue_id, 'asset': i.issue.asset.value, 'key': i.issue.key, 'status': i.issue.status,
                  'severity': i.issue.severity,
                  'title': CHECKS[i.issue.key].title if i.issue.source == 'check' and i.issue.key in CHECKS else i.issue.key,
                  'category': scoring.CATEGORY_LABELS[scoring.category_of(i.issue.key)]}
                 for i in req.items.select_related('issue__asset').order_by('issue__asset__value', 'issue__key', 'id')[:service.MAX_ISSUES]]
        return Response({**request_json(summary), 'items': items, 'impact': service.impact(req),
                         'messages': [{'author': _name(m.author), 'text': m.text, 'created_at': m.created_at}
                                      for m in req.messages.select_related('author').order_by('created_at', 'id')[:THREAD_CAP]],
                         'events': [{'kind': e.kind, 'text': e.text, 'actor': _name(e.actor), 'created_at': e.created_at}
                                    for e in req.events.select_related('actor').order_by('created_at', 'id')[:THREAD_CAP]]})


class RemediationStatus(Writer):
    def post(self, request):
        project, req = _load(request.data)
        if req is None:
            return _missing()
        try:
            req = service.set_status(req, request.user, request.data.get('status'))
        except service.RemediationError as e:
            return _bad(str(e))
        return Response({'status': True, 'request_status': req.status})


class RemediationMessagePost(Writer):
    def post(self, request):
        project, req = _load(request.data)
        if req is None:
            return _missing()
        try:
            service.add_message(req, request.user, request.data.get('text'))
        except service.RemediationError as e:
            return _bad(str(e))
        return Response({'status': True})


class Members(APIView):
    """Users who can be named as an approver or assignee (see limes.waivers.is_member)."""

    def get(self, request):
        project = _project(request.query_params)
        if project is None:
            return _missing('project not found')
        # only people who are members of this project, never the instance's other users
        users = [u.username for u in User.objects.filter(is_active=True, project_memberships__project=project).distinct().order_by('username')[:MEMBER_CAP * 5]
                 if waivers.is_member(u, project.id)][:MEMBER_CAP]
        return Response(users)


def waiver_json(w, now):
    state = ('revoked' if w.revoked_at else 'pending' if w.approval_pending else
             'expired' if w.expires_at and w.expires_at <= now else 'active')
    issue = w.issue
    return {'id': w.id, 'scope': 'all' if w.issue_id is None else 'issue', 'state': state, 'kind': w.kind,
            'key': w.key if w.issue_id is None else issue.key, 'asset': issue.asset.value if issue else None,
            'issue_id': w.issue_id, 'reason': w.reason, 'shared': w.shared, 'created_by': _name(w.created_by),
            'created_at': w.created_at, 'expires_at': w.expires_at, 'approver': _name(w.approver),
            'revoked_at': w.revoked_at, 'remind_days': w.remind_days}


def project_waivers(project, now):
    """(current, past) waiver rows, newest first, each list capped."""
    base = (IssueWaiver.objects.filter(Q(issue__project=project) | Q(issue__isnull=True, project=project))
            .select_related('issue__asset', 'created_by', 'approver').order_by('-created_at', '-id'))
    live = (Q(revoked_at__isnull=True) & (Q(expires_at__isnull=True) | Q(expires_at__gt=now)))
    return list(base.filter(live)[:WAIVER_CAP]), list(base.exclude(live)[:WAIVER_CAP])


class WaiverList(APIView):
    def get(self, request):
        project = _project(request.query_params)
        if project is None:
            return _missing('project not found')
        now = timezone.now()
        current, past = project_waivers(project, now)
        return Response({'current': [waiver_json(w, now) for w in current], 'past': [waiver_json(w, now) for w in past]})


class WaiverDecide(Writer):
    def post(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        project, wid = _project(data), _id(data.get('waiver_id'))
        if project is None or wid is None or not isinstance(data.get('approve'), bool):
            return _missing('waiver not found') if project is None or wid is None else _bad('approve must be true or false')
        try:
            waivers.decide_waiver(project, wid, request.user, data['approve'])
        except LookupError:
            return _missing('waiver not found')
        except waivers.WaiverError as e:
            return _bad(str(e))
        return Response({'status': True, 'message': 'approved' if data['approve'] else 'rejected'})


class WaiverRevoke(Writer):
    def post(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        project, wid = _project(data), _id(data.get('waiver_id'))
        if project is None or wid is None:
            return _missing('waiver not found')
        try:
            done = waivers.revoke_waiver_id(project, wid, request.user)
        except LookupError:
            return _missing('waiver not found')
        return Response({'status': done, 'message': 'revoked' if done else 'this waiver is already over'}, status=200 if done else 400)
