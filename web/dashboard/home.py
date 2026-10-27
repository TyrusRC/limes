"""The Home feed: what changed (All activity) and what needs a person (My tasks), with per-user dismissals.
Plain data with a fixed number of queries; titles and names are data, escaped by the template."""
from datetime import timedelta

from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from api.serializers import safe_redirect_link
from dashboard.models import FeedDismissal, InAppNotification
from dashboard.stats import CHANGE_LABELS
from limes.checks.catalogue import CHECKS, PROVISIONAL
from limes.risk_detail import detected_at
from startScan.models import Asset, ChangeEvent, IssueWaiver, TrackedIssue

WINDOW = timedelta(days=30)         # how far back activity goes
TASK_WINDOW = timedelta(days=7)     # "newly appearing" and "expiring soon"
ACTIVITY_LIMIT = 50
TASK_LIMIT = 20
CANDIDATE_LIMIT = 10
DISMISSED_CAP = 5000                # NOTE: dismissals are never pruned; past this many a user's oldest come back. Upgrade path: prune by item age.

# kind -> (tone, icon, action label, route name)
KINDS = {
    'issue_new': ('bad', 'fe-alert-triangle', 'Open issues', 'issues'), 'issue_regressed': ('bad', 'fe-rotate-ccw', 'Open issues', 'issues'),
    'issue_fixed': ('ok', 'fe-check', 'Open issues', 'issues'), 'waiver_expired': ('warn', 'fe-clock', 'Review issues', 'issues'),
    'score_dropped': ('warn', 'fe-trending-down', 'View score', 'dashboardIndex'), 'score_changed': ('', 'fe-trending-up', 'View score', 'dashboardIndex'),
    'asset_new': ('warn', 'fe-plus-circle', 'Review assets', 'assets'), 'asset_missing': ('warn', 'fe-eye-off', 'Review assets', 'assets'),
    'asset_auto_confirmed': ('ok', 'fe-globe', 'Review assets', 'assets'), 'cert_new': ('warn', 'fe-shield', 'Review assets', 'assets'),
    'dns_changed': ('warn', 'fe-shuffle', 'Review assets', 'assets'), 'monitoring_degraded': ('bad', 'fe-wifi-off', 'View overview', 'dashboardIndex'),
    'monitoring_restored': ('ok', 'fe-wifi', 'View overview', 'dashboardIndex'), 'breach_new': ('bad', 'fe-shield-off', 'Review assets', 'assets'),
    'lookalike_new': ('warn', 'fe-copy', 'Review lookalikes', 'lookalikes'), 'lookalike_active': ('bad', 'fe-alert-octagon', 'Review lookalikes', 'lookalikes'),
}
NOTICE_TONE = {'danger': 'bad', 'error': 'bad', 'warning': 'warn', 'success': 'ok'}


def _url(name, slug):
    return reverse(name, args=[slug])


def _card(key, title, when, description='', tone='', icon='fe-activity', label='', url=None, kind=''):
    return {'key': key, 'title': title, 'when': when, 'description': description, 'tone': tone, 'icon': icon,
            'action_label': label, 'url': url, 'kind': kind}


def _title(issue):
    check = CHECKS.get(issue.key) if issue.source == 'check' else None
    return check.title if check else issue.key


def activity(project, now, dismissed):
    slug = project.slug
    since = now - WINDOW
    cards = []
    for e in (ChangeEvent.objects.filter(project=project, created_at__gte=since).select_related('asset')
              .order_by('-created_at', '-id')[:ACTIVITY_LIMIT + len(dismissed)]):
        tone, icon, label, route = KINDS.get(e.kind, ('', 'fe-activity', 'Open overview', 'dashboardIndex'))
        cards.append(_card(f'event:{e.id}', e.title, e.created_at, CHANGE_LABELS.get(e.kind, e.kind) + (f' on {e.asset.value}' if e.asset else ''),
                           tone, icon, label, _url(route, slug), e.kind))
    for n in (InAppNotification.objects.filter(Q(project=project) | Q(project__isnull=True), created_at__gte=since)
              .order_by('-created_at', '-id')[:ACTIVITY_LIMIT]):
        link = safe_redirect_link(n.redirect_link)
        cards.append(_card(f'notice:{n.id}', n.title, n.created_at, n.description, NOTICE_TONE.get(n.status, ''), 'fe-bell',
                           'Open' if link else '', link, 'notice'))
    cards = [c for c in cards if c['key'] not in dismissed]
    cards.sort(key=lambda c: c['when'], reverse=True)
    return cards[:ACTIVITY_LIMIT]


def _waiver_tasks(project, now, user):
    """Waivers ending within their own reminder lead time, and the ones waiting for this user to approve."""
    slug = project.slug
    out = []
    # each waiver has its own lead time (remind_days, at most 90): fetch those ending within the longest, keep the due ones
    # NOTE: looks at the 200 soonest-ending waivers; more than that ending within 90 days and a later one may wait a day.
    near = (IssueWaiver.objects.filter(IssueWaiver.active_q(now), expires_at__lte=now + timedelta(days=90))
            .filter(Q(issue__project=project, issue__status='open') | Q(issue__isnull=True, project=project))
            .select_related('issue', 'issue__asset').order_by('expires_at', 'id')[:200])
    soon = [w for w in near if w.expires_at <= now + timedelta(days=w.remind_days)][:TASK_LIMIT]
    for w in soon:
        days = max(0, (w.expires_at - now).days)
        what = w.issue if w.issue_id else None
        out.append(_card(f'task:waiver:{w.id}', f'Waiver ends in {days} {"day" if days == 1 else "days"}: {_title(what) if what else w.key}', w.expires_at,
                         what.asset.value if what else 'All assets', 'warn', 'fe-clock', 'Review waiver',
                         reverse('issue_detail', args=[slug, w.issue_id]) if what else reverse('waivers_page', args=[slug]), 'waiver'))
        out[-1]['upcoming'] = True  # its time is in the future: the card says "in 3 days", not "ago"
    if user is not None and user.is_authenticated:
        pending = (IssueWaiver.objects.filter(approval_pending=True, revoked_at__isnull=True, approver=user)
                   .filter(Q(issue__project=project) | Q(issue__isnull=True, project=project))
                   .exclude(created_by=user).select_related('issue', 'created_by').order_by('-created_at', '-id')[:TASK_LIMIT])
        for w in pending:
            who = w.created_by.username if w.created_by else 'someone'
            out.append(_card(f'task:approve:{w.id}', f'Approve a waiver for {w.key or w.issue.key}', w.created_at, f'Requested by {who}',
                             'warn', 'fe-user-check', 'Review waiver', reverse('waivers_page', args=[slug]), 'approval'))
    return out


def _remediation_tasks(project, now):
    from remediation.models import RemediationRequest
    late = (RemediationRequest.objects.filter(project=project, status='active', due_date__lt=timezone.localdate(now))
            .order_by('due_date', 'id')[:TASK_LIMIT])
    return [_card(f'task:remediation:{r.id}', f'Overdue: {r.title}', r.updated_at, f'Due {r.due_date:%Y-%m-%d}', 'bad', 'fe-check-square',
                  'Open request', reverse('remediation_detail', args=[project.slug, r.id]), 'remediation') for r in late]


def tasks(project, now, dismissed, user=None):
    from limes.tasks.attribution import REVIEW  # candidates below it stay out of the lists, as on the Assets page
    slug = project.slug
    out = _waiver_tasks(project, now, user) + _remediation_tasks(project, now)
    fresh = (TrackedIssue.objects.filter(project=project, status='open', severity__gte=3)
             .exclude(source='check', key__in=PROVISIONAL).exclude(IssueWaiver.waived_exists(now)).select_related('asset'))
    fresh = [i for i in fresh.order_by('-severity', '-first_seen', 'id')[:TASK_LIMIT * 3] if detected_at(i) >= now - TASK_WINDOW][:TASK_LIMIT]
    for i in fresh:
        sev = 'Critical' if i.severity == 4 else 'High'
        out.append(_card(f'task:issue:{i.id}', f'New {sev.lower()} issue: {_title(i)}', detected_at(i), i.asset.value,
                         'bad', 'fe-alert-triangle', 'Open risk', reverse('issue_detail', args=[slug, i.id]), 'issue'))
    cands = (Asset.objects.filter(project=project, scope_tier='candidate').filter(Q(confidence__isnull=True) | Q(confidence__gte=REVIEW))
             .order_by('-first_seen', 'id')[:CANDIDATE_LIMIT])
    for a in cands:
        out.append(_card(f'task:candidate:{a.id}', f'Confirm or reject {a.value}', a.first_seen, 'Found but not yet confirmed as yours',
                         'warn', 'fe-help-circle', 'Review asset', _url('assets', slug) + '?scope_tier=candidate', 'candidate'))
    return [c for c in out if c['key'] not in dismissed]


def dismissed_keys(project, user, now):
    return set(FeedDismissal.objects.filter(user=user, project=project).order_by('-id').values_list('item', flat=True)[:DISMISSED_CAP])


def build(project, user, now=None):
    now = now or timezone.now()
    dismissed = dismissed_keys(project, user, now)
    return {'activity': activity(project, now, dismissed), 'tasks': tasks(project, now, dismissed, user)}
