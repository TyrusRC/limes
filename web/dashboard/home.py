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


def tasks(project, now, dismissed):
    from limes.tasks.attribution import REVIEW  # candidates below it stay out of the lists, as on the Assets page
    slug = project.slug
    out = []
    soon = (IssueWaiver.objects.filter(IssueWaiver.active_q(now), issue__project=project, issue__status='open',
                                       expires_at__lte=now + TASK_WINDOW)
            .select_related('issue', 'issue__asset').order_by('expires_at', 'id')[:TASK_LIMIT])
    for w in soon:
        days = max(0, (w.expires_at - now).days)
        out.append(_card(f'task:waiver:{w.id}', f'Waiver ends in {days} {"day" if days == 1 else "days"}: {_title(w.issue)}', w.expires_at,
                         w.issue.asset.value, 'warn', 'fe-clock', 'Review waiver', reverse('issue_detail', args=[slug, w.issue_id]), 'waiver'))
        out[-1]['upcoming'] = True  # its time is in the future: the card says "in 3 days", not "ago"
    live = IssueWaiver.objects.filter(IssueWaiver.active_q(now)).values('issue_id')
    fresh = (TrackedIssue.objects.filter(project=project, status='open', severity__gte=3)
             .exclude(source='check', key__in=PROVISIONAL).exclude(id__in=live).select_related('asset'))
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
    return {'activity': activity(project, now, dismissed), 'tasks': tasks(project, now, dismissed)}
