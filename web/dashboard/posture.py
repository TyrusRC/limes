"""Overview posture cards (richer Overview, Task 3): categories, exposure, certificates, technologies.
Each builder returns plain data with a fixed number of queries; names are data, escaped by the template."""
import socket
from datetime import datetime, timedelta, timezone as dt_timezone

from django.db.models import Count
from django.utils import timezone

from dashboard.stats import OWNED
from limes import scoring
from limes.checks.catalogue import RISKY_PORTS
from limes.checks.collect import _fresh_internetdb

EXPOSURE_LIMIT = 15
CERT_LIMIT = 10
TECH_LIMIT = 10
CERT_WINDOW = timedelta(days=30)
CHANGE_WINDOW = timedelta(days=30)
CERT_CHECKS = ('tls.cert_expired', 'tls.cert_expiring')


def _snapshot_categories(project, now):
    """The latest snapshot dated at or before today - 30 days that has category scores, else {}."""
    from startScan.models import ScoreSnapshot
    cutoff = timezone.localtime(now).date() - CHANGE_WINDOW
    rows = ScoreSnapshot.objects.filter(project=project, date__lte=cutoff).order_by('-date').values_list('categories', flat=True)
    # NOTE: skips pre-categories rows one by one; at most one snapshot per day, so the scan is short.
    return next((c for c in rows.iterator() if isinstance(c, dict)), {})


def category_cards(project, now=None):
    now = now or timezone.now()
    scores = scoring.category_scores(project, now)
    counts = scoring.category_issue_counts(project, now)
    before = _snapshot_categories(project, now)
    cards = []
    for key in scoring.CATEGORIES:
        s, c = scores[key], counts[key]
        old = before.get(key)
        cards.append({'key': key, 'label': scoring.CATEGORY_LABELS[key], 'score': s['score'], 'grade': s['grade'],
                      'raw_score': s['raw_score'], 'assessed': s['assessed'] > 0, 'open': c['open'], 'waived': c['waived'],
                      'delta_30': s['score'] - old if s['score'] is not None and isinstance(old, int) else None})
    return cards


def _service(port):
    if port in RISKY_PORTS:
        return RISKY_PORTS[port][0]
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return ''


def exposure(project, now=None):
    now = now or timezone.now()
    hosts_by_port = {}
    hosts = 0
    # NOTE: reads every owned IP's enrichment JSON into Python; fine for tens of thousands. Upgrade path: jsonb_array_elements in SQL.
    for asset in scoring.scored_assets(project).filter(kind='ip').only('id', 'value', 'enrichment'):
        fresh = _fresh_internetdb(asset, now)
        ports = set()
        for p in (fresh[0].get('ports') or []) if fresh else []:
            if isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536:
                ports.add(p)
        hosts += bool(ports)
        for p in ports:
            hosts_by_port[p] = hosts_by_port.get(p, 0) + 1
    rows = []
    for port, n in hosts_by_port.items():
        risky = RISKY_PORTS.get(port)
        rows.append({'port': port, 'service': _service(port), 'hosts': n, 'risky': bool(risky),
                     'severity': scoring.SEVERITY_NAMES[risky[1]] if risky else None,
                     'check': f'net.exposed_{risky[0]}' if risky else None})
    rows.sort(key=lambda r: (not r['risky'], -(RISKY_PORTS[r['port']][1] if r['risky'] else 0), -r['hosts'], r['port']))
    return {'rows': rows[:EXPOSURE_LIMIT], 'ports': len(hosts_by_port), 'hosts': hosts}


def _not_after(evidence):
    try:
        ts = datetime.fromisoformat(evidence['not_after'])
    except (KeyError, TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=dt_timezone.utc)


def certificates(project, now=None):
    now = now or timezone.now()
    best = {}  # asset id -> {host, not_after, severity}
    # NOTE: filters the window in Python (at most two rows per scored asset); upgrade path: a SQL cast of evidence.not_after.
    rows = (scoring._fresh_checks(project, now).filter(check_id__in=CERT_CHECKS, evidence__has_key='not_after')
            .values_list('asset_id', 'asset__value', 'status', 'severity', 'evidence'))
    for asset_id, host, status, severity, evidence in rows:
        ts = _not_after(evidence)
        if ts is None or ts > now + CERT_WINDOW:
            continue
        cur = best.setdefault(asset_id, {'host': host, 'not_after': ts, 'severity': None})
        cur['not_after'] = min(cur['not_after'], ts)
        if status == 'fail':  # a pass row has no severity to show
            cur['severity'] = max(cur['severity'] or 0, severity) or None
    out = sorted(best.values(), key=lambda r: (r['not_after'], r['host']))
    return {'rows': [{'host': r['host'], 'not_after': r['not_after'], 'days_left': (r['not_after'] - now).days,
                      'expired': r['not_after'] <= now, 'severity': scoring.SEVERITY_NAMES.get(r['severity'])}
                     for r in out[:CERT_LIMIT]], 'total': len(out)}


def technologies(project):
    from startScan.models import Asset
    rows = (Asset.objects.filter(project=project, scope_tier__in=OWNED).exclude(state='retired')
            .exclude(technologies__name__isnull=True).exclude(technologies__name='')
            .values('technologies__name').annotate(count=Count('id', distinct=True)).order_by('-count', 'technologies__name'))
    return [{'name': r['technologies__name'], 'count': r['count']} for r in rows[:TECH_LIMIT]]
