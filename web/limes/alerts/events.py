"""Change events: record one row per change. Delivery is elsewhere (limes.alerts.deliver)."""
from django.utils import timezone

from startScan.models import ChangeEvent

KINDS = ('issue_new', 'issue_fixed', 'issue_regressed', 'score_dropped', 'score_changed',
         'asset_auto_confirmed', 'asset_missing')
IMMEDIATE_SEVERITY = 3
ALWAYS_IMMEDIATE = ('score_dropped', 'asset_auto_confirmed')


def is_immediate(kind, key, severity):
    if kind in ALWAYS_IMMEDIATE:
        return True
    if kind not in ('issue_new', 'issue_regressed'):
        return False
    key = key or ''
    return (severity or 0) >= IMMEDIATE_SEVERITY or key in ('tls.cert_expired', 'tls.cert_expiring') \
        or key.startswith('net.exposed_')


def record(project, kind, title, severity=None, asset=None, detail=None, key=None):
    return ChangeEvent.objects.create(project=project, kind=kind, title=title[:300], severity=severity, asset=asset,
                                      detail=detail or {}, immediate=is_immediate(kind, key, severity),
                                      created_at=timezone.now())
