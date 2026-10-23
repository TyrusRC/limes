"""Change events: record one row per change. Delivery is elsewhere (limes.alerts.deliver)."""
import logging

from celery.exceptions import SoftTimeLimitExceeded
from django.db import transaction
from django.utils import timezone

from limes.checks import network
from startScan.models import ChangeEvent

logger = logging.getLogger(__name__)
KINDS = ('issue_new', 'issue_fixed', 'issue_regressed', 'score_dropped', 'score_changed',
         'asset_auto_confirmed', 'asset_missing', 'waiver_expired', 'asset_new')
IMMEDIATE_SEVERITY = 3
ALWAYS_IMMEDIATE = ('score_dropped', 'asset_auto_confirmed')


def is_immediate(kind, key, severity):
    if kind in ALWAYS_IMMEDIATE:
        return True
    if kind == 'asset_new':  # only a new host that exposes a risky service interrupts
        return (key or '').startswith('net.exposed_')
    if kind == 'waiver_expired':  # the caller passes severity only while the issue is still open
        return (severity or 0) >= IMMEDIATE_SEVERITY
    if kind not in ('issue_new', 'issue_regressed'):
        return False
    key = key or ''
    return (severity or 0) >= IMMEDIATE_SEVERITY or key in ('tls.cert_expired', 'tls.cert_expiring') \
        or key.startswith(('net.exposed_', 'rep.'))


def record(project, kind, title, severity=None, asset=None, detail=None, key=None):
    return ChangeEvent.objects.create(project=project, kind=kind, title=title[:300], severity=severity, asset=asset,
                                      detail=detail or {}, immediate=is_immediate(kind, key, severity),
                                      created_at=timezone.now())


def safe_record(*args, **kwargs):
    """record() for callers whose own work is already committed: a failure is logged and the event lost,
    never raised into the stage."""
    try:
        with transaction.atomic():
            return record(*args, **kwargs)
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        logger.exception('Could not record change event %s', args[1] if len(args) > 1 else kwargs.get('kind'))


def record_asset_new(project, asset, ports=()):
    """The one place an asset_new event is built. Callers stay silent on a first sweep."""
    ports = sorted(ports)
    key = network.risky_check(ports)
    title = f'New {asset.kind} {asset.value}' + (f' exposes {key[len("net.exposed_"):]}' if key else '')
    parent = asset.parent.value if asset.parent_id else None
    return safe_record(project, 'asset_new', title, asset=asset, detail={'ports': ports, 'parent': parent}, key=key)
