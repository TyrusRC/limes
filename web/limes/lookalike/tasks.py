"""Beat tasks for lookalike domains. DNS, RDAP and crt.sh only; nothing here creates or touches an Asset.

NOTE: due rows are loaded TICK_ROWS at a time and the tick DNS share is small by design (5000/day is about four
queries a minute), so a first sweep of a large root takes hours. Upgrade path: a larger budget or a local resolver.
"""
import logging
import time

from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from limes.celery import app
from limes.checks import collect
from limes.continuous import tick_lock
from limes.feeds import store
from limes.intel import crtsh, http, ratelimit
from limes.lookalike import check, generate
from startScan.models import Asset, Lookalike

log = logging.getLogger(__name__)

TICK_BUDGET = 45  # seconds
# New roots are not started after this many seconds: one root can cost ~130 s (crt.sh down, slow generation), and the
# task's soft limit is 780 s. The roots left over go first next time (generated_at).
GENERATE_BUDGET = 600
TICK_ROWS = 25
MIN_DNS_SHARE = 4  # one registered row costs NS, A, AAAA and MX; a smaller share could never finish one
CT_KEYWORD_EVERY = 20 * 3600
MIN_CT_LABEL = 4
MAX_CT_ROWS = 5000
OWNED = ('owned_root', 'owned_host')


def _clock():
    return time.monotonic()


def _enabled():
    return settings.LOOKALIKE_ENABLED and settings.CONTINUOUS_SCANS


def _owned_roots():
    return Asset.objects.filter(kind='root_domain', scope_tier='owned_root').exclude(state='retired').select_related('project')


def _state(root, **update):
    """Merge keys into root.enrichment['lookalike'] under the row lock (the baseline and the CT stamp are written by
    different tasks)."""
    from limes.tasks import intel
    with transaction.atomic():
        row = Asset.objects.select_for_update().only('enrichment').get(pk=root.pk)
        intel._store(root, 'lookalike', {**((row.enrichment or {}).get('lookalike') or {}), **update}, timezone.now())


def _rows(root, found, source, first_seen=None):
    extra = {'first_seen': first_seen} if first_seen else {}
    return [Lookalike(project_id=root.project_id, root=root, domain=c['domain'], unicode=c['unicode'][:253],
                      fuzzers=c['fuzzers'], source=source, **extra) for c in found]


# NOTE: a CT match on a subdomain (example.vendor.net) is reduced to its registrable parent (vendor.net), so a
# vendor-hosted subdomain makes the vendor a false-positive lookalike. Upgrade path: skip parents whose zone is a
# known shared host, or let the user mark a parent as ignored (already supported: the row stays ignored).
def _ct_keyword(root, owned, now):
    """(candidates, first): `first` is True for the root's first successful keyword run, whose rows are baseline."""
    state = (root.enrichment or {}).get('lookalike') or {}
    stamp = state.get('ct_at')
    if stamp and now.timestamp() - _ts(stamp) < CT_KEYWORD_EVERY:
        return [], False
    label = generate._EXTRACT(root.value).domain
    if len(label) < MIN_CT_LABEL:
        return [], False
    status, rows = http.get_json(crtsh.keyword_url(label), provider='crtsh', max_wait=10, max_bytes=http.MAX_BODY)
    if status != 200 or not isinstance(rows, list):
        return [], False  # no data is not "no lookalikes": retry on the next run
    first = 'ct_baseline_at' not in state
    _state(root, ct_at=now.isoformat(), **({'ct_baseline_at': now.isoformat()} if first else {}))
    names = [n for c in crtsh.parse(rows[:MAX_CT_ROWS]) for n in c['names']]
    return [{'domain': d, 'unicode': generate._unicode(d), 'fuzzers': []} for d in generate.ct_matches(names, label, owned)], first


def _ts(stamp):
    from datetime import datetime
    try:
        return datetime.fromisoformat(stamp).timestamp()
    except (TypeError, ValueError):
        return 0.0


@app.task(name='generate_lookalikes', bind=False)
def generate_lookalikes():
    """Daily: candidate rows for every owned root. Never deletes a row."""
    if not _enabled():
        return {'reason': 'disabled'}
    with tick_lock('generate_lookalikes') as got:
        if not got:
            return {'reason': 'locked'}
        now, roots, deferred, start = timezone.now(), 0, 0, _clock()
        # least recently generated first (never first), so roots left over by the budget are not starved
        # NOTE: sorts every owned root in Python; fine for hundreds. Upgrade path: a generated_at column.
        todo = sorted(_owned_roots(), key=lambda r: (((r.enrichment or {}).get('lookalike') or {}).get('generated_at') or '', r.id))
        for root in todo:
            if _clock() - start > GENERATE_BUDGET:
                deferred += 1
                continue
            try:
                owned = set(Asset.objects.filter(project_id=root.project_id, kind__in=('root_domain', 'hostname'),
                                                 scope_tier__in=OWNED).values_list('value', flat=True))
                found = generate.candidates(root.value, root.project.brand_keywords or [], owned)
                Lookalike.objects.bulk_create(_rows(root, found, 'permutation'), ignore_conflicts=True, batch_size=500)
                ct, first = _ct_keyword(root, owned, now)
                Lookalike.objects.bulk_create(_rows(root, ct, 'ct', now if first else None), ignore_conflicts=True)
                roots += 1
            except SoftTimeLimitExceeded:
                raise
            except Exception:  # noqa: BLE001 - one root must not stop the rest; no message (it may echo hostile names)
                log.exception('lookalike generation failed for a root')
            _state(root, generated_at=timezone.now().isoformat())  # attempted: a failing root does not starve the others
        return {'roots': roots, 'deferred': deferred}


def _ct_baseline(row, root):
    """True for a CT row found by the root's first successful keyword run: it is part of the baseline."""
    from datetime import datetime
    if row.source != 'ct':
        return False
    try:
        at = datetime.fromisoformat(((root.enrichment or {}).get('lookalike') or {}).get('ct_baseline_at') or '')
    except ValueError:
        return False
    return row.first_seen <= at


def _spender(shares):
    budgets = {'dns': ('lookalike_dns', settings.LOOKALIKE_DNS_DAILY_BUDGET), 'rdap': ('rdap', settings.RDAP_DAILY_BUDGET)}

    def spend(kind):
        if shares[kind] <= 0:
            return False
        provider, limit = budgets[kind]
        if not ratelimit.take_daily(provider, limit):
            return False
        shares[kind] -= 1
        return True
    return spend


def _check_one(row, now, bootstrap, spend, owned):
    events = []
    if check.covered(row.domain, owned.get(row.project_id, ())):  # it became ours since it was generated
        Lookalike.objects.filter(pk=row.pk).update(status='ours', next_check=now + check.NEXT['gone'])
        return [], False
    try:
        events = check.check_row(row, now, collect._resolve, http.get_json, bootstrap, spend)
    except check.Stop as s:
        return s.events, True
    except SoftTimeLimitExceeded:
        raise
    except Exception:  # noqa: BLE001 - park the row an hour so it cannot hot-loop; no message (hostile names)
        log.exception('lookalike check failed')
        Lookalike.objects.filter(pk=row.pk).update(next_check=now + check.DNS_RETRY)
        return [], False
    try:
        check.check_http(row, now, spend=spend)
    except check.Stop:
        return events, True
    except SoftTimeLimitExceeded:
        raise
    except Exception:  # noqa: BLE001
        log.exception('lookalike http look failed')
    return events, False


@app.task(name='lookalike_tick', bind=False)
def lookalike_tick():
    """Beat tick: check the due rows within the DNS/RDAP budgets and record events (silently, until the root's first
    sweep has covered every row)."""
    if not _enabled():
        return {'reason': 'disabled'}
    from dashboard.stats import invalidate
    from limes.alerts import events as change_events
    from limes.alerts.deliver import deliver_immediate
    with tick_lock('lookalike_tick') as got:
        if not got:
            return {'reason': 'locked'}
        start, now = _clock(), timezone.now()
        loaded = store.load('iana_rdap')
        bootstrap = loaded[0] if loaded else {}
        spend = _spender({'dns': max(ratelimit.per_tick(settings.LOOKALIKE_DNS_DAILY_BUDGET), MIN_DNS_SHARE),
                          'rdap': ratelimit.per_tick(settings.RDAP_DAILY_BUDGET)})
        baselined, touched, checked, recorded, stopped, owned = {}, {}, 0, 0, False, {}
        for row in check.due_rows(now, TICK_ROWS):
            if _clock() - start > TICK_BUDGET:
                break
            root = row.root
            baselined.setdefault(root.id, bool(((root.enrichment or {}).get('lookalike') or {}).get('baselined_at')))
            touched[root.id] = root
            if row.project_id not in owned:
                owned[row.project_id] = set(Asset.objects.filter(
                    project_id=row.project_id, kind__in=('root_domain', 'hostname'), scope_tier__in=OWNED
                ).values_list('value', flat=True))
            events, stopped = _check_one(row, now, bootstrap, spend, owned)
            checked += 1
            if baselined[root.id] and not _ct_baseline(row, root):
                for kind, title, key in events:
                    if change_events.safe_record(row.project, kind, title, asset=root, key=key,
                                                 detail={'domain': row.domain, 'root': root.value}):
                        recorded += 1
            if stopped:
                break
        projects = {}
        for root in touched.values():
            if not baselined[root.id] and not Lookalike.objects.filter(root=root, last_checked__isnull=True).exists():
                _state(root, baselined_at=now.isoformat())
            elif baselined[root.id]:
                projects[root.project_id] = root.project
        for project in projects.values():
            try:
                deliver_immediate(project)
                invalidate(project.id)
            except SoftTimeLimitExceeded:
                raise
            except Exception:  # noqa: BLE001
                log.exception('lookalike alert delivery failed for project %s', project.id)
        return {'checked': checked, 'events': recorded, 'stopped': stopped}
