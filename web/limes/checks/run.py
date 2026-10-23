"""Run the risk checks for one owned root (run_checks) or one monitored asset (run_asset_checks): collect,
evaluate, upsert. Honors the scope guard; every host is contacted only on its vetted IP (limes.safe_fetch)."""
import logging
import time
from datetime import timedelta

from celery.exceptions import SoftTimeLimitExceeded
from django.db.models import Max, Q
from django.utils import timezone

from limes import safe_fetch, scope
from limes.checks import collect, dns, email, network, tls, web
from limes.checks.catalogue import CHECKS
from limes.identity import ScanIdentity
from limes.scoring import _root_of
from startScan.models import Asset, RiskCheck

log = logging.getLogger(__name__)

# NOTE: ceiling of web/tls hosts contacted per run, oldest-checked first. Upgrade path:
# a per-project setting or a rolling cursor if inventories outgrow it.
MAX_HOSTS = 200
# NOTE: wall-clock budget for the contact phase; the stage runs under a 1-hour Celery limit.
# Hosts not reached keep their old rows and go first next run (oldest-checked first).
RUN_BUDGET = timedelta(minutes=45)
OWNED = ('owned_root', 'owned_host')


def _defaults():
    # http/tls are built per host from its vetted IP (_pinned): there is no unpinned default
    return {'mail_dns': collect.observe_mail_dns, 'ports': collect.ports_for_ip}


def _pinned(ip, deadline):
    """http/tls observers that connect only to the vetted ip, all within one host-check deadline, with the
    injectable observers' signatures."""
    return {'http': lambda host, ident: collect.observe_http(host, ident,
                                                             get=safe_fetch.pinned_get(host, ip, deadline=deadline)),
            'tls': lambda host: collect.observe_tls(host, connect=safe_fetch.pinned_tls_connect(ip, deadline=deadline))}


def _no_answer(asset, now):
    """What a host that never answered gets, written without contacting it: web not_applicable (no server) and tls
    'error' (unknown), as an unresolvable name produced before pinning. Old fails are superseded and the host
    rotates behind live ones."""
    return (web.evaluate({'host': asset.value, 'https': None, 'http': None})
            + tls.evaluate({'cert': 'error', 'legacy': {}}, now))


def _host_checks(asset, holder, now, observers, resolve, done, refused_rows=False):
    """web + tls results for one host, through observers pinned to its vetted IP. Resolves exactly once.
    A refused host is never contacted: it gets the no-answer rows when refused_rows (the scan path), else none."""
    ip, reason = safe_fetch.resolve_vetted(asset.value, resolve=resolve)
    if reason:
        done['refused'] = reason
        log.info('risk checks: %s not contacted: %s', asset.value, reason)
        return _no_answer(asset, now) if refused_rows else None
    deadline = safe_fetch.Deadline()
    obs = {**_pinned(ip, deadline), **(observers or {})}
    http = obs['http'](asset.value, ScanIdentity.for_domain(holder))
    tls_obs = obs['tls'](asset.value)
    # live = something answered: HTTP on either port, or a TLS handshake on 443 (a bad certificate still proves an
    # open port, though requests reports it only as an error)
    done['http_live'] = (any(isinstance(http.get(k), dict) for k in ('https', 'http'))
                         or isinstance(tls_obs.get('cert'), dict))
    done['timeout'] = deadline.expired()  # results stand (a timeout is 'error', never a pass); the caller is told
    return web.evaluate(http) + tls.evaluate(tls_obs, now)


def _stepper(now, done):
    def step(asset, produce):
        try:
            results = produce()
            if results is None:
                return
            _write(asset, results, now)
            done['checked'] += 1
        except SoftTimeLimitExceeded:
            raise
        except Exception:
            log.exception('risk check failed for %s', asset.value)
            done['failed'] += 1
    return step


def _write(asset, results, now):
    for r in results:
        RiskCheck.objects.update_or_create(
            asset=asset, check_id=r.check,
            defaults={'status': r.status, 'severity': CHECKS[r.check].severity,
                      'evidence': r.evidence, 'last_checked': now})


def _owned(project):
    return Asset.objects.filter(project=project, scope_tier__in=OWNED).exclude(state='retired')


def _web_hosts(project, root, hosts_cap):
    """Owned hostnames under root plus the root itself, scope-checked, oldest-checked first."""
    cands = [a for a in _owned(project).filter(kind__in=('hostname', 'root_domain'))
             if _root_of(a.value, [root.value])]
    allowed, _refused = scope.may_contact(project, [a.value for a in cands])
    ok = set(allowed)
    last = dict(Asset.objects.filter(id__in=[a.id for a in cands]).annotate(
        last=Max('risk_checks__last_checked', filter=Q(risk_checks__check_id__startswith='web.')
                 | Q(risk_checks__check_id__startswith='tls.'))).values_list('id', 'last'))
    picked = [a for a in cands if a.value in ok]
    picked.sort(key=lambda a: (last[a.id] is not None, last[a.id] or 0, a.value))
    return picked[:hosts_cap]


def run_checks(project, root, now=None, observers=None, clock=time.monotonic, resolve=collect._resolve):
    if root.scope_tier != 'owned_root':
        return {'checked': 0, 'failed': 0}
    start = clock()
    now = now or timezone.now()
    obs = {**_defaults(), **(observers or {})}
    done = {'checked': 0, 'failed': 0}
    step = _stepper(now, done)

    for a in _web_hosts(project, root, MAX_HOSTS):
        if clock() - start > RUN_BUDGET.total_seconds():
            break
        holder = a if a.request_headers else root
        step(a, lambda a=a, holder=holder: _host_checks(a, holder, now, observers, resolve, {}, refused_rows=True))

    if root.kind == 'root_domain':
        # DNS only, no contact: not capped or scope-gated
        def root_checks():
            mail, dns_obs = obs['mail_dns'](root.value)
            return email.evaluate(mail) + dns.evaluate(dns_obs)
        step(root, root_checks)

    # IPs have no hostname, so they belong to no root: evaluate them with the project's first
    # owned root only, instead of once per root.
    first = _owned(project).filter(kind='root_domain').order_by('id').first()
    if first and first.id == root.id:
        for ip in _owned(project).filter(kind='ip'):
            step(ip, lambda ip=ip: network.evaluate(*obs['ports'](ip, now)))
    return done


def run_asset_checks(asset, now=None, observers=None, resolve=collect._resolve):
    """The risk checks for one monitored asset, outside any root scan. Hostnames and roots get web + tls on their
    vetted IP (roots also email + dns); an ip gets the database-only network checks. A refused host is never
    contacted and gets no web/tls rows; a refused root still gets email + dns, which only query DNS."""
    now = now or timezone.now()
    obs = {'mail_dns': lambda root: collect.observe_mail_dns(root, resolve=resolve), 'ports': collect.ports_for_ip,
           **(observers or {})}
    done = {'checked': 0, 'failed': 0, 'http_live': False, 'refused': None, 'timeout': False}
    step = _stepper(now, done)
    if asset.kind in ('hostname', 'root_domain'):
        holder = asset if asset.request_headers else None
        if holder is None:
            roots = Asset.objects.filter(project_id=asset.project_id, kind='root_domain', scope_tier='owned_root')
            value = _root_of(asset.value, list(roots.values_list('value', flat=True)))
            holder = roots.filter(value=value).first() if value else None
        step(asset, lambda: _host_checks(asset, holder, now, observers, resolve, done))
    if asset.kind == 'root_domain':
        def root_checks():
            mail, dns_obs = obs['mail_dns'](asset.value)
            return email.evaluate(mail) + dns.evaluate(dns_obs)
        step(asset, root_checks)
    if asset.kind == 'ip':
        step(asset, lambda: network.evaluate(*obs['ports'](asset, now)))
    return done
