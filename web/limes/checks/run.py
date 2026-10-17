"""Run the risk checks for one owned root: collect, evaluate, upsert. Honors the scope guard."""
import logging

from django.db.models import Max, Q
from django.utils import timezone

from limes import scope
from limes.checks import collect, dns, email, network, tls, web
from limes.checks.catalogue import CHECKS
from limes.identity import ScanIdentity
from limes.scoring import _root_of
from startScan.models import Asset, RiskCheck

log = logging.getLogger(__name__)

# NOTE: ceiling of web/tls hosts contacted per run, oldest-checked first. Upgrade path:
# a per-project setting or a rolling cursor if inventories outgrow it.
MAX_HOSTS = 200
OWNED = ('owned_root', 'owned_host')


def _defaults():
    return {'http': collect.observe_http, 'tls': collect.observe_tls,
            'mail_dns': collect.observe_mail_dns, 'ports': collect.ports_for_ip}


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


def run_checks(project, root, now=None, observers=None):
    now = now or timezone.now()
    obs = {**_defaults(), **(observers or {})}
    done = {'checked': 0, 'failed': 0}

    def step(asset, produce):
        try:
            _write(asset, produce(), now)
            done['checked'] += 1
        except Exception:
            log.exception('risk check failed for %s', asset.value)
            done['failed'] += 1

    for a in _web_hosts(project, root, MAX_HOSTS):
        holder = a if a.request_headers else root
        def host_checks(a=a, holder=holder):
            ident = ScanIdentity.for_domain(holder)
            return (web.evaluate(obs['http'](a.value, ident))
                    + tls.evaluate(obs['tls'](a.value), now))
        step(a, host_checks)

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
            step(ip, lambda ip=ip: network.evaluate(obs['ports'](ip, now)))
    return done
