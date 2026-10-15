"""Ownership attribution (A3c): evidence collection, scoring and decisions for candidates.

DNS lookups go to resolvers only, never to a target.
"""
import logging
import os
import re
from collections import defaultdict
from datetime import timedelta

from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone

from limes import commands
from limes.intel import domains
from limes.pipeline import dnsx
from limes.tasks import inventory
from startScan.models import Asset, AssetFact

logger = logging.getLogger(__name__)

MAX_DNS_CANDIDATES = 2000  # NOTE: ceiling per run; oldest candidates first; upgrade path: rotate by last check
NS_MX_TIMEOUT = 10 * 60


def _drop_ns(asset_ids):
    AssetFact.objects.filter(asset_id__in=list(asset_ids), kind='ns').delete()


def collect_dns(project, results_dir, run=commands.run):
    """NS/MX/A for candidate root domains. NS facts are kept only when the zone resolved (a working
    delegation); each answered host's NS/MX facts are replaced by the latest answer."""
    cands = dict(Asset.objects.filter(project=project, kind='root_domain', scope_tier='candidate')
                 .order_by('id').values_list('value', 'id')[:MAX_DNS_CANDIDATES])
    if not cands:
        return {'dns_checked': 0}
    hosts_file = os.path.join(results_dir, 'attribution_hosts.txt')
    out_file = os.path.join(results_dir, 'attribution_dnsx.jsonl')
    try:
        if os.path.exists(out_file):
            os.remove(out_file)
        with open(hosts_file, 'w') as f:
            f.write('\n'.join(cands) + '\n')
        res = run(dnsx.build_ns_mx_argv(hosts_file, out_file), timeout=NS_MX_TIMEOUT)
        if res is None or res.return_code != 0:
            logger.warning(f'dnsx (ns/mx) exited with {getattr(res, "return_code", None)}')
        if not os.path.isfile(out_file):
            _drop_ns(cands.values())
            return {'dns_checked': 0}
        with open(out_file) as f:
            records = dnsx.parse_ns_mx(f)
        checked = 0
        for name, rec in records.items():
            asset_id = cands.get(name)
            if asset_id is None:
                continue
            asset = Asset.objects.get(pk=asset_id)
            ns = rec['ns'] if rec['a'] else []  # lame delegation proves nothing
            AssetFact.objects.filter(asset=asset, kind='ns').exclude(value__in=ns).delete()
            AssetFact.objects.filter(asset=asset, kind='mx').exclude(value__in=rec['mx']).delete()
            for h in ns:
                inventory.record_fact(asset, 'ns', h, 'dns')
            for h in rec['mx']:
                inventory.record_fact(asset, 'mx', h, 'dns')
            for ip in rec['a']:
                inventory.record_fact(asset, 'ip', ip, 'dns')
            checked += 1
        # dnsx -silent omits unanswered hosts: their old delegation proves nothing any more
        _drop_ns([i for n, i in cands.items() if n not in records])
        return {'dns_checked': checked}
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        logger.exception('Attribution DNS collection failed')
        _drop_ns(cands.values())  # fail closed: stale NS must not count as control
        return {'dns_checked': 0}


VERSION = 'attribution-v1'
WEIGHTS = {'ns_control': 0.95, 'mx': 0.60, 'ip': 0.60, 'cert': 0.50, 'brand': 0.30}
HOP2_FACTOR = 0.5
AUTO_CONFIRM = 0.90
REVIEW = 0.40
MIN_BRAND_LEN = 4  # NOTE: shorter keywords would match everything
OWNED = ('owned_root', 'owned_host')
NS_FRESH = timedelta(hours=24)  # NS control must come from a delegation seen this recently


def _under_root(host, roots):
    return next((r for r in roots if host == r or host.endswith('.' + r)), None)


def brand_tokens(value):
    """Whole label tokens of a name, excluding its public suffix (labels split on '.' and '-')."""
    reg = domains.registrable(value)
    head = value
    if reg and '.' in reg:
        suffix = reg.split('.', 1)[1]
        if value.endswith('.' + suffix):
            head = value[:-(len(suffix) + 1)]
    return {t for t in re.split(r'[.\-]', head) if t}


def _combine(contribs):
    p = 1.0
    for c in contribs:
        p *= 1 - c['weight']
    return 1 - p


def _hop1(asset, facts, roots, owned_ips, owned_certs, keywords):
    out, seen = [], set()

    def add(kind, value, via, weight, control=False, corroborates=False):
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append({'kind': kind, 'value': value, 'via': via, 'weight': weight, 'hop': 1,
                        'control': control, 'corroborates': corroborates})

    ns = sorted(v for k, v, _ in facts if k == 'ns')
    if ns and all(_under_root(h, roots) for h in ns):
        add('ns', ', '.join(ns), _under_root(ns[0], roots), WEIGHTS['ns_control'], control=True)
    for kind, value, _ in facts:
        if kind == 'mx' and _under_root(value, roots):
            add('mx', value, _under_root(value, roots), WEIGHTS['mx'])
        elif kind == 'ip' and value in owned_ips:
            # never corroborates: InternetDB hostnames include any domain whose A record points here
            add('ip', value, value, WEIGHTS['ip'])
        elif kind == 'cert' and value in owned_certs:
            add('cert', value, owned_certs[value], WEIGHTS['cert'], corroborates=True)
    tokens = brand_tokens(asset.value)
    for kw in keywords:
        if kw in tokens:
            add('brand', kw, 'brand keyword', WEIGHTS['brand'])
            break
    return out


def score_project(project):
    """Score every candidate of the project (set-based: a fixed number of queries per project)."""
    cands = list(Asset.objects.filter(project=project, scope_tier='candidate'))
    if not cands:
        return {'scored': 0}
    roots = inventory.owned_root_values(project)
    owned_ips = set(Asset.objects.filter(project=project, kind='ip', scope_tier__in=OWNED)
                    .values_list('value', flat=True))
    owned_certs = dict(AssetFact.objects.filter(asset__project=project, asset__scope_tier__in=OWNED, kind='cert')
                       .values_list('value', 'asset__value'))
    keywords = [k.lower() for k in (project.brand_keywords or []) if isinstance(k, str) and len(k) >= MIN_BRAND_LEN]
    facts = defaultdict(list)
    for aid, kind, value, source in (AssetFact.objects.filter(asset__in=cands)
                                     .values_list('asset_id', 'kind', 'value', 'source')):
        facts[aid].append((kind, value, source))
    hop1 = {c.id: _hop1(c, facts[c.id], roots, owned_ips, owned_certs, keywords) for c in cands}
    value_of = {c.id: c.value for c in cands}
    sharing = defaultdict(set)  # (kind, value) -> candidate ids, for hop 2
    for aid, fl in facts.items():
        for kind, value, _ in fl:
            if kind in ('cert', 'ip'):
                sharing[(kind, value)].add(aid)
    hop1_score = {cid: _combine(contribs) for cid, contribs in hop1.items()}
    for c in cands:
        contribs = list(hop1[c.id])
        seen = {(x['kind'], x['value']) for x in contribs}
        for kind, value, _ in facts[c.id]:
            if kind not in ('cert', 'ip') or (kind, value) in seen:
                continue
            via = sorted(o for o in sharing[(kind, value)] if o != c.id and hop1_score[o] >= REVIEW)
            if via:
                seen.add((kind, value))
                contribs.append({'kind': kind, 'value': value, 'via': value_of[via[0]],
                                 'weight': WEIGHTS[kind] * HOP2_FACTOR, 'hop': 2,
                                 'control': False, 'corroborates': False})
        score = round(_combine(contribs), 4)
        c.confidence = score
        c.confidence_detail = {'version': VERSION, 'score': score, 'contributions': contribs}
    # a human decision may have landed since load: never score a candidate that is no longer one
    still = set(Asset.objects.filter(pk__in=[c.pk for c in cands], scope_tier='candidate')
                .values_list('pk', flat=True))
    cands = [c for c in cands if c.pk in still]
    Asset.objects.bulk_update(cands, ['confidence', 'confidence_detail'], batch_size=500)
    return {'scored': len(cands)}


def apply_decisions(project):
    """Auto-confirm only score >= AUTO_CONFIRM with hop-1 NS control AND hop-1 corroboration, and only
    from NS facts seen within NS_FRESH. The conditional update means a concurrent human decision wins.
    With settings.ATTRIBUTION_AUTO_CONFIRM off (the default) no tier changes: qualifying candidates are
    only flagged 'would_auto_confirm' for a human to review."""
    from dashboard.stats import invalidate
    auto = would = 0
    fresh_after = timezone.now() - NS_FRESH
    # hostname candidates never get NS facts today, so they never qualify
    for a in Asset.objects.filter(project=project, scope_tier='candidate', kind__in=('root_domain', 'hostname'),
                                  confidence__gte=AUTO_CONFIRM):
        contribs = (a.confidence_detail or {}).get('contributions') or []
        control = next((c for c in contribs if c.get('hop') == 1 and c.get('control')), None)
        if not control or not any(c.get('hop') == 1 and c.get('corroborates') for c in contribs):
            continue
        # re-derive control from current facts: scoring may predate a dropped or replaced delegation
        ns_now = AssetFact.objects.filter(asset=a, kind='ns')
        if (not ns_now.exists() or ns_now.filter(last_seen__lt=fresh_after).exists()
                or ', '.join(sorted(ns_now.values_list('value', flat=True))) != control['value']):
            continue
        if not settings.ATTRIBUTION_AUTO_CONFIRM:
            would += Asset.objects.filter(pk=a.pk, scope_tier='candidate').update(
                confidence_detail={**a.confidence_detail, 'would_auto_confirm': True})
            continue
        reason = (f'auto-confirmed ({VERSION}) {a.confidence:.2f}: NS {control["value"]} '
                  f'under owned root {control["via"]}')
        # append to the sources as stored now, so provenance added concurrently is not overwritten
        a.sources = Asset.objects.filter(pk=a.pk).values_list('sources', flat=True).first() or []
        inventory._append_source(a, 'attribution', reason)
        tier = 'owned_root' if a.kind == 'root_domain' else 'owned_host'
        auto += Asset.objects.filter(pk=a.pk, scope_tier='candidate').update(
            scope_tier=tier, decision_reason=reason, sources=a.sources, added_by=None)
    if auto:
        invalidate(project.id)
    return {'auto_confirmed': auto, 'would_auto_confirm': would}
