"""Read tools: projects, summary, assets and the review queue. Text that came from scans or targets goes out only
through results.untrusted()."""
from typing import Annotated, Literal
from django.db.models import Count, Exists, F, OuterRef, Q
from django.utils import timezone
from pydantic import Field
from limes import monitor, scoring
from limes.mcp import access, results
from limes.mcp.access import McpError
from limes.mcp.registry import tool
from limes.mcp.results import Cursor, Limit, RowId, Slug, iso, page, untrusted
from limes.tasks.attribution import REVIEW
from dashboard import stats
from startScan.asset_models import ASSET_KINDS, ASSET_STATES, SCOPE_TIERS, Asset, IssueWaiver, TrackedIssue
from limes.checks.catalogue import CHECKS

KINDS = tuple(k for k, _ in ASSET_KINDS)
TIERS = tuple(k for k, _ in SCOPE_TIERS) + ('owned',)
STATES = tuple(k for k, _ in ASSET_STATES)
SOURCES = ('manual', 'scan', 'CT', 'InternetDB', 'CIDR', 'ASN', 'attribution', 'target')
PARENT_DEPTH = 5
ISSUE_CAP = 50


def asset_item(a):
    return {'id': a.id, 'kind': a.kind, 'value': untrusted(a.value), 'scope_tier': a.scope_tier, 'state': a.state,
            'cadence_tier': a.cadence_tier, 'first_seen': iso(a.first_seen), 'last_seen': iso(a.last_seen),
            'last_resolved_at': iso(a.last_resolved_at), 'http_status': a.http_status,
            'page_title': untrusted(a.page_title), 'found_by': monitor.found_by(a), 'parent_id': a.parent_id}


def issue_title(source, key):
    check = CHECKS.get(key) if source == 'check' else None
    return check.title if check else untrusted(key)


def waived_exists(now):
    return Exists(IssueWaiver.objects.filter(IssueWaiver.active_q(now), issue=OuterRef('pk')))



@tool(title='List projects')
def list_projects(caller, cursor: Cursor = None, limit: Limit = 50):
    """List the projects you can read (slug, name, creation time), ordered by slug."""
    return page(access.visible_projects(caller).order_by('slug'), cursor, limit, lambda p: {
        'slug': p.slug, 'name': untrusted(p.name), 'insert_date': iso(p.insert_date)})


def _counts(qs, field):
    return {r[field]: r['n'] for r in qs.values(field).annotate(n=Count('id')).order_by(field)}


@tool(title='Project summary')
def get_project_summary(caller, project: Slug):
    """The project's score and grade, asset counts, open issue counts by severity and monitoring state: the numbers the Overview shows."""
    p = access.project_for(caller, project)
    now = timezone.now()
    score = scoring.project_score(p, now)
    assets = Asset.objects.filter(project=p)
    monitoring = stats._monitoring(p, now)
    return {
        'project_score': {k: score[k] for k in ('version', 'score', 'grade', 'raw_score', 'raw_grade', 'waived_count',
                                                'coverage', 'check_coverage', 'asset_count', 'unassessed')},
        'assets_by_kind': _counts(assets, 'kind'),
        'assets_by_state': _counts(assets, 'state'),
        'owned_by_state': stats._inventory(p)['states'],
        'severity_counts': stats._findings(stats._live_issues(p)),
        'monitoring': {
            'enabled': monitoring['enabled'], 'running': monitoring['running'],
            'next_due': [{'value': untrusted(r['value']), 'cadence_tier': r['cadence_tier']}
                         for r in monitoring['next_due']],
            'last_auto': iso(monitoring['last_auto']), 'last_scan': iso(monitoring['last_scan'])},
    }


@tool(title='List assets')
def list_assets(caller, project: Slug, kind: Literal[KINDS] | None = None, scope_tier: Literal[TIERS] | None = None,
                state: Literal[STATES] | None = None, source: Literal[SOURCES] | None = None,
                text: Annotated[str, Field(max_length=200)] | None = None, cursor: Cursor = None, limit: Limit = 50):
    """List the project's assets, ordered by value. scope_tier 'owned' means owned and not retired, as on the Assets page. Candidates below the review threshold are left out, as there. text matches the asset value."""
    p = access.project_for(caller, project)
    qs = Asset.objects.filter(project=p).exclude(scope_tier='candidate', confidence__lt=REVIEW)
    if kind:
        qs = qs.filter(kind=kind)
    if scope_tier == 'owned':
        qs = qs.filter(scope_tier__in=monitor.OWNED).exclude(state='retired')
    elif scope_tier:
        qs = qs.filter(scope_tier=scope_tier)
    if state:
        qs = qs.filter(state=state)
    if source:
        qs = qs.filter(monitor.source_q(source))
    if text:
        qs = qs.filter(value__icontains=text)
    return page(qs.order_by('value', 'id'), cursor, limit, asset_item)


def _parent_chain(asset):
    chain, node = [], asset.parent
    while node is not None and len(chain) < PARENT_DEPTH:
        chain.append({'id': node.id, 'kind': node.kind, 'value': untrusted(node.value)})
        node = node.parent
    return chain


def _risk(asset):
    if not scoring.scored_assets(asset.project).filter(pk=asset.pk).exists():
        return None
    out = scoring.asset_breakdown(asset)
    out['penalties'] = [{**r, 'asset': untrusted(r['asset']), 'issue': untrusted(r['issue'])}
                        for r in out['penalties']]
    return out


def _asset_issues(asset, now):
    rows = list(TrackedIssue.objects.filter(asset=asset, status='open').annotate(waived=waived_exists(now))
                .order_by('-severity', 'id')[:ISSUE_CAP + 1])
    return [{'id': i.id, 'key': untrusted(i.key), 'title': issue_title(i.source, i.key), 'source': i.source,
             'severity': i.severity, 'waived': i.waived} for i in rows[:ISSUE_CAP]], len(rows) > ISSUE_CAP


@tool(title='Asset detail')
def get_asset(caller, project: Slug, asset_id: RowId):
    """One asset with its parents, sources, tracking state, technologies, addresses, open issues and risk breakdown."""
    p = access.project_for(caller, project)
    a = (Asset.objects.filter(project=p, pk=asset_id).select_related('parent__parent', 'added_by')
         .prefetch_related('technologies', 'ip_addresses').first())
    if a is None:
        raise McpError('not_found', 'asset not found')
    tracking = monitor.monitor_state(a)
    tracking['reason'] = untrusted(tracking['reason'])
    tracking['cadence_tier'] = a.cadence_tier
    tracking['cadence_explicit'] = bool((a.enrichment or {}).get('cadence_explicit'))
    issues, truncated = _asset_issues(a, timezone.now())
    return {
        **asset_item(a),
        'webserver': untrusted(a.webserver), 'cname': untrusted(a.cname), 'is_cdn': a.is_cdn,
        'cdn_name': untrusted(a.cdn_name), 'confidence': a.confidence,
        'decision_reason': untrusted(a.decision_reason or None),
        'added_by': a.added_by.username if a.added_by else None, 'missed_count': a.missed_count,
        'parent_chain': _parent_chain(a),
        'sources': [{'source': results.clean(str(s.get('source')), 60), 'evidence': untrusted(s.get('evidence')),
                     'seen_at': s.get('seen_at')} for s in a.sources or [] if isinstance(s, dict)],
        'tracking': tracking,
        'ip_addresses': [ip.address for ip in a.ip_addresses.all()],
        'technologies': [untrusted(t.name) for t in a.technologies.all()],
        'issues': issues, 'issues_truncated': truncated,
        'risk': _risk(a),
    }


@tool(title='Review queue')
def list_review_queue(caller, project: Slug, cursor: Cursor = None, limit: Limit = 50):
    """Discovered candidate assets awaiting a decision, most likely ours first (unscored last)."""
    p = access.project_for(caller, project)
    qs = (Asset.objects.filter(project=p, scope_tier='candidate').filter(Q(confidence__isnull=True) | Q(confidence__gte=REVIEW))
          .order_by(F('confidence').desc(nulls_last=True), 'value', 'id'))
    return page(qs, cursor, limit, lambda a: {
        'id': a.id, 'kind': a.kind, 'value': untrusted(a.value), 'confidence': a.confidence,
        'would_auto_confirm': bool((a.confidence_detail or {}).get('would_auto_confirm')),
        'first_seen': iso(a.first_seen), 'found_by': monitor.found_by(a)})
