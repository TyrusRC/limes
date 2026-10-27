"""Project-scoped subsidiaries: the one place names are validated and membership resolved (REST, MCP and pages call it).
An asset belongs to the subsidiary set on it, else on its nearest ancestor (so a root's hosts follow the root). Scores
come from scoring.group_scores and never feed back into the project's headline."""
from django.db import transaction
from django.utils import timezone

from dashboard.models import Project
from limes import scoring, tags
from startScan.asset_models import Asset, Subsidiary

MAX_PER_PROJECT = 50
NAME_MAX = 60
OWNED = ('owned_root', 'owned_host')
DEPTH = 5  # parent hops followed; assets nest root > host > api, so this is slack


class SubsidiaryError(ValueError):
    """The request is invalid (a 400)."""


class NotFound(LookupError):
    """The subsidiary or an asset id is not in the project (a 404)."""


def clean_name(raw, what='name'):
    if not isinstance(raw, str):
        raise SubsidiaryError(f'{what} must be text')
    name = ' '.join(raw.split())
    if not name or len(name) > NAME_MAX or not name.isprintable():
        raise SubsidiaryError(f'{what} is 1-{NAME_MAX} printable characters')
    return name


def members(project):
    """({subsidiary id: set of asset ids}, set of owned live asset ids). One query for the whole project.
    # NOTE: loads every asset row of the project; fine to tens of thousands, then resolve it in SQL."""
    rows = {i: (p, s, t, st) for i, p, s, t, st in Asset.objects.filter(project=project)
            .values_list('id', 'parent_id', 'subsidiary_id', 'scope_tier', 'state')}
    out = {s: set() for s in Subsidiary.objects.filter(project=project).values_list('id', flat=True)}
    for i in rows:
        j, sub = i, None
        for _ in range(DEPTH):
            p, s, _t, _st = rows[j]
            if s:
                sub = s
                break
            if p not in rows:
                break
            j = p
        if sub in out:
            out[sub].add(i)
    owned = {i for i, (_p, _s, t, st) in rows.items() if t in OWNED and st != 'retired'}
    return out, owned


def scores(project, now=None):
    """[{id, name, assets, assessed, score, grade, raw_score, raw_grade, open}] for every subsidiary, by name. assets
    counts the owned, live assets. A subsidiary with no assessed asset has score None, never 950."""
    subs = list(Subsidiary.objects.filter(project=project).order_by('name'))
    if not subs:
        return []
    mem, owned = members(project)
    rows = scoring.group_scores(project, mem, now or timezone.now())
    return [{'id': s.id, 'name': s.name, 'assets': len(mem[s.id] & owned), **rows[s.id]} for s in subs]


def get(project, name):
    sub = Subsidiary.objects.filter(project=project, name=clean_name(name)).first()
    if not sub:
        raise NotFound('subsidiary not found')
    return sub


def create(project, name):
    name = clean_name(name)
    with transaction.atomic():
        Project.objects.select_for_update().get(pk=project.pk)  # serialises the limit check
        if Subsidiary.objects.filter(project=project, name=name).exists():
            raise SubsidiaryError('that subsidiary already exists')
        if Subsidiary.objects.filter(project=project).count() >= MAX_PER_PROJECT:
            raise SubsidiaryError(f'a project holds at most {MAX_PER_PROJECT} subsidiaries')
        return Subsidiary.objects.create(project=project, name=name)


def delete(project, name):
    """Remove the subsidiary; its assets go back to the organization. Portfolios built on it go with it."""
    get(project, name).delete()


def assign(project, name, asset_ids):
    """Put assets of this project under the subsidiary `name`, or back to the organization when name is None. All or
    nothing: an unknown or foreign asset id changes nothing. Returns the number of assets set."""
    sub = None if name is None else get(project, name)
    try:
        ids = tags._ids(asset_ids)
    except tags.TagError as e:
        raise SubsidiaryError(str(e))
    with transaction.atomic():
        if Asset.objects.filter(project=project, id__in=ids).count() != len(ids):
            raise NotFound('asset not found')
        Asset.objects.filter(project=project, id__in=ids).update(subsidiary=sub)
    from dashboard.stats import invalidate
    invalidate(project.id)
    return len(ids)


def restrict(request, slug, qs, field):
    """Apply the page filters that cut a list by asset to `qs` (field names its asset column: 'id' or 'asset_id'):
    the session's current portfolio, ?subsidiary=<name> (just that entity; an unknown name matches nothing) and
    ?subsidiaries=false (the organization only, subsidiary assets left out). Costs no query when none applies."""
    from limes import portfolios
    q = request.query_params
    name, org_only = q.get('subsidiary'), q.get('subsidiaries') == 'false'
    if not (name or org_only or portfolios.SESSION_KEY in request.session):
        return qs
    project = Project.objects.filter(slug=slug).first()
    if project is None:
        return qs.none()
    scope = portfolios.scope(request, project)
    if scope is not None:
        qs = qs.filter(**{f'{field}__in': scope})
    if name or org_only:
        mem = members(project)[0]
        if name:
            sub = Subsidiary.objects.filter(project=project, name=name).first()
            qs = qs.filter(**{f'{field}__in': mem.get(sub.id, set()) if sub else set()})
        if org_only:
            qs = qs.exclude(**{f'{field}__in': set().union(*mem.values())})
    return qs
