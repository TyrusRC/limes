"""Portfolios: saved named filters over a project's assets (tags and/or a subsidiary, plus hand-picked assets). Not an
access rule: every project member sees every portfolio. The selection lives in the session and is re-validated against the
project on every read, so a stale or foreign id selects nothing."""
from django.db import transaction

from dashboard.models import Project
from limes import subsidiaries, tags
from limes.subsidiaries import NotFound, SubsidiaryError as PortfolioError, clean_name
from startScan.asset_models import Asset, Portfolio

MAX_PER_PROJECT = 50
SESSION_KEY = 'portfolio'  # {project slug: portfolio id}


def asset_ids(project, portfolio):
    """Ids of the assets in a portfolio of this project: (any rule tag, within the rule subsidiary when set) plus the
    hand-picked ones. A rule-less portfolio holds only its picks."""
    ids = None
    names = portfolio.tags if isinstance(portfolio.tags, list) else []
    if names:
        ids = set(Asset.tags.through.objects.filter(tag__project=project, tag__name__in=names).values_list('asset_id', flat=True))
    if portfolio.subsidiary_id:
        in_sub = subsidiaries.members(project)[0].get(portfolio.subsidiary_id, set())
        ids = in_sub if ids is None else ids & in_sub
    return (ids or set()) | set(portfolio.assets.filter(project=project).values_list('id', flat=True))


def create(project, name, tag_names=None, subsidiary=None, assets=None):
    name = clean_name(name)
    if tag_names is None:
        tag_names = []
    if not isinstance(tag_names, list) or len(tag_names) > tags.MAX_NAMES:
        raise PortfolioError(f'tags must be a list of at most {tags.MAX_NAMES} names')
    try:
        tag_names = sorted({tags.normalise(t) for t in tag_names})
        ids = tags._ids(assets) if assets else []
    except tags.TagError as e:
        raise PortfolioError(str(e))
    sub = subsidiaries.get(project, subsidiary) if subsidiary is not None else None
    if not (tag_names or sub or ids):
        raise PortfolioError('give at least one tag, a subsidiary or some assets')
    with transaction.atomic():
        Project.objects.select_for_update().get(pk=project.pk)
        if Portfolio.objects.filter(project=project, name=name).exists():
            raise PortfolioError('that portfolio already exists')
        if Portfolio.objects.filter(project=project).count() >= MAX_PER_PROJECT:
            raise PortfolioError(f'a project holds at most {MAX_PER_PROJECT} portfolios')
        if Asset.objects.filter(project=project, id__in=ids).count() != len(ids):
            raise NotFound('asset not found')
        p = Portfolio.objects.create(project=project, name=name, tags=tag_names, subsidiary=sub)
        p.assets.set(ids)
    return p


def listing(project):
    return [{'id': p.id, 'name': p.name, 'tags': p.tags, 'subsidiary': p.subsidiary.name if p.subsidiary else None,
             'picked': p.assets.count()} for p in Portfolio.objects.filter(project=project).select_related('subsidiary').order_by('name')]


def get(project, pid):
    p = Portfolio.objects.filter(project=project, id=pid).first() if isinstance(pid, int) and not isinstance(pid, bool) and 0 <= pid < 2 ** 63 else None
    if not p:
        raise NotFound('portfolio not found')
    return p


def select(request, project, pid):
    """Make portfolio `pid` of this project the session's current one, or clear it with None."""
    chosen = request.session.get(SESSION_KEY, {})
    if pid is None:
        chosen.pop(project.slug, None)
    else:
        chosen[project.slug] = get(project, pid).id
    request.session[SESSION_KEY] = chosen


def picked_id(request, project):
    """The portfolio id the session holds for this project (not yet checked against the project), or None."""
    session = getattr(request, 'session', None)
    pid = session.get(SESSION_KEY, {}).get(project.slug) if session is not None else None
    return pid if isinstance(pid, int) and not isinstance(pid, bool) else None


def selected(request, project):
    """The session's current portfolio for this project, or None (also when it no longer exists or is another project's)."""
    pid = picked_id(request, project)
    return Portfolio.objects.filter(project=project, id=pid).first() if pid is not None else None


def scope(request, project):
    """Asset ids the current portfolio limits the request to, or None when no portfolio is selected."""
    p = selected(request, project)
    return None if p is None else asset_ids(project, p)
