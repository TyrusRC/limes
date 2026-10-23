"""Project-scoped asset tags: the one place names are validated and limits enforced (REST and MCP both call it)."""
import re

from django.db import transaction
from django.db.models import Count

from dashboard.models import Project
from startScan.asset_models import Asset, Tag

NAME_RE = re.compile(r'[a-z0-9][a-z0-9._:/-]{0,39}')
MAX_PER_ASSET = 20
MAX_PER_PROJECT = 200
MAX_ASSETS = 200
MAX_NAMES = MAX_PER_ASSET  # per add or remove list


class TagError(ValueError):
    """The request is invalid (a 400)."""


class AssetNotFound(LookupError):
    """An asset id is not in the project (a 404 for the whole call)."""


def normalise(raw):
    if not isinstance(raw, str):
        raise TagError('tag names must be text')
    name = raw.strip().lower()
    if not NAME_RE.fullmatch(name):
        raise TagError('a tag is 1-40 characters: lower-case letters, digits and . _ : / -, starting with a letter or digit')
    return name


def lookup(raw):
    """The normalised name for a filter value, or None when it cannot name a tag (the filter then matches nothing)."""
    try:
        return normalise(raw)
    except TagError:
        return None


def _names(raw, field):
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise TagError(f'{field} must be a list of tag names')
    if len(raw) > MAX_NAMES:
        raise TagError(f'at most {MAX_NAMES} names in {field}')
    return sorted({normalise(n) for n in raw})


def _ids(raw):
    if not isinstance(raw, list) or not raw:
        raise TagError('assets must be a non-empty list of ids')
    if len(raw) > MAX_ASSETS:
        raise TagError(f'at most {MAX_ASSETS} assets per call')
    ids = set()
    for i in raw:
        if isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < 2 ** 63:
            raise TagError('assets must be a list of ids')
        ids.add(i)
    return sorted(ids)


def change_tags(project, asset_ids, add=None, remove=None):
    """Add and remove tag names on assets of this project. All or nothing: any bad name, unknown or foreign asset id or
    limit breach changes nothing. Tags in `add` that do not exist are created; `remove` tags nothing uses any more
    are deleted. Returns {'assets', 'added', 'removed'} (asset/tag pairs actually changed)."""
    ids, add, remove = _ids(asset_ids), _names(add, 'add'), _names(remove, 'remove')
    if not add and not remove:
        raise TagError('give at least one tag in add or remove')
    if set(add) & set(remove):
        raise TagError('a tag cannot be both added and removed')
    Through = Asset.tags.through
    with transaction.atomic():
        Project.objects.select_for_update().get(pk=project.pk)  # serialises the limit checks of concurrent calls
        if Asset.objects.filter(project=project, id__in=ids).count() != len(ids):
            raise AssetNotFound('asset not found')
        tags = dict(Tag.objects.filter(project=project).values_list('name', 'id'))
        # Limits refuse only a call that adds something new: removing must work on data that is already over them.
        # Tags no asset carries do not count (they are invisible and get reused or removed).
        used = set(Tag.objects.filter(project=project).annotate(n=Count('assets')).filter(n__gt=0).values_list('name', flat=True))
        if set(add) - used and len(used | set(add)) > MAX_PER_PROJECT:
            raise TagError(f'a project holds at most {MAX_PER_PROJECT} tags')
        have = {}
        for asset_id, name in Through.objects.filter(asset_id__in=ids).values_list('asset_id', 'tag__name'):
            have.setdefault(asset_id, set()).add(name)
        for asset_id in ids:
            if set(add) - have.get(asset_id, set()) and len((have.get(asset_id, set()) - set(remove)) | set(add)) > MAX_PER_ASSET:
                raise TagError(f'an asset carries at most {MAX_PER_ASSET} tags (asset {asset_id})')
        Tag.objects.bulk_create([Tag(project=project, name=n) for n in add if n not in tags], ignore_conflicts=True)
        tags = dict(Tag.objects.filter(project=project, name__in=add + remove).values_list('name', 'id'))
        pairs = [Through(asset_id=a, tag_id=tags[n]) for a in ids for n in add if n not in have.get(a, ())]
        Through.objects.bulk_create(pairs, ignore_conflicts=True)
        removed = Through.objects.filter(asset_id__in=ids, tag_id__in=[tags[n] for n in remove if n in tags]).delete()[0]
        Tag.objects.filter(project=project, name__in=remove).annotate(n=Count('assets')).filter(n=0).delete()
    from dashboard.stats import invalidate
    invalidate(project.id)
    return {'assets': len(ids), 'added': len(pairs), 'removed': removed}


def tag_counts(project):
    """[{'name', 'assets'}] of the project's tags that some asset carries, most used first."""
    rows = Tag.objects.filter(project=project).annotate(n=Count('assets')).filter(n__gt=0).order_by('-n', 'name')
    return [{'name': t.name, 'assets': t.n} for t in rows]
