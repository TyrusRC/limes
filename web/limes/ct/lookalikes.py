"""Optional hook onto the lookalike-domain watchlist (project 3). Inert while no `Lookalike` model exists.
This module never creates rows, records events or enqueues checks; the lookalike tick owns that. A lookalike is
someone else's domain: it is only read here, never contacted and never added to the inventory."""
import functools

from django.apps import apps
from django.db import transaction

WATCH_STATUSES = ('registered', 'watching', 'reported')
_FIELDS = {'project', 'domain', 'status', 'ct'}


@functools.lru_cache(maxsize=None)
def model():
    for m in apps.get_models():
        if m.__name__ == 'Lookalike' and _FIELDS <= {f.name for f in m._meta.concrete_fields}:
            return m
    return None


def _ascii(domain):
    d = (domain or '').strip().rstrip('.').lower()
    try:
        return d.encode('idna').decode('ascii')
    except UnicodeError:
        return None


def watched():
    """[(project_id, ascii domain)] for the lookalikes being watched."""
    m = model()
    if m is None:
        return []
    out = []
    for pid, dom in m.objects.filter(status__in=WATCH_STATUSES).values_list('project_id', 'domain'):
        d = _ascii(dom)
        if d:
            out.append((pid, d))
    return out


def record_sighting(project_id, domain, now):
    """Count one certificate sighting on the existing row. False when there is no model or no such row."""
    m = model()
    if m is None:
        return False
    with transaction.atomic():
        ascii_form = _ascii(domain)
        if ascii_form is None:
            return False
        try:
            unicode_form = ascii_form.encode('ascii').decode('idna')
        except UnicodeError:
            unicode_form = ascii_form
        row = (m.objects.select_for_update()  # the row may store either form
               .filter(project_id=project_id, domain__in={domain, ascii_form, unicode_form}).first())
        if row is None:
            return False
        ct = row.ct if isinstance(row.ct, dict) else {}
        n = ct.get('count')
        row.ct = {'count': (n if isinstance(n, int) else 0) + 1, 'first_seen': ct.get('first_seen') or now.isoformat(),
                  'last_seen': now.isoformat()}
        row.save(update_fields=['ct'])
    return True
