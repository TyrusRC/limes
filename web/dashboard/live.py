"""The Overview's live feed: new change events and the Real-time card, polled by overview.js. Project-scoped and
read-only; it never builds the cached stats."""
import re

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_GET

from dashboard.models import Project
from dashboard.stats import CHANGE_LABELS
from limes.ct import health
from startScan.models import ChangeEvent

LIVE_LIMIT = 20
SINCE = re.compile(r'\d{1,18}', re.ASCII)
COUNTERS = ('checked', 'cooled', 'overflow', 'burst', 'covered')
MODES = {'real-time': 'Real-time', 'api': 'API polling', 'cadence': 'Cadence only'}


def pill(card):
    """What the state pill says. 'Live' only for a healthy watch with a fresh heartbeat, never when off or degraded."""
    if card['state'] == 'healthy':
        return 'Live'
    if card['state'] == 'degraded':
        return 'Degraded'
    if card['state'] == 'idle':
        return 'Idle'
    return 'API polling' if card['mode'] == 'api' else 'Cadence only'


def realtime(project, now):
    card = health.card(project, now)
    card['queue']['counts'] = {k: int(card['queue']['counts'].get(k, 0)) for k in COUNTERS}
    card['label'] = pill(card)
    card['mode_label'] = MODES.get(card['mode'], card['mode'])
    card['reason_text'] = '; '.join(r['label'] for r in card['reasons'])
    return card


def event_row(e):
    return {'id': e.id, 'kind': e.kind, 'label': CHANGE_LABELS.get(e.kind, e.kind), 'title': e.title,
            'severity': e.severity, 'asset': e.asset.value if e.asset else None, 'created_at': e.created_at.isoformat()}


def newest_id(recent_changes):
    """The id the page already shows up to. Taken from the (cached) list itself, so an event the cache has not seen
    yet is still delivered by the first poll."""
    return max([c.get('id', 0) for c in recent_changes] or [0])


@require_GET
def live(request, slug):
    project = Project.objects.filter(slug=slug).first()
    if project is None:
        return JsonResponse({'error': 'not found'}, status=404)
    since = request.GET.get('since', '0')
    if not SINCE.fullmatch(since):
        return JsonResponse({'error': 'bad since'}, status=400)
    now = timezone.now()
    evs = (ChangeEvent.objects.filter(project=project, id__gt=int(since)).select_related('asset')
           .order_by('id')[:LIVE_LIMIT])
    r = JsonResponse({'events': [event_row(e) for e in evs], 'realtime': realtime(project, now),
                      'poll': settings.LIVE_POLL_SECONDS})
    r['Cache-Control'] = 'no-store'
    return r
