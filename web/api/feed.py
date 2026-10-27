import re

from django.db.models import Q
from rest_framework.response import Response
from rest_framework.views import APIView

from dashboard.models import FeedDismissal, InAppNotification, Project
from startScan.models import Asset, ChangeEvent, IssueWaiver, TrackedIssue

MAX_KEYS = 100
KEY = re.compile(r'^(event|notice|task:waiver|task:issue|task:candidate):([0-9]{1,18})$', re.ASCII)


def _exists(project, kind, pk):
    """Whether the card's source row belongs to this project (a notice may also be system-wide)."""
    if kind == 'event':
        return ChangeEvent.objects.filter(id=pk, project=project).exists()
    if kind == 'notice':
        return InAppNotification.objects.filter(Q(project=project) | Q(project__isnull=True), id=pk).exists()
    if kind == 'task:waiver':
        return IssueWaiver.objects.filter(id=pk, issue__project=project).exists()
    if kind == 'task:issue':
        return TrackedIssue.objects.filter(id=pk, project=project).exists()
    return Asset.objects.filter(id=pk, project=project).exists()


class DismissFeedItems(APIView):
    """Hide Home-feed cards for the calling user only, so any logged-in user may do it. A card that is not this project's
    fails the whole call with 404 and nothing is stored; a malformed key list is a 400."""

    def post(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        project = Project.objects.filter(slug=data['project']).first() if isinstance(data.get('project'), str) else None
        if not project:
            return Response({'status': False, 'message': 'project not found'}, status=404)
        keys = data.get('keys')
        if not isinstance(keys, list) or not 0 < len(keys) <= MAX_KEYS:
            return Response({'status': False, 'message': f'keys must be a list of 1 to {MAX_KEYS} card keys'}, status=400)
        parsed = []
        for key in keys:
            m = KEY.match(key) if isinstance(key, str) else None
            if not m:
                return Response({'status': False, 'message': 'unknown card key'}, status=400)
            parsed.append((key, m.group(1), int(m.group(2))))
        for key, kind, pk in parsed:
            if not _exists(project, kind, pk):
                return Response({'status': False, 'message': 'card not found'}, status=404)
        for key, _, _ in parsed:
            FeedDismissal.objects.get_or_create(user=request.user, project=project, item=key)
        return Response({'status': True, 'message': 'dismissed', 'dismissed': len(parsed)})
