from datetime import timedelta

from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from dashboard import activity
from dashboard.models import Project

RANGES = {'30': 30, '90': 90, '365': 365}  # the Overview toggle: 1, 3 and 12 months


class ScoreHistory(APIView):
    """Score series and the what-changed summary for one range of one project (read-only, login only)."""

    def get(self, request):
        from limes import scoring
        from startScan.models import ScoreSnapshot
        project = Project.objects.filter(slug=request.query_params.get('project') or '').first()
        if not project:
            return Response({'status': False, 'message': 'project not found'}, status=404)
        days = RANGES.get(request.query_params.get('days', '30'))
        if days is None:
            return Response({'status': False, 'message': 'days must be 30, 90 or 365'}, status=400)
        now = timezone.now()
        live = scoring.project_score(project, now)
        today = timezone.localdate()
        snaps = (ScoreSnapshot.objects.filter(project=project, date__gte=today - timedelta(days=days), date__lt=today)
                 .order_by('date').values('date', 'score', 'version'))
        series = [{'date': s['date'].isoformat(), 'score': s['score'], 'version': s['version']} for s in snaps]
        if live['score'] is not None:  # today's point is the live score, as on the Overview
            series.append({'date': today.isoformat(), 'score': live['score'], 'version': live['version']})
        change = activity.window(project, now, live['score'], days)
        change['score_from_date'] = change['score_from_date'].isoformat() if change['score_from_date'] else None
        return Response({'status': True, 'days': days, 'series': series, 'change': change, 'max_score': scoring.MAX_SCORE})
