"""Ignore a finding: hide it from the Issues list and its counts, with a reason, reversibly. Ignoring never changes the
score (scoring does not read these columns); to stop an issue counting, waive it."""
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import HasPermission
from api.views import _load_issue
from limes.definitions import PERM_MODIFY_TARGETS

MAX_REASON = 300


class _Base(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_MODIFY_TARGETS

    def load(self, request):
        if not isinstance(request.data, dict):
            return None
        return _load_issue(request, request.data)


class IgnoreIssue(_Base):
    def post(self, request):
        issue = self.load(request)
        if not issue:
            return Response({'status': False, 'message': 'issue not found'}, status=404)
        reason = request.data.get('reason')
        reason = reason.strip() if isinstance(reason, str) else ''
        if issue.source != 'finding':
            return Response({'status': False, 'message': 'only vulnerability findings can be ignored; waive a check instead'}, status=400)
        if not reason or len(reason) > MAX_REASON:
            return Response({'status': False, 'message': f'a reason of 1 to {MAX_REASON} characters is required'}, status=400)
        issue.__class__.objects.filter(pk=issue.pk).update(ignored_at=timezone.now(), ignored_reason=reason, ignored_by=request.user)
        return Response({'status': True, 'message': 'ignored'})


class UnignoreIssue(_Base):
    def post(self, request):
        issue = self.load(request)
        if not issue:
            return Response({'status': False, 'message': 'issue not found'}, status=404)
        issue.__class__.objects.filter(pk=issue.pk).update(ignored_at=None, ignored_reason='', ignored_by=None)
        return Response({'status': True, 'message': 'active again'})
