"""Lookalike domains of a project's owned roots: the list, the review decisions and the abuse-report text.
Every value is third-party data and goes out as JSON text; the page renders it with textContent only."""
from datetime import timedelta
from urllib.parse import quote

from django.conf import settings
from django.db.models import F
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import HasPermission
from api.views import _parse_id
from dashboard.stats import invalidate
from limes.definitions import PERM_MODIFY_TARGETS
from limes.lookalike import report
from limes.lookalike.check import with_created
from startScan.models import Lookalike

LIST_LIMIT = 2000
YOUNG = timedelta(days=30)
STATUSES = ('unchecked', 'unregistered', 'registered', 'watching', 'ignored', 'ours', 'reported', 'gone')
DECISIONS = {'watch': 'watching', 'ignore': 'ignored', 'ours': 'ours'}
CREDIT = 'Certificate data: crt.sh · Registration data: RDAP'


def _age_days(created, now):
    try:
        when = parse_datetime(str(created or '')[:40])
    except ValueError:
        return None
    return max((now - when).days, 0) if when is not None and when.tzinfo is not None else None


def _row(r, now):
    rdap, dns, ct = r.rdap or {}, r.dns or {}, r.ct or {}
    return {'id': r.id, 'domain': r.domain, 'unicode': r.unicode, 'idn': r.unicode != r.domain,
            'fuzzers': [str(f)[:40] for f in (r.fuzzers if isinstance(r.fuzzers, list) else [])[:10]], 'source': r.source,
            'registered': r.registered, 'created': rdap.get('created') or None, 'age_days': _age_days(rdap.get('created'), now),
            'registrar': str(rdap.get('registrar') or '')[:200], 'has_mx': r.has_mx, 'cert': bool(ct.get('count')),
            'has_a': bool(dns.get('a')), 'status': r.status, 'first_seen': r.first_seen, 'last_checked': r.last_checked,
            'root': r.root.value}


class LookalikeList(APIView):
    """Lookalikes of one project. Unknown filter values are ignored, not errors."""

    def get(self, request):
        q = request.query_params
        rows = Lookalike.objects.filter(project__slug=q.get('project') or '')
        if q.get('status') in STATUSES:
            rows = rows.filter(status=q['status'])
        if q.get('registered') in ('true', 'false'):
            rows = rows.filter(registered=q['registered'] == 'true')
        if q.get('mx') == 'true':
            rows = rows.filter(has_mx=True)
        now = timezone.now()
        if q.get('young') == 'true':
            rows = with_created(rows).filter(created__gte=now - YOUNG)
        total = rows.count()
        rows = rows.select_related('root').order_by(F('registered').desc(nulls_last=True), '-first_seen', 'id')[:LIST_LIMIT]
        return Response({'results': [_row(r, now) for r in rows],
                         'meta': {'enabled': settings.LOOKALIKE_ENABLED, 'total': total, 'truncated': total > LIST_LIMIT,
                                  'budgets': {'dns_daily': settings.LOOKALIKE_DNS_DAILY_BUDGET,
                                              'rdap_daily': settings.RDAP_DAILY_BUDGET, 'http': settings.LOOKALIKE_HTTP},
                                  'credit': CREDIT}})


def _load(request, *related):
    """The lookalike must belong to the project named in the request: ids alone must not cross projects."""
    data = request.data
    if not hasattr(data, 'get'):
        return None
    project, row_id = data.get('project'), _parse_id(data.get('id'))
    if not isinstance(project, str) or row_id is None:
        return None
    return Lookalike.objects.filter(id=row_id, project__slug=project).select_related(*related).first()


class DecideLookalike(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_MODIFY_TARGETS

    def post(self, request):
        row = _load(request, 'project')
        if not row:
            return Response({'status': False, 'message': 'lookalike not found'})
        decision, note = request.data.get('decision'), request.data.get('note')
        if not isinstance(decision, str) or decision not in DECISIONS:
            return Response({'status': False, 'message': 'decision must be watch, ignore or ours'})
        row.status = DECISIONS[decision]
        row.decided_by, row.decided_at = request.user, timezone.now()
        if isinstance(note, str):
            row.note = note[:1000]
        row.save(update_fields=['status', 'decided_by', 'decided_at', 'note'])
        invalidate(row.project_id)
        out = {'status': True, 'message': row.status}
        if decision == 'ours':  # nothing is created: the user confirms through the manual add flow
            out['add_url'] = reverse('assets', kwargs={'slug': row.project.slug}) + '?add=' + quote(row.domain, safe='')
        return Response(out)


class LookalikeReport(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_MODIFY_TARGETS

    def post(self, request):
        row = _load(request, 'project', 'root')
        if not row:
            return Response({'status': False, 'message': 'lookalike not found'})
        text = report.abuse_report(row, request.user)
        now = timezone.now()
        row.status, row.reported_at, row.decided_by, row.decided_at = 'reported', now, request.user, now
        row.save(update_fields=['status', 'reported_at', 'decided_by', 'decided_at'])
        invalidate(row.project_id)
        return Response({'status': True, **text})
