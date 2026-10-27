import re
import logging

from django.db import transaction
from django.db.models import Count, Exists, F, OuterRef, Prefetch, Q
from django.utils import timezone
from django.template.defaultfilters import slugify
from datetime import datetime
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_204_NO_CONTENT, HTTP_202_ACCEPTED
from rest_framework.decorators import action

from dashboard.models import *
from limes.celery import app
from limes.common_func import *
from limes.definitions import ABORTED_TASK
from limes.tasks import *
from limes.utilities import is_safe_path
from scanEngine.models import *
from startScan.models import *
from limes.continuous import start_asm_scan
from limes.event_queue import enqueue
from limes.scan_target import ensure_scan_target
from targetApp.models import *
from api.permissions import *
from api.serializers import *


logger = logging.getLogger(__name__)


class InAppNotificationManagerViewSet(viewsets.ModelViewSet):
	"""
		This class manages the notification model, provided CRUD operation on notif model
		such as read notif, clear all, fetch all notifications etc
	"""
	serializer_class = InAppNotificationSerializer
	pagination_class = None

	def get_queryset(self):
		# we will see later if user based notif is needed
		# return InAppNotification.objects.filter(user=self.request.user)
		project_slug = self.request.query_params.get('project_slug')
		queryset = InAppNotification.objects.all()
		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		return queryset.order_by('-created_at')

	@action(detail=False, methods=['post'])
	def mark_all_read(self, request):
		# marks all notification read
		project_slug = self.request.query_params.get('project_slug')
		queryset = self.get_queryset()

		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		queryset.update(is_read=True)
		return Response(status=HTTP_204_NO_CONTENT)

	@action(detail=True, methods=['post'])
	def mark_read(self, request, pk=None):
		# mark individual notification read when cliked
		notification = self.get_object()
		notification.is_read = True
		notification.save()
		return Response(status=HTTP_204_NO_CONTENT)

	@action(detail=False, methods=['get'])
	def unread_count(self, request):
		# this fetches the count for unread notif mainly for the badge
		project_slug = self.request.query_params.get('project_slug')
		queryset = self.get_queryset()
		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		count = queryset.filter(is_read=False).count()
		return Response({'count': count})

	@action(detail=False, methods=['post'])
	def clear_all(self, request):
		# when clicked on the clear button this must be called to clear all notif
		project_slug = self.request.query_params.get('project_slug')
		queryset = self.get_queryset()
		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		queryset.delete()
		return Response(status=HTTP_204_NO_CONTENT)


class CreateProjectApi(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def get(self, request):
		req = self.request
		project_name = req.query_params.get('name')
		slug = slugify(project_name)
		insert_date = timezone.now()

		try:
			project = Project.objects.create(
				name=project_name,
				slug=slug,
				insert_date =insert_date
			)
			response = {
				'status': True,
				'project_name': project_name
			}
			return Response(response)
		except Exception as e:
			response = {
				'status': False,
				'error': str(e)
			}
			return Response(response, status=HTTP_400_BAD_REQUEST)


class UniversalSearch(APIView):
	"""Top-bar search over one project's assets and issues (limes.search). The project is required; JSON only, the
	page renders every value as text."""

	def get(self, request):
		from limes import search
		q = request.query_params
		project = Project.objects.filter(slug=q.get('project') or '').first()
		if not project:
			return Response({'status': False, 'message': 'project not found'}, status=404)
		query = (q.get('query') or '').strip()
		if not 2 <= len(query) <= 200:
			return Response({'status': False, 'message': 'query must be 2 to 200 characters'}, status=400)
		return Response({'status': True, 'results': search.search(project, query)})


class AddAssets(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS
	MAX_ENTRIES = 5000

	def post(self, request):
		from api.asset_add import add_assets
		data = request.data
		if not isinstance(data, dict):
			return Response({'status': False, 'message': 'expected a JSON object'})
		project = Project.objects.filter(slug=data.get('project')).first()
		if not project:
			return Response({'status': False, 'message': 'unknown project'})
		raw = data.get('entries') or data.get('text') or []
		if isinstance(raw, str):
			raw = [l for l in raw.replace(',', '\n').splitlines() if l.strip()]
		if not isinstance(raw, list):
			return Response({'status': False, 'message': 'entries must be a list or text'})
		if len(raw) > self.MAX_ENTRIES:
			return Response({'status': False, 'message': f'too many entries (max {self.MAX_ENTRIES} per request)'})
		tier = data.get('tier', 'owned_host')
		if tier not in ('owned_root', 'owned_host', 'co_brand'):
			tier = 'owned_host'
		reason = str(data.get('reason') or '')[:5000]
		authorized = None  # not given: leave the flag alone
		if 'active_authorized' in data:
			authorized = data.get('active_authorized') in (True, 'true', 'True', '1', 1, 'on')
		return Response({'status': True, 'message': add_assets(project, raw, tier, reason, request.user, authorized)})


def _load_asset(request):
	"""The asset must belong to the project named in the request: ids alone must not cross projects."""
	if not isinstance(request.data, dict):
		return None
	project = request.data.get('project')
	if not project:
		return None
	try:
		return Asset.objects.filter(id=int(request.data.get('asset_id')), project__slug=project).first()
	except (TypeError, ValueError, OverflowError):
		return None


class ConfirmAsset(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		from dashboard.stats import invalidate
		data = request.data
		asset = _load_asset(request)
		if not asset:
			return Response({'status': False, 'message': 'asset not found'})
		tier = data.get('tier', 'owned_host')
		if tier not in ('owned_root', 'owned_host', 'co_brand'):
			tier = 'owned_host'
		asset.scope_tier = tier
		if tier == 'co_brand' and 'active_authorized' in data:
			asset.active_authorized = data.get('active_authorized') in (True, 'true', 'True', '1', 1, 'on')
		asset.state = 'active'
		asset.added_by = request.user
		asset.decision_reason = str(data.get('reason') or '')[:5000]
		asset.save()
		warning = ensure_scan_target(asset)[1]
		if asset.kind in ('hostname', 'ip', 'root_domain'):
			enqueue(asset, 'manual')
		invalidate(asset.project_id)
		return Response({'status': True, 'message': f'confirmed. {warning}' if warning else 'confirmed'})


class RejectAsset(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		from dashboard.stats import invalidate
		asset = _load_asset(request)
		if not asset:
			return Response({'status': False, 'message': 'asset not found'})
		asset.scope_tier = 'rejected'
		asset.added_by = request.user
		asset.decision_reason = str(request.data.get('reason') or '')[:5000]
		asset.save()
		invalidate(asset.project_id)
		return Response({'status': True, 'message': 'rejected'})


class RescanAsset(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		asset = _load_asset(request)
		if not asset:
			return Response({'status': False, 'message': 'asset not found'})
		ok, message = start_asm_scan(asset, engine_id=request.data.get('engine_id'), initiated_by_id=request.user.id)
		return Response({'status': ok, 'message': message})


class FullScanAsset(APIView):
	"""Run the full scanner run (port scan, crawl, vigil DAST, mantis) on one owned root: it actively tests the real
	target, so it is refused for anything but an owned (or authorised co-brand) root, and while the project has a scan
	running. An id from another project is a 404."""
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		asset = _load_asset(request)
		if not asset:
			return Response({'status': False, 'message': 'asset not found'}, status=404)
		ok, message = start_asm_scan(asset, engine_id=request.data.get('engine_id'),
									 initiated_by_id=request.user.id, mode='full')
		return Response({'status': ok, 'message': message})


class SetAssetCadence(APIView):
	"""How often an owned asset is rediscovered or monitored (limes.continuous, limes.monitor, limes.owned_ranges).
	A cadence set here is explicit: it overrides the monitor's activity rule ('off' stops monitoring)."""
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS
	def post(self, request):
		from limes.continuous import set_cadence
		asset = _load_asset(request)
		if not asset:
			return Response({'status': False, 'message': 'asset not found'})
		ok, message = set_cadence(asset, request.data.get('cadence_tier'))
		return Response({'status': ok, 'message': message})


class AssetScore(APIView):
	"""Project risk score (limes.scoring) with its last 30 daily snapshots."""

	def get(self, request):
		from limes import scoring
		project = Project.objects.filter(slug=request.query_params.get('project') or '').first()
		if not project:
			return Response({'status': False, 'message': 'project not found'}, status=404)
		data = scoring.project_score(project)
		data['history'] = list(project.score_snapshots.order_by('-date')
							   .values('date', 'score', 'grade', 'version')[:30])
		return Response(data)


class AssetTags(APIView):
	"""Add and remove tags on up to 200 assets of one project in one call (limes.tags holds the rules). An asset id from
	another project is a 404 for the whole call; a bad name or a limit breach is a 400. Nothing changes on an error."""
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		from limes import tags
		data = request.data
		if not isinstance(data, dict):
			return Response({'status': False, 'message': 'expected a JSON object'}, status=400)
		project = Project.objects.filter(slug=data['project']).first() if isinstance(data.get('project'), str) else None
		if not project:
			return Response({'status': False, 'message': 'project not found'}, status=404)
		try:
			done = tags.change_tags(project, data.get('assets'), data.get('add'), data.get('remove'))
		except tags.AssetNotFound as e:
			return Response({'status': False, 'message': str(e)}, status=404)
		except tags.TagError as e:
			return Response({'status': False, 'message': str(e)}, status=400)
		return Response({'status': True, 'message': 'tags updated', **done})


class TagList(APIView):
	"""The project's tags with their asset counts."""

	def get(self, request):
		from limes import tags
		project = Project.objects.filter(slug=request.query_params.get('project') or '').first()
		if not project:
			return Response({'status': False, 'message': 'project not found'}, status=404)
		return Response(tags.tag_counts(project))


class TagScores(APIView):
	"""Score, grade and open issues for the project's ten most used tags (limes.scoring.tag_scores)."""

	def get(self, request):
		from limes import scoring
		project = Project.objects.filter(slug=request.query_params.get('project') or '').first()
		if not project:
			return Response({'status': False, 'message': 'project not found'}, status=404)
		return Response(scoring.tag_scores(project))


def _parse_id(value):
	"""A row id from JSON or a query string: an int or a string of digits, within the DB range. Otherwise None."""
	if isinstance(value, str) and value.isascii() and value.isdigit():
		value = int(value)
	if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2 ** 63:
		return None
	return value


def _load_issue(request, data):
	"""The issue must belong to the project named in the request: ids alone must not cross projects."""
	if not hasattr(data, 'get'):
		return None
	project, issue_id = data.get('project'), _parse_id(data.get('issue_id'))
	if not isinstance(project, str) or issue_id is None:
		return None
	return TrackedIssue.objects.filter(id=issue_id, project__slug=project).select_related('asset').first()


def _waiver_json(w):
	return {'kind': w.kind, 'reason': w.reason, 'expires_at': w.expires_at, 'created_by': w.created_by.username if w.created_by else None, 'created_at': w.created_at}


class IssueList(APIView):
	"""Open issues of a project, worst first, with their active waiver and note count."""

	def get(self, request):
		from limes.checks.catalogue import CHECKS, PROVISIONAL
		q = request.query_params
		issues = TrackedIssue.objects.filter(project__slug=q.get('project') or '', status='open').select_related('asset')
		if q.get('severity') in ('1', '2', '3', '4'):
			issues = issues.filter(severity=int(q['severity']))
		if q.get('source') in ('check', 'finding'):
			issues = issues.filter(source=q['source'])
		from limes import scoring, tags
		category = scoring.category_q(q.get('category') or '')
		if category is not None:
			issues = issues.filter(category)
		if q.get('tag'):  # the tag is on the issue's asset; the project filter above already scopes it
			name = tags.lookup(q['tag'])
			issues = issues.filter(asset__tags__name=name) if name else issues.none()
		now = timezone.now()
		kev_only = q.get('kev') == 'true'
		if q.get('waived') in ('true', 'false'):
			ids = IssueWaiver.objects.filter(IssueWaiver.active_q(now)).values('issue_id')
			issues = issues.filter(id__in=ids) if q['waived'] == 'true' else issues.exclude(id__in=ids)
		out = []
		live = IssueWaiver.objects.filter(IssueWaiver.active_q(now))
		live = live.select_related('created_by').order_by('-created_at', '-id')
		# NOTE: loads every waiver an issue ever had, to read the newest one. Waivers are hand-made, so the history
		# per issue stays small; if it grows, filter this to the newest per issue with a Subquery on OuterRef('issue_id').
		latest = IssueWaiver.objects.select_related('created_by').order_by('-created_at', '-id')
		issues = issues.annotate(note_count=Count('notes', distinct=True)).prefetch_related(
			Prefetch('waivers', queryset=live, to_attr='live_waivers'),
			Prefetch('waivers', queryset=latest, to_attr='all_waivers'))
		issues = list(issues.order_by('-severity', 'first_seen', 'id'))
		from limes import exploit
		cves = exploit.issue_cves(issues[0].project_id if issues else None,
								  [(i.asset_id, i.key) for i in issues if i.source == 'finding'])
		marks = exploit.markers(c for found in cves.values() for c in found)
		for i in issues:
			found = cves.get((i.asset_id, i.key), [])
			hit = exploit.summary(found, marks)
			if kev_only and not hit['kev']:
				continue
			w = i.live_waivers[0] if i.live_waivers else None
			# the newest waiver ran out (not revoked, not replaced): the issue counts again, say so
			last = i.all_waivers[0] if i.all_waivers else None
			expired = last if not w and last and not last.revoked_at and last.expires_at and last.expires_at <= now else None
			check = CHECKS.get(i.key) if i.source == 'check' else None
			out.append({'id': i.id, 'asset': i.asset.value, 'key': i.key, 'title': check.title if check else i.key,
						'source': i.source, 'provisional': i.source == 'check' and i.key in PROVISIONAL, 'severity': i.severity, 'first_seen': i.first_seen, 'last_seen': i.last_seen,
						'waiver': _waiver_json(w) if w else None, 'note_count': i.note_count,
						'expired_waiver': _waiver_json(expired) if expired else None,
						'cves': exploit.cve_rows(found, marks),
						'kev': hit['kev'], 'epss': hit['epss']})
		return Response(out)


class WaiveIssue(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		from django.utils.dateparse import parse_datetime
		from limes import waivers
		issue = _load_issue(request, request.data)
		if not issue:
			return Response({'status': False, 'message': 'issue not found'})
		data = request.data
		if not isinstance(data.get('kind'), str) or not isinstance(data.get('reason'), str):
			return Response({'status': False, 'message': 'kind and reason must be text'})
		expires_at = data.get('expires_at')
		if expires_at in (None, ''):
			expires_at = None
		else:
			try:
				expires_at = parse_datetime(expires_at) if isinstance(expires_at, str) else None
			except ValueError:
				expires_at = None
			if expires_at is None:
				return Response({'status': False, 'message': 'expires_at must be an ISO-8601 datetime'})
			if timezone.is_naive(expires_at):
				expires_at = timezone.make_aware(expires_at)
		try:
			w = waivers.create_waiver(issue, data['kind'], data['reason'], request.user, expires_at)
		except waivers.WaiverError as e:
			return Response({'status': False, 'message': str(e)})
		return Response({'status': True, 'message': 'waived', 'waiver': _waiver_json(w)})


class RevokeIssueWaiver(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		from limes import waivers
		issue = _load_issue(request, request.data)
		if not issue:
			return Response({'status': False, 'message': 'issue not found'})
		if not waivers.revoke_waiver(issue, request.user):
			return Response({'status': False, 'message': 'no active waiver'})
		return Response({'status': True, 'message': 'revoked'})


class IssueEvidence(APIView):
	"""The scanner evidence (description, request, response, CVEs) behind one finding issue of the named project."""

	def get(self, request):
		from limes import evidence
		issue = _load_issue(request, request.query_params)
		if not issue:
			return Response({'status': False, 'message': 'issue not found'}, status=404)
		return Response(evidence.issue_evidence(issue))


class IssueNotes(APIView):
	"""Reading notes is login-only; adding one needs PERM_MODIFY_TARGETS (the auditor role holds PERM_MODIFY_SCAN_RESULTS, so that one cannot gate writes)."""

	def get_permissions(self):
		if self.request.method == 'POST':
			self.permission_required = PERM_MODIFY_TARGETS
			return [HasPermission()]
		return super().get_permissions()

	def get(self, request):
		issue = _load_issue(request, request.query_params)
		if not issue:
			return Response({'status': False, 'message': 'issue not found'}, status=404)
		return Response([{'author': n.author.username if n.author else None, 'text': n.text, 'created_at': n.created_at}
						 for n in issue.notes.select_related('author').order_by('created_at', 'id')])

	def post(self, request):
		from limes import waivers
		issue = _load_issue(request, request.data)
		if not issue:
			return Response({'status': False, 'message': 'issue not found'})
		if not isinstance(request.data.get('text'), str):
			return Response({'status': False, 'message': 'text must be text'})
		try:
			waivers.add_note(issue, request.user, request.data['text'])
		except waivers.WaiverError as e:
			return Response({'status': False, 'message': str(e)})
		return Response({'status': True, 'message': 'note added'})


MAX_FORECAST_ISSUES = 500


class ScoreForecast(APIView):
	"""Adjusted score if the chosen issues were fixed."""

	def post(self, request):
		from limes import scoring
		data = request.data if isinstance(request.data, dict) else {}
		project = Project.objects.filter(slug=data.get('project') if isinstance(data.get('project'), str) else '').first()
		if not project:
			return Response({'status': False, 'message': 'project not found'})
		raw = data.get('issues')
		if not isinstance(raw, list):
			return Response({'status': False, 'message': 'issues must be a list of ids'})
		if len(raw) > MAX_FORECAST_ISSUES:
			return Response({'status': False, 'message': f'at most {MAX_FORECAST_ISSUES} issues per forecast'})
		ids = [_parse_id(x) for x in raw]
		if None in ids:
			return Response({'status': False, 'message': 'issues must be a list of ids'})
		return Response({'status': True, **scoring.forecast(project, ids)})


class StopScan(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		req = self.request
		data = req.data
		scan_ids = data.get('scan_ids', [])

		scan_ids = [int(id) for id in scan_ids]

		response = {'status': False}

		def abort_scan(scan):
			response = {}
			logger.info(f'Aborting scan History')
			try:
				logger.info(f"Setting scan {scan} status to ABORTED_TASK")
				task_ids = scan.celery_ids
				scan.scan_status = ABORTED_TASK
				scan.stop_scan_date = timezone.now()
				scan.aborted_by = request.user
				scan.save()
				for task_id in task_ids:
					app.control.revoke(task_id, terminate=True, signal='SIGKILL')

				tasks = (
					ScanActivity.objects
					.filter(scan_of=scan)
					.filter(status=RUNNING_TASK)
					.order_by('-pk')
				)
				for task in tasks:
					task.status = ABORTED_TASK
					task.time = timezone.now()
					task.save()

				create_scan_activity(
					scan.id,
					"Scan aborted",
					ABORTED_TASK
				)
				response['status'] = True
			except Exception as e:
				logger.error(e)
				response = {'status': False, 'message': str(e)}

			return response

		for scan_id in scan_ids:
			try:
				scan = ScanHistory.objects.get(id=scan_id)
				# if scan is already successful or aborted then do nothing
				if scan.scan_status == SUCCESS_TASK or scan.scan_status == ABORTED_TASK:
					continue
				response = abort_scan(scan)
			except Exception as e:
				logger.error(e)
				response = {'status': False, 'message': str(e)}

		return Response(response)


class ScanStatus(APIView):
	def get(self, request):
		req = self.request
		slug = self.request.GET.get('project', None)
		# main tasks
		recently_completed_scans = (
			ScanHistory.objects
			.filter(domain__project__slug=slug)
			.order_by('-start_scan_date')
			.filter(Q(scan_status=0) | Q(scan_status=2) | Q(scan_status=3))[:10]
		)
		current_scans = (
			ScanHistory.objects
			.filter(domain__project__slug=slug)
			.order_by('-start_scan_date')
			.filter(scan_status=1)
		)
		pending_scans = (
			ScanHistory.objects
			.filter(domain__project__slug=slug)
			.filter(scan_status=-1)
		)

		response = {
			'scans': {
				'pending': ScanHistorySerializer(pending_scans, many=True).data,
				'scanning': ScanHistorySerializer(current_scans, many=True).data,
				'completed': ScanHistorySerializer(recently_completed_scans, many=True).data
			}
		}
		return Response(response)


class GetFileContents(APIView):
	def get(self, request, format=None):
		req = self.request
		name = req.query_params.get('name')

		response = {}
		response['status'] = False

		if 'nuclei_config' in req.query_params:
			path = "/root/.config/nuclei/config.yaml"
			if not os.path.exists(path):
				run_command(f'touch {path}')
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'subfinder_config' in req.query_params:
			path = "/root/.config/subfinder/config.yaml"
			if not os.path.exists(path):
				run_command(f'touch {path}')
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'naabu_config' in req.query_params:
			path = "/root/.config/naabu/config.yaml"
			if not os.path.exists(path):
				run_command(f'touch {path}')
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'amass_config' in req.query_params:
			path = "/root/.config/amass.ini"
			if not os.path.exists(path):
				run_command(f'touch {path}')
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'nuclei_template' in req.query_params:
			safe_dir = '/root/nuclei-templates'
			path = f'/root/nuclei-templates/{name}'
			if is_safe_path(safe_dir, path) and os.path.exists(path):
				content = open(path.format(name), "r").read()
				response['status'] = True
				response['content'] = content
			else:
				response['message'] = 'Invalid Path!'
				response['status'] = False
			return Response(response)

		response['message'] = 'Invalid Query Params'
		return Response(response)


class AssetDatatableViewSet(viewsets.ReadOnlyModelViewSet):
	queryset = Asset.objects.none()
	serializer_class = AssetSerializer

	def get_queryset(self):
		params = self.request.query_params
		project = params.get('project')
		if not project:
			return Asset.objects.none()
		qs = (
			Asset.objects.filter(project__slug=project)
			.select_related('parent', 'parent__parent')
			.prefetch_related('technologies', 'ip_addresses', 'tags')
			.annotate(vuln_count=Count('vulnerabilities', distinct=True),
					  has_target=Exists(Domain.objects.filter(project=OuterRef('project'), name=OuterRef('value'))))
		)
		source = params.get('source')
		if source:
			from limes import monitor
			qs = qs.filter(monitor.source_q(source))
		for field in ('kind', 'scope_tier', 'state'):
			value = params.get(field)
			if field == 'scope_tier' and value == 'owned':  # the rows the Overview counts: owned, not retired
				qs = qs.filter(scope_tier__in=('owned_root', 'owned_host')).exclude(state='retired')
			elif value:
				qs = qs.filter(**{field: value})
		tag = params.get('tag')
		if tag:
			from limes import tags
			qs = qs.filter(tags__name=tags.lookup(tag)) if tags.lookup(tag) else qs.none()
		tech = params.get('technology')
		if tech:  # a subquery, so the annotated counts do not fan out over the join
			qs = qs.filter(id__in=Asset.objects.filter(project__slug=project, technologies__name=tech).values('id'))
		if self.action == 'list' and not params.get('show_low'):
			from limes.tasks.attribution import REVIEW
			qs = qs.exclude(scope_tier='candidate', confidence__lt=REVIEW)  # unscored (null) stay visible
		return qs

	def filter_queryset(self, qs):
		search = self.request.GET.get('search[value]', '').strip()
		if search:
			qs = qs.filter(
				Q(value__icontains=search) | Q(page_title__icontains=search) | Q(webserver__icontains=search))
		col = self.request.GET.get('order[0][column]')
		direction = self.request.GET.get('order[0][dir]', 'asc')
		# No checkbox column in A2: DataTables column index -> model field.
		colmap = {'0': 'value', '1': 'kind', '2': 'scope_tier', '3': 'state',
				  '4': 'http_status', '8': 'last_seen', '10': 'confidence', '12': 'last_resolved_at'}
		field = colmap.get(col, 'value')
		if field in ('confidence', 'last_resolved_at'):
			f = F(field)
			return qs.order_by(f.desc(nulls_last=True) if direction == 'desc' else f.asc(nulls_last=True), 'id')
		return qs.order_by(('-' if direction == 'desc' else '') + field, 'id')

	def retrieve(self, request, *args, **kwargs):
		# Risk is computed on retrieve only: scoring every row of a list page would be N+1.
		from limes import scoring
		asset = self.get_object()
		data = self.get_serializer(asset).data
		scored = scoring.scored_assets(asset.project).filter(pk=asset.pk).exists()
		data['risk'] = scoring.asset_breakdown(asset) if scored else None
		from limes.checks.catalogue import CHECKS
		checks = []
		for rc in asset.risk_checks.all():
			c = CHECKS.get(rc.check_id)
			checks.append({'check': rc.check_id, 'title': c.title if c else rc.check_id, 'fix': c.fix if c else '',
						   'status': rc.status, 'severity': rc.severity, 'evidence': rc.evidence,
						   'last_checked': rc.last_checked})
		checks.sort(key=lambda r: (r['status'] != 'fail', -r['severity'], r['check']))
		data['risk_checks'] = checks
		if asset.kind == 'ip':
			from limes import exploit
			data['unverified_cves'] = exploit.unverified(asset)
		if asset.kind == 'root_domain':
			data['breaches'] = list(asset.domainbreach_set.order_by('-published', 'breach_name').annotate(name=F('breach_name'))
									.values('name', 'addresses', 'breach_date', 'published'))
		return Response(data)

	def paginate_queryset(self, queryset, view=None):
		if 'no_page' in self.request.query_params:
			return None
		return self.paginator.paginate_queryset(queryset, self.request, view=self)
