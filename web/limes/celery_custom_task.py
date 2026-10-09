import json

from celery import Task
from celery.utils.log import get_task_logger
from celery.worker.request import Request
from django.utils import timezone
from redis import Redis
from limes.db_ops import append_celery_id, notifications_enabled
from limes.common_func import (fmt_traceback, get_output_file_name,
								 get_task_cache_key, get_traceback_path)
from limes.definitions import *
from limes.settings import *
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, SubScan

logger = get_task_logger(__name__)

cache = None
if 'CELERY_BROKER' in os.environ:
	cache = Redis.from_url(os.environ['CELERY_BROKER'])


class LimesRequest(Request):
	success_msg = ''
	retry_msg = ''


class LimesTask(Task):
	"""A Celery task that is tracked by Limes. Save task output files and
	tracebacks to LIMES_RESULTS.

	The custom task meta-options are toggleable through environment variables:

	LIMES_RECORD_ENABLED:
	- Create / update ScanActivity object to track statuses.
	- Send notifications before and after each task (start / end).
	- Send traceback file to Limes's Discord channel if an exception happened.

	LIMES_CACHE_ENABLED:
	- Get result from cache if it exists.
	- Set result to cache after a task if no exceptions occured.

	LIMES_RAISE_ON_ERROR:
	- Raise the actual exception when task fails instead of just logging it.
	"""
	Request = LimesRequest

	@property
	def status_str(self):
		return CELERY_TASK_STATUS_MAP.get(self.status)

	def __call__(self, *args, **kwargs):
		self.result = None
		self.error = None
		self.traceback = None
		self.output_path = None
		self.status = RUNNING_TASK

		# Get task info
		self.task_name = self.name.split('.')[-1]
		self.description = kwargs.get('description') or ' '.join(self.task_name.split('_')).capitalize()
		logger = get_task_logger(self.task_name)

		# Get Limes context
		ctx = kwargs.get('ctx', {})
		self.track = ctx.pop('track', True)
		self.scan_id = ctx.get('scan_history_id')
		self.subscan_id = ctx.get('subscan_id')
		self.engine_id = ctx.get('engine_id')
		self.filename = ctx.get('filename')
		self.starting_point_path = ctx.get('starting_point_path', '')
		self.excluded_paths = ctx.get('excluded_paths', [])
		self.results_dir = ctx.get('results_dir', LIMES_RESULTS)
		self.yaml_configuration = ctx.get('yaml_configuration', {})
		self.out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
		self.history_file = f'{self.results_dir}/commands.txt'
		self.scan = ScanHistory.objects.filter(pk=self.scan_id).first()
		self.subscan = SubScan.objects.filter(pk=self.subscan_id).first()
		self.engine = EngineType.objects.filter(pk=self.engine_id).first()
		self.domain = self.scan.domain if self.scan else None
		self.domain_id = self.domain.id if self.domain else None
		self.subdomain = self.subscan.subdomain if self.subscan else None
		self.subdomain_id = self.subdomain.id if self.subdomain else None
		self.activity_id = None

		# Set file self.task_name if not already set
		if not self.filename:
			self.filename = get_output_file_name(
				self.scan_id,
				self.subscan_id,
				f'{self.task_name}.txt')
			if self.task_name == 'screenshot':
				self.filename = 'Requests.csv'
		self.output_path = f'{self.results_dir}/{self.filename}'

		if LIMES_RECORD_ENABLED:
			if self.engine: # task not in engine.tasks, skip it.
				# Map helper sub-tasks to the engine task that owns them, so they
				# are not skipped when only the parent is listed in engine.tasks.
				# (The old DAST sub-tasks now run inside vulnerability_scan/assay.)
				dependent_tasks = {}
				if self.track and self.task_name not in self.engine.tasks and dependent_tasks.get(self.task_name) not in self.engine.tasks:
					logger.debug(f'Task {self.name} is not part of engine "{self.engine.engine_name}" tasks. Skipping.')
					return

			# Create ScanActivity for this task and send start scan notifs
			if self.track:
				logger.warning(f'Task {self.task_name} is RUNNING')
				self.create_scan_activity()

		try:
			self._scan_job = self.create_scan_job(ctx)
		except Exception:
			# Bookkeeping must never fail the real stage.
			logger.exception('ScanJob create failed')
			self._scan_job = None

		if LIMES_CACHE_ENABLED:
			# Check for result in cache and return it if it's a hit
			record_key = get_task_cache_key(self.name, *args, **kwargs)
			result = cache.get(record_key)
			if result and result != b'null':
				self.status = SUCCESS_TASK
				if LIMES_RECORD_ENABLED and self.track:
					logger.warning(f'Task {self.task_name} status is SUCCESS (CACHED)')
					self.update_scan_activity()
				self.finish_scan_job()
				return json.loads(result)

		# Execute task, catch exceptions and update ScanActivity object after
		# task has finished running.
		try:
			self.result = self.run(*args, **kwargs)
			self.status = SUCCESS_TASK

		except Exception as exc:
			self.status = FAILED_TASK
			self.error = repr(exc)
			self.traceback = fmt_traceback(exc)
			self.result = self.traceback
			self.output_path = get_traceback_path(
				self.task_name,
				self.results_dir,
				self.scan_id,
				self.subscan_id)
			os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

			if LIMES_RAISE_ON_ERROR:
				raise exc

			logger.exception(exc)

		finally:
			self.finish_scan_job()
			self.write_results()

			if LIMES_RECORD_ENABLED and self.track:
				msg = f'Task {self.task_name} status is {self.status_str}'
				msg += f' | Error: {self.error}' if self.error else ''
				logger.warning(msg)
				self.update_scan_activity()

		# Set task result in cache if task was successful
		if LIMES_CACHE_ENABLED and self.status == SUCCESS_TASK and result:
			cache.set(record_key, json.dumps(result))
			cache.expire(record_key, 600) # 10mn cache

		return self.result

	def create_scan_job(self, ctx):
		# Lazy imports: avoid import cycles with the asset models / inventory.
		from limes.tasks.inventory import STAGE_BY_TASK
		run_id = ctx.get('scan_run_id')
		stage = STAGE_BY_TASK.get(self.name)
		if not (run_id and stage):
			return None
		from startScan.asset_models import ScanJob, ScanRun
		run = ScanRun.objects.filter(pk=run_id).first()
		if not run:
			return None
		return ScanJob.objects.create(
			run=run, asset=run.root_asset, stage=stage,
			started=timezone.now(), celery_id=self.request.id)

	def finish_scan_job(self):
		job = getattr(self, '_scan_job', None)
		if not job:
			return
		try:
			job.finished = timezone.now()
			job.status = self.status
			job.output_path = (self.output_path or '')[:300] or None
			job.error_message = (self.error or '')[:300] or None
			job.save()
		except Exception:
			logger.exception('ScanJob finish failed')

	def write_results(self):
		if not self.result:
			return False
		is_json_results = isinstance(self.result, dict) or isinstance(self.result, list)
		if not self.output_path:
			return False
		with open(self.output_path, 'w') as f:
			if is_json_results:
				json.dump(self.result, f, indent=4)
			else:
				f.write(str(self.result))
		logger.warning(f'Wrote {self.task_name} results to {self.output_path}')

	def create_scan_activity(self):
		if not self.track:
			return
		celery_id = self.request.id
		self.activity = ScanActivity.objects.create(
			name=self.task_name,
			title=self.description,
			time=timezone.now(),
			status=RUNNING_TASK,
			celery_id=celery_id,
			scan_of=self.scan)
		self.activity_id = self.activity.id
		if self.scan:
			append_celery_id(ScanHistory, self.scan.pk, celery_id)
		if self.subscan:
			append_celery_id(SubScan, self.subscan.pk, celery_id)

		# Send notification
		self.notify()

	def update_scan_activity(self):
		if not self.track:
			return

		# Trim error before saving to DB
		error_message = self.error
		if self.error and len(self.error) > 300:
			error_message = self.error[:288] + '...[trimmed]'

		ScanActivity.objects.filter(pk=self.activity.pk).update(
			status=self.status,
			error_message=error_message,
			traceback=self.traceback,
			time=timezone.now())
		self.notify()

	def notify(self, name=None, severity=None, fields={}, add_meta_info=True):
		# Import here to avoid Celery circular import and be able to use `delay`
		if not notifications_enabled():
			return None
		from limes.tasks import send_task_notif
		return send_task_notif.delay(
			name or self.task_name,
			status=self.status_str,
			result=self.result,
			traceback=self.traceback,
			output_path=self.output_path,
			scan_history_id=self.scan_id,
			engine_id=self.engine_id,
			subscan_id=self.subscan_id,
			severity=severity,
			add_meta_info=add_meta_info,
			update_fields=fields)

	def s(self, *args, **kwargs):
		# TODO: set task status to INIT when creating a signature.
		return super().s(*args, **kwargs)
