from limes.tasks.base import *
from limes.tasks import resolution
from limes.tasks.notifications import send_scan_notif
from limes.tasks.persistence import save_endpoint, save_imported_subdomains, save_subdomain
from limes.tasks.stages import code_audit, fetch_url, passive_intel, port_scan, screenshot, subdomain_discovery, vulnerability_scan

#----------------------#
# Scan / Subscan tasks #
#----------------------#


def build_workflow(ctx, mode):
	"""asm mode is passive only (no Scanner stages); full/scanner run every stage."""
	if mode == 'asm':
		return chain(
			subdomain_discovery.si(ctx=ctx, description='Subdomain discovery'),
			passive_intel.si(ctx=ctx, description='Passive intel'),
			screenshot.si(ctx=ctx, description='Screenshot'))
	return chain(
		subdomain_discovery.si(ctx=ctx, description='Subdomain discovery'),
		passive_intel.si(ctx=ctx, description='Passive intel'),
		port_scan.si(ctx=ctx, description='Port scan'),
		fetch_url.si(ctx=ctx, description='Fetch URL'),
		group(
			vulnerability_scan.si(ctx=ctx, description='Vulnerability scan'),
			screenshot.si(ctx=ctx, description='Screenshot'),
			code_audit.si(ctx=ctx, description='Code audit')
		)
	)


def start_scan_run(domain, scan, scan_mode, ctx, initiated_by_id=None):
	"""Create the ScanRun for this scan and thread its id into ctx. No-op
	(returns None) when the domain has no project."""
	if not domain.project:
		return None
	from limes.tasks import inventory as inv
	from startScan.asset_models import ScanRun
	root = inv.upsert_root_asset(domain.project, domain.name, getattr(domain, 'request_headers', None))
	if not root:
		return None
	run = ScanRun.objects.create(
		project=domain.project, root_asset=root, mode=scan_mode or 'full',
		initiated_by_id=initiated_by_id, results_dir=scan.results_dir,
		start_scan_date=timezone.now())
	ctx['scan_run_id'] = run.id
	return run


@app.task(name='initiate_scan', bind=False)
def initiate_scan(
		scan_history_id,
		domain_id,
		engine_id=None,
		scan_type=LIVE_SCAN,
		results_dir=LIMES_RESULTS,
		imported_subdomains=[],
		out_of_scope_subdomains=[],
		initiated_by_id=None,
		starting_point_path='',
		excluded_paths=[],
		scan_mode='full',
	):
	"""Initiate a new scan.

	Args:
		scan_history_id (int): ScanHistory id.
		domain_id (int): Domain id.
		engine_id (int): Engine ID.
		scan_type (int): Scan type (periodic, live).
		results_dir (str): Results directory.
		imported_subdomains (list): Imported subdomains.
		out_of_scope_subdomains (list): Out-of-scope subdomains.
		starting_point_path (str): URL path. Default: '' Defined where to start the scan.
		initiated_by (int): User ID initiating the scan.
		excluded_paths (list): Excluded paths. Default: [], url paths to exclude from scan.
		scan_mode (str): ScanRun mode (full / asm). Default: 'full'.
	"""
	logger.info('Initiating scan on celery')
	scan = None
	try:
		# Get scan engine
		engine_id = engine_id or scan.scan_type.id # scan history engine_id
		engine = EngineType.objects.get(pk=engine_id)

		# Get YAML config
		config = yaml.safe_load(engine.yaml_configuration)
		enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)

		# Get domain and set last_scan_date
		domain = Domain.objects.get(pk=domain_id)
		domain.last_scan_date = timezone.now()
		domain.save()

		# Get path filter
		starting_point_path = starting_point_path.rstrip('/')

		# for live scan scan history id is passed as scan_history_id 
		# and no need to create scan_history object
	
		if scan_type == SCHEDULED_SCAN: # scheduled
			# we need to create scan_history object for each scheduled scan 
			scan_history_id = create_scan_object(
				host_id=domain_id,
				engine_id=engine_id,
				initiated_by_id=initiated_by_id,
			)

		scan = ScanHistory.objects.get(pk=scan_history_id)
		scan.scan_status = RUNNING_TASK
		scan.scan_type = engine
		scan.celery_ids = [initiate_scan.request.id]
		scan.domain = domain
		scan.start_scan_date = timezone.now()
		scan.tasks = engine.tasks
		scan.results_dir = f'{results_dir}/{domain.name}_{scan.id}'
		# add configs to scan object, cfg_ prefix is used to avoid conflicts with other scan object fields
		scan.cfg_starting_point_path = starting_point_path
		scan.cfg_excluded_paths = excluded_paths
		scan.cfg_out_of_scope_subdomains = out_of_scope_subdomains
		scan.cfg_imported_subdomains = imported_subdomains

		scan.save()

		# Create scan results dir
		os.makedirs(scan.results_dir)

		# Build task context
		ctx = {
			'scan_history_id': scan_history_id,
			'engine_id': engine_id,
			'domain_id': domain.id,
			'results_dir': scan.results_dir,
			'starting_point_path': starting_point_path,
			'excluded_paths': excluded_paths,
			'yaml_configuration': config,
			'out_of_scope_subdomains': out_of_scope_subdomains
		}
		start_scan_run(domain, scan, scan_mode, ctx, initiated_by_id)
		ctx_str = json.dumps(ctx, indent=2)

		# Send start notif
		logger.warning(f'Starting scan {scan_history_id} with context:\n{ctx_str}')
		send_scan_notif.delay(
			scan_history_id,
			subscan_id=None,
			engine_id=engine_id,
			status=CELERY_TASK_STATUS_MAP[scan.scan_status])

		# Save imported subdomains in DB
		save_imported_subdomains(imported_subdomains, ctx=ctx)

		# Create initial subdomain in DB: make a copy of domain as a subdomain so
		# that other tasks using subdomains can use it.
		subdomain_name = domain.name
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)

		# If enable_http_crawl is set, create an initial root HTTP endpoint so that
		# HTTP crawling can start somewhere
		# Resolve first: the contact guard refuses unresolved hosts, so the root probe needs it.
		# Root only: this runs under the short orchestration time limit; discovery resolves the rest.
		resolution.resolve_domain(domain, scan.results_dir, root_only=True)
		http_url = f'{domain.name}{starting_point_path}' if starting_point_path else domain.name
		endpoint, _ = save_endpoint(
			http_url,
			ctx=ctx,
			crawl=enable_http_crawl,
			is_default=True,
			subdomain=subdomain
		)
		if endpoint and endpoint.is_alive:
			# TODO: add `root_endpoint` property to subdomain and simply do
			# subdomain.root_endpoint = endpoint instead
			logger.warning(f'Found subdomain root HTTP URL {endpoint.http_url}')
			subdomain.http_url = endpoint.http_url
			subdomain.http_status = endpoint.http_status
			subdomain.response_time = endpoint.response_time
			subdomain.page_title = endpoint.page_title
			subdomain.content_type = endpoint.content_type
			subdomain.content_length = endpoint.content_length
			for tech in endpoint.techs.all():
				subdomain.technologies.add(tech)
			subdomain.save()


		# Build Celery tasks, crafted according to the dependency graph below:
		# subdomain_discovery --> port_scan --> fetch_url --> vulnerability_scan (assay DAST)
		#                                                     screenshot
		#                                                     code_audit
		workflow = build_workflow(ctx, scan_mode)

		# Build callback
		callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

		# Run Celery chord
		logger.info(f'Running Celery workflow with {len(workflow.tasks) + 1} tasks')
		task = chain(workflow, callback).on_error(callback).delay()
		scan.celery_ids.append(task.id)
		scan.save()

		return {
			'success': True,
			'task_id': task.id
		}
	except Exception as e:
		logger.exception(e)
		if scan:
			scan.scan_status = FAILED_TASK
			scan.error_message = str(e)
			scan.save()
		return {
			'success': False,
			'error': str(e)
		}


@app.task(name='initiate_subscan', bind=False)
def initiate_subscan(
		scan_history_id,
		subdomain_id,
		engine_id=None,
		scan_type=None,
		results_dir=LIMES_RESULTS,
		starting_point_path='',
		excluded_paths=[],
	):
	"""Initiate a new subscan.

	Args:
		scan_history_id (int): ScanHistory id.
		subdomain_id (int): Subdomain id.
		engine_id (int): Engine ID.
		scan_type (int): Scan type (periodic, live).
		results_dir (str): Results directory.
		starting_point_path (str): URL path. Default: ''
		excluded_paths (list): Excluded paths. Default: [], url paths to exclude from scan.
	"""

	# Get Subdomain, Domain and ScanHistory
	subdomain = Subdomain.objects.get(pk=subdomain_id)
	scan = ScanHistory.objects.get(pk=subdomain.scan_history.id)
	domain = Domain.objects.get(pk=subdomain.target_domain.id)

	# Get EngineType
	engine_id = engine_id or scan.scan_type.id
	engine = EngineType.objects.get(pk=engine_id)

	# Get YAML config
	config = yaml.safe_load(engine.yaml_configuration)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)

	# Create scan activity of SubScan Model
	subscan = SubScan(
		start_scan_date=timezone.now(),
		celery_ids=[initiate_subscan.request.id],
		scan_history=scan,
		subdomain=subdomain,
		type=scan_type,
		status=RUNNING_TASK,
		engine=engine)
	subscan.save()

	# Get YAML configuration
	config = yaml.safe_load(engine.yaml_configuration)

	# Create results directory
	results_dir = f'{scan.results_dir}/subscans/{subscan.id}'
	os.makedirs(results_dir, exist_ok=True)

	# Run task
	method = globals().get(scan_type)
	if not method:
		logger.warning(f'Task {scan_type} is not supported by Limes. Skipping')
		return
	scan.tasks.append(scan_type)
	scan.save()

	# Send start notif
	send_scan_notif.delay(
		scan.id,
		subscan_id=subscan.id,
		engine_id=engine_id,
		status='RUNNING')

	# Build context
	ctx = {
		'scan_history_id': scan.id,
		'subscan_id': subscan.id,
		'engine_id': engine_id,
		'domain_id': domain.id,
		'subdomain_id': subdomain.id,
		'yaml_configuration': config,
		'results_dir': results_dir,
		'starting_point_path': starting_point_path,
		'excluded_paths': excluded_paths,
	}

	# Create initial endpoints in DB: find domain HTTP endpoint so that HTTP
	# crawling can start somewhere
	base_url = f'{subdomain.name}{starting_point_path}' if starting_point_path else subdomain.name
	endpoint, _ = save_endpoint(
		base_url,
		crawl=enable_http_crawl,
		ctx=ctx,
		subdomain=subdomain)
	if endpoint and endpoint.is_alive:
		# TODO: add `root_endpoint` property to subdomain and simply do
		# subdomain.root_endpoint = endpoint instead
		logger.warning(f'Found subdomain root HTTP URL {endpoint.http_url}')
		subdomain.http_url = endpoint.http_url
		subdomain.http_status = endpoint.http_status
		subdomain.response_time = endpoint.response_time
		subdomain.page_title = endpoint.page_title
		subdomain.content_type = endpoint.content_type
		subdomain.content_length = endpoint.content_length
		for tech in endpoint.techs.all():
			subdomain.technologies.add(tech)
		subdomain.save()

	# Build header + callback
	workflow = method.si(ctx=ctx)
	callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

	# Run Celery tasks
	task = chain(workflow, callback).on_error(callback).delay()
	subscan.celery_ids.append(task.id)
	subscan.save()

	return {
		'success': True,
		'task_id': task.id
	}


@app.task(name='report', bind=False)
def report(ctx={}, description=None):
	"""Report task running after all other tasks.
	Mark ScanHistory or SubScan object as completed and update with final
	status, log run details and send notification.

	Args:
		description (str, optional): Task description shown in UI.
	"""
	# Get objects
	subscan_id = ctx.get('subscan_id')
	scan_id = ctx.get('scan_history_id')
	engine_id = ctx.get('engine_id')
	scan = ScanHistory.objects.filter(pk=scan_id).first()
	subscan = SubScan.objects.filter(pk=subscan_id).first()

	# Get failed tasks
	tasks = ScanActivity.objects.filter(scan_of=scan).all()
	if subscan:
		tasks = tasks.filter(celery_id__in=subscan.celery_ids)
	failed_tasks = tasks.filter(status=FAILED_TASK)

	# Get task status
	failed_count = failed_tasks.count()
	status = SUCCESS_TASK if failed_count == 0 else FAILED_TASK
	status_h = 'SUCCESS' if failed_count == 0 else 'FAILED'

	# Update scan / subscan status
	if subscan:
		subscan.stop_scan_date = timezone.now()
		subscan.status = status
		subscan.save()
	else:
		scan.scan_status = status
	scan.stop_scan_date = timezone.now()
	scan.save(update_fields=['scan_status', 'stop_scan_date'])
	if ctx.get('scan_run_id') and not subscan:
		from startScan.asset_models import ScanRun
		ScanRun.objects.filter(pk=ctx['scan_run_id']).update(
			status=status, stop_scan_date=timezone.now())
		run = ScanRun.objects.filter(pk=ctx['scan_run_id']).first()
		if run and run.status == SUCCESS_TASK:  # failed scans must not age unseen hosts
			from limes.tasks import inventory as inv
			inv.finalize_lifecycle(run)
	from dashboard.stats import invalidate
	invalidate(scan.domain.project_id)

	# Send scan status notif
	send_scan_notif.delay(
		scan_history_id=scan_id,
		subscan_id=subscan_id,
		engine_id=engine_id,
		status=status_h)
