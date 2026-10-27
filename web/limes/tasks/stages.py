import glob

from celery.exceptions import SoftTimeLimitExceeded
from limes.tasks.base import *
from limes import scope
from limes.run_urls import RunUrls, is_alive
from limes.definitions import NOTHING_ASSESSED
from limes import api_discovery, cloud_storage, code_search, dangling
from limes.checks import leak, run as checks_run
from limes.tasks import attribution, intel, resolution
from limes.tasks.notifications import send_file_to_discord
from limes.tasks import inventory
from limes.tasks.persistence import extract_httpx_url, parse_nmap_results, probe_url, record_url, save_host, save_ip_address, save_vulnerability
from limes.tasks.runner import run_command, stream_command

def _in_scope(task, targets, level, allow_co_brand=True):
	"""Drop targets the scope guard refuses (fails closed) and report them."""
	project = task.domain.project if task.domain else None
	if level == 'contact':
		allowed, refused = scope.may_contact(project, targets)
	else:
		allowed, refused = scope.may_attack(project, targets, allow_co_brand=allow_co_brand)
	if refused:
		by_reason = {}
		for _, reason in refused:
			by_reason[reason] = by_reason.get(reason, 0) + 1
		logger.warning(f'Scope: refused {len(refused)} target(s) in {task.task_name}: {by_reason}; '
			f'first: {[t for t, _ in refused[:10]]}')
		try:
			with open(os.path.join(task.results_dir, 'scope_refused.txt'), 'a') as f:
				f.writelines(f'{task.task_name}\t{t}\t{r}\n' for t, r in refused)
		except OSError as e:
			logger.warning(f'Scope: could not write scope_refused.txt: {e}')
		task.notify(fields={'Refused (scope)': len(refused)})
	return allowed


#------------------------- #
# Tracked Limes tasks    #
#--------------------------#

@app.task(name='subdomain_discovery', base=LimesTask, bind=True)
def subdomain_discovery(
		self,
		host=None,
		ctx=None,
		description=None):
	"""Uses a set of tools (see SUBDOMAIN_SCAN_DEFAULT_TOOLS) to scan all
	subdomains associated with a domain.

	Args:
		host (str): Hostname to scan.

	Returns:
		subdomains (list): List of subdomain names.
	"""
	if not host:
		host = self.domain.name

	# Resolve before anything else (even the early return below): the contact guard refuses unresolved hosts.
	resolution.resolve_domain(self.domain, self.results_dir)

	if self.starting_point_path:
		logger.warning(f'Ignoring subdomains scan as an URL path filter was passed ({self.starting_point_path}).')
		return

	# Config
	config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL) or self.yaml_configuration.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	tools = config.get(USES_TOOLS, SUBDOMAIN_SCAN_DEFAULT_TOOLS)
	# amass's tool name is amass, but the engine may ask for amass-active/passive
	supported_tools = ('subfinder', 'amass', 'amass-passive', 'amass-active')
	subdomain_scope_checker = SubdomainScopeChecker(self.out_of_scope_subdomains)

	# Gather tools to run for subdomain scan
	if ALL in tools:
		tools = SUBDOMAIN_SCAN_DEFAULT_TOOLS
	tools = [t.lower() for t in tools]

	# Run tools
	for tool in tools:
		cmd = None
		logger.info(f'Scanning subdomains for {host} with {tool}')
		proxy = get_random_proxy()
		if tool in supported_tools:
			if tool in ('amass', 'amass-passive', 'amass-active'):
				# amass v5: names live in an asset DB under -dir, read back with `amass subs`.
				active = tool == 'amass-active' or bool(config.get(AMASS_ACTIVE, False))
				brute = bool(config.get(AMASS_BRUTE, active))
				wordlist = amass.wordlist_path(config.get(AMASS_WORDLIST, 'deepmagic.com-prefixes-top50000'))
				if brute and not wordlist:
					logger.warning('amass wordlist from the engine is not a plain name of an installed list; using amass default')
				amass_dir = f'{self.results_dir}/amass'
				try:
					commands.run(amass.build_enum_argv(host, amass_dir, active, brute, wordlist))
					subs = commands.run(amass.build_subs_argv(host, amass_dir))
					with open(f'{self.results_dir}/subdomains_amass.txt', 'w') as f:
						names = amass.parse_subs(subs.output, host)
						# trailing newline: `cat subdomains_*.txt` must not glue files' last/first lines
						f.write('\n'.join(names) + '\n' if names else '')
				except Exception as e:
					logger.error(f'Subdomain discovery tool "{tool}" raised an exception')
					logger.exception(e)
				continue

			elif tool == 'subfinder':
				argv = ['subfinder', '-d', host, '-o', f'{self.results_dir}/subdomains_subfinder.txt']
				if config.get(USE_SUBFINDER_CONFIG, False):
					argv += ['-config', '/root/.config/subfinder/config.yaml']
				if proxy:
					argv += ['-proxy', str(proxy)]
				if timeout:
					argv += ['-timeout', str(timeout)]
				if threads:
					argv += ['-t', str(threads)]
				argv.append('-silent')
				cmd = shlex.join(argv)

		else:
			logger.warning(
				f'Subdomain discovery tool "{tool}" is not supported by Limes. Skipping.')
			continue

		# Run tool
		try:
			run_command(
				cmd,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id)
		except Exception as e:
			logger.error(
				f'Subdomain discovery tool "{tool}" raised an exception')
			logger.exception(e)

	# Gather all the tools' results in one single file. Write subdomains into
	# separate files, and sort all subdomains.
	# (cat subdomains_*.txt | sort -u) done in Python: every line of every tool's file, once, sorted
	names = set()
	for path in sorted(glob.glob(f'{self.results_dir}/subdomains_*.txt')):
		with open(path, errors='replace') as f:
			names.update(line.strip() for line in f if line.strip())
	with open(self.output_path, 'w') as f:
		f.writelines(f'{name}\n' for name in sorted(names))

	with open(self.output_path) as f:
		lines = f.readlines()

	# Parse the output_file file and save the hostnames found as Assets.
	subdomains = []
	for line in lines:
		subdomain_name = line.strip()
		valid_url = bool(validators.url(subdomain_name))
		valid_domain = (
			bool(validators.domain(subdomain_name)) or
			bool(validators.ipv4(subdomain_name)) or
			bool(validators.ipv6(subdomain_name)) or
			valid_url
		)
		if not valid_domain:
			logger.error(f'Subdomain {subdomain_name} is not a valid domain, IP or URL. Skipping.')
			continue

		if valid_url:
			subdomain_name = urlparse(subdomain_name).netloc

		if subdomain_scope_checker.is_out_of_scope(subdomain_name):
			logger.error(f'Subdomain {subdomain_name} is out of scope. Skipping.')
			continue

		# Add subdomain
		if save_host(subdomain_name, ctx=ctx):
			subdomains.append(subdomain_name)

	# Resolve again: this run's newly discovered hosts have no answer yet (the call above only covers known ones).
	resolution.resolve_domain(self.domain, self.results_dir)

	# Bulk crawl subdomains
	if enable_http_crawl:
		ctx['track'] = True
		http_crawl(subdomains, ctx=ctx, is_ran_from_subdomain_scan=True)

	# Send notifications (new and missing hosts are change events on the inventory)
	subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in subdomains])
	self.notify(fields={
		'Subdomain count': len(subdomains),
		'Subdomains': subdomains_str,
	})

	return subdomains


@app.task(name='passive_intel', base=LimesTask, bind=True)
def passive_intel(self, ctx={}, description=None):
	"""Passive providers (crt.sh, Shodan InternetDB, RIPEstat) for the scan's owned root.

	Contacts only those third-party APIs, never a target, so it needs no scope guard.
	"""
	try:
		project, root = resolution.root_for_domain(self.domain) if self.domain else (None, None)
	except Exception:
		logger.exception('Passive intel: root lookup failed, skipping')
		return {}
	if not project or not root or root.scope_tier != 'owned_root':
		logger.warning('Passive intel: no owned root for this scan, skipping')
		return {}
	steps = (
		('crtsh', lambda: intel.run_crtsh(project, root)),
		# hostnames crt.sh added are resolved so the scope guard and per-IP enrichment see them
		('resolve', lambda: {'resolved': resolution.resolve_root(project, root, self.results_dir)}),
		('internetdb', lambda: intel.run_internetdb(project, root)),
		('ripestat', lambda: intel.run_ripestat(project, root)),
		('attribution_dns', lambda: attribution.collect_dns(project, self.results_dir)),
		('attribution_score', lambda: attribution.score_project(project)),
		('attribution_verify', lambda: attribution.verify_delegations(project)),
		('attribution_decide', lambda: attribution.apply_decisions(project)),
	)
	counts, failed = {}, []
	for name, step in steps:
		if name == 'resolve' and counts.get('hostnames') == 0:
			continue  # crt.sh found nothing new to resolve
		if name == 'attribution_decide' and {'attribution_dns', 'attribution_score', 'attribution_verify'} & set(failed):
			continue  # facts, scores or delegations may be stale or partial: never decide from them
		try:
			for k, v in step().items():
				counts[k] = counts.get(k, 0) + v
		except SoftTimeLimitExceeded:
			logger.warning(f'Passive intel: soft time limit hit in {name}, skipping remaining steps')
			failed.append(name)
			break
		except Exception:
			logger.exception(f'Passive intel: {name} failed')
			failed.append(name)
	if failed:
		counts['failed'] = ', '.join(failed)
	try:
		self.notify(fields={k.replace('_', ' ').capitalize(): v for k, v in counts.items()})
	except Exception:
		logger.exception('Passive intel: notify failed')
	return counts


@app.task(name='risk_checks', base=LimesTask, bind=True)
def risk_checks(self, ctx={}, description=None):
	"""Configuration risk checks for the scan's owned root. Contacts only in-scope hosts (the scope
	guard runs inside run_checks), and stays inside its own time budget."""
	try:
		project, root = resolution.root_for_domain(self.domain) if self.domain else (None, None)
	except Exception:
		logger.exception('Risk checks: root lookup failed, skipping')
		return {}
	if not project or not root or root.scope_tier != 'owned_root':
		logger.warning('Risk checks: no owned root for this scan, skipping')
		return {}
	# a crash propagates so LimesTask marks the stage FAILED; the chain still continues
	counts = checks_run.run_checks(project, root)
	try:  # APIs are a bonus on top of the checks: their failure never costs the stage
		logger.info('API discovery: %s', api_discovery.discover(project, root))
	except SoftTimeLimitExceeded:
		raise
	except Exception:
		logger.exception('API discovery failed, continuing')
	for name, step in (('Cloud storage', lambda: cloud_storage.discover(project, root)),
					   ('Dangling DNS', lambda: dangling.discover(project, root)),
					   ('Code search', lambda: code_search.discover(project, root))):
		try:  # provisional extras: their failure never costs the stage
			logger.info('%s: %s', name, step())
		except SoftTimeLimitExceeded:
			raise
		except Exception:
			logger.exception('%s check failed, continuing', name)
	try:
		self.notify(fields={k.replace('_', ' ').capitalize(): v for k, v in counts.items()})
	except Exception:
		logger.exception('Risk checks: notify failed')
	return counts


@app.task(name='screenshot', base=LimesTask, bind=True)
def screenshot(self, ctx={}, description=None):
	"""Uses httpx headless screenshots to capture a domain and/or url.

	Args:
		description (str, optional): Task description shown in UI.
	"""

	# Config
	screenshots_path = f'{self.results_dir}/screenshots'
	alive_endpoints_file = f'{self.results_dir}/endpoints_alive.txt'
	config = self.yaml_configuration.get(SCREENSHOT) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT + 5)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)

	# Get URLs to take screenshot of: the root URL of each host, from the run's URL file
	urls = RunUrls(self.results_dir).urls(alive=enable_http_crawl, default_only=True)
	urls = _in_scope(self, urls, 'contact')
	if not urls:
		logger.warning('Screenshot: no in-scope URLs, skipping')
		return []
	with open(alive_endpoints_file, 'w') as f:
		f.write('\n'.join(urls))

	# Send start notif
	notification = Notification.objects.first()
	send_output_file = notification.send_scan_output_file if notification else False

	# Run httpx headless screenshots (replaces EyeWitness)
	# TODO: the image has no Chrome; httpx -ss downloads a Chromium on first use (or add chromium + -system-chrome).
	cmd = ['/go/bin/httpx', '-silent', '-json', '-ss', '-esb', '-ehb', '-l', alive_endpoints_file, '-srd', screenshots_path]
	cmd += ['-st', str(timeout)] if timeout > 0 else []
	cmd += ['-t', str(threads)] if threads > 0 else []
	ident = identity.ScanIdentity.for_domain(self.domain)
	header_argv, hdr_tmps = identity.render_httpx(ident)
	cmd += header_argv
	try:
		res = commands.run(cmd, secrets=identity.redaction_secrets(ident))
	finally:
		identity.cleanup(hdr_tmps)
	if res.return_code != 0:
		logger.warning(f'httpx screenshot exited with {res.return_code}')

	# Loop through results and save objects in DB
	screenshot_paths = []
	for raw in res.output.splitlines():
		try:
			row = json.loads(raw)
		except ValueError:
			continue
		screenshot_path = row.get('screenshot_path')
		if not screenshot_path or not os.path.isfile(screenshot_path):
			continue
		subdomain_name = get_subdomain_from_url(row.get('url', ''))
		project = getattr(self.domain, 'project', None)
		if not inventory.run_host(project, self.scan_id, subdomain_name):
			continue
		screenshot_paths.append(screenshot_path)
		inventory.record_host_state(project, subdomain_name,
									screenshot_path=screenshot_path.replace('/usr/src/scan_results/', ''))
		logger.warning(f'Added screenshot for {subdomain_name} to DB')

	# Send finish notifs
	screenshots_str = '• ' + '\n• '.join([f'`{path}`' for path in screenshot_paths])
	self.notify(fields={'Screenshots': screenshots_str})
	if send_output_file:
		for path in screenshot_paths:
			title = get_output_file_name(
				self.scan_id,
				self.filename)
			send_file_to_discord.delay(path, title)


@app.task(name='port_scan', base=LimesTask, bind=True)
def port_scan(self, hosts=[], ctx={}, description=None):
	"""Run port scan.

	Args:
		hosts (list, optional): Hosts to run port scan on.
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of open ports (dict).
	"""
	input_file = f'{self.results_dir}/input_subdomains_port_scan.txt'
	proxy = get_random_proxy()

	# Config
	config = self.yaml_configuration.get(PORT_SCAN) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	exclude_ports = config.get(NAABU_EXCLUDE_PORTS, [])
	ports = config.get(PORTS, NAABU_DEFAULT_PORTS)
	ports = [str(port) for port in ports]
	rate_limit = config.get(NAABU_RATE) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	passive = config.get(NAABU_PASSIVE, False)
	use_naabu_config = config.get(USE_NAABU_CONFIG, False)
	exclude_ports_str = ','.join(return_iterable(exclude_ports))
	# nmap args
	nmap_enabled = config.get(ENABLE_NMAP, False)
	nmap_cmd = config.get(NMAP_COMMAND, '')
	nmap_script = config.get(NMAP_SCRIPT, '')
	nmap_script = ','.join(return_iterable(nmap_script))
	nmap_script_args = config.get(NMAP_SCRIPT_ARGS)

	project = self.domain.project if self.domain else None
	if not hosts:
		hosts = inventory.run_hostnames(project, self.scan_id) if project else []
		if not hosts:
			logger.error('No subdomains were found in query !')
	hosts = _in_scope(self, hosts, 'attack', allow_co_brand=False)
	if not hosts:
		logger.warning('Port scan: no in-scope hosts, skipping')
		return {}
	with open(input_file, 'w') as f:
		f.write('\n'.join(hosts))

	# Build cmd
	argv = ['naabu', '-json', '-exclude-cdn', '-list', input_file]
	if 'full' in ports or 'all' in ports:
		argv += ['-p', '-']
	elif 'top-100' in ports:
		argv += ['-top-ports', '100']
	elif 'top-1000' in ports:
		argv += ['-top-ports', '1000']
	else:
		argv += ['-p', ','.join(ports)]
	if use_naabu_config:
		argv += ['-config', '/root/.config/naabu/config.yaml']
	if proxy:
		argv += ['-proxy', str(proxy)]
	if threads:
		argv += ['-c', str(threads)]
	if rate_limit > 0:
		argv += ['-rate', str(rate_limit)]
	if timeout > 0:
		argv += ['-timeout', f'{timeout}s']
	if passive:
		argv.append('-passive')
	if exclude_ports:
		argv += ['-exclude-ports', exclude_ports_str]
	argv.append('-silent')
	cmd = shlex.join(argv)

	# Execute cmd and gather results
	results = []
	ports_data = {}
	for line in stream_command(
			cmd,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id):

		if not isinstance(line, dict):
			continue
		results.append(line)
		port_number = line['port']
		ip_address = line['ip']
		host = line.get('host') or ip_address
		if port_number == 0:
			continue

		# Grab the host's Asset
		host_asset = inventory.run_host(project, self.scan_id, host)

		# Add IP DB
		ip, _ = save_ip_address(ip_address, host_asset)

		# Add the URL to the run's URL file
		# port 80 and 443 not needed as http crawl already does that.
		if port_number not in [80, 443]:
			probe_url(f'{host}:{port_number}', ctx, crawl=enable_http_crawl)

		# Add Port in DB
		res = get_port_service_description(port_number)
		# get or create port
		port, created = update_or_create_port(
			port_number=port_number,
			service_name=res.get('service_name', ''),
			description=res.get('description', '')
		)

		if created:
			logger.warning(f'Added new port {port_number} to DB')

		if port_number in UNCOMMON_WEB_PORTS:
			port.is_uncommon = True
			port.save()
		ip.ports.add(port)
		ip.save()
		if host in ports_data:
			ports_data[host].append(port_number)
		else:
			ports_data[host] = [port_number]

		# Send notification
		logger.warning(f'Found opened port {port_number} on {ip_address} ({host})')

	if len(ports_data) == 0:
		logger.info('Finished running naabu port scan - No open ports found.')
		if nmap_enabled:
			logger.info('Nmap scans skipped')
		return ports_data

	# Send notification
	fields_str = ''
	for host, ports in ports_data.items():
		ports_str = ', '.join([f'`{port}`' for port in ports])
		fields_str += f'• `{host}`: {ports_str}\n'
	self.notify(fields={'Ports discovered': fields_str})

	# Save output to file
	with open(self.output_path, 'w') as f:
		json.dump(results, f, indent=4)

	logger.info('Finished running naabu port scan.')

	# NOTE: nmap runs in-process, one host after another; plan 0B batches hosts into one invocation.
	if nmap_enabled:
		logger.warning('Starting nmap scans ...')
		for host, port_list in ports_data.items():
			ctx_nmap = ctx.copy()
			ctx_nmap['description'] = get_task_title(f'nmap_{host}', self.scan_id)
			ctx_nmap['track'] = False
			nmap(
				cmd=nmap_cmd,
				ports=port_list,
				host=host,
				script=nmap_script,
				script_args=nmap_script_args,
				max_rate=rate_limit,
				ctx=ctx_nmap)

	return ports_data


@app.task(name='nmap', base=LimesTask, bind=True)
def nmap(
		self,
		cmd=None,
		ports=[],
		host=None,
		input_file=None,
		script=None,
		script_args=None,
		max_rate=None,
		ctx={},
		description=None):
	"""Run nmap on a host.

	Args:
		cmd (str, optional): Existing nmap command to complete.
		ports (list, optional): List of ports to scan.
		host (str, optional): Host to scan.
		input_file (str, optional): Input hosts file.
		script (str, optional): NSE script to run.
		script_args (str, optional): NSE script args.
		max_rate (int): Max rate.
		description (str, optional): Task description shown in UI.
	"""
	if not host or not _in_scope(self, [host], 'attack', allow_co_brand=False):
		logger.warning(f'nmap: {host or input_file} refused by scope guard')
		return
	notif = Notification.objects.first()
	ports_str = ','.join(str(port) for port in ports)
	self.filename = self.filename.replace('.txt', '.xml')
	filename_vulns = self.filename.replace('.xml', '_vulns.json')
	output_file = self.output_path
	output_file_xml = f'{self.results_dir}/{host}_{self.filename}'
	vulns_file = f'{self.results_dir}/{host}_{filename_vulns}'
	logger.warning(f'Running nmap on {host}:{ports}')

	# Build cmd
	nmap_argv = get_nmap_argv(
		cmd=cmd,
		ports=ports_str,
		script=script,
		script_args=script_args,
		max_rate=max_rate,
		host=host,
		input_file=input_file,
		output_file=output_file_xml)
	
	if not nmap_argv:
		logger.error('Could not build nmap command')
		return

	# Run cmd (an argv, no shell)
	run_command(
		shlex.join(nmap_argv),
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	# Get nmap XML results and convert to JSON
	vulns = parse_nmap_results(output_file_xml, output_file)
	with open(vulns_file, 'w') as f:
		json.dump(vulns, f, indent=4)

	# Save vulnerabilities found by nmap
	vulns_str = ''
	run_urls = RunUrls(self.results_dir)
	for vuln_data in vulns:
		# URL is not necessarily an HTTP URL when running nmap (can be any
		# other vulnerable protocols). Look for a URL of this run that contains
		# it and use that URL as vulnerability.http_url if there is one.
		matched = run_urls.first_containing(vuln_data['http_url'])
		if matched:
			vuln_data['http_url'] = matched
		vuln, created = save_vulnerability(scan_history=self.scan, **vuln_data)
		vulns_str += f'• {str(vuln)}\n'
		if created:
			logger.warning(str(vuln))

	# Send only 1 notif for all vulns to reduce number of notifs
	if notif and notif.send_vuln_notif and vulns_str:
		logger.warning(vulns_str)
		self.notify(fields={'CVEs': vulns_str})
	return vulns


@app.task(name='fetch_url', base=LimesTask, bind=True)
def fetch_url(self, urls=[], ctx={}, description=None):
	"""Crawl with katana (exact host) and gau, then collect code artifacts.

	Args:
		urls (list): List of URLs to start from.
		description (str, optional): Task description shown in UI.
	"""
	input_path = f'{self.results_dir}/input_endpoints_fetch_url.txt'
	proxy = get_random_proxy()

	# Config
	config = self.yaml_configuration.get(FETCH_URL) or {}
	should_remove_duplicate_endpoints = config.get(REMOVE_DUPLICATE_ENDPOINTS, True)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	ignore_file_extension = config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	exclude_subdomains = config.get(EXCLUDED_SUBDOMAINS, False)

	# Get URLs to scan and save to input file
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = RunUrls(self.results_dir).urls(
			alive=enable_http_crawl,
			default_only=True,
			root_host=self.domain.name if exclude_subdomains and self.domain else None)

	urls = _in_scope(self, urls or [], 'attack')
	if not urls:
		logger.warning('Fetch URL: no in-scope URLs, skipping')
		return []
	with open(input_path, 'w') as f:
		f.write('\n'.join(urls))

	# Domain regex
	host = self.domain.name if self.domain else urlparse(urls[0]).netloc

	# Crawl: katana (exact host, carries scan identity) + gau (archives, no identity)
	prof = (profiles.resolve_profile(self.engine.profile)
			if self.engine and getattr(self.engine, 'profile', None) else profiles.resolve_profile('normal'))
	ident = identity.ScanIdentity.for_domain(self.domain)
	header_argv, hdr_tmps = identity.render_header_args(ident)
	secrets = identity.redaction_secrets(ident)
	argv_map = {
		'katana': crawl.build_katana_argv(input_path, prof.crawl_depth, header_argv, threads, proxy),
		'gau': crawl.build_gau_argv(host, threads, proxy),
	}
	# NOTE: crawlers run one after another inside this task; plan 0B keeps only katana + gau.
	try:
		for tool, argv in argv_map.items():
			raw_path = f'{self.results_dir}/raw_{tool}.txt'
			res = commands.run(argv, output_path=raw_path, secrets=secrets)
			if res.return_code != 0:
				logger.warning(f'{tool} exited with {res.return_code}')
			with open(raw_path) if os.path.isfile(raw_path) else open(os.devnull) as f:
				kept = crawl.filter_host_urls(f, host)
			with open(f'{self.results_dir}/urls_{tool}.txt', 'w') as f:
				f.write('\n'.join(kept))
	finally:
		identity.cleanup(hdr_tmps)
	merge_url_files(
		results_dir=self.results_dir,
		input_path=input_path,
		output_path=self.output_path,
		ignore_exts=ignore_file_extension or [])

	# Collect code artifacts (JS, source maps, exposed .git) for code_audit
	try:
		with open(self.output_path) as f:
			crawled = [l.strip() for l in f if l.strip()]
		# collect_code_artifacts fetches every .js/.map and probes .git per origin
		crawled = _in_scope(self, crawled, 'attack')
		art_header_argv, art_tmps = identity.render_header_args(ident)
		try:
			_, art_map = crawl.collect_code_artifacts(
				self.results_dir, crawled, art_header_argv, secrets)
		finally:
			identity.cleanup(art_tmps)
		with open(f'{self.results_dir}/code_artifacts.json', 'w') as f:
			json.dump(art_map, f)
	except Exception as e:
		logger.warning(f'Code artifact collection failed: {e}')

	# Store all the endpoints and run httpx
	with open(self.output_path) as f:
		discovered_urls = f.readlines()
		self.notify(fields={'Discovered URLs': len(discovered_urls)})

	# Some tools can have an URL in the format <URL>] - <PATH> or <URL> - <PATH>, add them
	# to the final URL list
	all_urls = []
	for url in discovered_urls:
		url = url.strip()
		urlpath = None
		base_url = None
		if '] ' in url: # legacy scraped-endpoint format
			split = tuple(url.split('] '))
			if not len(split) == 2:
				logger.warning(f'URL format not recognized for "{url}". Skipping.')
				continue
			base_url, urlpath = split
			urlpath = urlpath.lstrip('- ')
		elif ' - ' in url: # legacy scraped-endpoint format
			base_url, urlpath = tuple(url.split(' - '))

		if base_url and urlpath:
			subdomain = urlparse(base_url)
			url = f'{subdomain.scheme}://{subdomain.netloc}{self.starting_point_path}'

		if not validators.url(url):
			logger.warning(f'Invalid URL "{url}". Skipping.')

		if url not in all_urls:
			all_urls.append(url)

	# Filter out URLs if a path filter was passed
	if self.starting_point_path:
		all_urls = [url for url in all_urls if self.starting_point_path in url]

	# if exclude_paths is found, then remove urls matching those paths
	if self.excluded_paths:
		all_urls = exclude_urls_by_patterns(self.excluded_paths, all_urls)

	# Write result to output path
	with open(self.output_path, 'w') as f:
		f.write('\n'.join(all_urls))
	logger.warning(f'Found {len(all_urls)} usable URLs')

	# Crawl discovered URLs
	if enable_http_crawl:
		ctx['track'] = False
		http_crawl(
			all_urls,
			ctx=ctx,
			should_remove_duplicate_endpoints=should_remove_duplicate_endpoints
		)


	return all_urls


@app.task(name='vulnerability_scan', bind=True, base=LimesTask)
def vulnerability_scan(self, urls=[], ctx={}, description=None):
	"""DAST stage: run vigil over the scan's crawled URLs and save findings.

	vigil runs nuclei and the active web checks internally. Exit code 2 means
	findings crossed a fail-on threshold (success-with-findings); only a non
	0/2 exit code is a real failure.

	Returns:
		int: number of vulnerabilities saved.
	"""
	logger.info('Running DAST (vigil) vulnerability scan')
	prof = (profiles.resolve_profile(self.engine.profile)
			if self.engine and getattr(self.engine, 'profile', None) else profiles.resolve_profile('normal'))

	# Gather crawled, alive HTTP URLs discovered for this scan
	target_urls = _in_scope(self, RunUrls(self.results_dir).urls(alive=True), 'attack')
	if not target_urls:
		logger.warning('No alive HTTP URLs to scan, skipping DAST stage')
		self.error = f'{NOTHING_ASSESSED}: no alive HTTP URLs'  # still SUCCESS, never a scoring baseline
		return 0

	targets_file = f'{self.results_dir}/vigil_targets.txt'
	with open(targets_file, 'w') as f:
		f.write('\n'.join(target_urls))

	out_dir = f'{self.results_dir}/vigil'
	os.makedirs(out_dir, exist_ok=True)
	config_path = f'{self.results_dir}/vigil_config.yaml'

	ident = identity.ScanIdentity.for_domain(self.domain)
	cfg_tmps = identity.write_vigil_config(ident, prof.vigil_profile, config_path)
	try:
		vigil_bin, vigil_env = vigil.prepare()  # raises VigilError if vigil can see a non-allowlisted tool
		argv = vigil.build_argv(targets_file, prof.vigil_profile, config_path, out_dir, extra_no_flags=[])
		argv[0] = vigil_bin
		rc_output = commands.run(
			argv,
			env=vigil_env,
			timeout=prof.timeouts.get('dast', 6 * 3600),
			secrets=identity.redaction_secrets(ident))
		if not vigil.is_success(rc_output.return_code):
			raise vigil.VigilError(
				f'vigil exited with {rc_output.return_code}: {rc_output.output_tail}')

		report_path = f'{out_dir}/vigil-report.json'
		if not os.path.isfile(report_path):
			logger.warning(f'vigil produced no report at {report_path}')
			self.error = f'{NOTHING_ASSESSED}: vigil produced no report'
			return 0
		# vigil echoes the raw request (incl. secret headers) into its report:
		# scrub it on disk and before anything reaches the DB.
		secrets = identity.redaction_secrets(ident)
		with open(report_path) as f:
			report = commands.redact_obj(json.load(f), secrets)
		with open(report_path, 'w') as f:
			json.dump(report, f)
		vulns = vigil.parse_report(report)

		count = 0
		for v in vulns:
			save_vulnerability(**{**v, 'scan_history': self.scan})
			count += 1
		logger.info(f'DAST stage saved {count} vulnerabilities')
		return count
	finally:
		# runs on every path (failure, timeout, parse error): vigil writes raw requests to disk
		commands.redact_tree(out_dir, identity.redaction_secrets(ident))
		identity.cleanup(cfg_tmps + [config_path])

@app.task(name='code_audit', bind=True, base=LimesTask)
def code_audit(self, urls=[], ctx={}, description=None):
	"""SAST stage: run mantis over crawl artifacts, map findings to source URLs.

	Returns:
		int: number of findings saved.
	"""
	map_path = f'{self.results_dir}/code_artifacts.json'
	if not os.path.isfile(map_path):
		logger.warning('No code artifacts collected, skipping code audit')
		return 0
	with open(map_path) as f:
		mapping = json.load(f)
	if not mapping:
		return 0
	try:
		leak.scan_artifacts(f'{self.results_dir}/code_artifacts', mapping, self.domain.project, timezone.now())
	except SoftTimeLimitExceeded:
		raise
	except Exception as e:  # never raised: the leak scan must not cost the code audit; log the type only
		logger.warning(f'Leak scan failed: {type(e).__name__}')
	try:
		findings = mantis.audit_dir(f'{self.results_dir}/code_artifacts', packs=['secrets', 'web'])
	except mantis.MantisError as e:
		logger.error(f'Code audit failed: {e}')
		return 0
	count = 0
	for finding in findings:
		source_url = crawl.artifact_source_url(finding.get('path', ''), mapping)
		v = mantis.map_finding(finding, source_url=source_url)
		save_vulnerability(**{**v, 'scan_history': self.scan})
		count += 1
	logger.info(f'Code audit saved {count} findings')
	return count


@app.task(name='http_crawl', base=LimesTask, bind=True)
def http_crawl(
		self,
		urls=[],
		method=None,
		recrawl=False,
		ctx={},
		track=True,
		description=None,
		is_ran_from_subdomain_scan=False,
		should_remove_duplicate_endpoints=True):
	"""Use httpx to query HTTP URLs for important info like page titles, http
	status, etc...

	Args:
		urls (list, optional): A set of URLs to check. Overrides default
			behavior which queries all endpoints related to this scan.
		method (str): HTTP method to use (GET, HEAD, POST, PUT, DELETE).
		recrawl (bool, optional): If False, filter out URLs that have already
			been crawled.
		should_remove_duplicate_endpoints (bool): Whether to remove duplicate endpoints

	Returns:
		list: httpx results.
	"""
	logger.info('Initiating HTTP Crawl')
	if is_ran_from_subdomain_scan:
		logger.info('Running From Subdomain Scan...')
	cfg = self.yaml_configuration.get(HTTP_CRAWL) or {}
	threads = cfg.get(THREADS, DEFAULT_THREADS)
	follow_redirect = cfg.get(FOLLOW_REDIRECT, True)
	self.output_path = None
	run_urls = RunUrls(self.results_dir)
	project = getattr(self.domain, 'project', None)
	input_path = f'{self.results_dir}/httpx_input.txt'
	history_file = f'{self.results_dir}/commands.txt'
	if urls: # direct passing URLs to check
		if self.starting_point_path:
			urls = [u for u in urls if self.starting_point_path in u]

		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = run_urls.urls(uncrawled=not recrawl)

	# exclude urls by pattern
	if self.excluded_paths:
		urls = exclude_urls_by_patterns(self.excluded_paths, urls)

	urls = _in_scope(self, urls or [], 'contact')
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))

	# If no URLs found, skip it
	if not urls:
		return

	# Re-adjust thread number if few URLs to avoid spinning up a monster to
	# kill a fly.
	if len(urls) < threads:
		threads = len(urls)

	# Get random proxy
	proxy = get_random_proxy()

	# Run command
	argv = ['/go/bin/httpx', '-cl', '-ct', '-rt', '-location', '-td', '-websocket', '-cname', '-asn', '-cdn', '-probe']
	if threads > 0:
		argv += ['-t', str(threads)]
	if proxy:
		argv += ['--http-proxy', str(proxy)]
	ident = identity.ScanIdentity.for_domain(self.domain)
	header_argv, hdr_tmps = identity.render_httpx(ident)
	secrets = identity.redaction_secrets(ident)
	argv += header_argv
	argv.append('-json')
	argv += ['-u', urls[0]] if len(urls) == 1 else ['-l', input_path]
	if method:
		argv += ['-x', method]
	argv.append('-silent')
	if follow_redirect:
		argv.append('-fr')
	cmd = shlex.join(argv)
	results = []
	stored_urls = []
	try:
		lines = list(stream_command(
			cmd,
			history_file=history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id,
			secrets=secrets))
	finally:
		identity.cleanup(hdr_tmps)
	for line in lines:

		if not line or not isinstance(line, dict):
			continue

		logger.debug(line)

		# No response from endpoint
		if line.get('failed', False):
			continue

		# Parse httpx output
		# httpx >= 1.7: 'host' is the hostname, the IP is in 'host_ip'
		host = line.get('host_ip', '')
		content_length = line.get('content_length', 0)
		http_status = line.get('status_code')
		http_url, is_redirect = extract_httpx_url(line)
		page_title = line.get('title')
		webserver = line.get('webserver')
		cdn = line.get('cdn', False)
		rt = line.get('time')
		techs = line.get('tech', [])
		cname = line.get('cname', '')
		content_type = line.get('content_type', '')
		response_time = -1
		if rt:
			response_time = float(''.join(ch for ch in rt if not ch.isalpha()))
			if rt[-2:] == 'ms':
				response_time = response_time / 1000

		# Save the host as an Asset
		subdomain_name = get_subdomain_from_url(http_url)
		host_asset = save_host(subdomain_name, ctx=ctx)

		if not host_asset:
			continue

		# Save the URL (the root one of a host when run from the discovery stage) in the run's URL file
		stored_url, created = record_url(
			run_urls, http_url, self.domain,
			is_default=is_ran_from_subdomain_scan,
			http_status=http_status, page_title=page_title, content_length=content_length)
		if not stored_url:
			continue
		endpoint_str = f'{http_url} [{http_status}] `{content_length}B` `{webserver}` `{rt}`'
		logger.warning(endpoint_str)
		if is_alive(http_status) and http_status != 403:
			self.notify(
				fields={'Alive endpoint': f'• {endpoint_str}'},
				add_meta_info=False)

		# Add URL to results
		line['_cmd'] = cmd
		line['final_url'] = http_url
		line['endpoint_url'] = stored_url
		line['endpoint_created'] = created
		line['is_redirect'] = is_redirect
		results.append(line)

		# Add technology objects to DB
		tech_objects = []
		for technology in techs:
			tech, _ = Technology.objects.get_or_create(name=technology)
			tech_objects.append(tech)
		techs_str = ', '.join([f'`{tech}`' for tech in techs])
		self.notify(
			fields={'Technologies': techs_str},
			add_meta_info=False)

		# Add IP objects for 'a' records to DB
		a_records = line.get('a', [])
		for ip_address in a_records:
			ip, created = save_ip_address(
				ip_address,
				host_asset,
				cdn=cdn)
		ips_str = '• ' + '\n• '.join([f'`{ip}`' for ip in a_records])
		self.notify(
			fields={'IPs': ips_str},
			add_meta_info=False)

		# Add IP object for host in DB
		if host:
			ip, created = save_ip_address(
				host,
				host_asset,
				cdn=cdn)
			if ip:
				self.notify(
					fields={'IPs': f'• `{ip.address}`'},
					add_meta_info=False)

		# Write the probe result on the host's Asset
		if is_ran_from_subdomain_scan:
			inventory.record_host_state(
				project, subdomain_name, technologies=tech_objects,
				http_status=http_status, page_title=page_title, webserver=webserver,
				content_type=content_type, content_length=content_length, response_time=response_time,
				cname=','.join(cname), is_cdn=cdn, cdn_name=line.get('cdn_name') if cdn else None)
		stored_urls.append(stored_url)

	if should_remove_duplicate_endpoints:
		# Remove 'fake' alive endpoints that are just redirects to the same page
		# (no URL answered: this looks at every URL of the run, as the endpoint filter always did)
		removed = run_urls.prune_duplicates(only=set(stored_urls))
		if removed:
			logger.warning(f'Deleted {len(removed)} URLs with the same content_length or page_title as others')

	# Remove input file
	try:
		os.remove(input_path)
	except FileNotFoundError:
		pass

	return results
