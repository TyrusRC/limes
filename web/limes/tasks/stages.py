from limes.tasks.base import *
from limes.tasks.enrichment import remove_duplicate_endpoints
from limes import scope
from limes.tasks import intel, resolution
from limes.tasks.notifications import send_file_to_discord
from limes.tasks.persistence import extract_httpx_url, parse_nmap_results, save_endpoint, save_ip_address, save_subdomain, save_vulnerability
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
		host = self.subdomain.name if self.subdomain else self.domain.name

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
	send_subdomain_changes, send_interesting = False, False
	notif = Notification.objects.first()
	subdomain_scope_checker = SubdomainScopeChecker(self.out_of_scope_subdomains)
	if notif:
		send_subdomain_changes = notif.send_subdomain_changes_notif
		send_interesting = notif.send_interesting_notif

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
				wordlist = f"/usr/src/wordlist/{config.get(AMASS_WORDLIST, 'deepmagic.com-prefixes-top50000')}.txt"
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
				cmd = f'subfinder -d {host} -o {self.results_dir}/subdomains_subfinder.txt'
				use_subfinder_config = config.get(USE_SUBFINDER_CONFIG, False)
				cmd += ' -config /root/.config/subfinder/config.yaml' if use_subfinder_config else ''
				cmd += f' -proxy {proxy}' if proxy else ''
				cmd += f' -timeout {timeout}' if timeout else ''
				cmd += f' -t {threads}' if threads else ''
				cmd += f' -silent'

		else:
			logger.warning(
				f'Subdomain discovery tool "{tool}" is not supported by Limes. Skipping.')
			continue

		# Run tool
		try:
			run_command(
				cmd,
				shell=True,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id)
		except Exception as e:
			logger.error(
				f'Subdomain discovery tool "{tool}" raised an exception')
			logger.exception(e)

	# Gather all the tools' results in one single file. Write subdomains into
	# separate files, and sort all subdomains.
	run_command(
		f'cat {self.results_dir}/subdomains_*.txt > {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	run_command(
		f'sort -u {self.output_path} -o {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	with open(self.output_path) as f:
		lines = f.readlines()

	# Parse the output_file file and store Subdomain and EndPoint objects found
	# in db.
	subdomain_count = 0
	subdomains = []
	urls = []
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
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		if subdomain:
			subdomain_count += 1
			subdomains.append(subdomain)
			urls.append(subdomain.name)

	# Resolve again: this run's newly discovered hosts have no answer yet (the call above only covers known ones).
	resolution.resolve_domain(self.domain, self.results_dir)

	# Bulk crawl subdomains
	if enable_http_crawl:
		ctx['track'] = True
		http_crawl(urls, ctx=ctx, is_ran_from_subdomain_scan=True)

	# Find root subdomain endpoints
	for subdomain in subdomains:
		pass

	# Send notifications
	subdomains_str = '\n'.join([f'• `{subdomain.name}`' for subdomain in subdomains])
	self.notify(fields={
		'Subdomain count': len(subdomains),
		'Subdomains': subdomains_str,
	})
	if send_subdomain_changes and self.scan_id and self.domain_id:
		added = get_new_added_subdomain(self.scan_id, self.domain_id)
		removed = get_removed_subdomain(self.scan_id, self.domain_id)

		if added:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in added])
			self.notify(fields={'Added subdomains': subdomains_str})

		if removed:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in removed])
			self.notify(fields={'Removed subdomains': subdomains_str})

	if send_interesting and self.scan_id and self.domain_id:
		interesting_subdomains = get_interesting_subdomains(self.scan_id, self.domain_id)
		if interesting_subdomains:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in interesting_subdomains])
			self.notify(fields={'Interesting subdomains': subdomains_str})

	return SubdomainSerializer(subdomains, many=True).data


@app.task(name='passive_intel', base=LimesTask, bind=True)
def passive_intel(self, ctx={}, description=None):
	"""Passive providers (crt.sh, Shodan InternetDB, RIPEstat) for the scan's owned root.

	Contacts only those third-party APIs, never a target, so it needs no scope guard.
	"""
	project, root = resolution.root_for_domain(self.domain) if self.domain else (None, None)
	if not project or not root or root.scope_tier != 'owned_root':
		logger.warning('Passive intel: no owned root for this scan, skipping')
		return {}
	steps = (
		('crtsh', lambda: intel.run_crtsh(project, root)),
		# hostnames crt.sh added must be resolved before later (guarded) stages
		('resolve', lambda: {'resolved': resolution.resolve_root(project, root, self.results_dir)}),
		('internetdb', lambda: intel.run_internetdb(project, root)),
		('ripestat', lambda: intel.run_ripestat(project, root)),
	)
	counts, failed = {}, []
	for name, step in steps:
		try:
			for k, v in step().items():
				counts[k] = counts.get(k, 0) + v
		except Exception:
			logger.exception(f'Passive intel: {name} failed')
			failed.append(name)
	if failed:
		counts['failed'] = ', '.join(failed)
	self.notify(fields={k.replace('_', ' ').capitalize(): v for k, v in counts.items()})
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
	intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT + 5)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)

	# If intensity is normal, grab only the root endpoints of each subdomain
	strict = True if intensity == 'normal' else False

	# Get URLs to take screenshot of
	urls = get_http_urls(
		is_alive=enable_http_crawl,
		strict=strict,
		write_filepath=alive_endpoints_file,
		get_only_default_urls=True,
		ctx=ctx
	) or []
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
		subdomain_query = Subdomain.objects.filter(name=subdomain_name)
		if self.scan:
			subdomain_query = subdomain_query.filter(scan_history=self.scan)
		subdomain = subdomain_query.first()
		if not subdomain:
			continue
		screenshot_paths.append(screenshot_path)
		subdomain.screenshot_path = screenshot_path.replace('/usr/src/scan_results/', '')
		subdomain.save()
		from limes.tasks import inventory
		inventory.mirror_subdomain_state(subdomain, getattr(self.domain, 'project', None))
		logger.warning(f'Added screenshot for {subdomain.name} to DB')

	# Send finish notifs
	screenshots_str = '• ' + '\n• '.join([f'`{path}`' for path in screenshot_paths])
	self.notify(fields={'Screenshots': screenshots_str})
	if send_output_file:
		for path in screenshot_paths:
			title = get_output_file_name(
				self.scan_id,
				self.subscan_id,
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
	exclude_subdomains = config.get(NAABU_EXCLUDE_SUBDOMAINS, False)
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

	if not hosts:
		hosts = get_subdomains(exclude_subdomains=exclude_subdomains, ctx=ctx)
	hosts = _in_scope(self, hosts, 'attack', allow_co_brand=False)
	if not hosts:
		logger.warning('Port scan: no in-scope hosts, skipping')
		return {}
	with open(input_file, 'w') as f:
		f.write('\n'.join(hosts))

	# Build cmd
	cmd = 'naabu -json -exclude-cdn'
	cmd += f' -list {input_file}' if len(hosts) > 0 else f' -host {hosts[0]}'
	if 'full' in ports or 'all' in ports:
		ports_str = ' -p "-"'
	elif 'top-100' in ports:
		ports_str = ' -top-ports 100'
	elif 'top-1000' in ports:
		ports_str = ' -top-ports 1000'
	else:
		ports_str = ','.join(ports)
		ports_str = f' -p {ports_str}'
	cmd += ports_str
	cmd += ' -config /root/.config/naabu/config.yaml' if use_naabu_config else ''
	cmd += f' -proxy "{proxy}"' if proxy else ''
	cmd += f' -c {threads}' if threads else ''
	cmd += f' -rate {rate_limit}' if rate_limit > 0 else ''
	cmd += f' -timeout {timeout}s' if timeout > 0 else ''
	cmd += f' -passive' if passive else ''
	cmd += f' -exclude-ports {exclude_ports_str}' if exclude_ports else ''
	cmd += f' -silent'

	# Execute cmd and gather results
	results = []
	urls = []
	ports_data = {}
	for line in stream_command(
			cmd,
			shell=True,
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

		# Grab subdomain
		subdomain = Subdomain.objects.filter(
			name=host,
			target_domain=self.domain,
			scan_history=self.scan
		).first()

		# Add IP DB
		ip, _ = save_ip_address(ip_address, subdomain, subscan=self.subscan)
		if self.subscan:
			ip.ip_subscan_ids.add(self.subscan)
			ip.save()

		# Add endpoint to DB
		# port 80 and 443 not needed as http crawl already does that.
		if port_number not in [80, 443]:
			http_url = f'{host}:{port_number}'
			endpoint, _ = save_endpoint(
				http_url,
				crawl=enable_http_crawl,
				ctx=ctx,
				subdomain=subdomain)
			if endpoint:
				http_url = endpoint.http_url
			urls.append(http_url)

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
			ctx_nmap['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
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
	nmap_cmd = get_nmap_cmd(
		cmd=cmd,
		ports=ports_str,
		script=script,
		script_args=script_args,
		max_rate=max_rate,
		host=host,
		input_file=input_file,
		output_file=output_file_xml)
	
	if not nmap_cmd:
		logger.error('Could not build nmap command')
		return

	# Run cmd
	run_command(
		nmap_cmd,
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	# Get nmap XML results and convert to JSON
	vulns = parse_nmap_results(output_file_xml, output_file)
	with open(vulns_file, 'w') as f:
		json.dump(vulns, f, indent=4)

	# Save vulnerabilities found by nmap
	vulns_str = ''
	for vuln_data in vulns:
		# URL is not necessarily an HTTP URL when running nmap (can be any
		# other vulnerable protocols). Look for existing endpoint and use its
		# URL as vulnerability.http_url if it exists.
		url = vuln_data['http_url']
		endpoint = EndPoint.objects.filter(http_url__contains=url).first()
		if endpoint:
			vuln_data['http_url'] = endpoint.http_url
		vuln, created = save_vulnerability(
			target_domain=self.domain,
			subdomain=self.subdomain,
			scan_history=self.scan,
			subscan=self.subscan,
			endpoint=endpoint,
			**vuln_data)
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
	duplicate_removal_fields = config.get(DUPLICATE_REMOVAL_FIELDS, ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	ignore_file_extension = config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	exclude_subdomains = config.get(EXCLUDED_SUBDOMAINS, False)

	# Get URLs to scan and save to input file
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_alive=enable_http_crawl,
			write_filepath=input_path,
			exclude_subdomains=exclude_subdomains,
			get_only_default_urls=True,
			ctx=ctx
		)

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
			should_remove_duplicate_endpoints=should_remove_duplicate_endpoints,
			duplicate_removal_fields=duplicate_removal_fields
		)


	return all_urls


@app.task(name='vulnerability_scan', bind=True, base=LimesTask)
def vulnerability_scan(self, urls=[], ctx={}, description=None):
	"""DAST stage: run assay over the scan's crawled URLs and save findings.

	assay runs nuclei and the active web checks internally. Exit code 2 means
	findings crossed a fail-on threshold (success-with-findings); only a non
	0/2 exit code is a real failure.

	Returns:
		int: number of vulnerabilities saved.
	"""
	logger.info('Running DAST (assay) vulnerability scan')
	prof = (profiles.resolve_profile(self.engine.profile)
			if self.engine and getattr(self.engine, 'profile', None) else profiles.resolve_profile('normal'))

	# Gather crawled, alive HTTP URLs discovered for this scan
	target_urls = _in_scope(self, get_http_urls(is_alive=True, ctx=ctx) or [], 'attack')
	if not target_urls:
		logger.warning('No alive HTTP URLs to scan, skipping DAST stage')
		return 0

	targets_file = f'{self.results_dir}/assay_targets.txt'
	with open(targets_file, 'w') as f:
		f.write('\n'.join(target_urls))

	out_dir = f'{self.results_dir}/assay'
	os.makedirs(out_dir, exist_ok=True)
	config_path = f'{self.results_dir}/assay_config.yaml'

	ident = identity.ScanIdentity.for_domain(self.domain)
	cfg_tmps = identity.write_assay_config(ident, prof.assay_profile, config_path)
	try:
		argv = assay.build_argv(targets_file, prof.assay_profile, config_path, out_dir, extra_no_flags=[])
		rc_output = commands.run(
			argv,
			timeout=prof.timeouts.get('dast', 6 * 3600),
			secrets=identity.redaction_secrets(ident))
		if not assay.is_success(rc_output.return_code):
			raise assay.AssayError(
				f'assay exited with {rc_output.return_code}: {rc_output.output_tail}')

		report_path = f'{out_dir}/assay-report.json'
		if not os.path.isfile(report_path):
			logger.warning(f'assay produced no report at {report_path}')
			return 0
		# assay echoes the raw request (incl. secret headers) into its report:
		# scrub it on disk and before anything reaches the DB.
		secrets = identity.redaction_secrets(ident)
		with open(report_path) as f:
			report = commands.redact_obj(json.load(f), secrets)
		with open(report_path, 'w') as f:
			json.dump(report, f)
		vulns = assay.parse_report(report)

		count = 0
		for v in vulns:
			http_url = v.get('http_url')
			subdomain_name = get_subdomain_from_url(http_url) if http_url else None
			subdomain = (Subdomain.objects
					.filter(scan_history=self.scan, name=subdomain_name)
					.first()) if subdomain_name else None
			save_vulnerability(**{
				**v,
				'scan_history': self.scan,
				'target_domain': self.domain,
				'subdomain': subdomain,
			})
			count += 1
		logger.info(f'DAST stage saved {count} vulnerabilities')
		return count
	finally:
		# runs on every path (failure, timeout, parse error): assay writes raw requests to disk
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
		findings = mantis.audit_dir(f'{self.results_dir}/code_artifacts', packs=['secrets', 'web'])
	except mantis.MantisError as e:
		logger.error(f'Code audit failed: {e}')
		return 0
	count = 0
	for finding in findings:
		source_url = crawl.artifact_source_url(finding.get('path', ''), mapping)
		v = mantis.map_finding(finding, source_url=source_url)
		save_vulnerability(**{**v, 'scan_history': self.scan, 'target_domain': self.domain})
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
		should_remove_duplicate_endpoints=True,
		duplicate_removal_fields=[]):
	"""Use httpx to query HTTP URLs for important info like page titles, http
	status, etc...

	Args:
		urls (list, optional): A set of URLs to check. Overrides default
			behavior which queries all endpoints related to this scan.
		method (str): HTTP method to use (GET, HEAD, POST, PUT, DELETE).
		recrawl (bool, optional): If False, filter out URLs that have already
			been crawled.
		should_remove_duplicate_endpoints (bool): Whether to remove duplicate endpoints
		duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates

	Returns:
		list: httpx results.
	"""
	logger.info('Initiating HTTP Crawl')
	if is_ran_from_subdomain_scan:
		logger.info('Running From Subdomain Scan...')
	cmd = '/go/bin/httpx'
	cfg = self.yaml_configuration.get(HTTP_CRAWL) or {}
	threads = cfg.get(THREADS, DEFAULT_THREADS)
	follow_redirect = cfg.get(FOLLOW_REDIRECT, True)
	self.output_path = None
	input_path = f'{self.results_dir}/httpx_input.txt'
	history_file = f'{self.results_dir}/commands.txt'
	if urls: # direct passing URLs to check
		if self.starting_point_path:
			urls = [u for u in urls if self.starting_point_path in u]

		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_uncrawled=not recrawl,
			write_filepath=input_path,
			ctx=ctx
		)
		# logger.debug(urls)

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
	cmd += f' -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe'
	cmd += f' -t {threads}' if threads > 0 else ''
	cmd += f' --http-proxy {proxy}' if proxy else ''
	ident = identity.ScanIdentity.for_domain(self.domain)
	header_argv, hdr_tmps = identity.render_httpx(ident)
	secrets = identity.redaction_secrets(ident)
	cmd += ' ' + shlex.join(header_argv)
	cmd += f' -json'
	cmd += f' -u {urls[0]}' if len(urls) == 1 else f' -l {input_path}'
	cmd += f' -x {method}' if method else ''
	cmd += f' -silent'
	if follow_redirect:
		cmd += ' -fr'
	results = []
	endpoint_ids = []
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

		# Create Subdomain object in DB
		subdomain_name = get_subdomain_from_url(http_url)
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)

		if not subdomain:
			continue

		# Save default HTTP URL to endpoint object in DB
		endpoint, created = save_endpoint(
			http_url,
			crawl=False,
			ctx=ctx,
			subdomain=subdomain,
			is_default=is_ran_from_subdomain_scan
		)
		if not endpoint:
			continue
		endpoint.http_status = http_status
		endpoint.page_title = page_title
		endpoint.content_length = content_length
		endpoint.webserver = webserver
		endpoint.response_time = response_time
		endpoint.content_type = content_type
		endpoint.save()
		endpoint_str = f'{http_url} [{http_status}] `{content_length}B` `{webserver}` `{rt}`'
		logger.warning(endpoint_str)
		if endpoint and endpoint.is_alive and endpoint.http_status != 403:
			self.notify(
				fields={'Alive endpoint': f'• {endpoint_str}'},
				add_meta_info=False)

		# Add endpoint to results
		line['_cmd'] = cmd
		line['final_url'] = http_url
		line['endpoint_id'] = endpoint.id
		line['endpoint_created'] = created
		line['is_redirect'] = is_redirect
		results.append(line)

		# Add technology objects to DB
		for technology in techs:
			tech, _ = Technology.objects.get_or_create(name=technology)
			endpoint.techs.add(tech)
			if is_ran_from_subdomain_scan:
				subdomain.technologies.add(tech)
				subdomain.save()
			endpoint.save()
		techs_str = ', '.join([f'`{tech}`' for tech in techs])
		self.notify(
			fields={'Technologies': techs_str},
			add_meta_info=False)

		# Add IP objects for 'a' records to DB
		a_records = line.get('a', [])
		for ip_address in a_records:
			ip, created = save_ip_address(
				ip_address,
				subdomain,
				subscan=self.subscan,
				cdn=cdn)
		ips_str = '• ' + '\n• '.join([f'`{ip}`' for ip in a_records])
		self.notify(
			fields={'IPs': ips_str},
			add_meta_info=False)

		# Add IP object for host in DB
		if host:
			ip, created = save_ip_address(
				host,
				subdomain,
				subscan=self.subscan,
				cdn=cdn)
			if ip:
				self.notify(
					fields={'IPs': f'• `{ip.address}`'},
					add_meta_info=False)

		# Save subdomain and endpoint
		if is_ran_from_subdomain_scan:
			# save subdomain stuffs
			subdomain.http_url = http_url
			subdomain.http_status = http_status
			subdomain.page_title = page_title
			subdomain.content_length = content_length
			subdomain.webserver = webserver
			subdomain.response_time = response_time
			subdomain.content_type = content_type
			subdomain.cname = ','.join(cname)
			subdomain.is_cdn = cdn
			if cdn:
				subdomain.cdn_name = line.get('cdn_name')
			subdomain.save()
			from limes.tasks import inventory
			inventory.mirror_subdomain_state(subdomain, getattr(self.domain, 'project', None))
		endpoint.save()
		endpoint_ids.append(endpoint.id)

	if should_remove_duplicate_endpoints:
		# Remove 'fake' alive endpoints that are just redirects to the same page
		remove_duplicate_endpoints(
			self.scan_id,
			self.domain_id,
			self.subdomain_id,
			filter_ids=endpoint_ids
		)

	# Remove input file
	run_command(
		f'rm {input_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	return results
