from limes.tasks.base import *
from limes.run_urls import RunUrls
from limes.scope import target_host

#-------------#
# Utils tasks #
#-------------#


@app.task(name='parse_nmap_results', bind=False)
def parse_nmap_results(xml_file, output_file=None):
	"""Parse results from nmap output file.

	Args:
		xml_file (str): nmap XML report file path.

	Returns:
		list: List of vulnerabilities found from nmap results.
	"""
	with open(xml_file, encoding='utf8') as f:
		content = f.read()
		try:
			nmap_results = xmltodict.parse(content) # parse XML to dict
		except Exception as e:
			logger.exception(e)
			logger.error(f'Cannot parse {xml_file} to valid JSON. Skipping.')
			return []

	# Write JSON to output file
	if output_file:
		with open(output_file, 'w') as f:
			json.dump(nmap_results, f, indent=4)
	logger.warning(json.dumps(nmap_results, indent=4))
	hosts = (
		nmap_results
		.get('nmaprun', {})
		.get('host', {})
	)
	all_vulns = []
	if isinstance(hosts, dict):
		hosts = [hosts]

	for host in hosts:
		# Grab hostname / IP from output
		hostnames_dict = host.get('hostnames', {})
		if hostnames_dict:
			# Ensure that hostnames['hostname'] is a list for consistency
			hostnames_list = hostnames_dict['hostname'] if isinstance(hostnames_dict['hostname'], list) else [hostnames_dict['hostname']]

			# Extract all the @name values from the list of dictionaries
			hostnames = [entry.get('@name') for entry in hostnames_list]
		else:
			hostnames = [host.get('address')['@addr']]

		# Iterate over each hostname for each port
		for hostname in hostnames:

			# Grab ports from output
			ports = host.get('ports', {}).get('port', [])
			if isinstance(ports, dict):
				ports = [ports]

			for port in ports:
				url_vulns = []
				port_number = port['@portid']
				url = sanitize_url(f'{hostname}:{port_number}')
				logger.info(f'Parsing nmap results for {hostname}:{port_number} ...')
				if not port_number or not port_number.isdigit():
					continue
				port_protocol = port['@protocol']
				scripts = port.get('script', [])
				if isinstance(scripts, dict):
					scripts = [scripts]

				for script in scripts:
					script_id = script['@id']
					script_output = script['@output']
					script_output_table = script.get('table', [])
					logger.debug(f'Ran nmap script "{script_id}" on {port_number}/{port_protocol}:\n{script_output}\n')
					if script_id == 'vulscan':
						vulns = parse_nmap_vulscan_output(script_output)
						url_vulns.extend(vulns)
					elif script_id == 'vulners':
						vulns = parse_nmap_vulners_output(script_output)
						url_vulns.extend(vulns)
					# elif script_id == 'http-server-header':
					# 	TODO: nmap can help find technologies as well using the http-server-header script
					# 	regex = r'(\w+)/([\d.]+)\s?(?:\((\w+)\))?'
					# 	tech_name, tech_version, tech_os = re.match(regex, test_string).groups()
					# 	Technology.objects.get_or_create(...)
					else:
						logger.warning(f'Script output parsing for script "{script_id}" is not supported yet.')

				# Add URL & source to vuln
				for vuln in url_vulns:
					vuln['source'] = NMAP
					# TODO: This should extend to any URL, not just HTTP
					vuln['http_url'] = url
					if 'http_path' in vuln:
						vuln['http_url'] += vuln['http_path']
					all_vulns.append(vuln)

	return all_vulns


def parse_nmap_vulscan_output(script_output):
	"""Parse nmap vulscan script output.

	Args:
		script_output (str): Vulscan script output.

	Returns:
		list: List of Vulnerability dicts.
	"""
	data = {}
	vulns = []
	provider_name = ''

	# Sort all vulns found by provider so that we can match each provider with
	# a function that pulls from its API to get more info about the
	# vulnerability.
	for line in script_output.splitlines():
		if not line:
			continue
		if not line.startswith('['): # provider line
			if "No findings" in line:
				logger.info(f"No findings: {line}")
				continue
			elif ' - ' in line:
				provider_name, provider_url = tuple(line.split(' - '))
				data[provider_name] = {'url': provider_url.rstrip(':'), 'entries': []}
				continue
			else:
				# Log a warning
				logger.warning(f"Unexpected line format: {line}")
				continue
		reg = r'\[(.*)\] (.*)'
		matches = re.match(reg, line)
		id, title = matches.groups()
		entry = {'id': id, 'title': title}
		data[provider_name]['entries'].append(entry)

	logger.warning('Vulscan parsed output:')
	logger.warning(pprint.pformat(data))

	for provider_name in data:
		if provider_name == 'Exploit-DB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'IBM X-Force':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'MITRE CVE':
			logger.error(f'Provider {provider_name} is not supported YET.')
			for entry in data[provider_name]['entries']:
				cve_id = entry['id']
				vuln = cve_to_vuln(cve_id)
				vulns.append(vuln)
		elif provider_name == 'OSVDB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'OpenVAS (Nessus)':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'SecurityFocus':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'VulDB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		else:
			logger.error(f'Provider {provider_name} is not supported.')
	return vulns


def parse_nmap_vulners_output(script_output, url=''):
	"""Parse nmap vulners script output.

	TODO: Rework this as it's currently matching all CVEs no matter the
	confidence.

	Args:
		script_output (str): Script output.

	Returns:
		list: List of found vulnerabilities.
	"""
	vulns = []
	# Check for CVE in script output
	CVE_REGEX = re.compile(r'.*(CVE-\d\d\d\d-\d+).*')
	matches = CVE_REGEX.findall(script_output)
	matches = list(dict.fromkeys(matches))
	for cve_id in matches: # get CVE info
		vuln = cve_to_vuln(cve_id, vuln_type='nmap-vulners-nse')
		if vuln:
			vulns.append(vuln)
	return vulns


def cve_to_vuln(cve_id, vuln_type=''):
	"""Search for a CVE using CVESearch and return Vulnerability data.

	Args:
		cve_id (str): CVE ID in the form CVE-*

	Returns:
		dict: Vulnerability dict.
	"""
	cve_info = CVESearch('https://cve.circl.lu').id(cve_id)
	if not cve_info:
		logger.error(f'Could not fetch CVE info for cve {cve_id}. Skipping.')
		return None
	vuln_cve_id = cve_info['id']
	vuln_name = vuln_cve_id
	vuln_description = cve_info.get('summary', 'none').replace(vuln_cve_id, '').strip()
	try:
		vuln_cvss = float(cve_info.get('cvss', -1))
	except (ValueError, TypeError):
		vuln_cvss = -1
	vuln_cwe_id = cve_info.get('cwe', '')
	exploit_ids = cve_info.get('refmap', {}).get('exploit-db', [])
	osvdb_ids = cve_info.get('refmap', {}).get('osvdb', [])
	references = cve_info.get('references', [])
	capec_objects = cve_info.get('capec', [])

	# Parse ovals for a better vuln name / type
	ovals = cve_info.get('oval', [])
	if ovals:
		vuln_name = ovals[0]['title']
		vuln_type = ovals[0]['family']

	# Set vulnerability severity based on CVSS score
	vuln_severity = 'info'
	if vuln_cvss < 4:
		vuln_severity = 'low'
	elif vuln_cvss < 7:
		vuln_severity = 'medium'
	elif vuln_cvss < 9:
		vuln_severity = 'high'
	else:
		vuln_severity = 'critical'

	# Build console warning message
	msg = f'{vuln_name} | {vuln_severity.upper()} | {vuln_cve_id} | {vuln_cwe_id} | {vuln_cvss}'
	for id in osvdb_ids:
		msg += f'\n\tOSVDB: {id}'
	for exploit_id in exploit_ids:
		msg += f'\n\tEXPLOITDB: {exploit_id}'
	logger.warning(msg)
	vuln = {
		'name': vuln_name,
		'type': vuln_type,
		'severity': NUCLEI_SEVERITY_MAP[vuln_severity],
		'description': vuln_description,
		'cvss_score': vuln_cvss,
		'references': references,
		'cve_ids': [vuln_cve_id],
		'cwe_ids': [vuln_cwe_id]
	}
	return vuln


def extract_httpx_url(line):
	"""Extract final URL from httpx results. Always follow redirects to find
	the last URL.

	Args:
		line (dict): URL data output by httpx.

	Returns:
		tuple: (final_url, redirect_bool) tuple.
	"""
	status_code = line.get('status_code', 0)
	final_url = line.get('final_url')
	location = line.get('location')
	chain_status_codes = line.get('chain_status_codes', [])

	# Final URL is already looking nice, if it exists return it
	if final_url:
		return final_url, False
	http_url = line['url'] # fallback to url field

	# Handle redirects manually
	REDIRECT_STATUS_CODES = [301, 302]
	is_redirect = (
		status_code in REDIRECT_STATUS_CODES
		or
		any(x in REDIRECT_STATUS_CODES for x in chain_status_codes)
	)
	if is_redirect and location:
		if location.startswith(('http', 'https')):
			http_url = location
		else:
			http_url = f'{http_url}/{location.lstrip("/")}'

	# Sanitize URL
	http_url = sanitize_url(http_url)

	return http_url, is_redirect


#-----------------#
# Utils functions #
#-----------------#

def create_scan_activity(scan_history_id, message, status):
	scan_activity = ScanActivity()
	scan_activity.scan_of = ScanHistory.objects.get(pk=scan_history_id)
	scan_activity.title = message
	scan_activity.time = timezone.now()
	scan_activity.status = status
	scan_activity.save()
	return scan_activity.id


#--------------------#
# Database functions #
#--------------------#


def resolve_vuln_asset(scan_history, http_url=None):
	"""The scan's project Asset (hostname or root domain) a finding is on, else None.
	Never crosses projects: the asset must belong to the scan's own project."""
	from urllib.parse import urlsplit
	from startScan.models import Asset
	if not scan_history:
		return None
	host = None
	if http_url:
		try:
			host = urlsplit(http_url if '://' in http_url else '//' + http_url).hostname
		except ValueError:
			host = None
	host = (host or '').strip().rstrip('.').lower()
	if not host:
		return None
	return (Asset.objects
			.filter(project_id=scan_history.domain.project_id, kind__in=('hostname', 'root_domain'), value=host)
			.first())


def _uniq(values):
	"""Non-empty strings, first occurrence wins, order kept."""
	return list(dict.fromkeys(v for v in values or [] if v))


def save_vulnerability(**vuln_data):
	references = _uniq(vuln_data.pop('references', []))
	cve_ids = vuln_data.pop('cve_ids', [])
	cwe_names = _uniq(vuln_data.pop('cwe_ids', []))
	tag_names = _uniq(vuln_data.pop('tags', []))

	# remove nulls
	vuln_data = replace_nulls(vuln_data)
	if not vuln_data.get('asset'):
		vuln_data['asset'] = resolve_vuln_asset(vuln_data.get('scan_history'), vuln_data.get('http_url'))

	# Create vulnerability
	vuln, created = Vulnerability.objects.get_or_create(**vuln_data)
	if created:
		vuln.discovered_date = timezone.now()
		vuln.open_status = True
		vuln.save()

	# Tags, CWEs and references are plain lists on the row; CVEs stay rows (the exploit-intel join needs them)
	merged = {}
	for field, new in (('tag_names', tag_names), ('cwe_names', cwe_names), ('reference_urls', references)):
		have = getattr(vuln, field) or []
		if any(n not in have for n in new):
			merged[field] = have + [n for n in new if n not in have]
			setattr(vuln, field, merged[field])
	if merged:
		vuln.save(update_fields=list(merged))

	# Save CVEs
	for cve_id in cve_ids or []:
		cve, _ = CveId.objects.get_or_create(name=cve_id)
		vuln.cve_ids.add(cve)

	return vuln, created


def host_in_domain(host, root):
	"""True when host is the root domain or a real subdomain of it. Not a substring test: `x.com.evil.org`,
	`notx.com` and `https://evil.org/?q=x.com` all contain `x.com` and are not ours."""
	host = (host or '').lower().rstrip('.')
	root = (root or '').lower().rstrip('.')
	return bool(host and root) and (host == root or host.endswith('.' + root))


def url_in_domain(url, root):
	return host_in_domain(target_host(url), root)


def record_url(store, http_url, domain, is_default=False, **fields):
	"""Record http_url in the run's URL store when it is a valid URL of the scan's domain.

	Returns:
		tuple: (stored url, created); (None, False) when the URL is refused.
	"""
	if domain and not url_in_domain(http_url, domain.name):
		logger.error(f"{http_url} is not a URL of domain {domain.name}. Skipping.")
		return None, False
	if not urlparse(http_url).scheme or not validators.url(http_url):
		return None, False
	url = sanitize_url(http_url)
	return url, store.record(url, is_default=is_default, **fields)


def probe_url(http_url, ctx, crawl=False, is_default=False):
	"""Put http_url in the run's URL file; with crawl, probe it with httpx first and record what answers.

	Returns:
		tuple: (url, created). url is None when the URL is refused or did not answer.
	"""
	domain = Domain.objects.filter(pk=ctx.get('domain_id')).first()
	if crawl:
		if domain and not url_in_domain(http_url, domain.name):
			logger.error(f"{http_url} is not a URL of domain {domain.name}. Skipping.")
			return None, False
		ctx['track'] = False
		from limes.tasks.stages import http_crawl
		results = http_crawl(urls=[http_url], method='HEAD', ctx=ctx)
		if not results:
			return None, False
		url, created = results[0]['endpoint_url'], results[0]['endpoint_created']
		if created and is_default:
			RunUrls(ctx['results_dir']).mark_default(url)
		return url, created
	# a URL that was never probed has status 0: it is not alive, but a default one is still screenshotted
	return record_url(RunUrls(ctx['results_dir']), http_url, domain, is_default=is_default, http_status=0)


def save_host(name, ctx={}):
	"""Validate name against the scan (valid host, in scope, under the scan's domain) and upsert its hostname Asset,
	stamped with this scan so the stages can list the hosts of the run. Returns the Asset, or None."""
	scan_id = ctx.get('scan_history_id')
	subdomain_checker = SubdomainScopeChecker(ctx.get('out_of_scope_subdomains', []))
	valid_domain = (
		validators.domain(name) or
		validators.ipv4(name) or
		validators.ipv6(name)
	)
	if not valid_domain:
		logger.error(f'{name} is not an invalid domain. Skipping.')
		return None

	if subdomain_checker.is_out_of_scope(name):
		logger.error(f'{name} is out-of-scope. Skipping.')
		return None

	if ctx.get('domain_id'):
		domain = Domain.objects.get(id=ctx.get('domain_id'))
		if not host_in_domain(name, domain.name):
			logger.error(f"{name} is not a subdomain of domain {domain.name}. Skipping.")
			return None

	scan = ScanHistory.objects.filter(pk=scan_id).first()
	domain = scan.domain if scan else None
	project = getattr(domain, 'project', None)
	if not project:
		return None
	from limes.tasks import inventory as inv  # lazy: persistence <-> inventory
	root = inv.upsert_root_asset(project, domain.name, getattr(domain, 'request_headers', None))
	return inv.upsert_hostname_asset(project, name, parent=root, source='discovery', evidence=f'scan:{scan.id}')


def save_ip_address(ip_address, host=None, **kwargs):
	"""Get or create the IP; with a hostname Asset, also record the ip Asset and link the IP to the host."""
	if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
		logger.info(f'IP {ip_address} is not a valid IP. Skipping.')
		return None, False
	if 'cdn' in kwargs:  # callers pass cdn=; the model field is is_cdn
		kwargs['is_cdn'] = kwargs.pop('cdn')
	ip, created = IpAddress.objects.get_or_create(address=ip_address)

	# Set extra attributes
	for key, value in kwargs.items():
		setattr(ip, key, value)
	ip.save()

	if host:
		from limes.tasks import inventory as inv
		if inv.upsert_ip_asset(host.project, ip_address, evidence=f'host:{host.value}'):
			host.ip_addresses.add(ip)

	return ip, created


def save_imported_hosts(subdomains, ctx={}):
	"""Take a list of imported subdomain names, save the valid ones under the scan's domain and write them to
	from_imported.txt in the results dir."""
	domain = Domain.objects.get(pk=ctx['domain_id'])
	results_dir = ctx.get('results_dir', LIMES_RESULTS)

	# Validate each subdomain and de-duplicate entries
	subdomains = list(set([
		subdomain for subdomain in subdomains
		if validators.domain(subdomain) and domain.name == get_domain_from_subdomain(subdomain)
	]))
	if not subdomains:
		return

	logger.warning(f'Found {len(subdomains)} imported subdomains.')
	with open(f'{results_dir}/from_imported.txt', 'w+') as output_file:
		for name in subdomains:
			host = save_host(name.strip(), ctx=ctx)
			output_file.write(f'{host.value if host else name.strip()}\n')
