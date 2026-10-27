import re
import shlex
import whatportis
import socket
import json
import os
import random
import traceback
import humanize
import redis
import requests
import tldextract
import xmltodict

from time import sleep
from urllib.parse import urlparse
from celery.utils.log import get_task_logger
from discord_webhook import DiscordEmbed, DiscordWebhook

from limes.definitions import *
from limes.settings import *
from scanEngine.models import *
from dashboard.models import *
from startScan.models import *
from targetApp.models import *
from limes.utilities import is_valid_url


logger = get_task_logger(__name__)
DISCORD_WEBHOOKS_CACHE = redis.Redis.from_url(CELERY_BROKER_URL)
CHAT_TIMEOUT = 10  # seconds; a hung chat host must not hold a worker forever

#-----------#
# URL utils #
#-----------#

def get_subdomain_from_url(url):
	"""Get subdomain from HTTP URL.

	Args:
		url (str): HTTP URL.

	Returns:
		str: Subdomain name.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in url:
		url = "http://" + url

	url_obj = urlparse(url.strip())
	return url_obj.netloc.split(':')[0]


def get_domain_from_subdomain(subdomain):
	"""Get domain from subdomain.

	Args:
		subdomain (str): Subdomain name.

	Returns:
		str: Domain name.
	"""
	# ext = tldextract.extract(subdomain)
	# return '.'.join(ext[1:3])

	if not validators.domain(subdomain):
		return None
	
	# Use tldextract to parse the subdomain
	extracted = tldextract.extract(subdomain)

	# if tldextract recognized the tld then its the final result
	if extracted.suffix:
		domain = f"{extracted.domain}.{extracted.suffix}"
	else:
		# Fallback method for unknown TLDs, like .clouds or .local etc
		parts = subdomain.split('.')
		if len(parts) >= 2:
			domain = '.'.join(parts[-2:])
		else:
			return None
		
	# Validate the domain before returning
	return domain if validators.domain(domain) else None



def sanitize_url(http_url):
	"""Removes HTTP ports 80 and 443 from HTTP URL because it's ugly.

	Args:
		http_url (str): Input HTTP URL.

	Returns:
		str: Stripped HTTP URL.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in http_url:
		http_url = "http://" + http_url
	url = urlparse(http_url)

	if url.netloc.endswith(':80'):
		url = url._replace(netloc=url.netloc.replace(':80', ''))
	elif url.netloc.endswith(':443'):
		url = url._replace(scheme=url.scheme.replace('http', 'https'))
		url = url._replace(netloc=url.netloc.replace(':443', ''))
	return url.geturl().rstrip('/')

#-------#
# Utils #
#-------#


def get_random_proxy():
	"""Get a random proxy from the list of proxies input by user in the UI.

	Returns:
		str: Proxy name or '' if no proxy defined in db or use_proxy is False.
	"""
	if not Proxy.objects.all().exists():
		return ''
	proxy = Proxy.objects.first()
	if not proxy.use_proxy:
		return ''
	proxy_name = random.choice(proxy.proxies.splitlines())
	logger.warning('Using proxy: ' + proxy_name)
	# os.environ['HTTP_PROXY'] = proxy_name
	# os.environ['HTTPS_PROXY'] = proxy_name
	return proxy_name

def remove_ansi_escape_sequences(text):
	# Regular expression to match ANSI escape sequences
	ansi_escape_pattern = r'\x1b\[.*?m'

	# Use re.sub() to replace the ANSI escape sequences with an empty string
	plain_text = re.sub(ansi_escape_pattern, '', text)
	return plain_text

#--------------------#
# NOTIFICATION UTILS #
#--------------------#

def escape_telegram_markdown(text):
	"""Escape Telegram Markdown (v1) specials, so a key like net.exposed_redis is not read as an unclosed italic."""
	return re.sub(r'([_*`\[])', r'\\\1', text)


def send_telegram_message(message):
	"""Send Telegram message.

	Args:
		message (str): Message.
	"""
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_telegram and
		notif.telegram_bot_token and
		notif.telegram_bot_chat_id)
	if not do_send:
		return
	telegram_bot_token = notif.telegram_bot_token
	telegram_bot_chat_id = notif.telegram_bot_chat_id
	send_url = f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage'
	params = {'chat_id': telegram_bot_chat_id, 'parse_mode': 'Markdown', 'text': escape_telegram_markdown(message)}
	try:
		resp = requests.get(send_url, params=params, timeout=CHAT_TIMEOUT)
	except requests.exceptions.RequestException as exc:
		logger.warning('Telegram notification failed: %s', type(exc).__name__)  # class only: the URL carries the token
		return
	if not resp.ok:  # status only: the URL carries the bot token
		logger.warning('Telegram answered %s', resp.status_code)


def send_slack_message(message):
	"""Send Slack message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {'text': message}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_slack and
		notif.slack_hook_url)
	if not do_send:
		return
	hook_url = notif.slack_hook_url
	try:
		requests.post(url=hook_url, data=json.dumps(message), headers=headers, timeout=CHAT_TIMEOUT)
	except requests.exceptions.RequestException as exc:
		logger.warning('Slack notification failed: %s', type(exc).__name__)  # class only: the URL is the secret

def send_lark_message(message):
	"""Send lark message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {"msg_type":"interactive","card":{"elements":[{"tag":"div","text":{"content":message,"tag":"lark_md"}}]}}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_lark and
		notif.lark_hook_url)
	if not do_send:
		return
	hook_url = notif.lark_hook_url
	try:
		requests.post(url=hook_url, data=json.dumps(message), headers=headers, timeout=CHAT_TIMEOUT)
	except requests.exceptions.RequestException as exc:
		logger.warning('Lark notification failed: %s', type(exc).__name__)  # class only: the URL is the secret

# Embed attributes that may come back from the cache. The cache holds JSON only, so
# whoever can write the broker cannot make a worker run code by planting a value.
DISCORD_EMBED_KEYS = ('title', 'description', 'url', 'footer', 'image', 'thumbnail', 'video',
		'provider', 'author', 'fields', 'color', 'timestamp')


def _discord_state_load(title):
	"""Message id and embed of the last Discord message sent under this title, or None."""
	raw = DISCORD_WEBHOOKS_CACHE.get('discord:' + title) if title else None
	try:
		state = json.loads(raw) if raw else None
	except ValueError:
		return None
	if not isinstance(state, dict):
		return None
	message_id = state.get('id') if isinstance(state.get('id'), str) else None
	embed = state.get('embed')
	if not isinstance(embed, dict) or not isinstance(embed.get('fields', []), list):
		embed = None
	return {'id': message_id, 'embed': embed}


def _discord_state_save(title, message_id, embed):
	state = {'id': message_id, 'embed': {k: v for k, v in embed.__dict__.items() if k in DISCORD_EMBED_KEYS}}
	DISCORD_WEBHOOKS_CACHE.set('discord:' + title, json.dumps(state))


def send_discord_message(
		message,
		title='',
		severity=None,
		url=None,
		files=None,
		fields={},
		fields_append=[]):
	"""Send Discord message.

	If title and fields are specified, ignore the 'message' and create a Discord
	embed that can be updated later if specifying the same title (title is the
	cache key).

	Args:
		message (str): Message to send. If an embed is used, this is ignored.
		severity (str, optional): Severity. Colors are picked based on severity.
		files (list, optional): List of files to attach to message.
		title (str, optional): Discord embed title.
		url (str, optional): Discord embed URL.
		fields (dict, optional): Discord embed fields.
		fields_append (list, optional): Discord embed field names to update
			instead of overwrite.
	"""

	# Check if do send
	notif = Notification.objects.first()
	if not (notif and notif.send_to_discord and notif.discord_hook_url):
		return False

	# If fields and title, use an embed
	use_discord_embed = fields and title
	if use_discord_embed:
		message = '' # no need for message in embeds

	# State of the previous message with this title: lets us edit it instead of posting again
	state = _discord_state_load(title)
	message_id = state['id'] if state else None
	webhook = DiscordWebhook(
		url=notif.discord_hook_url,
		rate_limit_retry=False,
		content=message)
	webhook.timeout = CHAT_TIMEOUT
	webhook.id = message_id

	embed = None
	if state and state['embed']:
		embed = DiscordEmbed(title=title)
		embed.__dict__.update({k: v for k, v in state['embed'].items() if k in DISCORD_EMBED_KEYS})
	elif use_discord_embed:
		embed = DiscordEmbed(title=title)

	# Set embed fields
	if embed:
		if url:
			embed.set_url(url)
		if severity:
			embed.set_color(DISCORD_SEVERITY_COLORS[severity])
		embed.set_description(message)
		embed.set_timestamp()
		existing_fields_dict = {field['name']: field['value'] for field in embed.fields}
		logger.debug(''.join([f'\n\t{k}: {v}' for k, v in fields.items()]))
		for name, value in fields.items():
			if not value: # cannot send empty field values to Discord [error 400]
				continue
			value = str(value)
			new_field = {'name': name, 'value': value, 'inline': False}

			# If field already existed in previous embed, update it.
			if name in existing_fields_dict.keys():
				field = [f for f in embed.fields if f['name'] == name][0]

				# Append to existing field value
				if name in fields_append:
					existing_val = field['value']
					existing_val = str(existing_val)
					if value not in existing_val:
						value = f'{existing_val}\n{value}'

					if len(value) > 1024: # character limit for embed field
						value = value[0:1016] + '\n[...]'

				# Update existing embed
				ix = embed.fields.index(field)
				embed.fields[ix]['value'] = value

			else:
				embed.add_embed_field(**new_field)

		webhook.add_embed(embed)

		# Keep the embed so a later message with this title can update it
		_discord_state_save(title, message_id, embed)

	# Add files to webhook
	if files:
		for (path, name) in files:
			with open(path, 'r') as f:
				content = f.read()
			webhook.add_file(content, name)

	# Edit webhook if it already existed, otherwise send new webhook
	try:
		if message_id:
			response = webhook.edit()
		else:
			response = webhook.execute()
	except requests.exceptions.RequestException as exc:
		logger.warning('Discord notification failed: %s', type(exc).__name__)  # class only: the URL is the secret
		return False
	if not message_id and embed and response.status_code == 200 and isinstance(webhook.id, str):
		_discord_state_save(title, webhook.id, embed)

	# Get status code
	if response.status_code == 429:
		errors = json.loads(
			response.content.decode('utf-8'))
		wh_sleep = (int(errors['retry_after']) / 1000) + 0.15
		sleep(wh_sleep)
		send_discord_message(
				message,
				title,
				severity,
				url,
				files,
				fields,
				fields_append)
	elif response.status_code != 200:
		logger.error(
			f'Error while sending webhook data to Discord.'
			f'\n\tHTTP code: {response.status_code}.'
			f'\n\tDetails: {response.content}')


def enrich_notification(message, scan_history_id):
	"""Add the scan id to a notification message.

	Args:
		message (str): Original notification message.
		scan_history_id (int): Scan history id.

	Returns:
		str: Message.
	"""
	if scan_history_id is not None:
		message = f'`#{scan_history_id}`: {message}'
	return message


def get_scan_title(scan_id):
	return f'Scan #{scan_id} summary'


def get_scan_url(scan=None):
	"""The project's Scan History page (the per-scan page is gone); None without a scan."""
	if scan:
		return f'{LIMES_PUBLIC_SCHEME}://{DOMAIN_NAME}/scan/{scan.domain.project.slug}/history/scan'
	return None


def get_scan_fields(engine, scan, status='RUNNING', tasks=[]):
	tasks_h = '• ' + '\n• '.join(f'`{task.name}`' for task in tasks) if tasks else ''

	# Find scan elapsed time
	duration = None
	if scan and status in ['ABORTED', 'FAILED', 'SUCCESS']:
		td = scan.stop_scan_date - scan.start_scan_date
		duration = humanize.naturaldelta(td)
	elif scan:
		td = timezone.now() - scan.start_scan_date
		duration = humanize.naturaldelta(td)

	# Build fields
	url = get_scan_url(scan)
	fields = {
		'Status': f'**{status}**',
		'Engine': engine.engine_name,
		'Scan ID': f'[#{scan.id}]({url})'
	}

	if duration:
		fields['Duration'] = duration

	fields['Host'] = scan.domain.name
	if tasks:
		fields['Tasks'] = tasks_h

	return fields


def get_task_title(task_name, scan_id=None):
	if scan_id:
		return f'`#{scan_id}` - `{task_name}`'
	return f'`{task_name}` [unbound]'


def get_task_cache_key(func_name, *args, **kwargs):
	args_str = '_'.join([str(arg) for arg in args])
	kwargs_str = '_'.join([f'{k}={v}' for k, v in kwargs.items() if k not in LIMES_TASK_IGNORE_CACHE_KWARGS])
	return f'{func_name}__{args_str}__{kwargs_str}'


def get_output_file_name(scan_history_id, filename):
	return f'#{scan_history_id}_{filename}'


def get_traceback_path(task_name, results_dir, scan_history_id=None):
	path = results_dir
	if scan_history_id:
		path += f'/#{scan_history_id}'
	path += f'-{task_name}.txt'
	return path


def fmt_traceback(exc):
	return '\n'.join(traceback.format_exception(None, exc, exc.__traceback__))


#--------------#
# CLI BUILDERS #
#--------------#

NMAP_ARG = re.compile(r'^[A-Za-z0-9_.,*/:=@+-]+$')  # scripts, script args, flags: one argv element, no shell syntax
NMAP_PORTS = re.compile(r'^[0-9][0-9,-]*$')
NMAP_HOST = re.compile(r'^[A-Za-z0-9_.:\[\]-]+$')


def get_nmap_argv(
		input_file,
		cmd=None,
		host=None,
		ports=None,
		output_file=None,
		script=None,
		script_args=None,
		max_rate=None,
		service_detection=True,
		flags=()):
	"""The nmap argv for one run, or None when any untrusted piece is refused.

	cmd is the engine's custom base command ("nmap -Pn -T4"); it goes through is_valid_nmap_command. Scripts, script
	args, ports, rate, flags, host and input file are checked one by one: the result is executed without a shell, so
	each piece must be a single safe argument (and no host or file may look like an option).
	"""
	try:
		argv = shlex.split(cmd) if cmd else ['nmap']
	except ValueError:
		return None
	if not argv or argv[0] != 'nmap' or not is_valid_nmap_command(shlex.join(argv)):
		logger.error(f'Invalid nmap command or potentially dangerous: {cmd}')
		return None
	if service_detection:
		argv.append('-sV')
	if ports:
		if not NMAP_PORTS.match(str(ports)):
			return None
		argv += ['-p', str(ports)]
	for option, value in (('--script', script), ('--script-args', script_args)):
		if value:
			if not NMAP_ARG.match(str(value)):
				return None
			argv += [option, str(value)]
	if max_rate:
		if not re.fullmatch(r'[0-9]+', str(max_rate)):
			return None
		argv += ['--max-rate', str(max_rate)]
	if output_file:
		argv += ['-oX', str(output_file)]
	for flag in flags or ():
		if flag:
			if not NMAP_ARG.match(str(flag)):
				return None
			argv.append(f'--{flag}')
	if input_file:
		if str(input_file).startswith('-') or any(c.isspace() for c in str(input_file)):
			return None
		argv += ['-iL', str(input_file)]
	elif host:
		if str(host).startswith('-') or not NMAP_HOST.match(str(host)):
			return None
		argv.append(str(host))
	return argv


def create_scan_object(host_id, engine_id, initiated_by_id=None):
	'''
	create task with pending status so that celery task will execute when
	threads are free
	Args:
		host_id: int: id of Domain model
		engine_id: int: id of EngineType model
		initiated_by_id: int : id of User model (Optional)
	'''
	# get current time
	current_scan_time = timezone.now()
	# fetch engine and domain object
	engine = EngineType.objects.get(pk=engine_id)
	domain = Domain.objects.get(pk=host_id)
	scan = ScanHistory()
	scan.scan_status = INITIATED_TASK
	scan.domain = domain
	scan.scan_type = engine
	scan.start_scan_date = current_scan_time
	if initiated_by_id:
		user = User.objects.get(pk=initiated_by_id)
		scan.initiated_by = user
	scan.save()
	# save last scan date for domain model
	domain.start_scan_date = current_scan_time
	domain.save()
	return scan.id


def get_port_service_description(port):
	"""
		Retrieves the standard service name and description for a given port 
		number using whatportis and the builtin socket library as fallback.

		Args:
			port (int or str): The port number to look up. 
				Can be an integer or a string representation of an integer.

		Returns:
			dict: A dictionary containing the service name and description for the port number.
	"""
	logger.info('Fetching Port Service Name and Description')
	try:
		port = int(port)
		whatportis_result = whatportis.get_ports(str(port))
		
		if whatportis_result and whatportis_result[0].name:
			return {
				"service_name": whatportis_result[0].name,
				"description": whatportis_result[0].description
			}
		else:
			try:
				service = socket.getservbyport(port)
				return {
					"service_name": service,
					"description": "" # Keep description blank when using socket
				}
			except OSError:
				# If both whatportis and socket fail
				return {
					"service_name": "",
					"description": ""
				}
	except:
		# port is not a valid int or any other exception
		return {
			"service_name": "",
			"description": ""
		}


def update_or_create_port(port_number, service_name=None, description=None):
	"""
		Updates or creates a new Port object with the provided information to 
		avoid storing duplicate entries when service or description information is updated.

		Args:
			port_number (int): The port number to update or create.
			service_name (str, optional): The name of the service associated with the port.
			description (str, optional): A description of the service associated with the port.

		Returns:
			Tuple: A tuple containing the Port object and a boolean indicating whether the object was created.
	"""
	created = False
	try:
		port = Port.objects.get(number=port_number)
		
		# avoid updating None values in service and description if they already exist
		if service_name is not None and port.service_name != service_name:
			port.service_name = service_name
		if description is not None and port.description != description:
			port.description = description
		port.save()	
	except Port.DoesNotExist:
		# for cases if the port doesn't exist, create a new one
		port = Port.objects.create(
			number=port_number,
			service_name=service_name,
			description=description
		)
		created = True
	finally:
		return port, created
	

def exclude_urls_by_patterns(exclude_paths, urls):
	"""
		Filter out URLs based on a list of exclusion patterns provided from user
		
		Args:
			exclude_patterns (list of str): A list of patterns to exclude. 
			These can be plain path or regex.
			urls (list of str): A list of URLs to filter from.
			
		Returns:
			list of str: A new list containing URLs that don't match any exclusion pattern.
	"""
	logger.info('exclude_urls_by_patterns')
	if not exclude_paths:
		# if no exclude paths are passed and is empty list return all urls as it is
		return urls
	
	compiled_patterns = []
	for path in exclude_paths:
		# treat each path as either regex or plain path
		try:
			raw_pattern = r"{}".format(path)
			compiled_patterns.append(re.compile(raw_pattern))
		except re.error:
			compiled_patterns.append(path)

	filtered_urls = []
	for url in urls:
		exclude = False
		for pattern in compiled_patterns:
			if isinstance(pattern, re.Pattern):
				if pattern.search(url):
					exclude = True
					break
			else:
				if pattern in url: #if the word matches anywhere in url exclude
					exclude = True
					break
		
		# if none conditions matches then add the url to filtered urls
		if not exclude:
			filtered_urls.append(url)

	return filtered_urls
	

def create_inappnotification(
		title,
		description,
		notification_type=SYSTEM_LEVEL_NOTIFICATION,
		project_slug=None,
		icon="mdi-bell",
		is_read=False,
		status='info',
		redirect_link=None,
		open_in_new_tab=False
):
	"""
		This function will create an inapp notification
		Inapp Notification not to be confused with Notification model 
		that is used for sending alerts on telegram, slack etc.
		Inapp notification is used to show notification on the web app

		Args: 
			title: str: Title of the notification
			description: str: Description of the notification
			notification_type: str: Type of the notification, it can be either
				SYSTEM_LEVEL_NOTIFICATION or PROJECT_LEVEL_NOTIFICATION
			project_slug: str: Slug of the project, if notification is PROJECT_LEVEL_NOTIFICATION
			icon: str: Icon of the notification, only use mdi icons
			is_read: bool: Whether the notification is read or not, default is False
			status: str: Status of the notification (success, info, warning, error), default is info
			redirect_link: str: Link to redirect when notification is clicked
			open_in_new_tab: bool: Whether to open the redirect link in a new tab, default is False

		Returns:
			ValueError: if error
			InAppNotification: InAppNotification object if successful
	"""
	logger.info('Creating InApp Notification with title: %s', title)
	if notification_type not in [SYSTEM_LEVEL_NOTIFICATION, PROJECT_LEVEL_NOTIFICATION]:
		raise ValueError("Invalid notification type")
	
	if status not in [choice[0] for choice in NOTIFICATION_STATUS_TYPES]:
		raise ValueError("Invalid notification status")
	
	project = None
	if notification_type == PROJECT_LEVEL_NOTIFICATION:
		if not project_slug:
			raise ValueError("Project slug is required for project level notification")
		try:
			project = Project.objects.get(slug=project_slug)
		except Project.DoesNotExist as e:
			raise ValueError(f"No project exists: {e}")
		
	notification = InAppNotification(
		title=title,
		description=description,
		notification_type=notification_type,
		project=project,
		icon=icon,
		is_read=is_read,
		status=status,
		redirect_link=redirect_link,
		open_in_new_tab=open_in_new_tab
	)
	notification.save()
	return notification




def is_valid_nmap_command(cmd):
	"""
		Check the engine's custom base nmap command ("nmap -Pn -T4"), not the full
		command line: Limes' own pieces (output path, host) are added after this check
		as separate arguments (see get_nmap_argv).
		Args:
			cmd: str: nmap command
		Returns:
			bool: True if valid, False otherwise

		Allowing user input in nmap command is by design
		as user can provide custom nmap command to run
		but we need to make sure that the command is safe
		and doesn't contain any malicious commands
		We do this by checking if the command starts with nmap
		and doesn't contain any dangerous characters, in the most basic form
	"""
	# if this is not a valid command nmap command at all, dont even run it
	if not cmd.strip().startswith('nmap'):
		return False
	
	# check for dangerous chars
	dangerous_chars = {';', '&', '|', '>', '<', '`', '$', '(', ')', '#', '\\'}
	if any(char in cmd for char in dangerous_chars):
		return False
		
	# but we also need to check for flags and options, for example - and -- are allowed
	parts = cmd.split()
	for part in parts[1:]: # ignoring nmap the first part of command
		if part.startswith('-') or part.startswith('--'):
			continue
		
		# check for valid characters, . - etc are allowed in valid nmap command
		if all(c.isalnum() or c in '.,/-_' for c in part):
			continue
		return False
		
	return True