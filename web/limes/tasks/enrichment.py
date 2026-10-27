from limes.tasks.base import *



@app.task(name='remove_duplicate_endpoints', bind=False)
def remove_duplicate_endpoints(
		scan_history_id,
		domain_id,
		subdomain_id=None,
		filter_ids=[],
		filter_status=[200, 301, 404],
		duplicate_removal_fields=ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS
	):
	"""Remove duplicate endpoints.

	Check for implicit redirections by comparing endpoints:
	- [x] `content_length` similarities indicating redirections
	- [x] `page_title` (check for same page title)
	- [ ] Sign-in / login page (check for endpoints with the same words)

	Args:
		scan_history_id: ScanHistory id.
		domain_id (int): Domain id.
		subdomain_id (int, optional): Subdomain id.
		filter_ids (list): List of endpoint ids to filter on.
		filter_status (list): List of HTTP status codes to filter on.
		duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates
	"""
	logger.info(f'Removing duplicate endpoints based on {duplicate_removal_fields}')
	endpoints = (
		EndPoint.objects
		.filter(scan_history__id=scan_history_id)
		.filter(target_domain__id=domain_id)
	)
	if filter_status:
		endpoints = endpoints.filter(http_status__in=filter_status)

	if subdomain_id:
		endpoints = endpoints.filter(subdomain__id=subdomain_id)

	if filter_ids:
		endpoints = endpoints.filter(id__in=filter_ids)

	for field_name in duplicate_removal_fields:
		cl_query = (
			endpoints
			.values_list(field_name)
			.annotate(mc=Count(field_name))
			.order_by('-mc')
		)
		for (field_value, count) in cl_query:
			if count > DELETE_DUPLICATES_THRESHOLD:
				eps_to_delete = (
					endpoints
					.filter(**{field_name: field_value})
					.order_by('discovered_date')
					.all()[1:]
				)
				msg = f'Deleting {len(eps_to_delete)} endpoints [reason: same {field_name} {field_value}]'
				for ep in eps_to_delete:
					url = urlparse(ep.http_url)
					if url.path in ['', '/', '/login']: # try do not delete the original page that other pages redirect to
						continue
					msg += f'\n\t {ep.http_url} [{ep.http_status}] [{field_name}={field_value}]'
					ep.delete()
				logger.warning(msg)
