function get_ips_from_port(port_number, history_id){
	document.getElementById("detailScanModalLabel").innerHTML='IPs with port ' + htmlEncode(port_number) + ' OPEN';
	var ip_badge = '';
	fetch('../port/ip/'+port_number+'/'+history_id+'/')
	.then(response => response.json())
	.then(data => render_ips(data));
}

function get_ports_for_ip(ip, history_id){
	console.log(ip, history_id);
	document.getElementById("detailScanModalLabel").innerHTML='Open Ports identified for ' + htmlEncode(ip);
	var port_badge = '';
	fetch('../ip/ports/'+ip+'/'+history_id+'/')
	.then(response => response.json())
	.then(data => render_ports(data));
}

function render_ports(data)
{
	var port_badge = ''
	ip_address_content = document.getElementById("detailScanModalContent");
	Object.entries(JSON.parse(data)).forEach(([key, value]) => {
		badge_color = value[3] ? 'danger' : 'info';
		title = value[3] ? 'Uncommon Port - ' + value[2] : value[2];
		port_badge += `<span class='m-1 badge  badge-soft-${badge_color} bs-tooltip' title='${htmlEncode(title)}'>${htmlEncode(value[0])}/${htmlEncode(value[1])}</span>`
	});
	ip_address_content.innerHTML = port_badge;
	$('.bs-tooltip').tooltip();
}

function render_ips(data)
{
	var ip_badge = ''
	content = document.getElementById("detailScanModalContent");
	Object.entries(JSON.parse(data)).forEach(([key, value]) => {
		badge_color = value[1] ? 'warning' : 'info';
		title = value[1] ? 'CDN IP Address' : '';
		ip_badge += `<span class='m-1 badge  badge-soft-${badge_color} bs-tooltip' title='${htmlEncode(title)}'>${htmlEncode(value[0])}</span>`
	});
	content.innerHTML = ip_badge;
	$('.bs-tooltip').tooltip();
}


function get_endpoints(project, scan_history_id=null, domain_id=null, gf_tags=null){
	var is_endpoint_grouping = false;
	var endpoint_grouping_col = 6;

	var lookup_url = '/api/listEndpoints/?format=datatables&project=' + project;

	if (scan_history_id) {
		lookup_url += `&scan_history=${scan_history_id}`;
	}
	else if (domain_id) {
		lookup_url += `&target_id=${domain_id}`;
	}

	if (gf_tags){
		lookup_url += `&gf_tag=${encodeURIComponent(gf_tags)}`
	}
	var endpoint_datatable_columns = [
		{'data': 'id'},
		{'data': 'http_url'},
		{'data': 'http_status'},
		{'data': 'page_title'},
		{'data': 'matched_gf_patterns'},
		{'data': 'content_type'},
		{'data': 'content_length', 'searchable': false},
		{'data': 'techs'},
		{'data': 'webserver'},
		{'data': 'response_time', 'searchable': false},
	];
	var endpoint_table = $('#endpoint_results').DataTable({
		"destroy": true,
		"processing": true,
		"oLanguage": {
			"oPaginate": { "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>', "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>' },
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sLengthMenu": "Results :  _MENU_",
			"sProcessing": "Processing... Please wait..."
		},
		"dom": "<'dt--top-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>" +
		"<'table-responsive'tr>" +
		"<'dt--bottom-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>",
		"stripeClasses": [],
		"lengthMenu": [100, 200, 300, 500, 1000],
		"pageLength": 100,
		'serverSide': true,
		"ajax": {
				'url': lookup_url,
		},
		"rowGroup": {
			"startRender": function(rows, group) {
				return htmlEncode(group) + ' (' + rows.count() + ' Endpoints)';
			}
		},
		"order": [[ 6, "desc" ]],
		"columns": endpoint_datatable_columns,
		"columnDefs": [
			{
				"targets": [ 0 ],
				"visible": false,
				"searchable": false,
			},
			{
				"targets": [ 7, 8 ],
				"visible": false,
				"searchable": true,
			},
			{
				"render": function ( data, type, row ) {
					var tech_badge = '';
					var web_server = '';
					if (row['techs']){
						tech_badge = `</br>` + parse_technology(row['techs'], "primary", outline=true);
					}

					if (row['webserver']) {
						web_server = `<span class='m-1 badge badge-soft-info' data-toggle="tooltip" data-placement="top" title="Web Server">${htmlEncode(row['webserver'])}</span>`;
					}

					var url = split_into_lines(data, 70);
					var action_icons = `
					<div class="float-left subdomain-table-action-icons mt-2">
					<span class="m-1">
					<a href="javascript:;" data-clipboard-action="copy" class="badge-link text-primary copyable text-primary" data-toggle="tooltip" data-placement="top" title="Copy Url!" data-clipboard-target="#url-${row['id']}" id="#url-${row['id']}" onclick="setTooltip(this.id, 'Copied!')">
					<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-copy"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></span>
					</a>
					</div>
					`;
					tech_badge += web_server;

					return `<div class="clipboard copy-txt">` + "<a href='"+ safeHref(data) +`' id="url-${row['id']}" target='_blank' class='text-primary'>`+ url +"</a>" + tech_badge + "<br>" + action_icons ;
				},
				"targets": 1,
			},
			{
				"render": function ( data, type, row ) {
					// display badge based on http status
					// green for http status 2XX, orange for 3XX and warning for everything else
					if (data) {
						return get_http_status_badge(data);
					}
					return '';

				},
				"targets": 2,
			},
			{
				"render": function ( data, type, row ) {
					return htmlEncode(data);
				},
				"targets": 3,
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return parse_comma_values_into_span(data, "info");
					}
					return "";
				},
				"targets": 8,
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return parse_comma_values_into_span(data, "danger", outline=true);
					}
					return "";
				},
				"targets": 4,
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return get_response_time_text(data);
					}
					return "";
				},
				"targets": 9,
			},
			// remaining cells (incl. hidden ones) as text
			{"targets": "_all", "render": $.fn.dataTable.render.text()},
		],
		"initComplete": function(settings, json) {
			api = this.api();
			endpoint_datatable_col_visibility(endpoint_table);
			$(".dtrg-group th:contains('No group')").remove();
		},
		"drawCallback": function () {
			$("body").tooltip({ selector: '[data-toggle=tooltip]' });
			// $('.dataTables_wrapper table').removeClass('table-striped');
			$('.badge').tooltip({ template: '<div class="tooltip status" role="tooltip"><div class="arrow"></div><div class="tooltip-inner"></div></div>' })
			$('.dtrg-group').remove();
			$('.bs-tooltip').tooltip();
			var clipboard = new Clipboard('.copyable');
			$('.bs-tooltip').tooltip();
			clipboard.on('success', function(e) {
				setTooltip(e.trigger, 'Copied!');
				hideTooltip(e.trigger);
			});
			drawCallback_api = this.api();
			setTimeout(function() {
				$(".dtrg-group th:contains('No group')").remove();
			}, 1);
		}
	});

	var radioGroup = document.getElementsByName('grouping_endpoint_row');
	radioGroup.forEach(function(radioButton) {
	  radioButton.addEventListener('change', function() {
	    if (this.checked) {
	      var groupRows = document.querySelectorAll('tr.group');
	      // Remove each group row
				var col_index = get_datatable_col_index(this.value, endpoint_datatable_columns);
				api.page.len(-1).draw();
				api.order([col_index, 'asc']).draw();
				endpoint_table.rowGroup().dataSrc(this.value);
	      Snackbar.show({
	        text: 'Endpoints grouped by ' + this.value,
	        pos: 'top-right',
	        duration: 2500
	      });
	    }
	  });
	});

	$('#endpoint-search-button').click(function () {
		endpoint_table.search($('#endpoints-search').val()).draw() ;
	});
	$('input[name=end_http_status_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(2).visible(true);
		} else {
			endpoint_table.column(2).visible(false);
		}
		window.localStorage.setItem('end_http_status_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_page_title_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(3).visible(true);
		} else {
			endpoint_table.column(3).visible(false);
		}
		window.localStorage.setItem('end_page_title_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_tags_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(4).visible(true);
		} else {
			endpoint_table.column(4).visible(false);
		}
		window.localStorage.setItem('end_tags_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_content_type_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(5).visible(true);
		} else {
			endpoint_table.column(5).visible(false);
		}
		window.localStorage.setItem('end_content_type_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_content_length_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(6).visible(true);
		} else {
			endpoint_table.column(6).visible(false);
		}
		window.localStorage.setItem('end_content_length_filter_checkbox', $(this).is(':checked'));
	});
	$('input[name=end_response_time_filter_checkbox]').change(function() {
		if ($(this).is(':checked')) {
			endpoint_table.column(9).visible(true);
		} else {
			endpoint_table.column(9).visible(false);
		}
		window.localStorage.setItem('end_response_time_filter_checkbox', $(this).is(':checked'));
	});
}

function get_subdomain_changes(scan_history_id){
	$('#table-subdomain-changes').DataTable({
		"drawCallback": function(settings, start, end, max, total, pre) {
			if (this.fnSettings().fnRecordsTotal() > 0) {
				$('#subdomain_change_count').empty();
				$("#subdomain_change_count").html(`<span class="badge badge-soft-primary me-1">${this.fnSettings().fnRecordsTotal()}</span>`);
				$('.recon-changes-tab-show').removeAttr('style');
				$('#subdomain_changes_alert').html(`${this.fnSettings().fnRecordsTotal()} Subdomain changes.`)
			}
			else{
				$('#recon_changes_subdomain_div').remove();
			}
			$("#subdomain-changes-loader").remove();
		},
		"oLanguage": {
			"oPaginate": { "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>', "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>' },
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
			"sSearchPlaceholder": "Search...",
			"sLengthMenu": "Results :  _MENU_",
		},
		"processing": true,
		"dom": "<'dt--top-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>" +
		"<'table-responsive'tr>" +
		"<'dt--bottom-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>",
		"destroy": true,
		"stripeClasses": [],
		'serverSide': true,
		"ajax": `/api/listSubdomainChanges/?scan_id=${scan_history_id}&format=datatables`,
		"order": [[ 3, "desc" ]],
		"columns": [
			{'data': 'name'},
			{'data': 'page_title'},
			{'data': 'http_status'},
			{'data': 'content_length'},
			{'data': 'change'},
			{'data': 'http_url'},
			{'data': 'is_cdn'},
			{'data': 'is_interesting'},
		],
		"bInfo": false,
		"columnDefs": [
			{
				"targets": [ 5, 6, 7 ],
				"visible": false,
				"searchable": false,
			},
			{"className": "text-center", "targets": [ 2, 4 ]},
			{
				"render": function ( data, type, row ) {
					badges = '';
					cdn_badge = '';
					tech_badge = '';
					interesting_badge = '';
					if (row['is_cdn'])
					{
						cdn_badge = "<span class='m-1 badge  badge-soft-warning'>CDN</span>"
					}
					if(row['is_interesting'])
					{
						interesting_badge = "<span class='m-1 badge  badge-soft-danger'>Interesting</span>"
					}
					if(cdn_badge || interesting_badge)
					{
						badges = cdn_badge + interesting_badge + '</br>';
					}
					if (row['http_url']) {
						if (row['cname']) {
							return badges + `<a href="`+safeHref(row['http_url'])+`" class="text-primary" target="_blank">`+htmlEncode(data)+`</a><br><span class="text-dark">CNAME<br><span class="text-warning"> ❯ </span>` + row['cname'].split(',').map(htmlEncode).join('<br><span class="text-warning"> ❯ </span>')+`</span>`;
						}
						return badges + `<a href="`+safeHref(row['http_url'])+`" class="text-primary" target="_blank">`+htmlEncode(data)+`</a>`;
					}
					return badges + `<a href="https://`+htmlEncode(data)+`" class="text-primary" target="_blank">`+htmlEncode(data)+`</a>`;
				},
				"targets": 0
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return htmlEncode(data);
					}
					return "";
				},
				"targets": 1,
			},
			{
				"render": function ( data, type, row ) {
					// display badge based on http status
					// green for http status 2XX, orange for 3XX and warning for everything else
					if (data >= 200 && data < 300) {
						return "<span class='badge  badge-soft-success'>"+data+"</span>";
					}
					else if (data >= 300 && data < 400) {
						return "<span class='badge  badge-soft-warning'>"+data+"</span>";
					}
					else if (data == 0){
						// datatable throws error when no data is returned
						return "";
					}
					return `<span class='badge  badge-soft-danger'>`+data+`</span>`;
				},
				"targets": 2,
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return `<span class='text-center' style="display:block; text-align:center; margin:0 auto;">${htmlEncode(data)}</span>`;
					}
					return "";
				},
				"targets": 3,
			},
			{
				"render": function ( data, type, row ) {
					if (data == 'added'){
						return `<span class='badge badge-soft-success'><i class="fe-plus-circle"></i> Added</span>`;
					}
					else{
						return `<span class='badge badge-soft-danger'><i class="fe-minus-circle"></i> Removed</span>`;
					}
				},
				"targets": 4,
			},
			// remaining cells (incl. hidden ones) as text
			{"targets": "_all", "render": $.fn.dataTable.render.text()},
		],
	});
}

function get_endpoint_changes(scan_history_id){
	$('#table-endpoint-changes').DataTable({
		"drawCallback": function(settings, start, end, max, total, pre) {
			if (this.fnSettings().fnRecordsTotal() > 0) {
				$("#endpoint_change_count").empty();
				$("#endpoint_change_count").html(`${this.fnSettings().fnRecordsTotal()}`);
				$('.recon-changes-tab-show').removeAttr('style');
			}
			else{
				$("#endpoint-changes-div").remove();
			}
			$("#endpoint-changes-loader").remove();
		},
		"oLanguage": {
			"oPaginate": { "sPrevious": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-left"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>', "sNext": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-arrow-right"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>' },
			"sInfo": "Showing page _PAGE_ of _PAGES_",
			"sSearch": '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
			"sSearchPlaceholder": "Search...",
			"sLengthMenu": "Results :  _MENU_",
		},
		"processing": true,
		"dom": "<'dt--top-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>" +
		"<'table-responsive'tr>" +
		"<'dt--bottom-section'<'row'<'col-12 mb-3 mb-sm-0 col-sm-4 col-md-3 col-lg-4 d-flex justify-content-sm-start justify-content-center'l><'dt--pages-count col-12 col-sm-6 col-md-4 col-lg-4 d-flex justify-content-sm-middle justify-content-center'i><'dt--pagination col-12 col-sm-2 col-md-5 col-lg-4 d-flex justify-content-sm-end justify-content-center'p>>>",
		"destroy": true,
		"stripeClasses": [],
		'serverSide': true,
		"ajax": `/api/listEndPointChanges/?scan_id=${scan_history_id}&format=datatables`,
		"order": [[ 3, "desc" ]],
		"columns": [
			{'data': 'http_url'},
			{'data': 'page_title'},
			{'data': 'http_status'},
			{'data': 'content_length'},
			{'data': 'change'},
		],
		"bInfo": false,
		"columnDefs": [
			{"className": "text-center", "targets": [ 2 ]},
			{
				"render": function ( data, type, row ) {
					var url = split_into_lines(data, 70);
					return "<a href='"+safeHref(data)+"' target='_blank' class='text-primary'>"+url+"</a>";
				},
				"targets": 0
			},
			{
				"render": function ( data, type, row ) {
					if (data){
						return htmlEncode(data);
					}
					return "";
				},
				"targets": 1,
			},
			{
				"render": function ( data, type, row ) {
					// display badge based on http status
					// green for http status 2XX, orange for 3XX and warning for everything else
					if (data >= 200 && data < 300) {
						return "<span class='badge  badge-soft-success'>"+data+"</span>";
					}
					else if (data >= 300 && data < 400) {
						return "<span class='badge  badge-soft-warning'>"+data+"</span>";
					}
					else if (data == 0){
						// datatable throws error when no data is returned
						return "";
					}
					return `<span class='badge  badge-soft-danger'>`+data+`</span>`;
				},
				"targets": 2,
			},
			{
				"render": function ( data, type, row ) {
					if (data == 'added'){
						return `<span class='badge badge-soft-success'><i class="fe-plus-circle"></i> Added</span>`;
					}
					else{
						return `<span class='badge badge-soft-danger'><i class="fe-minus-circle"></i> Removed</span>`;
					}
				},
				"targets": 4,
			},
			// remaining cells (incl. hidden ones) as text
			{"targets": "_all", "render": $.fn.dataTable.render.text()},
		],
	});
}

function get_screenshot(scan_id){
	var port_array = [];
	var service_array = [];
	var tech_array = [];
	var ip_array = [];
	var gridzyElement = document.querySelector('.gridzy');
	gridzyElement.classList.add('gridzySkinBlank');
	gridzyElement.setAttribute('data-gridzy-layout', 'waterfall');
	gridzyElement.setAttribute('data-gridzy-spaceBetween', 10);
	gridzyElement.setAttribute('data-gridzy-desiredwidth', 350);
	gridzyElement.setAttribute('data-gridzySearchField', "#screenshot-search");
	var interesting_badge = `<span class="m-1 float-end badge  badge-soft-danger">Interesting</span>`;
	// filter class tokens and option values are built from scan data: keep them to word chars so a quote or space cannot break the selector
	const filter_token = v => String(v).replace(/[^\w-]/g, '_');
	$.getJSON(`/api/listSubdomains/?scan_id=${scan_id}&no_page&only_screenshot`, function(data) {
		$("#screenshot-loader").remove();
		$("#filter-screenshot").show();
		for (var subdomain in data) {
			var figure = document.createElement('figure');
			var link = document.createElement('a');
			// return `<a href="/media/`+data+`" data-lightbox="screenshots" data-title="&lt;a target='_blank' href='`+row['http_url']+`'&gt;&lt;h3 style=&quot;color:white&quot;&gt;`+row['name']+`&lt;/h3&gt;&lt;/a&gt;"><img src="/media/`+data+`" class="img-fluid rounded mb-4 mt-4 screenshot" onerror="removeImageElement(this)"></a>`;
			// currently lookup is supported only for http_status, page title & subdomain name,
			interesting_field = data[subdomain]['is_interesting'] ? 'interesting' : '';
			var ips = data[subdomain]['ip_addresses'];
			var ip_search_values = '';
			for(var ip in ips){
				ip_address = ips[ip]['address'];
				ip_search_values += ip_address + ' ';
			}
			search_field = `${data[subdomain]['page_title']} ${data[subdomain]['name']} ${data[subdomain]['http_status']} ${ip_search_values} ${interesting_field}`;
			link.setAttribute('data-lightbox', 'screenshot-gallery')
			link.setAttribute('href', '/media/' + data[subdomain]['screenshot_path'])
			link.setAttribute('data-title', `<a target='_blank' href='`+safeHref(data[subdomain]['http_url'])+`'><h3 style="color:white">`+htmlEncode(data[subdomain]['name'])+`</h3></a>`);
			link.classList.add('img-fluid');
			link.classList.add('rounded');
			link.classList.add('screenshot-gallery');
			link.classList.add('mb-4');
			link.classList.add('mt-4');
			link.setAttribute('data-gridzySearchText', search_field);
			var newImage = document.createElement('img');
			newImage.setAttribute('data-gridzylazysrc', '/media/' + data[subdomain]['screenshot_path']);
			// newImage.setAttribute('data-gridzylazysrc', 'https://placeimg.com/1440/900/any?' + subdomain);
			newImage.setAttribute('height', 500);
			newImage.setAttribute('width', 500);
			newImage.setAttribute('class', 'gridzyImage');
			var figcaption = document.createElement('figcaption');
			figcaption.setAttribute('class', 'gridzyCaption');
			http_status_badge = 'danger';
			if (data[subdomain]['http_status'] >=200 && data[subdomain]['http_status'] < 300){
				http_status_badge = 'success';
			}
			else if (data[subdomain]['http_status'] >=300 && data[subdomain]['http_status'] < 400){
				http_status_badge = 'warning';
			}
			page_title = data[subdomain]['page_title'] ? htmlEncode(data[subdomain]['page_title']) + '</br>': '' ;
			subdomain_link = data[subdomain]['http_url'] ? `<a href="${safeHref(data[subdomain]['http_url'])}" target="_blank">${htmlEncode(data[subdomain]['name'])}</a>` : `<a href="https://${htmlEncode(data[subdomain]['name'])}" target="_blank">${htmlEncode(data[subdomain]['name'])}</a>`
			http_status = data[subdomain]['http_status'] ? `<span class="m-1 float-end badge  badge-soft-${http_status_badge}">${htmlEncode(data[subdomain]['http_status'])}</span>` : '';
			figcaption.innerHTML = data[subdomain]['is_interesting'] ? page_title + subdomain_link + interesting_badge + http_status : page_title + subdomain_link + http_status;
			figure.appendChild(figcaption);
			link.appendChild(newImage);
			link.appendChild(figure);
			gridzyElement.appendChild(link);

			// add http status to filter values
			filter_values = 'http_' + filter_token(data[subdomain]['http_status']) + ' ';

			// dynamic filtering menu
			http_status = data[subdomain]['http_status'];
			http_status_select = document.getElementById('http_select_filter');
			if(![...http_status_select.options].some(o => o.textContent === String(http_status))){
				var option = document.createElement('option');
				option.value = ".http_" + filter_token(http_status);
				option.textContent = http_status;
				http_status_select.appendChild(option);
			}

			// ip, port and services filtering
			ips = data[subdomain]['ip_addresses']
			for(var ip in ips){
				ip_address = ips[ip]['address'];
				filter_values += 'ip_' + filter_token(ip_address) + ' ';
				if (ip_array.indexOf(ip_address) === -1){
					ip_array.push(ip_address);
				}

				ports = ips[ip]['ports'];
				for(var port in ports){
					port_number = ips[ip]['ports'][port]['number'];
					service_name = ips[ip]['ports'][port]['service_name'];

					filter_values += 'port_' + filter_token(port_number) + ' ';
					if (port_array.indexOf(port_number) === -1){
						port_array.push(port_number);
					}

					filter_values += 'service_' + filter_token(service_name) + ' ';
					if (service_array.indexOf(service_name) === -1){
						service_array.push(service_name);
					}
				}
			}

			// technology stack filtering
			technology = data[subdomain]['technologies'];
			for(var tech in technology){
				tech_name = technology[tech]['name']
				filter_values += 'tech_' + filter_token(tech_name.toLowerCase()) + ' ';
				if (tech_array.indexOf(tech_name) === -1){
					tech_array.push(tech_name);
				}

			}

			link.setAttribute('class', filter_values);
		}

		// add port and service and tech to options
		port_select = document.getElementById('ports_select_filter');
		if (port_select) {
			port_array.sort((a, b) => a - b);
			for(var port in port_array){
				if(![...port_select.options].some(o => o.textContent === String(port_array[port]))){
					var option = document.createElement('option');
					option.value = ".port_" + filter_token(port_array[port]);
					option.textContent = port_array[port];
					port_select.appendChild(option);
				}
			}
		}

		// add ip to select
		ip_select = document.getElementById('ips_select_filter');
		for(var ip in ip_array){
			if(![...ip_select.options].some(o => o.textContent === ip_array[ip])){
				var option = document.createElement('option');
				option.value = ".ip_" + filter_token(ip_array[ip]);
				option.textContent = ip_array[ip];
				ip_select.appendChild(option);
			}
		}

		service_array.sort();
		service_select = document.getElementById('services_select_filter');
		if (service_select) {
			for(var service in service_array){
				if(![...service_select.options].some(o => o.textContent === service_array[service])){
					var option = document.createElement('option');
					option.value = ".service_" + filter_token(service_array[service]);
					option.textContent = service_array[service];
					service_select.appendChild(option);
				}
			}
		}

		tech_select = document.getElementById('tech_select_filter');
		for(var tech in tech_array){
			if(![...tech_select.options].some(o => o.textContent === tech_array[tech])){
				var option = document.createElement('option');
				option.value = ".tech_" + filter_token(tech_array[tech].toLowerCase());
				option.textContent = tech_array[tech];
				tech_select.appendChild(option);
			}
		}

		$(".tagging").select2({
			tags: true
		});
		// search functionality
		var gridzyElements = document.querySelectorAll('.gridzySkinBlank[data-gridzySearchField]'),
		pos = gridzyElements.length;

		while (pos--) {
			(function(gridzyElement) {
				var searchField = document.querySelector(gridzyElement.getAttribute('data-gridzySearchField'));
				var gridzyInstance = gridzyElement.gridzy;
				var gridzyItems = gridzyElement.children;

				if (searchField) {
					searchField.addEventListener('input', search);
				}

				function search() {
					var pos = gridzyItems.length,
					child,
					itemContent,
					found = false,
					searchValue = searchField.value.toLowerCase();

					if (searchValue) {
						while (pos--) {
							child = gridzyItems[pos];
							itemContent = (child.getAttribute('data-gridzySearchText') || child.innerText).toLowerCase();
							found = -1 < itemContent.search(searchValue);
							child.classList[found ? 'add' : 'remove']('searchResult');
						}
						if (gridzyInstance.getOption('filter') !== '.searchResult') {
							gridzyInstance.setOptions({filter:'.searchResult'});
						}
					} else {
						while (pos--) {
							gridzyItems[pos].classList.remove('searchResult');
						}
						if (gridzyInstance.getOption('filter') !== Gridzy.getDefaultOption('filter')) {
							gridzyInstance.setOptions({filter:null});
						}
					}
				}
			})(gridzyElements[pos]);
		}

		//filter functionality
		var gridzyInstance = document.querySelector('.gridzySkinBlank').gridzy;
		$('#http_select_filter, #ips_select_filter, #services_select_filter, #ports_select_filter, #tech_select_filter').on('change', function() {
			values = $(this).val();
			console.log(values);
			if(values.length){
				gridzyInstance.setOptions({
					filter: values
				});
			}
			else{
				gridzyInstance.setOptions({
					filter: '*'
				});
			}
		});
	});
}

function get_vulnerability_modal(scan_id=null, severity=null, subdomain_id=null, subdomain_name=null){
	var url = `/api/listVulnerability/?&format=json`;

	if (scan_id) {
		url += `&scan_history=${scan_id}`;
	}

	if (severity != null) {
		url += `&severity=${severity}`;
	}

	if (subdomain_id) {
		url += `&subdomain_id=${subdomain_id}`;
	}


	// else{
	// 	url = `/api/listVulnerability/?severity=${severity}&subdomain_name=${subdomain_name}&format=json`;
	// }
	switch (severity) {
		case 0:
		severity_title = 'Informational'
		break;
		case 1:
		severity_title = 'Low'
		break;
		case 2:
		severity_title = 'Medium'
		break;
		case 3:
		severity_title = 'High'
		break;
		case 4:
		severity_title = 'Critical'
		break;
		default:
		severity_title = ''
	}

	$('#xl-modal-title').empty();
	$('#xl-modal-content').empty();
	$('#xl-modal-footer').empty();

	Swal.fire({
		title: `Fetching ${severity_title} vulnerabilities for ${htmlEncode(subdomain_name)}...`
	});
	swal.showLoading();

	fetch(url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
	}).then(response => response.json()).then(function(response) {
		console.log(response);
		swal.close();
		$('#xl-modal_title').html(`${htmlEncode(subdomain_name)}`);
		render_vulnerability_in_xl_modal(response['count'], subdomain_name, response['results'])
	});
	$('#modal_xl_scroll_dialog').modal('show');
	$("body").tooltip({
		selector: '[data-toggle=tooltip]'
	});

}


function get_endpoint_modal(project, scan_id, subdomain_id, subdomain_name){
	// This function will display a xl modal with datatable for displaying endpoints
	// associated with the subdomain
	$('#xl-modal-title').empty();
	$('#xl-modal-content').empty();
	$('#xl-modal-footer').empty();

	if (scan_id) {
		url = `/api/listEndpoints/?project=${project}&scan_id=${scan_id}&subdomain_id=${subdomain_id}&format=json`
	}
	else{
		url = `/api/listEndpoints/?project=${project}&subdomain_id=${subdomain_id}&format=json`
	}

	Swal.fire({
		title: `Fetching Endpoints for ${htmlEncode(subdomain_name)}...`
	});
	swal.showLoading();

	fetch(url, {
		method: 'GET',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
	}).then(response => response.json()).then(function(response) {
		console.log(response);
		swal.close();
		$('#xl-modal_title').html(`${htmlEncode(subdomain_name)}`);
		render_endpoint_in_xlmodal(response['count'], subdomain_name, response['results'])
	});
	$('#modal_xl_scroll_dialog').modal('show');
	$("body").tooltip({
		selector: '[data-toggle=tooltip]'
	});

}

function create_log_element(log) {
	// command and output come from scan tools (incl. host responses): set as text, never parsed as markup
	let logElement = document.createElement("p");
	let command = document.createElement("p");
	command.className = "text-primary";
	command.setAttribute("data-bs-toggle", "collapse");
	command.setAttribute("data-bs-target", "#collapse" + log.id);
	command.innerHTML = '<i class="fe-terminal"></i>';
	command.append(log.command || '');
	logElement.appendChild(command);
	if (log.output){
		let collapse = document.createElement("div");
		collapse.className = "collapse";
		collapse.id = "collapse" + log.id;
		let output = document.createElement("code");
		output.style.whiteSpace = "pre-line";
		output.className = "card card-body";
		output.textContent = log.output;
		collapse.appendChild(output);
		logElement.appendChild(collapse);
	}
	return logElement;
}

function get_logs_modal(scan_id=null, activity_id=null) {

	// This function will display a xl modal with datatable for displaying endpoints
	// associated with the subdomain
	$('#xl-modal-title').empty();
	$('#xl-modal-content').empty();
	$('#xl-modal-footer').empty();

	if (scan_id) {
		url = `/api/listScanLogs?scan_id=${scan_id}&format=json`
		title = `Fetching logs for scan ${scan_id}`
	}
	else{
		url = `/api/listActivityLogs?activity_id=${activity_id}&format=json`
		title = `Fetching logs for activity ${activity_id}`
	}

	Swal.fire({
		title: title
	});
	swal.showLoading();

	// Get the initial logs
	fetch(url)
	.then(response => response.json())
	.then(data => {
		console.log(data);
		swal.close();
		$('#xl-modal_title').html(`Logs for scan #${scan_history_id}`);
		data.results.forEach(log => {
			$('#xl-modal-content').append(create_log_element(log));
		})
	});
	$('#modal_xl_scroll_dialog').modal('show');
	$("body").tooltip({
		selector: '[data-toggle=tooltip]'
	});
}

function download_subdomains(scan_id=null, domain_id=null, domain_name=null){
	Swal.fire({
		title: 'Querying Subdomains...'
	});
	swal.showLoading();
	count = `<span class="modal_count"></span>`;
	var url = `/api/querySubdomains?format=json&no_lookup_interesting`;
	if (scan_id) {
		url += `&scan_id=${scan_id}`;
	}
	else if(domain_id){
		url += `&target_id=${domain_id}`;
	}

	if (domain_name) {
		$('.modal-title').html(count + ' Subdomains for : <b>' + htmlEncode(domain_name) + '</b>');
	}
	else{
		$('.modal-title').html(count + ' Subdomains');
	}

	$('.modal-text').empty(); $('#modal-footer').empty();
	$('.modal-text').append(`<div class='outer-div' id="modal-loader"></div>`);
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close();
		if (data['subdomains'].length) {
			$('#modal_dialog').modal('show');
			$('.modal_count').html(data['subdomains'].length);
			$('#modal-content').empty();
			subdomains = '';
			$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="all_subdomains_text_area" rows="10" spellcheck="false"></textarea>`);
			for (subdomain in data['subdomains']){
				subdomain_obj = data['subdomains'][subdomain];
				subdomains += subdomain_obj['name'] + '\n'
			}
			$('#all_subdomains_text_area').val(subdomains);
			$("#modal-footer").empty();
			$("#modal-footer").append(`<a href="javascript:download('subdomains-${jsEscape(domain_name)}.txt', subdomains);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a>`);
			$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#all_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`);
		}
		else{
			swal.fire("No Subdomains", "Could not find any subdomains.", "warning", {
				button: "Okay",
			});
		}
	}).fail(function(){
		swal.fire("No Subdomains", "Could not find any subdomains.", "warning", {
			button: "Okay",
		});
	});
}

function download_interesting_subdomains(project, scan_id=null, domain_id=null, domain_name=null){
	Swal.fire({
		title: 'Querying Interesting Subdomains...'
	});
	swal.showLoading();
	count = `<span class="modal_count"></span>`;
	var url = `/api/queryInterestingSubdomains/?format=json&project=${project}`;
	if (scan_id) {
		url += `&scan_id=${scan_id}`;
	}
	else if(domain_id){
		url += `&target_id=${domain_id}`;
	}

	if (domain_name) {
		$('.modal-title').html( count + ' Interesting Subdomains for : <b>' + htmlEncode(domain_name) + '</b>');
	}
	else{
		$('.modal-title').html( count + ' Interesting Subdomains');
	}
	$('.modal-text').empty(); $('#modal-footer').empty();
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close()
		if (data.length) {
			$('#modal_dialog').modal('show');
			$('.modal_count').html(data.length);
			$('#modal-content').empty();
			subdomains = '';
			$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="interesting_subdomains_text_area" rows="10" spellcheck="false"></textarea>`);
			for (subdomain in data){
				subdomains += data[subdomain]['name'] + '\n'
			}
			$('#interesting_subdomains_text_area').val(subdomains);
			$("#modal-footer").empty();
			$("#modal-footer").append(`<a href="javascript:download('interesting_subdomains-${jsEscape(domain_name)}.txt', subdomains);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a>`);
			$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#interesting_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`);
		}
		else{
			swal.fire("No Interesting Subdomains", "Could not find any interesting subdomains.", "warning", {
				button: "Okay",
			});
		}

	}).fail(function(){
		swal.fire("No Interesting Subdomains", "Could not find any interesting subdomains.", "warning", {
			button: "Okay",
		});
	});
}

function download_interesting_endpoints(scan_id, domain_name){
	Swal.fire({
		title: 'Querying Interesting Endpoints...'
	});
	swal.showLoading();
	count = `<span class="modal_count"></span>`;
	if (scan_id) {
		url = `/api/listInterestingEndpoints/?scan_id=${scan_id}&format=json&no_page`;
	}
	else{
		url = `/api/listInterestingEndpoints/?format=json&no_page`;
	}
	if (domain_name) {
		$('.modal-title').html( count + ' Interesting Endpoints for : <b>' + htmlEncode(domain_name) + '</b>');
	}
	else{
		$('.modal-title').html( count + ' Interesting Endpoints');
	}
	$('.modal-text').empty(); $('#modal-footer').empty();
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close();
		if (data.length) {
			$('#modal_dialog').modal('show');
			$('.modal_count').html(data.length);
			$('#modal-content').empty();
			endpoints = '';
			$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="interesting_endpoints_text_area" rows="10" spellcheck="false"></textarea>`);
			for (endpoint in data){
				endpoints += data[endpoint]['http_url'] + '\n'
			}
			$('#interesting_endpoints_text_area').val(endpoints);
			$("#modal-footer").empty();
			$("#modal-footer").append(`<a href="javascript:download('interesting_endpoints-${jsEscape(domain_name)}.txt', endpoints);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Endpoints as txt</a>`);
			$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Endpoints!" data-clipboard-target="#interesting_endpoints_text_area"><i class="fe-copy me-1"></i> Copy Endpoints</a>`);
		}
		else{
			swal.fire("No Interesting Endpoints", "Could not find any interesting Endpoints.", "warning", {
				button: "Okay",
			});
		}

	}).fail(function(){
		swal.fire("No Interesting Endpoints", "Could not find any interesting Endpoints.", "warning", {
			button: "Okay",
		});
	});
}


function download_important_subdomains(scan_id=null, domain_id=null, domain_name=null){
	Swal.fire({
		title: 'Querying Interesting Subdomains...'
	});
	swal.showLoading();
	count = `<span class="modal_count"></span>`;
	var url = `/api/querySubdomains?format=json&no_lookup_interesting&only_important`;
	if (scan_id) {
		url = `/api/querySubdomains?format=json&no_lookup_interesting&only_important&scan_id=${scan_id}`;
	}
	else if (domain_id){
		url = `/api/querySubdomains?format=json&no_lookup_interesting&only_important&target_id=${domain_id}`;
	}
	if (domain_name) {
		$('.modal-title').html(count + ' Subdomains marked as important : <b>' + htmlEncode(domain_name) + '</b>');
	}
	else{
		$('.modal-title').html(count + ' Subdomains marked as important');
	}
	$('.modal-text').empty(); $('#modal-footer').empty();
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close();
		if (data['subdomains'].length) {
			$('#modal_dialog').modal('show');
			$('.modal_count').html(data['subdomains'].length);
			$('#modal-content').empty();
			subdomains = '';
			$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="all_subdomains_text_area" rows="10" spellcheck="false"></textarea>`);
			for (subdomain in data['subdomains']){
				subdomain_obj = data['subdomains'][subdomain];
				subdomains += subdomain_obj['name'] + '\n'
			}
			$('#all_subdomains_text_area').val(subdomains);
			$("#modal-footer").empty();
			$("#modal-footer").append(`<a href="javascript:download('important-subdomains-${jsEscape(domain_name)}.txt', subdomains);" class="m-1 btn btn-primary copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a>`);
			$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-dark copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#all_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`);
		}
		else{
			swal.fire("No Important Endpoints", "No subdomains has been marked as important.", "warning", {
				button: "Okay",
			});
		}
	}).fail(function(){
		swal.fire("No Important Endpoints", "No subdomains has been marked as important.", "warning", {
			button: "Okay",
		});
	});
}

function download_endpoints(scan_id=null, domain_id=null, domain_name='', pattern=null){
	Swal.fire({
		title: 'Querying Endpoints...'
	});
	swal.showLoading();
	var count = `<span class="modal_count">Loading... </span>`;

	var url = `/api/queryEndpoints/?format=json&only_urls`;

	if (scan_id) {
		url += `&scan_id=${scan_id}`;
	}
	else if (domain_id) {
		url += `&target_id=${domain_id}`;
	}

	if (pattern) {
		url += `&pattern=${encodeURIComponent(pattern)}`;
	}

	if (domain_name) {
		$('.modal-title').html( count + ' Endpoints for : <b>' + htmlEncode(domain_name) + '</b>');
	}
	else{
		$('.modal-title').html(count + ' Endpoints');
	}
	$('.modal-text').empty(); $('#modal-footer').empty();
	// query subdomains
	$.getJSON(url, function(data) {
		swal.close();
		$('#modal_dialog').modal('show');
		$('.modal_count').html(data['endpoints'].length);
		$('#modal-content').empty();
		endpoints = '';
		$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="all_endpoints_text_area" rows="10" spellcheck="false"></textarea>`);
		for (endpoint in data['endpoints']){
			endpoint_obj = data['endpoints'][endpoint];
			endpoints += endpoint_obj['http_url'] + '\n'
		}
		$('#all_endpoints_text_area').val(endpoints);
		$("#modal-footer").empty();
		if (domain_name) {
			$("#modal-footer").append(`<a href="javascript:download('endpoints-${jsEscape(domain_name)}.txt', endpoints);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Endpoints as txt</a>`);
		}
		else{
			$("#modal-footer").append(`<a href="javascript:download('endpoints-all.txt', endpoints);" class="m-1 btn btn-primary copyable float-end btn-md"><i class="fe-download me-1"></i> Download Endpoints as txt</a>`);
		}
		$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#all_endpoints_text_area"><i class="fe-copy me-1"></i> Copy Endpoints</a>`);
	}).fail(function(){
	});
}

function initiate_subscan(subdomain_ids){
	var engine_id = $('#subtaskScanEngine').val();
	var tasks = []
	var $engine_tasks = $('#engineTasks').find('input')
	$engine_tasks.each(function(i){
		if ($(this).is(':checked')){
			tasks.push(this.id)
		}
	})
	console.log(tasks)
	if (tasks.length === 0) {
		Swal.fire({
			title: 'Oops!',
			text: 'No subtasks selected. Please choose at least one subtask !',
			icon: 'error'
		});
		return;
	}
	var data = {
		'subdomain_ids': subdomain_ids,
		'tasks': tasks,
		'engine_id': engine_id,
	};
	Swal.fire({
		title: 'Initiating subtask...',
		allowOutsideClick: false
	});
	swal.showLoading();
	fetch('/api/action/initiate/subtask/', {
		method: 'POST',
		credentials: "same-origin",
		headers: {
			"X-CSRFToken": getCookie("csrftoken"),
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(data)
	})
	.then(response => response.json())
	.then(function (response) {
		swal.close();
		if (response['status']) {
			Snackbar.show({
				text: 'Subtask initiated successfully!',
				pos: 'top-right',
				duration: 2500
			});
		}
		else{
			Swal.fire({
				title:  'Could not initiate subtask!',
				icon: 'fail',
			});
		}
	});

}


// initiate sub scan
$('#btn-initiate-subtask').on('click', function(){
	$('#subscan-modal').modal('hide');
	if ($('#btn-initiate-subtask').attr('multiple-subscan') === 'true') {
		var subdomain_item = document.getElementsByClassName("subdomain_checkbox");
		var subdomain_ids = [];
		for (var i = 0; i < subdomain_item.length; i++) {
			if (subdomain_item[i].checked) {
				subdomain_ids.push($(subdomain_item[i]).val());
			}
		}
		initiate_subscan(subdomain_ids);
	}
	else{
		var subdomain_id = $('#subtask_subdomain_id').val();
		initiate_subscan([subdomain_id]);
	}
});


// Load engine tasks on modal load and engine input change
function load_engine_tasks(engine_name){
	var tasks = []
	var html = ''
	var url = `/api/listEngines/?format=json`;
	console.log(url);
	$.getJSON(url, function(data) {
		console.log(data);
		var engines = data.engines
		console.log(engines);
		console.log(engine_name);
		$.each(engines, function(i, engine){
			console.log(`${engine.engine_name} == ${engine_name}`)
			if (engine.engine_name === engine_name){
				tasks = engine.tasks
				console.log(tasks)
			}
		})
		$.each(tasks, function(i, task){
			html += `
			<div class="mt-1">
				<div class="form-check">
					<input type="checkbox" class="form-check-input" id="${htmlEncode(task)}">
					<label class="form-check-label" for="${htmlEncode(task)}">${htmlEncode(task)}</label>
				</div>
			</div>`
		});
		console.log(html)
		$('#engineTasks').html(html);
	})
}

$('#subscan-modal').on('shown.bs.modal', function () {
	var engine_name = $('#subtaskScanEngine option:selected').text();
	load_engine_tasks(engine_name);
})

$('#subtaskScanEngine').on('change', function(){
	var engine_name = $('#subtaskScanEngine option:selected').text();
	load_engine_tasks(engine_name);
})

// download subdomains
function downloadSelectedSubdomains(domain_name){
	if (!checkedCount()) {
		Swal.fire({
			title: 'Oops! No Subdomains has been selected!',
			icon: 'error',
			padding: '2em'
		})
	} else {
		Swal.fire({
			title: 'Querying Selected Subdomains...'
		});
		swal.showLoading();

		subdomain_item = document.getElementsByClassName("subdomain_checkbox");
		var subdomain_ids = [];
		for (var i = 0; i < subdomain_item.length; i++) {
			if (subdomain_item[i].checked) {
				subdomain_ids.push($(subdomain_item[i]).val());
			}
		}
		var data = {'subdomain_ids': subdomain_ids};
		fetch('/api/querySubdomains/', {
			method: 'POST',
			credentials: "same-origin",
			headers: {
				"X-CSRFToken": getCookie("csrftoken"),
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(data)
		})
		.then(response => response.json())
		.then(function (response) {
			swal.close();
			if (response['status']) {
				$('#modal_dialog').modal('show');
				$('.modal_count').html(response['results'].length);
				$('#modal-content').empty();
				subdomains = '';
				$('#modal-content').append(`<textarea class="form-control clipboard copy-txt" id="selected_subdomains_text_area" rows="10" spellcheck="false"></textarea>`);
				for (subdomain in response['results']){
					subdomain_obj = response['results'][subdomain];
					subdomains += subdomain_obj + '\n'
				}
				$('#selected_subdomains_text_area').val(subdomains);
				$("#modal-footer").empty();
				$("#modal-footer").append(`<a href="javascript:download('subdomains-${jsEscape(domain_name)}.txt', subdomains);" class="m-1 btn btn-dark copyable float-end btn-md"><i class="fe-download me-1"></i> Download Subdomains as txt</a>`);
				$("#modal-footer").append(`<a href="javascript:;" data-clipboard-action="copy" class="m-1 btn btn-primary copyable float-end btn-md" data-toggle="tooltip" data-placement="top" title="Copy Subdomains!" data-clipboard-target="#selected_subdomains_text_area"><i class="fe-copy me-1"></i> Copy Subdomains</a>`);
			}
			else{
				Swal.fire({
					title: 'Oops! Could not download selected subdomains.',
					icon: 'error',
					padding: '2em'
				});
			}
		});
	}
}


function deleteMultipleSubdomains(){
	if (!checkedCount()) {
		Swal.fire({
			title: 'Oops! No Subdomains has been selected!',
			icon: 'error',
			padding: '2em'
		});
	} else {
		// atleast one target is selected
		Swal.fire({
			showCancelButton: true,
			title: 'Are you sure you want to delete ' + checkedCount() + ' Subdomains?',
			text: 'Do you really want to delete these subdomains? This action cannot be undone.',
			icon: 'error',
			confirmButtonText: 'Delete',
		}).then((result) => {
			if (result.isConfirmed) {
				Swal.fire({
					title: 'Deleting Subdomain...',
					allowOutsideClick: false
				});
				swal.showLoading();

				subdomain_item = document.getElementsByClassName("subdomain_checkbox");
				var subdomain_ids = [];
				for (var i = 0; i < subdomain_item.length; i++) {
					if (subdomain_item[i].checked) {
						subdomain_ids.push($(subdomain_item[i]).val());
					}
				}
				var data = {'subdomain_ids': subdomain_ids};
				fetch('/api/action/subdomain/delete/', {
					method: 'POST',
					credentials: "same-origin",
					headers: {
						"X-CSRFToken": getCookie("csrftoken"),
						'Content-Type': 'application/json'
					},
					body: JSON.stringify(data)
				})
				.then(response => response.json())
				.then(function (response) {
					swal.close();
					if (response['status']) {
						// remove all rows
						var table = $('#subdomain_scan_results').DataTable();
						for (var id in subdomain_ids) {
							table.row('#subdomain_row_' + id).remove().draw();
						}
						Snackbar.show({
							text: 'Subdomain successfully deleted!',
							pos: 'top-right',
							duration: 2500
						});
					}
					else{
						Swal.fire({
							title:  'Could not delete Subdomain!',
							icon: 'fail',
						});
					}
				});
			}
		});
	}
}


function initiateMultipleSubscan(){
		$('#subscan-modal').modal('show');
		$('a[data-toggle="tooltip"]').tooltip("hide")
		// to distinguish multiple subscan or single, put a extra attribute on button
		$('#btn-initiate-subtask').attr('multiple-subscan', true);
}


