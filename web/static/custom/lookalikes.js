// Lookalikes page: review queue of look-alike domains of owned roots.
// Every value here is third-party data (names, RDAP strings). Cells are filled with textContent only: no HTML string
// is ever built from a row, and a domain is never turned into a link.

var LK_ROWS = {};

function lk_el(tag, cls, text) {
	var e = document.createElement(tag);
	if (cls) e.className = cls;
	if (text !== undefined && text !== null) e.textContent = String(text);
	return e;
}

function lk_table() {
	return document.getElementById('lk_table');
}

function lk_project() {
	return lk_table().dataset.project;
}

function lk_can_write() {
	return lk_table().dataset.canWrite === '1';
}

// Snackbar inserts its text as HTML, so escape it first.
function lk_toast(text) {
	var safe = String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
	Snackbar.show({text: safe, pos: 'top-right', duration: 3000});
}

function lk_post(url, body) {
	return fetch(url, {
		method: 'POST',
		credentials: 'same-origin',
		headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken')},
		body: JSON.stringify(body)
	}).then(function(r) {
		if (r.status === 403) return {status: false, message: 'You do not have permission for this action.'};
		return r.json();
	});
}

function lk_url() {
	var u = '/api/lookalikes/?project=' + encodeURIComponent(lk_project());
	['status', 'registered', 'mx', 'young'].forEach(function(k) {
		var v = document.getElementById('lk_f_' + k).value;
		if (v) u += '&' + k + '=' + encodeURIComponent(v);
	});
	return u;
}

var LK_STATUS = {unchecked: 'Not checked', unregistered: 'Not registered', registered: 'Awaiting review', watching: 'Watching',
	ignored: 'Ignored', ours: 'Ours', reported: 'Reported', gone: 'Gone'};

function lk_yes(td, on) {
	td.append(on ? lk_el('span', 'lk-yes', 'Yes') : lk_el('span', 'l-muted', '–'));
}

// Plain value for sorting and searching; the cell itself is built by createdCell.
function lk_plain(fn) {
	return function(d, t, row) { return t === 'display' ? '' : fn(d, row); };
}

function lk_action(act, id, label) {
	var b = lk_el('button', 'btn btn-light', label);
	b.type = 'button';
	b.dataset.act = act;
	b.dataset.id = String(Number(id));
	return b;
}

function lk_load_summary(meta, total) {
	var parts = [Number(total) + (Number(total) === 1 ? ' lookalike' : ' lookalikes') + ' match'];
	if (meta.truncated) parts.push('showing the first 2000');
	var box = document.getElementById('lk_summary');
	box.replaceChildren();
	parts.forEach(function(t) { box.appendChild(lk_el('span', null, t)); });
	document.getElementById('lk_off').hidden = !!meta.enabled;
	document.getElementById('lk_credit').textContent = meta.credit || '';
}

function lk_decide(id, decision) {
	lk_post('/api/action/lookalike/decide/', {project: lk_project(), id: id, decision: decision, note: ''}).then(function(d) {
		if (!d.status) { lk_toast(d.message); return; }
		if (d.add_url) {
			// the server built a same-site path to the Assets page; navigate only to a relative path, never to anything else
			if (typeof d.add_url === 'string' && d.add_url.charAt(0) === '/' && d.add_url.charAt(1) !== '/') window.location.assign(d.add_url);
			return;
		}
		lk_toast(decision === 'watch' ? 'Watching.' : 'Ignored.');
		$('#lk_table').DataTable().ajax.reload(null, false);
	}).catch(function() { lk_toast('Request failed.'); });
}

function lk_report(id) {
	lk_post('/api/action/lookalike/report/', {project: lk_project(), id: id}).then(function(d) {
		if (!d.status) { lk_toast(d.message); return; }
		var box = document.getElementById('lk_report');
		box.value = 'To: ' + (d.to || '(no abuse contact known: look the registrar up)') + '\nSubject: ' + d.subject + '\n\n' + d.body;
		document.getElementById('lk_report_card').hidden = false;
		box.scrollIntoView({block: 'center'});
		$('#lk_table').DataTable().ajax.reload(null, false);
	}).catch(function() { lk_toast('Request failed.'); });
}

function lookalikes_init() {
	$.fn.dataTable.ext.errMode = 'none';
	var query = new URLSearchParams(location.search);
	// ?status=, ?registered=, ?mx=, ?young= preselect a filter, but only to a value the select already offers
	var any = false;
	['status', 'registered', 'mx', 'young'].forEach(function(k) {
		var sel = document.getElementById('lk_f_' + k), v = query.get(k);
		if (v === null || !sel) return;
		any = true;
		if (Array.prototype.some.call(sel.options, function(o) { return o.value === v; })) sel.value = v;
	});
	if (any && query.get('registered') === null) document.getElementById('lk_f_registered').value = '';
	var cols = [
		{data: 'domain', className: 'lk-col-domain', render: lk_plain(function(d, row) { return d + ' ' + row.unicode + ' ' + row.fuzzers.join(' ') + ' ' + row.root; }), createdCell: function(td, d, row) {
			var box = lk_el('span', 'lk-domain mono', row.domain);
			td.append(box);
			if (row.idn) {
				box.append(lk_el('span', 'l-muted', row.unicode));
				td.append(' ', lk_el('span', 'badge l-badge-prov', 'IDN'));
			}
			var how = row.fuzzers.length ? row.fuzzers.join(', ') : row.source === 'ct' ? 'seen in certificates' : '';
			td.append(lk_el('span', 'l-muted lk-how', (how ? how + ' of ' : 'of ') + row.root));
		}},
		{data: 'registered', className: 'text-nowrap', render: lk_plain(function(d) { return d === null ? 'unknown' : d ? 'yes' : 'no'; }),
			createdCell: function(td, d) { td.append(d === null ? lk_el('span', 'l-muted', 'Unknown') : d ? lk_el('span', null, 'Yes') : lk_el('span', 'l-muted', 'No')); }},
		{data: 'age_days', className: 'text-nowrap', render: lk_plain(function(d) { return d === null ? -1 : d; }),
			createdCell: function(td, d) { td.append(d === null ? lk_el('span', 'l-muted', '–') : lk_el('span', null, d + (d === 1 ? ' day' : ' days'))); }},
		{data: 'registrar', className: 'lk-registrar', render: lk_plain(function(d) { return d; }), createdCell: function(td, d) { td.append(d ? d : lk_el('span', 'l-muted', '–')); }},
		{data: 'has_mx', render: lk_plain(function(d) { return d ? 1 : 0; }), createdCell: function(td, d) { lk_yes(td, d); }},
		{data: 'cert', render: lk_plain(function(d) { return d ? 1 : 0; }), createdCell: function(td, d) { lk_yes(td, d); }},
		{data: 'has_a', render: lk_plain(function(d) { return d ? 1 : 0; }), createdCell: function(td, d) { td.append(d ? lk_el('span', null, 'Yes') : lk_el('span', 'l-muted', '–')); }},
		{data: 'status', className: 'text-nowrap', render: lk_plain(function(d) { return LK_STATUS[d] || d; }),
			createdCell: function(td, d) { td.append(lk_el('span', 'badge l-badge-open', LK_STATUS[d] || d)); }},
		{data: 'first_seen', className: 'text-nowrap l-muted', render: lk_plain(function(d) { return String(d || ''); }),
			createdCell: function(td, d) { td.append(String(d || '').slice(0, 10)); }}
	];
	if (lk_can_write()) {
		cols.push({data: 'id', orderable: false, searchable: false, className: 'lk-col-actions', render: function() { return ''; }, createdCell: function(td, d, row) {
			var box = lk_el('div', 'lk-actions');
			if (row.status !== 'watching') box.append(lk_action('watch', d, 'Watch'));
			if (row.status !== 'ignored') box.append(lk_action('ignore', d, 'Ignore'));
			if (row.status !== 'ours') box.append(lk_action('ours', d, 'This is ours'));
			box.append(lk_action('report', d, 'Abuse report'));
			td.append(box);
		}});
	}
	var table = $('#lk_table').DataTable({
		processing: true,
		stripeClasses: [],
		autoWidth: false,
		dom: "<'l-dt-bar'if><'table-responsive't><'l-dt-bar l-dt-foot'lp>",
		language: {info: 'Showing _START_–_END_ of _TOTAL_', infoEmpty: 'No lookalikes', search: '', searchPlaceholder: 'Filter this list'},
		ajax: {url: lk_url(), dataSrc: function(body) {
			LK_ROWS = {};
			(body.results || []).forEach(function(r) { LK_ROWS[r.id] = r; });
			lk_load_summary(body.meta || {}, (body.meta || {}).total || 0);
			return body.results || [];
		}},
		columns: cols,
		order: [[8, 'desc']]
	});
	$('#lk_table_filter input').attr('aria-label', 'Filter this list');
	$('#lk_table').on('error.dt', function() { lk_toast('Could not load lookalikes.'); });
	['status', 'registered', 'mx', 'young'].forEach(function(k) {
		document.getElementById('lk_f_' + k).addEventListener('change', function() { table.ajax.url(lk_url()).load(); });
	});
	$('#lk_table').on('click', 'button[data-act]', function() {
		var id = Number(this.dataset.id), act = this.dataset.act;
		if (act === 'report') lk_report(id); else lk_decide(id, act);
	});
	document.getElementById('lk_copy').addEventListener('click', function() {
		var text = document.getElementById('lk_report').value;
		if (!navigator.clipboard) { document.getElementById('lk_report').select(); lk_toast('Press Ctrl+C to copy.'); return; }
		navigator.clipboard.writeText(text).then(function() { lk_toast('Copied.'); }, function() { lk_toast('Copy failed: select the text and press Ctrl+C.'); });
	});
}
