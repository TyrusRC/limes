// Issues page: list, waive/revoke, notes, fix forecast.
// Finding names, reasons, notes and asset values are scanner- or user-supplied: HTML strings go through issue_esc(),
// everything else reaches the DOM as textContent (issue_el).

var ISSUE_SEVERITY = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'};
var ISSUE_KIND = {accepted_risk: 'Accepted risk', false_positive: 'False positive'};
var ISSUE_ROWS = {};
var ISSUE_CURRENT = null;  // id of the issue open in the modal
var ISSUE_SCORE = null;    // last /api/asset_score/ payload with a score

// Escapes for text and for quoted attribute values.
function issue_esc(v) {
	return $('<div>').text(v === null || v === undefined ? '' : String(v)).html().replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function issue_el(tag, cls, text) {
	var e = document.createElement(tag);
	if (cls) e.className = cls;
	if (text !== undefined && text !== null) e.textContent = String(text);
	return e;
}

function issue_text(id, text) {
	document.getElementById(id).textContent = text === null || text === undefined ? '' : String(text);
}

function issue_date(v) {
	return String(v || '').slice(0, 10);
}

function issue_sev_name(sev) {
	var n = ISSUE_SEVERITY[sev] || '';
	return n.charAt(0).toUpperCase() + n.slice(1);
}

function issue_table() {
	return document.getElementById('issue_results');
}

function issue_project() {
	return issue_table().dataset.project;
}

function issue_can_write() {
	return issue_table().dataset.canWrite === '1';
}

function issue_toast(text) {
	// Snackbar inserts text as HTML
	Snackbar.show({text: issue_esc(text), pos: 'top-right', duration: 3000});
}

function issue_post(url, body) {
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

function issue_url() {
	var u = '/api/issues/?project=' + encodeURIComponent(issue_project());
	['severity', 'source', 'waived'].forEach(function(k) {
		var v = document.getElementById('f_' + k).value;
		if (v) u += '&' + k + '=' + encodeURIComponent(v);
	});
	return u;
}

function issue_waiver_text(w) {
	if (!w) return '';
	return (ISSUE_KIND[w.kind] || w.kind) + (w.expires_at ? ' until ' + issue_date(w.expires_at) : '');
}

// Waiver badge: accepted risk indigo, false positive grey, expired outline.
function issue_badge(w, expired) {
	var b = issue_el('span', 'badge'), icon = issue_el('i');
	icon.setAttribute('aria-hidden', 'true');
	if (expired) {
		b.className += ' l-badge-expired';
		icon.className = 'fe-clock';
		b.append(icon, 'Waiver expired');
	} else {
		var fp = w.kind === 'false_positive';
		b.className += fp ? ' l-badge-fp' : ' l-badge-waived';
		icon.className = fp ? 'fe-x' : 'fe-shield';
		b.append(icon, issue_waiver_text(w));
	}
	return b;
}

function issue_status_html(row) {
	if (row.waiver) return issue_badge(row.waiver).outerHTML;
	if (row.expired_waiver) return issue_badge(row.expired_waiver, true).outerHTML;
	return '<span class="badge l-badge-open">Open</span>';
}

function issue_status_text(row) {
	if (row.waiver) return 'waived ' + issue_waiver_text(row.waiver);
	return row.expired_waiver ? 'waiver expired' : 'open';
}

function issue_selected() {
	return $('#issue_results .issue_pick:checked').map(function() { return Number(this.value); }).get();
}

// Row highlight and the select-all box follow the ticked rows on this page.
function issue_sync_picks() {
	var picks = $('#issue_results .issue_pick:not(:disabled)'), n = picks.filter(':checked').length;
	picks.each(function() { $(this).closest('tr').toggleClass('l-selected', this.checked); });
	var all = document.getElementById('issue_pick_all');
	all.checked = n > 0 && n === picks.length;
	all.indeterminate = n > 0 && n < picks.length;
	all.disabled = picks.length === 0;
}

// Sub-line under the title: adjusted score, with the raw one when waivers make them differ.
function issue_load_score() {
	var box = document.getElementById('issue_score');
	fetch('/api/asset_score/?project=' + encodeURIComponent(issue_project()), {credentials: 'same-origin'})
		.then(function(r) { if (!r.ok) throw new Error('score'); return r.json(); })
		.then(function(s) {
			box.replaceChildren();
			ISSUE_SCORE = s.score === null ? null : s;
			if (s.score === null) return;
			var parts = ['Headline score ' + s.score + ' (' + s.grade + ')'];
			if (s.raw_score !== s.score) parts.push('Raw ' + s.raw_score + ' (' + s.raw_grade + ') before waivers');
			parts.push(s.waived_count + ' waived');
			parts.forEach(function(t) { box.appendChild(issue_el('span', null, t)); });
		}).catch(function() { ISSUE_SCORE = null; box.replaceChildren(); });
}

var issue_forecast_seq = 0;
function issue_forecast() {
	var seq = ++issue_forecast_seq, box = document.getElementById('issue_forecast'), ids = issue_selected();
	issue_sync_picks();
	if (!ids.length) { box.hidden = true; return; }
	issue_post('/api/score_forecast/', {project: issue_project(), issues: ids}).then(function(d) {
		if (seq !== issue_forecast_seq) return;  // a newer request superseded this one
		if (!d.status || d.score === null || d.score === undefined) { box.hidden = true; return; }
		var delta = Number(d.delta);
		issue_text('fc_score', d.score);
		issue_text('fc_grade', d.grade);
		issue_text('fc_delta', (delta >= 0 ? '+' : '') + delta);
		issue_text('fc_count', ids.length + (ids.length === 1 ? ' issue' : ' issues') + ' selected');
		issue_text('fc_current', ISSUE_SCORE ? ' \u00b7 current score ' + ISSUE_SCORE.score + ' (' + ISSUE_SCORE.grade + ')' : '');
		box.hidden = false;
	}).catch(function() { if (seq === issue_forecast_seq) box.hidden = true; });
}

function issue_note_item(n) {
	var who = n.author || 'unknown', li = issue_el('li', 'l-note');
	var avatar = issue_el('span', 'l-note-avatar', who.slice(0, 2).toUpperCase());
	avatar.setAttribute('aria-hidden', 'true');
	var bubble = issue_el('div', 'l-note-bubble'), meta = issue_el('div', 'l-note-meta');
	meta.append(issue_el('strong', null, who), issue_el('span', null, String(n.created_at).slice(0, 16).replace('T', ' ')));
	bubble.append(meta, issue_el('div', 'l-note-text', n.text));
	li.append(avatar, bubble);
	return li;
}

function issue_load_notes(id) {
	var list = document.getElementById('issue_notes');
	var url = '/api/issue/notes/?project=' + encodeURIComponent(issue_project()) + '&issue_id=' + Number(id);
	return fetch(url, {credentials: 'same-origin'}).then(function(r) {
		if (!r.ok) throw new Error('notes');
		return r.json();
	}).then(function(notes) {
		if (ISSUE_CURRENT !== id) return;  // the modal moved on to another issue
		issue_text('im_note_count', notes.length);
		list.replaceChildren.apply(list, notes.length ? notes.map(issue_note_item) : [issue_el('li', 'l-hint', 'No notes yet.')]);
	}).catch(function() {
		if (ISSUE_CURRENT === id) list.replaceChildren(issue_el('li', 'l-hint', 'Notes unavailable.'));
	});
}

function issue_date_in(days) {
	return new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
}

function issue_default_expiry() {
	return issue_date_in(90);
}

// accepted_risk needs an expiry (default +90 days); a false positive stays open-ended unless a date is chosen.
function issue_sync_expiry() {
	document.getElementById('issue_expiry').value = document.getElementById('issue_kind').value === 'accepted_risk' ? issue_default_expiry() : '';
}

// Left column: the active waiver (with revoke for writers), or why the issue counts.
function issue_render_waiver(row) {
	var box = document.getElementById('im_waiver'), w = row.waiver;
	box.replaceChildren();
	if (!w) {
		var x = row.expired_waiver, p = issue_el('p', 'l-hint mb-0', x ?
			'The waiver ran out on ' + issue_date(x.expires_at) + ', so this issue counts toward the headline score again.' :
			'Not waived: this issue counts toward the headline score.');
		if (x) box.append(issue_badge(x, true));
		box.append(p);
		return;
	}
	var card = issue_el('div', 'l-current-waiver' + (w.kind === 'false_positive' ? ' is-fp' : '')), top = issue_el('div', 'l-current-waiver-top');
	top.append(issue_badge(w));
	if (issue_can_write()) {
		var rv = issue_el('button', 'btn btn-sm btn-danger', 'Revoke waiver');
		rv.type = 'button';
		rv.id = 'issue_revoke';
		top.append(rv);
	}
	card.append(top, issue_el('p', 'l-waiver-reason', w.reason),
		issue_el('p', 'l-hint', 'Set by ' + (w.created_by || 'unknown') + ' on ' + issue_date(w.created_at) + ' \u00b7 excluded from the headline score'));
	box.append(card);
}

function issue_done(data, msg) {
	issue_toast(data.status ? msg : data.message);
	if (!data.status) return;
	$('#issue_modal').modal('hide');
	$('#issue_results').DataTable().ajax.reload(null, false);
	issue_load_score();
}

function issue_fail() {
	issue_toast('Request failed.');
}

function issue_modal(id) {
	var row = ISSUE_ROWS[id];
	if (!row) return;
	ISSUE_CURRENT = id;
	issue_text('im_title', row.title);
	var sev = document.getElementById('im_sev');
	sev.className = ISSUE_SEVERITY[row.severity] ? 'sev-' + ISSUE_SEVERITY[row.severity] : '';
	sev.textContent = issue_sev_name(row.severity);
	issue_text('im_asset', row.asset);
	issue_text('im_source', row.source === 'check' ? 'Check \u00b7 ' + row.key : 'Finding');
	issue_text('im_first', issue_date(row.first_seen));
	issue_render_waiver(row);
	issue_text('im_note_count', '');
	document.getElementById('issue_notes').replaceChildren();
	var form = document.getElementById('issue_waive_form');
	if (form) {
		form.reset();
		issue_text('im_form_title', row.waiver ? 'Change waiver' : 'Waive');
		// the date posts as UTC midnight, so today is already past: allow tomorrow..+365 days only
		var exp = document.getElementById('issue_expiry');
		exp.min = issue_date_in(1);
		exp.max = issue_date_in(365);
		var w = row.waiver;
		if (w) document.getElementById('issue_kind').value = w.kind;
		issue_sync_expiry();
		if (w) {
			document.getElementById('issue_reason').value = w.reason || '';
			var cur = issue_date(w.expires_at);
			if (cur && cur >= exp.min && cur <= exp.max) exp.value = cur;
		}
		document.getElementById('issue_note_form').reset();
	}
	$('#issue_modal').modal('show');
	issue_load_notes(id);
}

function issue_bind_forms() {
	if (!issue_can_write() || !document.getElementById('issue_waive_form')) return;
	document.getElementById('issue_kind').addEventListener('change', issue_sync_expiry);
	document.getElementById('issue_waive_form').addEventListener('submit', function(e) {
		e.preventDefault();
		var id = ISSUE_CURRENT, kind = document.getElementById('issue_kind').value, exp = document.getElementById('issue_expiry').value;
		var body = {project: issue_project(), issue_id: id, kind: kind, reason: document.getElementById('issue_reason').value};
		if (exp) body.expires_at = exp + 'T00:00:00Z';
		issue_post('/api/action/issue/waive/', body).then(function(d) { issue_done(d, 'Waived.'); }).catch(issue_fail);
	});
	document.getElementById('im_waiver').addEventListener('click', function(e) {
		if (!e.target.closest('#issue_revoke')) return;
		issue_post('/api/action/issue/revoke/', {project: issue_project(), issue_id: ISSUE_CURRENT}).then(function(d) { issue_done(d, 'Revoked.'); }).catch(issue_fail);
	});
	document.getElementById('issue_note_form').addEventListener('submit', function(e) {
		e.preventDefault();
		var id = ISSUE_CURRENT, box = document.getElementById('issue_note_text');
		issue_post('/api/issue/notes/', {project: issue_project(), issue_id: id, text: box.value}).then(function(d) {
			issue_toast(d.status ? 'Note added.' : d.message);
			if (!d.status) return;
			box.value = '';
			issue_load_notes(id);
			$('#issue_results').DataTable().ajax.reload(null, false);
		}).catch(issue_fail);
	});
}

function issue_is_ip(v) {
	// IPv4 or IPv6, optionally with a prefix length; a hostname never matches
	return /^[\d.]+(\/\d+)?$/.test(v) || /^[0-9a-f.]*:[0-9a-f:.]*(\/\d+)?$/i.test(String(v));
}

function issues_init() {
	issue_load_score();
	issue_bind_forms();
	$.fn.dataTable.ext.errMode = 'none';
	// display renders HTML; sort and search use the plain value
	var plain = function(fn) { return function(d, t, row) { return t === 'display' ? fn(d, row) : d; }; };
	var table = $('#issue_results').DataTable({
		processing: true,
		stripeClasses: [],
		autoWidth: false,
		dom: "<'l-dt-bar'if><'table-responsive't><'l-dt-bar l-dt-foot'lp>",
		language: {info: 'Showing _START_\u2013_END_ of _TOTAL_', infoEmpty: 'No issues', search: '', searchPlaceholder: 'Filter this list'},
		ajax: {url: issue_url(), dataSrc: function(rows) {
			ISSUE_ROWS = {};
			rows.forEach(function(r) { ISSUE_ROWS[r.id] = r; });
			return rows;
		}},
		columns: [
			{data: 'id', orderable: false, searchable: false, className: 'l-col-check', render: function(d, t, row) {
				return '<input type="checkbox" class="form-check-input issue_pick" value="' + Number(d) + '" aria-label="Select: ' + issue_esc(row.title) + (row.waiver ? ' (waived)' : '') + '"' +
					(row.waiver ? ' disabled title="Waived: already out of the headline score"' : '') + '>';
			}},
			{data: 'asset', className: 'l-col-wide', render: plain(function(d) {
				return '<span class="' + (issue_is_ip(d) ? 'mono' : '') + '">' + issue_esc(d) + '</span>';
			})},
			{data: 'title', className: 'l-col-wider', render: plain(function(d, row) {
				return '<button type="button" class="l-link-btn issue_open" data-id="' + Number(row.id) + '">' + issue_esc(d) + '</button>';
			})},
			{data: 'severity', render: plain(function(d) {
				return ISSUE_SEVERITY[d] ? '<span class="sev-' + ISSUE_SEVERITY[d] + '">' + issue_sev_name(d) + '</span>' : issue_esc(d);
			})},
			{data: 'source', className: 'text-nowrap', render: plain(function(d, row) {
				return d === 'check' ? '<span class="l-muted">Check</span> <span class="mono">' + issue_esc(row.key) + '</span>' : '<span class="l-muted">Finding</span>';
			})},
			{data: 'first_seen', className: 'text-nowrap l-muted', render: function(d) { return issue_esc(issue_date(d)); }},
			{data: 'waiver', render: function(d, t, row) { return t === 'display' ? issue_status_html(row) : issue_status_text(row); }},
			{data: 'note_count', className: 'text-nowrap', render: plain(function(d) {
				return Number(d) > 0 ? '<span class="l-note-count"><i class="fe-message-square" aria-hidden="true"></i>' + Number(d) +
					'<span class="visually-hidden"> notes</span></span>' : '<span class="l-muted"><span aria-hidden="true">\u2013</span><span class="visually-hidden">No notes</span></span>';
			})}
		],
		order: [[3, 'desc']]
	});
	$('#issue_results_filter input').attr('aria-label', 'Filter this list');
	$('#issue_results').on('error.dt', function() { issue_toast('Could not load issues.'); });
	['severity', 'source', 'waived'].forEach(function(k) {
		document.getElementById('f_' + k).addEventListener('change', function() { table.ajax.url(issue_url()).load(); });
	});
	table.on('draw', issue_forecast);
	$('#issue_results').on('change', '.issue_pick', issue_forecast);
	$('#issue_results').on('click', '.issue_open', function() { issue_modal(Number(this.dataset.id)); });
	document.getElementById('issue_pick_all').addEventListener('change', function() {
		var on = this.checked;
		$('#issue_results .issue_pick:not(:disabled)').prop('checked', on);
		issue_forecast();
	});
	document.getElementById('fc_clear').addEventListener('click', function() {
		$('#issue_results .issue_pick').prop('checked', false);
		issue_forecast();
	});
}
