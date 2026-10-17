// Issues page: list, waive/revoke, notes, fix forecast.
// Finding names, reasons, notes and asset values are scanner- or user-supplied: always render through issue_esc().

var ISSUE_SEVERITY = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'};
var ISSUE_ROWS = {};

function issue_esc(v) {
	return $('<div>').text(v === null || v === undefined ? '' : String(v)).html();
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
	return 'waived (' + w.kind + (w.expires_at ? ', until ' + String(w.expires_at).slice(0, 10) : '') + ')';
}

function issue_selected() {
	return $('#issue_results .issue_pick:checked').map(function() { return Number(this.value); }).get();
}

// Score card: adjusted score, with the raw one when waivers make them differ.
function issue_load_score() {
	var box = document.getElementById('issue_score');
	fetch('/api/asset_score/?project=' + encodeURIComponent(issue_project()), {credentials: 'same-origin'})
		.then(function(r) { if (!r.ok) throw new Error('score'); return r.json(); })
		.then(function(s) {
			if (s.score === null) { box.innerHTML = ''; return; }
			var raw = s.raw_score !== s.score ? ' <small class="text-muted">(raw ' + issue_esc(s.raw_score) + ' ' + issue_esc(s.raw_grade) + ')</small>' : '';
			box.innerHTML = '<span class="h2 me-2">' + issue_esc(s.score) + '</span><span class="badge bg-soft-primary text-primary me-2">' +
				issue_esc(s.grade) + '</span>' + raw + ' <small class="text-muted">' + issue_esc(s.waived_count) + ' waived</small>';
		}).catch(function() { box.innerHTML = ''; });
}

var issue_forecast_seq = 0;
function issue_forecast() {
	var seq = ++issue_forecast_seq, box = document.getElementById('issue_forecast'), ids = issue_selected();
	if (!ids.length) { box.style.display = 'none'; return; }
	issue_post('/api/score_forecast/', {project: issue_project(), issues: ids}).then(function(d) {
		if (seq !== issue_forecast_seq) return;  // a newer request superseded this one
		if (!d.status || d.score === null || d.score === undefined) { box.style.display = 'none'; return; }
		var delta = Number(d.delta);
		box.textContent = 'Forecast if fixed: ' + d.score + ' (' + d.grade + '), ' + (delta >= 0 ? '+' : '') + delta;
		box.style.display = '';
	}).catch(function() { if (seq === issue_forecast_seq) box.style.display = 'none'; });
}

function issue_notes_html(notes) {
	if (!notes.length) return '<p class="text-muted">No notes yet.</p>';
	return notes.map(function(n) {
		return '<div class="border-bottom py-1"><small class="text-muted">' + issue_esc(n.author || 'unknown') + ' &middot; ' +
			issue_esc(String(n.created_at).slice(0, 16).replace('T', ' ')) + '</small><div style="white-space:pre-wrap">' + issue_esc(n.text) + '</div></div>';
	}).join('');
}

function issue_load_notes(id) {
	var url = '/api/issue/notes/?project=' + encodeURIComponent(issue_project()) + '&issue_id=' + Number(id);
	return fetch(url, {credentials: 'same-origin'}).then(function(r) {
		if (!r.ok) throw new Error('notes');
		return r.json();
	}).then(function(notes) {
		document.getElementById('issue_notes').innerHTML = issue_notes_html(notes);
	}).catch(function() {
		document.getElementById('issue_notes').innerHTML = '<p class="text-muted">Notes unavailable.</p>';
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

function issue_form_html(row) {
	if (!issue_can_write()) return '<p class="text-muted">You can view issues but not change them.</p>';
	var revoke = row.waiver ? '<button class="btn btn-sm btn-soft-danger mb-3" id="issue_revoke">Revoke waiver</button>' : '';
	return revoke + '<h5>Waive</h5>' +
		'<label class="form-label" for="issue_kind">Kind</label>' +
		'<select id="issue_kind" class="form-select mb-2"><option value="accepted_risk">accepted_risk</option><option value="false_positive">false_positive</option></select>' +
		'<label class="form-label" for="issue_reason">Reason (required)</label>' +
		'<textarea id="issue_reason" class="form-control mb-2" rows="3" maxlength="5000"></textarea>' +
		'<label class="form-label" for="issue_expiry">Expires (required for accepted_risk, optional for false_positive, max 365 days)</label>' +
		'<input type="date" id="issue_expiry" class="form-control mb-2">' +
		'<button class="btn btn-sm btn-primary mb-3" id="issue_waive">Waive</button>';
}

function issue_note_box_html() {
	if (!issue_can_write()) return '';
	return '<textarea id="issue_note_text" class="form-control mb-2" rows="2" maxlength="5000" placeholder="Add a note"></textarea>' +
		'<button class="btn btn-sm btn-soft-primary" id="issue_note_add">Add note</button>';
}

function issue_done(data, id, msg) {
	issue_toast(data.status ? msg : data.message);
	if (!data.status) return;
	$('#modal_dialog').modal('hide');
	$('#issue_results').DataTable().ajax.reload(null, false);
	issue_load_score();
}

function issue_modal(id) {
	var row = ISSUE_ROWS[id];
	if (!row) return;
	$('#modal_title').text(row.title);
	$('#modal-footer').html('');
	$('#modal-content').html('<p><b>Asset</b> ' + issue_esc(row.asset) + ' &middot; <b>Severity</b> ' + issue_esc(ISSUE_SEVERITY[row.severity]) +
		' &middot; <b>Source</b> ' + issue_esc(row.source) + '</p>' +
		(row.waiver ? '<p><b>' + issue_esc(issue_waiver_text(row.waiver)) + '</b> by ' + issue_esc(row.waiver.created_by) +
			'<br><span style="white-space:pre-wrap">' + issue_esc(row.waiver.reason) + '</span></p>' : '') +
		issue_form_html(row) + '<h5>Notes</h5><div id="issue_notes"></div>' + issue_note_box_html());
	$('#modal_dialog').modal('show');
	issue_load_notes(id);
	var fail = function() { issue_toast('Request failed.'); };
	if (!issue_can_write()) return;
	// the date posts as UTC midnight, so today is already past: allow tomorrow..+365 days only
	var exp_input = document.getElementById('issue_expiry');
	exp_input.min = issue_date_in(1);
	exp_input.max = issue_date_in(365);
	issue_sync_expiry();
	document.getElementById('issue_kind').addEventListener('change', issue_sync_expiry);
	document.getElementById('issue_waive').addEventListener('click', function() {
		var kind = document.getElementById('issue_kind').value, exp = document.getElementById('issue_expiry').value;
		var body = {project: issue_project(), issue_id: id, kind: kind, reason: document.getElementById('issue_reason').value};
		if (exp) body.expires_at = exp + 'T00:00:00Z';
		issue_post('/api/action/issue/waive/', body).then(function(d) { issue_done(d, id, 'Waived.'); }).catch(fail);
	});
	var rv = document.getElementById('issue_revoke');
	if (rv) rv.addEventListener('click', function() {
		issue_post('/api/action/issue/revoke/', {project: issue_project(), issue_id: id}).then(function(d) { issue_done(d, id, 'Revoked.'); }).catch(fail);
	});
	document.getElementById('issue_note_add').addEventListener('click', function() {
		var box = document.getElementById('issue_note_text');
		issue_post('/api/issue/notes/', {project: issue_project(), issue_id: id, text: box.value}).then(function(d) {
			issue_toast(d.status ? 'Note added.' : d.message);
			if (!d.status) return;
			box.value = '';
			issue_load_notes(id);
			$('#issue_results').DataTable().ajax.reload(null, false);
		}).catch(fail);
	});
}

function issues_init() {
	issue_load_score();
	$.fn.dataTable.ext.errMode = 'none';
	var table = $('#issue_results').DataTable({
		processing: true,
		stripeClasses: [],
		ajax: {url: issue_url(), dataSrc: function(rows) {
			ISSUE_ROWS = {};
			rows.forEach(function(r) { ISSUE_ROWS[r.id] = r; });
			return rows;
		}},
		columns: [
			{data: 'id', orderable: false, render: function(d) { return '<input type="checkbox" class="issue_pick" value="' + Number(d) + '">'; }},
			{data: 'asset', render: $.fn.dataTable.render.text()},
			{data: 'title', render: function(d, t, row) {
				return '<a href="#" onclick="issue_modal(' + Number(row.id) + ');return false;">' + issue_esc(d) + '</a>';
			}},
			{data: 'severity', render: function(d) { return issue_esc(ISSUE_SEVERITY[d] || d); }},
			{data: 'source', render: $.fn.dataTable.render.text()},
			{data: 'first_seen', render: function(d) { return issue_esc(String(d || '').slice(0, 10)); }},
			{data: 'waiver', render: function(d) { return issue_esc(issue_waiver_text(d)); }},
			{data: 'note_count', render: function(d) { return issue_esc(d); }}
		],
		order: [[3, 'desc']]
	});
	$('#issue_results').on('error.dt', function() { issue_toast('Could not load issues.'); });
	['severity', 'source', 'waived'].forEach(function(k) {
		document.getElementById('f_' + k).addEventListener('change', function() { table.ajax.url(issue_url()).load(); });
	});
	table.on('draw', issue_forecast);
	$('#issue_results').on('change', '.issue_pick', issue_forecast);
}
