// Assets inventory page: detail modal, row actions, add-assets modal.
// Every value from the API is user- or scan-supplied: always render through asset_esc().

function asset_esc(v) {
	return $('<div>').text(v === null || v === undefined ? '' : String(v)).html();
}

function asset_project() {
	return document.getElementById('asset_results').dataset.project;
}

function asset_reload() {
	$('#asset_results').DataTable().ajax.reload(null, false);
}

function asset_toast(text) {
	// Snackbar inserts text as HTML
	Snackbar.show({text: asset_esc(text), pos: 'top-right', duration: 3000});
}

function asset_fetch(id) {
	var url = '/api/listDatatableAsset/' + Number(id) + '/?project=' + encodeURIComponent(asset_project());
	return fetch(url, {credentials: 'same-origin'}).then(function(r) {
		if (!r.ok) throw new Error('asset not found');
		return r.json();
	});
}

function asset_post(url, body) {
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

function asset_actions(row) {
	var id = Number(row.id), html = '';
	if (row.scope_tier === 'candidate') {
		html += '<button class="btn btn-xs btn-soft-success me-1" onclick="confirm_asset(' + id + ')">Confirm</button>';
		html += '<button class="btn btn-xs btn-soft-danger me-1" onclick="reject_asset(' + id + ')">Reject</button>';
	}
	if (row.kind === 'root_domain') {
		html += '<button class="btn btn-xs btn-soft-primary" onclick="rescan_asset(' + id + ')">Rescan</button>';
	}
	return html;
}

function asset_run_action(path, id, extra) {
	var body = Object.assign({asset_id: Number(id), project: asset_project()}, extra || {});
	return asset_post('/api/action/asset/' + path + '/', body).then(function(data) {
		asset_toast(data.message);
		if (data.status) {
			$('#modal_dialog').modal('hide');
			asset_reload();
		}
	}).catch(function() {
		asset_toast('Request failed.');
	});
}

function confirm_asset(id) {
	var reason = prompt('Reason for confirming this asset as owned (optional):');
	if (reason === null) return;
	asset_run_action('confirm', id, {reason: reason});
}

function reject_asset(id) {
	var reason = prompt('Reason for rejecting this asset (optional):');
	if (reason === null) return;
	asset_run_action('reject', id, {reason: reason});
}

function rescan_asset(id) {
	asset_run_action('rescan', id);
}

// "Why is this mine": follow parent links up to the root. Depth-capped so a bad cycle can't loop.
function asset_parent_chain(asset) {
	var chain = [asset];
	function step(a) {
		if (!a.parent || chain.length >= 10) return Promise.resolve(chain);
		return asset_fetch(a.parent).then(function(p) {
			chain.push(p);
			return step(p);
		}).catch(function() { return chain; });
	}
	return step(asset);
}

function get_asset_modal(id) {
	asset_fetch(id).then(asset_parent_chain).then(function(chain) {
		var a = chain[0];
		var path = chain.slice().reverse().map(function(c) {
			return '<span class="badge bg-soft-primary text-primary me-1">' + asset_esc(c.kind) + '</span>' + asset_esc(c.value);
		}).join(' <i class="fe-arrow-right mx-1"></i> ');
		var sources = (a.sources || []).map(function(s) {
			return '<tr><td>' + asset_esc(s.source) + '</td><td>' + asset_esc(s.evidence) + '</td><td>' +
				asset_esc(s.confidence) + '</td><td>' + asset_esc(s.seen_at) + '</td></tr>';
		}).join('') || '<tr><td colspan="4" class="text-muted">No recorded sources.</td></tr>';
		$('#modal_title').text(a.value);
		$('#modal-content').html(
			'<p><b>Kind</b> ' + asset_esc(a.kind) + ' &middot; <b>Scope</b> ' + asset_esc(a.scope_tier) +
			' &middot; <b>State</b> ' + asset_esc(a.state) + ' &middot; <b>Vulnerabilities</b> ' + asset_esc(a.vuln_count) + '</p>' +
			(a.decision_reason ? '<p><b>Decision reason</b> ' + asset_esc(a.decision_reason) + '</p>' : '') +
			'<h5>Why is this mine</h5><p>' + path + '</p>' +
			'<h5>Sources</h5><table class="table table-sm"><thead><tr><th>Source</th><th>Evidence</th><th>Confidence</th><th>Seen</th></tr></thead><tbody>' +
			sources + '</tbody></table>'
		);
		$('#modal-footer').html(asset_actions(a));
		$('#modal_dialog').modal('show');
	}).catch(function() {
		asset_toast('Unable to load asset.');
	});
}

function show_add_asset_modal() {
	$('#modal_title').text('Add assets');
	$('#modal-content').html(
		'<label class="form-label" for="asset_entries">Domains, hosts, IPs or CIDRs (one per line or comma separated)</label>' +
		'<textarea id="asset_entries" class="form-control mb-2" rows="6" placeholder="example.com&#10;app.example.com&#10;203.0.113.10"></textarea>' +
		'<label class="form-label" for="asset_csv">Or load a CSV / text file</label>' +
		'<input type="file" id="asset_csv" class="form-control mb-2" accept=".csv,.txt,text/csv,text/plain">' +
		'<label class="form-label" for="asset_tier">Scope tier</label>' +
		'<select id="asset_tier" class="form-select mb-2">' +
		'<option value="owned_host">Owned host / IP / CIDR</option><option value="owned_root">Owned root domain</option>' +
		'<option value="co_brand">Co-brand host (passive unless authorized)</option></select>' +
		'<label class="form-label" for="asset_reason">Reason (audited)</label>' +
		'<input type="text" id="asset_reason" class="form-control mb-2" maxlength="5000">' +
		'<div id="asset_add_result"></div>'
	);
	$('#modal-footer').html('<button class="btn btn-primary" onclick="add_assets()">Add</button>');
	document.getElementById('asset_csv').addEventListener('change', function(e) {
		var file = e.target.files[0];
		if (!file) return;
		var reader = new FileReader();
		reader.onload = function() {
			var box = document.getElementById('asset_entries');
			box.value = (box.value ? box.value + '\n' : '') + reader.result;
		};
		reader.readAsText(file);
	});
	$('#modal_dialog').modal('show');
}

function add_assets() {
	var body = {
		project: asset_project(),
		entries: document.getElementById('asset_entries').value,
		tier: document.getElementById('asset_tier').value,
		reason: document.getElementById('asset_reason').value
	};
	asset_post('/api/add/assets/', body).then(function(data) {
		var out = document.getElementById('asset_add_result');
		if (!data.status) {
			out.innerHTML = '<div class="alert alert-danger">' + asset_esc(data.message) + '</div>';
			return;
		}
		var m = data.message;
		var warnings = (m.warnings || []).map(function(w) { return '<li>' + asset_esc(w) + '</li>'; }).join('');
		out.innerHTML = '<div class="alert alert-' + (m.skipped ? 'warning' : 'success') + '">Added ' + Number(m.added) +
			', already present ' + Number(m.existing) + ', skipped ' + Number(m.skipped) +
			(warnings ? '<ul class="mb-0">' + warnings + '</ul>' : '') + '</div>';
		asset_reload();
	}).catch(function() {
		asset_toast('Request failed.');
	});
}
