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
	if (row.scope_tier === 'candidate' || row.scope_tier === 'dependency') {
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

var ASSET_CADENCES = [['crown_jewel', 'Crown jewel (daily)'], ['standard', 'Standard (weekly)'],
	['inactive', 'Inactive (monthly)'], ['off', 'Off (manual only)']];

// How often continuous monitoring rediscovers an owned root.
function asset_cadence_html(a) {
	if (a.kind !== 'root_domain') return '';
	var opts = ASSET_CADENCES.map(function(c) {
		return '<option value="' + c[0] + '"' + (a.cadence_tier === c[0] ? ' selected' : '') + '>' + c[1] + '</option>';
	}).join('');
	return '<div class="d-flex align-items-center mb-2"><label class="form-label mb-0 me-2" for="asset_cadence"><b>Cadence</b></label>' +
		'<select id="asset_cadence" class="form-select form-select-sm w-auto me-2">' + opts + '</select>' +
		'<button class="btn btn-xs btn-soft-primary" onclick="set_asset_cadence(' + Number(a.id) + ')">Save</button></div>';
}

function set_asset_cadence(id) {
	var body = {asset_id: Number(id), project: asset_project(), cadence_tier: document.getElementById('asset_cadence').value};
	asset_post('/api/action/asset/cadence/', body).then(function(data) {
		asset_toast(data.message);
	}).catch(function() {
		asset_toast('Request failed.');
	});
}

function asset_penalty_rows(rows, withAsset) {
	return (rows || []).map(function(r) {
		return '<tr>' + (withAsset ? '<td>' + asset_esc(r.asset) + '</td>' : '') + '<td>' + asset_esc(r.issue) +
			'</td><td>' + asset_esc(r.severity) + '</td><td>-' + asset_esc(r.points) + '</td></tr>';
	}).join('');
}

// Risk section of the asset modal (limes.scoring); null for assets that are not scored.
function asset_risk_html(risk) {
	if (!risk) return '';
	var rows = asset_penalty_rows(risk.penalties, false);
	return '<h5>Risk ' + asset_esc(risk.score) + ' <span class="badge bg-soft-primary text-primary">' + asset_esc(risk.grade) +
		'</span></h5>' + (rows ? '<table class="table table-sm"><thead><tr><th>Issue</th><th>Severity</th><th>Points</th></tr></thead><tbody>' +
		rows + '</tbody></table>' : '<p class="text-muted">No open findings in the latest vulnerability scan.</p>');
}

// Project score card above the Assets table.
function load_asset_score() {
	var box = document.getElementById('asset_score');
	fetch('/api/asset_score/?project=' + encodeURIComponent(asset_project()), {credentials: 'same-origin'})
		.then(function(r) { if (!r.ok) throw new Error('score'); return r.json(); })
		.then(function(s) {
			if (s.score === null) {
				box.innerHTML = '<p class="text-muted mb-0">No owned assets to score yet.</p>';
				return;
			}
			var cov = s.coverage === null ? 'n/a' : Math.round(Number(s.coverage) * 100) + '%';
			var rows = asset_penalty_rows(s.top_penalties, true);
			box.innerHTML = '<div class="d-flex align-items-baseline mb-1"><span class="h2 mb-0 me-2">' + asset_esc(s.score) +
				'</span><span class="badge bg-soft-primary text-primary me-3">' + asset_esc(s.grade) + '</span>' +
				'<small class="text-muted">' + asset_esc(cov) + ' of owned roots scanned for vulnerabilities in 30 days &middot; ' +
				asset_esc(s.version) + '</small></div>' + (rows ? '<table class="table table-sm mb-0"><thead><tr><th>Asset</th>' +
				'<th>Issue</th><th>Severity</th><th>Points</th></tr></thead><tbody>' + rows + '</tbody></table>' : '');
		}).catch(function() {
			box.innerHTML = '<p class="text-muted mb-0">Score unavailable.</p>';
		});
}

function asset_confidence_html(a) {
	var d = a.confidence_detail;
	if (!d || !Array.isArray(d.contributions)) return '';
	var rows = d.contributions.map(function(c) {
		return '<tr><td>' + asset_esc(c.kind) + '</td><td>' + asset_esc(c.value) + '</td><td>' + asset_esc(c.via) +
			'</td><td>' + asset_esc(c.weight) + '</td><td>' + asset_esc(c.hop) + '</td></tr>';
	}).join('') || '<tr><td colspan="5" class="text-muted">No evidence yet.</td></tr>';
	var dg = d.delegation, delegation = '';
	if (dg && typeof dg === 'object') {
		delegation = '<p class="' + (dg.ok === true ? 'text-success' : 'text-muted') + '">' +
			asset_esc(dg.ok === true ? 'Delegation verified at the registry' : 'Delegation not verified: ' + dg.reason) + '</p>';
	}
	return '<h5>Confidence ' + asset_esc(Number(d.score).toFixed(2)) + ' <small class="text-muted">(' +
		asset_esc(d.version) + ')</small></h5><table class="table table-sm"><thead><tr><th>Evidence</th><th>Value</th>' +
		'<th>Via</th><th>Weight</th><th>Hop</th></tr></thead><tbody>' + rows + '</tbody></table>' + delegation +
		(d.would_auto_confirm === true ? '<p class="text-warning">' +
			asset_esc('Would auto-confirm (delegation verified); auto-confirm is disabled.') + '</p>' : '');
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

function asset_intel_html(e) {
	e = e || {};
	var rows = [], idb = e.internetdb, ripe = e.ripestat;
	if (idb) {
		if (idb.no_data) {
			rows.push('<tr><td>InternetDB</td><td class="text-muted">No data</td><td>' + asset_esc(idb.fetched_at) + '</td></tr>');
		} else {
			rows.push('<tr><td>Open ports</td><td>' + asset_esc((idb.ports || []).join(', ')) + '</td><td>' + asset_esc(idb.fetched_at) + '</td></tr>');
			rows.push('<tr><td>CPEs</td><td>' + asset_esc((idb.cpes || []).join(', ')) + '</td><td></td></tr>');
			rows.push('<tr><td>Vulnerabilities</td><td>' + asset_esc((idb.vulns || []).join(', ')) + '</td><td></td></tr>');
			rows.push('<tr><td>Tags</td><td>' + asset_esc((idb.tags || []).join(', ')) + '</td><td></td></tr>');
		}
	}
	if (ripe) {
		rows.push('<tr><td>ASN / prefix</td><td>' + asset_esc((ripe.asn ? 'AS' + ripe.asn : '') + (ripe.prefix ? ' ' + ripe.prefix : '')) +
			'</td><td>' + asset_esc(ripe.fetched_at) + '</td></tr>');
		rows.push('<tr><td>Holder</td><td>' + asset_esc(ripe.holder) + '</td><td></td></tr>');
	}
	if (!rows.length) return '';
	return '<h5>Intel</h5><table class="table table-sm"><thead><tr><th></th><th>Value</th><th>Fetched</th></tr></thead><tbody>' +
		rows.join('') + '</tbody></table>';
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
			asset_cadence_html(a) +
			asset_risk_html(a.risk) + '<h5>Why is this mine</h5><p>' + path + '</p>' + asset_confidence_html(a) +
			'<h5>Sources</h5><table class="table table-sm"><thead><tr><th>Source</th><th>Evidence</th><th>Confidence</th><th>Seen</th></tr></thead><tbody>' +
			sources + '</tbody></table>' + asset_intel_html(a.enrichment)
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
