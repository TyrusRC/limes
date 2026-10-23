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

var ASSET_MONITORABLE = ['root_domain', 'hostname', 'ip', 'cidr', 'asn'];

function asset_owned(a) {
	return a.scope_tier === 'owned_root' || a.scope_tier === 'owned_host';
}

function asset_when(iso) {
	return iso ? String(iso).slice(0, 16).replace('T', ' ') + ' UTC' : '';
}

// "Monitored" cell: interval and next due, "off", or the refusal/limit reason. Everything goes through asset_esc.
function asset_monitor_html(a) {
	if (!asset_owned(a) || ASSET_MONITORABLE.indexOf(a.kind) === -1) return '';
	var m = a.monitor || {};
	if (a.cadence_tier === 'off') return 'off';
	if (m.status === 'refused') return '<span class="l-monitor-bad">Refused: ' + asset_esc(m.reason || 'no reason given') + '</span>';
	if (m.status === 'range_sweep') return '<span class="l-muted">Range sweep</span>';
	if (m.status === 'enumeration_off') return '<span class="l-muted">' + asset_esc(m.reason) + '</span>';
	if (!m.interval) return '';
	var due = m.next_due ? 'next ' + asset_when(m.next_due) : 'not checked yet';
	var note = m.status && m.status !== 'ok' ? '<br><span class="l-muted">' + asset_esc(m.status + (m.reason ? ': ' + m.reason : '')) + '</span>' : '';
	return asset_esc(m.interval) + '<br><span class="l-muted">' + asset_esc(due) + '</span>' + note;
}

function asset_actions(row) {
	var id = Number(row.id), html = '';
	if (row.scope_tier === 'candidate' || row.scope_tier === 'dependency') {
		html += '<button class="btn btn-xs btn-soft-success me-1" onclick="confirm_asset(' + id + ')">Confirm</button>';
		html += '<button class="btn btn-xs btn-soft-danger me-1" onclick="reject_asset(' + id + ')">Reject</button>';
	}
	if (row.kind === 'root_domain') {
		html += '<button class="btn btn-xs btn-soft-primary me-1" onclick="rescan_asset(' + id + ')">Rescan</button>';
	}
	if (asset_owned(row) && ASSET_MONITORABLE.indexOf(row.kind) !== -1 && row.cadence_tier !== 'off') {
		html += '<button class="btn btn-xs btn-soft-secondary" onclick="stop_monitoring(' + id + ')">Stop monitoring</button>';
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

function stop_monitoring(id) {
	asset_run_action('cadence', id, {cadence_tier: 'off'});
}

function rescan_asset(id) {
	asset_run_action('rescan', id);
}

var ASSET_CADENCES = [['crown_jewel', 'Crown jewel (daily)'], ['standard', 'Standard (weekly)'],
	['inactive', 'Inactive (monthly)'], ['off', 'Off (manual only)']];

// How often continuous monitoring rediscovers an owned root.
function asset_cadence_html(a) {
	if (!asset_owned(a) || ASSET_MONITORABLE.indexOf(a.kind) === -1) return '';
	var opts = ASSET_CADENCES.map(function(c) {
		return '<option value="' + c[0] + '"' + (a.cadence_tier === c[0] ? ' selected' : '') + '>' + c[1] + '</option>';
	}).join('');
	return '<div class="d-flex flex-wrap align-items-center gap-2"><label class="form-label mb-0" for="asset_cadence"><b>Cadence</b></label>' +
		'<select id="asset_cadence" class="form-select form-select-sm w-auto">' + opts + '</select>' +
		'<button class="btn btn-xs btn-soft-primary" onclick="set_asset_cadence(' + Number(a.id) + ')">Save</button></div>';
}

function set_asset_cadence(id) {
	var body = {asset_id: Number(id), project: asset_project(), cadence_tier: document.getElementById('asset_cadence').value};
	asset_post('/api/action/asset/cadence/', body).then(function(data) {
		asset_toast(data.message);
		if (data.status) asset_reload();
	}).catch(function() {
		asset_toast('Request failed.');
	});
}

var ASSET_SEVERITY = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'};

// Severity as a sev-* pill; takes a name ('high') or a number (3). Unknown values fall back to escaped text.
function asset_sev_html(sev) {
	var n = typeof sev === 'number' ? ASSET_SEVERITY[sev] : String(sev || '').toLowerCase();
	if (['critical', 'high', 'medium', 'low', 'info'].indexOf(n) === -1) return asset_esc(sev);
	return '<span class="sev-' + n + '">' + n.charAt(0).toUpperCase() + n.slice(1) + '</span>';
}

function asset_section(title, body) {
	return '<section><h3 class="l-section-title">' + title + '</h3>' + body + '</section>';
}

function asset_table(head, rows) {
	return '<div class="table-responsive"><table class="table table-sm mb-0"><thead><tr>' + head.map(function(h) { return '<th>' + h + '</th>'; }).join('') +
		'</tr></thead><tbody>' + rows + '</tbody></table></div>';
}

// Waived rows stay listed (the raw score still counts them) but are muted and badged instead of showing points.
function asset_penalty_rows(rows, withAsset) {
	return (rows || []).map(function(r) {
		return '<tr' + (r.waived ? ' class="l-row-waived"' : '') + '>' + (withAsset ? '<td>' + asset_esc(r.asset) + '</td>' : '') + '<td>' + asset_esc(r.issue) +
			'</td><td>' + asset_sev_html(r.severity) + '</td><td class="text-nowrap">' +
			(r.waived ? '<span class="badge l-badge-waived"><i class="fe-shield" aria-hidden="true"></i>Waived</span>' : r.provisional ? 'Provisional' : '-' + asset_esc(r.points)) + '</td></tr>';
	}).join('');
}

// Grade badge coloured like the Overview's; the class is built only from a checked A-F letter.
function asset_grade_html(grade) {
	var g = String(grade || '');
	var cls = /^[A-F]$/.test(g) ? ' ov-grade-' + g.toLowerCase() : '';
	return '<span class="ov-grade ov-grade-sm' + cls + '">' + asset_esc(g) + '</span>';
}

// Risk section of the asset modal (limes.scoring); null for assets that are not scored.
function asset_risk_html(risk) {
	if (!risk) return '';
	if (risk.assessed === false) return asset_section('Risk', '<p class="l-hint mb-0">Not yet vulnerability-scanned: no score.</p>');
	var rows = asset_penalty_rows(risk.penalties, false);
	return asset_section('<span>Risk <span class="l-score-big">' + asset_esc(risk.score) + '</span> ' + asset_grade_html(risk.grade) + '</span>',
		rows ? asset_table(['Issue', 'Severity', 'Points'], rows) : '<p class="l-hint mb-0">No open findings in the latest vulnerability scan.</p>');
}

// Risk checks table of the asset modal. Evidence carries target header/cookie text: escape every field.
function asset_checks_html(checks) {
	if (!checks || !checks.length) return '';
	var rows = checks.map(function(c) {
		var ev = Object.keys(c.evidence || {}).map(function(k) {
			var v = c.evidence[k];
			return asset_esc(k + ': ' + (typeof v === 'string' ? v : JSON.stringify(v)));
		}).join('<br>');
		var st = c.status === 'fail' ? 'badge-soft-danger' : c.status === 'pass' ? 'badge-soft-success' : 'badge-soft-secondary';
		return '<tr><td>' + asset_esc(c.title) + '</td><td><span class="badge ' + st + '">' + asset_esc(c.status) + '</span></td><td>' + asset_sev_html(c.severity) +
			'</td><td>' + asset_esc(c.fix) + '</td><td>' + ev + '</td><td class="text-nowrap">' + asset_esc(String(c.last_checked || '').slice(0, 10)) + '</td></tr>';
	}).join('');
	return asset_section('Risk checks', asset_table(['Check', 'Status', 'Severity', 'Fix', 'Evidence', 'Checked'], rows));
}

// Reputation listings (rep.* rows that fail): feed, entry, listed since, credit. Feed text is hostile: escape every field.
function asset_reputation_html(checks) {
	var rows = (checks || []).filter(function(c) { return String(c.check || '').indexOf('rep.') === 0 && c.status === 'fail'; }).map(function(c) {
		var e = c.evidence || {};
		return '<tr><td>' + asset_esc(e.feed) + '</td><td>' + asset_esc(e.entry) + '</td><td class="text-nowrap">' + asset_esc(String(e.listed_at || '').slice(0, 10) || 'unknown') +
			'</td><td>' + asset_esc(e.credit) + '</td></tr>';
	}).join('');
	return rows ? asset_section('Reputation', asset_table(['Feed', 'Entry', 'Listed since', 'Credit'], rows)) : '';
}

// InternetDB banner-matched CVEs of an IP: not verified, never scored. CVE ids are validated server-side; escape anyway.
function asset_unverified_cves_html(rows) {
	if (!rows || !rows.length) return '';
	var body = rows.map(function(r) {
		var pct = r.epss === null || r.epss === undefined ? '' : (r.epss > 0 && r.epss < 0.01 ? '<1' : Math.round(r.epss * 100)) + '%';
		return '<tr><td class="mono">' + asset_esc(r.cve) + '</td><td>' + (r.kev ? '<span class="badge l-badge-kev">KEV</span>' : '') + '</td><td class="text-nowrap">' + asset_esc(pct) + '</td></tr>';
	}).join('');
	return asset_section('Unverified CVEs (InternetDB banner)', '<p class="l-hint">Banner match, not verified, not scored.</p>' + asset_table(['CVE', 'Known exploited', 'EPSS'], body));
}

// Score sub-line under the title, and the top-penalties card above the Assets table.
function load_asset_score() {
	var box = document.getElementById('asset_score'), card = document.getElementById('asset_penalties');
	var line = function(parts) {
		box.replaceChildren.apply(box, parts.map(function(t) { var e = document.createElement('span'); e.textContent = t; return e; }));
	};
	fetch('/api/asset_score/?project=' + encodeURIComponent(asset_project()), {credentials: 'same-origin'})
		.then(function(r) { if (!r.ok) throw new Error('score'); return r.json(); })
		.then(function(s) {
			if (s.score === null) {
				line([Number(s.unassessed) > 0 ? 'No owned root has had a vulnerability scan yet: no score.' : 'No owned assets to score yet.']);
				card.hidden = true;
				return;
			}
			var parts = ['Headline score ' + s.score + ' (' + s.grade + ')'];
			if (s.raw_score !== s.score) parts.push('Raw ' + s.raw_score + ' (' + s.raw_grade + ') before waivers');
			parts.push((s.coverage === null ? 'n/a' : Math.round(Number(s.coverage) * 100) + '%') + ' of owned roots scanned for vulnerabilities in 30 days');
			if (s.check_coverage !== null && s.check_coverage !== undefined) parts.push(Math.round(Number(s.check_coverage) * 100) + '% of owned assets checked in 30 days');
			if (Number(s.unassessed) > 0) parts.push(Number(s.unassessed) + ' assets not yet scanned (not scored)');
			parts.push(String(s.version));
			line(parts);
			var rows = asset_penalty_rows(s.top_penalties, true);
			document.getElementById('asset_penalty_rows').innerHTML = rows;
			card.hidden = !rows;
		}).catch(function() {
			line(['Score unavailable.']);
			card.hidden = true;
		});
}

function asset_confidence_html(a) {
	var d = a.confidence_detail;
	if (!d || !Array.isArray(d.contributions)) return '';
	var rows = d.contributions.map(function(c) {
		return '<tr><td>' + asset_esc(c.kind) + '</td><td>' + asset_esc(c.value) + '</td><td>' + asset_esc(c.via) +
			'</td><td>' + asset_esc(c.weight) + '</td><td>' + asset_esc(c.hop) + '</td></tr>';
	}).join('') || '<tr><td colspan="5" class="l-muted">No evidence yet.</td></tr>';
	var dg = d.delegation, delegation = '';
	if (dg && typeof dg === 'object') {
		delegation = '<p class="mb-0 ' + (dg.ok === true ? 'text-success' : 'l-muted') + '">' +
			asset_esc(dg.ok === true ? 'Delegation verified at the registry' : 'Delegation not verified: ' + dg.reason) + '</p>';
	}
	return asset_section('<span>Confidence ' + asset_esc(Number(d.score).toFixed(2)) + ' <span class="l-muted">(' + asset_esc(d.version) + ')</span></span>',
		asset_table(['Evidence', 'Value', 'Via', 'Weight', 'Hop'], rows) + delegation +
		(d.would_auto_confirm === true ? '<p class="mb-0 text-warning">' +
			asset_esc('Would auto-confirm (delegation verified); auto-confirm is disabled.') + '</p>' : ''));
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
			rows.push('<tr><td>InternetDB</td><td class="l-muted">No data</td><td>' + asset_esc(idb.fetched_at) + '</td></tr>');
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
	return asset_section('Intel', asset_table(['<span class="visually-hidden">Field</span>', 'Value', 'Fetched'], rows.join('')));
}

function get_asset_modal(id) {
	asset_fetch(id).then(asset_parent_chain).then(function(chain) {
		var a = chain[0];
		var path = chain.slice().reverse().map(function(c) {
			return '<span><span class="badge bg-soft-primary me-1">' + asset_esc(c.kind) + '</span>' + asset_esc(c.value) + '</span>';
		}).join('<i class="fe-arrow-right l-muted" aria-hidden="true"></i>');
		var sources = (a.sources || []).map(function(s) {
			return '<tr><td>' + asset_esc(s.source) + '</td><td>' + asset_esc(s.evidence) + '</td><td>' +
				asset_esc(s.confidence) + '</td><td>' + asset_esc(s.seen_at) + '</td></tr>';
		}).join('') || '<tr><td colspan="4" class="l-muted">No recorded sources.</td></tr>';
		$('#modal_title').text(a.value);
		$('#modal-content').html('<div class="l-asset-modal">' +
			'<div class="l-meta-row mt-0"><span class="badge">' + asset_esc(a.kind) + '</span><span class="badge">' + asset_esc(a.scope_tier) +
			'</span><span class="badge">' + asset_esc(a.state) + '</span><span>' + asset_esc(a.vuln_count) + ' vulnerabilities</span></div>' +
			(a.decision_reason ? '<p class="mb-0"><b>Decision reason</b> ' + asset_esc(a.decision_reason) + '</p>' : '') +
			'<p class="mb-0"><b>Monitored</b> ' + (asset_monitor_html(a) || '<span class="l-muted">not monitored</span>').replace(/<br>/g, ' ') +
			' &middot; <b>Last checked</b> ' + (asset_esc(asset_when(a.last_resolved_at)) || '<span class="l-muted">never</span>') +
			' &middot; <b>Found by</b> ' + asset_esc((a.found_by || []).join(', ')) + '</p>' +
			asset_cadence_html(a) +
			asset_risk_html(a.risk) + asset_reputation_html(a.risk_checks) + asset_checks_html(a.risk_checks) + asset_unverified_cves_html(a.unverified_cves) + asset_section('Why is this mine', '<div class="l-chain">' + path + '</div>') +
			asset_confidence_html(a) + asset_section('Sources', asset_table(['Source', 'Evidence', 'Confidence', 'Seen'], sources)) +
			asset_intel_html(a.enrichment) + '</div>'
		);
		$('#modal-footer').html(asset_actions(a));
		asset_modal_wide(true);
		$('#modal_dialog').modal('show');
	}).catch(function() {
		asset_toast('Unable to load asset.');
	});
}

// The shared modal goes wide for the asset detail and back to its default size when it closes.
function asset_modal_wide(on) {
	$('#modal_dialog .modal-dialog').toggleClass('modal-xl', on);
	if (on) $('#modal_dialog').off('hidden.bs.modal.assetwide').one('hidden.bs.modal.assetwide', function() { asset_modal_wide(false); });
}

function show_add_asset_modal() {
	asset_modal_wide(false);
	$('#modal_title').text('Add assets');
	$('#modal-content').html(
		'<label class="form-label" for="asset_entries">Domains, hosts, IPs, CIDRs, start\u2013end ranges (1.2.3.0-1.2.3.255) or ASNs (AS12345); one per line or comma separated</label>' +
		'<textarea id="asset_entries" class="form-control mb-2" rows="6" placeholder="example.com&#10;app.example.com&#10;203.0.113.10"></textarea>' +
		'<label class="form-label" for="asset_csv">Or load a CSV / text file</label>' +
		'<input type="file" id="asset_csv" class="form-control mb-2" accept=".csv,.txt,text/csv,text/plain">' +
		'<label class="form-label" for="asset_tier">Scope tier</label>' +
		'<select id="asset_tier" class="form-select mb-2">' +
		'<option value="owned_host">Host: monitored only</option><option value="owned_root">Owned root: discovers subdomains</option>' +
		'<option value="co_brand">Co-brand host (passive unless authorized)</option></select>' +
		'<p class="l-hint mb-2"><b>A host added alone is watched, but its subdomains are not discovered.</b> Add the domain as an owned root to find its subdomains.</p>' +
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
