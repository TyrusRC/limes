// Alert rules page. Rule names, tags and error texts are user or scan data: cells are filled with textContent only,
// and a saved secret is never in a response (only {set, last4}), so nothing secret is ever written into the page.

var AR = {rules: {}, meta: {}, editing: null};
var AR_SEV = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'};

function ar_el(tag, cls, text) {
	var e = document.createElement(tag);
	if (cls) e.className = cls;
	if (text !== undefined && text !== null) e.textContent = String(text);
	return e;
}

function ar_project() { return document.getElementById('ar_root').dataset.project; }

// Snackbar inserts its text as HTML, so escape it first.
function ar_toast(text) {
	var safe = String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
	Snackbar.show({text: safe, pos: 'top-right', duration: 4000});
}

function ar_call(method, url, body) {
	var opts = {method: method, credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken')}};
	if (body) opts.body = JSON.stringify(body);
	return fetch(url, opts).then(function(r) {
		if (r.status === 204) return {status: true};
		if (r.status === 403) return {status: false, message: 'You do not have permission for this action.'};
		return r.json().then(function(j) { j.ok = r.ok; return j; }, function() { return {ok: false, message: 'Unexpected answer (' + r.status + ')'}; });
	});
}

function ar_q() { return '?project=' + encodeURIComponent(ar_project()); }

function ar_conditions(r) {
	var parts = [];
	if (r.min_severity) parts.push('severity >= ' + AR_SEV[r.min_severity]);
	if (r.tags.length) parts.push('tagged ' + r.tags.join(' / '));
	if (r.score_drop_points) parts.push('score -' + r.score_drop_points + ' in ' + r.score_window_days + 'd');
	return parts.length ? parts.join('; ') : 'none';
}

function ar_result(r) {
	var td = ar_el('td');
	if (r.last_error) td.append(ar_el('span', 'text-danger', r.last_error));
	else if (r.last_sent) td.append(ar_el('span', 'l-muted', 'Sent ' + new Date(r.last_sent).toLocaleString()));
	else td.append(ar_el('span', 'l-muted', 'Never sent'));
	return td;
}

function ar_btn(label, aria, fn) {
	var b = ar_el('button', 'btn btn-ghost', label);
	b.type = 'button';
	b.setAttribute('aria-label', aria);
	b.addEventListener('click', fn);
	return b;
}

function ar_draw() {
	var body = document.getElementById('ar_rows');
	body.replaceChildren();
	var rows = Object.keys(AR.rules).map(function(k) { return AR.rules[k]; });
	if (!rows.length) {
		var tr = ar_el('tr'), td = ar_el('td', 'l-muted', 'No rules yet. Default alerts are unchanged.');
		td.colSpan = 7;
		tr.append(td); body.append(tr);
		return;
	}
	rows.forEach(function(r) {
		var tr = ar_el('tr');
		tr.append(ar_el('td', null, r.name), ar_el('td', null, r.kinds.join(', ')), ar_el('td', null, ar_conditions(r)),
			ar_el('td', null, r.channels.join(', ')), ar_result(r));
		var en = ar_el('td'), tg = ar_btn(r.enabled ? 'On' : 'Off', (r.enabled ? 'Disable ' : 'Enable ') + r.name, function() {
			ar_call('PATCH', '/api/alert_rules/' + r.id + '/' + ar_q(), {enabled: !r.enabled}).then(ar_after);
		});
		en.append(tg);
		var act = ar_el('td');
		act.append(ar_btn('Edit', 'Edit ' + r.name, function() { ar_open(r); }),
			ar_btn('Test', 'Send a test through ' + r.name, function() {
				ar_call('POST', '/api/alert_rules/' + r.id + '/test/' + ar_q(), {}).then(function(j) {
					if (!j.results) { ar_toast(j.message || 'Test failed'); return; }
					ar_toast(Object.keys(j.results).map(function(c) { return c + ': ' + j.results[c]; }).join(' | '));
					ar_load();
				});
			}),
			ar_btn('Delete', 'Delete ' + r.name, function() {
				if (confirm('Delete the rule "' + r.name + '"?')) ar_call('DELETE', '/api/alert_rules/' + r.id + '/' + ar_q()).then(ar_after);
			}));
		tr.append(en, act);
		body.append(tr);
	});
}

function ar_after(j) {
	if (j.ok === false || j.status === false) ar_toast(j.message || 'Failed');
	ar_load();
}

function ar_load() {
	return ar_call('GET', '/api/alert_rules/' + ar_q()).then(function(j) {
		if (!j.results) { ar_toast(j.message || 'Could not load rules'); return; }
		AR.meta = j.meta;
		AR.rules = {};
		j.results.forEach(function(r) { AR.rules[r.id] = r; });
		document.getElementById('ar_email_off').hidden = !!j.meta.email_configured;
		ar_draw();
	});
}

function ar_checks(box, name, values, chosen) {
	box.replaceChildren();
	values.forEach(function(v) {
		var lab = ar_el('label', 'me-3 d-inline-block'), cb = document.createElement('input');
		cb.type = 'checkbox'; cb.value = v; cb.name = name; cb.checked = chosen.indexOf(v) >= 0;
		lab.append(cb, ' ' + v);
		box.append(lab);
	});
}

function ar_checked(name) {
	return Array.prototype.map.call(document.querySelectorAll('input[name=' + name + ']:checked'), function(c) { return c.value; });
}

function ar_list(text) { return text.split(',').map(function(s) { return s.trim(); }).filter(Boolean); }

function ar_open(rule) {
	AR.editing = rule ? rule.id : null;
	var r = rule || {name: '', enabled: true, kinds: ['issue_new'], channels: ['in_app'], tags: [], email_to: [], min_severity: null};
	document.getElementById('ar_modal_title').textContent = rule ? 'Edit alert rule' : 'New alert rule';
	document.getElementById('r_name').value = r.name;
	ar_checks(document.getElementById('r_kinds'), 'kind', AR.meta.kinds || [], r.kinds);
	ar_checks(document.getElementById('r_channels'), 'channel', AR.meta.channels || [], r.channels);
	document.getElementById('r_min_severity').value = r.min_severity || '';
	document.getElementById('r_tags').value = r.tags.join(', ');
	document.getElementById('r_points').value = r.score_drop_points || '';
	document.getElementById('r_window').value = r.score_window_days || '';
	document.getElementById('r_email_to').value = r.email_to.join(', ');
	document.getElementById('r_enabled').checked = r.enabled;
	document.getElementById('ar_error').hidden = true;
	bootstrap.Modal.getOrCreateInstance(document.getElementById('ar_modal')).show();
}

function ar_num(id) { var v = document.getElementById(id).value; return v === '' ? null : parseInt(v, 10); }

function ar_save(ev) {
	ev.preventDefault();
	var body = {project: ar_project(), name: document.getElementById('r_name').value, enabled: document.getElementById('r_enabled').checked,
		kinds: ar_checked('kind'), channels: ar_checked('channel'), min_severity: ar_num('r_min_severity'),
		tags: ar_list(document.getElementById('r_tags').value), email_to: ar_list(document.getElementById('r_email_to').value),
		score_drop_points: ar_num('r_points'), score_window_days: ar_num('r_window')};
	var edit = AR.editing;
	ar_call(edit ? 'PATCH' : 'POST', edit ? '/api/alert_rules/' + edit + '/' + ar_q() : '/api/alert_rules/', body).then(function(j) {
		if (j.ok === false || j.status === false) {
			var e = document.getElementById('ar_error');
			e.textContent = j.message || 'Could not save';
			e.hidden = false;
			return;
		}
		bootstrap.Modal.getInstance(document.getElementById('ar_modal')).hide();
		ar_load();
	});
}

function ar_show_integ(j) {
	document.querySelectorAll('#ar_integ [data-f]').forEach(function(inp) {
		var k = inp.dataset.f, v = j[k];
		if (inp.dataset.secret) {
			inp.value = '';
			var st = document.querySelector('[data-state=' + k + ']');
			st.textContent = v && v.set ? 'Set' + (v.last4 ? ' (' + v.last4 + ')' : '') : 'Not set';
			document.querySelector('[data-clear=' + k + ']').checked = false;
		} else {
			inp.value = Array.isArray(v) ? v.join(', ') : (v || '');
		}
	});
}

function ar_integ_body() {
	var body = {project: ar_project()};
	document.querySelectorAll('#ar_integ [data-f]').forEach(function(inp) {
		var k = inp.dataset.f;
		if (inp.dataset.secret) {
			if (document.querySelector('[data-clear=' + k + ']').checked) body[k] = '';
			else if (inp.value) body[k] = inp.value;
		} else if (k === 'jira_labels') {
			body[k] = ar_list(inp.value);
		} else {
			body[k] = inp.value;
		}
	});
	return body;
}

function alert_rules_init() {
	document.getElementById('ar_new').addEventListener('click', function() { ar_open(null); });
	document.getElementById('ar_form').addEventListener('submit', ar_save);
	var st = document.getElementById('ar_integ_state');
	document.getElementById('ar_integ').addEventListener('submit', function(ev) {
		ev.preventDefault();
		ar_call('PUT', '/api/alert_integration/', ar_integ_body()).then(function(j) {
			if (j.ok === false || j.status === false) { st.textContent = j.message || 'Could not save'; return; }
			ar_show_integ(j);
			st.textContent = 'Saved';
		});
	});
	document.getElementById('ar_jira_test').addEventListener('click', function() {
		st.textContent = 'Creating a test issue...';
		ar_call('POST', '/api/alert_integration/jira_test/', {project: ar_project()}).then(function(j) {
			st.textContent = j.key ? 'Created ' + j.key : (j.message || 'Failed');
		});
	});
	ar_call('GET', '/api/alert_integration/' + ar_q()).then(function(j) { if (j.jira_base_url !== undefined) ar_show_integ(j); });
	ar_load();
}
