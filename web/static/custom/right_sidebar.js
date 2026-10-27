// Right-hand scan activity bar: running, queued and recently finished scans of the current project.
// Every value reaches the DOM as textContent; nothing is concatenated into HTML.

function rs_el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}

function rs_csrf() {
  var m = document.cookie.match(/(?:^|; )csrftoken=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : '';
}

function rs_title(scan) {
  return (scan.scan_type && scan.scan_type.engine_name || '') + ' on ' + (scan.domain && scan.domain.name || '');
}

function rs_counts(scan) {
  var row = rs_el('div');
  [['badge-soft-info', scan.subdomain_count], ['badge-soft-primary', scan.endpoint_count], ['badge-soft-danger', scan.vulnerability_count]].forEach(function(c) {
    row.append(rs_el('span', 'badge ' + c[0] + ' me-1', c[1] === null || c[1] === undefined ? 0 : c[1]));
  });
  return row;
}

function rs_card(color, title, badge, lines, inside, after) {
  var card = rs_el('div', 'card border-' + color + ' border mini-card');
  var link = rs_el('a', 'text-reset item-hovered');
  link.href = '/scan/' + encodeURIComponent(document.body.dataset.currentProject) + '/history/scan';
  var head = rs_el('div', 'card-header bg-soft-' + color + ' text-' + color + ' mini-card-header', title);
  var body = rs_el('div', 'card-body mini-card-body');
  var p = rs_el('p', 'card-text');
  if (badge) p.append(rs_el('span', 'float-end badge bg-' + color, badge));
  p.append(rs_el('span', null, lines));
  body.append(p);
  (inside || []).forEach(function(e) { body.append(e); });
  link.append(head, body);
  card.append(link);
  (after || []).forEach(function(e) { card.append(e); });
  return card;
}

function rs_fill(id, nodes, emptyText) {
  var box = document.getElementById(id);
  if (!box) return;
  box.replaceChildren.apply(box, nodes.length ? nodes : [rs_el('div', 'alert alert-info', emptyText)]);
}

function getScanStatusSidebar(project) {
  $.getJSON('/api/scan_status/?project=' + encodeURIComponent(project), function(data) {
    var scans = data.scans;
    rs_fill('upcoming_scans', scans.pending.map(function(s) { return rs_el('div', 'alert alert-warning', rs_title(s)); }), 'No upcoming scans.');
    var pending = document.getElementById('pending_scan_count');
    if (pending) pending.textContent = scans.pending.length || '';
    var counter = document.getElementById('current_scan_counter');
    if (counter) counter.textContent = scans.scanning.length || '';
    var running = document.getElementById('current_scan_count');
    if (running) running.textContent = scans.scanning.length ? scans.scanning.length + ' scans currently running' : '';

    rs_fill('currently_scanning', scans.scanning.map(function(s) {
      var stop = rs_el('button', 'btn btn-xs btn-soft-danger m-1 float-end', 'Stop');
      stop.type = 'button';
      stop.addEventListener('click', function() { stop_scan(s.id, project); });
      var pct = Number(s.current_progress) || 0;
      var bar = rs_el('div', 'progress mt-2');
      bar.style.height = '4px';
      var fill = rs_el('div', 'progress-bar progress-bar-striped progress-bar-animated bg-primary');
      fill.style.width = Math.min(100, pct) + '%';
      bar.append(fill);
      return rs_card('primary', rs_title(s), pct + '%', 'Started ' + s.elapsed_time + ' ago.', [rs_counts(s), bar], [stop]);
    }), 'No scans are currently running.');

    var status = {0: ['danger', 'Failed'], 3: ['danger', 'Aborted'], 2: ['success', 'Completed']};
    rs_fill('completed', scans.completed.map(function(s) {
      var st = status[s.scan_status] || ['secondary', 'Unknown'];
      return rs_card(st[0], rs_title(s), st[1], st[1] + ' ' + s.completed_ago + ' ago', [rs_counts(s)]);
    }), 'No scans have been recently completed.');
  });
}

// Asks first, then aborts the scan through the API and reloads the bar.
function stop_scan(scan_id, project) {
  if (!confirm('Stop this scan?')) return;
  fetch('/api/action/stop/scan/', {
    method: 'POST', credentials: 'same-origin',
    headers: {'X-CSRFToken': rs_csrf(), 'Content-Type': 'application/json'},
    body: JSON.stringify({scan_ids: [Number(scan_id)]})
  }).then(function(r) { return r.json(); }).then(function() {
    getScanStatusSidebar(project);
  });
}
