/* Risk detail page: waive, revoke and add a note through the existing issue APIs, then reload so the page shows the saved state.
   The page itself is server-rendered (escaped by Django); this file only posts. */
(function () {
  var root = document.getElementById('rd');
  if (!root) return;
  var project = root.dataset.project, issueId = Number(root.dataset.issue);

  function done(d, msg) {
    LimesUx.toast(d.status ? msg : d.message, !d.status);
    if (d.status) setTimeout(function () { location.reload(); }, 600);
  }
  function fail() { LimesUx.toast('Request failed.', true); }
  function iso(days) { return new Date(Date.now() + days * 86400000).toISOString().slice(0, 10); }

  var form = document.getElementById('rd_waive_form');
  if (form) {
    var kind = document.getElementById('rd_kind'), exp = document.getElementById('rd_expiry');
    exp.min = iso(1); exp.max = iso(365);  // posts as UTC midnight: tomorrow..+365 days only
    var sync = function () { exp.value = kind.value === 'accepted_risk' ? iso(90) : ''; };
    kind.addEventListener('change', sync);
    sync();
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var body = {project: project, issue_id: issueId, kind: kind.value, reason: document.getElementById('rd_reason').value};
      if (exp.value) body.expires_at = exp.value + 'T00:00:00Z';
      LimesUx.post('/api/action/issue/waive/', body).then(function (d) { done(d, 'Waived.'); }).catch(fail);
    });
  }
  var revoke = document.getElementById('rd_revoke');
  if (revoke) revoke.addEventListener('click', function () {
    LimesUx.post('/api/action/issue/revoke/', {project: project, issue_id: issueId}).then(function (d) { done(d, 'Revoked.'); }).catch(fail);
  });
  var note = document.getElementById('rd_note_form');
  if (note) note.addEventListener('submit', function (e) {
    e.preventDefault();
    var box = document.getElementById('rd_note_text');
    LimesUx.post('/api/issue/notes/', {project: project, issue_id: issueId, text: box.value}).then(function (d) { done(d, 'Note added.'); }).catch(fail);
  });
  // Scanner evidence for a finding, from the same project-scoped endpoint the API serves; scanner output only ever becomes textContent.
  var evBox = document.getElementById('rd_evidence');
  if (evBox) {
    var el = LimesUx.el;
    var item = function (e) {
      var box = el('div', 'mb-3');
      box.append(el('div', 'fw-semibold text-break', e.name));
      var facts = [e.http_url, e.matcher_name, e.cvss_score !== null && e.cvss_score !== undefined ? 'CVSS ' + e.cvss_score : '',
        (e.cves || []).join(', ')].filter(Boolean);
      if (facts.length) box.append(el('div', 'small l-muted text-break', facts.join(' \u00b7 ')));
      [['Description', e.description], ['Impact', e.impact], ['Remediation', e.remediation], ['Request', e.request],
        ['Response', e.response], ['Reproduce', e.curl_command], ['Extracted', (e.extracted_results || []).join('\n')],
        ['References', (e.references || []).join('\n')]].forEach(function (f) {
        if (!f[1]) return;
        var d = document.createElement('details');
        d.append(el('summary', null, f[0]), el('pre', 'small text-break', f[1]));
        box.append(d);
      });
      return box;
    };
    fetch('/api/issue/evidence/?project=' + encodeURIComponent(project) + '&issue_id=' + issueId, {credentials: 'same-origin'})
      .then(function (r) { if (!r.ok) throw new Error('evidence'); return r.json(); })
      .then(function (rows) {
        evBox.replaceChildren.apply(evBox, rows.length ? rows.map(item) : [el('p', 'l-hint', 'No open scanner evidence.')]);
      })
      .catch(function () { evBox.replaceChildren(el('p', 'l-hint', 'Evidence unavailable.')); });
  }
})();
