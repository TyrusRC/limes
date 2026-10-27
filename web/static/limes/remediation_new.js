/* Remediation wizard: 1 select issues, 2 recipients and message, 3 review with the live score impact, then submit.
   Issue titles, asset names and typed text reach the DOM only through textContent. The impact is the score forecast
   the Issues page uses (POST /api/score_forecast/); nothing is recomputed here. */
(function () {
  var root = document.getElementById('rw');
  if (!root) return;
  var el = LimesUx.el, project = root.dataset.project, MAX = Number(root.dataset.maxIssues), MAX_EMAILS = Number(root.dataset.maxEmails);
  var groups = [], picked = new Set(), expanded = {}, names = {}, step = 1, fseq = 0;
  function $(id) { return document.getElementById(id); }
  function detailUrl(id) { return root.dataset.detail.replace('/0/', '/' + Number(id) + '/'); }

  var pre = new URLSearchParams(location.search).get('issues') || '';
  pre.split(',').slice(0, MAX).forEach(function (v) { if (/^[0-9]{1,18}$/.test(v)) picked.add(Number(v)); });

  function show(n) {
    step = n;
    [1, 2, 3].forEach(function (i) {
      $('rp' + i).hidden = i !== n;
      var s = $('rs' + i);
      if (i === n) s.setAttribute('aria-current', 'step'); else s.removeAttribute('aria-current');
    });
    window.scrollTo(0, 0);
  }

  /* step 1 */
  function matches(g, q) {
    if (!q) return true;
    q = q.toLowerCase();
    return g.title.toLowerCase().indexOf(q) !== -1 || g.key.toLowerCase().indexOf(q) !== -1 ||
      g.assets.some(function (a) { return a.asset.toLowerCase().indexOf(q) !== -1; });
  }
  function box(label, checked, onChange) {
    var cb = el('input', 'form-check-input');
    cb.type = 'checkbox';
    cb.checked = checked;
    cb.setAttribute('aria-label', label);
    cb.addEventListener('change', function () { onChange(cb.checked); });
    return cb;
  }
  function toggle(ids, on) {
    ids.forEach(function (id) {
      if (!on) picked.delete(id);
      else if (picked.size < MAX || picked.has(id)) picked.add(id);
    });
    if (on && ids.some(function (id) { return !picked.has(id); })) LimesUx.toast('A request holds at most ' + MAX + ' issues.', true);
    renderList();
  }
  function renderList() {
    var q = $('rw_q').value.trim(), list = $('rw_list');
    var shown = groups.filter(function (g) { return matches(g, q); });
    list.replaceChildren();
    shown.forEach(function (g, n) {
      var ids = g.unwaived_ids, on = ids.filter(function (id) { return picked.has(id); }).length;
      var row = el('div', 'd-flex align-items-center gap-2 py-1');
      var cb = box('Select ' + g.title, ids.length > 0 && on === ids.length, function (c) { toggle(ids, c); });
      cb.disabled = !ids.length;
      cb.indeterminate = on > 0 && on < ids.length;
      var btn = el('button', 'lx-expander');
      btn.type = 'button';
      btn.setAttribute('aria-expanded', expanded[g.source + g.key] ? 'true' : 'false');
      btn.setAttribute('aria-label', 'Show assets for ' + g.title);
      var ic = el('i', 'fe-chevron-right');
      ic.setAttribute('aria-hidden', 'true');
      btn.append(ic);
      btn.addEventListener('click', function () { expanded[g.source + g.key] = !expanded[g.source + g.key]; renderList(); });
      row.append(cb, btn, el('span', 'fw-semibold', g.title), el('span', 'l-muted', g.category_label + ' · ' + on + ' of ' + g.count + ' assets'));
      list.append(row);
      if (expanded[g.source + g.key]) {
        var ul = el('ul', 'rm-assets');
        g.assets.forEach(function (a) {
          var li = el('li'), waived = !!a.waiver;
          var c = box(a.asset, picked.has(a.id), function (v) { toggle([a.id], v); });
          c.disabled = waived;
          li.append(c, el('span', 'mono', a.asset), waived ? el('span', 'badge l-badge-waived', 'Waived') : '');
          ul.append(li);
        });
        if (g.count > g.assets.length) ul.append(el('li', 'l-hint', (g.count - g.assets.length) + ' more assets: select the whole risk to include them'));
        list.append(ul);
      }
    });
    if (!shown.length) list.append(el('p', 'l-hint', groups.length ? 'No issues match.' : 'No open issues.'));
    $('rw_count').textContent = picked.size;
    $('rw_next1').disabled = picked.size === 0;
  }
  function load() {
    var u = '/api/issues/?group=1&project=' + encodeURIComponent(project) + ($('rw_cat').value ? '&category=' + encodeURIComponent($('rw_cat').value) : '');
    $('rw_list').setAttribute('aria-busy', 'true');
    fetch(u, {credentials: 'same-origin'}).then(function (r) { if (!r.ok) throw new Error('issues'); return r.json(); }).then(function (rows) {
      groups = rows;
      rows.forEach(function (g) { g.assets.forEach(function (a) { names[a.id] = a.asset; }); });
      $('rw_list').setAttribute('aria-busy', 'false');
      renderList();
    }).catch(function () {
      $('rw_list').replaceChildren(el('p', 'l-hint text-danger', 'Could not load issues.'));
    });
  }
  var typing = null;
  $('rw_q').addEventListener('input', function () { clearTimeout(typing); typing = setTimeout(renderList, 150); });
  $('rw_cat').addEventListener('change', load);
  $('rw_next1').addEventListener('click', function () { show(2); });

  /* step 2 */
  fetch('/api/members/?project=' + encodeURIComponent(project), {credentials: 'same-origin'}).then(function (r) { return r.ok ? r.json() : []; })
    .then(function (rows) { rows.forEach(function (n) { var o = el('option', null, n); o.value = n; $('rw_assignee').append(o); }); }).catch(function () {});
  function emails() {
    return $('rw_emails').value.split(/[\s,;]+/).filter(Boolean);
  }
  function err(text) { var e = $('rw_err2'); e.textContent = text || ''; e.hidden = !text; }
  $('rw_back2').addEventListener('click', function () { show(1); });
  $('rw_form').addEventListener('submit', function (e) {
    e.preventDefault();
    if (!$('rw_title').value.trim()) { err('Give the request a title.'); $('rw_title').focus(); return; }
    if (emails().length > MAX_EMAILS) { err('At most ' + MAX_EMAILS + ' external recipients.'); return; }
    err('');
    review();
    show(3);
  });

  /* step 3 */
  function review() {
    var dl = $('rw_review'), ids = Array.from(picked);
    var assets = new Set(ids.map(function (i) { return names[i]; }).filter(Boolean));
    var rows = [['Title', $('rw_title').value.trim()], ['Issues', String(ids.length)], ['Assets', String(assets.size || '')],
      ['Assigned to', $('rw_assignee').value || 'No one'], ['External recipients', emails().join(', ') || 'None'],
      ['Due', $('rw_due').value || 'No due date'], ['Message', $('rw_msg').value.trim() || '(none)']];
    dl.replaceChildren();
    rows.forEach(function (r) { var dd = el('dd', 'rm-text', r[1]); dl.append(el('dt', null, r[0]), dd); });
    var mine = ++fseq, out = $('rw_impact');
    out.replaceChildren(el('p', 'l-hint', 'Calculating'));
    LimesUx.post('/api/score_forecast/', {project: project, issues: ids.slice(0, 500)}).then(function (d) {
      if (mine !== fseq) return;
      if (!d.status || d.score === null || d.score === undefined) { out.replaceChildren(el('p', 'l-hint', 'No score change to forecast.')); return; }
      var delta = Number(d.delta);
      out.replaceChildren(el('p', 'lx-gain', (delta >= 0 ? '+' : '') + delta),
        el('p', null, 'If all ' + ids.length + ' are fixed the score becomes ' + d.score + ' (grade ' + d.grade + ').'));
    }).catch(function () { if (mine === fseq) out.replaceChildren(el('p', 'l-hint', 'Forecast unavailable.')); });
  }
  $('rw_back3').addEventListener('click', function () { show(2); });
  $('rw_submit').addEventListener('click', function () {
    var b = this;
    b.disabled = true;
    var body = {project: project, title: $('rw_title').value, message: $('rw_msg').value, issues: Array.from(picked), emails: emails()};
    if ($('rw_due').value) body.due_date = $('rw_due').value;
    if ($('rw_assignee').value) body.assignee = $('rw_assignee').value;
    LimesUx.post('/api/remediation/create/', body).then(function (d) {
      if (!d.status) { b.disabled = false; LimesUx.toast(d.message || 'Could not create the request.', true); return; }
      location.href = detailUrl(d.id);
    }).catch(function () { b.disabled = false; LimesUx.toast('Request failed.', true); });
  });

  load();
})();
