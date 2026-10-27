/* Issues page: one row per risk (api/issues?group=1), worst first, rows expand to their assets, chips filter the list.
   Scan- and user-supplied text (titles, asset names, tags) reaches the DOM only through textContent. */
(function () {
  var root = document.getElementById('iss');
  if (!root) return;
  var el = LimesUx.el, project = root.dataset.project, PAGE = 50;
  var SEV = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'};
  var KEYS = ['severity', 'category', 'source', 'waived', 'kev', 'tag'];
  var filters = {}, groups = [], shown = PAGE, seq = 0, score = null;

  function detailUrl(id) { return root.dataset.detail.replace('/0/', '/' + Number(id) + '/'); }
  function day(v) { return String(v || '').slice(0, 10); }
  function $(id) { return document.getElementById(id); }
  function icon(cls) { var i = el('i', cls); i.setAttribute('aria-hidden', 'true'); return i; }

  function apiUrl() {
    var u = '/api/issues/?group=1&project=' + encodeURIComponent(project);
    KEYS.forEach(function (k) { if (filters[k]) u += '&' + k + '=' + encodeURIComponent(filters[k]); });
    return u;
  }

  function syncUrl() {
    var p = new URLSearchParams();
    KEYS.forEach(function (k) { if (filters[k]) p.set(k, filters[k]); });
    history.replaceState(null, '', location.pathname + (p.toString() ? '?' + p.toString() : ''));
    $('iss_clear').hidden = !KEYS.some(function (k) { return filters[k]; }) && !$('iss_q').value;
    Array.prototype.forEach.call(document.querySelectorAll('#iss .lx-chip[data-k]'), function (c) {
      c.setAttribute('aria-pressed', filters[c.dataset.k] === c.dataset.v ? 'true' : 'false');
    });
  }

  function sevCell(g) {
    var td = el('td');
    if (g.provisional) {
      td.append(el('span', 'badge lx-info', 'Informational'), el('div', 'l-hint', 'provisional, not scored'));
    } else if (SEV[g.severity]) {
      td.append(el('span', 'sev-' + SEV[g.severity], SEV[g.severity].charAt(0).toUpperCase() + SEV[g.severity].slice(1)));
    }
    return td;
  }

  function statusBadge(g) {
    var map = {waived: ['l-badge-waived', 'Waived'], expired: ['l-badge-expired', 'Waiver expired'], open: ['l-badge-open', 'Open'],
               partial: ['l-badge-waived', g.waived_count + ' of ' + g.count + ' waived']};
    var m = map[g.status] || map.open;
    return el('span', 'badge ' + m[0], m[1]);
  }

  function assetStatus(a) {
    return a.waiver ? el('span', 'badge l-badge-waived', 'Waived') : a.expired_waiver ? el('span', 'badge l-badge-expired', 'Waiver expired') : el('span', 'badge l-badge-open', 'Open');
  }

  function subRow(g, id) {
    var tr = el('tr', 'lx-subrow'), td = el('td');
    tr.id = id;
    td.colSpan = 8;
    var ul = el('ul', 'lx-sublist');
    g.assets.forEach(function (a) {
      var li = el('li'), link = el('a', 'mono', a.asset);
      link.href = detailUrl(a.id);
      li.append(link, el('span', 'l-muted', 'First detected ' + day(a.first_seen)), assetStatus(a));
      ul.append(li);
    });
    if (g.count > g.assets.length) ul.append(el('li', 'l-hint', (g.count - g.assets.length) + ' more assets not listed'));
    td.append(ul);
    tr.append(td);
    return tr;
  }

  function row(g, n) {
    var tr = el('tr'), subId = 'iss_sub_' + n, open = false, sub = null;
    var pick = el('td', 'l-col-check'), cb = el('input', 'form-check-input iss_pick');
    cb.type = 'checkbox';
    cb.value = g.unwaived_ids.join(',');
    cb.disabled = !g.unwaived_ids.length;
    cb.setAttribute('aria-label', 'Select ' + g.title);
    pick.append(cb);
    var ex = el('td'), btn = el('button', 'lx-expander');
    btn.type = 'button';
    btn.setAttribute('aria-expanded', 'false');
    btn.setAttribute('aria-controls', subId);
    btn.setAttribute('aria-label', 'Show ' + g.count + (g.count === 1 ? ' asset' : ' assets') + ' for ' + g.title);
    btn.append(icon('fe-chevron-right'));
    btn.addEventListener('click', function () {
      open = !open;
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) { sub = subRow(g, subId); tr.after(sub); } else if (sub) { sub.remove(); }
    });
    ex.append(btn);
    var title = el('td', 'l-col-wider'), link = el('a', 'lx-title', g.title);
    link.href = detailUrl(g.id);
    title.append(link);
    if (g.kev) title.append(' ', el('span', 'badge l-badge-kev', 'KEV'));
    if (g.source === 'check') title.append(el('div', 'l-hint mono', g.key));
    var assets = el('td', 'text-nowrap', g.count + (g.count === 1 ? ' asset' : ' assets'));
    if (g.count === 1) { assets.className = 'mono'; assets.textContent = g.assets[0].asset; }
    var st = el('td');
    st.append(statusBadge(g));
    tr.append(pick, ex, sevCell(g), title, el('td', 'lx-hide-sm', g.category_label), assets, el('td', 'text-nowrap l-muted lx-hide-sm', day(g.first_seen)), st);
    return tr;
  }

  function matches(g, q) {
    if (!q) return true;
    q = q.toLowerCase();
    return g.title.toLowerCase().indexOf(q) !== -1 || g.key.toLowerCase().indexOf(q) !== -1 ||
      g.assets.some(function (a) { return a.asset.toLowerCase().indexOf(q) !== -1; });
  }

  function stateBox(kind, title, text, action) {
    var box = el('div', 'lx-state' + (kind === 'error' ? ' lx-error' : ''));
    box.append(icon(kind === 'error' ? 'fe-alert-triangle' : kind === 'loading' ? 'fe-loader' : 'fe-check-circle'), el('strong', null, title));
    if (text) box.append(el('span', null, text));
    if (action) { var b = el('button', 'btn btn-light', action[0]); b.type = 'button'; b.addEventListener('click', action[1]); box.append(b); }
    $('iss_state').replaceChildren(box);
  }

  function render() {
    var q = $('iss_q').value.trim(), list = groups.filter(function (g) { return matches(g, q); });
    var body = $('iss_body'), n = 0;
    body.replaceChildren();
    list.slice(0, shown).forEach(function (g) { body.append(row(g, n++)); });
    var assets = list.reduce(function (s, g) { return s + g.count; }, 0);
    $('iss_summary').textContent = list.length ? list.length + (list.length === 1 ? ' risk' : ' risks') + ' on ' + assets + (assets === 1 ? ' asset' : ' assets') : 'No risks';
    $('iss_more').hidden = list.length <= shown;
    $('iss_pick_all').disabled = !list.length;
    if (!list.length) {
      var filtered = KEYS.some(function (k) { return filters[k]; }) || q;
      if (filtered) stateBox('empty', 'No issues match these filters', 'Remove a filter to see more.', ['Clear filters', clearAll]);
      else stateBox('empty', 'No open issues', 'Nothing needs attention right now. New findings appear here after the next scan.');
    } else {
      $('iss_state').replaceChildren();
    }
    forecast();
  }

  function load() {
    var mine = ++seq;
    syncUrl();
    $('iss_card').setAttribute('aria-busy', 'true');
    stateBox('loading', 'Loading issues', '');
    fetch(apiUrl(), {credentials: 'same-origin'}).then(function (r) {
      if (!r.ok) throw new Error('issues');
      return r.json();
    }).then(function (rows) {
      if (mine !== seq) return;
      groups = rows;
      shown = PAGE;
      render();
    }).catch(function () {
      if (mine !== seq) return;
      groups = [];
      $('iss_body').replaceChildren();
      $('iss_summary').textContent = 'Issues unavailable';
      stateBox('error', 'Could not load issues', 'Check your connection and try again.', ['Try again', load]);
      LimesUx.toast('Could not load issues.', true);
    }).then(function () { if (mine === seq) $('iss_card').setAttribute('aria-busy', 'false'); });
  }

  function clearAll() {
    filters = {};
    $('iss_q').value = '';
    load();
  }

  /* fix forecast for the ticked rows */
  var fseq = 0;
  function picked() {
    var ids = [];
    Array.prototype.forEach.call(document.querySelectorAll('#iss_body .iss_pick:checked'), function (c) {
      c.value.split(',').forEach(function (v) { if (v) ids.push(Number(v)); });
    });
    return ids;
  }
  function forecast() {
    var mine = ++fseq, box = $('issue_forecast'), ids = picked();
    var cbs = document.querySelectorAll('#iss_body .iss_pick:not(:disabled)');
    var on = document.querySelectorAll('#iss_body .iss_pick:checked').length;
    var all = $('iss_pick_all');
    all.checked = cbs.length > 0 && on === cbs.length;
    all.indeterminate = on > 0 && on < cbs.length;
    Array.prototype.forEach.call(cbs, function (c) { c.closest('tr').classList.toggle('l-selected', c.checked); });
    if (!ids.length) { box.hidden = true; return; }
    var rem = $('fc_remediate');
    if (rem) rem.href = rem.pathname + '?issues=' + ids.slice(0, 200).join(',');
    LimesUx.post('/api/score_forecast/', {project: project, issues: ids.slice(0, 500)}).then(function (d) {
      if (mine !== fseq) return;
      if (!d.status || d.score === null || d.score === undefined) { box.hidden = true; return; }
      var delta = Number(d.delta);
      $('fc_score').textContent = d.score;
      $('fc_grade').textContent = d.grade;
      $('fc_delta').textContent = (delta >= 0 ? '+' : '') + delta;
      $('fc_count').textContent = on + (on === 1 ? ' risk' : ' risks') + ' selected';
      $('fc_current').textContent = score ? ' · current score ' + score.score + ' (' + score.grade + ')' : '';
      box.hidden = false;
    }).catch(function () { if (mine === fseq) box.hidden = true; });
  }

  function loadScore() {
    var box = $('issue_score');
    fetch('/api/asset_score/?project=' + encodeURIComponent(project), {credentials: 'same-origin'})
      .then(function (r) { if (!r.ok) throw new Error('score'); return r.json(); })
      .then(function (s) {
        box.replaceChildren();
        score = s.score === null ? null : s;
        if (s.score === null) return;
        var parts = ['Headline score ' + s.score + ' (' + s.grade + ')'];
        if (s.raw_score !== s.score) parts.push('Raw ' + s.raw_score + ' (' + s.raw_grade + ') before waivers');
        parts.push(s.waived_count + ' waived');
        parts.forEach(function (t) { box.append(el('span', null, t)); });
      }).catch(function () { score = null; box.replaceChildren(); });
  }

  function loadTags() {
    fetch('/api/tags/?project=' + encodeURIComponent(project), {credentials: 'same-origin'})
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (rows) {
        var box = $('tag_chips');
        rows.slice(0, 12).forEach(function (t) {
          var b = el('button', 'lx-chip', t.name);
          b.type = 'button';
          b.dataset.k = 'tag';
          b.dataset.v = t.name;
          b.setAttribute('aria-pressed', filters.tag === t.name ? 'true' : 'false');
          box.append(b);
        });
        box.hidden = !rows.length;
      }).catch(function () {});
  }

  /* wiring */
  var q = new URLSearchParams(location.search);
  KEYS.forEach(function (k) { if (q.get(k)) filters[k] = q.get(k).slice(0, 100); });
  root.addEventListener('click', function (e) {
    var chip = e.target.closest('.lx-chip[data-k]');
    if (!chip) return;
    filters[chip.dataset.k] = filters[chip.dataset.k] === chip.dataset.v ? '' : chip.dataset.v;
    load();
  });
  var typing = null;
  $('iss_q').addEventListener('input', function () {
    clearTimeout(typing);
    typing = setTimeout(function () { shown = PAGE; syncUrl(); render(); }, 150);
  });
  $('iss_clear').addEventListener('click', clearAll);
  $('iss_more_btn').addEventListener('click', function () { shown += PAGE; render(); });
  $('iss_body').addEventListener('change', function (e) { if (e.target.classList.contains('iss_pick')) forecast(); });
  $('iss_pick_all').addEventListener('change', function () {
    var on = this.checked;
    Array.prototype.forEach.call(document.querySelectorAll('#iss_body .iss_pick:not(:disabled)'), function (c) { c.checked = on; });
    forecast();
  });
  $('fc_clear').addEventListener('click', function () {
    Array.prototype.forEach.call(document.querySelectorAll('#iss_body .iss_pick'), function (c) { c.checked = false; });
    forecast();
  });
  loadScore();
  loadTags();
  load();
})();
