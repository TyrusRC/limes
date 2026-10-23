/* Overview "What changed": the 30 / 90 day toggle only flips hidden and aria-pressed; it touches no text. */
(function () {
  var buttons = document.querySelectorAll('#dash_what_changed .ov-toggle button');
  Array.prototype.forEach.call(buttons, function (btn) {
    btn.addEventListener('click', function () {
      Array.prototype.forEach.call(buttons, function (b) {
        var on = b === btn;
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
        var panel = document.getElementById(b.getAttribute('aria-controls'));
        if (panel) panel.hidden = !on;
      });
    });
  });
})();

/* Overview score trend: ApexCharts area from the ScoreSnapshot series (json_script), coloured from the theme tokens.
   Only numbers and dates reach the DOM, and only through textContent. */
(function () {
  var dataEl = document.getElementById('score_trend_data');
  var el = document.getElementById('score_trend');
  if (!dataEl || !el) return;
  var trend = JSON.parse(dataEl.textContent).filter(function (p) { return p.score !== null; });
  if (trend.length < 2 || !window.ApexCharts) {
    document.getElementById('score_trend_empty').hidden = false;
    return;
  }

  function day(iso) {
    return new Date(Date.parse(iso)).toLocaleDateString(undefined, {month: 'short', day: 'numeric', timeZone: 'UTC'});
  }
  function signed(n) { return (n > 0 ? '+' : n < 0 ? '−' : '±') + Math.abs(n); }

  var first = trend[0], last = trend[trend.length - 1];
  var delta = document.getElementById('score_delta');
  delta.textContent = signed(last.score - first.score) + ' since ' + day(first.date);
  delta.className = 'ov-delta ' + (last.score > first.score ? 'ov-delta-up' : last.score < first.score ? 'ov-delta-down' : '');
  delta.hidden = false;

  // the largest day-over-day fall, if any, is marked on the chart and named in the legend
  var drop = null;
  for (var i = 1; i < trend.length; i++) {
    var d = trend[i].score - trend[i - 1].score;
    if (d < 0 && (!drop || d < drop.d)) drop = {d: d, p: trend[i]};
  }
  var model = null;  // first scoring-model change in the window
  for (var j = 1; j < trend.length && !model; j++) if (trend[j].version !== trend[j - 1].version) model = trend[j];

  document.getElementById('score_legend').hidden = false;
  if (drop) {
    var dropEl = document.getElementById('score_drop');
    dropEl.querySelector('span').textContent = day(drop.p.date) + ' · ' + signed(drop.d);
    dropEl.hidden = false;
  }

  var scores = trend.map(function (p) { return p.score; });
  var lo = Math.min.apply(null, scores), hi = Math.max.apply(null, scores);
  var pad = Math.max(10, Math.ceil((hi - lo) * 0.15));

  function tok(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function options() {
    var brand = tok('--brand'), crit = tok('--sev-critical'), muted = tok('--ink-3'), border = tok('--border');
    var xs = [];
    if (drop) xs.push({x: Date.parse(drop.p.date), borderColor: crit, strokeDashArray: 3});
    if (model) xs.push({x: Date.parse(model.date), borderColor: muted, strokeDashArray: 3,
      label: {text: 'model ' + model.version, borderColor: border, style: {background: tok('--surface'), color: muted, fontSize: '11px'}}});
    return {
      chart: {type: 'area', height: 230, toolbar: {show: false}, zoom: {enabled: false}, fontFamily: 'Inter, sans-serif',
              animations: {enabled: false}, background: 'transparent'},
      series: [{name: 'Headline score', data: trend.map(function (p) { return {x: Date.parse(p.date), y: p.score}; })}],
      colors: [brand],
      stroke: {width: 2, curve: 'straight'},
      fill: {type: 'solid', colors: [tok('--brand-tint')], opacity: 1},
      dataLabels: {enabled: false},
      legend: {show: false},
      markers: {size: 0, discrete: [{seriesIndex: 0, dataPointIndex: trend.length - 1, size: 4.5,
                                     fillColor: tok('--surface'), strokeColor: brand}]},
      grid: {borderColor: border, strokeDashArray: 0, padding: {left: 4, right: 8}},
      xaxis: {type: 'datetime', labels: {style: {colors: muted, fontSize: '11px'}, datetimeUTC: true},
              axisBorder: {show: false}, axisTicks: {show: false}, tooltip: {enabled: false}},
      yaxis: {min: Math.max(0, lo - pad), max: Math.min(Number(el.dataset.max) || Infinity, hi + pad), tickAmount: 3,
              labels: {style: {colors: [muted], fontSize: '11px'}, formatter: function (v) { return Math.round(v); }}},
      annotations: {xaxis: xs,
                    points: drop ? [{x: Date.parse(drop.p.date), y: drop.p.score, marker: {size: 4, fillColor: crit, strokeColor: crit}}] : []},
      tooltip: {theme: document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light',
                x: {format: 'MMM d'}}
    };
  }

  var chart = new ApexCharts(el, options());
  chart.render();
  // follow the theme toggle: re-read the tokens when data-theme changes
  new MutationObserver(function () { chart.updateOptions(options(), false, false); })
    .observe(document.documentElement, {attributes: true, attributeFilter: ['data-theme']});
})();

/* Overview live updates: poll the project's live endpoint for new change events and the Real-time card.
   Everything in the payload is untrusted: it reaches the DOM only through textContent, and the icon classes come from
   the fixed map below, never from the payload. One request at a time; paused while the tab is hidden; backs off on errors. */
(function () {
  var root = document.getElementById('ov_live');
  var feed = document.getElementById('dash_changes_feed');
  if (!root || !feed) return;
  var poll = parseInt(root.dataset.poll, 10);
  if (!(poll > 0)) return;
  var url = root.dataset.url;
  var since = parseInt(root.dataset.since, 10);
  if (isNaN(since)) return;  // no cursor: polling from 0 would replay the oldest events as new
  var MAX_ROWS = 6, MAX_BACKOFF = 300;
  var delay = poll, timer = null, inflight = false, lastOk = Date.now(), stopped = false, pageSize = 20;

  var ICONS = {  // kind -> [circle class, icon class]
    issue_fixed: ['ov-fi-ok', 'fe-check'], issue_new: ['ov-fi-bad', 'fe-alert-triangle'],
    issue_regressed: ['ov-fi-bad', 'fe-rotate-ccw'], waiver_expired: ['ov-fi-waived', 'fe-clock'],
    score_dropped: ['ov-fi-warn', 'fe-trending-down'], asset_missing: ['ov-fi-warn', 'fe-eye-off'],
    asset_auto_confirmed: ['ov-fi-ok', 'fe-globe'], asset_new: ['ov-fi-warn', 'fe-plus-circle'],
    cert_new: ['ov-fi-warn', 'fe-shield'], dns_changed: ['ov-fi-warn', 'fe-shuffle'],
    monitoring_degraded: ['ov-fi-bad', 'fe-wifi-off'], monitoring_restored: ['ov-fi-ok', 'fe-wifi'],
    breach_new: ['ov-fi-bad', 'fe-shield-off'], lookalike_new: ['ov-fi-warn', 'fe-copy'],
    lookalike_active: ['ov-fi-bad', 'fe-alert-octagon']
  };
  var PILLS = {Live: 'ov-rt-healthy', Idle: 'ov-rt-healthy', Degraded: 'ov-rt-degraded'};  // anything else is "off"

  function fmtAge(s) {  // mirrors the rt_age template filter
    if (typeof s !== 'number' || !isFinite(s)) return '—';
    s = Math.max(0, Math.floor(s));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm';
    if (s < 86400) return Math.floor(s / 3600) + 'h';
    return Math.floor(s / 86400) + 'd';
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function row(ev) {
    var icon = ICONS[ev.kind] || ['', 'fe-activity'];
    var li = el('li', 'ov-feed-new');
    li.dataset.id = String(ev.id);
    var circle = el('span', 'ov-fi ' + icon[0]);
    circle.setAttribute('aria-hidden', 'true');
    circle.appendChild(el('i', icon[1]));
    var text = el('div', 'ov-feed-text');
    text.appendChild(el('div', 'ov-feed-title', String(ev.title)));
    text.appendChild(el('div', 'ov-feed-sub', String(ev.label) + (ev.asset ? ' · ' + String(ev.asset) : '')));
    var time = el('time', 'ov-feed-time', 'just now');
    var when = new Date(ev.created_at);
    if (!isNaN(when)) { time.setAttribute('datetime', when.toISOString()); time.title = when.toLocaleString(); }
    li.appendChild(circle); li.appendChild(text); li.appendChild(time);
    return li;
  }

  function rel(t) {  // 'just now' must not stay true: re-rendered on a timer
    var s = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (s < 60) return 'just now';
    if (s < 3600) { var m = Math.floor(s / 60); return m + (m === 1 ? ' minute ago' : ' minutes ago'); }
    if (s < 86400) { var h = Math.floor(s / 3600); return h + (h === 1 ? ' hour ago' : ' hours ago'); }
    var d = Math.floor(s / 86400); return d + (d === 1 ? ' day ago' : ' days ago');
  }
  function refreshTimes() {
    Array.prototype.forEach.call(feed.querySelectorAll('time[datetime]'), function (t) {
      var when = Date.parse(t.getAttribute('datetime'));
      if (!isNaN(when)) t.textContent = rel(when);
    });
  }

  function clock() { return new Date().toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}); }
  var asof = document.getElementById('rt_asof'), cardEl = document.getElementById('dash_realtime');
  var okAt = clock();
  function setAsof(t) { if (asof) asof.textContent = 'as of ' + t; }
  setAsof(okAt);
  function notUpdating() {  // the card is frozen: say so rather than keep a stale 'Live'
    if (cardEl) cardEl.classList.add('ov-rt-notupdating');
    var pill = document.querySelector('#dash_realtime .ov-rt-pill');
    if (pill) { pill.className = 'ov-rt-pill ov-rt-stale'; pill.textContent = 'Not updating'; }
    if (asof) asof.textContent = 'Not updating, last update ' + okAt;
  }

  function addEvents(events) {
    var added = 0;
    events.forEach(function (ev) {
      if (typeof ev.id !== 'number' || ev.id <= since) return;
      since = ev.id;
      feed.insertBefore(row(ev), feed.firstChild);
      added++;
    });
    while (feed.children.length > MAX_ROWS) feed.removeChild(feed.lastChild);
    if (added) {
      var note = document.getElementById('live_announce');
      if (note) note.textContent = added === 1 ? '1 new change' : added + ' new changes';  // one short summary, not each row
      var empty = document.getElementById('dash_changes_empty');
      if (empty) empty.hidden = true;
      var stale = document.getElementById('live_stale');
      if (stale) stale.hidden = false;
    }
  }

  function pick(obj, path) {
    return path.split('.').reduce(function (o, k) { return o !== null && typeof o === 'object' ? o[k] : undefined; }, obj);
  }

  function showCard(card) {
    Array.prototype.forEach.call(document.querySelectorAll('#dash_realtime [data-rt]'), function (n) {
      var v = pick(card, n.dataset.rt);
      n.textContent = n.dataset.fmt === 'age' ? fmtAge(v) : (v === null || v === undefined || v === '' ? (n.dataset.rt === 'reason_text' || n.dataset.rt === 'watch.last_error_summary' ? '' : '—') : String(v));
    });
    var pill = document.querySelector('#dash_realtime .ov-rt-pill');
    if (pill) pill.className = 'ov-rt-pill ' + (Object.prototype.hasOwnProperty.call(PILLS, card.label) ? PILLS[card.label] : 'ov-rt-off');
  }

  function schedule(ms) {
    clearTimeout(timer);
    timer = setTimeout(tick, ms);
  }

  function tick() {
    if (inflight || document.visibilityState !== 'visible') return;
    inflight = true;
    var more = false;
    fetch(url + '?since=' + since, {credentials: 'same-origin', headers: {'Accept': 'application/json'}})
      .then(function (r) {
        if (r.redirected || r.status === 401 || r.status === 403) {  // session over: the login page, not data
          stopped = true;
          clearTimeout(timer);
          location.reload();
          throw new Error('session');
        }
        if (!r.ok) throw new Error('status ' + r.status);
        return r.json();
      })
      .then(function (body) {
        if (!body || !Array.isArray(body.events)) throw new Error('bad payload');
        addEvents(body.events);
        if (body.realtime && typeof body.realtime === 'object') showCard(body.realtime);
        if (typeof body.limit === 'number') pageSize = body.limit;
        more = body.events.length >= pageSize;  // a full page: there may be more waiting
        delay = poll;
        lastOk = Date.now();
        okAt = clock(); setAsof(okAt);
        if (cardEl) cardEl.classList.remove('ov-rt-notupdating');
      })
      .catch(function () { if (stopped) return; delay = Math.min(delay * 2, MAX_BACKOFF); notUpdating(); })
      .then(function () {
        inflight = false;
        if (!stopped && document.visibilityState === 'visible') schedule(more ? 2000 : delay * 1000);
      });
  }

  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState !== 'visible') { clearTimeout(timer); return; }
    refreshTimes();
    if (stopped) return;
    // back in view: refresh at once if the data is older than one interval, else wait out the rest of it
    var age = Date.now() - lastOk;
    schedule(age > poll * 1000 ? 0 : Math.max(0, delay * 1000 - age));
  });

  setInterval(function () { if (document.visibilityState === 'visible') refreshTimes(); }, 30000);

  var stale = document.getElementById('live_stale');
  if (stale) stale.addEventListener('click', function () { location.reload(); });

  if (document.visibilityState === 'visible') schedule(delay * 1000);
})();
