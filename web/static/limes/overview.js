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
