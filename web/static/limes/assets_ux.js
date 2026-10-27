/* Assets page: Active / Inactive tabs with counts, clear-selection and bulk rescan (at most 50 assets per call).
   Needs ux.js and asset.js (asset_project, asset_reload). Text reaches the DOM only through textContent. */
var ASSETS_RESCAN_MAX = 50;  // api.views.RescanAsset.MAX_BATCH

function assets_ux_init() {
  var project = asset_project();

  function count(activity, id) {
    var u = '/api/listDatatableAsset/?project=' + encodeURIComponent(project) + '&format=datatables&length=1' +
      (activity ? '&activity=' + activity : '');
    return fetch(u, {credentials: 'same-origin'}).then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
      if (d) document.getElementById(id).textContent = String(Number(d.recordsFiltered));
      return d ? Number(d.recordsFiltered) : null;
    }).catch(function () { return null; });
  }
  function counts() {
    count('', 'cnt_all'); count('active', 'cnt_active'); count('inactive', 'cnt_inactive');
  }

  var tabs = document.getElementById('asset_tabs'), select = LimesUx.tabs(tabs), field = document.getElementById('f_activity');
  function show(value) {
    var tab = tabs.querySelector('[data-value="' + value + '"]') || document.getElementById('tab_all');
    Array.prototype.forEach.call(tabs.querySelectorAll('[role="tab"]'), function (t) {
      var on = t === tab;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
    });
  }
  show(field.value);  // ?activity= preselects its tab
  tabs.addEventListener('lx-tab', function (e) {
    var value = tabs.querySelector('#' + e.detail.id).dataset.value;
    if (field.value === value) return;
    field.value = value;
    field.dispatchEvent(new Event('change'));
  });
  counts();
  $('#asset_results').on('draw.dt', counts);

  var clear = document.getElementById('bulk_clear');
  if (clear) clear.addEventListener('click', function () {
    $('#asset_results .asset_pick, #asset_pick_all').prop('checked', false).trigger('change');
  });

  var rescan = document.getElementById('rescan_bulk');
  if (!rescan) return;
  rescan.addEventListener('click', function () {
    var ids = tag_selected_ids();
    if (!ids.length) return;
    if (ids.length > ASSETS_RESCAN_MAX) {
      LimesUx.toast('Select at most ' + ASSETS_RESCAN_MAX + ' assets to rescan at once.', true);
      return;
    }
    if (!window.confirm('Rescan ' + ids.length + (ids.length === 1 ? ' asset' : ' assets') + '? This starts scans against the real targets.')) return;
    rescan.disabled = true;
    LimesUx.post('/api/action/asset/rescan/', {project: project, asset_ids: ids}).then(function (d) {
      if (!d.status) { LimesUx.toast(d.message, true); return; }
      var failed = (d.results || []).filter(function (r) { return !r.ok; });
      var why = failed.length ? ' ' + failed[0].message : '';
      LimesUx.toast('Rescan ' + d.message + '.' + why, failed.length === (d.results || []).length);
      asset_reload();
    }).catch(function () { LimesUx.toast('Request failed.', true); }).then(function () { rescan.disabled = false; });
  });
}
