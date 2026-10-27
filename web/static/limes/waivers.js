/* Waivers page: revoke, approve or reject through the project-scoped API, then reload. The tables are server-rendered. */
(function () {
  var root = document.getElementById('wv');
  if (!root) return;
  var project = root.dataset.project;
  var URL = {approve: ['/api/action/waiver/decide/', {approve: true}], reject: ['/api/action/waiver/decide/', {approve: false}],
             revoke: ['/api/action/waiver/revoke/', {}]};
  root.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-act]');
    if (!b) return;
    var u = URL[b.dataset.act], body = {project: project, waiver_id: Number(b.dataset.id)};
    Object.keys(u[1]).forEach(function (k) { body[k] = u[1][k]; });
    b.disabled = true;
    LimesUx.post(u[0], body).then(function (d) {
      if (!d.status) { b.disabled = false; LimesUx.toast(d.message || 'Request failed.', true); return; }
      location.reload();
    }).catch(function () { b.disabled = false; LimesUx.toast('Request failed.', true); });
  });
})();
