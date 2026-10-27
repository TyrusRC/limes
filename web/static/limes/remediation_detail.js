/* Remediation detail: status buttons post to the project-scoped API, then reload. The page is
   server-rendered (escaped by Django); this file only posts. */
(function () {
  var root = document.getElementById('rm');
  if (!root) return;
  var project = root.dataset.project, id = Number(root.dataset.id);
  function done(d) {
    if (!d.status) { LimesUx.toast(d.message || 'Request failed.', true); return; }
    location.reload();
  }
  function fail() { LimesUx.toast('Request failed.', true); }
  var actions = document.getElementById('rm_actions');
  if (actions) actions.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-status]');
    if (b) LimesUx.post('/api/remediation/status/', {project: project, id: id, status: b.dataset.status}).then(done).catch(fail);
  });
})();
