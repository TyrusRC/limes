/* Notes timeline: add and delete through the project-scoped notes API, then reload. The list itself is server-rendered (escaped). */
(function () {
  var root = document.getElementById('nt');
  if (!root) return;
  var project = root.dataset.project, type = root.dataset.type, id = Number(root.dataset.id);
  function done(d) {
    if (!d.status) { LimesUx.toast(d.message || 'Request failed.', true); return; }
    location.reload();
  }
  function fail() { LimesUx.toast('Request failed.', true); }
  var form = document.getElementById('nt_form');
  if (form) form.addEventListener('submit', function (e) {
    e.preventDefault();
    LimesUx.post('/api/notes/create/', {project: project, type: type, id: id, body: document.getElementById('nt_text').value}).then(done).catch(fail);
  });
  root.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-note-delete]');
    if (b) LimesUx.post('/api/notes/delete/', {project: project, note_id: Number(b.dataset.noteDelete)}).then(done).catch(fail);
  });
})();
