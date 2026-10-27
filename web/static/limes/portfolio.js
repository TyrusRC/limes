/* Header portfolio switcher: stores the pick in the session (server-side, validated against the project), then reloads. */
(function () {
  var menu = document.getElementById('portfolio_menu');
  if (!menu) return;
  menu.addEventListener('click', function (e) {
    var b = e.target.closest('[data-portfolio]');
    if (!b) return;
    var id = b.dataset.portfolio;
    LimesUx.post('/api/action/portfolio/select/', {project: menu.dataset.project, portfolio: id === '' ? null : Number(id)})
      .then(function (r) { if (r && r.status) location.reload(); else LimesUx.toast((r && r.message) || 'Could not switch portfolio.', true); });
  });
})();
