/* Home feed: All activity / My tasks tabs, dismiss one card or the whole tab. Cards are server-rendered (escaped by
   Django); this file only posts keys and removes nodes. */
(function () {
  var root = document.getElementById('home');
  if (!root) return;
  var project = root.dataset.project, MAX = 100;  // api.feed.MAX_KEYS
  LimesUx.tabs(document.getElementById('home_tabs'));

  function counts() {
    [['hp_activity', 'hc_activity'], ['hp_tasks', 'hc_tasks']].forEach(function (p) {
      var panel = document.getElementById(p[0]), n = panel.querySelectorAll('.lx-card').length;
      document.getElementById(p[1]).textContent = String(n);
      panel.querySelector('[data-caught-up]').hidden = n > 0;
      panel.querySelector('[data-dismiss-all]').hidden = n === 0;
    });
  }

  function dismiss(cards, button) {
    var keys = cards.map(function (c) { return c.dataset.key; });
    if (!keys.length) return;
    button.disabled = true;
    LimesUx.post('/api/action/feed/dismiss/', {project: project, keys: keys}).then(function (d) {
      if (!d.status) { LimesUx.toast(d.message, true); return; }
      var next = cards[0].nextElementSibling || cards[0].previousElementSibling;
      cards.forEach(function (c) { c.remove(); });
      counts();
      LimesUx.toast(keys.length === 1 ? 'Dismissed.' : 'Dismissed ' + keys.length + ' cards.');
      if (next && keys.length === 1) { var b = next.querySelector('[data-dismiss]'); if (b) b.focus(); }
    }).catch(function () { LimesUx.toast('Request failed.', true); }).then(function () { button.disabled = false; });
  }

  root.addEventListener('click', function (e) {
    var one = e.target.closest('[data-dismiss]');
    if (one) { dismiss([one.closest('.lx-card')], one); return; }
    var all = e.target.closest('[data-dismiss-all]');
    if (all) {
      var cards = Array.prototype.slice.call(document.getElementById(all.dataset.dismissAll).querySelectorAll('.lx-card'), 0, MAX);
      dismiss(cards, all);
    }
  });
})();
