/* Limes theme switch. Loaded in <head> before the stylesheets so data-theme is set before first paint.
   localStorage['limes-theme'] holds an explicit "light"/"dark"; anything else means "follow the OS". */
(function () {
  var KEY = 'limes-theme';
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function stored() {
    try {
      var v = localStorage.getItem(KEY);
      return v === 'dark' || v === 'light' ? v : null;
    } catch (e) {
      return null;
    }
  }

  function current() {
    return root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function sync() {
    var box = document.getElementById('dark-mode-check');
    if (box) box.checked = current() === 'dark';
  }

  function apply(theme) {
    root.setAttribute('data-theme', theme === 'dark' ? 'dark' : 'light');
    sync();
  }

  function set(theme) {
    apply(theme);
    try { localStorage.setItem(KEY, current()); } catch (e) { /* private mode: still applies for this page */ }
  }

  apply(stored() || (media && media.matches ? 'dark' : 'light'));

  if (media && media.addEventListener) {
    media.addEventListener('change', function (e) { if (!stored()) apply(e.matches ? 'dark' : 'light'); });
  }

  document.addEventListener('DOMContentLoaded', sync);
  document.addEventListener('change', function (e) {
    if (e.target && e.target.id === 'dark-mode-check') set(e.target.checked ? 'dark' : 'light');
  });

  window.limesTheme = {
    get: current,
    set: set,
    toggle: function () { set(current() === 'dark' ? 'light' : 'dark'); }
  };
})();
