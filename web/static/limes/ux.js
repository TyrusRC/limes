/* Shared UX helpers (vanilla, no dependencies). Text reaches the DOM only through textContent.
   LimesUx.toast(text, isError)  one look for every action result, announced politely
   LimesUx.post(url, body)       JSON POST with the CSRF token; resolves to the parsed body, 403 becomes a message
   LimesUx.el(tag, cls, text)    element builder
   LimesUx.tabs(root)            ARIA tablist: click, arrows, Home, End; dispatches 'lx-tab' on the root.
                                 data-shared-panel on the root: every tab controls one panel that stays visible. */
(function () {
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  var stack = null;
  function toast(text, isError) {
    if (!stack) {
      stack = el('div', 'lx-toasts');
      stack.setAttribute('role', 'status');
      stack.setAttribute('aria-live', 'polite');
      document.body.appendChild(stack);
    }
    var t = el('div', 'lx-toast' + (isError ? ' is-error' : ''), text);
    stack.appendChild(t);
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, isError ? 6000 : 3500);
  }

  function csrf() {
    var m = document.cookie.match(/(?:^|; )csrftoken=([^;]*)/);
    return m ? decodeURIComponent(m[1]) : '';
  }

  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf()},
      body: JSON.stringify(body)
    }).then(function (r) {
      if (r.status === 403) return {status: false, message: 'You do not have permission for this action.'};
      return r.json();
    });
  }

  function tabs(root) {
    var list = root.querySelectorAll('[role="tab"]');
    function select(tab, focus) {
      Array.prototype.forEach.call(list, function (t) {
        var on = t === tab;
        t.setAttribute('aria-selected', on ? 'true' : 'false');
        t.tabIndex = on ? 0 : -1;
        var panel = document.getElementById(t.getAttribute('aria-controls'));
        if (panel && !root.hasAttribute('data-shared-panel')) panel.hidden = !on;
      });
      if (focus) tab.focus();
      root.dispatchEvent(new CustomEvent('lx-tab', {detail: {id: tab.id, value: tab.dataset.value || tab.id}}));
    }
    Array.prototype.forEach.call(list, function (tab, i) {
      tab.addEventListener('click', function () { select(tab, false); });
      tab.addEventListener('keydown', function (e) {
        var to = {ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: list.length - 1}[e.key];
        if (to === undefined) return;
        e.preventDefault();
        select(list[(to + list.length) % list.length], true);
      });
    });
    return select;
  }

  window.LimesUx = {el: el, toast: toast, post: post, tabs: tabs, csrf: csrf};
})();
