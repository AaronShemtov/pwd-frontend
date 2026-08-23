/* Tab bar with hash-based routing.
 *
 * The open tab is reflected in the URL (pwd.1ms.my/#kubernetes), so a
 * single tool can be linked directly. An unknown hash silently falls
 * back to the default tab.
 */
(function (global) {
  'use strict';

  var DEFAULT = 'passwords';

  function activate(name, pushHash) {
    var tabs = U.$$('.tab');
    var panels = U.$$('.panel-tool');
    var known = tabs.some(function (t) { return t.dataset.tab === name; });
    if (!known) name = DEFAULT;

    tabs.forEach(function (t) {
      var on = t.dataset.tab === name;
      t.classList.toggle('active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    panels.forEach(function (p) {
      p.classList.toggle('hidden', p.dataset.panel !== name);
    });

    if (pushHash && global.location.hash.slice(1) !== name) {
      global.history.replaceState(null, '', '#' + name);
    }
    var active = panels.filter(function (p) { return p.dataset.panel === name; })[0];
    if (active) {
      var ev = new CustomEvent('tab:shown', { detail: { name: name } });
      active.dispatchEvent(ev);
    }
  }

  U.ready(function () {
    U.$$('.tab').forEach(function (t) {
      t.addEventListener('click', function () { activate(t.dataset.tab, true); });
    });
    global.addEventListener('hashchange', function () {
      activate(global.location.hash.slice(1), false);
    });
    activate(global.location.hash.slice(1) || DEFAULT, false);
  });

  global.PwdTabs = { activate: activate };
})(typeof globalThis !== 'undefined' ? globalThis : this);
