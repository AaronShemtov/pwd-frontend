/* Theme toggle.
 *
 * Loaded synchronously in <head>, before first paint: applying the theme
 * any later produces a white flash on the dark theme. This used to be an
 * inline script and was pulled out so the CSP can drop 'unsafe-inline'.
 */
(function () {
  'use strict';

  function apply(t) {
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('theme', t); } catch (e) { /* private mode */ }
    var sun = document.getElementById('icon-sun');
    var moon = document.getElementById('icon-moon');
    if (sun && moon) {
      sun.classList.toggle('hidden', t !== 'dark');
      moon.classList.toggle('hidden', t === 'dark');
    }
  }

  // Runs immediately, before <body> even exists.
  var saved = 'light';
  try { saved = localStorage.getItem('theme') || 'light'; } catch (e) { /* ignore */ }
  document.documentElement.setAttribute('data-theme', saved);

  var wired = false;
  function wire() {
    if (wired) return;
    wired = true;
    apply(document.documentElement.getAttribute('data-theme') || 'light');
    var btn = document.getElementById('theme-btn');
    if (!btn) return;
    btn.addEventListener('click', function () {
      var cur = document.documentElement.getAttribute('data-theme') || 'light';
      apply(cur === 'light' ? 'dark' : 'light');
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }
})();
