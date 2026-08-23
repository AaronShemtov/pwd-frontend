/* Checksums of text and of files.
 *
 * SHA-* come from WebCrypto. No browser engine exposes MD5, so the local
 * implementation in md5.js is used instead — it exists to check against
 * legacy checksums, never for passwords.
 */
(function (global) {
  'use strict';

  var ALGOS = ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
  var outFormat = 'hex';
  var lastDigests = null;
  var lastLabel = '';

  function encodeDigest(bytes) {
    return outFormat === 'hex' ? U.toHex(bytes) : U.b64FromBytes(bytes, false);
  }

  function computeAll(bytes) {
    var jobs = ALGOS.map(function (a) {
      if (a === 'MD5') return Promise.resolve({ algo: a, d: PwdMd5.md5(bytes) });
      return U.digest(a, bytes).then(function (d) { return { algo: a, d: d }; });
    });
    return Promise.all(jobs);
  }

  function render() {
    var box = U.$('hash-out');
    box.innerHTML = '';
    if (!lastDigests) return;

    var table = U.el('table', 'slo-table');
    var tb = U.el('tbody');
    lastDigests.forEach(function (r) {
      var tr = U.el('tr');
      tr.appendChild(U.el('td', 'svc', r.algo));
      var td = U.el('td', 'val-cell');
      td.appendChild(U.el('span', 'val-text mono-wrap', encodeDigest(r.d)));
      tr.appendChild(td);
      tb.appendChild(tr);
    });
    table.appendChild(tb);
    box.appendChild(table);

    if (lastLabel) box.appendChild(U.el('p', 'ctrl-sub', '▸ ' + lastLabel));

    var warn = U.el('p', 'ctrl-sub note-weak');
    warn.textContent = 'MD5 and SHA-1 are for verifying published checksums only. Do not use them for signatures or passwords.';
    box.appendChild(warn);
  }

  function fromText() {
    var t = U.$('hash-text').value;
    if (!t) { lastDigests = null; lastLabel = ''; render(); return; }
    var bytes = U.utf8Encode(t);
    lastLabel = 'input: text, ' + U.humanBytes(bytes.length) + ' as UTF-8';
    computeAll(bytes).then(function (r) { lastDigests = r; render(); });
  }

  function fromFile(file) {
    if (!file) return;
    var box = U.$('hash-out');
    box.innerHTML = '';
    box.appendChild(U.el('p', 'ctrl-sub', 'reading ' + file.name + ' (' + U.humanBytes(file.size) + ')…'));
    var reader = new FileReader();
    reader.onload = function () {
      var bytes = new Uint8Array(reader.result);
      lastLabel = 'input: file ' + file.name + ', ' + U.humanBytes(bytes.length);
      computeAll(bytes).then(function (r) { lastDigests = r; render(); });
    };
    reader.onerror = function () { U.setError(box, 'Could not read the file.'); };
    reader.readAsArrayBuffer(file);
  }

  function init() {
    if (!U.$('hash-out')) return;

    U.bindSegmented(U.$('hash-source'), function (v) {
      U.$('hash-text-wrap').classList.toggle('hidden', v !== 'text');
      U.$('hash-file-wrap').classList.toggle('hidden', v !== 'file');
      lastDigests = null; lastLabel = '';
      render();
      if (v === 'text') fromText();
    });

    U.bindSegmented(U.$('hash-format'), function (v) { outFormat = v; render(); });

    U.$('hash-text').addEventListener('input', fromText);

    var drop = U.$('hash-drop');
    var input = U.$('hash-file');
    drop.addEventListener('click', function () { input.click(); });
    input.addEventListener('change', function () { fromFile(input.files[0]); });
    ['dragenter', 'dragover'].forEach(function (e) {
      drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.add('over'); });
    });
    ['dragleave', 'drop'].forEach(function (e) {
      drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.remove('over'); });
    });
    drop.addEventListener('drop', function (ev) {
      if (ev.dataTransfer && ev.dataTransfer.files.length) fromFile(ev.dataTransfer.files[0]);
    });
  }

  U.ready(init);
})(typeof globalThis !== 'undefined' ? globalThis : this);
