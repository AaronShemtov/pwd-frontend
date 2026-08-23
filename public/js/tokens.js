/* Случайные байты, UUID и ULID.
 *
 * Это то, что обычно добывают через `openssl rand`. Под каждым выводом
 * показана эквивалентная команда — чтобы страницей можно было
 * пользоваться как шпаргалкой, а не только как генератором.
 */
(function (global) {
  'use strict';

  var state = { bytes: 32, format: 'hex', count: 1 };
  var out, cli, idOut;

  function encode(bytes, format) {
    if (format === 'hex') return U.toHex(bytes);
    if (format === 'base64') return U.b64FromBytes(bytes, false);
    if (format === 'base64url') return U.b64FromBytes(bytes, true);
    return U.toHex(bytes);
  }

  function cliFor(format, n) {
    if (format === 'hex') return 'openssl rand -hex ' + n;
    if (format === 'base64') return 'openssl rand -base64 ' + n;
    // base64url отдельной команды не имеет — правим вывод на месте
    return 'openssl rand -base64 ' + n + " | tr '+/' '-_' | tr -d '='";
  }

  function generate() {
    out.innerHTML = '';
    for (var i = 0; i < state.count; i++) {
      out.appendChild(U.el('div', 'pwd-row', encode(U.randomBytes(state.bytes), state.format)));
    }
    cli.textContent = cliFor(state.format, state.bytes);
    var bits = state.bytes * 8;
    U.$('tok-meta').textContent = state.bytes + ' байт · ' + bits + ' бит энтропии' +
      (bits < 128 ? ' — для секретов долгого хранения бери от 32 байт' : '');
  }

  /* ---------- UUID v4 ---------- */

  function uuidv4() {
    if (global.crypto.randomUUID) return global.crypto.randomUUID();
    var b = U.randomBytes(16);
    b[6] = (b[6] & 0x0f) | 0x40; // версия 4
    b[8] = (b[8] & 0x3f) | 0x80; // вариант RFC 4122
    var h = U.toHex(b);
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' +
           h.slice(16, 20) + '-' + h.slice(20);
  }

  /* ---------- ULID ---------- */

  // 48 бит времени в миллисекундах + 80 бит случайности, всё это
  // в base32 Крокфорда. В отличие от UUID сортируется по времени.
  var CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  function ulid() {
    var now = Date.now();
    var time = '';
    for (var i = 9; i >= 0; i--) {
      time = CROCKFORD.charAt(now % 32) + time;
      now = Math.floor(now / 32);
    }
    var rnd = '';
    var buf = U.randomBytes(16);
    for (i = 0; i < 16; i++) rnd += CROCKFORD.charAt(buf[i] & 31);
    return time + rnd;
  }

  function renderIds(kind) {
    idOut.innerHTML = '';
    var n = parseInt(U.$('tok-id-count').value, 10) || 1;
    n = Math.min(Math.max(n, 1), 50);
    for (var i = 0; i < n; i++) {
      idOut.appendChild(U.el('div', 'pwd-row', kind === 'ulid' ? ulid() : uuidv4()));
    }
    U.$('tok-id-cli').textContent = kind === 'ulid'
      ? '# у ULID стандартной утилиты нет — обычно берут библиотеку'
      : 'uuidgen        # или: cat /proc/sys/kernel/random/uuid';
  }

  function init() {
    out = U.$('tok-output');
    if (!out) return;
    cli = U.$('tok-cli');
    idOut = U.$('tok-id-output');

    U.$$('#panel-tokens .len-btn').forEach(function (b) {
      b.addEventListener('click', function () {
        state.bytes = parseInt(b.dataset.len, 10);
        U.$$('#panel-tokens .len-btn').forEach(function (x) { x.classList.toggle('active', x === b); });
        U.$('tok-custom').value = '';
        generate();
      });
    });

    U.$('tok-custom').addEventListener('input', function () {
      var v = parseInt(this.value, 10);
      if (!isNaN(v) && v >= 4 && v <= 512) {
        state.bytes = v;
        U.$$('#panel-tokens .len-btn').forEach(function (x) { x.classList.remove('active'); });
        generate();
      }
    });

    U.bindSegmented(U.$('tok-format'), function (v) { state.format = v; generate(); });

    U.$$('#panel-tokens .batch-btn').forEach(function (b) {
      b.addEventListener('click', function () {
        state.count = parseInt(b.dataset.count, 10);
        U.$$('#panel-tokens .batch-btn').forEach(function (x) { x.classList.toggle('active', x === b); });
        generate();
      });
    });

    U.$('tok-regen').addEventListener('click', generate);
    U.bindCopy(U.$('tok-copy'), function () {
      return U.$$('.pwd-row', out).map(function (r) { return r.textContent; }).join('\n');
    }, U.$('tok-copy-label'));

    var currentId = U.bindSegmented(U.$('tok-id-kind'), function (v) { renderIds(v); });
    U.$('tok-id-count').addEventListener('input', function () { renderIds(currentId()); });
    U.$('tok-id-regen').addEventListener('click', function () { renderIds(currentId()); });
    U.bindCopy(U.$('tok-id-copy'), function () {
      return U.$$('.pwd-row', idOut).map(function (r) { return r.textContent; }).join('\n');
    }, U.$('tok-id-copy-label'));

    generate();
    renderIds('uuid');
  }

  U.ready(init);
})(typeof globalThis !== 'undefined' ? globalThis : this);
