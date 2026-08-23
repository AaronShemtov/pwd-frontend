/* Общие помощники для всех инструментов.
 * Ничего не отправляет в сеть — здесь нет ни fetch, ни XHR.
 */
(function (global) {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  /* ---------- Случайность ---------- */

  // Равномерный индекс без смещения по модулю: значения выше последней
  // полной кратности отбрасываются и тянутся заново.
  function uniformInt(max) {
    if (max <= 0) throw new Error('max должен быть больше нуля');
    var limit = Math.floor(0x100000000 / max) * max;
    var buf = new Uint32Array(1);
    for (;;) {
      global.crypto.getRandomValues(buf);
      if (buf[0] < limit) return buf[0] % max;
    }
  }

  function randomBytes(n) {
    var b = new Uint8Array(n);
    global.crypto.getRandomValues(b);
    return b;
  }

  /* ---------- Кодировки ---------- */

  var TE = new TextEncoder();
  var TD = new TextDecoder('utf-8', { fatal: false });

  function utf8Encode(str) { return TE.encode(str); }
  function utf8Decode(bytes) { return TD.decode(bytes); }

  function toHex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
    return s;
  }

  function fromHex(str) {
    var clean = str.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2) throw new Error('нечётное число шестнадцатеричных цифр');
    var out = new Uint8Array(clean.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }

  // btoa работает с байтами, а не с символами, поэтому строку сначала
  // переводим в UTF-8 — иначе кириллица и эмодзи ломаются.
  function b64FromBytes(bytes, urlSafe) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    var out = global.btoa(bin);
    if (urlSafe) out = out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return out;
  }

  function bytesFromB64(str) {
    var s = String(str).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = global.atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64Encode(str, urlSafe) { return b64FromBytes(utf8Encode(str), urlSafe); }
  function b64Decode(str) { return utf8Decode(bytesFromB64(str)); }

  function looksLikeBase64(s) {
    var t = String(s).trim().replace(/\s+/g, '');
    return t.length > 0 && t.length % 4 <= 3 && /^[A-Za-z0-9+/_=-]+$/.test(t);
  }

  // Признак того, что расшифрованные байты — читаемый текст, а не бинарь
  // (сертификат, ключ, tar). Нужен, чтобы не вываливать мусор в таблицу.
  function isPrintable(bytes) {
    var suspicious = 0;
    for (var i = 0; i < bytes.length; i++) {
      var c = bytes[i];
      if (c === 9 || c === 10 || c === 13) continue;
      if (c < 32 || c === 127) suspicious++;
    }
    return bytes.length === 0 || suspicious / bytes.length < 0.02;
  }

  function humanBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(2) + ' MB';
  }

  /* ---------- Хеши ---------- */

  // 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
  function digest(algo, bytes) {
    return global.crypto.subtle.digest(algo, bytes).then(function (buf) {
      return new Uint8Array(buf);
    });
  }

  /* ---------- Интерфейс ---------- */

  function flash(btn, labelNode, msg) {
    var original = labelNode ? labelNode.textContent : null;
    if (labelNode) labelNode.textContent = msg;
    btn.classList.add('copied');
    setTimeout(function () {
      if (labelNode) labelNode.textContent = original;
      btn.classList.remove('copied');
    }, 1400);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      // Запасной путь для контекстов без Clipboard API.
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'offscreen';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error('копирование недоступно'));
    });
  }

  // Вешает копирование на кнопку. getText вызывается в момент клика,
  // поэтому копируется всегда актуальное значение.
  function bindCopy(btn, getText, labelNode) {
    if (!btn) return;
    btn.addEventListener('click', function () {
      var text = getText();
      if (!text) return;
      copyText(text).then(function () {
        flash(btn, labelNode, 'Copied!');
      }, function () {
        flash(btn, labelNode, 'Failed');
      });
    });
  }

  // Сегментированный переключатель: одна активная кнопка из группы.
  function bindSegmented(root, onChange) {
    var btns = $$('.seg-btn', root);
    btns.forEach(function (b) {
      b.addEventListener('click', function () {
        btns.forEach(function (x) { x.classList.toggle('active', x === b); });
        if (onChange) onChange(b.dataset.value, b);
      });
    });
    return function current() {
      var active = btns.filter(function (b) { return b.classList.contains('active'); })[0];
      return active ? active.dataset.value : null;
    };
  }

  // Запускает fn ровно один раз, независимо от того, сколько раз
  // придёт DOMContentLoaded и в каком состоянии документ на момент вызова.
  function ready(fn) {
    var done = false;
    function run() { if (done) return; done = true; fn(); }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', run);
    } else {
      run();
    }
  }

  function setError(node, msg) {
    node.innerHTML = '';
    node.appendChild(el('div', 'pwd-error', msg));
  }

  global.U = {
    $: $, $$: $$, el: el,
    uniformInt: uniformInt, randomBytes: randomBytes,
    utf8Encode: utf8Encode, utf8Decode: utf8Decode,
    toHex: toHex, fromHex: fromHex,
    b64FromBytes: b64FromBytes, bytesFromB64: bytesFromB64,
    b64Encode: b64Encode, b64Decode: b64Decode,
    looksLikeBase64: looksLikeBase64, isPrintable: isPrintable,
    humanBytes: humanBytes, digest: digest,
    copyText: copyText, bindCopy: bindCopy, bindSegmented: bindSegmented, ready: ready,
    flash: flash, setError: setError
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
