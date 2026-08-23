/* Kubernetes: сборка Secret, разбор Secret и разбор JWT.
 *
 * Всё считается в браузере. Ни один вставленный сюда Secret или токен
 * никуда не уходит — в странице нет ни одного сетевого вызова, и CSP
 * с директивой connect-src 'none' запрещает их на уровне браузера.
 */
(function (global) {
  'use strict';

  /* ================= Сборка Secret ================= */

  var kvBox, secOutYaml, secOutCmd;

  function kvRows() {
    return U.$$('.kv-row', kvBox).map(function (r) {
      return {
        key: U.$$('.kv-key', r)[0].value.trim(),
        val: U.$$('.kv-val', r)[0].value
      };
    }).filter(function (r) { return r.key; });
  }

  function addKv(key, val) {
    var row = U.el('div', 'kv-row');
    var k = U.el('input', 'text-input kv-key');
    k.type = 'text'; k.placeholder = 'DB_PASSWORD'; k.value = key || '';
    k.setAttribute('aria-label', 'Ключ');
    var v = U.el('textarea', 'text-input kv-val');
    v.rows = 1; v.placeholder = 'значение'; v.value = val || '';
    v.setAttribute('aria-label', 'Значение');
    var del = U.el('button', 'action-btn kv-del', '×');
    del.type = 'button';
    del.setAttribute('aria-label', 'Удалить строку');
    del.addEventListener('click', function () {
      if (U.$$('.kv-row', kvBox).length <= 1) return;
      kvBox.removeChild(row); buildSecret();
    });
    [k, v].forEach(function (n) { n.addEventListener('input', buildSecret); });
    row.appendChild(k); row.appendChild(v); row.appendChild(del);
    kvBox.appendChild(row);
  }

  function shellQuote(v) {
    if (v.indexOf('\n') >= 0) return "$'" + v.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/'/g, "\\'") + "'";
    return "'" + v.replace(/'/g, "'\\''") + "'";
  }

  function buildSecret() {
    var list = kvRows();
    var name = U.$('k8s-name').value.trim() || 'my-secret';
    var ns = U.$('k8s-ns').value.trim() || 'default';
    var mode = U.$('k8s-mode-stringdata').checked ? 'stringData' : 'data';

    if (!list.length) {
      secOutYaml.textContent = '# добавь хотя бы один ключ';
      secOutCmd.textContent = '';
      return;
    }

    var y = 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: ' + name +
            '\n  namespace: ' + ns + '\ntype: Opaque\n' + mode + ':\n';
    list.forEach(function (r) {
      if (mode === 'data') {
        y += '  ' + r.key + ': ' + U.b64Encode(r.val) + '\n';
      } else if (r.val.indexOf('\n') >= 0) {
        y += '  ' + r.key + ': |\n';
        r.val.split('\n').forEach(function (line) { y += '    ' + line + '\n'; });
      } else {
        y += '  ' + r.key + ': ' + JSON.stringify(r.val) + '\n';
      }
    });
    secOutYaml.textContent = y.replace(/\n$/, '');

    var cmd = 'kubectl create secret generic ' + name + ' -n ' + ns;
    list.forEach(function (r) {
      cmd += ' \\\n  --from-literal=' + r.key + '=' + shellQuote(r.val);
    });
    cmd += ' \\\n  --dry-run=client -o yaml | kubectl apply -f -';
    secOutCmd.textContent = cmd;
  }

  /* ================= Разбор Secret ================= */

  // Небольшой разборщик, рассчитанный на вывод `kubectl get secret -o yaml`.
  // Полноценный YAML он не заменяет и не пытается: берёт блок data или
  // stringData и читает из него пары ключ-значение.
  function parseSecretBlock(text) {
    var lines = text.replace(/\r\n?/g, '\n').split('\n');
    var result = [], mode = null, baseIndent = -1, i;

    for (i = 0; i < lines.length; i++) {
      var m = /^(\s*)(data|stringData):\s*$/.exec(lines[i]);
      if (!m) continue;
      mode = m[2];
      baseIndent = m[1].length;

      for (var j = i + 1; j < lines.length; j++) {
        var line = lines[j];
        if (!line.trim()) continue;
        var indent = line.length - line.replace(/^\s*/, '').length;
        if (indent <= baseIndent) break;

        var kv = /^\s*([A-Za-z0-9._\-\/]+):\s*(.*)$/.exec(line);
        if (!kv) continue;
        var key = kv[1], raw = kv[2].trim();

        if (raw === '|' || raw === '>' || raw === '|-' || raw === '>-') {
          var chunk = [];
          for (var k = j + 1; k < lines.length; k++) {
            var ind2 = lines[k].length - lines[k].replace(/^\s*/, '').length;
            if (lines[k].trim() && ind2 <= indent) break;
            chunk.push(lines[k].replace(/^\s{0,64}/, function (s) { return s.slice(indent + 2); }));
            j = k;
          }
          raw = chunk.join(raw[0] === '>' ? ' ' : '\n');
        } else if (/^"(.*)"$/.test(raw)) {
          try { raw = JSON.parse(raw); } catch (e) { raw = raw.slice(1, -1); }
        } else if (/^'(.*)'$/.test(raw)) {
          raw = raw.slice(1, -1).replace(/''/g, "'");
        }
        result.push({ key: key, raw: raw, encoded: mode === 'data' });
      }
      break;
    }
    return result;
  }

  function decodeInput() {
    var text = U.$('k8s-decode-in').value;
    var box = U.$('k8s-decode-out');
    box.innerHTML = '';
    if (!text.trim()) return;

    var entries = parseSecretBlock(text);

    // Ничего похожего на Secret не нашли — считаем ввод голым base64.
    if (!entries.length) {
      var single = text.trim();
      if (!U.looksLikeBase64(single)) {
        U.setError(box, 'Не похоже ни на Secret, ни на строку base64.');
        return;
      }
      try {
        var bytes = U.bytesFromB64(single);
        var pre = U.el('pre', 'plain-out');
        pre.textContent = U.isPrintable(bytes)
          ? U.utf8Decode(bytes)
          : 'бинарные данные, ' + U.humanBytes(bytes.length) + '\n' + U.toHex(bytes).slice(0, 128) + '…';
        box.appendChild(pre);
      } catch (e) {
        U.setError(box, 'Строка не декодируется как base64.');
      }
      return;
    }

    var table = U.el('table', 'slo-table');
    var thead = U.el('thead');
    var htr = U.el('tr');
    ['Ключ', 'Размер', 'Значение'].forEach(function (h) { htr.appendChild(U.el('th', null, h)); });
    thead.appendChild(htr); table.appendChild(thead);
    var tbody = U.el('tbody');

    entries.forEach(function (e) {
      var tr = U.el('tr');
      tr.appendChild(U.el('td', 'svc', e.key));
      var value, size;
      if (e.encoded) {
        try {
          var b = U.bytesFromB64(e.raw);
          size = U.humanBytes(b.length);
          value = U.isPrintable(b) ? U.utf8Decode(b)
            : '⟨бинарные данные⟩ ' + U.toHex(b).slice(0, 48) + '…';
        } catch (err) {
          size = '—'; value = '⟨не декодируется как base64⟩';
        }
      } else {
        size = U.humanBytes(U.utf8Encode(e.raw).length);
        value = e.raw;
      }
      tr.appendChild(U.el('td', null, size));
      var td = U.el('td', 'val-cell');
      td.appendChild(U.el('span', 'val-text', value));
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    box.appendChild(table);

    var hint = U.el('p', 'ctrl-sub',
      '▸ Найдено ключей: ' + entries.length +
      (entries[0].encoded ? ' (из блока data, значения раскодированы из base64)'
                          : ' (из блока stringData, значения уже открытым текстом)'));
    box.appendChild(hint);
  }

  /* ================= Разбор JWT ================= */

  function fmtDate(sec) {
    var d = new Date(sec * 1000);
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  }

  function relative(sec) {
    var diff = sec * 1000 - Date.now();
    var abs = Math.abs(diff);
    var unit, n;
    if (abs < 60000) { n = Math.round(abs / 1000); unit = 'сек'; }
    else if (abs < 3600000) { n = Math.round(abs / 60000); unit = 'мин'; }
    else if (abs < 86400000) { n = Math.round(abs / 3600000); unit = 'ч'; }
    else { n = Math.round(abs / 86400000); unit = 'дн'; }
    return diff >= 0 ? 'через ' + n + ' ' + unit : n + ' ' + unit + ' назад';
  }

  function decodeJwt() {
    var raw = U.$('k8s-jwt-in').value.trim();
    var box = U.$('k8s-jwt-out');
    box.innerHTML = '';
    if (!raw) return;

    var parts = raw.replace(/^Bearer\s+/i, '').split('.');
    if (parts.length < 2) {
      U.setError(box, 'Это не JWT: не нашлось трёх частей, разделённых точкой.');
      return;
    }

    var header, payload;
    try {
      header = JSON.parse(U.utf8Decode(U.bytesFromB64(parts[0])));
      payload = JSON.parse(U.utf8Decode(U.bytesFromB64(parts[1])));
    } catch (e) {
      U.setError(box, 'Части токена не разбираются как base64url + JSON.');
      return;
    }

    function section(title, obj) {
      var wrap = U.el('div', 'code-block');
      var head = U.el('div', 'code-head');
      head.appendChild(U.el('span', 'lbl', title));
      wrap.appendChild(head);
      var pre = U.el('pre', 'code');
      pre.textContent = JSON.stringify(obj, null, 2);
      wrap.appendChild(pre);
      return wrap;
    }

    box.appendChild(section('header', header));
    box.appendChild(section('payload', payload));

    var facts = [];
    if (header.alg) facts.push(['Алгоритм', header.alg]);
    if (payload.iss) facts.push(['Издатель (iss)', payload.iss]);
    if (payload.sub) facts.push(['Субъект (sub)', payload.sub]);
    if (payload.aud) facts.push(['Аудитория (aud)', [].concat(payload.aud).join(', ')]);
    if (payload.iat) facts.push(['Выпущен (iat)', fmtDate(payload.iat) + ' · ' + relative(payload.iat)]);
    if (payload.nbf) facts.push(['Действует с (nbf)', fmtDate(payload.nbf) + ' · ' + relative(payload.nbf)]);
    if (payload.exp) {
      var expired = payload.exp * 1000 < Date.now();
      facts.push([expired ? 'Истёк (exp)' : 'Истекает (exp)',
                  fmtDate(payload.exp) + ' · ' + relative(payload.exp), expired ? 'bad' : 'good']);
    } else {
      facts.push(['Срок жизни', 'поле exp отсутствует — токен бессрочный', 'warn']);
    }
    var k8s = payload['kubernetes.io'];
    if (k8s) {
      if (k8s.namespace) facts.push(['Namespace', k8s.namespace]);
      if (k8s.serviceaccount && k8s.serviceaccount.name) {
        facts.push(['ServiceAccount', k8s.serviceaccount.name]);
      }
      if (k8s.pod && k8s.pod.name) facts.push(['Pod', k8s.pod.name]);
    }

    var table = U.el('table', 'slo-table');
    var tb = U.el('tbody');
    facts.forEach(function (f) {
      var tr = U.el('tr');
      tr.appendChild(U.el('td', 'svc', f[0]));
      tr.appendChild(U.el('td', f[2] === 'bad' ? 'pending' : null, f[1]));
      tb.appendChild(tr);
    });
    table.appendChild(tb);
    box.appendChild(table);

    box.appendChild(U.el('p', 'ctrl-sub',
      '▸ Подпись не проверяется — для этого нужен открытый ключ издателя. Здесь только разбор содержимого.'));
  }

  /* ================= Инициализация ================= */

  function init() {
    kvBox = U.$('k8s-kv');
    if (!kvBox) return;
    secOutYaml = U.$('k8s-out-yaml');
    secOutCmd = U.$('k8s-out-cmd');

    addKv('DB_PASSWORD', '');
    U.$('k8s-add-kv').addEventListener('click', function () { addKv('', ''); buildSecret(); });
    U.$('k8s-name').addEventListener('input', buildSecret);
    U.$('k8s-ns').addEventListener('input', buildSecret);
    U.$('k8s-mode-stringdata').addEventListener('change', buildSecret);
    U.bindCopy(U.$('k8s-copy-yaml'), function () { return secOutYaml.textContent; }, U.$('k8s-copy-yaml-label'));
    U.bindCopy(U.$('k8s-copy-cmd'), function () { return secOutCmd.textContent; }, U.$('k8s-copy-cmd-label'));

    U.$('k8s-decode-in').addEventListener('input', decodeInput);
    U.$('k8s-decode-clear').addEventListener('click', function () {
      U.$('k8s-decode-in').value = ''; decodeInput();
    });

    U.$('k8s-jwt-in').addEventListener('input', decodeJwt);
    U.$('k8s-jwt-clear').addEventListener('click', function () {
      U.$('k8s-jwt-in').value = ''; decodeJwt();
    });

    buildSecret();
  }

  U.ready(init);
})(typeof globalThis !== 'undefined' ? globalThis : this);
