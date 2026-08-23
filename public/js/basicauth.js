/* htpasswd для basic auth.
 *
 * Три формата, потому что их требуют разные потребители:
 *   {SHA}   — Envoy и Envoy Gateway, другого они не понимают
 *   $2a$    — bcrypt, его хочет ArgoCD в поле admin.password
 *   $apr1$  — Apache MD5, его понимают nginx и Traefik
 *
 * Все хеши считаются здесь же: SHA-1 через WebCrypto, bcrypt и apr1 —
 * своим кодом в bcrypt.js и md5.js.
 */
(function (global) {
  'use strict';

  var FORMATS = {
    sha1: {
      title: '{SHA} — Envoy',
      cli: 'htpasswd -nbs USER PASSWORD',
      note: 'Единственный формат, который понимает Envoy. Это SHA-1 без соли: против перебора он слабый, но выбора у Envoy пока нет — поддержка bcrypt в фильтре basic_auth до сих пор в открытых задачах. Компенсируй длиной пароля.',
      strength: 'weak'
    },
    bcrypt: {
      title: '$2a$ — bcrypt',
      cli: 'htpasswd -nbBC 10 USER PASSWORD',
      note: 'Соль плюс настраиваемая стоимость. Именно это ждёт ArgoCD в admin.password. Учти: bcrypt использует только первые 72 байта пароля, остальное молча отбрасывается.',
      strength: 'strong'
    },
    apr1: {
      title: '$apr1$ — Apache MD5',
      cli: 'htpasswd -nb USER PASSWORD',
      note: 'Формат htpasswd по умолчанию, понимают nginx и Traefik. Соль есть, но внутри MD5 — заметно слабее bcrypt. Бери, только если потребитель не умеет иначе.',
      strength: 'medium'
    }
  };

  var format = 'sha1';
  var rowsBox, outHtpasswd, outCmd, outYaml, noteBox, cliBox, costWrap, argoBox, argoWrap;

  function safeUser(s) {
    return String(s).replace(/[^A-Za-z0-9._@-]/g, '').slice(0, 64);
  }

  function rows() {
    return U.$$('.ba-row', rowsBox).map(function (r) {
      return {
        node: r,
        user: safeUser(U.$$('.ba-user', r)[0].value),
        pass: U.$$('.ba-pass', r)[0].value
      };
    });
  }

  function addRow(user, pass) {
    var row = U.el('div', 'ba-row');

    var u = U.el('input', 'text-input ba-user');
    u.type = 'text'; u.placeholder = 'admin'; u.value = user || '';
    u.setAttribute('aria-label', 'Имя пользователя');

    var p = U.el('input', 'text-input ba-pass');
    p.type = 'text'; p.placeholder = 'пароль'; p.value = pass || '';
    p.setAttribute('aria-label', 'Пароль');

    var gen = U.el('button', 'action-btn ba-gen', 'Сгенерировать');
    gen.type = 'button';
    gen.addEventListener('click', function () {
      p.value = randomPassword(24);
      recompute();
    });

    var del = U.el('button', 'action-btn ba-del', '×');
    del.type = 'button';
    del.setAttribute('aria-label', 'Удалить строку');
    del.addEventListener('click', function () {
      if (U.$$('.ba-row', rowsBox).length <= 1) return;
      rowsBox.removeChild(row);
      recompute();
    });

    [u, p].forEach(function (n) { n.addEventListener('input', recompute); });

    row.appendChild(u); row.appendChild(p); row.appendChild(gen); row.appendChild(del);
    rowsBox.appendChild(row);
  }

  var PW_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_=+.@';
  function randomPassword(n) {
    var s = '';
    for (var i = 0; i < n; i++) s += PW_ALPHA.charAt(U.uniformInt(PW_ALPHA.length));
    return s;
  }

  function hashOne(pass) {
    if (format === 'bcrypt') {
      var cost = parseInt(U.$('ba-cost').value, 10) || 10;
      return Promise.resolve(PwdBcrypt.hash(pass, cost, null, '2a'));
    }
    if (format === 'apr1') {
      return Promise.resolve(PwdMd5.apr1(pass, null));
    }
    return U.digest('SHA-1', U.utf8Encode(pass)).then(function (d) {
      return '{SHA}' + U.b64FromBytes(d, false);
    });
  }

  // Экранирование в shell: bcrypt и apr1 содержат $, который в двойных
  // кавычках bash попытается раскрыть как переменную. Поэтому одинарные.
  function shellQuote(value) {
    if (value.indexOf('\n') >= 0) {
      return "$'" + value.replace(/\n/g, '\\n') + "'";
    }
    return "'" + value + "'";
  }

  function recompute() {
    var list = rows().filter(function (r) { return r.user && r.pass; });
    if (!list.length) {
      outHtpasswd.textContent = '# заполни имя пользователя и пароль';
      outCmd.textContent = '';
      outYaml.textContent = '';
      argoWrap.classList.add('hidden');
      return;
    }

    outHtpasswd.textContent = 'считаю…';
    // bcrypt намеренно медленный, поэтому отдаём браузеру шанс перерисоваться.
    setTimeout(function () {
      Promise.all(list.map(function (r) {
        return hashOne(r.pass).then(function (h) { return r.user + ':' + h; });
      })).then(function (lines) {
        var content = lines.join('\n');
        outHtpasswd.textContent = content;

        var secret = U.$('ba-secret').value.trim() || 'basic-auth';
        var ns = U.$('ba-ns').value.trim() || 'default';

        outCmd.textContent =
          'kubectl create secret generic ' + secret + ' -n ' + ns + ' \\\n' +
          '  --from-literal=.htpasswd=' + shellQuote(content) + ' \\\n' +
          '  --dry-run=client -o yaml | kubectl apply -f -';

        outYaml.textContent =
          'apiVersion: v1\n' +
          'kind: Secret\n' +
          'metadata:\n' +
          '  name: ' + secret + '\n' +
          '  namespace: ' + ns + '\n' +
          'type: Opaque\n' +
          'data:\n' +
          '  .htpasswd: ' + U.b64Encode(content);

        if (format === 'bcrypt') {
          argoWrap.classList.remove('hidden');
          argoBox.textContent =
            '# первая строка списка, для admin.password в argocd-secret\n' +
            'kubectl -n argocd patch secret argocd-secret -p \\\n' +
            '  \'{"stringData": {"admin.password": "' + lines[0].split(':').slice(1).join(':') + '",\n' +
            '                   "admin.passwordMtime": "\'$(date +%FT%T%Z)\'"}}\'';
        } else {
          argoWrap.classList.add('hidden');
        }
      });
    }, 0);
  }

  function applyFormat(f) {
    format = f;
    var meta = FORMATS[f];
    noteBox.textContent = meta.note;
    noteBox.className = 'ctrl-sub note-' + meta.strength;
    cliBox.textContent = meta.cli;
    costWrap.classList.toggle('hidden', f !== 'bcrypt');
    recompute();
  }

  function init() {
    rowsBox = U.$('ba-rows');
    if (!rowsBox) return;
    outHtpasswd = U.$('ba-out-htpasswd');
    outCmd = U.$('ba-out-cmd');
    outYaml = U.$('ba-out-yaml');
    noteBox = U.$('ba-note');
    cliBox = U.$('ba-cli');
    costWrap = U.$('ba-cost-wrap');
    argoBox = U.$('ba-out-argo');
    argoWrap = U.$('ba-argo-wrap');

    addRow('admin', randomPassword(24));

    U.$('ba-add').addEventListener('click', function () { addRow('', randomPassword(24)); recompute(); });
    U.$('ba-cost').addEventListener('change', recompute);
    U.$('ba-secret').addEventListener('input', recompute);
    U.$('ba-ns').addEventListener('input', recompute);
    U.bindSegmented(U.$('ba-format'), applyFormat);

    U.bindCopy(U.$('ba-copy-htpasswd'), function () { return outHtpasswd.textContent; }, U.$('ba-copy-htpasswd-label'));
    U.bindCopy(U.$('ba-copy-cmd'), function () { return outCmd.textContent; }, U.$('ba-copy-cmd-label'));
    U.bindCopy(U.$('ba-copy-yaml'), function () { return outYaml.textContent; }, U.$('ba-copy-yaml-label'));
    U.bindCopy(U.$('ba-copy-argo'), function () { return argoBox.textContent; }, U.$('ba-copy-argo-label'));

    applyFormat('sha1');
  }

  U.ready(init);
})(typeof globalThis !== 'undefined' ? globalThis : this);
