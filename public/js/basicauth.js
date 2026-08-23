/* htpasswd for basic auth.
 *
 * Three formats, because three different consumers demand them:
 *   {SHA}   — Envoy and Envoy Gateway, which understand nothing else
 *   $2a$    — bcrypt, what ArgoCD expects in admin.password
 *   $apr1$  — Apache MD5, understood by nginx and Traefik
 *
 * Every hash is computed here: SHA-1 through WebCrypto, bcrypt and apr1
 * from the local code in bcrypt.js and md5.js.
 */
(function (global) {
  'use strict';

  var FORMATS = {
    sha1: {
      title: '{SHA} — Envoy',
      cli: 'htpasswd -nbs USER PASSWORD',
      note: 'The only format Envoy understands. Unsalted SHA-1 is weak against brute force, but Envoy offers no alternative — bcrypt support in the basic_auth filter is still an open issue. Compensate with password length.',
      strength: 'weak'
    },
    bcrypt: {
      title: '$2a$ — bcrypt',
      cli: 'htpasswd -nbBC 10 USER PASSWORD',
      note: 'Salt plus a tunable cost factor. This is exactly what ArgoCD expects in admin.password. Note that bcrypt uses only the first 72 bytes of the password and silently discards the rest.',
      strength: 'strong'
    },
    apr1: {
      title: '$apr1$ — Apache MD5',
      cli: 'htpasswd -nb USER PASSWORD',
      note: 'The htpasswd default, understood by nginx and Traefik. It is salted, but MD5 underneath makes it noticeably weaker than bcrypt. Pick it only when the consumer accepts nothing else.',
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
    u.setAttribute('aria-label', 'Username');

    var p = U.el('input', 'text-input ba-pass');
    p.type = 'text'; p.placeholder = 'password'; p.value = pass || '';
    p.setAttribute('aria-label', 'Password');

    var gen = U.el('button', 'action-btn ba-gen', 'Generate');
    gen.type = 'button';
    gen.addEventListener('click', function () {
      p.value = randomPassword(24);
      recompute();
    });

    var del = U.el('button', 'action-btn ba-del', '×');
    del.type = 'button';
    del.setAttribute('aria-label', 'Remove row');
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

  // Shell quoting: bcrypt and apr1 hashes contain $, which bash would try
  // to expand inside double quotes. Hence single quotes throughout.
  function shellQuote(value) {
    if (value.indexOf('\n') >= 0) {
      return "$'" + value.replace(/\n/g, '\\n') + "'";
    }
    return "'" + value + "'";
  }

  function recompute() {
    var list = rows().filter(function (r) { return r.user && r.pass; });
    if (!list.length) {
      outHtpasswd.textContent = '# fill in a username and a password';
      outCmd.textContent = '';
      outYaml.textContent = '';
      argoWrap.classList.add('hidden');
      return;
    }

    outHtpasswd.textContent = 'computing…';
    // bcrypt is deliberately slow, so let the browser repaint first.
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
            '# first row of the list, for admin.password in argocd-secret\n' +
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
