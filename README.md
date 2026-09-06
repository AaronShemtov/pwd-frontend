# pwd-frontend

**Secrets toolkit for DevOps** — live at [secrets.1ms.my](https://secrets.1ms.my/).

The secrets chores that come up daily when working with Kubernetes, in one page. Everything is computed in the browser: the page makes no network call, and that is not a promise in a paragraph — it is enforced by the browser, because the CSP header carries `connect-src 'none'`.

## Tools

| Tab | What it does |
|---|---|
| **Passwords** | Random passwords, with presets aimed at where the password will actually live: Shell-safe, YAML-safe, URL-safe, DB-safe, PIN. Entropy meter. |
| **Tokens** | Random bytes as hex / base64 / base64url — a replacement for `openssl rand`. Plus UUID v4 and ULID. |
| **Basic auth** | `.htpasswd` lines in three formats, with the commands to go with them. |
| **Kubernetes** | Build a `Secret` from key/value pairs, decode one back, inspect a JWT or a service account token. |
| **Hashes** | MD5, SHA-1, SHA-256, SHA-384, SHA-512 over text or a file. |

### Why Basic auth has three formats

Because three different consumers demand three different things, and mixing them up is easy:

- `{SHA}` — **Envoy and Envoy Gateway**. They understand nothing else: bcrypt support in the `basic_auth` filter is still an open issue. Unsalted SHA-1 is weak, so compensate with password length.
- `$2a$` — **bcrypt**. Exactly what ArgoCD expects in the `admin.password` field of `argocd-secret`. The prefix is deliberately `$2a$` rather than the `$2y$` that `htpasswd` emits: ArgoCD wants the former, and the usual fix is `sed 's/$2y/$2a/'`. That step is not needed here.
- `$apr1$` — **nginx and Traefik**. The `htpasswd` default.

Two landmines the page walks around for you:

1. **Quoting.** bcrypt and apr1 hashes contain `$`. Inside double quotes, bash would try to expand `$2a` as a variable. Every generated command uses single quotes, and multi-line values use the `$'...\n...'` form.
2. **Line endings.** Envoy rejects a `.htpasswd` with CRLF endings while the `SecurityPolicy` reports `Accepted: True`, leaving the real error visible only in the Envoy logs. Lines here are always separated by a single LF.

## Cryptography, and how it was checked

No dependencies — no npm, no CDN. SHA-* come from WebCrypto, which means native browser code. Browsers expose neither MD5 nor bcrypt, so those live in `public/js/md5.js` and `public/js/bcrypt.js`.

The Blowfish constants in `bcrypt.js` were not typed from memory. They are the hexadecimal expansion of the fractional part of π, exactly as in Schneier's original paper, derived programmatically and checked against independently known values. They sit in the file as one string and are parsed at load time, so anyone can verify them.

Both implementations were cross-checked against references:

| What | Checked against | Coverage |
|---|---|---|
| bcrypt | `bcrypt` (Python) | 11 vectors, including UTF-8, emoji, empty password and the 72-byte boundary |
| apr1 | `passlib.hash.apr_md5_crypt` | 11 vectors |
| MD5 | `hashlib` | 23 vectors, including the 55/56/57/63/64/65-byte block boundaries |
| `{SHA}` | `openssl dgst -sha1` | exact string match |

The check ran in both directions: hashes produced by the page were fed back through `bcrypt.checkpw()` and `apr_md5_crypt.verify()`, confirming that they really do validate the original password.

## Deliberately not included

- **SSH key generation.** Technically feasible, but "generate my private key in a browser tab" is precisely the operation a sensible person performs locally with `ssh-keygen`. A tool that undermines trust in the rest of the page does not belong here.
- **TOTP secrets.** The second factor is issued by the service itself, and typing it into someone else's page is a habit not worth encouraging.
- **Diceware passphrases.** Postponed: the EFF wordlist costs about 60 KB for a single feature. Worth revisiting when there is a concrete need.

## Stack

- Static HTML, CSS and plain JavaScript, no bundler
- nginx-unprivileged (Alpine), UID 101, port 8080
- GitHub Actions → OCIR (linux/arm64)
- Flux Image Automation writes the new tag back into [personal-k8s](https://github.com/AaronShemtov/personal-k8s)

## Shared styling

All four 1ms.my sites (1ms.my, cv, infra, pwd) use the same `blueprint.css`, physically copied into each repository.

**That file is not edited here.** Any change to it has to land in all four repositories at once, otherwise the copies drift apart and it stops being obvious which one is current. Everything only this page needs lives in `public/pwd.css`.

## Layout

```
public/
├── index.html        markup only
├── blueprint.css     shared across four sites — do not edit here
├── pwd.css           styles for this page
├── favicon.ico
└── js/
    ├── theme.js      theme; loaded in <head> before first paint
    ├── util.js       shared helpers
    ├── tabs.js       tab bar and hash routing
    ├── md5.js        MD5 and apr1
    ├── bcrypt.js     bcrypt
    ├── passwords.js  tab 01
    ├── tokens.js     tab 02
    ├── basicauth.js  tab 03
    ├── kubernetes.js tab 04
    └── hashes.js     tab 05
```

The markup contains no inline script, no inline style and no attribute event handler — which is exactly why the CSP needs no `unsafe-inline`.

## Linking to a single tool

The open tab is reflected in the URL, so a specific tool can be shared directly:

```
https://secrets.1ms.my/#basicauth
https://secrets.1ms.my/#kubernetes
```

## Local preview

```bash
cd public
python3 -m http.server 8000
# open http://localhost:8000
```

Serving it that way sends none of the headers from `nginx.conf`, so the CSP is not exercised locally. To see the page with the real headers, build the image:

```bash
docker build -t pwd-frontend:local .
docker run --rm -p 8080:8080 pwd-frontend:local
curl -sI http://localhost:8080/ | grep -i 'content-security\|cache-control\|x-content-type'
```

## License

MIT.
