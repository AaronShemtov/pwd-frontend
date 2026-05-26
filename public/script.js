// Password Generator — runs entirely client-side.
//
// Cryptographic notes:
//   * Randomness source is window.crypto.getRandomValues(), the browser's
//     CSPRNG (backed by OS-level /dev/urandom or BCryptGenRandom). Never
//     uses Math.random(), which is a PRNG predictable after a few samples.
//   * Charset indexing uses rejection sampling instead of `random % N` —
//     a `% charset.length` operation introduces modulo bias whenever
//     charset.length doesn't evenly divide 2^32. Rejection sampling
//     discards values in the "biased zone" and tries again, giving a
//     uniform distribution.
//   * Entropy is computed correctly as log2(charset_size) * length, which
//     is the maximum entropy of a uniformly-random string from that charset.
//
// No framework, no build step. Plain ES2017+ — modern browsers only.

(function () {
    'use strict';

    // ---------- Character classes ----------

    const CHARS = {
        upper:  'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lower:  'abcdefghijklmnopqrstuvwxyz',
        digit:  '0123456789',
        symbol: '!@#$%^&*()-_=+[]{};:,.<>?/~`|\\\'"',
    };

    // Visually ambiguous characters — easy to misread when copying a
    // password by hand. Excluding them dents entropy slightly but is
    // worth it for human-typed passwords.
    const AMBIGUOUS = new Set('0O1lI|'.split(''));

    // Characters that frequently break things when used inside SQL
    // connection strings, JSON payloads, shell commands, or YAML values.
    // The full hostile set is bigger; this is the conservative subset
    // that breaks the most common cases without crippling entropy.
    const DB_UNFRIENDLY = new Set('\'"\\;$`&'.split(''));

    // ---------- DOM refs ----------

    const outputArea  = document.getElementById('output-area');
    const copyBtn     = document.getElementById('copy-btn');
    const copyLabel   = document.getElementById('copy-label');
    const regenBtn    = document.getElementById('regen-btn');
    const revealBtn   = document.getElementById('reveal-btn');
    const revealLabel = document.getElementById('reveal-label');
    const eyeOn       = document.getElementById('eye-on');
    const eyeOff      = document.getElementById('eye-off');

    const entropyFill  = document.getElementById('entropy-fill');
    const entropyBits  = document.getElementById('entropy-bits');
    const entropyLabel = document.getElementById('entropy-label');

    const lengthBtns   = document.querySelectorAll('.length-btn');
    const customLenInp = document.getElementById('custom-len');

    const optUpper          = document.getElementById('opt-upper');
    const optLower          = document.getElementById('opt-lower');
    const optDigit          = document.getElementById('opt-digit');
    const optSymbol         = document.getElementById('opt-symbol');
    const optNoAmbig        = document.getElementById('opt-no-ambig');
    const optNoDbUnfriendly = document.getElementById('opt-no-dbunfriendly');

    const batchBtns = document.querySelectorAll('.batch-btn');

    // ---------- State ----------

    let length    = 16;  // length of each password
    let batch     = 1;   // how many passwords to generate at once
    let revealed  = true;

    // ---------- Theme switch (identical to other sites) ----------

    const themeToggle = document.getElementById('theme-toggle');
    const iconSun     = document.getElementById('icon-sun');
    const iconMoon    = document.getElementById('icon-moon');
    const STORAGE_KEY = 'pwd-theme';

    function applyTheme(theme) {
        if (theme === 'light') {
            document.documentElement.setAttribute('data-theme', 'light');
            if (iconSun) iconSun.style.display = 'none';
            if (iconMoon) iconMoon.style.display = '';
        } else {
            document.documentElement.removeAttribute('data-theme');
            if (iconSun) iconSun.style.display = '';
            if (iconMoon) iconMoon.style.display = 'none';
        }
    }
    function detectTheme() {
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored === 'light' || stored === 'dark') return stored;
        } catch (e) { /* private mode — ignore */ }
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
        return 'dark';
    }
    applyTheme(detectTheme());
    if (themeToggle) {
        themeToggle.addEventListener('click', function () {
            const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
            applyTheme(next);
            try { localStorage.setItem(STORAGE_KEY, next); } catch (e) { /* ignore */ }
        });
    }

    // ---------- Charset builder ----------

    // Build the active character set based on the user's selections.
    // Returns an array of single-character strings (easier to index than
    // a string when applying exclusions).
    function buildCharset() {
        let chars = '';
        if (optUpper.checked)  chars += CHARS.upper;
        if (optLower.checked)  chars += CHARS.lower;
        if (optDigit.checked)  chars += CHARS.digit;
        if (optSymbol.checked) chars += CHARS.symbol;

        let arr = chars.split('');
        if (optNoAmbig.checked)        arr = arr.filter(c => !AMBIGUOUS.has(c));
        if (optNoDbUnfriendly.checked) arr = arr.filter(c => !DB_UNFRIENDLY.has(c));

        // Deduplicate — paranoia in case future class additions overlap.
        return Array.from(new Set(arr));
    }

    // ---------- Uniform random integer in [0, max) ----------
    //
    // Rejection sampling against a uint32. We compute the largest multiple
    // of `max` that fits in uint32 range; any sample at or above it is
    // discarded and re-rolled. This guarantees a uniform distribution
    // regardless of whether `max` is a power of two.
    function uniformInt(max) {
        if (max <= 0 || max > 0xFFFFFFFF) {
            throw new RangeError('max must be in (0, 2^32]');
        }
        const limit = Math.floor(0x100000000 / max) * max;
        const buf = new Uint32Array(1);
        // eslint-disable-next-line no-constant-condition
        while (true) {
            window.crypto.getRandomValues(buf);
            if (buf[0] < limit) return buf[0] % max;
        }
    }

    // ---------- Generate one password ----------

    function generateOne(charset, n) {
        const out = new Array(n);
        for (let i = 0; i < n; i++) {
            out[i] = charset[uniformInt(charset.length)];
        }
        return out.join('');
    }

    // After generating, verify that each REQUESTED class appears at least
    // once. If not, re-roll a random position to a character from the
    // missing class. This is a soft guarantee — most generators do this
    // because services often require at least one of each class.
    function enforceClasses(pwd, charset) {
        const need = [];
        if (optUpper.checked)  need.push({ name: 'upper',  charset: CHARS.upper.split('').filter(c => charset.includes(c)) });
        if (optLower.checked)  need.push({ name: 'lower',  charset: CHARS.lower.split('').filter(c => charset.includes(c)) });
        if (optDigit.checked)  need.push({ name: 'digit',  charset: CHARS.digit.split('').filter(c => charset.includes(c)) });
        if (optSymbol.checked) need.push({ name: 'symbol', charset: CHARS.symbol.split('').filter(c => charset.includes(c)) });

        const chars = pwd.split('');
        for (const cls of need) {
            if (cls.charset.length === 0) continue;
            const has = chars.some(c => cls.charset.includes(c));
            if (!has) {
                const pos = uniformInt(chars.length);
                chars[pos] = cls.charset[uniformInt(cls.charset.length)];
            }
        }
        return chars.join('');
    }

    // ---------- Entropy & strength rating ----------

    // Bits of entropy = log2(charset_size) * length.
    function entropyBitsOf(charsetSize, n) {
        if (charsetSize <= 1) return 0;
        return Math.log2(charsetSize) * n;
    }

    // Rough mapping based on practical guidance:
    //   < 28  : very weak
    //   28-50 : weak
    //   50-72 : moderate
    //   72-128: strong
    //   ≥ 128 : excellent
    function ratingFor(bits) {
        if (bits < 28)  return { label: 'very weak',  pct: 10, cls: 'rating-vweak' };
        if (bits < 50)  return { label: 'weak',       pct: 30, cls: 'rating-weak' };
        if (bits < 72)  return { label: 'moderate',   pct: 55, cls: 'rating-mod' };
        if (bits < 128) return { label: 'strong',     pct: 80, cls: 'rating-strong' };
        return                  { label: 'excellent', pct: 100, cls: 'rating-excellent' };
    }

    // ---------- Render output + entropy meter ----------

    function render(passwords, charsetSize) {
        outputArea.innerHTML = '';
        passwords.forEach(function (p) {
            const row = document.createElement('div');
            row.className = 'pwd-row' + (revealed ? '' : ' is-hidden');
            row.textContent = p;
            outputArea.appendChild(row);
        });

        const bits = entropyBitsOf(charsetSize, length);
        const r = ratingFor(bits);
        entropyFill.style.width = r.pct + '%';
        entropyFill.className = 'entropy-fill ' + r.cls;
        entropyBits.textContent = bits.toFixed(0) + ' bits of entropy';
        entropyLabel.textContent = r.label;
        entropyLabel.className = 'entropy-label ' + r.cls;
    }

    // ---------- Main: generate and display ----------

    function generate() {
        const charset = buildCharset();
        if (charset.length === 0) {
            outputArea.innerHTML = '<div class="pwd-row pwd-error">Select at least one character class.</div>';
            entropyFill.style.width = '0%';
            entropyBits.textContent = '— bits of entropy';
            entropyLabel.textContent = '—';
            entropyLabel.className = 'entropy-label';
            return;
        }
        const results = [];
        for (let i = 0; i < batch; i++) {
            let p = generateOne(charset, length);
            p = enforceClasses(p, charset);
            results.push(p);
        }
        render(results, charset.length);
    }

    // ---------- Length button handling ----------

    lengthBtns.forEach(function (btn) {
        btn.addEventListener('click', function () {
            length = parseInt(btn.dataset.len, 10);
            lengthBtns.forEach(b => b.classList.toggle('is-active', b === btn));
            customLenInp.value = '';
            generate();
        });
    });

    customLenInp.addEventListener('input', function () {
        const v = parseInt(customLenInp.value, 10);
        if (!isNaN(v) && v >= 4 && v <= 128) {
            length = v;
            lengthBtns.forEach(b => b.classList.remove('is-active'));
            generate();
        }
    });

    // ---------- Character class toggles ----------

    [optUpper, optLower, optDigit, optSymbol, optNoAmbig, optNoDbUnfriendly].forEach(function (el) {
        el.addEventListener('change', generate);
    });

    // ---------- Batch ----------

    batchBtns.forEach(function (btn) {
        btn.addEventListener('click', function () {
            batch = parseInt(btn.dataset.count, 10);
            batchBtns.forEach(b => b.classList.toggle('is-active', b === btn));
            generate();
        });
    });

    // ---------- Regenerate ----------

    regenBtn.addEventListener('click', generate);

    // ---------- Copy ----------

    copyBtn.addEventListener('click', async function () {
        const rows = outputArea.querySelectorAll('.pwd-row');
        if (rows.length === 0) return;
        const text = Array.from(rows).map(r => r.textContent).join('\n');
        try {
            await navigator.clipboard.writeText(text);
            const old = copyLabel.textContent;
            copyLabel.textContent = 'Copied!';
            copyBtn.classList.add('is-copied');
            setTimeout(function () {
                copyLabel.textContent = old;
                copyBtn.classList.remove('is-copied');
            }, 1500);
        } catch (e) {
            // Older browsers / insecure contexts — fall back to a textarea.
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch (_) {}
            document.body.removeChild(ta);
            copyLabel.textContent = 'Copied!';
            setTimeout(() => { copyLabel.textContent = 'Copy'; }, 1500);
        }
    });

    // ---------- Reveal / hide ----------

    revealBtn.addEventListener('click', function () {
        revealed = !revealed;
        outputArea.querySelectorAll('.pwd-row').forEach(function (row) {
            row.classList.toggle('is-hidden', !revealed);
        });
        revealLabel.textContent = revealed ? 'Hide' : 'Show';
        revealBtn.setAttribute('aria-pressed', revealed ? 'true' : 'false');
        eyeOn.style.display  = revealed ? '' : 'none';
        eyeOff.style.display = revealed ? 'none' : '';
    });

    // ---------- Initial generation ----------

    generate();
})();
