/* Password generator.
 *
 * Randomness comes from window.crypto.getRandomValues(). The index into
 * the alphabet is drawn by rejection sampling rather than a modulo, so
 * the distribution stays uniform.
 */
(function (global) {
  "use strict";

  var CHARS = {
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lower: "abcdefghijklmnopqrstuvwxyz",
    digit: "0123456789",
    symbol: "!@#$%^&*()-_=+[]{};:,.<>?/~`|\\'\"",
  };

  var AMBIG = "0O1lI|";
  var DBUF = "'\"\\;$`&";

  /* Presets aimed at wherever the password actually ends up. The point is
   * not "stronger" — it is that the password should need no escaping and
   * should not break the config it is pasted into. */
  var PRESETS = {
    balanced: {
      title: "Balanced",
      len: 20,
      upper: true,
      lower: true,
      digit: true,
      symbol: true,
      note: "All four classes. Fine when the password lives in a password manager and nobody ever types it by hand.",
    },
    shell: {
      title: "Shell-safe",
      len: 24,
      upper: true,
      lower: true,
      digit: true,
      symbol: true,
      symbolSet: "-_=+.,:@%^",
      note: "No characters that bash would interpret. Safe to paste straight into a command without quoting or escaping.",
    },
    yaml: {
      title: "YAML-safe",
      len: 24,
      upper: true,
      lower: true,
      digit: true,
      symbol: true,
      symbolSet: "-_=+.()/",
      note: "Avoids the characters that force YAML to demand quoting. For values.yaml and stringData.",
    },
    url: {
      title: "URL-safe",
      len: 32,
      upper: true,
      lower: true,
      digit: true,
      symbol: true,
      symbolSet: "-._~",
      note: "Only the unreserved characters from RFC 3986. Survives being dropped into a connection string or a query parameter.",
    },
    db: {
      title: "DB-safe",
      len: 24,
      upper: true,
      lower: true,
      digit: true,
      symbol: true,
      noDb: true,
      noAmbig: true,
      note: "No quotes, backslash, semicolon or ampersand. For database passwords and connection strings.",
    },
    pin: {
      title: "PIN",
      len: 8,
      upper: false,
      lower: false,
      digit: true,
      symbol: false,
      note: "Digits only. For safes, keypads and anything else with a numeric keyboard.",
    },
  };

  var state = { length: 20, batch: 1, revealed: true, symbolSet: null };
  var out, entropyFill, entropyBits, entropyLabel, presetNote;
  var optUpper, optLower, optDigit, optSymbol, optNoAmbig, optNoDb;
  var lenBtns, batchBtns, customLen, presetBtns;

  function activeSymbols() {
    return state.symbolSet || CHARS.symbol;
  }

  function buildCharset() {
    var chars = "";
    if (optUpper.checked) chars += CHARS.upper;
    if (optLower.checked) chars += CHARS.lower;
    if (optDigit.checked) chars += CHARS.digit;
    if (optSymbol.checked) chars += activeSymbols();
    var arr = chars.split("");
    if (optNoAmbig.checked)
      arr = arr.filter(function (c) {
        return AMBIG.indexOf(c) < 0;
      });
    if (optNoDb.checked)
      arr = arr.filter(function (c) {
        return DBUF.indexOf(c) < 0;
      });
    return Array.from(new Set(arr));
  }

  function genOne(charset, n) {
    var o = new Array(n);
    for (var i = 0; i < n; i++) o[i] = charset[U.uniformInt(charset.length)];
    return o.join("");
  }

  function formatEnv(passwords) {
    return (
      passwords
        .map(function (password, i) {
          var value = String(password)
            .replace(/[\r\n]/g, "")
            .replace(/\\/g, "\\\\")
            .replace(/"/g, '\\"');
          return "GENERATED_PASSWORD_" + (i + 1) + '="' + value + '"';
        })
        .join("\n") + "\n"
    );
  }

  // If a class is enabled but happened not to appear, drop one of its
  // characters into a random position. This costs a sliver of entropy but
  // makes the password pass "must contain a digit" style validators.
  function enforceClasses(pwd, charset) {
    var classes = [];
    function present(src) {
      return src.split("").filter(function (c) {
        return charset.indexOf(c) >= 0;
      });
    }
    if (optUpper.checked) classes.push(present(CHARS.upper));
    if (optLower.checked) classes.push(present(CHARS.lower));
    if (optDigit.checked) classes.push(present(CHARS.digit));
    if (optSymbol.checked) classes.push(present(activeSymbols()));

    var arr = pwd.split("");
    classes.forEach(function (cls) {
      if (!cls.length) return;
      var has = arr.some(function (c) {
        return cls.indexOf(c) >= 0;
      });
      if (!has) arr[U.uniformInt(arr.length)] = cls[U.uniformInt(cls.length)];
    });
    return arr.join("");
  }

  function rating(bits) {
    if (bits < 28) return { lbl: "very weak", pct: 10, cls: "vweak" };
    if (bits < 50) return { lbl: "weak", pct: 30, cls: "weak" };
    if (bits < 72) return { lbl: "moderate", pct: 55, cls: "mod" };
    if (bits < 128) return { lbl: "strong", pct: 80, cls: "strong" };
    return { lbl: "excellent", pct: 100, cls: "excellent" };
  }

  function render(list, csize) {
    out.innerHTML = "";
    list.forEach(function (p) {
      var row = U.el("div", "pwd-row" + (state.revealed ? "" : " hidden"), p);
      out.appendChild(row);
    });
    var bits = csize > 1 ? Math.log2(csize) * state.length : 0;
    var r = rating(bits);
    entropyFill.style.width = r.pct + "%";
    entropyFill.className = "entropy-fill " + r.cls;
    entropyBits.textContent =
      bits.toFixed(0) + " bits of entropy · alphabet of " + csize;
    entropyLabel.textContent = r.lbl;
    entropyLabel.className = "label " + r.cls;
  }

  function generate() {
    var charset = buildCharset();
    if (!charset.length) {
      U.setError(out, "Enable at least one character class.");
      entropyFill.style.width = "0%";
      entropyFill.className = "entropy-fill";
      entropyBits.textContent = "— bits of entropy";
      entropyLabel.textContent = "—";
      entropyLabel.className = "label";
      return;
    }
    var results = [];
    for (var i = 0; i < state.batch; i++) {
      results.push(enforceClasses(genOne(charset, state.length), charset));
    }
    render(results, charset.length);
  }

  function syncLengthButtons() {
    var matched = false;
    lenBtns.forEach(function (b) {
      var on = parseInt(b.dataset.len, 10) === state.length;
      b.classList.toggle("active", on);
      if (on) matched = true;
    });
    if (!matched) customLen.value = state.length;
  }

  function applyPreset(name) {
    var p = PRESETS[name];
    if (!p) return;
    optUpper.checked = !!p.upper;
    optLower.checked = !!p.lower;
    optDigit.checked = !!p.digit;
    optSymbol.checked = !!p.symbol;
    optNoAmbig.checked = !!p.noAmbig;
    optNoDb.checked = !!p.noDb;
    state.symbolSet = p.symbolSet || null;
    state.length = p.len;
    customLen.value = "";
    syncLengthButtons();
    presetNote.textContent = p.note;
    presetBtns.forEach(function (b) {
      b.classList.toggle("active", b.dataset.preset === name);
    });
    generate();
  }

  function clearPreset() {
    presetBtns.forEach(function (b) {
      b.classList.remove("active");
    });
    state.symbolSet = null;
    presetNote.textContent = "Custom settings.";
  }

  function init() {
    out = U.$("pw-output");
    if (!out) return;
    entropyFill = U.$("pw-entropy-fill");
    entropyBits = U.$("pw-entropy-bits");
    entropyLabel = U.$("pw-entropy-label");
    presetNote = U.$("pw-preset-note");
    optUpper = U.$("pw-upper");
    optLower = U.$("pw-lower");
    optDigit = U.$("pw-digit");
    optSymbol = U.$("pw-symbol");
    optNoAmbig = U.$("pw-no-ambig");
    optNoDb = U.$("pw-no-db");
    lenBtns = U.$$("#panel-passwords .len-btn");
    batchBtns = U.$$("#panel-passwords .batch-btn");
    presetBtns = U.$$("#panel-passwords .preset-btn");
    customLen = U.$("pw-custom-len");

    presetBtns.forEach(function (b) {
      b.addEventListener("click", function () {
        applyPreset(b.dataset.preset);
      });
    });

    lenBtns.forEach(function (b) {
      b.addEventListener("click", function () {
        state.length = parseInt(b.dataset.len, 10);
        customLen.value = "";
        syncLengthButtons();
        generate();
      });
    });

    customLen.addEventListener("input", function () {
      var v = parseInt(customLen.value, 10);
      if (!isNaN(v) && v >= 4 && v <= 256) {
        state.length = v;
        lenBtns.forEach(function (b) {
          b.classList.remove("active");
        });
        generate();
      }
    });

    [optUpper, optLower, optDigit, optSymbol, optNoAmbig, optNoDb].forEach(
      function (c) {
        c.addEventListener("change", function () {
          clearPreset();
          generate();
        });
      },
    );

    batchBtns.forEach(function (b) {
      b.addEventListener("click", function () {
        state.batch = parseInt(b.dataset.count, 10);
        batchBtns.forEach(function (x) {
          x.classList.toggle("active", x === b);
        });
        generate();
      });
    });

    U.$("pw-regen").addEventListener("click", generate);
    U.bindCopy(
      U.$("pw-copy"),
      function () {
        return U.$$(".pwd-row", out)
          .map(function (r) {
            return r.textContent;
          })
          .join("\n");
      },
      U.$("pw-copy-label"),
    );
    U.$("pw-copy-env").addEventListener("click", function () {
      var btn = U.$("pw-copy-env");
      var label = U.$("pw-copy-env-label");
      var text = formatEnv(
        U.$$(".pwd-row", out).map(function (r) {
          return r.textContent;
        }),
      );
      U.copyText(text).then(
        function () {
          U.flash(btn, label, "Copied as .env");
        },
        function () {
          U.flash(btn, label, "Copy failed");
        },
      );
    });

    U.$("pw-reveal").addEventListener("click", function () {
      state.revealed = !state.revealed;
      U.$$(".pwd-row", out).forEach(function (r) {
        r.classList.toggle("hidden", !state.revealed);
      });
      U.$("pw-reveal-label").textContent = state.revealed ? "Hide" : "Show";
      U.$("pw-eye-on").classList.toggle("hidden", !state.revealed);
      U.$("pw-eye-off").classList.toggle("hidden", state.revealed);
    });

    applyPreset("balanced");
  }

  U.ready(init);
  global.PwdPasswords = { PRESETS: PRESETS, formatEnv: formatEnv };
})(typeof globalThis !== "undefined" ? globalThis : this);
