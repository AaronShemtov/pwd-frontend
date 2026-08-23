/* MD5 и apr1 ($apr1$) — для htpasswd в формате Apache/nginx/Traefik.
 *
 * MD5 давно сломан как хеш общего назначения и здесь присутствует только
 * потому, что этого требует формат apr1, который до сих пор понимают
 * nginx и Traefik. Для новых конфигураций выбирай bcrypt.
 *
 * Таблица K — это floor(abs(sin(i+1)) * 2^32), как в RFC 1321.
 * Проверено против hashlib и passlib.
 */
(function (global) {
  'use strict';

  var K = new Uint32Array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
  ]);

  var SHIFT = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];

  function rotl(x, c) { return ((x << c) | (x >>> (32 - c))) >>> 0; }

  /* md5(Uint8Array) -> Uint8Array(16) */
  function md5(msg) {
    var origLen = msg.length;
    var padLen = ((origLen + 8) % 64 < 56 || (origLen + 8) % 64 === 0)
      ? 0 : 0; // вычисляем ниже явно
    var withOne = origLen + 1;
    var total = withOne + ((56 - withOne % 64) + 64) % 64 + 8;
    var buf = new Uint8Array(total);
    buf.set(msg, 0);
    buf[origLen] = 0x80;
    var bitLenLo = (origLen << 3) >>> 0;
    var bitLenHi = Math.floor(origLen / 536870912) >>> 0;
    buf[total - 8] = bitLenLo & 0xff;
    buf[total - 7] = (bitLenLo >>> 8) & 0xff;
    buf[total - 6] = (bitLenLo >>> 16) & 0xff;
    buf[total - 5] = (bitLenLo >>> 24) & 0xff;
    buf[total - 4] = bitLenHi & 0xff;
    buf[total - 3] = (bitLenHi >>> 8) & 0xff;
    buf[total - 2] = (bitLenHi >>> 16) & 0xff;
    buf[total - 1] = (bitLenHi >>> 24) & 0xff;

    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    var M = new Uint32Array(16);

    for (var off = 0; off < total; off += 64) {
      for (var i = 0; i < 16; i++) {
        M[i] = (buf[off + i * 4] | (buf[off + i * 4 + 1] << 8) |
                (buf[off + i * 4 + 2] << 16) | (buf[off + i * 4 + 3] << 24)) >>> 0;
      }
      var A = a0, B = b0, C = c0, D = d0, F, g, tmp;
      for (i = 0; i < 64; i++) {
        if (i < 16)      { F = (B & C) | (~B & D);        g = i; }
        else if (i < 32) { F = (D & B) | (~D & C);        g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;                 g = (3 * i + 5) % 16; }
        else             { F = C ^ (B | (~D >>> 0));      g = (7 * i) % 16; }
        F = (F + A + K[i] + M[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + rotl(F, SHIFT[i])) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0;
      c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }

    var out = new Uint8Array(16), words = [a0, b0, c0, d0];
    for (i = 0; i < 4; i++) {
      out[i * 4]     = words[i] & 0xff;
      out[i * 4 + 1] = (words[i] >>> 8) & 0xff;
      out[i * 4 + 2] = (words[i] >>> 16) & 0xff;
      out[i * 4 + 3] = (words[i] >>> 24) & 0xff;
    }
    return out;
  }

  function concat(parts) {
    var len = 0, i;
    for (i = 0; i < parts.length; i++) len += parts[i].length;
    var out = new Uint8Array(len), off = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], off); off += parts[i].length; }
    return out;
  }

  var ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  function to64(v, n) {
    var s = '';
    while (--n >= 0) { s += ITOA64.charAt(v & 0x3f); v >>>= 6; }
    return s;
  }

  /* apr1(password, salt) -> "$apr1$salt$hash" */
  function apr1(password, salt) {
    var enc = new TextEncoder();
    var pw = enc.encode(password);
    if (!salt) {
      var rnd = new Uint8Array(8);
      global.crypto.getRandomValues(rnd);
      salt = '';
      for (var s = 0; s < 8; s++) salt += ITOA64.charAt(rnd[s] & 0x3f);
    }
    salt = salt.slice(0, 8);
    var saltBytes = enc.encode(salt);
    var magic = enc.encode('$apr1$');

    // Промежуточный хеш: пароль + соль + пароль.
    var inner = md5(concat([pw, saltBytes, pw]));

    var parts = [pw, magic, saltBytes];
    for (var i = pw.length; i > 0; i -= 16) {
      parts.push(inner.subarray(0, i > 16 ? 16 : i));
    }
    // Разрядка длины пароля: единичный бит даёт нулевой байт,
    // нулевой — первый байт пароля.
    var zero = new Uint8Array([0]);
    for (i = pw.length; i !== 0; i >>= 1) {
      parts.push((i & 1) ? zero : pw.subarray(0, 1));
    }
    var final = md5(concat(parts));

    // 1000 проходов — то, что делает apr1 медленнее голого MD5.
    for (i = 0; i < 1000; i++) {
      var p = [];
      if (i & 1) p.push(pw); else p.push(final);
      if (i % 3) p.push(saltBytes);
      if (i % 7) p.push(pw);
      if (i & 1) p.push(final); else p.push(pw);
      final = md5(concat(p));
    }

    var out = '';
    out += to64((final[0] << 16) | (final[6] << 8) | final[12], 4);
    out += to64((final[1] << 16) | (final[7] << 8) | final[13], 4);
    out += to64((final[2] << 16) | (final[8] << 8) | final[14], 4);
    out += to64((final[3] << 16) | (final[9] << 8) | final[15], 4);
    out += to64((final[4] << 16) | (final[10] << 8) | final[5], 4);
    out += to64(final[11], 2);
    return '$apr1$' + salt + '$' + out;
  }

  function md5Hex(bytes) {
    var d = md5(bytes), s = '';
    for (var i = 0; i < d.length; i++) s += ('0' + d[i].toString(16)).slice(-2);
    return s;
  }

  global.PwdMd5 = { md5: md5, md5Hex: md5Hex, apr1: apr1 };
})(typeof globalThis !== 'undefined' ? globalThis : this);
