// B64Crypto — hash & encryption helpers (no chrome APIs) used by the popup.
// MD5, SHA3-256 and CRC32 are implemented locally (WebCrypto does not offer
// them); SHA, HMAC and AES use the platform WebCrypto API. Safe to load in
// a browser or in Node.
(function (global) {
  'use strict';

  // ---------- MD5 (RFC 1321), operating on UTF-8 bytes ----------

  var S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
           5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
           4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
           6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  var K = [];
  for (var i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;

  function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }

  function md5(input) {
    var msg = new TextEncoder().encode(String(input == null ? '' : input));
    var bitLen = msg.length * 8;
    var paddedLen = (((msg.length + 8) / 64) | 0) * 64 + 64;
    var buf = new Uint8Array(paddedLen);
    buf.set(msg, 0);
    buf[msg.length] = 0x80;
    var view = new DataView(buf.buffer);
    view.setUint32(paddedLen - 8, bitLen & 0xFFFFFFFF, true);
    view.setUint32(paddedLen - 4, Math.floor(bitLen / 4294967296), true);

    var a0 = 0x67452301, b0 = 0xEFCDAB89, c0 = 0x98BADCFE, d0 = 0x10325476;
    for (var off = 0; off < paddedLen; off += 64) {
      var M = [];
      for (var j = 0; j < 16; j++) M[j] = view.getUint32(off + j * 4, true);
      var A = a0, B = b0, C = c0, D = d0;
      for (var k = 0; k < 64; k++) {
        var F, g;
        if (k < 16) { F = (B & C) | (~B & D); g = k; }
        else if (k < 32) { F = (D & B) | (~D & C); g = (5 * k + 1) % 16; }
        else if (k < 48) { F = B ^ C ^ D; g = (3 * k + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * k) % 16; }
        F = (F + A + K[k] + M[g]) | 0;
        A = D; D = C; C = B;
        B = (B + rotl(F, S[k])) | 0;
      }
      a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    }
    function hex32(x) {
      var h = '';
      for (var n = 0; n < 4; n++) h += ((x >>> (n * 8)) & 0xFF).toString(16).padStart(2, '0');
      return h;
    }
    return hex32(a0) + hex32(b0) + hex32(c0) + hex32(d0);
  }

  // ---------- SHA (WebCrypto) ----------

  function bytesToHex(bytes) {
    return Array.prototype.map.call(bytes, function (b) {
      return b.toString(16).padStart(2, '0');
    }).join('');
  }

  function sha(algo, text) {
    var data = new TextEncoder().encode(String(text == null ? '' : text));
    return global.crypto.subtle.digest(algo, data).then(function (buf) {
      return bytesToHex(new Uint8Array(buf));
    });
  }

  function shaAll(text) {
    return Promise.all([
      sha('SHA-1', text), sha('SHA-256', text), sha('SHA-384', text), sha('SHA-512', text)
    ]).then(function (r) {
      return { 'SHA-1': r[0], 'SHA-256': r[1], 'SHA-384': r[2], 'SHA-512': r[3] };
    });
  }

  // ---------- SHA3-256 (FIPS 202): Keccak-f[1600], 32-bit lane halves ----------

  var KECCAK_R = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20,
                  3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
                  18, 2, 61, 56, 14];
  var KECCAK_RC_LO = [0x00000001, 0x00008082, 0x0000808A, 0x80008000, 0x0000808B,
                      0x80000001, 0x80008081, 0x00008009, 0x0000008A, 0x00000088,
                      0x80008009, 0x8000000A, 0x8000808B, 0x0000008B, 0x00008089,
                      0x00008003, 0x00008002, 0x00000080, 0x0000800A, 0x8000000A,
                      0x80008081, 0x00008080, 0x80000001, 0x80008008];
  var KECCAK_RC_HI = [0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000,
                      0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000,
                      0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000,
                      0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000,
                      0x80000000, 0x80000000, 0x00000000, 0x80000000];

  // Rotate a 64-bit lane (given as [lo, hi]) left by n bits.
  function rotLane(lo, hi, n) {
    if (n === 0) return [lo, hi];
    if (n === 32) return [hi, lo];
    if (n < 32) {
      return [((lo << n) | (hi >>> (32 - n))) >>> 0,
              ((hi << n) | (lo >>> (32 - n))) >>> 0];
    }
    var m = n - 32;
    return [((hi << m) | (lo >>> (32 - m))) >>> 0,
            ((lo << m) | (hi >>> (32 - m))) >>> 0];
  }

  function keccakF(state) {
    var x, y, round;
    for (round = 0; round < 24; round++) {
      // Theta
      var C = [];
      for (x = 0; x < 5; x++) {
        C[x] = [state[x][0] ^ state[x + 5][0] ^ state[x + 10][0] ^ state[x + 15][0] ^ state[x + 20][0],
                state[x][1] ^ state[x + 5][1] ^ state[x + 10][1] ^ state[x + 15][1] ^ state[x + 20][1]];
      }
      for (x = 0; x < 5; x++) {
        var rC = rotLane(C[(x + 1) % 5][0], C[(x + 1) % 5][1], 1);
        var dLo = C[(x + 4) % 5][0] ^ rC[0];
        var dHi = C[(x + 4) % 5][1] ^ rC[1];
        for (y = 0; y < 5; y++) {
          state[x + 5 * y][0] ^= dLo;
          state[x + 5 * y][1] ^= dHi;
        }
      }
      // Rho + Pi
      var B = [];
      for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
          var idx = x + 5 * y;
          B[y + 5 * ((2 * x + 3 * y) % 5)] = rotLane(state[idx][0], state[idx][1], KECCAK_R[idx]);
        }
      }
      // Chi
      for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
          var b0 = B[x + 5 * y];
          var b1 = B[((x + 1) % 5) + 5 * y];
          var b2 = B[((x + 2) % 5) + 5 * y];
          state[x + 5 * y] = [b0[0] ^ (~b1[0] & b2[0]), b0[1] ^ (~b1[1] & b2[1])];
        }
      }
      // Iota
      state[0][0] ^= KECCAK_RC_LO[round];
      state[0][1] ^= KECCAK_RC_HI[round];
    }
  }

  function keccakXorBlock(state, block, offset, len) {
    for (var i = 0; i < len; i++) {
      var lane = (i / 8) | 0;
      var byteInLane = i % 8;
      if (byteInLane < 4) state[lane][0] ^= block[offset + i] << (byteInLane * 8);
      else state[lane][1] ^= block[offset + i] << ((byteInLane - 4) * 8);
    }
  }

  function sha3_256(input) {
    var msg = new TextEncoder().encode(String(input == null ? '' : input));
    var rate = 136; // bytes (1088-bit rate for SHA3-256)
    var state = [];
    for (var i = 0; i < 25; i++) state.push([0, 0]);
    var offset = 0;
    while (offset + rate <= msg.length) {
      keccakXorBlock(state, msg, offset, rate);
      keccakF(state);
      offset += rate;
    }
    // Final block: pad10*1 with the 0x06 domain suffix
    var last = new Uint8Array(rate);
    last.set(msg.subarray(offset));
    last[msg.length - offset] ^= 0x06;
    last[rate - 1] ^= 0x80;
    keccakXorBlock(state, last, 0, rate);
    keccakF(state);
    var out = new Uint8Array(32);
    for (var j = 0; j < 32; j++) {
      var lane = (j / 8) | 0;
      var byteInLane = j % 8;
      var word = byteInLane < 4 ? state[lane][0] : state[lane][1];
      out[j] = (word >>> ((byteInLane % 4) * 8)) & 0xFF;
    }
    return bytesToHex(out);
  }

  // ---------- CRC32 (IEEE 802.3, polynomial 0xEDB88320) ----------

  var CRC32_TABLE = (function () {
    var table = [];
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      table.push(c >>> 0);
    }
    return table;
  })();

  function crc32(input) {
    var bytes = new TextEncoder().encode(String(input == null ? '' : input));
    var crc = 0xFFFFFFFF;
    for (var i = 0; i < bytes.length; i++) {
      crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
    }
    return ((crc ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, '0');
  }

  // ---------- HMAC (WebCrypto) ----------

  function hmacRaw(algo, keyBytes, dataBytes) {
    return global.crypto.subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash: algo }, false, ['sign']
    ).then(function (key) {
      return global.crypto.subtle.sign('HMAC', key, dataBytes);
    }).then(function (buf) { return new Uint8Array(buf); });
  }

  function hmac(algo, key, text) {
    return hmacRaw(algo,
      new TextEncoder().encode(String(key == null ? '' : key)),
      new TextEncoder().encode(String(text == null ? '' : text))
    ).then(function (bytes) { return bytesToHex(bytes); });
  }

  // ---------- AES with passphrase (PBKDF2), modes GCM / CBC / CTR ----------

  var AES_PREFIXES = { GCM: 'AES-GCM:v1:', CBC: 'AES-CBC:v1:', CTR: 'AES-CTR:v1:' };
  var AES_PREFIX = AES_PREFIXES.GCM; // kept for backward compatibility

  function bytesToB64(bytes) {
    var bin = '';
    var CHUNK = 0x8000;
    for (var i = 0; i < bytes.length; i += CHUNK) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(bin);
  }

  function b64ToBytes(s) {
    var bin = atob(s);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function hexToBytes(s) {
    var bytes = new Uint8Array(s.length / 2);
    for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(s.substr(i * 2, 2), 16);
    return bytes;
  }

  function deriveKey(passphrase, salt, algoName) {
    return global.crypto.subtle.importKey(
      'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
    ).then(function (baseKey) {
      return global.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        baseKey, { name: algoName, length: 256 }, false, ['encrypt', 'decrypt']
      );
    });
  }

  function aesParams(mode, iv) {
    if (mode === 'CTR') return { name: 'AES-CTR', counter: iv, length: 64 };
    return { name: 'AES-' + mode, iv: iv };
  }

  // GCM authenticates via its tag; CBC/CTR get a magic prefix so a wrong
  // passphrase is detected instead of returning garbage bytes.
  var AES_MAGIC = new Uint8Array([0x53, 0x44, 0x76, 0x33, 0x3A]); // 'SDv3:'

  // Returns a self-contained string:
  // AES-<MODE>:v1:<base64(salt[16] || iv[12 for GCM, 16 otherwise] || ciphertext)>
  function aesEncrypt(plaintext, passphrase, mode) {
    mode = mode || 'GCM';
    if (!AES_PREFIXES[mode]) return Promise.reject(new Error('不支持的加密模式：' + mode));
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var salt = global.crypto.getRandomValues(new Uint8Array(16));
    var iv = global.crypto.getRandomValues(new Uint8Array(mode === 'GCM' ? 12 : 16));
    var plainBytes = new TextEncoder().encode(String(plaintext));
    if (mode !== 'GCM') {
      var withMagic = new Uint8Array(AES_MAGIC.length + plainBytes.length);
      withMagic.set(AES_MAGIC, 0);
      withMagic.set(plainBytes, AES_MAGIC.length);
      plainBytes = withMagic;
    }
    return deriveKey(passphrase, salt, 'AES-' + mode).then(function (key) {
      return global.crypto.subtle.encrypt(
        aesParams(mode, iv), key, plainBytes
      );
    }).then(function (ct) {
      var out = new Uint8Array(16 + iv.length + ct.byteLength);
      out.set(salt, 0);
      out.set(iv, 16);
      out.set(new Uint8Array(ct), 16 + iv.length);
      return AES_PREFIXES[mode] + bytesToB64(out);
    });
  }

  function aesDecrypt(ciphertext, passphrase) {
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var s = String(ciphertext == null ? '' : ciphertext).trim();
    var mode = null;
    for (var m in AES_PREFIXES) {
      if (s.indexOf(AES_PREFIXES[m]) === 0) { mode = m; break; }
    }
    if (!mode) {
      return Promise.reject(new Error('不是本插件加密的格式（应以 AES-GCM:v1:、AES-CBC:v1: 或 AES-CTR:v1: 开头）'));
    }
    var raw;
    try {
      raw = b64ToBytes(s.slice(AES_PREFIXES[mode].length));
    } catch (e) {
      return Promise.reject(new Error('密文不是合法的 Base64'));
    }
    var ivLen = mode === 'GCM' ? 12 : 16;
    if (raw.length < 16 + ivLen + 1) return Promise.reject(new Error('密文过短或已损坏'));
    var salt = raw.slice(0, 16);
    var iv = raw.slice(16, 16 + ivLen);
    var ct = raw.slice(16 + ivLen);
    return deriveKey(passphrase, salt, 'AES-' + mode).then(function (key) {
      return global.crypto.subtle.decrypt(aesParams(mode, iv), key, ct);
    }).then(function (pt) {
      var bytes = new Uint8Array(pt);
      if (mode !== 'GCM') {
        if (bytes.length < AES_MAGIC.length) throw new Error('bad magic');
        for (var i = 0; i < AES_MAGIC.length; i++) {
          if (bytes[i] !== AES_MAGIC[i]) throw new Error('bad magic');
        }
        bytes = bytes.slice(AES_MAGIC.length);
      }
      return new TextDecoder().decode(bytes);
    }).catch(function () {
      throw new Error('解密失败：口令错误或密文已损坏');
    });
  }

  // Raw-key AES (no passphrase derivation), for interop and test vectors.
  // mode: 'GCM' | 'CBC' | 'CTR'; keyBytes: 16/24/32 bytes; ivBytes: 12 (GCM)
  // or 16 bytes. CTR uses a 64-bit counter by default (counterBits param).
  function aesEncryptRaw(mode, keyBytes, ivBytes, dataBytes, counterBits) {
    var params = mode === 'CTR'
      ? { name: 'AES-CTR', counter: ivBytes, length: counterBits || 64 }
      : { name: 'AES-' + mode, iv: ivBytes };
    return global.crypto.subtle.importKey('raw', keyBytes, { name: 'AES-' + mode }, false, ['encrypt'])
      .then(function (key) { return global.crypto.subtle.encrypt(params, key, dataBytes); })
      .then(function (buf) { return new Uint8Array(buf); });
  }

  function aesDecryptRaw(mode, keyBytes, ivBytes, dataBytes, counterBits) {
    var params = mode === 'CTR'
      ? { name: 'AES-CTR', counter: ivBytes, length: counterBits || 64 }
      : { name: 'AES-' + mode, iv: ivBytes };
    return global.crypto.subtle.importKey('raw', keyBytes, { name: 'AES-' + mode }, false, ['decrypt'])
      .then(function (key) { return global.crypto.subtle.decrypt(params, key, dataBytes); })
      .then(function (buf) { return new Uint8Array(buf); });
  }

  // ---------- RC4 (stream cipher; encrypt/decrypt are the same operation) ----------

  function rc4Bytes(data, key) {
    var S = [];
    for (var i = 0; i < 256; i++) S[i] = i;
    var j = 0;
    for (i = 0; i < 256; i++) {
      j = (j + S[i] + key[i % key.length]) & 0xFF;
      var tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    var out = new Uint8Array(data.length);
    var a = 0, b = 0;
    for (var n = 0; n < data.length; n++) {
      a = (a + 1) & 0xFF;
      b = (b + S[a]) & 0xFF;
      tmp = S[a]; S[a] = S[b]; S[b] = tmp;
      out[n] = data[n] ^ S[(S[a] + S[b]) & 0xFF];
    }
    return out;
  }

  // RC4 output is hex text (no prefix); the key is used directly, not derived.
  function rc4Encrypt(text, key) {
    if (!key) throw new Error('请填写密钥');
    var data = new TextEncoder().encode(String(text == null ? '' : text));
    return bytesToHex(rc4Bytes(data, new TextEncoder().encode(String(key))));
  }

  function rc4Decrypt(hexStr, key) {
    if (!key) throw new Error('请填写密钥');
    var s = String(hexStr == null ? '' : hexStr).trim().replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]*$/.test(s) || s.length % 2 !== 0) {
      throw new Error('密文不是合法的十六进制');
    }
    return new TextDecoder().decode(rc4Bytes(hexToBytes(s), new TextEncoder().encode(String(key))));
  }

  // ---------- XOR (repeating-key; encrypt/decrypt are the same operation) ----------

  function xorBytes(data, key) {
    var out = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length];
    return out;
  }

  function xorEncrypt(text, key) {
    if (!key) throw new Error('请填写密钥');
    var data = new TextEncoder().encode(String(text == null ? '' : text));
    return bytesToHex(xorBytes(data, new TextEncoder().encode(String(key))));
  }

  function xorDecrypt(hexStr, key) {
    if (!key) throw new Error('请填写密钥');
    var s = String(hexStr == null ? '' : hexStr).trim().replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]*$/.test(s) || s.length % 2 !== 0) {
      throw new Error('密文不是合法的十六进制');
    }
    return new TextDecoder().decode(xorBytes(hexToBytes(s), new TextEncoder().encode(String(key))));
  }

  // ---------- JWT: HS256 sign & verify ----------

  function b64urlEncode(bytes) {
    return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64urlDecode(s) {
    var std = String(s).replace(/-/g, '+').replace(/_/g, '/');
    var rem = std.length % 4;
    if (rem) std += '===='.slice(0, 4 - rem);
    return b64ToBytes(std);
  }

  function jwtSign(header, payload, secret) {
    if (!secret) return Promise.reject(new Error('请填写密钥'));
    var h, p;
    try {
      h = b64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
      p = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
    } catch (e) {
      return Promise.reject(new Error('Header / Payload 不是合法的 JSON'));
    }
    var data = h + '.' + p;
    return hmacRaw('SHA-256',
      new TextEncoder().encode(secret),
      new TextEncoder().encode(data)
    ).then(function (sig) { return data + '.' + b64urlEncode(sig); });
  }

  // Returns { valid, header, payload } — header/payload are parsed JSON or
  // null when that part is not JSON.
  function jwtVerify(token, secret) {
    if (!secret) return Promise.reject(new Error('请填写密钥'));
    var parts = String(token == null ? '' : token).trim().split('.');
    if (parts.length !== 3) return Promise.reject(new Error('不是 JWT 格式（应为三段）'));
    var data = parts[0] + '.' + parts[1];
    return hmacRaw('SHA-256',
      new TextEncoder().encode(secret),
      new TextEncoder().encode(data)
    ).then(function (sig) {
      var out = { valid: b64urlEncode(sig) === parts[2] };
      try { out.header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0]))); }
      catch (e) { out.header = null; }
      try { out.payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]))); }
      catch (e) { out.payload = null; }
      return out;
    });
  }

  // ---------- Generators & converters ----------

  function uuidv4() {
    var b = new Uint8Array(16);
    global.crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    var h = bytesToHex(b);
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) +
      '-' + h.slice(16, 20) + '-' + h.slice(20);
  }

  function isUuid(s) {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/
      .test(String(s == null ? '' : s).trim());
  }

  // opts: { lower, upper, digits, symbols } — all default true except symbols.
  function generatePassword(length, opts) {
    var len = Math.max(4, Math.min(128, parseInt(length, 10) || 16));
    opts = opts || {};
    var sets = [];
    if (opts.lower !== false) sets.push('abcdefghijklmnopqrstuvwxyz');
    if (opts.upper !== false) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (opts.digits !== false) sets.push('0123456789');
    if (opts.symbols) sets.push('!@#$%^&*()-_=+[]{};:,.<>?');
    if (!sets.length) sets.push('abcdefghijklmnopqrstuvwxyz');
    var all = sets.join('');
    var rand = new Uint32Array(len);
    global.crypto.getRandomValues(rand);
    var chars = [];
    for (var i = 0; i < sets.length && i < len; i++) {
      chars.push(sets[i][rand[i] % sets[i].length]);
    }
    while (chars.length < len) chars.push(all[rand[chars.length] % all.length]);
    for (var j = chars.length - 1; j > 0; j--) {
      var k = rand[j] % (j + 1);
      var t = chars[j]; chars[j] = chars[k]; chars[k] = t;
    }
    return chars.join('');
  }

  function formatTsResult(ms) {
    var d = new Date(ms);
    return { ok: true, ms: ms, seconds: Math.floor(ms / 1000),
             iso: d.toISOString(), local: d.toLocaleString('zh-CN', { hour12: false }) };
  }

  // Accepts seconds (10 digits) or milliseconds (13 digits); auto-detected.
  function timestampToDate(ts) {
    var s = String(ts == null ? '' : ts).trim();
    if (!/^\d+$/.test(s)) return { ok: false, error: '请输入纯数字时间戳' };
    var num = parseInt(s, 10);
    var ms = s.length <= 10 ? num * 1000 : num;
    if (isNaN(new Date(ms).getTime())) return { ok: false, error: '时间戳超出范围' };
    return formatTsResult(ms);
  }

  function dateToTimestamp(str) {
    var s = String(str == null ? '' : str).trim();
    if (!s) return { ok: false, error: '请输入日期时间' };
    var d = new Date(s.replace(' ', 'T'));
    if (isNaN(d.getTime())) d = new Date(s);
    if (isNaN(d.getTime())) return { ok: false, error: '无法解析这个日期时间' };
    return formatTsResult(d.getTime());
  }

  var api = {
    md5: md5, sha: sha, shaAll: shaAll, sha3_256: sha3_256, crc32: crc32,
    hmac: hmac, hmacRaw: hmacRaw,
    aesEncrypt: aesEncrypt, aesDecrypt: aesDecrypt,
    aesEncryptRaw: aesEncryptRaw, aesDecryptRaw: aesDecryptRaw,
    AES_PREFIX: AES_PREFIX, AES_PREFIXES: AES_PREFIXES,
    rc4Encrypt: rc4Encrypt, rc4Decrypt: rc4Decrypt,
    xorEncrypt: xorEncrypt, xorDecrypt: xorDecrypt,
    jwtSign: jwtSign, jwtVerify: jwtVerify,
    uuidv4: uuidv4, isUuid: isUuid,
    generatePassword: generatePassword,
    timestampToDate: timestampToDate, dateToTimestamp: dateToTimestamp
  };
  global.B64Crypto = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
