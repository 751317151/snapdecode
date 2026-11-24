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
    return md5Bytes(new TextEncoder().encode(String(input == null ? '' : input)));
  }

  // MD5 over raw bytes (used for file hashing); md5() is the text wrapper.
  function md5Bytes(msg) {
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
    return shaBytes(algo, new TextEncoder().encode(String(text == null ? '' : text)));
  }

  // SHA over raw bytes (used for file hashing); sha() is the text wrapper.
  function shaBytes(algo, bytes) {
    return global.crypto.subtle.digest(algo, bytes).then(function (buf) {
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
    return sha3Bytes(new TextEncoder().encode(String(input == null ? '' : input)));
  }

  // SHA3-256 over raw bytes (used for file hashing); sha3_256() is the
  // text wrapper.
  function sha3Bytes(msg) {
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
    return crc32Bytes(new TextEncoder().encode(String(input == null ? '' : input)));
  }

  // CRC32 over raw bytes (used for file hashing); crc32() is the text wrapper.
  function crc32Bytes(bytes) {
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

  // ---------- Shared helpers for the v4 crypto modules ----------

  var WRONG_PASS_ERROR = '解密失败：口令错误或密文已损坏';

  function concatBytes(parts) {
    var len = 0;
    for (var i = 0; i < parts.length; i++) len += parts[i].length;
    var out = new Uint8Array(len);
    var off = 0;
    for (var j = 0; j < parts.length; j++) {
      out.set(parts[j], off);
      off += parts[j].length;
    }
    return out;
  }

  // PBKDF2-SHA256, 100000 iterations, returning raw key bytes of the
  // requested length (the AES helpers use deriveKey; these ciphers need
  // the raw bytes for their hand-written implementations).
  function pbkdf2Bytes(passphrase, salt, lengthBytes) {
    return global.crypto.subtle.importKey(
      'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveBits']
    ).then(function (baseKey) {
      return global.crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        baseKey, lengthBytes * 8
      );
    }).then(function (bits) { return new Uint8Array(bits); });
  }

  function pkcs7Pad(data, blockSize) {
    var padLen = blockSize - (data.length % blockSize);
    var out = new Uint8Array(data.length + padLen);
    out.set(data, 0);
    for (var i = 0; i < padLen; i++) out[data.length + i] = padLen;
    return out;
  }

  function pkcs7Unpad(data, blockSize) {
    if (!data.length || data.length % blockSize !== 0) {
      throw new Error('填充无效：数据长度不是分组长度的倍数');
    }
    var padLen = data[data.length - 1];
    if (padLen < 1 || padLen > blockSize) throw new Error('填充无效');
    for (var i = 1; i <= padLen; i++) {
      if (data[data.length - i] !== padLen) throw new Error('填充无效');
    }
    return data.slice(0, data.length - padLen);
  }

  function u32le(bytes, off) {
    return (bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) |
      (bytes[off + 3] << 24)) >>> 0;
  }

  function putU32le(out, off, v) {
    out[off] = v & 0xFF;
    out[off + 1] = (v >>> 8) & 0xFF;
    out[off + 2] = (v >>> 16) & 0xFF;
    out[off + 3] = (v >>> 24) & 0xFF;
  }

  function u32be(bytes, off) {
    return ((bytes[off] << 24) | (bytes[off + 1] << 16) |
      (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0;
  }

  function putU32be(out, off, v) {
    out[off] = (v >>> 24) & 0xFF;
    out[off + 1] = (v >>> 16) & 0xFF;
    out[off + 2] = (v >>> 8) & 0xFF;
    out[off + 3] = v & 0xFF;
  }

  // ---------- DES / Triple-DES (FIPS 46-3), hand-written ----------
  // WebCrypto does not offer DES, so this is a bit-level implementation.
  // Slow but correct; fine for the small texts this extension handles.

  var DES_IP = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7];
  var DES_FP = [40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25];
  var DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
               8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
               16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
               24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
  var DES_P = [16, 7, 20, 21, 29, 12, 28, 17,
               1, 15, 23, 26, 5, 18, 31, 10,
               2, 8, 24, 14, 32, 27, 3, 9,
               19, 13, 30, 6, 22, 11, 4, 25];
  var DES_PC1 = [57, 49, 41, 33, 25, 17, 9,
                 1, 58, 50, 42, 34, 26, 18,
                 10, 2, 59, 51, 43, 35, 27,
                 19, 11, 3, 60, 52, 44, 36,
                 63, 55, 47, 39, 31, 23, 15,
                 7, 62, 54, 46, 38, 30, 22,
                 14, 6, 61, 53, 45, 37, 29,
                 21, 13, 5, 28, 20, 12, 4];
  var DES_PC2 = [14, 17, 11, 24, 1, 5,
                 3, 28, 15, 6, 21, 10,
                 23, 19, 12, 4, 26, 8,
                 16, 7, 27, 20, 13, 2,
                 41, 52, 31, 37, 47, 55,
                 30, 40, 51, 45, 33, 48,
                 44, 49, 39, 56, 34, 53,
                 46, 42, 50, 36, 29, 32];
  var DES_ROT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
  var DES_SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
  ];

  function desBytesToBits(bytes) {
    var bits = new Array(bytes.length * 8);
    for (var i = 0; i < bytes.length; i++) {
      for (var b = 0; b < 8; b++) bits[i * 8 + b] = (bytes[i] >> (7 - b)) & 1;
    }
    return bits;
  }

  function desBitsToBytes(bits) {
    var bytes = new Uint8Array(bits.length / 8);
    for (var i = 0; i < bytes.length; i++) {
      var v = 0;
      for (var b = 0; b < 8; b++) v = (v << 1) | bits[i * 8 + b];
      bytes[i] = v;
    }
    return bytes;
  }

  function desPermute(bits, table) {
    var out = new Array(table.length);
    for (var i = 0; i < table.length; i++) out[i] = bits[table[i] - 1];
    return out;
  }

  function desRotLeft(bits, n) {
    return bits.slice(n).concat(bits.slice(0, n));
  }

  // Returns the 16 round subkeys (each 48 bits) for an 8-byte key.
  function desSubkeys(keyBytes) {
    var key56 = desPermute(desBytesToBits(keyBytes), DES_PC1);
    var c = key56.slice(0, 28);
    var d = key56.slice(28, 56);
    var subkeys = [];
    for (var i = 0; i < 16; i++) {
      c = desRotLeft(c, DES_ROT[i]);
      d = desRotLeft(d, DES_ROT[i]);
      subkeys.push(desPermute(c.concat(d), DES_PC2));
    }
    return subkeys;
  }

  function desF(right, subkey) {
    var expanded = desPermute(right, DES_E);
    for (var i = 0; i < 48; i++) expanded[i] ^= subkey[i];
    var out = new Array(32);
    for (var s = 0; s < 8; s++) {
      var chunk = expanded.slice(s * 6, s * 6 + 6);
      var row = (chunk[0] << 1) | chunk[5];
      var col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4];
      var val = DES_SBOX[s][row * 16 + col];
      for (var b = 0; b < 4; b++) out[s * 4 + b] = (val >> (3 - b)) & 1;
    }
    return desPermute(out, DES_P);
  }

  // One DES block (8 bytes) with precomputed subkeys; decrypt reverses them.
  function desCryptBlock(block, subkeys, decrypt) {
    var bits = desPermute(desBytesToBits(block), DES_IP);
    var left = bits.slice(0, 32);
    var right = bits.slice(32, 64);
    for (var i = 0; i < 16; i++) {
      var k = decrypt ? subkeys[15 - i] : subkeys[i];
      var fOut = desF(right, k);
      var nextRight = new Array(32);
      for (var j = 0; j < 32; j++) nextRight[j] = left[j] ^ fOut[j];
      left = right;
      right = nextRight;
    }
    return desBitsToBytes(desPermute(right.concat(left), DES_FP));
  }

  // Generic ECB/CBC driver over 8-byte blocks. blockFn(block, decrypt)
  // transforms one block.
  function desModeCrypt(data, mode, iv, blockFn, decrypt) {
    if (mode !== 'ECB' && mode !== 'CBC') throw new Error('不支持的加密模式：' + mode);
    if (mode === 'CBC' && (!iv || iv.length !== 8)) {
      throw new Error('CBC 模式需要 8 字节 IV');
    }
    var out = new Uint8Array(data.length);
    var prev = iv;
    for (var off = 0; off < data.length; off += 8) {
      var block = data.slice(off, off + 8);
      if (mode === 'CBC' && !decrypt) {
        for (var i = 0; i < 8; i++) block[i] ^= prev[i];
      }
      var done = blockFn(block, decrypt);
      if (mode === 'CBC' && decrypt) {
        for (var j = 0; j < 8; j++) done[j] ^= prev[j];
        prev = data.slice(off, off + 8);
      } else if (mode === 'CBC') {
        prev = done;
      }
      out.set(done, off);
    }
    return out;
  }

  function desEncryptRaw(keyBytes8, ivBytes8, dataBytes, mode) {
    if (!keyBytes8 || keyBytes8.length !== 8) throw new Error('DES 密钥必须是 8 字节');
    mode = mode || 'CBC';
    var subkeys = desSubkeys(keyBytes8);
    return desModeCrypt(pkcs7Pad(dataBytes, 8), mode, ivBytes8,
      function (block, decrypt) { return desCryptBlock(block, subkeys, decrypt); }, false);
  }

  function desDecryptRaw(keyBytes8, ivBytes8, dataBytes, mode) {
    if (!keyBytes8 || keyBytes8.length !== 8) throw new Error('DES 密钥必须是 8 字节');
    mode = mode || 'CBC';
    var subkeys = desSubkeys(keyBytes8);
    return pkcs7Unpad(desModeCrypt(dataBytes, mode, ivBytes8,
      function (block, decrypt) { return desCryptBlock(block, subkeys, decrypt); }, true), 8);
  }

  // 3DES-EDE: encrypt = E_K3(D_K2(E_K1(.))); decrypt reverses the order.
  function tripleDesCryptBlock(block, subs1, subs2, subs3, decrypt) {
    if (!decrypt) {
      return desCryptBlock(
        desCryptBlock(desCryptBlock(block, subs1, false), subs2, true), subs3, false);
    }
    return desCryptBlock(
      desCryptBlock(desCryptBlock(block, subs3, true), subs2, false), subs1, true);
  }

  function tripleDesEncryptRaw(keyBytes24, ivBytes8, dataBytes, mode) {
    if (!keyBytes24 || keyBytes24.length !== 24) throw new Error('3DES 密钥必须是 24 字节');
    mode = mode || 'CBC';
    var s1 = desSubkeys(keyBytes24.slice(0, 8));
    var s2 = desSubkeys(keyBytes24.slice(8, 16));
    var s3 = desSubkeys(keyBytes24.slice(16, 24));
    return desModeCrypt(pkcs7Pad(dataBytes, 8), mode, ivBytes8,
      function (block, decrypt) { return tripleDesCryptBlock(block, s1, s2, s3, decrypt); }, false);
  }

  function tripleDesDecryptRaw(keyBytes24, ivBytes8, dataBytes, mode) {
    if (!keyBytes24 || keyBytes24.length !== 24) throw new Error('3DES 密钥必须是 24 字节');
    mode = mode || 'CBC';
    var s1 = desSubkeys(keyBytes24.slice(0, 8));
    var s2 = desSubkeys(keyBytes24.slice(8, 16));
    var s3 = desSubkeys(keyBytes24.slice(16, 24));
    return pkcs7Unpad(desModeCrypt(dataBytes, mode, ivBytes8,
      function (block, decrypt) { return tripleDesCryptBlock(block, s1, s2, s3, decrypt); }, true), 8);
  }

  var TDES_PREFIXES = { ECB: '3DES-ECB:v1:', CBC: '3DES-CBC:v1:' };

  // Passphrase 3DES, self-contained like aesEncrypt:
  // 3DES-<MODE>:v1:<base64(salt[16] || iv[8] || ciphertext)>
  // (ECB carries an unused random iv so the layout stays uniform.)
  // PBKDF2-SHA256/100k derives the 24-byte key; the SDv3: magic prefix
  // detects a wrong passphrase.
  function tripleDesEncrypt(text, passphrase, mode) {
    mode = mode || 'CBC';
    if (!TDES_PREFIXES[mode]) return Promise.reject(new Error('不支持的加密模式：' + mode));
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var salt = global.crypto.getRandomValues(new Uint8Array(16));
    var iv = global.crypto.getRandomValues(new Uint8Array(8));
    var plainBytes = concatBytes([AES_MAGIC,
      new TextEncoder().encode(String(text == null ? '' : text))]);
    return pbkdf2Bytes(passphrase, salt, 24).then(function (key) {
      var ct = tripleDesEncryptRaw(key, iv, plainBytes, mode);
      return TDES_PREFIXES[mode] + bytesToB64(concatBytes([salt, iv, ct]));
    });
  }

  function tripleDesDecrypt(ciphertext, passphrase) {
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var s = String(ciphertext == null ? '' : ciphertext).trim();
    var mode = null;
    for (var m in TDES_PREFIXES) {
      if (s.indexOf(TDES_PREFIXES[m]) === 0) { mode = m; break; }
    }
    if (!mode) {
      return Promise.reject(new Error('不是本插件加密的格式（应以 3DES-ECB:v1: 或 3DES-CBC:v1: 开头）'));
    }
    var raw;
    try {
      raw = b64ToBytes(s.slice(TDES_PREFIXES[mode].length));
    } catch (e) {
      return Promise.reject(new Error('密文不是合法的 Base64'));
    }
    if (raw.length < 16 + 8 + 8) return Promise.reject(new Error('密文过短或已损坏'));
    var salt = raw.slice(0, 16);
    var iv = raw.slice(16, 24);
    var ct = raw.slice(24);
    return pbkdf2Bytes(passphrase, salt, 24).then(function (key) {
      var bytes = tripleDesDecryptRaw(key, iv, ct, mode);
      if (bytes.length < AES_MAGIC.length) throw new Error('bad magic');
      for (var i = 0; i < AES_MAGIC.length; i++) {
        if (bytes[i] !== AES_MAGIC[i]) throw new Error('bad magic');
      }
      return new TextDecoder().decode(bytes.slice(AES_MAGIC.length));
    }).catch(function () {
      throw new Error(WRONG_PASS_ERROR);
    });
  }

  // ---------- RIPEMD-160 (ISO/IEC 10118-3), hand-written ----------

  var RMD160_K_LEFT = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
  var RMD160_K_RIGHT = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];
  var RMD160_R_LEFT = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
  var RMD160_R_RIGHT = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
  var RMD160_S_LEFT = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
  var RMD160_S_RIGHT = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];

  function rmd160F(round, x, y, z) {
    if (round === 0) return x ^ y ^ z;
    if (round === 1) return (x & y) | (~x & z);
    if (round === 2) return (x | ~y) ^ z;
    if (round === 3) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }

  function ripemd160(text) {
    return ripemd160Bytes(new TextEncoder().encode(String(text == null ? '' : text)));
  }

  function ripemd160Bytes(msg) {
    var bitLenLow = (msg.length << 3) >>> 0;
    var bitLenHigh = Math.floor(msg.length / 0x20000000) >>> 0;
    var paddedLen = (((msg.length + 8) / 64) | 0) * 64 + 64;
    var buf = new Uint8Array(paddedLen);
    buf.set(msg, 0);
    buf[msg.length] = 0x80;
    var view = new DataView(buf.buffer);
    view.setUint32(paddedLen - 8, bitLenLow, true);
    view.setUint32(paddedLen - 4, bitLenHigh, true);

    var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE,
        h3 = 0x10325476, h4 = 0xC3D2E1F0;
    for (var off = 0; off < paddedLen; off += 64) {
      var M = [];
      for (var j = 0; j < 16; j++) M[j] = view.getUint32(off + j * 4, true);
      var A = h0, B = h1, C = h2, D = h3, E = h4;
      var Ap = h0, Bp = h1, Cp = h2, Dp = h3, Ep = h4;
      for (var k = 0; k < 80; k++) {
        var round = (k / 16) | 0;
        var t = (rotl((A + rmd160F(round, B, C, D) + M[RMD160_R_LEFT[k]] +
          RMD160_K_LEFT[round]) | 0, RMD160_S_LEFT[k]) + E) | 0;
        A = E; E = D; D = rotl(C, 10); C = B; B = t;
        // The right line runs the round functions in reverse order.
        var tp = (rotl((Ap + rmd160F(4 - round, Bp, Cp, Dp) + M[RMD160_R_RIGHT[k]] +
          RMD160_K_RIGHT[round]) | 0, RMD160_S_RIGHT[k]) + Ep) | 0;
        Ap = Ep; Ep = Dp; Dp = rotl(Cp, 10); Cp = Bp; Bp = tp;
      }
      var t2 = (h1 + C + Dp) | 0;
      h1 = (h2 + D + Ep) | 0;
      h2 = (h3 + E + Ap) | 0;
      h3 = (h4 + A + Bp) | 0;
      h4 = (h0 + B + Cp) | 0;
      h0 = t2;
    }
    function hex32le(x) {
      var h = '';
      for (var n = 0; n < 4; n++) h += ((x >>> (n * 8)) & 0xFF).toString(16).padStart(2, '0');
      return h;
    }
    return hex32le(h0) + hex32le(h1) + hex32le(h2) + hex32le(h3) + hex32le(h4);
  }

  // ---------- ChaCha20-Poly1305 (RFC 8439), hand-written AEAD ----------

  function chachaQuarterRound(s, a, b, c, d) {
    s[a] = (s[a] + s[b]) | 0; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) | 0; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) | 0; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) | 0; s[b] = rotl(s[b] ^ s[c], 7);
  }

  // One 64-byte ChaCha20 block for the given counter.
  function chacha20Block(key32, nonce12, counter) {
    var st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];
    for (var i = 0; i < 8; i++) st.push(u32le(key32, i * 4));
    st.push(counter >>> 0);
    for (var j = 0; j < 3; j++) st.push(u32le(nonce12, j * 4));
    var w = st.slice(0);
    for (var r = 0; r < 10; r++) {
      chachaQuarterRound(w, 0, 4, 8, 12);
      chachaQuarterRound(w, 1, 5, 9, 13);
      chachaQuarterRound(w, 2, 6, 10, 14);
      chachaQuarterRound(w, 3, 7, 11, 15);
      chachaQuarterRound(w, 0, 5, 10, 15);
      chachaQuarterRound(w, 1, 6, 11, 12);
      chachaQuarterRound(w, 2, 7, 8, 13);
      chachaQuarterRound(w, 3, 4, 9, 14);
    }
    var out = new Uint8Array(64);
    for (var k = 0; k < 16; k++) putU32le(out, k * 4, (w[k] + st[k]) | 0);
    return out;
  }

  function chacha20Crypt(key32, nonce12, counter, data) {
    var out = new Uint8Array(data.length);
    var off = 0;
    var ctr = counter;
    while (off < data.length) {
      var block = chacha20Block(key32, nonce12, ctr);
      var n = Math.min(64, data.length - off);
      for (var i = 0; i < n; i++) out[off + i] = data[off + i] ^ block[i];
      off += n;
      ctr = (ctr + 1) >>> 0;
    }
    return out;
  }

  // Poly1305 one-time authenticator (RFC 8439 §2.5), BigInt arithmetic.
  function poly1305(key32, msg) {
    function leBigInt(bytes, off, len) {
      var v = BigInt(0);
      for (var i = len - 1; i >= 0; i--) v = (v << BigInt(8)) | BigInt(bytes[off + i]);
      return v;
    }
    var r = leBigInt(key32, 0, 16) & BigInt('0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF');
    var s = leBigInt(key32, 16, 16);
    var p = (BigInt(1) << BigInt(130)) - BigInt(5); // 2^130 - 5
    var acc = BigInt(0);
    for (var off = 0; off < msg.length; off += 16) {
      var len = Math.min(16, msg.length - off);
      var n = leBigInt(msg, off, len) + (BigInt(1) << BigInt(8 * len));
      acc = ((acc + n) * r) % p;
    }
    var tag = (acc + s) % (BigInt(1) << BigInt(128));
    var out = new Uint8Array(16);
    for (var i = 0; i < 16; i++) {
      out[i] = Number(tag & BigInt(0xFF));
      tag = tag >> BigInt(8);
    }
    return out;
  }

  function chachaAeadTag(polyKey, aad, ct) {
    function pad16(bytes) {
      var rem = bytes.length % 16;
      if (!rem) return bytes;
      var out = new Uint8Array(bytes.length + (16 - rem));
      out.set(bytes, 0);
      return out;
    }
    function u64le(n) {
      var out = new Uint8Array(8);
      putU32le(out, 0, n >>> 0);
      putU32le(out, 4, Math.floor(n / 4294967296) >>> 0);
      return out;
    }
    var macData = concatBytes([pad16(aad), pad16(ct),
      u64le(aad.length), u64le(ct.length)]);
    return poly1305(polyKey, macData);
  }

  function chacha20Poly1305EncryptRaw(keyBytes32, nonceBytes12, dataBytes, aadBytes) {
    if (!keyBytes32 || keyBytes32.length !== 32) throw new Error('ChaCha20 密钥必须是 32 字节');
    if (!nonceBytes12 || nonceBytes12.length !== 12) throw new Error('ChaCha20 nonce 必须是 12 字节');
    var aad = aadBytes || new Uint8Array(0);
    var polyKey = chacha20Block(keyBytes32, nonceBytes12, 0).slice(0, 32);
    var ct = chacha20Crypt(keyBytes32, nonceBytes12, 1, dataBytes);
    var tag = chachaAeadTag(polyKey, aad, ct);
    return { ciphertext: ct, tag: tag };
  }

  function chacha20Poly1305DecryptRaw(keyBytes32, nonceBytes12, ctBytes, tagBytes, aadBytes) {
    if (!keyBytes32 || keyBytes32.length !== 32) throw new Error('ChaCha20 密钥必须是 32 字节');
    if (!nonceBytes12 || nonceBytes12.length !== 12) throw new Error('ChaCha20 nonce 必须是 12 字节');
    if (!tagBytes || tagBytes.length !== 16) throw new Error('ChaCha20-Poly1305 标签必须是 16 字节');
    var aad = aadBytes || new Uint8Array(0);
    var polyKey = chacha20Block(keyBytes32, nonceBytes12, 0).slice(0, 32);
    var expect = chachaAeadTag(polyKey, aad, ctBytes);
    var diff = 0;
    for (var i = 0; i < 16; i++) diff |= expect[i] ^ tagBytes[i];
    if (diff !== 0) throw new Error('ChaCha20-Poly1305：认证标签不匹配，密文可能已被篡改');
    return chacha20Crypt(keyBytes32, nonceBytes12, 1, ctBytes);
  }

  var CHACHA_PREFIX = 'CHACHA:v1:';

  // Passphrase ChaCha20-Poly1305, self-contained:
  // CHACHA:v1:<base64(salt[16] || nonce[12] || ciphertext || tag[16])>
  // PBKDF2-SHA256/100k derives the 32-byte key; no AAD. The Poly1305
  // tag itself detects a wrong passphrase.
  function chachaEncrypt(text, passphrase) {
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var salt = global.crypto.getRandomValues(new Uint8Array(16));
    var nonce = global.crypto.getRandomValues(new Uint8Array(12));
    var plainBytes = new TextEncoder().encode(String(text == null ? '' : text));
    return pbkdf2Bytes(passphrase, salt, 32).then(function (key) {
      var r = chacha20Poly1305EncryptRaw(key, nonce, plainBytes, null);
      return CHACHA_PREFIX + bytesToB64(concatBytes([salt, nonce, r.ciphertext, r.tag]));
    });
  }

  function chachaDecrypt(ciphertext, passphrase) {
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var s = String(ciphertext == null ? '' : ciphertext).trim();
    if (s.indexOf(CHACHA_PREFIX) !== 0) {
      return Promise.reject(new Error('不是本插件加密的格式（应以 CHACHA:v1: 开头）'));
    }
    var raw;
    try {
      raw = b64ToBytes(s.slice(CHACHA_PREFIX.length));
    } catch (e) {
      return Promise.reject(new Error('密文不是合法的 Base64'));
    }
    if (raw.length < 16 + 12 + 16) return Promise.reject(new Error('密文过短或已损坏'));
    var salt = raw.slice(0, 16);
    var nonce = raw.slice(16, 28);
    var ct = raw.slice(28, raw.length - 16);
    var tag = raw.slice(raw.length - 16);
    return pbkdf2Bytes(passphrase, salt, 32).then(function (key) {
      var bytes = chacha20Poly1305DecryptRaw(key, nonce, ct, tag, null);
      return new TextDecoder().decode(bytes);
    }).catch(function () {
      throw new Error(WRONG_PASS_ERROR);
    });
  }

  // ---------- SM3 (GB/T 32905-2016), hand-written ----------

  var SM3_IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
                0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E];
  // The round constant T_j is rotated left by j inside the compression
  // function; precompute the rotated values (rotation amount mod 32).
  var SM3_T = (function () {
    var t = [];
    for (var j = 0; j < 64; j++) {
      t.push(rotl(j < 16 ? 0x79CC4519 : 0x7A879D8A, j % 32));
    }
    return t;
  })();

  function sm3P0(x) { return x ^ rotl(x, 9) ^ rotl(x, 17); }
  function sm3P1(x) { return x ^ rotl(x, 15) ^ rotl(x, 23); }

  function sm3(text) {
    return sm3Bytes(new TextEncoder().encode(String(text == null ? '' : text)));
  }

  function sm3Bytes(msg) {
    var bitLenLow = (msg.length << 3) >>> 0;
    var bitLenHigh = Math.floor(msg.length / 0x20000000) >>> 0;
    var paddedLen = (((msg.length + 8) / 64) | 0) * 64 + 64;
    var buf = new Uint8Array(paddedLen);
    buf.set(msg, 0);
    buf[msg.length] = 0x80;
    var view = new DataView(buf.buffer);
    view.setUint32(paddedLen - 8, bitLenHigh, false);
    view.setUint32(paddedLen - 4, bitLenLow, false);

    var v = SM3_IV.slice(0);
    for (var off = 0; off < paddedLen; off += 64) {
      var W = [];
      for (var j = 0; j < 16; j++) W[j] = view.getUint32(off + j * 4, false);
      for (j = 16; j < 68; j++) {
        W[j] = (sm3P1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15)) ^
          rotl(W[j - 13], 7) ^ W[j - 6]) | 0;
      }
      var A = v[0], B = v[1], C = v[2], D = v[3],
          E = v[4], F = v[5], G = v[6], H = v[7];
      for (j = 0; j < 64; j++) {
        var ff = j < 16 ? (A ^ B ^ C) : ((A & B) | (A & C) | (B & C));
        // Note: GG_j operates on (E, F, G), not (A, B, C).
        var gg = j < 16 ? (E ^ F ^ G) : ((E & F) | (~E & G));
        var ss1 = rotl(((rotl(A, 12) + E + SM3_T[j]) | 0), 7);
        var ss2 = ss1 ^ rotl(A, 12);
        var tt1 = (ff + D + ss2 + (W[j] ^ W[j + 4])) | 0;
        var tt2 = (gg + H + ss1 + W[j]) | 0;
        D = C;
        C = rotl(B, 9);
        B = A;
        A = tt1;
        H = G;
        G = rotl(F, 19);
        F = E;
        E = sm3P0(tt2);
      }
      v[0] ^= A; v[1] ^= B; v[2] ^= C; v[3] ^= D;
      v[4] ^= E; v[5] ^= F; v[6] ^= G; v[7] ^= H;
    }
    var out = new Uint8Array(32);
    var outView = new DataView(out.buffer);
    for (var k = 0; k < 8; k++) outView.setUint32(k * 4, v[k], false);
    return bytesToHex(out);
  }

  // ---------- SM4 (GB/T 32907-2016), hand-written ----------

  var SM4_SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
    0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A,
    0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
    0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B,
    0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2,
    0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
    0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
    0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F,
    0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F,
    0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E,
    0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20,
    0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
  ];
  var SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];
  var SM4_CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
  ];

  function sm4Tau(a) {
    return ((SM4_SBOX[(a >>> 24) & 0xFF] << 24) |
            (SM4_SBOX[(a >>> 16) & 0xFF] << 16) |
            (SM4_SBOX[(a >>> 8) & 0xFF] << 8) |
            SM4_SBOX[a & 0xFF]) >>> 0;
  }

  function sm4L(b) {
    return (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) >>> 0;
  }

  function sm4Lp(b) {
    return (b ^ rotl(b, 13) ^ rotl(b, 23)) >>> 0;
  }

  function sm4ExpandKey(key16) {
    var k = [];
    for (var i = 0; i < 4; i++) k.push((u32be(key16, i * 4) ^ SM4_FK[i]) >>> 0);
    var rk = [];
    for (i = 0; i < 32; i++) {
      var t = sm4Lp(sm4Tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]));
      k.push((k[i] ^ t) >>> 0);
      rk.push(k[i + 4]);
    }
    return rk;
  }

  function sm4CryptBlock(block16, rk, decrypt) {
    var x = [];
    for (var i = 0; i < 4; i++) x.push(u32be(block16, i * 4));
    for (i = 0; i < 32; i++) {
      var k = decrypt ? rk[31 - i] : rk[i];
      x.push((x[i] ^ sm4L(sm4Tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ k))) >>> 0);
    }
    var out = new Uint8Array(16);
    for (var j = 0; j < 4; j++) putU32be(out, j * 4, x[35 - j]);
    return out;
  }

  // Generic ECB/CBC driver over 16-byte blocks (mirrors desModeCrypt).
  function sm4ModeCrypt(data, mode, iv, blockFn, decrypt) {
    if (mode !== 'ECB' && mode !== 'CBC') throw new Error('不支持的加密模式：' + mode);
    if (mode === 'CBC' && (!iv || iv.length !== 16)) {
      throw new Error('CBC 模式需要 16 字节 IV');
    }
    var out = new Uint8Array(data.length);
    var prev = iv;
    for (var off = 0; off < data.length; off += 16) {
      var block = data.slice(off, off + 16);
      if (mode === 'CBC' && !decrypt) {
        for (var i = 0; i < 16; i++) block[i] ^= prev[i];
      }
      var done = blockFn(block, decrypt);
      if (mode === 'CBC' && decrypt) {
        for (var j = 0; j < 16; j++) done[j] ^= prev[j];
        prev = data.slice(off, off + 16);
      } else if (mode === 'CBC') {
        prev = done;
      }
      out.set(done, off);
    }
    return out;
  }

  function sm4EncryptRaw(keyBytes16, ivBytes16, dataBytes, mode) {
    if (!keyBytes16 || keyBytes16.length !== 16) throw new Error('SM4 密钥必须是 16 字节');
    mode = mode || 'CBC';
    var rk = sm4ExpandKey(keyBytes16);
    return sm4ModeCrypt(pkcs7Pad(dataBytes, 16), mode, ivBytes16,
      function (block, decrypt) { return sm4CryptBlock(block, rk, decrypt); }, false);
  }

  function sm4DecryptRaw(keyBytes16, ivBytes16, dataBytes, mode) {
    if (!keyBytes16 || keyBytes16.length !== 16) throw new Error('SM4 密钥必须是 16 字节');
    mode = mode || 'CBC';
    var rk = sm4ExpandKey(keyBytes16);
    return pkcs7Unpad(sm4ModeCrypt(dataBytes, mode, ivBytes16,
      function (block, decrypt) { return sm4CryptBlock(block, rk, decrypt); }, true), 16);
  }

  var SM4_PREFIXES = { ECB: 'SM4-ECB:v1:', CBC: 'SM4-CBC:v1:' };

  // Passphrase SM4, self-contained:
  //   SM4-CBC:v1:<base64(salt[16] || iv[16] || ciphertext)>
  //   SM4-ECB:v1:<base64(salt[16] || ciphertext)>
  // PBKDF2-SHA256/100k derives the 16-byte key; the SDv3: magic prefix
  // detects a wrong passphrase.
  function sm4Encrypt(text, passphrase, mode) {
    mode = mode || 'CBC';
    if (!SM4_PREFIXES[mode]) return Promise.reject(new Error('不支持的加密模式：' + mode));
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var salt = global.crypto.getRandomValues(new Uint8Array(16));
    var iv = mode === 'CBC' ? global.crypto.getRandomValues(new Uint8Array(16)) : null;
    var plainBytes = concatBytes([AES_MAGIC,
      new TextEncoder().encode(String(text == null ? '' : text))]);
    return pbkdf2Bytes(passphrase, salt, 16).then(function (key) {
      var ct = sm4EncryptRaw(key, iv, plainBytes, mode);
      var payload = mode === 'CBC'
        ? concatBytes([salt, iv, ct]) : concatBytes([salt, ct]);
      return SM4_PREFIXES[mode] + bytesToB64(payload);
    });
  }

  function sm4Decrypt(ciphertext, passphrase) {
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var s = String(ciphertext == null ? '' : ciphertext).trim();
    var mode = null;
    for (var m in SM4_PREFIXES) {
      if (s.indexOf(SM4_PREFIXES[m]) === 0) { mode = m; break; }
    }
    if (!mode) {
      return Promise.reject(new Error('不是本插件加密的格式（应以 SM4-ECB:v1: 或 SM4-CBC:v1: 开头）'));
    }
    var raw;
    try {
      raw = b64ToBytes(s.slice(SM4_PREFIXES[mode].length));
    } catch (e) {
      return Promise.reject(new Error('密文不是合法的 Base64'));
    }
    var salt, iv, ct;
    if (mode === 'CBC') {
      if (raw.length < 16 + 16 + 16) return Promise.reject(new Error('密文过短或已损坏'));
      salt = raw.slice(0, 16);
      iv = raw.slice(16, 32);
      ct = raw.slice(32);
    } else {
      if (raw.length < 16 + 16) return Promise.reject(new Error('密文过短或已损坏'));
      salt = raw.slice(0, 16);
      iv = null;
      ct = raw.slice(16);
    }
    return pbkdf2Bytes(passphrase, salt, 16).then(function (key) {
      var bytes = sm4DecryptRaw(key, iv, ct, mode);
      if (bytes.length < AES_MAGIC.length) throw new Error('bad magic');
      for (var i = 0; i < AES_MAGIC.length; i++) {
        if (bytes[i] !== AES_MAGIC[i]) throw new Error('bad magic');
      }
      return new TextDecoder().decode(bytes.slice(AES_MAGIC.length));
    }).catch(function () {
      throw new Error(WRONG_PASS_ERROR);
    });
  }

  // ---------- SM2 (GB/T 32918), hand-written with BigInt ----------
  // Curve sm2p256v1 (GM/T 0003.5 / GB/T 32918.5).

  var SM2_P = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF');
  var SM2_A = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC');
  var SM2_B = BigInt('0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93');
  var SM2_N = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123');
  var SM2_GX = BigInt('0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7');
  var SM2_GY = BigInt('0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0');
  var SM2_G = { x: SM2_GX, y: SM2_GY };
  var SM2_DEFAULT_ID = '1234567812345678';

  function sm2Mod(a, m) {
    var r = a % m;
    return r >= BigInt(0) ? r : r + m;
  }

  function sm2ModInv(a, m) {
    var oldR = sm2Mod(a, m), r = m;
    var oldS = BigInt(1), s = BigInt(0);
    while (r !== BigInt(0)) {
      var q = oldR / r;
      var tmpR = oldR - q * r;
      oldR = r;
      r = tmpR;
      var tmpS = oldS - q * s;
      oldS = s;
      s = tmpS;
    }
    if (oldR !== BigInt(1)) throw new Error('SM2：不存在模逆元');
    return sm2Mod(oldS, m);
  }

  function sm2PointDouble(P) {
    if (P === null) return null;
    var lam = sm2Mod((BigInt(3) * P.x * P.x + SM2_A) *
      sm2ModInv(BigInt(2) * P.y, SM2_P), SM2_P);
    var x3 = sm2Mod(lam * lam - BigInt(2) * P.x, SM2_P);
    var y3 = sm2Mod(lam * (P.x - x3) - P.y, SM2_P);
    return { x: x3, y: y3 };
  }

  function sm2PointAdd(P, Q) {
    if (P === null) return Q;
    if (Q === null) return P;
    if (P.x === Q.x) {
      if (sm2Mod(P.y + Q.y, SM2_P) === BigInt(0)) return null;
      return sm2PointDouble(P);
    }
    var lam = sm2Mod((Q.y - P.y) * sm2ModInv(Q.x - P.x, SM2_P), SM2_P);
    var x3 = sm2Mod(lam * lam - P.x - Q.x, SM2_P);
    var y3 = sm2Mod(lam * (P.x - x3) - P.y, SM2_P);
    return { x: x3, y: y3 };
  }

  function sm2ScalarMult(k, P) {
    var R = null;
    var Q = P;
    while (k > BigInt(0)) {
      if ((k & BigInt(1)) === BigInt(1)) R = sm2PointAdd(R, Q);
      Q = sm2PointDouble(Q);
      k = k >> BigInt(1);
    }
    return R;
  }

  function sm2BytesToBigInt(bytes) {
    var v = BigInt(0);
    for (var i = 0; i < bytes.length; i++) v = (v << BigInt(8)) | BigInt(bytes[i]);
    return v;
  }

  function sm2BigIntToBytes(n, len) {
    var out = new Uint8Array(len);
    for (var i = len - 1; i >= 0; i--) {
      out[i] = Number(n & BigInt(0xFF));
      n = n >> BigInt(8);
    }
    return out;
  }

  function sm2PointToBytes(P) {
    return concatBytes([new Uint8Array([0x04]),
      sm2BigIntToBytes(P.x, 32), sm2BigIntToBytes(P.y, 32)]);
  }

  function sm2ParsePoint(hex) {
    var s = String(hex == null ? '' : hex).trim().replace(/\s+/g, '');
    if (!/^04[0-9a-fA-F]{128}$/.test(s)) {
      throw new Error('SM2 公钥应为 130 个十六进制字符（04 开头的未压缩点）');
    }
    var bytes = hexToBytes(s);
    var x = sm2BytesToBigInt(bytes.slice(1, 33));
    var y = sm2BytesToBigInt(bytes.slice(33, 65));
    // Verify the point lies on the curve.
    if (sm2Mod(y * y - (x * x * x + SM2_A * x + SM2_B), SM2_P) !== BigInt(0)) {
      throw new Error('SM2 公钥不在曲线上');
    }
    return { x: x, y: y };
  }

  function sm2ParsePrivateKey(hex) {
    var s = String(hex == null ? '' : hex).trim().replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]{64}$/.test(s)) {
      throw new Error('SM2 私钥应为 64 个十六进制字符');
    }
    var d = sm2BytesToBigInt(hexToBytes(s));
    if (d <= BigInt(0) || d >= SM2_N) throw new Error('SM2 私钥超出有效范围');
    return d;
  }

  // Random scalar in [1, n-1].
  function sm2RandomScalar() {
    var bytes = new Uint8Array(32);
    var d;
    do {
      global.crypto.getRandomValues(bytes);
      d = sm2BytesToBigInt(bytes);
    } while (d <= BigInt(0) || d >= SM2_N);
    return d;
  }

  function sm2GenerateKeyPair() {
    var d = sm2RandomScalar();
    return {
      privateKeyHex: bytesToHex(sm2BigIntToBytes(d, 32)),
      publicKeyHex: bytesToHex(sm2PointToBytes(sm2ScalarMult(d, SM2_G)))
    };
  }

  // SM2 key derivation function (GB/T 32918.1 §5.4.3): SM3(Z || ct),
  // ct = 1, 2, ... as 4-byte big-endian counters.
  function sm2Kdf(zBytes, klen) {
    var out = new Uint8Array(klen);
    var ct = 1;
    var off = 0;
    while (off < klen) {
      var input = new Uint8Array(zBytes.length + 4);
      input.set(zBytes, 0);
      input[zBytes.length] = (ct >>> 24) & 0xFF;
      input[zBytes.length + 1] = (ct >>> 16) & 0xFF;
      input[zBytes.length + 2] = (ct >>> 8) & 0xFF;
      input[zBytes.length + 3] = ct & 0xFF;
      var hash = hexToBytes(sm3Bytes(input));
      var n = Math.min(32, klen - off);
      out.set(hash.subarray(0, n), off);
      off += n;
      ct++;
    }
    return out;
  }

  // SM2 public-key encryption (GB/T 32918.4), C1 || C3 || C2 layout:
  // C1 = 65-byte uncompressed point, C3 = 32-byte SM3 hash, C2 = ciphertext.
  function sm2Encrypt(publicKeyHex, text) {
    var P = sm2ParsePoint(publicKeyHex);
    var msg = new TextEncoder().encode(String(text == null ? '' : text));
    var k = sm2RandomScalar();
    var c1 = sm2ScalarMult(k, SM2_G);
    var s = sm2ScalarMult(k, P);
    if (s === null) throw new Error('SM2 加密失败：共享点为无穷远点');
    var x2 = sm2BigIntToBytes(s.x, 32);
    var y2 = sm2BigIntToBytes(s.y, 32);
    var t = sm2Kdf(concatBytes([x2, y2]), msg.length);
    var c2 = new Uint8Array(msg.length);
    for (var i = 0; i < msg.length; i++) c2[i] = msg[i] ^ t[i];
    var c3 = hexToBytes(sm3Bytes(concatBytes([x2, msg, y2])));
    return bytesToHex(concatBytes([sm2PointToBytes(c1), c3, c2]));
  }

  function sm2Decrypt(privateKeyHex, hexCiphertext) {
    var d = sm2ParsePrivateKey(privateKeyHex);
    var s = String(hexCiphertext == null ? '' : hexCiphertext).trim().replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]*$/.test(s) || s.length % 2 !== 0 || s.length < 2 * (65 + 32)) {
      throw new Error('SM2 密文格式不正确');
    }
    var bytes = hexToBytes(s);
    var c1 = sm2ParsePoint(bytesToHex(bytes.slice(0, 65)));
    var c3 = bytes.slice(65, 97);
    var c2 = bytes.slice(97);
    var pt = sm2ScalarMult(d, c1);
    if (pt === null) throw new Error('SM2 解密失败：共享点为无穷远点');
    var x2 = sm2BigIntToBytes(pt.x, 32);
    var y2 = sm2BigIntToBytes(pt.y, 32);
    var t = sm2Kdf(concatBytes([x2, y2]), c2.length);
    var msg = new Uint8Array(c2.length);
    for (var i = 0; i < c2.length; i++) msg[i] = c2[i] ^ t[i];
    var u = hexToBytes(sm3Bytes(concatBytes([x2, msg, y2])));
    var diff = 0;
    for (var j = 0; j < 32; j++) diff |= u[j] ^ c3[j];
    if (diff !== 0) throw new Error('SM2 解密失败：密文校验失败（私钥错误或密文已损坏）');
    return new TextDecoder().decode(msg);
  }

  // ZA = SM3(ENTL || ID || a || b || Gx || Gy || xA || yA) (GB/T 32918.2).
  function sm2ZA(publicKeyHex, userId) {
    var P = sm2ParsePoint(publicKeyHex);
    var id = new TextEncoder().encode(String(userId == null ? SM2_DEFAULT_ID : userId));
    var entl = new Uint8Array(2);
    entl[0] = ((id.length * 8) >>> 8) & 0xFF;
    entl[1] = (id.length * 8) & 0xFF;
    return hexToBytes(sm3Bytes(concatBytes([
      entl, id,
      sm2BigIntToBytes(SM2_A, 32), sm2BigIntToBytes(SM2_B, 32),
      sm2BigIntToBytes(SM2_GX, 32), sm2BigIntToBytes(SM2_GY, 32),
      sm2BigIntToBytes(P.x, 32), sm2BigIntToBytes(P.y, 32)
    ])));
  }

  // SM2 signature (GB/T 32918.2 §6.1); returns r || s as 128 hex chars.
  function sm2Sign(privateKeyHex, text, userId) {
    var d = sm2ParsePrivateKey(privateKeyHex);
    var pubHex = bytesToHex(sm2PointToBytes(sm2ScalarMult(d, SM2_G)));
    var za = sm2ZA(pubHex, userId);
    var msg = new TextEncoder().encode(String(text == null ? '' : text));
    var e = sm2BytesToBigInt(hexToBytes(sm3Bytes(concatBytes([za, msg]))));
    var inv = sm2ModInv(BigInt(1) + d, SM2_N);
    var r, s;
    do {
      var k = sm2RandomScalar();
      var p1 = sm2ScalarMult(k, SM2_G);
      r = sm2Mod(e + p1.x, SM2_N);
      if (r === BigInt(0) || sm2Mod(r + k, SM2_N) === BigInt(0)) {
        s = BigInt(0);
        continue;
      }
      s = sm2Mod(inv * sm2Mod(k - r * d, SM2_N), SM2_N);
    } while (s === BigInt(0));
    return bytesToHex(concatBytes([sm2BigIntToBytes(r, 32), sm2BigIntToBytes(s, 32)]));
  }

  // SM2 verification (GB/T 32918.2 §7.1); returns true/false and never
  // throws on a merely-invalid signature or key.
  function sm2Verify(publicKeyHex, text, signatureHex, userId) {
    var P, r, s;
    try {
      P = sm2ParsePoint(publicKeyHex);
    } catch (e) {
      return false;
    }
    var sig = String(signatureHex == null ? '' : signatureHex).trim().replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]{128}$/.test(sig)) return false;
    var sigBytes = hexToBytes(sig);
    r = sm2BytesToBigInt(sigBytes.slice(0, 32));
    s = sm2BytesToBigInt(sigBytes.slice(32, 64));
    if (r <= BigInt(0) || r >= SM2_N || s <= BigInt(0) || s >= SM2_N) return false;
    var za = sm2ZA(publicKeyHex, userId);
    var msg = new TextEncoder().encode(String(text == null ? '' : text));
    var e = sm2BytesToBigInt(hexToBytes(sm3Bytes(concatBytes([za, msg]))));
    var t = sm2Mod(r + s, SM2_N);
    if (t === BigInt(0)) return false;
    var point = sm2PointAdd(sm2ScalarMult(s, SM2_G), sm2ScalarMult(t, P));
    if (point === null) return false;
    return sm2Mod(e + point.x, SM2_N) === r;
  }

  // ---------- RSA / ECDSA (WebCrypto) ----------

  function pemEncode(label, derBytes) {
    var b64 = bytesToB64(derBytes);
    var lines = [];
    for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
    return '-----BEGIN ' + label + '-----\n' + lines.join('\n') +
      '\n-----END ' + label + '-----';
  }

  function pemDecode(pem, label) {
    var s = String(pem == null ? '' : pem).trim();
    var begin = '-----BEGIN ' + label + '-----';
    var end = '-----END ' + label + '-----';
    if (s.indexOf(begin) < 0 || s.indexOf(end) < 0) {
      throw new Error('不是有效的 ' + label + ' PEM 格式');
    }
    var body = s.slice(s.indexOf(begin) + begin.length, s.indexOf(end))
      .replace(/\s+/g, '');
    try {
      return b64ToBytes(body);
    } catch (e) {
      throw new Error('PEM 内容不是合法的 Base64');
    }
  }

  function rsaGenerateKeyPair() {
    return global.crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']
    ).then(function (pair) {
      return Promise.all([
        global.crypto.subtle.exportKey('spki', pair.publicKey),
        global.crypto.subtle.exportKey('pkcs8', pair.privateKey)
      ]);
    }).then(function (der) {
      return {
        publicKeyPem: pemEncode('PUBLIC KEY', new Uint8Array(der[0])),
        privateKeyPem: pemEncode('PRIVATE KEY', new Uint8Array(der[1]))
      };
    });
  }

  function rsaEncrypt(publicKeyPem, text) {
    var der;
    try {
      der = pemDecode(publicKeyPem, 'PUBLIC KEY');
    } catch (e) {
      return Promise.reject(e);
    }
    return global.crypto.subtle.importKey(
      'spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']
    ).then(function (key) {
      return global.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' }, key,
        new TextEncoder().encode(String(text == null ? '' : text)));
    }).then(function (ct) { return bytesToB64(new Uint8Array(ct)); });
  }

  function rsaDecrypt(privateKeyPem, base64) {
    var der, ct;
    try {
      der = pemDecode(privateKeyPem, 'PRIVATE KEY');
      ct = b64ToBytes(String(base64 == null ? '' : base64).trim());
    } catch (e) {
      return Promise.reject(e);
    }
    return global.crypto.subtle.importKey(
      'pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']
    ).then(function (key) {
      return global.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, ct);
    }).then(function (pt) { return new TextDecoder().decode(new Uint8Array(pt)); });
  }

  function ecdsaGenerateKeyPair() {
    return global.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['sign', 'verify']
    ).then(function (pair) {
      return Promise.all([
        global.crypto.subtle.exportKey('spki', pair.publicKey),
        global.crypto.subtle.exportKey('pkcs8', pair.privateKey)
      ]);
    }).then(function (der) {
      return {
        publicKeyPem: pemEncode('PUBLIC KEY', new Uint8Array(der[0])),
        privateKeyPem: pemEncode('PRIVATE KEY', new Uint8Array(der[1]))
      };
    });
  }

  // WebCrypto ECDSA signatures are ASN.1 DER encoded; the hex string is
  // the DER bytes as-is, passed straight back to ecdsaVerify.
  function ecdsaSign(privateKeyPem, text) {
    var der;
    try {
      der = pemDecode(privateKeyPem, 'PRIVATE KEY');
    } catch (e) {
      return Promise.reject(e);
    }
    return global.crypto.subtle.importKey(
      'pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
    ).then(function (key) {
      return global.crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' }, key,
        new TextEncoder().encode(String(text == null ? '' : text)));
    }).then(function (sig) { return bytesToHex(new Uint8Array(sig)); });
  }

  function ecdsaVerify(publicKeyPem, text, sigHex) {
    var der, sig;
    try {
      der = pemDecode(publicKeyPem, 'PUBLIC KEY');
      var s = String(sigHex == null ? '' : sigHex).trim().replace(/\s+/g, '');
      if (!/^[0-9a-fA-F]*$/.test(s) || s.length % 2 !== 0) {
        throw new Error('签名不是合法的十六进制');
      }
      sig = hexToBytes(s);
    } catch (e) {
      return Promise.reject(e);
    }
    return global.crypto.subtle.importKey(
      'spki', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    ).then(function (key) {
      return global.crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' }, key, sig,
        new TextEncoder().encode(String(text == null ? '' : text)));
    }).catch(function () { return false; });
  }

  // ---------- File hashing: all hashes over raw bytes ----------

  function hashAllBytes(bytes) {
    return Promise.all([
      shaBytes('SHA-1', bytes), shaBytes('SHA-256', bytes),
      shaBytes('SHA-384', bytes), shaBytes('SHA-512', bytes)
    ]).then(function (r) {
      return {
        'MD5': md5Bytes(bytes),
        'SHA-1': r[0],
        'SHA-256': r[1],
        'SHA-384': r[2],
        'SHA-512': r[3],
        'SHA3-256': sha3Bytes(bytes),
        'CRC32': crc32Bytes(bytes),
        'RIPEMD-160': ripemd160Bytes(bytes),
        'SM3': sm3Bytes(bytes)
      };
    });
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
    timestampToDate: timestampToDate, dateToTimestamp: dateToTimestamp,
    // v4.0.0: DES / Triple-DES
    desEncryptRaw: desEncryptRaw, desDecryptRaw: desDecryptRaw,
    tripleDesEncryptRaw: tripleDesEncryptRaw, tripleDesDecryptRaw: tripleDesDecryptRaw,
    tripleDesEncrypt: tripleDesEncrypt, tripleDesDecrypt: tripleDesDecrypt,
    TDES_PREFIXES: TDES_PREFIXES,
    // v4.0.0: RIPEMD-160
    ripemd160: ripemd160, ripemd160Bytes: ripemd160Bytes,
    // v4.0.0: ChaCha20-Poly1305
    chacha20Poly1305EncryptRaw: chacha20Poly1305EncryptRaw,
    chacha20Poly1305DecryptRaw: chacha20Poly1305DecryptRaw,
    chachaEncrypt: chachaEncrypt, chachaDecrypt: chachaDecrypt,
    CHACHA_PREFIX: CHACHA_PREFIX,
    // v4.0.0: SM3 / SM4 / SM2
    sm3: sm3, sm3Bytes: sm3Bytes,
    sm4EncryptRaw: sm4EncryptRaw, sm4DecryptRaw: sm4DecryptRaw,
    sm4Encrypt: sm4Encrypt, sm4Decrypt: sm4Decrypt,
    SM4_PREFIXES: SM4_PREFIXES,
    sm2GenerateKeyPair: sm2GenerateKeyPair,
    sm2Encrypt: sm2Encrypt, sm2Decrypt: sm2Decrypt,
    sm2Sign: sm2Sign, sm2Verify: sm2Verify,
    // v4.0.0: RSA / ECDSA
    rsaGenerateKeyPair: rsaGenerateKeyPair,
    rsaEncrypt: rsaEncrypt, rsaDecrypt: rsaDecrypt,
    ecdsaGenerateKeyPair: ecdsaGenerateKeyPair,
    ecdsaSign: ecdsaSign, ecdsaVerify: ecdsaVerify,
    // v4.0.0: byte-based hashes for file hashing
    md5Bytes: md5Bytes, shaBytes: shaBytes, sha3Bytes: sha3Bytes,
    crc32Bytes: crc32Bytes, hashAllBytes: hashAllBytes
  };
  global.B64Crypto = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
