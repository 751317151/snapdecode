// B64Crypto — hash & encryption helpers (no chrome APIs) used by the popup.
// MD5 is implemented locally (WebCrypto does not offer it); SHA and AES-GCM
// use the platform WebCrypto API. Safe to load in a browser or in Node.
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
      sha('SHA-1', text), sha('SHA-256', text), sha('SHA-512', text)
    ]).then(function (r) {
      return { 'SHA-1': r[0], 'SHA-256': r[1], 'SHA-512': r[2] };
    });
  }

  // ---------- AES-GCM with passphrase (PBKDF2) ----------

  var AES_PREFIX = 'AES-GCM:v1:';

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

  function deriveKey(passphrase, salt) {
    return global.crypto.subtle.importKey(
      'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
    ).then(function (baseKey) {
      return global.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
      );
    });
  }

  // Returns a self-contained string: AES-GCM:v1:<base64(salt[16] || iv[12] || ciphertext)>
  function aesEncrypt(plaintext, passphrase) {
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var salt = global.crypto.getRandomValues(new Uint8Array(16));
    var iv = global.crypto.getRandomValues(new Uint8Array(12));
    return deriveKey(passphrase, salt).then(function (key) {
      return global.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(String(plaintext))
      );
    }).then(function (ct) {
      var out = new Uint8Array(16 + 12 + ct.byteLength);
      out.set(salt, 0);
      out.set(iv, 16);
      out.set(new Uint8Array(ct), 28);
      return AES_PREFIX + bytesToB64(out);
    });
  }

  function aesDecrypt(ciphertext, passphrase) {
    if (!passphrase) return Promise.reject(new Error('请填写口令'));
    var s = String(ciphertext == null ? '' : ciphertext).trim();
    if (s.indexOf(AES_PREFIX) !== 0) {
      return Promise.reject(new Error('不是本插件加密的格式（应以 AES-GCM:v1: 开头）'));
    }
    var raw;
    try {
      raw = b64ToBytes(s.slice(AES_PREFIX.length));
    } catch (e) {
      return Promise.reject(new Error('密文不是合法的 Base64'));
    }
    if (raw.length < 29) return Promise.reject(new Error('密文过短或已损坏'));
    var salt = raw.slice(0, 16);
    var iv = raw.slice(16, 28);
    var ct = raw.slice(28);
    return deriveKey(passphrase, salt).then(function (key) {
      return global.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
    }).then(function (pt) {
      return new TextDecoder().decode(pt);
    }).catch(function () {
      throw new Error('解密失败：口令错误或密文已损坏');
    });
  }

  var api = {
    md5: md5, sha: sha, shaAll: shaAll,
    aesEncrypt: aesEncrypt, aesDecrypt: aesDecrypt, AES_PREFIX: AES_PREFIX
  };
  global.B64Crypto = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
