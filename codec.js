// B64Codec — shared codec logic (no chrome APIs) used by the content script
// and the popup. Covers Base64/32/58/62/85/91, Hex, binary, octal, URL
// encoding, Unicode escapes, HTML entities, Morse, ROT13/Caesar, JWT,
// format detection, candidate extraction, image/gzip detection and
// multi-encoding text fallback (UTF-8 -> GBK -> GB18030).
// Safe to load in a browser page context or in Node (for tests).
(function (global) {
  'use strict';

  var FORMAT_LABELS = {
    base64: 'Base64', base32: 'Base32', base58: 'Base58', base62: 'Base62',
    base85: 'Base85', base91: 'Base91', hex: 'Hex', binary: '二进制', octal: '八进制',
    url: 'URL 编码', unicode: 'Unicode 转义', html: 'HTML 实体', morse: '摩斯电码',
    rot13: 'ROT13', caesar: '凯撒密码', jwt: 'JWT'
  };

  // ---------- byte helpers ----------

  function bytesToBinaryString(bytes) {
    var out = '';
    var CHUNK = 0x8000;
    for (var i = 0; i < bytes.length; i += CHUNK) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return out;
  }

  function binaryStringToBytes(s) {
    var bytes = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.prototype.map.call(bytes, function (b) {
      return b.toString(16).padStart(2, '0');
    }).join(' ');
  }

  // Decode bytes to text, trying UTF-8 first, then GBK / GB18030.
  // Returns { text, encoding } or { text: null, encoding: null }.
  function bytesToText(bytes) {
    try {
      return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), encoding: 'UTF-8' };
    } catch (e) { /* fall through */ }
    var encodings = ['gbk', 'gb18030'];
    for (var i = 0; i < encodings.length; i++) {
      try {
        var text = new TextDecoder(encodings[i]).decode(bytes);
        if (text.indexOf('\uFFFD') !== -1) continue;
        if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) continue;
        if (!/[\u4E00-\u9FFF]/.test(text)) continue; // must look like Chinese text
        return { text: text, encoding: encodings[i].toUpperCase() };
      } catch (e) { /* unsupported encoding, try next */ }
    }
    return { text: null, encoding: null };
  }

  function bytesResult(bytes, format, cleaned) {
    var t = bytesToText(bytes);
    if (t.text !== null) {
      return { ok: true, kind: 'text', text: t.text, encoding: t.encoding,
               byteLength: bytes.length, bytes: bytes, format: format, cleaned: cleaned };
    }
    return { ok: true, kind: 'binary', text: null, hex: bytesToHex(bytes),
             byteLength: bytes.length, bytes: bytes, format: format, cleaned: cleaned };
  }

  function fail(error, format) {
    return { ok: false, kind: 'error', error: error, format: format || null };
  }

  // ---------- Base64 ----------

  function cleanBase64(input) {
    var s = String(input == null ? '' : input).trim();
    var m = s.match(/^data:[^,]*;base64,/i);
    if (m) s = s.slice(m[0].length);
    if (s.length >= 2) {
      var first = s[0], last = s[s.length - 1];
      if ((first === '"' && last === '"') ||
          (first === "'" && last === "'") ||
          (first === '`' && last === '`')) {
        s = s.slice(1, -1);
      }
    }
    return s.replace(/\s+/g, '');
  }

  function encodeBase64(text, opts) {
    var bytes = new TextEncoder().encode(String(text == null ? '' : text));
    var out = btoa(bytesToBinaryString(bytes));
    if (opts && opts.urlSafe) out = out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return out;
  }

  function decodeBase64(input) {
    var cleaned = cleanBase64(input);
    if (!cleaned) return fail('没有可解码的内容', 'base64');
    if (!/^[A-Za-z0-9+/=_-]+$/.test(cleaned)) {
      return fail('包含非 Base64 字符，请检查选中内容', 'base64');
    }
    var std = cleaned.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    var rem = std.length % 4;
    if (rem === 1) return fail('长度无效，不是合法的 Base64', 'base64');
    if (rem) std += '===='.slice(0, 4 - rem);
    var binary;
    try {
      binary = atob(std);
    } catch (e) {
      return fail('解码失败，不是合法的 Base64', 'base64');
    }
    return bytesResult(binaryStringToBytes(binary), 'base64', cleaned);
  }

  // ---------- Hex ----------

  function encodeHex(text) {
    var bytes = new TextEncoder().encode(String(text == null ? '' : text));
    return Array.prototype.map.call(bytes, function (b) {
      return b.toString(16).padStart(2, '0');
    }).join('');
  }

  function decodeHex(input) {
    var s = String(input == null ? '' : input).trim().replace(/^0x/i, '').replace(/\s+/g, '');
    if (!s) return fail('没有可解码的内容', 'hex');
    if (!/^[0-9a-fA-F]+$/.test(s)) return fail('包含非十六进制字符', 'hex');
    if (s.length % 2 !== 0) return fail('十六进制长度应为偶数', 'hex');
    var bytes = new Uint8Array(s.length / 2);
    for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(s.substr(i * 2, 2), 16);
    return bytesResult(bytes, 'hex', s);
  }

  // ---------- URL encoding ----------

  function encodeUrl(text) {
    return encodeURIComponent(String(text == null ? '' : text));
  }

  function decodeUrl(input) {
    var s = String(input == null ? '' : input).trim();
    if (!s) return fail('没有可解码的内容', 'url');
    try {
      return { ok: true, kind: 'text', text: decodeURIComponent(s),
               encoding: 'UTF-8', byteLength: s.length, bytes: null, format: 'url', cleaned: s };
    } catch (e) { /* lone % etc. — decode only valid %XX sequences */ }
    if (!/%[0-9A-Fa-f]{2}/.test(s)) return fail('未发现 %XX 形式的 URL 编码', 'url');
    var out = s.replace(/%[0-9A-Fa-f]{2}/g, function (m) {
      try { return decodeURIComponent(m); } catch (e2) { return m; }
    });
    return { ok: true, kind: 'text', text: out,
             encoding: 'UTF-8', byteLength: out.length, bytes: null, format: 'url', cleaned: s };
  }

  // ---------- Unicode escapes ----------

  // Encode non-ASCII characters as \uXXXX (surrogate pairs for astral
  // characters); ASCII printable characters stay as-is.
  function encodeUnicode(text) {
    var s = String(text == null ? '' : text);
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var code = s.charCodeAt(i);
      if (code === 0x5C) out += '\\\\';
      else if (code === 0x0A) out += '\\n';
      else if (code === 0x0D) out += '\\r';
      else if (code === 0x09) out += '\\t';
      else if (code >= 0x20 && code <= 0x7E) out += s[i];
      else out += '\\u' + code.toString(16).padStart(4, '0');
    }
    return out;
  }

  // One regex for all escape forms; a single left-to-right pass is required
  // so that a literal backslash (\\) followed by 'n' is not mistaken for a
  // newline escape after the backslash pair is collapsed.
  var UNICODE_ESCAPE_RE = /\\(u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}|[nrt'"\\])/g;

  function decodeUnicode(input) {
    var s = String(input == null ? '' : input);
    if (!UNICODE_ESCAPE_RE.test(s)) {
      return fail('未发现 \\uXXXX、\\xXX 或 \\n、\\t 等转义', 'unicode');
    }
    UNICODE_ESCAPE_RE.lastIndex = 0;
    var out = s.replace(UNICODE_ESCAPE_RE, function (m, esc) {
      if (esc[0] === 'u') return String.fromCharCode(parseInt(esc.slice(1), 16));
      if (esc[0] === 'x') return String.fromCharCode(parseInt(esc.slice(1), 16));
      if (esc === 'n') return '\n';
      if (esc === 't') return '\t';
      if (esc === 'r') return '\r';
      if (esc === '"') return '"';
      if (esc === "'") return "'";
      if (esc === '\\') return '\\';
      return m;
    });
    return { ok: true, kind: 'text', text: out,
             encoding: 'UTF-8', byteLength: out.length, bytes: null, format: 'unicode', cleaned: s.trim() };
  }

  // ---------- Base32 (RFC 4648) ----------

  var B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function encodeBase32(text) {
    var bytes = new TextEncoder().encode(String(text == null ? '' : text));
    var out = '';
    var bits = 0, value = 0;
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        out += B32_ALPHABET[(value >>> bits) & 31];
      }
    }
    if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
    while (out.length % 8 !== 0) out += '=';
    return out;
  }

  function decodeBase32(input) {
    var s = String(input == null ? '' : input).trim().replace(/\s+/g, '').toUpperCase();
    if (!s) return fail('没有可解码的内容', 'base32');
    if (!/^[A-Z2-7]+={0,6}$/.test(s)) return fail('包含非 Base32 字符', 'base32');
    var clean = s.replace(/=+$/, '');
    if (clean.length % 8 === 1) return fail('长度无效，不是合法的 Base32', 'base32');
    var bytes = [];
    var bits = 0, value = 0;
    for (var i = 0; i < clean.length; i++) {
      value = (value << 5) | B32_ALPHABET.indexOf(clean[i]);
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        bytes.push((value >>> bits) & 0xFF);
      }
    }
    return bytesResult(new Uint8Array(bytes), 'base32', s);
  }

  // ---------- Base58 / Base62 (shared big-number core) ----------

  var B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  var B62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  function baseNEncode(bytes, alphabet) {
    if (!bytes.length) return '';
    var zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    if (zeros === bytes.length) {
      var only = '';
      for (var z = 0; z < zeros; z++) only += alphabet[0];
      return only;
    }
    var digits = [0];
    for (var i = zeros; i < bytes.length; i++) {
      var carry = bytes[i];
      for (var j = 0; j < digits.length; j++) {
        carry += digits[j] << 8;
        digits[j] = carry % alphabet.length;
        carry = (carry / alphabet.length) | 0;
      }
      while (carry > 0) {
        digits.push(carry % alphabet.length);
        carry = (carry / alphabet.length) | 0;
      }
    }
    var out = '';
    for (var k = 0; k < zeros; k++) out += alphabet[0];
    for (var m = digits.length - 1; m >= 0; m--) out += alphabet[digits[m]];
    return out;
  }

  function baseNDecode(s, alphabet, format) {
    if (!s) return fail('没有可解码的内容', format);
    var map = {};
    for (var i = 0; i < alphabet.length; i++) map[alphabet[i]] = i;
    var zeros = 0;
    while (zeros < s.length && s[zeros] === alphabet[0]) zeros++;
    var bytes = [0];
    for (var i = 0; i < s.length; i++) {
      var v = map[s[i]];
      if (v === undefined) return fail('包含非 ' + format + ' 字符', format);
      var carry = v;
      for (var j = 0; j < bytes.length; j++) {
        carry += bytes[j] * alphabet.length;
        bytes[j] = carry & 0xFF;
        carry >>= 8;
      }
      while (carry > 0) {
        bytes.push(carry & 0xFF);
        carry >>= 8;
      }
    }
    // bytes is little-endian with a phantom [0] when the value is zero
    var valueLen = (bytes.length === 1 && bytes[0] === 0) ? 0 : bytes.length;
    var out = new Uint8Array(zeros + valueLen);
    for (var m = 0; m < valueLen; m++) out[zeros + m] = bytes[valueLen - 1 - m];
    return bytesResult(out, format, s);
  }

  function encodeBase58(text) {
    return baseNEncode(new TextEncoder().encode(String(text == null ? '' : text)), B58_ALPHABET);
  }

  function decodeBase58(input) {
    return baseNDecode(String(input == null ? '' : input).trim().replace(/\s+/g, ''), B58_ALPHABET, 'base58');
  }

  function encodeBase62(text) {
    return baseNEncode(new TextEncoder().encode(String(text == null ? '' : text)), B62_ALPHABET);
  }

  function decodeBase62(input) {
    return baseNDecode(String(input == null ? '' : input).trim().replace(/\s+/g, ''), B62_ALPHABET, 'base62');
  }

  // ---------- Base85 (Ascii85, Adobe variant with 'z') ----------

  function encodeBase85(text) {
    var bytes = new TextEncoder().encode(String(text == null ? '' : text));
    var out = '';
    for (var i = 0; i < bytes.length; i += 4) {
      var n = Math.min(4, bytes.length - i);
      var v = ((bytes[i] << 24) | (bytes[i + 1] || 0) << 16 | (bytes[i + 2] || 0) << 8 | (bytes[i + 3] || 0)) >>> 0;
      if (v === 0 && n === 4) { out += 'z'; continue; }
      var chars = [];
      for (var j = 0; j < 5; j++) {
        chars.push(String.fromCharCode((v % 85) + 33));
        v = Math.floor(v / 85);
      }
      chars.reverse();
      out += chars.join('').slice(0, n + 1);
    }
    return out;
  }

  function decodeBase85(input) {
    var s = String(input == null ? '' : input).trim();
    if (s.indexOf('<~') === 0) s = s.slice(2);
    if (s.slice(-2) === '~>') s = s.slice(0, -2);
    s = s.replace(/\s+/g, '');
    if (!s) return fail('没有可解码的内容', 'base85');
    if (!/^[!-uz]+$/.test(s)) return fail('包含非 Ascii85 字符', 'base85');
    var bytes = [];
    var i = 0;
    while (i < s.length) {
      if (s[i] === 'z') { bytes.push(0, 0, 0, 0); i++; continue; }
      var group = s.slice(i, i + 5);
      var n = group.length;
      if (n === 1) return fail('Ascii85 分组长度无效', 'base85');
      var padded = group;
      while (padded.length < 5) padded += 'u';
      var v = 0;
      for (var j = 0; j < 5; j++) v = v * 85 + (padded.charCodeAt(j) - 33);
      if (v > 4294967295) return fail('Ascii85 分组数值溢出', 'base85');
      var b = [(v >>> 24) & 0xFF, (v >>> 16) & 0xFF, (v >>> 8) & 0xFF, v & 0xFF];
      var take = n === 5 ? 4 : n - 1;
      for (var k = 0; k < take; k++) bytes.push(b[k]);
      i += n;
    }
    return bytesResult(new Uint8Array(bytes), 'base85', s);
  }

  // ---------- Base91 (basE91, joachim-henke) ----------

  var B91_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';

  function encodeBase91(text) {
    var bytes = new TextEncoder().encode(String(text == null ? '' : text));
    var b = 0, n = 0, out = '';
    for (var i = 0; i < bytes.length; i++) {
      b |= bytes[i] << n;
      n += 8;
      if (n > 13) {
        var v = b & 8191;
        if (v > 88) { b >>= 13; n -= 13; }
        else { v = b & 16383; b >>= 14; n -= 14; }
        out += B91_ALPHABET[v % 91] + B91_ALPHABET[(v / 91) | 0];
      }
    }
    if (n) {
      out += B91_ALPHABET[b % 91];
      if (n > 7 || b > 90) out += B91_ALPHABET[(b / 91) | 0];
    }
    return out;
  }

  function decodeBase91(input) {
    var s = String(input == null ? '' : input).trim().replace(/\s+/g, '');
    if (!s) return fail('没有可解码的内容', 'base91');
    var table = {};
    for (var i = 0; i < B91_ALPHABET.length; i++) table[B91_ALPHABET[i]] = i;
    var bytes = [];
    var b = 0, n = 0, v = -1;
    for (var i = 0; i < s.length; i++) {
      var p = table[s[i]];
      if (p === undefined) return fail('包含非 Base91 字符', 'base91');
      if (v < 0) { v = p; continue; }
      v += p * 91;
      b |= v << n;
      n += (v & 8191) > 88 ? 13 : 14;
      do {
        bytes.push(b & 0xFF);
        b >>= 8;
        n -= 8;
      } while (n > 7);
      v = -1;
    }
    if (v >= 0) bytes.push((b | (v << n)) & 0xFF);
    return bytesResult(new Uint8Array(bytes), 'base91', s);
  }

  // ---------- Binary / Octal (text) ----------

  function encodeBinary(text) {
    var bytes = new TextEncoder().encode(String(text == null ? '' : text));
    return Array.prototype.map.call(bytes, function (b) {
      return b.toString(2).padStart(8, '0');
    }).join(' ');
  }

  function decodeBinary(input) {
    var s = String(input == null ? '' : input).trim().replace(/\s+/g, '');
    if (!s) return fail('没有可解码的内容', 'binary');
    if (!/^[01]+$/.test(s)) return fail('包含非二进制字符（只应有 0 和 1）', 'binary');
    if (s.length % 8 !== 0) return fail('二进制长度应为 8 的倍数', 'binary');
    var bytes = new Uint8Array(s.length / 8);
    for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(s.substr(i * 8, 8), 2);
    return bytesResult(bytes, 'binary', s);
  }

  function encodeOctal(text) {
    var bytes = new TextEncoder().encode(String(text == null ? '' : text));
    return Array.prototype.map.call(bytes, function (b) {
      return b.toString(8).padStart(3, '0');
    }).join(' ');
  }

  function decodeOctal(input) {
    var s = String(input == null ? '' : input).trim().replace(/\s+/g, '');
    if (!s) return fail('没有可解码的内容', 'octal');
    if (!/^[0-7]+$/.test(s)) return fail('包含非八进制字符（只应有 0-7）', 'octal');
    if (s.length % 3 !== 0) return fail('八进制长度应为 3 的倍数', 'octal');
    var bytes = new Uint8Array(s.length / 3);
    for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(s.substr(i * 3, 3), 8);
    return bytesResult(bytes, 'octal', s);
  }

  // ---------- Morse code ----------

  var MORSE_TABLE = {
    A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.',
    H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.',
    O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-',
    V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
    '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
    ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
    '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
  };
  var MORSE_REV = {};
  (function () {
    for (var k in MORSE_TABLE) MORSE_REV[MORSE_TABLE[k]] = k;
  })();

  function encodeMorse(text) {
    var s = String(text == null ? '' : text).toUpperCase();
    var words = s.split(/\s+/);
    var out = [];
    for (var w = 0; w < words.length; w++) {
      var letters = [];
      for (var i = 0; i < words[w].length; i++) {
        var code = MORSE_TABLE[words[w][i]];
        if (code) letters.push(code);
      }
      if (letters.length) out.push(letters.join(' '));
    }
    return out.join(' / ');
  }

  function decodeMorse(input) {
    var s = String(input == null ? '' : input).trim();
    if (!s) return fail('没有可解码的内容', 'morse');
    if (!/^[.\-/\s]+$/.test(s)) return fail('摩斯电码只应包含 . - / 和空格', 'morse');
    var words = s.split('/');
    var out = [];
    for (var w = 0; w < words.length; w++) {
      var letters = words[w].trim().split(/\s+/).filter(Boolean);
      var word = '';
      for (var i = 0; i < letters.length; i++) word += MORSE_REV[letters[i]] || '?';
      out.push(word);
    }
    var text = out.join(' ');
    return { ok: true, kind: 'text', text: text,
             encoding: 'UTF-8', byteLength: text.length, bytes: null, format: 'morse', cleaned: s };
  }

  // ---------- ROT13 / Caesar ----------

  function caesarShift(text, shift) {
    var s = String(text == null ? '' : text);
    var n = ((shift % 26) + 26) % 26;
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c >= 65 && c <= 90) out += String.fromCharCode(65 + (c - 65 + n) % 26);
      else if (c >= 97 && c <= 122) out += String.fromCharCode(97 + (c - 97 + n) % 26);
      else out += s[i];
    }
    return out;
  }

  function shiftResult(input, shift, format) {
    var s = String(input == null ? '' : input);
    if (!s.trim()) return fail('没有可解码的内容', format);
    var text = caesarShift(s, shift);
    return { ok: true, kind: 'text', text: text,
             encoding: 'UTF-8', byteLength: text.length, bytes: null, format: format, cleaned: s.trim() };
  }

  // ---------- HTML entities ----------

  var HTML_NAMED = {
    amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00A0',
    copy: '\u00A9', reg: '\u00AE', trade: '\u2122', hellip: '\u2026',
    mdash: '\u2014', ndash: '\u2013', laquo: '\u00AB', raquo: '\u00BB',
    lsquo: '\u2018', rsquo: '\u2019', ldquo: '\u201C', rdquo: '\u201D',
    times: '\u00D7', divide: '\u00F7', plusmn: '\u00B1', deg: '\u00B0',
    micro: '\u00B5', para: '\u00B6', middot: '\u00B7', bull: '\u2022',
    dagger: '\u2020', Dagger: '\u2021', permil: '\u2030', lsaquo: '\u2039',
    rsaquo: '\u203A', euro: '\u20AC', pound: '\u00A3', yen: '\u00A5',
    cent: '\u00A2', curren: '\u00A4', brvbar: '\u00A6', sect: '\u00A7',
    uml: '\u00A8', ordf: '\u00AA', ordm: '\u00BA', iexcl: '\u00A1',
    iquest: '\u00BF', szlig: '\u00DF', agrave: '\u00E0', aacute: '\u00E1',
    acirc: '\u00E2', atilde: '\u00E3', auml: '\u00E4', aring: '\u00E5',
    aelig: '\u00E6', ccedil: '\u00E7', egrave: '\u00E8', eacute: '\u00E9',
    ecirc: '\u00EA', euml: '\u00EB', igrave: '\u00EC', iacute: '\u00ED',
    icirc: '\u00EE', iuml: '\u00EF', ntilde: '\u00F1', ograve: '\u00F2',
    oacute: '\u00F3', ocirc: '\u00F4', otilde: '\u00F5', ouml: '\u00F6',
    oslash: '\u00F8', ugrave: '\u00F9', uacute: '\u00FA', ucirc: '\u00FB',
    uuml: '\u00FC', yacute: '\u00FD', yuml: '\u00FF'
  };

  function encodeHtml(text) {
    var s = String(text == null ? '' : text);
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c === 38) out += '&amp;';
      else if (c === 60) out += '&lt;';
      else if (c === 62) out += '&gt;';
      else if (c === 34) out += '&quot;';
      else if (c === 39) out += '&apos;';
      else if (c > 127) out += '&#x' + c.toString(16) + ';';
      else out += s[i];
    }
    return out;
  }

  function decodeHtml(input) {
    var s = String(input == null ? '' : input);
    if (!/&(#\d+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);/.test(s)) {
      return fail('未发现 HTML 实体（如 &amp; &#x4f60;）', 'html');
    }
    var out = s.replace(/&(#\d+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);/g, function (m, body) {
      if (body[0] === '#') {
        var code = (body[1] === 'x' || body[1] === 'X')
          ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
        if (isNaN(code) || code < 0 || code > 0x10FFFF) return m;
        try { return String.fromCodePoint(code); } catch (e) { return m; }
      }
      return HTML_NAMED[body] !== undefined ? HTML_NAMED[body] : m;
    });
    return { ok: true, kind: 'text', text: out,
             encoding: 'UTF-8', byteLength: out.length, bytes: null, format: 'html', cleaned: s.trim() };
  }

  // ---------- JWT ----------

  function isJwtLike(s) {
    if (typeof s !== 'string') return false;
    var parts = s.trim().split('.');
    return parts.length === 3 &&
      parts.every(function (p) { return /^[A-Za-z0-9_-]+$/.test(p); });
  }

  function parseJwt(input) {
    var s = String(input == null ? '' : input).trim();
    if (!isJwtLike(s)) return { ok: false, error: '不是 JWT 格式（应为 header.payload.signature 三段）' };
    var parts = s.split('.');
    function part(i) {
      var r = decodeBase64(parts[i]);
      if (!r.ok || r.text === null) return { raw: parts[i], json: null };
      try { return { raw: r.text, json: JSON.parse(r.text) }; }
      catch (e) { return { raw: r.text, json: null }; }
    }
    var header = part(0);
    var payload = part(1);
    return { ok: true, kind: 'jwt', format: 'jwt', header: header, payload: payload,
             signature: parts[2], byteLength: s.length, bytes: null, cleaned: s };
  }

  // Format a JWT numeric time claim (seconds since epoch) for display.
  function formatJwtTime(seconds) {
    if (typeof seconds !== 'number' || !isFinite(seconds)) return null;
    var d = new Date(seconds * 1000);
    if (isNaN(d.getTime())) return null;
    var rel;
    var diff = d.getTime() - Date.now();
    var abs = Math.abs(diff);
    var amount;
    if (abs < 60000) amount = Math.round(abs / 1000) + ' 秒';
    else if (abs < 3600000) amount = Math.round(abs / 60000) + ' 分钟';
    else if (abs < 86400000) amount = Math.round(abs / 3600000) + ' 小时';
    else amount = Math.round(abs / 86400000) + ' 天';
    rel = diff >= 0 ? '还有 ' + amount : '已过去 ' + amount;
    var pad = function (n) { return String(n).padStart(2, '0'); };
    var local = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
      ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    return local + '（' + rel + '）';
  }

  // ---------- format detection & dispatch ----------

  function decodeAs(input, format, opts) {
    switch (format) {
      case 'base64': return decodeBase64(input);
      case 'base32': return decodeBase32(input);
      case 'base58': return decodeBase58(input);
      case 'base62': return decodeBase62(input);
      case 'base85': return decodeBase85(input);
      case 'base91': return decodeBase91(input);
      case 'hex': return decodeHex(input);
      case 'binary': return decodeBinary(input);
      case 'octal': return decodeOctal(input);
      case 'url': return decodeUrl(input);
      case 'unicode': return decodeUnicode(input);
      case 'html': return decodeHtml(input);
      case 'morse': return decodeMorse(input);
      case 'rot13': return shiftResult(input, 13, 'rot13');
      case 'caesar': return shiftResult(input, -(opts && opts.shift != null ? opts.shift : 3), 'caesar');
      case 'jwt': {
        var r = parseJwt(input);
        if (!r.ok) return fail(r.error, 'jwt');
        return r;
      }
      default: return fail('未知格式', format);
    }
  }

  // Encode text into the given format. Returns the encoded string, or null
  // for formats that cannot be encoded from plain text (JWT needs signing).
  function encodeAs(text, format, opts) {
    switch (format) {
      case 'base64': return encodeBase64(text, opts);
      case 'base32': return encodeBase32(text);
      case 'base58': return encodeBase58(text);
      case 'base62': return encodeBase62(text);
      case 'base85': return encodeBase85(text);
      case 'base91': return encodeBase91(text);
      case 'hex': return encodeHex(text);
      case 'binary': return encodeBinary(text);
      case 'octal': return encodeOctal(text);
      case 'url': return encodeUrl(text);
      case 'unicode': return encodeUnicode(text);
      case 'html': return encodeHtml(text);
      case 'morse': return encodeMorse(text);
      case 'rot13': return caesarShift(text, 13);
      case 'caesar': return caesarShift(text, opts && opts.shift != null ? opts.shift : 3);
      default: return null;
    }
  }

  function detectFormat(input) {
    var s = String(input == null ? '' : input).trim();
    if (!s) return null;
    // JWT: three base64url parts, header decodes to JSON with alg/typ
    if (isJwtLike(s)) {
      var h = decodeBase64(s.split('.')[0]);
      if (h.ok && h.text !== null) {
        try {
          var hj = JSON.parse(h.text);
          if (hj && typeof hj === 'object' && (hj.alg || hj.typ)) return 'jwt';
        } catch (e) { /* not JSON header — fall through */ }
      }
      return 'jwt'; // three-part shape is distinctive enough
    }
    if (/\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}/.test(s)) return 'unicode';
    if (/%[0-9A-Fa-f]{2}/.test(s)) return 'url';
    if (/&(#\d+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);/.test(s)) return 'html';
    // Morse: only dots, dashes, slashes and spaces, at least two valid groups
    if (/^[.\-/\s]+$/.test(s)) {
      var groups = s.split(/[\s/]+/).filter(Boolean);
      if (groups.length >= 2 && groups.every(function (g) { return MORSE_REV[g] !== undefined; })) {
        return 'morse';
      }
    }
    var nospace = s.replace(/\s+/g, '');
    // Binary: only 0/1, multiple of 8, decodes to readable text
    if (/^[01]+$/.test(nospace) && nospace.length >= 8 && nospace.length % 8 === 0) {
      var bin = decodeBinary(s);
      if (bin.ok && bin.kind === 'text') return 'binary';
    }
    // Hex: all hex chars, even length, and decodes to readable text
    var hexOnly = /^[0-9a-fA-F]+$/.test(nospace);
    if (hexOnly) {
      var h2 = decodeHex(s);
      if (h2.ok && h2.kind === 'text') return 'hex';
    }
    // Base32: A-Z2-7 with padding or a 2-7 digit (keeps plain words out),
    // decodes to readable text
    var b32 = nospace.toUpperCase();
    if (/^[A-Z2-7]+={0,6}$/.test(b32) && b32.length >= 8 &&
        (/=/.test(b32) || /[2-7]/.test(b32))) {
      var d32 = decodeBase32(s);
      if (d32.ok && d32.kind === 'text') return 'base32';
    }
    // Base64: prefer when it decodes to text; keep a binary fallback in case
    // a later, more specific format does not match
    var cleaned = cleanBase64(s);
    var b64Binary = null;
    if (cleaned.length >= 4 && /^[A-Za-z0-9+/=_-]+$/.test(cleaned)) {
      var b = decodeBase64(s);
      if (b.ok) {
        if (b.kind === 'text') return 'base64';
        b64Binary = 'base64';
      }
    }
    // Base58: no 0, O, I, l — checked before Base62 (a superset charset)
    if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(nospace) && nospace.length >= 8) {
      var d58 = decodeBase58(s);
      if (d58.ok && d58.kind === 'text') return 'base58';
    }
    // Base62: plain alphanumerics
    if (/^[0-9A-Za-z]+$/.test(nospace) && nospace.length >= 8) {
      var d62 = decodeBase62(s);
      if (d62.ok && d62.kind === 'text') return 'base62';
    }
    // Base85: '!'..'u' plus 'z'
    if (/^[!-uz]+$/.test(nospace) && nospace.length >= 8) {
      var d85 = decodeBase85(s);
      if (d85.ok && d85.kind === 'text') return 'base85';
    }
    // Base91: broadest printable charset — checked last
    if (nospace.length >= 8 && /^[A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_`{|}~"]+$/.test(nospace)) {
      var d91 = decodeBase91(s);
      if (d91.ok && d91.kind === 'text') return 'base91';
    }
    return b64Binary;
  }

  function looksLikeBase64(str) {
    if (typeof str !== 'string') return false;
    var s = str.trim();
    if (s.length < 8) return false;
    if (!/^[A-Za-z0-9+/=_-]+$/.test(s)) return false;
    var core = s.replace(/=+$/, '');
    return core.length % 4 !== 1;
  }

  // ---------- candidate extraction (mixed text) ----------

  // A token only counts as a candidate if it is not a plain word: it must
  // contain a digit, a Base64 symbol, or mixed upper/lower case.
  function isEncodedToken(tok) {
    if (tok.length < 16) return false;
    if (/[0-9]/.test(tok)) return true;
    if (/[+/=_-]/.test(tok)) return true;
    return /[a-z]/.test(tok) && /[A-Z]/.test(tok);
  }

  function extractCandidates(input) {
    var s = String(input == null ? '' : input);
    var found = [];
    var seen = {};
    function push(tok) {
      if (!tok || seen[tok]) return;
      seen[tok] = true;
      found.push(tok);
    }
    var jwtRe = /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    var m;
    while ((m = jwtRe.exec(s)) !== null) push(m[0]);
    var b64Re = /[A-Za-z0-9+/_-]{16,}={0,2}/g; // '=' only as trailing padding, else 'key=<b64>' merges into one token
    while ((m = b64Re.exec(s)) !== null) {
      if (isEncodedToken(m[0])) push(m[0]);
    }
    return found.slice(0, 20);
  }

  // Smart decode: detect the format and decode; if the whole input does not
  // decode, try to extract decodable fragments from it.
  // Returns a decode result, or { ok: true, multiple: [...] } when several
  // fragments decode, or { ok: false, ... }.
  function smartDecode(input) {
    var fmt = detectFormat(input);
    if (fmt) {
      var r = decodeAs(input, fmt);
      if (r.ok) return r;
    }
    var candidates = extractCandidates(input);
    var decoded = [];
    for (var i = 0; i < candidates.length; i++) {
      var f = detectFormat(candidates[i]) || 'base64';
      var d = decodeAs(candidates[i], f);
      if (d.ok) {
        d.extractedFrom = candidates[i];
        decoded.push(d);
      }
    }
    if (decoded.length === 1) {
      decoded[0].extracted = true;
      return decoded[0];
    }
    if (decoded.length > 1) {
      return { ok: true, kind: 'multiple', multiple: decoded, extracted: true, format: null };
    }
    return fail('无法识别为 Base64、Base32、Base58、Hex、URL 编码、Unicode 转义、HTML 实体、摩斯电码或 JWT', fmt);
  }

  // Find encoded tokens with positions (for the page scanner). Returns
  // [{ text, index }], JWT tokens first, Base64-like tokens after; a Base64
  // match inside a JWT match is skipped. minLen defaults to 16.
  function findEncodedTokens(input, minLen) {
    var s = String(input == null ? '' : input);
    var min = minLen || 16;
    var out = [];
    var jwtRanges = [];
    var jwtRe = /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    var m;
    while ((m = jwtRe.exec(s)) !== null) {
      out.push({ text: m[0], index: m.index });
      jwtRanges.push([m.index, m.index + m[0].length]);
    }
    var b64Re = /[A-Za-z0-9+/_-]{16,}={0,2}/g; // '=' only as trailing padding, else 'key=<b64>' merges into one token
    while ((m = b64Re.exec(s)) !== null) {
      var tok = m[0];
      if (tok.length < min) continue;
      var inside = jwtRanges.some(function (r) { return m.index >= r[0] && m.index < r[1]; });
      if (inside) continue;
      if (isEncodedToken(tok)) out.push({ text: tok, index: m.index });
    }
    return out;
  }

  // Heuristic for the floating button: is this selection worth offering
  // decode/encode for?
  function looksEncoded(s) {
    if (typeof s !== 'string') return false;
    var t = s.trim();
    if (t.length < 8) return false;
    if (/%[0-9A-Fa-f]{2}/.test(t)) return true;
    if (/\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}/.test(t)) return true;
    if (/&(#\d+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);/.test(t)) return true;
    if (/^[.\-/\s]{8,}$/.test(t)) return true;
    if (/^[01\s]{8,}$/.test(t)) return true;
    return extractCandidates(t).length > 0;
  }

  // ---------- image / compression detection ----------

  function detectImage(bytes) {
    if (!bytes || bytes.length < 4) return null;
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'png';
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'jpeg';
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) return 'gif';
    if (bytes[0] === 0x42 && bytes[1] === 0x4D) return 'bmp';
    if (bytes.length >= 12 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
        bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return 'webp';
    return null;
  }

  function detectCompression(bytes) {
    if (!bytes || bytes.length < 2) return null;
    if (bytes[0] === 0x1F && bytes[1] === 0x8B) return 'gzip';
    if (bytes[0] === 0x78 && (bytes[1] === 0x01 || bytes[1] === 0x9C || bytes[1] === 0xDA)) return 'zlib';
    return null;
  }

  function decompressBytes(bytes, kind) {
    var format = kind === 'gzip' ? 'gzip' : 'deflate';
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
    return new Response(stream).arrayBuffer().then(function (buf) { return new Uint8Array(buf); });
  }

  // Async post-processing for a decoded result: image preview, gzip/zlib
  // decompression. Returns an enhanced copy of the result.
  function enhanceDecoded(result) {
    if (!result || !result.ok || !result.bytes) return Promise.resolve(result);
    var img = detectImage(result.bytes);
    if (img) {
      var copy = Object.assign({}, result);
      copy.image = img;
      return Promise.resolve(copy);
    }
    var comp = detectCompression(result.bytes);
    if (!comp) return Promise.resolve(result);
    return decompressBytes(result.bytes, comp).then(function (out) {
      var t = bytesToText(out);
      if (t.text === null) return result;
      var copy2 = Object.assign({}, result);
      copy2.kind = 'text';
      copy2.text = t.text;
      copy2.encoding = t.encoding;
      copy2.decompressed = comp;
      copy2.byteLength = out.length;
      copy2.bytes = out;
      copy2.hex = undefined;
      return copy2;
    }).catch(function () { return result; });
  }

  // ---------- JSON ----------

  // Returns pretty-printed JSON if text parses as a JSON object/array.
  function tryParseJson(text) {
    if (typeof text !== 'string') return null;
    var t = text.trim();
    if (!t || (t[0] !== '{' && t[0] !== '[')) return null;
    try {
      var v = JSON.parse(t);
      if (v && typeof v === 'object') return JSON.stringify(v, null, 2);
    } catch (e) { /* not JSON */ }
    return null;
  }

  var api = {
    FORMAT_LABELS: FORMAT_LABELS,
    cleanBase64: cleanBase64,
    encodeBase64: encodeBase64,
    decodeBase64: decodeBase64,
    encodeBase32: encodeBase32,
    decodeBase32: decodeBase32,
    encodeBase58: encodeBase58,
    decodeBase58: decodeBase58,
    encodeBase62: encodeBase62,
    decodeBase62: decodeBase62,
    encodeBase85: encodeBase85,
    decodeBase85: decodeBase85,
    encodeBase91: encodeBase91,
    decodeBase91: decodeBase91,
    encodeHex: encodeHex,
    decodeHex: decodeHex,
    encodeBinary: encodeBinary,
    decodeBinary: decodeBinary,
    encodeOctal: encodeOctal,
    decodeOctal: decodeOctal,
    encodeUrl: encodeUrl,
    decodeUrl: decodeUrl,
    encodeUnicode: encodeUnicode,
    decodeUnicode: decodeUnicode,
    encodeHtml: encodeHtml,
    decodeHtml: decodeHtml,
    encodeMorse: encodeMorse,
    decodeMorse: decodeMorse,
    caesarShift: caesarShift,
    isJwtLike: isJwtLike,
    parseJwt: parseJwt,
    formatJwtTime: formatJwtTime,
    decodeAs: decodeAs,
    encodeAs: encodeAs,
    detectFormat: detectFormat,
    looksLikeBase64: looksLikeBase64,
    extractCandidates: extractCandidates,
    findEncodedTokens: findEncodedTokens,
    smartDecode: smartDecode,
    looksEncoded: looksEncoded,
    detectImage: detectImage,
    detectCompression: detectCompression,
    decompressBytes: decompressBytes,
    enhanceDecoded: enhanceDecoded,
    bytesToText: bytesToText,
    tryParseJson: tryParseJson
  };
  global.B64Codec = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
