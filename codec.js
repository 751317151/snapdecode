// B64Codec — shared codec logic (no chrome APIs) used by the content script
// and the popup. Covers Base64, Hex, URL encoding, Unicode escapes, JWT,
// format detection, candidate extraction, image/gzip detection and
// multi-encoding text fallback (UTF-8 -> GBK -> GB18030).
// Safe to load in a browser page context or in Node (for tests).
(function (global) {
  'use strict';

  var FORMAT_LABELS = {
    base64: 'Base64', hex: 'Hex', url: 'URL 编码', unicode: 'Unicode 转义', jwt: 'JWT'
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

  function decodeAs(input, format) {
    switch (format) {
      case 'base64': return decodeBase64(input);
      case 'hex': return decodeHex(input);
      case 'url': return decodeUrl(input);
      case 'unicode': return decodeUnicode(input);
      case 'jwt': {
        var r = parseJwt(input);
        if (!r.ok) return fail(r.error, 'jwt');
        return r;
      }
      default: return fail('未知格式', format);
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
    // Hex: all hex chars, even length, and decodes to readable text
    var hexOnly = /^[0-9a-fA-F]+$/.test(s.replace(/\s+/g, ''));
    if (hexOnly) {
      var h2 = decodeHex(s);
      if (h2.ok && h2.kind === 'text') return 'hex';
    }
    var cleaned = cleanBase64(s);
    if (cleaned.length >= 4 && /^[A-Za-z0-9+/=_-]+$/.test(cleaned)) {
      var b = decodeBase64(s);
      if (b.ok) return 'base64';
    }
    return null;
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
    return fail('无法识别为 Base64、Hex、URL 编码、Unicode 转义或 JWT', fmt);
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
    encodeHex: encodeHex,
    decodeHex: decodeHex,
    encodeUrl: encodeUrl,
    decodeUrl: decodeUrl,
    encodeUnicode: encodeUnicode,
    decodeUnicode: decodeUnicode,
    isJwtLike: isJwtLike,
    parseJwt: parseJwt,
    formatJwtTime: formatJwtTime,
    decodeAs: decodeAs,
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
