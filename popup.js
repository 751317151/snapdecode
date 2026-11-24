// Popup logic v4: tabbed tool — codec (decode/encode + page scan + QR),
// batch decode, hash/HMAC/cipher/JWT/RSA/ECDSA/SM2 tools, file hash,
// dev tools (JSON/URL/regex/diff), codec-chain pipeline with recipes,
// local history with favorites, format filter and export.
'use strict';

var $ = function (id) { return document.getElementById(id);};

// ---------------- tabs ----------------

document.querySelectorAll('.tab-btn').forEach(function (btn) {
btn.addEventListener('click', function () {
document.querySelectorAll('.tab-btn').forEach(function (b) { b.classList.remove('on');});
document.querySelectorAll('.panel').forEach(function (p) { p.classList.remove('on');});
btn.classList.add('on');
$('tab-' + btn.dataset.tab).classList.add('on');
if (btn.dataset.tab === 'history') renderHistory();
});
});

// ---------------- helpers ----------------

function flash(btn, text) {
var old = btn.textContent;
btn.textContent = text;
setTimeout(function () { btn.textContent = old;}, 1500);
}

function copyValue(value, btn) {
if (!value) return;
if (navigator.clipboard && navigator.clipboard.writeText) {
navigator.clipboard.writeText(value).then(
function () { flash(btn, '已复制 ✓');},
function () { flash(btn, '复制失败');});
}
}

function truncate(s, n) {
s = String(s == null? '': s);
return s.length > n? s.slice(0, n) + '…': s;
}

// ---------------- codec tab ----------------

var codecState = { rawText: '', prettyJson: null, jsonPretty: true, imageUrl: null};

function setCodecOutput(result) {
var errEl = $('codecError');
var metaEl = $('codecMeta');
var outEl = $('codecOutput');
var imgEl = $('codecImg');
var toggleBtn = $('jsonToggleBtn');
if (codecState.imageUrl) {
URL.revokeObjectURL(codecState.imageUrl);
codecState.imageUrl = null;
}
imgEl.style.display = 'none';
imgEl.src = '';
toggleBtn.style.display = 'none';
codecState.prettyJson = null;
codecState.jsonPretty = true;

if (!result.ok) {
errEl.textContent = result.error;
metaEl.textContent = '';
outEl.value = '';
codecState.rawText = '';
return;
}
errEl.textContent = '';
if (result.kind === 'multiple') {
metaEl.textContent = '输入里有 ' + result.multiple.length + ' 处可解码内容（已显示第一处，逐条解请用批量）：';
var first = result.multiple[0];
setCodecOutput(first);
return;
}
if (result.kind === 'jwt') {
var parts = [];
parts.push('\n' + (result.header.json
? JSON.stringify(result.header.json, null, 2): result.header.raw));
parts.push('\n' + (result.payload.json
? JSON.stringify(result.payload.json, null, 2): result.payload.raw));
if (result.payload.json) {
var claims = [];
['exp', 'iat', 'nbf', 'auth_time'].forEach(function (k) {
var f = B64Codec.formatJwtTime(result.payload.json[k]);
if (f) claims.push(k + ': ' + result.payload.json[k] + ' → ' + f);
});
if (claims.length) parts.push('\n' + claims.join('\n'));
}
parts.push('\n' + result.signature + '\n（签名验证请到「工具」页）');
metaEl.textContent = 'JWT 解析完成';
outEl.value = parts.join('\n\n');
codecState.rawText = outEl.value;
return;
}
var metaParts = [];
if (result.extracted) metaParts.push('已从输入中提取片段');
if (result.format) metaParts.push('识别为 ' + B64Codec.FORMAT_LABELS[result.format]);
if (result.decompressed) metaParts.push('已自动解压（' + result.decompressed + '）');
if (result.encoding) metaParts.push('编码：' + result.encoding);
metaParts.push('共 ' + result.byteLength + ' 字节');
if (result.kind === 'binary') metaParts.push('非文本内容，以下为十六进制');
metaEl.textContent = metaParts.join(' · ');

if (result.image) {
var blob = new Blob([result.bytes], { type: 'image/' + result.image});
codecState.imageUrl = URL.createObjectURL(blob);
imgEl.src = codecState.imageUrl;
imgEl.style.display = 'block';
}
var full = result.kind === 'binary'? result.hex: result.text;
codecState.rawText = full;
var pretty = result.kind === 'text'? B64Codec.tryParseJson(result.text): null;
if (pretty) {
codecState.prettyJson = pretty;
toggleBtn.style.display = '';
toggleBtn.textContent = '显示原文';
outEl.value = pretty;
} else {
outEl.value = full;
}
}

function codecOpts() {
var shift = parseInt($('caesarShift').value, 10);
return { shift: isNaN(shift) ? 3 : shift };
}

function doCodecDecode() {
var input = $('codecInput').value;
var fmt = $('formatSelect').value;
var result = fmt === 'auto'? B64Codec.smartDecode(input): B64Codec.decodeAs(input, fmt, codecOpts());
// gzip64 / deflate64 decode asynchronously — normalize with Promise.resolve
Promise.resolve(result).then(function (r) { return B64Codec.enhanceDecoded(r); }).then(function (enhanced) {
setCodecOutput(enhanced);
saveCodecHistory('decode', input, enhanced);
});
}

function doCodecEncode() {
var input = $('codecInput').value;
if (!input.trim()) {
$('codecError').textContent = '请输入要编码的文本';
return;
}
var fmt = $('formatSelect').value;
if (fmt === 'jwt') {
$('codecError').textContent = 'JWT 需要签名，请到「工具」页生成';
return;
}
var format = fmt === 'auto' ? 'base64' : fmt;
var encoded = B64Codec.encodeAs(input, format, codecOpts());
if (encoded == null) {
$('codecError').textContent = '这种格式无法直接编码';
return;
}
// gzip64 / deflate64 encode asynchronously — normalize with Promise.resolve
Promise.resolve(encoded).then(function (str) {
setCodecOutput({ ok: true, kind: 'text', text: str, encoding: 'UTF-8',
byteLength: str.length, bytes: null, format: format });
saveCodecHistory('encode', input,
{ ok: true, kind: 'text', text: str, format: format });
});
}

// Keep the encode button label in sync with the selected format.
function updateEncodeButton() {
var fmt = $('formatSelect').value;
var btn = $('encodeBtn');
btn.disabled = false;
$('caesarRow').style.display = fmt === 'caesar' ? '' : 'none';
switch (fmt) {
case 'base32': btn.textContent = '编码为 Base32'; break;
case 'base58': btn.textContent = '编码为 Base58'; break;
case 'base62': btn.textContent = '编码为 Base62'; break;
case 'base85': btn.textContent = '编码为 Base85'; break;
case 'base91': btn.textContent = '编码为 Base91'; break;
case 'base122': btn.textContent = '编码为 Base122'; break;
case 'base32768': btn.textContent = '编码为 Base32768'; break;
case 'base45': btn.textContent = '编码为 Base45'; break;
case 'qp': btn.textContent = '编码为 Quoted-Printable'; break;
case 'punycode': btn.textContent = '编码为 Punycode'; break;
case 'gzip64': btn.textContent = '编码为 gzip+Base64'; break;
case 'deflate64': btn.textContent = '编码为 deflate+Base64'; break;
case 'hex': btn.textContent = '编码为 Hex'; break;
case 'binary': btn.textContent = '编码为二进制'; break;
case 'octal': btn.textContent = '编码为八进制'; break;
case 'url': btn.textContent = '编码为 URL'; break;
case 'unicode': btn.textContent = '编码为 Unicode'; break;
case 'html': btn.textContent = '编码为 HTML 实体'; break;
case 'morse': btn.textContent = '编码为摩斯电码'; break;
case 'rot13': btn.textContent = 'ROT13 转换'; break;
case 'caesar': btn.textContent = '凯撒加密'; break;
case 'jwt': btn.textContent = 'JWT 请到工具页签名'; btn.disabled = true; break;
default: btn.textContent = '编码为 Base64';
}
}

$('formatSelect').addEventListener('change', updateEncodeButton);
updateEncodeButton();

function saveCodecHistory(mode, input, result) {
try {
if (!result ||!result.ok || result.kind === 'multiple') return;
var output = result.kind === 'jwt'
? (result.payload.json? JSON.stringify(result.payload.json): result.payload.raw)
: (result.kind === 'binary'? result.hex: result.text);
B64Store.add({ ts: Date.now(), mode: mode, format: result.format || null,
input: String(input).slice(0, 200), output: String(output || '').slice(0, 500)});
} catch (e) { /* best-effort */}
}

$('decodeBtn').addEventListener('click', doCodecDecode);
$('encodeBtn').addEventListener('click', doCodecEncode);
$('codecInput').addEventListener('keydown', function (e) {
if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') doCodecDecode();
});
$('clearBtn').addEventListener('click', function () {
$('codecInput').value = '';
$('codecOutput').value = '';
$('codecError').textContent = '';
$('codecMeta').textContent = '';
$('codecImg').style.display = 'none';
$('jsonToggleBtn').style.display = 'none';
codecState.rawText = '';
$('codecInput').focus();
});
$('copyBtn').addEventListener('click', function () {
copyValue($('codecOutput').value, this);
});
$('jsonToggleBtn').addEventListener('click', function () {
codecState.jsonPretty =!codecState.jsonPretty;
if (codecState.jsonPretty) {
$('codecOutput').value = codecState.prettyJson;
this.textContent = '显示原文';
} else {
$('codecOutput').value = codecState.rawText;
this.textContent = '格式化 JSON';
}
});

// page scan (from popup)
function activeTabId() {
return new Promise(function (resolve) {
chrome.tabs.query({ active: true, currentWindow: true}, function (tabs) {
resolve(tabs && tabs[0]? tabs[0].id: null);
});
});
}

function sendToTab(action) {
return activeTabId().then(function (tabId) {
if (tabId == null) return Promise.reject(new Error('找不到当前标签页'));
return new Promise(function (resolve, reject) {
chrome.tabs.sendMessage(tabId, { action: action}, function (res) {
if (chrome.runtime.lastError) {
chrome.scripting.executeScript(
{ target: { tabId: tabId}, files: ['codec.js', 'store.js', 'lib/qrcode.js', 'lib/jsqr.js', 'content.js']},
function () {
if (chrome.runtime.lastError) {
reject(new Error('该页面不支持（如 chrome:// 页面）'));
return;
}
chrome.tabs.sendMessage(tabId, { action: action}, function (res2) {
resolve(res2 || {});
});
});
} else {
resolve(res || {});
}
});
});
});
}

$('scanBtn').addEventListener('click', function () {
var btn = this;
$('scanStatus').textContent = '扫描中…';
sendToTab('scan-page').then(function (res) {
$('scanStatus').textContent = res.count > 0
? '已高亮 ' + res.count + ' 处，点击页面上的高亮处即可解码'
: '本页没有发现疑似编码内容';
}).catch(function (err) {
$('scanStatus').textContent = err.message;
});
});
$('clearScanBtn').addEventListener('click', function () {
sendToTab('clear-scan').then(function () {
$('scanStatus').textContent = '已清除高亮';
}).catch(function (err) {
$('scanStatus').textContent = err.message;
});
});

// ---------------- batch tab ----------------

var batchOutputs = [];

$('batchBtn').addEventListener('click', function () {
var lines = $('batchInput').value.split('\n')
.map(function (l) { return l.trim();})
.filter(function (l) { return l.length > 0;});
var box = $('batchResults');
box.innerHTML = '';
batchOutputs = [];
if (!lines.length) {
$('batchMeta').textContent = '请先输入要解码的内容，每行一条。';
return;
}
var okCount = 0;
var jobs = lines.map(function (line) {
return B64Codec.enhanceDecoded(B64Codec.smartDecode(line));
});
Promise.all(jobs).then(function (results) {
results.forEach(function (result, i) {
var row = document.createElement('div');
row.className = 'batch-row';
var no = document.createElement('span');
no.className = 'batch-no';
no.textContent = (i + 1) + '.';
var out = document.createElement('span');
out.className = 'batch-out';
if (result.ok && result.kind!== 'multiple') {
okCount++;
var text = result.kind === 'jwt'
? (result.payload.json? JSON.stringify(result.payload.json): result.payload.raw)
: (result.kind === 'binary'? result.hex: result.text);
out.textContent = truncate(text, 300);
batchOutputs.push(text);
var copy = document.createElement('button');
copy.className = 'small';
copy.textContent = '复制';
copy.addEventListener('click', function () { copyValue(text, copy);});
row.appendChild(no);
row.appendChild(out);
row.appendChild(copy);
} else {
out.className = 'batch-out err';
out.textContent = result.ok? '多处可解码，请单独处理': ('解码失败：' + result.error);
batchOutputs.push('[行 ' + (i + 1) + '] 解码失败');
row.appendChild(no);
row.appendChild(out);
}
box.appendChild(row);
});
$('batchMeta').textContent = '共 ' + lines.length + ' 行，成功 ' + okCount + ' 行，失败 ' + (lines.length - okCount) + ' 行。';
});
});
$('batchCopyBtn').addEventListener('click', function () {
copyValue(batchOutputs.join('\n'), this);
});
$('batchClearBtn').addEventListener('click', function () {
$('batchInput').value = '';
$('batchResults').innerHTML = '';
$('batchMeta').textContent = '';
batchOutputs = [];
});

// ---------------- tools tab ----------------

$('hashBtn').addEventListener('click', function () {
var text = $('hashInput').value;
$('hashMd5').value = B64Crypto.md5(text);
$('hashSha3').value = B64Crypto.sha3_256(text);
$('hashRipemd').value = B64Crypto.ripemd160(text);
$('hashSm3').value = B64Crypto.sm3(text);
$('hashCrc32').value = B64Crypto.crc32(text);
$('hashSha1').value = '计算中…';
$('hashSha256').value = '计算中…';
$('hashSha384').value = '计算中…';
$('hashSha512').value = '计算中…';
B64Crypto.shaAll(text).then(function (r) {
$('hashSha1').value = r['SHA-1'];
$('hashSha256').value = r['SHA-256'];
$('hashSha384').value = r['SHA-384'];
$('hashSha512').value = r['SHA-512'];
});
});
document.querySelectorAll('[data-copy]').forEach(function (btn) {
btn.addEventListener('click', function () {
copyValue($(btn.dataset.copy).value, btn);
});
});

$('hmacBtn').addEventListener('click', function () {
var key = $('hmacKey').value;
var msg = $('hmacInput').value;
$('hmacSha256').value = '计算中…';
$('hmacSha512').value = '计算中…';
Promise.all([
B64Crypto.hmac('SHA-256', key, msg),
B64Crypto.hmac('SHA-512', key, msg)
]).then(function (r) {
$('hmacSha256').value = r[0];
$('hmacSha512').value = r[1];
});
});

$('aesEncBtn').addEventListener('click', function () {
var pass = $('aesPass').value;
var mode = $('cipherMode').value;
$('aesError').textContent = '';
if (mode === 'RC4' || mode === 'XOR') {
try {
$('aesOutput').value = mode === 'RC4'
? B64Crypto.rc4Encrypt($('aesInput').value, pass)
: B64Crypto.xorEncrypt($('aesInput').value, pass);
} catch (err) {
$('aesError').textContent = err.message;
}
return;
}
var p;
if (mode === '3DES-ECB' || mode === '3DES-CBC') {
p = Promise.resolve(B64Crypto.tripleDesEncrypt($('aesInput').value, pass, mode.slice(5)));
} else if (mode === 'CHACHA') {
p = Promise.resolve(B64Crypto.chachaEncrypt($('aesInput').value, pass));
} else if (mode === 'SM4-ECB' || mode === 'SM4-CBC') {
p = Promise.resolve(B64Crypto.sm4Encrypt($('aesInput').value, pass, mode.slice(4)));
} else {
p = B64Crypto.aesEncrypt($('aesInput').value, pass, mode);
}
p.then(function (ct) {
$('aesOutput').value = ct;
}).catch(function (err) {
$('aesError').textContent = err.message;
});
});
$('aesDecBtn').addEventListener('click', function () {
var pass = $('aesPass').value;
var mode = $('cipherMode').value;
$('aesError').textContent = '';
if (mode === 'RC4' || mode === 'XOR') {
try {
$('aesOutput').value = mode === 'RC4'
? B64Crypto.rc4Decrypt($('aesInput').value, pass)
: B64Crypto.xorDecrypt($('aesInput').value, pass);
} catch (err) {
$('aesError').textContent = err.message;
$('aesOutput').value = '';
}
return;
}
// 解密按密文前缀自动识别算法与模式
var ct = $('aesInput').value.trim();
var dp;
if (ct.indexOf('3DES-') === 0) {
dp = Promise.resolve(B64Crypto.tripleDesDecrypt(ct, pass));
} else if (ct.indexOf('CHACHA:') === 0) {
dp = Promise.resolve(B64Crypto.chachaDecrypt(ct, pass));
} else if (ct.indexOf('SM4-') === 0) {
dp = Promise.resolve(B64Crypto.sm4Decrypt(ct, pass));
} else {
dp = B64Crypto.aesDecrypt(ct, pass);
}
dp.then(function (pt) {
$('aesOutput').value = pt;
}).catch(function (err) {
$('aesError').textContent = err.message;
$('aesOutput').value = '';
});
});
$('aesCopyBtn').addEventListener('click', function () {
copyValue($('aesOutput').value, this);
});

$('jwtSignBtn').addEventListener('click', function () {
$('jwtError').textContent = '';
$('jwtMeta').textContent = '';
var header, payload;
try {
header = JSON.parse($('jwtHeader').value);
payload = JSON.parse($('jwtPayload').value || '{}');
} catch (e) {
$('jwtError').textContent = 'Header / Payload 不是合法的 JSON';
return;
}
B64Crypto.jwtSign(header, payload, $('jwtSecret').value).then(function (token) {
$('jwtOutput').value = token;
$('jwtMeta').textContent = '已用 HS256 签名';
}).catch(function (err) {
$('jwtError').textContent = err.message;
});
});
$('jwtVerifyBtn').addEventListener('click', function () {
$('jwtError').textContent = '';
$('jwtMeta').textContent = '';
B64Crypto.jwtVerify($('jwtOutput').value, $('jwtSecret').value).then(function (r) {
var meta = r.valid ? '签名有效 ✓' : '签名无效 ✗（密钥不对或 Token 被改过）';
if (r.payload) meta += ' · Payload: ' + truncate(JSON.stringify(r.payload), 200);
$('jwtMeta').textContent = meta;
}).catch(function (err) {
$('jwtError').textContent = err.message;
});
});
$('jwtCopyBtn').addEventListener('click', function () {
copyValue($('jwtOutput').value, this);
});

$('uuidBtn').addEventListener('click', function () {
$('uuidOut').value = B64Crypto.uuidv4();
});
$('pwBtn').addEventListener('click', function () {
$('pwOut').value = B64Crypto.generatePassword($('pwLen').value,
{ symbols: $('pwSymbols').checked });
});

function renderTsResult(r) {
if (!r.ok) {
$('tsError').textContent = r.error;
$('tsMeta').textContent = '';
$('tsSeconds').value = '';
$('tsMs').value = '';
$('tsIso').value = '';
$('tsLocal').value = '';
return;
}
$('tsError').textContent = '';
$('tsMeta').textContent = '已转换';
$('tsSeconds').value = String(r.seconds);
$('tsMs').value = String(r.ms);
$('tsIso').value = r.iso;
$('tsLocal').value = r.local;
}
$('tsToDateBtn').addEventListener('click', function () {
renderTsResult(B64Crypto.timestampToDate($('tsInput').value));
});
$('dateToTsBtn').addEventListener('click', function () {
renderTsResult(B64Crypto.dateToTimestamp($('tsInput').value));
});

// ---------------- history tab ----------------

function renderHistory() {
var q = $('histSearch').value.trim().toLowerCase();
var fmtFilter = $('histFilter').value;
B64Store.list().then(function (list) {
var box = $('histList');
box.innerHTML = '';
var filtered = list.filter(function (e) {
if (fmtFilter && e.format !== fmtFilter) return false;
if (q && (e.input + '\n' + e.output).toLowerCase().indexOf(q) === -1) return false;
return true;
});
// favorites (pinned) first, otherwise newest first (storage order)
filtered.sort(function (a, b) { return (b.fav ? 1 : 0) - (a.fav ? 1 : 0); });
if (!filtered.length) {
var empty = document.createElement('div');
empty.className = 'empty';
empty.textContent = q? '没有匹配的历史记录': '暂无历史记录，解码或编码后会自动保存在这里';
box.appendChild(empty);
return;
}
filtered.forEach(function (entry) {
var item = document.createElement('div');
item.className = 'hist-item';
var head = document.createElement('div');
head.className = 'hist-head';
var left = document.createElement('span');
var badge = document.createElement('span');
badge.className = 'hist-badge';
badge.textContent = (entry.mode === 'encode'? '编码': '解码') +
(entry.format? ' · ' + (B64Codec.FORMAT_LABELS[entry.format] || entry.format): '');
left.appendChild(badge);
left.appendChild(document.createTextNode(' ' + new Date(entry.ts).toLocaleString('zh-CN')));
var del = document.createElement('button');
del.className = 'small danger';
del.textContent = '删除';
del.addEventListener('click', function () {
B64Store.remove(entry.ts).then(renderHistory);
});
var fav = document.createElement('button');
fav.className = 'small' + (entry.fav ? ' fav-on' : '');
fav.textContent = entry.fav ? '★ 已收藏' : '☆ 收藏';
fav.addEventListener('click', function () {
B64Store.toggleFav(entry.ts).then(renderHistory);
});
head.appendChild(left);
head.appendChild(fav);
head.appendChild(del);
item.appendChild(head);
var inputEl = document.createElement('div');
inputEl.className = 'hist-text dim';
inputEl.textContent = '入：' + truncate(entry.input, 200);
item.appendChild(inputEl);
var outEl = document.createElement('div');
outEl.className = 'hist-text';
outEl.textContent = '出：' + truncate(entry.output, 300);
item.appendChild(outEl);
var row = document.createElement('div');
row.className = 'row';
row.style.margin = '4px 0 0';
var copy = document.createElement('button');
copy.className = 'small';
copy.textContent = '复制结果';
copy.addEventListener('click', function () { copyValue(entry.output, copy);});
var reuse = document.createElement('button');
reuse.className = 'small';
reuse.textContent = '填入编解码';
reuse.addEventListener('click', function () {
$('codecInput').value = entry.input;
document.querySelector('[data-tab="codec"]').click();
$('codecInput').focus();
});
row.appendChild(copy);
row.appendChild(reuse);
item.appendChild(row);
box.appendChild(item);
});
});
}

$('histSearch').addEventListener('input', renderHistory);
$('histClearBtn').addEventListener('click', function () {
B64Store.clear().then(renderHistory);
});

$('codecInput').focus();

// ---------------- QR code (codec tab) ----------------

var qrDataUrl = null;

$('qrGenBtn').addEventListener('click', function () {
  var text = $('codecOutput').value || $('codecInput').value;
  var status = $('qrStatus');
  var img = $('qrImg');
  if (!text) {
    status.textContent = '没有可生成二维码的内容（先解码/编码，或在输入框里粘贴文本）';
    return;
  }
  if (typeof qrcode === 'undefined') {
    status.textContent = '二维码库未加载';
    return;
  }
  try {
    // qrcode-generator defaults to a latin1 byte conversion; switch to
    // its built-in UTF-8 encoder first, otherwise Chinese text breaks.
    if (qrcode.stringToBytesFuncs && qrcode.stringToBytesFuncs['UTF-8']) {
      qrcode.stringToBytes = qrcode.stringToBytesFuncs['UTF-8'];
    }
    var qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    qrDataUrl = qr.createDataURL(4, 8);
    img.src = qrDataUrl;
    img.style.display = 'block';
    $('qrDlRow').style.display = '';
    status.textContent = '已生成二维码（' + text.length + ' 字符）';
  } catch (err) {
    status.textContent = '生成失败：' + err.message;
  }
});

$('qrDlBtn').addEventListener('click', function () {
  if (!qrDataUrl) return;
  var a = document.createElement('a');
  a.href = qrDataUrl;
  a.download = 'snapdecode-qrcode.gif'; // qrcode-generator renders GIF data URLs
  document.body.appendChild(a);
  a.click();
  a.remove();
});

$('qrScanBtn').addEventListener('click', function () {
  $('qrStatus').textContent = '正在识别页面图片里的二维码…';
  sendToTab('scan-qr').then(function (res) {
    $('qrStatus').textContent = res.count > 0
      ? '已在页面图片里识别出 ' + res.count + ' 个二维码，结果显示在页面上'
      : '页面图片里没有识别出二维码' + (res.skipped ? '（' + res.skipped + ' 张图片因跨域无法读取）' : '');
  }).catch(function (err) {
    $('qrStatus').textContent = err.message;
  });
});

// ---------------- clipboard auto-decode on popup open ----------------

(function clipboardAutoDecode() {
  if (!navigator.clipboard || !navigator.clipboard.readText) return;
  navigator.clipboard.readText().then(function (text) {
    if (!text || !text.trim()) return;
    if ($('codecInput').value) return;
    // looksEncoded needs a 16+ char token; also accept short Base64 with
    // '=' padding (e.g. 'aGVsbG8=') — plain words have no padding, and
    // detectFormat alone is too eager ('helloworld' would match base64).
    var t = text.trim();
    var shortB64 = /=+$/.test(t) && B64Codec.detectFormat(t) === 'base64';
    if (!B64Codec.looksEncoded(text) && !shortB64) return;
    $('codecInput').value = text;
    $('clipNote').textContent = '已从剪贴板自动填入并解码';
    doCodecDecode();
  }).catch(function () { /* clipboard permission denied or empty — ignore */ });
})();

// ---------------- file hash (tools tab) ----------------

function fillHashRows(r) {
  $('hashMd5').value = r['MD5'] || '';
  $('hashSha1').value = r['SHA-1'] || '';
  $('hashSha256').value = r['SHA-256'] || '';
  $('hashSha384').value = r['SHA-384'] || '';
  $('hashSha512').value = r['SHA-512'] || '';
  $('hashSha3').value = r['SHA3-256'] || '';
  $('hashRipemd').value = r['RIPEMD-160'] || '';
  $('hashSm3').value = r['SM3'] || '';
  $('hashCrc32').value = r['CRC32'] || '';
}

function handleHashFile(file) {
  if (!file) return;
  $('fileMeta').textContent = '正在计算：' + file.name + '（' + file.size + ' 字节）…';
  file.arrayBuffer().then(function (buf) {
    return B64Crypto.hashAllBytes(new Uint8Array(buf));
  }).then(function (r) {
    fillHashRows(r);
    $('fileMeta').textContent = '已计算：' + file.name + '（' + file.size + ' 字节），结果已填入上方哈希栏';
  }).catch(function (err) {
    $('fileMeta').textContent = '计算失败：' + err.message;
  });
}

$('fileDrop').addEventListener('click', function () { $('fileInput').click(); });
$('fileInput').addEventListener('change', function () {
  handleHashFile(this.files && this.files[0]);
  this.value = '';
});
['dragenter', 'dragover'].forEach(function (ev) {
  $('fileDrop').addEventListener(ev, function (e) {
    e.preventDefault();
    $('fileDrop').classList.add('over');
  });
});
['dragleave', 'drop'].forEach(function (ev) {
  $('fileDrop').addEventListener(ev, function (e) {
    e.preventDefault();
    $('fileDrop').classList.remove('over');
  });
});
$('fileDrop').addEventListener('drop', function (e) {
  var files = e.dataTransfer && e.dataTransfer.files;
  if (files && files.length) handleHashFile(files[0]);
});

// ---------------- RSA / ECDSA / SM2 (tools tab) ----------------

$('rsaGenBtn').addEventListener('click', function () {
  $('rsaError').textContent = '';
  B64Crypto.rsaGenerateKeyPair().then(function (kp) {
    $('rsaPub').value = kp.publicKeyPem;
    $('rsaPriv').value = kp.privateKeyPem;
  }).catch(function (err) { $('rsaError').textContent = err.message; });
});
$('rsaEncBtn').addEventListener('click', function () {
  $('rsaError').textContent = '';
  B64Crypto.rsaEncrypt($('rsaPub').value, $('rsaInput').value).then(function (ct) {
    $('rsaOutput').value = ct;
  }).catch(function (err) { $('rsaError').textContent = err.message; });
});
$('rsaDecBtn').addEventListener('click', function () {
  $('rsaError').textContent = '';
  B64Crypto.rsaDecrypt($('rsaPriv').value, $('rsaInput').value).then(function (pt) {
    $('rsaOutput').value = pt;
  }).catch(function (err) { $('rsaError').textContent = err.message; $('rsaOutput').value = ''; });
});
$('rsaCopyBtn').addEventListener('click', function () {
  copyValue($('rsaOutput').value, this);
});

$('ecdsaGenBtn').addEventListener('click', function () {
  $('ecdsaError').textContent = '';
  B64Crypto.ecdsaGenerateKeyPair().then(function (kp) {
    $('ecdsaPub').value = kp.publicKeyPem;
    $('ecdsaPriv').value = kp.privateKeyPem;
  }).catch(function (err) { $('ecdsaError').textContent = err.message; });
});
$('ecdsaSignBtn').addEventListener('click', function () {
  $('ecdsaError').textContent = '';
  $('ecdsaMeta').textContent = '';
  B64Crypto.ecdsaSign($('ecdsaPriv').value, $('ecdsaInput').value).then(function (sig) {
    $('ecdsaOutput').value = sig;
    $('ecdsaMeta').textContent = '已用 ECDSA P-256 签名';
  }).catch(function (err) { $('ecdsaError').textContent = err.message; });
});
$('ecdsaVerifyBtn').addEventListener('click', function () {
  $('ecdsaError').textContent = '';
  $('ecdsaMeta').textContent = '';
  B64Crypto.ecdsaVerify($('ecdsaPub').value, $('ecdsaInput').value, $('ecdsaOutput').value).then(function (ok) {
    $('ecdsaMeta').textContent = ok ? '签名有效 ✓' : '签名无效 ✗（公钥不对、消息被改过或签名有误）';
  }).catch(function (err) { $('ecdsaError').textContent = err.message; });
});
$('ecdsaCopyBtn').addEventListener('click', function () {
  copyValue($('ecdsaOutput').value, this);
});

$('sm2GenBtn').addEventListener('click', function () {
  $('sm2Error').textContent = '';
  try {
    var kp = B64Crypto.sm2GenerateKeyPair();
    $('sm2Pub').value = kp.publicKeyHex;
    $('sm2Priv').value = kp.privateKeyHex;
  } catch (err) { $('sm2Error').textContent = err.message; }
});
function sm2Run(fn) {
  $('sm2Error').textContent = '';
  $('sm2Meta').textContent = '';
  try {
    return fn();
  } catch (err) {
    $('sm2Error').textContent = err.message;
    return null;
  }
}
$('sm2EncBtn').addEventListener('click', function () {
  var out = sm2Run(function () {
    return B64Crypto.sm2Encrypt($('sm2Pub').value, $('sm2Input').value);
  });
  if (out != null) $('sm2Output').value = out;
});
$('sm2DecBtn').addEventListener('click', function () {
  var out = sm2Run(function () {
    return B64Crypto.sm2Decrypt($('sm2Priv').value, $('sm2Input').value);
  });
  if (out != null) $('sm2Output').value = out; else $('sm2Output').value = '';
});
$('sm2SignBtn').addEventListener('click', function () {
  var out = sm2Run(function () {
    return B64Crypto.sm2Sign($('sm2Priv').value, $('sm2Input').value);
  });
  if (out != null) {
    $('sm2Output').value = out;
    $('sm2Meta').textContent = '已用 SM2 签名（默认用户 ID）';
  }
});
$('sm2VerifyBtn').addEventListener('click', function () {
  var ok = sm2Run(function () {
    return B64Crypto.sm2Verify($('sm2Pub').value, $('sm2Input').value, $('sm2Output').value);
  });
  if (ok != null) {
    $('sm2Meta').textContent = ok ? '签名有效 ✓' : '签名无效 ✗（公钥不对、消息被改过或签名有误）';
  }
});
$('sm2CopyBtn').addEventListener('click', function () {
  copyValue($('sm2Output').value, this);
});

// ---------------- dev tools tab ----------------

// --- JSON ---
function parseJsonInput() {
  var text = $('jsonInput').value;
  if (!text.trim()) {
    $('jsonError').textContent = '请先粘贴 JSON';
    return null;
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    $('jsonError').textContent = 'JSON 解析失败：' + e.message;
    return null;
  }
}
$('jsonFormatBtn').addEventListener('click', function () {
  $('jsonError').textContent = '';
  $('jsonMeta').textContent = '';
  var v = parseJsonInput();
  if (v === null && $('jsonError').textContent) return;
  $('jsonOutput').value = JSON.stringify(v, null, 2);
  $('jsonMeta').textContent = '已格式化';
});
$('jsonMinifyBtn').addEventListener('click', function () {
  $('jsonError').textContent = '';
  $('jsonMeta').textContent = '';
  var v = parseJsonInput();
  if (v === null && $('jsonError').textContent) return;
  $('jsonOutput').value = JSON.stringify(v);
  $('jsonMeta').textContent = '已压缩';
});
$('jsonValidateBtn').addEventListener('click', function () {
  $('jsonError').textContent = '';
  var v = parseJsonInput();
  if (v === null && $('jsonError').textContent) return;
  var kind = Array.isArray(v) ? '数组（' + v.length + ' 项）' : (v && typeof v === 'object' ? '对象（' + Object.keys(v).length + ' 个键）' : typeof v);
  $('jsonMeta').textContent = '合法的 JSON · ' + kind;
  $('jsonOutput').value = JSON.stringify(v, null, 2);
});
function yamlScalar(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  var s = String(v);
  if (s === '' || /[:#\n]|^\s|\s$|^(true|false|null|~|[-+]?\d+(\.\d+)?)$/i.test(s) || /["'\\]/.test(s)) {
    return JSON.stringify(s);
  }
  return s;
}
function jsonToYaml(v, indent) {
  indent = indent || 0;
  var pad = new Array(indent + 1).join('  ');
  if (Array.isArray(v)) {
    if (v.length === 0) return '[]';
    var lines = [];
    v.forEach(function (item) {
      if (item && typeof item === 'object') {
        var sub = jsonToYaml(item, indent + 1);
        var subLines = sub.split('\n');
        lines.push(pad + '- ' + subLines[0].slice(pad.length + 2));
        for (var i = 1; i < subLines.length; i++) {
          lines.push(pad + '  ' + subLines[i].slice(pad.length + 2));
        }
      } else {
        lines.push(pad + '- ' + yamlScalar(item));
      }
    });
    return lines.join('\n');
  }
  if (v && typeof v === 'object') {
    var keys = Object.keys(v);
    if (keys.length === 0) return '{}';
    return keys.map(function (k) {
      var val = v[k];
      if (val && typeof val === 'object') {
        if (Array.isArray(val) && val.length === 0) return pad + yamlScalar(k) + ': []';
        if (!Array.isArray(val) && Object.keys(val).length === 0) return pad + yamlScalar(k) + ': {}';
        return pad + yamlScalar(k) + ':\n' + jsonToYaml(val, indent + 1);
      }
      return pad + yamlScalar(k) + ': ' + yamlScalar(val);
    }).join('\n');
  }
  return yamlScalar(v);
}
$('jsonYamlBtn').addEventListener('click', function () {
  $('jsonError').textContent = '';
  $('jsonMeta').textContent = '';
  var v = parseJsonInput();
  if (v === null && $('jsonError').textContent) return;
  $('jsonOutput').value = jsonToYaml(v, 0);
  $('jsonMeta').textContent = '已转为 YAML';
});
$('jsonCopyBtn').addEventListener('click', function () {
  copyValue($('jsonOutput').value, this);
});

// --- URL params ---
var urlBase = '';
var urlHash = '';

function addParamRow(key, value) {
  var tbody = $('urlParamsBody');
  var tr = document.createElement('tr');
  var tdK = document.createElement('td');
  var inputK = document.createElement('input');
  inputK.type = 'text';
  inputK.value = key || '';
  inputK.placeholder = '参数名';
  tdK.appendChild(inputK);
  var tdV = document.createElement('td');
  var inputV = document.createElement('input');
  inputV.type = 'text';
  inputV.value = value || '';
  inputV.placeholder = '参数值';
  tdV.appendChild(inputV);
  var tdD = document.createElement('td');
  tdD.className = 'del';
  tdD.textContent = '✕';
  tdD.title = '删除这一行';
  tdD.addEventListener('click', function () { tr.remove(); });
  tr.appendChild(tdK);
  tr.appendChild(tdV);
  tr.appendChild(tdD);
  tbody.appendChild(tr);
  $('urlParamsTable').style.display = '';
}

$('urlParseBtn').addEventListener('click', function () {
  $('urlError').textContent = '';
  var raw = $('urlInput').value.trim();
  if (!raw) {
    $('urlError').textContent = '请先粘贴 URL';
    return;
  }
  var u;
  try {
    u = new URL(raw);
  } catch (e) {
    try {
      u = new URL('https://' + raw);
    } catch (e2) {
      $('urlError').textContent = '无法解析这个 URL';
      return;
    }
  }
  urlBase = u.origin + u.pathname;
  urlHash = u.hash || '';
  $('urlParamsBody').innerHTML = '';
  var count = 0;
  u.searchParams.forEach(function (value, key) {
    addParamRow(key, value);
    count++;
  });
  if (count === 0) {
    $('urlError').textContent = '这个 URL 没有查询参数（? 后面是空的）';
    $('urlParamsTable').style.display = 'none';
    return;
  }
  $('urlOutput').value = '';
});

$('urlAddParamBtn').addEventListener('click', function () {
  addParamRow('', '');
});

$('urlBuildBtn').addEventListener('click', function () {
  $('urlError').textContent = '';
  if (!urlBase) {
    $('urlError').textContent = '请先解析一个 URL';
    return;
  }
  var rows = $('urlParamsBody').querySelectorAll('tr');
  var parts = [];
  rows.forEach(function (tr) {
    var inputs = tr.querySelectorAll('input');
    var k = inputs[0].value.trim();
    var v = inputs[1].value;
    if (!k) return;
    parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
  });
  $('urlOutput').value = urlBase + (parts.length ? '?' + parts.join('&') : '') + urlHash;
});
$('urlCopyBtn').addEventListener('click', function () {
  copyValue($('urlOutput').value, this);
});

// --- regex ---
function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
$('reTestBtn').addEventListener('click', function () {
  $('reError').textContent = '';
  $('reMeta').textContent = '';
  var pattern = $('rePattern').value;
  var flags = $('reFlags').value || '';
  var text = $('reText').value;
  if (!pattern) {
    $('reError').textContent = '请先填写正则表达式';
    return;
  }
  var re;
  try {
    re = new RegExp(pattern, flags);
  } catch (e) {
    $('reError').textContent = '正则表达式无效：' + e.message;
    return;
  }
  var matches = [];
  if (re.global) {
    var m;
    re.lastIndex = 0;
    while ((m = re.exec(text)) !== null) {
      matches.push({ index: m.index, text: m[0] });
      if (m[0] === '') re.lastIndex++;
      if (matches.length > 500) break;
    }
  } else {
    var single = re.exec(text);
    if (single) matches.push({ index: single.index, text: single[0] });
  }
  if (!matches.length) {
    $('reMeta').textContent = '没有匹配到任何内容';
    $('reOutput').textContent = text;
    return;
  }
  var html = '';
  var pos = 0;
  matches.forEach(function (mt) {
    html += escapeHtml(text.slice(pos, mt.index));
    html += '<mark>' + escapeHtml(mt.text) + '</mark>';
    pos = mt.index + mt.text.length;
  });
  html += escapeHtml(text.slice(pos));
  $('reOutput').innerHTML = html;
  $('reMeta').textContent = '共匹配 ' + matches.length + ' 处' + (matches.length >= 500 ? '（仅显示前 500 处）' : '');
});

// --- diff ---
function lineDiff(aLines, bLines) {
  var m = aLines.length;
  var n = bLines.length;
  // LCS dynamic programming table
  var dp = [];
  for (var i = 0; i <= m; i++) {
    dp.push(new Array(n + 1).fill(0));
  }
  for (var i = m - 1; i >= 0; i--) {
    for (var j = n - 1; j >= 0; j--) {
      dp[i][j] = aLines[i] === bLines[j]
        ? dp[i + 1][j + 1] + 1
        : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  var ops = [];
  var x = 0, y = 0;
  while (x < m && y < n) {
    if (aLines[x] === bLines[y]) {
      ops.push({ type: 'same', text: aLines[x] });
      x++; y++;
    } else if (dp[x + 1][y] >= dp[x][y + 1]) {
      ops.push({ type: 'del', text: aLines[x] });
      x++;
    } else {
      ops.push({ type: 'add', text: bLines[y] });
      y++;
    }
  }
  while (x < m) { ops.push({ type: 'del', text: aLines[x] }); x++; }
  while (y < n) { ops.push({ type: 'add', text: bLines[y] }); y++; }
  return ops;
}
$('diffBtn').addEventListener('click', function () {
  var a = $('diffA').value.split('\n');
  var b = $('diffB').value.split('\n');
  var box = $('diffOutput');
  box.innerHTML = '';
  if (a.length > 500 || b.length > 500) {
    $('diffMeta').textContent = '行数太多（每侧最多 500 行），请缩短后再对比';
    return;
  }
  var ops = lineDiff(a, b);
  var adds = 0, dels = 0;
  ops.forEach(function (op) {
    var span = document.createElement('span');
    if (op.type === 'del') {
      span.className = 'diff-del';
      span.textContent = '- ' + op.text;
      dels++;
    } else if (op.type === 'add') {
      span.className = 'diff-add';
      span.textContent = '+ ' + op.text;
      adds++;
    } else {
      span.className = 'diff-same';
      span.textContent = '  ' + op.text;
    }
    box.appendChild(span);
  });
  $('diffMeta').textContent = adds === 0 && dels === 0
    ? '两段文本完全相同'
    : '新增 ' + adds + ' 行，删除 ' + dels + ' 行';
});

// ---------------- codec chain tab ----------------

var CHAIN_FORMATS = ['base64', 'base32', 'base58', 'base62', 'base85', 'base91',
  'base122', 'base32768', 'base45', 'qp', 'punycode', 'gzip64', 'deflate64',
  'hex', 'binary', 'octal', 'url', 'unicode', 'html', 'morse', 'rot13', 'caesar'];
var chainSteps = [];

function renderChainSteps() {
  var box = $('chainSteps');
  box.innerHTML = '';
  if (!chainSteps.length) {
    var empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = '还没有步骤，点「添加步骤」开始（建议从 URL 解码、Base64 解码这类开始）';
    box.appendChild(empty);
    return;
  }
  chainSteps.forEach(function (step, idx) {
    var row = document.createElement('div');
    row.className = 'chain-step';
    var no = document.createElement('span');
    no.className = 'step-no';
    no.textContent = (idx + 1) + '.';
    var fmtSel = document.createElement('select');
    CHAIN_FORMATS.forEach(function (f) {
      var opt = document.createElement('option');
      opt.value = f;
      opt.textContent = B64Codec.FORMAT_LABELS[f] || f;
      if (f === step.format) opt.selected = true;
      fmtSel.appendChild(opt);
    });
    fmtSel.addEventListener('change', function () { step.format = fmtSel.value; });
    var arrow = document.createElement('span');
    arrow.className = 'arrow';
    arrow.textContent = '→';
    var dirSel = document.createElement('select');
    [['decode', '解码'], ['encode', '编码']].forEach(function (d) {
      var opt = document.createElement('option');
      opt.value = d[0];
      opt.textContent = d[1];
      if (d[0] === step.dir) opt.selected = true;
      dirSel.appendChild(opt);
    });
    dirSel.addEventListener('change', function () { step.dir = dirSel.value; });
    var up = document.createElement('button');
    up.className = 'small';
    up.textContent = '↑';
    up.disabled = idx === 0;
    up.title = '上移';
    up.addEventListener('click', function () {
      var t = chainSteps[idx - 1];
      chainSteps[idx - 1] = chainSteps[idx];
      chainSteps[idx] = t;
      renderChainSteps();
    });
    var down = document.createElement('button');
    down.className = 'small';
    down.textContent = '↓';
    down.disabled = idx === chainSteps.length - 1;
    down.title = '下移';
    down.addEventListener('click', function () {
      var t = chainSteps[idx + 1];
      chainSteps[idx + 1] = chainSteps[idx];
      chainSteps[idx] = t;
      renderChainSteps();
    });
    var del = document.createElement('button');
    del.className = 'small danger';
    del.textContent = '✕';
    del.title = '删除这一步';
    del.addEventListener('click', function () {
      chainSteps.splice(idx, 1);
      renderChainSteps();
    });
    row.appendChild(no);
    row.appendChild(fmtSel);
    row.appendChild(arrow);
    row.appendChild(dirSel);
    row.appendChild(up);
    row.appendChild(down);
    row.appendChild(del);
    box.appendChild(row);
  });
}

$('chainAddBtn').addEventListener('click', function () {
  chainSteps.push({ format: 'base64', dir: 'decode' });
  renderChainSteps();
});
$('chainClearBtn').addEventListener('click', function () {
  chainSteps = [];
  renderChainSteps();
  $('chainOutput').value = '';
  $('chainMeta').textContent = '';
  $('chainError').textContent = '';
});

$('chainRunBtn').addEventListener('click', function () {
  var input = $('chainInput').value;
  $('chainError').textContent = '';
  $('chainMeta').textContent = '';
  if (!chainSteps.length) {
    $('chainError').textContent = '请先添加至少一个步骤';
    return;
  }
  if (!input) {
    $('chainError').textContent = '请先粘贴要处理的文本';
    return;
  }
  var cur = input;
  var chain = Promise.resolve();
  chainSteps.forEach(function (step, idx) {
    chain = chain.then(function () {
      var label = (B64Codec.FORMAT_LABELS[step.format] || step.format) +
        (step.dir === 'decode' ? '解码' : '编码');
      if (step.dir === 'decode') {
        return Promise.resolve(B64Codec.decodeAs(cur, step.format)).then(function (r) {
          if (!r.ok) throw new Error('第 ' + (idx + 1) + ' 步（' + label + '）失败：' + r.error);
          cur = r.kind === 'binary' ? r.hex : r.text;
        });
      }
      return Promise.resolve(B64Codec.encodeAs(cur, step.format)).then(function (enc) {
        if (enc == null) throw new Error('第 ' + (idx + 1) + ' 步（' + label + '）无法编码');
        cur = enc;
      });
    });
  });
  chain.then(function () {
    $('chainOutput').value = cur;
    $('chainMeta').textContent = '已执行 ' + chainSteps.length + ' 步';
  }).catch(function (err) {
    $('chainError').textContent = err.message;
  });
});
$('chainCopyBtn').addEventListener('click', function () {
  copyValue($('chainOutput').value, this);
});

function refreshRecipeSelect() {
  B64Store.listRecipes().then(function (list) {
    var sel = $('recipeSelect');
    sel.innerHTML = '';
    var first = document.createElement('option');
    first.value = '';
    first.textContent = list.length ? '选择已保存的配方…' : '暂无已保存的配方';
    sel.appendChild(first);
    list.forEach(function (r) {
      var opt = document.createElement('option');
      opt.value = r.name;
      opt.textContent = r.name + '（' + r.steps.length + ' 步）';
      sel.appendChild(opt);
    });
  });
}

$('recipeSaveBtn').addEventListener('click', function () {
  var name = $('recipeName').value.trim();
  if (!name) {
    $('chainError').textContent = '请先填写配方名称';
    return;
  }
  if (!chainSteps.length) {
    $('chainError').textContent = '当前没有步骤可保存';
    return;
  }
  $('chainError').textContent = '';
  B64Store.saveRecipe({
    name: name,
    steps: chainSteps.map(function (s) { return { format: s.format, dir: s.dir }; }),
    ts: Date.now()
  }).then(function () {
    $('chainMeta').textContent = '配方「' + name + '」已保存';
    $('recipeName').value = '';
    refreshRecipeSelect();
  });
});
$('recipeLoadBtn').addEventListener('click', function () {
  var name = $('recipeSelect').value;
  if (!name) {
    $('chainError').textContent = '请先选择一个配方';
    return;
  }
  B64Store.listRecipes().then(function (list) {
    for (var i = 0; i < list.length; i++) {
      if (list[i].name === name) {
        chainSteps = list[i].steps.map(function (s) { return { format: s.format, dir: s.dir }; });
        renderChainSteps();
        $('chainError').textContent = '';
        $('chainMeta').textContent = '已加载配方「' + name + '」';
        return;
      }
    }
    $('chainError').textContent = '找不到这个配方';
  });
});
$('recipeDelBtn').addEventListener('click', function () {
  var name = $('recipeSelect').value;
  if (!name) {
    $('chainError').textContent = '请先选择一个配方';
    return;
  }
  B64Store.removeRecipe(name).then(function () {
    $('chainMeta').textContent = '已删除配方「' + name + '」';
    refreshRecipeSelect();
  });
});

document.querySelectorAll('.tab-btn').forEach(function (btn) {
  btn.addEventListener('click', function () {
    if (btn.dataset.tab === 'chain') refreshRecipeSelect();
  });
});
renderChainSteps();
refreshRecipeSelect();

// ---------------- history filter & export ----------------

(function initHistFilter() {
  var sel = $('histFilter');
  Object.keys(B64Codec.FORMAT_LABELS).forEach(function (f) {
    var opt = document.createElement('option');
    opt.value = f;
    opt.textContent = B64Codec.FORMAT_LABELS[f];
    sel.appendChild(opt);
  });
  sel.addEventListener('change', renderHistory);
})();

function downloadTextFile(filename, text) {
  var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
}
$('histExportJsonBtn').addEventListener('click', function () {
  B64Store.list().then(function (list) {
    downloadTextFile('snapdecode-history.json', JSON.stringify(list, null, 2));
  });
});
$('histExportTextBtn').addEventListener('click', function () {
  B64Store.list().then(function (list) {
    var lines = [];
    list.forEach(function (e) {
      lines.push('[' + new Date(e.ts).toLocaleString('zh-CN') + '] ' +
        (e.mode === 'encode' ? '编码' : '解码') +
        (e.format ? ' · ' + (B64Codec.FORMAT_LABELS[e.format] || e.format) : '') +
        (e.fav ? ' ★' : ''));
      lines.push('入：' + e.input);
      lines.push('出：' + e.output);
      lines.push('---');
    });
    downloadTextFile('snapdecode-history.txt', lines.join('\n'));
  });
});
$('histFilter').addEventListener('change', renderHistory);
