// Popup logic v2: tabbed tool — codec (decode/encode + page scan),
// batch decode, hash/AES tools, local history.
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
parts.push('\n' + result.signature + '\n（签名无法在此验证，验证需要密钥）');
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

function doCodecDecode() {
var input = $('codecInput').value;
var fmt = $('formatSelect').value;
var result = fmt === 'auto'? B64Codec.smartDecode(input): B64Codec.decodeAs(input, fmt);
B64Codec.enhanceDecoded(result).then(function (enhanced) {
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
var encoded, format;
switch (fmt) {
case 'hex': encoded = B64Codec.encodeHex(input); format = 'hex'; break;
case 'url': encoded = B64Codec.encodeUrl(input); format = 'url'; break;
case 'unicode': encoded = B64Codec.encodeUnicode(input); format = 'unicode'; break;
case 'jwt':
$('codecError').textContent = 'JWT 需要签名，无法直接编码';
return;
default: encoded = B64Codec.encodeBase64(input); format = 'base64';
}
setCodecOutput({ ok: true, kind: 'text', text: encoded, encoding: 'UTF-8',
byteLength: encoded.length, bytes: null, format: format });
saveCodecHistory('encode', input,
{ ok: true, kind: 'text', text: encoded, format: format });
}

// Keep the encode button label in sync with the selected format.
function updateEncodeButton() {
var fmt = $('formatSelect').value;
var btn = $('encodeBtn');
btn.disabled = false;
switch (fmt) {
case 'hex': btn.textContent = '编码为 Hex'; break;
case 'url': btn.textContent = '编码为 URL'; break;
case 'unicode': btn.textContent = '编码为 Unicode'; break;
case 'jwt': btn.textContent = 'JWT 无法编码'; btn.disabled = true; break;
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
{ target: { tabId: tabId}, files: ['codec.js', 'store.js', 'content.js']},
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
$('hashSha1').value = '计算中…';
$('hashSha256').value = '计算中…';
$('hashSha512').value = '计算中…';
B64Crypto.shaAll(text).then(function (r) {
$('hashSha1').value = r['SHA-1'];
$('hashSha256').value = r['SHA-256'];
$('hashSha512').value = r['SHA-512'];
});
});
document.querySelectorAll('[data-copy]').forEach(function (btn) {
btn.addEventListener('click', function () {
copyValue($(btn.dataset.copy).value, btn);
});
});

$('aesEncBtn').addEventListener('click', function () {
var pass = $('aesPass').value;
$('aesError').textContent = '';
B64Crypto.aesEncrypt($('aesInput').value, pass).then(function (ct) {
$('aesOutput').value = ct;
}).catch(function (err) {
$('aesError').textContent = err.message;
});
});
$('aesDecBtn').addEventListener('click', function () {
var pass = $('aesPass').value;
$('aesError').textContent = '';
B64Crypto.aesDecrypt($('aesInput').value, pass).then(function (pt) {
$('aesOutput').value = pt;
}).catch(function (err) {
$('aesError').textContent = err.message;
$('aesOutput').value = '';
});
});
$('aesCopyBtn').addEventListener('click', function () {
copyValue($('aesOutput').value, this);
});

// ---------------- history tab ----------------

function renderHistory() {
var q = $('histSearch').value.trim().toLowerCase();
B64Store.list().then(function (list) {
var box = $('histList');
box.innerHTML = '';
var filtered = q
? list.filter(function (e) {
return (e.input + '\n' + e.output).toLowerCase().indexOf(q)!== -1;
})
: list;
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
head.appendChild(left);
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
