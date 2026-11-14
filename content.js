// Content script v2: smart decode / encode of the current selection with a
// floating result panel (Shadow DOM), a floating decode/encode button that
// appears next to a selection, and a page scanner that highlights encoded
// tokens. Successful decodes are saved to local history (B64Store).
(function () {
  'use strict';
  if (window.__b64d_installed) return;
  window.__b64d_installed = true;

  var PANEL_HOST_ID = 'b64d-panel-host';
  var FLOAT_HOST_ID = 'b64d-float-host';
  var TOAST_HOST_ID = 'b64d-toast-host';
  var SCAN_STYLE_ID = 'b64d-scan-style';
  var MAX_DISPLAY = 10000;
  var MAX_HISTORY_TEXT = 500;

  var session = null; // { mode, input, format, result, stack, jsonPretty, imageUrl }
  var floatTimer = null;

  // ---------------- messaging ----------------

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (!msg) return;
    if (msg.action === 'decode-selection') {
      hideFloat();
      var sel = currentSelectionText();
      runDecode(sel, getSelectionRect());
      sendResponse({ received: true });
    } else if (msg.action === 'encode-selection') {
      hideFloat();
      var sel2 = currentSelectionText();
      runEncode(sel2, getSelectionRect());
      sendResponse({ received: true });
    } else if (msg.action === 'scan-page') {
      var n = scanPage();
      sendResponse({ received: true, count: n });
    } else if (msg.action === 'clear-scan') {
      clearScan();
      sendResponse({ received: true });
    }
  });

  // ---------------- selection helpers ----------------

  function currentSelectionText() {
    try {
      var sel = window.getSelection();
      return sel ? sel.toString() : '';
    } catch (e) {
      return '';
    }
  }

  function getSelectionRect() {
    try {
      var sel = window.getSelection();
      if (sel && sel.rangeCount > 0) {
        var r = sel.getRangeAt(0).getBoundingClientRect();
        if (r && (r.width || r.height)) return r;
      }
    } catch (e) { /* ignore */ }
    return null;
  }

  function isOurHost(el) {
    return !!(el && el.closest &&
      el.closest('#' + PANEL_HOST_ID + ',#' + FLOAT_HOST_ID + ',#' + TOAST_HOST_ID));
  }

  // ---------------- decode / encode flows ----------------

  function runDecode(input, rect) {
    var result = B64Codec.smartDecode(input);
    B64Codec.enhanceDecoded(result).then(function (enhanced) {
      session = { mode: 'decode', input: input, format: 'auto',
                  result: enhanced, stack: [enhanced], jsonPretty: true, imageUrl: null };
      showPanel(rect);
      saveHistory(session);
    });
  }

  function runEncode(input, rect) {
    var text = String(input == null ? '' : input);
    var result;
    if (!text.trim()) {
      result = { ok: false, kind: 'error', error: '没有选中可编码的内容', format: 'base64' };
    } else {
      var encoded = B64Codec.encodeBase64(text);
      result = { ok: true, kind: 'text', text: encoded, encoding: 'UTF-8',
                 byteLength: encoded.length, bytes: null, format: 'base64' };
    }
    session = { mode: 'encode', input: input, format: 'base64',
                result: result, stack: [result], jsonPretty: true, imageUrl: null };
    showPanel(rect);
    saveHistory(session);
  }

  function forceFormat(fmt) {
    if (!session || session.mode !== 'decode') return;
    var result = fmt === 'auto'
      ? B64Codec.smartDecode(session.input)
      : B64Codec.decodeAs(session.input, fmt);
    B64Codec.enhanceDecoded(result).then(function (enhanced) {
      session.format = fmt;
      session.result = enhanced;
      session.stack = [enhanced];
      session.jsonPretty = true;
      renderPanel();
    });
  }

  function decodeAgain() {
    if (!session) return;
    var text = session.result && session.result.text;
    if (!text || !B64Codec.looksLikeBase64(text)) return;
    var next = B64Codec.smartDecode(text);
    B64Codec.enhanceDecoded(next).then(function (enhanced) {
      if (!enhanced.ok) return;
      session.stack.push(enhanced);
      session.result = enhanced;
      session.jsonPretty = true;
      renderPanel();
    });
  }

  function stepBack() {
    if (!session || session.stack.length <= 1) return;
    session.stack.pop();
    session.result = session.stack[session.stack.length - 1];
    session.jsonPretty = true;
    renderPanel();
  }

  function pickCandidate(result) {
    if (!session) return;
    B64Codec.enhanceDecoded(result).then(function (enhanced) {
      session.result = enhanced;
      session.stack = [enhanced];
      session.jsonPretty = true;
      renderPanel();
    });
  }

  // ---------------- history ----------------

  function saveHistory(sess) {
    try {
      if (!sess || !sess.result || !sess.result.ok) return;
      if (sess.result.kind === 'multiple') return;
      var output;
      var r = sess.result;
      if (r.kind === 'jwt') {
        output = r.payload.json ? JSON.stringify(r.payload.json) : r.payload.raw;
      } else if (r.kind === 'binary') {
        output = r.hex;
      } else {
        output = r.text;
      }
      if (typeof B64Store !== 'undefined') {
        B64Store.add({
          ts: Date.now(),
          mode: sess.mode,
          format: r.format || null,
          input: String(sess.input).slice(0, 200),
          output: String(output == null ? '' : output).slice(0, MAX_HISTORY_TEXT)
        });
      }
    } catch (e) { /* history is best-effort */ }
  }

  // ---------------- panel ----------------

  function closePanel() {
    if (session && session.imageUrl) {
      try { URL.revokeObjectURL(session.imageUrl); } catch (e) { /* ignore */ }
    }
    var host = document.getElementById(PANEL_HOST_ID);
    if (host) host.remove();
    document.removeEventListener('mousedown', onDocMouseDown, true);
    document.removeEventListener('keydown', onDocKeyDown, true);
  }

  function onDocMouseDown(e) {
    var host = document.getElementById(PANEL_HOST_ID);
    if (host && !host.contains(e.target)) closePanel();
  }

  function onDocKeyDown(e) {
    if (e.key === 'Escape') { closePanel(); hideFloat(); }
  }

  function showPanel(rect) {
    closePanel();
    var host = document.createElement('div');
    host.id = PANEL_HOST_ID;
    host.style.cssText = 'position:fixed;left:0;top:0;z-index:2147483647;';
    var shadow = host.attachShadow({ mode: 'open' });
    shadow.appendChild(buildStyle());
    var panel = document.createElement('div');
    panel.className = 'b64d-panel';
    shadow.appendChild(panel);
    (document.body || document.documentElement).appendChild(host);
    renderPanel();
    positionPanel(host, panel, rect);
    document.addEventListener('mousedown', onDocMouseDown, true);
    document.addEventListener('keydown', onDocKeyDown, true);
  }

  function getPanelEl() {
    var host = document.getElementById(PANEL_HOST_ID);
    return host && host.shadowRoot ? host.shadowRoot.querySelector('.b64d-panel') : null;
  }

  function renderPanel() {
    var panel = getPanelEl();
    if (!panel || !session) return;
    panel.innerHTML = '';
    var result = session.result;
    var depth = session.stack.length;

    // header
    var head = el('div', 'b64d-head');
    var title = el('span', 'b64d-title');
    if (session.mode === 'encode') {
      title.textContent = '编码结果 · Base64';
    } else if (result.ok && result.kind === 'jwt') {
      title.textContent = 'JWT 解析';
    } else if (result.ok && result.kind === 'multiple') {
      title.textContent = '找到多处可解码内容';
    } else if (result.ok) {
      title.textContent = '解码结果' + (result.format ? ' · ' + B64Codec.FORMAT_LABELS[result.format] : '');
    } else {
      title.textContent = '无法解码';
    }
    if (depth > 1) {
      title.appendChild(document.createTextNode(' '));
      var badge = el('span', 'b64d-badge', '第 ' + depth + ' 次解码');
      title.appendChild(badge);
    }
    var closeBtn = el('button', 'b64d-x', '✕');
    closeBtn.title = '关闭 (Esc)';
    closeBtn.addEventListener('click', closePanel);
    head.appendChild(title);
    head.appendChild(closeBtn);
    panel.appendChild(head);

    // format switcher (decode mode, single result)
    if (session.mode === 'decode' && result.kind !== 'multiple') {
      var sw = el('div', 'b64d-switch');
      var formats = [['auto', '自动'], ['base64', 'Base64'], ['hex', 'Hex'],
                     ['url', 'URL'], ['unicode', 'Unicode'], ['jwt', 'JWT']];
      formats.forEach(function (f) {
        var b = el('button', 'b64d-sw' + (session.format === f[0] ? ' b64d-sw-on' : ''), f[1]);
        b.addEventListener('click', function () { forceFormat(f[0]); });
        sw.appendChild(b);
      });
      panel.appendChild(sw);
    }

    if (result.extracted) {
      panel.appendChild(el('div', 'b64d-note', '已从选中内容中提取出可解码片段'));
    }

    var body = el('div', 'b64d-body');
    if (!result.ok) {
      body.appendChild(el('div', 'b64d-error', result.error));
      body.appendChild(el('div', 'b64d-hint',
        '请确认选中的是完整的编码文本，或点上方格式按钮换一种格式试试。'));
    } else if (result.kind === 'multiple') {
      body.appendChild(el('div', 'b64d-meta', '选中内容里有 ' + result.multiple.length + ' 处可解码，点一行查看：'));
      result.multiple.forEach(function (cand) {
        var row = el('div', 'b64d-cand');
        var label = el('span', 'b64d-cand-label',
          (B64Codec.FORMAT_LABELS[cand.format] || cand.format || '') + ' · ' +
          truncate(cand.extractedFrom, 46));
        var btn = el('button', 'b64d-btn', '解码');
        btn.addEventListener('click', function () { pickCandidate(cand); });
        row.appendChild(label);
        row.appendChild(btn);
        body.appendChild(row);
      });
    } else if (result.kind === 'jwt') {
      renderJwt(body, result);
    } else {
      renderTextResult(body, result);
    }
    panel.appendChild(body);

    // footer
    var foot = el('div', 'b64d-foot');
    if (result.ok && result.kind !== 'multiple') {
      var copyBtn = el('button', 'b64d-btn b64d-primary', '复制结果');
      copyBtn.addEventListener('click', function () {
        copyText(copyContent(result), copyBtn);
      });
      foot.appendChild(copyBtn);
      if (result.image) {
        var dlBtn = el('button', 'b64d-btn', '下载图片');
        dlBtn.addEventListener('click', function () { downloadImage(result); });
        foot.appendChild(dlBtn);
      }
      if (result.kind === 'text' && result.text && B64Codec.looksLikeBase64(result.text)) {
        var againBtn = el('button', 'b64d-btn', '再次解码');
        againBtn.title = '结果本身看起来还是 Base64，继续解一层';
        againBtn.addEventListener('click', decodeAgain);
        foot.appendChild(againBtn);
      }
      if (depth > 1) {
        var backBtn = el('button', 'b64d-btn', '上一步');
        backBtn.addEventListener('click', stepBack);
        foot.appendChild(backBtn);
      }
    }
    var close2 = el('button', 'b64d-btn', '关闭');
    close2.addEventListener('click', closePanel);
    foot.appendChild(close2);
    panel.appendChild(foot);
  }

  function copyContent(result) {
    if (result.kind === 'jwt') {
      return result.payload.json
        ? JSON.stringify(result.payload.json, null, 2)
        : result.payload.raw;
    }
    if (result.kind === 'binary') return result.hex;
    return result.text;
  }

  function renderJwt(body, result) {
    body.appendChild(el('div', 'b64d-sub', 'Header'));
    body.appendChild(jsonPre(result.header));
    body.appendChild(el('div', 'b64d-sub', 'Payload'));
    body.appendChild(jsonPre(result.payload));
    // time claims
    var claims = [];
    if (result.payload.json) {
      ['exp', 'iat', 'nbf', 'auth_time'].forEach(function (k) {
        var v = result.payload.json[k];
        var f = B64Codec.formatJwtTime(v);
        if (f) claims.push(k + ': ' + v + ' → ' + f);
      });
    }
    if (claims.length) {
      body.appendChild(el('div', 'b64d-sub', '时间字段'));
      var c = el('div', 'b64d-claims', claims.join('\n'));
      body.appendChild(c);
    }
    body.appendChild(el('div', 'b64d-sub', 'Signature'));
    var sig = el('div', 'b64d-sig', truncate(result.signature, 64));
    body.appendChild(sig);
    body.appendChild(el('div', 'b64d-hint', '签名无法在此验证，验证需要密钥。'));
  }

  function jsonPre(part) {
    var pre = el('pre', 'b64d-json');
    if (part.json) {
      pre.textContent = JSON.stringify(part.json, null, 2);
    } else {
      pre.textContent = part.raw;
    }
    return pre;
  }

  function renderTextResult(body, result) {
    var metaParts = [];
    if (result.decompressed) metaParts.push('已自动解压（' + result.decompressed + '）');
    if (result.encoding) metaParts.push('编码：' + result.encoding);
    metaParts.push('共 ' + result.byteLength + ' 字节');
    if (result.kind === 'binary') metaParts.push('非文本内容，以下为十六进制');
    body.appendChild(el('div', 'b64d-meta', metaParts.join(' · ')));

    if (result.image) {
      var img = document.createElement('img');
      img.className = 'b64d-img';
      img.alt = '解码出的图片（' + result.image + '）';
      if (!session.imageUrl) {
        var blob = new Blob([result.bytes], { type: 'image/' + result.image });
        session.imageUrl = URL.createObjectURL(blob);
      }
      img.src = session.imageUrl;
      body.appendChild(img);
    }

    var pretty = result.kind === 'text' ? B64Codec.tryParseJson(result.text) : null;
    if (pretty) {
      var toggle = el('button', 'b64d-btn b64d-json-toggle',
        session.jsonPretty ? '显示原文' : '格式化 JSON');
      toggle.addEventListener('click', function () {
        session.jsonPretty = !session.jsonPretty;
        renderPanel();
      });
      body.appendChild(toggle);
    }
    var full = result.kind === 'binary' ? result.hex : result.text;
    var shown = full;
    if (pretty && session.jsonPretty) shown = pretty;
    if (shown.length > MAX_DISPLAY) {
      shown = shown.slice(0, MAX_DISPLAY) + '\n…（过长，仅显示前 ' + MAX_DISPLAY + ' 字符，复制可获得全部）';
    }
    var area = document.createElement('textarea');
    area.className = 'b64d-area';
    area.readOnly = true;
    area.value = shown;
    area.spellcheck = false;
    body.appendChild(area);
  }

  function downloadImage(result) {
    if (!session.imageUrl) return;
    var a = document.createElement('a');
    a.href = session.imageUrl;
    a.download = 'decoded-image.' + result.image;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function positionPanel(host, panel, rect) {
    var w = panel.offsetWidth;
    var h = panel.offsetHeight;
    var vw = window.innerWidth;
    var vh = window.innerHeight;
    var left, top;
    if (rect) {
      left = Math.min(Math.max(rect.left, 8), Math.max(8, vw - w - 8));
      top = rect.bottom + 8;
      if (top + h > vh - 8) top = Math.max(8, rect.top - h - 8);
    } else {
      left = Math.max(8, (vw - w) / 2);
      top = Math.max(8, vh * 0.2);
    }
    host.style.left = left + 'px';
    host.style.top = top + 'px';
  }

  // ---------------- small DOM helpers ----------------

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function truncate(s, n) {
    s = String(s == null ? '' : s);
    return s.length > n ? s.slice(0, n) + '…' : s;
  }

  function copyText(text, btn) {
    function done(ok) {
      if (!btn) return;
      var old = btn.textContent;
      btn.textContent = ok ? '已复制 ✓' : '复制失败';
      setTimeout(function () { btn.textContent = old; }, 1500);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () {
        fallbackCopy(text, done);
      });
    } else {
      fallbackCopy(text, done);
    }
  }

  function fallbackCopy(text, done) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0;';
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      ta.remove();
      done(ok);
    } catch (e) {
      done(false);
    }
  }

  function buildStyle() {
    var style = document.createElement('style');
    style.textContent = [
      '.b64d-panel{',
      '  width:440px;max-width:calc(100vw - 16px);',
      '  font-family:-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;',
      '  font-size:13px;line-height:1.5;color:#e8eaed;',
      '  background:#202124;border:1px solid #5f6368;border-radius:10px;',
      '  box-shadow:0 8px 28px rgba(0,0,0,.45);overflow:hidden;',
      '}',
      '.b64d-head{display:flex;align-items:center;justify-content:space-between;',
      '  padding:9px 12px;background:#303134;border-bottom:1px solid #5f6368;}',
      '.b64d-title{font-weight:600;font-size:13px;color:#e8eaed;}',
      '.b64d-badge{display:inline-block;font-size:11px;font-weight:400;color:#8ab4f8;',
      '  background:#1a2b45;border-radius:8px;padding:1px 7px;margin-left:4px;}',
      '.b64d-x{border:none;background:transparent;color:#9aa0a6;font-size:14px;',
      '  cursor:pointer;padding:2px 6px;border-radius:6px;line-height:1;}',
      '.b64d-x:hover{background:#5f6368;color:#fff;}',
      '.b64d-switch{display:flex;gap:6px;flex-wrap:wrap;padding:8px 12px 0;}',
      '.b64d-sw{border:1px solid #5f6368;background:#303134;color:#9aa0a6;',
      '  font-size:12px;padding:2px 10px;border-radius:12px;cursor:pointer;}',
      '.b64d-sw:hover{color:#e8eaed;}',
      '.b64d-sw-on{background:#8ab4f8;border-color:#8ab4f8;color:#202124;font-weight:600;}',
      '.b64d-note{font-size:12px;color:#fdd663;padding:8px 12px 0;}',
      '.b64d-body{padding:10px 12px;}',
      '.b64d-meta{font-size:12px;color:#9aa0a6;margin-bottom:6px;}',
      '.b64d-error{color:#f28b82;font-weight:600;margin-bottom:6px;}',
      '.b64d-hint{font-size:12px;color:#9aa0a6;}',
      '.b64d-area{width:100%;height:150px;max-height:45vh;resize:vertical;box-sizing:border-box;',
      '  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;',
      '  color:#e8eaed;background:#17181a;border:1px solid #5f6368;border-radius:6px;',
      '  padding:8px;white-space:pre-wrap;word-break:break-all;}',
      '.b64d-sub{font-size:12px;font-weight:600;color:#8ab4f8;margin:8px 0 4px;}',
      '.b64d-sub:first-child{margin-top:0;}',
      '.b64d-json{margin:0 0 4px;padding:8px;max-height:160px;overflow:auto;white-space:pre-wrap;',
      '  word-break:break-all;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;',
      '  background:#17181a;border:1px solid #5f6368;border-radius:6px;color:#e8eaed;}',
      '.b64d-claims{white-space:pre-wrap;font-size:12px;color:#e8eaed;}',
      '.b64d-sig{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;',
      '  word-break:break-all;color:#9aa0a6;}',
      '.b64d-cand{display:flex;align-items:center;gap:8px;padding:6px 0;',
      '  border-bottom:1px solid #3c4043;}',
      '.b64d-cand:last-child{border-bottom:none;}',
      '.b64d-cand-label{flex:1;font-family:ui-monospace,Menlo,Consolas,monospace;',
      '  font-size:12px;word-break:break-all;color:#e8eaed;}',
      '.b64d-img{display:block;max-width:100%;max-height:260px;margin:0 auto 8px;',
      '  border-radius:6px;border:1px solid #5f6368;background:#fff;}',
      '.b64d-json-toggle{margin-bottom:6px;}',
      '.b64d-foot{display:flex;gap:8px;justify-content:flex-end;padding:9px 12px;',
      '  border-top:1px solid #5f6368;background:#303134;}',
      '.b64d-btn{border:1px solid #5f6368;background:#3c4043;color:#e8eaed;',
      '  font-size:12.5px;padding:5px 12px;border-radius:16px;cursor:pointer;}',
      '.b64d-btn:hover{background:#5f6368;}',
      '.b64d-primary{background:#8ab4f8;border-color:#8ab4f8;color:#202124;font-weight:600;}',
      '.b64d-primary:hover{background:#aecbfa;}'
    ].join('\n');
    return style;
  }

  // ---------------- floating button ----------------

  function showFloat(rect) {
    hideFloat();
    var host = document.createElement('div');
    host.id = FLOAT_HOST_ID;
    host.style.cssText = 'position:fixed;left:0;top:0;z-index:2147483646;';
    var shadow = host.attachShadow({ mode: 'open' });
    var style = document.createElement('style');
    style.textContent = [
      '.b64d-float{display:flex;overflow:hidden;border-radius:16px;',
      '  box-shadow:0 4px 14px rgba(0,0,0,.35);border:1px solid #5f6368;}',
      '.b64d-float button{border:none;background:#202124;color:#e8eaed;',
      '  font-family:-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;',
      '  font-size:12.5px;padding:5px 12px;cursor:pointer;}',
      '.b64d-float button:first-child{background:#8ab4f8;color:#202124;font-weight:600;}',
      '.b64d-float button:hover{filter:brightness(1.15);}'
    ].join('\n');
    shadow.appendChild(style);
    var wrap = el('div', 'b64d-float');
    var decBtn = el('button', null, '解码');
    decBtn.addEventListener('click', function () {
      hideFloat();
      runDecode(currentSelectionText(), rect);
    });
    var encBtn = el('button', null, '编码');
    encBtn.addEventListener('click', function () {
      hideFloat();
      runEncode(currentSelectionText(), rect);
    });
    wrap.appendChild(decBtn);
    wrap.appendChild(encBtn);
    shadow.appendChild(wrap);
    (document.body || document.documentElement).appendChild(host);
    var w = wrap.offsetWidth;
    var h = wrap.offsetHeight;
    var left = Math.min(Math.max(rect.left, 8), Math.max(8, window.innerWidth - w - 8));
    var top = rect.top - h - 8;
    if (top < 8) top = rect.bottom + 8;
    host.style.left = left + 'px';
    host.style.top = top + 'px';
  }

  function hideFloat() {
    var host = document.getElementById(FLOAT_HOST_ID);
    if (host) host.remove();
  }

  function maybeShowFloat() {
    if (document.getElementById(PANEL_HOST_ID)) return;
    var text = currentSelectionText();
    if (!text || text.trim().length < 8) { hideFloat(); return; }
    if (!B64Codec.looksEncoded(text)) { hideFloat(); return; }
    var rect = getSelectionRect();
    if (!rect) { hideFloat(); return; }
    showFloat(rect);
  }

  function scheduleFloatCheck() {
    clearTimeout(floatTimer);
    floatTimer = setTimeout(maybeShowFloat, 150);
  }

  document.addEventListener('mouseup', function (e) {
    if (isOurHost(e.target)) return;
    scheduleFloatCheck();
  });
  document.addEventListener('keyup', function (e) {
    if (e.key === 'Escape') { hideFloat(); return; }
    if (e.shiftKey || e.key.indexOf('Arrow') === 0) scheduleFloatCheck();
  });
  document.addEventListener('mousedown', function (e) {
    if (!isOurHost(e.target)) hideFloat();
  }, true);
  window.addEventListener('scroll', hideFloat, true);

  // ---------------- page scan ----------------

  var SCAN_TOKEN_MIN = 20;
  var SCAN_MAX = 500;

  function scanPage() {
    clearScan();
    var style = document.createElement('style');
    style.id = SCAN_STYLE_ID;
    style.textContent = '.b64d-hit{background:#fff3b0 !important;outline:1px dashed #e6a817;' +
      'border-radius:2px;cursor:pointer;} .b64d-hit:hover{background:#ffe066 !important;}';
    document.head.appendChild(style);

    var count = 0;
    var walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: function (node) {
          var p = node.parentElement;
          if (!p) return NodeFilter.FILTER_REJECT;
          var tag = p.tagName;
          if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' ||
              tag === 'TEXTAREA' || tag === 'SELECT' || tag === 'OPTION' ||
              tag === 'INPUT') return NodeFilter.FILTER_REJECT;
          if (p.closest && p.closest('[contenteditable="true"],#' + PANEL_HOST_ID +
              ',#' + FLOAT_HOST_ID + ',#' + TOAST_HOST_ID)) return NodeFilter.FILTER_REJECT;
          if (!node.nodeValue || node.nodeValue.length > 20000) return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );
    var nodes = [];
    var n;
    while ((n = walker.nextNode())) nodes.push(n);

    nodes.forEach(function (textNode) {
      if (count >= SCAN_MAX) return;
      var text = textNode.nodeValue;
      var tokens = B64Codec.findEncodedTokens(text, SCAN_TOKEN_MIN);
      if (!tokens.length) return;
      // wrap from last to first so earlier indices stay valid
      for (var i = tokens.length - 1; i >= 0; i--) {
        if (count >= SCAN_MAX) break;
        var tok = tokens[i];
        var span = document.createElement('span');
        span.className = 'b64d-hit';
        span.title = '点击解码这段内容';
        textNode.splitText(tok.index + tok.text.length);
        var mid = textNode.splitText(tok.index);
        mid.parentNode.insertBefore(span, mid);
        span.appendChild(mid);
        count++;
      }
    });

    showToast(count);
    return count;
  }

  function clearScan() {
    document.querySelectorAll('.b64d-hit').forEach(function (span) {
      var parent = span.parentNode;
      if (!parent) return;
      while (span.firstChild) parent.insertBefore(span.firstChild, span);
      parent.removeChild(span);
      parent.normalize();
    });
    var style = document.getElementById(SCAN_STYLE_ID);
    if (style) style.remove();
    var toast = document.getElementById(TOAST_HOST_ID);
    if (toast) toast.remove();
  }

  function showToast(count) {
    var old = document.getElementById(TOAST_HOST_ID);
    if (old) old.remove();
    var host = document.createElement('div');
    host.id = TOAST_HOST_ID;
    host.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483645;';
    var shadow = host.attachShadow({ mode: 'open' });
    var style = document.createElement('style');
    style.textContent = [
      '.b64d-toast{display:flex;align-items:center;gap:10px;',
      '  font-family:-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;',
      '  font-size:13px;color:#e8eaed;background:#202124;border:1px solid #5f6368;',
      '  border-radius:10px;padding:10px 12px;box-shadow:0 8px 28px rgba(0,0,0,.45);}',
      '.b64d-toast button{border:1px solid #5f6368;background:#3c4043;color:#e8eaed;',
      '  font-size:12.5px;padding:4px 12px;border-radius:16px;cursor:pointer;}',
      '.b64d-toast button:hover{background:#5f6368;}'
    ].join('\n');
    shadow.appendChild(style);
    var box = el('div', 'b64d-toast');
    box.appendChild(el('span', null, count > 0
      ? '已高亮 ' + count + ' 处疑似编码内容，点击任意一处解码'
      : '本页没有发现疑似编码内容'));
    var clearBtn = el('button', null, count > 0 ? '清除高亮' : '关闭');
    clearBtn.addEventListener('click', clearScan);
    box.appendChild(clearBtn);
    shadow.appendChild(box);
    (document.body || document.documentElement).appendChild(host);
    if (count === 0) {
      setTimeout(function () {
        var t = document.getElementById(TOAST_HOST_ID);
        if (t) t.remove();
      }, 4000);
    }
  }

  document.addEventListener('click', function (e) {
    var hit = e.target && e.target.closest ? e.target.closest('.b64d-hit') : null;
    if (!hit) return;
    e.preventDefault();
    e.stopPropagation();
    runDecode(hit.textContent, hit.getBoundingClientRect());
  }, true);
})();
