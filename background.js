// Service worker: context menus + keyboard shortcuts -> ask the content
// script in the active tab to decode/encode the current selection.
'use strict';

var CONTENT_FILES = ['codec.js', 'store.js', 'content.js'];

chrome.runtime.onInstalled.addListener(function () {
  chrome.contextMenus.create({
    id: 'b64d-decode',
    title: '智能解码',
    contexts: ['selection']
  });
  chrome.contextMenus.create({
    id: 'b64d-encode',
    title: '编码为 Base64',
    contexts: ['selection']
  });
});

chrome.contextMenus.onClicked.addListener(function (info, tab) {
  if (!tab || tab.id == null) return;
  if (info.menuItemId === 'b64d-decode') trigger(tab.id, 'decode-selection');
  if (info.menuItemId === 'b64d-encode') trigger(tab.id, 'encode-selection');
});

chrome.commands.onCommand.addListener(function (command, tab) {
  if (!tab || tab.id == null) return;
  if (command === 'decode-selection') trigger(tab.id, 'decode-selection');
  if (command === 'encode-selection') trigger(tab.id, 'encode-selection');
});

function trigger(tabId, action) {
  chrome.tabs.sendMessage(tabId, { action: action }, function () {
    if (chrome.runtime.lastError) {
      // Content script is not present in this tab (e.g. the page was opened
      // before the extension was installed). Inject it, then retry once.
      chrome.scripting.executeScript(
        { target: { tabId: tabId }, files: CONTENT_FILES },
        function () {
          if (chrome.runtime.lastError) return; // e.g. chrome:// pages
          chrome.tabs.sendMessage(tabId, { action: action });
        }
      );
    }
  });
}
