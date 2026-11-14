// B64Store — decode history in chrome.storage.local (local only, never synced
// or uploaded). Shared by the content script (writes) and the popup (reads).
(function (global) {
  'use strict';

  var KEY = 'b64d_history_v1';
  var MAX = 50;

  function storageAvailable() {
    try {
      return !!(global.chrome && global.chrome.storage && global.chrome.storage.local);
    } catch (e) {
      return false;
    }
  }

  function getAll() {
    if (!storageAvailable()) return Promise.resolve([]);
    return new Promise(function (resolve) {
      global.chrome.storage.local.get(KEY, function (res) {
        resolve(Array.isArray(res && res[KEY]) ? res[KEY] : []);
      });
    });
  }

  function add(entry) {
    if (!storageAvailable()) return Promise.resolve();
    return getAll().then(function (list) {
      // de-dupe consecutive identical inputs
      if (list.length > 0 && list[0].input === entry.input && list[0].mode === entry.mode) {
        list[0] = entry;
      } else {
        list.unshift(entry);
      }
      list = list.slice(0, MAX);
      return new Promise(function (resolve) {
        global.chrome.storage.local.set({ [KEY]: list }, resolve);
      });
    });
  }

  function clear() {
    if (!storageAvailable()) return Promise.resolve();
    return new Promise(function (resolve) {
      global.chrome.storage.local.remove(KEY, resolve);
    });
  }

  function remove(ts) {
    if (!storageAvailable()) return Promise.resolve();
    return getAll().then(function (list) {
      list = list.filter(function (e) { return e.ts !== ts; });
      return new Promise(function (resolve) {
        global.chrome.storage.local.set({ [KEY]: list }, resolve);
      });
    });
  }

  var api = { add: add, list: getAll, clear: clear, remove: remove, MAX: MAX };
  global.B64Store = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
