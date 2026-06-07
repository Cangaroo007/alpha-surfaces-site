(function () {
  'use strict';

  if (window.loadPublicStones) return;

  var DEFAULT_TIMEOUT_MS = 2500;
  var STATIC_TIMEOUT_MS = 8000;

  function countStones(data) {
    if (!data || !Array.isArray(data.collections)) return 0;
    return data.collections.reduce(function(total, collection) {
      return total + ((collection.stones || []).length);
    }, 0);
  }

  function hasSlug(data, slug) {
    if (!slug || !data || !Array.isArray(data.collections)) return true;
    for (var ci = 0; ci < data.collections.length; ci++) {
      var stones = data.collections[ci].stones || [];
      for (var si = 0; si < stones.length; si++) {
        if (stones[si].slug === slug) return true;
      }
    }
    return false;
  }

  function isUsableStoneData(data, requiredSlug) {
    return countStones(data) > 0 && hasSlug(data, requiredSlug);
  }

  function fetchJsonWithTimeout(url, timeoutMs) {
    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timeoutId;
    var options = controller ? { signal: controller.signal } : {};

    return new Promise(function(resolve, reject) {
      timeoutId = setTimeout(function() {
        if (controller) controller.abort();
        reject(new Error(url + ' timed out after ' + timeoutMs + 'ms'));
      }, timeoutMs);

      fetch(url, options)
        .then(function(response) {
          if (!response.ok) throw new Error(url + ' returned HTTP ' + response.status);
          return response.json();
        })
        .then(function(data) {
          clearTimeout(timeoutId);
          resolve(data);
        })
        .catch(function(err) {
          clearTimeout(timeoutId);
          reject(err);
        });
    });
  }

  window.loadPublicStones = function(staticPath, requiredSlug, options) {
    options = options || {};
    var apiTimeout = Number(options.apiTimeoutMs || DEFAULT_TIMEOUT_MS);
    var staticTimeout = Number(options.staticTimeoutMs || STATIC_TIMEOUT_MS);
    var fallbackPath = staticPath || '/data/stones.json';

    return fetchJsonWithTimeout('/api/public/stones', apiTimeout)
      .then(function(data) {
        if (!isUsableStoneData(data, requiredSlug)) {
          throw new Error('Managed stone data missing required stone data');
        }
        return data;
      })
      .catch(function(apiErr) {
        return fetchJsonWithTimeout(fallbackPath, staticTimeout)
          .then(function(data) {
            if (!isUsableStoneData(data, requiredSlug)) {
              throw new Error('Static stone data missing required stone data');
            }
            if (window.console && console.warn) {
              console.warn('[stones] using static fallback:', apiErr.message);
            }
            return data;
          });
      });
  };
})();
