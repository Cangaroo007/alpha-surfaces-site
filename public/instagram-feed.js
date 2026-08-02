(function () {
  // Any element with [data-instagram-feed] gets populated.
  // Kept #instagram-carousel as a selector so the existing home page
  // markup keeps working if it isn't updated at the same time.
  var SELECTOR = '[data-instagram-feed], #instagram-carousel';

  function tile(post) {
    var a = document.createElement('a');
    a.className = 'instagram-tile';
    a.href = post.permalink;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';

    var img = document.createElement('img');
    // Behold serves several renditions; originalLarge holds up better in a
    // 4:5 frame than originalMedium did in the old 1:1 tile.
    img.src = String(post.image).replace('class=originalMedium', 'class=originalLarge');
    img.alt = post.caption || 'Alpha Surfaces Instagram post';
    img.loading = 'lazy';

    a.appendChild(img);
    return a;
  }

  function loadInstagramFeed() {
    var targets = document.querySelectorAll(SELECTOR);
    if (!targets.length || !window.fetch) return;

    fetch('/api/public/instagram', { headers: { Accept: 'application/json' } })
      .then(function (res) {
        var ct = res.headers.get('content-type') || '';
        if (!res.ok || ct.indexOf('application/json') === -1) {
          throw new Error('Instagram feed unavailable');
        }
        return res.json();
      })
      .then(function (posts) {
        if (!Array.isArray(posts) || !posts.length) return;

        var usable = posts.filter(function (p) {
          return p && p.permalink && p.image;
        });
        if (!usable.length) return;

        Array.prototype.forEach.call(targets, function (el) {
          // Per-container count, defaults to 4.
          var limit = parseInt(el.getAttribute('data-count'), 10) || 4;
          var slice = usable.slice(0, limit);
          if (!slice.length) return;

          // Only clear the placeholders once we know we have real posts,
          // so a failed fetch leaves the existing markup intact.
          el.innerHTML = '';
          slice.forEach(function (post) {
            el.appendChild(tile(post));
          });
        });
      })
      .catch(function () {
        /* placeholders / static fallback remain visible */
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadInstagramFeed);
  } else {
    loadInstagramFeed();
  }
})();
