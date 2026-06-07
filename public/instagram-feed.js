(function() {
  function loadInstagramFeed() {
    var carousel = document.getElementById('instagram-carousel');
    if (!carousel || !window.fetch) return;

    fetch('/api/public/instagram', { headers: { 'Accept': 'application/json' } })
      .then(function(res) {
        var contentType = res.headers.get('content-type') || '';
        if (!res.ok || contentType.indexOf('application/json') === -1) {
          throw new Error('Instagram feed unavailable');
        }
        return res.json();
      })
      .then(function(posts) {
        if (!Array.isArray(posts) || !posts.length) return;
        var usablePosts = posts.filter(function(post) {
          return post && post.permalink && post.image;
        }).slice(0, 4);
        if (!usablePosts.length) return;

        carousel.innerHTML = '';
        usablePosts.forEach(function(post) {
          var tile = document.createElement('a');
          tile.className = 'instagram-tile';
          tile.href = post.permalink;
          tile.target = '_blank';
          tile.rel = 'noopener noreferrer';

          var image = document.createElement('img');
          image.src = post.image;
          image.alt = post.caption || 'Alpha Surfaces Instagram post';
          image.loading = 'lazy';

          tile.appendChild(image);
          carousel.appendChild(tile);
        });
      })
      .catch(function() {});
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadInstagramFeed);
  } else {
    loadInstagramFeed();
  }
})();
