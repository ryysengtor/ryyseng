// sw.js — Service Worker Dongtube v7
// Strategi: Network-First untuk semua request.
// HTML pages & API: TIDAK di-cache (selalu dari network).
// Aset statis (font, gambar): cache dengan network-first + fallback.
// Login/token: TIDAK di-cache (disimpan di localStorage, bukan SW).

const CACHE_NAME  = 'dongtube-v7-static';
const FONT_CACHE  = 'dongtube-v7-fonts';

// Aset yang boleh di-cache (font & gambar statis saja)
const CACHEABLE_EXTS = /\.(woff2?|ttf|eot|png|jpg|jpeg|webp|svg|ico|gif)(\?.*)?$/i;

self.addEventListener('install', function(e) {
  self.skipWaiting(); // Langsung aktif, tidak perlu tunggu tab lama ditutup
});

self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys
          .filter(function(k) { return k !== CACHE_NAME && k !== FONT_CACHE; })
          .map(function(k) { return caches.delete(k); })
      );
    }).then(function() { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function(e) {
  if (e.request.method !== 'GET') return;

  var url = new URL(e.request.url);

  // API & halaman HTML: selalu dari network, JANGAN cache
  if (
    url.pathname.startsWith('/api/') ||
    url.pathname === '/' ||
    url.pathname.endsWith('.html') ||
    e.request.mode === 'navigate'
  ) {
    e.respondWith(
      fetch(e.request).catch(function() {
        // Offline fallback hanya untuk navigasi
        if (e.request.mode === 'navigate') {
          return caches.match('/index.html').then(function(c) {
            return c || new Response('Offline', { status: 503 });
          });
        }
      })
    );
    return;
  }

  // Font & gambar: cache-first (jarang berubah)
  if (CACHEABLE_EXTS.test(url.pathname)) {
    e.respondWith(
      caches.open(FONT_CACHE).then(function(cache) {
        return cache.match(e.request).then(function(cached) {
          if (cached) return cached;
          return fetch(e.request).then(function(res) {
            if (res.ok) cache.put(e.request, res.clone());
            return res;
          }).catch(function() { return cached || new Response('', { status: 503 }); });
        });
      })
    );
    return;
  }

  // JS/CSS: network-first, cache sebagai fallback
  if (/\.(js|css)(\?.*)?$/i.test(url.pathname)) {
    e.respondWith(
      fetch(e.request).then(function(res) {
        if (res.ok) {
          var clone = res.clone();
          caches.open(CACHE_NAME).then(function(c) { c.put(e.request, clone); });
        }
        return res;
      }).catch(function() {
        return caches.match(e.request).then(function(c) {
          return c || new Response('', { status: 503 });
        });
      })
    );
    return;
  }

  // Default: network langsung, tanpa cache
  // (ini juga memastikan login/token flow tidak pernah di-cache)
});
