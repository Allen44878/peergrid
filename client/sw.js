const CACHE_NAME = 'dcp-chat-v4';
const ASSETS = [
  './index.html',
  './styles.css',
  './app.js',
  './dcp-sdk.js',
  './manifest.json',
  './libs/nacl.min.js'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS);
    })
  );
});

self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request).then((cachedResponse) => {
      return cachedResponse || fetch(e.request);
    })
  );
});
