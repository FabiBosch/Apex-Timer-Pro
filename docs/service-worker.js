// Diese Versionsnummer bei jedem Update erhöhen (z.B. 'v2', 'v3', ...)
// Das ist der SCHALTER für Updates: neue Nummer = altes Cache wird verworfen
const CACHE_VERSION = 'apex-timer-v1';

const FILES_TO_CACHE = [
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

// Beim Installieren: aktuelle Dateien in den Cache legen
self.addEventListener('install', (event) => {
  self.skipWaiting(); // sofort aktiv werden, nicht auf Tab-Schließen warten
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(FILES_TO_CACHE))
  );
});

// Beim Aktivieren: alte Cache-Versionen aufräumen
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_VERSION)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

// Strategie: Netzwerk zuerst versuchen (aktuelle Version), bei Fehler auf Cache zurückfallen (offline-fähig)
self.addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const clone = response.clone();
        caches.open(CACHE_VERSION).then((cache) => cache.put(event.request, clone));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});