/* GitHub Pages(정적·암호화) 모드 서비스 워커 — 게시할 때 sw.js 로 복사된다. */
const SHELL = 'jk-shell-v2';
const IMG = 'jk-img-v1';
const DATA = 'jk-data-v1';
const SHELL_URLS = ['./', 'app.js', 'app.css', 'config.json', 'icons/icon-192.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(SHELL).then((c) => c.addAll(SHELL_URLS)).catch(() => {}).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (![SHELL, IMG, DATA].includes(k)) await caches.delete(k);
    await self.clients.claim();
  })());
});

async function networkFirst(req, cacheName, key) {
  const cache = await caches.open(cacheName);
  try {
    const res = await fetch(req, { cache: 'no-cache' });
    if (res.ok) cache.put(key || req, res.clone());
    return res;
  } catch (err) {
    const hit = await cache.match(key || req);
    if (hit) return hit;
    throw err;
  }
}

async function cacheFirst(req) {
  const cache = await caches.open(IMG);
  const hit = await cache.match(req);
  if (hit) return hit;
  const res = await fetch(req);
  if (res.ok) cache.put(req, res.clone());
  return res;
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;
  const p = url.pathname;
  // 목록·검색 색인은 이름이 고정 → 늘 새로 받고, 끊겼을 때만 저장본
  if (p.endsWith('/d/lib.bin') || p.endsWith('/d/search.bin')) { e.respondWith(networkFirst(req, DATA, p)); return; }
  // 나머지 교재 파일은 이름이 내용(판)마다 달라짐 → 한 번 받으면 그대로
  if (p.includes('/d/')) { e.respondWith(cacheFirst(req)); return; }
  if (req.mode === 'navigate') { e.respondWith(networkFirst(req, SHELL, new URL('./', self.registration.scope).href)); return; }
  if (/\/(app\.js|app\.css|config\.json|manifest\.webmanifest)$/.test(p) || p.includes('/icons/')) {
    e.respondWith(networkFirst(req, SHELL, p));
  }
});
