// 13 06 Constructora — Service Worker Criptográfico Zero-Knowledge (AES-256-GCM)
// Versión de compilación: 8404d7b3e681
const DB_NAME = '1306_vault_crypto_db';
const STORE_NAME = 'keys';
const KEY_ID = 'master_aes256';
let MEM_CRYPTO_KEY = null;

function abrirDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function guardarKeyB64EnDb(b64url) {
  const db = await abrirDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(b64url, KEY_ID);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
  });
}

async function leerKeyB64DeDb() {
  const db = await abrirDb();
  return new Promise((resolve) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(KEY_ID);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => resolve(null);
  });
}

function b64urlToBytes(b64url) {
  const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function obtenerCryptoKey() {
  if (MEM_CRYPTO_KEY) return MEM_CRYPTO_KEY;
  const b64url = await leerKeyB64DeDb();
  if (!b64url) return null;
  const raw = b64urlToBytes(b64url);
  MEM_CRYPTO_KEY = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  return MEM_CRYPTO_KEY;
}

function detectarMime(ruta) {
  const p = ruta.toLowerCase();
  if (p.endsWith('.html')) return 'text/html; charset=utf-8';
  if (p.endsWith('.png')) return 'image/png';
  if (p.endsWith('.jpg') || p.endsWith('.jpeg')) return 'image/jpeg';
  if (p.endsWith('.webp')) return 'image/webp';
  if (p.endsWith('.json')) return 'application/json; charset=utf-8';
  return 'application/octet-stream';
}

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'SET_KEY' && data.key) {
    event.waitUntil((async () => {
      try {
        const raw = b64urlToBytes(data.key);
        MEM_CRYPTO_KEY = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
        await guardarKeyB64EnDb(data.key);
        if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: true });
      } catch (err) {
        if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: false, error: String(err) });
      }
    })());
  }
});

self.addEventListener('fetch', (event) => {
  const reqUrl = new URL(event.request.url);
  if (reqUrl.origin !== self.location.origin) return;

  const scopePath = new URL(self.registration.scope).pathname;
  if (!reqUrl.pathname.startsWith(scopePath)) return;

  let relPath = decodeURIComponent(reqUrl.pathname.slice(scopePath.length));
  if (!relPath || relPath === 'index.html' || relPath === 'sw.js' || relPath === '404.html' || relPath === 'robots.txt' || relPath.endsWith('.enc')) {
    return;
  }

  event.respondWith((async () => {
    try {
      const cryptoKey = await obtenerCryptoKey();
      if (!cryptoKey) {
        return Response.redirect(scopePath + 'index.html', 302);
      }
      const encUrl = scopePath + relPath + '.enc?v=8404d7b3e681';
      const resp = await fetch(encUrl, { cache: 'no-cache' });
      if (!resp.ok) {
        return Response.redirect(scopePath + 'Portal_1306.html', 302);
      }
      const buf = new Uint8Array(await resp.arrayBuffer());
      const flag = buf[0];
      const iv = buf.slice(1, 13);
      const ct = buf.slice(13);
      const decBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, ct);

      let finalStreamOrBuf = decBuf;
      if (flag === 1 && typeof DecompressionStream !== 'undefined') {
        const ds = new DecompressionStream('gzip');
        finalStreamOrBuf = new Response(decBuf).body.pipeThrough(ds);
      }
      return new Response(finalStreamOrBuf, {
        status: 200,
        headers: {
          'Content-Type': detectarMime(relPath),
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    } catch (err) {
      return Response.redirect(scopePath + 'index.html?reauth=1', 302);
    }
  })());
});
