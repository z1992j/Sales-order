/* 销售订单登记 —— Service Worker
 *
 * 目的：装到手机主屏后能离线打开。
 *
 * 策略分两类：
 * - 页面导航：优先走网络，拿不到再用缓存。这样每次联网打开都是最新版本，
 *   断网时退回上一次缓存的页面，不会白屏。
 * - 静态资源（图标、manifest）：优先用缓存，后台顺带更新。
 *
 * Supabase 的接口请求一律不缓存 —— 订单数据必须实时，缓存了会看到旧账。
 * 离线时的数据展示由页面自己用 localStorage 处理，见 index.html。
 */
const VERSION = 'v1';
const CACHE = 'sales-order-' + VERSION;

const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE)
      // 单个文件取不到不应导致整个安装失败
      .then(cache => Promise.allSettled(SHELL.map(url => cache.add(url))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // 接口请求交给页面自己处理，不进缓存
  if (url.hostname.endsWith('.supabase.co')) return;
  // 跨域资源不接管
  if (url.origin !== self.location.origin) return;

  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then(res => {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put('./index.html', copy));
          return res;
        })
        .catch(() => caches.match('./index.html').then(r => r || caches.match('./')))
    );
    return;
  }

  event.respondWith(
    caches.match(req).then(cached => {
      const network = fetch(req).then(res => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(req, copy));
        }
        return res;
      }).catch(() => cached);
      return cached || network;
    })
  );
});
