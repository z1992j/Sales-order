/* 销售订单登记 —— Service Worker
 *
 * 目的：装到手机主屏后能离线打开。
 *
 * 策略：同源资源一律「网络优先、带协商校验」，拿不到再用缓存。
 * 页面拆成了 index.html / app.css / app.js 三个文件，它们必须来自同一次
 * 发布——如果 HTML 是新的而 JS 还是缓存里的旧版，界面会直接出错。
 * 所以不能对 JS/CSS 用「缓存优先」，每次都向服务器确认（未变化时只回 304，
 * 开销很小），只有断网时才退回缓存。
 *
 * Supabase 的接口请求一律不经过这里 —— 订单数据必须实时，缓存了会看到旧账。
 * 离线时的数据展示由页面自己用 localStorage 处理，见 app.js。
 */
const VERSION = 'v2';
const CACHE = 'sales-order-' + VERSION;

const SHELL = [
  './',
  './index.html',
  './app.css',
  './app.js',
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

  // 导航请求统一存成 index.html，离线时不管带什么查询参数都能打开
  const cacheKey = req.mode === 'navigate' ? './index.html' : req;

  event.respondWith(
    fetch(req, { cache: 'no-cache' })
      .then(res => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(cacheKey, copy));
        }
        return res;
      })
      .catch(() => caches.match(cacheKey).then(r => r || caches.match('./')))
  );
});
