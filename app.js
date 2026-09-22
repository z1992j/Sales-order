const SUPABASE_URL = 'https://cgieubqhafwwprwzerty.supabase.co';
const SUPABASE_KEY = 'sb_publishable_EDGkPqT_UPcwDD_n3ozuHA_mw_EL0hY';
const REST = SUPABASE_URL + '/rest/v1/orders';

/* ==========================================================================
   访问控制
   --------------------------------------------------------------------------
   两层：
   1) 页面密码闸门 —— 阻挡随手打开链接的人。密码只以加盐 SHA-256 形式存放，
      源码里没有明文；但页面是纯静态的，懂技术的人绕过它并不难。
   2) Supabase 账号鉴权 —— 真正的防线。登录成功后用同一个密码换取数据库
      JWT，之后所有读写都带这个令牌。配合 supabase/security.sql 里的 RLS
      策略，没有令牌的请求会被数据库直接拒绝。
   修改密码：改 AUTH_EMAIL 对应账号的密码，并把新的哈希写入 PASSWORD_HASH
   （生成方式见 tools/hash-password.js），两处必须一致。
   ========================================================================== */
const PASSWORD_SALT = 'sales-order-auth-v1';
const PASSWORD_HASH = 'x5tI6XfoxrZBKGPbvWaN7FGK2gG8oc6/5d/AdTjd648=';
const AUTH_EMAIL = 'team@sales-order.local';
const AUTH_STORE_KEY = 'salesOrderSession';

let dbSession = null;    // { access_token, refresh_token, expires_at }
let dbAuthReady = false; // 数据库账号鉴权是否生效
let dbAuthError = '';    // Supabase 返回的失败原因，原样展示给使用者

// 把 Supabase 的英文报错翻译成可以照着做的处置办法
function authErrorHint(msg) {
  const m = (msg || '').toLowerCase();
  if (m.includes('email not confirmed') || m.includes('not confirmed')) {
    return '账号没有确认。到 Authentication → Users 找到该账号，点右侧 ⋯ → Confirm email；' +
           '或删除后重建，务必勾选 Auto Confirm User。';
  }
  if (m.includes('invalid login credentials')) {
    return '邮箱或密码对不上。确认账号邮箱是 ' + AUTH_EMAIL + '，密码是页面登录用的同一个。';
  }
  if (m.includes('email logins are disabled') || m.includes('email provider') || m.includes('signups not allowed')) {
    return '项目没有启用邮箱登录。到 Authentication → Providers → Email，打开 Enable Email provider。';
  }
  if (m.includes('email address') && m.includes('invalid')) {
    return 'Supabase 不接受这个邮箱域名。把 app.js 里的 AUTH_EMAIL 换成常规域名' +
           '（如 team@example.com），并用同样的邮箱重建账号。';
  }
  return '到 Authentication → Users 确认账号 ' + AUTH_EMAIL + ' 已存在且已确认。';
}

function HEADERS() {
  return {
    'apikey': SUPABASE_KEY,
    'Authorization': 'Bearer ' + ((dbSession && dbSession.access_token) || SUPABASE_KEY),
    'Content-Type': 'application/json'
  };
}

async function sha256b64(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function readStoredSession() {
  for (const store of [localStorage, sessionStorage]) {
    try {
      const raw = store.getItem(AUTH_STORE_KEY);
      if (raw) return { data: JSON.parse(raw), store };
    } catch (e) { /* 隐私模式或存储被禁用 */ }
  }
  return null;
}

function writeStoredSession(session, remember) {
  const store = remember ? localStorage : sessionStorage;
  const other = remember ? sessionStorage : localStorage;
  try { other.removeItem(AUTH_STORE_KEY); } catch (e) {}
  try { store.setItem(AUTH_STORE_KEY, JSON.stringify(session)); } catch (e) {}
}

function clearStoredSession() {
  for (const store of [localStorage, sessionStorage]) {
    try { store.removeItem(AUTH_STORE_KEY); } catch (e) {}
  }
}

// 用密码向 Supabase 换取数据库令牌。项目未建账号时返回 null，此时退回到
// 仅用 publishable key 访问（功能不变，但数据库层没有保护）。
async function signInToDatabase(password) {
  try {
    const res = await fetch(SUPABASE_URL + '/auth/v1/token?grant_type=password', {
      method: 'POST',
      headers: { 'apikey': SUPABASE_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: AUTH_EMAIL, password })
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok || !d.access_token) {
      // 记下确切原因，否则失败时无从排查
      dbAuthError = d.error_description || d.msg || d.error ||
                    d.message || ('HTTP ' + res.status);
      return null;
    }
    dbAuthError = '';
    return {
      access_token: d.access_token,
      refresh_token: d.refresh_token || '',
      expires_at: Date.now() + ((d.expires_in || 3600) - 60) * 1000
    };
  } catch (e) {
    dbAuthError = '无法连接 Supabase：' + e.message;
    return null;
  }
}

async function refreshDatabaseSession() {
  if (!dbSession || !dbSession.refresh_token) return false;
  try {
    const res = await fetch(SUPABASE_URL + '/auth/v1/token?grant_type=refresh_token', {
      method: 'POST',
      headers: { 'apikey': SUPABASE_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: dbSession.refresh_token })
    });
    if (!res.ok) return false;
    const d = await res.json();
    if (!d.access_token) return false;
    dbSession = {
      access_token: d.access_token,
      refresh_token: d.refresh_token || dbSession.refresh_token,
      expires_at: Date.now() + ((d.expires_in || 3600) - 60) * 1000
    };
    const stored = readStoredSession();
    writeStoredSession({ ok: true, db: dbSession }, !!(stored && stored.store === localStorage));
    return true;
  } catch (e) {
    return false;
  }
}

// 令牌快过期时先续期，避免请求打回 401
async function ensureFreshSession() {
  if (dbSession && Date.now() >= dbSession.expires_at) {
    const ok = await refreshDatabaseSession();
    if (!ok) {
      dbSession = null;
      dbAuthReady = false;
      showLogin('登录已过期，请重新输入密码');
    }
  }
}

function showLogin(message) {
  const overlay = document.getElementById('loginOverlay');
  const app = document.getElementById('appRoot');
  if (overlay) overlay.classList.remove('hidden');
  if (app) app.classList.remove('ready');
  const err = document.getElementById('loginErr');
  if (err) err.textContent = message || '';
  const input = document.getElementById('loginPassword');
  if (input) { input.value = ''; setTimeout(() => input.focus(), 50); }
}

function enterApp() {
  document.getElementById('loginOverlay').classList.add('hidden');
  document.getElementById('appRoot').classList.add('ready');
  const banner = document.getElementById('setupBanner');
  if (banner && !dbAuthReady) {
    banner.innerHTML = '⚠️ <b>数据库登录失败</b>，当前仅有页面密码保护。' +
      (dbAuthError
        ? '<br>Supabase 返回：<code>' + esc(dbAuthError) + '</code><br>处理办法：' + esc(authErrorHint(dbAuthError))
        : '请按 <code>README.md</code> 创建登录账号并执行 <code>supabase/security.sql</code>。') +
      '<br>账号邮箱应为 <code>' + esc(AUTH_EMAIL) + '</code>，密码与页面登录密码相同。';
    banner.classList.add('visible');
  } else if (banner) {
    banner.classList.remove('visible');
  }
  loadData();
}

async function submitLogin(event) {
  if (event) event.preventDefault();
  const input = document.getElementById('loginPassword');
  const err = document.getElementById('loginErr');
  const btn = document.getElementById('loginBtn');
  const password = (input.value || '').trim();
  if (!password) { err.textContent = '请输入密码'; return; }

  btn.disabled = true;
  btn.textContent = '验证中…';
  try {
    const hash = await sha256b64(PASSWORD_SALT + password);
    if (hash !== PASSWORD_HASH) {
      err.textContent = '密码错误';
      input.value = '';
      input.focus();
      return;
    }
    dbSession = await signInToDatabase(password);
    dbAuthReady = !!dbSession;
    const remember = document.getElementById('loginRemember').checked;
    writeStoredSession({ ok: true, db: dbSession }, remember);
    err.textContent = '';
    enterApp();
  } catch (e) {
    err.textContent = '登录失败：' + e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = '进入系统';
  }
}

function logout() {
  if (!confirm('确认退出登录？')) return;
  clearStoredSession();
  clearCachedOrders();   // 退出后不该在本机留下客户资料
  dbSession = null;
  dbAuthReady = false;
  location.reload();
}

async function bootstrap() {
  const stored = readStoredSession();
  if (!stored || !stored.data || !stored.data.ok) { showLogin(''); return; }
  dbSession = stored.data.db || null;
  // 上次登录没换到数据库令牌（多半是当时 Supabase 账号还没配好）。
  // 缓存这个残缺状态没有意义，重新要一次密码，好再试一遍换取令牌。
  if (!dbSession) { showLogin('请重新输入密码，以连接数据库'); return; }
  if (Date.now() >= dbSession.expires_at) {
    const refreshed = await refreshDatabaseSession();
    if (!refreshed) { clearStoredSession(); showLogin('登录已过期，请重新输入密码'); return; }
  }
  dbAuthReady = !!dbSession;
  enterApp();
}

// 单人使用：新建订单一律记在这个名下。
// 该字段仍写入数据库，历史数据与导出格式保持兼容。
const SALES_PERSON = '大卫';

let orders = [];
let editingIdx = -1;
let saving = false;
let usingCachedData = false;

// 趋势图看的是佣金还是订单量
let trendMetric = 'commission';
try { trendMetric = localStorage.getItem('salesOrderTrendMetric') || 'commission'; } catch (e) {}

// 最近一次成功加载的数据，供离线时只读展示
const DATA_CACHE_KEY = 'salesOrderData';

// 只显示本人名下的订单。数据库里可能还留着他人（或早期导入时归属为空）的
// 历史记录，它们不进入界面，但会在顶部标出条数，避免悄无声息地消失。
let hiddenCount = 0;     // 当前视图之外还有多少条
let allOrders = [];      // 数据库返回的全部记录
// 'mine' = 只看本人名下；'others' = 只看非本人名下，用于清理历史遗留数据。
// 不做持久化：每次打开一律回到「我的订单」，避免莫名其妙停在另一个视图里。
let viewMode = 'mine';

function isMine(o) { return o.salesPerson === SALES_PERSON; }

// 收到数据后重新切分两个视图；换视图时也走这里，无需重新请求。
function applyView() {
  const mine = allOrders.filter(isMine);
  const others = allOrders.filter(o => !isMine(o));
  orders = viewMode === 'others' ? others : mine;
  hiddenCount = viewMode === 'others' ? mine.length : others.length;
  refreshViewToggle(others.length);
}

function refreshViewToggle(otherCount) {
  const btn = document.getElementById('viewToggle');
  const banner = document.getElementById('otherViewBanner');
  if (!btn) return;
  // 没有遗留数据时不必露出这个入口
  btn.style.display = (otherCount > 0 || viewMode === 'others') ? '' : 'none';
  btn.textContent = viewMode === 'others'
    ? '← 返回我的订单'
    : '查看其他归属 (' + otherCount + ')';
  btn.classList.toggle('active', viewMode === 'others');
  if (banner) banner.classList.toggle('visible', viewMode === 'others');
}

function toggleView() {
  viewMode = viewMode === 'others' ? 'mine' : 'others';
  applyView();
  refreshFilterOptions();
  renderAll();
  document.getElementById('lastUpdate').textContent =
    statusLine('最后更新：' + new Date().toLocaleString('zh-CN'));
}

function statusLine(suffix) {
  if (viewMode === 'others') {
    return '⚠️ 正在查看非本人名下的 ' + orders.length + ' 条记录（你自己的 ' +
      hiddenCount + ' 条已暂时隐藏）· ' + suffix;
  }
  return '共 ' + orders.length + ' 条记录' +
    (hiddenCount ? '（另有 ' + hiddenCount + ' 条非本人名下，未显示）' : '') +
    ' · ' + suffix;
}

function cacheOrders(rows) {
  try {
    localStorage.setItem(DATA_CACHE_KEY, JSON.stringify({ at: Date.now(), rows }));
  } catch (e) { /* 超出配额时放弃缓存即可，不影响主流程 */ }
}

function readCachedOrders() {
  try {
    const raw = localStorage.getItem(DATA_CACHE_KEY);
    if (!raw) return null;
    const d = JSON.parse(raw);
    return (d && Array.isArray(d.rows)) ? d : null;
  } catch (e) { return null; }
}

function clearCachedOrders() {
  try { localStorage.removeItem(DATA_CACHE_KEY); } catch (e) {}
}

// 服务端说有多少条但这次没全给：> 0 表示被截断了，界面必须提示
let truncatedTotal = 0;
// 读不到总数（跨域下 Content-Range 需要服务端 expose）且条数已经很多时，
// 无法证明数据取全了。这种「查不了」也要说出来，否则守卫本身就是静默失效的。
let countUnverified = false;
const COUNT_SUSPICIOUS_AT = 1000;   // 常见的单次返回上限

// Content-Range 形如 "0-999/1350"
function parseTotalCount(header, got) {
  const total = parseInt(String(header || '').split('/')[1], 10);
  countUnverified = !isFinite(total) && got >= COUNT_SUSPICIOUS_AT;
  return (isFinite(total) && total > got) ? total : 0;
}

// 本地日期格式化：避免 toISOString() 因 UTC 时区导致日期偏移一天
function ymd(d) {
  const p = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
}
function todayStr() { return ymd(new Date()); }

function toRow(o) {
  return {
    apply_date:      o.applyDate || null,
    payback_date:    o.paybackDate || null,
    name:            o.name || '',
    phone:           o.phone || '',
    province:        o.province || '',
    city:            o.city || '',
    carrier:         o.carrier || '',
    package:         o.package || '',
    duration:        o.duration || '',
    install_fee:     Number(o.installFee)     || 0,
    package_fee:     Number(o.packageFee)     || 0,
    commission:      Number(o.commission)     || 0,
    commission_rate: Number(o.commissionRate) || 0,
    id_card:         o.idCard  || '',
    address:         o.address || '',
    sales_person:    o.salesPerson || SALES_PERSON
  };
}

function fromRow(r) {
  return {
    id:             r.id,
    applyDate:      r.apply_date || '',
    paybackDate:    r.payback_date || '',
    name:           r.name || '',
    phone:          r.phone || '',
    province:       r.province || '',
    city:           r.city || '',
    carrier:        r.carrier || '',
    package:        r.package || '',
    duration:       r.duration || '',
    installFee:     Number(r.install_fee)     || 0,
    packageFee:     Number(r.package_fee)     || 0,
    commission:     Number(r.commission)      || 0,
    commissionRate: Number(r.commission_rate) || 0,
    idCard:         r.id_card || '',
    address:        r.address || '',
    salesPerson:    r.sales_person || ''
  };
}

async function loadData() {
  document.getElementById('lastUpdate').textContent = '数据加载中…';
  await ensureFreshSession();
  try {
    // count=exact 让 Supabase 在 Content-Range 里回总行数。接口有默认返回上限，
    // 超出会被静默截断——不比对的话统计和合计会悄悄算少，这是会「算错钱」的。
    const res = await fetch(REST + '?select=*&order=apply_date.desc.nullslast,created_at.desc', {
      headers: Object.assign(HEADERS(), { 'Prefer': 'count=exact' })
    });
    if (res.status === 401 || res.status === 403) {
      throw new Error('无访问权限（' + res.status + '），请重新登录或检查 Supabase RLS 配置');
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const rows = await res.json();
    truncatedTotal = parseTotalCount(res.headers.get('Content-Range'), rows.length);
    allOrders = rows.map(fromRow);
    applyView();
    usingCachedData = false;
    cacheOrders(rows);
  } catch (e) {
    // 装到主屏后断网也会走到这里：有缓存就以只读方式先顶上，好过一片空白
    const cached = readCachedOrders();
    if (cached) {
      allOrders = cached.rows.map(fromRow);
      truncatedTotal = 0; countUnverified = false;   // 缓存里就这些，无从判断是否截断
      applyView();
      usingCachedData = true;
      showOfflineBanner(cached.at, e.message);
      refreshFilterOptions();
      renderAll();
      document.getElementById('lastUpdate').textContent =
        statusLine('离线数据，缓存于 ' + new Date(cached.at).toLocaleString('zh-CN'));
      return;
    }
    orders = [];
    truncatedTotal = 0; countUnverified = false;
    document.getElementById('lastUpdate').textContent = '加载失败：' + e.message;
    renderAll();
    return;
  }
  hideOfflineBanner();
  refreshFilterOptions();
  renderAll();
  document.getElementById('lastUpdate').textContent =
    statusLine('最后更新：' + new Date().toLocaleString('zh-CN'));
}

function refreshFilterOptions() {
  refreshMonthOptions();
  const sel = document.getElementById('filterProvince');
  if (!sel) return;
  const prev = sel.value;
  const provinces = Array.from(new Set(
    orders.map(o => o.province).filter(Boolean)
  )).sort((a,b) => a.localeCompare(b,'zh-CN'));
  sel.innerHTML = '<option value="">全部省份</option>' +
    provinces.map(p => `<option value="${escAttr(p)}">${esc(p)}</option>`).join('');
  if (provinces.includes(prev)) sel.value = prev;
  refreshCityOptions();
}

/* 月份筛选值就是日期前缀：'' 全部、'2026' 整年、'2026-09' 单月，
   所以匹配逻辑一句 startsWith 就够，不必再维护起止日期两个输入框。 */
function refreshMonthOptions() {
  const sel = document.getElementById('filterMonth');
  if (!sel) return;
  const prev = sel.value;
  const months = new Set(orders.map(o => (o.applyDate || '').slice(0, 7)).filter(m => m.length === 7));
  months.add(todayStr().slice(0, 7));   // 本月没单也要能选，看板「本月订单」要跳过来
  const byYear = new Map();
  Array.from(months).sort().reverse().forEach(m => {
    const y = m.slice(0, 4);
    if (!byYear.has(y)) byYear.set(y, []);
    byYear.get(y).push(m);
  });
  let html = '<option value="">全部时间</option>';
  for (const [year, list] of byYear) {
    html += '<optgroup label="' + year + '">' +
      '<option value="' + year + '">' + year + ' 全年</option>' +
      list.map(m => '<option value="' + m + '">' + m.replace('-', ' 年 ') + ' 月</option>').join('') +
      '</optgroup>';
  }
  sel.innerHTML = html;
  sel.value = prev;
  if (sel.value !== prev) sel.value = '';   // 原来选的月份已无数据，退回全部
}

// 城市跟着省份走：选了省份就只列该省的城市，避免一长串跨省城市
function refreshCityOptions() {
  const sel = document.getElementById('filterCity');
  if (!sel) return;
  const prev = sel.value;
  const province = document.getElementById('filterProvince').value;
  const cities = Array.from(new Set(
    orders.filter(o => !province || o.province === province)
          .map(o => o.city).filter(Boolean)
  )).sort((a,b) => a.localeCompare(b,'zh-CN'));
  sel.innerHTML = '<option value="">全部城市</option>' +
    cities.map(c => `<option value="${escAttr(c)}">${esc(c)}</option>`).join('');
  sel.value = cities.includes(prev) ? prev : '';
}

function onProvinceChange() {
  refreshCityOptions();
  renderAll();
}

/* 所有筛选入口都走这里：看板、趋势图、分析卡、表格用的是同一份筛选结果。
   以前只有表格跟着筛选走，卡片和图表永远显示全量，筛完对不上号。 */
function renderAll() {
  const view = getFilteredOrders();
  renderScope(view);
  renderStats(view);
  renderRenewals();
  renderTrend();
  renderAnalysis();
  renderTable(view);
  renderTruncBanner();
}

// 写清楚当前这批数字是什么口径的，不然筛完不知道看的是哪一撮
function renderScope(view) {
  const el = document.getElementById('scopeLine');
  if (!el) return;
  const parts = [];
  const month = document.getElementById('filterMonth');
  const province = document.getElementById('filterProvince').value;
  const city = document.getElementById('filterCity').value;
  const carrier = document.getElementById('filterCarrier').value;
  if (month.value) parts.push(month.options[month.selectedIndex].text);
  if (province) parts.push(province);
  if (city) parts.push(city);
  if (carrier) parts.push(carrier);
  const statusText = { unpaid: '未结佣', paid: '已结佣', over30: '逾 30 天', over60: '逾 60 天' }[paybackFilter];
  if (statusText) parts.push(statusText);
  const q = document.getElementById('searchInput').value.trim();
  if (q) parts.push('搜索「' + q + '」');

  el.innerHTML = parts.length
    ? '<b>当前口径</b>：' + parts.map(esc).join(' · ') + ' —— 以下卡片、图表与表格均只统计这 ' + view.length + ' 笔'
    : '<b>当前口径</b>：全部 ' + view.length + ' 笔订单';
}

function renderStats(view) {
  const mine = view || orders;
  const total = mine.length;
  const totalCommission = mine.reduce((s, o) => s + (Number(o.commission)||0), 0);

  // 本月与上月：用于环比。这两项按自然月取，不受月份筛选影响，
  // 否则筛到 8 月时「本月订单」会变成 0，读起来是错的。
  const byMonth = selectOrders('month');
  const now = new Date();
  const ym = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2,'0');
  const lastMonthDate = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const lastYm = lastMonthDate.getFullYear() + '-' + String(lastMonthDate.getMonth()+1).padStart(2,'0');

  const thisMonthOrders = byMonth.filter(o => o.applyDate && o.applyDate.startsWith(ym));
  const lastMonthOrders = byMonth.filter(o => o.applyDate && o.applyDate.startsWith(lastYm));
  const monthNew = thisMonthOrders.length;
  const monthCommission = thisMonthOrders.reduce((s, o) => s + (Number(o.commission)||0), 0);

  // 环比：按订单数比，上月为 0 时百分比没有意义，只说明是新增
  let deltaHtml = '';
  if (lastMonthOrders.length > 0) {
    const pct = Math.round((monthNew - lastMonthOrders.length) / lastMonthOrders.length * 100);
    const cls = pct > 0 ? 'delta-up' : (pct < 0 ? 'delta-down' : 'delta-flat');
    const arrow = pct > 0 ? '↑' : (pct < 0 ? '↓' : '–');
    deltaHtml = '<span class="delta ' + cls + '">' + arrow + ' ' + Math.abs(pct) + '% 环比上月</span>';
  } else if (monthNew > 0) {
    deltaHtml = '<span class="delta delta-up">上月无订单</span>';
  }

  const unpaid = mine.filter(o => !o.paybackDate);
  const unpaidCount = unpaid.length;
  const agings = unpaid.map(agingDays).filter(d => d !== null);
  const oldestAging = agings.length ? Math.max(...agings) : null;

  // 结佣周期：CPS 模式下「钱多久到」比「做了多少单」更值得盯
  const st = settleStats(mine);

  document.getElementById('stats').innerHTML = [
    {
      label: '本月订单',
      value: monthNew + ' 笔',
      extra: deltaHtml || '<div class="sub">本月佣金 ¥' + monthCommission.toLocaleString() + '</div>',
      onclick: 'setMonthFilter(\'' + ym + '\')'
    },
    {
      label: '佣金合计',
      value: '¥' + totalCommission.toLocaleString(),
      extra: '<div class="sub">共 ' + total + ' 笔订单</div>',
      onclick: 'setMonthFilter(\'\')'
    },
    {
      label: '未结佣',
      value: unpaidCount + ' 笔',
      cls: unpaidCount > 0 ? ' warn' : '',
      // 这张卡不放金额（此前明确要求去掉）；压着多少钱看下面的账龄分布卡
      extra: oldestAging !== null ? '<div class="sub">最久 ' + oldestAging + ' 天</div>' : '',
      onclick: 'applyPaybackFilter(\'unpaid\')'
    },
    {
      label: '结佣周期（中位数）',
      value: st ? st.median + ' 天' : '—',
      extra: st
        ? '<div class="sub">最快 ' + st.min + ' · 最慢 ' + st.max + ' 天（' + st.n + ' 笔已结佣）</div>'
        : '<div class="sub">还没有已结佣的订单</div>',
      onclick: st ? 'applyPaybackFilter(\'paid\')' : ''
    }
  ].map(c => {
    const body = '<div class="value">' + c.value + '</div>' + (c.extra || '');
    const clickable = c.onclick ? ' clickable" onclick="' + c.onclick + '" title="点击查看对应记录' : '';
    return '<div class="stat-card' + (c.cls || '') + clickable + '"><div class="label">' + c.label + '</div>' + body + '</div>';
  }).join('');
}

function carrierBadge(c) {
  if (c === '联通') return 'badge-unicom';
  if (c === '移动') return 'badge-mobile';
  return 'badge-telecom';
}

const CARRIER_COLOR = { '联通': 'var(--c-unicom)', '移动': 'var(--c-mobile)', '电信': 'var(--c-telecom)' };

function money(n) { return '¥' + Number(n || 0).toLocaleString(); }

/* ========== 分析区 ==========
   三张卡都吃当前筛选；但按某维度拆分的卡不吃自己那一维的筛选
   （否则只剩一行），改为把选中的那一项高亮。 */
function renderAnalysis() {
  // 左：卖什么最好卖 · 中：在哪卖得最多 · 右：跟谁家合作更划算
  document.getElementById('analysisGrid').innerHTML =
    renderComboCard() + renderCityCard() + renderCarrierCard();
}

/* 热销组合：城市 × 运营商 × 套餐 一起看，回答「在哪、用谁家、卖哪档最好卖」。
   单看城市或单看套餐都答不了这个——旁边两张卡已经分别拆了运营商和地区，
   这张卡的价值就在于三者绑在一起的那个具体组合。
   「热销」看的是走量，所以排序和条长都用笔数，佣金另列；
   套餐写法大小写不一（300m / 300M）先统一成大写，否则同一档会被拆成两行。 */
function comboGroups(list) {
  const map = new Map();
  list.forEach(o => {
    const city = (o.city || '').trim();
    const carrier = (o.carrier || '').trim();
    const pkg = (o.package || '').trim().toUpperCase();
    if (!city && !carrier && !pkg) return;   // 三项全空的记录没什么可分析的
    const key = [city || '未填', carrier || '未填', pkg || '未填'].join('');
    if (!map.has(key)) {
      map.set(key, { city, carrier, pkg, province: (o.province || '').trim(), count: 0, commission: 0 });
    }
    const g = map.get(key);
    g.count++;
    g.commission += Number(o.commission) || 0;
  });
  return Array.from(map.values())
    // 笔数并列时按佣金高的排前，避免顺序随数据顺序漂移
    .sort((a, b) => b.count - a.count || b.commission - a.commission);
}

function renderComboCard() {
  const groups = comboGroups(selectOrders());
  const top = groups.slice(0, 6);
  const max = Math.max(...top.map(g => g.count), 1);

  const body = top.length === 0
    ? '<div class="an-empty">当前口径下暂无可分析的组合</div>'
    : '<table class="an-table"><thead><tr>' +
        '<th>城市 · 运营商 · 套餐</th><th>笔数</th><th>佣金</th>' +
      '</tr></thead><tbody>' +
      top.map(g => {
        const color = CARRIER_COLOR[g.carrier] || 'var(--c-bar)';
        const label = (g.city || '未填') + ' · ' + (g.carrier || '未填') + ' · ' + (g.pkg || '未填');
        return '<tr class="clickable" onclick="setComboFilter(' +
            '\'' + escAttr(g.province) + '\',\'' + escAttr(g.city) + '\',' +
            '\'' + escAttr(g.carrier) + '\',\'' + escAttr(g.pkg) + '\')"' +
            ' title="点击只看「' + escAttr(label) + '」的订单，再点一次取消">' +
          '<td class="an-combo"><span class="an-swatch" style="background:' + color + '"></span>' + esc(label) + '</td>' +
          '<td><div class="an-share"><div class="an-track"><div class="an-fill" style="width:' +
            (g.count / max * 100).toFixed(1) + '%;background:var(--c-bar)"></div></div>' +
            '<span class="an-val">' + g.count + '</span></div></td>' +
          '<td>' + money(g.commission) + '</td>' +
        '</tr>';
      }).join('') + '</tbody></table>';

  const more = groups.length > 6 ? '（共 ' + groups.length + ' 种组合，只显示前 6）' : '';
  return '<div class="an-card"><h3>热销组合</h3>' +
    '<div class="an-hint">城市 × 运营商 × 套餐，按笔数排序' + more + '</div>' + body + '</div>';
}

/* 一次落三个筛选条件。城市下拉的选项跟着省份走，所以要先把省份设好
   再设城市，否则城市不在当前选项里会被静默置空。套餐没有独立控件，
   借搜索框（搜索本就覆盖套餐字段）。再点同一行则整组取消。 */
function setComboFilter(province, city, carrier, pkg) {
  const pSel = document.getElementById('filterProvince');
  const cSel = document.getElementById('filterCity');
  const carSel = document.getElementById('filterCarrier');
  const box = document.getElementById('searchInput');

  const already = cSel.value === city && carSel.value === carrier &&
                  box.value.trim().toUpperCase() === pkg;
  if (already) {
    pSel.value = ''; cSel.value = ''; carSel.value = ''; box.value = '';
    refreshCityOptions();
  } else {
    if (province) pSel.value = province;
    refreshCityOptions();
    if (city) setSelectValue(cSel, city);
    carSel.value = carrier || '';
    box.value = pkg || '';
  }
  renderAll();
}

// P1+P3 运营商表现：不只看发单量，更要看谁赚得多、谁回款快
function renderCarrierCard() {
  const list = selectOrders('carrier');
  const groups = groupBy(list, o => o.carrier);
  const active = document.getElementById('filterCarrier').value;
  const totalCommission = groups.reduce((s, g) => s + g.commission, 0) || 1;
  groups.sort((a, b) => b.commission - a.commission);

  const body = groups.length === 0
    ? '<div class="an-empty">当前口径下暂无数据</div>'
    : '<table class="an-table"><thead><tr>' +
        '<th>运营商</th><th>佣金占比</th><th>笔数</th><th>单均佣金</th><th>结佣周期</th>' +
      '</tr></thead><tbody>' +
      groups.map(g => {
        const pct = Math.round(g.commission / totalCommission * 100);
        const color = CARRIER_COLOR[g.key] || 'var(--c-bar)';
        const on = active === g.key;
        return '<tr class="clickable"' + (on ? ' style="background:#f1f5f9"' : '') +
            ' onclick="setCarrierFilter(\'' + escAttr(g.key) + '\')"' +
            ' title="点击只看' + escAttr(g.key) + '">' +
          '<td><span class="an-swatch" style="background:' + color + '"></span>' + esc(g.key) + '</td>' +
          '<td><div class="an-share"><div class="an-track"><div class="an-fill" style="width:' +
            pct + '%;background:' + color + '"></div></div><span class="an-val">' + pct + '%</span></div></td>' +
          '<td>' + g.count + '</td>' +
          '<td>' + money(g.avgCommission) + '</td>' +
          '<td>' + (g.settleMedian === null
            ? '<span class="an-muted">—</span>'
            : g.settleMedian + ' 天') + '</td>' +
        '</tr>';
      }).join('') + '</tbody></table>';

  return '<div class="an-card"><h3>运营商表现</h3>' +
    '<div class="an-hint">单均佣金决定把客资给谁，结佣周期决定钱多久到（中位数）</div>' + body + '</div>';
}

/* 城市 Top5：一律按城市看，不再按省份聚合。
   省份在筛选行里仍可单独筛，这张卡只回答「哪个城市最出货」。
   带上省份是因为城市下拉的选项跟着省份走，点选时要先把省份设对。 */
function cityGroups(list) {
  const map = new Map();
  list.forEach(o => {
    const city = (o.city || '').trim();
    if (!city) return;
    if (!map.has(city)) {
      map.set(city, { city, province: (o.province || '').trim(), count: 0, commission: 0 });
    }
    const g = map.get(city);
    g.count++;
    g.commission += Number(o.commission) || 0;
  });
  return Array.from(map.values())
    .sort((a, b) => b.commission - a.commission || b.count - a.count);
}

function renderCityCard() {
  const groups = cityGroups(selectOrders('region'));
  const top = groups.slice(0, 5);
  const max = Math.max(...top.map(g => g.commission), 1);
  const activeCity = document.getElementById('filterCity').value;

  const body = top.length === 0
    ? '<div class="an-empty">当前口径下暂无城市数据</div>'
    : top.map(g => {
        const on = activeCity === g.city;
        return '<div class="an-row clickable"' + (on ? ' style="background:#f1f5f9"' : '') +
            ' onclick="setCityFilter(\'' + escAttr(g.province) + '\',\'' + escAttr(g.city) + '\')"' +
            ' title="点击只看' + escAttr(g.city) + '，再点一次取消">' +
          '<span class="an-label">' + esc(g.city) + '</span>' +
          '<div class="an-track"><div class="an-fill" style="width:' +
            (g.commission / max * 100).toFixed(1) + '%;background:var(--c-bar)"></div></div>' +
          '<span class="an-val"><b>' + money(g.commission) + '</b> · ' + g.count + ' 笔</span>' +
        '</div>';
      }).join('');

  const more = groups.length > 5 ? '（共 ' + groups.length + ' 个城市，只显示前 5）' : '';
  return '<div class="an-card"><h3>城市 Top 5</h3>' +
    '<div class="an-hint">按佣金排序' + more + '</div>' + body + '</div>';
}

// 从分析卡点选运营商：再点一次同一个取消，和胶囊的手感一致
function setCarrierFilter(name) {
  const sel = document.getElementById('filterCarrier');
  sel.value = sel.value === name ? '' : name;
  renderAll();
}

// 设城市前先设省份：城市下拉的选项跟着省份走，顺序反了会被静默置空
function setCityFilter(province, city) {
  const pSel = document.getElementById('filterProvince');
  const cSel = document.getElementById('filterCity');
  if (cSel.value === city) {
    pSel.value = '';
    cSel.value = '';
    refreshCityOptions();
  } else {
    if (province) pSel.value = province;
    refreshCityOptions();
    setSelectValue(cSel, city);
  }
  renderAll();
}

/* ========== 页面内提示（替代 alert）==========
   alert() 在手机上是阻塞式弹窗，还会打断正在填的表单。
   opts.type: info / success / warn / error；opts.action: { label, onClick }（如「撤销」）。
   报错信息里可能带服务端原文，一律按纯文本塞，不当 HTML 解析。
   返回一个关闭函数。 */
function toast(message, opts = {}) {
  const stack = document.getElementById('toastStack');
  if (!stack) return () => {};
  const type = opts.type || 'info';
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');

  const text = document.createElement('span');
  text.className = 'toast-text';
  text.textContent = message;
  el.appendChild(text);

  let timer = null;
  let gone = false;
  const dismiss = () => {
    if (gone) return;
    gone = true;
    clearTimeout(timer);
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 200);
  };

  if (opts.action) {
    const btn = document.createElement('button');
    btn.className = 'toast-action';
    btn.textContent = opts.action.label;
    btn.onclick = () => { dismiss(); opts.action.onClick(); };
    el.appendChild(btn);
  }
  const close = document.createElement('button');
  close.className = 'toast-close';
  close.setAttribute('aria-label', '关闭提示');
  close.textContent = '×';
  close.onclick = dismiss;
  el.appendChild(close);

  // 带操作的（如撤销）要留够反应时间；报错比普通提示多停一会儿
  const ms = opts.duration ?? (opts.action ? 8000 : type === 'error' ? 6000 : 3500);
  const arm = t => { clearTimeout(timer); timer = setTimeout(dismiss, t); };
  arm(ms);
  // 鼠标停在上面时不自动收走，读长报错时不会看到一半消失。
  // 只认真鼠标：手机上点一下会触发 mouseenter 却不会有 mouseleave，
  // 用 mouse 事件的话提示会永远挂在屏幕上。
  el.addEventListener('pointerenter', e => { if (e.pointerType === 'mouse') clearTimeout(timer); });
  el.addEventListener('pointerleave', e => { if (e.pointerType === 'mouse') arm(2000); });

  stack.appendChild(el);
  return dismiss;
}

function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
// 放进属性值时还要挡住引号
function escAttr(s) { return esc(s).replace(/"/g, '&quot;'); }

/* ========== 未结佣账龄 ==========
   'YYYY-MM-DD' 交给 Date 解析会按 UTC 处理，东八区会差一天，这里按本地日期解。*/
function parseYmd(str) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(str || '');
  return m ? new Date(+m[1], +m[2] - 1, +m[3]) : null;
}

// 从办理日期到今天的天数；日期缺失或在未来时返回 null
function agingDays(o) {
  if (o.paybackDate) return null;
  const d = parseYmd(o.applyDate);
  if (!d) return null;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const days = Math.round((today - d) / 86400000);
  return days >= 0 ? days : null;
}

// 30 / 60 天两道线，与催款节奏对应
function agingLevel(days) {
  if (days === null) return '';
  if (days >= 60) return 'age-bad';
  if (days >= 30) return 'age-warn';
  return 'age-ok';
}

/* ========== 结佣周期 ==========
   CPS 模式下真正要回答的是「钱多久到」：办理日期 → 结佣日期的天数。
   只有已结佣的订单才有这个值。 */
function settleDays(o) {
  if (!o.paybackDate) return null;
  const a = parseYmd(o.applyDate), b = parseYmd(o.paybackDate);
  if (!a || !b) return null;
  const days = Math.round((b - a) / 86400000);
  return days >= 0 ? days : null;
}

/* ========== 套餐到期续约提醒 ==========
   到期日 = 办理日期 + 时限。没有单独记录装机日，办理日期是能拿到的最近似值。
   到期是二次客资机会：提前联系续约或推荐升级。 */

// 时限写法五花八门：6个月 / 1年 / 18个月 / 一年 / 两年 / 半年；认不出返回 0
function durationMonths(str) {
  const s = String(str || '').trim();
  if (!s) return 0;
  if (/半年/.test(s)) return 6;
  const y = s.match(new RegExp('([' + CN_NUM_CHARS + ']+)\\s*年'));
  if (y && cnNumber(y[1])) return cnNumber(y[1]) * 12;
  const m = s.match(new RegExp('([' + CN_NUM_CHARS + ']+)\\s*个?月'));
  if (m && cnNumber(m[1])) return cnNumber(m[1]);
  return 0;
}

// 加月份时日要夹紧：1 月 31 日 + 1 个月应是 2 月 28/29 日，
// 直接 new Date(y, m+1, 31) 会溢出成 3 月初
function addMonthsClamped(d, n) {
  const y = d.getFullYear(), m = d.getMonth() + n;
  const lastDay = new Date(y, m + 1, 0).getDate();
  return new Date(y, m, Math.min(d.getDate(), lastDay));
}

function expiryDate(o) {
  const start = parseYmd(o.applyDate);
  const months = durationMonths(o.duration);
  return (start && months) ? addMonthsClamped(start, months) : null;
}

const RENEW_WINDOW = 30;   // 前后各看 30 天：快到期的要联系，刚过期的还来得及挽回

function renewalCandidates(list) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  // 同一手机号后来又办过单，说明已经续上了，不必再提醒
  const latestByPhone = new Map();
  allOrders.forEach(o => {
    if (!o.phone || !o.applyDate) return;
    if (!latestByPhone.has(o.phone) || o.applyDate > latestByPhone.get(o.phone)) {
      latestByPhone.set(o.phone, o.applyDate);
    }
  });
  return list
    .filter(o => !o.phone || latestByPhone.get(o.phone) === o.applyDate)
    .map(o => {
      const exp = expiryDate(o);
      if (!exp) return null;
      return { o, exp, daysLeft: Math.round((exp - today) / 86400000) };
    })
    .filter(r => r && r.daysLeft >= -RENEW_WINDOW && r.daysLeft <= RENEW_WINDOW)
    .sort((a, b) => a.daysLeft - b.daysLeft);
}

let renewExpanded = false;
const RENEW_PREVIEW = 5;

function toggleRenewals() {
  renewExpanded = !renewExpanded;
  renderRenewals();
}

// 跟随除月份以外的筛选：到期的单都是一两年前办的，吃了月份筛选就永远是空的
function renderRenewals() {
  const wrap = document.getElementById('renewWrap');
  if (!wrap) return;
  const items = renewalCandidates(selectOrders('month'));
  if (!items.length) { wrap.innerHTML = ''; return; }

  const expired = items.filter(r => r.daysLeft < 0).length;
  const upcoming = items.length - expired;
  const shown = renewExpanded ? items : items.slice(0, RENEW_PREVIEW);

  const rows = shown.map(({ o, exp, daysLeft }) => {
    const idx = orders.indexOf(o);
    const status = daysLeft < 0
      ? '<span class="age-bad">已到期 ' + (-daysLeft) + ' 天</span>'
      : daysLeft === 0
        ? '<span class="age-bad">今天到期</span>'
        : '<span class="' + (daysLeft <= 7 ? 'age-warn' : 'age-ok') + '">剩 ' + daysLeft + ' 天</span>';
    return '<tr class="clickable"' + (idx >= 0 ? ' onclick="showRowDetail(' + idx + ')"' : '') +
        ' title="点击查看订单详情">' +
      '<td class="col-name">' + esc(o.name) + '</td>' +
      // tel: 链接在手机上点一下就能拨号；阻止冒泡，免得同时弹出详情
      '<td><a class="renew-tel" href="tel:' + escAttr(o.phone) + '" onclick="event.stopPropagation()">' +
        esc(o.phone) + '</a></td>' +
      '<td class="renew-city">' + esc(o.city) + '</td>' +
      '<td><span class="badge ' + carrierBadge(o.carrier) + '">' + esc(o.carrier) + '</span> ' +
        '<span class="col-package">' + esc(o.package) + '</span> ' +
        '<span class="an-muted">' + esc(o.duration) + '</span></td>' +
      '<td class="renew-apply">' + esc(o.applyDate) + '</td>' +
      '<td>' + ymd(exp) + '</td>' +
      '<td class="text-right">' + status + '</td>' +
    '</tr>';
  }).join('');

  const more = items.length > RENEW_PREVIEW
    ? '<button class="btn-link" onclick="toggleRenewals()">' +
        (renewExpanded ? '收起' : '展开全部 ' + items.length + ' 位') + '</button>'
    : '';

  wrap.innerHTML = '<div class="renew-card">' +
    '<h3>续约提醒' +
      '<span class="hint">' +
        (upcoming ? RENEW_WINDOW + ' 天内到期 <b>' + upcoming + '</b> 位' : '') +
        (upcoming && expired ? ' · ' : '') +
        (expired ? '已到期 <b>' + expired + '</b> 位' : '') +
        ' · 到期日按办理日期 + 时限推算</span>' + more + '</h3>' +
    '<table class="renew-table"><thead><tr>' +
      '<th>客户</th><th>手机号</th><th class="renew-city">城市</th><th>原套餐</th>' +
      '<th class="renew-apply">办理日期</th><th>到期日</th><th class="text-right">状态</th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table></div>';
}

// 用中位数而不是平均：样本少的时候一笔拖很久的单会把平均值整个带偏
function median(nums) {
  if (!nums.length) return null;
  const s = [...nums].sort((x, y) => x - y);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
}

function settleStats(list) {
  const days = list.map(settleDays).filter(d => d !== null);
  if (!days.length) return null;
  return { median: median(days), min: Math.min(...days), max: Math.max(...days), n: days.length };
}

// 按任意字段聚合：笔数、佣金、单均佣金、结佣周期中位数
function groupBy(list, keyOf) {
  const map = new Map();
  list.forEach(o => {
    const k = keyOf(o);
    if (!k) return;
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(o);
  });
  return Array.from(map, ([key, items]) => {
    const commission = items.reduce((s, o) => s + (Number(o.commission) || 0), 0);
    const st = settleStats(items);
    return {
      key, count: items.length, commission,
      avgCommission: Math.round(commission / items.length),
      settleMedian: st ? st.median : null
    };
  });
}

// 与 CSS 里的手机端断点保持一致
function isNarrow() { return window.matchMedia('(max-width:768px)').matches; }

// 给下拉框赋一个选项里没有的值，浏览器会静默置空，保存时就把原值抹掉了。
// 智能提取和 CSV 导入都可能给出「18个月」这类非预置写法，这里按需补进去。
function setSelectValue(sel, value) {
  const v = (value || '').trim();
  if (!v) { sel.selectedIndex = 0; return; }
  if (!Array.from(sel.options).some(o => o.value === v)) {
    sel.add(new Option(v, v));
  }
  sel.value = v;
}

/* 按维度取数。except 用来排除某一个维度自身的筛选：
   按月份拆的趋势图若吃掉月份筛选，就只剩一根柱子；运营商图、地区图同理。
   这些图改为「不吃自己那一维，但高亮选中项」，其余维度照常生效。 */
function selectOrders(except) {
  const q = document.getElementById('searchInput').value.toLowerCase();
  const carrierFilter = except === 'carrier' ? '' : document.getElementById('filterCarrier').value;
  const provinceFilter = except === 'region' ? '' : document.getElementById('filterProvince').value;
  const cityFilter = except === 'region' ? '' : document.getElementById('filterCity').value;
  const monthFilter = except === 'month' ? '' : document.getElementById('filterMonth').value;
  return orders.filter(o => {
    if (q && !((o.name||'').toLowerCase().includes(q) || (o.phone||'').includes(q) ||
               (o.city||'').toLowerCase().includes(q) || (o.package||'').toLowerCase().includes(q) ||
               (o.province||'').toLowerCase().includes(q) || (o.carrier||'').toLowerCase().includes(q))) return false;
    if (carrierFilter && o.carrier !== carrierFilter) return false;
    if (provinceFilter && o.province !== provinceFilter) return false;
    if (cityFilter && o.city !== cityFilter) return false;
    if (monthFilter && !(o.applyDate || '').startsWith(monthFilter)) return false;
    if (paybackFilter === 'paid' && !o.paybackDate) return false;
    if (paybackFilter === 'unpaid' && o.paybackDate) return false;
    if (paybackFilter === 'over30' && !(agingDays(o) >= 30)) return false;
    if (paybackFilter === 'over60' && !(agingDays(o) >= 60)) return false;
    return true;
  });
}

function getFilteredOrders() {
  const sortVal = document.getElementById('sortBy').value;
  const filtered = selectOrders();

  const [key, dir] = sortVal.split('_');
  filtered.sort((a, b) => {
    let va, vb;
    if (key === 'apply')        { va = a.applyDate || ''; vb = b.applyDate || ''; }
    else if (key === 'payback') { va = a.paybackDate || ''; vb = b.paybackDate || ''; }
    else if (key === 'commission') { va = Number(a.commission)||0; vb = Number(b.commission)||0; }
    else if (key === 'packageFee') { va = Number(a.packageFee)||0; vb = Number(b.packageFee)||0; }
    else if (key === 'commissionRate') { va = Number(a.commissionRate)||0; vb = Number(b.commissionRate)||0; }
    else return 0;
    if (va < vb) return dir === 'asc' ? -1 : 1;
    if (va > vb) return dir === 'asc' ? 1 : -1;
    return 0;
  });
  return filtered;
}

// 已结佣显示日期；未结佣显示已拖欠天数，比一个「-」有用得多
function paybackCell(o) {
  if (o.paybackDate) return esc(o.paybackDate);
  const days = agingDays(o);
  if (days === null) return '<span class="age-ok">未结佣</span>';
  return '<span class="' + agingLevel(days) + '">未结佣 ' + days + '天</span>';
}

function renderTable(view) {
  const filtered = view || getFilteredOrders();
  const tbody = document.getElementById('tableBody');
  document.getElementById('emptyMsg').style.display = filtered.length ? 'none' : 'block';

  tbody.innerHTML = filtered.map((o, i) => {
    const ri = orders.indexOf(o);
    const unpaidCls = !o.paybackDate ? ' unpaid-row' : '';
    return '<tr class="' + unpaidCls.trim() + '" data-idx="' + ri + '" onclick="showRowDetail(' + ri + ')">' +
      '<td class="nowrap">' + (i+1) + '</td>' +
      '<td class="nowrap">' + esc(o.applyDate) + '</td>' +
      '<td class="nowrap">' + paybackCell(o) + '</td>' +
      '<td class="col-name nowrap">' + esc(o.name) + '</td>' +
      '<td class="nowrap">' + esc(o.phone) + '</td>' +
      '<td class="nowrap">' + esc(o.province) + '</td>' +
      '<td class="nowrap">' + esc(o.city) + '</td>' +
      '<td class="nowrap"><span class="badge ' + carrierBadge(o.carrier) + '">' + esc(o.carrier) + '</span></td>' +
      '<td class="nowrap col-package">' + esc(o.package) + '</td>' +
      '<td class="nowrap">' + esc(o.duration) + '</td>' +
      '<td class="text-right nowrap">\u00a5' + Number(o.installFee||0).toLocaleString() + '</td>' +
      '<td class="text-right nowrap">\u00a5' + Number(o.packageFee||0).toLocaleString() + '</td>' +
      '<td class="text-right col-commission nowrap">\u00a5' + Number(o.commission||0).toLocaleString() + '</td>' +
      '<td class="text-right nowrap">' + Math.round((Number(o.commissionRate)||0)*100) + '%</td>' +
      '<td class="nowrap col-id">' + esc(o.idCard||'') + '</td>' +
      '<td class="col-address"><span title="' + escAttr(o.address||'') + '">' +
        esc(o.address||'') + '</span></td>' +
      '<td class="nowrap" onclick="event.stopPropagation()">' +
        '<button class="btn btn-sm btn-cancel" onclick="editOrder(' + ri + ')">编辑</button>' +
        '<button class="btn btn-sm btn-danger" onclick="deleteOrder(' + ri + ')">删除</button>' +
      '</td>' +
    '</tr>';
  }).join('');

  refreshFilterIndicator();

  const sumInstall = filtered.reduce((s,o)=>s+(Number(o.installFee)||0),0);
  const sumPkg = filtered.reduce((s,o)=>s+(Number(o.packageFee)||0),0);
  const sumCom = filtered.reduce((s,o)=>s+(Number(o.commission)||0),0);
  // 合计行的单元格必须与当前可见列一一对应：colspan 写死在 HTML 里，
  // 光靠 CSS 隐藏列会让列宽模型多算几列，表体右侧就会空出一块。
  const foot = document.getElementById('totalRow');
  if (isNarrow()) {
    // 跨列数按当前实际可见的表头列算，增删手机端列时不用再同步改这里
    const visibleCols = Array.from(document.querySelectorAll('.table-wrap thead th'))
      .filter(th => getComputedStyle(th).display !== 'none').length;
    foot.innerHTML = '<tr class="total-row">' +
      '<td colspan="' + Math.max(1, visibleCols - 1) + '">合计 (' + filtered.length + '笔)</td>' +
      '<td class="text-right col-commission">¥' + sumCom.toLocaleString() + '</td>' +
    '</tr>';
  } else {
    // 表头前 10 列（序号…时限）固定，其后为 安装费/套餐费/佣金 三列，
    // 尾部为 佣金率/身份证号/地址/[销售员]/操作
    const baseCols = 10;   // 序号…时限
    const tailCols = 4;    // 佣金率 / 身份证号 / 地址 / 操作
    foot.innerHTML = '<tr class="total-row">' +
      '<td colspan="' + baseCols + '">合计 (' + filtered.length + '笔)</td>' +
      '<td class="text-right">¥' + sumInstall.toLocaleString() + '</td>' +
      '<td class="text-right">¥' + sumPkg.toLocaleString() + '</td>' +
      '<td class="text-right col-commission">¥' + sumCom.toLocaleString() + '</td>' +
      '<td colspan="' + tailCols + '"></td>' +
    '</tr>';
  }
}

/* ========== 离线提示 ========== */
function showOfflineBanner(at, reason) {
  const el = document.getElementById('offlineBanner');
  if (!el) return;
  el.innerHTML = '📴 <b>离线模式</b> —— 显示的是 ' + new Date(at).toLocaleString('zh-CN') +
    ' 缓存的数据，可能已不是最新。此状态下新增、修改、删除都会失败。' +
    '<br><span style="color:#6366f1">原因：' + esc(reason || '网络不可用') + '</span>';
  el.classList.add('visible');
}

function hideOfflineBanner() {
  const el = document.getElementById('offlineBanner');
  if (el) el.classList.remove('visible');
}

// 被截断时所有统计都是不完整的，不说清楚会让人按错的数字做判断
function renderTruncBanner() {
  const el = document.getElementById('truncBanner');
  if (!el) return;
  if (truncatedTotal) {
    el.innerHTML = '⚠️ <b>数据未取全</b>：数据库共 ' + truncatedTotal + ' 条，本次只取回 ' +
      allOrders.length + ' 条（接口单次返回条数有上限）。<b>当前所有统计、图表和合计都是不完整的。</b>' +
      '<br>请到 Supabase → Settings → API 调高 Max rows，或改为分页加载。';
  } else if (countUnverified) {
    el.innerHTML = '⚠️ <b>无法确认数据是否取全</b>：已取回 ' + allOrders.length +
      ' 条，但没读到服务端返回的总数，无法比对。<br>' +
      '请在 Supabase → Settings → API 确认 Max rows 高于实际订单数。';
  } else {
    el.classList.remove('visible');
    return;
  }
  el.classList.add('visible');
}

// 网络恢复后自动重新拉取
window.addEventListener('online', () => { if (usingCachedData) loadData(); });

/* ========== 筛选 ==========
   下拉部分（月份/省份/城市/运营商）直接以 DOM 为准；结佣状态用胶囊，
   状态存在这里：'' | 'unpaid' | 'over30' | 'over60' | 'paid'。
   逾期两档是「未结佣」的子集，所以选中它们时父胶囊也算选中。 */
const FILTER_IDS = ['filterMonth', 'filterProvince', 'filterCity', 'filterCarrier'];
let paybackFilter = '';

function isUnpaidFilter() {
  return paybackFilter === 'unpaid' || paybackFilter === 'over30' || paybackFilter === 'over60';
}

// 胶囊点自己 = 取消；点逾期档再点一次退回「未结佣」，不会整个清空
function togglePaybackFilter(val) {
  if (paybackFilter === val) {
    paybackFilter = (val === 'over30' || val === 'over60') ? 'unpaid' : '';
  } else {
    paybackFilter = val;
  }
  renderAll();
}

// 看板卡片用：直接套用，不做反选
function applyPaybackFilter(val) {
  paybackFilter = val;
  renderAll();
}

function setMonthFilter(val) {
  const sel = document.getElementById('filterMonth');
  if (!sel) return;
  sel.value = val;
  if (sel.value !== val) sel.value = '';   // 该月不在选项里（无数据）时退回全部
  renderAll();
}

function renderPaybackChips() {
  const unpaidOn = isUnpaidFilter();
  document.getElementById('chipUnpaid').classList.toggle('active', unpaidOn);
  document.getElementById('chipPaid').classList.toggle('active', paybackFilter === 'paid');
  document.getElementById('chipOver30').classList.toggle('active', paybackFilter === 'over30');
  document.getElementById('chipOver60').classList.toggle('active', paybackFilter === 'over60');
  document.getElementById('agingChips').classList.toggle('visible', unpaidOn);
}

function activeFilterCount() {
  return FILTER_IDS.filter(id => (document.getElementById(id) || {}).value).length +
         (paybackFilter ? 1 : 0);
}

function refreshFilterIndicator() {
  renderPaybackChips();
  const n = activeFilterCount();
  const badge = document.getElementById('filterCount');
  const clear = document.getElementById('clearFilters');
  if (badge) badge.innerHTML = n ? ' <span class="filter-count">' + n + '</span>' : '';
  if (clear) clear.classList.toggle('visible', n > 0);
}

function clearAllFilters() {
  FILTER_IDS.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  paybackFilter = '';
  refreshCityOptions();
  renderAll();
}

function openModal(idx) {
  editingIdx = idx ?? -1;
  document.getElementById('modalTitle').textContent = idx != null ? '编辑订单' : '新增订单';
  if (idx != null) {
    const o = orders[idx];
    f_applyDate.value=o.applyDate||''; f_paybackDate.value=o.paybackDate||'';
    f_name.value=o.name||''; f_phone.value=o.phone||'';
    f_province.value=o.province||''; f_city.value=o.city||'';
    setSelectValue(f_carrier, o.carrier || '联通'); f_package.value=o.package||'300m';
    setSelectValue(f_duration, o.duration || '1年'); f_installFee.value=o.installFee||'';
    f_packageFee.value=o.packageFee||''; f_commission.value=o.commission||'';
    f_commissionRate.value=o.commissionRate ? Math.round(o.commissionRate*100) : ''; f_idCard.value=o.idCard||'';
    f_address.value=o.address||'';
  } else {
    f_applyDate.value=todayStr();
    f_paybackDate.value=''; f_name.value=''; f_phone.value='';
    f_province.value=''; f_city.value='';
    f_carrier.value='联通'; f_package.value='300m'; f_duration.value='1年';
    f_installFee.value=''; f_packageFee.value=''; f_commission.value='';
    f_commissionRate.value=''; f_idCard.value=''; f_address.value='';
  }
  document.getElementById('modalOverlay').classList.add('active');
}

function closeModal() { document.getElementById('modalOverlay').classList.remove('active'); }

// 手动录入时，从地址栏文本识别省市并回填——复用智能录入用的同一套地址解析逻辑
function fillLocationFromAddress() {
  const addr = f_address.value.trim();
  if (!addr) { toast('请先填写地址', { type: 'warn' }); return; }
  const loc = extractCityFromAddress(addr);
  if (!loc.city && !loc.province) { toast('未能从地址中识别出省市，请手动填写', { type: 'warn' }); return; }
  if (loc.city) f_city.value = loc.city;
  if (loc.province) f_province.value = loc.province;
}

async function saveOrder() {
  if (saving) return;
  const name=f_name.value.trim(), phone=f_phone.value.trim(), pkgFee=Number(f_packageFee.value)||0;
  if (!name || !phone || !pkgFee) { toast('请填写姓名、手机号和套餐费', { type: 'error' }); return; }

  // 字段校验
  if (!/^1[3-9]\d{9}$/.test(phone)) { toast('手机号格式不正确，应为 11 位数字', { type: 'error' }); f_phone.focus(); return; }
  const idCard = f_idCard.value.trim().toUpperCase();
  if (idCard && !/^\d{17}[\dX]$/.test(idCard)) { toast('身份证号格式不正确，应为 18 位', { type: 'error' }); f_idCard.focus(); return; }
  const ratePctRaw = f_commissionRate.value.trim();
  if (ratePctRaw && (Number(ratePctRaw) < 0 || Number(ratePctRaw) > 100)) {
    toast('佣金率应在 0–100 之间', { type: 'error' }); f_commissionRate.focus(); return;
  }
  if (f_paybackDate.value && f_applyDate.value && f_paybackDate.value < f_applyDate.value) {
    toast('结佣日期不能早于办理日期', { type: 'error' }); f_paybackDate.focus(); return;
  }

  // 新增时提醒重复手机号；查全库（含隐藏的非本人归属记录），不只查当前视图
  if (editingIdx < 0) {
    const dup = allOrders.find(o => o.phone === phone);
    if (dup && !confirm('手机号 ' + phone + ' 已存在（' + (dup.name||'') + ' · ' +
        (dup.applyDate||'无日期') + (isMine(dup) ? '' : ' · 归属：' + (dup.salesPerson||'(空)')) +
        '），仍要继续新增吗？')) return;
  }
  const commission=Number(f_commission.value)||0;
  let ratePct=Number(f_commissionRate.value);
  let rate = ratePct ? ratePct/100 : (pkgFee>0 ? commission/pkgFee : 0);
  rate = Math.round(rate*10000)/10000;
  const order={
    applyDate:f_applyDate.value, paybackDate:f_paybackDate.value,
    name, phone, province:f_province.value.trim(), city:f_city.value.trim(),
    carrier:f_carrier.value, package:f_package.value, duration:f_duration.value,
    installFee:Number(f_installFee.value)||0, packageFee:pkgFee,
    commission, commissionRate:rate,
    idCard, address:f_address.value.trim(),
    salesPerson: editingIdx >= 0 ? orders[editingIdx].salesPerson : SALES_PERSON
  };

  saving = true;
  await ensureFreshSession();
  try {
    if (editingIdx >= 0) {
      const id = orders[editingIdx].id;
      const res = await fetch(REST + '?id=eq.' + encodeURIComponent(id), {
        method: 'PATCH',
        headers: HEADERS(),
        body: JSON.stringify(toRow(order))
      });
      if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + await res.text());
    } else {
      const res = await fetch(REST, {
        method: 'POST',
        headers: HEADERS(),
        body: JSON.stringify(toRow(order))
      });
      if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + await res.text());
    }
    closeModal();
    await loadData();
  } catch (e) {
    toast('保存失败：' + e.message, { type: 'error' });
  } finally {
    saving = false;
  }
}

function editOrder(i){openModal(i)}

async function deleteOrder(i){
  const o = orders[i];
  if(!o)return;
  const label = (o.name || '该订单') + ' · ' + (o.phone || '');
  if (!confirm('确认删除「' + label + '」？\n删除后可在提示里撤销，或到操作日志中恢复。')) return;
  // 先把删除前的完整数据留下来，撤销时原样插回
  const snapshot = toRow(o);
  await ensureFreshSession();
  try {
    const res = await fetch(REST + '?id=eq.' + encodeURIComponent(o.id), {
      method: 'DELETE',
      headers: HEADERS()
    });
    if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + await res.text());
    await loadData();
    toast('已删除「' + label + '」', {
      type: 'success',
      action: { label: '撤销', onClick: () => reinsertOrder(snapshot, label) }
    });
  } catch (e) {
    toast('删除失败：' + e.message, { type: 'error' });
  }
}

/* 把删掉的订单重新插回去。不带原 id：id 由数据库生成，硬塞旧 id
   可能与自增序列冲突；插回后是一条新记录，内容与删除前一致，
   操作日志里会多一条「新增」。 */
async function reinsertOrder(row, label) {
  await ensureFreshSession();
  try {
    const res = await fetch(REST, { method: 'POST', headers: HEADERS(), body: JSON.stringify(row) });
    if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + await res.text());
    await loadData();
    toast('已恢复「' + label + '」', { type: 'success' });
    return true;
  } catch (e) {
    toast('恢复失败：' + e.message, { type: 'error' });
    return false;
  }
}

// 日志里的 old_data 是数据库原始行：去掉由数据库生成的字段，其余照原样插回
function rowForReinsert(old) {
  const row = Object.assign({}, old);
  delete row.id;
  delete row.created_at;
  delete row.updated_at;
  return row;
}

// 同名、同手机号、同办理日期的订单已经在库里了，说明恢复过（或本来就重复录过）
function alreadyInDb(old) {
  return allOrders.some(o => o.phone === (old.phone || '') &&
                             o.name === (old.name || '') &&
                             o.applyDate === (old.apply_date || ''));
}

async function restoreFromLog(logId, btn) {
  const log = logRowsById.get(logId);
  if (!log || !log.old_data) return;
  const old = log.old_data;
  const label = (old.name || '该订单') + ' · ' + (old.phone || '');
  if (alreadyInDb(old) && !confirm('「' + label + '」看起来已经在订单里了，仍要再恢复一条吗？')) return;
  btn.disabled = true;
  btn.textContent = '恢复中…';
  const ok = await reinsertOrder(rowForReinsert(old), label);
  btn.textContent = ok ? '已恢复' : '恢复';
  btn.disabled = ok;
}

function exportCSV(){
  const list = getFilteredOrders();
  // 表头与导入端的别名表一致，导出的文件可以直接改完再导回来
  const h='序号,办理日期,结佣日期,姓名,手机号,省份,城市,运营商,套餐,时限,安装费,套餐费,佣金,佣金率,身份证号,地址\n';
  const cell=v=>'"'+String(v==null?'':v).replace(/"/g,'""')+'"';
  const rows=list.map((o,i)=>[i+1,o.applyDate,o.paybackDate,o.name,o.phone,o.province,o.city,o.carrier,o.package,o.duration,o.installFee,o.packageFee,o.commission,Math.round((Number(o.commissionRate)||0)*100)+'%',o.idCard,o.address].map(cell).join(',')).join('\n');
  const blob=new Blob(['\uFEFF'+h+rows],{type:'text/csv;charset=utf-8'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='销售订单_'+todayStr()+'.csv';a.click();
}

const CITY_PROVINCE_MAP = {
  '北京':'北京','上海':'上海','天津':'天津','重庆':'重庆',
  '广州':'广东','深圳':'广东','东莞':'广东','佛山':'广东','珠海':'广东',
  '南京':'江苏','苏州':'江苏','无锡':'江苏','常州':'江苏',
  '杭州':'浙江','宁波':'浙江','温州':'浙江',
  '成都':'四川','绵阳':'四川',
  '武汉':'湖北','宜昌':'湖北',
  '长沙':'湖南','株洲':'湖南',
  '南宁':'广西','柳州':'广西','桂林':'广西',
  '海口':'海南','三亚':'海南',
  '青岛':'山东','济南':'山东','烟台':'山东','聊城':'山东',
  '哈尔滨':'黑龙江','大庆':'黑龙江',
  '郑州':'河南','洛阳':'河南',
  '石家庄':'河北','唐山':'河北',
  '西安':'陕西','咸阳':'陕西',
  '福州':'福建','厦门':'福建',
  '合肥':'安徽','芜湖':'安徽',
  '南昌':'江西','赣州':'江西',
  '昆明':'云南','贵阳':'贵州','兰州':'甘肃','银川':'宁夏','西宁':'青海',
  '沈阳':'辽宁','大连':'辽宁','长春':'吉林','呼和浩特':'内蒙古',
  '拉萨':'西藏','太原':'山西','乌鲁木齐':'新疆'
};

function extractCityFromAddress(addr) {
  if (!addr) return {city:'', province:''};
  const cityMatch = addr.match(/(?:^|省|自治区)(.{2,3}(?:市|自治州|地区|盟))/);
  if (cityMatch) {
    const city = cityMatch[1].replace(/[市自治州地区盟]$/, '');
    return {city, province: CITY_PROVINCE_MAP[city] || ''};
  }
  const simpleMatch = addr.match(/^(.{2,3}?)[市]/);
  if (simpleMatch) {
    const city = simpleMatch[1];
    return {city, province: CITY_PROVINCE_MAP[city] || ''};
  }
  for (const [c, p] of Object.entries(CITY_PROVINCE_MAP)) {
    if (addr.includes(c)) return {city: c, province: p};
  }
  return {city:'', province:''};
}

function extractProvinceFromContext(text) {
  const provinces = ['北京','上海','天津','重庆','河北','山西','辽宁','吉林','黑龙江',
    '江苏','浙江','安徽','福建','江西','山东','河南','湖北','湖南','广东','海南',
    '四川','贵州','云南','陕西','甘肃','青海','广西','内蒙古','西藏','宁夏','新疆'];
  for (const p of provinces) {
    if (text.includes(p)) return p;
  }
  return '';
}

/* 标签解析：真实模板里标签后面经常带括号备注、全角空格，或者干脆没有冒号，
   例如「办理地址（具体到房号） ：」。逐个写死正则维护不过来，统一用这个helper。 */
function fieldValue(text, labels) {
  const label = '(?:' + labels.join('|') + ')';
  const note = '\\s*(?:[（(][^）)]{0,30}[）)])?\\s*';   // 可选的括号备注
  // 优先按冒号切分；没有冒号时退回用空白分隔
  for (const sep of ['[：:]\\s*', '\\s+']) {
    const m = text.match(new RegExp(label + note + sep + '([^\\n]+)'));
    if (m && m[1].trim()) return m[1].trim();
  }
  return '';
}

const CN_DIGITS = { '一':1,'二':2,'两':2,'三':3,'四':4,'五':5,'六':6,'七':7,'八':8,'九':9 };
const CN_NUM_CHARS = '0-9一二两三四五六七八九十';

// 「一年」「两年」「十二个月」这类中文数字，销售发来的原文里很常见
function cnNumber(s) {
  s = (s || '').trim();
  if (/^\d+$/.test(s)) return parseInt(s, 10);
  const m = s.match(/^([一二两三四五六七八九])?十([一二三四五六七八九])?$/);
  if (m) return (m[1] ? CN_DIGITS[m[1]] : 1) * 10 + (m[2] ? CN_DIGITS[m[2]] : 0);
  if (s.length === 1 && CN_DIGITS[s]) return CN_DIGITS[s];
  return 0;
}

function parseOrderText(text) {
  const result = {
    name:'', phone:'', idCard:'', address:'',
    carrier:'联通', package:'300m', duration:'1年',
    packageFee:0, installFee:0, commission:0,
    province:'', city:''
  };

  // 姓名后面可能跟着别的内容，只取第一段
  const nameRaw = fieldValue(text, ['客户姓名', '姓\\s*名', '客户']);
  if (nameRaw) result.name = nameRaw.split(/[,，、\s]/)[0].trim();

  // 号码可能写成 173-6530-6527 或带空格，先取标签值再抽数字；
  // 标签没匹配上时退回全文找一个手机号
  const phoneRaw = fieldValue(text, ['联系方式', '联系电话', '手机号码', '手机号', '手机', '电话']);
  const phoneHit = (phoneRaw.replace(/[\s\-]/g, '').match(/1[3-9]\d{9}/) ||
                    text.replace(/[\s\-]/g, '').match(/1[3-9]\d{9}/));
  if (phoneHit) result.phone = phoneHit[0];

  const idRaw = fieldValue(text, ['身份证号码', '身份证号', '身份证', '证件号码', '证件号', '证件']);
  const idHit = (idRaw.match(/\d{17}[\dXx]/) || text.match(/\d{17}[\dXx]/));
  if (idHit) result.idCard = idHit[0].toUpperCase();

  const addr = fieldValue(text, ['办理地址', '安装地址', '装机地址', '详细地址', '收货地址', '地址']);
  if (addr) {
    result.address = addr;
    const loc = extractCityFromAddress(addr);
    result.city = loc.city;
    result.province = loc.province;
  }
  if (!result.province) result.province = extractProvinceFromContext(text);
  // 地址里带了省份但城市不在对照表中时，至少把省份留下
  if (!result.province && result.address) {
    result.province = extractProvinceFromContext(result.address);
  }

  const pkg = fieldValue(text, ['办理套餐', '宽带套餐', '套餐内容', '套餐']);
  if (pkg) {
    const carrierMatch = pkg.match(/(联通|移动|电信|广电)/);
    if (carrierMatch) result.carrier = carrierMatch[1];

    // 带宽写法：1000M / 1000m / 1000兆 / 千兆
    if (/千兆/.test(pkg)) {
      result.package = '1000M';
    } else {
      const speedMatch = pkg.match(/(\d+)\s*(?:兆|[Mm][Bb]?)/);
      if (speedMatch) result.package = speedMatch[1] + 'M';
    }

    const feeMatch = pkg.match(/(\d+(?:\.\d+)?)\s*元/);
    if (feeMatch) result.packageFee = Math.round(parseFloat(feeMatch[1]));

    // 时限：支持「一年」「两年」「18个月」「半年」
    if (/半年/.test(pkg)) {
      result.duration = '6个月';
    } else {
      const yr = pkg.match(new RegExp('([' + CN_NUM_CHARS + ']+)\\s*年'));
      const mo = pkg.match(new RegExp('([' + CN_NUM_CHARS + ']+)\\s*个?月'));
      if (yr && cnNumber(yr[1])) result.duration = cnNumber(yr[1]) + '年';
      else if (mo && cnNumber(mo[1])) result.duration = cnNumber(mo[1]) + '个月';
    }

    // 「包安装」「免安装费」= 不另收安装费
    if (/包安装|免安装|送安装/.test(pkg)) result.installFee = 0;
  }

  const carrierLine = text.match(/运营商[：:\s]*(联通|移动|电信|广电)/);
  if (carrierLine) result.carrier = carrierLine[1];

  const installFee = text.match(/安装费[：:\s]*(\d+)/);
  if (installFee) result.installFee = parseInt(installFee[1], 10);

  const comMatch = text.match(/佣金[：:\s]*(\d+)/);
  if (comMatch) result.commission = parseInt(comMatch[1], 10);

  return result;
}

function openSmartModal() {
  document.getElementById('smartText').value = '';
  resetSmartMode();
  document.getElementById('smartOverlay').classList.add('active');
  setTimeout(() => document.getElementById('smartText').focus(), 100);
}

function closeSmartModal() {
  document.getElementById('smartOverlay').classList.remove('active');
}

/* ========== 智能录入：一次粘贴多条 ==========
   客资常常是群里一次发好几条。每条以「姓名」标签开头就按它切；
   第一个「姓名」之前的文字（如「新增以下广西宽带」）当作抬头，
   拼到每一条前面，用来补省份。没有「姓名」可切时，退而按空行切，
   前提是每一段各有一个手机号——否则宁可当成一条，也不乱切。 */
const NAME_LINE = /^\s*(?:客户姓名|姓\s*名|客户)\s*(?:[（(][^）)]{0,30}[）)])?\s*[：:\s]/;

function splitOrderText(text) {
  const lines = text.split(/\r?\n/);
  const starts = lines.map((l, i) => NAME_LINE.test(l) ? i : -1).filter(i => i >= 0);
  if (starts.length >= 2) {
    const header = lines.slice(0, starts[0]).join('\n').trim();
    return starts.map((s, k) => {
      const body = lines.slice(s, k + 1 < starts.length ? starts[k + 1] : lines.length).join('\n').trim();
      return header ? header + '\n' + body : body;
    });
  }
  const blocks = text.split(/\n\s*\n/).map(b => b.trim()).filter(Boolean);
  if (blocks.length >= 2 && blocks.every(b => /1[3-9]\d{9}/.test(b.replace(/[\s-]/g, '')))) return blocks;
  return [text];
}

let smartBatch = [];   // 多条模式下的待保存清单

// 改了粘贴内容就回到「提取」状态，免得拿着旧的解析结果去保存
function resetSmartMode() {
  smartBatch = [];
  const preview = document.getElementById('extractedPreview');
  preview.style.display = 'none';
  preview.innerHTML = '';
  preview.classList.remove('batch');
  document.querySelector('#smartOverlay .modal').classList.remove('modal-wide');
  const btn = document.getElementById('smartActionBtn');
  btn.textContent = '提取并填充';
  btn.onclick = parseAndFill;
  btn.disabled = false;
}

// 与单条保存用同一套校验：错误挡住保存，提醒只是提示
function checkParsed(p, seenPhones) {
  const errors = [], warns = [];
  if (!p.name) errors.push('缺姓名');
  if (!p.phone) errors.push('缺手机号');
  else if (!/^1[3-9]\d{9}$/.test(p.phone)) errors.push('手机号格式不对');
  if (!p.packageFee) errors.push('缺套餐费');
  if (p.idCard && !/^\d{17}[\dX]$/.test(p.idCard)) errors.push('身份证号格式不对');
  if (p.phone && allOrders.some(o => o.phone === p.phone)) warns.push('手机号已存在');
  if (p.phone && seenPhones.has(p.phone)) warns.push('本批重复');
  if (p.phone) seenPhones.add(p.phone);
  return { errors, warns };
}

function renderSmartBatch() {
  const preview = document.getElementById('extractedPreview');
  const rows = smartBatch.map((r, i) => {
    const p = r.parsed;
    const notes = r.errors.map(e => '<span class="batch-err">' + e + '</span>')
      .concat(r.warns.map(w => '<span class="batch-warn">' + w + '</span>'));
    return '<tr class="' + (r.errors.length ? 'batch-bad' : '') + '">' +
      '<td class="b-chk"><input type="checkbox" ' + (r.include ? 'checked ' : '') + (r.errors.length ? 'disabled ' : '') +
        'onchange="smartBatch[' + i + '].include = this.checked; refreshBatchButton()" ' +
        'aria-label="保存第 ' + (i + 1) + ' 条"></td>' +
      '<td class="col-name b-name">' + esc(p.name || '—') + '</td>' +
      '<td class="b-phone">' + esc(p.phone || '—') + '</td>' +
      '<td class="b-city">' + esc(p.city || '—') + '</td>' +
      '<td class="b-pkg">' + esc(p.carrier) + ' ' + esc(p.package) + ' ' + esc(p.duration) + '</td>' +
      '<td class="text-right b-fee">' + (p.packageFee ? money(p.packageFee) : '—') + '</td>' +
      '<td class="b-com"><input type="number" class="batch-commission" min="0" placeholder="佣金" value="' +
        (p.commission || '') + '" oninput="smartBatch[' + i + '].commission = Number(this.value) || 0"></td>' +
      '<td class="b-note">' + (notes.join(' ') || '<span class="an-muted">—</span>') + '</td>' +
    '</tr>';
  }).join('');
  preview.innerHTML =
    '<div class="batch-head">识别到 <b>' + smartBatch.length + '</b> 条，核对后勾选要保存的；' +
      '佣金可在这里直接填。有错误的不能勾选，「手机号已存在」的默认不勾。</div>' +
    '<div class="batch-scroll"><table class="batch-table"><thead><tr>' +
      '<th></th><th>姓名</th><th>手机号</th><th>城市</th><th>套餐</th><th class="text-right">套餐费</th>' +
      '<th>佣金</th><th>提示</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
  preview.classList.add('batch');
  preview.style.display = 'block';
  refreshBatchButton();
}

function refreshBatchButton() {
  const n = smartBatch.filter(r => r.include).length;
  const btn = document.getElementById('smartActionBtn');
  btn.textContent = n ? '批量保存 ' + n + ' 条' : '没有可保存的';
  btn.disabled = n === 0;
  btn.onclick = saveSmartBatch;
}

async function saveSmartBatch() {
  const picked = smartBatch.filter(r => r.include && !r.errors.length);
  if (!picked.length) return;
  const missingCommission = picked.filter(r => !r.commission).length;
  if (missingCommission && !confirm(missingCommission + ' 条没有填佣金，会按 ¥0 保存，之后可以再编辑。继续吗？')) return;

  const rows = picked.map(r => {
    const p = r.parsed;
    const rate = p.packageFee > 0 ? Math.round(r.commission / p.packageFee * 10000) / 10000 : 0;
    return toRow({
      applyDate: todayStr(), paybackDate: '',
      name: p.name, phone: p.phone, province: p.province, city: p.city,
      carrier: p.carrier, package: p.package, duration: p.duration,
      installFee: p.installFee, packageFee: p.packageFee,
      commission: r.commission, commissionRate: rate,
      idCard: p.idCard, address: p.address, salesPerson: SALES_PERSON
    });
  });

  const btn = document.getElementById('smartActionBtn');
  btn.disabled = true;
  btn.textContent = '保存中…';
  await ensureFreshSession();
  try {
    // 一次请求整批插入：要么全进要么全不进，不会留下半截
    const res = await fetch(REST, { method: 'POST', headers: HEADERS(), body: JSON.stringify(rows) });
    if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + await res.text());
    closeSmartModal();
    await loadData();
    toast('已保存 ' + rows.length + ' 条订单', { type: 'success' });
  } catch (e) {
    toast('批量保存失败，一条都没有写入：' + e.message, { type: 'error' });
    refreshBatchButton();
  }
}

function parseAndFill() {
  const text = document.getElementById('smartText').value.trim();
  if (!text) { toast('请粘贴订单信息', { type: 'warn' }); return; }

  const parts = splitOrderText(text);
  if (parts.length > 1) {
    const seen = new Set();
    smartBatch = parts.map(t => {
      const parsed = parseOrderText(t);
      const { errors, warns } = checkParsed(parsed, seen);
      // 有错误的不能保存；手机号已在库里的多半是重复粘贴，默认不勾，需要时手动勾上
      return { parsed, errors, warns, commission: parsed.commission || 0,
               include: !errors.length && !warns.includes('手机号已存在') && !warns.includes('本批重复') };
    });
    document.querySelector('#smartOverlay .modal').classList.add('modal-wide');
    renderSmartBatch();
    return;
  }

  const parsed = parseOrderText(text);
  // 单条：填进「新增订单」表单。必须重置编辑状态——否则刚编辑过别的订单再来
  // 智能录入，保存时会覆盖掉那一条，而不是新增。
  editingIdx = -1;
  document.getElementById('modalTitle').textContent = '新增订单';
  const preview = document.getElementById('extractedPreview');
  const fields = [
    ['姓名', parsed.name], ['手机', parsed.phone], ['身份证', parsed.idCard],
    ['地址', parsed.address], ['省份', parsed.province], ['城市', parsed.city],
    ['运营商', parsed.carrier], ['套餐', parsed.package], ['时限', parsed.duration],
    ['套餐费', parsed.packageFee ? '¥'+parsed.packageFee : ''],
  ];
  preview.innerHTML = fields
    .filter(([,v]) => v)
    .map(([l,v]) => `<div class="field-row"><span class="field-label">${l}</span><span class="field-value">${esc(v)}</span></div>`)
    .join('');
  preview.style.display = 'block';

  f_applyDate.value = todayStr();
  f_paybackDate.value = '';
  f_name.value = parsed.name;
  f_phone.value = parsed.phone;
  f_province.value = parsed.province;
  f_city.value = parsed.city;
  setSelectValue(f_carrier, parsed.carrier);
  f_package.value = parsed.package;
  setSelectValue(f_duration, parsed.duration);
  f_installFee.value = parsed.installFee || '';
  f_packageFee.value = parsed.packageFee || '';
  f_commission.value = parsed.commission || '';
  f_commissionRate.value = '';
  f_idCard.value = parsed.idCard;
  f_address.value = parsed.address;

  setTimeout(() => {
    closeSmartModal();
    document.getElementById('modalOverlay').classList.add('active');
  }, 1200);
}

function showRowDetail(idx) {
  const o = orders[idx];
  if (!o) return;
  const card = document.getElementById('detailCard');
  const fields = [
    ['办理日期', o.applyDate || '-'],
    ['结佣日期', o.paybackDate ||
      (agingDays(o) !== null ? '未结佣（已 ' + agingDays(o) + ' 天）' : '未结佣')],
    ['姓名', o.name],
    ['手机号', o.phone],
    ['省份', o.province],
    ['城市', o.city],
    ['运营商', o.carrier],
    ['套餐', o.package],
    ['时限', o.duration],
    ['安装费', '\u00a5' + Number(o.installFee||0).toLocaleString()],
    ['套餐费', '\u00a5' + Number(o.packageFee||0).toLocaleString()],
    ['佣金', '\u00a5' + Number(o.commission||0).toLocaleString()],
    ['佣金率', Math.round((Number(o.commissionRate)||0)*100) + '%'],
    ['身份证号', o.idCard || '-'],
    ['地址', o.address || '-'],
  ];
  // 只有非本人订单才显示归属，本人视图下这一行是废话
  if (!isMine(o)) fields.push(['当前归属', o.salesPerson || '(空)']);
  const claimBtn = isMine(o) ? '' :
    '<button class="btn btn-sm btn-claim" onclick="claimOrder(' + idx + ')">归到我名下</button>';
  card.innerHTML = '<h3>订单详情 <button class="close-btn" onclick="document.getElementById(\'detailOverlay\').classList.remove(\'active\')">&times;</button></h3>' +
    fields.map(function(f) {
      return '<div class="detail-row"><span class="dl">' + f[0] + '</span><span class="dv">' + esc(f[1]) + '</span></div>';
    }).join('') +
    '<div style="margin-top:16px;display:flex;gap:8px;justify-content:flex-end">' +
    claimBtn +
    '<button class="btn btn-sm btn-cancel" onclick="document.getElementById(\'detailOverlay\').classList.remove(\'active\');editOrder(' + idx + ')">编辑</button>' +
    '<button class="btn btn-sm btn-danger" onclick="document.getElementById(\'detailOverlay\').classList.remove(\'active\');deleteOrder(' + idx + ')">删除</button>' +
    '</div>';
  document.getElementById('detailOverlay').classList.add('active');
}

/* ========== 近 12 个月佣金趋势 ========== */
function renderTrend() {
  const wrap = document.getElementById('trendWrap');
  if (!wrap) return;
  // 按月拆的图不吃月份筛选，否则只剩一根柱子；选中的那个月改为高亮。
  const mine = selectOrders('month');
  const picked = document.getElementById('filterMonth').value;

  // 选了某一年就看那一年的 12 个月，否则看最近 12 个自然月
  const now = new Date();
  const pickedYear = /^\d{4}$/.test(picked) ? +picked
                   : (/^\d{4}-\d{2}$/.test(picked) ? +picked.slice(0, 4) : null);
  const buckets = [];
  for (let i = 0; i < 12; i++) {
    const d = pickedYear !== null
      ? new Date(pickedYear, i, 1)
      : new Date(now.getFullYear(), now.getMonth() - 11 + i, 1);
    const key = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
    buckets.push({ key, label: (d.getMonth() + 1) + '月', settled: 0, unsettled: 0, count: 0 });
  }
  const index = new Map(buckets.map(b => [b.key, b]));
  mine.forEach(o => {
    if (!o.applyDate) return;
    const b = index.get(String(o.applyDate).slice(0, 7));
    if (!b) return;
    const v = trendMetric === 'count' ? 1 : (Number(o.commission) || 0);
    if (o.paybackDate) b.settled += v; else b.unsettled += v;
    b.count++;
  });

  const isCount = trendMetric === 'count';
  const totalOf = b => b.settled + b.unsettled;
  const rangeLabel = pickedYear !== null ? (pickedYear + ' 年') : '近 12 个月';
  const title = rangeLabel + (isCount ? '订单量趋势' : '佣金趋势');
  const toggle = '<span class="trend-toggle">' +
    '<button class="' + (isCount ? '' : 'active') + '" onclick="setTrendMetric(\'commission\')">佣金</button>' +
    '<button class="' + (isCount ? 'active' : '') + '" onclick="setTrendMetric(\'count\')">订单数</button>' +
    '</span>';
  // 两个系列必须有图例，识别不能只靠颜色
  const legend = '<div class="an-legend" style="margin:2px 0 8px">' +
    '<span><i style="background:var(--c-settled)"></i>已结佣</span>' +
    '<span><i style="background:var(--c-unsettled)"></i>未结佣</span>' +
    '<span class="an-muted">堆叠高度为当月合计</span></div>';

  const max = Math.max(...buckets.map(totalOf));
  if (max <= 0) {
    wrap.innerHTML = '<div class="trend-card"><h3>' + title + toggle + '</h3>' +
      '<div class="trend-empty">' + rangeLabel + '暂无订单数据</div></div>';
    return;
  }

  // SVG 按 viewBox 等比缩放：窄屏上像素被压缩，所以字号和留白都用
  // 用户单位放大一档，否则月份标签会糊成一片或与柱子重叠。
  const narrow = window.innerWidth <= 768;
  const W = 1000;
  const H = narrow ? 170 : 116;
  const padBottom = narrow ? 46 : 18;
  const padTop = narrow ? 18 : 16;
  const labelSize = narrow ? 26 : 10;
  const slot = W / buckets.length;
  // 柱子封顶，别把格子填满，余下的留白。宽屏 SVG 会被放大约 1.4 倍，
  // 16 用户单位落到屏幕上约 22–25px，正好在「柱宽不超过 24px」这条线附近；
  // 窄屏整体缩小，按槽宽比例走反而更合适。
  const barW = narrow ? slot * 0.56 : Math.min(slot * 0.56, 16);
  const plot = H - padTop - padBottom;
  const GAP = 2;   // 堆叠两段之间留表面色间隙，靠留白分隔而不是描边

  const bars = buckets.map((b, i) => {
    const total = totalOf(b);
    const x = i * slot + (slot - barW) / 2;
    const isPicked = b.key === picked;
    const isCurrent = !picked && b.key === (now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0'));
    const hTotal = total > 0 ? Math.max(2, total / max * plot) : 0;
    const hUnsettled = total > 0 ? (b.unsettled / total) * hTotal : 0;
    const hSettled = hTotal - hUnsettled;
    const yTop = H - padBottom - hTotal;

    // 未结佣在上、已结佣在下：下段贴基线，圆角只给整根柱子的顶端
    let seg = '';
    if (hSettled > 0) {
      seg += '<rect x="' + x.toFixed(1) + '" y="' + (H - padBottom - hSettled).toFixed(1) +
        '" width="' + barW.toFixed(1) + '" height="' + hSettled.toFixed(1) +
        '" fill="var(--c-settled)"' + (hUnsettled > 0 ? '' : ' rx="4"') + '/>';
    }
    if (hUnsettled > 0) {
      const h = Math.max(1, hUnsettled - (hSettled > 0 ? GAP : 0));
      seg += '<rect x="' + x.toFixed(1) + '" y="' + yTop.toFixed(1) +
        '" width="' + barW.toFixed(1) + '" height="' + h.toFixed(1) +
        '" fill="var(--c-unsettled)" rx="4"/>';
    }

    const fmt = v => isCount ? v : (v >= 10000 ? (v / 10000).toFixed(1) + '万' : v);
    // 只给选中月/当月标数值，不是每根都标——标满了没人看
    const valueLabel = (total > 0 && !narrow && (isPicked || isCurrent))
      ? '<text class="trend-value" x="' + (x + barW / 2) + '" y="' + (yTop - 5) + '" text-anchor="middle">' +
        fmt(total) + '</text>'
      : '';
    // 有单的月份才能点：空月份不在月份下拉里，点了也筛不出东西
    const clickable = b.count > 0;
    const tip = b.key + '：' + b.count + ' 笔\n已结佣 ' + (isCount ? b.settled + ' 笔' : money(b.settled)) +
                ' · 未结佣 ' + (isCount ? b.unsettled + ' 笔' : money(b.unsettled)) +
                (clickable ? '\n' + (isPicked ? '点击取消月份筛选' : '点击只看这个月') : '');
    // 点击和提示挂在整组上：柱子画在热区上面，挂在热区上的话点柱子本身反而没反应
    return '<g class="trend-bar-g' + (isPicked || isCurrent ? ' current' : '') + (clickable ? ' clickable' : '') + '"' +
        (clickable ? ' onclick="setMonthFilter(\'' + (isPicked ? '' : b.key) + '\')"' : '') + '>' +
      '<title>' + tip + '</title>' +
      // 透明热区：命中面积比柱子宽，窄柱子也好点
      '<rect x="' + (i * slot).toFixed(1) + '" y="' + padTop + '" width="' + slot.toFixed(1) +
        '" height="' + (plot + padBottom) + '" fill="transparent"/>' +
      seg + valueLabel +
      '<text class="trend-label" x="' + (x + barW / 2) + '" y="' + (H - padBottom + labelSize + 4) +
        '" style="font-size:' + labelSize + 'px" text-anchor="middle">' + b.label + '</text>' +
      '</g>';
  }).join('');

  const sumSettled = buckets.reduce((s, b) => s + b.settled, 0);
  const sumUnsettled = buckets.reduce((s, b) => s + b.unsettled, 0);
  const fmtVal = n => isCount ? (n + ' 笔') : money(n);
  wrap.innerHTML = '<div class="trend-card">' +
    '<h3>' + title +
      '<span class="hint">合计 ' + fmtVal(sumSettled + sumUnsettled) +
      ' · 其中未结佣 ' + fmtVal(sumUnsettled) + '</span>' + toggle + '</h3>' + legend +
    '<svg class="trend-svg" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' + title + '">' +
    '<line x1="0" y1="' + (H - padBottom) + '" x2="' + W + '" y2="' + (H - padBottom) +
      '" stroke="var(--grid-line)" stroke-width="1"/>' +
    bars + '</svg></div>';
}

function setTrendMetric(metric) {
  trendMetric = metric;
  try { localStorage.setItem('salesOrderTrendMetric', metric); } catch (e) {}
  renderTrend();
}

// 横竖屏或窗口尺寸切换时重画，让窄屏/宽屏两套排版都能生效。
// 表格也要重画：合计行的 colspan 在两套排版下不同。
let layoutResizeTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(layoutResizeTimer);
  layoutResizeTimer = setTimeout(() => { renderAll(); }, 200);
});

/* ========== 把历史订单改到自己名下 ========== */
async function claimOrder(idx) {
  const o = orders[idx];
  if (!o || isMine(o)) return;
  if (!confirm('把「' + (o.name || '该订单') + ' · ' + (o.phone || '') + '」的归属从「' +
      (o.salesPerson || '(空)') + '」改为「' + SALES_PERSON + '」？\n\n' +
      '改完它会出现在你的订单列表和统计里。')) return;
  await ensureFreshSession();
  try {
    const res = await fetch(REST + '?id=eq.' + encodeURIComponent(o.id), {
      method: 'PATCH',
      headers: HEADERS(),
      body: JSON.stringify({ sales_person: SALES_PERSON })
    });
    if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + await res.text());
    document.getElementById('detailOverlay').classList.remove('active');
    await loadData();
  } catch (e) {
    toast('改归属失败：' + e.message, { type: 'error' });
  }
}

/* ========== Esc 关闭弹窗 ========== */
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  const ids = ['detailOverlay', 'logOverlay', 'csvImportOverlay', 'smartOverlay', 'modalOverlay'];
  for (const id of ids) {
    const el = document.getElementById(id);
    if (el && el.classList.contains('active')) { el.classList.remove('active'); return; }
  }
});

/* ========== 功能 3：CSV 批量导入 ==========
   按表头名称匹配列，因此列顺序变化、多余列、缺列都不会导致数据错位。 */
let pendingImport = { rows: [], skipped: 0, invalid: 0 };

// 表头别名 → 内部字段
const CSV_HEADER_ALIASES = {
  '办理日期': 'applyDate', '下单日期': 'applyDate', '日期': 'applyDate',
  '结佣日期': 'paybackDate', '结佣': 'paybackDate',
  '回款日期': 'paybackDate', '回款': 'paybackDate',   // 旧表头，保留兼容
  '姓名': 'name', '客户': 'name', '客户姓名': 'name',
  '手机号': 'phone', '手机': 'phone', '电话': 'phone', '联系方式': 'phone',
  '省份': 'province', '省': 'province',
  '城市': 'city', '市': 'city',
  '运营商': 'carrier',
  '套餐': 'package', '套餐名称': 'package',
  '时限': 'duration', '期限': 'duration',
  '安装费': 'installFee',
  '套餐费': 'packageFee', '金额': 'packageFee',
  '佣金': 'commission',
  '佣金率': 'commissionRate',
  '身份证号': 'idCard', '身份证': 'idCard',
  '地址': 'address', '办理地址': 'address', '安装地址': 'address',
  '销售员': 'salesPerson', '业务员': 'salesPerson'
};

// 支持引号内的逗号与换行，以及 "" 转义
function parseCSV(text) {
  const rows = [];
  let row = [], cur = '', inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') {
        if (text[i + 1] === '"') { cur += '"'; i++; }
        else inQ = false;
      } else cur += c;
    } else if (c === '"') {
      inQ = true;
    } else if (c === ',') {
      row.push(cur); cur = '';
    } else if (c === '\n') {
      row.push(cur); rows.push(row); row = []; cur = '';
    } else if (c !== '\r') {
      cur += c;
    }
  }
  row.push(cur);
  rows.push(row);
  return rows.filter(r => r.some(cell => cell.trim() !== ''));
}

function normalizeDate(v) {
  const s = (v || '').trim();
  if (!s) return null;
  let m = s.match(/^(\d{4})[-\/.](\d{1,2})[-\/.](\d{1,2})/);
  if (m) return m[1] + '-' + m[2].padStart(2, '0') + '-' + m[3].padStart(2, '0');
  m = s.match(/^(\d{4})(\d{2})(\d{2})$/);
  if (m) return m[1] + '-' + m[2] + '-' + m[3];
  return null;
}

function normalizeRate(v) {
  const s = String(v == null ? '' : v).replace('%', '').trim();
  if (!s) return 0;
  const n = Number(s);
  if (!isFinite(n) || n <= 0) return 0;
  // 大于等于 1 视为百分数（30 → 0.3），小于 1 视为小数（0.3 → 0.3）
  return n >= 1 ? Math.round(n) / 100 : Math.round(n * 10000) / 10000;
}

function triggerCSVImport() {
  document.getElementById('csvFileInput').value = '';
  document.getElementById('csvFileInput').click();
}

function buildImportPlan(text) {
  const table = parseCSV(String(text).replace(/^﻿/, ''));
  if (table.length < 2) return { error: 'CSV 文件为空或没有数据行' };

  const header = table[0].map(h => h.trim());
  const fieldOf = header.map(h => CSV_HEADER_ALIASES[h] || '');
  if (!fieldOf.includes('name') || !fieldOf.includes('phone')) {
    return { error: '未能识别表头：CSV 必须包含「姓名」和「手机号」两列。\n可先用「导出 CSV」得到标准模板再填写。' };
  }

  const existingKeys = new Set(
    orders.filter(o => o.phone && o.applyDate).map(o => o.phone + '|' + o.applyDate)
  );
  const rows = [], preview = [];
  let skipped = 0, invalid = 0;

  for (const cells of table.slice(1)) {
    const rec = {};
    fieldOf.forEach((f, i) => { if (f) rec[f] = (cells[i] || '').trim(); });
    const phone = (rec.phone || '').replace(/\D/g, '');
    if (!rec.name || !phone) { invalid++; continue; }
    const applyDate = normalizeDate(rec.applyDate);
    const key = phone + '|' + (applyDate || '');
    if (applyDate && existingKeys.has(key)) { skipped++; continue; }
    if (applyDate) existingKeys.add(key);

    const salesPerson = rec.salesPerson || SALES_PERSON;
    rows.push({
      apply_date:      applyDate,
      payback_date:    normalizeDate(rec.paybackDate),
      name:            rec.name,
      phone:           phone,
      province:        rec.province || '',
      city:            rec.city || '',
      carrier:         rec.carrier || '',
      package:         rec.package || '',
      duration:        rec.duration || '',
      install_fee:     Number(rec.installFee) || 0,
      package_fee:     Number(rec.packageFee) || 0,
      commission:      Number(rec.commission) || 0,
      commission_rate: normalizeRate(rec.commissionRate),
      id_card:         (rec.idCard || '').toUpperCase(),
      address:         rec.address || '',
      sales_person:    salesPerson
    });
    if (preview.length < 5) {
      preview.push([rec.name, phone, applyDate || '—', rec.carrier || '—',
                    rec.package || '—', rec.commission || '0', salesPerson]);
    }
  }

  return {
    rows, preview, skipped, invalid,
    unmapped: header.filter((h, i) => !fieldOf[i])
  };
}

function handleCSVFile(input) {
  const file = input.files && input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    const plan = buildImportPlan(e.target.result);
    if (plan.error) { toast(plan.error, { type: 'error', duration: 8000 }); return; }
    pendingImport = { rows: plan.rows, skipped: plan.skipped, invalid: plan.invalid };

    document.getElementById('csvImportContent').innerHTML =
      '<p class="csv-import-info">可导入 <strong>' + plan.rows.length + '</strong> 条' +
        (plan.skipped ? '，跳过重复 <strong>' + plan.skipped + '</strong> 条' : '') +
        (plan.invalid ? '，缺少姓名或手机号 <strong>' + plan.invalid + '</strong> 条' : '') + '</p>' +
      (plan.unmapped.length ? '<p style="font-size:12px;color:#9ca3af">未识别的列（忽略）：' +
        esc(plan.unmapped.join('、')) + '</p>' : '') +
      (plan.rows.length
        ? '<div style="overflow-x:auto;margin:10px 0"><table class="csv-preview-table">' +
          '<thead><tr><th>姓名</th><th>手机号</th><th>办理日期</th><th>运营商</th><th>套餐</th><th>佣金</th><th>销售员</th></tr></thead>' +
          '<tbody>' + plan.preview.map(r => '<tr>' + r.map(c => '<td>' + esc(String(c)) + '</td>').join('') + '</tr>').join('') +
          '</tbody></table></div>' +
          (plan.rows.length > 5 ? '<p style="font-size:12px;color:#6b7280">… 还有 ' + (plan.rows.length - 5) + ' 条未显示</p>' : '')
        : '<p style="font-size:13px;color:#dc2626;margin-top:8px">没有可导入的新记录。</p>') +
      '<p style="font-size:12px;color:#6b7280;margin-top:8px">重复判定依据：手机号 + 办理日期</p>';
    document.getElementById('csvConfirmBtn').disabled = plan.rows.length === 0;
    document.getElementById('csvImportOverlay').classList.add('active');
  };
  reader.onerror = () => toast('读取文件失败，请重试', { type: 'error' });
  reader.readAsText(file, 'utf-8');
}

function closeCSVImport() {
  document.getElementById('csvImportOverlay').classList.remove('active');
  pendingImport = { rows: [], skipped: 0, invalid: 0 };
}

async function confirmCSVImport() {
  const btn = document.getElementById('csvConfirmBtn');
  const rows = pendingImport.rows;
  const { skipped, invalid } = pendingImport;
  if (!rows.length) return;
  btn.disabled = true;

  await ensureFreshSession();
  const CHUNK = 100;   // 分批提交，避免一条一条发请求
  let imported = 0;
  const errors = [];
  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    btn.textContent = '导入中… ' + Math.min(i + chunk.length, rows.length) + '/' + rows.length;
    try {
      const res = await fetch(REST, { method: 'POST', headers: HEADERS(), body: JSON.stringify(chunk) });
      if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + (await res.text()).slice(0, 200));
      imported += chunk.length;
    } catch (e) {
      errors.push('第 ' + (i + 1) + '–' + (i + chunk.length) + ' 条：' + e.message);
    }
  }

  closeCSVImport();
  btn.textContent = '确认导入';
  await loadData();
  // 有失败批次时停久一点，失败明细要看得完
  toast('导入完成：成功 ' + imported + ' 条' +
        (skipped ? '，跳过重复 ' + skipped + ' 条' : '') +
        (invalid ? '，无效 ' + invalid + ' 条' : '') +
        (errors.length ? '\n失败：\n' + errors.join('\n') : ''),
        { type: errors.length ? 'warn' : 'success', duration: errors.length ? 12000 : 5000 });
}

/* ========== 功能 7：操作日志 ========== */
async function openLogViewer() {
  document.getElementById('logContent').innerHTML = '<div class="log-empty">加载中…</div>';
  document.getElementById('logOverlay').classList.add('active');
  await ensureFreshSession();
  const url = SUPABASE_URL + '/rest/v1/order_logs?select=*&order=created_at.desc&limit=50';
  fetch(url, { headers: HEADERS() })
    // 401/404 时返回的是报错对象而不是数组，先判掉，否则会报一个看不懂的 map 错误
    .then(r => r.ok ? r.json() : r.text().then(t => { throw new Error('HTTP ' + r.status + ' ' + t.slice(0, 120)); }))
    .then(rows => {
      logRowsById = new Map((rows || []).map(r => [r.id, r]));
      if (!rows || rows.length === 0) {
        document.getElementById('logContent').innerHTML = '<div class="log-empty">暂无操作日志</div>';
        return;
      }
      document.getElementById('logContent').innerHTML = rows.map(renderLogRow).join('');
    })
    .catch(err => {
      document.getElementById('logContent').innerHTML =
        '<div class="log-empty" style="color:#dc2626">加载失败：' + esc(err.message) +
        '（确认已在 SQL Editor 执行 order_logs 表建表脚本）</div>';
    });
}

// 当前日志列表按 id 存一份，「恢复」按钮只传 id，不把整行数据塞进 onclick
let logRowsById = new Map();

function closeLogViewer() {
  document.getElementById('logOverlay').classList.remove('active');
}

const FIELD_ZH = {
  apply_date: '办理日期', payback_date: '结佣日期', name: '姓名', phone: '手机号',
  province: '省份', city: '城市', carrier: '运营商', package: '套餐', duration: '时限',
  install_fee: '安装费', package_fee: '套餐费', commission: '佣金',
  commission_rate: '佣金率', id_card: '身份证号', address: '地址', sales_person: '销售员'
};

function renderLogRow(row) {
  const time = row.created_at ? new Date(row.created_at).toLocaleString('zh-CN') : '';
  const actionLabel = { insert: '➕ 新增', update: '✏️ 修改', delete: '❌ 删除' }[row.action] || row.action;
  const personName = (row.new_data && row.new_data.name) || (row.old_data && row.old_data.name) || '—';
  const fields = row.changed_fields || [];

  let details = '';
  if (row.action === 'update' && fields.length && row.old_data && row.new_data) {
    details = '<details><summary>查看字段变更</summary><div class="log-diff">' +
      fields.map(f => {
        const old = row.old_data[f] ?? '';
        const nw = row.new_data[f] ?? '';
        return '<div class="log-diff-row">' +
          '<span class="log-diff-field">' + (FIELD_ZH[f] || f) + '</span>' +
          '<span class="log-diff-old">' + esc(String(old)) + '</span>' +
          '<span class="log-diff-arrow">→</span>' +
          '<span class="log-diff-new">' + esc(String(nw)) + '</span></div>';
      }).join('') +
      '</div></details>';
  } else if (row.action === 'delete' && row.old_data) {
    // 已经在库里的就不再给恢复入口，避免同一条被恢复两次
    const restored = alreadyInDb(row.old_data);
    // id 可能是数字也可能是 uuid 字符串，JSON.stringify 后两种都是合法的 JS 字面量
    const btn = restored
      ? '<span class="log-restored">已在订单中</span>'
      : '<button class="btn btn-sm btn-restore" onclick="restoreFromLog(' +
          escAttr(JSON.stringify(row.id)) + ', this)">恢复</button>';
    details = '<div class="log-diff log-deleted"><span>删除前：' +
      esc(row.old_data.name || '') + ' / ' + esc(row.old_data.phone || '') + '</span>' + btn + '</div>';
  }

  return '<div class="log-item">' +
    '<div class="log-header">' +
      '<span><span class="log-action log-action-' + esc(row.action) + '">' + actionLabel + '</span>' +
        ' · ' + esc(row.actor || '未知') + '</span>' +
      '<span class="log-time">' + time + '</span>' +
    '</div>' +
    '<div style="margin-top:4px"><span class="log-name">' + esc(personName) + '</span>' +
      (fields.length ? ' 修改了 ' + fields.length + ' 个字段' : '') +
    '</div>' +
    details +
    '</div>';
}

/* ========== 启动 ========== */
bootstrap();

// 注册 Service Worker，让页面能添加到主屏并离线打开。
// 失败不影响正常使用（例如通过 file:// 打开时没有 SW 环境）。
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  });
}
