/* =====================================================================
 * 智目科技 · 测试组工作台 —— 认证 + API 代理（平台无关核心）
 * =====================================================================
 * 这个模块承担三件事：
 *   1. 登录认证（账号密码 / 游客），会话、单点登录、限时
 *   2. 简易管理后台接口（账号增删改、在线查看、强制下线）
 *   3. 大模型 API 代理 —— ★ 这是最关键的一件：
 *      API Key 存在服务端环境变量里，前端拿不到。
 *      之前 Key 写在前端 config.js 里，base64 拆两段而已、
 *      任何人查看源代码就能拿走，等于把额度公开。
 *
 * 平台无关：本文件不出现任何 Deno / Cloudflare 专有 API，
 * 只吃标准 Web API（Request / Response / crypto / fetch）。
 * 入口见 worker.js（Cloudflare）与 deno/main.js（Deno Deploy）。
 *
 * ★★ 会话为什么改成无状态签名 ★★
 * Deno KV 和 Cloudflare KV 都是**最终一致**（全球 60s 内同步）。
 * 旧版每次请求都去 KV 读 sess:<token>，登录后下一个请求如果被调度
 * 到另一个边缘节点，会话还没同步过去 —— 用户会被莫名其妙踢下线。
 * 现在改成：Cookie 里放 HMAC 签名的无状态令牌，鉴权**零 KV 读取**。
 * KV 只在两处用：
 *   · 登录时查账号
 *   · uid:<用户名> 这条「单点登录指针」，用于强制下线/停用/改密码
 *
 * ★ 最终一致下的作废判据（很关键）
 * 指针记录 uid:<用户名> = { jti, iat, role, enabled }
 * 令牌里也有签发时间 a。
 * 判据是【只有当指针的 iat 比令牌的 a 更新时才作废】：
 *   读到旧指针 → 放过（宁可晚 60s 生效，也不误踢在线用户）
 *   读到新指针 → 作废（真正被顶掉/停用/改密码的，一定生效）
 * 这是「陈旧只可能放宽、绝不放严」的偏置，是最终一致下的正确做法。
 *
 * KV 键设计
 *   user:<userId>        账号 { id, name, pwd, salt, role, enabled, createdAt }
 *   name:<用户名>         → userId（登录时按名字查）
 *   sess:<jti>           会话 { jti, name, role, ip, ua, guest, expAt, loginAt }
 *   ip:<ip>              { token, jti, guest, lastGuestAt }
 *   uid:<用户名>         { token, jti, iat, role, enabled }  ← 单点登录指针
 *   lock:<ip>            登录失败锁定截止时间戳
 * ===================================================================== */

/* ---------- KV 键名转义：用户输入绝不能直接拼进键 ---------- */
const kUser = (id) => `user:${id}`;
const kName = (n) => `name:${encodeURIComponent(String(n).trim().toLowerCase())}`;
const kSess = (jti) => `sess:${jti}`;
const kIp = (ip) => `ip:${encodeURIComponent(ip || 'unknown')}`;
const kUid = (n) => `uid:${encodeURIComponent(String(n).trim().toLowerCase())}`;
const kLock = (ip) => `lock:${encodeURIComponent(ip)}`;
/* ---------- 更新通知的已读位置 ----------
   ★ 为什么必须存服务端：localStorage 是**这台电脑**的。
     换个浏览器、清一次缓存、或者换个 IP 从别处登录，红点就全量回来 ——
     而需求是「已读跟着账号走，只有发了新消息才算未读」。
     存本机等于把这个需求实现成了「已读跟着这台机器走」。
   值 { seen: "<通知 id>", at }；只存「读到哪一条」，未读条数由前端按数组下标算，
   这样加通知、删通知都不用动服务端。 */
const kSeen = (n) => `seen:${encodeURIComponent(String(n).trim().toLowerCase())}`;
/* ★ 被强制下线的 IP：拉黑名单，冷却期内该 IP 登不进来。
   key 是 kick:<ip>，值 { ip, at, until, by, name }，用 TTL 自然过期。
   ★ 只有拿得到真实 IP 时才写这条：Deno Deploy 不下发客户端 IP，所有人
     都记成 unknown，那是全站共享的一个桶，拉黑它等于封掉所有人。 */
const kKick = (ip) => `kick:${encodeURIComponent(ip || 'unknown')}`;
/* ★ 账号级冷却：key 是 kickn:<账号名>，值同 kick。
   拿不到真实 IP 时（unknown）靠这条兜底——否则「强制下线」退化成
   「下次刷新就回来」。IP 和账号双写，任一条生效就拦住。 */
const kKickName = (n) => `kickn:${encodeURIComponent(String(n || '').trim().toLowerCase())}`;
/* ★ 拥有者登录过的 IP：白名单，永不拉黑。
   拥有者换了 IP 登录会自动多登记一条；TTL 与会话一致，
   过期后不再登录就不再豁免（避免永久留后门）。 */
const kOwnerIp = (ip) => `ownerip:${encodeURIComponent(ip)}`;

/** 拿不到真实客户端 IP 时各平台给的都是 'unknown'，那不是「一个 IP」，是「没有 IP」。 */
const isRealIp = (ip) => !!ip && ip !== 'unknown' && ip !== 'UNKNOWN';

/* 「当前在线」的判定窗口。
   ★ sess: 记录只靠 TTL 自然过期（7 天），用户关掉浏览器后记录还在、
   单点登录指针也还对得上 —— 所以以前这个列表其实是
   「持有有效登录令牌的账号」，不是「现在在线的人」。
   表现就是明明有人早就走了，还挂着「剩余 7 天」排在最上面。
   现在加一个轻量心跳（/api/ping），超过这个窗口没心跳的就不算在线。
   取 15 分钟：比前端的 5 分钟心跳宽 3 倍，网络抖一下不会把人踢出列表。 */
const ONLINE_WINDOW_MIN = 15;

/* ★ 写「作废指针」时，i-iat 必须**严格大于**被作废令牌的签发时刻。
   getSession 的作废判据是 (cur.iat > p.a) —— 严格大于，不是大于等于。
   这里原来直接写 Date.now()：只要登录与「踢下线 / 改密码 / 删号」
   落在**同一毫秒**，指针 iat 就会跟令牌的 issuedAt 完全相等，
   判据不成立 → **被作废的令牌继续能用满 7 天**，而接口照样回 200。
   现场表现是「强制下线时灵时不灵」，而且极难复现（Date.now() 只到毫秒）。
   所以凡是抬高指针时间的地方一律过这个函数，下界取已知的最老签发时刻。 */
function bumpIat(earliest) {
  const now = Date.now();
  const floor = (earliest || 0) + 1;      /* 至少要比下界新 1ms */
  return now > floor ? now : floor;
}

const TTL_SESSION = 60 * 60 * 24 * 7;      /* 正常会话 7 天 */
const TTL_GUEST = 8 * 60;                  /* ★ 游客 8 分钟 */
const TTL_GUEST_IP = 6 * 60 * 60;          /* ★ 同 IP 游客冷却 6 小时 */
const KICK_COOLDOWN = 6 * 60 * 60;         /* ★ 被强制下线的 IP 冷却 6 小时 */
const PBKDF2_ITER_DEFAULT = 100000;

/* ---------- 基础工具 ---------- */
const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extra }
  });

const fail = (msg, status = 400) => json({ ok: false, error: msg }, status);

/* ★ 客户端 IP。各平台塞的请求头不一样，全都要认。
   ⚠ 2026-11-18 实测：Deno Deploy 这边**一个 IP 请求头都不给**
   （cf-connecting-ip / dpc-connecting-ip / x-forwarded-for 全是空），
   老实现于是永远返回 'unknown' —— 全站共用一个 q:ip:unknown 键，
   「同一 IP 免密」就变成了「谁后登录谁覆盖」，等于没有。
   现在多认几个头，并做形状校验（不像 IP 的值直接丢掉，别把 'for=1.2.3.4'
   这种 RFC 7239 写法或 'unknown' 当成 IP）。 */
const IP_HEADERS = ['cf-connecting-ip', 'dpc-connecting-ip', 'x-forwarded-for',
  'x-real-ip', 'true-client-ip', 'x-client-ip', 'x-forwarded'];
function looksLikeIp(v) {
  if (!v) return false;
  if (/^(unknown|null|undefined|off|none)$/i.test(v)) return false;
  return /^[0-9a-f:.]{3,45}$/i.test(v);
}
function clientIp(req) {
  for (const n of IP_HEADERS) {
    const raw = req.headers.get(n);
    if (!raw) continue;
    const first = String(raw).split(',')[0].trim();
    if (looksLikeIp(first)) return first;
  }
  return 'unknown';
}

/* ---------- 登录限速的「桶」 ----------
 * ★ 正常按 IP 分桶；拿不到真实 IP 时**不能**用 'unknown'：
 *   Deno Deploy 不下发客户端 IP，所有人算出来都是 unknown，那是个全站共享桶 ——
 *   一个人输错 5 次密码，全站所有人 10 分钟都登不进去
 *   （2026-11-18 用户撞上了：登录页把 429 说成「网关不可用」，他以为平台坏了）。
 * ⇒ 拿不到真实 IP 时改成「账号名 + 浏览器指纹」：
 *   同一个账号在同一浏览器上输错 5 次照样锁（防手抖、防针对单账号的爆破），
 *   但不会连累别的账号、也不会连累同一出口的同事。
 * ★ 改了要重新部署网关才生效（deno deploy）。 */
function lockScope(req, name) {
  const ip = clientIp(req);
  if (isRealIp(ip)) return 'ip:' + ip;
  const ua = String(req.headers.get('User-Agent') || '').slice(0, 120);
  const who = encodeURIComponent(String(name || '').trim().toLowerCase());
  return 'acct:' + who + ':' + encodeURIComponent(ua);
}

/** 统一允许的来源：站点自己的域名 + 本地开发。
 *  没做白名单的话，任何人拿个网页都能拿你的 token 来调 —— 那登录就白做了。 */function corsOrigin(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allow = (env.ALLOW_ORIGINS || '')
    .split(',').map((s) => s.trim()).filter(Boolean);
  if (allow.indexOf(origin) >= 0) return origin;
  return '';
}

function withCors(req, env, extra = {}) {
  const o = corsOrigin(req, env);
  return {
    'Access-Control-Allow-Origin': o || 'null',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
    ...extra
  };
}

/* =====================================================================
 * HMAC 签名令牌（无状态会话）
 * ===================================================================== */
function b64uEncode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDecode(str) {
  const s = atob(String(str).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    'raw', new TextEncoder().encode(String(secret)), { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign', 'verify']);
}

/** payload（普通对象）→ "b64u(json).b64u(hmac)" */
async function makeToken(payload, secret) {
  if (!secret) throw new Error('服务端没有配置 SESSION_SECRET');
  const body = b64uEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret),
    new TextEncoder().encode(body));
  return body + '.' + b64uEncode(new Uint8Array(sig));
}

/** 验签 + 解析。签名不对一律返回 null，绝不「猜」 */
async function verifyToken(tok, secret) {
  if (!secret || !tok) return null;
  const dot = String(tok).lastIndexOf('.');
  if (dot <= 0) return null;
  const body = String(tok).slice(0, dot);
  const sig = String(tok).slice(dot + 1);
  let ok = false;
  try {
    ok = await crypto.subtle.verify('HMAC', await hmacKey(secret),
      b64uDecode(sig), new TextEncoder().encode(body));
  } catch (e) { return null; }
  if (!ok) return null;
  try {
    return JSON.parse(new TextDecoder().decode(b64uDecode(body)));
  } catch (e) { return null; }
}

/* ---------- 密码哈希：PBKDF2-SHA256 + 每账号独立随机 salt ---------- */
function toHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(pwd, saltHex, env) {
  const iter = Number(env && env.PBKDF2_ITER) > 0
    ? Number(env.PBKDF2_ITER) : PBKDF2_ITER_DEFAULT;
  const salt = saltHex
    ? Uint8Array.from(saltHex.match(/.{2}/g).map((h) => parseInt(h, 16)))
    : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(pwd), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, key, 256);
  return { hash: toHex(bits), salt: toHex(salt.buffer) };
}

/** 定长比较，避免按前缀逐字符比较泄露信息 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function sha256Hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)));
  return toHex(d);
}

function token() {
  return (crypto.randomUUID() + crypto.randomUUID()).replace(/-/g, '');
}

function readCookie(req, name) {
  const raw = req.headers.get('Cookie') || '';
  const hit = raw.split(';').map((s) => s.trim())
    .find((s) => s.startsWith(name + '='));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : '';
}

/* ★ 必须 SameSite=None。
   站点在 space.mcode.cn、网关在 deno.net —— 这是**跨站**。
   SameSite=Lax 的规则是「跨站子请求既不发送也不存储 Cookie」，
   于是 /api/session 请求到网关时根本没带 Cookie → 401 →
   主页面跳登录页、登录页跳回来 → 无限闪屏。
   None + Secure 是跨站 Cookie 认证的硬性要求（Secure 不能省）。
   因为放开成跨站了，必须配套 CSRF 防护，见 assertSameOrigin()。 */
/* ★ 清 Cookie 的属性必须和当初设置时**完全一致**（Path / Secure / SameSite），
   否则浏览器不认这是同一个 Cookie，Max-Age=0 根本删不掉它。
   我们当初为了跨站用的是 SameSite=None; Secure，删的时候也得原样带上。
   少了 Secure 的症状是：点「退出登录」跳回登录页，登录页一查会话还在，
   又自动跳回工作台 —— 用户看到的就是「退出后又自己进去了」。 */
function clearCookie() {
  return 'ztk=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None';
}

function setCookie(tk, maxAge) {
  return `ztk=${tk}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=None`;
}

/* ★ CSRF 防护：Cookie 既然允许跨站带了，就必须校验来源。
   带 Origin 头且不在白名单里的写操作一律 403。
   （同站部署时浏览器可能不带 Origin，此时放行 —— 那本来就不是跨站攻击面。） */
function assertSameOrigin(req, env) {
  const origin = req.headers.get('Origin');
  if (!origin) return null;                       /* 同站请求，没有 Origin */
  if (corsOrigin(req, env)) return null;          /* 白名单里的来源 */
  return fail('来源不被允许：' + origin, 403);
}

/* =====================================================================
 * 会话读取：验签（0 次 KV 读）+ 指针校验（1 次 KV 读）
 * ===================================================================== */
async function getSession(req, env) {
  const tk = readCookie(req, 'ztk') || (req.headers.get('X-ZT-Token') || '');
  if (!tk) return null;

  const p = await verifyToken(tk, env.SESSION_SECRET);
  if (!p) return null;
  if (!p.e || Date.now() > p.e) return null;

  const s = {
    token: tk, jti: p.j, uid: null, name: p.n, role: p.r || 'user',
    ip: p.i || 'unknown', guest: !!p.g,
    expAt: p.e, loginAt: p.a, lastSeen: Date.now()
  };

  /* 游客不查 KV：8 分钟短令牌，被顶掉也无所谓 */
  if (p.g) return s;

  /* ★ 单点登录 / 停用 / 改密码：
     只有当指针比令牌「新」才作废 —— 见文件头「最终一致下的作废判据」 */
  const cur = await env.KV.get(kUid(p.n), 'json');
  if (cur && (cur.iat || 0) > (p.a || 0)) {
    if (cur.jti !== p.j) return null;         // 被别处登录顶掉了
    if (cur.enabled === false) return null;   // 账号被停用
    if (cur.role) s.role = cur.role;          // 角色以指针为准（管理员改的）
  }
  return s;
}

function pubUser(name, role = 'user') {
  return { name, role };
}

/* ---------- 登录 ---------- */
async function handleLogin(req, env) {
  let body;
  try { body = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }
  const name = String(body.name || '').trim();
  const pwd = String(body.pwd || '');
  const ip = clientIp(req);
  const ua = String(req.headers.get('User-Agent') || '').slice(0, 200);

  if (!name || !pwd) return fail('请填写账号与密码');

  /* ★ 被强制下线的 IP：6 小时内一律登不进来。
     没有这条的话，被踢的人换个浏览器/清个 Cookie 就能立刻回来，
     「强制下线」等于没踢。解除只能由拥有者在管理台手动放行。
     只有拿得到真实 IP 才拦；ip 为 unknown 时这是个全站共享桶，拦它等于拦所有人。 */
  if (isRealIp(ip)) {
    const kicked = await env.KV.get(kKick(ip), 'json');
    if (kicked && Date.now() < (kicked.until || 0)) {
      const mins = Math.max(1, Math.ceil(((kicked.until - Date.now()) / 60000)));
      return json({
        ok: false, error: 'ip_cooldown',
        msg: '本机 IP（' + ip + '）因被强制下线，' + mins + ' 分钟内无法登录。'
          + '若你换了账号仍然如此，说明是同 IP 的其他人被踢了。'
      }, 429);
    }
  }

  /* 暴力破解限速：同一 IP 连续失败 5 次锁 10 分钟
     ★ 2026-11-18：桶不能是全站共享的 'unknown'。
       Deno Deploy 不下发真实客户端 IP（cf-connecting-ip / dpc-connecting-ip /
       x-forwarded-for 全都没有），所有人算出来都是 'unknown' —— 那是个**全站共享桶**：
       一个人输错 5 次密码，**全站所有人 10 分钟都登不进去**
       （用户当场撞上了：登录页又把 429 说成「网关不可用」，他以为平台坏了，越试越多）。
       ⇒ 拿不到真实 IP 时，桶改成「账号名 + 浏览器指纹」：
         同一个账号在同一浏览器上输错 5 次照样锁（防手抖、防针对单账号的爆破），
         但不会连累别的账号、更不会连累同一出口的同事。
       ★ 改完必须重新部署网关才生效（deno deploy），见文件末尾的说明。 */
  const lockKey = kLock(lockScope(req, name));
  const lock = await env.KV.get(lockKey);
  if (lock && Date.now() < Number(lock)) {
    return fail('失败次数过多，请 ' + Math.ceil((lock - Date.now()) / 60000) + ' 分钟后再试', 429);
  }

  const id = await env.KV.get(kName(name), 'json');
  const user = id ? await env.KV.get(kUser(id), 'json') : null;

  if (!user || !user.enabled) {
    await bumpQFail(env, lockKey, lockIpKey);
    return fail('账号或密码不正确', 401);
  }
  const { hash } = await hashPassword(pwd, user.salt, env);
  if (!safeEqual(hash, user.pwd)) {
    await bumpFail(env, lockKey);
    return fail('账号或密码不正确', 401);
  }

  await env.KV.delete(lockKey);

  /* ★ 账号级冷却：拿不到真实 IP 时这是唯一的拦截手段。
     放在口令校验之后：放前面的话，不带口令的人挨个试就能知道
     「哪些账号正在被踢」，等于开了一个账号状态查询接口。
     拥有者账号豁免——能删这条冷却记录的只有拥有者本人，
     万一记上了就是永久自锁，谁也救不了。 */
  if (user.role !== 'owner') {
    const kickedName = await env.KV.get(kKickName(user.name), 'json');
    if (kickedName && Date.now() < (kickedName.until || 0)) {
      const mins = Math.max(1, Math.ceil(((kickedName.until - Date.now()) / 60000)));
      return json({
        ok: false, error: 'account_cooldown',
        msg: '账号 ' + user.name + ' 因被强制下线，' + mins + ' 分钟内无法登录。'
          + '若你不是本人操作，请联系拥有者。'
      }, 429);
    }
  }

  /* ★ 拥有者登录过的 IP 登记为白名单：这条 IP 永不被拉黑。
     必须放在「同 IP 复用会话」那条捷径之前，否则复用命中时不会走到这里。
     白名单只认「拥有者本人登录」这一件事——别人冒充 owner 账号是没用的，
     因为口令校验在更前面就过了。 */
  if (isRealIp(ip) && user.role === 'owner') {
    await env.KV.put(kOwnerIp(ip), JSON.stringify({
      ip, name: user.name, at: Date.now()
    }), { expirationTtl: TTL_SESSION });
  }

  /* ★ 同 IP 已有「同一个账号」的有效会话 → 直接复用（不必再走一遍会话写入）。
     必须比对账号名：只判断「这个 IP 上有会话」的话，
     共享 IP（办公室/网吧）下任何人输任意账号都会被换成已登录者的身份。

     ★ 还必须确认这条令牌没被作废。verifyToken 只验签名和过期，
       被踢 / 单点登录顶掉的令牌签名照样是好的；不复核 uid 指针的话，
       这里会把一条死令牌递回去 —— 登录显示成功，下一个请求就 401，
       表现就是「怎么都登不进去」，而且换个浏览器也一样。 */
  const ipRec = await env.KV.get(kIp(ip), 'json');
  if (ipRec && ipRec.token && !ipRec.guest && ipRec.name === user.name) {
    const p = await verifyToken(ipRec.token, env.SESSION_SECRET);
    const ptr = p ? await env.KV.get(kUid(user.name), 'json') : null;
    /* 指针缺失也算作废：宁可重新签一个，也别递一条可能已经作废的 */
    const alive = p && !p.g && p.n === user.name && Date.now() < p.e
      && ptr && ptr.jti === p.j && ptr.token === ipRec.token && ptr.token;
    if (alive) {
      return json({
        ok: true, reused: true, user: pubUser(p.n, p.r), token: ipRec.token,
        expireAt: p.e, guest: false
      }, 200, { 'Set-Cookie': setCookie(ipRec.token, TTL_SESSION) });
    }
  }

  /* 新会话 */
  const jti = token();
  const issuedAt = Date.now();
  const expAt = issuedAt + TTL_SESSION * 1000;
  const tk = await makeToken(
    { j: jti, n: user.name, r: user.role, g: 0, e: expAt, a: issuedAt, i: ip },
    env.SESSION_SECRET);

  /* sess: 只给「在线列表」和「强制下线」用，不参与鉴权 */
  await env.KV.put(kSess(jti), JSON.stringify({
    jti, name: user.name, role: user.role, ip, ua,
    guest: false, loginAt: issuedAt, lastSeen: issuedAt, expAt
  }), { expirationTtl: TTL_SESSION });

  /* 单点登录指针。旧 token 无需删除：旧令牌比这条旧，会被判失效。 */
  await env.KV.put(kUid(user.name), JSON.stringify({
    ip, token: tk, jti, iat: issuedAt, role: user.role, enabled: true
  }), { expirationTtl: TTL_SESSION });

  await env.KV.put(kIp(ip), JSON.stringify({
    token: tk, jti, name: user.name, guest: false,
    lastGuestAt: (ipRec || {}).lastGuestAt || 0
  }), { expirationTtl: TTL_SESSION });

  return json({
    ok: true, user: pubUser(user.name, user.role), token: tk, expireAt: expAt, guest: false
  }, 200, { 'Set-Cookie': setCookie(tk, TTL_SESSION) });
}

async function bumpFail(env, lockKey) {
  const k = `fail:${lockKey}`;
  const n = ((Number(await env.KV.get(k)) || 0) + 1);
  await env.KV.put(k, String(n), { expirationTtl: 900 });
  if (n >= 5) {
    await env.KV.put(lockKey, String(Date.now() + 10 * 60000), { expirationTtl: 900 });
    await env.KV.delete(k);
  }
}

/* ---------- 游客登录 ---------- */
async function handleGuest(req, env) {
  const ip = clientIp(req);
  const ipKey = kIp(ip);
  const rec = (await env.KV.get(ipKey, 'json')) || {};

  /* ★ 同 IP 6 小时内只能游客一次 */
  const cd = rec.lastGuestAt || 0;
  const left = 6 * 60 * 60 * 1000 - (Date.now() - cd);
  if (left > 0) {
    return json({
      ok: false, error: 'cooldown',
      msg: '本机 IP 在 ' + (cd ? Math.ceil(left / 60000) : 6 * 60) + ' 分钟内已经用过游客体验，'
        + '每个 IP 每 6 小时只能体验一次。需要的话请用正式账号登录。'
    }, 429);
  }

  const jti = token();
  const issuedAt = Date.now();
  const expAt = issuedAt + TTL_GUEST * 1000;
  const tk = await makeToken(
    { j: jti, n: '游客', r: 'guest', g: 1, e: expAt, a: issuedAt, i: ip },
    env.SESSION_SECRET);

  await env.KV.put(kSess(jti), JSON.stringify({
    jti, name: '游客', role: 'guest', ip,
    ua: String(req.headers.get('User-Agent') || '').slice(0, 200),
    guest: true, loginAt: issuedAt, lastSeen: issuedAt, expAt
  }), { expirationTtl: TTL_GUEST });

  await env.KV.put(ipKey, JSON.stringify({
    token: tk, jti, name: '游客', guest: true, lastGuestAt: issuedAt
  }), { expirationTtl: TTL_GUEST_IP });

  return json({
    ok: true, user: { name: '游客', role: 'guest' }, token: tk,
    expireAt: expAt, guest: true, ttlSeconds: TTL_GUEST
  }, 200, { 'Set-Cookie': setCookie(tk, TTL_GUEST) });
}

async function handleLogout(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const s = await getSession(req, env);
  if (s) {
    await env.KV.delete(kSess(s.jti));
    if (!s.guest) {
      const u = await env.KV.get(kUid(s.name), 'json');
      if (u && u.jti === s.jti) await env.KV.delete(kUid(s.name));
    }
  }
  /* 同 IP 的记忆也要清，否则下次进来会被自动登进去 */
  const ipKey = kIp(clientIp(req));
  const rec = await env.KV.get(ipKey, 'json');
  if (rec && s && rec.token === s.token) {
    await env.KV.put(ipKey, JSON.stringify({
      token: '', guest: false, lastGuestAt: rec.lastGuestAt || 0
    }), { expirationTtl: 60 });
  }
  return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}

/* ---------- 会话查询（前端启动时调；被挤下线时返回 ok:false）---------- */
async function handleSession(req, env) {
  const s = await getSession(req, env);
  if (!s) return json({ ok: false, reason: 'no_session' }, 401);
  return json({
    ok: true, user: pubUser(s.name, s.role),
    guest: !!s.guest, expireAt: s.expAt,
    leftSeconds: Math.max(0, Math.round((s.expAt - Date.now()) / 1000)),
    ip: s.ip
  });
}

/* ---------- 在线心跳 ----------
   ★ 为什么必须有它：sess: 记录只靠 TTL 自然过期（7 天）。
     用户关掉浏览器、页面一关，令牌还在、记录还在、指针也对得上 ——
     于是「当前在线」列出来的其实是「持有有效登录令牌的账号」，
     明明早就下线的人还挂着「剩余 7 天」排在最上面。
   工作台每 5 分钟（仅在页面可见时）打一次这个接口刷新 lastSeen，
   管理台按「多久没心跳」判定在线与否。
   成本：一次 KV 写 + 一个 204，空响应；60 秒内重复调用直接跳过写入。 */
/* ---------- 更新通知的已读位置 ----------
   GET  → 这个账号读到哪一条了
   POST → 标记已读（body { id }）
   ★ 游客不落盘：所有游客共用一个账号名，写进去就等于所有人的已读互相污染。
     这种情况返回 persisted:false，前端退回本机 localStorage —— 游客本来就是
     「用完就走」，已读不跟着走是合理的。 */
async function handleNotifySeen(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const s = await getSession(req, env);
  if (!s) return json({ ok: false, error: 'no_session' }, 401);
  if (Date.now() > s.expAt) return json({ ok: false, error: 'expired' }, 401);

  if (s.guest) return json({ ok: true, seen: '', persisted: false });

  const key = kSeen(s.name);
  if (req.method === 'POST') {
    let b; try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }
    /* id 只是「读到哪一条」的标记，不是自由文本，但仍然限长 + 去掉控制字符：
       它要拼进 KV 值的 JSON，存太长或带怪字符会让排查变得很痛苦。 */
    const id = String(b.id == null ? '' : b.id).replace(/[\x00-\x1F]/g, '').slice(0, 40);
    await env.KV.put(key, JSON.stringify({ seen: id, at: Date.now() }));
    return json({ ok: true, seen: id, persisted: true });
  }
  const rec = (await env.KV.get(key, 'json')) || {};
  return json({ ok: true, seen: String(rec.seen || ''), persisted: true });
}

async function handlePing(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const s = await getSession(req, env);
  if (!s) return json({ ok: false, error: 'no_session' }, 401);
  if (Date.now() > s.expAt) return json({ ok: false, error: 'expired' }, 401);
  const key = kSess(s.jti);
  const now = Date.now();
  const rec = (await env.KV.get(key, 'json')) || {
    jti: s.jti, name: s.name, role: s.role, ip: s.ip,
    guest: !!s.guest, loginAt: s.loginAt || now, lastSeen: 0
  };
  /* 防抖动：短时间内的重复心跳不重写，省掉无谓的 KV 写 */
  if (now - (rec.lastSeen || 0) < 60000) return json({ ok: true, skipped: true });
  rec.lastSeen = now;
  rec.expAt = s.expAt;
  await env.KV.put(key, JSON.stringify(rec), { expirationTtl: TTL_SESSION });
  return json({ ok: true, lastSeen: now });
}

/* =====================================================================
 * 答题站专用账号空间（与工作台完全隔离）
 * ---------------------------------------------------------------------
 * ★ 为什么要单独一套：答题站和工作台是两个产品，账号不该互相影响。
 *   共用一张账号表的话，「答题站只留 ZM1 / ZM2 两个管理员」会把
 *   工作台的运维账号一起降级 —— 这是实际踩过的坑，别再改回去。
 * ★ 隔离三件套：
 *   1) KV 键全部加 q: 前缀：账号 / 会话 / 单点指针 / 答题数据各有一套
 *   2) 令牌里带 s:'quiz' 站点标记：两边的令牌互相不认
 *   3) Cookie 用独立名 qztk、请求头用独立头 X-QZ-Token
 * ★ 答题站只有两种角色：admin / user，**没有拥有者**。
 * ===================================================================== */
const qUser = (id) => `q:user:${id}`;
const qName = (n) => `q:name:${encodeURIComponent(String(n).trim().toLowerCase())}`;
const qSess = (jti) => `q:sess:${jti}`;
const qIp = (ip) => `q:ip:${encodeURIComponent(ip || 'unknown')}`;
/* ★ 按**设备**记的免密记录（客户端 localStorage 里的随机 qdid）。
   为什么不能只靠 IP：手机走 4G/5G，运营商 CGNAT 的出口 IP 经常变；
   而 Deno Deploy 干脆连 IP 都给不出来。所以免密改成认「这台设备」。 */
const qDev = (did) => `q:dev:${encodeURIComponent(String(did || '').slice(0, 64))}`;
/* ★ 后端题库：q:qbank —— 判分用的权威题目+标准答案+得分点。
   ★ 判分绝不能信前端传上来的标准答案（能被篡改成满分），所以题目必须存服务端。 */
const Q_QBANK = 'q:qbank';
/* ★ AI 配置：q:aicfg —— {key, base, model}。API Key 只存在服务端，不进仓库。 */
const Q_AICFG = 'q:aicfg';
/* ★ 站内通知：q:notice:<账号名> → 通知数组（最多 20 条，新的在前） */
const qNotice = (name) => `q:notice:${encodeURIComponent(String(name || '').trim().toLowerCase())}`;
const NOTICE_TTL = 60 * 60 * 24 * 30;   /* 通知留 30 天 */
/* ★ 答题站的拥有者：**有且只有这 2 个，固定不可转让**（2026-11-23 用户要求）。
   拥有者 = 管理员的全部权利 + 「把普通用户提升为管理员」这一条。
   通过注册只能成为普通用户 —— 注册处理器里 role 写死 'user'。 */
const QUIZ_OWNERS = ['ZM1', 'ZM2'];
const qUid = (n) => `q:uid:${encodeURIComponent(String(n).trim().toLowerCase())}`;
const qState = (n) => `q:state:${encodeURIComponent(String(n).trim().toLowerCase())}`;
/* ★ 锁按「IP + 账号」计，不再按 IP 一把大锁。
   原因：原来的「同 IP 连错 5 次 → 整个 IP 锁 10 分钟」会连坐 ——
   一个人手滑输错密码，整个办公室（共用出口 IP）10 分钟全登不进来。
   2026-11-18 实际发生过。改成：同 IP **同一账号**错 5 次 → 只锁这个账号；
   另外保留一个宽松的 IP 级计数（30 次）防批量撞不同账号。 */
const qLock = (ip, name) =>
  `q:lock:${encodeURIComponent(ip)}|${encodeURIComponent(String(name || '').trim().toLowerCase())}`;
const qLockIp = (ip) => `q:lockip:${encodeURIComponent(ip)}`;
const Q_LOCK_ACCOUNT_MAX = 5;      /* 同账号连续错 5 次 → 锁 10 分钟 */
const Q_LOCK_IP_MAX = 30;          /* 同 IP 跨账号错 30 次 → 锁 30 分钟 */
const Q_REGISTER_PER_HOUR = 30;   /* 原为 5：公司共用出口 IP 时，
                                  一次培训会大家同时注册会被卡住 */
const Q_ONLINE_WINDOW_MIN = 5;

function qSetCookie(tk, maxAge) {
  return `qztk=${tk}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=None`;
}

/** 答题站会话：只认 s==='quiz' 的令牌，读写都用 q: 前缀的键 */
async function getQuizSession(req, env, tokenOverride) {
  /* tokenOverride：会话检查走 POST + form body 时，令牌放在 body 里传过来
     （这样是**简单请求**，浏览器不预检，手机慢网下不会超时）。 */
  const tk = tokenOverride || readCookie(req, 'qztk') || (req.headers.get('X-QZ-Token') || '');
  if (!tk) return null;
  const p = await verifyToken(tk, env.SESSION_SECRET);
  if (!p || p.s !== 'quiz') return null;          /* ★ 站点标记：工作台的令牌这里不认 */
  if (!p.e || Date.now() > p.e) return null;
  const s = {
    token: tk, jti: p.j, name: p.n, role: p.r || 'user',
    ip: p.i || 'unknown', guest: false, expAt: p.e, loginAt: p.a, lastSeen: Date.now()
  };
  const cur = await env.KV.get(qUid(p.n), 'json');
  if (cur) {
    /* 被封禁 / 被删号 → 立刻失效 */
    if (cur.enabled === false) return null;
    if (cur.role) s.role = cur.role;
    /* ★ 不再因为「别处又登录了一次」就把当前会话作废。
       原来这里判 cur.iat > p.a 且 jti 不同就 return null，等于
       「同一账号同时只能在一处登录」—— 手机和电脑互相踢，
       用户要的「7 天不用再输密码」根本落不了地。
       改密码 / 删号 / 封禁 依然立刻踢掉（见 admin users PUT/DELETE 与 qPurgeSessions）。 */
  }
  return s;
}

/** 答题站管理员：admin 或 owner 都算（owner 拥有管理员的全部权利） */
async function isQuizAdmin(req, env) {
  const s = await getQuizSession(req, env);
  if (!s) return null;
  const id = await env.KV.get(qName(s.name), 'json');
  const u = id ? await env.KV.get(qUser(id), 'json') : null;
  return u && u.enabled && (u.role === 'admin' || u.role === 'owner') ? u : null;
}

/** 答题站拥有者：只有 ZM1 / ZM2 */
async function isQuizOwner(req, env) {
  const s = await getQuizSession(req, env);
  if (!s) return null;
  const id = await env.KV.get(qName(s.name), 'json');
  const u = id ? await env.KV.get(qUser(id), 'json') : null;
  return u && u.enabled && u.role === 'owner' ? u : null;
}

/** 是否已经存在拥有者（用来限制 setup 只有拥有者能调） */
async function hasQuizOwner(env) {
  for (const nm of QUIZ_OWNERS) {
    const id = await env.KV.get(qName(nm), 'json');
    if (!id) continue;
    const u = await env.KV.get(qUser(id), 'json');
    if (u && u.enabled && u.role === 'owner') return true;
  }
  return false;
}

async function qIssueSession(env, u, req, did) {
  const ip = clientIp(req);
  const ua = String(req.headers.get('User-Agent') || '').slice(0, 200);
  const jti = token();
  const issuedAt = Date.now();
  const expAt = issuedAt + TTL_SESSION * 1000;
  const tk = await makeToken(
    { j: jti, n: u.name, r: u.role, g: 0, s: 'quiz', e: expAt, a: issuedAt, i: ip },
    env.SESSION_SECRET);
  await env.KV.put(qSess(jti), JSON.stringify({
    jti, name: u.name, role: u.role, ip, ua, guest: false,
    loginAt: issuedAt, lastSeen: issuedAt, expAt
  }), { expirationTtl: TTL_SESSION });
  await env.KV.put(qUid(u.name), JSON.stringify({
    ip, token: tk, jti, iat: issuedAt, role: u.role, enabled: u.enabled !== false
  }), { expirationTtl: TTL_SESSION });
  const ipRec = await env.KV.get(qIp(ip), 'json');
  await env.KV.put(qIp(ip), JSON.stringify({
    token: tk, jti, name: u.name, guest: false,
    /* keep=true 才记这个 —— 之后同 IP 同账号可以直接复用会话，免密进 */
    keep: u.keep !== false,
    lastGuestAt: (ipRec || {}).lastGuestAt || 0
  }), { expirationTtl: TTL_SESSION });
  /* ★ 按设备记一份（免密的主路径）：换 IP、换网络都不影响。
     did 是客户端 localStorage 里的随机串，不是密码也不是隐私。 */
  if (did) {
    if (u.keep !== false) {
      await env.KV.put(qDev(did), JSON.stringify({
        name: u.name, token: tk, jti, at: issuedAt
      }), { expirationTtl: TTL_SESSION });
    } else {
      /* ★ 用户把「保持登录」关了 → 本机的免密记录必须一起清掉。
         不清的话会出现「明明取消了，下次密码留空还是能进」的诡异行为。 */
      await env.KV.delete(qDev(did));
    }
  }
  return { token: tk, expireAt: expAt };
}

/* ---------- AI 配置：KV 优先，其次环境变量 ---------- */
async function qModelConfig(env) {
  let rec = null;
  try { rec = await env.KV.get(Q_AICFG, 'json'); } catch (e) { rec = null; }
  rec = rec || {};
  return {
    key: rec.key || env.MODEL_API_KEY || '',
    /* ★ 默认用**新的** OpenAI 兼容端点：旧的 api.minimax.chat/v1/text/chatcompletion_v2
       已废弃（M2 / abab6.5-chat / MiniMax-Text-01 全部下线），现在报
       "The model X is no longer available"。国内基址 api.minimaxi.com。 */
    base: rec.base || 'https://api.minimaxi.com/v1/chat/completions',
    model: rec.model || 'MiniMax-M3.1-Flash'
  };
}

/* ---------- 填空题：规范化比对 ---------- */
function qNormText(s) {
  return String(s == null ? '' : s)
    .replace(/[\s\u3000]/g, '')                 /* 去掉所有空白（含全角空格） */
    .replace(/[（]/g, '(').replace(/[）]/g, ')')
    .replace(/[，]/g, ',').replace(/[。]/g, '.')
    .replace(/[：]/g, ':').replace(/[；]/g, ';')
    .replace(/[：]/g, ':')
    .replace(/[～]/g, '-').replace(/~/g, '-')
    .replace(/[－—–−]/g, '-')                     /* 各种横线统一 */
    .replace(/[×✕✖]/g, 'x')
    .replace(/[°]/g, '')
    .toLowerCase();
}
/* 同义词表：标准答案 → 其它可接受的写法（规范化后比较） */
const Q_ANSWER_ALIAS = {
  'stm32g474ret6': ['stm32g474'],
  '4.75-5.25v': ['4.75-5.25', '4.75~5.25'],
  '4.7-5.2v': ['4.7-5.2', '4.7~5.2'],
  '0.5-1.0m': ['0.5-1.0', '0.5m-1.0m', '0.5-1.0m'],
  '62.70x17.80mm': ['62.7x17.8mm', '62.70x17.80'],
  '4.75-5.25': ['4.75~5.25'],
  'ip65': ['ip65'],
  '±1.2a': ['1.2a', '±1.2'],
  'l1': ['l1'],
  '32': ['32颗']
};
function qFillMatch(std, user) {
  const a = qNormText(std), b = qNormText(user);
  if (!a || !b) return false;
  if (a === b) return true;
  const alias = Q_ANSWER_ALIAS[a];
  if (alias && alias.indexOf(b) >= 0) return true;
  /* 数字近似：两边数字个数相同且逐个相对误差 ≤1% */
  const na = a.match(/-?\d+(?:\.\d+)?/g), nb = b.match(/-?\d+(?:\.\d+)?/g);
  if (na && nb && na.length === nb.length && na.length > 0) {
    return na.every(function (x, i) {
      const fx = parseFloat(x), fy = parseFloat(nb[i]);
      if (fx === fy) return true;
      const scale = Math.max(Math.abs(fx), Math.abs(fy));
      return scale > 0 && Math.abs(fx - fy) <= scale * 0.01;
    });
  }
  return false;
}

/* ---------- 从模型输出里抠出 JSON ---------- */
function qParseAiJson(raw) {
  let t = String(raw || '');
  /* ★ 兜底：有些模型（如 MiniMax-M3）会先输出一段 <think>…</think> 思考过程，
       JSON 在后面。M3.1-Flash 一般不输出，但统一剥一下更保险。 */
  t = t.replace(/<think[\s\S]*?<\/think>/gi, '');
  const i = t.indexOf('{'), j = t.lastIndexOf('}');
  if (i < 0 || j <= i) return null;
  try { return JSON.parse(t.slice(i, j + 1)); } catch (e) { return null; }
}

/* ---------- 简答题 AI 判分 ---------- */
/* ★ 模型只回答「哪些得分点命中了」，**分数由程序按命中累加** ——
   模型就算胡说，也最多错几个点，不会凭空给出 8 分。 */
async function qAiGradeShort(env, q, userAnswer) {
  const points = Array.isArray(q.points) ? q.points : [];
  const max = Number(q.score || 3);
  const answer = String(userAnswer || '').trim();
  if (!points.length) {
    return { score: 0, max: max, hits: [], confidence: 0, reason: '题目没有得分点', needManual: true };
  }
  if (!answer) {
    return { score: 0, max: max, hits: [], confidence: 0, reason: '未作答', needManual: true };
  }
  const cfg = await qModelConfig(env);
  if (!cfg.key) {
    return { score: 0, max: max, hits: [], confidence: 0, reason: '服务端未配置模型密钥', needManual: true };
  }
  const pl = points.map(function (p, i) {
    return '[' + i + '] ' + p.text + '（' + p.points + ' 分）';
  }).join('\n');
  const prompt = [
    '你是培训考试判分助手。判断「考生答案」是否命中了每一个得分点。',
    '',
    '【题目】' + q.stem,
    '',
    '【参考答案】' + (q.reference || ''),
    '',
    '【得分点】',
    pl,
    '',
    '【考生答案】' + answer,
    '',
    '只输出一个 JSON 对象，不要任何其它文字，也不要输出思考过程：',
    '{"hits":[命中的得分点编号],"confidence":0到1之间的数,"reason":"一句话理由"}',
    '',
    '判定规则：',
    '1. 只有当考生答案**实质性地表达**了该得分点的内容才算命中；只是出现了相近的词但意思相反，不算命中。',
    '2. 没提到、答非所问、或与得分点无关的得分点，不命中。',
    '3. 允许用不同措辞表达同一个意思。',
    '4. confidence 是你对本次判断的把握程度（0 到 1）。'
  ].join('\n');

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(function () { ctrl.abort(); }, 25000);
    const r = await fetch(cfg.base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + cfg.key },
      body: JSON.stringify({
        model: cfg.model,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.1,
        stream: false
      }),
      signal: ctrl.signal
    });
    clearTimeout(timer);
    if (!r.ok) {
      return { score: 0, max: max, hits: [], confidence: 0,
        reason: '模型返回 HTTP ' + r.status, needManual: true };
    }
    const j = await r.json();
    const raw = (j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || '';
    const out = qParseAiJson(raw);
    if (!out || !Array.isArray(out.hits)) {
      return { score: 0, max: max, hits: [], confidence: 0,
        reason: '模型输出无法解析，需人工判分', needManual: true };
    }
    /* 只接受合法范围内的编号 */
    const hits = [];
    for (const h of out.hits) {
      const i = parseInt(h, 10);
      if (Number.isInteger(i) && i >= 0 && i < points.length && hits.indexOf(i) < 0) hits.push(i);
    }
    hits.sort(function (a, b) { return a - b; });
    let score = 0;
    for (const i of hits) score += Number(points[i].points || 0);
    score = Math.max(0, Math.min(score, max));
    let conf = parseFloat(out.confidence);
    if (!Number.isFinite(conf)) conf = 0;
    conf = Math.max(0, Math.min(1, conf));
    /* 可信度低 → 标记出来让管理员重点看 */
    const needManual = conf < 0.6 || (score === 0 && answer.length > 12);
    return {
      score: score, max: max, hits: hits, confidence: Math.round(conf * 100) / 100,
      reason: String(out.reason || '').slice(0, 200),
      needManual: needManual
    };
  } catch (e) {
    const msg = (e && e.name === 'AbortError') ? '判分超时' : ('判分失败：' + ((e && e.message) || e));
    return { score: 0, max: max, hits: [], confidence: 0, reason: msg, needManual: true };
  }
}

/* 写一条通知。★ 通知写失败**绝不能影响主流程**（封禁/改角色照样要成功） */
async function qNotify(env, name, type, title, body, link) {
  if (!name) return;
  try {
    const key = qNotice(name);
    const arr = (await env.KV.get(key, 'json')) || [];
    arr.unshift({
      id: token().slice(0, 16),
      type: type || 'info',
      title: title || '',
      body: body || '',
      link: link || '',
      at: Date.now(),
      read: false
    });
    await env.KV.put(key, JSON.stringify(arr.slice(0, 20)), { expirationTtl: NOTICE_TTL });
  } catch (e) {
    /* 通知写失败就忽略 */
  }
}

/* ---------- 题库存取（gzip + base64 + 分块） ----------
   ★ Deno KV 单个 value 上限 64 KiB，100 题 × 2 板块的题库 JSON 有 ~190 KB，
     直接存会报 "Value too large (max 65536 bytes)"。
     所以：gzip → base64 → 分块（每块 56 KB）写到 q:qbank:c0/c1/…，
     头信息（块数、编码）写在 q:qbank，读取时拼回来解压。 */
const Q_QBANK_CHUNK = 'q:qbank:c';
const Q_QBANK_CHUNK_SIZE = 56000;

async function qGzipB64(text) {
  const bytes = new TextEncoder().encode(text);
  const cs = new CompressionStream('gzip');
  const w = cs.writable.getWriter();
  w.write(bytes);
  w.close();
  const buf = new Uint8Array(await new Response(cs.readable).arrayBuffer());
  let s = '';
  for (let i = 0; i < buf.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
  }
  return btoa(s);
}
async function qGunzipB64(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const ds = new DecompressionStream('gzip');
  const w = ds.writable.getWriter();
  w.write(bytes);
  w.close();
  const out = await new Response(ds.readable).arrayBuffer();
  return new TextDecoder().decode(out);
}

/* ---------- 交卷 / 判分 / 复核 ---------- */
/* ★ 题库进程内缓存：题库是 gzip 分块存的，每次读都要拉 4 个 KV 块再解压，
   复核详情页一次要读好几遍（列表、判分、详情），没有缓存要等 3~5 秒。
   60 秒过期，写题库时立刻失效。 */
let Q_QBANK_CACHE = null;
const Q_QBANK_CACHE_MS = 60000;

async function qLoadQbank(env) {
  const now = Date.now();
  if (Q_QBANK_CACHE && (now - Q_QBANK_CACHE.at) < Q_QBANK_CACHE_MS) {
    return Q_QBANK_CACHE.rec;
  }
  let head = null;
  try { head = await env.KV.get(Q_QBANK, 'json'); } catch (e) { head = null; }
  if (!head || !head.chunks) return null;
  let raw = '';
  for (let i = 0; i < head.chunks; i++) {
    let c = null;
    try { c = await env.KV.get(Q_QBANK_CHUNK + i); } catch (e) { c = null; }
    if (c == null) return null;
    raw += c;
  }
  let text;
  try {
    text = (head.codec === 'gz64') ? await qGunzipB64(raw) : raw;
  } catch (e) { return null; }
  try {
    const rec = JSON.parse(text);
    if (rec && rec.boards) {
      Q_QBANK_CACHE = { at: now, rec: rec };
      return rec;
    }
    return null;
  } catch (e) { return null; }
}
function qFindBoard(qb, boardId) {
  if (!qb) return null;
  for (const b of qb.boards) if (b.id === boardId) return b;
  return null;
}
function qFindQ(board, qid) {
  if (!board) return null;
  for (const q of (board.questions || [])) if (q.id === qid) return q;
  return null;
}

/* POST /api/q/submit —— 交卷：程序判选择/填空，简答题留给 AI */
async function handleQSubmit(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const sess = await getQuizSession(req, env);
  if (!sess) return fail('登录已失效，请重新登录', 401);

  let b;
  try { b = await qReadBody(req); } catch (e) { return fail('请求体不是合法 JSON'); }
  const boardId = String(b.board || '').trim();
  const answers = (b.answers && typeof b.answers === 'object') ? b.answers : {};
  const usedMs = Math.max(0, Number(b.usedMs) || 0);

  const qb = await qLoadQbank(env);
  if (!qb) return fail('题库尚未同步到服务器，请联系管理员', 503);
  const board = qFindBoard(qb, boardId);
  if (!board) return fail('没有这个板块', 404);

  const auto = {};     /* 程序判的：选择题 / 填空题 */
  const needGrade = []; /* 要 AI 判的：简答题 */
  let autoScore = 0;
  for (const q of (board.questions || [])) {
    const raw = answers[q.id];
    if (q.type === 'short') {
      needGrade.push(q.id);
      auto[q.id] = { score: 0, max: q.score || 3, kind: 'short', done: false };
      continue;
    }
    if (q.type === 'fill') {
      const blanks = q.blanks || [];
      let sc = 0;
      const detail = [];
      for (let i = 0; i < blanks.length; i++) {
        const user = raw && typeof raw === 'object' ? (raw['b' + (i + 1)] || '') : '';
        const hit = qFillMatch(blanks[i].answer, user);
        if (hit) sc += blanks[i].points;
        detail.push({ id: blanks[i].id, answer: blanks[i].answer, user: String(user || ''), hit: hit });
      }
      sc = Math.max(0, Math.min(sc, q.score || 2));
      auto[q.id] = { score: sc, max: q.score || 2, kind: 'fill', done: true, blanks: detail };
      autoScore += sc;
      continue;
    }
    /* choice：答案是 0~3 的索引 */
    let pick = -1;
    if (typeof raw === 'number') pick = raw;
    else if (typeof raw === 'string') {
      const s = raw.trim().toUpperCase();
      if (s >= 'A' && s <= 'D') pick = s.charCodeAt(0) - 65;
      else if (/^[0-3]$/.test(s)) pick = parseInt(s, 10);
    }
    const ok = pick === q.answer;
    const sc = ok ? (q.score || 1) : 0;
    auto[q.id] = { score: sc, max: q.score || 1, kind: 'choice', done: true, pick: pick, right: ok };
    autoScore += sc;
  }

  const subId = token().slice(0, 20);
  const totalScore = (board.totalScore || (board.questions || []).reduce(function (a, q) { return a + (q.score || 0); }, 0));
  const rec = {
    id: subId, name: sess.name, board: boardId, boardName: board.name,
    at: Date.now(), usedMs: usedMs, totalScore: totalScore,
    answers: answers, auto: auto, ai: {},
    status: needGrade.length ? 'grading' : 'pending_review',
    finalScore: null, confidence: null
  };
  await env.KV.put('q:sub:' + subId, JSON.stringify(rec), { expirationTtl: 60 * 60 * 24 * 180 });

  if (!needGrade.length) {
    /* 没有简答题 → 直接进入待复核 */
    rec.status = 'pending_review';
    rec.finalScore = autoScore;
    rec.confidence = 100;
    await env.KV.put('q:sub:' + subId, JSON.stringify(rec), { expirationTtl: 60 * 60 * 24 * 180 });
    await qAfterGrading(env, rec, board);
  }
  return json({
    ok: true, subId: subId, totalScore: totalScore, autoScore: autoScore,
    needGrade: needGrade, status: rec.status
  });
}

/* POST /api/q/grade-one —— 判一道简答题（前端并行调 N 次，每次请求都短） */
async function handleQGradeOne(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const sess = await getQuizSession(req, env);
  if (!sess) return fail('登录已失效，请重新登录', 401);

  let b;
  try { b = await qReadBody(req); } catch (e) { return fail('请求体不是合法 JSON'); }
  const subId = String(b.subId || '').trim();
  const qid = String(b.qid || '').trim();
  const rec = await env.KV.get('q:sub:' + subId, 'json');
  if (!rec) return fail('考试记录不存在', 404);
  if (rec.name !== sess.name) return fail('只能判自己的卷', 403);

  const qb = await qLoadQbank(env);
  const board = qFindBoard(qb, rec.board);
  const q = qFindQ(board, qid);
  if (!q) return fail('题目不存在', 404);

  const raw = rec.answers ? rec.answers[qid] : '';
  const g = await qAiGradeShort(env, q, raw);
  rec.ai = rec.ai || {};
  rec.ai[qid] = g;
  await env.KV.put('q:sub:' + subId, JSON.stringify(rec), { expirationTtl: 60 * 60 * 24 * 180 });
  return json({ ok: true, qid: qid, result: g });
}

/* POST /api/q/finish —— 全部判完：汇总总分 + 可信度 + 发通知 */
async function handleQFinish(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const sess = await getQuizSession(req, env);
  if (!sess) return fail('登录已失效，请重新登录', 401);

  let b;
  try { b = await qReadBody(req); } catch (e) { return fail('请求体不是合法 JSON'); }
  const subId = String(b.subId || '').trim();
  const rec = await env.KV.get('q:sub:' + subId, 'json');
  if (!rec) return fail('考试记录不存在', 404);
  if (rec.name !== sess.name) return fail('只能提交自己的卷', 403);

  const qb = await qLoadQbank(env);
  const board = qFindBoard(qb, rec.board);

  let score = 0, confSum = 0, confN = 0, shortCount = 0, shortMax = 0, pending = 0;
  const perQ = {};
  for (const q of ((board && board.questions) || [])) {
    const a = rec.auto && rec.auto[q.id];
    const g = rec.ai && rec.ai[q.id];
    if (q.type === 'short') {
      shortCount++; shortMax += (q.score || 3);
      if (g) {
        score += g.score; confSum += g.confidence; confN++;
        perQ[q.id] = { score: g.score, max: g.max, ai: true };
      } else {
        pending++;
        perQ[q.id] = { score: 0, max: q.score || 3, ai: true, pending: true };
      }
    } else if (a) {
      score += a.score;
    }
  }
  const confidence = confN ? Math.round((confSum / confN) * 100) : 100;
  rec.status = pending ? 'grading' : 'pending_review';
  rec.finalScore = score;
  rec.confidence = confidence;
  rec.perQ = perQ;
  rec.shortCount = shortCount;
  rec.shortMax = shortMax;
  rec.pendingCount = pending;
  await env.KV.put('q:sub:' + subId, JSON.stringify(rec), { expirationTtl: 60 * 60 * 24 * 180 });

  if (!pending) await qAfterGrading(env, rec, board);
  return json({
    ok: true, subId: subId, score: score, totalScore: rec.totalScore,
    confidence: confidence, pending: pending, status: rec.status
  });
}

/* 判分完成后：写进用户成绩记录 + 通知管理员 + 通知答题人 */
async function qAfterGrading(env, rec, board) {
  /* 写进用户自己的答题状态（这样「我的考试记录」里能看到） */
  try {
    const key = qState(rec.name);
    const cur = (await env.KV.get(key, 'json')) || {};
    const st = (cur.state && typeof cur.state === 'object') ? cur.state : {};
    st.exams = Array.isArray(st.exams) ? st.exams : [];
    st.exams.push({
      at: rec.at, board: rec.board, boardName: rec.boardName,
      score: rec.finalScore, total: rec.totalScore, usedMs: rec.usedMs,
      subId: rec.id, pending: rec.status === 'pending_review'
    });
    if (st.exams.length > 100) st.exams = st.exams.slice(-100);
    st.best = st.best || {};
    const curBest = st.best[rec.board];
    if (!curBest || rec.finalScore > curBest.score) {
      st.best[rec.board] = { score: rec.finalScore, total: rec.totalScore, at: rec.at };
    }
    await env.KV.put(key, JSON.stringify({ state: st, name: rec.name, at: Date.now() }),
      { expirationTtl: 60 * 60 * 24 * 365 });
  } catch (e) { /* 写成绩失败不影响主流程 */ }

  /* 通知管理员/拥有者 */
  const users = await env.KV.list({ prefix: 'q:user:' });
  const admins = [];
  for (const k of users.keys) {
    const u = await env.KV.get(k.name, 'json');
    if (u && u.enabled && (u.role === 'admin' || u.role === 'owner')) admins.push(u.name);
  }
  const low = rec.confidence != null && rec.confidence < 70;
  for (const nm of admins) {
    await qNotify(env, nm, low ? 'review_low' : 'review_new',
      low ? '⚠ 有低可信度的判分待复核' : '有新的考试待复核',
      rec.name + ' 刚提交了「' + rec.boardName + '」考试。AI 建议得分 ' + rec.finalScore
      + ' / ' + rec.totalScore + '，整体可信度 ' + rec.confidence + '%。'
      + (rec.shortCount ? rec.shortCount + ' 道简答题由 AI 判定，建议优先复核其中可信度偏低的几题。' : ''),
      '#/admin');
  }
  /* 通知答题人 */
  await qNotify(env, rec.name, 'grading_done', '等待管理员复核',
    '「' + rec.boardName + '」考试已完成初步判分：AI 建议得分 ' + rec.finalScore
    + ' / ' + rec.totalScore + '，整体可信度 ' + rec.confidence + '%。'
    + '这只是初步结果，管理员会逐题复核，最终成绩以复核结果为准。',
    '#/admin');
}

/* ---------- 复核相关 ---------- */
async function handleQSubmissions(req, env, path, subId) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isQuizAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);

  const list = await env.KV.list({ prefix: 'q:sub:' });
  const rows = [];
  let qb = null;
  if (subId) qb = await qLoadQbank(env);
  for (const k of list.keys) {
    const r = await env.KV.get(k.name, 'json');
    if (!r) continue;
    if (subId) {
      if (r.id !== subId) continue;
      const board = qFindBoard(qb, r.board);
      const detail = {};
      for (const q of ((board && board.questions) || [])) {
        detail[q.id] = {
          no: q.no, seq: (q.seq != null) ? q.seq : q.no,
          type: q.type, stem: q.stem, score: q.score,
          options: q.options || null, reference: q.reference || null,
          points: q.points || null, blanks: q.blanks || null,
          /* ★ answer：选择题的正确选项下标。漏了它管理员只能看到
             「对/错」，看不到「正确答案是什么」，没法判断该不该改分。 */
          answer: (typeof q.answer === 'number') ? q.answer : null,
          explanation: q.explanation || '', source: q.source || '',
          user: r.answers ? r.answers[q.id] : '',
          auto: (r.auto && r.auto[q.id]) || null,
          ai: (r.ai && r.ai[q.id]) || null
        };
      }
      return json({ ok: true, sub: r, detail: detail });
    }
    rows.push({
      id: r.id, name: r.name, board: r.board, boardName: r.boardName,
      at: r.at, usedMs: r.usedMs, score: r.finalScore, total: r.totalScore,
      confidence: r.confidence, status: r.status,
      shortCount: r.shortCount || 0, shortMax: r.shortMax || 0
    });
  }
  if (subId) return fail('考试记录不存在', 404);
  rows.sort(function (a, b2) { return (b2.at || 0) - (a.at || 0); });
  return json({ ok: true, rows: rows });
}

/* POST /api/q/submissions/:id/review —— 管理员逐题确认/改分后提交 */
async function handleQReview(req, env, subId) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isQuizAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);

  let b;
  try { b = await qReadBody(req); } catch (e) { return fail('请求体不是合法 JSON'); }
  const rec = await env.KV.get('q:sub:' + subId, 'json');
  if (!rec) return fail('考试记录不存在', 404);

  const perQ = (b.perQ && typeof b.perQ === 'object') ? b.perQ : {};
  const qb = await qLoadQbank(env);
  const board = qFindBoard(qb, rec.board);
  const finalPer = {};
  let score = 0;
  for (const q of ((board && board.questions) || [])) {
    const a = rec.auto && rec.auto[q.id];
    const g = rec.ai && rec.ai[q.id];
    let sc = null;
    if (Object.prototype.hasOwnProperty.call(perQ, q.id)) {
      const v = Number(perQ[q.id]);
      if (Number.isFinite(v)) sc = Math.max(0, Math.min(v, q.score || 0));
    }
    if (sc == null) {
      if (g) sc = g.score;
      else if (a) sc = a.score;
      else sc = 0;
    }
    finalPer[q.id] = { score: sc, max: q.score || 0 };
    score += sc;
  }
  rec.perQ = finalPer;
  rec.finalScore = score;
  rec.status = 'reviewed';
  rec.review = { by: admin.name, at: Date.now() };
  await env.KV.put('q:sub:' + subId, JSON.stringify(rec), { expirationTtl: 60 * 60 * 24 * 180 });

  /* 同步更新用户成绩记录里的分数 */
  try {
    const key = qState(rec.name);
    const cur = (await env.KV.get(key, 'json')) || {};
    const st = (cur.state && typeof cur.state === 'object') ? cur.state : {};
    if (Array.isArray(st.exams)) {
      st.exams.forEach(function (e) {
        if (e.subId === subId) { e.score = score; e.pending = false; e.reviewed = true; }
      });
    }
    if (st.best && st.best[rec.board]) {
      const curBest = st.best[rec.board];
      if (score > curBest.score) st.best[rec.board] = { score: score, total: rec.totalScore, at: rec.at };
    }
    await env.KV.put(key, JSON.stringify({ state: st, name: rec.name, at: Date.now() }),
      { expirationTtl: 60 * 60 * 24 * 365 });
  } catch (e) { /* 忽略 */ }

  await qNotify(env, rec.name, 'review_done', '考试评价已完成',
    admin.name + ' 已完成你的「' + rec.boardName + '」考试评价，最终得分 ' + score + ' / '
    + rec.totalScore + '（' + (rec.totalScore ? Math.round(score * 100 / rec.totalScore) : 0)
    + '%）。复核明细可以在「我的考试记录」里逐题查看。', '#/admin');
  return json({ ok: true, finalScore: score, totalScore: rec.totalScore });
}

/* ---------- 我的考试记录（普通用户看自己的） ---------- */
async function handleQMySubs(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const sess = await getQuizSession(req, env);
  if (!sess) return fail('登录已失效，请重新登录', 401);
  const list = await env.KV.list({ prefix: 'q:sub:' });
  const rows = [];
  for (const k of list.keys) {
    const r = await env.KV.get(k.name, 'json');
    if (!r || r.name !== sess.name) continue;
    rows.push({
      id: r.id, board: r.board, boardName: r.boardName, at: r.at, usedMs: r.usedMs,
      score: r.finalScore, total: r.totalScore, confidence: r.confidence,
      status: r.status, shortCount: r.shortCount || 0, shortMax: r.shortMax || 0
    });
  }
  rows.sort(function (a, b2) { return (b2.at || 0) - (a.at || 0); });
  return json({ ok: true, rows: rows });
}

/* GET /api/q/my/subs/:id —— 用户查**自己**那次的逐题明细
   ★ 只给他自己的答案 + AI 判定 + 最终得分，**不下发标准答案/得分点**：
     否则用户做完就能翻出答案背下一次考试，题库就废了。 */
async function handleQMySubDetail(req, env, subId) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const sess = await getQuizSession(req, env);
  if (!sess) return fail('登录已失效，请重新登录', 401);
  const rec = await env.KV.get('q:sub:' + subId, 'json');
  if (!rec) return fail('考试记录不存在', 404);
  if (rec.name !== sess.name) return fail('只能查看自己的考试记录', 403);

  const qb = await qLoadQbank(env);
  const board = qFindBoard(qb, rec.board);
  const detail = {};
  for (const q of ((board && board.questions) || [])) {
    const a = (rec.auto && rec.auto[q.id]) || null;
    const g = (rec.ai && rec.ai[q.id]) || null;
    const fin = (rec.perQ && rec.perQ[q.id]) ? rec.perQ[q.id] : null;
    const item = {
      no: q.no, seq: (q.seq != null) ? q.seq : q.no,
      type: q.type, stem: q.stem, score: q.score,
      user: rec.answers ? rec.answers[q.id] : '',
      final: fin ? fin.score : null,
      max: q.score || 0,
      options: q.options || null,
      answer: (typeof q.answer === 'number') ? q.answer : null,
      reference: q.reference || null,
      points: q.points || null,
      explanation: q.explanation || ''
    };
    if (q.type === 'choice' && a) {
      item.pick = (typeof a.pick === 'number' && a.pick >= 0) ? a.pick : null;
      item.right = !!a.right;
    }
    if (q.type === 'fill' && a && Array.isArray(a.blanks)) {
      item.blanks = a.blanks.map(function (b) {
        return { id: b.id, user: b.user, answer: b.answer, hit: !!b.hit };
      });
    }
    if (q.type === 'short' && g) {
      item.ai = { score: g.score, max: g.max, hits: g.hits || [],
        confidence: g.confidence, reason: g.reason, needManual: !!g.needManual };
      /* 得分点的文字也要打码 —— 只给编号，文字是答案的一部分 */
      item.hitCount = (g.hits || []).length;
      item.pointCount = Array.isArray(q.points) ? q.points.length : 0;
    }
    detail[q.id] = item;
  }
  return json({
    ok: true,
    sub: {
      id: rec.id, board: rec.board, boardName: rec.boardName, at: rec.at,
      usedMs: rec.usedMs, score: rec.finalScore, total: rec.totalScore,
      confidence: rec.confidence, status: rec.status,
      shortCount: rec.shortCount || 0, shortMax: rec.shortMax || 0
    },
    detail: detail
  });
}

/* POST /api/q/admin/qbank —— 把题库同步进服务器（owner 才能写）
   POST /api/q/admin/aicfg —— 写 AI 配置（key/base/model），owner 才能写 */
async function handleQAdminConfig(req, env, what) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const owner = await isQuizOwner(req, env);
  if (!owner) return fail('只有拥有者可以执行', 403);
  let b;
  try { b = await qReadBody(req); } catch (e) { return fail('请求体不是合法 JSON'); }

  if (what === 'qbank') {
    if (!b || !Array.isArray(b.boards)) return fail('缺少 boards');
    const rec = { version: String(b.version || ''), boards: b.boards, at: Date.now() };
    const text = JSON.stringify(rec);
    /* 压缩优先；运行环境没有 CompressionStream 就退回明文分块 */
    const canGzip = (typeof CompressionStream !== 'undefined');
    let payload = text;
    if (canGzip) {
      try { payload = await qGzipB64(text); } catch (e) { payload = text; }
    }
    const codec = (payload !== text) ? 'gz64' : 'raw';
    const n = Math.max(1, Math.ceil(payload.length / Q_QBANK_CHUNK_SIZE));
    for (let i = 0; i < n; i++) {
      await env.KV.put(Q_QBANK_CHUNK + i, payload.slice(i * Q_QBANK_CHUNK_SIZE, (i + 1) * Q_QBANK_CHUNK_SIZE));
    }
    /* 清掉上一版多余的块（从 n 开始往后找，碰到空就停） */
    for (let i = n; i < n + 20; i++) {
      const old = await env.KV.get(Q_QBANK_CHUNK + i);
      if (old == null) break;
      await env.KV.delete(Q_QBANK_CHUNK + i);
    }
    await env.KV.put(Q_QBANK, JSON.stringify({
      v: 1, codec: codec, chunks: n, size: payload.length, at: Date.now()
    }));
    /* 题库刚更新 → 缓存立刻失效，下一次读就是新题库 */
    Q_QBANK_CACHE = null;
    const cnt = b.boards.reduce(function (a, x) { return a + ((x.questions || []).length); }, 0);
    return json({ ok: true, boards: b.boards.length, questions: cnt,
      bytes: payload.length, chunks: n, codec: codec });
  }
  /* aicfg：
     ★ key 留空 = **保持原密钥不变**（原来留空等于清空，一不小心就把判分通道弄挂了）。
       要清除必须显式传 clearKey:true。 */
  let prev = null;
  try { prev = await env.KV.get(Q_AICFG, 'json'); } catch (e) { prev = null; }
  prev = prev || {};
  let key = prev.key || '';
  if (b.clearKey === true) key = '';
  else if (typeof b.key === 'string' && b.key.trim()) key = b.key.trim();
  const rec = {
    key: key,
    base: typeof b.base === 'string' && b.base ? b.base.trim() : (prev.base || 'https://api.minimaxi.com/v1/chat/completions'),
    model: typeof b.model === 'string' && b.model ? b.model.trim() : (prev.model || 'MiniMax-M3.1-Flash')
  };
  await env.KV.put(Q_AICFG, JSON.stringify(rec));
  return json({ ok: true, base: rec.base, model: rec.model, hasKey: !!rec.key });
}

/* 站内通知接口：GET 读我的 / POST 标记已读 */
async function handleQNotices(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const sess = await getQuizSession(req, env);
  if (!sess) return fail('登录已失效，请重新登录', 401);

  const key = qNotice(sess.name);
  const arr = (await env.KV.get(key, 'json')) || [];

  if (req.method === 'POST') {
    let b = {};
    try { b = await qReadBody(req); } catch (e) { b = {}; }
    const ids = Array.isArray(b.ids) ? b.ids.map(x => String(x)) : null;
    for (const n of arr) {
      if (!n.read && (!ids || ids.indexOf(String(n.id)) >= 0)) n.read = true;
    }
    await env.KV.put(key, JSON.stringify(arr), { expirationTtl: NOTICE_TTL });
    return json({ ok: true, unread: 0 });
  }

  const unread = arr.filter(n => !n.read).length;
  return json({ ok: true, notices: arr.slice(0, 20), unread: unread });
}

async function qPurgeSessions(env, name) {
  const list = await env.KV.list({ prefix: 'q:sess:' });
  for (const k of list.keys) {
    const s = await env.KV.get(k.name, 'json');
    if (s && s.name === name) await env.KV.delete(k.name);
  }
}

/* ★ 读请求体：兼容 application/json 和 application/x-www-form-urlencoded。
   为什么要兼容后者：POST 带 application/json 属于「非简单请求」，
   浏览器必须先发一次 CORS 预检（OPTIONS），等于一次操作两个往返。
   移动网络下实测登录就是这么超时失败的（网关本身要 2~3 秒，冷启动更久）。
   改用 form-urlencoded 就是**简单请求**，不用预检 —— 直接一次往返。 */
async function qReadBody(req) {
  const ct = (req.headers.get('Content-Type') || '').toLowerCase();
  if (ct.indexOf('application/x-www-form-urlencoded') >= 0) {
    const form = await req.formData();
    const o = {};
    for (const [k, v] of form.entries()) o[k] = (typeof v === 'string') ? v : '';
    return o;
  }
  return await req.json();
}

/* ---------- 答题站：公开注册 ---------- */
async function handleQRegister(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  if (req.method !== 'POST') return fail('仅支持 POST', 405);
  let b;
  try { b = await qReadBody(req); } catch (e) { return fail('请求体不是合法 JSON'); }

  const name = String(b.name || '').trim();
  const pwd = String(b.pwd || '');
  const ip = clientIp(req);
  if (!name || !pwd) return fail('请填写账号与密码');
  if (name.length < 2 || name.length > 24) return fail('账号长度要 2~24 个字符');
  if (!/^[\u4e00-\u9fa5A-Za-z0-9_.\-]+$/.test(name)) {
    return fail('账号只能用中文、字母、数字、下划线、点和短横线');
  }
  if (pwd.length < 6) return fail('密码至少 6 位');
  if (pwd.length > 64) return fail('密码太长（最多 64 位）');
  if (await env.KV.get(qName(name))) return fail('这个账号已存在，换一个', 409);

  const regKey = 'q:reg:' + encodeURIComponent(ip || 'unknown');
  const cnt = Number(await env.KV.get(regKey)) || 0;
  if (cnt >= Q_REGISTER_PER_HOUR) return fail('这个 IP 注册太频繁了，一小时后再试', 429);

  const id = token().slice(0, 12);
  const { hash, salt } = await hashPassword(pwd, null, env);
  /* role 写死 user：注册的人一律是普通用户，要管理员找 ZM1/ZM2 建 */
  const u = { id, name, pwd: hash, salt, role: 'user', enabled: true, createdAt: Date.now(), regIp: ip };
  await env.KV.put(qUser(id), JSON.stringify(u));
  await env.KV.put(qName(name), JSON.stringify(id));
  await env.KV.put(regKey, String(cnt + 1), { expirationTtl: 3600 });

  const sess = await qIssueSession(env, Object.assign({}, u, { keep: parseKeep(b.keep) }),
    req, String(b.did || '').slice(0, 64));
  return json({
    ok: true, user: { name: u.name, role: u.role },
    token: sess.token, expireAt: sess.expireAt
  }, 200, { 'Set-Cookie': qSetCookie(sess.token, TTL_SESSION) });
}

/* 答题站自己的失败计数：账号级 + IP 级两把计数 */
async function bumpQFail(env, lockKey, lockIpKey) {
  try {
    const k = `q:fail:${lockKey}`;
    const n = ((Number(await env.KV.get(k)) || 0) + 1);
    await env.KV.put(k, String(n), { expirationTtl: 900 });
    if (n >= Q_LOCK_ACCOUNT_MAX) {
      await env.KV.put(lockKey, String(Date.now() + 10 * 60000), { expirationTtl: 900 });
      await env.KV.delete(k);
    }
    const ki = `q:failip:${lockIpKey}`;
    const m = ((Number(await env.KV.get(ki)) || 0) + 1);
    await env.KV.put(ki, String(m), { expirationTtl: 3600 });
    if (m >= Q_LOCK_IP_MAX) {
      await env.KV.put(lockIpKey, String(Date.now() + 30 * 60000), { expirationTtl: 3600 });
      await env.KV.delete(ki);
    }
  } catch (e) { /* 计数坏了也不能挡住登录 */ }
}

/* ---------- 答题站：免密复用（按设备优先，其次按 IP） ---------- */
/* 前端传的是字符串 '1' / '0'，JS 里 '0' 是**真值** ——
   `b.keep !== false` 恒为 true，勾不勾「保持登录」都按保持处理。 */
function parseKeep(v) {
  if (v === undefined || v === null || v === '') return true;
  const s = String(v).trim().toLowerCase();
  return !(s === '0' || s === 'false' || s === 'no' || s === 'off');
}

/* 复用会话：**只认这台设备**（q:dev:<did>）。
   ★ 为什么不能按 IP：Deno Deploy 给不出真实 IP，clientIp() 恒为 'unknown'
     → 全站共用一个 q:ip:unknown 键 → 「同 IP 免密」等于
     **任何人只要知道账号名、密码留空，就能登进别人的账号**。
     IP 记录还留着，但只给管理后台显示「谁在线」，不再参与登录授权。
   复用前要真正验签 + 确认会话记录还在，不能只看指针。 */
async function qReuseSession(env, name, did) {
  if (!did) return null;
  const rec = await env.KV.get(qDev(did), 'json');
  if (!rec || !rec.token || rec.name !== name) return null;
  const pv = await verifyToken(rec.token, env.SESSION_SECRET);
  if (!pv || pv.g || pv.n !== name || !pv.e || Date.now() > pv.e) return null;
  const sess = await env.KV.get(qSess(rec.jti), 'json');
  if (!sess || sess.jti !== rec.jti) return null;   /* 会话已被登出/改密清掉 */
  return { token: rec.token, user: pubUser(pv.n, pv.r), expireAt: pv.e };
}

/* ---------- 答题站：登录 / 会话 / 登出 ---------- */
async function handleQLogin(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  if (req.method !== 'POST') return fail('仅支持 POST', 405);
  let b;
  try { b = await qReadBody(req); } catch (e) { return fail('请求体不是合法 JSON'); }
  const name = String(b.name || '').trim();
  const pwd = String(b.pwd || '');
  const did = String(b.did || '').slice(0, 64);
  const keepOn = parseKeep(b.keep);
  /* keep=true 时密码可以留空：同一台设备（或同一 IP）的会话还活着就直接进（7 天内免密） */
  if (!name) return fail('请填写账号');
  if (!pwd && !keepOn) return fail('请填写账号与密码');

  /* 暴力破解限速：同 IP 同一账号连错 5 次 → 只锁这个账号 10 分钟；
     同 IP 跨账号连错 30 次 → 锁这个 IP 30 分钟（防批量撞库）。
     ★ 不再因为「某人输错自己密码」而连坐整个办公室。 */
  const ip = clientIp(req);
  const lockKey = qLock(ip, name);
  const lock = await env.KV.get(lockKey);
  if (lock && Date.now() < Number(lock)) {
    return fail('失败次数过多，请 ' + Math.ceil((lock - Date.now()) / 60000) + ' 分钟后再试', 429);
  }
  const lockIpKey = qLockIp(ip);
  const lockIp = await env.KV.get(lockIpKey);
  if (lockIp && Date.now() < Number(lockIp)) {
    return fail('本机 IP 尝试次数过多，请 ' + Math.ceil((lockIp - Date.now()) / 60000) + ' 分钟后再试', 429);
  }

  /* ★ 「保持登录」：密码留空时直接复用本设备/本 IP 上还活着的会话。
     ★ 只在**密码留空**时复用 —— 填了密码就老老实实验密码，
       不然「密码写错了也照样登进去」是很糟糕的行为。
     主路径是**按设备**（q:dev）：手机换网络、换 IP 都不影响；
     同 IP 只是补充（旧数据兼容）。 */
  if (keepOn && !pwd) {
    const reuse = await qReuseSession(env, name, did);
    if (reuse) {
      return json({
        ok: true, reused: true, user: reuse.user,
        token: reuse.token, expireAt: reuse.expireAt, guest: false
      }, 200, { 'Set-Cookie': qSetCookie(reuse.token, TTL_SESSION) });
    }
    return fail('本机没有可复用的登录记录，请输入密码', 401);
  }

  const id = await env.KV.get(qName(name), 'json');
  const user = id ? await env.KV.get(qUser(id), 'json') : null;
  if (!user || !user.enabled) {
    /* ⚠ 这里原来调的是工作台的 bumpFail（单键版），
       答题站要用自己那套（账号级 + IP 级两把计数），否则计数会写错键。 */
    await bumpQFail(env, lockKey, lockIpKey);
    return fail('账号或密码不正确', 401);
  }
  const { hash } = await hashPassword(pwd, user.salt, env);
  if (!safeEqual(hash, user.pwd)) {
    await bumpQFail(env, lockKey, lockIpKey);
    return fail('账号或密码不正确', 401);
  }
  await env.KV.delete(lockKey);
  await env.KV.delete(lockIpKey);

  user.lastLoginAt = Date.now();
  await env.KV.put(qUser(id), JSON.stringify(user));

  const sess = await qIssueSession(env, Object.assign({}, user, { keep: keepOn }), req, did);
  return json({
    ok: true, user: { name: user.name, role: user.role },
    token: sess.token, expireAt: sess.expireAt
  }, 200, { 'Set-Cookie': qSetCookie(sess.token, TTL_SESSION) });
}

async function handleQSession(req, env) {
  /* ★ 支持 POST + form-urlencoded：令牌放 body 里传过来。
     这样前端发的是**简单请求**，浏览器不发 CORS 预检 —— 手机慢网下
     「GET + X-QZ-Token 头」会被预检拖超时，表现就是每次都要重新登录。 */
  let tk = '';
  if (req.method === 'POST') {
    let b = {};
    try { b = await qReadBody(req); } catch (e) { b = {}; }
    tk = String(b.tk || '').slice(0, 4000);
  }
  const s = await getQuizSession(req, env, tk);
  if (!s) return json({ ok: false, error: 'no_session' }, 401);
  return json({ ok: true, user: { name: s.name, role: s.role }, expireAt: s.expAt });
}

async function handleQLogout(req, env) {
  let did = '';
  try { const b = await qReadBody(req); did = String(b.did || '').slice(0, 64); } catch (e) {}
  const s = await getQuizSession(req, env);
  if (did) await env.KV.delete(qDev(did));
  if (s) {
    await env.KV.delete(qSess(s.jti));
    const cur = await env.KV.get(qUid(s.name), 'json');
    if (cur && cur.jti === s.jti) {
      cur.jti = '__revoked__';
      cur.iat = bumpIat(cur.iat);
      await env.KV.put(qUid(s.name), JSON.stringify(cur), { expirationTtl: TTL_SESSION });
    }
  }
  return json({ ok: true }, 200, { 'Set-Cookie': qSetCookie('', 0) });
}

/* ---------- 诊断：服务端看到的「我是谁 / 我带了什么」 ---------- */
/* 只回显**请求方自己**的请求信息（IP、UA、有没有带 Cookie/令牌），
   不含任何他人数据。用来一次性搞清楚「Deno Deploy 到底给不给真实 IP」，
   以及手机上「保持登录」到底卡在哪一环。 */
async function handleQWhereami(req, env) {
  const seen = {};
  for (const n of IP_HEADERS) {
    const v = req.headers.get(n);
    if (v) seen[n] = String(v).slice(0, 120);
  }
  return json({
    ok: true,
    ip: clientIp(req),
    ipHeaders: seen,
    ua: String(req.headers.get('User-Agent') || '').slice(0, 140),
    hasCookie: !!readCookie(req, 'qztk'),
    hasTokenHeader: !!req.headers.get('X-QZ-Token'),
    hasDevId: !!(req.headers.get('X-QZ-Dev') || ''),
    serverTime: Date.now()
  });
}

/* ---------- 答题站：答题状态（错题本 / 进度 / 成绩） ---------- */
const MAX_QUIZ_WRONG = 2000;
const MAX_QUIZ_PROGRESS_Q = 5000;
const MAX_QUIZ_EXAMS = 100;

function sanitizeQuizState(st) {
  const out = { wrong: {}, progress: {}, exams: [], best: {} };
  const str = (v, n) => String(v == null ? '' : v).replace(/[\x00-\x1F]/g, '').slice(0, n);

  if (st.wrong && typeof st.wrong === 'object') {
    let n = 0;
    for (const qid of Object.keys(st.wrong)) {
      if (n++ >= MAX_QUIZ_WRONG) break;
      const id = str(qid, 64); if (!id) continue;
      const w = st.wrong[qid] || {};
      out.wrong[id] = {
        first: Number(w.first) || 0, last: Number(w.last) || 0,
        times: Math.max(1, Math.min(9999, Number(w.times) || 1)),
        board: str(w.board, 40)
      };
    }
  }
  if (st.progress && typeof st.progress === 'object') {
    let total = 0;
    for (const bid of Object.keys(st.progress)) {
      const b = str(bid, 40); if (!b) continue;
      const p = st.progress[bid] || {};
      out.progress[b] = {};
      for (const qid of Object.keys(p)) {
        if (total++ >= MAX_QUIZ_PROGRESS_Q) break;
        const id = str(qid, 64); if (!id) continue;
        const it = p[qid] || {};
        out.progress[b][id] = {
          chosen: Math.max(0, Math.min(3, Number(it.chosen) || 0)),
          ok: !!it.ok, at: Number(it.at) || 0
        };
      }
    }
  }
  if (Array.isArray(st.exams)) {
    for (const e of st.exams.slice(-MAX_QUIZ_EXAMS)) {
      if (!e || typeof e !== 'object') continue;
      /* boardName：板块**名字**（后台直接显示「V6X 飞控控制器」，不用拿 id 去猜）
         wrongPicks：错题对应的「他选了第几项」—— 后台要能看出
                     「他选 B，正确答案是 C」，不能只知道这题错了 */
      const wp = {};
      if (e.wrongPicks && typeof e.wrongPicks === 'object') {
        for (const wk of Object.keys(e.wrongPicks).slice(0, 500)) {
          wp[str(wk, 64)] = Math.max(0, Math.min(3, Number(e.wrongPicks[wk]) || 0));
        }
      }
      out.exams.push({
        at: Number(e.at) || 0, board: str(e.board, 40), boardName: str(e.boardName, 60),
        score: Math.max(0, Number(e.score) || 0), total: Math.max(0, Number(e.total) || 0),
        usedMs: Math.max(0, Number(e.usedMs) || 0),
        wrongIds: Array.isArray(e.wrongIds) ? e.wrongIds.slice(0, 500).map(x => str(x, 64)) : [],
        wrongPicks: wp,
        /* ★ subId / pending / reviewed **必须保留**：
           handleQReview 靠 subId 找到「哪一条考试记录」并改分，
           洗掉之后管理员复核改分永远不生效（复核页改了分，成绩也不变）。
           老记录没有 subId 就是空串，不影响。 */
        subId: str(e.subId, 64),
        pending: !!e.pending,
        reviewed: !!e.reviewed
      });
    }
  }
  if (st.best && typeof st.best === 'object') {
    for (const bid of Object.keys(st.best)) {
      const b = str(bid, 40); if (!b) continue;
      const e = st.best[bid] || {};
      out.best[b] = { score: Number(e.score) || 0, total: Number(e.total) || 0, at: Number(e.at) || 0 };
    }
  }
  return out;
}

async function handleQQuizState(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  /* ★ POST 时令牌放在 body 里（form-urlencoded）→ 简单请求，浏览器不预检。
     原来只有 GET 可用，GET + 自定义头会触发 CORS 预检，手机慢网下超时，
     结果是错题本同步不上去。 */
  let tk = '', b = null;
  if (req.method === 'POST') {
    try { b = await qReadBody(req); } catch (e) { b = null; }
    if (b) tk = String(b.tk || '').slice(0, 4000);
  }
  const s = await getQuizSession(req, env, tk);
  if (!s) return fail('登录已失效，请重新登录', 401);

  const key = qState(s.name);
  if (req.method === 'GET') {
    const rec = await env.KV.get(key, 'json');
    return json({ ok: true, state: (rec && rec.state) ? rec.state : null });
  }
  if (req.method === 'POST') {
    if (!b) return fail('请求体不是合法 JSON');
    /* op=load：只读（前端用 POST + form 传令牌，免 CORS 预检） */
    if (b.op === 'load') {
      const rec = await env.KV.get(key, 'json');
      return json({ ok: true, state: (rec && rec.state) ? rec.state : null });
    }
    /* form 传过来的 state 是 JSON 字符串，要解一次 */
    let st = b.state;
    if (typeof st === 'string') { try { st = JSON.parse(st); } catch (e) { st = null; } }
    if (!st || typeof st !== 'object') return fail('缺少 state');
    const clean = sanitizeQuizState(st);
    /* ★ 考试记录是**服务端权威**，不能被前端整份覆盖。
       前端 persist() 推上来的是本地 state（本地没有服务端那条新记录），
       直接 put 的话会把刚写入的考试记录连同 subId/pending 一起抹掉，
       表现为「交卷后成绩条没了 / 复核完分数又跳回去」。
       合并规则：服务端的排前面（分数已定稿），客户端独有的追加在后面，
       按 subId 去重；老记录（没有 subId）按「时间|板块|分数」去重。 */
    try {
      const prev = await env.KV.get(key, 'json');
      const pst = (prev && prev.state) ? prev.state : null;
      if (pst && Array.isArray(pst.exams) && pst.exams.length) {
        const seen = {};
        const merged = [];
        const push = function (e) {
          if (!e || typeof e !== 'object') return;
          const k = e.subId
            ? 's:' + String(e.subId)
            : 'c:' + (Number(e.at) || 0) + '|' + String(e.board || '') + '|' + (Number(e.score) || 0) + '|' + (Number(e.total) || 0);
          if (seen[k]) return;
          seen[k] = 1;
          merged.push(e);
        };
        for (const e of pst.exams) push(e);
        for (const e of (clean.exams || [])) push(e);
        clean.exams = merged.slice(-MAX_QUIZ_EXAMS);
      }
    } catch (e) { /* 读不到就按前端的状态写 */ }
    await env.KV.put(key, JSON.stringify({ state: clean, name: s.name, at: Date.now() }));
    return json({ ok: true, saved: true });
  }
  return json({ ok: false, error: 'method_not_allowed' }, 405);
}

/* ---------- 答题站：全员答题数据 ---------- */
async function collectQuizRows(env) {
  const list = await env.KV.list({ prefix: 'q:user:' });
  const rows = [];
  for (const k of list.keys) {
    const u = await env.KV.get(k.name, 'json');
    if (!u) continue;
    const rec = await env.KV.get(qState(u.name), 'json');
    const st = (rec && rec.state) ? rec.state : null;
    const exams = (st && Array.isArray(st.exams)) ? st.exams : [];
    const last = exams.length ? exams[exams.length - 1] : null;
    const best = (st && st.best && last) ? (st.best[last.board] || null) : null;
    rows.push({
      name: u.name, role: u.role || 'user', enabled: !!u.enabled,
      createdAt: u.createdAt || 0, lastLoginAt: u.lastLoginAt || null,
      exams: exams.length, examList: exams,
      score: last ? last.score : null, total: last ? last.total : null,
      at: last ? last.at : null,
      wrong: (st && st.wrong) ? Object.keys(st.wrong).length : 0,
      best: best ? { score: best.score, total: best.total, at: best.at } : null
    });
  }
  rows.sort((a, b) => (b.at || 0) - (a.at || 0));
  return rows;
}

async function handleQQuizStats(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isQuizAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);
  const rows = await collectQuizRows(env);
  return json({ ok: true, rows });
}

/* CSV 单元格：含逗号/引号/换行就加引号，内部的引号翻倍 */
function csvCell(v) {
  let s = (v == null) ? '' : String(v);
  if (/[",\r\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}

/* 导出全员答题数据。带 UTF-8 BOM —— Excel / WPS 双击能直接认中文。 */
async function handleQQuizExport(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isQuizAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);

  const rows = await collectQuizRows(env);
  const head = ['账号', '角色', '账号状态', '考试时间', '板块', '得分', '总题数', '得分率',
    '用时(秒)', '累计考试次数', '最好成绩', '错题数', '注册时间', '最后登录'];
  const lines = [head.join(',')];
  const fmtTime = (t) => {
    if (!t) return '';
    const d = new Date(t);
    const p = (n) => (n < 10 ? '0' + n : '' + n);
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' '
      + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  };
  const roleCn = (r) => (r === 'admin' ? '管理员' : '普通用户');

  for (const r of rows) {
    const base = [
      r.name, roleCn(r.role), r.enabled ? '正常' : '已封禁',
      fmtTime(r.at), '', r.score == null ? '' : r.score, r.total == null ? '' : r.total,
      (r.score == null || !r.total) ? '' : (Math.round(r.score * 100 / r.total) + '%'),
      '', r.exams,
      r.best ? (r.best.score + '/' + r.best.total) : '',
      r.wrong, fmtTime(r.createdAt), fmtTime(r.lastLoginAt)
    ];
    if (!r.examList.length) { lines.push(base.map(csvCell).join(',')); continue; }
    for (const e of r.examList) {
      const row = base.slice();
      row[3] = fmtTime(e.at);
      row[4] = e.boardName || e.board || '';   /* 板块名，不是 id */
      row[5] = e.score == null ? '' : e.score;
      row[6] = e.total == null ? '' : e.total;
      row[7] = e.total ? (Math.round(e.score * 100 / e.total) + '%') : '';
      row[8] = e.usedMs ? Math.round(e.usedMs / 1000) : '';
      lines.push(row.map(csvCell).join(','));
    }
  }

  const csv = '\uFEFF' + lines.join('\r\n');
  const stamp = fmtTime(Date.now()).replace(/[-: ]/g, '');
  return new Response(csv, {
    status: 200,
    headers: withCors(req, env, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="quiz-data-' + stamp + '.csv"'
    })
  });
}

/* ---------- 答题站：账号管理（管理员） ---------- */
async function handleQAdminUsers(req, env, path) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isQuizAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);

  if (req.method === 'GET') {
    const list = await env.KV.list({ prefix: 'q:user:' });
    const users = [];
    for (const k of list.keys) {
      const u = await env.KV.get(k.name, 'json');
      if (!u) continue;
      users.push({
        id: u.id, name: u.name, role: u.role || 'user', enabled: !!u.enabled,
        createdAt: u.createdAt || 0, lastLoginAt: u.lastLoginAt || null,
        updAt: u.updAt || null, pwdAt: u.pwdAt || null
      });
    }
    users.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    return json({ ok: true, users });
  }

  /* PUT /api/q/admin/users/:id —— 启停 / 改密码 / 改角色 */
  const id = decodeURIComponent(path.replace('/api/q/admin/users/', ''));
  if (req.method === 'PUT') {
    let b; try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }
    const u = await env.KV.get(qUser(id), 'json');
    if (!u) return fail('账号不存在', 404);
    if (u.name === admin.name && b.enabled === false) return fail('不能停用自己这个管理员', 403);
    /* ★ 拥有者不能被停用 —— 否则「拥有者有且只有这 2 个」就不成立了。
       （降级 owner 也在下面那条 role 分支里挡住了） */
    if (b.enabled === false && (u.role === 'owner' || QUIZ_OWNERS.indexOf(u.name) >= 0)) {
      return fail('拥有者不能停用', 403);
    }
    let revoke = false;
    const oldRole = u.role;
    const oldEnabled = u.enabled !== false;
    if (typeof b.enabled === 'boolean') u.enabled = b.enabled;
    if (b.role) {
      /* ★ 角色变更**只有拥有者**能做（2026-11-23）。
         拥有者身份固定（ZM1 / ZM2，有且只有 2 个）：
           既不能被降级成管理员，也不能把 owner 转给别人。 */
      if (admin.role !== 'owner') return fail('只有拥有者可以调整管理员身份', 403);
      if (u.role === 'owner' || QUIZ_OWNERS.indexOf(u.name) >= 0) {
        return fail('拥有者身份固定，不能修改', 403);
      }
      u.role = (b.role === 'admin') ? 'admin' : 'user';
    }
    if (b.pwd) {
      if (String(b.pwd).length < 6) return fail('密码至少 6 位');
      const { hash, salt } = await hashPassword(String(b.pwd), null, env);
      u.pwd = hash; u.salt = salt;
      u.pwdAt = Date.now();
      revoke = true;
    }
    /* ★ 给当事人发站内通知（文案见 站内通知文案（2026-11-23）.md） */
    if (u.role !== oldRole) {
      await qNotify(env, u.name, u.role === 'admin' ? 'role_admin' : 'role_user',
        u.role === 'admin' ? '你已被设为管理员' : '管理员身份已取消',
        u.role === 'admin'
          ? admin.name + ' 已将你设为答题库管理员，现在你可以查看全员答题数据、导出报表、管理账号。你原有的学习记录不受影响。'
          : admin.name + ' 已取消你的管理员身份。你原有的学习记录、错题本和考试成绩都不受影响，仍然可以正常答题。',
        '#/admin');
    }
    if (u.enabled === false && oldEnabled) {
      await qNotify(env, u.name, 'banned', '账号已被停用',
        admin.name + ' 已停用你的账号，暂时无法登录。如有疑问请联系管理员。', '');
    } else if (u.enabled !== false && !oldEnabled) {
      await qNotify(env, u.name, 'unbanned', '账号已恢复',
        admin.name + ' 已恢复你的账号，可以正常登录了。', '');
    }
    if (b.pwd) {
      await qNotify(env, u.name, 'pwd_reset', '密码已被重置',
        admin.name + ' 已重置你的密码，请用新密码登录。', '#/login');
    }
    u.updAt = Date.now();
    await env.KV.put(qUser(id), JSON.stringify(u));
    const s = await env.KV.get(qUid(u.name), 'json');
    if (s) {
      s.iat = bumpIat(s.iat);
      s.role = u.role;
      s.enabled = u.enabled !== false;
      if (revoke) s.jti = '__revoked__';
      await env.KV.put(qUid(u.name), JSON.stringify(s), { expirationTtl: TTL_SESSION });
    }
    if (revoke) await qPurgeSessions(env, u.name);
    return json({ ok: true, revoked: revoke });
  }

  /* DELETE —— 删除账号 */
  if (req.method === 'DELETE') {
    const u = await env.KV.get(qUser(id), 'json');
    if (!u) return fail('账号不存在', 404);
    if (u.name === admin.name) return fail('不能删掉自己这个管理员', 403);
    /* ★ 拥有者不能被删除（用户要求：拥有者有且只有 ZM1、ZM2 两个） */
    if (u.role === 'owner' || QUIZ_OWNERS.indexOf(u.name) >= 0) {
      return fail('拥有者不能删除', 403);
    }
    const prev = await env.KV.get(qUid(u.name), 'json');
    await env.KV.delete(qUser(id));
    await env.KV.delete(qName(u.name));
    await env.KV.delete(qState(u.name));
    await qPurgeSessions(env, u.name);
    await env.KV.put(qUid(u.name), JSON.stringify({
      token: '', jti: '__deleted__', iat: bumpIat(prev && prev.iat), role: u.role, enabled: false
    }), { expirationTtl: TTL_SESSION });
    return json({ ok: true });
  }

  return fail('不支持的方法', 405);
}

/* ---------- 答题站：心跳（刷新 lastSeen） ----------
   ★ 没有它，在线判定会「5 分钟后自动掉线」：
     在线判定看 q:sess 记录的 lastSeen 是否在 Q_ONLINE_WINDOW_MIN 内，
     而 lastSeen 只在登录那一刻写过一次 —— 之后没人刷新它。
   工作台那边有 /api/ping 干这件事，答题站一开始漏了。 */
async function handleQPing(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  /* POST + form body 传令牌 → 简单请求，不预检 */
  let tk = '';
  if (req.method === 'POST') {
    let b = {};
    try { b = await qReadBody(req); } catch (e) { b = {}; }
    tk = String(b.tk || '').slice(0, 4000);
  }
  const s = await getQuizSession(req, env, tk);
  if (!s) return json({ ok: false, error: 'no_session' }, 401);

  const now = Date.now();
  const rec = await env.KV.get(qSess(s.jti), 'json');
  if (!rec) {
    /* 会话记录没了（比如 TTL 过期），补一条，免得刚登录就掉出在线列表 */
    await env.KV.put(qSess(s.jti), JSON.stringify({
      jti: s.jti, name: s.name, role: s.role, ip: s.ip, ua: '',
      guest: false, loginAt: s.loginAt || now, lastSeen: now, expAt: s.expAt
    }), { expirationTtl: TTL_SESSION });
    return json({ ok: true, lastSeen: now, revived: true });
  }
  /* 60 秒内的重复心跳不重写，省掉无谓的 KV 写 */
  if (now - (rec.lastSeen || 0) < 60000) return json({ ok: true, skipped: true });
  rec.lastSeen = now;
  await env.KV.put(qSess(s.jti), JSON.stringify(rec), { expirationTtl: TTL_SESSION });
  return json({ ok: true, lastSeen: now });
}

/* ---------- 答题站：在线情况（管理员） ---------- */
async function handleQAdminOnline(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isQuizAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);

  const list = await env.KV.list({ prefix: 'q:sess:' });
  const now = Date.now();
  const rows = [];
  for (const k of list.keys) {
    const s = await env.KV.get(k.name, 'json');
    if (!s) continue;
    if (now > (s.expAt || 0)) { await env.KV.delete(k.name); continue; }
    const ptr = await env.KV.get(qUid(s.name), 'json');
    if (!ptr || ptr.jti !== s.jti) continue;          /* 单点登录后失效的旧会话不算 */
    const lastSeen = s.lastSeen || s.loginAt || 0;
    if (now - lastSeen > Q_ONLINE_WINDOW_MIN * 60000) continue;
    const uId = await env.KV.get(qName(s.name), 'json');
    const u = uId ? await env.KV.get(qUser(uId), 'json') : null;
    rows.push({
      jti: s.jti || k.name.slice(7), name: s.name, ip: s.ip,
      role: (u && u.role) || s.role || 'user',
      enabled: u ? !!u.enabled : true,
      lastSeen, loginAt: s.loginAt,
      leftMinutes: Math.max(0, Math.round((s.expAt - now) / 60000))
    });
  }
  rows.sort((a, b) => b.lastSeen - a.lastSeen);
  return json({ ok: true, online: rows });
}

/* ---------- 答题站：初始化管理员（一次性） ----------
   首次部署时用来建 ZM1 / ZM2 两个管理员（口令按需求固定）。
   ★ 建过之后这个接口**永久关闭** —— 跟工作台 /api/init 一个套路：
     留一个「谁都能重置管理员口令」的接口等于给站点开后门。 */
async function handleQInit(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  if (req.method !== 'POST') return fail('仅支持 POST', 405);
  const list = await env.KV.list({ prefix: 'q:user:' });
  for (const k of list.keys) {
    const u = await env.KV.get(k.name, 'json');
    if (u && u.role === 'admin') return fail('管理员已存在，请在管理后台操作', 409);
  }
  const ADMINS = [{ name: 'ZM1', pwd: 'ZM1' }, { name: 'ZM2', pwd: 'ZM2' }];
  const created = [];
  for (const a of ADMINS) {
    const id = token().slice(0, 12);
    const { hash, salt } = await hashPassword(a.pwd, null, env);
    await env.KV.put(qUser(id), JSON.stringify({
      id, name: a.name, pwd: hash, salt, role: 'admin', enabled: true, createdAt: Date.now()
    }));
    await env.KV.put(qName(a.name), JSON.stringify(id));
    created.push(a.name);
  }
  return json({ ok: true, msg: '管理员已创建，请用它登录', created });
}

/* ---------- 答题站：一次性运维（管理员） ----------
   建/重置 ZM1、ZM2 两个管理员；可把新站点域名加进 ALLOW_ORIGINS。
   只影响答题站账号空间，不碰工作台的任何账号。 */
async function handleQAdminSetup(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isQuizAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);
  /* ★ 一旦存在拥有者，setup 就**只有拥有者能调** ——
     否则普通管理员能重置 ZM1/ZM2 的密码 → 直接拿到拥有者权限（提权漏洞）。
     没有任何拥有者时（首次初始化）管理员也能调，用于把 ZM1/ZM2 升为拥有者。 */
  if (await hasQuizOwner(env) && admin.role !== 'owner') {
    return fail('只有拥有者可以执行初始化', 403);
  }
  if (req.method !== 'POST') return fail('仅支持 POST', 405);
  let b;
  try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }

  const ADMINS = [{ name: 'ZM1', pwd: 'ZM1' }, { name: 'ZM2', pwd: 'ZM2' }];
  const created = [], updated = [];
  for (const a of ADMINS) {
    const id = await env.KV.get(qName(a.name), 'json');
    const { hash, salt } = await hashPassword(a.pwd, null, env);
    if (id) {
      const u = await env.KV.get(qUser(id), 'json');
      if (!u) continue;
      /* ★ ZM1 / ZM2 是固定的两个拥有者 */
      u.pwd = hash; u.salt = salt; u.role = 'owner'; u.enabled = true;
      u.pwdAt = Date.now(); u.updAt = Date.now();
      await env.KV.put(qUser(id), JSON.stringify(u));
      updated.push(a.name);
    } else {
      const nid = token().slice(0, 12);
      await env.KV.put(qUser(nid), JSON.stringify({
        /* ★ 新建分支也要是 owner —— 之前只在「更新」分支改了 role，
           导致账号被删后重建会变成 admin，拥有者就只剩一个了。 */
        id: nid, name: a.name, pwd: hash, salt, role: 'owner', enabled: true, createdAt: Date.now()
      }));
      await env.KV.put(qName(a.name), JSON.stringify(nid));
      created.push(a.name);
    }
  }

  let allowOrigins = env.ALLOW_ORIGINS || '';
  if (b.origin) {
    const list = allowOrigins.split(',').map((x) => x.trim()).filter(Boolean);
    if (list.indexOf(b.origin) < 0) list.push(b.origin);
    allowOrigins = list.join(',');
    env.ALLOW_ORIGINS = allowOrigins;
    const cfg = await env.KV.get('config:server', 'json');
    if (cfg) {
      cfg.allowOrigins = allowOrigins;
      await env.KV.put('config:server', JSON.stringify(cfg));
    }
  }
  return json({ ok: true, created, updated, allowOrigins });
}

/* ---------- 一次性：拥有者移交（仅拥有者会话） ----------
   背景：那次误操作临时建了 ZM1 当拥有者，而系统接口既不许降级拥有者、
   也不许转移拥有者（错误信息原文就是「想移交请直接改数据库」）。
   这个接口在服务端直接改 KV 完成移交，**做完一次就永久关闭**。
   用法：POST { to: '目标账号名', remove: ['要删掉的账号名', ...] } */
async function handleOwnerTransfer(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  if (req.method !== 'POST') return fail('仅支持 POST', 405);

  const done = await env.KV.get('ops:owner_transfer', 'json');
  if (done) return fail('拥有者移交已完成，接口已关闭', 409);

  const admin = await isAdmin(req, env);
  if (!admin || !isOwner(admin)) return fail('需要拥有者权限', 403);

  let b;
  try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }
  const to = String(b.to || '').trim();
  const remove = Array.isArray(b.remove) ? b.remove.map(x => String(x || '').trim()).filter(Boolean) : [];
  if (!to) return fail('缺少目标账号名');

  const targetId = await env.KV.get(kName(to), 'json');
  const target = targetId ? await env.KV.get(kUser(targetId), 'json') : null;
  if (!target) return fail('目标账号不存在：' + to, 404);

  const removed = [];
  for (const nm of remove) {
    if (nm === to) continue;
    const id = await env.KV.get(kName(nm), 'json');
    const u = id ? await env.KV.get(kUser(id), 'json') : null;
    if (!u) continue;
    await env.KV.delete(kUser(id));
    await env.KV.delete(kName(nm));
    await env.KV.delete(kUid(nm));
    await purgeUserSessions(env, nm);
    removed.push(nm);
  }

  target.role = 'owner';
  target.enabled = true;
  target.updAt = Date.now();
  await env.KV.put(kUser(targetId), JSON.stringify(target));
  /* 让目标账号的会话立刻带上新角色 */
  const s = await env.KV.get(kUid(to), 'json');
  if (s) {
    s.role = 'owner';
    await env.KV.put(kUid(to), JSON.stringify(s), { expirationTtl: TTL_SESSION });
  }

  await env.KV.put('ops:owner_transfer', JSON.stringify({ at: Date.now(), to, removed }));
  return json({ ok: true, to, removed });
}

/* ---------- 管理后台 ---------- */
async function isAdmin(req, env) {
  const s = await getSession(req, env);
  if (!s || s.guest) return null;
  const id = await env.KV.get(kName(s.name), 'json');
  const u = id ? await env.KV.get(kUser(id), 'json') : null;
  return u && u.enabled && (u.role === 'admin' || u.role === 'owner') ? u : null;
}

/* ★ 拥有者（owner）：比管理员高一级。
   非拥有者的管理员对拥有者账号一律只能看、不能改 ——
   踢下线、改密码、停用、删除、动角色，全部拦在服务端。 */
const isOwner = (u) => !!(u && u.role === 'owner');

/** 按账号名查它是不是拥有者（踢下线时用：会话里只有名字） */
async function isOwnerName(env, name) {
  const id = await env.KV.get(kName(name), 'json');
  if (!id) return false;
  const u = await env.KV.get(kUser(id), 'json');
  return isOwner(u);
}

/** 清掉某用户在 sess: 里残留的会话记录。
    只影响管理后台的「在线列表」——令牌作废靠指针 iat，不靠这里。 */
async function purgeUserSessions(env, name) {
  const list = await env.KV.list({ prefix: 'sess:' });
  for (const k of list.keys) {
    const s = await env.KV.get(k.name, 'json');
    if (s && s.name === name) await env.KV.delete(k.name);
  }
}

/* ---------- Token 用量计量 ---------- */
const kUsage = (name) => 'usage:' + name;

/** 把一次调用的 usage 累加到该账号名下。计量失败绝不能影响用户拿结果，
 *  所以内部全程吞异常，调用方也不用 await 它。 */
async function addUsage(env, name, usage) {
  try {
    if (!name || !usage) return;
    const p = Number(usage.prompt_tokens) || 0;
    const c = Number(usage.completion_tokens) || 0;
    const t = Number(usage.total_tokens) || (p + c);
    if (!t && !p && !c) return;
    const cur = (await env.KV.get(kUsage(name), 'json'))
      || { total: 0, prompt: 0, completion: 0, calls: 0, at: 0 };
    cur.total += t; cur.prompt += p; cur.completion += c;
    cur.calls += 1; cur.at = Date.now();
    await env.KV.put(kUsage(name), JSON.stringify(cur));
  } catch (e) { /* 计量是旁路，坏了也不能拖垮主流程 */ }
}

/** 流式响应：从 SSE 里捞 usage。MiniMax 会在最后一个 chunk 里带 usage，
 *  所以整段扫一遍只累加那一次。
 *  用 tee() 分一支出来扫，另一支原样回给浏览器 —— 浏览器端代码一行不用改。 */
async function scanStreamUsage(body, env, name) {
  try {
    const reader = body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line.indexOf('data:') !== 0) continue;
        const raw = line.slice(5).trim();
        if (!raw || raw === '[DONE]') continue;
        try {
          const j = JSON.parse(raw);
          if (j && j.usage) await addUsage(env, name, j.usage);
        } catch (_) { /* 非 JSON 的心跳行，忽略 */ }
      }
    }
  } catch (_) { /* 同上，旁路 */ }
}

/** 这次调用记在谁头上。游客也耗额度，单开一个桶，
 *  否则游客白嫖的量在管理台完全看不见。 */
const usageBucket = (s) => (s && !s.guest ? s.name : '__guest__');

async function handleAdminUsers(req, env, path) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);

  if (req.method === 'GET') {
    const list = await env.KV.list({ prefix: 'user:' });
    const users = [];
    for (const k of list.keys) {
      const u = await env.KV.get(k.name, 'json');
      if (!u) continue;
      /* ★ 用量一并带出来，管理台不用再发一次请求 */
      const us = (await env.KV.get(kUsage(u.name), 'json'))
        || { total: 0, prompt: 0, completion: 0, calls: 0, at: 0 };
      users.push({
        id: u.id, name: u.name, role: u.role, enabled: !!u.enabled,
        createdAt: u.createdAt, lastLoginAt: u.lastLoginAt || null,
        /* updAt = 最后一次**任意**修改；pwdAt = 最后一次改密码。
           两者都带上，否则管理台问「密码什么时候改的」只能回答「不知道」——
           那正是之前没记录、也没暴露造成的。 */
        updAt: u.updAt || null, pwdAt: u.pwdAt || null,
        usage: { total: us.total || 0, prompt: us.prompt || 0, completion: us.completion || 0,
          calls: us.calls || 0, at: us.at || null }
      });
    }
    users.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    const guest = (await env.KV.get(kUsage('__guest__'), 'json')) || null;
    return json({ ok: true, users, guestUsage: guest ? (guest.total || 0) : 0 });
  }

  if (req.method === 'POST') {
    let b; try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }
    const name = String(b.name || '').trim();
    const pwd = String(b.pwd || '');
    /* ★★ 拥有者有且只有一个，且**只能由 /api/init 首次初始化产生**。
       原来这里写的是「拥有者也能建拥有者」，于是拥有者可以无限增殖 ——
       一个人开一堆小号全塞成 owner，普通管理员完全管不动。
       现在前端不给这个选项，服务端也硬拦，两道都留。 */
    if (b.role === 'owner') {
      return fail('拥有者唯一，不可新增（拥有者由系统首次初始化时产生）', 403);
    }
    const role = (b.role === 'admin') ? 'admin' : 'user';
    /* 这里不需要再扫一遍「系统里是不是已经有拥有者」——
       上面那道 role==='owner' 的拒绝已经把唯一的造 owner 入口堵死了，
       而 handleInit 建的是 admin、PUT 那头也堵了，三条路全断。
       （曾经在这里加过一个「已有 owner 就拒绝」的兜底循环，
        结果它对**每一个**建号都生效 —— 系统里有拥有者之后连普通用户都建不出来。）*/
    if (!name || !pwd) return fail('账号与密码都要填');
    if (name.length > 32) return fail('账号太长（最多 32 字符）');
    if (pwd.length < 6) return fail('密码至少 6 位');
    if (await env.KV.get(kName(name))) return fail('这个账号已存在', 409);
    const id = token().slice(0, 12);
    const { hash, salt } = await hashPassword(pwd, null, env);
    const u = { id, name, pwd: hash, salt, role, enabled: true, createdAt: Date.now() };
    await env.KV.put(kUser(id), JSON.stringify(u));
    /* ★ 必须 JSON.stringify：读的时候用的是 get(key,'json')，
       存裸字符串的话 JSON.parse 会失败，登录就永远认不出这个账号。 */
    await env.KV.put(kName(name), JSON.stringify(id));
    return json({ ok: true, id }, 200);
  }

  /* PUT /api/admin/users/:id —— 改密码 / 改角色 / 启停 */
  const id = decodeURIComponent(path.replace('/api/admin/users/', ''));
  if (req.method === 'PUT') {
    let b; try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }
    const u = await env.KV.get(kUser(id), 'json');
    if (!u) return fail('账号不存在', 404);
    /* ★ 拥有者保护 */
    if (isOwner(u) && !isOwner(admin)) return fail('拥有者账号只能由拥有者本人修改', 403);
    if (isOwner(u) && b.role && b.role !== 'owner') return fail('不能降级拥有者账号', 403);
    if (isOwner(u) && b.enabled === false) return fail('不能停用拥有者账号', 403);
    /* ★★ 也不许把别人**升**成拥有者。升格是「新增一个拥有者」，
       和 POST 的限制是同一件事 —— 只堵新增那一头等于留了个后门：
       「先建成管理员，再改成拥有者」照样能造出第二个。
       降级方向上面已经堵了，两头都堵才真正保证「有且只有一个」。 */
    if (!isOwner(u) && b.role === 'owner') {
      return fail('拥有者唯一，不可新增或提升（想移交请直接改数据库）', 403);
    }
    let revoke = false;
    if (typeof b.enabled === 'boolean') u.enabled = b.enabled;
    /* ★ 三档角色：owner / admin / user。
       原来只认 'admin'，传 owner 会被静默打成 user —— 升权看着成功、
       其实把人降级了，而且因为 owner 权限更大，升完之后反而什么都做不了。
       「升 owner」只允许两种人做：本来就是拥有者的，
       或者**给自己升**（首个拥有者的产生方式；给别人升一律压回 admin）。 */
    if (b.role) {
      const self = u.name === admin.name;
      u.role = (b.role === 'owner' && (isOwner(admin) || self)) ? 'owner'
        : (b.role === 'admin' ? 'admin' : 'user');
    }
    if (b.pwd) {
      if (String(b.pwd).length < 6) return fail('密码至少 6 位');
      const { hash, salt } = await hashPassword(String(b.pwd), null, env);
      u.pwd = hash; u.salt = salt;
      /* ★ 密码单独打点。之前只有 updAt，而它在下一行是**任何**修改都写的
         （改角色、停用账号都会刷），所以「密码是什么时候改的」根本查不出来 ——
         这是被用户直接问到、查了半天发现没记的。现在从这条起有据可查，
         过去的记录补不回来。 */
      u.pwdAt = Date.now();
      revoke = true;                        /* 改密码 = 旧会话全部作废 */
    }
    u.updAt = Date.now();
    await env.KV.put(kUser(id), JSON.stringify(u));

    /* 把指针时间戳往前推：已签发的令牌比它旧 → 下次请求即判失效 */
    const s = await env.KV.get(kUid(u.name), 'json');
    if (s) {
      /* 指针时间要严格新于它原先记的签发时刻（同毫秒就作废不掉，见 bumpIat） */
      s.iat = bumpIat(s.iat);
      s.role = u.role;
      s.enabled = u.enabled !== false;
      if (revoke) s.jti = '__revoked__';
      await env.KV.put(kUid(u.name), JSON.stringify(s), { expirationTtl: TTL_SESSION });
    }
    if (revoke) await purgeUserSessions(env, u.name);
    return json({ ok: true, revoked: revoke });
  }

  if (req.method === 'DELETE') {
    const u = await env.KV.get(kUser(id), 'json');
    if (!u) return fail('账号不存在', 404);
    if (isOwner(u) && !isOwner(admin)) return fail('拥有者账号不能被删除', 403);
    if (u.role === 'admin' && u.name === admin.name) return fail('不能删掉自己这个管理员');
    /* 墓碑要比「最后一次登录」新，否则同毫秒时删号作废不掉（见 bumpIat） */
    const prev = await env.KV.get(kUid(u.name), 'json');
    await env.KV.delete(kUser(id));
    await env.KV.delete(kName(u.name));
    await purgeUserSessions(env, u.name);
    /* ★ 墓碑：不能直接删指针。
       删了的话 getSession 读到 null 会「放过」，被删账号的令牌还能再用 7 天。
       写一条新时间的墓碑才能让旧令牌判失效。 */
    await env.KV.put(kUid(u.name), JSON.stringify({
      token: '', jti: '__deleted__', iat: bumpIat(prev && prev.iat), role: u.role, enabled: false
    }), { expirationTtl: TTL_SESSION });
    return json({ ok: true });
  }

  return fail('不支持的方法', 405);
}

/** 在线会话：扫 sess: 前缀。只给管理后台看，允许几十秒的最终一致延迟。 */
async function handleOnline(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);
  const list = await env.KV.list({ prefix: 'sess:' });
  const now = Date.now();
  const rows = [];
  let pruned = 0;
  for (const k of list.keys) {
    const s = await env.KV.get(k.name, 'json');
    if (!s) continue;
    if (now > (s.expAt || 0)) { await env.KV.delete(k.name); continue; }
    /* ★ 角色不能直接用会话里存的那份 —— 那是登录当时的快照，
       管理员升成拥有者之后会话记录还写着 admin，在线列表会把
       「不可踢」显示成「可踢」。这里按账号名回查一次真实角色。
       管理员接口本来就低频，多一次读换正确性，值。 */
    let role = s.role || 'user';
    /* ★ 这条会话还算不算数，要看单点登录指针还指着它不指着。
       sess: 记录在登录时写、只靠 TTL 自然过期，登出/踢人才删。
       但「同一账号只能在一处登录」——后来那次登录会把 uid: 指针挪到新 jti，
       旧令牌当场作废，旧 sess: 却还要在列表里挂 7 天。
       结果就是「当前在线」里同一个人七八条，「剩余 7 天」整齐划一看着像
       有很多活跃会话，其实只有最新那条能用；对着死会话点「强制下线」
       也是白点（它早就死了），白让人以为没踢成功。
       所以这里核对一次指针，指针不再指向它就当已失效，顺手清掉。 */
    if (!s.guest) {
      const ptr = await env.KV.get(kUid(s.name), 'json');
      if (!ptr || ptr.jti !== s.jti) {
        await env.KV.delete(k.name);
        pruned++;
        continue;
      }
      const uid = await env.KV.get(kName(s.name), 'json');
      if (uid) {
        const cur = await env.KV.get(kUser(uid), 'json');
        if (cur && cur.role) role = cur.role;
      }
    }
    /* ★ 真正判「在线」：看有没有心跳，不是看令牌还有没有效。
       超窗的**不列出来，但也别删记录** —— 令牌还有效，管理员想作废它
       应该用「停用 / 删除账号」，而不是对着一个离线会话点「强制下线」。
       （删掉 sess: 反而会让「踢下线」这条路对离线用户失效。） */
    const lastSeen = s.lastSeen || s.loginAt || 0;
    if (now - lastSeen > ONLINE_WINDOW_MIN * 60000) continue;
    rows.push({
      jti: s.jti || k.name.slice(5), name: s.name, ip: s.ip, guest: !!s.guest,
      role, lastSeen,
      loginAt: s.loginAt, leftMinutes: Math.max(0, Math.round((s.expAt - now) / 60000))
    });
  }
  rows.sort((a, b) => (b.loginAt || 0) - (a.loginAt || 0));
  /* pruned 告诉管理台刚才顺手清了几条失效记录，界面上给个提示，
     否则管理员会怀疑「我明明登过，怎么少了几条」。 */
  return json({ ok: true, online: rows, pruned });
}

/** 强制下线 */
async function handleKick(req, env, path) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);
  if (req.method !== 'POST') return fail('仅支持 POST', 405);
  const jti = path.replace('/api/admin/kick/', '');
  const s = await env.KV.get(kSess(jti), 'json');
  if (!s) return json({ ok: true, note: '该会话已失效' });
  /* ★ 拥有者保护：非拥有者的管理员踢不动拥有者 */
  if (!s.guest && admin.role !== 'owner' && await isOwnerName(env, s.name)) {
    return fail('拥有者账号不能被强制下线', 403);
  }
  await env.KV.delete(kSess(jti));
  /* 这两个要报给管理员看，必须声明在 if 外面；
     尤其别在块里再 let 一遍 —— 内层会遮蔽外层，report 里就成了空字符串。 */
  let ipBanned = false;
  let why = s.guest ? '游客会话，只断开不写冷却' : '';
  if (!s.guest) {
    /* 目标是拥有者账号时只断会话、不写任何冷却。
       理由和登录侧那道豁免一样：能删冷却的只有拥有者本人，
       给自己记一条就是把自己永久锁在门外。 */
    const targetIsOwner = isOwner(s) || await isOwnerName(env, s.name);
    if (targetIsOwner) why = '目标是拥有者账号，只断会话不写冷却（否则拥有者会把自己锁死）';

    /* ★ 先判断「能不能安全地拉黑这个 IP」，再决定写哪一条冷却。
         - 拿得到真实 IP、且没有拥有者从这儿登录过 → 拉黑 IP（正常语义）
         - 拿不到真实 IP（unknown，全站共享桶）    → 不能拉黑，改按账号
         - 这个 IP 是拥有者登录过的                → 永不拉黑，改按账号
       「被踢的人换个 IP 还能登回来」是设计如此：需求就是「被强制下线的
       IP 冷却 6 小时」，封的是 IP 不是账号。账号级冷却只在 IP 不能封时兜底。 */
    if (!targetIsOwner) {
      if (!isRealIp(s.ip)) {
        why = '拿不到真实 IP（记为 unknown，这是全站共享桶），不拉黑 IP，改为按账号冷却';
      } else if (await env.KV.get(kOwnerIp(s.ip), 'json')) {
        why = '该 IP 是拥有者登录过的，永不拉黑，改为按账号冷却';
      }
    }

    const rec = {
      kind: 'ip', ip: s.ip, name: s.name, role: s.role, jti,
      at: Date.now(), until: Date.now() + KICK_COOLDOWN * 1000,
      by: admin.name
    };
    if (!why) {
      await env.KV.put(kKick(s.ip), JSON.stringify(rec), { expirationTtl: KICK_COOLDOWN });
      ipBanned = true;
    } else if (!targetIsOwner) {
      await env.KV.put(kKickName(s.name),
        JSON.stringify({ ...rec, kind: 'account' }), { expirationTtl: KICK_COOLDOWN });
    }

    await env.KV.put(kUid(s.name), JSON.stringify({
      ip: s.ip, token: '', jti: '__kicked__', iat: bumpIat(s.loginAt),
      role: s.role, enabled: true
    }), { expirationTtl: TTL_SESSION });

    /* ★ 还要清掉 kIp 里指向这个 token 的记录。
       不清的话，被踢的人重新登录会命中「同 IP 复用会话」那条捷径，
       又把那个已经作废的旧 token 递回去 → 登录成功但立刻 401，
       表现就是「被踢之后再也登不回来」。 */
    const ipRec = await env.KV.get(kIp(s.ip), 'json');
    if (ipRec && ipRec.jti === jti) {
      await env.KV.put(kIp(s.ip), JSON.stringify({
        token: '', jti: '', guest: false, name: ipRec.name,
        lastGuestAt: ipRec.lastGuestAt || 0
      }), { expirationTtl: 60 });
    }
  }
  /* 告诉管理员这次到底拦了什么，别让人以为「拉黑了 IP」却发现同事还能登 */
  return json({ ok: true, ipBanned, note: why || undefined });
}

/* ---------- 首次初始化管理员 ---------- */
async function handleInit(req, env) {
  /* 已经建过管理员就不许再建 */
  const list = await env.KV.list({ prefix: 'user:' });
  for (const k of list.keys) {
    const u = await env.KV.get(k.name, 'json');
    if (u && u.role === 'admin') return fail('管理员已存在，请用管理后台添加账号', 409);
  }
  if (req.method !== 'POST') return fail('仅支持 POST', 405);
  let b; try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }
  const name = String(b.name || '').trim();
  const pwd = String(b.pwd || '');
  if (!name || pwd.length < 8) return fail('账号不能为空，密码至少 8 位');
  const id = token().slice(0, 12);
  const { hash, salt } = await hashPassword(pwd, null, env);
  await env.KV.put(kUser(id), JSON.stringify(
    { id, name, pwd: hash, salt, role: 'admin', enabled: true, createdAt: Date.now() }));
  await env.KV.put(kName(name), JSON.stringify(id));   /* 同上：必须 JSON */
  return json({ ok: true, msg: '管理员已创建，请用它登录', name });
}

/* ---------- 一次性引导：把服务端配置写进 KV ----------
   为什么需要：Deno 控制台的环境变量入口在这个控制台上找不到，
   而 deno deploy env add 在 0.0.9908 里是坏的（env 子命令不接受参数）。
   所以改成：启动时先读 KV，KV 里没有再等一次引导写入。
   安全模型：仓库是公开的，里面只放口令的 SHA-256；口令本身只有本地有，
   哈希不可逆，攻击者读得到代码也猜不出口令。写成功后此接口永久关闭。 */
async function handleBootstrap(req, env) {
  if (req.method !== 'POST') return fail('仅支持 POST', 405);
  let b;
  try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }

  const presented = String(b.token || '');
  if (!env.BOOTSTRAP_HASH) return fail('服务端没配引导口令哈希，引导接口不可用', 500);
  const h = await sha256Hex(presented);
  if (!safeEqual(h, String(env.BOOTSTRAP_HASH))) return fail('引导口令不对', 401);

  const exists = await env.KV.get('config:server', 'json');
  if (exists) return fail('已经初始化过了，引导接口已关闭', 409);

  const cfg = {
    sessionSecret: String(b.sessionSecret || ''),
    modelApiKey: String(b.modelApiKey || ''),
    allowOrigins: String(b.allowOrigins || ''),
    bootstrappedAt: Date.now()
  };
  if (cfg.sessionSecret.length < 32) return fail('sessionSecret 至少 32 位');
  if (!cfg.modelApiKey) return fail('modelApiKey 不能为空');

  await env.KV.put('config:server', JSON.stringify(cfg));
  return json({ ok: true, msg: '配置已写入 KV，需要重新部署一次才会生效' });
}

/* ---------- 被踢 IP 名单（仅拥有者） ---------- */

/** 列出所有处于冷却期的被踢 IP —— 只有拥有者能看/能放行。
 *  这张表是「IP 放行」这个运维动作的唯一入口，所以权限必须卡死在服务端。 */
async function handleKickedIps(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);
  if (!isOwner(admin)) return fail('只有拥有者可以查看和解除被踢 IP', 403);

  /* 两类冷却都要列出来：kick:（IP 级）和 kickn:（账号级）。
     拿不到真实 IP 时只有账号级会命中，只列一种会让管理台显示「名单是空的」，
     看上去像没踢，实际谁都登不回来。 */
  const rows = [];
  const now = Date.now();
  const collect = async (prefix, kind) => {
    const list = await env.KV.list({ prefix });
    for (const k of list.keys) {
      const rec = await env.KV.get(k.name, 'json');
      if (!rec || now >= (rec.until || 0)) { await env.KV.delete(k.name); continue; }
      rows.push({
        kind, ip: rec.ip || '', name: rec.name || '', by: rec.by || '',
        at: rec.at, until: rec.until,
        leftMinutes: Math.ceil((rec.until - now) / 60000)
      });
    }
  };
  await collect('kick:', 'ip');
  await collect('kickn:', 'account');

  /* 拥有者登录过的 IP 在名单里标出来：这些是真 IP，但永不会被拦，
     放行按钮对它们是空操作，标一下免得运维对着它纳闷。 */
  for (const r of rows) {
    if (r.kind === 'ip' && isRealIp(r.ip)) {
      r.ownerProtected = !!(await env.KV.get(kOwnerIp(r.ip), 'json'));
    }
  }
  rows.sort((a, b) => (b.at || 0) - (a.at || 0));
  return json({ ok: true, cooldownHours: KICK_COOLDOWN / 3600, kicked: rows });
}

/** 手动放行：既可以按 IP 放，也可以按账号放（拿不到真实 IP 时只能按账号）。 */
async function handleUnblockIp(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;
  const admin = await isAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);
  if (!isOwner(admin)) return fail('只有拥有者可以解除被踢 IP', 403);
  if (req.method !== 'POST') return fail('仅支持 POST', 405);

  let b; try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }
  const ip = String(b.ip || '').trim();
  const name = String(b.name || '').trim();
  const kind = String(b.kind || (ip ? 'ip' : name ? 'account' : '')).trim();
  if (!kind || (!ip && !name)) return fail('缺少 ip 或 name 参数');

  const hit = [];
  const cleared = [];        /* 被解掉账号的 { name, role }，用来抬单点登录指针 */
  const unblockAccount = async (nm, role) => {
    const r = await env.KV.get(kKickName(nm), 'json');
    if (r) {
      await env.KV.delete(kKickName(nm));
      hit.push(nm);
      cleared.push({ name: r.name || nm, role: r.role || role || 'user' });
    }
  };

  if (kind === 'account') {
    if (!name) return fail('按账号放行需要 name');
    await unblockAccount(name);
  } else {
    if (!ip) return fail('按 IP 放行需要 ip');
    const r = await env.KV.get(kKick(ip), 'json');
    if (r) { await env.KV.delete(kKick(ip)); hit.push(ip); }
    /* 放行 IP 时顺手把该 IP 上所有账号级冷却也清了：
       用户在管理台看到的是一行，恢复就该恢复干净。 */
    const all = await env.KV.list({ prefix: 'kickn:' });
    for (const k of all.keys) {
      const rec = await env.KV.get(k.name, 'json');
      if (rec && rec.ip === ip) await unblockAccount(rec.name || '', rec.role);
    }
    /* 顺手把该 IP 的「同 IP 复用」记录也清掉，
       否则放行之后他第一次登录还会拿到之前那条旧令牌。 */
    const ipRec = await env.KV.get(kIp(ip), 'json');
    if (ipRec) {
      await env.KV.put(kIp(ip), JSON.stringify({
        token: '', jti: '', guest: false, name: ipRec.name, lastGuestAt: ipRec.lastGuestAt || 0
      }), { expirationTtl: 60 });
    }
  }

  /* 被踢的那些账号的单点登录指针也抬一下，让他们能干净地重新登录 */
  for (const c of cleared) {
    const uid = await env.KV.get(kUid(c.name), 'json');
    if (!uid || uid.jti !== '__kicked__') continue;
    await env.KV.put(kUid(c.name), JSON.stringify({
      ip: '', token: '', jti: '__unblocked__', iat: Date.now(),
      role: c.role, enabled: true
    }), { expirationTtl: TTL_SESSION });
  }

  if (!hit.length) return json({ ok: true, note: '该记录本来就不在冷却中' });
  return json({ ok: true, msg: '已解除 ' + hit.join('、') + ' 的登录限制' });
}

/* ---------- PX4 Flight Review 上传中转 ----------
 *
 * ★ 为什么必须有这个端点：logs.px4.io 一个 CORS 头都没有
 *   （OPTIONS 直接 405，POST 的 302 里也没有 Access-Control-Allow-Origin），
 *   浏览器直接跨域 POST 会被同源策略拦死，拿不到回跳里的 log id。
 *   服务端发请求不受 CORS 限制，所以在网关这里中转一次。
 *
 * 用法：前端把 .ulg 原始字节 POST 过来，这里 multipart 转投给
 *   https://logs.px4.io/upload（redirect=true → 302 到 plot_app?log=<uuid>），
 *   把 uuid 抠出来回给前端，前端拿去 iframe ④ 区。
 *
 * 风险与限制（都写死在这里，不给前端留口子）：
 *   - 这是把用户的飞行日志转发给第三方。站点按「不脱敏」策略设计，故默认开启；
 *     若将来要改成必须用户点确认，只需在 config.js 关掉 openAutoUpload。
 *   - 单文件上限 64MB（PX4 官方单次 SDLOG_MODE 最大 1024MiB 但没意义这么大）。
 *   - 必须登录，且游客不给用（会白嫖 PX4 的服务器）。
 *   - 不缓存、不落盘：字节只在内存里过一遍，转发完就丢。
 */
const PX4_FR_UPLOAD = 'https://logs.px4.io/upload';
const PX4_MAX_UPLOAD = 64 * 1024 * 1024;

async function handlePx4Upload(req, env) {
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;

  const s = await getSession(req, env);
  if (!s) return json({ ok: false, error: '登录已失效，请重新登录' }, 401);
  /* 游客不给转发：这是白嫖第三方的服务器和带宽 */
  if (s.guest) return json({ ok: false, error: '游客体验不能上传 Flight Review，请用正式账号' }, 403);
  if (Date.now() > s.expAt) return json({ ok: false, error: '会话已到期，请重新登录' }, 401);
  if (req.method !== 'POST') return fail('仅支持 POST', 405);

  let form;
  /* ★ 必须把真实异常带出来。以前一律返回「上传内容解析失败」四个字，
     现场表现是 ④ 区弹一句没头没尾的话、日志里什么都没有 ——
     上线后第一版就踩过：前端给 FormData 请求显式写了
     `Content-Type: application/json`（浏览器不会覆盖，于是 boundary 丢失），
     req.formData() 抛的就是它。
     现在把 Content-Type 和异常原文一起回传，下一次一眼能看出是哪一类。 */
  try { form = await req.formData(); }
  catch (e) {
    return json({
      ok: false,
      error: '上传内容解析失败（网关没能读懂这个请求）',
      contentType: String(req.headers.get('content-type') || ''),
      detail: String((e && e.message) || e).slice(0, 200)
    }, 400);
  }

  const file = form.get('file');
  if (!file || typeof file === 'string') return fail('没有收到 .ulg 文件');
  const name = String(file.name || '').toLowerCase();
  if (!name.endsWith('.ulg')) return fail('只接受 .ulg 文件（收到的是 ' + (name || '无名文件') + '）');
  if (file.size > PX4_MAX_UPLOAD) {
    return json({ ok: false, error: '文件太大：' + Math.round(file.size / 1048576)
      + 'MB，上限 ' + Math.round(PX4_MAX_UPLOAD / 1048576) + 'MB' }, 413);
  }

  const buf = new Uint8Array(await file.arrayBuffer());
  /* 转发前自己先验一遍文件头，别把垃圾数据丢给 PX4 */
  const magic = String.fromCharCode(buf[0], buf[1], buf[2], buf[3]);
  if (magic !== 'ULog') {
    return fail('这不是 PX4 ULog 文件（文件头应为 "ULog"，实际是 "' + magic + '"');
  }

  /* multipart 重建：logs.px4.io 要的是 filearg / public / redirect / type / email */
  const fd = new FormData();
  fd.set('filearg', new Blob([buf], { type: 'application/octet-stream' }), file.name || 'log.ulg');
  fd.set('description', String(form.get('description') || 'via AI 测试工具工作台'));
  fd.set('feedback', '');
  fd.set('email', '');           /* 留空即可，不必收集用户邮箱 */
  fd.set('type', 'private');     /* 分享链接模式，不进公开库 */
  fd.set('public', 'false');
  fd.set('redirect', 'true');    /* ★ 不发邮件，直接 302 回 plot_app，我们从回跳里取 id */

  let up;
  try {
    up = await fetch(PX4_FR_UPLOAD, { method: 'POST', body: fd, redirect: 'manual' });
  } catch (e) {
    return json({ ok: false, error: '连不上 PX4 Flight Review：' + (e && e.message ? e.message : e) }, 502);
  }

  /* redirect: 'manual' 在 Deno 上返回 3xx 且带 Location */
  const loc = up.headers.get('location') || '';
  const m = loc.match(/[?&]log=([0-9a-f-]{36})/i);
  if (!m) {
    const txt = await up.text().catch(() => '');
    return json({ ok: false, error: 'PX4 没返回 log id（HTTP ' + up.status + '）',
      detail: txt.slice(0, 300) }, 502);
  }
  return json({
    ok: true,
    logId: m[1],
    url: 'https://logs.px4.io/plot_app?log=' + m[1],
    sizeMB: Math.round(file.size / 1048576 * 100) / 100
  });
}

/* ---------- 大模型 API 代理（★ API Key 只存在服务端）---------- */
async function handleProxy(req, env) {
  /* Cookie 现在允许跨站带了，所以每个会改状态/动用额度的接口都要先验来源 */
  const bad = assertSameOrigin(req, env);
  if (bad) return bad;

  const s = await getSession(req, env);
  if (!s) return json({ ok: false, error: '登录已失效，请重新登录' }, 401);

  let body;
  try { body = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }

  /* 会话到期直接拦下，别让游客超时后还能白嫖 */
  if (Date.now() > s.expAt) {
    await env.KV.delete(kSess(s.jti));
    return json({ ok: false, error: '体验时间已到，请重新登录' }, 401);
  }

  const target = env.MODEL_API || 'https://api.minimax.chat/v1/text/chatcompletion_v2';
  const key = env.MODEL_API_KEY;
  if (!key) return fail('服务端没有配置 MODEL_API_KEY', 500);

  const stream = !!body.stream;
  /* ★ 模型名：**前端指定优先**。
     原来是 env.MODEL_NAME || body.model —— 服务端永远赢，
     于是工作台上那个「模型接口」设置（每账号自选模型）根本推不动，
     改了也白改。现在用户没指定时才回落到服务端默认，
     **不修改任何全局配置**，只影响这一次请求。 */
  const payload = { ...body, model: body.model || env.MODEL_NAME };
  const init = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
    body: JSON.stringify(payload)
  };

  const bucket = usageBucket(s);

  if (stream) {
    /* 流式：原样把上游响应体转回去，浏览器端代码不用改逻辑。
       ★ 用 tee() 分一支出来扫 usage：累加 token 用量是旁路，
         绝不能为了计量去动往浏览器送的那一支的字节。 */
    const up = await fetch(target, init);
    if (up.body && up.ok) {
      const [toClient, toMeter] = up.body.tee();
      /* 不 await：让计量在后台跑，不给主响应加延迟 */
      scanStreamUsage(toMeter, env, bucket);
      return new Response(toClient, {
        status: up.status,
        headers: {
          'Content-Type': up.headers.get('Content-Type') || 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache',
          ...withCors(req, env)
        }
      });
    }
    return new Response(up.body, {
      status: up.status,
      headers: {
        'Content-Type': up.headers.get('Content-Type') || 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        ...withCors(req, env)
      }
    });
  }

  const up = await fetch(target, init);
  const txt = await up.text();
  /* 非流式：响应体本来就要整段读，直接从 JSON 里取 usage */
  if (up.ok) {
    try {
      const j = JSON.parse(txt);
      if (j && j.usage) addUsage(env, bucket, j.usage);
    } catch (_) { /* 不是 JSON 就没用量可记 */ }
  }
  return new Response(txt, {
    status: up.status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...withCors(req, env) }
  });
}

/* ---------- 路由 ---------- */
/* ★ 函数名不能叫 fetch。
   模块级 `function fetch` 会遮蔽全局 fetch，于是 handleProxy 里那句
   `fetch(target, init)` 会调到自己 —— 传进去的是个 URL 字符串，
   字符串没有 .url → new URL(undefined) 直接抛「Invalid URL」。
   结果：代理接口只要真带着有效会话去调模型就必崩。
   （冒烟测试没抓到，是因为测的是「未带会话→401」，走不到上游那行。）
   改叫 route，全局 fetch 就露出来了。 */
async function route(req, env) {
  const url = new URL(req.url);
  const p = url.pathname;

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: withCors(req, env, {
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-ZT-Token,X-QZ-Token'
    }) });
  }

  try {
    /* ★ /api/init 已下线。
       它是个**公开的**管理员创建接口：任何人 POST 一下就能造一个 admin 出来。
       就算前端不露入口，接口本身也在，等于给站点留后门。
       现在唯一的建号路径是管理后台（需要已有管理员会话 + Origin 白名单）。
       env.ALLOW_INIT 只在本地回归测试里为 true，生产恒为 false。 */
    if (p === '/api/init') {
      if (!env.ALLOW_INIT) return fail('该接口已下线，请在管理后台添加账号', 410);
      return withJson(await handleInit(req, env), req, env);
    }
    if (p === '/api/login')   return withJson(await handleLogin(req, env), req, env);
    /* ===== 答题站专用接口（/api/q/*）：与工作台账号空间完全隔离 ===== */
    if (p === '/api/q/init')     return withJson(await handleQInit(req, env), req, env);
    if (p === '/api/q/register') return withJson(await handleQRegister(req, env), req, env);
    if (p === '/api/q/login')    return withJson(await handleQLogin(req, env), req, env);
    if (p === '/api/q/session')  return withJson(await handleQSession(req, env), req, env);
    if (p === '/api/q/whereami') return withJson(await handleQWhereami(req, env), req, env);
    if (p === '/api/q/notices')  return withJson(await handleQNotices(req, env), req, env);
    if (p === '/api/q/submit')   return withJson(await handleQSubmit(req, env), req, env);
    if (p === '/api/q/grade-one') return withJson(await handleQGradeOne(req, env), req, env);
    if (p === '/api/q/finish')  return withJson(await handleQFinish(req, env), req, env);
    if (p === '/api/q/my/subs') return withJson(await handleQMySubs(req, env), req, env);
    if (p.startsWith('/api/q/my/subs/')) {
      const mid = decodeURIComponent(p.replace('/api/q/my/subs/', ''));
      return withJson(await handleQMySubDetail(req, env, mid), req, env);
    }
    if (p === '/api/q/submissions') return withJson(await handleQSubmissions(req, env, p, ''), req, env);
    if (p.startsWith('/api/q/submissions/')) {
      const sid = decodeURIComponent(p.replace('/api/q/submissions/', ''));
      if (req.method === 'POST' && sid.endsWith('/review')) {
        return withJson(await handleQReview(req, env, sid.replace(/\/review$/, '')), req, env);
      }
      return withJson(await handleQSubmissions(req, env, p, sid), req, env);
    }
    if (p === '/api/q/admin/qbank') return withJson(await handleQAdminConfig(req, env, 'qbank'), req, env);
    if (p === '/api/q/admin/aicfg') return withJson(await handleQAdminConfig(req, env, 'aicfg'), req, env);
    if (p === '/api/q/ping')     return withJson(await handleQPing(req, env), req, env);
    if (p === '/api/q/logout')   return withJson(await handleQLogout(req, env), req, env);
    if (p === '/api/q/quiz/state') return withJson(await handleQQuizState(req, env), req, env);
    if (p === '/api/q/quiz/stats') return withJson(await handleQQuizStats(req, env), req, env);
    if (p === '/api/q/quiz/export') return withJson(await handleQQuizExport(req, env), req, env);
    if (p === '/api/q/admin/users') return withJson(await handleQAdminUsers(req, env, p), req, env);
    if (p.startsWith('/api/q/admin/users/')) return withJson(await handleQAdminUsers(req, env, p), req, env);
    if (p === '/api/q/admin/online') return withJson(await handleQAdminOnline(req, env), req, env);
    if (p === '/api/q/admin/setup')  return withJson(await handleQAdminSetup(req, env), req, env);
    if (p === '/api/guest')   return withJson(await handleGuest(req, env), req, env);
    if (p === '/api/logout')  return withJson(await handleLogout(req, env), req, env);
    if (p === '/api/session') return withJson(await handleSession(req, env), req, env);
    /* 更新通知的已读位置：跟着**账号**走，存在服务端 KV（见 kSeen 的说明）。
       缺了它，已读就只存在于「这台电脑」，换个浏览器/清缓存/换 IP 全量回红点。 */
    if (p === '/api/notify/seen') return withJson(await handleNotifySeen(req, env), req, env);
    /* 在线心跳：工作台定时打，只为刷新 lastSeen，不返回业务数据 */
    if (p === '/api/ping') return withJson(await handlePing(req, env), req, env);
    if (p === '/api/bootstrap') return withJson(await handleBootstrap(req, env), req, env);
    /* ★ 必须 await。写成 `return handleProxy(...)` 的话，Promise 会直接逃出
       上面那个 try/catch —— handleProxy 里任何异步异常（上游网络错误之类）
       都会变成未捕获的 Promise 拒绝，而不是我们准备好��� 500 JSON。 */
    if (p === '/api/proxy')   return await handleProxy(req, env);
    if (p === '/api/px4/upload') return withJson(await handlePx4Upload(req, env), req, env);
    if (p === '/api/admin/users') return withJson(await handleAdminUsers(req, env, p), req, env);
    /* 一次性：拥有者移交（善后用，做完自动关闭） */
    if (p === '/api/admin/owner-transfer') return withJson(await handleOwnerTransfer(req, env), req, env);
    if (p.startsWith('/api/admin/users/')) {
      return withJson(await handleAdminUsers(req, env, p), req, env);
    }
    if (p === '/api/admin/online') return withJson(await handleOnline(req, env), req, env);
    /* 被踢 IP 名单 + 手动放行：仅拥有者 */
    if (p === '/api/admin/kicked-ips') return withJson(await handleKickedIps(req, env), req, env);
    if (p === '/api/admin/unblock-ip') return withJson(await handleUnblockIp(req, env), req, env);
    if (p.startsWith('/api/admin/kick/')) {
      return withJson(await handleKick(req, env, p), req, env);
    }
    /* 健康检查：部署完先打这个，确认 KV 绑定正常 */
    if (p === '/api/health') {
      let kvOk = false, kvErr = '';
      try { await env.KV.get('__health__'); kvOk = true; }
      catch (e) { kvErr = (e && e.message) ? String(e.message) : String(e); }
      let admin = false;
      try { admin = !!(await isAdmin(req, env)); } catch (e) { admin = false; }
      return json({
        ok: true, kv: kvOk, kvError: kvErr || env.KV_ERROR || '',
        kvMissing: !!env.KV._dead,
        strongRead: typeof env.KV._strong === 'function' ? env.KV._strong() : null,
        configured: !!(env.SESSION_SECRET && env.MODEL_API_KEY),
        hasSecret: !!env.SESSION_SECRET, hasModelKey: !!env.MODEL_API_KEY,
        configSource: env.CONFIG_SOURCE || 'none',
        admin: !!admin, runtime: env.RUNTIME || 'unknown'
      });
    }
    return json({ ok: false, error: '没有这个接口' }, 404);
  } catch (e) {
    return json({ ok: false, error: '服务端出错：' + (e && e.message ? e.message : String(e)) }, 500);
  }
}

function withJson(resp, req, env) {
  /* 给跨域响应补上 CORS 头（登录/会话这些接口需要） */
  const h = new Headers(resp.headers);
  const o = corsOrigin(req, env);
  h.set('Access-Control-Allow-Origin', o || 'null');
  h.set('Access-Control-Allow-Credentials', 'true');
  h.set('Vary', 'Origin');
  return new Response(resp.body, { status: resp.status, headers: h });
}

export { route, kUser, kName, kSess, kIp, kUid, kLock,
         makeToken, verifyToken, TTL_SESSION, TTL_GUEST };
