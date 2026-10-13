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

/** 客户端 IP。各平台塞的请求头不一样，全都要认。 */
function clientIp(req) {
  const cf = req.headers.get('cf-connecting-ip');
  if (cf) return cf;
  const dpc = req.headers.get('dpc-connecting-ip');
  if (dpc) return dpc;
  const xff = req.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  return 'unknown';
}

/** 统一允许的来源：站点自己的域名 + 本地开发。
 *  没做白名单的话，任何人拿个网页都能拿你的 token 来调 —— 那登录就白做了。 */
function corsOrigin(req, env) {
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

  /* 暴力破解限速：同一 IP 连续失败 5 次锁 10 分钟 */
  const lockKey = kLock(ip);
  const lock = await env.KV.get(lockKey);
  if (lock && Date.now() < Number(lock)) {
    return fail('失败次数过多，请 ' + Math.ceil((lock - Date.now()) / 60000) + ' 分钟后再试', 429);
  }

  const id = await env.KV.get(kName(name), 'json');
  const user = id ? await env.KV.get(kUser(id), 'json') : null;

  if (!user || !user.enabled) {
    await bumpFail(env, lockKey);
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
  const payload = { ...body, model: env.MODEL_NAME || body.model };
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
      'Access-Control-Allow-Headers': 'Content-Type,X-ZT-Token'
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
    if (p === '/api/guest')   return withJson(await handleGuest(req, env), req, env);
    if (p === '/api/logout')  return withJson(await handleLogout(req, env), req, env);
    if (p === '/api/session') return withJson(await handleSession(req, env), req, env);
    /* 在线心跳：工作台定时打，只为刷新 lastSeen，不返回业务数据 */
    if (p === '/api/ping') return withJson(await handlePing(req, env), req, env);
    if (p === '/api/bootstrap') return withJson(await handleBootstrap(req, env), req, env);
    /* ★ 必须 await。写成 `return handleProxy(...)` 的话，Promise 会直接逃出
       上面那个 try/catch —— handleProxy 里任何异步异常（上游网络错误之类）
       都会变成未捕获的 Promise 拒绝，而不是我们准备好��� 500 JSON。 */
    if (p === '/api/proxy')   return await handleProxy(req, env);
    if (p === '/api/px4/upload') return withJson(await handlePx4Upload(req, env), req, env);
    if (p === '/api/admin/users') return withJson(await handleAdminUsers(req, env, p), req, env);
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
