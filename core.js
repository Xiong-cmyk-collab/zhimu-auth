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

const TTL_SESSION = 60 * 60 * 24 * 7;      /* 正常会话 7 天 */
const TTL_GUEST = 8 * 60;                  /* ★ 游客 8 分钟 */
const TTL_GUEST_IP = 6 * 60 * 60;          /* ★ 同 IP 游客冷却 6 小时 */
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

function token() {
  return (crypto.randomUUID() + crypto.randomUUID()).replace(/-/g, '');
}

function readCookie(req, name) {
  const raw = req.headers.get('Cookie') || '';
  const hit = raw.split(';').map((s) => s.trim())
    .find((s) => s.startsWith(name + '='));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : '';
}

function setCookie(tk, maxAge) {
  return `ztk=${tk}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
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

  /* ★ 同 IP 已有「同一个账号」的有效会话 → 直接复用（不必再走一遍会话写入）。
     必须比对账号名：只判断「这个 IP 上有会话」的话，
     共享 IP（办公室/网吧）下任何人输任意账号都会被换成已登录者的身份。 */
  const ipRec = await env.KV.get(kIp(ip), 'json');
  if (ipRec && ipRec.token && !ipRec.guest && ipRec.name === user.name) {
    const p = await verifyToken(ipRec.token, env.SESSION_SECRET);
    if (p && !p.g && p.n === user.name && Date.now() < p.e) {
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
  return json({ ok: true }, 200, { 'Set-Cookie': 'ztk=; Path=/; Max-Age=0' });
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

/* ---------- 管理后台 ---------- */
async function isAdmin(req, env) {
  const s = await getSession(req, env);
  if (!s || s.guest) return null;
  const id = await env.KV.get(kName(s.name), 'json');
  const u = id ? await env.KV.get(kUser(id), 'json') : null;
  return u && u.enabled && u.role === 'admin' ? u : null;
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

async function handleAdminUsers(req, env, path) {
  const admin = await isAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);

  if (req.method === 'GET') {
    const list = await env.KV.list({ prefix: 'user:' });
    const users = [];
    for (const k of list.keys) {
      const u = await env.KV.get(k.name, 'json');
      if (u) users.push({
        id: u.id, name: u.name, role: u.role, enabled: !!u.enabled,
        createdAt: u.createdAt, lastLoginAt: u.lastLoginAt || null
      });
    }
    users.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    return json({ ok: true, users });
  }

  if (req.method === 'POST') {
    let b; try { b = await req.json(); } catch (e) { return fail('请求体不是合法 JSON'); }
    const name = String(b.name || '').trim();
    const pwd = String(b.pwd || '');
    const role = b.role === 'admin' ? 'admin' : 'user';
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
    let revoke = false;
    if (typeof b.enabled === 'boolean') u.enabled = b.enabled;
    if (b.role) u.role = b.role === 'admin' ? 'admin' : 'user';
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
      s.iat = Date.now();
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
    if (u.role === 'admin' && u.name === admin.name) return fail('不能删掉自己这个管理员');
    await env.KV.delete(kUser(id));
    await env.KV.delete(kName(u.name));
    await purgeUserSessions(env, u.name);
    /* ★ 墓碑：不能直接删指针。
       删了的话 getSession 读到 null 会「放过」，被删账号的令牌还能再用 7 天。
       写一条新时间的墓碑才能让旧令牌判失效。 */
    await env.KV.put(kUid(u.name), JSON.stringify({
      token: '', jti: '__deleted__', iat: Date.now(), role: u.role, enabled: false
    }), { expirationTtl: TTL_SESSION });
    return json({ ok: true });
  }

  return fail('不支持的方法', 405);
}

/** 在线会话：扫 sess: 前缀。只给管理后台看，允许几十秒的最终一致延迟。 */
async function handleOnline(req, env) {
  const admin = await isAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);
  const list = await env.KV.list({ prefix: 'sess:' });
  const now = Date.now();
  const rows = [];
  for (const k of list.keys) {
    const s = await env.KV.get(k.name, 'json');
    if (!s) continue;
    if (now > (s.expAt || 0)) { await env.KV.delete(k.name); continue; }
    rows.push({
      jti: s.jti || k.name.slice(5), name: s.name, ip: s.ip, guest: !!s.guest,
      loginAt: s.loginAt, leftMinutes: Math.max(0, Math.round((s.expAt - now) / 60000))
    });
  }
  rows.sort((a, b) => (b.loginAt || 0) - (a.loginAt || 0));
  return json({ ok: true, online: rows });
}

/** 强制下线 */
async function handleKick(req, env, path) {
  const admin = await isAdmin(req, env);
  if (!admin) return fail('需要管理员权限', 403);
  if (req.method !== 'POST') return fail('仅支持 POST', 405);
  const jti = path.replace('/api/admin/kick/', '');
  const s = await env.KV.get(kSess(jti), 'json');
  if (!s) return json({ ok: true, note: '该会话已失效' });
  await env.KV.delete(kSess(jti));
  if (!s.guest) {
    await env.KV.put(kUid(s.name), JSON.stringify({
      ip: s.ip, token: '', jti: '__kicked__', iat: Date.now(),
      role: s.role, enabled: true
    }), { expirationTtl: TTL_SESSION });
  }
  return json({ ok: true });
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

/* ---------- 大模型 API 代理（★ API Key 只存在服务端）---------- */
async function handleProxy(req, env) {
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

  if (stream) {
    /* 流式：原样把上游响应体转回去，浏览器端代码不用改逻辑 */
    const up = await fetch(target, init);
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
  return new Response(txt, {
    status: up.status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...withCors(req, env) }
  });
}

/* ---------- 路由 ---------- */
async function fetch(req, env) {
  const url = new URL(req.url);
  const p = url.pathname;

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: withCors(req, env, {
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-ZT-Token'
    }) });
  }

  try {
    if (p === '/api/init')    return withJson(await handleInit(req, env), req, env);
    if (p === '/api/login')   return withJson(await handleLogin(req, env), req, env);
    if (p === '/api/guest')   return withJson(await handleGuest(req, env), req, env);
    if (p === '/api/logout')  return withJson(await handleLogout(req, env), req, env);
    if (p === '/api/session') return withJson(await handleSession(req, env), req, env);
    if (p === '/api/proxy')   return handleProxy(req, env);
    if (p === '/api/admin/users') return withJson(await handleAdminUsers(req, env, p), req, env);
    if (p.startsWith('/api/admin/users/')) {
      return withJson(await handleAdminUsers(req, env, p), req, env);
    }
    if (p === '/api/admin/online') return withJson(await handleOnline(req, env), req, env);
    if (p.startsWith('/api/admin/kick/')) {
      return withJson(await handleKick(req, env, p), req, env);
    }
    /* 健康检查：部署完先打这个，确认 KV 绑定正常 */
    if (p === '/api/health') {
      let kvOk = false, kvErr = '';
      try { await env.KV.get('__health__'); kvOk = true; }
      catch (e) { kvErr = (e && e.message) ? String(e.message) : String(e); }
      const admin = await isAdmin(req, env);
      return json({
        ok: true, kv: kvOk, kvError: kvErr,
        strongRead: typeof env.KV._strong === 'function' ? env.KV._strong() : null,
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

export { fetch, kUser, kName, kSess, kIp, kUid, kLock,
         makeToken, verifyToken, TTL_SESSION, TTL_GUEST };
