/* =====================================================================
 * Deno Deploy 入口
 * =====================================================================
 * core.js 是平台无关的，这里只干两件事：
 *   1. 把 Deno KV 包成 core.js 期望的那套 Cloudflare-KV 风格接口
 *      —— 这样 core.js 里 60 多处 env.KV.* 调用一行都不用改
 *   2. 从环境变量拼出 env 对象
 *
 * ★ 为什么用强一致读（consistency: 'strong'）
 * Deno KV 默认最终一致（全球 60s 内同步）。登录后紧接着的请求如果
 * 落在另一个边缘节点，可能读不到刚写的单点登录指针。
 * 强一致读直接消掉这个问题。内部工具量很小，读单元完全够用。
 * core.js 里那条「iat 比令牌新才作废」的规则保留着当双保险。
 * ===================================================================== */

import { fetch as coreFetch } from '../core.js';
import { toKey, toStr, toPrefix } from './kv-keys.js';

/* 键名转换规则见同目录 kv-keys.js（抽成独立模块是为了能直接跑单测）：
   toKey  → Cloudflare 字符串键转 Deno 数组键
   toStr  → 反向
   toPrefix → list 的前缀转换（必须单独处理，否则列表永远是空的） */

function mkKV(dkv) {
  /* 强一致读在 Deno Deploy 上原生支持；本地 SQLite 版 Deno KV 不认这个参数。
     第一次踩到就把强一致关掉，降级成默认读，保证任何环境都不会因为
     「传了个不支持的 option」而整个挂掉。 */
  const state = { strong: true };
  const read = async (key) => {
    if (state.strong) {
      try { return await dkv.get(key, { consistency: 'strong' }); }
      catch (e) { state.strong = false; console.warn('KV 不支持强一致读，降级为默认读：' + (e && e.message)); }
    }
    return await dkv.get(key);
  };
  return {
    _strong: () => state.strong,
    async get(key, opts) {
      const r = await read(toKey(key));
      const v = r.value;
      if (v === null || v === undefined) return null;
      if (opts === 'json') {
        try { return JSON.parse(v); } catch (e) { return null; }
      }
      return v;
    },

    async put(key, value, opts) {
      /* Cloudflare 用 expirationTtl（秒），Deno 用 expireIn（毫秒） */
      const o = {};
      if (opts && opts.expirationTtl) {
        o.expireIn = Math.max(1000, Math.round(opts.expirationTtl * 1000));
      }
      await dkv.set(toKey(key), String(value), o);
    },

    async delete(key) { await dkv.delete(toKey(key)); },

    async list({ prefix } = {}) {
      const keys = [];
      const opt = prefix ? { prefix: toPrefix(prefix) } : {};
      for await (const e of dkv.list(opt)) {
        keys.push({ name: toStr(e.key) });
      }
      return { keys };
    }
  };
}

/* 没挂 KV 数据库时不要让整个 isolate 崩掉 —— 否则连 /api/health 都打不开，
   只能去翻构建日志。这里降级成一个「拒绝服务」的桩：健康检查会如实报
   kv=false，其它接口一律 503，日志里也写清楚原因。 */
/** KV 没挂时的降级桩：所有读写都抛，附带人话解释 */
function mkDeadKV(reason) {
  const boom = (op) => () => {
    throw new Error('服务端没有挂 KV 数据库（' + op + ' 失败）：' + (reason || '未附加'));
  };
  return {
    _strong: () => false,
    _dead: true,
    get: boom('读'),
    put: boom('写'),
    delete: boom('删'),
    list: boom('列举'),
  };
}

let dkv = null;
let kvError = '';
try {
  dkv = await Deno.openKv();
} catch (e) {
  kvError = (e && e.message) ? String(e.message) : String(e);
  console.error('⚠ 打不开 KV：' + kvError);
  console.error('  去控制台 Databases 页面给这个 app 挂一个 KV 数据库，然后重新部署。');
}

/* 配置来源优先级：环境变量 > KV。
   Deno 控制台的环境变量入口在当前版本找不到、CLI 的 env 子命令也是坏的，
   所以留一条 KV 通道：/api/bootstrap 一次性写入 config:server，
   重启（重新部署）后启动时从这里读回来。 */
let kvConfig = {};
let configSource = 'none';
async function loadKvConfig() {
  if (!dkv) return {};
  /* 强一致读优先；万一这个环境不认 consistency，退回默认读再试一次，
     免得一次异常就默默当成「没配置」。 */
  let r = null;
  try { r = await dkv.get(['config', 'server'], { consistency: 'strong' }); }
  catch (e) {
    console.warn('强一致读配置失败，退回默认读：' + (e && e.message ? e.message : e));
    try { r = await dkv.get(['config', 'server']); } catch (e2) { r = null; }
  }
  /* ★ 必须 JSON.parse。KV 里存的是 JSON 文本，直接把字符串丢给调用方的话，
     调用方写 c.sessionSecret 永远是 undefined —— 配置看着「读到了」其实没读进来，
     于是 configSource 永远是 none。 */
  const raw = (r && r.value) ? r.value : '';
  if (!raw) return {};
  try {
    const o = JSON.parse(raw);
    return (o && typeof o === 'object') ? o : {};
  } catch (e) {
    console.warn('KV 里的配置不是合法 JSON：' + (e && e.message ? e.message : e));
    return {};
  }
}
try {
  kvConfig = await loadKvConfig();
} catch (e) {
  console.warn('读 KV 配置失败：' + (e && e.message ? e.message : e));
}

const pick = (envName, kvKey) => {
  const fromEnv = Deno.env.get(envName);
  if (fromEnv) return { value: fromEnv, from: 'env' };
  const fromKv = kvConfig[kvKey];
  if (fromKv) return { value: String(fromKv), from: 'kv' };
  return { value: '', from: 'none' };
};

const secret = pick('SESSION_SECRET', 'sessionSecret');
const modelKey = pick('MODEL_API_KEY', 'modelApiKey');
const origins = pick('ALLOW_ORIGINS', 'allowOrigins');
if (secret.from === 'kv' || modelKey.from === 'kv' || origins.from === 'kv') configSource = 'kv';
else if (secret.from === 'env' && modelKey.from === 'env') configSource = 'env';

const env = {
  KV: dkv ? mkKV(dkv) : mkDeadKV(kvError),
  KV_ERROR: kvError,
  CONFIG_SOURCE: configSource,
  /* 引导口令的 SHA-256。仓库公开，但哈希不可逆 —— 只有本地知道原口令。 */
  BOOTSTRAP_HASH: '13dd4f9c966522c4bf74aa03ee359abbe72453bc57c23d41ea9b5fd1653712b6',
  SESSION_SECRET: secret.value,
  MODEL_API: Deno.env.get('MODEL_API') || kvConfig.modelApi
    || 'https://api.minimax.chat/v1/text/chatcompletion_v2',
  MODEL_NAME: Deno.env.get('MODEL_NAME') || kvConfig.modelName || 'MiniMax-M3',
  MODEL_API_KEY: modelKey.value,
  ALLOW_ORIGINS: origins.value,
  PBKDF2_ITER: Deno.env.get('PBKDF2_ITER') || '',
  RUNTIME: 'deno-deploy'
};

const missing = ['SESSION_SECRET', 'MODEL_API_KEY', 'ALLOW_ORIGINS']
  .filter((k) => !env[k]);
if (missing.length) {
  console.error('⚠ 缺少环境变量：' + missing.join(', ') + ' —— 对应功能会不可用');
} else {
  console.log('✅ 环境变量齐全，KV 已连接');
}

/* Deno.serve 的第二个参数是连接信息，不是我们的 env，所以要用闭包包一层 */

/* ★★ 惰性补配置：启动时读一次只是快路径，真正兜底的是这里。
   之前只在启动时读，于是「引导写完 KV → 必须重启进程才生效」，
   而重启要靠部署完成，部署又卡在 Deno 构建机拉 GitHub 上，
   于是一环扣一环。现在改成：只要 env 里还是空的，第一次请求时
   就自己去 KV 补，补上后立刻可用 —— 不用等重启。
   写完 /api/bootstrap 之后，打一次任意请求就能看到效果。 */
let cfgChecked = false;
async function ensureConfig() {
  if (cfgChecked) return;
  cfgChecked = true;
  if (env.SESSION_SECRET && env.MODEL_API_KEY) return;
  const c = await loadKvConfig();
  if (!c || !c.sessionSecret) return;
  env.SESSION_SECRET = env.SESSION_SECRET || c.sessionSecret || '';
  env.MODEL_API_KEY = env.MODEL_API_KEY || c.modelApiKey || '';
  env.ALLOW_ORIGINS = env.ALLOW_ORIGINS || c.allowOrigins || '';
  env.MODEL_API = env.MODEL_API || c.modelApi || 'https://api.minimax.chat/v1/text/chatcompletion_v2';
  env.MODEL_NAME = env.MODEL_NAME || c.modelName || 'MiniMax-M3';
  env.CONFIG_SOURCE = 'kv';
  console.log('✅ 已从 KV 补齐配置');
}

Deno.serve(async (req) => {
  try { await ensureConfig(); } catch (e) { /* 补不上就按原样跑，health 会如实报 */ }
  return coreFetch(req, env);
}, { port: 8000 });
