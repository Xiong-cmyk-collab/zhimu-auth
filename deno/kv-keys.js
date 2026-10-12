/* =====================================================================
 * Deno KV ↔ Cloudflare KV 的键名映射（独立成模块是为了能直接跑单测）
 * ===================================================================== */

/** Cloudflare 的键是字符串（'sess:abc'）→ Deno 的键是数组（['sess','abc']）。
 *  直接传字符串会报「serde_v8 error: invalid type; expected: array, got: string」。
 *  core.js 里所有键都是 `<类型>:<值>`，且用户输入一律经 encodeURIComponent
 *  （':' 变成 %3A），所以按 ':' 拆分是无损的。 */
export const toKey = (k) => (Array.isArray(k) ? k : String(k).split(':'));

/** 数组 → core.js 期望的字符串 */
export const toStr = (a) => (Array.isArray(a) ? a.join(':') : String(a));

/* ★ list 的前缀必须单独转，不能复用 toKey。
   toKey('user:') 得到 ['user','']，而 Deno KV 的前缀是「路径逐段相等」，
   只匹配键 ['user','']；真实键是 ['user','abc123'] —— 一条都列不出来。
   症状：管理后台账号列表永远 0 个、在线会话永远空、
   「管理员已存在」检查永远为假 → /api/init 能被反复调用造出一堆管理员。
   去掉末尾空段：'user:' → ['user']，这才是真正的路径前缀。 */
export function toPrefix(prefix) {
  const parts = String(prefix).split(':');
  while (parts.length > 1 && parts[parts.length - 1] === '') parts.pop();
  return parts;
}

/** 复刻 Deno KV 的前缀匹配规则，供单测验证映射是否正确 */
export function matchPrefix(key, prefix) {
  if (prefix.length > key.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (String(key[i]) !== String(prefix[i])) return false;
  }
  return true;
}