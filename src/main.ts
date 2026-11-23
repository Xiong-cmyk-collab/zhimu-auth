/* =====================================================================
 * Deno Deploy 构建入口
 * ---------------------------------------------------------------------
 * 平台构建器找的是 <app 根>/src/main.ts，控制台 Runtime Configuration 里
 * 的 Entrypoint 默认值却是 main.ts —— 两者不一致。
 * 这里按构建器的路径来，根目录另有一个 main.ts 作为双保险。
 * 真正的逻辑在 ../deno/main.js（读环境变量、连 KV、起服务）。
 * ===================================================================== */
import '../deno/main.js';
/* ★ Deno Deploy 的 cron 任务要求**入口模块**导出同名函数。
   任务名 retrygrading（deno.json 里的 "cron"）→ 这里必须 export 出去。 */
export { retrygrading } from '../deno/main.js';
