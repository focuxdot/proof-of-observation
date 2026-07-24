// 本地校验代理(透明每调验,「最省心」的客户端验证组件)。
//
//   npx tsx tee-verify-proxy.ts --upstream https://api.example.com --pcr0 <hex> [--port 8788] [--enforce]
//
// 把你的 LLM 客户端 baseURL 改指向本代理(http://127.0.0.1:8788),其余照常调用。代理对每次请求:
//   ① 原样转发到真实上游(relay),逐字节回传给你的客户端 —— 流式不破(holdback 只压住流末)。
//      不注入任何头:nonce 由 relay 端生成、随 proof 回(客户端不提供 —— 见 docs/TEE.md §5)。
//   ② 流末剥 proof,再以签名哈希为闸剥固定前置 keepalive,还原上游原文走 v2 response-only 验证:
//      attestation 链 + PCR0 + 公钥绑定 + nonce 绑定 + 声明验签;并**读出签名覆盖的 upstream_host/path**。
//   ③ 默认 fail-open:无论判定都把响应交给客户端,但把判定**大声打到本代理日志**(持续抽查/威慑)。
//      `--enforce`:fail-closed —— 整段缓冲、验过才放行;有 proof 但验不过回 502(牺牲流式,换强阻断)。
//
// response-only:能验真飞地跑审计镜像、签了你逐字收到的响应(未篡改),并**读出签名覆盖的 host/path**。
// 不含**请求绑定**(代理看不到你发往上游的原始请求体)。要连「答的就是我这条请求」一并钉,
// 用整 bundle 验证(verify-real-bundle.ts,full 档)。
//
// 验证逻辑全部落在共享核心 tee-verify-core.ts(与 CLI 抽查 / 整 bundle 验证同一份,零漂移)。

import http from 'node:http';
import https from 'node:https';
import { realpathSync } from 'node:fs';
import { fileURLToPath, URL } from 'node:url';
import {
  verifyTeeExchange,
  parseTeeProofEvent,
  type AttestationVerifier,
  type TeeVerifyResult,
} from './tee-verify-core.ts';

// 转发时必须丢弃的逐跳头(由本代理自行重设帧):
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailers', 'transfer-encoding', 'upgrade',
]);

const DEFAULT_HOLDBACK = 64 * 1024; // 须 ≥ 最大 proof 体积(含 COSE attestation b64),否则会把 proof 前缀误转给客户端

export interface VerifyingProxyOptions {
  upstream: string; // 真实上游 base URL,如 https://api.example.com
  expectedPcr0: string; // 审计公布的镜像度量
  enforce?: boolean; // true=fail-closed(缓冲+阻断);默认 false=fail-open(流式+日志)
  holdback?: number; // 流式压住流末的字节数;默认 64KiB
  verifyAttestationDoc?: AttestationVerifier; // 默认真 COSE;测试注桩
  onVerdict?: (
    verdict: TeeVerifyResult | null,
    ctx: { method: string; path: string; nonce: string; attested: boolean },
  ) => void;
  onWarning?: (msg: string) => void; // 运营告警(如 holdback 过小);默认 console.warn
}

export function createVerifyingProxy(opts: VerifyingProxyOptions): http.Server {
  const upstreamUrl = new URL(opts.upstream);
  const transport = upstreamUrl.protocol === 'http:' ? http : https;
  const holdback = opts.holdback ?? DEFAULT_HOLDBACK;
  const warn = opts.onWarning ?? ((m: string) => console.warn(`[tee-proxy] ${m}`));

  return http.createServer((clientReq, clientRes) => {
    const reqChunks: Buffer[] = [];
    clientReq.on('data', (c) => reqChunks.push(c as Buffer));
    clientReq.on('error', () => {/* 客户端断开:让下方 upstream/clientRes 自然收尾 */});
    clientReq.on('end', () => {
      const reqBody = Buffer.concat(reqChunks);
      const target = new URL(clientReq.url || '/', upstreamUrl);

      // 透传客户端头(发往 relay 的 Authorization 是用户自己的 key,保留),只改写 host 与 content-length(不注入任何头)。
      const headers: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(clientReq.headers)) {
        if (v == null || HOP_BY_HOP.has(k.toLowerCase())) continue;
        headers[k] = v as string | string[];
      }
      headers['host'] = target.host;
      delete headers['content-length'];
      if (reqBody.length) headers['content-length'] = String(reqBody.length);

      // nonce 不由代理生成/注入:relay 端生成、随 proof 回(见 docs/TEE.md §5)。ctx.nonce 取自
      // 已验证的 proof(仅供日志展示);核心缺省即以 proof.nonce 做一致性核对。
      const report = (verdict: TeeVerifyResult | null, attested: boolean, nonce = '') =>
        opts.onVerdict?.(verdict, { method: clientReq.method || 'GET', path: clientReq.url || '/', nonce, attested });
      const runVerify = (body: Buffer, proof: any): TeeVerifyResult =>
        verifyTeeExchange(
          { expectedPcr0: opts.expectedPcr0, responseBody: body, proof },
          { verifyAttestationDoc: opts.verifyAttestationDoc },
        );

      let upResRef: http.IncomingMessage | undefined;
      const up = transport.request(target, { method: clientReq.method, headers }, (upRes) => {
        upResRef = upRes;
        const ct = String(upRes.headers['content-type'] || '');
        const streaming = ct.includes('text/event-stream');

        // ── fail-closed:整段缓冲,验过(或本就无 proof)才放行;有 proof 但验不过 → 502。
        if (opts.enforce) {
          const buf: Buffer[] = [];
          upRes.on('data', (c: Buffer) => buf.push(c));
          upRes.on('end', () => {
            const whole = Buffer.concat(buf);
            const { body, proof } = parseTeeProofEvent(whole);
            const verdict = proof ? runVerify(body, proof) : null;
            report(verdict, Boolean(proof), proof?.nonce ?? '');
            if (proof && (!verdict || !verdict.ok)) {
              clientRes.writeHead(502, { 'content-type': 'application/json' });
              clientRes.end(JSON.stringify({ error: 'tee_verification_failed', checks: verdict?.checks ?? null }));
              return;
            }
            copyHeaders(upRes, clientRes, Boolean(proof));
            clientRes.end(proof ? body : whole);
          });
          upRes.on('error', () => endError(clientRes));
          return;
        }

        // ── fail-open · 非流式(无 proof 预期):逐字节透传,改都不改。
        if (!streaming) {
          copyHeaders(upRes, clientRes, false);
          upRes.on('data', (c: Buffer) => clientRes.write(c));
          upRes.on('end', () => { clientRes.end(); report(null, false); });
          upRes.on('error', () => endError(clientRes));
          return;
        }

        // ── fail-open · 流式:holdback 压住流末,边收边转;流末剥 proof + 验 + 日志。
        copyHeaders(upRes, clientRes, true);
        let acc = Buffer.alloc(0);
        let forwarded = 0;
        upRes.on('data', (c: Buffer) => {
          acc = Buffer.concat([acc, c]);
          const safeEnd = acc.length - holdback;
          if (safeEnd > forwarded) {
            clientRes.write(acc.subarray(forwarded, safeEnd));
            forwarded = safeEnd;
          }
        });
        upRes.on('end', () => {
          const {
            body,
            proof,
            ignoredTransportKeepaliveBytes = 0,
          } = parseTeeProofEvent(acc);
          // `body` is normalized for verification and may omit proof-gated
          // leading transport keepalives. Client passthrough stays in `acc`'s
          // raw coordinate space so an already-forwarded marker cannot shift
          // or truncate the remaining upstream response bytes.
          const rawBodyEnd = proof
            ? body.length + ignoredTransportKeepaliveBytes
            : acc.length;
          // forwarded > rawBodyEnd ⇒ holdback 没压住整个 proof,已有 (forwarded-rawBodyEnd)
          // 字节 proof 误转给客户端(不可撤回)。判定仍用完整 body 算,故 verdict 不受影响。
          if (forwarded > rawBodyEnd) {
            warn(`holdback(${holdback}) 小于 proof 体积,已有 ${forwarded - rawBodyEnd} 字节 proof 误转给客户端;增大 holdback/--holdback`);
          }
          if (rawBodyEnd > forwarded) clientRes.write(acc.subarray(forwarded, rawBodyEnd));
          clientRes.end();
          const verdict = proof ? runVerify(body, proof) : null;
          report(verdict, Boolean(proof), proof?.nonce ?? '');
        });
        upRes.on('error', () => endError(clientRes));
      });

      up.on('error', (err) => {
        if (clientRes.headersSent) { clientRes.end(); return; }
        clientRes.writeHead(502, { 'content-type': 'application/json' });
        clientRes.end(JSON.stringify({ error: 'tee_proxy_upstream_error', detail: String((err as Error).message) }));
      });
      // 客户端中途断开:别把上游晾着(漏一个在途请求),也别让 write-after-close 的未监听
      // 'error' 掀翻进程。writableEnded 为真 = 正常收尾,不动。
      clientRes.on('error', () => { try { up.destroy(); } catch { /* ignore */ } });
      clientRes.on('close', () => {
        if (!clientRes.writableEnded) {
          try { up.destroy(); } catch { /* ignore */ }
          try { upResRef?.destroy(); } catch { /* ignore */ }
        }
      });
      if (reqBody.length) up.write(reqBody);
      up.end();
    });
  });
}

function copyHeaders(upRes: http.IncomingMessage, clientRes: http.ServerResponse, stripLength: boolean): void {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(upRes.headers)) {
    if (v == null) continue;
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (stripLength && lk === 'content-length') continue; // 剥了 proof → 长度变了,交给 Node 重设
    out[k] = v as string | string[];
  }
  clientRes.writeHead(upRes.statusCode || 200, out);
}

function endError(clientRes: http.ServerResponse): void {
  if (clientRes.headersSent) { clientRes.end(); return; }
  clientRes.writeHead(502, { 'content-type': 'application/json' });
  clientRes.end(JSON.stringify({ error: 'tee_proxy_stream_error' }));
}

// ── CLI(直接运行时)──────────────────────────────────────────────────────────
function runCli(): void {
  const args = process.argv.slice(2);
  const flag = (n: string) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
  const has = (n: string) => args.includes(n);

  const upstream = flag('--upstream') ?? process.env.TEE_PROXY_UPSTREAM;
  const pcr0 = flag('--pcr0');
  const port = Number(flag('--port') ?? process.env.TEE_PROXY_PORT ?? 8788);
  const enforce = has('--enforce');
  if (!upstream || !pcr0) {
    console.error('用法: tsx tee-verify-proxy.ts --upstream <url> --pcr0 <hex> [--port 8788] [--enforce]');
    console.error('  把客户端 baseURL 指向 http://127.0.0.1:<port>;--pcr0 为审计公布、可由 reproducible-build 复算的镜像度量。');
    process.exit(2);
  }

  const server = createVerifyingProxy({
    upstream,
    expectedPcr0: pcr0,
    enforce,
    onVerdict: (v, ctx) => {
      const tag = `${ctx.method} ${ctx.path}`;
      if (!ctx.attested) { console.log(`·  ${tag} —— 未自证(无 proof:非流式 / transform / 降级直连)`); return; }
      if (!v) { console.log(`?  ${tag} —— 有 proof 但无法解析验证`); return; }
      console.log(`${v.ok ? '✅' : '❌'} ${tag} —— ${v.ok ? '真飞地 · 未篡改' : '校验失败'}  [host ${v.provenance.upstreamHost}]`);
      if (!v.ok) for (const c of v.checks) if (!c.ok) console.log(`     ❌ ${c.name}: ${c.detail}`);
    },
  });

  server.listen(port, '127.0.0.1', () => {
    console.log('── 本地校验代理 ──');
    console.log(`  监听  http://127.0.0.1:${port}  →  上游 ${upstream}`);
    console.log(`  PCR0  ${pcr0}`);
    console.log(`  模式  ${enforce ? 'fail-closed(--enforce:有 proof 验不过 → 502)' : 'fail-open(放行 + 日志,持续抽查/威慑)'}`);
    console.log('  用法  把你的 LLM 客户端 baseURL 改成上面的监听地址即可(代理不注入任何头;nonce 由 relay 端生成)。');
    console.log('  注    response-only 会展示签名覆盖的 host;但不含请求绑定,要连「答的就是我这条请求」用整 bundle 验证。');
  });
}

const invokedDirectly = (() => {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (invokedDirectly) runCli();
