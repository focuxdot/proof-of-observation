// 真硬件客户端 verifier 的**纯核心**(让自证成立的那一半,可复用)—— v2 字段分解版。
//
// 设计见 docs/tee-signing-v2-design.md。与 mock 的 verifier.ts 不同:这里走真路径 ——
// attestation 是 COSE/P-384 链到 AWS 根(verify-attestation-cose.mjs),响应签名是 Ed25519
// 覆盖「字段分解声明」(signing.ts buildV2Statement)。verify-real-bundle.ts / 客户端 CLI /
// 校验代理 / tee-verify.html 都对齐本逻辑,杜绝漂移。
//
// 用户拿到 (收到的完整响应 + proof[,可选:自己发的请求体]) 后独立校验:
//   ① attestation 链到 AWS 根 + 证书有效期 + PCR0 == 审计公布值(跑的是审计镜像)
//   ② proof 签名公钥 == attestation 背书的公钥
//   ③ nonce 绑定:att 内嵌 nonce == proof 顶层 nonce(均被签名覆盖;relay 端 nonce,一致性核对)
//   ④ 上游 host:**直接读**签名覆盖的 upstream_host(给了 expectedHost 则比对,否则展示由你判断)
//   ⑤ 响应签名:用绑定公钥对「重建的声明」验签 + 收到的字节哈希 == 签名覆盖的 response_body_sha256
//   ⑥ 请求绑定(给了 requestBody 才做):你发的 body 哈希 == 签名覆盖的 request_body_sha256
// 全过 = 不是黑箱。任一不过 = 当场识破。
//
// 两档:full(给了 requestBody)= 多一项请求绑定(答的就是你这条请求);response-only = 只验响应未篡改 + 读 host。

import { createPublicKey, verify as edVerify } from 'node:crypto';
import { buildV2Statement, sha256 } from './signing.ts';
// @ts-expect-error 纯 JS 零依赖模块
import { verifyAttestationDoc as realVerifyAttestationDoc } from './verify-attestation-cose.mjs';

// v2 proof 线格式(docs/tee-signing-v2-design.md §5)。前 9 字段(nonce…response_body_sha256)即签名载荷。
export interface TeeProofWire {
  v?: number; // 2
  alg?: string;
  public_key: string; // base64 SPKI
  nonce: string; // base64
  upstream_host: string;
  upstream_path: string;
  http_method: string;
  http_status: number;
  resp_content_type: string;
  request_body_sha256: string; // hex
  response_body_sha256: string; // hex
  signature: string; // base64 Ed25519(覆盖重建声明)
  attestation: string; // base64 COSE_Sign1 文档
  pcr0?: string;
}

// verify-attestation-cose.mjs verifyAttestationDoc 的返回形状(只取核验用得到的字段)。
export interface AttestationVerdict {
  ok: boolean;
  sigOk: boolean;
  chainOk: boolean;
  rootSelf: boolean;
  rootPinned: boolean;
  timeValid: boolean;
  leafNotAfter?: string;
  moduleId?: string;
  pcr0?: string | null;
  publicKey?: string | null;
  nonce?: string | null;
  rootFingerprint?: string;
}

export type AttestationVerifier = (doc: Buffer, opts?: { now?: number }) => AttestationVerdict;

export interface TeeVerifyInput {
  expectedPcr0: string; // hex,审计公布、可由 reproducible-build 复算
  responseBody: Buffer; // 你实际收到的完整响应体(已剥掉 tee.proof 流末事件)
  proof: TeeProofWire;
  // 可选(full 档):你**自己发的请求体**,用来核对请求绑定(⑥)。
  requestBody?: Buffer;
  // 可选:核对签名覆盖的 upstream_host;不给则只展示由你判断(④)。
  expectedHost?: string;
  now?: number; // 证书有效期判定基准(测试可注)
}

export interface TeeCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface TeeVerifyResult {
  ok: boolean;
  mode: 'full' | 'response-only';
  checks: TeeCheck[];
  attestation: {
    moduleId?: string;
    pcr0?: string | null;
    publicKey?: string | null;
    nonce?: string | null;
  };
  // 签名覆盖的来源事实,供展示(验签过即可信)。
  provenance: {
    upstreamHost: string;
    upstreamPath: string;
    httpMethod: string;
    httpStatus: number;
    respContentType: string;
  };
}

const b64 = (s: string): Buffer => Buffer.from(s, 'base64');

/**
 * 纯核验:无 I/O、无 console、无 process.exit。`deps.verifyAttestationDoc` 默认走真
 * COSE 实现;单测可注入桩以独立验证签名/摘要/nonce/host 半边(无需伪造真 Nitro 文档)。
 */
export function verifyTeeExchange(
  input: TeeVerifyInput,
  deps: { verifyAttestationDoc?: AttestationVerifier } = {},
): TeeVerifyResult {
  const verifyAttestationDoc = deps.verifyAttestationDoc ?? (realVerifyAttestationDoc as AttestationVerifier);
  const t = input.proof;
  const full = input.requestBody !== undefined;
  const mode: TeeVerifyResult['mode'] = full ? 'full' : 'response-only';
  const checks: TeeCheck[] = [];

  // ① attestation:COSE/P-384 链到 AWS 根 + 有效期 + PCR0 == 审计值。异常不抛 —— 收成失败检查项。
  let att: AttestationVerdict | undefined;
  try {
    att = verifyAttestationDoc(b64(t.attestation), { now: input.now });
  } catch (err) {
    att = undefined;
    checks.push({ name: '远程证明', ok: false, detail: `attestation 解析/验证异常:${(err as Error).message}` });
  }
  if (att) {
    const chainOk = att.sigOk && att.chainOk && att.rootSelf && att.rootPinned;
    checks.push({ name: '远程证明', ok: chainOk, detail: chainOk ? `COSE/P-384 链到 AWS 根(指纹 ${att.rootFingerprint?.slice(0, 11)}…)` : 'attestation 链校验失败' });
    checks.push({ name: '证书有效期', ok: !!att.timeValid, detail: att.timeValid ? `链上证书均在有效期内(叶 notAfter ${att.leafNotAfter})` : `证书过期/未生效(叶 notAfter ${att.leafNotAfter})——无法确认新鲜` });
    const pcr0Ok = att.pcr0 === input.expectedPcr0;
    checks.push({ name: 'PCR0 比对', ok: pcr0Ok, detail: pcr0Ok ? 'PCR0 == 审计值(跑的是审计镜像)' : `PCR0 不符: ${String(att.pcr0).slice(0, 12)}… ≠ ${input.expectedPcr0.slice(0, 12)}…` });
    // ② 签名公钥被 attestation 背书
    const bound = !!att.publicKey && att.publicKey === t.public_key;
    checks.push({ name: '公钥绑定', ok: bound, detail: bound ? '签名公钥 == attestation 背书的公钥' : '签名公钥与 attestation 不符(换了把没被认证的钥匙)' });
    // ③ nonce 绑定:att 内嵌 nonce == proof 顶层 nonce(均被签名覆盖)。relay 端 nonce,一致性核对。
    const nonceOk = att.nonce === t.nonce;
    checks.push({ name: 'nonce 绑定', ok: nonceOk, detail: nonceOk ? 'att 内嵌 nonce == proof 顶层 nonce(均被签名覆盖)' : `nonce 不符:proof=${String(t.nonce).slice(0, 10)}… att=${String(att.nonce).slice(0, 10)}…(拼接/伪造)` });
  }

  // ④ 上游 host:签名覆盖、直接读。给了 expectedHost 则比对,否则展示由你判断。
  if (input.expectedHost) {
    const hostOk = t.upstream_host.toLowerCase() === input.expectedHost.toLowerCase();
    checks.push({ name: '上游 host', ok: hostOk, detail: hostOk ? `签名覆盖的上游 host == ${input.expectedHost}(path ${t.upstream_path})` : `上游 host = ${t.upstream_host},≠ 期望的 ${input.expectedHost}` });
  } else {
    checks.push({ name: '上游 host', ok: true, detail: `签名覆盖的上游 host = ${t.upstream_host}(path ${t.upstream_path};请自行核对是否官方端点)` });
  }

  // ⑤ 响应签名:对「重建声明」验签 + 收到字节哈希核对。
  checks.push(verifySignatureCheck(t, input.responseBody));

  // ⑥ 请求绑定(full 档):你发的 body 哈希 == 签名覆盖的 request_body_sha256。
  if (full) {
    const reqOk = sha256(input.requestBody!).toString('hex') === t.request_body_sha256;
    checks.push({ name: '请求绑定', ok: reqOk, detail: reqOk ? '你发的请求体哈希 == 签名覆盖值(答的就是你这条请求)' : '你的请求体哈希 ≠ 签名覆盖值(请求被改 / 不是这条)' });
  }

  const ok = checks.length > 0 && checks.every((c) => c.ok);
  return {
    ok,
    mode,
    checks,
    attestation: { moduleId: att?.moduleId, pcr0: att?.pcr0, publicKey: att?.publicKey, nonce: att?.nonce },
    provenance: {
      upstreamHost: t.upstream_host,
      upstreamPath: t.upstream_path,
      httpMethod: t.http_method,
      httpStatus: t.http_status,
      respContentType: t.resp_content_type,
    },
  };
}

// 重建 v2 声明(用 proof 自报的字段值)→ 用绑定公钥验签;再核对收到的字节哈希 == 签名覆盖的响应体哈希。
function verifySignatureCheck(t: TeeProofWire, responseBody: Buffer): TeeCheck {
  try {
    const statement = buildV2Statement({
      nonceB64: t.nonce,
      upstreamHost: t.upstream_host,
      upstreamPath: t.upstream_path,
      httpMethod: t.http_method,
      httpStatus: t.http_status,
      respContentType: t.resp_content_type,
      requestBodySha256Hex: t.request_body_sha256,
      responseBodySha256Hex: t.response_body_sha256,
    });
    const pub = createPublicKey({ key: b64(t.public_key), format: 'der', type: 'spki' });
    const sigOk = edVerify(null, statement, pub, b64(t.signature));
    if (!sigOk) return { name: '响应签名', ok: false, detail: '验签失败:声明与签名不符(被改过)' };
    const bodyOk = sha256(responseBody).toString('hex') === t.response_body_sha256;
    if (!bodyOk) {
      return { name: '响应签名', ok: false, detail: '签名有效但你收到的响应体哈希 ≠ 签名覆盖值(响应被改过)' };
    }
    return { name: '响应签名', ok: true, detail: '声明验签通过,且你收到的响应体哈希吻合' };
  } catch (err) {
    return { name: '响应签名', ok: false, detail: `验签异常:${(err as Error).message}` };
  }
}

// production 流式下发:relay 原生透传的上游 SSE 字节之后附一条流末事件
//   event: tee.proof\ndata: {json}\n\n
// 验证方必须先剥掉这条末尾事件,再对**其余字节**(= 飞地签名的上游原文)重算 H(respBody)。
// 从末尾定位(proof 永远是最后一条事件),避免上游内容里偶现同名字串。
export const TEE_PROOF_EVENT = 'tee.proof';

export interface ParsedTeeProofStream {
  body: Buffer; // 上游原文(飞地签名的字节)
  proof?: TeeProofWire; // 末尾 tee.proof 事件(无则 undefined)
}

export function parseTeeProofEvent(streamText: string): ParsedTeeProofStream {
  const marker = `event: ${TEE_PROOF_EVENT}\n`;
  const idx = streamText.lastIndexOf(marker);
  if (idx < 0) return { body: Buffer.from(streamText, 'utf8') };
  const before = streamText.slice(0, idx);
  const eventBlock = streamText.slice(idx);
  const dataLine = eventBlock.split('\n').find((line) => line.startsWith('data: '));
  let proof: TeeProofWire | undefined;
  if (dataLine) {
    try {
      proof = JSON.parse(dataLine.slice('data: '.length)) as TeeProofWire;
    } catch {
      proof = undefined;
    }
  }
  return { body: Buffer.from(before, 'utf8'), proof };
}
