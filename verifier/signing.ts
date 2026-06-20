// 签名覆盖规范(v2 字段分解) —— the v2 field-decomposition signing statement.
//
// 飞地(Rust `build_v2_statement`)、本文件(verifier)、浏览器(docs/tee-verify.html)三处必须**逐字节**
// 产出同一份声明,否则验签必崩 —— 自证的承重墙。golden 向量锁死:`signing-vectors.json` cases_v2 +
// `signing-vectors.test.ts` + 飞地 `#[cfg(test)] mod golden`。
//
// 路由/来源明文可还原、请求体/响应体各自哈希,一个 Ed25519 盖整份声明。
//
// 声明逐行布局(每行含末尾 \n,包括域名行与最后一行):
//   tee-exchange-v2\n
//   nonce=<base64>\n
//   upstream-host=<host 小写>\n
//   upstream-path=<path,只取 ? 之前>\n
//   http-method=<METHOD 大写>\n
//   http-status=<十进制>\n
//   resp-content-type=<原值>\n
//   request-body-sha256=<hex>\n
//   response-body-sha256=<hex>\n
// Ed25519 直接对整块字节签。

import { createHash } from 'node:crypto';

export function sha256(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

export const SIGNING_DOMAIN_V2 = 'tee-exchange-v2';

// 只取 ? 之前的路径(query string 不进签名)。
export function pathWithoutQuery(path: string): string {
  const q = path.indexOf('?');
  return q >= 0 ? path.slice(0, q) : path;
}

// 声明的字段视图。签名方与验证方都用这些**确切值**重建同一份声明:
//  · 签名方(飞地):host/path/method/status/ct 来自本次出口;两个 *Sha256Hex 由 body 现算。
//  · 验证方:全部取自 proof(再额外用收到的字节/自己的请求体复核两个哈希)。
export interface V2StatementFields {
  nonceB64: string;
  upstreamHost: string;
  upstreamPath: string; // 传入可含 query,内部 strip
  httpMethod: string;
  httpStatus: number;
  respContentType: string;
  requestBodySha256Hex: string;
  responseBodySha256Hex: string;
}

// 承重墙:从字段值重建待签声明字节。**所有可还原值禁含 CR/LF**(飞地入站已拒;调用方保证)。
export function buildV2Statement(f: V2StatementFields): Buffer {
  const lines = [
    SIGNING_DOMAIN_V2,
    `nonce=${f.nonceB64}`,
    `upstream-host=${f.upstreamHost.toLowerCase()}`,
    `upstream-path=${pathWithoutQuery(f.upstreamPath)}`,
    `http-method=${f.httpMethod.toUpperCase()}`,
    `http-status=${String(f.httpStatus)}`,
    `resp-content-type=${f.respContentType}`,
    `request-body-sha256=${f.requestBodySha256Hex}`,
    `response-body-sha256=${f.responseBodySha256Hex}`,
  ];
  return Buffer.from(lines.map((l) => `${l}\n`).join(''), 'utf8');
}

// 签名方便利:给 body,现算两段哈希并产出待签声明(enclave 走这条;golden 也走这条生成期望值)。
export function computeV2SigningMaterial(input: {
  nonceB64: string;
  upstreamHost: string;
  upstreamPath: string;
  httpMethod: string;
  httpStatus: number;
  respContentType: string;
  requestBody: Buffer;
  responseBody: Buffer;
}): {
  statement: Buffer;
  digests: { requestBody: Buffer; responseBody: Buffer };
} {
  const requestBody = sha256(input.requestBody);
  const responseBody = sha256(input.responseBody);
  const statement = buildV2Statement({
    nonceB64: input.nonceB64,
    upstreamHost: input.upstreamHost,
    upstreamPath: input.upstreamPath,
    httpMethod: input.httpMethod,
    httpStatus: input.httpStatus,
    respContentType: input.respContentType,
    requestBodySha256Hex: requestBody.toString('hex'),
    responseBodySha256Hex: responseBody.toString('hex'),
  });
  return { statement, digests: { requestBody, responseBody } };
}
