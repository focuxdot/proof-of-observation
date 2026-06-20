// 生成 signing-vectors.json —— 用 signing.ts 算出每个固定输入的「标准答案」并冻结入库(v2 字段分解)。
//
//   npx tsx signing-vectors.gen.ts
//
// 这份冻结答案是飞地(Rust, enclave/src/main.rs 的 #[cfg(test)] mod golden)、验证器
// (TS, signing-vectors.test.ts)与浏览器(tests/tee_verify_html_v2_align.test.ts)共同的对账基准:
// 三边各自重算,都必须 == 这里 cases_v2 的值。谁把声明布局改歪,谁的测试当场红 —— 签名「承重墙」的 CI 防漂移线。
//
// ⚠️ 只在**有意修改 v2 声明布局**(buildV2Statement 的字段/顺序/归一)时才重跑本脚本。那是破坏性变更:
//    三处实现需同步、客户端验证器需重发、PCR0 会变。平时不要重跑——否则等于把改歪的新行为祝福成标准答案。
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { computeV2SigningMaterial, SIGNING_DOMAIN_V2 } from './signing.ts';

const b = (s: string) => Buffer.from(s, 'utf8').toString('base64');
// 16 字节 ASCII → 合法 base64 nonce（签名把 nonce 的 base64 串原样拼进声明，这里取真实的 16B）
const nonce = (s: string) => Buffer.from(s, 'utf8').toString('base64');

interface CaseV2 {
  name: string;
  note: string;
  nonce_b64: string;
  upstream_host: string;
  upstream_path: string;
  http_method: string;
  http_status: number;
  resp_content_type: string;
  request_body_b64: string;
  response_body_b64: string;
}

const casesV2: CaseV2[] = [
  {
    name: 'v2-basic',
    note: 'host 小写、path 去 query(?beta=true 丢弃)、method 大写;content-type 含 charset',
    nonce_b64: nonce('0123456789abcdef'),
    upstream_host: 'API.Example.Com',
    upstream_path: '/v1/chat?beta=true',
    http_method: 'post',
    http_status: 200,
    resp_content_type: 'text/event-stream; charset=utf-8',
    request_body_b64: b('{"model":"example","stream":true}'),
    response_body_b64: b('event: message_start\ndata: {}\n\n'),
  },
  {
    name: 'v2-plain',
    note: '已规范化输入原样:host 已小写、method 已大写、无 query 的 path 原样;content-type 无 charset',
    nonce_b64: nonce('nonce-no-spki-00'),
    upstream_host: 'api.example.com',
    upstream_path: '/v1/chat',
    http_method: 'POST',
    http_status: 200,
    resp_content_type: 'text/event-stream',
    request_body_b64: b('{"model":"example"}'),
    response_body_b64: b('data: hi\n\n'),
  },
  {
    name: 'v2-empty-bodies',
    note: '空请求体/空响应体的 sha256',
    nonce_b64: nonce('empty-bodies-v2A'),
    upstream_host: 'api.example.com',
    upstream_path: '/v1/chat',
    http_method: 'POST',
    http_status: 204,
    resp_content_type: 'application/json',
    request_body_b64: '',
    response_body_b64: '',
  },
  {
    name: 'v2-unicode',
    note: '非 ASCII body,两边按同一 UTF-8 字节哈希',
    nonce_b64: nonce('unicode-nonce-v2'),
    upstream_host: 'api.example.com',
    upstream_path: '/v1/chat',
    http_method: 'POST',
    http_status: 200,
    resp_content_type: 'application/json',
    request_body_b64: b('{"q":"什么是远程证明？"}'),
    response_body_b64: b('{"a":"隔着网线证明我没被改过"}'),
  },
];

const outV2 = casesV2.map((c) => {
  const { statement, digests } = computeV2SigningMaterial({
    nonceB64: c.nonce_b64,
    upstreamHost: c.upstream_host,
    upstreamPath: c.upstream_path,
    httpMethod: c.http_method,
    httpStatus: c.http_status,
    respContentType: c.resp_content_type,
    requestBody: Buffer.from(c.request_body_b64, 'base64'),
    responseBody: Buffer.from(c.response_body_b64, 'base64'),
  });
  return {
    ...c,
    expected: {
      statement: statement.toString('utf8'),
      statement_hex: statement.toString('hex'),
      request_body_sha256: digests.requestBody.toString('hex'),
      response_body_sha256: digests.responseBody.toString('hex'),
    },
  };
});

const outPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'enclave', 'signing-vectors.json');
writeFileSync(
  outPath,
  JSON.stringify(
    {
      _comment: '由 signing-vectors.gen.ts 从 signing.ts 生成；勿手改。改 v2 声明布局才重跑(破坏性)。',
      domain_v2: SIGNING_DOMAIN_V2,
      cases_v2: outV2,
    },
    null,
    2,
  ) + '\n',
);
console.log('wrote', outPath, '—', outV2.length, 'v2 cases\n');
for (const c of outV2) {
  console.log('#'.repeat(4), c.name);
  console.log('statement:\n' + c.expected.statement);
}
