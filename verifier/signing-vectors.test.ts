// Golden 向量 · TS 侧(v2 字段分解)—— 验证器用的 signing.ts 必须算出与冻结答案逐字节一致的结果。
//
// 配对:飞地 Rust ../enclave/src/main.rs 的 #[cfg(test)] mod golden + 浏览器 tests/tee_verify_html_v2_align.test.ts。
// 三边都钉在 signing-vectors.json 的 cases_v2 上 → 任一边把声明布局改歪,其测试当场红。fixture 由 signing-vectors.gen.ts 生成。
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { computeV2SigningMaterial, buildV2Statement } from './signing.ts';

const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'enclave', 'signing-vectors.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  cases_v2: Array<{
    name: string;
    nonce_b64: string;
    upstream_host: string;
    upstream_path: string;
    http_method: string;
    http_status: number;
    resp_content_type: string;
    request_body_b64: string;
    response_body_b64: string;
    expected: { statement: string; statement_hex: string; request_body_sha256: string; response_body_sha256: string };
  }>;
};

describe('signing golden vectors v2 — 字段分解声明 == 冻结答案', () => {
  expect(fixture.cases_v2.length).toBeGreaterThan(0);
  for (const c of fixture.cases_v2) {
    it(c.name, () => {
      const requestBody = Buffer.from(c.request_body_b64, 'base64');
      const responseBody = Buffer.from(c.response_body_b64, 'base64');
      // 签名方路径:body → 哈希 → 声明,逐字节对答案卡
      const { statement, digests } = computeV2SigningMaterial({
        nonceB64: c.nonce_b64,
        upstreamHost: c.upstream_host,
        upstreamPath: c.upstream_path,
        httpMethod: c.http_method,
        httpStatus: c.http_status,
        respContentType: c.resp_content_type,
        requestBody,
        responseBody,
      });
      expect(statement.toString('utf8')).toBe(c.expected.statement);
      expect(statement.toString('hex')).toBe(c.expected.statement_hex);
      expect(digests.requestBody.toString('hex')).toBe(c.expected.request_body_sha256);
      expect(digests.responseBody.toString('hex')).toBe(c.expected.response_body_sha256);
      // 验证方路径:只用 proof 里的两段哈希(不碰 body)重建声明,必须一致
      const fromHashes = buildV2Statement({
        nonceB64: c.nonce_b64,
        upstreamHost: c.upstream_host,
        upstreamPath: c.upstream_path,
        httpMethod: c.http_method,
        httpStatus: c.http_status,
        respContentType: c.resp_content_type,
        requestBodySha256Hex: c.expected.request_body_sha256,
        responseBodySha256Hex: c.expected.response_body_sha256,
      });
      expect(fromHashes.toString('hex')).toBe(c.expected.statement_hex);
    });
  }
});
