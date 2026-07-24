// 本地校验代理的端到端单测:假上游 + 经代理打真请求。
//
// attestation 半边用**注入桩**(无法伪造真 Nitro 文档);签名半边用真 Ed25519 + 真 signing.ts。
// 假上游(模拟 relay)**自生成 nonce** 并对它签名;代理不注入头,从 proof 读 nonce 验一致性 —— 覆盖 生成→绑定→验签 闭环。

import { afterEach, describe, expect, it } from 'vitest';
import http from 'node:http';
import { generateKeyPairSync, randomBytes, sign as edSign } from 'node:crypto';
import { createVerifyingProxy } from './tee-verify-proxy.ts';
import {
  TEE_PROOF_EVENT,
  WOKEY_SSE_TRANSPORT_KEEPALIVE_V1,
  type AttestationVerifier,
} from './tee-verify-core.ts';
import { computeV2SigningMaterial } from './signing.ts';

const PCR0 = 'aeb9e595deadbeef';
const HOST = 'api.example.com';
const PATH = '/v1/messages';
const REQUEST_BODY = Buffer.from('{"model":"example","stream":true}', 'utf8');

const servers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

function track<T extends http.Server>(s: T): T { servers.push(s); return s; }
function listen(s: http.Server): Promise<number> {
  return new Promise((resolve) => s.listen(0, '127.0.0.1', () => resolve((s.address() as any).port)));
}
function postThrough(port: number, path: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json' } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () => resolve({ status: res.statusCode || 0, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

// 用真 Ed25519 + 真 v2 声明对给定 nonce/响应体造一个签名合法的 proof。
function signProof(args: { nonce: string; body: Buffer; privateKey: any; pubB64: string }): string {
  const { statement, digests } = computeV2SigningMaterial({
    nonceB64: args.nonce,
    upstreamHost: HOST,
    upstreamPath: PATH,
    httpMethod: 'POST',
    httpStatus: 200,
    respContentType: 'text/event-stream',
    requestBody: REQUEST_BODY,
    responseBody: args.body,
  });
  const signature = edSign(null, statement, args.privateKey).toString('base64');
  const wire = {
    v: 2,
    alg: 'ed25519',
    public_key: args.pubB64,
    nonce: args.nonce,
    upstream_host: HOST,
    upstream_path: PATH,
    http_method: 'POST',
    http_status: 200,
    resp_content_type: 'text/event-stream',
    request_body_sha256: digests.requestBody.toString('hex'),
    response_body_sha256: digests.responseBody.toString('hex'),
    signature,
    attestation: 'AA==', // 桩忽略内容
    pcr0: PCR0,
  };
  return `event: ${TEE_PROOF_EVENT}\ndata: ${JSON.stringify(wire)}\n\n`;
}

// att 桩:声称背书 publicKey、对 nonceGetter() 这个 nonce、跑 PCR0 镜像。nonce 在请求中途才确定 → 用 getter。
function stubAtt(over: { publicKey: string; nonce: () => string; pcr0?: string; chainOk?: boolean; sigOk?: boolean }): AttestationVerifier {
  return () => ({
    ok: true,
    sigOk: over.sigOk ?? true,
    chainOk: over.chainOk ?? true,
    rootSelf: true,
    rootPinned: true,
    timeValid: true,
    leafNotAfter: '2099-01-01T00:00:00Z',
    moduleId: 'i-test-enc',
    pcr0: over.pcr0 ?? PCR0,
    nonce: over.nonce(),
    publicKey: over.publicKey,
    rootFingerprint: '64:1A:03:21',
  });
}

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { privateKey, pubB64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64') };
}

describe('createVerifyingProxy (fail-open)', () => {
  it('verifies a genuine attested stream (nonce read from proof) and strips the proof from client output', async () => {
    const { privateKey, pubB64 } = newKey();
    const upstreamBody = Buffer.from('event: message_start\ndata: {"a":1}\n\nevent: message_stop\ndata: {}\n\n', 'utf8');
    let relayNonce = '';
    const upstream = track(http.createServer((req, res) => {
      relayNonce = randomBytes(16).toString('base64'); // 模拟 relay 自生成 nonce
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(upstreamBody);
      res.write(signProof({ nonce: relayNonce, body: upstreamBody, privateKey, pubB64 }));
      res.end();
    }));
    const upPort = await listen(upstream);

    const verdicts: any[] = [];
    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      verifyAttestationDoc: stubAtt({ publicKey: pubB64, nonce: () => relayNonce }),
      onVerdict: (v, ctx) => verdicts.push({ v, ctx }),
    }));
    const proxyPort = await listen(proxy);

    const res = await postThrough(proxyPort, '/v1/messages', '{"x":1}');
    expect(relayNonce.length).toBeGreaterThan(0); // relay 端确实生成了 nonce
    expect(res.body).toBe(upstreamBody.toString('utf8')); // 逐字节还原上游原文
    expect(res.body).not.toContain('tee.proof'); // 带外 proof 已剥,客户端看不到
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].v.ok, JSON.stringify(verdicts[0].v.checks)).toBe(true);
    expect(verdicts[0].ctx.nonce).toBe(relayNonce);
    expect(verdicts[0].ctx.attested).toBe(true);
  });

  it('detects a tampered body but still passes it through (fail-open)', async () => {
    const { privateKey, pubB64 } = newKey();
    const original = Buffer.from('event: message_stop\ndata: {"ok":1}\n\n', 'utf8');
    const tampered = Buffer.from('event: message_stop\ndata: {"evil":1}\n\n', 'utf8');
    let relayNonce = '';
    const upstream = track(http.createServer((req, res) => {
      relayNonce = randomBytes(16).toString('base64'); // 模拟 relay 自生成 nonce
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(tampered); // 发出去的是篡改版……
      res.write(signProof({ nonce: relayNonce, body: original, privateKey, pubB64 })); // ……但 proof 签的是原版
      res.end();
    }));
    const upPort = await listen(upstream);

    const verdicts: any[] = [];
    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      verifyAttestationDoc: stubAtt({ publicKey: pubB64, nonce: () => relayNonce }),
      onVerdict: (v, ctx) => verdicts.push({ v, ctx }),
    }));
    const proxyPort = await listen(proxy);

    const res = await postThrough(proxyPort, '/v1/messages', '{"x":1}');
    expect(res.body).toBe(tampered.toString('utf8')); // fail-open:照样交给客户端
    expect(verdicts[0].v.ok).toBe(false);
    expect(verdicts[0].v.checks.find((c: any) => c.name === '响应签名')?.ok).toBe(false);
  });

  it('passes non-streaming responses through verbatim and reports unattested', async () => {
    const upstream = track(http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"choices":[{"message":{"content":"hi"}}]}');
    }));
    const upPort = await listen(upstream);

    const verdicts: any[] = [];
    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      verifyAttestationDoc: stubAtt({ publicKey: 'x', nonce: () => '' }),
      onVerdict: (v, ctx) => verdicts.push({ v, ctx }),
    }));
    const proxyPort = await listen(proxy);

    const res = await postThrough(proxyPort, '/v1/chat/completions', '{"x":1}');
    expect(res.body).toBe('{"choices":[{"message":{"content":"hi"}}]}');
    expect(verdicts[0].v).toBeNull();
    expect(verdicts[0].ctx.attested).toBe(false);
  });

  it('preserves byte-exactness across the holdback boundary (body ≫ holdback)', async () => {
    const { privateKey, pubB64 } = newKey();
    const line = 'event: chunk\ndata: ' + 'x'.repeat(120) + '\n\n';
    const upstreamBody = Buffer.from(line.repeat(40), 'utf8'); // ~5.6KB,远大于下方 holdback
    let relayNonce = '';
    const upstream = track(http.createServer((req, res) => {
      relayNonce = randomBytes(16).toString('base64'); // 模拟 relay 自生成 nonce
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      // 分多片写,跨越 holdback 边界
      for (let i = 0; i < upstreamBody.length; i += 700) res.write(upstreamBody.subarray(i, i + 700));
      res.write(signProof({ nonce: relayNonce, body: upstreamBody, privateKey, pubB64 }));
      res.end();
    }));
    const upPort = await listen(upstream);

    const verdicts: any[] = [];
    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      holdback: 1024,
      verifyAttestationDoc: stubAtt({ publicKey: pubB64, nonce: () => relayNonce }),
      onVerdict: (v) => verdicts.push(v),
    }));
    const proxyPort = await listen(proxy);

    const res = await postThrough(proxyPort, '/v1/messages', '{"x":1}');
    expect(res.body).toBe(upstreamBody.toString('utf8')); // 整段逐字节还原,proof 已剥
    expect(res.body).not.toContain('tee.proof');
    expect(verdicts[0].ok, JSON.stringify(verdicts[0].checks)).toBe(true);
  });

  it('keeps raw passthrough coordinates aligned when a transport keepalive precedes a body larger than holdback', async () => {
    const { privateKey, pubB64 } = newKey();
    const line = 'event: chunk\ndata: ' + 'x'.repeat(120) + '\n\n';
    const upstreamBody = Buffer.from(line.repeat(40), 'utf8');
    const transportKeepalive = Buffer.from(WOKEY_SSE_TRANSPORT_KEEPALIVE_V1, 'utf8');
    let relayNonce = '';
    const upstream = track(http.createServer((_req, res) => {
      relayNonce = randomBytes(16).toString('base64');
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(transportKeepalive);
      for (let i = 0; i < upstreamBody.length; i += 700) {
        res.write(upstreamBody.subarray(i, i + 700));
      }
      res.write(signProof({ nonce: relayNonce, body: upstreamBody, privateKey, pubB64 }));
      res.end();
    }));
    const upPort = await listen(upstream);

    const verdicts: any[] = [];
    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      holdback: 1024,
      verifyAttestationDoc: stubAtt({ publicKey: pubB64, nonce: () => relayNonce }),
      onVerdict: (v) => verdicts.push(v),
    }));
    const proxyPort = await listen(proxy);

    const res = await postThrough(proxyPort, '/v1/messages', '{"x":1}');
    expect(res.body).toBe(Buffer.concat([transportKeepalive, upstreamBody]).toString('utf8'));
    expect(res.body).not.toContain('tee.proof');
    expect(verdicts[0].ok, JSON.stringify(verdicts[0].checks)).toBe(true);
  });

  it('warns when holdback is too small to cover the proof (but the verdict is still correct)', async () => {
    const { privateKey, pubB64 } = newKey();
    const upstreamBody = Buffer.from('event: message_stop\ndata: {"ok":1}\n\n', 'utf8');
    let relayNonce = '';
    const upstream = track(http.createServer((req, res) => {
      relayNonce = randomBytes(16).toString('base64'); // 模拟 relay 自生成 nonce
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(upstreamBody);
      res.write(signProof({ nonce: relayNonce, body: upstreamBody, privateKey, pubB64 }));
      res.end();
    }));
    const upPort = await listen(upstream);

    const warnings: string[] = [];
    const verdicts: any[] = [];
    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      holdback: 8, // 远小于 proof 体积 → 部分 proof 会被误转
      verifyAttestationDoc: stubAtt({ publicKey: pubB64, nonce: () => relayNonce }),
      onWarning: (m) => warnings.push(m),
      onVerdict: (v) => verdicts.push(v),
    }));
    const proxyPort = await listen(proxy);

    await postThrough(proxyPort, '/v1/messages', '{"x":1}');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('holdback');
    expect(verdicts[0].ok, JSON.stringify(verdicts[0].checks)).toBe(true); // 判定用完整 body,仍正确
  });

  it('tears down the upstream request when the client disconnects mid-stream', async () => {
    let resolveClosed!: () => void;
    const upstreamClosed = new Promise<void>((r) => { resolveClosed = r; });
    const upstream = track(http.createServer((req, res) => {
      req.on('close', () => resolveClosed()); // 上游请求被 abort 时触发
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('event: chunk\ndata: hi\n\n');
      // 故意不 end —— 保持打开,直到客户端断开 → 代理须 abort 上游
    }));
    const upPort = await listen(upstream);

    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      holdback: 0, // 立即转发,客户端才收得到首片并断开
      verifyAttestationDoc: stubAtt({ publicKey: 'x', nonce: () => '' }),
    }));
    const proxyPort = await listen(proxy);

    await new Promise<void>((resolve) => {
      const req = http.request(
        { host: '127.0.0.1', port: proxyPort, path: '/v1/messages', method: 'POST' },
        (res) => { res.once('data', () => { req.destroy(); resolve(); }); }, // 收到首片即断开
      );
      req.on('error', () => {/* destroy 触发的 ECONNRESET,忽略 */});
      req.end('{"x":1}');
    });
    await upstreamClosed; // 无 abort 修复则永不 resolve → 超时失败
  });
});

describe('createVerifyingProxy (--enforce / fail-closed)', () => {
  it('blocks a tampered attested response with 502', async () => {
    const { privateKey, pubB64 } = newKey();
    const original = Buffer.from('event: message_stop\ndata: {"ok":1}\n\n', 'utf8');
    const tampered = Buffer.from('event: message_stop\ndata: {"evil":1}\n\n', 'utf8');
    let relayNonce = '';
    const upstream = track(http.createServer((req, res) => {
      relayNonce = randomBytes(16).toString('base64'); // 模拟 relay 自生成 nonce
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(tampered);
      res.write(signProof({ nonce: relayNonce, body: original, privateKey, pubB64 }));
      res.end();
    }));
    const upPort = await listen(upstream);

    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      enforce: true,
      verifyAttestationDoc: stubAtt({ publicKey: pubB64, nonce: () => relayNonce }),
    }));
    const proxyPort = await listen(proxy);

    const res = await postThrough(proxyPort, '/v1/messages', '{"x":1}');
    expect(res.status).toBe(502);
    expect(res.body).toContain('tee_verification_failed');
    expect(res.body).not.toContain('evil'); // 篡改体未泄给客户端
  });

  it('lets a genuine attested response through (stripped) under enforce', async () => {
    const { privateKey, pubB64 } = newKey();
    const upstreamBody = Buffer.from('event: message_stop\ndata: {"ok":1}\n\n', 'utf8');
    let relayNonce = '';
    const upstream = track(http.createServer((req, res) => {
      relayNonce = randomBytes(16).toString('base64'); // 模拟 relay 自生成 nonce
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(upstreamBody);
      res.write(signProof({ nonce: relayNonce, body: upstreamBody, privateKey, pubB64 }));
      res.end();
    }));
    const upPort = await listen(upstream);

    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      enforce: true,
      verifyAttestationDoc: stubAtt({ publicKey: pubB64, nonce: () => relayNonce }),
    }));
    const proxyPort = await listen(proxy);

    const res = await postThrough(proxyPort, '/v1/messages', '{"x":1}');
    expect(res.status).toBe(200);
    expect(res.body).toBe(upstreamBody.toString('utf8'));
    expect(res.body).not.toContain('tee.proof');
  });

  it('passes non-attested responses through under enforce (does not block what it cannot attest)', async () => {
    const upstream = track(http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    }));
    const upPort = await listen(upstream);

    const proxy = track(createVerifyingProxy({
      upstream: `http://127.0.0.1:${upPort}`,
      expectedPcr0: PCR0,
      enforce: true,
      verifyAttestationDoc: stubAtt({ publicKey: 'x', nonce: () => '' }),
    }));
    const proxyPort = await listen(proxy);

    const res = await postThrough(proxyPort, '/v1/chat/completions', '{"x":1}');
    expect(res.status).toBe(200);
    expect(res.body).toBe('{"ok":true}');
  });
});
