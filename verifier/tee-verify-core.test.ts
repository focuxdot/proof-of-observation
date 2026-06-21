// 共享验证核心(v2 字段分解)+ 流式 proof 解析的单测。
//
// attestation 半边(真 COSE/P-384)用**注入桩**覆盖 —— 无法伪造真 Nitro 文档,但能完整测
// 编排 + 公钥绑定/PCR0/nonce 三项;真文档半边由 verify-real-bundle 对真 bundle 验。
// 签名半边用真 Ed25519(自生成密钥)+ signing.ts 真 v2 声明,验的是真验签逻辑。

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import {
  verifyTeeExchange,
  parseTeeProofCapture,
  parseTeeProofEvent,
  parseTeeProofMultipartResponse,
  TEE_PROOF_EVENT,
  type TeeProofWire,
  type AttestationVerifier,
} from './tee-verify-core.ts';
import { computeV2SigningMaterial } from './signing.ts';

const NONCE = Buffer.from('a-fresh-16b-nonce').toString('base64');
const PCR0 = 'aeb9e595deadbeef';
const HOST = 'api.example.com';
const PATH = '/v1/messages';
const REQUEST_BODY = Buffer.from('{"model":"example","stream":true}', 'utf8');
const RESPONSE_BODY = Buffer.from('event: message_stop\ndata: {}\n\n', 'utf8');

// 用真 Ed25519 + 真 v2 声明造一个签名合法的 proof;att 桩声称背书这把公钥/PCR0/nonce。
function makeSigned(overrides: { requestBody?: Buffer; responseBody?: Buffer } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const requestBody = overrides.requestBody ?? REQUEST_BODY;
  const responseBody = overrides.responseBody ?? RESPONSE_BODY;
  const { statement, digests } = computeV2SigningMaterial({
    nonceB64: NONCE,
    upstreamHost: HOST,
    upstreamPath: PATH,
    httpMethod: 'POST',
    httpStatus: 200,
    respContentType: 'text/event-stream',
    requestBody,
    responseBody,
  });
  const signature = edSign(null, statement, privateKey).toString('base64');
  const proof: TeeProofWire = {
    v: 2,
    alg: 'ed25519',
    public_key: pubB64,
    nonce: NONCE,
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
  return { proof, pubB64, requestBody, responseBody };
}

function stubAtt(over: Partial<ReturnType<AttestationVerifier>> & { publicKey?: string }): AttestationVerifier {
  return () => ({
    ok: true, sigOk: true, chainOk: true, rootSelf: true, rootPinned: true, timeValid: true,
    leafNotAfter: '2099-01-01T00:00:00Z', moduleId: 'i-test-enc', pcr0: PCR0, nonce: NONCE,
    rootFingerprint: '64:1A:03:21', ...over,
  });
}

describe('verifyTeeExchange v2 (full mode)', () => {
  it('passes every check for a genuine exchange (incl. host + request binding)', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: HOST, requestBody, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.mode).toBe('full');
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.checks.find((c) => c.name === '上游 host')?.ok).toBe(true);
    expect(r.checks.find((c) => c.name === '请求绑定')?.ok).toBe(true);
    expect(r.provenance.upstreamHost).toBe(HOST);
    expect(r.provenance.upstreamPath).toBe(PATH);
  });

  it('fails the signature check when the response body is tampered', () => {
    const { proof, pubB64, requestBody } = makeSigned();
    const tampered = Buffer.from('event: message_stop\ndata: {"evil":1}\n\n', 'utf8');
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: HOST, requestBody, responseBody: tampered, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '响应签名')?.ok).toBe(false);
  });

  it('fails request binding when a different request body is presented', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const otherReq = Buffer.from('{"model":"cheap"}', 'utf8');
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: HOST, requestBody: otherReq, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '请求绑定')?.ok).toBe(false);
  });

  it('fails host binding when expectedHost differs', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: 'api.different.com', requestBody, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '上游 host')?.ok).toBe(false);
  });
});

describe('verifyTeeExchange v2 (response-only mode)', () => {
  it('verifies untampered response from captured bytes alone; host is displayed (ok)', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.mode).toBe('response-only');
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    // response-only 没有请求绑定项
    expect(r.checks.find((c) => c.name === '请求绑定')).toBeUndefined();
    // host 这关只展示(无 expectedHost),ok=true 且 detail 带签名覆盖的 host
    const hostCheck = r.checks.find((c) => c.name === '上游 host');
    expect(hostCheck?.ok).toBe(true);
    expect(hostCheck?.detail).toContain(HOST);
  });

  it('rejects a wrong-image PCR0', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: 'cafe0000', responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64, pcr0: 'deadbeef' }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'PCR0 比对')?.ok).toBe(false);
  });

  it('rejects an unbound signing key (attestation endorses a different pubkey)', () => {
    const { proof, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: 'c29tZS1vdGhlci1rZXk=' }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '公钥绑定')?.ok).toBe(false);
  });

  it('rejects a spliced attestation (att.nonce != proof.nonce)', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64, nonce: Buffer.from('other-nonce!!!').toString('base64') }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'nonce 绑定')?.ok).toBe(false);
  });

  it('fails the attestation chain when the doc does not verify', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64, chainOk: false, sigOk: false }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '远程证明')?.ok).toBe(false);
  });
});

describe('parseTeeProofEvent', () => {
  it('splits the trailing tee.proof event from the upstream bytes', () => {
    const upstream = 'event: message_start\ndata: {"a":1}\n\nevent: message_stop\ndata: {}\n\n';
    const { proof, pubB64 } = makeSigned();
    const stream = upstream + `event: ${TEE_PROOF_EVENT}\ndata: ${JSON.stringify(proof)}\n\n`;
    const parsed = parseTeeProofEvent(stream);
    expect(parsed.body.toString('utf8')).toBe(upstream); // 逐字节还原上游原文
    expect(parsed.proof?.public_key).toBe(pubB64);
    expect(parsed.proof?.upstream_host).toBe(HOST);
  });

  it('splits proof from buffers without re-encoding the signed upstream bytes', () => {
    const upstream = Buffer.concat([
      Buffer.from('event: response.output_text.delta\r\ndata: {"delta":"', 'utf8'),
      Buffer.from([0xff, 0x00, 0xfe]),
      Buffer.from('"}\r\n\r\n', 'utf8'),
    ]);
    const { proof } = makeSigned({ responseBody: upstream });
    const suffix = Buffer.from(`event: ${TEE_PROOF_EVENT}\r\ndata: ${JSON.stringify(proof)}\r\n\r\n`, 'utf8');
    const parsed = parseTeeProofEvent(Buffer.concat([upstream, suffix]));

    expect(parsed.body).toEqual(upstream);
    expect(parsed.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('does not strip an invalid tee.proof-looking suffix', () => {
    const upstream = Buffer.from('event: response.output_text.delta\ndata: {"delta":"ok"}\n\n', 'utf8');
    const invalidSuffix = Buffer.from(`event: ${TEE_PROOF_EVENT}\ndata: {not-json}\n\n`, 'utf8');
    const whole = Buffer.concat([upstream, invalidSuffix]);

    const parsed = parseTeeProofEvent(whole);

    expect(parsed.proof).toBeUndefined();
    expect(parsed.body).toEqual(whole);
  });

  it('does not accept a proof event with unsigned trailing bytes', () => {
    const upstream = Buffer.from('event: response.output_text.delta\ndata: {"delta":"ok"}\n\n', 'utf8');
    const { proof } = makeSigned();
    const suffix = Buffer.from(`event: ${TEE_PROOF_EVENT}\ndata: ${JSON.stringify(proof)}\n\n`, 'utf8');
    const trailing = Buffer.from('event: response.output_text.delta\ndata: {"delta":"unsigned"}\n\n', 'utf8');
    const whole = Buffer.concat([upstream, suffix, trailing]);

    const parsed = parseTeeProofEvent(whole);

    expect(parsed.proof).toBeUndefined();
    expect(parsed.body).toEqual(whole);
  });

  it('returns no proof when the stream was not attested', () => {
    const upstream = 'event: message_stop\ndata: {}\n\n';
    const parsed = parseTeeProofEvent(upstream);
    expect(parsed.proof).toBeUndefined();
    expect(parsed.body.toString('utf8')).toBe(upstream);
  });

  it('parses multipart captures with raw response bytes and tee proof', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}\n', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const multipart = formatMultipart({
      rawBody,
      rawContentType: 'application/json; charset=utf-8',
      proof,
      boundary: 'proof-observation-test',
    });

    const parsed = parseTeeProofMultipartResponse(multipart.body, multipart.contentType);

    expect(parsed?.body).toEqual(rawBody);
    expect(parsed?.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('parses multipart captures by boundary when response Content-Length is stale', () => {
    const originalBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}\n', 'utf8');
    const mutatedBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"xok"}]}\n', 'utf8');
    const { proof } = makeSigned({ responseBody: originalBody });
    const multipart = formatMultipart({
      rawBody: mutatedBody,
      rawContentType: 'application/json; charset=utf-8',
      proof,
      boundary: 'proof-observation-stale-length',
      contentLengthOverride: originalBody.byteLength,
    });

    const parsed = parseTeeProofMultipartResponse(multipart.body, multipart.contentType);

    expect(mutatedBody.byteLength).toBe(originalBody.byteLength + 1);
    expect(parsed?.body).toEqual(mutatedBody);
    expect(parsed?.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('infers multipart boundary from the captured body when headers were not saved', () => {
    const rawBody = Buffer.from('event: response.completed\ndata: {"type":"response.completed"}\n\n', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const multipart = formatMultipart({
      rawBody,
      rawContentType: 'text/event-stream',
      proof,
      boundary: 'proof-observation-body-boundary',
    });

    const parsed = parseTeeProofCapture(multipart.body);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.proof?.public_key).toBe(proof.public_key);
  });

  it('skips command text before a full multipart capture', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const multipart = formatMultipart({
      rawBody,
      rawContentType: 'application/json',
      proof,
      boundary: 'proof-observation-prefixed-boundary',
    });
    const capture = Buffer.concat([Buffer.from('curl -N https://api.example.com/v1/messages\n', 'utf8'), multipart.body]);

    const parsed = parseTeeProofCapture(capture);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('parses terminal-copied captures that start with raw response then proof part', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const capture = formatProofTailCapture({
      rawBody,
      proof,
      boundary: 'proof-observation-tail-boundary',
    });

    const parsed = parseTeeProofCapture(capture);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('ignores pasted leading blank lines in body+proof captures only when the signed hash proves it', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const capture = Buffer.concat([
      Buffer.from('\n\n', 'utf8'),
      formatProofTailCapture({
        rawBody,
        proof,
        boundary: 'proof-observation-tail-leading-blanks',
      }),
    ]);

    const parsed = parseTeeProofCapture(capture);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.ignoredLeadingBlankBytes).toBe(2);
    expect(parsed.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('returns the raw multipart response body when the proof part says unavailable', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[]}', 'utf8');
    const multipart = formatMultipart({
      rawBody,
      rawContentType: 'application/json',
      proof: { type: 'tee.proof_unavailable', code: 'proof_unavailable', message: 'no proof', attested: false },
      boundary: 'proof-observation-unavailable',
    });

    const parsed = parseTeeProofCapture(multipart.body);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.proof).toBeUndefined();
  });
});

function formatMultipart(params: {
  rawBody: Buffer;
  rawContentType: string;
  proof: TeeProofWire | { type: 'tee.proof_unavailable'; code: string; message: string; attested: false };
  boundary: string;
  contentLengthOverride?: number;
}) {
  const proofBody = Buffer.from(JSON.stringify(params.proof), 'utf8');
  const responseHead = Buffer.from([
    `--${params.boundary}`,
    `Content-Type: ${params.rawContentType}`,
    'Content-Disposition: inline; name="response"',
    'Content-Transfer-Encoding: binary',
    `Content-Length: ${params.contentLengthOverride ?? params.rawBody.byteLength}`,
    '',
    '',
  ].join('\r\n'), 'utf8');
  const proofHead = Buffer.from([
    '',
    `--${params.boundary}`,
    'Content-Type: application/vnd.proof-observation.proof+json',
    'Content-Disposition: attachment; name="proof"',
    'Content-Transfer-Encoding: binary',
    `Content-Length: ${proofBody.byteLength}`,
    '',
    '',
  ].join('\r\n'), 'utf8');
  const end = Buffer.from(`\r\n--${params.boundary}--\r\n`, 'utf8');
  return {
    body: Buffer.concat([responseHead, params.rawBody, proofHead, proofBody, end]),
    contentType: `multipart/mixed; boundary=${params.boundary}`,
  };
}

function formatProofTailCapture(params: {
  rawBody: Buffer;
  proof: TeeProofWire;
  boundary: string;
}) {
  const proofBody = Buffer.from(JSON.stringify(params.proof), 'utf8');
  const proofPart = Buffer.from([
    '',
    `--${params.boundary}`,
    'Content-Type: application/vnd.proof-observation.proof+json',
    'Content-Disposition: attachment; name="proof"',
    'Content-Transfer-Encoding: binary',
    `Content-Length: ${proofBody.byteLength}`,
    '',
    '',
  ].join('\n'), 'utf8');
  const end = Buffer.from(`\n--${params.boundary}--`, 'utf8');
  return Buffer.concat([params.rawBody, proofPart, proofBody, end]);
}
