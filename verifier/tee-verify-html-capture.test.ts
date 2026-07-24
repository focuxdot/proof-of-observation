// docs/tee-verify.html must verify the exact captured response bytes. The page
// may parse the trailing proof as text, but it must not normalize signed
// response bytes before hashing them.

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(join(root, 'docs/tee-verify.html'), 'utf8');
const js = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]).join('\n');
const start = js.indexOf('const te = new TextEncoder();');
const end = js.indexOf('// v2 字段分解声明:与', start);
if (start < 0 || end < 0) throw new Error('failed to locate tee-verify.html capture parser block');

const parser = new Function(
  js.slice(start, end) + '\nreturn { parseProofEventBytes, parseProofEventText, parseProofMultipartBytes, normalizePastedBodyBytes, normalizeSseTransportKeepalives };',
)() as {
  parseProofEventBytes: (bytes: Uint8Array) => { bodyBytes: Uint8Array; proof: Record<string, unknown> } | null;
  parseProofEventText: (text: string) => { bodyBytes: Uint8Array; proof: Record<string, unknown> } | null;
  parseProofMultipartBytes: (bytes: Uint8Array) => { bodyBytes: Uint8Array; proof?: Record<string, unknown>; unavailable?: Record<string, unknown>; tail?: boolean } | null;
  normalizePastedBodyBytes: (
    bodyBytes: Uint8Array,
    proof?: Record<string, unknown>,
    allowLeadingBlankTrim?: boolean,
  ) => Promise<{ bodyBytes: Uint8Array; ignoredLeadingBytes: number }>;
  normalizeSseTransportKeepalives: (
    bodyBytes: Uint8Array,
    proof?: Record<string, unknown>,
  ) => Promise<{
    bodyBytes: Uint8Array;
    ignoredTransportKeepaliveBytes: number;
    ignoredTransportKeepaliveCount: number;
  }>;
};

const formatterStart = js.indexOf('function formatSseResponseBodyText');
const formatterEnd = js.indexOf('// 从已载入材料解析出 proof', formatterStart);
if (formatterStart < 0 || formatterEnd < 0) throw new Error('failed to locate tee-verify.html response body formatter block');
const ttStub = `
const TRANSLATIONS = {
  jsonBody: 'JSON 响应体',
  sseBody: 'SSE 事件流',
  rawBody: '原始响应体',
  bodyJsonNote: 'JSON 已展开格式化',
  bodySseNote: 'SSE 事件流 JSON 已展开格式化',
  bodyRawNote: '原始文本显示',
  streamTitle: '流式请求 · 保存 response.sse',
  multipartTitle: '非流式请求 · 保存 response.multipart',
  streamIntro: '保存完整 SSE 响应；末尾会包含 <code>event: tee.proof</code>。',
  multipartIntro: '开启 multipart proof 模式，保存完整 <code>multipart/mixed</code> 响应。',
  messagesTab: 'Messages',
  responsesTab: 'Responses',
  messagesFormatNote: 'Messages 格式使用 <code>messages</code>，保留 <code>max_tokens</code>。',
  responsesFormatNote: 'Responses 格式使用 <code>input</code>，不要带 <code>max_tokens</code> / <code>max_output_tokens</code>。'
};
const tt = (key, ...args) => {
  const value = TRANSLATIONS[key] || key;
  return typeof value === 'function' ? value(...args) : value;
};
`;
const formatter = new Function(
  ttStub + js.slice(formatterStart, formatterEnd) + '\nreturn { formatResponseBodyText, formatSseResponseBodyText };',
)() as {
  formatResponseBodyText: (text: string) => { kind: string; text: string; note: string };
  formatSseResponseBodyText: (text: string) => string;
};

const modelStart = js.indexOf('function modelFromResponseJson');
const modelEnd = js.indexOf('function escHtml', modelStart);
if (modelStart < 0 || modelEnd < 0) throw new Error('failed to locate tee-verify.html model extractor block');
const modelExtractor = new Function(
  'Buffer',
  'const b64ToBytes=(b)=>Uint8Array.from(Buffer.from(b, "base64"));\n'
    + js.slice(modelStart, modelEnd)
    + '\nreturn { extractServedModel, extractMessageId, maskMessageId, maskFingerprint, formatLocalVerifyTime };',
)(Buffer) as {
  extractServedModel: (b64: string) => string | null;
  extractMessageId: (b64: string) => string | null;
  maskMessageId: (id: string | null) => string | null;
  maskFingerprint: (v: string | null) => string | null;
  formatLocalVerifyTime: (d: Date) => string;
};

const exampleStart = js.indexOf('function requestExample');
const exampleEnd = js.indexOf('function showRequestExample', exampleStart);
if (exampleStart < 0 || exampleEnd < 0) throw new Error('failed to locate tee-verify.html request example block');
const exampleBuilder = new Function(
  ttStub + js.slice(exampleStart, exampleEnd) + '\nreturn { requestExample };',
)() as {
  requestExample: (mode: 'stream' | 'multipart', format?: 'messages' | 'responses') => { title: string; intro: string; output: string; command: string };
};

const proof = {
  public_key: 'pub',
  nonce: 'nonce',
  signature: 'sig',
  attestation: 'att',
  upstream_host: 'api.example.com',
  request_body_sha256: '00',
  response_body_sha256: '11',
  pcr0: 'aeb9e595',
};

describe('docs/tee-verify.html capture parser preserves signed response bytes', () => {
  it('styles fresh certificate soft rows as success instead of warning', () => {
    expect(html).toContain('.vc-soft.ok { background:var(--ok-bg); border-color:var(--ok-border); }');
    expect(html).toContain("s.soft.skip?'skip':(s.soft.ok?'ok':'bad')");
  });

  it('uses verification language for gate status labels', () => {
    expect(html).toContain("'✓ 验证通过'");
    expect(html).toContain("'✕ 验证失败'");
    expect(html).not.toContain('✓ 成立');
  });

  it('renders the final trust verdict as a scannable summary card', () => {
    expect(html).toContain('.result-fields { display:grid; grid-template-columns:1.4fr 1fr 1.05fr 1.45fr');
    expect(html).toContain('.result-chain { display:grid; grid-template-columns:repeat(3,minmax(0,1fr))');
    expect(html).toContain('function renderTrustSummary');
    expect(html).toContain("title:tt('verifyOk')");
    expect(html).toContain("resultField(L('消息 ID','Message ID'),messageId)");
    expect(html).toContain("resultField(tt('verifyTime'),'<b>'+escHtml(o.verifiedAt||tt('notRecorded'))+'</b>')");
    expect(html).toContain("escHtml(maskFingerprint(o.pcr0))");
    expect(html).toContain("tt('checkTeeOkDetail')");
    expect(html).toContain("v.className='verdict bad result-summary'");
    expect(html).toContain('focuxdot/proof-of-observation');
  });

  it('shows both response hash values in the stage-C comparison row', () => {
    expect(html).toContain('.vc-hash-compare');
    expect(html).toContain("L('SHA256(你的响应) == 签名覆盖的哈希 → <b>','SHA256(your response) == signed hash → <b>')");
    expect(html).toContain("'<div class=\"vc-hash-row\"><span class=\"vc-hash-k\">'+L('你的响应','your response')+'</span>");
    expect(html).toContain("'<div class=\"vc-hash-row\"><span class=\"vc-hash-k\">'+L('签名覆盖','signed hash')+'</span>");
    expect(html).toContain('title="\'+esc(recomputed)+\'"');
    expect(html).toContain('title="\'+esc(t.response_body_sha256)+\'"');
  });

  it('color-codes the detailed hash comparison rows by match status', () => {
    expect(html).toContain('.mkrow.ok { background:var(--ok-bg); }');
    expect(html).toContain('.mkrow.bad { background:var(--bad-bg); }');
    expect(html).toContain("const kv = (k,v,state)=>'<div class=\"mkrow'+(state?' '+state:'')+'\">");
    expect(html).toContain("kv(L('SHA256(你收到的响应正文)','SHA256(response body you received)'), recomputed, kvState(bodyOk))");
    expect(html).toContain("kv(L('签名覆盖的 response_body_sha256','signed response_body_sha256'), t.response_body_sha256, kvState(bodyOk))");
    expect(html).toContain("kv(L('是否相等','Equal?'),'bodyOk = '+bodyOk, kvState(bodyOk))");
  });

  it('color-codes every modal comparison row by pass/fail status', () => {
    expect(html).toContain('const kvState = ok=>ok?\'ok\':\'bad\';');
    expect(html).toContain("kv(L('COSE 验签(用叶证书公钥)','COSE signature verification (leaf certificate public key)'),'sigOk = '+fSigOk, kvState(fSigOk))");
    expect(html).toContain("kv(L('逐级验签','Chain verification'),'chainOk = '+fLink, kvState(fLink))");
    expect(html).toContain("kv(L('根自签','Root self-signature'),'rootSelf = '+fRootSelf, kvState(fRootSelf))");
    expect(html).toContain("kv(L('链顶根指纹(解出)','Root fingerprint decoded from chain'), fRootFp||L('(无法解析链)','(chain could not be parsed)'), kvState(fRootPinned))");
    expect(html).toContain("kv(L('本页 pin 的 AWS 根','AWS root pinned by this page'), AWS_NITRO_ROOT_FP, kvState(fRootPinned))");
    expect(html).toContain("kv(L('是否相等','Equal?'),'rootPinned = '+fRootPinned, kvState(fRootPinned))");
    expect(html).toContain("kv(L('attestation 报告的 PCR0','PCR0 reported by attestation'), attPcr0, kvState(pcrPass))");
    expect(html).toContain("kv(L('你认可的审计 PCR0','audited PCR0 you trust'), trust.expectedPcr0, kvState(pcrPass))");
    expect(html).toContain("kv(L('proof 里验签用的公钥','public key used to verify proof'), t.public_key, kvState(bound))");
    expect(html).toContain("kv(L('attestation 背书的公钥','public key attested by attestation'), boundPub, kvState(bound))");
    expect(html).toContain("kv(L('attestation 内嵌 nonce','nonce embedded in attestation'), attNonce, kvState(nOk))");
    expect(html).toContain("kv(L('proof 顶层 nonce','top-level proof nonce'), t.nonce, kvState(nOk))");
    expect(html).toContain("kv(L('结果','Result'),'valid = '+valid, kvState(valid))");
  });

  it('has a non-persistent language switch', () => {
    expect(html).toContain('data-lang-choice="zh"');
    expect(html).toContain('data-lang-choice="en"');
    expect(html).toContain('const I18N=');
    expect(html).toContain('applyLanguage(currentLang)');
    expect(html).toContain('function rerenderVerificationForLanguage');
    expect(html).toContain("runVerification({animate:false, scroll:false, rerender:true})");
    expect(html).toContain('verificationRendered=true');
    expect(html).not.toContain('localStorage');
    expect(html).not.toContain('sessionStorage');
  });

  it('localizes deep verification explanations and glossary tooltips', () => {
    expect(html).toContain('function glossEntries');
    expect(html).toContain("L('信任锚','Trust anchors')");
    expect(html).toContain("L('怎么做到的 · 自己复核 ▸','How it works · verify yourself ▸')");
    expect(html).toContain("badgeSub:L('证书已过期','CERT EXPIRED')");
    expect(html).toContain('<div class="fnd-ah"><a href="https://github.com/focuxdot/proof-of-observation" target="_blank" rel="noopener noreferrer">\'+L(\'↗ 拿开源代码自己跑复现构建');
    expect(html).toContain("['leaf certificate','The final certificate in the chain");
  });

  it('shows concrete host and model in the trusted answer stage output', () => {
    expect(html).toContain("L('来源 <b>','source <b>')+esc(host)+L('</b>、模型 <b>','</b>, model <b>')+esc(servedModel)");
    expect(html).not.toContain("signedScope+'已完成核验");
  });

  it('opens runnable curl examples from a compact request example modal', () => {
    expect(html).toContain('data-example="stream">查看请求示例');
    expect(html).toContain('data-example-tab="');
    expect(html).toContain('data-example-format-tab="');

    const stream = exampleBuilder.requestExample('stream');
    expect(stream.output).toBe('response.sse');
    expect(stream.command).toContain('curl -N https://api.wokey.ai/v1/messages \\');
    expect(stream.command).toContain('-H "Content-Type: application/json" \\');
    expect(stream.command).toContain('"messages": [');
    expect(stream.command).toContain('"max_tokens": 64');
    expect(stream.command).toContain('"stream": true');
    expect(stream.command).toContain('> response.sse');

    const multipart = exampleBuilder.requestExample('multipart');
    expect(multipart.output).toBe('response.multipart');
    expect(multipart.command).toContain('curl https://api.wokey.ai/v1/messages \\');
    expect(multipart.command).toContain('-H "Content-Type: application/json" \\');
    expect(multipart.command).toContain('-H "x-wokey-tee-proof-mode: multipart" \\');
    expect(multipart.command).toContain('"messages": [');
    expect(multipart.command).toContain('"max_tokens": 64');
    expect(multipart.command).toContain('"stream": false');
    expect(multipart.command).toContain('> response.multipart');

    const responseStream = exampleBuilder.requestExample('stream', 'responses');
    expect(responseStream.command).toContain('curl -N https://api.wokey.ai/v1/responses \\');
    expect(responseStream.command).toContain('-H "Content-Type: application/json" \\');
    expect(responseStream.command).toContain('"input": [');
    expect(responseStream.command).toContain('"store": false');
    expect(responseStream.command).toContain('"stream": true');
    expect(responseStream.command).not.toContain('"messages"');
    expect(responseStream.command).not.toContain('max_tokens');
    expect(responseStream.command).not.toContain('max_output_tokens');

    const responseMultipart = exampleBuilder.requestExample('multipart', 'responses');
    expect(responseMultipart.command).toContain('curl https://api.wokey.ai/v1/responses \\');
    expect(responseMultipart.command).toContain('-H "Content-Type: application/json" \\');
    expect(responseMultipart.command).toContain('-H "x-wokey-tee-proof-mode: multipart" \\');
    expect(responseMultipart.command).toContain('"input": [');
    expect(responseMultipart.command).toContain('"store": false');
    expect(responseMultipart.command).toContain('"stream": false');
    expect(responseMultipart.command).not.toContain('"messages"');
    expect(responseMultipart.command).not.toContain('max_tokens');
    expect(responseMultipart.command).not.toContain('max_output_tokens');
    expect(responseMultipart.command).toContain('> response.multipart');
  });

  it('shows parser/load failures as prominent load-message errors', () => {
    expect(html).toContain('.hint.load-msg.error');
    expect(html).toContain('function setLoadMsg');
    expect(html).toContain("setLoadMsg(tt('invalidJsonOrSse'),'error')");
    expect(html).toContain("setLoadMsg(tt('noInputLoad'),'error')");
  });

  it('does not normalize CRLF in the SSE body before tee.proof', () => {
    const body = 'event: message_start\r\ndata: {"type":"message_start"}\r\n\r\n';
    const stream = `${body}event: tee.proof\r\ndata: ${JSON.stringify(proof)}\r\n\r\n`;

    const parsed = parser.parseProofEventText(stream);

    expect(parsed?.proof).toMatchObject(proof);
    expect(Buffer.from(parsed!.bodyBytes).toString('utf8')).toBe(body);
    expect(Buffer.from(parsed!.bodyBytes).toString('utf8')).not.toBe(body.replace(/\r\n/g, '\n'));
  });

  it('proof-gates removal of leading transport keepalive comments', async () => {
    const marker = ': wokey-transport-keepalive-v1\n\n';
    const body = Buffer.from('event: message_start\ndata: {"type":"message_start"}\n\n', 'utf8');
    const signedProof = {
      ...proof,
      response_body_sha256: createHash('sha256').update(body).digest('hex'),
    };
    const stream = Buffer.concat([
      Buffer.from(marker.repeat(2), 'utf8'),
      body,
      Buffer.from(`event: tee.proof\ndata: ${JSON.stringify(signedProof)}\n\n`, 'utf8'),
    ]);

    const parsed = parser.parseProofEventBytes(new Uint8Array(stream));
    const normalized = await parser.normalizeSseTransportKeepalives(parsed!.bodyBytes, parsed!.proof);

    expect(Buffer.from(normalized.bodyBytes)).toEqual(body);
    expect(normalized.ignoredTransportKeepaliveCount).toBe(2);
    expect(normalized.ignoredTransportKeepaliveBytes).toBe(Buffer.byteLength(marker.repeat(2)));
  });

  it('preserves a matching leading upstream comment covered by the signed hash', async () => {
    const marker = ': wokey-transport-keepalive-v1\n\n';
    const body = Buffer.from(`${marker}event: message_start\ndata: {}\n\n`, 'utf8');
    const signedProof = {
      ...proof,
      response_body_sha256: createHash('sha256').update(body).digest('hex'),
    };
    const parsed = parser.parseProofEventBytes(new Uint8Array(Buffer.concat([
      body,
      Buffer.from(`event: tee.proof\ndata: ${JSON.stringify(signedProof)}\n\n`, 'utf8'),
    ])));

    const normalized = await parser.normalizeSseTransportKeepalives(parsed!.bodyBytes, parsed!.proof);

    expect(Buffer.from(normalized.bodyBytes)).toEqual(body);
    expect(normalized.ignoredTransportKeepaliveCount).toBe(0);
  });

  it('does not remove near matches or markers after upstream bytes begin', async () => {
    const marker = ': wokey-transport-keepalive-v1\n\n';
    const body = Buffer.from('event: message_start\ndata: {}\n\n', 'utf8');
    const signedProof = {
      ...proof,
      response_body_sha256: createHash('sha256').update(body).digest('hex'),
    };
    const near = Buffer.from(': wokey-transport-keepalive-v2\n\n', 'utf8');
    const after = Buffer.concat([body, Buffer.from(marker, 'utf8')]);

    const nearNormalized = await parser.normalizeSseTransportKeepalives(
      new Uint8Array(Buffer.concat([near, body])),
      signedProof,
    );
    const afterNormalized = await parser.normalizeSseTransportKeepalives(new Uint8Array(after), signedProof);

    expect(Buffer.from(nearNormalized.bodyBytes)).toEqual(Buffer.concat([near, body]));
    expect(nearNormalized.ignoredTransportKeepaliveCount).toBe(0);
    expect(Buffer.from(afterNormalized.bodyBytes)).toEqual(after);
    expect(afterNormalized.ignoredTransportKeepaliveCount).toBe(0);
  });

  it('keeps file/drop SSE bytes byte-for-byte while parsing the proof as text', () => {
    const body = Buffer.from('curl prefix\nignored\n\nevent: message_start\r\ndata: hello\r\n\r\n', 'utf8');
    const suffix = Buffer.from(`event: tee.proof\r\ndata: ${JSON.stringify(proof)}\r\n\r\n`, 'utf8');
    const parsed = parser.parseProofEventBytes(new Uint8Array(Buffer.concat([body, suffix])));

    expect(parsed?.proof).toMatchObject(proof);
    expect(Buffer.from(parsed!.bodyBytes)).toEqual(body);
  });

  it('does not discard an unsigned SSE event before a later transport keepalive', async () => {
    const marker = Buffer.from(': wokey-transport-keepalive-v1\n\n', 'utf8');
    const unsignedPrefix = Buffer.from('data: {"unsigned":true}\n\n', 'utf8');
    const body = Buffer.from('event: message_stop\ndata: {}\n\n', 'utf8');
    const signedProof = {
      ...proof,
      response_body_sha256: createHash('sha256').update(body).digest('hex'),
    };
    const parsed = parser.parseProofEventBytes(new Uint8Array(Buffer.concat([
      unsignedPrefix,
      marker,
      body,
      Buffer.from(`event: tee.proof\ndata: ${JSON.stringify(signedProof)}\n\n`, 'utf8'),
    ])));

    const normalized = await parser.normalizeSseTransportKeepalives(parsed!.bodyBytes, parsed!.proof);

    expect(Buffer.from(parsed!.bodyBytes)).toEqual(Buffer.concat([unsignedPrefix, marker, body]));
    expect(Buffer.from(normalized.bodyBytes)).toEqual(Buffer.concat([unsignedPrefix, marker, body]));
    expect(normalized.ignoredTransportKeepaliveCount).toBe(0);
  });

  it('does not accept tee.proof when unsigned bytes follow the proof event', () => {
    const body = Buffer.from('event: response.output_text.delta\ndata: hello\n\n', 'utf8');
    const proofEvent = Buffer.from(`event: tee.proof\ndata: ${JSON.stringify(proof)}\n\n`, 'utf8');
    const unsignedTail = Buffer.from('event: response.output_text.delta\ndata: unsigned\n\n', 'utf8');

    const parsed = parser.parseProofEventBytes(new Uint8Array(Buffer.concat([body, proofEvent, unsignedTail])));

    expect(parsed).toBeNull();
  });

  it('accepts a tee.proof event missing the trailing blank-line terminator (no final newline)', () => {
    const body = 'event: message_start\ndata: {"type":"message_start"}\n\n';
    // 末尾既无空行也无换行 —— 终端复制/curl 落盘常见;流末尾即终止事件。
    const stream = `${body}event: tee.proof\ndata: ${JSON.stringify(proof)}`;

    const parsed = parser.parseProofEventText(stream);

    expect(parsed?.proof).toMatchObject(proof);
    expect(Buffer.from(parsed!.bodyBytes).toString('utf8')).toBe(body);
  });

  it('accepts a tee.proof event ending with only trailing whitespace and no blank line', () => {
    const body = 'event: message_start\ndata: {"type":"message_start"}\n\n';
    const stream = `${body}event: tee.proof\ndata: ${JSON.stringify(proof)}   \n  `;

    const parsed = parser.parseProofEventText(stream);

    expect(parsed?.proof).toMatchObject(proof);
    expect(Buffer.from(parsed!.bodyBytes).toString('utf8')).toBe(body);
  });

  it('parses multipart captures while preserving the raw response part exactly', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}\r\n', 'utf8');
    const capture = formatMultipart({
      rawBody,
      proof,
      boundary: 'proof-observation-html-test',
      prefix: 'curl command pasted above the response\n',
    });

    const parsed = parser.parseProofMultipartBytes(new Uint8Array(capture));

    expect(parsed?.proof).toMatchObject(proof);
    expect(Buffer.from(parsed!.bodyBytes)).toEqual(rawBody);
  });

  it('falls back to multipart boundaries when a mutated response body makes Content-Length stale', () => {
    const originalBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}\r\n', 'utf8');
    const mutatedBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"xok"}]}\r\n', 'utf8');
    const capture = formatMultipart({
      rawBody: mutatedBody,
      proof,
      boundary: 'proof-observation-html-stale-length',
      contentLengthOverride: originalBody.byteLength,
    });

    const parsed = parser.parseProofMultipartBytes(new Uint8Array(capture));

    expect(mutatedBody.byteLength).toBe(originalBody.byteLength + 1);
    expect(parsed?.proof).toMatchObject(proof);
    expect(Buffer.from(parsed!.bodyBytes)).toEqual(mutatedBody);
  });

  it('parses terminal-copied captures that start with raw response then proof part', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}', 'utf8');
    const capture = formatProofTailCapture({
      rawBody,
      proof,
      boundary: 'proof-observation-html-tail-test',
    });

    const parsed = parser.parseProofMultipartBytes(new Uint8Array(capture));

    expect(parsed?.proof).toMatchObject(proof);
    expect(Buffer.from(parsed!.bodyBytes)).toEqual(rawBody);
  });

  it('ignores pasted leading blank lines for body+proof captures when the signed hash proves it', async () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}', 'utf8');
    const signedProof = {
      ...proof,
      response_body_sha256: createHash('sha256').update(rawBody).digest('hex'),
    };
    const capture = Buffer.concat([
      Buffer.from('\n\n', 'utf8'),
      formatProofTailCapture({
        rawBody,
        proof: signedProof,
        boundary: 'proof-observation-html-tail-leading-blanks',
      }),
    ]);

    const parsed = parser.parseProofMultipartBytes(new Uint8Array(capture));
    const normalized = await parser.normalizePastedBodyBytes(parsed!.bodyBytes, parsed!.proof, parsed!.tail);

    expect(parsed?.proof).toMatchObject(signedProof);
    expect(Buffer.from(normalized.bodyBytes)).toEqual(rawBody);
    expect(normalized.ignoredLeadingBytes).toBe(2);
  });

  it('formats non-streaming JSON response bodies for the response modal', () => {
    const rawBody = '{"model":"claude-sonnet-4-5-20250929","id":"msg_1","content":[{"type":"text","text":"ok"}]}';

    const formatted = formatter.formatResponseBodyText(rawBody);

    expect(formatted.kind).toBe('JSON 响应体');
    expect(formatted.text).toContain('{\n  "model": "claude-sonnet-4-5-20250929"');
    expect(formatted.text).toContain('\n  "content": [\n    {');
    expect(formatted.note).toContain('JSON 已展开格式化');
  });

  it('extracts the served model from non-streaming JSON response bodies', () => {
    const rawBody = '{"model":"claude-sonnet-4-5-20250929","id":"msg_1","content":[{"type":"text","text":"ok"}]}';

    const model = modelExtractor.extractServedModel(Buffer.from(rawBody, 'utf8').toString('base64'));

    expect(model).toBe('claude-sonnet-4-5-20250929');
  });

  it('extracts and masks the message id from non-streaming JSON response bodies', () => {
    const id = 'msg_01Q5jrW2vbH2RcFaZr66gJpN';
    const rawBody = JSON.stringify({ model: 'claude-sonnet-4-5-20250929', id, content: [] });

    const extracted = modelExtractor.extractMessageId(Buffer.from(rawBody, 'utf8').toString('base64'));
    const masked = modelExtractor.maskMessageId(extracted);

    expect(extracted).toBe(id);
    expect(masked).toBe('msg_01Q5…66gJpN');
    expect(masked).not.toBe(id);
  });

  it('formats share-card metadata without exposing full long identifiers', () => {
    expect(modelExtractor.maskFingerprint('23696aa5aa2c2dbacfe6dc48c21e67400dd2571f7105c359dd072d3ae14cfac10bfe8509ae7e3db2a078d630d81efec7'))
      .toBe('23696aa5…d81efec7');
    expect(modelExtractor.formatLocalVerifyTime(new Date(2026, 5, 21, 11, 7))).toBe('2026-06-21 11:07');
  });

  it('extracts the served model from SSE response events', () => {
    const rawBody = 'event: message_start\ndata: {"type":"message_start","message":{"model":"claude-3-5-sonnet-latest"}}\n\n';

    const model = modelExtractor.extractServedModel(Buffer.from(rawBody, 'utf8').toString('base64'));

    expect(model).toBe('claude-3-5-sonnet-latest');
  });

  it('extracts the message id from SSE response events', () => {
    const rawBody = 'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_01ABCDEF1234567890","model":"claude-3-5-sonnet-latest"}}\n\n';

    const id = modelExtractor.extractMessageId(Buffer.from(rawBody, 'utf8').toString('base64'));

    expect(id).toBe('msg_01ABCDEF1234567890');
  });

  it('keeps SSE response body formatting support for data JSON lines', () => {
    const rawBody = 'event: response.output_text.delta\ndata: {"type":"delta","delta":"ok"}\n\n';

    const formatted = formatter.formatResponseBodyText(rawBody);

    expect(formatted.kind).toBe('SSE 事件流');
    expect(formatted.text).toContain('data: {\n  "type": "delta",\n  "delta": "ok"\n}');
  });

  it('falls back to raw text when the response body is not JSON or SSE', () => {
    const rawBody = 'plain response body';

    const formatted = formatter.formatResponseBodyText(rawBody);

    expect(formatted.kind).toBe('原始响应体');
    expect(formatted.text).toBe(rawBody);
  });
});

function formatMultipart(params: {
  rawBody: Buffer;
  proof: Record<string, unknown>;
  boundary: string;
  prefix?: string;
  contentLengthOverride?: number;
}) {
  const proofBody = Buffer.from(JSON.stringify(params.proof), 'utf8');
  const responseHead = Buffer.from([
    params.prefix ? `${params.prefix}--${params.boundary}` : `--${params.boundary}`,
    'Content-Type: application/json',
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
  return Buffer.concat([responseHead, params.rawBody, proofHead, proofBody, end]);
}

function formatProofTailCapture(params: {
  rawBody: Buffer;
  proof: Record<string, unknown>;
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
