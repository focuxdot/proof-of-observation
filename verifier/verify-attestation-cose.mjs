// 真 Nitro attestation 文档验证器（参考实现，已在真硬件文档上验通）。
//
//   node verify-attestation-cose.mjs <att.b64>
//
// 与 mock 的 verify-attestation-cose.mjs 不同：真 Nitro 用 CBOR + COSE_Sign1 + ECDSA P-384(ES384)
// + SHA384 PCR + X.509 证书链到 AWS Nitro 根。这份是生产级 attestation 半边的参考。
// 验签的「响应签名」半边仍是我们自己的 Ed25519（见 signing.ts）。
//
// AWS Nitro 根（G1）指纹（硬编码 pin，官方公布值）：
//   64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
import { readFileSync } from 'node:fs';
import { X509Certificate, verify as nodeVerify } from 'node:crypto';

const AWS_NITRO_ROOT_FP = '64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B';

const MAX_ATTESTATION_BYTES = 256 * 1024;
const MAX_ATTESTATION_B64_CHARS = Math.ceil(MAX_ATTESTATION_BYTES / 3) * 4 + 4;
const MAX_CBOR_DEPTH = 32;
const MAX_CBOR_CONTAINER_ITEMS = 1024;
const MAX_CBOR_STRING_BYTES = MAX_ATTESTATION_BYTES;
const CBOR_BREAK = Symbol('cbor.break');

function cborError(message) {
  throw new Error(`invalid CBOR: ${message}`);
}

function requireAvailable(b, p, n) {
  if (!Number.isSafeInteger(p) || !Number.isSafeInteger(n) || p < 0 || n < 0 || p + n > b.length) {
    cborError('truncated item');
  }
}

function readAdditional(b, p, ai) {
  if (ai < 24) return [ai, p];
  if (ai === 24) { requireAvailable(b, p, 1); return [b[p], p + 1]; }
  if (ai === 25) { requireAvailable(b, p, 2); return [b.readUInt16BE(p), p + 2]; }
  if (ai === 26) { requireAvailable(b, p, 4); return [b.readUInt32BE(p), p + 4]; }
  if (ai === 27) {
    requireAvailable(b, p, 8);
    const v = b.readBigUInt64BE(p);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) cborError('integer too large');
    return [Number(v), p + 8];
  }
  if (ai === 31) cborError('unexpected indefinite-length marker');
  cborError('invalid additional information');
}

function boundedSlice(b, p, len, kind) {
  if (len > MAX_CBOR_STRING_BYTES) cborError(`${kind} too large`);
  requireAvailable(b, p, len);
  return b.subarray(p, p + len);
}

function decodeIndefiniteCbor(b, p, mt, depth) {
  switch (mt) {
    case 2: {
      const chunks = [];
      let total = 0;
      for (;;) {
        let chunk;[chunk, p] = dec(b, p, depth + 1, true);
        if (chunk === CBOR_BREAK) return [Buffer.concat(chunks, total), p];
        if (!Buffer.isBuffer(chunk)) cborError('non-bytes chunk in indefinite byte string');
        total += chunk.length;
        if (chunks.length >= MAX_CBOR_CONTAINER_ITEMS || total > MAX_CBOR_STRING_BYTES) cborError('byte string too large');
        chunks.push(chunk);
      }
    }
    case 3: {
      const chunks = [];
      let total = 0;
      for (;;) {
        let chunk;[chunk, p] = dec(b, p, depth + 1, true);
        if (chunk === CBOR_BREAK) return [chunks.join(''), p];
        if (typeof chunk !== 'string') cborError('non-text chunk in indefinite text string');
        total += Buffer.byteLength(chunk, 'utf8');
        if (chunks.length >= MAX_CBOR_CONTAINER_ITEMS || total > MAX_CBOR_STRING_BYTES) cborError('text string too large');
        chunks.push(chunk);
      }
    }
    case 4: {
      const a = [];
      for (;;) {
        let v;[v, p] = dec(b, p, depth + 1, true);
        if (v === CBOR_BREAK) return [a, p];
        if (a.length >= MAX_CBOR_CONTAINER_ITEMS) cborError('array too large');
        a.push(v);
      }
    }
    case 5: {
      const m = Object.create(null);
      let count = 0;
      for (;;) {
        let k, v;[k, p] = dec(b, p, depth + 1, true);
        if (k === CBOR_BREAK) return [m, p];
        [v, p] = dec(b, p, depth + 1);
        if (count >= MAX_CBOR_CONTAINER_ITEMS) cborError('map too large');
        m[k] = v;
        count++;
      }
    }
    default:
      cborError('invalid indefinite-length item');
  }
}

// 最小有界 CBOR 解码器:仅覆盖 attestation 文档用到的类型。
function dec(b, p, depth = 0, allowBreak = false) {
  if (depth > MAX_CBOR_DEPTH) cborError('nesting too deep');
  requireAvailable(b, p, 1);
  if (b[p] === 0xff) {
    if (allowBreak) return [CBOR_BREAK, p + 1];
    cborError('unexpected break');
  }
  const ib = b[p], mt = ib >> 5, ai = ib & 0x1f; p++;
  if (ai === 31) return decodeIndefiniteCbor(b, p, mt, depth);
  let len;[len, p] = readAdditional(b, p, ai);
  switch (mt) {
    case 0: return [len, p];
    case 1: return [-1 - len, p];
    case 2: return [boundedSlice(b, p, len, 'byte string'), p + len];
    case 3: return [boundedSlice(b, p, len, 'text string').toString('utf8'), p + len];
    case 4: {
      if (len > MAX_CBOR_CONTAINER_ITEMS) cborError('array too large');
      const a = [];
      for (let i = 0; i < len; i++) { let v;[v, p] = dec(b, p, depth + 1); a.push(v); }
      return [a, p];
    }
    case 5: {
      if (len > MAX_CBOR_CONTAINER_ITEMS) cborError('map too large');
      const m = Object.create(null);
      for (let i = 0; i < len; i++) { let k, v;[k, p] = dec(b, p, depth + 1);[v, p] = dec(b, p, depth + 1); m[k] = v; }
      return [m, p];
    }
    case 6: return dec(b, p, depth + 1);
    case 7: { if (ai === 20) return [false, p]; if (ai === 21) return [true, p]; return [null, p]; }
    default: cborError('unknown major type');
  }
}

function decodeComplete(b) {
  const [value, p] = dec(b, 0);
  if (p !== b.length) cborError('trailing bytes');
  return value;
}

function asBoundedBuffer(value, label) {
  const b = Buffer.isBuffer(value) ? value : value instanceof Uint8Array ? Buffer.from(value) : null;
  if (!b) throw new Error(`${label} must be bytes`);
  if (b.length === 0 || b.length > MAX_ATTESTATION_BYTES) throw new Error(`${label} too large or empty`);
  return b;
}

function requireDocBytes(value, label) {
  if (!Buffer.isBuffer(value)) throw new Error(`invalid attestation document: ${label} must be bytes`);
  return value;
}

function requireDocObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Buffer.isBuffer(value)) {
    throw new Error(`invalid attestation document: ${label} must be a map`);
  }
  return value;
}

function requireDocByteArray(value, label) {
  if (!Array.isArray(value) || !value.every(Buffer.isBuffer)) {
    throw new Error(`invalid attestation document: ${label} must be byte strings`);
  }
  return value;
}

const enc = {
  text: (s) => { const b = Buffer.from(s, 'utf8'); return Buffer.concat([Buffer.from([0x60 | b.length]), b]); },
  bstr: (b) => {
    if (b.length < 24) return Buffer.concat([Buffer.from([0x40 | b.length]), b]);
    if (b.length < 256) return Buffer.concat([Buffer.from([0x58, b.length]), b]);
    if (b.length < 65536) { const h = Buffer.alloc(3); h[0] = 0x59; h.writeUInt16BE(b.length, 1); return Buffer.concat([h, b]); }
    const h = Buffer.alloc(5); h[0] = 0x5a; h.writeUInt32BE(b.length, 1); return Buffer.concat([h, b]);
  },
};

export function verifyAttestationDoc(buf, opts = {}) {
  buf = asBoundedBuffer(buf, 'attestation');
  const cose = decodeComplete(buf);
  if (!Array.isArray(cose) || cose.length !== 4) throw new Error('invalid COSE_Sign1 envelope');
  const [protectedRaw, , payloadRaw, sig] = cose;
  requireDocBytes(protectedRaw, 'protected header');
  requireDocBytes(payloadRaw, 'payload');
  requireDocBytes(sig, 'signature');
  const doc = requireDocObject(decodeComplete(payloadRaw), 'payload');
  const leafCert = requireDocBytes(doc.certificate, 'certificate');
  const cabundle = requireDocByteArray(doc.cabundle, 'cabundle');
  const pcrs = requireDocObject(doc.pcrs, 'pcrs');
  const pcr0 = requireDocBytes(pcrs[0], 'pcrs[0]');

  // COSE 签名（ES384）
  const leaf = new X509Certificate(Buffer.from(leafCert));
  const sigStruct = Buffer.concat([Buffer.from([0x84]), enc.text('Signature1'), enc.bstr(Buffer.from(protectedRaw)), enc.bstr(Buffer.alloc(0)), enc.bstr(Buffer.from(payloadRaw))]);
  const sigOk = nodeVerify('sha384', sigStruct, { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig));

  // 证书链：cabundle[root..int] + leaf 逐级验签
  const chain = [...cabundle.map((c) => new X509Certificate(Buffer.from(c))), leaf];
  let chainOk = true;
  for (let i = 1; i < chain.length; i++) chainOk = chainOk && chain[i].verify(chain[i - 1].publicKey);
  const root = chain[0];
  const rootSelf = root.verify(root.publicKey);
  const rootPinned = root.fingerprint256 === AWS_NITRO_ROOT_FP;

  // 证书有效期（新鲜性）：每张证书都在有效窗口内。叶证书短命（~小时级），过期即视为陈旧。
  const now = opts.now ?? Date.now();
  const timeValid = chain.every((c) => Date.parse(c.validFrom) <= now && now <= Date.parse(c.validTo));

  const hex = (b) => Buffer.from(b).toString('hex');
  return {
    ok: sigOk && chainOk && rootSelf && rootPinned && timeValid,
    sigOk, chainOk, rootSelf, rootPinned, timeValid,
    leafNotAfter: leaf.validTo,
    moduleId: doc.module_id,
    pcr0: hex(pcr0),
    publicKey: Buffer.isBuffer(doc.public_key) ? Buffer.from(doc.public_key).toString('base64') : null,
    userData: Buffer.isBuffer(doc.user_data) ? Buffer.from(doc.user_data).toString('base64') : null,
    nonce: Buffer.isBuffer(doc.nonce) ? Buffer.from(doc.nonce).toString('base64') : null,
    rootFingerprint: root.fingerprint256,
    leafSubject: leaf.subject.replace(/\n/g, ', '),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const path = process.argv[2];
  if (!path) { console.error('用法: node verify-attestation-cose.mjs <att.b64>'); process.exit(2); }
  const attB64 = readFileSync(path, 'utf8').trim();
  if (attB64.length > MAX_ATTESTATION_B64_CHARS) throw new Error('attestation base64 too large');
  const buf = Buffer.from(attB64, 'base64');
  const r = verifyAttestationDoc(buf);
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ok ? 0 : 1);
}
