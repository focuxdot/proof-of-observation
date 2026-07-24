// 客户端验证组件(CLI · 抓流抽查)—— v2 字段分解版。对应「生产流式 proof 带外下发」的消费端。
//
//   npx tsx tee-verify-stream.ts <captured-response> --pcr0 <hex> [--host <api.example.com>]
//
// 输入是你**实际收到的完整响应**:SSE(可选前置传输 keepalive + 上游字节 + 末尾
// event: tee.proof)或 multipart/mixed(第一段 raw response bytes,第二段 proof)。
// 本工具:① 剥出 proof;② 以签名哈希为闸剥固定前置 keepalive,还原上游原文并重算 H(respBody);
// ③ 调共享核心 v2 验证(attestation 链 + PCR0 + 公钥绑定 + nonce 绑定 + 声明验签 + 读 host/path)。
//
//   · --pcr0  (必填)审计公布、可由 reproducible-build 复算的镜像度量
//   · --host  (可选)核对签名覆盖的 upstream_host(官方端点);不给则只展示,由你自行判断
//
// response-only:能验「真飞地跑审计镜像 + 逐字签了你收到的响应(未篡改)」,并**读出签名覆盖的 host/path**。
// 不含**请求绑定**(没有你的原始请求体);要连「答的就是我这条请求」一并钉,用 verify-real-bundle(整 bundle)。

import { readFileSync } from 'node:fs';
import { parseTeeProofCapture, verifyTeeExchange } from './tee-verify-core.ts';

const args = process.argv.slice(2);
const flag = (name: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
const consumed = new Set<number>();
for (const name of ['--pcr0', '--host']) {
  const i = args.indexOf(name);
  if (i >= 0) { consumed.add(i); consumed.add(i + 1); }
}
const capturePath = args.find((a, i) => !consumed.has(i) && !a.startsWith('--'));
const pcr0 = flag('--pcr0');
const expectedHost = flag('--host');
if (!capturePath || !pcr0) {
  console.error('用法: tsx tee-verify-stream.ts <captured-response> --pcr0 <hex> [--host <api.example.com>]');
  console.error('  --host 可选:给了就核对签名覆盖的 upstream_host;不给则只展示。');
  process.exit(2);
}

const streamBytes = readFileSync(capturePath);
const { body, proof, ignoredTransportKeepaliveCount } = parseTeeProofCapture(streamBytes);
if (!proof) {
  console.error('❌ 未在响应中找到可验证的 tee.proof —— 该响应未自证(可能走了降级/transform 路径,或 proof 被中间层吞掉)。');
  process.exit(1);
}

const result = verifyTeeExchange({
  expectedPcr0: pcr0,
  responseBody: body,
  proof,
  expectedHost,
});

console.log('── 客户端流式抽查 · response-only (v2) ──');
console.log('module_id :', result.attestation.moduleId);
console.log('PCR0(文档):', result.attestation.pcr0);
console.log('绑定公钥  :', result.attestation.publicKey);
console.log('上游 host :', result.provenance.upstreamHost, result.provenance.upstreamPath);
console.log('状态/类型 :', `${result.provenance.httpStatus} · ${result.provenance.respContentType}`);
console.log('响应字节  :', `${body.byteLength} B(已剥离流末 tee.proof${ignoredTransportKeepaliveCount ? ` + ${ignoredTransportKeepaliveCount} 条传输 keepalive` : ''})`);
console.log('──');
for (const c of result.checks) console.log(`  ${c.ok ? '✅' : '❌'} ${String(c.name).padEnd(6, '　')} ${c.detail}`);
console.log(`  判定: ${result.ok ? '✅ 全过——真飞地跑审计镜像、签了你收到的这段响应(未篡改),host 已签名覆盖' : '❌ 校验失败'}`);
console.log('  注: response-only 未含请求绑定;要连「答的就是我这条请求」一并钉,用整 bundle(verify-real-bundle)。');
process.exit(result.ok ? 0 : 1);
