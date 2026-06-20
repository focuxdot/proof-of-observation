# 自证验证侧 + golden 向量(v2 字段分解)

> 总纲见 [`../docs/TEE.md`](../docs/TEE.md);签名设计见 [`../docs/tee-signing-v2-design.md`](../docs/tee-signing-v2-design.md)。
>
> 真飞地核是 Rust([`../enclave/`](../enclave),装进 Nitro EIF、真 NSM attestation COSE/ECDSA-P384)。
> 本目录是**验证侧**:签名承重墙、共享验证核、客户端验证器、golden 向量。

## 文件

| 文件 | 角色 |
|---|---|
| `signing.ts` | v2 声明 `buildV2Statement`(承重墙;与飞地 Rust `build_v2_statement` 逐字节一致) |
| `tee-verify-core.ts` | 共享验证核:重建 v2 声明验签 + body 哈希核对 + 读 host;各验证器共用、零漂移 |
| `verify-attestation-cose.mjs` | 真 Nitro attestation(COSE_Sign1 / ECDSA-P384 / X.509 链到 AWS 根)验证器 |
| `tee-verify-stream.ts` | CLI 抓流抽查(response-only):粘 SSE → 验 v2 proof + **读出签名覆盖的 host** |
| `verify-real-bundle.ts` | CLI 整 bundle 离线验(full 档):多一项请求绑定 |
| `tee-verify-proxy.ts` | 本地校验代理:把客户端 baseURL 指过来,每调透明验 |
| `signing-vectors.{gen,test}.ts` + `../enclave/signing-vectors.json` | golden 向量(`cases_v2`) |
| `test-cose-browser.mjs` | 浏览器 COSE 验证逻辑对齐自查 |

## 验证(客户端)

```bash
# 抓一段流式 SSE 响应(末尾自带 tee.proof 事件)→ 验
npx tsx tee-verify-stream.ts captured.sse --pcr0 <规范 PCR0>
#   → 链到 AWS 根 + PCR0==公布值 + 公钥绑定 + nonce 绑定 + 声明验签 + 读出签名覆盖的 host
```
或浏览器:开 [`../docs/tee-verify.html`](../docs/tee-verify.html) 贴 SSE。规范 PCR0 见
[`../docs/tee-reproducible-build.md`](../docs/tee-reproducible-build.md)。

## golden 向量(承重墙防漂移)

`../enclave/signing-vectors.json` 的 `cases_v2` 是**三处共同答案卡**:飞地 Rust(`../enclave/src/main.rs` 的
`#[cfg(test)] mod golden`)、TS(`signing-vectors.test.ts`)、浏览器各自重算都必须 == 它,任一处把 v2 声明
布局改歪即红。**只在有意改 v2 布局时**重跑 `npx tsx signing-vectors.gen.ts`(破坏性 → 验证器需重发 + PCR0 变)。
