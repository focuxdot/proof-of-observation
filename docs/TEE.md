# proof-of-observation — 出口自证(总纲)

一个 AWS Nitro enclave:在飞地内终结上游 TLS、流式哈希响应、对一份 `tee-exchange-v2` 字段分解声明做
Ed25519 签名,并用 NSM attestation 把签名公钥 + PCR0 绑定到 AWS Nitro 根 —— 让用户能**自己验证**:
拿到的响应确实来自指定上游、且字节未被篡改,**无需信任中转方**。

## 文档地图

| 文档 | 内容 |
|---|---|
| 本文 | 总纲:架构 / 信任模型 / 怎么验 |
| [`proof-of-observation-protocol-v1.md`](proof-of-observation-protocol-v1.md) | **规范文本**(RFC2119,实现无关):签名声明 / attestation / wire / 验证流程 —— **以此为准** |
| [`tee-signing-v2-design.md`](tee-signing-v2-design.md) | 设计 rationale(为什么这么分字段),非规范 |
| [`tee-reproducible-build.md`](tee-reproducible-build.md) | 从公开源复算 PCR0 的可复现构建 |
| [`tee-verify.html`](tee-verify.html) — [**在线打开 ↗**](https://focuxdot.github.io/proof-of-observation/tee-verify.html) | 浏览器端验证器(贴流式 SSE / 非流式 proof 响应即验) |
| [`tee-attestation-demo.html`](tee-attestation-demo.html) — [**在线打开 ↗**](https://focuxdot.github.io/proof-of-observation/tee-attestation-demo.html) | 自证原理交互演示页 |
| [`../enclave/README.md`](../enclave/README.md) | 飞地 crate(受度量 TCB) |
| [`../verifier/README.md`](../verifier/README.md) | 验证侧 + golden 向量 |

## 1. 架构

飞地在 Nitro EIF 内运行,**只走 vsock,无网卡、无盘**。每条请求:

1. 父实例经 vsock 送来 `REQUEST_HEAD`(JSON 元数据)+ `REQUEST_BODY`。
2. 飞地经 vsock-proxy 建 TLS 直连上游(用**编入镜像的 CA bundle** 校验真证书),发 HTTP 请求。
3. **边读边喂哈希、不缓冲整段**,流式把响应转发回父实例。
4. 按 `tee-exchange-v2` 规范构建字段分解声明 → 用飞地私钥(开机生成、**永不出飞地**)签 → 取**绑入本次 nonce** 的 attestation。
5. 回 attestation + 响应 + 签名声明(proof)。

飞地是**受度量 TCB**:它做什么,就是公布的 PCR0 所度量的那份代码(见 §4)。

## 2. 信任模型(完整性,不是机密性)

自证保证的是**完整性 / 真实性**,不是机密性:

- ✅ 用户能确认:响应来自签名声明里的 host/path、是该模型对自己请求的真实输出、字节未被篡改。
- ⚠️ 中转方(父实例)仍**短暂经手明文**(只是从不持久化)。若你的威胁模型要求中转方也看不到明文,本方案不覆盖。

签名覆盖面:`nonce`、`upstream-host`、`upstream-path`(去 query)、`http-method`、`http-status`、
`resp-content-type`、`request-body-sha256`、`response-body-sha256`。凭证头(`Authorization`)**不进签名**。
残余风险(headers / query 不绑定)见 [`tee-signing-v2-design.md`](tee-signing-v2-design.md) §9。

## 3. 客户端怎么验

流式响应末尾自带一条 `event: tee.proof`;非流式 proof mode 可保存 `multipart/mixed`
响应(第一段 raw response bytes,第二段 proof)。如果终端保存到的是 raw response body 后面直接接
proof part 和 closing boundary,也可以使用。慢速 SSE 响应可能在上游原文之前带有
`: wokey-transport-keepalive-v1` 传输注释；验证器仅在剥离后的字节哈希等于 TEE 签名哈希时
忽略这些精确匹配的前置注释。把响应材料存下来,用[**在线验证器 ↗**](https://focuxdot.github.io/proof-of-observation/tee-verify.html)
(源码即 [`tee-verify.html`](tee-verify.html),在线页面逐字节一致、纯本地核对)或 `verifier/tee-verify-stream.ts`(CLI)逐关核:

1. COSE/P-384 attestation 链到 **AWS Nitro 根**(根指纹你自己从 AWS 官网 pin)。
2. PCR0 == 你从可复现构建复算 / 公布的值。
3. 签名公钥被 attestation 绑定(防换钥)。
4. nonce 绑定(防重放)。
5. Ed25519 验签声明 + 用收到的字节复核响应体哈希(防篡改)。

五关全过 ⟹ 跑的是审计过的飞地代码、响应未被动过。

## 4. 可复现 PCR0(信任承重墙之一)

「PCR0 == 审计源码」这步,理想是**任何人都能从公开源独立重算**,而不是信运营方。被度量源逐字节敏感
(连注释都算)。完整流程见 [`tee-reproducible-build.md`](tee-reproducible-build.md):对齐工具链双
`--no-cache` 构建 → 两次 PCR0 逐字节一致 → 与运行中飞地 attestation 里的 PCR0 三方比对。
