# proof-of-observation

> 用密码学证明一条 API 响应确实是真的 —— 终端用户可自行验证，**无需信任转发它的 relay**。

[English](README.md)

`proof-of-observation` 是一个可复现构建的 **AWS Nitro Enclave**。它位于 relay 的出口侧，把
“相信我，这条响应是真的”变成客户端可以**自己检查**的证明。

```text
        你                 relay（不可信）          AWS Nitro Enclave    ───▶  上游 API
         |   请求              |                   （由 PCR0 度量）
         | -------------------> | ---------------->  (1) 在 enclave 内终结上游 TLS、验证证书
         |                      |                    (2) 流式转发响应并计算哈希（不缓冲全文）
         |  响应 + tee.proof   |                    (3) 签名 tee-exchange-v2 声明（Ed25519）
         | <------------------- | <---------------   (4) attestation：把 {签名公钥, PCR0} 绑定到 AWS 根
         v                                             签名私钥永不离开 enclave
   在本地验证，只信 AWS 根：
     (1) attestation 链到 AWS Nitro 根      (3) 收到的字节哈希等于被签名的声明
     (2) PCR0 == 你复现构建出的值            (4) 签名公钥由 attestation 背书；nonce 新鲜
```

## 工作原理

每条请求中，enclave 会：

1. **在 enclave 内终结上游 TLS 连接** —— 使用编入受度量镜像的 CA bundle 验证上游证书；
2. **边流式返回响应、边计算哈希** —— 不缓冲完整响应体；
3. **签名一份 `tee-exchange-v2` 字段分解声明**（Ed25519），把路由事实
   （host / path / method / status / content-type）与请求体、响应体哈希绑定在一起；
4. 附带一份 **NSM attestation**，把签名公钥和 enclave 的 **PCR0** 绑定到 AWS Nitro 根。

签名密钥在启动时生成，并且**永不离开 enclave**。

客户端可以在浏览器或 CLI 中端到端、离线验证：

- attestation **链到 AWS Nitro 根**（这个根由你从 AWS 官方文档 pin）；
- enclave 的 **PCR0 匹配**你从本源码复现构建出的值；
- 你收到的响应字节 **hash 到** enclave 签名覆盖的值；
- 签名公钥被 attestation **绑定**，且 **nonce 新鲜**（防重放）。

全部通过后，就能证明响应来自声明中的上游，且没有被篡改 —— 即使你不信任 relay 本身。

## 它不保证什么

它提供的是**完整性 / 真实性**保证，**不是机密性**保证：relay 仍会短暂经手明文
（只是不会持久化）。如果你的威胁模型要求运营方连流量内容都不能读取，本方案不覆盖。
见 [`docs/TEE.md` §2](docs/TEE.md)。

## 为什么可以信任 PCR0

整个方案的承重墙是：客户端比对的 PCR0 必须能从公开源代码**独立复算**，而不是运营方单方面声称的数字。
enclave 的完整受度量 TCB 位于 [`enclave/`](enclave)；在固定工具链下双构会得到**逐字节一致**的 PCR0。

**当前生产发布版的规范 PCR0：**

```
4bec69861c775a59278f2775f7e7eda8bf4a8c8b15c039c31dd675591e6054b7be5609ba8dcd716f330f6242b23ea8af
```

该生产值对应受度量源码 revision
`19122df6e69d4256e84eb5cf5c875ec4a197bab3`。2026-07-14 在生产 aarch64 构建机清空缓存双构，
两次均得到相同 PCR0；随后完成 EIF 切换，并用真实 Grok 响应的 attestation 核验通过
AWS 证书链、PCR0、飞地公钥、nonce、签名覆盖的 `api.x.ai` host 与响应字节。此前的
`650d3f81…a572` 已作废且从未上线。完整流程见
[`docs/tee-reproducible-build.md`](docs/tee-reproducible-build.md)。

## 协议规范

规范性的、实现无关的协议文本是
[**`docs/proof-of-observation-protocol-v1.md`**](docs/proof-of-observation-protocol-v1.md)
—— 其中定义了 canonical signing statement、attestation Evidence profile、wire format 和验证流程，
并使用 RFC 2119 关键词描述互操作要求。**该文档是权威规范**；本 README 只是总览，仓库代码是其中一个符合规范的实现。

## 仓库结构

| 路径 | 内容 |
|---|---|
| [`enclave/`](enclave) | 受度量的 Rust enclave —— PCR0 度量的关键 TCB |
| [`verifier/`](verifier) | Proof verifier（TypeScript / JS）+ golden test vectors |
| [`docs/proof-of-observation-protocol-v1.md`](docs/proof-of-observation-protocol-v1.md) | **规范协议文本**（RFC 2119） |
| [`docs/`](docs) | 架构、设计 rationale、可复现构建流程 |
| [`docs/tee-verify.html`](docs/tee-verify.html) — [**在线打开 ↗**](https://focuxdot.github.io/proof-of-observation/tee-verify.html) | 自包含的**浏览器验证器** —— 粘贴响应即可本地验证 |
| [`docs/tee-attestation-demo.html`](docs/tee-attestation-demo.html) — [**在线打开 ↗**](https://focuxdot.github.io/proof-of-observation/tee-attestation-demo.html) | **自证原理**交互演示页 |

## 验证一条响应

流式响应末尾会带一条 `event: tee.proof`;非流式 proof mode 可保存完整
`multipart/mixed` 响应(第一段是 raw response bytes,第二段是 proof)。如果终端保存到的是
raw response body 后面直接接 proof part 和 closing boundary,也可以直接验证。慢速 SSE
响应开头可能包含传输层 `: wokey-transport-keepalive-v1` 注释；验证器只会在签名响应哈希
能够证明剥离结果时忽略精确匹配的前置记录。保存响应材料后运行：

```bash
# CLI
npx tsx verifier/tee-verify-stream.ts captured-response --pcr0 <canonical-PCR0>
```

也可以打开**[在线浏览器验证器 ↗](https://focuxdot.github.io/proof-of-observation/tee-verify.html)**
(源码:[`docs/tee-verify.html`](docs/tee-verify.html)，在线页面与该文件逐字节一致)，粘贴流式 SSE 或非流式 proof 响应；
终端保存的 body+proof 尾段也兼容。
验证完全在你的机器上完成。完整 walkthrough 见 [`docs/TEE.md` §3](docs/TEE.md)。

## 复现 PCR0

```bash
cd enclave
bash reproducible-build.sh        # double --no-cache build → two byte-identical PCR0s
```

复现当前生产值时，先 checkout `19122df6e69d4256e84eb5cf5c875ec4a197bab3`，再把结果与
[`docs/tee-reproducible-build.md`](docs/tee-reproducible-build.md) 的 canonical value 以及运行中 enclave 的
attestation 比对。后续发布版只有在最终源码双构和线上 attestation 切换完成后，才同时更新文档值和 revision。

> 需要 `aarch64` 主机、Docker 和 AWS Nitro CLI（固定版本见文档）。

## License

本项目按你的选择使用 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 双许可证。
第三方 attribution 见 [`NOTICE`](NOTICE)。
