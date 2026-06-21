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

**当前发布版的规范 PCR0：**

```
23696aa5aa2c2dbacfe6dc48c21e67400dd2571f7105c359dd072d3ae14cfac10bfe8509ae7e3db2a078d630d81efec7
```

这是你比对的目标值 —— 但**别只信这个数**：自己复现它（见下文「复现 PCR0」），再和运行中 enclave 的
attestation 比对。完整流程见 [`docs/tee-reproducible-build.md`](docs/tee-reproducible-build.md)。

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
| [`docs/tee-verify.html`](docs/tee-verify.html) | 自包含的**浏览器验证器** —— 粘贴响应即可本地验证 |

## 验证一条响应

流式响应末尾会带一条 `event: tee.proof`;非流式 proof mode 可保存完整
`multipart/mixed` 响应(第一段是 raw response bytes,第二段是 proof)。如果终端保存到的是
raw response body 后面直接接 proof part 和 closing boundary,也可以直接验证。保存响应材料后运行：

```bash
# CLI
npx tsx verifier/tee-verify-stream.ts captured-response --pcr0 <canonical-PCR0>
```

也可以在浏览器中打开 [`docs/tee-verify.html`](docs/tee-verify.html)，粘贴流式 SSE 或非流式 proof 响应；
终端保存的 body+proof 尾段也兼容。
验证完全在你的机器上完成。完整 walkthrough 见 [`docs/TEE.md` §3](docs/TEE.md)。

## 复现 PCR0

```bash
cd enclave
bash reproducible-build.sh        # double --no-cache build → two byte-identical PCR0s
```

把结果与 [`docs/tee-reproducible-build.md`](docs/tee-reproducible-build.md) 中的 canonical value
以及运行中 enclave 的 attestation 进行比对。三者一致
（你的构建 == 文档 == live attestation）就能证明运行中的 enclave 正是由这份源码编译而来，没有夹带内容。

> 需要 `aarch64` 主机、Docker 和 AWS Nitro CLI（固定版本见文档）。

## License

本项目按你的选择使用 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 双许可证。
第三方 attribution 见 [`NOTICE`](NOTICE)。
