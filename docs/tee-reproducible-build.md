# 可复现构建 —— 让任何人从源码重算出同一个 PCR0

> 总纲见 [`TEE.md`](TEE.md)。

TEE 自证的承重墙之一:用户验 attestation 时比对的 `expectedPcr0`,理想是**任何人都能从公开源独立重算
出来**的值,而不是运营方单方面声称的数字。本文件钉死所有构建输入,并给出第三方复算与比对步骤。

## 规范 PCR0

```
23696aa5aa2c2dbacfe6dc48c21e67400dd2571f7105c359dd072d3ae14cfac10bfe8509ae7e3db2a078d630d81efec7
```

> 飞地源逐字节敏感:改 `enclave/{Cargo.toml,Cargo.lock,Dockerfile,src/**}` 任一字节(**包括注释**)
> 都会改 PCR0 → 须重走本流程产出新规范值。

## 钉死的输入(改任一项 PCR0 都会变)

| 输入 | 钉法 |
|---|---|
| 源码 | git:`enclave/{Cargo.toml,Cargo.lock,Dockerfile,src/{main.rs,lib.rs,tls_profile.rs,egress_boring.rs,egress_openssl.rs,ca-bundle.pem}}`。`src/bin/profile-encode.rs` 是独立 bin、不进 EIF → **不影响 PCR0** |
| builder / runtime 基础镜像 | sha256 digest(见 `Dockerfile`,非 tag) |
| Rust 依赖 | `Cargo.lock` + `cargo build --locked` |
| CA 根 | `src/ca-bundle.pem`(公共根;飞地 runtime 无系统根,自带,校验上游用) |
| 构建工具链 | 版本对齐(Docker / Nitro CLI / `aarch64`;具体版本见 `Dockerfile` 头注释) |

> Nitro CLI 把内核 + init 打进 EIF,PCR0 度量整份 EIF(内核 + ramdisk + 启动)。同版本 Nitro CLI
> 与 Docker 同样是输入的一部分;跨大版本可能改变内核 blob → PCR0 变。

> **⚠️ 源逐字节敏感 —— 连 `.rs` 注释也算。** rustc 的符号修饰含一个从 crate 源内容派生的哈希,改任一
> 字节(哪怕普通注释)都会令符号名连锁变化、二进制散布漂移 → PCR0 变。第三方复算务必用 git 里逐字节
> 一致的源,勿"顺手"改注释。

## 为什么这套能复现(两处非确定源都已消除)

1. **编译产物确定**:基础镜像按 digest 钉死 + `Cargo.lock` 钉死依赖 + `--remap-path-prefix`(Rust)与
   `CFLAGS/CXXFLAGS -ffile-prefix-map`(C 侧)归一化嵌入路径 + `CARGO_INCREMENTAL=0`。两次干净
   `--no-cache` 构建的 `/attest` 二进制逐字节相同。
2. **rootfs 元数据确定**:Docker 给 COPY/RUN 文件打构建时刻 mtime,会进 EIF ramdisk → PCR0 漂移。
   Dockerfile 末层 `find / -xdev -exec touch -hcd "@0"` 把整个 rootfs mtime 归一到 epoch,消除这一源。

## 第三方复算与比对(不信运营方)

```bash
# 1. 取 enclave/ 源码(连同本仓库)
# 2. 在对齐工具链的 aarch64 机器上双构(--no-cache),两次 PCR0 必须逐字节一致
cd enclave
docker build --no-cache -t attest:audit .
sudo env NITRO_CLI_BLOBS=/usr/share/nitro_enclaves/blobs \
         NITRO_CLI_ARTIFACTS="$PWD/nitro-artifacts" \
         nitro-cli build-enclave --docker-uri attest:audit --output-file audit.eif   # 打印 PCR0
#    或一键双构 + 比对:bash reproducible-build.sh
# 3. 比对:你的 PCR0 == 本文「规范 PCR0」
# 4. 比对运行中飞地 attestation 里的 PCR0:
npx tsx ../verifier/verify-attestation-cose.mjs <att.b64>
```

三处对上(自己 build 的 PCR0 == 文档 == 运行中 attestation)⟹ 运行的飞地跑的就是这份公开源,没夹带。

## 留意

- `--remap-path-prefix` 与 `touch @0` 是当前消除非确定性的最小集;升级 Nitro CLI 或基础镜像需重新双构确认 PCR0 仍一致,并更新本文与发布给用户的 trust.json / 响应包 `expectedPcr0`。
- 构建机架构必须 `aarch64`;x86 上构建得到不同 PCR0。
