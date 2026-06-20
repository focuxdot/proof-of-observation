# 可复现构建 —— 让任何人能从源码重算出同一个 PCR0。
#
# 钉死的输入（改任一项，PCR0 都会变）：
#   · 基础镜像按 sha256 digest 钉死（不是 tag，tag 会漂）
#   · 依赖按 Cargo.lock 钉死，cargo build --locked 拒绝任何偏离
#   · 编译路径/时间戳归一（remap-path-prefix + SOURCE_DATE_EPOCH + 关增量 + CFLAGS file-prefix-map）
#   · boring 出口栈的 cmake + clang/libclang 工具链（见下方 RUN；⚠️ 版本未钉死=硬化待办）
# 配合同版本工具链（复现现行 PCR0 用 Docker 29.1.3 + Nitro CLI 1.4.5 / aarch64；
# 版本以 docs/tee-reproducible-build.md 为准），
# 独立构建两次 PCR0 逐字节一致。
FROM rust@sha256:19817ead3289c8c631c73df281e18b59b172f6a31f4f563290f69cddd06c30e9 AS builder
WORKDIR /src
ENV SOURCE_DATE_EPOCH=0 \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/src=/src --remap-path-prefix=/usr/local/cargo=/cargo"
# boring(BoringSSL)出口栈所需：cmake + clang/libclang（boring-sys 的 bindgen 要 libclang；Go 不需要，v5 预生成）。
# 已验证版本：cmake 3.25.1-1 / clang+libclang-dev 1:14.0-55.7~deb12u1（debian bookworm）。
# ⚠️ 未按版本钉死（依赖 base image digest 锁定的 bookworm 快照稳定）；长期硬化应钉精确版本或走 snapshot.debian.org。
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang libclang-dev && rm -rf /var/lib/apt/lists/*
# C 侧(BoringSSL)编译路径归一 → 复现（与 RUSTFLAGS 的 remap 对应；否则 .o 里嵌绝对路径会漂 PCR0）。
ENV CFLAGS="-O2 -g0 -ffile-prefix-map=/src=/src -ffile-prefix-map=/usr/local/cargo=/cargo" \
    CXXFLAGS="-O2 -g0 -ffile-prefix-map=/src=/src -ffile-prefix-map=/usr/local/cargo=/cargo"
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716
COPY --from=builder /src/target/release/attest /attest
# 归一化整个 rootfs 的 mtime → EIF ramdisk 不再随构建时刻漂移（PCR0 的关键非确定源）。
# 编译产物 /attest 本身已逐字节确定（同 Cargo.lock + 同 digest 基础镜像）。
RUN find / -xdev -exec touch -hcd "@0" {} + 2>/dev/null || true
CMD ["/attest"]
