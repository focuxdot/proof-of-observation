#!/usr/bin/env bash
# 在对齐工具链的 aarch64 box 上做两次独立复现构建（工具链版本见 docs/tee-reproducible-build.md），
# 打印两次 PCR0 并比对。两次逐字节一致 → 可复现。详见 docs/tee-reproducible-build.md。
#
#   ./reproducible-build.sh [build_dir]    # 默认 ${HOME}/attest-build
#
# 所有 docker / build-enclave 输出都落到 *.docker.log / *.enclave.log（失败可直接读），
# 不靠 stdout 捕获，避免错误被吞。进度打到 stdout（journal 可见）。
set -uo pipefail

DIR="${1:-${HOME}/attest-build}"
cd "$DIR"

# nitro-cli build-enclave 需要 blobs 路径 + 工件目录 + root；非登录 shell（systemd/ssh -c）
# 不会自动带这些 env，且写 EIF 需 root，故统一用 `sudo env VARS ...`。
BLOBS=/usr/share/nitro_enclaves/blobs
ARTIFACTS="$DIR/nitro-artifacts"
mkdir -p "$ARTIFACTS"

extract_pcr0() { grep '"PCR0"' "$1" 2>/dev/null | grep -oE '[0-9a-f]{96}' | head -1; }

run_build() { # $1=tag $2=eif $3=docker_log $4=enclave_log
  local tag="$1" eif="$2" dlog="$3" elog="$4"
  # 清掉上轮可能为 root 所有的同名产物（eif 由 sudo nitro-cli 生成→root），否则 the build user
  # 重定向 >"$dlog" / 写 eif 会被拒（Permission denied），整轮误判为构建失败。
  sudo rm -f "$dlog" "$elog" "$eif"
  echo "## docker builder prune"
  docker builder prune -af >/dev/null 2>&1 || true
  echo "## docker build --no-cache -t $tag  (→ $dlog)"
  if ! docker build --no-cache -t "$tag" . >"$dlog" 2>&1; then
    echo "!! DOCKER_BUILD_FAILED ($tag) — 末尾 50 行:"
    tail -50 "$dlog"
    exit 11
  fi
  echo "## nitro-cli build-enclave → $eif  (→ $elog)"
  sudo rm -f "$eif"
  if ! sudo env NITRO_CLI_BLOBS="$BLOBS" NITRO_CLI_ARTIFACTS="$ARTIFACTS" \
        nitro-cli build-enclave --docker-uri "$tag" --output-file "$eif" >"$elog" 2>&1; then
    echo "!! BUILD_ENCLAVE_FAILED ($tag) — 末尾 30 行:"
    tail -30 "$elog"
    exit 12
  fi
}

echo "######## BUILD A ########"
run_build attest:v6a "$DIR/v6a.eif" "$DIR/v6a.docker.log" "$DIR/v6a.enclave.log"
PA=$(extract_pcr0 "$DIR/v6a.enclave.log")
echo "PCR0_A=$PA"

echo "######## BUILD B ########"
run_build attest:v6b "$DIR/v6b.eif" "$DIR/v6b.docker.log" "$DIR/v6b.enclave.log"
PB=$(extract_pcr0 "$DIR/v6b.enclave.log")
echo "PCR0_B=$PB"

echo "######## RESULT ########"
if [ -n "$PA" ] && [ "$PA" = "$PB" ]; then
  echo "REPRO_RESULT=MATCH"
  echo "CANONICAL_PCR0=$PA"
else
  echo "REPRO_RESULT=DIFFER (A=$PA B=$PB)"
  exit 3
fi
