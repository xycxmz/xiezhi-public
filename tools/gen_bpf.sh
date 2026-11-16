#!/bin/bash
# 编译 eBPF 采集程序 → agent/internal/collector/ebpf/events.bpf.o（CO-RE，clang 经 docker）。
# vmlinux.h 来自 5.8+ 目标内核 BTF（当前基于 6.8 内核生成，见 bpf/README）。
set -euo pipefail
cd "$(dirname "$0")/.."
WINPWD="$(pwd -W 2>/dev/null || pwd)"
# buildkit 网络层在本机对 apt 网络异常（docker run 同命令可过）：
# 先试 buildkit，失败回退传统构建器（R8.4 终门禁实测两轮 100）。
docker build -q -t xiezhi-bpf-clang tools/bpf >/dev/null 2>&1 ||   DOCKER_BUILDKIT=0 docker build -q -t xiezhi-bpf-clang tools/bpf >/dev/null
MSYS_NO_PATHCONV=1 docker run --rm -v "$WINPWD":/w -w /w xiezhi-bpf-clang \
  clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I bpf -c bpf/events.bpf.c \
  -o agent/internal/collector/ebpf/events.bpf.o
ls -l agent/internal/collector/ebpf/events.bpf.o
