#!/bin/bash
# 生成 proto Go 代码（protoc 经 docker，宿机无需装链）。
# Git Bash/MSYS 下 $PWD 会被误转换，挂载路径用 pwd -W 取 Windows 形态。
set -euo pipefail
cd "$(dirname "$0")/.."
WINPWD="$(pwd -W 2>/dev/null || pwd)"
docker build -q -t xiezhi-protoc tools/proto >/dev/null
MSYS_NO_PATHCONV=1 docker run --rm -v "$WINPWD":/w -w /w xiezhi-protoc \
  protoc -I proto \
  --go_out=. --go_opt=module=github.com/xycxmz/xiezhi-public \
  --go-grpc_out=. --go-grpc_opt=module=github.com/xycxmz/xiezhi-public \
  proto/event.proto proto/ingest.proto
ls -l proto/*.pb.go
