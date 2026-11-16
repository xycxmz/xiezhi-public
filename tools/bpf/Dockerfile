FROM ubuntu:24.04
# 本网络下 archive.ubuntu.com 的 apt 常瞬时 100（R8.4 终门禁实测两轮失败）；
# 换 aliyun 镜像 + 重试，与 build_driver_docker.sh 的 aliyun vault 同惯例。
RUN sed -i 's|archive.ubuntu.com|mirrors.aliyun.com|g; s|security.ubuntu.com|mirrors.aliyun.com|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true     && apt-get update -o Acquire::Retries=3 && apt-get install -y --no-install-recommends       clang llvm libbpf-dev make     && rm -rf /var/lib/apt/lists/*
WORKDIR /w
