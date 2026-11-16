#!/bin/bash
# 用法：tools/build_driver_docker.sh <内核版本>
# 例：  tools/build_driver_docker.sh 3.10.0-1160.el7.x86_64
# 在 centos:7 容器内（vault 源）装 kernel-devel-<版本> 后编译 driver/*.ko。
# 产物留在 driver/ 下（.ko 已进 .gitignore，不入库）。
# Git Bash 下 MSYS 会把容器内路径误转换成盘符，须 MSYS_NO_PATHCONV=1 并用
# pwd -W 取 Windows 形态挂载（同 tools/gen_bpf.sh）。
set -euo pipefail
KVER="${1:?usage: build_driver_docker.sh <kernel-version>}"
# M 批：KVER 拼进远端（容器内）shell 命令，先做白名单校验防注入，
# 形如 3.10.0-1160.el7.x86_64：el7 前仅数字/点/横线，el7 后仅内核版本
# 字符（数字/小写字母/点/下划线/横线）——全串锚定，杜绝 el7 后元字符注入。
if ! printf '%s' "$KVER" | grep -Eq '^[0-9][0-9.-]*el7[0-9a-z._-]*$'; then
  echo "FATAL: KVER 不合规: $KVER（期望形如 3.10.0-1160.el7.x86_64）" >&2
  exit 1
fi
cd "$(dirname "$0")/.."
WINPWD="$(pwd -W 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 docker run --rm -v "$WINPWD:/src" -w /src/driver centos:7 bash -exc "
  sed -i -e 's/mirror.centos.org/vault.centos.org/g' \
         -e 's|^#baseurl=http|baseurl=http|' \
         -e 's|^mirrorlist=http|#mirrorlist=http|' /etc/yum.repos.d/*.repo &&
  # vault.centos.org 对本网络不稳（403），优先阿里云 centos-vault 镜像
  sed -i 's|vault.centos.org/centos/\\\$releasever|mirrors.aliyun.com/centos-vault/7.9.2009|g' /etc/yum.repos.d/*.repo &&
  # 老内核的 kernel-devel 不在 7.9 仓：从所在更新线的历史 vault 仓兜底
  # （版本号是发行版代号：7.5.1804/7.6.1810/7.7.1908/7.8.2003；缺仓跳过不拖死 yum）
  cat > /etc/yum.repos.d/centos-vault-history.repo <<'REPO'
[c7.5]
name=CentOS-7.5.1804-updates
baseurl=https://mirrors.aliyun.com/centos-vault/7.5.1804/updates/\$basearch/
# 取舍：centos-vault 历史更新线已不再提供/维护 repo GPG 签名（vault 归档
# 无 repodata 签名可验），gpgcheck 只能置 0；缓解=baseurl 锁 https 阿里云
# vault 归档 + 仅装 kernel-devel 单包 + 一次性构建容器（--rm，用完即弃）。
gpgcheck=0
skip_if_unavailable=1
[c7.6]
name=CentOS-7.6.1810-updates
baseurl=https://mirrors.aliyun.com/centos-vault/7.6.1810/updates/\$basearch/
gpgcheck=0
skip_if_unavailable=1
[c7.7]
name=CentOS-7.7.1908-updates
baseurl=https://mirrors.aliyun.com/centos-vault/7.7.1908/updates/\$basearch/
gpgcheck=0
skip_if_unavailable=1
[c7.8]
name=CentOS-7.8.2003-updates
baseurl=https://mirrors.aliyun.com/centos-vault/7.8.2003/updates/\$basearch/
gpgcheck=0
skip_if_unavailable=1
REPO
  yum install -y "kernel-devel-$KVER" make gcc perl &&
  make KVER="$KVER" KDIR=/usr/src/kernels/$KVER clean >/dev/null &&
  make KVER='$KVER' KDIR=/usr/src/kernels/$KVER &&
  mkdir -p /src/build/ko && cp -f xiezhi_driver.ko "/src/build/ko/xiezhi_driver-$KVER.ko" &&
  /sbin/modinfo "/src/build/ko/xiezhi_driver-$KVER.ko" | head -6 &&
  ls -l "/src/build/ko/xiezhi_driver-$KVER.ko"
"
