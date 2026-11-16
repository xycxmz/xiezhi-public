# xiezhi（獬豸）

Linux 主机入侵检测系统：内核级事件采集 + 规则 / 意图 / LLM 三层检测。

獬豸是中国神话中明辨是非的神兽——这个项目做的事是同一件：在一台被攻陷的主机上，判断「正在发生的事」是不是入侵。

```
┌─────────────────────── 主机 ───────────────────────┐    ┌────────────────── 服务端 ──────────────────┐
│  eBPF 线（现代内核 ≥4.x）      LKM 线（CentOS 7 / 3.10）│    │  mTLS gRPC 接入 + spool 重放 + 幂等去重      │
│  events.bpf.c                 xiezhi.ko (kprobe)    │    │  规则引擎（ed25519 签名，fail-closed）       │
│        └──────────────┬──────────────┘             │───▶│  意图标签 + 会话树聚合（RootFinder）         │
│                       agent（Go，单进程）            │    │  LLM 研判（shadow 三态，零关闭权）           │
│  自保护：dead-man 心跳 / spool 离线暂存              │    │  告警 + Web 控制台（ack / SSE / 溯源钻取）    │
└────────────────────────────────────────────────────┘    └────────────────────────────────────────────┘
```

## 为什么又造一个 HIDS

调研了 Elkeid / Wazuh / 驭龙等开源方案，没有找到同时满足这几点的：

- **CentOS 7 / 3.10 内核一等公民**：大量存量机器没有 eBPF，本项目用一条自研 LKM kprobe 采集线覆盖它们，与新内核 eBPF 线并存于同一个 agent。
- **误报治理是设计目标而不是运营活**：规则输入做规范化（shell 语法折叠、编码折叠），规则层之上叠意图标签层，再之上叠 LLM shadow 研判——每层都为压误报服务。
- **规则供应链可信**：规则包 ed25519 签名，验签失败 fail-closed 拒载，而非哈希对账。
- **agent 被摘除本身就是告警**：dead-man 看门狗心跳缺失 × 云电源状态对账（关机机抑制，不误报），带外感知 agent 下线。

## 架构速览

| 组件 | 位置 | 说明 |
|---|---|---|
| agent | `agent/` | 单进程 Go agent；加载 eBPF（libbpf CO-RE）或 LKM ko；事件富化（argv/tty/cgroup/pid_tree）后 gRPC 上送 |
| eBPF 采集 | `bpf/events.bpf.c` | execve / connect / DNS / memfd / module 等探针，vmlinux.h 由目标内核 BTF 生成 |
| LKM 采集 | `driver/` | CentOS 7（3.10.0-1160 系列）kprobe 驱动；加载器带版本锁，未知 build 拒载 |
| server | `server/` | 接入（mTLS+spool 重放）→ 规则引擎 → 意图标签 → 会话树聚合（RootFinder 找意图桶锚点）→ 告警 |
| LLM 研判 | `server/internal/llm/` | DeepSeek 兼容端点；shadow 三态输出（escalate / insufficient / dismiss），对告警无关闭权，先观察后放量 |
| 控制台 | `server/internal/httpapi/static/` | 单文件原生 JS，六 tab：总览/告警/意图/规则/Agent/审计；ack 流转、SSE 实时、告警溯源抽屉 |
| 规则 | `rules/seed/` | 43 条 seed 规则（凭据访问/持久化/横向/渗出/挖矿/反弹 shell…），带签名 manifest 与 pubkey |

安全机制一览：

- **规则签名**：ed25519 manifest，验签失败 fail-closed（`tools/sign_rules.sh`）
- **传输**：mTLS gRPC，双向证书；断网本地 spool 环形暂存，恢复补传 + 服务端幂等去重
- **存活**：systemd `WATCHDOG` + 服务端 dead-man 心跳对账；agent 被停 = 带外告警
- **LLM 隔离**：研判只读影子链路，输出三态且不可关闭告警；prompt 注入面收敛在服务端模板

## 快速开始

依赖：Go 1.22+；跑 driver 编译需 Docker（CentOS 7 工具链容器）。

```bash
# 编译（agent + server，linux/amd64）
make build

# 测试 + 静态检查
make test && make vet

# 检测质量门禁（基准集 102 用例：75 攻击检出 + 15 误报压制，退出码即判定）
go run ./server/tools/r5check tools/benchmark/corpus.yaml rules/seed
go run ./server/tools/r5check tools/benchmark/probes.yaml   rules/seed

# 生成 mTLS 证书 / 生成规则签名密钥 / 规则签名
tools/gen_certs.sh && tools/gen_signing_key.sh && tools/sign_rules.sh

# 部署（systemd 单元在 tools/*.service，部署脚本 host 必填）
tools/deploy_server.sh root@your-server
```

内核驱动编译（可选，仅 CentOS 7 目标机需要）：

```bash
tools/build_driver_docker.sh 3.10.0-1160.80.1.el7.x86_64   # Docker 内交叉编译 ko
```

## 检测能力与实测

数字来自自建基准集（`tools/benchmark/`，ECS 真实链路执行）：

- **检出**：corpus 75 攻击用例 100% 检出（规则 43 条 + 意图层）
- **误报**：probes 15 个日常运维动作误报 2 例（93% 压制），长尾由 LLM shadow 研判吸收
- **LLM 研判**（shadow 期实测）：escalate 判定 84% 落在 high+ 告警；证据不足显式输出 insufficient 而非硬猜（NOP 树证据补齐后 insufficient 率从 86.9% 降到 18%）
- **性能**：agent 常态 CPU ~2%；服务端会话树聚合 + ClickHouse 落库按千台级事件量预算设计

## 已知边界

- 3.10 线无 eBPF 面（`bpf()` 系统调用 3.18 才引入），rootkit 检测依赖驱动自身完整性
- LLM 研判处于 shadow 阶段，不参与告警关闭决策
- 多机关联攻击（横向移动跨机串联）未在 v1 范围
- 控制台单管理员模型，多租户/RBAC 未做

## 贡献与安全披露

- 贡献指南：[CONTRIBUTING.md](CONTRIBUTING.md)
- 漏洞披露：[SECURITY.md](SECURITY.md)（请勿直接开公开 issue 报安全漏洞）

## License

[Apache-2.0](LICENSE)。

注意：`driver/` 是 Linux 内核模块，其源码中的 `MODULE_LICENSE("GPL")` 是内核模块加载接口的要求（用于访问 kprobe 等 GPL-only 符号），**不是**本项目的版权许可证；本项目全部代码（含 `driver/`）的版权许可为 Apache-2.0，详见 LICENSE 末尾说明。
