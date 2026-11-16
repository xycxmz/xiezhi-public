# 贡献指南

感谢你有兴趣为 xiezhi 做贡献。

## 开发环境

- Go 1.22+
- 驱动编译（可选）：Docker（CentOS 7 工具链容器）
- proto 重新生成（改了 `proto/` 才需要）：Docker 里的 protoc（`tools/gen_proto.sh`）

```bash
make test && make vet   # 提交前必须全绿
go run ./server/tools/r5check tools/benchmark/corpus.yaml rules/seed   # 检出门禁
go run ./server/tools/r5check tools/benchmark/probes.yaml   rules/seed # 误报门禁
```

## 服务端部署依赖（自建环境）

代码仓里看不到的运行时依赖在这里列全（版本自选，均为常见容器形态）：

| 组件 | 必需性 | 用途 | 对应配置 |
|---|---|---|---|
| ClickHouse | **必需** | 事件/告警/研判落库 | `XIEZHI_CH_DSN`（例 `clickhouse://user:pass@host:19000/xiezhi`），库表由 server 自动建 |
| NATS | **必需** | 事件双写总线（与 CH 并行，供实时消费方） | `XIEZHI_NATS_URL`，默认 `nats://127.0.0.1:4222`；server 启动时连不上会拒启 |
| PostgreSQL | 可选 | first-seen 降噪、会话树聚合、告警溯源钻取 | `XIEZHI_PG_DSN`；不配则这三层禁用（日志 WARN） |

其余按需开关的环境变量见 `server/cmd/xiezhi-server/main.go` 顶部装配段：mTLS（`XIEZHI_TLS_CA/CERT/KEY`）、控制台（`XIEZHI_CONSOLE_PASSWORD`）、LLM 研判（`XIEZHI_LLM_*`，缺省 provider=mock 零外部依赖）、degraded 外部出口（`XIEZHI_WEBHOOK_URL`）、规则验签 fail-closed（`XIEZHI_RULES_REQUIRE_SIGNATURE=1`）。

部署参考：`tools/deploy_server.sh`（host 必填）与 `tools/xiezhi-server.service`、`tools/xiezhi-agent.service`（systemd 单元）。

## 提交规范

- 一个 PR 做一件事；标题用一句中文（或英文）说清楚改了什么、为什么。
- 涉及检测行为的改动（规则 / 引擎 / 意图层）：**必须**附带基准集结果的前后对比——新增检出或消除误报都拿用例说话；r5check 两条门禁退出码必须为 0。
- 涉及内核驱动（`driver/`、`bpf/`）的改动：说明在哪些内核 build 上验证过（至少一个 3.10.0-1160 系列 + 一个现代内核），并确认版本锁拒载路径未被破坏。
- 新增依赖需要说明理由；供应链敏感项目从严。

## 检测规则贡献

规则文件在 `rules/seed/*.yaml`，改动后需重新签名：

```bash
tools/gen_signing_key.sh   # 首次生成 ed25519 密钥对
tools/sign_rules.sh        # 生成 manifest 签名
```

规则 PR 请包含：触发该行为的完整命令/样本（进 corpus 或 probes）、预期严重级别、误报边界说明（哪些正常运维动作会碰到同类事件）。

## 安全问题

不要在 issue / PR / commit message 里放真实环境的 IP、凭据、样本哈希以外的攻击载荷细节。漏洞走 [SECURITY.md](SECURITY.md) 的私下披露流程。

## 行为准则

保持专业与尊重。对事不对人。
