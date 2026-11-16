# rules — 检测规则（M3 规则引擎 / M4 意图风险分）

两类规则：

- **field**：字段规则（Elkeid-HUB 算子集语义：INCL/EQU/NEQ/REGEX/START/END/MT/LT +
  AND/OR 组合），YAML 声明，服务端热更（ed25519 签名+单调版本）。
- **intent**：意图风险分规则（SecEBL tag_risk_policy 格式：标签静态分+marker+会话累加
  阈值+运维降噪），M4 接入。

`examples/` 为格式示例，引擎实现在 M3，规则语法以实现时冻结的 schema 为准。
