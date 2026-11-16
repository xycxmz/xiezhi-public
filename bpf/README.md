# bpf — eBPF 采集线（M5）

cilium/ebpf + bpf2go，服务车队中的现代内核机器（TencentOS 2.4/Ubuntu 22.04+/Rocky/6.8 等），
事件 schema 与 LKM 线同一 `proto/event.proto`。

在 libvirt 挂起期间，本线承担端到端链路的真实运行时验证（6.8 内核宿主全功能）。
