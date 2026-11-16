# driver — xiezhi LKM 采集驱动（主线）

> 全新开发（参考 Elkeid 思路，不抄代码），目标内核 CentOS 7（3.10.0-x.el7）。
> 版权许可为 Apache-2.0（仓库根 LICENSE）；源码内 `MODULE_LICENSE("GPL")`
> 是内核接口要求，见 LICENSE 末尾说明。

## 状态

M0 骨架：kprobe 登记表框架（LIFO 注册回退）+ 模块入口。事件 hook 自 M1 起填充。

## 构建

目标机器直接构建：

```bash
cd driver && make
```

交叉构建（本机无 3.10 环境，在 centos:7 容器内装目标内核 headers 编译）：

```bash
tools/build_driver_docker.sh 3.10.0-1160.el7.x86_64
```

构建矩阵内核清单按目标车队内核分布实拉（M0）。

## 约束（开发红线）

- handler 内禁睡眠；锁只用 spinlock；用户态内存 copy_from_user 系。
- 每个新增内核 API 调用先核对 3.10 语义（fput 事故先例）。
- 加载器版本锁（uname -r 精确匹配）+ 崩溃退避（dmesg 扫描）由 agent 侧实现。
- 运行时验证仅限 CentOS 7 KVM 虚机（待 libvirt 授权后搭建），宿主机禁止 insmod。
