# Hydra：区块链机密计算环境通用可信远程证明协议框架

由**武汉大学**、**浙江蚂蚁密算科技有限公司**共同研发，提出 **Hydra 区块链机密计算环境下通用可信远程证明协议关键构造方法**。

该成果受到以下项目资助：

- **中国网络空间安全协会**
- **中国互联网发展基金会**
- **第三期网络安全学院学生创新资助计划**

---

## 成果简介

Hydra 面向区块链机密计算环境中多类型 TEE 架构并存、证明协议不统一、跨架构互操作验证困难等问题，基于 **IETF 远程证明服务标准 RATS**，构建了一套通用可信远程证明协议框架。

该框架通过统一设备认证、证明生成、证明验证与链上可信调用流程，实现不同 TEE 架构之间的互操作验证，为数据要素在混合 TEE 环境中的合规、安全流通与价值转化提供技术参考。

---

## 核心工作

###  通用可信远程证明协议设计

基于 **IETF RATS** 标准，提出一种面向区块链机密计算环境的通用可信远程证明协议。该协议通过统一设备身份认证与证明验证流程，实现异构 TEE 设备在区块链环境中的可信接入与可验证运行。

该协议具备以下特性：

- 支持不同 TEE 架构之间的互操作验证；
- 支持交互式与非交互式协同证明；
- 具备公共可验证性；
- 具备证据透明性；
- 支持无信任验证；
- 支持 TEE 设备的动态批量添加与删除；
- 支撑混合 TEE 环境下数据要素的合规流通、安全共享与价值转化。

---



## 成果特点

Hydra 的主要创新与优势如下：

| 特性 | 说明 |
|---|---|
| 通用性 | 支持多种主流 TEE 架构，适用于异构可信执行环境 |
| 互操作性 | 通过统一远程证明协议实现跨 TEE 架构可信验证 |
| 公共可验证性 | 验证过程可由多方独立完成，降低中心化信任依赖 |
| 证据透明性 | 证明证据与验证结果可链上记录，便于审计与追溯 |
| 无信任验证 | 借助区块链与密码学机制减少对单一验证方的依赖 |
| 动态扩展性 | 支持 TEE 设备批量添加、删除与状态更新 |
| 区块链适配性 | 面向区块链机密计算场景设计，支持智能合约可信调用 |

---

## 应用价值

Hydra 可为区块链机密计算环境提供统一、可验证、可扩展的可信远程证明支撑，适用于以下场景：

- 区块链节点可信接入；
- 机密计算任务可信调度；
- 数据要素可信流通；
- 多 TEE 架构协同验证；
- 智能合约调用前可信状态确认；
- 设备状态链上透明管理；
- 分布式可信基础设施建设。

---

## 项目结构

- `attester`：生成设备信息 `dev_infor`，发送给 `verifier`；收到 `dev_res` 后生成 `reply` 和 `sig`，发送给 `relying-party`。
- `verifier`：持续监听 attester 的连接，接收 `dev_infor`，生成 `dev_res`、`root` 和 verifier 公钥；把 `dev_res + public_context` 返回给 attester，同时把公开的 `root + verifier_pk` 发布给 relying-party。
- `relying-party`：持续监听，接收 verifier 发布的公开上下文，也接收 attester 发来的证据并执行最终验证。

默认地址：

- verifier：`127.0.0.1:7001`
- relying-party：`127.0.0.1:7002`

## 推荐启动方式：打开 3 个 cmd

### cmd 1：启动 relying-party

```bash
cargo run -p relying-party
```

### cmd 2：启动 verifier

```bash
cargo run -p verifier
```

### cmd 3：启动 attester，触发一次完整流程

```bash
cargo run -p attester
```

运行后流程是：

```text
attester -> verifier: dev_infor
verifier -> attester: dev_res + public_context
verifier -> relying-party: public_context(root + verifier_pk)
attester -> relying-party: reply + sig
relying-party: rely_party_verification(&root, &reply, sig, &verifier_pk)
```

`verifier` 和 `relying-party` 都是持续监听的。你可以多次执行 `cargo run -p attester`，每次都会重新发起一轮认证流程。

## 自定义端口

### relying-party

```bash
cargo run -p relying-party -- 127.0.0.1:8002
```

### verifier

第一个参数是 verifier 自己监听的地址，第二个参数是 relying-party 地址：

```bash
cargo run -p verifier -- 127.0.0.1:8001 127.0.0.1:8002
```

### attester

第一个参数是 verifier 地址，第二个参数是 relying-party 地址：

```bash
cargo run -p attester -- 127.0.0.1:8001 127.0.0.1:8002
```

## 通信格式

TCP 采用简单长度前缀帧：

```text
8 字节 big-endian u64 消息长度 + 消息体
```

其中发给 relying-party 的消息体前 4 字节用于区分消息类型：

- `PUBC`：verifier 发布的公开上下文 `PublicContext`
- `EVID`：attester 发送的证据消息 `EvidenceReply + Signature`

