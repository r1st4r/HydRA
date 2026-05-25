# Hydra：区块链机密计算环境通用可信远程证明协议框架

由**武汉大学**、**浙江蚂蚁密算科技有限公司**共同研发，提出 **Hydra 区块链机密计算环境下通用可信远程证明协议关键构造方法**。

该成果受到以下资助：

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

## 1. 项目概述

本项目实现了一个基于 Rust 的三方验证系统，系统中包含三个主要角色：

- `attester`：被验证方，负责生成本地身份信息、签名数据、生成零知识证明并发送给 relying-party。
- `verifier`：验证者，负责接收 attester 的身份信息，维护 shrubs tree，生成并更新 attester 的 `shrubs_path` 和 `shrubs_tag`。
- `relying-party`：依赖方，负责接收 verifier 发布的公共信息，并验证 attester 提交的零知识证明。

项目支持两种运行模式：

- `passport` 模式：attester 向 verifier 注册并获取响应信息，然后生成 `EvidenceReply`，由 relying-party 进行零知识证明验证。
- `background_check` 模式：attester 将签名后的 `DeviceClientInfor` 发送给 relying-party，relying-party 再签名后转发给 verifier，由 verifier 验证双方签名。

项目使用的主要技术包括：

- Rust 异步网络通信：`tokio`
- ECDSA 签名：`k256::ecdsa`
- 零知识证明：Groth16
- Merkle/shrubs tree 路径计算
- 并行计算：`rayon`
- 本地二进制序列化存储

## 2. 项目目录结构

项目根目录为：

```text
C:\Users\11197\Documents\New project\hydra
```

主要目录如下：

```text
hydra
├── attester
│   └── src/main.rs
├── verifier
│   └── src/main.rs
├── relying-party
│   └── src/main.rs
├── hydra-sys
│   └── src/lib.rs
├── Cargo.toml
└── Cargo.lock
```

各目录作用：

- `attester`：attester 角色的执行程序。
- `verifier`：verifier 角色的执行程序。
- `relying-party`：relying-party 角色的执行程序。
- `hydra-sys`：公共库，存放公共结构体、签名、加密、零知识证明、shrubs tree 相关逻辑。

## 3. 环境安装步骤

### 3.1 安装 Rust

如果电脑还没有安装 Rust，需要先安装 Rust 工具链。

推荐使用 `rustup` 安装。安装完成后，在 PowerShell 中执行：

```powershell
rustc --version
cargo --version
```

如果能正确输出版本号，说明 Rust 安装成功。

### 3.2 进入项目目录

打开 PowerShell，进入项目目录：

```powershell
cd "C:\Users\11197\Documents\New project\hydra"
```

### 3.3 编译检查项目

第一次运行前，建议先执行：

```powershell
cargo check
```

如果依赖完整、代码无错误，会看到类似：

```text
Finished `dev` profile
```

如果出现 warning，例如：

```text
warning: unused variable
```

这类 warning 不影响项目运行。

## 4. 本地数据存储说明

项目中三个角色会分别将自己的本地数据存储在各自目录下，不再统一存储到 `hydra-sys` 目录。

三个角色的数据目录如下：

```text
attester/workspace-data
verifier/workspace-data
relying-party/workspace-data
```

### 4.1 attester 本地数据

attester 每次运行都会创建一个唯一 session 目录，例如：

```text
attester/workspace-data/attester-runs/attester-1779602536325204600-20396-0
```

该目录中会保存：

- `attester_key.bin`
- `dev_infor.bin`
- `dev_config.bin`
- `dev_res.bin`
- `public_context.bin`
- `evidence-*.bin`

每次运行 attester 都会生成不同的 session 目录，避免多个 attester 同时运行时互相覆盖数据。

### 4.2 verifier 本地数据

verifier 会将每个 attester 的响应数据保存到：

```text
verifier/workspace-data/verifier-responses
```

### 4.3 relying-party 本地数据

relying-party 会保存 verifier 发送过来的公共上下文：

```text
relying-party/workspace-data/public_context.bin
```

该文件包含：

- 当前 shrubs tree 的 root
- verifier 的公钥 `verifier_pk`

如果 verifier 发送新的 root，relying-party 会自动更新并覆盖旧数据。

## 5. 运行前注意事项

运行项目时，建议分别打开多个 PowerShell 窗口。

推荐启动顺序：

1. 启动 verifier。
2. 启动一个或多个 relying-party。
3. 启动 attester。

如果端口被占用，会出现类似错误：

```text
通常每个套接字地址(协议/网络地址/端口)只允许使用一次
```

这说明该端口已经有程序在使用。可以关闭对应窗口，或者换一个端口。

## 6. 三个角色的启动指令

以下示例使用一个 verifier、三个 relying-party。

首先进入项目目录：

```powershell
cd "C:\Users\11197\Documents\New project\hydra"
```

### 6.1 启动 verifier

打开第一个 PowerShell 窗口，运行：

```powershell
cargo run -p verifier -- 127.0.0.1:7001 127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004
```

参数说明：

- `127.0.0.1:7001` 是 verifier 自己监听的地址。
- `127.0.0.1:7002`、`127.0.0.1:7003`、`127.0.0.1:7004` 是三个 relying-party 的地址。

verifier 启动后会监听 attester 和 relying-party 发来的消息。

### 6.2 启动第一个 relying-party

打开第二个 PowerShell 窗口，运行：

```powershell
cargo run -p relying-party -- 127.0.0.1:7002 127.0.0.1:7001
```

参数说明：

- `127.0.0.1:7002` 是当前 relying-party 自己监听的地址。
- `127.0.0.1:7001` 是 verifier 的地址。

### 6.3 启动第二个 relying-party

打开第三个 PowerShell 窗口，运行：

```powershell
cargo run -p relying-party -- 127.0.0.1:7003 127.0.0.1:7001
```

### 6.4 启动第三个 relying-party

打开第四个 PowerShell 窗口，运行：

```powershell
cargo run -p relying-party -- 127.0.0.1:7004 127.0.0.1:7001
```

## 7. passport 模式使用方法

`passport` 模式用于完整演示 attester 注册、verifier 响应、attester 生成零知识证明、relying-party 验证证明的流程。

### 7.1 passport 一条指令模式

打开新的 PowerShell 窗口，运行：

```powershell
cargo run -p attester -- passport 127.0.0.1:7001 127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004
```

参数说明：

- 第一个地址 `127.0.0.1:7001` 是 verifier 地址。
- 后面三个地址是 relying-party 地址。

该指令会自动完成以下步骤：

1. attester 生成本地密钥。
2. attester 构造 `DeviceClientInfor`。
3. attester 将签名后的 `DeviceClientInfor` 发送给 verifier。
4. verifier 收集 attester 的 merkle leaf。
5. verifier 构建或更新 shrubs tree。
6. verifier 为 attester 生成 `ResponseDeviceInfor`。
7. verifier 使用 attester 公钥加密响应信息。
8. attester 解密 verifier 返回的响应信息。
9. attester 构造并保存 `DeviceConfigInfor`。
10. attester 生成 `EvidenceReply`。
11. attester 将 `EvidenceReply` 发送给三个 relying-party。
12. relying-party 验证 attester 的零知识证明。
13. attester 保持与 verifier 的连接，继续接收后续更新。

注意：该命令运行后不会立刻退出，因为它会继续保持与 verifier 的 TCP 连接。

如果你想主动断开，可以在 attester 窗口按：

```text
Ctrl + C
```

### 7.2 passport 两步模式

两步模式适合演示“先注册，后续再单独生成证明”的场景。

第一步：提交信息给 verifier。

```powershell
cargo run -p attester -- passport submit 127.0.0.1:7001
```

该命令会输出一个 session 路径，例如：

```text
attester session path: C:\Users\11197\Documents\New project\hydra\attester\workspace-data\attester-runs\attester-xxxx
```

第一步运行后，attester 会保持与 verifier 的连接，并继续接收 verifier 后续推送的最新 `shrubs_path` 和 `shrubs_tag`。

第二步：使用指定 session 生成证明，并发送给 relying-party。

```powershell
cargo run -p attester -- passport evidence --session "这里填写第一步输出的attester session path" 127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004
```

示例：

```powershell
cargo run -p attester -- passport evidence --session "C:\Users\11197\Documents\New project\hydra\attester\workspace-data\attester-runs\attester-xxxx" 127.0.0.1:7002
```

如果不指定 `--session`，attester 会默认读取最近一次 session。

但是，如果你同时运行多个 attester，不建议省略 `--session`，因为最近一次 session 可能被其他 attester 覆盖。

## 8. background_check 模式使用方法

`background_check` 模式下，attester 不直接向 verifier 提交证明，而是先将签名后的 `DeviceClientInfor` 发送给 relying-party。

运行命令：

```powershell
cargo run -p attester -- background_check 127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004
```

该模式流程如下：

1. attester 生成本地密钥。
2. attester 构造 `DeviceClientInfor`。
3. attester 对 `DeviceClientInfor` 进行 ECDSA 签名。
4. attester 将签名后的数据发送给 relying-party。
5. relying-party 验证 attester 签名。
6. relying-party 对该数据再次签名。
7. relying-party 将双签名数据转发给 verifier。
8. verifier 验证 relying-party 签名和 attester 签名。

## 9. 多 attester 测试说明

可以打开多个 PowerShell 窗口，运行多个 attester，用于模拟多个 attester 同时加入系统。

例如，多次运行：

```powershell
cargo run -p attester -- passport 127.0.0.1:7001 127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004
```

每个 attester 都会生成独立 session 目录，因此本地数据不会互相覆盖。

但是需要注意：

- 如果使用一条指令模式，attester 会自己使用当前 session，不容易混淆。
- 如果使用两步模式，第二步建议显式指定 `--session`。
- 如果不指定 `--session`，程序会读取最近一次 session，多个 attester 同时运行时可能读错。

## 10. verifier 动态更新说明

verifier 会批量收集 attester 的 merkle leaf。

第一次批量处理时，verifier 调用：

```rust
create_batch_devices(...)
```

后续有新的 attester 加入时，verifier 调用：

```rust
insert_batch_devices(...)
```

每次 shrubs tree 更新后，verifier 都会重新为所有历史 attester 计算：

- `shrubs_path`
- `shrubs_tag`
- verifier 签名 `sig`
- 最新 `ResponseDeviceInfor`

该过程使用 `rayon` 并行处理，提高多个 attester 场景下的更新效率。

attester 如果保持与 verifier 的连接，就会自动收到更新，并保存到自己的 session 目录。

如果 attester 主动断开连接，那么 verifier 后续无法再主动推送最新路径信息给该 attester。此时如果使用旧的 `shrubs_path` 和 `shrubs_tag` 生成 proof，可能导致 relying-party 验证失败。

## 11. relying-party 验证说明

relying-party 不需要在命令行指定模式。

它会根据收到的消息类型自动判断：

- 收到 `PublicContext`：保存 verifier 发来的 root 和 verifier 公钥。
- 收到 `DeviceClientInfor`：按 `background_check` 流程处理。
- 收到 `EvidenceReply`：按 `passport` 流程验证零知识证明。

在 passport 模式下，relying-party 验证零知识证明时，会输出 attester 公钥编码。

成功示例：

```text
relying-party proof verification success; attester_pubkey=...
```

失败示例：

```text
relying-party proof verification failed; attester_pubkey=...
```

## 12. 常见问题

### 12.1 端口被占用

错误示例：

```text
通常每个套接字地址(协议/网络地址/端口)只允许使用一次
```

原因：该端口已经被其他进程占用。

解决方法：

- 关闭占用该端口的 PowerShell 窗口。
- 或者更换端口，例如把 `7002` 改为 `7012`。

### 12.2 attester 第二步验证失败

如果运行：

```powershell
cargo run -p attester -- passport evidence --session "某个旧session路径" 127.0.0.1:7002
```

relying-party 可能输出：

```text
relying-party proof verification failed
```

常见原因是：

- 该 session 中保存的是旧 root。
- verifier 后续已经插入新节点。
- attester 没有保持连接，因此没有收到最新 `shrubs_path` 和 `shrubs_tag`。

解决方法：

- 保持第一步 `passport submit` 的窗口不要关闭。
- 等待 verifier 更新后，使用同一个 session 再执行第二步。
- 或者直接使用 passport 一条指令模式。

### 12.3 relying-party 出现 MalformedVerifyingKey

该错误通常表示零知识证明验证时 public inputs 不匹配。

常见原因：

- proof 是用旧 root 生成的。
- relying-party 已经保存了 verifier 最新 root。
- proof 中 public input 数量和当前 root 长度不一致。

当前代码已经将该错误处理为验证失败，不会导致 relying-party 直接崩溃。

### 12.4 多个 attester 是否会互相影响

一般不会。

因为每次 attester 运行都会创建唯一 session 目录。

但如果使用两步模式，并且第二步不指定 `--session`，可能会读取最近一次 session，从而读到其他 attester 的数据。

因此，多 attester 测试时建议显式指定：

```powershell
--session "attester session path"
```

## 13. 推荐演示流程

推荐使用以下流程进行完整演示。

第一步，启动 verifier：

```powershell
cargo run -p verifier -- 127.0.0.1:7001 127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004
```

第二步，启动三个 relying-party：

```powershell
cargo run -p relying-party -- 127.0.0.1:7002 127.0.0.1:7001
```

```powershell
cargo run -p relying-party -- 127.0.0.1:7003 127.0.0.1:7001
```

```powershell
cargo run -p relying-party -- 127.0.0.1:7004 127.0.0.1:7001
```

第三步，运行 passport 模式：

```powershell
cargo run -p attester -- passport 127.0.0.1:7001 127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004
```

第四步，如需测试 background_check：

```powershell
cargo run -p attester -- background_check 127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004
```


