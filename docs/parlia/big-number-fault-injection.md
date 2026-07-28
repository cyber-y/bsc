# Header.Number 大数截断故障注入（正常 miner 路径 · QA 验证）

> 仅用于 **devnet / QA** 环境验证 `big.Int -> uint64` 截断防御。**禁止用于生产**。
> 代码对 BSC 主网（chainID 56）与 Chapel 测试网（chainID 97）做了硬禁用，无视环境变量。
> 注入只挂在**正常 miner 出块路径**（`Prepare`）上；MEV / BidBlock 路径（`PrepareForBidBlock`）**不注入**。

## 1. 威胁模型

一个合法签名者（validator）在**出块时**把 `header.Number` 抬高 `2^64`：

- `header.Number = 真实高度 H + 2^64`
- 低 64 位不变，因此 `header.Number.Uint64() == H`，所有基于 `Uint64()` 的检查都自洽；
- 但 `header.Number` 的 `BitLen() > 64`，`IsUint64() == false`，即 `Header.SanityCheck()` 应当拒绝的形态。

注入发生在 `Prepare()` 里、`FinalizeAndAssemble` / `Seal` **计算签名之前**，所以 seal 签名是对这个“畸形大数 header”本身签的，**签名合法**。这与“封块后再篡改”不同——后者会被 `verifySeal` 的 ecrecover 失配拦下，掩盖真正要验证的“数值形态”缺陷。

## 2. 代码位置与开关

- 注入实现：`consensus/parlia/big_number_injection.go`
- 挂载点：`consensus/parlia/parlia.go` 的 `Prepare()` 末尾调用 `p.maybeInjectBigBlockNumber(header)`（**仅此一处**）
- 开关（默认关闭，opt-in）：环境变量 `MALICIOUS_BIG_NUMBER=1`
- 安全护栏：mainnet / chapel 直接返回，忽略环境变量

```bash
# 恶意 validator 节点上启用（须写进进程环境，见第 4 节）
export MALICIOUS_BIG_NUMBER=1
```

## 3. 传播路径与预期结果（修复验证的核心观测矩阵）

同一个新出的块会同时经两条路发给不同 peer 子集（见 `eth/handler.go: BroadcastBlock`）：

| 观测点 | 路径 | 关键防御锚点 | 未修复时的现象 | 说明 |
|---|---|---|---|---|
| 出块节点自身 | 本地封块 + 写库 | `miner/worker.go` `WriteBlockAndSetHead`（不调 `SanityCheck`）；`Seal`/`Finalize` 用 `Uint64()` 截断到 H | 正常封块、入库、并广播 | 本地全部 uint64 检查自洽 |
| 完整块广播 peer | `NewBlockMsg` | `eth/protocols/eth/protocol.go` `NewBlockPacket.sanityCheck` → `core/types/block.go:192` `!IsUint64()` | **被拒**（“too large block number”），签名检查都没轮到 | 这是唯一生效的数值形态防御 |
| 仅广播哈希 peer | `NewBlockHashesMsg` + fetcher 拉取 | `eth/fetcher/block_fetcher.go` `header.Number.Uint64() != announce.number`（截断比较，通过）；`InsertChain`（不调 `SanityCheck`） | **被接受入库**：畸形大数 Number 写进 peer 的规范链，落在截断后的高度 H | 绕过点：全程无 `IsUint64` 形态检查，仅 `verifySeal` 校验签名而签名又是合法的 |

**修复验证判定：**

- **修复有效**：仅广播哈希 + fetcher 路径的 peer 也应**拒绝**该块（在 fetcher 的 `verifyHeader` 回调 / `InsertChain` / Parlia `VerifyHeader` 中补 `!Number.IsUint64()` 检查后，日志出现 “too large block number” 或等价拒绝，且该 peer 规范链高度 H 上不是这个恶意 hash）。
- **修复无效 / 存在缺口**：该 peer 日志显示成功 import，`eth_getBlockByNumber(H)` 能查到这个 hash，且直接读取 `header.Number`（非 `.Uint64()`）时得到 `H + 2^64` 这样的巨大值。

## 4. 运行步骤（QA devnet）

1. 起一条本地 devnet（≥ 2 个 validator + 若干全节点 peer），确认 chainID 既不是 56 也不是 97。
2. 用**打了本注入的二进制**在其中一个 validator 上启动，并保证 `MALICIOUS_BIG_NUMBER=1` 进入**进程环境**：
   - systemd：unit 里 `Environment=MALICIOUS_BIG_NUMBER=1`；
   - docker：`-e MALICIOUS_BIG_NUMBER=1`；
   - 直接起进程：与启动命令同一 shell 内 `export`。
   仅在交互 shell `export` 而 daemon 已在运行**不会**生效。确认：`cat /proc/<pid>/environ | tr '\0' '\n' | grep MALICIOUS`。
3. 等该 validator 轮到出块（该注入只在它自建块时触发），抓恶意节点日志中的：
   `MALICIOUS_BIG_NUMBER active: inflated header.Number beyond uint64`
   记录 `expectedHeight`(H)、`bigNumber`(H+2^64)、`coinbase`。
4. 到各 peer 节点按上表对照现象。
5. 对比“打了修复”与“未打修复”两组二进制，确认修复后**所有**路径都拒绝。

## 5. 清理

- 验证结束后 `unset MALICIOUS_BIG_NUMBER` 并用未注入的二进制重启，或直接回退 `consensus/parlia/big_number_injection.go` 与 `parlia.go` 中的挂载调用。
- 该注入不得进入任何面向主网 / Chapel 的发布分支；本工作位于 `test` 分支。
