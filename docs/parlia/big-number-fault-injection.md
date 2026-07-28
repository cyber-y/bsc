# Header.Number 大数截断故障注入（正常 miner 路径 · QA 验证）

> 仅用于 **devnet / QA** 环境验证 `big.Int -> uint64` 截断防御。**禁止用于生产**。
> 代码对 BSC 主网（chainID 56）与 Chapel 测试网（chainID 97）做了硬禁用，无视环境变量。
> 注入只挂在**正常 miner 出块路径**（`Prepare`）上；MEV / BidBlock 路径（`PrepareForBidBlock`）**不注入**。
>
> **开关语义（默认开启，反向）**：注入**默认开启**，无需设任何环境变量。仅当
> `MALICIOUS_BIG_NUMBER=2` 时**关闭**；unset / `""` / `1` / 除 `2` 外的任意值都视为开启。
>
> **两种攻击模式**（`MALICIOUS_BIG_NUMBER_MODE`）：
> - `add64`（默认）：`Prepare` 里 `Number += 2^64`，`Uint64()` 保持 = 真实高度 H。
> - `zero64`：`Seal` 签名前把 `Number = H<<64`，低 64 位全 0 → `Uint64() == 0`，用于**逃逸 `verifyCascadingFields` 的 `number==0` genesis 短路**（即绕过放在该短路之后的父子高度连续性修复）。

## 0. 两种模式与 zero64 逃逸原理

| 模式 | 注入点 | Number 形态 | `Uint64()` | 目的 |
|---|---|---|---|---|
| `add64` | `Prepare`（`prepare()` 后） | `parent+1 + 2^64` | = H | 通用截断攻击；会被"父子高度差 == 1（big.Int）"的修复拦下 |
| `zero64` | `Seal`（签名前） | `H << 64` | **= 0** | 专打盲区：命中 `verifyCascadingFields` 顶部 `if number==0 { return nil }`，使其后的连续性检查**不可达** |

`zero64` 为什么注入在 `Seal` 而不是 `Prepare`：`Seal` 顶部有 `header.Number.Uint64()==0 -> errUnknownBlock` 守卫，`snapshot(number-1)`、`delay`、投票聚合也都要用真实 H。若在 `Prepare` 就把 Number 变成 `H<<64`，恶意节点自身 `Seal` 阶段直接失败、发不出块。所以让前置流程全用真实 H 跑通，只在**签名前一刻**盖上 `H<<64`，签名即覆盖畸形值。

**逃逸链**（对"在 707 行加 `header.Number-parent==1` 的修复"）：`verifyCascadingFields` → `number := header.Number.Uint64()` 得 0 → `if number==0 { return nil }` 提前返回 → 707 行的连续性检查**永不执行**。

**注意区分"逃逸 707"与"块被接受"**：
- 完整块广播路径：`SanityCheck` 判 `!IsUint64()` → 拒。
- 仅哈希 + fetcher 路径：`verifySeal` 顶部同样 `number==0 -> errUnknownBlock` → 拒。
- 真正无兜底的是**单独调用 `VerifyUnsealedHeader`（不跟 `verifySeal`）的路径**，如 MEV BidBlock 准入。
- 本地出块节点自身：`WriteBlockAndSetHead` 不做形态检查，会把 `NumberU64()==0` 的块写在**高度 0**，覆盖 genesis 规范映射 → 本地链头损坏/自我分区（这是 zero64 最直接的"危害"）。

**修复有效性判定**：装了"早期 `!Number.IsUint64()` 拒绝"（在任何 `Uint64()` 截断之前）的分支，应对 `zero64` 块返回 `ErrInvalidNumber` 并**在所有入口**（含 MEV / fetcher / 本地）拒绝；未修分支则表现为上面各路径不一致（部分拒、本地损坏）。

## 1. 威胁模型

一个合法签名者（validator）在**出块时**把 `header.Number` 抬高 `2^64`：

- `header.Number = 真实高度 H + 2^64`
- 低 64 位不变，因此 `header.Number.Uint64() == H`，所有基于 `Uint64()` 的检查都自洽；
- 但 `header.Number` 的 `BitLen() > 64`，`IsUint64() == false`，即 `Header.SanityCheck()` 应当拒绝的形态。

注入发生在 `Prepare()` 里、`FinalizeAndAssemble` / `Seal` **计算签名之前**，所以 seal 签名是对这个“畸形大数 header”本身签的，**签名合法**。这与“封块后再篡改”不同——后者会被 `verifySeal` 的 ecrecover 失配拦下，掩盖真正要验证的“数值形态”缺陷。

## 2. 代码位置与开关

- 注入实现：`consensus/parlia/big_number_injection.go`
- 挂载点：`consensus/parlia/parlia.go` 的 `Prepare()` 末尾调用 `p.maybeInjectBigBlockNumber(header)`（**仅此一处**）
- 版本横幅：`New()` 里调用 `p.logInjectionBanner()`，每个节点启动即打印一次
- 开关（**默认开启**）：仅 `MALICIOUS_BIG_NUMBER=2` 关闭
- 安全护栏：mainnet / chapel 直接返回，忽略环境变量

```bash
# 默认即开启（add64 模式），无需任何设置。
# 切到 zero64（Uint64()==0）攻击：
export MALICIOUS_BIG_NUMBER_MODE=zero64
# 临时关闭注入：
export MALICIOUS_BIG_NUMBER=2
```

### zero64 受控测试（验证 707 盲区 + 修复有效性）

1. **只让 1 个验证者注入**，其余节点 `MALICIOUS_BIG_NUMBER=2` 关闭，避免上次"全员作恶 + 复利"导致的整网崩溃、结论不可读。
2. 恶意验证者：`MALICIOUS_BIG_NUMBER_MODE=zero64`（默认已开启）。启动后确认横幅 `mode=zero64 resolvedMode=ENABLED`。
3. 轮到它出块时抓 `BIG_NUMBER_INJECTION[zero64] active`，记录 `realHeight`(H)、`bigNumber`(H<<64)、`truncatedUint64=0`。
4. 观测面（未修 vs 已修分支各跑一遍对比）：
   - 本地恶意节点：是否出现写库/设头异常、`NumberU64()==0` 覆盖 genesis 的迹象。
   - 完整块 peer：`too large block number`（SanityCheck）拒绝。
   - 仅哈希 peer：未修分支 `verifySeal` 报 `errUnknownBlock` 拒；**已修分支应更早地以 `ErrInvalidNumber` 拒**。
   - 若被测分支含 MEV BidBlock 准入：未修时 `zero64` header 可穿过 `VerifyUnsealedHeader`；已修（早期 `IsUint64` 检查）应拒。

### 日志（判断"注入是否发生" + "版本是否正确"）

`buildTag = big-number-injection/v2 (default-ON, disable=MALICIOUS_BIG_NUMBER=2)`；行为变更时应 bump 此常量。

| 日志串 | 级别 | 触发时机 | 用途 |
|---|---|---|---|
| `BIG_NUMBER_INJECTION build loaded ...` | Warn | 引擎构造 `New()`（**每个节点**，启动即打印一次） | **确认运行的二进制带了这段代码**（`buildTag`）+ 解析出的模式（`resolvedMode`）+ chainID / 是否护栏链 / envValue |
| `BIG_NUMBER_INJECTION first Prepare reached (miner path is live)` | Warn | 该节点第一次走到 miner 出块 hook | 确认**出块路径确实被执行**（非出块 fullnode 不会打印） |
| `BIG_NUMBER_INJECTION active: inflated header.Number beyond uint64` | Warn | 每次成功注入 | 逐块确认注入发生，含 `expectedHeight`(H)、`bigNumber`(H+2^64)、`bitlen` |
| `BIG_NUMBER_INJECTION skipped: disabled by env` | Info | 每块，`MALICIOUS_BIG_NUMBER=2` 时 | 确认已按预期关闭 |
| `BIG_NUMBER_INJECTION skipped: protected chain ...` | Warn | 每块，chainID=56/97 时 | 护栏生效（正常 devnet 不应出现） |

快速校验运行的是否为正确版本：

```bash
grep "BIG_NUMBER_INJECTION build loaded" <log> | head -1   # 看到 = 二进制含本代码；buildTag 对得上 = 版本正确
grep "BIG_NUMBER_INJECTION active"       <log>             # 看到 = 正在逐块注入
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
2. 用**打了本注入的二进制**在其中一个 validator 上启动。注入**默认开启**，无需设环境变量；启动后先到该节点日志确认版本横幅：
   `BIG_NUMBER_INJECTION build loaded ... resolvedMode=ENABLED ... buildTag=big-number-injection/v2 ...`
   —— 看到这行即证明**跑的是带注入的正确二进制**。若要临时关闭，把 `MALICIOUS_BIG_NUMBER=2` 写进**进程环境**（systemd `Environment=` / docker `-e`；交互 shell 对已运行 daemon 无效）。
3. 等该 validator 轮到出块（该注入只在它自建块时触发），抓恶意节点日志中的：
   `BIG_NUMBER_INJECTION active: inflated header.Number beyond uint64`
   记录 `expectedHeight`(H)、`bigNumber`(H+2^64)、`coinbase`。首次出块还会有一条
   `BIG_NUMBER_INJECTION first Prepare reached`，确认出块路径已执行。
4. 到各 peer 节点按上表对照现象。
5. 对比“打了修复”与“未打修复”两组二进制，确认修复后**所有**路径都拒绝。

## 5. 清理

- 注入**默认开启**，`unset` 环境变量并不会关闭它。要停止注入，必须用**未打注入的二进制**重启，或回退 `consensus/parlia/big_number_injection.go` 与 `parlia.go` 中的挂载调用（`maybeInjectBigBlockNumber` / `logInjectionBanner`）；临时关闭可设 `MALICIOUS_BIG_NUMBER=2`。
- 该注入不得进入任何面向主网 / Chapel 的发布分支；本工作位于 `test` 分支。
