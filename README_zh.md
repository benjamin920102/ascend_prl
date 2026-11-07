# `ascend_prl` — 全球首个昇腾 NPU 加密货币矿工

[English](README.md) | **中文**

一个从零编写、面向 [Pearl](https://arxiv.org/abs/2504.09971) **有用工作量证明（Proof-of-**Useful**-Work）** 币的矿工，
运行在华为**昇腾 910B** NPU 上。已在 910B4 上实测，端到端可达 **~10 TH/s/卡**。

> **免责声明：** 仅供学习研究之用。请仅在你拥有授权的硬件上运行。

每次算子提交固定處理一個 strip，主機端保留兩槽非同步流水線。Vector partial 輸入使用 TQue 兩塊緩衝，預載下一個 fold。

## 快速开始

1. **创建 Pearl 钱包。** 使用[官方钱包](https://github.com/pearl-research-labs/pearl/releases/tag/pearl-wallet-v2.0.0)
   并按其说明操作。你会得到一个形如下面的地址：
   `prl1p2skcz8kxn03p3j2hzaz4j687ewan8deju7lgvpswux9hkgavcz5s6v5p83`。
2. **选择矿池。** 任何标准 `stratum` 协议的 Pearl 矿池都应可用。本项目在
   [Kryptex](https://pool.kryptex.com/prl) 上测试。注意：不同矿池接受的 M、N、K 形状不同（见[性能与形状](#性能与形状)）。
3. **运行** —— 以下三选一：

   **方式一 —— Docker**（推荐）：
   ```bash
   docker pull arabel1a/ascend_prl
   docker run --rm -it --privileged --network host \
     -v /usr/local/Ascend/driver/lib64:/usr/local/Ascend/driver/lib64 \
     -v /usr/local/Ascend/driver/version.info:/usr/local/Ascend/driver/version.info \
     -v /etc/ascend_install.info:/etc/ascend_install.info \
     -v /usr/local/dcmi:/usr/local/dcmi \
     -v /usr/local/bin/npu-smi:/usr/local/bin/npu-smi \
     -e WALLET=prl1...你的钱包地址 -e POOL=矿池地址 -e PORT=7000 \
     -e ASCEND_RT_VISIBLE_DEVICES=0,1,2,3,4,5,6,7 \
     arabel1a/ascend_prl:latest
   ```
   镜像内只包含 CANN **运行时**；NPU 驱动（`libascend_hal.so`）由宿主机提供，
   因此 `-v /usr/local/Ascend/driver/...` 这几个挂载和 `--privileged` 是矿工访问
   NPU 的**必需项**。用 `ASCEND_RT_VISIBLE_DEVICES` 指定要挖矿的芯片（die）。

   > **国内用户注意：** Docker Hub 在中国大陆基本不可用，请通过
   > [Docker Hub 镜像](https://github.com/dongyubin/DockerHub)（需支持代理「用户仓库」，
   > 并非所有镜像都支持）拉取，例如：
   > ```bash
   > docker pull docker.1panel.live/arabel1a/ascend_prl   # 本仓库实测最快的镜像（仅限国内）
   > ```

   **方式二 —— 预编译二进制**（需要 Linux/aarch64 + CANN 运行时）：
   ```bash
   git clone https://github.com/arabel1a/ascend_prl.git && cd ascend_prl
   ./scripts/get_release.sh                 # 或从 Releases 页面手动下载
   export WALLET=prl1...你的钱包地址
   export POOL=矿池地址   PORT=7000          # 你的矿池 stratum 主机/端口
   ASCEND_RT_VISIBLE_DEVICES=0,1,2,3 ./scripts/launch.sh
   ```

   **方式三 —— 自行编译。** 见[编译](#编译)。

## 与其他 NPU 任务共存

可以让矿工与其他进程跑在同一批芯片上，并自动「让路」：当有其他进程进入该设备时，
矿工会自动停止，无需手动重启。在启动时设置 **`PRL_COEXIST_GUARD=1`** 即可启用：

```bash
PRL_COEXIST_GUARD=1 ASCEND_RT_VISIBLE_DEVICES=0,1,2,3,4,5,6,7 ./scripts/launch.sh
# Docker：在 run 命令中加上  -e PRL_COEXIST_GUARD=1 （scripts/run_container.sh 会自动透传）
```

## 编译

依赖：
- CANN 9.0.0 工具链 + Ascend-C 编译器
- 支持 `-march=armv8-a+crypto` 的 `gcc`（用于 NEON 版 BLAKE3）
- `cmake ≥ 3.16`
- BLAKE3 的 C 源码（`blake3-1.x/c` 目录 —— 已随仓库附带，或取自 cargo registry）
- cargo，以及用于 proof FFI 的 Pearl Rust 工作区（`pearl-blake3`、`zk-pow`）——
  请在 `proof-ffi/Cargo.toml` 中把路径改成你本地的检出目录。

```bash
make                     # 固定 rank=128、K=4096；生成全部正式版构建产物
```

编译选项（`make 变量=...`）：

| 选项 | 默认 | 含义 |
| ---- | ------- | ------- |
| `MDIM` | `16384` | 16384 可让矿池的区块证明（block-proof）足够快，避免产生孤块（orphan）。 |

## 性能与形状

Cube 单元无法做异或（XOR）与移位，而 Vector 单元不擅长矩阵乘法。因此需要把每个 k-partial
经 L2（聚合带宽 2TB/s）从 Cube 搬运到 Vector。这就把吞吐限制为
TH/s ~ OP/s / 2 =（内存带宽）×（fold 的算术强度）。我们总共搬运 8/r 字节 → 算术强度 = r/8。
所以硅片理论峰值约为 rank / 8 TH/s。

币种规范允许其他 rank，但本正式版源代码固定 `r=128`、`K=4096`、`NINNER=1`、`NFOLD=32`，不再提供编译或运行时的 rank 选择。

> 注意：**昇腾 310** 和 **950** 没有上述限制，理论上可以更接近硬件峰值 TOP/s。

## GZIP v2 + 自定义份额难度（Kryptex）

通过 Pearl stratum gzip 协议，提交份额的网络流量可降低约 **80–100 倍**
（[协议说明](https://gist.github.com/maxmalysh/eaaf4332dbc5ca99d0a78f24a733fffe)）：

1. `mining.authorize` 发送 `"type":"v2"`。矿池在应答中回显 `"type":"v2"` 后，矿工提交
   `base64(gzip(bincode(plain_proof)))`，而不是约 136 KB 的明文 base64 证明（压缩后约 15 KB）。
2. 矩阵 A/B **始终零填充**（仅前 8 字节写入 seed 戳），证明可被 gzip 高效压缩。
   旧版随机填充与对应环境变量开关已彻底移除。

**自定义份额难度**（[说明](https://gist.github.com/maxmalysh/f4c29f532e650a114b317e234f1393fb)）：
把 CLI 第 6 个参数（password）设为 `d=<N>`。例如高算力矿机目标约每 30 秒一个份额：

```bash
./ascend_prl_kryptex 0 worker pool.kryptex.com 7000 prl1...你的钱包 'd=349245965'
```

password 为空 → 使用矿池默认（`d=2097152` ≈ 9000 TH）。公式：
`d = 算力_H/s × 目标份额间隔秒数 / 4_294_967_296`。

| 环境变量 | 含义 |
| --- | --- |
| `PRL_NOGZIP` | 强制 v1（不发 `"type":"v2"`，明文证明） |
| `PRL_GZIP` | 不等 authorize 应答就假定启用 gzip |
| `PRL_GZIP_FIELD` | 覆盖 submit 字段名（默认仍为 `plain_proof`） |

## 矿池兼容性

目前已测试过的矿池：

| 矿池 | 备注 |
| --- | --- |
| `kryptex` | 推荐；支持 gzip v2 + 自定义 `d=` 难度 |

只要是讲标准 stratum 协议的新矿池，大概率走 `kryptex` 路径就能用；如果不行，请附上一段抓包
开一个 issue，通常只需要对握手/解析做一点小调整。我会按需添加矿池支持。

## 贡献

欢迎提交 PR / 提需求（例如支持某个非标准协议的矿池）！

目前矿工仅在 910B4 上测试过。如果你愿意把设备共享给我，我可以适配到其他 NPU。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。按**「现状」提供，不作任何担保**。

<!-- discovery: 昇腾 910B / Ascend 910B4 NPU Pearl 挖矿 miner; 用闲置 NPU 挖 Pearl (PRL) 币;
     world-first Ascend NPU cryptocurrency miner; Huawei Atlas 800/300 idle NPU mining. -->

### Host CPU 优化

- 固定 zero-seed：原始 A/B 以 `calloc` 初始化，此后每轮只覆盖前 8 bytes seed；
  A noise 直接从零基底生成，最后以 int8 wrap 补回 seed stamp。原始矩阵仍完整保留给
  Merkle hash 和 proof，因此这里只消除 noise 阶段的 A 全量读取。
  内部 `*_reuse` API 要求 buffer 初次清零、后续只由生成器写入；普通 API 每次先清零。
- BLAKE3：首次大 hash 懒初始化持久 pthread pool，之后复用；无空闲 worker 时在调用线程
  计算，不阻塞等待可用 worker。prep 的 A/B root 顺序提交，同一个 hash 可使用整个 prep
  额度。OpenMP 与 BLAKE3 是先后执行的阶段。正常退出时先排空 prep/proof，再关闭 pool。
- reuse-B：每代 B 的首次 proof 懒建立 B Merkle tree，之后只提取需要的 multileaf proof。
  cache 只保留一棵 B tree，会增加常驻内存；A tree 仍逐次建立。job / PRL_BREUSE 更新 B
  前先排空 proof、清除 cache、递增 generation，退出时也清除。cache 同时核对 pointer、
  generation、key、n、k；非 reuse-B 路径不启用 cache。

计算线程统一受进程 CPU affinity 与 `PRL_CPU_THREADS` 限制，默认预算为 affinity 内的 CPU
数量。prep/OpenMP/BLAKE3 与 proof/Rayon 分配不同额度；不代表进程全部 OS 线程数上限
（I/O、NPU 控制线程及休眠的 pool worker 不计入）。`PRL_PREP_THREADS` 默认为约 3/4
预算，最多总预算减 1；`PRL_PROOF_THREADS` 默认取剩余额度，也不能超过剩余额度。
单 CPU 时 prep 与 proof/encoding 串行。`PRL_POW_THREADS` 在当前 NPU scan 中原本就不使用。
proof 使用专用 Rayon pool，不修改全局 Rayon pool。无需新增 make 参数。

直接运行二进制时，建议在启动前设置 `OMP_WAIT_POLICY=PASSIVE GOMP_SPINCOUNT=0`；
`launch.sh` 已自动设置，避免空闲 OpenMP worker 自旋。miner 内也设置这两个变量，但
部分 OpenMP runtime 可能在 main 前读取环境，故启动环境最可靠。

相同 seed/key/dimension 的零填充数据、noise 公式和 proof 序列化格式保持不变。
ARM64 正式路径固定使用 rank-128 NEON TBL；可移植的非 ARM64 路径也仅支持 rank 128。
不再提供旧版随机填充，也不再有 rank 运行参数或编译选项。

## BLAKE3 Vector64 正式版（僅 Vector Hash）

正式 Vector Kernel **一律使用 64-way Memory-based Vector** 執行 BLAKE3 Keyed
Hash，直接讀取原有 `16 × 64` Transcript SoA，完整計算七輪壓縮及八個 Hash Words。
**不再保留 Scalar BLAKE3、Scalar Fallback、診斷模式或 Vector64 切換編譯參數。**
Host 強制要求 `n_hi=64`，不符合時直接報錯，避免悄悄切換回 Scalar。
目前兩種 Pool Profile 都使用 `nrows=2`，所以 `n_hi=128/2=64`。

原本的 256-bit Target 比較仍逐 Lane 讀取 Vector64 已完成的八個 Hash Words，
以維持原本 Hit 判定順序及 Proof 格式。**這部分是 Scalar Target 比較，
不是 Scalar BLAKE3 Hash。**

重用 Fold 完成後 `foldB` 的 7,424 Bytes（原本共 16 KiB UB），沒有新增 TBuf
或 Kernel Launch。GRID=20、VEC2X=2、BUFS=4，Cube/Fold/Proof 均維持原設定。

獨立 910B4 Benchmark 的 2.3774x 來自只計時第一個輸出 Word 的測試；
八個 Words 的正確性另外驗證。此數字不代表正式版 TH/s。
本版遵照要求未編譯、未執行測試，尚未經 910B4／910C 實機確認。


## A 噪聲 BLAKE3 4-way NEON（ARM64）

`src/prep.c` 的 A 行噪聲產生（`compute_an128_fused_stamp`、
`compute_an128_fused_raw`）固定為 rank=128；每列原本依序計算 4 個
64-byte Keyed BLAKE3 digest。現在透過 `src/prl_blake3_neon4.h` 的
4 個 32-bit NEON lanes 同時計算 4 個獨立 BLAKE3 root。

- 訊息位元組不變：`LE32(draw+1) || 28*0 || seed[32]`。
- 7 rounds、KEYED_HASH/CHUNK_START/CHUNK_END/ROOT flags、輸出前 32 bytes 不變。
- `noise_digest_store`、rank-128 TBL、A seed stamp、原始 A/commit hash、B 路徑不變。
- 非 aarch64 平台保留原有可攜式 A 路徑；沒有新增執行期開關。
- 本變更不代表整體礦工 TH/s 實測提升；效益須在目標 910B 主機量測。
