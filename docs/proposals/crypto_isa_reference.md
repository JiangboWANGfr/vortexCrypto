# 加密 ISA 扩展参考：AES-GCM 与 ChaCha20-Poly1305

> **2026-08-31 起，lane 对 subgroup 的比值以冻结数据集为准。**本文引用的该类
> 比值全部测于 `-n64`：lane 映射的核（S0/S1/S2）在 c2w4t16 下让 core 1 完全
> 空转，而 subgroup 映射填满两核，等于拿一个核比两个核。经 gate 的 n=128 数据
> 集（`docs/proposals/data/measure-n128-2r1w-v1.csv`，标签
> `hare-dac-measure-n128-v1`）给出的公平数字是：ChaCha SG16 对同 build S1 在
> memory-bound 侧 **4.08x**（cache-resident 侧 8.41x），不是 4.98x —— 较此前
> 报告值下降 18.1%；S2 对 SG16 为 1.835 对 1.756 c/B。lane 对 lane、subgroup
> 对 subgroup 的内部比值不受影响。

本文件是 `docs/proposals/crypto_isa_proposal.md`（3343 行实验日志）的**结论性提炼**：
现在到底加了哪些指令、每条怎么实现、以及各自测到了什么数。日志里的推导过程、被
推翻的中间结论和逐节的自我修正不在这里重复，只在第 6 节列出「已撤回的结论」，因为
读数时需要知道哪些数字不能再引用。

**每个数字都标注了它出自 proposal 的哪一节。**跨节的数字不能直接相减 —— 见 4.1 的
噪声底说明。

---

## 1. 总览

### 1.1 两条 AEAD，四个粒度层级

| 层级 | 含义 | AES-GCM | ChaCha20-Poly1305 |
| --- | --- | --- | --- |
| **S0** | 纯软件，`rv32imaf` | T-table AES + 查表 GHASH | ARX + radix-2^26 Poly1305 |
| **S1** | 细粒度、无状态、lane 本地指令 | `aes32esi/esmi` + `clmul/clmulh/brev8` | `rori`、`chacha32.xr`、`poly26.mac*` |
| **S2** | 粗粒度、单元内持有 (warp, lane) 上下文 | `aes.*` + `ghash.*` 引擎 | `chacha.*` 引擎 |
| **S3** | 子组协作，四个 lane 共同持有一份 128/512-bit 状态 | `aesrm/aesrf.sg4` + `ghmul.sg4` | `chadd.sg4` + `chacha32.xr` 的 sg4 位 + `poly26.rsum.sg4` |

**两条算法的最优层级是相反的**（proposal §23.5）：

| | S0 | S1 | S2 | S3 |
| --- | --- | --- | ---: | ---: |
| AES-GCM | 有 | 基线 | 2.10x | **3.76x** |
| ChaCha20-Poly1305 | 有 | 1.69x | **3.9x** | 1.26x |

> 这些倍数**各自对自己的基线**，不能横向读。AES 的块是 16 字节、ChaCha 的是 64 字节，
> 归一化到 cycles/byte 后结论会变（见 4.4）。

### 1.2 两个执行单元

指令按**角色**而不是按算法分到两个 EX 单元，这样算法族扩展时拓扑不动（§7）：

| EX 单元 | 现在的 PE | 规划中 |
| --- | --- | --- |
| `EX_SYM` | `PE_AES`、`PE_ROT`、`PE_CHACHA` | — |
| `EX_AUTH` | `PE_GHASH`、`PE_POLY` | — |
| `EX_HASH` | | Keccak |
| `EX_MOD` | | NTT / 模运算 |

拆成两个 EX 的理由**不是** backpressure —— proposal §7 明确记录了这个最初的理由是错的：
所有 S1 指令都是单周期无状态、后面挂一个 1 深的 elastic buffer，`execute_if.ready`
不会低于一个周期，`fu_goingfull` 和 `VX_pe_switch` 的 head-of-line 阻塞都不会触发。
而且树里本来就有反例：`EX_ALU` 里挂着 bit-serial 的 `VX_serial_div`，一次整数除法会
把单周期整数 ALU 堵约 32 个周期，设计就那么发布了。

**真实理由是测量完整性**：这项工作的全部内容就是比较不同的指令粒度。如果细粒度变体
住在 `VX_alu_unit` 里、后来的粗粒度变体住在自己的 EX 里，两者的比较就同时变了指令粒度
和调度域两件事。从一开始就把 EX id、模块边界、payload 类型、lane 数、commit beat 数
钉死，后来的变体才能在拓扑不动的情况下和这些数字比较。

代价是已知且接受的：`EX_BITS` 从 2 加宽到 3（连带加宽 `decode_t`/`ibuffer_t`/
`scoreboard_t`/`operands_t` 里的 `ex_type`），每个单元每个 issue slice 多一个
`DISPATCH_QSIZE` 深的 dispatch 队列，两个单元都落在 `VX_commit` 静态优先级仲裁器的底部。

### 1.3 配置开关

全部默认关闭。`VX_config.toml` 只声明两个总开关，其余是 `CONFIGS` 传入的宏：

| 宏 | 打开什么 |
| --- | --- |
| `VX_CFG_EXT_SYM_ENABLE` | EX_SYM 单元本身；`aes32esi/esmi`、`rori` |
| `VX_CFG_EXT_AUTH_ENABLE` | EX_AUTH 单元本身；`clmul/clmulh/brev8`、`ghred32l/h` |
| `VX_CFG_EXT_SYM_SG4_ENABLE` | `aesrm.sg4` / `aesrf.sg4` |
| `VX_CFG_EXT_AUTH_SG4_ENABLE` | `ghmul.sg4`（与上一个共用 opcode arm，必须同时开） |
| `VX_CFG_EXT_SYM_S2_ENABLE` | 有状态 AES 引擎 |
| `VX_CFG_EXT_AUTH_S2_ENABLE` | 有状态 GHASH 引擎 |
| `VX_CFG_EXT_SYM_CHACHA_ENABLE` | `chacha32.xr` |
| `VX_CFG_EXT_SYM_CHACHA_SG4_ENABLE` | `chadd.sg4` + `chacha32.xr` 的 sg4 路由位 |
| `VX_CFG_EXT_SYM_CHACHA_S2_ENABLE` | 有状态 ChaCha 引擎 |
| `VX_CFG_EXT_AUTH_POLY_ENABLE` | `poly26.mac{l,h}{,5}` |
| `VX_CFG_EXT_AUTH_POLY_SG4_ENABLE` | `poly26.rsum.sg4` |

`VX_types.toml` 另外占用了三个 MPM CSR 槽：`VX_CSR_MPM_INSTR_SYM` (0xB18)、
`VX_CSR_MPM_INSTR_AUTH` (0xB19)、`VX_CSR_MPM_STALL_CRYPTO` (0xB1F)。最后一个把
SYM 和 AUTH 的 dispatch stall **求和**成一个计数器，因为 MPM core class 窗口
`[VX_CSR_MPM_BASE, +32)` 只剩这一个空位；两个单元的指令数分开计（mix 确实不同），
而 stall 计数器存在的目的只是证明两个单元都从不 backpressure，和为零就同时证明了两者。

---

## 2. 指令全集

### 2.1 编码总表

| 指令 | opcode | funct3 | funct7 / imm | 类型 | 单元 | 层级 |
| --- | --- | ---: | --- | --- | --- | --- |
| `aes32esi` | OP `0x33` | 0 | `{bs[1:0], 10001}` | R | SYM/AES | S1 |
| `aes32esmi` | OP `0x33` | 0 | `{bs[1:0], 10011}` | R | SYM/AES | S1 |
| `clmul` | OP `0x33` | 1 | `0000101` | R | AUTH/GHASH | S1 |
| `clmulh` | OP `0x33` | 3 | `0000101` | R | AUTH/GHASH | S1 |
| `brev8` | OP-IMM `0x13` | 5 | imm `0x687` | I | AUTH/GHASH | S1 |
| `rori` | OP-IMM `0x13` | 5 | imm `{0110000, shamt}` | I | SYM/ROT | S1(B 扩展) |
| `ghred32l` | custom-2 `0x5B` | 0 | 0 | R | AUTH/GHASH | S1(自定义) |
| `ghred32h` | custom-2 `0x5B` | 1 | 0 | R | AUTH/GHASH | S1(自定义) |
| `chacha32.xr` | custom-3 `0x7B` | 6 | `funct7[4:0]`=左旋量, `[5]`=sg4 | R | SYM/ROT | S1 / S3 |
| `poly26.mac{l,h}{,5}` | custom-2 `0x5B` | 5 | funct2 = `{scale5, high}` | **R4** | AUTH/POLY | S1 |
| `aesrm.sg4` | custom-3 `0x7B` | 0 | 0 | R | SYM/AES | S3 |
| `aesrf.sg4` | custom-3 `0x7B` | 1 | 0 | R | SYM/AES | S3 |
| `ghmul.sg4` | custom-3 `0x7B` | 2 | 0 | R | AUTH/GHASH | S3 |
| `chadd.sg4` | custom-3 `0x7B` | 7 | 0 | R | SYM/ROT | S3 |
| `poly26.rsum.sg4` | custom-2 `0x5B` | 6 | 0 | R | AUTH/POLY | S3 |
| `aes.cwr` | custom-3 `0x7B` | 3 | `funct7[2:0]`=sel 0-7 | R, rd=x0 | SYM/AES | S2 |
| `aes.crd` | custom-3 `0x7B` | 4 | `funct7[2:0]`=sel 0-3 | R | SYM/AES | S2 |
| `aes.begin/rndm/rndf` | custom-3 `0x7B` | 5 | `funct7[1:0]` = 0/1/2 | R, rd=x0 | SYM/AES | S2 |
| `ghash.cwr` | custom-2 `0x5B` | 2 | `funct7[2:0]`=sel 0-7 | R, rd=x0 | AUTH/GHASH | S2 |
| `ghash.crd` | custom-2 `0x5B` | 3 | `funct7[2:0]`=sel 0-3 | R | AUTH/GHASH | S2 |
| `ghash.init/block` | custom-2 `0x5B` | 4 | `funct7[0]` = 0/1 | R, rd=x0 | AUTH/GHASH | S2 |
| `chacha.cwr/crd/begin/dr` | custom-1 `0x2B` | 1 | `funct7[6:5]`=类, `[3:0]`=词 | R | SYM/CHACHA | S2 |

三个自定义 opcode 的分工：**custom-3 (0x7B)** 是 SYM 的扩展 arm（外加共用的
`ghmul.sg4`），**custom-2 (0x5B)** 是 AUTH 的扩展 arm，**custom-1 (0x2B)** 只给
ChaCha S2 引擎 —— 因为十六个字的状态需要**四位**选择子，而 crypto opcode 的三位
`sel` 字段装不下。

### 2.2 AES-GCM 路线

#### S1 —— 五条已批准指令，零新增状态

```
aes32esi  rd, rs1, rs2, bs    rd = rs1 ^ rol32(zext32(sbox(rs2 的第 bs 字节)), 8*bs)
aes32esmi rd, rs1, rs2, bs    rd = rs1 ^ rol32(mixcol(sbox(rs2 的第 bs 字节)), 8*bs)
clmul  rd, rs1, rs2           无进位乘积的低 XLEN 位
clmulh rd, rs1, rs2           无进位乘积的高 XLEN 位
brev8  rd, rs1                每个字节内部比特翻转
```

RISC-V Zkne（RV32 形式）+ Zbkc + Zbkb，全部已批准。四条 `aes32*` 构成一个输出列，
一整轮是十六条。只实现加密方向：GCM 用 counter mode，永不解密，Zknd 是**故意不实现**
而不是遗漏。

GHASH 累加器 `Y` 和哈希子密钥 `H` 留在通用寄存器里，单元内**不存任何状态** —— 这是
S1 相对 S2 的核心性质，也是它 context-switch 安全的原因。

比特序是最容易悄悄搞错的地方：GCM 对每字节的比特编号与 `clmul` 假设的多项式约定相反，
`x^i` 的系数是第 `i/8` 字节的第 `(7 - i%8)` 位。小端字加载把它放在
`8*(i/8) + 7 - i%8`，所以**只需要 `brev8`**，limb 顺序已经对了 —— 不需要 128 位整体
翻转，也不需要整值反射会带来的 shift-by-1 修正。

#### S1 自定义补充 —— `ghred32l/h`（已测，负结果）

```
ghred32l rd, rs1, rs2         rd = rs1 ^ clmul_lo(rs2, 0x87)
ghred32h rd, rs1, rs2         rd = rs1 ^ clmul_hi(rs2, 0x87)
```

GHASH 的模是 `x^128 + x^7 + x^2 + x + 1`，把 256 位乘积的高半折下来就是每个 limb 乘
常数 `0x87` 再累加。因为常数已知，硬件不需要通用无进位乘法器：`0x87 = 0b10000111`，
乘积就是 `x ^ (x<<1) ^ (x<<2) ^ (x<<7)`，四个移位异或。

**这条指令测出来是负的**（§13.1）：指令数 -1.96%，周期 +4.4~10.2%。保留在树里是因为
它是本项目第一条「减指令反而变慢」的记录，后面几条的符号判断都参照它。

#### S3 —— 融合子组轮

```
aesrm.sg4 rd, rs1, rs2        中间轮
aesrf.sg4 rd, rs1, rs2        末轮
ghmul.sg4 rd, rs1, rs2        A*H mod P，一个 limb 一个 lane
```

`aesrm/aesrf`：`rs1` 是本 lane 的轮密钥列，`rs2` 是本 lane 的状态列，`rd` 是下一轮的
状态列。一条指令推进一个对齐 quad 上按列分布的整个 128 位状态。

**跨 lane 网络是固定的字节转置，不是 crossbar。** lane `j` 产出列 `j`，按 ShiftRows
它取列 `(j+r)&3` 的第 `r` 字节，而在这个布局下那一列就在 lane `(j+r)&3`。源索引是
genvar 表达式 `((i/4)*4) + ((i+r)%4)`，综合出来就是走线：每 quad 十六字节进、十六字节
出，没有 mux。把四个字节步骤枚举进指令还顺带把 lane 本地形式需要的两个 4:1 mux
（`sel_byte` 按 `bs`、`rol32` 按 `bs`）折成了常量。

`ghmul.sg4`：quad 的 `rs1`、`rs2` 各是一个 128 位值、每 lane 一个 limb，每个 lane 收到
它那一份 `A*H mod P` 的 limb，仍在软件路径用的同一个反射 limb 域里，所以内核的 `brev8`
约定不用改。代价是**每 quad 十六次 32x32 无进位乘 —— 每 lane 四次**，是 lane 本地路径
的四倍，把 §13.1 记录的「最大的 crypto 块」的乘法器阵列翻了四倍。

**收敛是体系结构前提，不是约定。** quad 的每个 lane 都被其他所有 lane 读，两个模型都
**不查**源 lane 的 mask —— 这是故意的，为了让 RTL 和 simx 不会像现在的 `SHFL` 那样漂移
（`VX_alu_int.sv:219` 回退到读方 lane，`alu_unit.cpp:291-296` 不回退）。发散区域的代价
在 §20.1 有记录：计数器对、lane 映射对、每一个字节的密文错，而且是静默的。

#### S2 —— 有状态的每-lane 引擎

九条指令，占两个空闲自定义 opcode 的六个 decode 槽，不新增 opcode：

| | funct3 | funct7[2:0] | rd | 语义 |
| --- | ---: | ---: | --- | --- |
| `aes.cwr` | 3 | sel 0-7 | x0 | S0..S3 (0-3)、K0..K3 (4-7) |
| `aes.crd` | 4 | sel 0-3 | data | rd = S[sel] |
| `aes.begin` | 5 | 0 | x0 | S ^= K; rnd = 1 |
| `aes.rndm` | 5 | 1 | x0 | K = NextKey(K,rnd); S = round(S,K); rnd++ |
| `aes.rndf` | 5 | 2 | x0 | 同上，无 MixColumns |
| `ghash.cwr` | 2 | sel 0-7 | x0 | Y[sel] ^= rs1 (0-3)、H[sel-4] = rs1 (4-7) |
| `ghash.crd` | 3 | sel 0-3 | data | rd = Y[sel] |
| `ghash.init` | 4 | 0 | x0 | Y = 0 |
| `ghash.block` | 4 | 1 | x0 | Y = Y*H mod P |

轮计数器从 **1** 起，不是 0，这样第一条中间轮产生带 `Rcon[1]` 的 K1；从 0 起是初稿的
off-by-one。

上下文必须按 **(warp, lane)** 索引，不能只按 lane：warp 自由交错，只按 lane 的上下文会
被最后发射的那个 warp 覆盖。

第一次构建后移除了两个 128 位字段，且没有削弱指令的表达能力：

- **X 没了。** `ghash.cwr` 直接把 limb 折进累加器，四次写加一条 `ghash.block` 仍然
  计算 `Y <- (Y ^ X)*H`，不需要存 X，流水线第一级少一个数组。
- **存储的密码密钥没了。** `aes.cwr` 直接写工作轮密钥，`aes.begin` 不再从 K0 复位它。
  软件在每次 begin 前重写密钥：每块四次写，摊到十六个 lane 上是每块 0.25 条指令，且
  不产生额外 load —— 密钥本来就在寄存器里。

**每 warp 共享一份密钥会省下同样的 256 位且不花指令，被否决了。**那会把一个 warp 限制
成十六条同密钥消息，而批处理不同 TLS 会话的记录（同一 warp 里不同密钥）恰恰是 GPU 做
AEAD 唯一值得做的场景。这里的 benchmark 碰巧是单密钥，采纳那个限制会给一个做不了通用
任务的 ISA 刷出好看的数字。

每 (warp, lane) 从 772 位降到 516 位；每核从 49,408 位降到 33,024 位。

### 2.3 ChaCha20-Poly1305 路线

#### S1

```
rori rd, rs1, shamt              rd = (rs1 >> shamt) | (rs1 << (32-shamt))
chacha32.xr rd, rs1, rs2, rot    rd = rol32(rs1 ^ rs2, rot)     -- rot 是左旋量
poly26.macl  rd, rs1, rs2, rs3   rd = rs1 + ((rs2 * r)     & 0x3ffffff)
poly26.mach  rd, rs1, rs2, rs3   rd = rs1 + ((rs2 * r)     >> 26)
poly26.macl5 rd, rs1, rs2, rs3   rd = rs1 + ((rs2 * r * 5) & 0x3ffffff)
poly26.mach5 rd, rs1, rs2, rs3   rd = rs1 + ((rs2 * r * 5) >> 26)
                                 其中 r = rs3 & 0x3ffffff
```

**`rori` 不是加密指令，它抬高的是基线。** `rv32imaf` 完全没有 rotate，ChaCha 的
quarter-round 是 add/xor/rotate，所以软件基线对每一次旋转都付 `slli`+`srli`+`or`：
每 64 字节块八十个 quarter-round × 四次旋转 × 三条指令 = 960 条旋转指令，而整块约
2611 条 —— 37% 的块是 ISA 缺失的 rotate。用没有 rori 的基线去测 ChaCha 加速比，是在
把 B 扩展的功劳算到加密 ISE 头上。所以**本文所有 ChaCha 的对比基线是 `rori` 行，不是
`sw` 行**。

`chacha32.xr` 去的是**旋转 PE**，不是 AES PE —— 它不带 S-box、不带域运算、不带算法
常数，是本文唯一一条这样的扩展。`rot` 是**左**旋量（ChaCha 就是这么规定的），而同一
字段里 `rori` 的 `shamt` 是右旋量。

`poly26.mac` 是 **R4 型**，和 WGATHER 用的形状一样，所以 rs3 不需要新的操作数通路：
operand collector 本来就取三个源、scoreboard 本来就跟踪 rs3。这条纠正了设计讨论早期
「机器是 2R1W、真正的 multiply-accumulate 表达不出来」的假设。

**`scale5` 形式不是便利品。** 归约的 wrap 项带一个因子五，软件常用的
`s_i = 5*r_i` 预计算会到 2^28.3，26 位操作数装不下；有了 scale5，密钥只要五个寄存器而
不是九个。低半和高半累加进**分开的**寄存器，每个输出 limb 重组一次 —— 这是**精确的**
而不是近似：低累加器求的是乘积模 2^26 之和，高累加器求的是它们的商之和。五个乘积下
低累加器不超过 2^28.4、高累加器不超过 2^30.4，都在 32 位内。

#### S3

一个 quad 拥有一条消息。ChaCha 的 4x4 状态每 lane 放一列，于是列轮完全 lane 本地，
对角轮就是同一个轮把第 1、2、3 行跨 quad 旋转。

Poly1305 **不能按 limb 拆** —— 130 位不被 4 整除，五-lane 子组也不对齐到 2 的幂，
跨 lane 路由会从固定置换退化成通用网络。它按**块**拆：

```
h4 = (h0 + m1) r^4 + m2 r^3 + m3 r^2 + m4 r   (mod 2^130-5)
```

一个 64 字节 ChaCha 块恰好是四个 Poly1305 块，恰好是 quad 宽度。lane `c` 拿 `m_{c+1}`
和 `r^{4-c}`。累加器在四个 lane 里**复制保存** —— 跨 lane 求和是个 butterfly，每个 lane
最后都得到同一个 h，所以 AAD、tail、长度块这些串行部分不需要广播。

融合行加三个编码，其中一个只是已有指令上的一个比特：

```
chadd.sg4 rd, rs1, rs2      rd = rs1 + quad 中下一个 lane 的 rs2
chacha32.xr funct7[5]       同样的路由加到已有的 xor-rotate 上
poly26.rsum.sg4 rd, rs1     rs1 在 quad 内求和，结果进每个 lane
```

**一个路由方向覆盖整个对角轮**：对角 j 的 D 操作数在 lane `j+3`、读 lane `j` 的 A，
而 `-3 ≡ +1 (mod 4)`，所以八个读全都来自 lane +1，源索引是对齐四元组内的常量置换 ——
走线，不是 crossbar。

#### S2

四条指令挤在 custom-1 的一个 funct3 上：

```
chacha.cwr rs1, sel     sel 0..7 密钥字，8..10 nonce 字；每条消息一次
chacha.begin rs1        rs1 是块计数器
chacha.dr               一个 double-round，八个 quarter-round
chacha.crd rd, sel      x[sel] + init[sel]
```

引擎自己保存密钥和 nonce，所以 `begin` 从计数器就能重建初始状态，**一个块完全不需要
上下文写**；`crd` 把 ChaCha 的 feed-forward 折进读操作，所以没有收尾指令、也不需要
初始状态的影子副本。

---

## 3. 硬件实现

### 3.1 文件

| 文件 | 行数 | 内容 |
| --- | ---: | --- |
| `hw/rtl/crypto/sym/VX_sym_unit.sv` | 162 | EX_SYM 外壳，2 或 3 个 PE |
| `hw/rtl/crypto/sym/VX_sym_aes.sv` | 384 | `aes32*` + `aesr*.sg4` + AES S2 引擎 |
| `hw/rtl/crypto/sym/VX_sym_rot.sv` | 142 | `rori` + `chacha32.xr` + `chadd.sg4` |
| `hw/rtl/crypto/sym/VX_sym_chacha.sv` | 261 | ChaCha S2 引擎 |
| `hw/rtl/crypto/auth/VX_auth_unit.sv` | 141 | EX_AUTH 外壳，1 或 2 个 PE |
| `hw/rtl/crypto/auth/VX_auth_ghash.sv` | 389 | `clmul/clmulh/brev8/ghred32*` + `ghmul.sg4` + GHASH S2 引擎 |
| `hw/rtl/crypto/auth/VX_auth_poly.sv` | 123 | `poly26.mac*` + `poly26.rsum.sg4` |

simx 侧对应 `sim/simx/sym_unit.{h,cpp}`（342+81 行）和 `sim/simx/auth_unit.{h,cpp}`
（302+61 行），`sim/simx/decode.cpp` +257 行。

lane 几何镜像 `[alu]`/`[sfu]` 而不是 `[tcu]`：`NUM_SYM_LANES = NUM_AUTH_LANES =
SIMD_WIDTH`，blocks = 1。取 `NUM_THREADS` 会通过 `VX_lane_dispatch` 的整除断言把
`SIMD_WIDTH == NUM_THREADS` 钉死到整个核。lane 保持在 `SIMD_WIDTH` 也让
`NUM_PACKETS = 1`，即每个 uop 一个 commit beat —— 这是「放在 commit 静态仲裁器底部
仍然可接受」这个论证的前提。

### 3.2 S1 数据通路：单周期、组合逻辑 + 一个 elastic buffer

`VX_sym_aes` 的 lane 本地路径：

```systemverilog
wire [7:0]  sel_byte = execute_if.data.rs2_data[i][8*bs +: 8];
wire [7:0]  sbox_out = aes_sbox_fwd(sel_byte);
wire [31:0] so       = is_mix ? aes_mixcol_byte(sbox_out) : {24'b0, sbox_out};
assign aes_result[i] = execute_if.data.rs1_data[i] ^ rol32(so, bs);
```

S-box 是 FIPS-197 图 7 的表，按自然顺序写但降序声明（house style），所以查表是
`sbox[255 - x]`。两条都是 2R1W：rd 只写不读，不需要第三个寄存器端口。

`VX_auth_ghash` 的 `clmul` 写成归约树而不是进位链，让综合器展平它：

```systemverilog
clmul_prod = '0;
for (int k = 0; k < XLEN; ++k)
    if (b[k]) clmul_prod ^= ({{XLEN{1'b0}}, a} << k);
```

`VX_sym_rot` 的左旋量取 `5'd0 - shamt`，这样 `shamt == 0` 自然退化成拷贝，不需要特例。

`VX_auth_poly` 是纯整数乘累加，和旁边的无进位域乘法**不共享任何逻辑**，所以它是独立
的 PE 而不是 GHASH 数据通路里的又一个模式。

### 3.3 XLEN 和 lane 数守卫用「引用不存在的模块」

`STATIC_ASSERT` 在 `SYNTHESIS` 下展开为空（`VX_platform.vh:136`），而 DE10-Pro 流程
定义了 `SYNTHESIS` —— 检查恰好在最需要它的那个构建里消失。所以用引用一个不存在的模块
来代替，Verilator 和 Quartus 都会在 elaboration 失败并把原因印在名字里：

```systemverilog
`ifdef VX_CFG_XLEN_64
    VX_sym_aes_requires_XLEN_32__use_AES64_for_RV64 __config_error();
`endif
if ((NUM_LANES < 4) || ((NUM_LANES % 4) != 0)) begin : g_sg4_guard
    VX_sym_aes_sg4_requires_NUM_LANES_multiple_of_4 __config_error();
end
```

XLEN=64 下不守卫的后果是静默错误：数据通路会把零扩展的 32 位结果异或进 64 位 rs1、
让 rd 的高半等于 rs1 的高半，而 simx 会把它清零 —— 两个模型静默地不一致。

### 3.4 S2 引擎：状态、拍数与冒险机制

三个引擎的共同结构：上下文按 (warp, lane) 索引的寄存器阵列，**除读指令外全部编码
`rd = x0`**。`VX_decode` 的 `wb` 是 `use_regs[RD] && rd != 0`，所以不产生写回、也不产生
scoreboard 条目 —— **顺序因此不可能来自 scoreboard**。单元自己互锁：一个全局 busy 位
就够，因为进入单元的流水是有序的，排在多周期操作后面的东西反正要用同一份硬件；
per-warp 互锁是多花机器换不到好处。软件侧靠 `volatile` asm 阻止编译器重排这条链。

**AES 引擎（`VX_sym_aes.sv`）：一轮四拍，每拍产出一个输出列。** S-box 阵列因此按
「每 lane 一列」而不是「每 lane 十六字节」定尺寸 —— `4*NUM_LANES` 而不是
`16*NUM_LANES`。前三拍把 `execute_if.ready` 拉低。轮密钥字是链式的（字 c 需要字 c-1），
每拍一个字正好和状态列的调度对上：

```systemverilog
wire [31:0] rotk = {ck[3][7:0], ck[3][31:8]};              // RotWord
wire [31:0] subk = {sbox(rotk[31:24]), ..., sbox(rotk[7:0])};  // SubWord
wire [31:0] tw   = subk ^ {24'b0, aes_rcon(cr)};
assign s2_kw[i] = ck[s2_phase] ^ ((s2_phase == 0) ? tw : s2_nk_prev[i]);
```

**没有 lane 读其他 lane，所以 thread mask 是被遵守的** —— 和 SG4 形式相反，被 mask 掉
的 lane 不能推进它的上下文。

**GHASH 引擎（`VX_auth_ghash.sv`）：三级流水，逐 lane 走。** 这是修 Fmax 失败的结果
（见 4.6）：

```
S0  读 mux，独占一级
S1  乘法阵列
S2  mul87 折叠 + 写回 Y
```

各 lane 相互独立，所以级间没有冒险。吞吐仍是每周期一个 lane，指令从 `NUM_LANES` 拍
变成 `NUM_LANES+2` 拍。

**ChaCha 引擎（`VX_sym_chacha.sv`）：一个 double-round 八拍（每拍一个 quarter-round），
且每个 quarter-round 自身再流水两级。** 上下文是
`ctx_x[16][32]` + `ctx_k[8][32]` + `ctx_n[3][32]` + `ctx_ctr[32]`，每 (warp, lane)。

流水线需要一个调度上不明显的气泡：quarter-round 0-3 触及互不相交的列、4-7 触及互不
相交的对角，但**最后一个列轮写 x[15]，第一个对角轮读 x[15]**，背靠背发射会读到旧值。
这是构建前用一次八个索引集合的静态检查抓到的；否则它会是当月第三个「指令数对、周期数
对、时序也对，唯一症状是密文错」的 bug。

### 3.5 Decode 侧的三个坑

1. **`brev8` 和 `rori` 都是 OP-IMM funct3=101。** fallback 路径只看 funct3 就把
   OP-IMM 解码掉，所以没有专门的 arm，`brev8` 会静默地当移位执行。而且必须匹配 `u_12`
   （原始 `instr[31:20]`）而不是 `i_imm`：funct3=101 时 `is_itype_sh` 为真，会把
   `i_imm` 换成 5 位 shamt，高位只在原始字段里看得见。
   `rori` 更糟 —— 交给 fallback 时**两个模型的行为不同**：RTL 看 `instr[30]`（置位）
   会当 `SRAI` 跑，simx 会当 `SRL` 跑。
2. **`casez` 而不是 `case`。** AES32 的 arm 需要带掩码的 funct7（高两位是 `bs` 操作数）。
   其他 arm 都是无通配的精确常量，匹配行为不变，且没有 AES32 模式与它们重叠。
3. **已批准的 Zkn `INST_R` 编码空间不可用。** `VX_decode.sv` 有一个无条件 catch-all，
   已经把全部十六个 AES32 funct7 值解码成 ADD/SUB；simx 则把 `Opcode::R` 下所有奇数
   funct7 划给了 MULDIV。两个模型对那片空间本来就不一致，所以自定义指令走
   `INST_EXT3`/`INST_EXT4`（RTL 和 simx 都完全没解码过的 arm），不可能和已批准编码冲突。

此外 decode 必须给**每条 crypto 指令分配不同的 `ex_type`**：AES 和 GHASH 的 op_type
值会撞车，而两个 PE 都不检查 unit 字段，路由依据弱于此就会把一条 AES 操作当 GHASH
执行并静默破坏状态。

### 3.6 为什么内在函数用 `.insn` 而不是 `-march`

`sw/kernel/include/crypto/vx_crypto_defs.h` 里记录了理由，是正确性风险而非偏好：
在 `-march` 里点名一个扩展，会让 clang 在**程序任何地方**发出该扩展的**任何**指令，
包括和加密无关的代码。本设计只实现了其中少数几条。**未实现的指令在这里不会陷入 ——
它会被解码成别的指令，而且 RTL 和 simx 未必解码成同一条**，结果是不相关代码里的静默
错误答案。用显式 asm 把发射权握在自己手里，生成代码的质量没有损失（编码完全相同）。
只有当某个扩展被完整实现后，在 `-march` 里点名它才安全。

---

## 4. 实验数据

### 4.1 测量协议与噪声底（先读这一节）

- **记录配置是 `c2w4t16`**：2 核、4 warp、16 线程，即 `SIMD_WIDTH=16`、`ISSUE_WIDTH=1`。
  §11 把记录点从 `c1w4t32` 移过来，因为后者 Fmax 差 7%、**综合不出正确的比特流**：
  `c1w4t32` setup slack -0.348 ns、TNS -60.679、Fmax 186.99 MHz；`c2w4t16` slack
  +0.199 ns、TNS 0.000、Fmax 208.29 MHz。**在前者上测的数字描述的是一个造不出来的设计。**
- 树里 checked-in 的形状是 `c1w4t4`，所以核数和线程数必须每次 run 都作为 build override
  带上，而且必须走 `run-<driver>` 目标 —— `CONFIGS` 传给测试目录只会重建 kernel，
  形状住在 driver 的 `.so` 里（§15.2）。
- 消息数设为 lane 数，每个 lane 正好一条消息，无尾巴。
- 两条 AEAD 按**字节**对齐而不是按块：`-n128 -b64`（AES，16 B 块）和 `-n128 -b16`
  （ChaCha，64 B 块）都是 128 条消息 × 1024 字节 = 131072 字节。
- **rtlsim 是权威**，simx 只作参照。在 `c2w4t16` 上两者的周期差是 aes_gcm 1.97%、
  chacha_poly 2.30%（在 `c1w4t32` 上曾是 16.3%）。**退休指令数两者永远完全一致。**

**噪声底。**
- aes_gcm 软件内核：0.16% ~ 0.47%（§16.2）。约半个百分点以下不可读。
- aes_gcm 硬件端点自身的 probe：最高 4.68%（§12）。所以 15.77x 应读作「15.8x，底约 5%」。
- chacha_poly：0.81% ~ 2.26%（§16.2），最宽的样本正好落在记录点 `-b16`。
- **ChaCha 各表约 4% 的构建间浮动**（§23 开头）：`s1` 行在三个不同构建里测过，
  cache-resident 周期读到 515.0、488.6、477.7，而每块指令数三次都是 75.5，一位不差。
  **指令数是体系结构量、精确复现；周期数带指令布局带来的构建间变化。**
  所以只能在**同一张表内**比较行 —— 每张表的所有行来自同一个构建。

### 4.2 AES-GCM 全部记录

**软件基线**（§5，`c2w4t16`、`-n128 -b64`、8192 块、131072 字节、空 AAD、无尾）：

| | simx | rtlsim |
| --- | ---: | ---: |
| cycles | 9,195,286 | 9,380,132 |
| instrs | 2,474,230 | 2,474,230 |
| cycles/block | 1122.47 | 1145.04 |
| bytes/cycle | 0.0143 | 0.0140 |

**S1 对软件**（§16.3，同一棵树同一次提交）：

| | sw | hw_s1 | 比值 |
| --- | ---: | ---: | ---: |
| cycles | 9,380,132 | 594,958 | **15.77x** |
| instrs | 2,474,230 | 212,162 | 11.66x |
| bytes/cycle | 0.0140 | **0.2203** | |

这个 15.77x 有一段值得记的历史（§8 → §10 → §11）：最初记录的是 **2.67x**，测的是一个
57% 内存流量都非算法性的内核。原因**不是**寄存器溢出（一次分配器溢出都没有），是两件事：
helper 没被内联（`inline` 只是提示，LLVM 在 `-O3` 下拒绝了；因为它们取数组指针，
`ctr[]`/`ks[]`/`y[]`/`h[]` 被强制进栈槽，每块 45 次访存），以及流式访问是逐字节的
（RISC-V 严格对齐默认阻止 LLVM 加宽 `load_le32`/`store_le32`，每块 16 个 `lbu` +
16 个 `sb`，本来 4+4 就够，多出 24 次)。而 `vx_start.S:96` 让每个 hart 的栈相距 8 KB，
所以一个 warp 里的一次 `sp` 相对访问就是 `NUM_THREADS` 条相距 8 KB 的独立 cache line ——
在单 bank L1 上是按 warp 宽度重放的完全发散 gather。加 `__attribute__((always_inline))`
和按字访问后：**2.67x → 13.54x，硬件一行没动。**静态 `sp` 相对访存从 103 降到 47。

**S3 与 S2**（§21.2、§21.5、§22.3，`c2w4t16`、`-n128 -b64`、rtlsim、开 §19 的
per-hart 栈错开）：

| | cycles | instrs | 对 hw_s1 |
| --- | ---: | ---: | --- |
| hw_s1（发布版） | 543,229 | 212,186 | 基线 |
| hw_s3，软件路由 | 691,665 | 479,618 | +27.3% 周期 |
| hw_s3f，融合轮 | 379,655 | 252,978 | **-30.1% 周期**，+19.2% 指令 |
| hw_s3f（§21.5 构建） | 371,139 | 236,138 | -31.7% |
| **hw_s3g，两半都融合** | **144,612** | **96,658** | **-73.4% 周期，-54.4% 指令 = 3.76x** |
| hw_s2 | 258,199 | | **2.10x**，指令少 6.0x |

边际每块（`-b8`/`-b64` 两点拟合）：

| | 指令/块 | 周期/块 |
| --- | ---: | ---: |
| `hw_s1` | 25.25 | 62.18 |
| `hw_s2` | **4.19** | **28.21** |
| `hw_s3g` | 11.25 | **15.08** |

**两个必须一起读的数字**（§21.3）：同一条指令、同一个内核，只差启动时的两条指令
（per-hart 栈错开）：

| | cycles | 对 hw_s1 |
| --- | ---: | ---: |
| hw_s3f，栈如发布版 | 1,060,903 | **+82.9%** |
| hw_s3f，per-hart 错开 | 379,655 | **-30.1%** |

**在如发布版的机器上，融合子组轮看起来是 83% 的退化；在只改了两条启动指令的同一台
机器上，它是 30% 的收益。**§17 和 §18 各自在第一种机器上测过一个子组设计并判了死刑,
这就是那两个裁决被撤回的原因。

**`ghred32` 的负结果**（§13.1）：指令 -1.96%，周期 +4.4~10.2%。独立复现来自
`myvortex/docs/results/ghash_design_space.csv` 的一次**已构建的** S2 GHASH 乘法器基数
扫描（1 warp/core，完全没有 warp 级延迟隐藏）：

| radix | MUL cycles | total cycles |
| ---: | ---: | ---: |
| 1 | 130 | 60,157 |
| 128 | 3 | 60,137 |

**乘法快 43 倍，总周期动 0.03%。**同一份结果里 ChaCha20 quarter-round 是同样的签名：
快 80 倍，每块周期动约 0.6%。结论：**有限域算术不是周期所在的地方。**

**轮密钥 load 才是杠杆**（§13.3）：一个指令数完全一致的 probe 把每轮的 `k` 钉成 `rk`，
`aes32` 计数一位不差，只让每块 44 次 LMEM 密钥 load 中的 40 次消失（结果密码学上是错的，
它测的是 load 成本）：

| | cycles | instructions |
| --- | ---: | ---: |
| 当前 | 597,233 | 212,162 |
| 去掉密钥 load | 512,782 | 176,298 |
| | **-14.14%** | -16.90% |

但**要看清它为什么是真的**：每去掉一条指令省 2.35 周期，而平均 CPI 是 2.81 —— 轮密钥
load **比平均指令还便宜**。它们打的是 16-bank LMEM，不是单通道 DRAM。这 14% 是线性的
指令数回报，不是被回收的 stall。

### 4.3 ChaCha20-Poly1305 全部记录

**软件基线**（§6，`c2w4t16`、`-n128 -b16`、2048 块、131072 字节）：

| | simx | rtlsim |
| --- | ---: | ---: |
| cycles | 1,435,309 | 1,469,082 |
| instrs | 351,144 | 351,144 |
| cycles/block (64 B) | 700.83 | 717.32 |
| bytes/cycle | 0.0913 | 0.0892 |

**`rori` 行**（§9，`-n128 -b16`）：

| | sw | rori | 比值 |
| --- | ---: | ---: | ---: |
| cycles, rtlsim | 1,469,082 | 1,671,111 | **0.879** |
| cycles, simx | 1,435,309 | 1,646,897 | 0.872 |
| instrs | 351,144 | 265,488 | 1.323 |

**去掉三分之一的指令，内核慢了 13.8%。**而且这个符号是**翻转过的** —— 同一配置、
同样两条指令流，在 §16.1 的 AAD/尾块工作前后各测了一次：

| | before | after | 移动 | instrs before | after |
| --- | ---: | ---: | ---: | ---: | ---: |
| sw | 1,599,484 | 1,469,082 | **-8.153%** | 351,024 | 351,144 |
| rori | 1,575,430 | 1,671,111 | **+6.073%** | 263,584 | 265,488 |

一次源码修改作用在一个模板化的函数体上，把它的两个实例往**相反方向**推了 8% 和 6%，
而两边的指令数变化都不到 0.75%。**这行能确立的是 1.323x 这个指令比，它是精确的；
周期比在同一配置下已经在 1 的两侧各测到过一次，这说的是这套装置的性质，而不是 B 扩展的。**

**S1 表**（§23.1，rtlsim、`c2w4t16`、边际每 64 B 块、两个工作点：`b=1..4` 工作集
4-16 KB 装得下 16 KB D-cache，`b=16..32` 工作集 64-128 KB 装不下）：

| | 指令/块 | 周期，cache-resident | 周期，memory-bound |
| --- | ---: | ---: | ---: |
| `sw` | 162.3 | 864.4 | 788.0 |
| `rori`（基线） | 123.0 | 801.0 | 769.7 |
| `xr` | 102.9 **-16%** | 787.2 -1.7% | 749.3 -2.6% |
| `mac` | 135.5 **+10%** | 601.7 **-24.9%** | 453.2 **-41.1%** |
| `s1` | 75.5 **-39%** | 515.0 -35.7% | 454.7 **-40.9%** |

**1.69x**，且贡献切得很干净：memory-bound 点上 ChaCha 半边贡献为零、Poly1305 半边贡献
全部；cache-resident 点上 ChaCha 值 14%。（`xr` 的 -1.7% / -2.6% 在 4% 噪声底以内，
应读作「无可测量的周期效应」，它 load/store 计数一位不差也是这么说的。）

**为什么 `xr` 几乎不值钱、`mac` 值全部钱**（§23.2，`-n64 -b32` 的 per-class 计数器）：

| | `rori` | `xr` | `mac` |
| --- | ---: | ---: | ---: |
| instructions | 258,908 | 216,540 -16% | 285,876 **+10%** |
| cycles | 1,751,046 | 1,648,878 | 1,057,384 **-40%** |
| **loads** | **215,104** | **215,104** | 141,184 **-34%** |
| **stores** | **92,480** | **92,480** | 80,256 |
| load latency | 233.89 | 232.67 | 153.37 |
| scoreboard stall | 94% | **97%** | 87% |

`xr` 改变指令流而**对内存毫无影响** —— load 和 store 是同一个整数，不是「接近」。
融合的 xor-rotate 两个操作数本来就活着、结果又写回其中一个，活跃集不变。在一条 94%
时间卡在 234 周期 load 上的流里删掉 16%，删的是本来就在 stall 阴影里执行的指令；
stall 比例升到 97%，因为剩下能填的东西更少了。

`poly26.mac` 去掉四个 `s_i` 寄存器和 64 位中间值。load 降 34%，load 延迟同步降 34% ——
更少的溢出访问给 payload 留下更多 D-cache。

> **有用的那条指令，恰恰是让指令数变多的那条。**

**S3 表**（§23.3，三行同一构建，测于 §23.7 的优化之后）：

| | 指令/块 | 周期，cache-resident | 周期，memory-bound |
| --- | ---: | ---: | ---: |
| `s1` | 75.5 | 492.5 | 470.5 |
| `s3` probe | 110.0 **+46%** | 586.8 +19.2% | 485.1 +3.1% |
| `s3f` fused | 90.5 **+20%** | 477.9 -3.0% | 367.5 **-21.9%** |

**布局本身是输的。把它的跨 lane 流量融合掉值二十二个百分点**，把它变成 1.26x 的胜利，
同时仍比 S1 多退休 19% 的指令。store 数：`s1` 78,208、probe 75,520、融合行 **49,920** ——
每个 double-round 的六次显式旋转都产生一个必须保持活跃的值；融合之后什么都不动，
每个 lane 只是读它的邻居。

**S2 表**（§23.4）：

| | 指令/块 | 周期，cache-resident | 周期，memory-bound |
| --- | ---: | ---: | ---: |
| `s1` | 75.5 | 477.7 | 468.2 |
| `s2` | **28.9 -62%** | **112.7 -76%** | **121.4 -74%** |

约 **3.9x**，在 `-b32` 的总量上是 3.52x。比这条 AEAD 的其他所有层级都好，也比 AES-GCM
从 S2 拿到的多。

**S3 的三次后续优化**（§23.7）：渐进选择 `r^k` 而不是全算完再选 —— 有用；丢掉融合后
已死的六个 rotate 描述符 —— 有用；把每消息一次的 AAD 吸收 `noinline` 外联 —— **+13.9%，
已回退**。前两项把静态栈访问从 213 降到 176（低于 `s1` 的 189），simx 快 10.1%，
**rtlsim 从 1.26x 只动到 1.28x**：动态 load 反而**上升**（159,616 → 163,968），
store 下降（49,920 → 46,080）。静态溢出点又一次没能预测动态 load 流量。第三项值得留作
结论：外联把长活跃区间换成了**调用边界上的 ABI 溢出** —— 块循环必须在一个每消息只跑
一次的调用周围保存和恢复它整个活跃集。**在一台周期由 load 流量决定的机器上，把代码
移出热循环和把数据移出热循环不是一回事。**

### 4.4 跨算法归一化：cycles/byte

倍数各对各自的基线，横向读会错。归一化到每字节（§23.5，memory-bound 点）：

| | cycles/byte |
| --- | ---: |
| ChaCha20-Poly1305, `sw` | 12.31 |
| ChaCha20-Poly1305, `rori` | 12.03 |
| ChaCha20-Poly1305, S1 | 7.32 |
| ChaCha20-Poly1305, S3 fused | 5.73 |
| AES-GCM, S1 (`hw_s1`) | 3.89 |
| **ChaCha20-Poly1305, S2** | **1.90** |
| **AES-GCM, S3 (`hw_s3g`)** | **0.94** |

**最好的 AES-GCM 行比最好的 ChaCha20-Poly1305 行每字节快 2.01x** —— 而按块的数字
（3.76x 和 3.9x 并排）把这件事完全掩盖了。

第二个观察和第一个一样值钱：**ChaCha20-Poly1305 的纯软件行每字节比 AES-GCM 的 S1 慢
3.2x。**ChaCha20 在通用 CPU 上快，恰恰是因为那些 CPU 有宽 SIMD 而没有 AES 硬件；
在一台已经带 AES 数据通路的 SIMT 机器上，优势反转。

软件对软件（§6，同字节数）：AES-GCM 花 ChaCha20-Poly1305 **6.39x** 的周期、7.05x 的
指令。这不是 AES 基线的缺陷 —— AES 在这台机器上是查表加 GF(2^128) 乘法，ISA 两样都不
支持；ChaCha20 是加、异或、旋转，Poly1305 是 32x32 乘法，ISA 全都有。

### 4.5 两条规则

这是本工作能给出的、第三个算法可以拿去检验的东西，而不只是一串加速比（§23.5）：

> **S2 的收益正比于它从寄存器堆里赶走的状态量。**
> AES 持有四个字的状态加四个字的轮密钥，RV32 装得下；它的 S2 只去掉指令，回报 2.10x。
> ChaCha 持有十六个字，加上 feed-forward 的另外十六个 —— 那是整个寄存器堆；它的 S2
> 去掉指令**并且**去掉内核里最大的溢出来源，回报 3.9x。**这是本文唯一一行指令数和
> 周期数同向移动的记录，原因就在这里。**

> **S3 的收益取决于跨 lane 流量能否折进算术。**
> AES 的 ShiftRows 是**读侧置换** —— 输出列 j 取列 (j+r)&3 的第 r 字节，每个 lane
> 只写自己的输出 —— 所以它作为免费走线折进 `aesrm.sg4`；GHASH 的操作数本来就一 limb
> 一 lane 摊开，聚集动作折进 `ghmul.sg4`。合起来 3.76x。
> ChaCha 的对角步骤是**写侧状态搬移**：一个 quarter-round 在四个不同 lane 里产生四个
> 结果，一个写端口表达不了，所以只有路由能折、算术留在原地。1.26x。

### 4.6 FPGA 综合数据

DE10-Pro，`1SG280HU1F50E1VG`，Vortex 时钟要求 200 MHz，PCIe avst512 250 MHz。
八次 fitter 运行（§22.4、§22.5、§23.6）：

| 构建 | ALMs | registers | Vortex Fmax | PCIe slack |
| --- | ---: | ---: | ---: | ---: |
| baseline | 208,513 | 377,741 | 208.29 | **+0.204** |
| SG4 | 260,938 +25.1% | 452,906 | 206.91 | -0.424 |
| ChaCha S2, flat | 281,666 | | **-2.752 ns** | -0.130 |
| AES S2, reduced context | 286,974 +37.6% | 530,318 | 207.68 | -0.001 |
| 同上，seed 7 | 287,512 | | | **-0.816** |
| ChaCha S2, pipelined | 289,353 | | 205.63 | -0.374 |
| AES S2, single-cycle | 294,216 +41.1% | 560,788 | **130.82** | -0.470 |
| **AES S2, pipelined** | **299,907 +43.8%** | 562,705 | 205.72 | **+0.236** |

按核分项的 ALM（§11，`c2w4t16` 每核 ×2）：

| entity | c1w4t32 | c2w4t16 每核 | ×2 核 | 变化 |
| --- | ---: | ---: | ---: | ---: |
| `alu_unit` | 37,831 | 14,473 | 28,946 | **-23%** |
| `execute` | 71,124 | 32,018 | 64,035 | -10% |
| `auth_ghash` | 13,442 | 7,615 | 15,229 | **+13%** |
| `sym_aes` | 2,561 | 1,284 | 2,569 | 持平 |

**GHASH 是目前最大的单项 crypto 成本：15,229 ALM，两倍于 LSU、四倍于 SFU** —— 而这个
单元在所有测过的点上 backpressure 都是 0%。（我曾预测把 crypto 单元拆到两个核会减少
它们的面积；**结果相反** —— GHASH 在 16 lane 时是 476 ALM/lane，32 lane 时是 420，
因为每单元的固定成本 wrapper/`pe_switch`/elastic buffer 只摊到一半的 lane 上。
总的收益全在 ALU 和其他按 lane 缩放的逻辑里。）

**面积估计错了 4.5 倍。**第一次运行前写下的估计是 **+19,000 ALM**，实测 **+85,703**。
估计给算术定了价（一个共享 128x128 乘法器而不是十六个、四分之一的 S-box 阵列），
把上下文存储当成了附带项 —— 这恰好是反的：**寄存器涨了 183,047，增量的主体就是它。**
**时分复用能省算术，省不了存储，因为每个 (warp, lane) 的上下文都必须同时存在。**

> 这句话是 S2 和 S3 的分界：
> **S3 把 128 位状态放在本来就存在的寄存器堆里。S2 必须再造一个。**
> `aesrm.sg4` 是纯组合的，一个触发器都不花；S2 引擎无论如何都要每 warp 每 lane 一份上下文。

**上下文模型本身是准的，而且在第二个算法上也成立：**
- 移除 32,768 位上下文，预测减少 32,768 个寄存器，实测 **-32,387**，误差 1.2%。
- ChaCha 的上下文两核合计 114,688 位，flat 构建的寄存器增量 **+117,386**，误差 2.4%。

**结论：一个 S2 设计的触发器成本可以在写任何 RTL 之前从它的上下文定义算出来。**
ALM 数字算不出来：ChaCha S2 预测 310,000、实测 281,666，差 9%。

**两次同样的频率失败，两次同样的原因。**
- **GHASH 单周期版跑到 130.82 MHz**（要求 200）。最差的两百条 setup 路径**全部**在
  `VX_auth_ghash` 内，`VX_sym_aes` 内**一条都没有**。这个不对称就指认了原因：AES 引擎
  的每个 lane 读**自己**那份条目，lane 索引是 genvar，所以只 mux warp，四选一；
  GHASH 引擎用计数器遍历 lane，所以它的读是 **64:1 mux**，后面还挂着一整个 GF(2^128)
  乘法。AES 的轮已经把工作切成四拍一列，GHASH 只切了 lane 循环、没切算术。
  把 `ghash.block` 流水三级后恢复到 **205.72 MHz**，代价为零：吞吐仍是每周期一个 lane，
  指令从 `NUM_LANES` 拍变成 `NUM_LANES+2` 拍，rtlsim 在 `-n64 -b4 -t5 -a20` 读到
  74,168 周期，与单周期版**逐字节相同**。单元在一次 block-step 约 441 周期里只占住流水 16 拍。
  另外，`VX_auth_ghash` 的寄存器有一半是 retiming 产物而非体系结构状态：98,457 对上下文
  所需的 49,152，而 `VX_sym_aes` 是 56,394 对预测的 56,832（3% 吻合）。流水化还回来
  29,046 个。**面积失败和频率失败是同一条坏路径的两张脸。**
- **ChaCha flat 版跑到 -2.752 ns**，比 GHASH 第一次还差，最差的**全部六十条**路径都在
  `VX_sym_chacha` 内。构建前写下的预测是它会过，理由是这个引擎没有挂着域乘法的 64:1
  lane mux。漏了两件事：状态字索引来自步进计数器而不是 genvar，所以每个 lane 做四次
  **16:1** 读加四次译码写；而一个 quarter-round 是**八个严格依赖的步骤**（加、异或旋转、
  加、异或旋转，两遍），AES 的一轮只有一个 S-box 加一棵异或树那么深。
  **lane 循环被切了、算术没切 —— 和 GHASH 犯的是同一个错。**把 quarter-round 切两级后
  恢复 **205.63 MHz**，double-round 从八拍变十拍，rtlsim 读到 188,196 周期对 flat 版的
  189,168 —— 多出的两拍不只是便宜，是在噪声以下。

**PCIe 域：面积无关，布局敏感。**每一个失败的构建都失败在 PCIe `avst512` 250 MHz 域，
路径全在 Platform Designer 的 `mm_interconnect` 里（BAM master 的 waitrequest-allowance
适配 FIFO，`out_payload[604]` 进它的 M20K 输入），Vortex 里一条都没有，crypto 单元里
一条都没有。250 MHz 不是选择：Gen3 x16 是 128 Gb/s、应用接口 512 位宽，
`128e9/512 = 250 MHz` 整，由硬 IP 自己的 IOPLL 产生；不像 Vortex 时钟在重配置 MIF 里
带四档 profile，它不能降频，除非掉到 x8 或 Gen2 并把带宽砍半。而且这里的负 slack 是
主机加载 kernel 和 buffer 那条路径上的**功能性风险**，不是「跑慢一点」。

**曾经用了好几节的因果解释是「面积挤占」，三次测量说这个解释是错的**：
**最大的设计是唯一收敛的那个**，而两个面积相差 0.2% 的构建 slack 差 **0.815 ns**。
单周期版的 PCIe 失败更好的解释是 fitter 把力气花在一条 -2.644 ns 的 Vortex 路径上、
放任其他一切退化；SG4 版的失败（它的 Vortex 时钟是好的）在这里还没有解释。
**换 seed 不是修复** —— 0.815 ns 的散布下，seed 6 的 -0.001 已经是好签，再抽是彩票。
剩下的补救在 FPGA 工程那一侧：Qsys interconnect 里加一级流水（代价一拍 DMA 延迟），
或者给 PCIe shell 靠近硬 IP 划一个 LogicLock 区域。
**注意流水化的构建把每一个域都关上了，所以 S2 今天就有一个能工作的比特流，299,907 ALM。**

### 4.7 正确性验证

- `tests/crypto/isa_check`：逐指令对照主机参考。`clmul`/`clmulh`/`brev8`/`aes32esi`/
  `aes32esmi`/`ghred32l`/`ghred32h` 在两个模拟器上 **80/80**；`rori` 四个 shamt × 十六个
  向量 **16/16 + 16/16**。发出的编码还直接对照过汇编器：`6105d513` 反汇编为
  `rori a0, a1, 0x10`。
  这个测试**故意不在** `tests/crypto` family 列表里 —— 它是唯一需要 crypto 单元打开的
  app，而 family 跑在单元关闭的默认配置下，那样它会把编码当成它们别名到的指令执行然后失败。
- 两个 AEAD 的 `main.cpp` 做**两级**检查：主机参考实现必须先复现编译进去的标准向量
  （GCM test case 2/3/4 含 20 字节 AAD + 60 字节明文；ChaCha 是 RFC 8439 的 block、
  stream、Poly1305、AEAD 向量），然后才有资格判设备。设备的 Poly1305 用 radix-2^26
  五 limb 形式、主机参考用显式 base-2^32 大数，所以两者的分歧点在打包而不是在共同的误读上。
- `ghmul.sg4` 三方验证：RTL、simx、独立参考实现对常量输入
  A = (0x11111111, 0x22222222, 0x33333333, 0x44444444)、H = (0x01020304 .. 07)
  都返回 `b34491b3 cc2389d5 e6fe8193 76a9fdbf`。
- **两个单元不扰动基线**：`sw_ttable` 在单元关和开两种情况下返回**完全相同**的周期数和
  指令数（两个模拟器都是）。chacha_poly 的 `sw` 行同样。这个检查只有配合构建验证才有
  意义（两个相同的数字同样符合「第二次构建根本没发生」），所以每一行都记录了 `make`
  退出码、跨构建比对 driver `.so` 的 mtime、从应用自己的 banner 断言形状（而不是从传入
  的标签），并要求应用的计数器行与 runtime 的 `PERF:` 行一致。

### 4.8 原始数据在哪里

本文所有数字都能追到单次运行。

| | |
| --- | --- |
| `docs/proposals/data/crypto_measurements.csv` | **271 行**，每行一次模拟器运行，进了版本库，是持久记录 |
| `docs/proposals/data/README.md` | 列定义、边际拟合公式、复现方法 |
| `build32/crypto_runs/archive-2026-08/` | 那些行提取自的原始日志，649 个文件、78 MB |
| `build32/crypto_runs/logs/` + `records.csv` | 此后新做的运行 |

CSV 的 15 列自描述：`app, impl, driver, cores, warps, threads, msgs, blocks_per_msg,
blocks, bytes, cycles, instrs, opts, extensions, log`。`cores/warps/threads` 取自应用
自己的 banner 而不是构建标志，`extensions` 是构建实际编进去的宏（从
`build32/tests/crypto/<app>/config.stamp` 读回，不是你以为你敲了什么），`log` 是
archive 目录下的相对路径，271 行每一行都能解析到一个真实文件。

**`build32/` 是 gitignored 的**，所以日志在磁盘上但不在版本控制里、也没有备份。
`rm -rf build32` 会毁掉它们；版本库里的 CSV 就是为了在那之后仍然活着而存在的。

**每块的数字都是两点边际拟合，从来不是总量除以计数** —— 后者带着每消息的启动成本，
在 `blocks_per_msg` 小的时候会主导：

```
per_block = (metric[hi] - metric[lo]) / (blocks[hi] - blocks[lo])
```

`chacha_poly` 用 `lo/hi = 1/4`（cache-resident）和 `16/32`（memory-bound），
`aes_gcm` 用 `8/64`。参与拟合的行必须共享 `driver`、`warps` 和 `extensions`。

per-class 计数器（stall、指令 mix、load 延迟、load/store 计数）需要 make 上加 `PERF=1`
并在环境里设 `VORTEX_PROFILING=1`。它们进日志但不进 CSV。

fitter 结果不在本仓库，在 FPGA 工程的 `results/` 目录，每次构建一个子目录。

### 4.9 CI 覆盖

`ci/testcases/crypto.yaml` 有 **32 个用例**，覆盖每个层级各自的 configs 组合：
`crypto-family-{1,2}`（simx + rtlsim 跑整个 tests/crypto 家族）、
`crypto-isa-check-{1,2,wide}`、`crypto-aes-gcm-{hw-1,hw-2,hw-wide,aad-tail,hw-aad-tail,
sg4-probe,ilv-diag,s3,s3-fused,s3-ghmul,s2-aes,s2,s2-ilv}`、
`crypto-chacha-poly-{aad-tail,xr,mac,s1,s3,s3f,s2}`，以及六个 perf gate：
`perf_gate-aes-gcm-{sw,s2,s3g}`、`perf_gate-chacha-poly-{sw,s1,s2,s3f}`。

性能基线（golden rtlsim 周期数）在 `ci/perf/baselines/crypto.json`，容差 ±2%，
CI 只读，只有 `pytest --update-baselines` 会写。

---

## 5. 复现命令

树里 checked-in 的形状是 `c1w4t4`，所以每次都要带 override，而且必须走 `run-<driver>`：

```bash
# AES-GCM 软件基线（§5）
CONFIGS="-DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16" OPTS="-n128 -b64 -i0" \
  make -C tests/crypto/aes_gcm run-rtlsim

# AES-GCM S1（§16.3）
CONFIGS="-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE \
  -DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16" OPTS="-n128 -b64 -i1" \
  make -C tests/crypto/aes_gcm run-rtlsim

# AES-GCM S3g，两半都融合（§21.5）
CONFIGS="-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE \
  -DVX_CFG_EXT_SYM_SG4_ENABLE -DVX_CFG_EXT_AUTH_SG4_ENABLE \
  -DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16" OPTS="-n128 -b64 -i8" \
  make -C tests/crypto/aes_gcm run-rtlsim

# AES-GCM S2（§22.3）
CONFIGS="-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE \
  -DVX_CFG_EXT_SYM_S2_ENABLE -DVX_CFG_EXT_AUTH_S2_ENABLE \
  -DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16" OPTS="-n128 -b64 -i10" \
  make -C tests/crypto/aes_gcm run-rtlsim

# ChaCha-Poly 软件基线（§6）
CONFIGS="-DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16" OPTS="-n128 -b16 -i0" \
  make -C tests/crypto/chacha_poly run-rtlsim

# ChaCha-Poly S2（§23.4）
CONFIGS="-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE \
  -DVX_CFG_EXT_AUTH_POLY_ENABLE -DVX_CFG_EXT_SYM_CHACHA_S2_ENABLE \
  -DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16" OPTS="-n128 -b16 -i10" \
  make -C tests/crypto/chacha_poly run-rtlsim
```

需要保留日志时用 `tests/crypto/bench.sh`：它跑一个用例、保留整份日志、并把解析出来的
记录追加进 `build32/crypto_runs/records.csv`：

```sh
export CONFIGS="-DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16 \
                -DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE"
tests/crypto/bench.sh aes_gcm rtlsim -n32 -b4 -i1
```

`CONFIGS` 是**必填**而不是有默认值：`run-<driver>` 会重建 driver 的共享对象，空的
`CONFIGS` 会静默地在默认形状 `c1w4t4` 上重建它，然后测出一个看起来合理但不是你要的数字。
脚本选择拒绝执行。`RUNS=<dir>` 可以改日志落点。

`-i` 的取值就是 `main.cpp` 里 `kImpls[]` 的下标：

**aes_gcm**：0 `sw_ttable`、1 `hw_s1`、2 `sw_perm`、3 `hw_sg4`、4 `hw_s1_ilv`、
5 `hw_s1_ofs`、6 `hw_s3`、7 `hw_s3f`、8 `hw_s3g`、9 `hw_s2a`、10 `hw_s2`、11 `hw_s2_ilv`

**chacha_poly**：0 `sw`、1 `rori`、2 `sw_perm`、3/4 `sw_perm2/3`（已作为仪器否决）、
5 `xr`、6 `mac`、7 `s1`、8 `s3`、9 `s3f`、10 `s2`

需要的扩展没编进去时，host 会**拒绝**（打印 SKIPPED）而不是算错；需要收敛 quad 的
变体会检查 `-n` 是 4 的倍数；只处理整块的变体会检查 `-t 0`。

---

## 6. 已撤回的结论（不要再引用）

保留是因为错误本身是最可迁移的部分。

| 曾经写的 | 实际 | 出处 |
| --- | --- | --- |
| AES-GCM S1 是「2.67x」 | 内核有 57% 非算法内存流量；修好后 13.54x，换配置后 15.77x | §10 |
| 「2.80x against the shipped kernel」（S2） | 那来自 simx + 交织布局；rtlsim 说 **2.18x**，而它被用来论证要不要造 RTL | §22.7 |
| 「S2 是 memory-bound，交织 payload 能修」 | simx 显示布局帮 S2 22%、伤 hw_s1 77%，整个论证靠这个不对称的符号。rtlsim 上交织**伤** S2 4.4%。诊断撤回 | §22.7 |
| 「不要造 S2 的 RTL」 | 推理依据是一条和 `hw_s3g` 比较的 kill rule，而 `hw_s3g` 时序关不上。**拿一个造不出来的东西作比较不是停手的理由** | §22.7 |
| 「+19,000 ALM」 | 实测 +85,703。估计给算术定价、低估存储 | §22.4 |
| 「Poly1305 基本没有 S1」 | 依据的机器模型是错的：树不是 2R1W，WGATHER 已经读 rs3。`poly26.mac` 结果是这条 AEAD 里唯一重要的指令 | §23.8 |
| 「ChaCha-Poly S3 不该造」 | probe 确实输，融合行赢 20.5% | §23.8 |
| 「融合的 S3 指令也不该造」 | 值二十二个百分点 | §23.8 |
| 「S3 probe 让 load 差 6.6x」 | 那是用 `l[5]`/`u[5]` 和循环下标写的、编译器把它们放上了栈：165.5 指令/块、926,336 loads。标量化成 `l0..l4` 后是 111.2 和 164,736 | §23.8 |
| 「S2 是 6.0x」 | 算术错误，用错了块增量。是 **3.9x** | §23.8 |
| S1 结果的 warp scan 结论，以及基于它的 S2 决定 | 那次扫描跑在内联/按字访问修复**之前**的内核上；在修好的内核上重跑，趋势不是变弱而是**反转** | §10 |
| PCIe 域失败归因于面积增长 | 八次 fitter 运行显示毫无关系：最大的设计是唯一收敛的，面积差 0.2% 的两个构建差 0.815 ns。是布局彩票 | §23.6 |
| 「halving the LMEM banks multiplies the movement by 3.1x」 | 只描述了一个内核的一次扰动。chacha_poly 完全没有 local memory，movement 在两个形状间差 **140x** | §16.4 |
| 「S3 融合轮是 83% 的退化」（§17/§18 的裁决） | 那是在没有 per-hart 栈错开的机器上测的。同一台机器改两条启动指令后是 **30% 的收益** | §21.3 |
| `ghmul.sg4` 是退化（-19.9%） | probe kernel 的 bug：路由模板用 `if (ROUND == S3_ROUTING_FUSED)` 选融合 AES 轮，而两半都融合的内核是 `S3_ROUTING_FUSED_ALL`，走了 else 分支跑软件 AES。它从来就不是「both fused」 | §21.6 |

**方法论上留下来的三条：**
1. **per-class 动态计数能分辨静态指令数分辨不了的东西。**§17 和 §18 都在静态 `sp` 相对
   计数和反汇编清单上花了功夫；两次动态计数器都能更快给出答案。§21.6 的 bug 就是这么
   一次跑出来的：`sym` 占流的 25%、每块 10.6 条，而融合轮发 2.75 条、软件形式在四个 lane
   上十轮每轮正好四条 `aes32` 也就是 10.0 —— 算术直接点了名。
2. **静态溢出点无法预测动态 load 流量。**§17、§21.6、§23.7 各有一次。
3. **一个内部自洽的坏结果 —— 完整的 profile、可信的机制、和预测相反的符号 —— 是最值得
   拿去对自己的实现重新核对的那一类。**

以及一个只有已知答案测试才抓得到的 bug（§23.8）：ChaCha 引擎第一次 RTL 构建用
`csel[2:0]` 索引密钥、而应该是 `csel-4`，把八个密钥字轮转了四位。**指令数对、周期数对、
时序也对，只有 known-answer test 失败。**

---

## 7. 还没解决的

- **布局移动的机制**，两个内核、两个方向都没有解释。四对测量，没有一个说法能同时容纳四个。
- **chacha_poly 的稳态门**在测过的每个尺寸上都失败，而且比以前更宽（`-b16` 时固定项约
  263k 周期、占总量 17.9%）。留着失败而不去掩盖，因为 `-b32` 通过但会毁掉这个应用与
  aes_gcm 唯一可比的东西：两边都是每消息 1024 字节。
- **AAD 是否该进入被测配置。**所有行都是 `-a0 -t0`。功能实现了、检查了、CI 覆盖了，
  但没有任何一行是**带着** AAD 测的，所以它的运行时成本没有记录。
- **`aesrm.sg4` 的时序和面积。**融合数据通路是每 lane 四个 S-box 实例加四个 MixColumns，
  而发布版各一个，换回两个 4:1 mux。`sym_aes` 在 16 lane 时是 1,284 ALM/核，占
  208,513 ALM 设计的 0.6%、周期还有 4.0% 余量，所以纸面上面积是负担得起的 —— 但
  fitter 和时序分析器都还没见过它。
- **`poly26.rsum.sg4` 可以吃进位。**把每 limb 的进位加折进归约，每块-quad 省五条指令、
  折合每块 1.25 条，对一个每块 90 条的实现是不到 1.4% —— 换一个三源编码和更宽的 PE。
  没有造。真正的限制既不是实现也不是编码：块并行的 Poly1305 要求每个 lane 持有自己那份
  `r^{4-c}` 的五个 limb，这是分解方式固有的。唯一去掉这些寄存器的办法是把它们放进
  上下文，而那就是 S2，S2 已经给了 3.9x。
