# Cryptographic ISA extensions: software baseline

This document fixes the measurement contract for comparing software
cryptography against the instruction-set extensions that will replace it. The
numbers a later hardware variant is compared against are only meaningful if the
baseline, the workload and the counter definitions do not move, so they are
recorded here rather than left to whoever runs the benchmark.

## 1. Scope

The first landing is `tests/crypto/aes_gcm`, a software AES-128-GCM running on
unmodified hardware: no RTL, no decode change, no simulator change, no new
instruction. It establishes the correctness oracle and the cycle numbers that
the hardware work is measured against.

`tests/crypto/chacha_poly` follows under the same protocol and on the
same unmodified hardware, so the family holds one recorded row per AEAD before
any instruction exists. Section 6 records it and says what the two rows mean
together.

AES-GCM is the target, so the cipher is measured in the mode it is actually
used in: counter-mode encryption over whole blocks, GHASH authentication over
the resulting ciphertext, and tag generation. ECB was rejected because it is
not on the GCM critical path.

## 2. Design

### Workload shape

One independent GCM message per thread, one shared key, a distinct 96-bit IV
per message, empty AAD. Both halves of GCM are then parallel across threads:
counter-mode encryption is parallel by construction, and the GHASH chain is
serial only within a message. This matches the shape a hardware GHASH would
need, which keeps per-warp or per-lane state, and it models a server handling
many independent records rather than one long stream.

### Tables live in local memory

The four 1 KB T-tables, the 176-byte key schedule and the 256-byte GHASH table
are copied into local memory once per CTA and then read by every thread.

This is forced by the machine, not preferred. A table lookup is a
data-dependent gather across the SIMD width, and in this configuration
`VX_CFG_LMEM_NUM_BANKS` scales with `VX_CFG_SIMD_WIDTH` (32 banks at
`SIMD_WIDTH=32`) while `VX_CFG_DCACHE_NUM_BANKS` is 1. A table left in global
memory would serialise every gather through a single cache bank, and with
`VX_CFG_L2_ENABLED=0` and `VX_CFG_L3_ENABLED=0` the streaming plaintext would
evict it continuously. The baseline would then measure the memory system rather
than the round function, and would inflate any speedup claimed against it.

### One CTA per core

`grid_dim = num_cores`, `block_dim = num_warps * num_threads`, with a
grid-stride loop over messages. Sizing the grid to the problem instead would
launch one CTA per few messages, each refilling 4 KB of local memory, and the
fill would dominate. One persistent CTA per core amortises the fill. The CTA
spans every warp on the core, so the fill is strided over `threadIdx.x` and
fenced with `__syncthreads()`.

### Key expansion is host-side

The host expands the key and uploads the schedule; the device only copies it
into local memory. This is a policy, not an implementation detail: a hardware
variant that expands keys on-device would otherwise be measured against a
baseline that does not, so either both include expansion or neither does. This
baseline excludes it.

## 3. Correctness

Two levels, because a device-versus-host comparison alone cannot catch a broken
oracle.

1. The host reference — byte-oriented AES from FIPS-197 and a bit-at-a-time
   GF(2^128) multiply from SP 800-38D Algorithm 1 — must reproduce FIPS-197
   Appendix C.1 and two published GCM vectors before any device call. The
   vectors are compiled into `main.cpp`; there is no external file to fetch.
2. The device output over pseudorandom messages is compared against that
   reference.

Both levels earned their place during bring-up: level 1 caught a test vector
that mixed one GCM case's tag with another's key, and level 2 isolated a
reversed Horner iteration in the device GHASH — the ciphertext matched, so only
the authentication half was suspect.

## 4. Measurement protocol

Frozen. Changing any of it invalidates comparison with the numbers in section 5.

**Counters.** `cycles` is the maximum of `VX_CSR_MCYCLE` across cores;
`instrs` is the sum of `VX_CSR_MINSTRET` across cores. MCYCLE is per-core
elapsed time, so summing it is wrong by a factor of the core count — passing
the broadcast core id to `vx_device_mpm_query` sums, and must not be used for
cycles. The application recomputes both with an explicit per-core loop and
prints them; they must equal the runtime's own `PERF:` line or the run is
discarded.

**No `--perf` flag.** `VX_CSR_MCYCLE` and `VX_CSR_MINSTRET` are decoded outside
the `PERF_ENABLE` guard, so the baseline needs no `PERF` build and the only
`CONFIGS` it carries is the shape override recorded in section 5. A pipeline
breakdown, if ever wanted, is a separate run whose cycle count is not mixed
with this one.

**One launch per process.** rtlsim asserts reset once at device construction, so
MCYCLE accumulates across launches, while simx resets per launch. A warmup
launch or a repeat loop would mean different things in the two drivers. Repeat
by re-running the process.

**rtlsim is authoritative.** Its counter is busy-gated, so host idle time is not
counted. simx is recorded as a secondary line and the gap is reported, never
substituted.

**Steady state.** The problem size must be large enough that the one-time local
memory fill does not dominate. The gate is that doubling the block count
doubles the cycles: `cycles(2N)/cycles(N)` in `[1.96, 2.04]`.

**Determinism.** Three rtlsim runs at the recorded point returned identical
cycle and instruction counts. A run that does not reproduce means something in
the harness is varying — a stray flag, a leftover `CONFIGS`, a second launch —
and must be found before a number is recorded.

## 5. Recorded baseline

Configuration `c1w4t32`: one core, four warps, 32 threads, therefore
`SIMD_WIDTH=32` and `ISSUE_WIDTH=1`. Message count is set to the thread count
so every lane carries exactly one message with no tail. The tree's checked-in
shape is `c1w4t4`, so the thread count is a build override and has to be
carried on every run that is compared against these numbers:

```
CONFIGS="-DVX_CFG_NUM_THREADS=32" OPTS="-n128 -b64 -i0" make run-simx
```

128 messages of 64 blocks: 8192 blocks, 131072 bytes.

| | simx | rtlsim |
| --- | ---: | ---: |
| cycles | 12,255,505 | 14,247,819 |
| instrs | 1,229,052 | 1,229,052 |
| cycles/block | 1496.03 | 1739.24 |
| bytes/cycle | 0.0107 | 0.0092 |

Retired instruction counts agree exactly. The cycle gap is 16.3% at this size
and 6.3% at `-n64 -b4`, so it grows with the problem; that is a modelling
discrepancy to resolve before a `model_parity` gate can cover these cases, not
a tolerance to widen.

Steady-state evidence, simx, `-n128`:

| blocks/msg | cycles | ratio |
| ---: | ---: | ---: |
| 16 | 3,241,766 | |
| 32 | 6,202,459 | 1.913 |
| 64 | 12,255,505 | 1.976 |

`-b64` is the first size inside the gate. Below it the fixed cost — the local
memory fill plus launch, about 137k cycles by a two-point fit — is still
visible.

Provenance:

- commit `6533ce29fc2f44572b2bc3e6144f594bbd96e635`
- `VX_config.toml` sha256 `3f020a15364555da8da610b5f78501f670299440685846fb40bb0f757593fb93`
- `VX_types.toml` sha256 `2e22f4fbac08fe54036ee80b01116615f7675bb7cc512f6de77571ca5d91f877`
- clang 20.1.8 (vortexgpgpu/llvm 4c836512)

## 6. The second baseline: ChaCha20-Poly1305

`tests/crypto/chacha_poly` is the other AEAD the hardware has to cover,
measured under the protocol of section 4 without changing any of it. The launch
geometry, the one-message-per-thread shape, the counters and the reduction are
the same, so the two baselines differ in their algorithm and in nothing else.
Correctness is the same two levels: the host reference must reproduce the
RFC 8439 block, stream, Poly1305 and AEAD vectors, compiled in, before it is
allowed to judge the device.

### What the algorithm forces to differ

Three of section 2's decisions have no counterpart here, and in each case the
reason is the algorithm rather than a preference:

- **No tables, so no local memory.** ChaCha20 is ARX over sixteen 32-bit words
  and Poly1305 is integer arithmetic modulo 2^130-5. Nothing is looked up, so
  `lmem_size` is zero and the data-dependent-gather argument of section 2 has
  nothing to apply to. This is also the reason the baseline is as strong as it
  turns out to be.
- **No key schedule**, so the host has nothing to precompute and the policy of
  section 2 is vacuous; the host uploads the key itself.
- **The Poly1305 one-time key is per message.** It is the keystream at counter
  zero, so it depends on the nonce and must be derived on the device: one extra
  ChaCha20 block per message. GHASH's `H` depends only on the key, which is why
  aes_gcm can compute it once on the host and upload it. The asymmetry is
  algorithmic and survives into every later variant.

The device's Poly1305 uses the radix-2^26 five-limb form and the host reference
an explicit base-2^32 bignum, so the two disagree at the packing rather than at
a shared misreading, exactly as aes_gcm's table-driven GHASH is checked against
a bit-at-a-time multiply.

### Sizes are matched by the byte, not by the block

ChaCha20's block is 64 bytes and AES's is 16, so the two applications are lined
up on bytes per message. `-n128 -b16` here and `-n128 -b64` there are both 128
messages of 1024 bytes, 131072 bytes in total, and `bytes_per_cycle` is the
field that compares between them.

### Recorded baseline

Same configuration as section 5, same override:

```
CONFIGS="-DVX_CFG_NUM_THREADS=32" OPTS="-n128 -b16 -i0" make run-simx
```

| | simx | rtlsim |
| --- | ---: | ---: |
| cycles | 2,464,332 | 2,629,820 |
| instrs | 175,816 | 175,816 |
| cycles/block (64 B) | 1203.29 | 1284.09 |
| bytes/cycle | 0.0532 | 0.0498 |

Retired instruction counts agree exactly. The cycle gap is 6.7%, against 16.3%
for aes_gcm at the same byte count, so whatever section 5's modelling
discrepancy is, it tracks something aes_gcm does and this does not. Three
rtlsim runs returned identical cycle and instruction counts.

Steady-state evidence, simx, `-n128`:

| blocks/msg | bytes/msg | cycles | ratio |
| ---: | ---: | ---: | ---: |
| 4 | 256 | 754,851 | |
| 8 | 512 | 1,242,231 | 1.646 |
| 16 | 1024 | 2,464,332 | 1.984 |

`-b16` is the first size inside the gate, and it is the size the byte matching
asks for independently. Below it the per-message cost that does not scale with
the payload is still visible, and here that cost is algorithmic rather than a
fill: at `-b4` the counter-zero block alone is a fifth of the ChaCha20 work.

Provenance:

- commit `16c8506e288376920587a63c2c174b0f160243b2`
- `VX_config.toml` sha256 `3f020a15364555da8da610b5f78501f670299440685846fb40bb0f757593fb93`
- `VX_types.toml` sha256 `2e22f4fbac08fe54036ee80b01116615f7675bb7cc512f6de77571ca5d91f877`
- clang 20.1.8 (vortexgpgpu/llvm 4c836512)

### What the two rows say

| `-n128`, 131072 bytes | aes_gcm | chacha_poly | ratio |
| --- | ---: | ---: | ---: |
| cycles, simx | 12,255,505 | 2,464,332 | 4.97 |
| cycles, rtlsim | 14,247,819 | 2,629,820 | 5.42 |
| instrs | 1,229,052 | 175,816 | 6.99 |

The software ChaCha20-Poly1305 is five times faster and needs seven times fewer
instructions than the software AES-GCM over the same bytes. That is not a defect
in the AES baseline. AES on this machine is a table lookup and a GF(2^128)
multiply, neither of which the ISA supports at all, while ChaCha20 is adds,
xors and rotates and Poly1305 is a 32x32 multiply, all of which it does. The
cipher that was designed to be fast in software is fast in software.

The consequence for the instruction work is that the two algorithms start with
very different headroom, and a speedup quoted without naming its baseline says
nothing. Where the ChaCha20 headroom is can be stated exactly: `rv32imaf` has
no rotate, so each of the four rotates in a quarter-round compiles to
`slli`/`srli`/`or`, and eighty quarter-rounds per block put 960 instructions of
rotation into a block that costs about 2611 instructions per lane at the margin
(the `-b8` to `-b16` instruction delta, per warp, per block). Thirty-seven per
cent of the block is the ISA's missing rotate.

## 7. Hardware: two execute units, named by role

The hardware variants join the same application as additional entry points in
the same binary, selected by `-i`. The host program, buffers, vectors, counter
reduction and output format are shared, so a comparison between two rows
measures the device code and nothing else. Splitting them into separate
applications would reintroduce exactly the variables this protocol removes.

### The split

AES and GHASH get separate EX units, not two PEs behind one. They are named by
role rather than by algorithm, so the topology does not change as the family
grows:

| EX unit | now | later |
| --- | --- | --- |
| `EX_SYM` | `PE_AES` | `PE_CHACHA` |
| `EX_AUTH` | `PE_GHASH` | `PE_POLY1305` |
| `EX_HASH` | | `PE_KECCAK` |
| `EX_MOD` | | NTT, modular arithmetic |

AES and ChaCha share `EX_SYM` because they are the same role and a cipher suite
picks one or the other; GHASH and Poly1305 share `EX_AUTH` for the same reason.
Keccak and NTT will not join either: their dispatch geometry, latency and data
flow differ enough that sharing a scheduling domain would couple unrelated
things.

### Why an EX rather than a second PE

An EX unit is a scheduling domain, not just a datapath. Splitting buys an
independent dispatch queue, an independent dispatch credit, and an independent
input port.

**The backpressure argument does not apply to the instructions actually built,
and must not be claimed.** It was the original justification here and it was
wrong. Both mechanisms an EX split buys are gated on a PE going busy:

- The per-EX dispatch credit `fu_goingfull` (`VX_scoreboard.sv:44`, `:50-64`,
  `:189`) halts issue of every instruction bound for that EX, from every warp
  in the issue slice, once one PE stops draining.
- `VX_pe_switch`'s request side is a `VX_stream_switch` with `NUM_INPUTS=1`
  and `REQ_OUT_BUF=0`, so a ready PE is head-of-line blocked behind a busy one.

Every instruction implemented here is single-cycle and stateless behind a 1-deep
output elastic buffer, so `execute_if.ready` is never low for more than a cycle
and neither mechanism fires. `fu_goingfull` still asserts transiently under
back-to-back issue, but that is a pipeline-depth rate limit shared by every EX
in the design, not something a split changes.

There is also a counterexample in-tree that makes backpressure insufficient on
its own: `EX_ALU` already hosts a long-blocking PE. `VX_alu_muldiv.sv:320` ties
`execute_if.ready` to the divider, and `VX_serial_div` is bit-serial over
`WIDTHN-1` = 31 steps, so an integer divide head-of-line blocks the single-cycle
integer ALU for ~32 cycles. The design ships that way and DIV was never given
its own EX. An argument from backpressure would need a quantitative
dispatch-stall budget to survive that.

**The actual reason is measurement integrity.** The point of this work is to
compare instruction granularities against each other. If a fine-grained variant
lived inside `VX_alu_unit` and a later coarser or stateful variant lived in its
own EX, a comparison between them would confound two changes — the instruction
granularity and the scheduling domain — which is the class of confound the
protocol in section 4 exists to remove. Fixing the EX id, module boundary,
payload types, lane count and commit-beat count from the start means a later
variant is measured against these numbers without the topology moving underneath
it.

That is not free, and the price is known and accepted: `EX_BITS` widens 2 to 3
(widening `ex_type` in `decode_t`, `ibuffer_t`, `scoreboard_t`, `operands_t`),
each unit adds a `DISPATCH_QSIZE`-deep dispatch queue per issue slice, and both
land at the bottom of `VX_commit`'s static priority arbiter.

Two things this argument must **not** claim, because the code says otherwise:

- Not `fu_locked`. That reacts only to a non-`11` `fu_lock`/`fu_unlock`
  encoding, whose sole producer is WGMMA uop expansion, which is disabled in
  this configuration. It is about multi-uop atomicity, not backpressure, and a
  long crypto op would not assert it.
- Not op-encoding scarcity. `INST_OP_BITS` is 4, but `op_type` travels with a
  27-bit `op_args_t` union, and four existing units already use that as opcode
  space. A single crypto EX would not run out.

Splitting also does not eliminate head-of-line blocking; it bounds it. The
serialisation point becomes the per-issue-slice operands stream
(`VX_dispatcher.sv:40`), with `DISPATCH_QSIZE = 4` of slack: up to four AUTH
ops buffer before an AES op at the head stalls again.

### Constraints that follow from the tree

- **Lane geometry mirrors ALU and SFU, not TCU.** `NUM_SYM_LANES` and
  `NUM_AUTH_LANES` equal `SIMD_WIDTH`, blocks are 1. The TCU shape would pin
  `SIMD_WIDTH == NUM_THREADS` core-wide through `VX_lane_dispatch`'s divisibility
  assertion. Keeping lanes at `SIMD_WIDTH` also keeps `NUM_PACKETS = 1`, one
  commit beat per uop, which is what the commit-arbiter reasoning below rests on.
- **Encodings are `INST_EXT3` and `INST_EXT4`**, both undecoded in the RTL and
  in simx. The standard Zkn `INST_R` encodings are unavailable: `VX_decode.sv`
  has an unconditional catch-all that already decodes all sixteen AES32 funct7
  values as ADD/SUB, and simx claims every odd funct7 under `Opcode::R` for
  MULDIV. The two models already disagree about that space.
- **EX indices are a derived cascade**, so a disabled unit collapses its index
  and the dispatch and commit arrays resize with no other edit.
- **Decode assigns a distinct `ex_type` per crypto instruction.** The AES and
  GHASH op_type values collide, and neither PE inspects the unit field, so
  routing on anything weaker would execute an AES op as a GHASH op and corrupt
  state silently.
- **Both units land at the bottom of the commit priority.** `VX_commit.sv` uses
  a static priority arbiter with the lowest index winning and no aging, and
  `NUM_EX_UNITS` grows upward. This is survivable only while each uop yields
  exactly one commit beat.

### The comparison this is all for

Three AES instruction granularities — standard `aes32`, full-round, and
warp-cooperative — are swapped inside `PE_AES` by a configuration knob. The EX
id, module boundary, payload types, lane count and commit-beat count are
identical across all three, so the measured difference is the instruction
granularity and not the surrounding structure. Only the standard granularity
exists today; the other two are new design work, not a port.

## 7. Recorded: the S1 hardware variant

`aes_gcm_hw_s1` is the same GCM in the same application, selected by `-i1`. It
uses five ratified instructions — `aes32esi`, `aes32esmi` (Zkne) in `EX_SYM`,
and `clmul`, `clmulh`, `brev8` (Zbkc + Zbkb) in `EX_AUTH` — and keeps no state
in either unit: the GHASH accumulator and the hash subkey live in the register
file. Both T-tables and the GHASH nibble table are gone; only the key schedule
remains in local memory, read the same way by both variants so neither is
advantaged by what it keeps resident.

Same configuration and same command as section 5, `c1w4t32`, `-n128 -b64`:

| | sw_ttable simx | sw_ttable rtlsim | hw_s1 simx | hw_s1 rtlsim |
| --- | ---: | ---: | ---: | ---: |
| cycles | 12,252,182 | 14,333,745 | 4,167,472 | 5,373,159 |
| instrs | 1,229,052 | 1,229,052 | 134,872 | 134,872 |
| cycles/block | 1495.63 | 1749.72 | 508.72 | 655.90 |
| bytes/cycle | 0.0107 | 0.0091 | 0.0315 | 0.0244 |

On rtlsim, which section 4 makes authoritative: **2.67x fewer cycles, 9.11x
fewer retired instructions.**

### The two numbers disagree, and that is the result

The instruction count falls 9.11x while cycles fall only 2.67x, so IPC drops
from 0.086 to 0.025. The hardware variant is latency-bound, not throughput-
bound: each block is a ~40-deep serial chain of `aes32esmi` (ten rounds, four
chained byte-steps per output word) followed by a GHASH whose reduction is
itself serial, and at four warps there is not enough independent work to cover
it. The software variant hid its own latency behind table gathers that gave the
scheduler something else to issue.

This bounds what a coarser-grained AES instruction can buy. Shortening the
chain — a full-round or warp-cooperative instruction — attacks exactly the term
that dominates here, whereas making each existing step cheaper does not. It
also means the S1 result should be re-measured at higher warp counts before it
is read as a ceiling; the number above is for the frozen configuration, not a
statement about the design's limit.

### The units do not perturb the baseline

`sw_ttable` was measured with `VX_CFG_EXT_SYM_ENABLE`/`AUTH_ENABLE` off and on
and returned **identical** cycle and instruction counts in both simulators
(12,252,182 / 14,333,745). Widening `EX_BITS` from 2 to 3 and adding two
dispatch queues therefore costs nothing measurable to code that does not use
them, so the two rows above differ only in the device code.

### Discrepancy against section 5, not yet attributed

Section 5's numbers do not reproduce exactly in the current tree: simx moved
12,255,505 -> 12,252,182 (-0.03%) and rtlsim 14,247,819 -> 14,333,745 (+0.60%),
while retired instructions are unchanged at 1,229,052, so the compiled kernel is
identical. The off/on comparison above rules out the crypto units as the cause.
Something else between commit `6533ce29f` and now moved rtlsim timing slightly
and has not been identified. The section 7 rows are all measured in one tree at
one commit, so the comparison between them stands regardless; but section 5's
numbers should not be quoted against section 7's until this is explained.

Provenance for this section:

- `VX_CFG_EXT_SYM_ENABLE` and `VX_CFG_EXT_AUTH_ENABLE` both on
- `CONFIGS="-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE -DVX_CFG_NUM_WARPS=4 -DVX_CFG_NUM_THREADS=32"`
- correctness: `tests/crypto/isa_check` passes 80/80 on both simulators, and
  both GCM variants pass the two-level check in `main.cpp`

### Warp scan: what actually limits the S1 result

The gap between the 9.11x instruction reduction and the 2.67x cycle speedup was
attributed above to dependency-chain latency. **That was wrong**, and the
correction matters more than the original number, so it is recorded here rather
than quietly amended.

A pipeline breakdown (`VORTEX_PROFILING=1`, a separate run per section 4, its
cycle count not mixed with the recorded rows) at `c1w4t32`, `-n128 -b8`:

| | sw_ttable | hw_s1 |
| --- | ---: | ---: |
| IPC | 0.087 | 0.031 |
| scheduler idle | 91% | 97% |
| scoreboard (operand) stall | 95% | 100% |
| alu / lsu / sfu / fpu stall | 0% / 0% / 0% / 0% | 0% / 0% / 0% / 0% |
| loads | 991,192 | 105,644 |
| average load latency | 48.8 | 126.9 |

Two things fall out. **The crypto units are never the bottleneck** -- functional
unit backpressure is flat zero in both, which is the empirical form of the claim
in section 6 that a single-cycle stateless PE never deasserts ready. And the
stall is not arithmetic: it is 100% operand stall, caused by a 127-cycle average
load latency. `hw_s1` issues 9.4x fewer loads, exactly as designed, but its
average load latency is 2.6x *worse* -- the fast 32-bank local-memory table
gathers were what pulled the software baseline's average down, and what remains
after deleting them is streaming plaintext and ciphertext through a
single-banked D-cache with L2 and L3 disabled.

A warp scan holding `SIMD_WIDTH` fixed confirms it. Warps are the only variable:
`ISSUE_WIDTH`, `SIMD_WIDTH`, `NUM_ALU_LANES`, `NUM_SYM_LANES` and
`LMEM_NUM_BANKS` are all constant across the three points, and the scan stops at
16 warps because `ISSUE_WIDTH = up(NUM_WARPS/16)` steps to 2 at 32. Message
count tracks thread count so no lane idles. `c1w{4,8,16}t4`, `-b64`, rtlsim:

| warps | hw_s1 cycles/block | IPC | avg load latency | loads/cycle |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 338.97 | 0.389 | 16.8 | 0.260 |
| 8 | **254.97** | **0.517** | 27.0 | **0.346** |
| 16 | 324.11 | 0.406 | 45.8 | 0.272 |

It peaks at eight warps and **regresses 27% at sixteen**. Load latency grows
monotonically with concurrency, about 1.7x per doubling, and load throughput
tops out around 0.35 warp-loads per cycle -- which at four lanes per load is
1.38 lane-accesses per cycle against one D-cache bank, already oversubscribed.
Functional unit backpressure stays at zero across all three points.

The same conclusion arrives independently from the other direction: `hw_s1`
sustains 0.0472 bytes/cycle at `t4` and only 0.0244 at `t32`. Eight times the
lanes, half the throughput. Added parallelism is being converted into queueing
delay, not work.

**So 2.67x is a floor, not a ceiling, and what caps it is not the instruction
set.** Two levers, neither of them ISA:

- `VX_CFG_DCACHE_NUM_BANKS` is 1 and L2/L3 are off. That is the wall.
- Roughly 60% of the kernel's memory traffic looks like register spill: the
  measured 126 memory operations per block per thread against about 52 the
  algorithm requires. Spill lands directly on the resource that is already
  saturated.

This reorders the roadmap. A coarser-grained AES instruction shortens the
dependency chain, and the dependency chain is not what is binding -- S2 would
hit the same wall. Fix the spill, then the memory configuration, then re-measure
S1. Only the number that survives that is a statement about the instruction set.

**A caution about `t4` numbers.** The scan above is internally valid because
only the warp count moves, but its *speedups* must not be quoted: at
`LMEM_NUM_BANKS=4` the software baseline's table gather is starved while the
hardware variant, which has no table, is unaffected. That inflates the ratio to
7-9x. The honest ISA figure remains the `t32` 2.67x.
