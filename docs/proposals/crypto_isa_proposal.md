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
| cycles | 2,258,400 | 2,548,408 |
| instrs | 175,512 | 175,512 |
| cycles/block (64 B) | 1102.73 | 1244.34 |
| bytes/cycle | 0.0580 | 0.0514 |

Retired instruction counts agree exactly; the cycle gap is 12.8%.

### The steady-state gate no longer passes at the comparison point

Steady-state evidence, simx, `-n128`:

| blocks/msg | bytes/msg | cycles | ratio |
| ---: | ---: | ---: | ---: |
| 8 | 512 | 1,190,454 | |
| 16 | 1024 | 2,258,400 | 1.897 |
| 32 | 2048 | 4,579,135 | 2.028 |

`-b16` is **outside** the `[1.96, 2.04]` gate of section 4; `-b32` is inside it.
An earlier revision of this kernel passed at `-b16` with 1.984, and what moved
is the kernel rather than the measurement: fusing the keystream into the XOR
(section 9) cut the per-block cost, which raises the share taken by the
per-message cost that does not scale with the payload -- the counter-zero
ChaCha20 block, the Poly1305 setup and the tag. A two-point fit puts that fixed
term at about 122.5k cycles, 5.4% of the total at `-b16`.

The gate is left failing rather than resolved, and the recorded row stays at
`-b16`. The alternative is to record `-b32`, which passes the gate and destroys
the one thing that makes this application comparable to aes_gcm at all: 1024
bytes per message on both sides. A gate calibrated against a kernel with a
larger per-block cost necessarily loosens when that cost is cut, so it failing
here is a consequence of the fusion working rather than evidence against the
number. The fixed-cost share is stated above so that a reader can discount it
explicitly instead of trusting the gate to have done it.

Provenance:

- commit `4e7ee9c4d`, crypto units off,
  `CONFIGS="-DVX_CFG_NUM_THREADS=32"`
- clang 20.1.8 (vortexgpgpu/llvm 4c836512)
- every row re-taken after a concurrent-build hazard was identified in this
  shared tree: `make` exit status recorded, the driver `.so` mtime compared
  across each build, the `CONFIGS` banner checked for the warp, thread and
  unit-enable values actually requested, and the application's counter line
  required to agree with the runtime's `PERF:` line. All rows passed. A build
  that silently does not run leaves the mtime unchanged and is otherwise
  invisible: it yields a plausible number from a stale binary.

### What the two rows say

Both applications measured in the same tree at the same commit, because
section 5's rows no longer reproduce exactly (section 8):

| `-n128`, 131072 bytes | aes_gcm | chacha_poly | ratio |
| --- | ---: | ---: | ---: |
| cycles, simx | 12,224,492 | 2,258,400 | 5.41 |
| cycles, rtlsim | 14,379,377 | 2,548,408 | 5.64 |
| instrs | 1,229,052 | 175,512 | 7.00 |

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
cent of the block is the ISA's missing rotate. Section 9 implements that rotate
and measures what removing it is worth, which is not what this paragraph would
lead a reader to expect.

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

## 8. Recorded: the S1 hardware variant

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
and has not been identified. The section 8 rows are all measured in one tree at
one commit, so the comparison between them stands regardless; but section 5's
numbers should not be quoted against section 8's until this is explained.

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

## 9. RORI: a third of the instructions, and none of the cycles

`chacha_poly_rori` is the same AEAD in the same application, selected by `-i1`.
It adds exactly one instruction, and the instruction is deliberately not a
cryptographic one: ratified Zbb/Zbkb `RORI`, executed by a second PE in `EX_SYM`
(`hw/rtl/crypto/sym/VX_sym_rot.sv`).

### Why a non-cryptographic instruction is recorded here

`rv32imaf` has no rotate at all. ChaCha20's quarter-round is add, xor and
rotate, so each of the four rotates in each of the eighty quarter-rounds per
64-byte block compiles to `slli`/`srli`/`or`: 960 instructions of rotation in a
block that costs about 2611. Implementing `RORI` therefore **raises the
baseline** rather than accelerating the cipher, and a ChaCha20 speedup measured
against a baseline without it would be claiming credit for the B extension.

Section 6's rows are the `rv32imaf` baseline. The `sw` row below is that same
source measured in the current tree; the `rori` row is what the B extension is
worth. Only a fused xor-rotate, which has no ratified encoding, would be an
extension in the sense the rest of this document means.

### Conformance before performance

`tests/crypto/isa_check` gained a `rori` case: four `shamt` values over sixteen
vectors against a host reference, **16/16 on simx and 16/16 on rtlsim**. That
check is not ceremony. Left to the fallback decode path the two models disagree
about this encoding -- the RTL keys on `instr[30]` and would run it as `SRAI`,
simx would run it as `SRL` -- so a kernel-level test would have shown a wrong
answer without saying which instruction produced it. The emitted encoding was
also checked directly against the assembler: `6105d513` disassembles as
`rori a0, a1, 0x10`.

### Recorded

`c1w4t32`, `-n128 -b16`, 131072 bytes, both units enabled:

```
CONFIGS="-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE -DVX_CFG_NUM_THREADS=32" \
  OPTS="-n128 -b16 -i{0,1}" make run-simx
```

| | sw | rori | ratio |
| --- | ---: | ---: | ---: |
| cycles, rtlsim | 2,548,408 | 2,513,410 | 1.014 |
| cycles, simx | 2,258,400 | 2,229,517 | 1.013 |
| instrs | 175,512 | 131,792 | 1.332 |
| cycles/block (64 B), rtlsim | 1244.34 | 1227.25 | |

**A third of the instructions removed, and one and a half per cent of the
cycles.** Both simulators agree on the sign and very nearly on the size.

The `sw` row here and section 6's are the same number, 2,548,408 / 175,512 on
rtlsim, measured once with the units off and once with them on. That is the
check section 8 ran for aes_gcm, and it passes here too: a kernel that issues no
crypto instruction is unaffected by the units existing. The check is only worth
anything with the build verification described in section 6's provenance, since
two identical numbers are equally consistent with the second build never having
happened; the driver `.so` mtime changed across that build and the `CONFIGS`
banner reported both units enabled, so it did.

### What this apparatus can resolve

Both numbers above are small, and a small number is only a result if the
apparatus can tell it from nothing. `chacha_poly_sw_perm` exists to answer
that: it issues the four quarter-rounds of each round in reverse order, which
is bit-identical by construction rather than merely equivalent, since the four
touch disjoint columns. Two kernels that cannot differ, so the distance between
them is the floor.

| | sw | sw_perm | distance |
| --- | ---: | ---: | ---: |
| cycles, rtlsim | 2,548,408 | 2,541,483 | -0.272% |
| cycles, simx | 2,258,400 | 2,260,762 | +0.105% |
| instrs | 175,512 | 175,508 | 0.002% |

**The floor is about 0.3%**, and the two signs are opposite, which is the shape
scheduling variance should have rather than a systematic effect. Against it,
`rori`'s 1.5% is roughly five times the floor and the keystream fusion's 5.7%
roughly twenty; both are resolved rather than small. A change worth less than
about 1% is not measurable here and should not be recorded as a result.

This is a different property from determinism, and the distinction cost a
retraction elsewhere before it was drawn. Byte-identical repeat runs, agreement
across simx and rtlsim, and agreement across units-off and units-on builds all
say that the same input gives the same output. None of them says how far apart
two different inputs that should agree will land. Only this row does.

One caveat: 0.3% is a single perturbation at a single point, so it establishes
that the floor is at least that rather than that no perturbation lands further
out. If a future result lands under about 1%, two or three more reorderings
should be measured before it is believed.

### The ratio to watch is the divergence, not the speedup

1.014x cycles against 1.332x instructions. Those two ratios should track each
other in a kernel whose cost is the instructions it issues, and they do not.
Section 10 records the same divergence for AES before its kernel was fixed --
9.11x instructions for 2.67x cycles -- and records it closing to 11.56x against
13.54x afterwards. ChaCha has not closed, which is the single most useful fact
in this section: it says the ChaCha kernel is still spending its time on
something the instruction set cannot reach, and it says so without needing to
identify what.

### It is not dependency latency, and more warps do not help

Section 8 left open that the S1 result should be re-measured at higher warp
counts before being read as a ceiling. For ChaCha that door is now closed.
simx, `SIMD_WIDTH` fixed at 32, message count tracking thread count so no lane
idles:

| warps | messages | sw cycles/block | rori cycles/block | ratio |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 128 | 1165.69 | 1173.46 | 1.007 |
| 8 | 256 | 1183.01 | 1219.99 | 1.031 |
| 16 | 512 | 1228.81 | 1224.11 | 0.996 |

The ratio stays at one throughout, and cycles per block get slightly *worse*
with more warps for both variants. The machine is saturated at four warps on
something that is neither instruction issue nor arithmetic latency.

### Where the cycles go

IPC is 0.078. The arithmetic closes on the measured numbers without a model:
each 64-byte block costs a lane 16 word loads and 16 word stores, so 4 warps x
16 blocks x 32 memory instructions is 2048 warp memory instructions, and at 32
lanes each that is 65,536 individual accesses -- 262,144 bytes, exactly the
plaintext read plus the ciphertext written. Against 2,258,400 cycles that is
**34.5 cycles per access**, and it accounts for essentially the whole run.
Stack traffic is on top of this, so 34.5 is an upper bound on the per-access
cost and 65,536 a lower bound on the access count.

The cause is the workload shape rather than the algorithm. One independent
message per thread puts consecutive lanes 1024 bytes apart, so every warp
memory instruction touches 32 distinct cache lines, and `DCACHE_NUM_BANKS` is
1 with L2 and L3 off.

A correction, because the first version of this section overstated it: these
rows were **not** taken under `PLATFORM_MEMORY_NUM_BANKS=1`. The banner says 2.
One DDR4 channel is a property of the DE10-Pro bitstream, where only one of the
four was ever on the Vortex path; the simulated configuration these numbers come
from has two. The direction matters and is not the flattering one -- the
simulated memory system is the more generous of the two, so a board measurement
should come out worse than what is recorded here, not better.

### What this settles

**This conclusion has been narrowed, and the narrowing is the point.** It
originally read: two independent algorithms, two independent routes, one
conclusion -- on this configuration the instruction set is not the binding
constraint. The AES half of that has since collapsed. Section 10 shows the AES
wall was a property of the kernel rather than of the machine: two code defects,
non-inlined helpers forcing arrays onto an 8 KB-strided stack and byte-wise
accessors defeating strict-align widening, and once removed the same
configuration yields 13.54x. The wall was removable.

What survives is narrower and still worth having. ChaCha20 has no tables, so
nothing was deleted from its memory system and the divergence cannot be an
artefact of a deletion -- but nor is it evidence about the machine. The honest
statement is about this kernel: **chacha_poly still carries the class of defect
that AES has had removed, and until it is gone every ChaCha ISA number measures
the defect rather than the instruction set.** `rori` removing a third of the
instructions for one and a half per cent of the cycles is a measurement of that
defect, not of the rotate.

The immediate consequence is that a fused ChaCha xor-rotate -- the natural next
step, and the only one that would be a genuine extension -- removes a further
~320 instructions per block and would also buy approximately zero. It should
not be built until the memory side moves.

For ChaCha specifically the spill lever section 8 names is structural rather
than incidental: sixteen live ChaCha state words plus Poly1305's five `h`, five
`r` and four `5r` limbs is thirty values on a thirty-two register machine, and
the compiled kernel shows 145 `lw` and 108 `sw` statically. The form that fixes
that is the subgroup-cooperative one -- four state words per lane instead of
sixteen -- which is a different axis from instruction granularity.

Provenance:

- commit `3a66ec981` plus this section's own commit
- the working tree also carried unrelated in-flight MPM-counter edits in
  `VX_csr_data.sv`, `sim/simx/core.*` and `perf.cpp` at measurement time; both
  rows were measured in that same tree, so the comparison between them stands
- `CONFIGS="-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE -DVX_CFG_NUM_THREADS=32"`

### Three attempts to remove the defect, and what they cost

The defect is named precisely: the keystream materialises. The permutation
keeps all sixteen words in registers -- the double-round loop is 162
instructions with zero memory operations -- and then they are spilled and
reloaded four at a time by the XOR. Each reload is a per-hart stack access at
`vx_start.S`'s 8 KB stride, which is 32 distinct cache lines per warp, the same
shape as the payload layout at four times the stride.

A prediction was registered before the attempts: if the payload and the
keystream each contribute about 32 line-touches per block and the machine is
line-touch-bound, removing the keystream half alone is worth close to 2x, with
1.3x named in advance as the point below which the model would be abandoned.

| attempt | result |
| --- | --- |
| Fuse the keystream into the XOR so no `ks[]` array exists | **-5.7%** (2,394,487 -> 2,258,400) |
| Unroll the absorb, so constant indices let SROA hold the words in registers | **+19% worse** (2,258,400 -> 2,688,685) |
| Drop the precomputed `r*5` limbs to free four registers | byte-identical binary |

1.06x is below the 1.3x floor, so the line-touch model does not survive in the
form it was stated. But the intervention did not achieve its precondition
either: the keystream still materialises after the fusion, reloaded through a
register holding a stack address rather than through `sp`, which is why an
earlier count of `sp`-relative accesses missed it entirely.

Taken together the three say the keystream cannot be held in registers here.
Sixteen keystream words alongside the Poly1305 accumulator, key limbs and pad
do not fit in thirty-two registers, and every route to making them fit costs
more than it saves -- the unroll by raising pressure further, the `r*5` removal
by freeing registers the compiler was already rematerialising. That is three
measured failures rather than the live-value arithmetic that was retracted
earlier, and it is the first real evidence for the subgroup-cooperative form,
which reduces the per-lane state from sixteen words to four instead of trying
to schedule sixteen.

## 10. AES-GCM re-recorded, and what it does to section 8

### Re-recorded: what the instruction set is worth once the kernel is not in the way

The 2.67x in the table above was never an instruction-set number. It was
measured on a kernel whose memory traffic was about 57% non-algorithmic, and on
this machine that traffic had the worst possible shape.

The cause was **not** register spill, which is what the previous section
suspected. There are zero register-allocator spills: `p[8]`, `y[4]`, `h[4]` and
every clmul temporary live in registers. Two other things were responsible:

- **The helpers were not inlined.** `inline` is a hint and LLVM declined both at
  `-O3`. Because they take array pointers, `ctr[]`, `ks[]`, `y[]` and `h[]` were
  forced into stack slots -- 45 memory ops per block. `vx_start.S:96` gives each
  hart a stack 8 KB apart, so one `sp`-relative access in a warp is
  `NUM_THREADS` distinct cache lines 8 KB apart: a fully divergent gather on a
  single-banked L1, replayed at warp width.
- **The streaming accessors were byte-wise.** RISC-V's strict-alignment default
  stops LLVM widening `load_le32`/`store_le32`, costing 16 `lbu` + 16 `sb` per
  block where 4 + 4 suffice -- 24 more ops.

`__attribute__((always_inline))` and word-wise access fix both. Re-measured at
`c1w4t32`, `-n128 -b64`, rtlsim authoritative, on a build with no `PERF_ENABLE`:

| | sw_ttable | hw_s1 | ratio |
| --- | ---: | ---: | ---: |
| cycles (rtlsim) | 14,379,377 | 1,061,573 | **13.54x** |
| instrs | 1,229,052 | 106,356 | **11.56x** |
| cycles/block | 1755.30 | 129.59 | |
| bytes/cycle | 0.0091 | 0.1235 | |
| cycles (simx) | 12,224,492 | 888,983 | 13.75x |

**2.67x -> 13.54x from two kernel attributes, with the hardware unchanged.**

That the two ratios now nearly agree -- 13.54x cycles against 11.56x
instructions, where before it was 2.67x against 9.11x -- is the substantive
result. The kernel is no longer dominated by a term the instruction set cannot
touch.

Evidence the mechanism is what moved, rather than codegen luck (a fair caution:
a peer session measured 24% swings in both directions from `always_inline`
alone on a different kernel):

- Static `sp`-relative memory operations across the hardware path fall from
  **103 to 47**: 91 in `aes_gcm_hw_s1` plus 12 in the out-of-line `ghash_mul_hw`
  before, 47 after, with both helper symbols gone and `aes_gcm_hw_s1` now one
  566-instruction function. (An earlier version of this line claimed **zero**.
  That was a measurement error, not a result: the counting regex matched only
  decimal stack offsets and objdump emits them in hex, so every `lw a6, 0x4c(sp)`
  was invisible to it. The halving is real; the elimination was not.)
- Three rtlsim runs return identical cycles and instructions, per section 4.
- The residual 44 `lbu`/`sb` in `hw_s1` are the per-*message* IV load and tag
  store, amortised over 64 blocks, not per-block traffic.

`PERF_ENABLE` was checked rather than assumed: the counters do not perturb
timing here, and the numbers above are byte-identical to a PERF build.

**The memory wall is still there, and the rows above understate it.** These
numbers were measured with `VX_CFG_PLATFORM_MEMORY_NUM_BANKS = 2`
(`VX_config.toml:81`) behind `DCACHE_NUM_BANKS = 1` with L2 and L3 off. The
DE10-Pro image has **one** memory bank, not two: DDR4 B/C/D were removed
outright and only one channel was ever on the Vortex path, which is a property
of the bitstream rather than a configuration choice.

Those are two different machines and an earlier version of this section
conflated them, citing the board's single channel as the condition these rows
were taken under. They were not. The direction matters: the simulated
configuration is the **more** generous of the two, so a board measurement should
be expected to come out worse than what is recorded here, not better. Nothing
above is invalidated -- both variants ran on the same configuration, so their
ratio stands -- but the absolute cycles/block and bytes/cycle figures are for a
two-bank memory system.

The remaining `scrb` stall is that wall, and it now caps a kernel that is
otherwise clean.

### Retracted: the warp-scan conclusion, and the S2 decision that rested on it

The warp scan above was run on the kernel **before** the inlining and
word-access fixes, i.e. on a kernel whose memory traffic was 57%
non-algorithmic and 8 KB-strided. Re-run on the fixed kernel at the same points
(`c1w{4,8,16}t4`, `-b64`, one message per lane, rtlsim, no `PERF_ENABLE`), the
trend does not merely weaken. **It inverts.**

| warps | cycles/block, pre-fix | cycles/block, post-fix | hw IPC | speedup |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 338.97 | 255.75 | 0.407 | 11.13x |
| 8 | **254.97** (recorded as the peak) | 169.53 | 0.613 | 13.72x |
| 16 | 324.11 (recorded as a 27% regression) | **152.77** | **0.680** | **15.05x** |

Every post-fix row above was re-measured under the full check: build exit
status recorded, driver `.so` mtime confirmed to change, `CONFIGS` banner
checked for the intended warp count, and the application's counters agreed with
the runtime's `PERF:` line. The `w8` figure first published here was **254.75**
and was wrong -- corrupted by a concurrent build in the shared tree, 50% high on
cycles. The verified value is 169.53.

Post-fix cycles/block, IPC and speedup are all **monotonic** in warp count.
More warps keep helping; sixteen is the best point measured, not the worst. The
first version of this table showed w4 and w8 as flat and w16 as a sudden jump,
which was noted as odd at the time; the oddity was the corrupted row. The "peaks at eight warps and regresses at
sixteen" finding was an artifact of the stack traffic, which grew with warp
count because each `sp`-relative access was `NUM_THREADS` distinct lines 8 KB
apart. Remove it and the machine is no longer saturated at eight warps.

Note also that post-fix `w4` (255.75) lands on pre-fix `w8` (254.97): the kernel
fix bought at four warps exactly what doubling the warp count used to buy.

**Consequently the S2 recommendation above is withdrawn, not merely weakened.**
It read: a coarser-grained AES instruction shortens the dependency chain, the
dependency chain is not binding, therefore S2 hits the same wall. That inference
was drawn from a scan that was measuring stack-gather latency, so it establishes
nothing about dependency chains. S2 is undecided again, and deciding it needs a
pipeline breakdown on the fixed kernel.

Both endpoints of the new scan were re-run with build output visible and are
reproduced above; the application's own counters and the runtime's `PERF:` line
agree at each, as section 4 requires. A first attempt at the accompanying
pipeline breakdown produced all-zero counters and instruction counts a quarter
of the non-PERF run's. It was discarded rather than reported, and the cause is
now identified: two measurement scripts were running concurrently in the same
`build32` tree, each invoking `make` on the runtime and the application, so the
binaries were being rebuilt underneath the running measurement. `build32` is a
single shared tree -- shared with other sessions working in this repository as
well -- and build-and-measure runs in it have to be serial.

### Where that leaves S2

Re-run serially, the breakdown at the new best point is clean:

| | w4 | w16 |
| --- | ---: | ---: |
| IPC | 0.407 | **0.680** |
| scheduler idle | 60% | 32% |
| scoreboard stall | 48% | 100% |
| crypto backpressure | 0% | 0% |
| average load latency | 10.47 | 16.62 |
| instruction mix, `sym` | 39% | 39% |

Against pre-fix `w16`, average load latency falls 45.81 to 16.62 and idle falls
57% to 32%. With `ISSUE_WIDTH = 1` the ceiling on IPC is 1, so the machine has
gone from roughly 3% of peak issue to 68%.

**S2 remains undecided, but the reasons have changed sign.** The argument
against it -- that the dependency chain is not binding -- is retracted above and
does not come back. What the new numbers say instead:

- `aes32` is **39% of the instruction stream**, the largest single category. A
  round-granular instruction replacing sixteen `aes32` with one attacks exactly
  that.
- The crypto units still show **0% backpressure at every point measured**, so
  a wider or deeper unit has headroom in the scheduling domain it already owns.
- But the machine is now at 68% of peak issue rather than 3%, so removing
  instructions is closer to removing the actual limit than it was -- and equally,
  there is less slack left for a coarser instruction to claim.

What these counters cannot separate is operand stall caused by memory latency
from operand stall caused by arithmetic dependency, since `scrb` counts both.
Deciding S2 needs that separation -- a critical-path measurement, or a
prototype -- not another warp scan.


### Measured: the custom fused reduction does not pay

`ghred32l` / `ghred32h` are the one non-ratified instruction pair in this work:
`rd = rs1 ^ clmul_{lo,hi}(rs2, 0x87)`, fusing the multiply by the GF(2^128)
reduction constant with its accumulate. They occupy the two `INST_AUTH_*` slots
reserved for them and a previously undecoded opcode (`INST_EXT3`), so they
displace nothing. Both pass `isa_check` 16/16 on RTL and simx against a
reference written from the definition.

Predicted before measuring: the reduction is 9 clmul-class + 8 XOR = 17
instructions and becomes 9, saving 8 of roughly 415 per warp-block, so **1.93%
fewer instructions and 1.5-2.5% fewer cycles**.

Measured at `c1w4t32`, `-n128 -b64`, rtlsim:

| | clmul reduction | ghred32 | |
| --- | ---: | ---: | --- |
| instructions | 106,356 | 104,276 | **-1.96%** |
| cycles | 1,061,573 | 1,169,373 | **+10.2%** |
| IPC | 0.100 | 0.089 | |

At `w16t4` the same change costs +4.4% cycles for the same -1.96% instructions.

**The instruction prediction was almost exact and the cycle prediction had the
wrong sign.** Fewer instructions, more cycles, in both configurations.

Why, as far as the counters show: `crypto` backpressure stays at 0%, so the unit
is not the problem. Static `sp`-relative operations rise 47 to 50 and dynamic
loads rise ~2 per block per thread, with average load latency up 16.62 to 21.05
at `w16t4`. The fused form also serialises what the unfused form left parallel
-- `r1 = ghred32h(r1, p4); r1 = ghred32l(r1, p5)` is a two-deep chain on `r1`,
where `r1 ^= clmulh(p4,R) ^ clmul(p5,R)` issues two independent multiplies and
combines them. Trading instruction count for instruction-level parallelism is a
bad trade on a machine whose stall is already 99% operand-wait.

The instructions are kept -- they are verified, they cost nothing when unused,
and the negative result is the finding -- but the recorded kernel uses the
ratified `clmul` form. **The useful claim is that ratified Zbkc plus Zbkb
captures essentially all of the available win here, and a custom fused
instruction on top of them is worse than nothing.**

### When would ghred32 pay? Below this method's resolution

The question the negative result raises is not "why did it lose" but "under what
conditions would it win". Three kernel variants were swept across three warp
counts to find that crossing point:

- **clmul** -- the ratified reduction, 9 clmul-class + 8 XOR.
- **ghred** -- fused, 9 instructions. Saves 8, serialises two multiplies per limb.
- **ilp** -- fused but with a zero accumulator so the two multiplies per limb stay
  independent. **Identical instruction count to clmul**, so it isolates
  serialisation from everything else.

rtlsim, `t4`, `-b64`, one message per lane, cycles:

| warps | clmul | ghred | ilp |
| ---: | ---: | ---: | ---: |
| 4 | 261,892 | 261,742 (-0.06%) | 261,197 (-0.27%) |
| 8 | 347,191 | 362,456 (+4.4%) | 355,216 (+2.3%) |
| 16 | 625,745 | 653,067 (+4.4%) | **671,973 (+7.4%)** |

**The serialisation hypothesis is refuted.** If losing instruction-level
parallelism were the cause, `ilp` would recover `clmul`'s performance. It does
not -- at 16 warps it is the *slowest* of the three, while having the same
instruction count as the fastest.

`ilp` and `clmul` are indistinguishable on every static metric measured: 566
instructions, 47 static `sp`-relative operations, same reduction arithmetic.
They differ by **7.4% of cycles**.

That is the finding, with one important qualification on how far it goes.
**A pair of variants that differ in no measured static property differ by more
than the effect being investigated.** But `ilp` is not a true no-op against
`clmul`: it has the same instruction count and the same static stack traffic,
yet it executes *different* instructions -- `ghred32` where `clmul` was. So the
7.4% conflates two things this experiment did not separate: layout and
scheduling variance, and any genuine difference between the two instructions.

**7.4% is therefore an upper bound on the resolution floor, not a measurement of
it.** The floor may be well below that, in which case part of the 7.4% is real
signal about `ghred32` rather than noise.

**Measured, and that is what happened.** The floor probe is the four `r0..r3`
statements of the reduction, reversed: they touch disjoint accumulators and read
only `p[]`, so their order carries no meaning. Instruction counts came out
within 0.008%, which is what makes it a probe rather than a variant.

| point | reference | reordered | cycle delta |
| --- | ---: | ---: | ---: |
| `w16t4` rtlsim | 625,745 | 627,642 | **+0.303%** |
| `c1w4t32` rtlsim | 1,061,573 | 1,092,285 | **+2.89%** |
| `c1w4t32` simx | 888,983 | 885,313 | **-0.41%** |

The floor is **configuration-dependent**: about 0.3% at `t4` and about 2.9% at
`c1w4t32` on rtlsim, an order of magnitude apart. simx moves the opposite way at
the same point, which is the shape scheduling variance should have and a
systematic effect should not.

Against those floors the `ghred32` results are **real, not noise**:

| measurement | effect | floor | ratio |
| --- | ---: | ---: | ---: |
| ghred, `w8t4` | +4.4% | 0.30% | 14.5x |
| ghred, `w16t4` | +4.4% | 0.30% | 14.5x |
| ghred, `c1w4t32` | +10.2% | 2.89% | 3.5x |
| ilp, `w16t4` | +7.4% | 0.30% | 24x |
| ghred, `w4t4` | -0.06% | 0.30% | 0.2x -- the only one inside the floor |

So the previous section's conclusion was wrong in the direction of
under-claiming: these are genuine findings that were about to be written off.
The `ilp` row is the sharpest -- 24x the floor, with an instruction count 0.24%
from the reference -- so **there is a real cost to using `ghred32` that is not
instruction count, not serialisation, and not layout**. It shows up as loads
(231,596 against 227,564) and load latency (21.93 against 16.62). The mechanism
is not identified.

A note on the probe that failed first, because the failure is instructive.
Swapping the `i`/`j` loop order of the schoolbook accumulation is bit-identical
by associativity and commutativity of XOR, so it looked like the ideal probe. It
produced **1.24% more instructions**. A source transformation being
semantically equivalent does not make it instruction-identical, and a probe that
moves the instruction count cannot separate layout from content -- which was the
exact flaw in using `ilp` as a probe. The instruction count has to be checked
before the cycle number means anything.

Measuring the floor properly needs a perturbation that is bit-identical by
construction rather than merely semantically equivalent -- same instructions,
different order. Two exist in this kernel: the four AES state words `t0..t3` in
a round are computed from disjoint inputs, so reordering them changes nothing;
and the sixteen schoolbook partial products accumulate into `p[]` by XOR, so
reordering the accumulation is exact. That test is not yet run.

So the honest answer to "when does ghred32 pay" is: not here, and now with
enough resolution to say that rather than to shrug. The regressions are 3.5x to
24x the measured floor. The reason is still not instruction count -- On a machine 99-100% stalled on operands, with
IPC between 0.1 and 0.68, **instruction count is not the currency** -- the issue
slot is idle most of the time and removing work from it buys nothing. These
instructions would pay on a machine that is issue-bound. Establishing that on
this one would need layout-controlled repetition, not another variant.

Two consequences worth carrying forward:

- An instruction-count reduction is not evidence that a change is directionally
  good here. It was treated as such earlier in this document and that reasoning
  is unsound: -1.96% instructions produced +4.4% to +10.2% cycles.
- Any recorded result smaller than roughly 7% on this configuration should be
  treated as unresolved rather than as a small win, unless it is accompanied by
  a mechanism that was independently measured. This threshold is provisional and
  is an upper bound; the bit-identical reordering test above would replace it
  with a real one, and would likely lower it.

A distinction worth stating because it was being conflated here: byte-identical
results across repeated runs, across simx and rtlsim, across units-off and
units-on, and across separate rebuilds all establish **determinism** -- the same
input gives the same output. None of them establishes a **floor**, which is how
far apart two different inputs that should be equivalent actually land. This
document treated the first as evidence for the second.
