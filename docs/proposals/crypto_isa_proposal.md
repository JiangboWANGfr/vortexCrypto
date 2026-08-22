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
per message, and an AAD shared by every message -- empty in every recorded row,
though both kernels implement it (sections 12 and 16.1). Both halves of GCM are
then parallel across threads: counter-mode encryption is parallel by
construction, and the GHASH chain is serial only within a message. This matches
the shape a hardware GHASH would need, which keeps per-warp or per-lane state,
and it models a server handling many independent records rather than one long
stream.

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

Configuration `c2w4t16`: two cores, four warps, 16 threads, therefore
`SIMD_WIDTH=16` and `ISSUE_WIDTH=1`. Section 11 moved the record to this shape
because `c1w4t32` misses sign-off Fmax by 7% and cannot be built into a
bitstream. Message count is set to the lane count so every lane carries exactly
one message with no tail. The tree's checked-in shape is `c1w4t4`, so cores and
threads are a build override, and it has to be carried on every run compared
against these numbers -- on a `run-<driver>` target, because `CONFIGS` handed to
a test directory rebuilds only the kernel while the shape lives in the driver
(section 15.2):

```
CONFIGS="-DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16" OPTS="-n128 -b64 -i0" \
  make -C tests/crypto/aes_gcm run-rtlsim
```

128 messages of 64 blocks: 8192 blocks, 131072 bytes, empty AAD, no tail.

| | simx | rtlsim |
| --- | ---: | ---: |
| cycles | 9,195,286 | 9,380,132 |
| instrs | 2,474,230 | 2,474,230 |
| cycles/block | 1122.47 | 1145.04 |
| bytes/cycle | 0.0143 | 0.0140 |

Retired instruction counts agree exactly. The cycle gap is **1.97%**, against
16.3% at the `c1w4t32` shape this row used to be recorded at, so the modelling
discrepancy that gap represents is largely a property of that shape rather than
of this workload.

Steady-state evidence, rtlsim, `-n128`:

| blocks/msg | cycles | ratio |
| ---: | ---: | ---: |
| 16 | 2,585,284 | |
| 32 | 4,777,489 | 1.848 |
| 64 | 9,380,132 | **1.963** |

`-b64` is the first size inside the gate, as it was at the old shape.

The floor for this kernel -- the distance between two entry points that cannot
differ -- is measured in section 16.2 and runs **0.16% to 0.47%** across these
three sizes, instruction-identical at each. Nothing under about half a per cent
from this application is legible.

**What this replaced, and why three things moved at once.** This row previously
read 12,255,505 (simx) / 14,247,819 (rtlsim) with 1,229,052 instructions, at
`c1w4t32`, from a kernel with no AAD and no partial-block support. Since then the
recorded shape changed (section 11), the kernel gained AAD and partial blocks
(section 12), and it gained a floor probe that cost it 8 instructions and 0.445%
(section 16.2). Instruction counts do not compare across the two shapes at all:
a 16-lane warp needs twice the warp-instructions for the same lane-work.

Provenance:

- measured on the tree as committed with this section, parent `74f068551`
- crypto units off; `CONFIGS="-DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16"`
- clang 20.1.8 (vortexgpgpu/llvm 4c836512)
- every row: `make` exit status recorded, the shape asserted from the
  application's own banner rather than from the label passed in, and the
  application's counter line required to agree with the runtime's `PERF:` line
- three rtlsim runs at the recorded point returned identical cycle and
  instruction counts

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

Same configuration as section 5, the same override, and the same form of
invocation for the same reason:

```
CONFIGS="-DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16" OPTS="-n128 -b16 -i0" \
  make -C tests/crypto/chacha_poly run-rtlsim
```

128 messages of 16 blocks: 2048 blocks, 131072 bytes, empty AAD, no tail.

| | simx | rtlsim |
| --- | ---: | ---: |
| cycles | 1,435,309 | 1,469,082 |
| instrs | 351,144 | 351,144 |
| cycles/block (64 B) | 700.83 | 717.32 |
| bytes/cycle | 0.0913 | 0.0892 |

Retired instruction counts agree exactly; the cycle gap is 2.30%.

This kernel implements AAD and partial final blocks as of section 16.1, and the
row above is taken at `-a0 -t0` -- which is what keeps it comparable with the
aes_gcm row, not a statement that the feature is absent.

The floor for this application at this shape is the sweep in section 16.2:
**0.81% to 2.26%**, and the widest sample sits at `-b16`, the size this row is
recorded at. Nothing here under about 2.3% is legible.

### The steady-state gate no longer passes at the comparison point

Steady-state evidence, rtlsim, `-n128`:

| blocks/msg | bytes/msg | cycles | ratio |
| ---: | ---: | ---: | ---: |
| 4 | 256 | 583,551 | |
| 8 | 512 | 865,866 | 1.484 |
| 16 | 1024 | 1,469,082 | 1.697 |
| 32 | 2048 | 2,779,520 | 1.892 |

Every ratio is **outside** the `[1.96, 2.04]` gate of section 4, and the gap is
wider than when this row was recorded at `c1w4t32`, where `-b16` read 1.897.
Two changes push the same way: fusing the keystream into the XOR (section 9) cut
the per-block cost, and the AAD and partial-block support of section 16.1 added
per-message cost. Both raise the share of the total that does not scale with the
payload -- the counter-zero ChaCha20 block, the Poly1305 setup, the trailer and
the tag.

A two-point fit over `-b8` and `-b16`, the pair this section used before, puts
that fixed term at about **263k cycles, 17.9% of the total at `-b16`**, against
5.4% when it was first written. The `-b16`/`-b32` pair gives 159k, 10.8%. The
two disagree because the per-block cost is itself still falling with size here,
which is the same fact the failing gate reports rather than a second problem.

The gate is left failing rather than resolved, and the recorded row stays at
`-b16`, for the reason it always was: `-b32` passes and destroys the one thing
that makes this application comparable to aes_gcm at all, 1024 bytes per message
on both sides. What has changed is that the fixed share is now large enough to
belong in the reading of the cross-algorithm ratio below, not in a footnote: a
sixth to a fifth of this row is per-message work, and aes_gcm's per-message work
is a far smaller share of a far larger number.

Provenance:

- measured on the tree as committed with this section, parent `74f068551`,
  crypto units off,
  `CONFIGS="-DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16"`
- clang 20.1.8 (vortexgpgpu/llvm 4c836512)
- every row: `make` exit status recorded, the driver `.so` mtime compared across
  each build, the shape asserted from the application's own banner rather than
  from the label passed in, and the application's counter line required to agree
  with the runtime's `PERF:` line. All rows passed. A build that silently does
  not run leaves the mtime unchanged and is otherwise invisible: it yields a
  plausible number from a stale binary.
- three rtlsim runs at the recorded point returned identical cycle and
  instruction counts (1,469,082 / 351,144)
- the same row with both crypto units enabled returns identical cycles and
  instructions, so the units cost nothing to a kernel that does not use them

### What the two rows say

Both applications measured in the same tree at the same commit, at the same
shape, with both kernels implementing the same feature set:

| `-n128`, 131072 bytes | aes_gcm | chacha_poly | ratio |
| --- | ---: | ---: | ---: |
| cycles, simx | 9,195,286 | 1,435,309 | 6.41 |
| cycles, rtlsim | 9,380,132 | 1,469,082 | **6.39** |
| instrs | 2,474,230 | 351,144 | 7.05 |

The software ChaCha20-Poly1305 is six times faster and needs seven times fewer
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
rotation into a block that costs about 2597 instructions per lane at the margin
(the `-b8` to `-b16` instruction delta, per warp, per block; it was 2611 at the
old shape, because warp-instructions per block do not depend on the shape while
each lane holds one message). Thirty-seven per
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

`c2w4t16`, `-n128 -b16`, 131072 bytes, both units enabled:

```
CONFIGS="-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE \
  -DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_THREADS=16" \
  OPTS="-n128 -b16 -i{0,1}" make -C tests/crypto/chacha_poly run-rtlsim
```

| | sw | rori | ratio |
| --- | ---: | ---: | ---: |
| cycles, rtlsim | 1,469,082 | 1,671,111 | **0.879** |
| cycles, simx | 1,435,309 | 1,646,897 | 0.872 |
| instrs | 351,144 | 265,488 | 1.323 |
| cycles/block (64 B), rtlsim | 717.32 | 815.97 | |

**A third of the instructions removed, and the kernel is 13.8% slower.** That
reverses the sign of what this row used to record, and the reversal is not
subtle: 13.8% is six times the widest floor sample this application produces at
this shape (2.264%, section 16.2).

What moved was the kernel, not the shape. Both entry points were measured before
and after the AAD and partial-block work of section 16.1, at this configuration,
on rtlsim:

| | before | after | move | instrs before | after |
| --- | ---: | ---: | ---: | ---: | ---: |
| sw | 1,599,484 | 1,469,082 | **-8.153%** | 351,024 | 351,144 |
| rori | 1,575,430 | 1,671,111 | **+6.073%** | 263,584 | 265,488 |

One source change, applied to one templated body, moved its two instantiations
**in opposite directions by 8% and 6%**. Neither instruction count moved by more
than three quarters of a per cent (+0.034% and +0.722%). Whatever this is, it is not the rotate, and it is the same
unattributed layout effect that section 16.4 finds on both applications and
cannot account for.

So the honest reading of the recorded row is unchanged in substance from the
version that read +1.4%: **the instruction ratio, 1.323x, is exact and is what
this row establishes.** The cycle ratio has now been measured on both sides of
unity at the same configuration with the same two instruction streams, which is
a statement about this apparatus rather than about the B extension. It remains
an argument against building a fused xor-rotate, and a stronger one than before:
a third of the instructions is not reliably worth anything here.

The `sw` row here and section 6's are the same number, 1,469,082 / 351,144 on
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

Sampled across problem size, rtlsim, `-n128`, everything else fixed. This sweep
was taken at `c1w4t32` on the kernel as it stood before section 16.1; the same
sweep at the recorded shape on the current kernel is in section 16.2, and it
does not agree size for size:

| blocks/msg | sw | sw_perm | distance |
| ---: | ---: | ---: | ---: |
| 4 | 709,964 | 693,747 | **-2.284%** |
| 8 | 1,203,154 | 1,206,432 | +0.272% |
| 16 | 2,548,408 | 2,541,483 | -0.272% |
| 32 | 4,837,117 | 4,852,750 | +0.323% |
| 64 | 9,516,001 | 9,536,209 | +0.212% |

Instruction counts differ by exactly four at every size, so the probe is valid
at all of them. The signs alternate, which is the shape scheduling variance
should have rather than a systematic effect.

**Two kernels that cannot differ land up to 2.3% apart.** Four samples sit near
0.27% and one at 2.28%, so the floor is not a number even for one application
at one configuration; the same measurement on aes_gcm ranges from 0.13% to
2.89% over the same sweep.

The standard has to be a margin over the widest floor sample seen **anywhere**,
not over the nearest one, and that follows from this section's own conclusion:
if the spread is a property of the apparatus rather than of either application,
then aes_gcm's samples bound chacha_poly's results too. The widest seen across
both applications is 2.893%. Against it:

- The keystream fusion's **5.7% stands**, at 1.96x. Not comfortable.
- `rori`'s **1.4% does not**. It is well below and is withdrawn as a result.
  What survives is the instruction count, 1.332x, which is exact.

Quoting 2.5x here, against this application's own widest sample of 2.284%,
would be the cross-application transfer this section already withdrew, run in
the direction that flatters the result.

It is tempting to judge a result quoted at `-b16` against the `-b16` floor of
0.27% and conclude that `rori` survives after all. That does not hold: one
perturbation per size gives one draw from each size's distribution, not that
size's floor, and `-b4` shows this same perturbation reaching 2.28% somewhere in
this application. Nothing measured here says `-b16` is safe from that.

Settling it needs several *different* perturbations at one size. That was
attempted and it failed, which is itself the more useful finding.

Two further perturbations were built, both bit-identical by construction and
both verified to compute the correct AEAD: the diagonal round reversed
independently of the column round, and the five Poly1305 limb products computed
in reverse. Neither is a valid instrument.

| probe | instr delta, -b4 | instr delta, -b16 | verdict |
| --- | ---: | ---: | --- |
| column round reversed | -4 | -4 | fixed, **valid** |
| diagonal round reversed | +28 | +124 | scales, rejected |
| Poly1305 limbs reversed | +340 | +292 | 0.67% and 0.17%, rejected |

**Bit-identical by construction is necessary for a floor probe and nowhere near
sufficient: the compiler has to agree, and in three of the four perturbations
tried here it did not.** All three compute the same ciphertext and tag. The
column-round reversal is the only one whose instruction stream is comparable,
and its four-instruction difference is fixed across a sixteenfold change in
problem size, which is the signature of a probe measuring layout rather than
work.

The rejected pair is kept in the tree, labelled `(rejected)` in the
implementation table and annotated at the entry points, so that the rejection is
not rediscovered by someone who notices the same two perturbations are available
and assumes nobody tried them.

The question the Poly1305 probe was built to answer therefore stays open: the
tight samples may belong to this application, or only to the
disjoint-quarter-round structure, which is about the most reorder-tolerant thing
a compiler can be handed. Until a valid second perturbation exists, **no result
under about 3% should be quoted from this application**, and the instruction
counts -- which are exact -- carry whatever argument is being made.

This is a different property from determinism, and the distinction cost a
retraction elsewhere before it was drawn. Byte-identical repeat runs, agreement
across simx and rtlsim, and agreement across units-off and units-on builds all
say that the same input gives the same output. None of them says how far apart
two different inputs that should agree will land. Only this table does.

The first version of this section recorded the `-b16` row alone and called it
"about 0.3%", with a caveat that the floor was at least that. The caveat pointed
the wrong way. The risk was never that the floor is larger than the sample; it
is that the sample is unrepresentative, and a lower bound drawn from what may be
the minimum is worth nothing. The sweep above is what the caveat should have
been.

### The ratio to watch is the divergence, not the speedup

1.332x instructions against a cycle change too small to resolve. Those two
should track each other in a kernel whose cost is the instructions it issues,
and they do not. The withdrawal above does not weaken this: the claim being made
is that the cycles did not move, and "indistinguishable from zero" is that
claim, arrived at more honestly than a small measured number would have been.
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

> **State of the AES-GCM measurements.** Sections 8 and 10 have been corrected
> repeatedly as measurements replaced reasoning, and the corrections are left in
> place rather than edited away. That is right for the record but leaves a
> reader unable to tell what is currently live, so:
>
> **Established.** The hardware AES-GCM is **13.54x fewer cycles and 11.56x
> fewer instructions** than the software baseline at `c1w4t32` -- both halves
> verified under the build-log-and-mtime check, and the software figure
> independently reproduced from another session's build. The crypto units never
> backpressure at any point measured. What capped the earlier 2.67x was the
> kernel's memory traffic, not the instruction set. Once that traffic is gone,
> more warps help monotonically. The custom `ghred32` pair costs cycles rather
> than saving them, by a margin above the widest floor sample observed.
>
> **Retracted.** That the gap between the instruction and cycle ratios was
> dependency-chain latency. That the warp scan peaked at eight warps and
> regressed at sixteen. That S2 can be ruled out. That ~60% of the memory
> traffic was register spill. That `sp`-relative operations fell to zero after
> the inlining fix. That losing instruction-level parallelism explains the
> `ghred32` regression. That the apparatus has a characterisable resolution
> floor.
>
> **Open.** Why using `ghred32` raises load count and load latency when
> instruction count and static stack traffic are unchanged. Whether S2 is worth
> building. What the floor actually is, given it varies by a factor of 23 across
> problem size at a single application and configuration.
>
> **Weaker than recorded below.** The `ghred32` regressions at `t4` (+4.4%) rest
> on a *single* floor sample at that shape (0.303%). By the same argument that
> retired other single-sample claims here, one draw is not a floor: the same
> probe reaches 2.893% elsewhere in this application. Against the observed range
> the margin is between 1.5x and 34x, not the 14.5x recorded. Only the +10.2% at
> `c1w4t32` clears the widest sample taken at its own point.
>
> Each retraction was replaced by a measurement rather than by a better
> argument, and several were prompted by build32-73 checking work I had
> published.

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

simx moves the opposite way at the same point, which is the shape scheduling
variance should have and a systematic effect should not.

**But a single probe point is a sample, not a floor.** Repeating the probe
across problem size at one configuration (`c1w4t32`, rtlsim, `-n128`):

| blocks/msg | floor | instruction delta |
| ---: | ---: | ---: |
| 4 | -0.335% | -0.090% |
| 8 | **-1.301%** | -0.052% |
| 16 | **-0.126%** | -0.028% |
| 32 | -0.751% | -0.015% |
| 64 | **+2.893%** | -0.008% |

The floor is not a number even at a fixed application and fixed configuration.
It ranges over a factor of 23 across problem size, from 0.126% to 2.893%, and
changes sign. The 2.893% quoted above is the most extreme of five samples, not a
representative value.

It also refutes a plausible explanation. If the floor were driven by pressure on
a queueing-sensitive memory system -- `aes_gcm` streams eight times the memory
instructions per byte that `chacha_poly` does, which would explain why its probe
is ten times wider at the same configuration -- then reducing the block count
should narrow it monotonically. It does not.

What follows for anyone using these numbers: **a floor has to be measured at the
application, the configuration AND the problem size where the result is
quoted**, and from more than one sample. Neither axis transfers on its own, and
one probe establishes only that the floor is at least that wide.

Against those floors the `ghred32` results are **real, not noise**:

| measurement | effect | floor | ratio |
| --- | ---: | ---: | ---: |
| ghred, `w8t4` | +4.4% | 0.30% | 14.5x |
| ghred, `w16t4` | +4.4% | 0.30% | 14.5x |
| ghred, `c1w4t32` | +10.2% | 2.89% (worst of 5) | 3.5x |
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


### Two more probes, both rejected by their own validity condition

Getting several independent draws at one point needs several perturbations that
are bit-identical by construction. Two more were built for this kernel, with the
validity condition -- instruction counts must match -- stated before running:

- **B**, the four AES round words `t0..t3` reversed. Disjoint outputs, disjoint
  inputs, so the order between the groups carries no meaning.
- **C**, the ciphertext/GHASH loop run `i=3..0`. Each iteration touches a
  distinct `ct_w[i]`, `y[i]`, `pt_w[i]` and `ks[i]`.

Both are bit-identical in their arithmetic. **Both failed the check**: B emits
0.237% more instructions and C emits 2.92% more. Their cycle deltas -- +6.5% and
**+66.4%** at `c1w4t32` -- are therefore readings of a different program, not of
the apparatus. Reported as rejected instruments rather than as floor samples.

Had the condition not been stated in advance, C's +66.4% would have been
recorded as a floor sample and would have "established" that nothing at any
scale is measurable here.

The finding is that **almost nothing in this kernel is instruction-identical
under this compiler.** Reordering four independent statements changes register
allocation enough to add instructions; reversing a loop changes addressing.
Exactly one perturbation out of three survived, so the plan of taking several
draws at one point is not currently executable for `aes_gcm`, and the `t4`
result stays on one sample.

**Confirmed independently on the other application.** build32-73 built two more
perturbations for `chacha_poly`, both bit-identical by construction and both
verified to compute the correct AEAD before any cycle was read: the diagonal
round reversed (disjoint quarter-rounds), and the five Poly1305 limb products
reversed (disjoint accumulators). The diagonal probe perturbs the instruction
count by +28 at `-b4` and +124 at `-b16` -- it *scales with the workload*, which
is the disqualifying signature -- and the Poly1305 probe by 0.67%. Both
rejected. `chacha_poly` is one valid perturbation out of four, against
`aes_gcm`'s one out of three.

So the generalisation is not about either kernel: **bit-identical by
construction is necessary and nowhere near sufficient.** The property has to be
one the compiler preserves into the instruction stream, and provable arithmetic
independence does not buy that. Two applications, two authors, seven
perturbations, two survivors.

The consequence for everything quoted in this section is that **no result here
rests on more than a single floor sample**, and that is a property of the
toolchain rather than of a kernel or of an author's care. A result needs a
margin over the widest sample seen anywhere, not over the sample nearest to it.

One question this leaves open rather than settles. The two surviving probes are
both reorderings of disjoint state over a fixed register set -- structurally the
most reorder-tolerant shape available -- so the tight samples they produce may
be a property of that structure rather than of either application. The probe
that would have discriminated was the Poly1305 one, and it was rejected. Nothing
measured says the floor is tight anywhere else.

One refinement to the condition itself. A flat percentage threshold is the wrong
form: the reduction reversal perturbs the instruction count by a fixed ~8
instructions regardless of problem size, so the same valid probe reads 0.0075%
at `-b64` and 0.090% at `-b4`. The criterion should be that the absolute
perturbation is small and does not scale with the workload, not that a ratio
sits under a constant.

## 11. The recorded configuration moves to c2w4t16, and the first hardware evidence

Every number above was taken at `c1w4t32`. That configuration should not be the
one this work is quoted at, for a reason that only appears on the board.

### c1w4t32 does not close timing; c2w4t16 does

From the DE10-Pro builds in the FPGA project's `results/`, Slow 900mV 100C,
`vortex_iopll_outclk0` (the Vortex fabric clock), 200 MHz requested:

| | c1w4t32 | c2w4t16 |
| --- | ---: | ---: |
| setup slack | **-0.348 ns** | **+0.199 ns** |
| total negative slack | **-60.679** | **0.000** |
| Fmax | 186.99 MHz | **208.29 MHz** |
| logic | 219,351 ALMs (24%) | **208,513 ALMs (22%)** |

`c1w4t32`'s bitstream boots the fabric at 200 MHz while STA signs off only
186.99 -- roughly 7% past its own ceiling, with 60 ns of accumulated violation.
`c2w4t16` has no violating path at all. **A number measured on the first
describes a design that cannot be built correctly; a number measured on the
second describes one that can.**

### Where the area goes, and a prediction of mine that was wrong

Per-entity ALMs from the fitter, with `c2w4t16` shown per core and doubled:

| entity | c1w4t32 | c2w4t16 per core | x2 cores | change |
| --- | ---: | ---: | ---: | ---: |
| `alu_unit` | 37,831 | 14,473 | 28,946 | **-23%** |
| `execute` | 71,124 | 32,018 | 64,035 | -10% |
| `auth_ghash` | 13,442 | 7,615 | 15,229 | **+13%** |
| `sym_aes` | 2,561 | 1,284 | 2,569 | flat |

I predicted splitting the crypto units across two cores would reduce their area.
**It does the opposite** -- GHASH costs 476 ALM/lane at 16 lanes against 420 at
32, because the per-unit fixed cost (wrapper, `pe_switch`, elastic buffers)
amortises over half as many lanes. The total win is entirely in the ALU and the
other lane-scaled logic, where a 32-lane block is much more expensive than two
16-lane blocks to route.

**GHASH is still the largest single crypto cost by far: 15,229 ALMs, twice the
LSU, four times the SFU, for a unit that shows 0% backpressure at every point
measured.** That is the number this work has to answer for, and until now it
existed only inside a gitignored fitter report.

### The recorded numbers at c2w4t16

rtlsim, `-n128 -b64`, both variants, `num_cores=2` confirmed in the banner:

| | sw_ttable | hw_s1 | ratio |
| --- | ---: | ---: | ---: |
| cycles | 7,744,779 | 655,712 | **11.81x** |
| cycles/block | 945.41 | 80.04 | |
| bytes/cycle | 0.0169 | **0.1999** | |

Superseded once partial-block support landed, which changed both kernels:
**7,841,847 against 653,277, a ratio of 12.00x.** The software baseline costs
1.25% more cycles for 1.20% more instructions (the tail branch and the strided
addressing) and the hardware kernel 0.37% fewer for 0.39% fewer (its length
block now reuses an already-computed byte count). Cycle and instruction changes
move together in sign and magnitude on both sides, so this is the price of the
feature rather than layout noise -- which a cycle change alone could not have
distinguished, given floor samples at the neighbouring configuration range up to
2.89%.

Against `c1w4t32`, the hardware kernel gains 62% throughput (0.1235 to 0.1999
bytes/cycle) and the software baseline gains 86%, **so the ratio falls from
13.54x to 11.81x**. The shape change helps the memory-bound software variant
more than the hardware one, which is the honest direction and the one that costs
this work rather than flattering it.

Instruction counts are not comparable across the two shapes -- a 16-lane warp
needs twice the warp-instructions for the same lane-work -- so cycles and
bytes/cycle are the quantities that transfer, which is why the absolute
throughput is recorded alongside the ratio from here on.

**11.81x is therefore the number to quote.** It is smaller than 13.54x and it
corresponds to a bitstream that meets timing.


## 12. AAD, partial blocks, and a measurement that stopped resolving

`aes_gcm` now implements the parts of SP 800-38D it previously did not: AAD
absorbed by GHASH before any ciphertext and never encrypted, partial final
blocks zero-padded before absorption, and a length block carrying both
`[len(A)]64` and `[len(C)]64`. Both kernels and the host reference. Level 1 gains
**GCM test case 4** -- 20 bytes of AAD over 60 bytes of plaintext, so it
exercises AAD and a partial tail together -- with its published tag; corrupting
one bit of that tag fails the check, so it is genuinely validated rather than
merely present. Level 2 passes 20/20 across AAD lengths 0/1/16/20/33 crossed
with tails 0/5 and both implementations.

**The performance numbers stopped being comparable, and this is the honest
record of that rather than a set of new numbers.**

At `c2w4t16`, `-n128 -b64`, no AAD, against the figures recorded in section 11:

| | before | after | instructions |
| --- | ---: | ---: | ---: |
| sw_ttable | 7,841,847 | 9,338,582 (**+19.1%**) | **-0.56%** |
| hw_s1 | 653,277 | 597,233 (**-8.6%**) | **+0.11%** |

Cycles and instructions move in **opposite** directions on both kernels, and the
hardware kernel got 8.6% faster from a change that only adds work. That is not
what the price of a feature looks like.

A floor probe at this configuration -- the four reduction statements reversed,
instruction count **exactly unchanged** at 212,162 -- gives:

- **hardware kernel: 4.68%.** Wider than every sample taken at `c1w4t32`, where
  five perturbations across problem size ranged 0.126% to 2.893%. So `c2w4t16`
  is the noisier shape, and the hardware kernel's -8.6% is **1.8x a single floor
  sample**: not attributable.
- **software kernel: 0.00%, byte-identical.** The probe touches only
  `ghash_mul_hw`, which that kernel never calls, so its +19.1% is at least not
  cross-contamination from the hardware-side edits.

What that leaves: the software baseline's +19.1% is real enough not to be
explained by an unrelated code change, and its mechanism is **unidentified** --
instructions fell while cycles rose by a fifth. No probe exists inside that
kernel's own hot path, so layout cannot be ruled out either. Recorded as open
rather than attributed.

**Consequence for the recorded ratio.** 9,338,582 / 597,233 is 15.64x, against
12.00x before. Both numbers are arithmetic on measurements that reproduce; what
does not survive is any claim that the difference between them means something.
Until the software kernel has a floor probe of its own, the ratio at this
configuration should be treated as bounded below by roughly 12x rather than
quoted at a point. **Closed in section 16.2**: that kernel now has a probe of its
own, its floor is 0.16% to 0.47%, and section 16.5 says what the ratio may be
quoted as.

## 13. Should S2 be built? Measured answer: no for GHASH, and not in the S2 shape for AES

S2 in this taxonomy means coarser instructions holding hidden context in the
unit. The two candidates are a round-granular AES and a blocking GHASH that
keeps the subkey H and the accumulator Y. Both were assessed against
measurement rather than argued from instruction counts.

### 13.1 GHASH: negative, and independently replicated

`ghred32`, the fused GF(2^128) reduction, removed **1.96% of instructions** and
cycles rose **4.4-10.2%**. That result stood alone and unexplained.

It is no longer alone. `myvortex/docs/results/ghash_design_space.csv` sweeps a
*built* S2 GHASH's multiplier radix on cycle-accurate rtlsim at 1 warp/core,
i.e. with no warp-level latency hiding at all:

| radix | MUL cycles | total cycles |
| ---: | ---: | ---: |
| 1 | 130 | 60,157 |
| 128 | 3 | 60,137 |

**A 43x faster multiply moves total cycles by 0.03%.** That repository's own
conclusion, `docs/results/summary.md:5`: *"the MUL is off the critical path
(dwarfed by per-block memory), so the cheap bit-serial multiplier suffices."*
Line 7 reports the identical signature for the ChaCha20 quarter round -- an 80x
faster QR moves per-block cycles ~0.6%.

Two independent designs, two independent measurements, one conclusion: **the
finite-field arithmetic is not where the cycles are.** S2 GHASH accelerates the
part that was already free.

Three further defects, each independently disqualifying:

- **Storage.** Held state at c2w4t16 is 23,172 flops/core, 46,344 across two
  cores. The c2w4t16 GPR file is 65,536 bits/core, so the shadow state is **25%
  of a whole register file re-implemented in flops** -- and it cannot become
  RAM, because the design resets every bit and reads 4,096 bits combinationally
  in one cycle to load the multiplier. S2 does not remove storage; it duplicates
  it in the worst available technology, to hold what the current design keeps in
  the register file for free.
- **Issue rate.** `execute_if.ready = (state_r == ST_IDLE)` de-asserts during
  `ST_RESP` as well, so even SETH/XOR/RD accept **one op every two cycles**. The
  stateless `VX_auth_ghash` here accepts one per cycle through its elastic
  buffer. S2 halves the issue rate of exactly the cheap ops that the radix sweep
  identifies as the ones that matter.
- **H is write-only, which is the worst of both properties.** No op reads H. The
  legitimate owner therefore cannot checkpoint a GHASH-using warp, since
  H = E_K(0^128) exists nowhere else. An attacker is not correspondingly
  blocked: state is aliased by (warp, lane) with no owner tag and no clear at a
  context boundary, so a tenant inheriting a slot can zero Y using the design's
  own documented idiom, XOR in a chosen block B, MUL, and RD to obtain B·H, then
  divide in GF(2^128). Write-only H prevents saving and does not prevent
  extraction. Keeping Y and H in the GPRs, as here, has neither problem and
  needs no new mechanism.

### 13.2 A claim from section 9 is withdrawn

It was suggested that a blocking S2 GHASH would finally make the EX_SYM/EX_AUTH
split earn its keep by producing real head-of-line blocking. **That is wrong.**
`VX_auth_unit.sv:36` sets `PE_COUNT = 1` with `pe_select` hardwired, so the
`VX_pe_switch` behind EX_AUTH is degenerate -- GHASH is the only PE there and
there is nothing co-resident to block.

The split's actual value runs the other way and is prophylactic: because AES and
GHASH sit in different scheduling domains, a blocking GHASH could not stall AES.
That is a property worth having, but it is not evidence for building one.

### 13.3 AES: the lever is round-key loads, and it does not need S2

An instruction-identical probe pins `k = rk` for every round, so the `aes32`
count is bit-identical and only 40 of the 44 per-block LMEM key loads disappear.
The result is cryptographically wrong by construction; it measures load cost.

| | cycles | instructions |
| --- | ---: | ---: |
| current | 597,233 | 212,162 |
| key loads removed | 512,782 | 176,298 |
| | **-14.14%** | -16.90% |

At 3.0x the measured 4.68% floor for this configuration, the effect is real.
**But read why it is real:** the probe saves 2.35 cycles per instruction removed
against an average CPI of 2.81, so the round-key loads are *cheaper* than the
average instruction. They hit the 16-bank LMEM, not the single-channel DRAM. The
14% is a linear instruction-count return, not a recovered stall.

That splits the two halves of an S2 AES cleanly:

- **160 `aes32` -> 10 round instructions.** ALU-instruction removal. The one
  time that was measured here (`ghred32`) it went negative, and the myvortex
  sweeps show the same not-compute-bound signature twice. Unlikely to convert.
- **44 key loads -> 0.** Measured at -14.1%. Converts.

**The half that converts does not need round granularity**, and the cost of S2
falls almost entirely on the half that does not. Key storage is the cheap part:
`main.cpp:305-308` expands one key for every message and `kernel.cpp:437,463,488`
pass `lm->rk` with no per-thread index, so the schedule is **uniform across the
grid** and a per-core key register is both the cheapest and the *correct*
granularity -- 1,408 flops/core, 0.75% of the design's registers, versus 22,528
for per-lane. The blocker is operand width: a round needs 4 state words plus 4
key words in and 4 words out, against `NUM_SRC_OPDS = 3` and a single `rd`. Uop
splitting does not rescue the read side, because every output word depends on
all four input state words; supplying keys from GPRs instead forces the *state*
into the unit, 8,192 flops/core of per-lane per-warp context -- precisely the
property that makes S1 cheap and safe.

Caveat for any generality claim: uniform-key is a property of this benchmark,
not of AES-GCM. A per-connection-key workload would need per-lane keys and the
cost table inverts.

### 13.4 What to build instead: fuse the round key into `aes32`

Each round's first instruction is `t0 = k[0]`, a load, followed by three
`aes32`. Fusing the key as an implicit source of that first operation removes
the load without touching operand width:

```
aes32esmi_k rd, rs1, {keyidx[5:0], bs[1:0]}
    rd = keyreg[keyidx] ^ MixColumns(SubBytes(rs1 >> 8*bs))
```

Still 2R1W, still lane-local, still single-cycle, still no memory port -- every
S1 property preserved. The only new state is a per-core 1,408-bit key register
written once per CTA and amortised over 8,192 blocks, and unlike myvortex's H it
is **readable**, so context remains saveable. It collects the measured 14%
without the uop sequencer, the operand-path widening, or the per-lane state.

## 14. The floor is a mechanism, not noise

Every floor probe in this document was read as measurement scatter -- an error
bar to discount observed gains against. A peer session measuring
`chacha_poly` supplied the observation that reframes it: that kernel requests
`lmem_size = 0`, and its floor probe at c2w4t16 reads **-0.051%** on rtlsim
against the **4.68%** measured here at the same configuration.

The difference is not the applications' complexity. It is that this kernel gathers
into local memory -- four 1 KB T-tables, the key schedule, the GHASH table -- and
`LMEM_NUM_BANKS = SIMD_WIDTH`. Reversing four reduction statements leaves the
instruction stream bit-identical but changes which addresses are in flight in the
same cycle, hence the bank-conflict pattern, hence cycles. A kernel with no local
memory has nothing for a *bank* conflict to form in -- which, per 14.1, is not
the same as having nothing to perturb.

**So the floor here has a sign.** Part of the 4.68% is an access order not yet
chosen, not irreducible uncertainty. Using it as a symmetric error bar
understates what a deliberate layout could buy and overstates how much of an
observed gain must be discounted. The bit-identical-by-construction requirement
was necessary and remains so; the interpretation of what survives it was wrong.

This also resolves a loose end in section 13.3. The round-key probe removes 40
LMEM loads per block and saves 2.35 cycles per instruction removed, *below* the
2.81 average CPI -- which would be strange if LMEM traffic were conflict-prone.
It is not strange, because the round keys are read **uniformly**: every lane
loads the same address (`kernel.cpp:437,463,488` pass `lm->rk` with no
per-thread index). Uniform reads broadcast and do not conflict. The T-table
gathers in the software kernel are data-dependent and do conflict, which is why
that kernel is the floor-sensitive one. The two facts fit: the 14.1% really is a
linear instruction-count return, and the floor really is a gather effect.

**Open, with a decisive test.** The unexplained +19.1% on the software kernel in
section 12 is a candidate for the same mechanism: AAD support did not change
`AES_GCM_LMEM_BYTES`, but it added live values across the message loop, which can
shift register allocation and therefore spill addresses and therefore the bank
pattern. If that is the cause, the regression should be *smaller* at c1w4t32,
where `LMEM_NUM_BANKS = SIMD_WIDTH` gives 32 banks against 16. Not yet run.

### 14.1 Correction: this explains the gap, not the spread

The section above shaded into claiming that local memory is *the* source of
layout sensitivity. It is not, and the peer session that supplied the mechanism
also supplied the counterexample: their floor spread across problem sizes runs
**0.05% to 2.28%**, and they have no local memory at any of those points. A
2.28% instruction-identical swing with zero LMEM traffic has to come from
somewhere else -- D-cache set aliasing, DRAM row behaviour, or warp interleave.

So the correct scope is narrower. LMEM bank conflicts explain **why 4.68% here
is larger than 0.051% there at the same configuration and problem size**. They
do not explain layout sensitivity in general, and they are not the whole of the
4.68% either. Treating them as a complete account would repeat an error this
document has already made twice: taking a mechanism that explains a difference
and promoting it into an explanation of the quantity.

**And the reframing is recorded without taking the relief.** If part of the
floor is directional, the arithmetically permitted move is to narrow the error
bar. That move happens to flatter every result here, which is reason enough to
decline it absent a measurement that isolates the directional part. The
conservative two-sided bound stays. What changes is only the forward-looking
claim that a deliberately chosen access order is worth measuring -- a statement
about opportunity, not a relaxation of any bound already published.

## 15. The unexplained regression, resolved on a pre-registered prediction

Section 12 recorded a post-AAD movement it could not attribute: the software
kernel +19-20% cycles with instructions *falling*, the hardware kernel 9% faster
from a change that only adds work. Section 14 proposed a mechanism -- AAD added
live values across the message loop, shifting register allocation, spill slot
addresses, and therefore the LMEM bank-conflict pattern -- and stated the test
**before running it**: if that is the cause, the movement must be smaller at
c1w4t32, where `LMEM_NUM_BANKS = SIMD_WIDTH` gives 32 banks against 16.

Both shapes measured in one pass, each row's `num_cores`/`num_threads` asserted
from the application's own banner. Pre-AAD reference is the earlier run in which
both shapes were likewise shape-verified.

| shape | LMEM banks | sw pre | sw post | move | hw pre | hw post | move |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| c1w4t32 | 32 | 14,379,377 | 15,328,651 | **+6.60%** | 1,061,573 | 1,032,241 | **-2.76%** |
| c2w4t16 | 16 | 7,744,779 | 9,338,582 | **+20.58%** | 655,712 | 597,233 | **-8.92%** |

**Confirmed, and more sharply than the prediction required** -- but see
section 16.4, which measures the same shape pair on a kernel with no local
memory and on a second perturbation of this one, and finds the scaling does not
generalise. Halving the LMEM
banks multiplies the movement by **3.1x on the software kernel and 3.2x on the
hardware kernel** -- two kernels whose movements have *opposite signs*, scaling
by the same factor. Random layout scatter does not do that. A mechanism that
acts through bank conflicts does.

**What this does not establish.** The two shapes differ in cores, threads per
warp, LMEM banks *and* D-cache banks simultaneously, so "32 versus 16 LMEM
banks" is not isolated -- only correlated with the change. And the mechanism is
not the whole account even on its own terms: the residual +6.60% at 32 banks is
still 2.3x that shape's widest floor sample, so something survives at the bank
count where the effect should have largely vanished. One problem size.

### 15.1 The withdrawn ratio, recovered

Section 12 withdrew the +86% shape gain because one endpoint had moved 19% for
unexplained reasons. Both endpoints are now measured post-AAD in a single
shape-verified pass:

| | c1w4t32 | c2w4t16 | gain |
| --- | ---: | ---: | ---: |
| sw_ttable | 15,328,651 | 9,338,582 | **+64.1%** |
| hw_s1 | 1,032,241 | 597,233 | **+72.8%** |
| ratio | 14.85x | 15.64x | |

A peer session measuring ChaCha20-Poly1305 -- a kernel that requests no local
memory at all, so with a disjoint bottleneck story -- records **+59.3%** for the
same shape change on rtlsim, at roughly 1000x its floor at that shape. Three
figures in one band, across two AEADs, two instruction-set extensions, and two
different reasons for being memory-bound.

**So the largest single lever measured in this project is the memory
configuration, not the instruction set.** Doubling the D-cache banks at constant
lane count, with no ISA change of any kind, is worth more than every crypto
instruction added here.

### 15.2 A measurement invalidated, and what survived it

The first attempt at the table above returned all four rows byte-identical with
`num_cores=2` on every row. Cause: `CONFIGS` passed to a *test* directory builds
the kernel only. Shape lives in `sw/runtime/librtlsim.so`, so every row ran on
whichever shape was built last -- in that instance, another session's. `make
run-rtlsim` is the form that rebuilds the driver. No error was raised and all
four rows passed.

The scoping rule this forces, worth stating because it decides what else has to
be re-checked: **a probe that rebuilds only the kernel between its two rows
remains a valid relative measurement** -- both rows ran on the same driver -- but
its *shape label* is unverified. Deltas keep; shape attributions do not. The
floor probe (-4.68%) and the round-key probe (-14.14%) were both of this form.
Their labels are now confirmed independently: 597,233 reproduces exactly at a
driver-verified c2w4t16.

## 16. Both baselines re-recorded at one configuration, and the software floor measured

Four things were stale at once, and they interact, so they are fixed in one pass
rather than four.

1. Sections 5, 6 and 9 recorded their rows at `c1w4t32`. Section 11 moved the
   recorded configuration to `c2w4t16`, the shape whose bitstream closes timing,
   and did not move them.
2. Sections 5 and 8 predate the AAD and partial-block work of section 12, which
   moved the software kernel by a fifth.
3. `chacha_poly` did not implement AAD or partial blocks at all. Section 6's
   claim that the two baselines "differ in their algorithm and in nothing else"
   had stopped being true, and the cross-algorithm row was comparing an AEAD
   that authenticates a header against one that could not.
4. Section 12 left the software kernel with no floor probe of its own, so its
   +19.1% could not be told from layout noise. The probe that existed reverses
   statements inside `ghash_mul_hw`, which that kernel never calls: it read
   0.00%, byte-identical, and bounded nothing.

### 16.1 ChaCha20-Poly1305 gains AAD and partial blocks

`tests/crypto/chacha_poly` now implements the parts of RFC 8439 section 2.8 it
previously did not: AAD absorbed before any ciphertext and never encrypted, a
partial final ChaCha20 block whose keystream is consumed only `tail` bytes deep,
and a trailer carrying `le64(len(AAD)) || le64(len(C))` rather than
`le64(0) || le64(len(C))`. The host reference already supported all three and
level 1 already checked the RFC's section 2.8.2 vector against its published
tag -- 12 bytes of AAD over a 114-byte payload, so both pads and both lengths.
What was missing was on the device, which is the half the measurements run on.

One thing differs from GCM, and it removes a case rather than adding one:
RFC 8439's `pad16` zero-fills the AAD and the ciphertext to a whole 16-byte
boundary before Poly1305 sees either, so **every Poly1305 block in this AEAD is
a full block**. Poly1305's partial-block rule -- the 0x01 byte moving to the
fragment's end -- is unreachable here. GHASH has no padding rule of its own,
which is why aes_gcm's kernel pads into a buffer and this one does not need to.

Level 2 now passes **30/30** on the software entry points: AAD lengths
0/1/16/20/33 crossed with tails 0/5/37 -- a fragment shorter than one
authentication block and one spanning three of them -- on both `sw` and the
floor probe. With the units enabled it passes 8/8 across `rori` and aes_gcm's
hardware kernel. Both apps also gained CI cases for the AAD and tail paths,
which had none: every case in `ci/testcases/crypto.yaml` ran at `-a0 -t0`.

### 16.2 A floor probe for the software AES kernel

`aes_gcm_sw_ttable_perm` computes the four column words of each AES round in
reverse order. They are independent -- each reads the whole state and the round
key and writes only its own temporary -- so it is bit-identical by construction,
and unlike the existing probe it perturbs the hot path of the kernel being
measured rather than a function that kernel never calls.

It passes section 9's validity condition more cleanly than any probe here so
far: **the instruction counts are exactly equal at every problem size**, not
merely fixed. That is the strongest form the condition can take.

Sampled across problem size, rtlsim, `c2w4t16`, `-n128`:

| blocks/msg | sw_ttable | sw_perm | distance | instr delta |
| ---: | ---: | ---: | ---: | ---: |
| 16 | 2,585,284 | 2,597,353 | **+0.467%** | 0 |
| 32 | 4,777,489 | 4,785,114 | +0.160% | 0 |
| 64 | 9,380,132 | 9,405,033 | +0.265% | 0 |

**The software AES kernel's floor is 0.16% to 0.47% at the recorded shape.**
simx disagrees: it reads +0.113%, -0.046% and **-0.928%**, the last wider than
anything rtlsim shows and pointing the other way. Section 4 makes rtlsim
authoritative, and this is a case where that matters -- taking simx's `-b64`
sample would have set the floor twice as wide, and with the opposite sign.

The chacha_poly probe was re-swept at the same shape after its kernel changed:

| blocks/msg | sw | sw_perm | distance | instr delta |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 583,551 | 588,279 | +0.810% | +24 |
| 8 | 865,866 | 874,898 | +1.043% | +24 |
| 16 | 1,469,082 | 1,502,336 | **+2.264%** | +24 |
| 32 | 2,779,520 | 2,807,301 | +0.999% | +24 |

The delta is fixed at +24 across an eightfold change in problem size, so the
probe is still valid; it was +4 before the AAD work, which is what a probe of a
larger body looks like.

**All seven rtlsim samples across the two applications are positive**: at this
shape the reversed order is uniformly the slower one. The `c1w4t32` sweep in
section 9 alternated in sign and was read there as the shape scheduling variance
should have. This one does not alternate, which is section 14's claim that the
floor has a sign showing up as a measurement rather than as an inference -- and
it means treating the floor as a symmetric error bar is, at this shape,
measurably wrong in a known direction. **The `-b16` sample moved from -0.051% to +2.264%** --
same probe, same shape, same size, different kernel -- and `-b16` is the size
this application's row is recorded at. A floor belongs to a kernel at a shape,
not to a machine, and it has to be re-measured when the kernel changes.

### 16.3 The joint table

Everything at `c2w4t16`, `-n128`, 131072 bytes, rtlsim, one tree, one commit.
The two software rows are sections 5 and 6; the other two are what they are
compared against.

| | aes_gcm sw | aes_gcm hw_s1 | chacha_poly sw | chacha_poly rori |
| --- | ---: | ---: | ---: | ---: |
| cycles | 9,380,132 | 594,958 | 1,469,082 | 1,671,111 |
| instrs | 2,474,230 | 212,162 | 351,144 | 265,488 |
| bytes/cycle | 0.0140 | **0.2203** | 0.0892 | 0.0784 |

- **AES-GCM: 15.77x** for the S1 instruction set over its software baseline.
- **ChaCha20-Poly1305: 0.88x** for `rori` -- a third fewer instructions and 14%
  *more* cycles. Section 9 records what that reverses.
- Across algorithms, the software AES-GCM costs **6.39x** the cycles and 7.05x
  the instructions of the software ChaCha20-Poly1305 over the same bytes.

### 16.4 The price of the two changes, and what it does to section 15

Both changes were measured before and after in this tree, at both shapes, with
every row's shape asserted from the application's own banner:

| shape | kernel | change | before | after | move | instrs |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| c2w4t16 | chacha_poly sw | AAD + tail | 1,599,484 | 1,469,082 | **-8.153%** | +120 |
| c1w4t32 | chacha_poly sw | AAD + tail | 2,548,408 | 2,546,918 | **-0.058%** | +60 |
| c2w4t16 | aes_gcm sw | probe refactor | 9,338,582 | 9,380,132 | **+0.445%** | +8 |
| c1w4t32 | aes_gcm sw | probe refactor | 15,328,651 | 15,754,074 | **+2.775%** | +4 |

Three of the four `before` rows reproduce numbers already in this document --
2,548,408 in section 9's sweep, 9,338,582 in section 12, 15,328,651 in section
15.1 -- **to the cycle**. The fourth, 1,599,484, was measured in a peer session
and never recorded here; it reproduced to the cycle as well, as did that
session's whole `c2w4t16` size sweep (540,892 / 899,464 / 3,062,616). That is the
check that this apparatus and the one those numbers came from are the same
apparatus, and it is the reason the before/after rows can be read as a
difference rather than as two measurements.

**Adding a feature made ChaCha20-Poly1305 8.2% faster.** Instructions went the
other way, by +0.034%. Decomposed over the size sweep, per-block cycles fell
12.9% (90,061 to 78,427) while per-block *instructions* fell 0.38% (20,856 to
20,776), and the fixed per-message cost rose 49% in cycles for 8% in
instructions. A 34-fold disproportion between the cycle change and the
instruction change is not an instruction-count effect. It is the same class of
thing as section 12's unexplained +19.1%, in the favourable direction, on a
kernel that requests **no local memory at all**.

**That is a problem for section 15's account, and the problem is the
generalisation rather than the measurement.** Section 15 found the post-AAD
movement 3.1x larger at 16 LMEM banks than at 32 and concluded that a mechanism
acting through bank conflicts was at work. Two things here do not fit:

- chacha_poly's movement is **140x** larger at `c2w4t16` than at `c1w4t32`, and
  it has no local memory for a bank conflict to form in. Whatever sets the scale
  of layout movement between these two shapes is available to a kernel with
  `lmem_size = 0`.
- aes_gcm's movement under a *different* perturbation runs the **opposite** way
  between the same two shapes -- 6.2x larger at `c1w4t32`, the 32-bank shape. If
  bank count set the scale, the ordering would not depend on which
  bit-identical-by-construction change is applied.

So "halving the LMEM banks multiplies the movement by 3.1x" describes one
perturbation of one kernel. It does not describe the phenomenon, and section
15's own caveat -- that the two shapes differ in cores, threads, LMEM banks and
D-cache banks at once -- was carrying more weight than it was given credit for.
What survives is section 14.1's narrower claim, now with a second and much
larger counterexample: **layout sensitivity here is not an LMEM-bank effect, and
no mechanism proposed so far accounts for its size.**

### 16.5 What this closes

**Section 12's open item is closed.** It said the ratio at this configuration
should be treated as bounded below by roughly 12x rather than quoted at a point,
because the software kernel had no floor probe of its own. It has one now, and
its floor is 0.16% to 0.47% -- so the ratio can be quoted: **15.77x**, with the
resolution set by the *hardware* endpoint, whose own probe ranges up to 4.68%
(section 12). Read it as **15.8x with a floor of about 5%**, and note that the
uncertainty now sits entirely on the instruction-set side of the comparison.

**The +19.1% is real and still unexplained.** It is forty times the software
kernel's floor at this shape, so it was never measurement scatter; section 15
attributes part of it to bank conflicts and 16.4 says why that cannot be the
whole account.

**The simx-versus-rtlsim gap is largely a property of the old shape.** Section 5
recorded 16.3% at `c1w4t32` and called it a modelling discrepancy to resolve
before a `model_parity` gate could cover these cases. At `c2w4t16` it is
**1.97%** for aes_gcm and 2.30% for chacha_poly. That does not resolve the
discrepancy, but it does relocate it.

**Both AEAD kernels implement the same feature set again**, so section 6's
cross-algorithm row compares like with like for the first time since section 12.

### 16.6 What it does not close

- **The mechanism of the layout movements**, on either kernel, in either
  direction. Four measured pairs, and no account that fits all four.
- **chacha_poly's steady-state gate**, which fails at every size measured and
  fails wider than before. Section 6 states the fixed-cost share so a reader can
  discount it explicitly rather than trust the gate to have done it.
- **`rori`'s sign flip**, section 9. The instruction ratio is exact and stable;
  the cycle ratio has now been measured on both sides of unity at the same shape
  with the same instructions, which says more about this apparatus than about
  the B extension.
- **Whether AAD belongs in the measured configuration at all.** Every row here
  is `-a0 -t0`. The feature is implemented, checked and regression-covered, but
  nothing is measured *with* it, so its runtime cost is unrecorded.

## 17. S3 pre-registered: what a subgroup-cooperative AES would have to convert

This section states a prediction and a decision rule before reading the result,
for the reason section 15 gives: a prediction stated afterwards is not a
prediction. **The exact provenance, because it is weaker than the ideal and the
difference matters:** 17.1 to 17.5 were written while the probe runs were in
flight and committed (`f830089c6`) before their numbers were read -- but the
runs had already written some rows to disk by then, so git proves only that the
prediction preceded the *reading*, not that it preceded the *measurement*. A
reader should weigh it as an author's account rather than as a timestamped
pre-registration. The rule below was not adjusted after the fact; 17.6 records
which parts of the prediction failed, and by how much.

S3 in the taxonomy this project now uses is a *subgroup-cooperative, stateless*
extension: the algorithm's state is distributed across lanes' general registers,
the instruction adds fixed cross-lane routing, and nothing survives retirement
inside the unit. For AES the natural mapping is four lanes to the four state
columns, because `aes32esmi`'s byte-step already makes output column `j` consume
state column `(j + bs) & 3` -- so ShiftRows, which in the lane-local form is
free (it is a choice of which register to name), becomes a rotate within an
aligned quad.

### 17.1 The arithmetic that has to be said first

**A subgroup AES is instruction-neutral per block, exactly, by construction.**
Four lanes doing a quarter of the work each is the same warp-instruction count
as one lane doing all of it: the mapping quarters the work per block and
quarters the blocks per warp simultaneously. At the recorded point the shipped
`hw_s1` issues 160 `aes32` per block from one lane, which is 10 warp-instructions
per block across 16 lanes; a byte-granular `.sg4` form issues 40 per quad-pass,
which is also 10 per block. There is no instruction saving to protect, and a
design that reports "16 issues become 4" is quoting a per-subgroup count while
the subgroup covers four times fewer blocks.

The saving only appears if the four byte-steps are **fused into one instruction
per round**, which is what makes S3 worth an opcode at all:

| | per block | |
| --- | ---: | --- |
| `hw_s1` total | **25.899** | 212,162 instructions / 8192 blocks |
| ... of which `aes32` | 10.00 | 160 per block, 16 blocks per warp |
| S3 probe: adds 3 rotates per round | +7.50 | 120 per quad-pass-set / 16 blocks |
| S3 probe: adds 2 transposes per block | +0.50 | 8 wgather / 16 blocks |
| **probe predicted** | **33.899** | **277,700 instructions, +30.9%** |
| fused round (`aesrm.sg4`), hypothetical | 18.899 | **-27.0%** |

Round-key loads (2.75 per block), payload loads and stores, the AAD path, the
GHASH half and the number of messages in flight per warp are **unchanged** in
both forms: the quad round-robins over the four messages it owns rather than
giving four lanes to one message, so the memory side of the kernel is left
exactly where it is. That is deliberate. It costs two 4x4 transposes per block
and it keeps the comparison attributable to the keystream generator.

### 17.2 Which half of the machine this acts on

Section 13.3 split an AES ISE cleanly and measured both halves: **"44 key loads
-> 0. Measured at -14.1%. Converts"** against **"160 aes32 -> 10 round
instructions ... Unlikely to convert"**. Counted against the kernel, every SG4
layout including this one issues the same 11 warp-loads of round key per four
blocks that the shipped kernel issues, and the same payload traffic.

**So this removes zero loads. It acts entirely on the half that has never
converted here.** The three in-tree measurements of removing arithmetic all have
the wrong sign: `ghred32` -1.96% instructions for +10.2% cycles, `rori` -24.4%
for +13.8%, and the `ilp` variant identical in instruction count for +7.4%. The
best conversion rate ever measured in this tree is **r = 0.837**, and it came
from removing loads.

One counterweight is often quoted against that -- section 10's "the machine is
at 68% of peak issue", "0% crypto backpressure", "`aes32` is 39% of the
instruction stream". Those were taken at `c1w{4,8,16}t4`. At `c2w4t16`, where
every recorded row now lives, per-core IPC is 106,081/594,958 = **0.178** with
`ISSUE_WIDTH = 1`: the issue slot is 82% idle. The 39% mix figure does transfer
(10 of 25.899 warp-instructions per block is 38.6%); the 68% does not.

### 17.3 The probe, and why it needs no hardware

The probe is a kernel entry point, `aes_gcm_hw_sg4`, and it changes no RTL,
because **this tree already has the routing**. `SHFL` (UP/DOWN/BFLY/IDX),
`VOTE`/`BALLOT` and `WGATHER` are decoded unconditionally in every build on
custom0/custom1, implemented in RTL and simx, and `vx_transpose4` is already
written as four `wgather`. With `mask = 0x3c`, `cval = 3` and a per-lane
`bval = (c + p) & 3`, `SHFL.IDX` resolves to `(i & ~3) | ((i + p) & 3)` -- the
aligned rotate -- identically at 4, 16 and 32 threads.

### 17.4 The rule, fixed in advance

Let `r = Dcycles% / Dinstrs%` measured on the probe against `hw_s1` at the
recorded point.

- **KILL-C, integrity.** If the probe's instruction count is not within two
  percentage points of the predicted +30.9%, the lane mapping or the transpose
  accounting is wrong. The cycle number is not read and not reported until the
  count is explained and the prediction re-registered. This check fires on my
  arithmetic, not on the machine.
- **KILL-B, weak conversion.** The fused round is worth -27.0% instructions, so
  clearing 10% of cycles -- about twice this kernel's 4.68% floor -- needs
  `r >= 0.370`. If the measured `r` is below that, **stop: do not write the
  RTL.** Record the null.
- **KILL-A, layout penalty.** If `r > 0.837`, the excess is not instruction
  count, because 0.837 is the highest rate this machine has ever shown and it
  was for loads. The excess is the subgroup layout itself, which the fused form
  still pays. **Stop** unless the excess is identified and removed.
- **BUILD only for `0.370 <= r <= 0.837`.**

The probe is asymmetric and that is worth stating: a *gain* would be decisive,
because it would appear despite +30.9% instructions; a *loss* is not, because it
could be either the machine's conversion rate or the layout. The rule above is
written so that the ambiguous outcome stops the work rather than licensing it.

### 17.5 Prediction

I expect **KILL-B**: `r` between 0.15 and 0.40, and the probe landing between
+5% and +12% of cycles. If it is built anyway I expect the fused form to land
within +/-6% of `hw_s1`, inside the floor, quotable only as a null.

### 17.6 Measured: the probe fires two of its own kill rules

`aes_gcm_hw_sg4` computes the correct AEAD on both drivers at the first attempt,
with **identical retired-instruction counts on rtlsim and simx** (51,555 at the
tree default), so the lane rotation, the transposes and the per-lane round-key
indexing are right and the two models agree about the cross-lane path.

Recorded point, `c2w4t16`, `-n128 -b64`, rtlsim, one tree, one commit:

| | hw_s1 | hw_sg4 | |
| --- | ---: | ---: | ---: |
| cycles | 580,088 | 1,078,038 | **+85.84%** |
| instrs | 212,170 | 345,128 | **+62.66%** |
| instrs/block | 25.900 | 42.13 | +16.23 |
| bytes/cycle | 0.2260 | 0.1216 | |

Three rtlsim runs at the probe point returned 1,078,038 / 345,128 identically.
simx reads 555,063 and 1,079,043 for the same pair.

**Both halves of 17.5's prediction failed, and in the same direction.** It said
the probe would land at +5% to +12% of cycles for +30.9% instructions; it landed
at **+85.8% for +62.7%**. The instruction model was wrong, and the cycle
prediction that rested on it was wrong by seven times.

**KILL-C fires.** The prediction was +30.9% instructions; the measurement is
+62.66%. The excess decomposes, and it is stable across a fourfold change in
problem size (+16.23 per block at `-b64`, +16.36 at `-b16`), so it is all in the
block loop:

| component | per block | |
| --- | ---: | --- |
| rotates | +7.50 | 3 per round x 10 rounds x 4 passes / 16 blocks |
| transposes | +0.50 | 8 wgather / 16 blocks |
| **residual** | **+8.23** | not predicted |

The residual is spill traffic, and the disassembly says so: `aes_gcm_hw_sg4`
carries **179 `sp`-relative accesses against `aes_gcm_hw_s1`'s 125**, for 1,112
static instructions against 983. Crossing the seam requires the four transposed
counters and the four results live simultaneously across four AES computations,
which is eight values on top of a kernel that already fills the register file.
The descriptor packing, the other candidate, is not the cause: the two kernels
differ by two `or` instructions in total, so the loop-invariant descriptors are
hoisted as intended.

**KILL-A fires too, and harder.** `r = 85.84 / 62.66 = 1.370`, against 0.837 for
the highest rate this machine has ever shown. Cycles rose *faster* than
instructions, which means the added instructions are more expensive than the
average one. The pipeline breakdown at `-b16` says exactly where they went
(separate PERF runs, shape asserted from the application's banner):

| per core, `-n128 -b16` | hw_s1 | hw_sg4 | |
| --- | ---: | ---: | ---: |
| loads | 61,548 | 70,552 | +14.6% |
| **average load latency** | **91.69** | **130.98** | **+42.8%** |
| D-cache requests | 19,388 | 29,352 | +51.4% |
| D-cache read misses | 7,403 (39% hit) | 16,173 (**24% hit**) | +118% |
| bank stalls | 20,873 | 32,633 | +56% |
| instruction mix | sym 38%, alu 33% | sym **24%**, alu **52%** | |
| crypto backpressure | 0% | 0% | |

**The subgroup layout does not merely add ALU work; it adds D-cache traffic to
the one part of this machine that was already binding.** Read hit rate falls
from 39% to 24%, misses more than double, and average load latency goes from 92
to 131 cycles. Section 13.3's rule -- loads convert, arithmetic does not -- holds
here with its sign reversed: this design adds loads, and they converted.

### 17.7 The consequence for the fused instruction, and the verdict

The whole case for `aesrm.sg4` was that it deletes the rotates and folds four
`aes32` into one, which section 17.1 priced at -27.0% of the instruction stream.
That price assumed the seam was free. Measured, it is not:

```
fused = 25.900 + 16.23 (measured SG4 cost) - 7.50 (rotates) - 7.50 (4 aes32 -> 1)
      = 27.13 instructions per block  =  +4.7% against hw_s1
```

**The fused subgroup round is instruction-positive in this composition, not
-27%.** It removes the two cheap components and leaves the expensive one: the
spill traffic is 8.23 of the 16.23 added instructions, and by the breakdown
above those are the ones costing 131-cycle loads. There is nothing left for the
instruction to convert.

**Verdict for THIS composition: do not build it.** Two pre-registered rules
fired, and the re-derivation removes the premise for the composition measured
here. Recorded as a null; the reserved encoding stays unspent.

> **Correction, and it matters more than the verdict.** The paragraph above
> originally read "do not build it" without qualification, which took a result
> about one composition and applied it to the instruction. That is wrong, and
> section 18.5 states the corrected arithmetic. The +4.7% figure adds this
> composition's 8.23 spill instructions per block, and those exist only because
> the quad round-robins over four messages and has to transpose in and out. In
> the mapping where a quad owns ONE message end to end there is no transpose and
> no seam, and a fused round instruction issues 2.75 warp-instructions per block
> against the shipped kernel's 10 -- a fourfold reduction on the AES path, not
> instruction neutrality. Nothing measured here bears on that instruction.

**What this does not kill.** The probe deliberately kept the payload, the GHASH
half and the number of messages in flight per warp exactly as they are, by
having each quad round-robin over the four messages it owns. That choice is what
created the seam, and the seam is what killed it. The other mapping -- four lanes
to *one* message, lane `c` holding column `c` throughout -- has no seam and no
transposes, reads the payload as four consecutive words per quad instead of
sixteen 1024-byte-strided ones, and holds one state word per lane instead of
four. It also cuts the messages in flight per warp by four and **cannot be built
without a distributed GHASH**, because `ghash_mul_hw` takes four limbs in one
lane. That is the form worth measuring next, and it is measurable the same way:
a distributed GHASH is expressible as `clmul` plus `SHFL` plus an XOR reduction,
so it needs no RTL either.

**What the exercise establishes independently of the result.** A subgroup design
in this tree can be falsified for the cost of one kernel file. `SHFL`, `WGATHER`
and `vx_transpose4` are decoded in every build, so the S3 tier has a zero-RTL
instrument, and section 10's standing request -- that deciding S2/S3 needs "a
critical-path measurement, or a prototype, not another warp scan" -- is now
answerable without spending an opcode, a PE, a conformance harness or a
re-baselining.

**One baseline movement, recorded.** Templating the hardware body on the
keystream generator moved `hw_s1` from 594,958 to **580,088** cycles (-2.50%)
for +8 instructions, the same shape of layout movement section 16.4 records for
the software kernel. It is below this kernel's 4.68% floor and is not
attributable; both rows above were measured after it, in one tree, so the
comparison between them is unaffected.

## 18. The other subgroup mapping, and the tide it would have to be measured against

Section 17 killed the mapping that keeps the payload lane-local. The mapping it
left standing gives four lanes to *one* message -- lane `c` holds column `c`
throughout, no transposes, one state word per lane, and the block's sixteen
bytes read as four consecutive words by the quad. It has one advantage nothing
in section 17 refuted: **payload locality**. It also cannot be built without a
distributed GHASH, because `ghash_mul_hw` takes four limbs in one lane.

Rather than build the distributed GHASH to find out, the locality was measured
on its own.

### 18.1 The diagnostic: interleaving the payload is 25% slower, not faster

`aes_gcm_hw_s1_ilv` is the shipped hardware kernel with **only** the payload
layout changed: block `b` of every message stored together, so one warp-load
touches four 64-byte lines instead of sixteen. It is a diagnostic and not a
proposal -- a server handling independent records does not choose its buffer
layout -- but it moves the access pattern in the direction a subgroup mapping
would, four times fewer lines per load instruction, without any cross-lane
machinery.

At the recorded point, `c2w4t16`, `-n128 -b64`, rtlsim, one tree:

| | cycles | instrs | vs hw_s1 |
| --- | ---: | ---: | ---: |
| hw_s1 | 580,088 | 212,170 | |
| hw_s1_ilv | 871,210 | 214,682 | **+50.19%** cycles, +1.18% instructions |

simx agrees in direction and size (+30.0%). The pipeline breakdown says why
(`-b16`, separate PERF runs, shape asserted from the banner):

| per core | hw_s1 | hw_s1_ilv | |
| --- | ---: | ---: | ---: |
| D-cache read misses | 7,403 (**39%** hit) | 11,909 (**26%** hit) | +61% |
| average load latency | 91.69 | 115.30 | +25.8% |
| D-cache requests | 19,388 | 23,356 | +20.5% |
| bank stalls | 20,873 (48% util) | 15,792 (**60%** util) | **-24%** |

**The coalescing worked and the kernel got slower anyway.** Bank stalls fell by a
quarter and bank utility rose from 48% to 60% -- the thing the layout was
supposed to improve, improved. What it destroyed is temporal reuse: in the
shipped layout a 64-byte line holds four *consecutive blocks of one message* and
is hit on the next three loop iterations, which is where the 39% read hit rate
comes from. Interleaved, a line holds four blocks of four *different* messages,
consumed in one instruction, and the next iteration is two kilobytes away.
Misses rise 61% and latency follows, and this kernel is scoreboard-stalled 88%
of the time waiting on exactly that latency.

**What this does not settle.** The mapping that gives four lanes to one message
keeps each message contiguous, so it would keep the temporal reuse *and* share
each sixteen-byte block across four lanes. That is a third pattern, not the one
measured here, and this diagnostic does not bound it. The honest statement is
that the obvious way to buy cross-lane payload locality costs 25% at equal
addressing, and the mechanism it lost through is the one the subgroup mapping
would have to protect.

### 18.2 The accident that is the biggest number in this section

The first version of the layout parameter rewrote the *contiguous* arm as
`src_base + (msg_stride * msg + 16 * b)` instead of leaving it as the pointer
walk `pt + 16 * b`. Semantically identical addressing, same buffer, same order.

| hw_s1 | cycles | instrs |
| --- | ---: | ---: |
| pointer walk (shipped) | 580,088 | 212,170 |
| computed offset | 699,757 | 213,674 |
| | **+20.63%** | +0.71% |

**1,504 added instructions cost 119,669 cycles: 79.6 cycles per instruction.**
Restoring the pointer walk returned the kernel to 580,088 / 212,170, byte for
byte, so the attribution is exact rather than inferred.

That is **4.4x this kernel's widest floor sample** and larger than every
instruction-set effect measured in this project apart from the shape change of
section 15.1. It also decomposes cleanly against 18.1, which is the check that
both numbers are real: measured at equal addressing style, interleaving costs
+25.13%; addressing style alone costs +20.63%; 1.2063 x 1.2513 = **1.5095**
against the 1.5019 measured for the two together.

### 18.3 What the remaining mapping would cost, from measured parts

The distributed GHASH was not built, and this is an estimate with its
derivation, not a measurement. `ghash_mul_hw` is 16 `clmul` + 16 `clmulh` + 32
XOR for the schoolbook product and 17 more for the reduction: **81 instructions
per block in one lane, 5.06 warp-instructions per block across sixteen.**
Distributed over a quad, lane `i` holding limb `i`, each lane computes four
products, and every `clmulh` term lands in the *next* lane's limb -- so the
products cannot be accumulated without cross-lane movement. Counting one rotate
plus a select per step, plus the fold, the quad needs roughly 56
warp-instructions per block, and a warp of four quads advances four blocks with
them: **about 14 warp-instructions per block, against 5.06.**

Adding the AES rotates already measured at +7.50 per block, the mapping lands
near **+16 warp-instructions per block, +64%** -- the same order as the mapping
section 17 measured (+62.7%), for the same structural reason. Distributing work
that is already parallel across lanes does not reduce warp-instructions; it
adds routing. Against that it offers a fourfold cut in payload D-cache
*requests* on a kernel whose stall is load *latency*, and 18.1 has just shown
that request count is not what binds here: the interleaved kernel cut bank
stalls 24% and still lost 25%.

**Withdrawn.** This section originally concluded "S3 for AES-GCM is closed", and
that conclusion does not survive its own arithmetic. The +64% above is the cost
of the SOFTWARE probe of that mapping -- shuffles standing in for routing that
would be wiring -- not the cost of the mapping with the instruction built. It
was then combined with 17.7's +4.7%, which carries a seam the mapping does not
have. Two different compositions, neither of them the one being ruled out. See
18.5.

### 18.4 The finding that outlives the question

Section 16.4 recorded four measured layout movements and no account that fits
them. This section adds a fifth, and it is the largest and the cleanest: a
source-level rewrite with no semantic content, exactly attributable because
reverting it restored the number byte for byte, worth **20.6%** on the kernel
every instruction-set claim in this document is measured against.

That is larger than the AES S1 extension's margin over its own floor, larger
than every S2 and S3 result here, and second only to the memory-configuration
change of section 15.1. **The apparatus's sensitivity to source-level layout now
exceeds the effect size of the thing being studied.** Until that is understood,
another instruction-set probe on this kernel measures the tide.

### 18.5 Corrected: what S3 actually is, and what it would cost

The correction came from the user and it is structural, not a matter of wording.
**S3 is a mapping of a message onto a subgroup, not a substitution of one
instruction for another.** Written out for `t16`:

| | S1 | S3 |
| --- | --- | --- |
| lanes per message | 1 | 4 |
| messages per warp | 16 | **4** |
| AES state | 128 bits in one lane | one 32-bit column per lane |
| ciphertext block | 16 bytes in one lane | one word per lane |
| GHASH `Y`, `H` | four limbs in one lane | one limb per lane |
| AES to GHASH | nothing to do | nothing to do -- the layout never changes |

Everything stays distributed from the counter to the tag: counter word ->
state column -> ciphertext word -> GHASH limb. That is what makes it S3 rather
than a lane-local kernel that borrows a subgroup for ten rounds.

**The two things measured in sections 17 and 18 are not that.** Section 17's
probe keeps 16 messages per warp and transposes into a subgroup layout for the
AES and back out for a lane-local GHASH; section 18.1's diagnostic changes the
buffer layout and nothing else. Both are compositions that a real S3 does not
contain, and both carry costs it does not pay -- above all the two 4x4
transposes per block and the eight extra live values they force, measured at
8.23 of the 16.23 added instructions per block.

**The corrected instruction arithmetic**, per block, against the shipped
`hw_s1`'s 25.90 warp-instructions per block at the recorded point:

| AES path | per block-round | per block |
| --- | ---: | ---: |
| S1: 16 `aes32` advance 16 blocks | 1.00 | 10.00 |
| byte-granular `.sg4`: 4 advance 4 blocks | 1.00 | 10.00 |
| **fused `aesrm.sg4`: 1 advances 4 blocks** | **0.25** | **2.75** |
| software probe of S3: 3 rotates + 4 `aes32` advance 4 blocks | 1.75 | 17.50 |

So the fused round is a **fourfold reduction on the AES path**, from 10.00 to
2.75 per block. Section 17.1 said the byte-granular form is instruction-neutral
and that the saving needs the fuse, and that much was right; 17.7 then priced
the fuse at +4.7% by adding the seam's spill traffic, which the real mapping
does not have. **That number is withdrawn.**

GHASH follows the same shape. `ghash_mul_hw` is 81 instructions in one lane,
5.06 warp-instructions per block; distributed across a quad with rotates and
selects standing in for routing it is roughly 9.5 per block in software, and
with a fused stateless group multiply it would be under 1. Together the two
dominant paths go from 15.06 per block to about **3.25 with both instructions
fused** -- a 45% cut of the whole stream, not the +4.7% this document previously
recorded.

**What is still unmeasured, and it is the whole risk.** Three things, none of
them derivable:

- **Message parallelism falls from 16 per warp to 4.** The kernel is
  scoreboard-stalled 88% of the time waiting on loads at 64 to 92 cycles;
  removing three quarters of the independent work in flight is the single
  largest threat to the mapping, and section 17's probe was deliberately built
  to avoid testing it.
- **Payload coalescing.** Four lanes reading four consecutive words of one block
  keeps each message contiguous, so the temporal reuse 18.1 found decisive is
  preserved *and* four lanes share one line. That is a third access pattern,
  and neither measurement here bounds it.
- **The real cost of a distributed GHASH**, which is an estimate above and
  nothing more.

All three are properties of the data layout, not of the instruction count, so
all three are measurable with the instructions this tree already has: `SHFL`
supplies the routing, and the software composition computes bit-for-bit what a
fused instruction would. The instruction count is the one quantity that differs,
and it is the one quantity that can be calculated exactly. That is the whole
reason the probe comes before the RTL.

## 19. The layout tide has a mechanism, and a two-instruction fix

Section 18.4 said the apparatus's sensitivity to source-level layout exceeds the
effect size of the thing being studied, and that until it was understood another
instruction-set probe measured the tide. It is now understood.

### 19.1 The mechanism

Every hart's stack is placed by `vx_start.S`:

```
sp = VX_MEM_STACK_BASE_ADDR - (mhartid << VX_MEM_STACK_LOG2_SIZE)
```

with `VX_MEM_STACK_LOG2_SIZE = 13` (`VX_types.toml:22`), confirmed in the
compiled prologue: `lui sp, 0xffff0 / csrr t0, mhartid / slli t1, t0, 0xd /
sub sp, sp, t1`. **Consecutive harts' stacks are 8192 bytes apart, and the harts
of a warp are consecutive.**

That the stride makes a warp-wide stack access a divergent gather was already
known and is written into the kernels: `tests/crypto/aes_gcm/kernel.cpp:339-345`
says "vx_start.S gives each hart a stack 8 KB apart, so a single sp-relative
access in a warp becomes NUM_THREADS distinct cache lines 8 KB apart -- a fully
divergent gather on a single-banked L1". What was not noticed is the arithmetic
one step further:

- D-cache: 16,384 bytes, 4 ways, 64-byte lines -> **64 sets**, spanning
  64 x 64 = **4096 bytes** of address.
- The stack stride is 8192 = 2 x 4096, an exact multiple of the set span.
- Therefore every lane's copy of the *same* stack slot has the **same set
  index**. It is not merely a divergent gather across sets; it is
  `NUM_THREADS` accesses into **one** 4-way set.

At 16 threads that is a 16-way conflict on four ways, on every access to every
spilled value. It also evicts whatever else was living in that set -- which is
why a handful of extra spill accesses can cost far more than themselves.

### 19.2 The intervention, and it is two instructions

`VX_MEM_STACK_LOG2_SIZE` has exactly one consumer in the whole tree: the two
sites in `vx_start.S`. No MMU check, no memory map, no linker script -- the
linker script never mentions the stack at all -- no runtime allocator, no
assertion. So the blast radius of changing the placement is that one file.

Added, **off by default**, behind `VX_MEM_STACK_SKEW_LOG2`:

```
  sll   t1, t0, VX_MEM_STACK_SKEW_LOG2
  sub   sp, sp, t1
```

At `SKEW = 6` each hart's stack is displaced a further 64 bytes, which rotates
the set index by one per hart, so the lanes of a warp land in distinct sets
instead of colliding. Cost: two instructions of startup and 64 bytes per hart of
address space -- 8 KiB across the 128 harts of the recorded shape.

Verified as taken effect rather than assumed, by disassembling the prologue: two
shifts appear, `slli t1, t0, 0xd` and `slli t1, t0, 0x6`. Every kernel's retired
instruction count rises by exactly 16 -- two instructions on each of the eight
warps -- which is the second, independent confirmation that the change is exactly
what it claims to be and nothing more.

### 19.3 Measured

`c2w4t16`, rtlsim, one tree, one commit, shape asserted per row from the
application's banner:

| kernel | skew off | skew on | |
| --- | ---: | ---: | ---: |
| `aes_gcm` sw_ttable, `-n128 -b64` | 9,454,077 | 7,065,173 | **-25.27%** |
| `chacha_poly` sw, `-n128 -b16` | 1,469,082 | 923,628 | **-37.13%** |
| `aes_gcm` hw_s1_ofs, `-n128 -b64` | 695,177 | 468,748 | **-32.57%** |
| `aes_gcm` hw_s1, `-n128 -b64` | 580,088 | 543,229 | -6.35% |
| `sgemm -n128` | 927,672 | 927,056 | **-0.07%** |
| `vecadd -n16384` | 49,840 | 49,891 | **+0.10%** |

**The last two rows are the result.** `sgemm` and `vecadd` do not spill, and they
do not move: a tenth of a per cent, an order of magnitude inside this
apparatus's floor. A change that perturbed layout in general would have moved
them. This one moves exactly the kernels that carry stack traffic, in proportion
to how much they carry -- `chacha_poly`, which section 9 measured at thirty live
values on a thirty-two register machine with 145 static `lw` and 108 `sw`, moves
most.

**Section 18.2's specimen inverts.** `hw_s1_ofs` was 19.84% *slower* than
`hw_s1`; with the skew it is 13.7% *faster*. The largest unexplained layout
movement in this document is not merely explained, it changes sign once the
aliasing is removed -- which is what an explanation is supposed to do.

### 19.4 What this settles and what it costs

**Settles.** The mediating variable section 14 proposed for the post-AAD
regression -- "it added live values across the message loop, which can shift
register allocation and therefore spill addresses" -- is right in outline, and
the missing half is why a shifted spill address matters so much: it is a
conflict on a single set, not a bank pattern. Section 14's LMEM bank-conflict
account explains the floor of a kernel that gathers into local memory;
`chacha_poly` requests `lmem_size = 0` and moves 37% here, which is the
counterexample 14.1 recorded and could not account for.

**Does not settle.** Section 18.1's interleaving result is untouched by this: it
moved the payload, not the stack. And nothing here says the remaining movements
are all spill-mediated; it says the largest ones are.

**Costs, if it were made the default.** Every recorded row in this document was
measured without it, so switching would invalidate all of them -- sections 5, 6,
9, 11, 12, 15, 16, 17 and 18 -- and the CI perf baselines with them. It is left
opt-in for that reason. The decision is worth taking deliberately: a 25 to 37%
improvement on the two software baselines is larger than every instruction-set
effect recorded in this project, and larger than the memory-configuration change
of section 15.1.

## 20. True S3, measured -- and the two verdicts that were measured on a broken machine

Sections 17 and 18 ruled against the subgroup tier. Both were measured before
section 19 found that per-hart stacks alias into one D-cache set, and both
kernels involved carry more stack traffic than the shipped one. **The rulings do
not survive the fix.**

### 20.1 The kernel

`aes_gcm_hw_s3` is the mapping section 18.5 defines: a quad of four lanes owns
one message from the counter to the tag, lane `c` holding counter word `c`, AES
state column `c`, ciphertext word `c` and GHASH limb `c` throughout. **There is
no transpose anywhere.** A warp carries four messages instead of sixteen.

Both halves are distributed. The AES reuses the rotate-based round of section
17. GHASH is new: with `Y` one limb per lane and `H` replicated, rotating `Y` by
`j` puts the term whose limb index is `k` in lane `k` when `k >= j` and `k+4`
when the rotate wrapped, so each lane accumulates `p[k]` and `p[k+4]`; every
`clmulh` half belongs one limb higher and is rotated one lane up and steered on
arrival. The fold has the same shape, with lane 3's carry closing back into lane
0. It is 8 shuffles, 11 `clmul`-class and the selects, all stateless.

**A hazard worth recording, because it is silent.** The first version put
`if (c == 3) ctr = inc(ctr);` before the AES. The counter was right, the
lane-to-word mapping was right, the AES round was the one already validated in
section 17 -- and the cipher was wrong, every byte. A divergent region before a
cross-lane operation breaks the quad, and nothing reports it. The increment is
now branchless. Any fused subgroup instruction needs this as an architectural
precondition, not a coding convention.

Correctness: four configurations at the tree default including 20- and 33-byte
AAD, identical retired-instruction counts on rtlsim and simx, and passing at
`c2w4t16` where four quads share a warp so inter-quad divergence is live. Two
runs at the recorded point return identical counts.

### 20.2 Measured, and the confound is the result

`c2w4t16`, `-n128 -b64`, rtlsim, one tree:

| | cycles | instrs | vs hw_s1 |
| --- | ---: | ---: | --- |
| hw_s1, stack as shipped | 580,088 | 212,170 | |
| hw_s3, stack as shipped | 1,966,839 | 481,682 | **+239.1%** cycles, +127.0% instrs |
| hw_s1, per-hart skew | 543,229 | 212,186 | |
| **hw_s3, per-hart skew** | **696,676** | 481,698 | **+28.3%** cycles, +127.0% instrs |

**The skew removes 64.6% of this kernel's cycles and changes not one
instruction.** The conversion rate for the software routing goes from r = 1.88
to **r = 0.22**: once the spill slots stop colliding, the added instructions are
nearly free in cycles, which is what an 82%-idle issue port should do with them.

Section 17's hybrid probe moves the same way: +82.2% against `hw_s1` without the
skew, **+11.1% with it**. Both of this document's rulings against the subgroup
tier were artefacts of the stack aliasing.

### 20.3 The memory side, which is what the probe was built for

`-b16`, per core, both kernels with the skew, so the comparison is at equal
stack configuration:

| | hw_s1 | hw_s3 |
| --- | ---: | ---: |
| D-cache read hit | 84% | **97%** |
| read misses | 1,931 | **1,052** |
| **average load latency** | 45.28 | **22.40** |
| loads | 61,548 | 88,812 (+44%) |
| write hit | 1% | 27% |
| scheduler idle | 82% | 69% |
| `simt_util` | 16.0 (100%) | 14.9 (93%) |

**The coalescing hypothesis is confirmed.** Four lanes reading four consecutive
words of one block, with each message still contiguous, gives a 97% read hit
rate and **half the load latency of the shipped kernel**. Section 18.1's
interleaving diagnostic lost because it traded temporal reuse for spatial
sharing; this mapping keeps both, which is exactly the distinction 18.1 could
not test.

The 4x loss of message parallelism -- 16 messages per warp down to 4 -- is inside
these numbers and did not prevent them. That was the largest stated risk and it
is now quantified rather than feared.

`simt_util` at 93% is this kernel's own selects, the per-lane branchless
predicates standing in for what an instruction would do in its decode. A fused
form has none of them.

### 20.4 What it implies for the instruction, stated as arithmetic

The probe pays +127% instructions for routing that hardware would do as wiring:
three rotates per AES round, eight per GHASH multiply, and the selects. Fusing
removes them.

| per block | |
| --- | ---: |
| hw_s1 | 25.90 |
| hw_s3, software routing (measured) | 58.80 |
| AES rotates + four `aes32` folded to one `aesrm.sg4` | -15.00 |
| distributed GHASH folded to one `ghmul.sg4` | about -30 |
| **hw_s3 with both fused (derived, not measured)** | **about 13.8** |

That is **roughly 47% below the shipped kernel's instruction count**, on a
layout measured to halve load latency, with the parallelism loss already paid
for in the +28% figure above.

**So the case for building the subgroup instructions is open again, and it is
stronger than it was before either ruling.** What has not changed is the other
half of the question: whether `aesrm.sg4` closes timing, and whether a stateless
group multiply is affordable in area on a design with 4.0% of period slack --
section 13.1 measured GHASH as the largest crypto block at 15,229 ALM. Those are
still unanswered, and this probe cannot answer them.

### 20.5 What this costs the rest of the document

Every conclusion in sections 17 and 18 that rests on a cycle comparison was
measured with the stack aliasing present. The instruction counts stand -- they
are exact and the skew changes them by 16 -- and so do the ratios between
kernels measured in the same configuration. What does not stand is any statement
of the form "the subgroup layout costs X%": those numbers were the aliasing,
and section 19's control shows why it took this long to see it -- the two
ordinary applications used as sanity checks do not spill, so they never moved.

## 21. The fused subgroup round, built and measured: 30% faster than the shipped kernel

Section 20 ended with an arithmetic argument that the routing a software S3 pays
for would be wiring in hardware, and could not say what that was worth in
cycles. It is now built.

### 21.1 The instruction

```
aesrm.sg4 rd, rs1, rs2      # middle round   custom-3 (0x7B), funct3 = 0
aesrf.sg4 rd, rs1, rs2      # final round    custom-3 (0x7B), funct3 = 1
```

`rs1` is this lane's round-key column, `rs2` its state column, `rd` the next
state column. One instruction advances a whole 128-bit state held one column per
lane across an aligned quad. No immediate: the four byte steps are enumerated
inside the instruction, so `sym_args_t` is unchanged and `INST_SYM_BITS` already
had room.

**The cross-lane network is a fixed byte transpose, not a crossbar.** Lane `j`
produces column `j`, which by ShiftRows takes byte `r` from column `(j+r)&3`,
and under this layout that column is in lane `(j+r)&3`. The source index is a
genvar expression -- `((i/4)*4) + ((i+r)%4)` -- so it elaborates to wiring:
sixteen bytes in, sixteen out, per quad, with no mux. Enumerating the four steps
also collapses the two 4:1 muxes the lane-local `aes32esmi` needs, `sel_byte` on
`bs` and `rol32` on `bs`, into constants.

**Convergence is an architectural precondition, not a convention.** Every lane
of a quad is read by every other, and neither model consults the source lane's
mask -- deliberately, so the two cannot drift the way `SHFL` currently does
(`VX_alu_int.sv:219` falls back to the reading lane, `alu_unit.cpp:291-296` does
not). Section 20.1 records what a divergent region costs here: a correct
counter, a correct lane mapping and a wrong cipher in every byte, silently.

Opt-in behind `VX_CFG_EXT_SYM_SG4_ENABLE`, and a build with `SIMD_WIDTH` not a
multiple of four fails elaboration by name -- Verilator reports
`%Error-MODMISSING: VX_sym_aes_sg4_requires_NUM_LANES_multiple_of_4` -- using
the same nonexistent-module trick as the XLEN guard, because `STATIC_ASSERT`
expands to nothing under `SYNTHESIS`.

It was correct on simx and on rtlsim at the first attempt, including with AAD,
and the two models return identical retired-instruction counts.

### 21.2 Measured

`c2w4t16`, `-n128 -b64`, rtlsim, one tree, with the per-hart stack skew of
section 19:

| | cycles | instrs | vs hw_s1 |
| --- | ---: | ---: | --- |
| hw_s1 (shipped) | 543,229 | 212,186 | |
| hw_s3, software routing | 691,665 | 479,618 | +27.3% cycles |
| **hw_s3f, fused round** | **379,655** | 252,978 | **-30.1% cycles**, +19.2% instrs |

Two runs at the recorded point return identical counts; simx reads 369,303, a
2.7% model gap.

**Against the software S3 the fused round removes 47.3% of the instructions and
45.1% of the cycles: r = 0.95.** That is the first arithmetic instruction
removal in this project to convert at all, let alone one for one. Every previous
one had the wrong sign -- `ghred32` -1.96% instructions for +10.2% cycles,
`rori` -24.4% for +13.8%, the `ilp` variant identical in count for +7.4%.

**And the GHASH half is still entirely software-routed.** The -30.1% is what the
AES half alone is worth.

### 21.3 The two fixes are not separable

The same instruction, the same kernel, without the stack skew:

| | cycles | vs hw_s1 |
| --- | ---: | ---: |
| hw_s3f, stack as shipped | 1,060,903 | **+82.9%** |
| hw_s3f, per-hart skew | 379,655 | **-30.1%** |

**On the machine as shipped the fused subgroup round looks like a 83%
regression. On the same machine with two instructions of startup changed it is a
30% gain.** Nothing else differs. Section 17 and section 18 each measured a
subgroup design on the first of those machines and ruled against it; this is why
those rulings were withdrawn, and it is the strongest possible statement of what
section 19's aliasing was costing.

### 21.4 What is now known, and what is still not

Known: the subgroup layout is buildable with a fixed byte transpose, it agrees
bit-exactly across both models, it requires a converged quad, and with the AES
round fused it is **30% faster than the kernel every ISA claim in this document
is measured against**, on a layout that also reads at a 97% D-cache hit rate
(section 20.3).

Not known, and this method cannot reach it:

- **Timing and area.** The fused datapath is four S-box instances and four
  MixColumns per lane where the shipped one has one of each, against two 4:1
  muxes recovered. `sym_aes` is 1,284 ALM per core at 16 lanes, 0.6% of a
  208,513-ALM design with 4.0% of period slack, so the area is affordable on
  paper -- but neither the fitter nor the timing analyser has seen it.
- **`ghmul.sg4`.** Built; see 21.5. With both instructions fused the kernel
  reaches 3.76x the shipped one.
- **Whether the recorded configuration should move again.** Every row in this
  document is measured without the stack skew; sections 19, 20 and 21 are the
  case for changing that, and it is not a decision to take inside a section.

### 21.5 `ghmul.sg4`: built, and the two fused instructions together are 3.76x

The GHASH half was the majority of what remained after 21.2, so it was built on
the same terms.

```
ghmul.sg4 rd, rs1, rs2      # custom-3 (0x7B), funct3 = 2
```

The quad's `rs1` and `rs2` are one 128-bit value each, a limb per lane; each lane
receives its limb of `A*H mod x^128+x^7+x^2+x+1`, in the same reflected limb
domain the software path uses, so the kernel's `brev8` conventions are untouched.
Sixteen 32x32 carry-less multiplies per quad -- **four per lane against the one
the lane-local path needs**, which quadruples the multiplier array of what
section 13.1 records as the largest crypto block.

Verified three ways on constant inputs: the RTL, simx and an independent
reference implementation all return `b34491b3 cc2389d5 e6fe8193 76a9fdbf` for
A = (0x11111111, 0x22222222, 0x33333333, 0x44444444), H = (0x01020304 .. 07).
Correct on both drivers with AAD, at the tree default and at `c2w4t16` where four
quads share a warp; two runs identical.

**Measured, and it is the largest result in this document.** `c2w4t16`,
`-n128 -b64`, rtlsim, stack skew on, one tree:

| | cycles | instrs | vs hw_s1 |
| --- | ---: | ---: | ---: |
| hw_s1, shipped | 543,229 | 212,186 | |
| hw_s3f, AES fused | 371,139 | 236,138 | -31.7% |
| **hw_s3g, both fused** | **144,612** | **96,658** | **-73.4% cycles, -54.4% instructions** |

**3.76x the shipped kernel**, on identical output, with both models agreeing on
retired counts and two runs identical. Per block, from a `-b8`/`-b64` marginal
fit: 15.2 cycles against the shipped kernel's 62.18, and 11.25 instructions
against 25.25.

Cycles fell further than instructions -- 73.4% against 54.4%, a conversion rate
of 1.35 -- which is the opposite of everything else measured in this project and
is what a layout with a 97% D-cache hit rate (20.3) does once the instruction
stream stops being the thing in the way.

### 21.6 Correction: the first version of 21.5 was wrong, and the bug was mine

The paragraph this replaced reported `ghmul.sg4` as a **regression**: -19.9%
against `hw_s3f`'s -31.7%, with 37% more retired instructions from a kernel 39%
smaller statically, attributed to clang declining to unroll a smaller loop body.

That was a bug in the probe kernel, not a code-generation effect. The routing
template selected the fused AES round with

```
if (ROUND == S3_ROUTING_FUSED)
```

and the both-fused kernel is `S3_ROUTING_FUSED_ALL`, so it took the `else` and
ran the **software** AES with three shuffles per round alongside the fused
multiply. It was never "both fused".

**What identified it was the instruction mix, not the disassembly.** Static
analysis went in circles for several rounds: loop sizes, unroll factors, spill
counts. The dynamic per-class counters settled it in one run -- `sym` was 25% of
the stream at 10.6 instructions per block, and the fused round issues 2.75, while
the software form issues exactly 4 `aes32` per round over ten rounds across four
lanes, which is 10.0. The arithmetic named the culprit.

The lesson worth keeping: **a per-class dynamic count discriminates where a
static instruction count cannot.** Sections 17 and 18 both spent effort on static
`sp`-relative counts and disassembly listings; in each case the counters would
have been faster.
## 22. S2 for AES-GCM: a stateful engine, built, measured, and fitted

S2 keeps the message-to-lane mapping of S1 -- one lane, one message, sixteen
messages per warp at t16 -- and moves the 128-bit state out of the
general-purpose registers into a per-lane context, so that one instruction
advances a whole AES round or a whole GHASH block update. Because the mapping is
unchanged, a comparison against `hw_s1` isolates instruction granularity from
data layout, which none of the S3 rows can do.

### 22.1 The instructions

Nine, on six decode slots of the two free custom opcodes. No new opcode.

| | funct3 | funct7[2:0] | rd | semantics |
| --- | ---: | ---: | --- | --- |
| `aes.cwr` | 3 | sel 0-7 | x0 | S0..S3 (0-3), K0..K3 (4-7) |
| `aes.crd` | 4 | sel 0-3 | data | rd = S[sel] |
| `aes.begin` | 5 | 0 | x0 | S ^= K; rnd = 1 |
| `aes.rndm` | 5 | 1 | x0 | K = NextKey(K,rnd); S = round(S,K); rnd++ |
| `aes.rndf` | 5 | 2 | x0 | as above without MixColumns |
| `ghash.cwr` | 2 | sel 0-7 | x0 | Y[sel] ^= rs1 (0-3), H[sel-4] = rs1 (4-7) |
| `ghash.crd` | 3 | sel 0-3 | data | rd = Y[sel] |
| `ghash.init` | 4 | 0 | x0 | Y = 0 |
| `ghash.block` | 4 | 1 | x0 | Y = Y*H mod P |

The round counter starts at 1, not 0, so that the first middle round produces K1
with Rcon[1]; starting it at zero is an off-by-one that the first draft had.

Everything but the two reads is encoded `rd = x0`. `VX_decode` already derives
writeback as `use_regs[RD] && rd != 0`, so no writeback and no scoreboard entry
are produced -- and therefore **ordering cannot come from the scoreboard**. The
units interlock instead. One global busy flag is enough, because the pipeline
into a unit is in-order and anything queued behind a multi-cycle op wants the
same hardware anyway; a per-warp interlock would be more machinery for no gain.

### 22.2 The context, and the two fields that left it

The context must be keyed by **(warp, lane)**, not lane alone: warps interleave
freely and a per-lane context would be clobbered by whichever issued last.

Two 128-bit fields were removed after the first build, without restricting what
the instructions can express:

- **X** is gone. `ghash.cwr` folds its limb straight into the accumulator, so
  four writes then `ghash.block` still computes `Y <- (Y ^ X)*H`, with no X to
  store and one array fewer in the pipeline's first stage.
- **The stored cipher key** is gone. `aes.cwr` writes the working round key
  directly and `aes.begin` no longer resets it from a K0. Software rewrites the
  key before each begin: four writes per block, 0.25 instructions per block
  amortised over sixteen lanes, and no extra loads because the key is already in
  registers.

Sharing one key per warp would have saved the same 256 bits and cost nothing in
instructions. **It was rejected.** It restricts a warp to sixteen messages under
one key, and batching records from different TLS sessions -- different keys in
the same warp -- is the case that makes a GPU worth using for AEAD at all. The
benchmark here happens to be single-key, so adopting that restriction would have
produced good numbers for an ISA that cannot do the general job.

Per (warp, lane): 772 bits down to 516; 49,408 per core down to 33,024.

### 22.3 Measured

rtlsim, c2w4t16, `-n128`, at the same two operating points the ChaCha section
uses: `b=2..8` is 4-16 KiB and fits the 16 KiB D-cache, `b=32..64` is
64-128 KiB and does not.

| | instrs/block | cycles/block, cache-resident | cycles/block, memory-bound |
| --- | ---: | ---: | ---: |
| `hw_s1` | 25.25 | 60.75 | 61.79 |
| `hw_s2` | **4.19** | **15.55** | **27.73** |
| `hw_s3g` | 11.25 | 11.03 | 14.90 |

Against `hw_s1`, S2 is **2.23x** at the memory-bound point and **3.91x** at the
cache-resident one, on **6.0x fewer instructions**. Both models retire identical
counts and agree with AAD and a partial tail.

Earlier drafts of this table had one column, fitted over `b=8..64`, and reported
2.10x. That span runs from 16 KiB to 128 KiB -- across the cache boundary, not
within either side of it -- so it averaged the two regimes into one slope and
hid the difference between them. The instruction counts are unchanged from that
draft, to the digit, and the memory-bound column reproduces its cycles within
1.7%; what is new is the left-hand column, which had never been measured.

The difference is the point. `hw_s1` barely notices the working set at all --
60.75 against 61.79, a 1.7% spread -- while `hw_s2` nearly doubles when the data
fits. Once the stateful engine has taken the register pressure away, what is
left is memory, and the row becomes sensitive to a size the software row is
indifferent to.

It still does not beat `hw_s3g`, at either point: 5.51x and 4.15x against S1.
The pre-registered kill rule therefore fires. What keeps the row interesting is
that `hw_s3g` does not close timing on the DE10-Pro, so the comparison is
against something that cannot ship.

### 22.4 Fitted: three builds, and the area estimate was wrong by 4.5x

DE10-Pro, `1SG280HU1F50E1VG`, 200 MHz Vortex clock, 250 MHz PCIe avst512:

| | ALMs | registers | Vortex | PCIe |
| --- | ---: | ---: | ---: | ---: |
| baseline | 208,513 | 377,741 | 208.29 | 263.44 |
| SG4 | 260,938 +25.1% | 452,906 | 206.91 | **226.04** |
| S2, single-cycle | 294,216 +41.1% | 560,788 | **130.82** | **223.71** |
| S2, pipelined | 299,907 +43.8% | 562,705 | 205.72 | 265.67 |
| S2, reduced context | 286,974 +37.6% | 530,318 | 207.68 | **249.94** |

The estimate written before the first run was **+19,000 ALMs**. The measurement
was **+85,703**. The estimate priced the arithmetic -- one shared 128x128
multiplier instead of sixteen, a quarter of the S-box array -- and treated the
context storage as an afterthought, which is exactly backwards: registers rose
by 183,047 and that is the bulk of the increase. **Time-multiplexing saves
arithmetic; it cannot save storage, because every (warp, lane) context has to
exist at once.**

The structural point, and the one that separates S2 from S3:

> S3 keeps the 128-bit state in the register file that already exists. S2 has to
> build a second one.

`aesrm.sg4` is purely combinational and costs no flip-flop; the S2 engines cost
one context per warp per lane whatever else is done.

The context model itself is accurate. Removing 32,768 bits of context was
predicted to remove 32,768 registers; the measurement was **-32,387**, within
1.2%. Bits of context and flip-flops are one to one.

### 22.5 The frequency failure, and what fixed it

The single-cycle build ran the Vortex clock at **130.82 MHz** against a 200 MHz
requirement. All two hundred of the worst setup paths were inside
`VX_auth_ghash`; **none** were inside `VX_sym_aes`.

That asymmetry names the cause. Both engines read the same kind of context, but

- the AES engine's lanes each read their **own** entry: the lane index is a
  genvar, so only the warp is muxed, four to one;
- the GHASH engine walks the lanes with a **counter**, so its read is a 64:1
  mux, and it then hangs an entire GF(2^128) multiply off the end of it.

The AES round already split its work across four cycles, one output column each.
The GHASH engine had split only the lane loop, not the arithmetic.

Pipelining `ghash.block` three deep -- the read mux alone, then the multiply
array, then the fold and the writeback -- restored **205.72 MHz**, and cost
nothing measurable: throughput stays one lane per cycle, so the instruction goes
from NUM_LANES to NUM_LANES+2 cycles, and rtlsim reads 74,168 cycles at
`-n64 -b4 -t5 -a20`, byte-identical to the single-cycle version. The unit holds
the pipe for 16 of the ~441 cycles a block-step takes.

Half of `VX_auth_ghash`'s registers were retiming artefacts, not architectural
state: 98,457 against the 49,152 its context needs, while `VX_sym_aes` carried
56,394 against a predicted 56,832, a 3% match. Pipelining returned 29,046 of
them. **The area and the frequency failures were two faces of one broken path.**

### 22.6 The PCIe domain, and the causal story that turned out to be wrong

Every build that fails, fails on the PCIe `avst512` 250 MHz domain, whose paths
are all inside Platform Designer's `mm_interconnect` -- the BAM master's
waitrequest-allowance adapter FIFO, `out_payload[604]` into its M20K inputs.
Nothing in Vortex, nothing in the crypto units.

250 MHz is not a choice. Gen3 x16 is 128 Gb/s and the application interface is
512 bits wide, so 128e9/512 = 250 MHz exactly, generated by the hard IP's own
IOPLL. Unlike the Vortex clock, which carries four profiles in the
reconfiguration MIF, it cannot be lowered without dropping to x8 or Gen2 and
halving bandwidth. And a negative setup slack there is a functional hazard on the
path the host uses to load kernels and buffers, not a "runs slower".

The story used for several sections was **area displacement**: the design grows,
the fitter spreads logic, the interconnect's already-thin margin is stretched.
Three measurements say that story is wrong.

| build | area | PCIe |
| --- | ---: | ---: |
| SG4 | +25.1% | 226.04 |
| S2, single-cycle | +41.1% | 223.71 |
| S2, pipelined | **+43.8%** | **265.67** -- best of all, better than baseline |
| S2, reduced context | +37.6% | 249.94 |
| S2, reduced, seed 7 | +37.6% | **207.64** |

The **largest** design has the **best** PCIe result. And a seed change alone, at
0.2% area difference, moves the domain by **0.815 ns** -- from -0.001 to -0.816.

So: the domain is insensitive to area and violently sensitive to placement. The
single-cycle build's PCIe failure is better explained as the fitter spending
itself on a -2.644 ns Vortex path and letting everything else degrade; the SG4
build's failure, whose Vortex clock was fine, has no explanation here yet.

**A seed sweep is not a fix.** With a 0.815 ns spread, seed 6's -0.001 is already
a good draw and further draws are a lottery. The remedies left are on the FPGA
project's side of the boundary: a pipeline stage in the Qsys interconnect, at one
cycle of DMA latency, or a LogicLock region pinning the PCIe shell near its hard
IP. Note that **the pipelined build closes every domain**, so a working bitstream
for S2 exists today at 299,907 ALMs.

### 22.7 What this section got wrong, and how

Kept because the errors are the most transferable part.

- **"+19,000 ALMs."** Measured +85,703. The estimate priced arithmetic and
  discounted storage, having written in the same paragraph that storage might
  dominate and that extrapolation could not settle it -- and then used the number
  anyway.
- **"2.80x against the shipped kernel."** That came from simx with the
  interleaved layout. rtlsim says **2.18x**. It was used to argue for building
  the RTL.
- **"S2 is memory-bound, and interleaving the payload fixes it."** simx showed
  the layout helping S2 by 22% and hurting `hw_s1` by 77%, and the sign of that
  asymmetry was the whole argument. On rtlsim, interleaving **hurts** S2 by 4.4%.
  The diagnosis was withdrawn. The memory-bound reading was later re-established
  on rtlsim by a different route -- 94% scoreboard stall on 252-cycle loads -- but
  the layout claim never reproduced.
- **"Do not build the RTL."** Reasoned from a kill rule that compares against
  `hw_s3g`, a design that does not close timing. Comparing against something that
  cannot ship is not a reason to stop.


## 23. ChaCha20-Poly1305 gets S1, S2 and S3, and the ordering is the opposite of AES-GCM's

Everything before this section is AES-GCM. The second baseline had only S0, and
a taxonomy with one algorithm in it cannot tell a property of the design from a
property of the algorithm. This section fills the other three tiers.

All numbers are rtlsim, c2w4t16, marginal over the block count, at **two
operating points**: `b=1..4`, where the working set is 4-16 KiB and fits the
16 KiB D-cache, and `b=16..32`, where it is 64-128 KiB and does not. Measuring at
one point only cannot distinguish an extension that does not help from a size at
which nothing helps -- which is precisely how the `rori` row below was
misread once. Section 22.3 now uses the same two points, at `b=2..8` and
`b=32..64`, a ChaCha block being 64 bytes against AES-GCM's 16; the grid is in
payload bytes so that the two algorithms answer the same question.

**Every row here comes from one build per algorithm**, with the tier selected by
the application's `-i` flag. ChaCha was brought up in three narrower builds --
S1 alone, S1 plus S2, S1 plus the subgroup pair -- and for several drafts these
tables came from all three, each carrying its own `s1` row as an anchor against
build-to-build drift. That is no longer necessary and no longer done: the all-on
build runs every implementation, compiles byte-identical code, and reproduces
every tier inside the noise floor. One build removes the cross-build comparison
rather than correcting for it. Area and Fmax are the opposite case and are still
synthesised per feature, because what a design costs is what it costs alone.

The baseline for every comparison is the `rori` row, not `sw`. RORI is ratified
Zbb/Zbkb; crediting the B extension to a cryptographic ISE would be false.

**A noise floor applies across the tables below, and it is not one number: it is
about 3% at the memory-bound point and about 9% at the cache-resident one.**

Instruction count is architectural and reproduces exactly. Cycle count does not:
it carries variation from where the compiler happened to place a kernel, the
mechanism recorded in sections 18 and 21.6. The floor differs between the two
operating points because a marginal fit amplifies whatever error its endpoints
carry. For a fit over `[lo, hi]` the slope's relative error is roughly the
endpoints' own, multiplied by `(c_lo + c_hi) / (c_hi - c_lo)`: the closer the two
cycle counts, the larger the factor. Measured here:

| | `mac` | `rori` | `s1` | `sw` | `xr` | `s3` | `s3f` | `s2` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cache-resident `1..4` | 3.1x | 3.4x | 3.1x | 3.3x | 3.3x | 5.8x | 5.9x | **8.1x** |
| memory-bound `16..32` | 3.6x | 3.4x | 3.1x | 3.2x | 3.3x | 4.4x | 4.6x | 3.5x |

The factor is worst for the *fastest* kernels, which is where the headline claims
live: a small marginal sits on the same per-message setup cost as a large one, so
it is a smaller fraction of both endpoints.

The measurement behind those numbers is `tests/crypto/probe_build_merge.yaml`,
which runs every implementation in the all-on build and compares it against the
three narrower ones. The code is identical -- every instruction count matches to
the digit -- and per-run cycles differ by at most 2.7%. Yet the cache-resident
fits of that identical code diverge by up to 13.9%, on `s2`, whose amplification
factor is 8.1x. At the memory-bound point the largest divergence is 2.9%.

Two consequences. A cache-resident difference under about 9% is not a difference,
and `chacha32.xr`'s 1% below is exactly that. And a fit's two points must come
from one build -- which, now that each algorithm has only one, they do by
construction.

### 23.1 S1: two instructions, and the useful one costs more instructions

```
chacha32.xr rd, rs1, rs2, rot        rd = rol32(rs1 ^ rs2, rot)
poly26.mac{l,h}{,5} rd, rs1, rs2, rs3
```

`chacha32.xr` goes to the **rotate** PE beside RORI, not the AES one. It carries
no S-box, no field arithmetic and no algorithm constant -- the only extension in
this document that does not -- because ChaCha's software form is already
add/xor/rotate and the one thing left to fuse is the pair the quarter-round
always performs together. `rot` is a **left** amount, unlike RORI's right amount
in the same field, because that is how ChaCha is specified.

`poly26.mac` is R4-type, the shape WGATHER already uses, so rs3 costs no new
operand path: the collector fetches three sources and the scoreboard tracks rs3
today. This corrects an assumption made earlier in the design discussion, that
the machine was 2R1W and a true multiply-accumulate could not be expressed.
funct2 selects `{scale5, high_part}` over one datapath, and the two halves
accumulate into separate registers, recombined once per output limb -- exact, not
approximate: the low accumulator sums the products modulo 2^26 and the high one
sums their quotients.

The `scale5` forms are not a convenience. The reduction's wrapped terms carry a
factor of five and the usual `s_i = 5*r_i` precompute reaches 2^28.3, which a
26-bit operand cannot hold, so without them the key needs nine registers instead
of five.

| | instrs/block | cycles, cache-resident | cycles, memory-bound |
| --- | ---: | ---: | ---: |
| `sw` | 162.3 | 864.4 | 788.0 |
| `rori` | 123.0 | 801.0 | 769.7 |
| `xr` | 102.9 **-16%** | 777.2 -3.0% | 764.0 -0.7% |
| `mac` | 135.5 **+10%** | 601.7 **-24.9%** | 453.2 **-41.1%** |
| `s1` | 75.5 **-39%** | 492.5 **-38.5%** | 470.5 **-38.9%** |

**1.64x**, and the contribution splits cleanly: at both points the ChaCha half
contributes nothing and the Poly1305 half contributes everything. `poly26.mac`
alone is 1.70x at the memory-bound point, marginally *better* than the pair, so
adding `chacha32.xr` to it buys nothing measurable -- the 3.7% between them is
inside the floor at either point.

### 23.2 Why `chacha32.xr` buys almost nothing, and `poly26.mac` buys everything

The per-class counters at `-n64 -b32` settle it, and one row is bit-identical:

| | `rori` | `xr` | `mac` |
| --- | ---: | ---: | ---: |
| instructions | 258,908 | 216,540 -16% | 285,876 **+10%** |
| cycles | 1,751,046 | 1,648,878 | 1,057,384 **-40%** |
| **loads** | **215,104** | **215,104** | 141,184 **-34%** |
| **stores** | **92,480** | **92,480** | 80,256 |
| load latency | 233.89 | 232.67 | 153.37 |
| scoreboard stall | 94% | **97%** | 87% |

`xr` changes the instruction stream and **nothing about memory** -- its loads and
stores are the same integers, not merely similar. Both operands of the fused
xor-rotate were already live and the result goes back to one of them, so the live
set is unchanged. Deleting 16% of a stream that is 94% stalled on 234-cycle loads
deletes instructions that were executing in the shadow of a stall; the stall
fraction rises to 97% because there is less left to fill it with.

`poly26.mac` removes the four `s_i` registers and the 64-bit intermediates.
Loads fall 34% and the load latency falls by the same 34% -- fewer spill
accesses leave more of the D-cache for the payload.

> **The instruction that helps is the one that costs more instructions.**

### 23.3 S3: the layout loses, and fusing its traffic is worth 22 points

A quad owns one message. ChaCha's 4x4 state puts one column in each lane, so a
column round is entirely lane-local and a diagonal round is the same round with
rows 1, 2 and 3 rotated across the quad.

Poly1305 cannot be split by limb -- 130 bits does not divide by four, and a
five-lane subgroup would not align to a power of two, so its cross-lane routing
would stop being a fixed permutation and become a general network. It is split by
**block** instead:

```
h4 = (h0 + m1) r^4 + m2 r^3 + m3 r^2 + m4 r   (mod 2^130-5)
```

and one 64-byte ChaCha block is exactly four Poly1305 blocks, which is exactly
the quad width. Lane c takes m_{c+1} and r^{4-c}. The accumulator is kept
**replicated** in all four lanes -- the cross-lane sum is a butterfly, so every
lane ends with the same h and the serial parts, AAD and tail and length block,
need no broadcast.

The fused row adds three encodings, one of which is a bit on an existing
instruction:

```
chadd.sg4 rd, rs1, rs2      rd = rs1 + rs2 from the next lane of the quad
chacha32.xr funct7[5]       the same routing on the existing xor-rotate
poly26.rsum.sg4 rd, rs1     rs1 summed across the quad, into every lane
```

One route direction covers the whole diagonal round. Its D operand lives in lane
j+3 and reads A from lane j, and -3 == +1 mod 4, so **all eight reads are from
lane +1** and the source index is a constant permutation within an aligned four --
wires, not a crossbar.

| | instrs/block | cycles, cache-resident | cycles, memory-bound |
| --- | ---: | ---: | ---: |
| `s1` | 75.5 | 492.5 | 470.5 |
| `s3` probe | 110.0 **+46%** | 587.4 +19.3% | 487.7 +3.7% |
| `s3f` fused | 90.5 **+20%** | 466.1 -5.4% | 368.5 **-21.7%** |

All three rows come from one build, measured after the optimisations of 23.7.
Earlier drafts of this table mixed a `s3f` row from one build with `s1` and `s3`
rows from another, which is exactly the error the noise-floor note above warns
about; with a single build per algorithm that class of error is now structurally
impossible rather than merely avoided.

The layout by itself loses. Fusing its cross-lane traffic is worth **twenty-five
percentage points** and turns it into a 1.28x win -- while still retiring 20%
more instructions than S1. The twenty-five points are the gap between the probe
and the fused row at the memory-bound point, a 24.4% reduction; `s3f`'s own
-5.4% against `s1` at the cache-resident point is inside the floor there and
should be read as no measurable difference. The -21.7% at the memory-bound point
is where this row earns its result.

Stores again: 78,208 for `s1`, 75,520 for the probe, **49,920** for the fused
row. Each of the six explicit rotations per double-round produced a value that
had to stay live; fused, nothing moves at all and each lane merely reads its
neighbour.

### 23.4 S2: 3.87x, and the best row until section 23.5

Four instructions on one funct3 of custom-1, because a sixteen-word state needs
four bits of selector and the crypto opcodes' three-bit field could not hold it.

```
chacha.cwr rs1, sel     sel 0..7 key, 8..10 nonce; once per message
chacha.begin rs1        rs1 is the block counter
chacha.dr               one double-round, eight quarter-rounds
chacha.crd rd, sel      x[sel] + init[sel]
```

The engine keeps the key and the nonce, so `begin` rebuilds the initial state
from a counter and **a block costs no context writes at all**; `crd` folds
ChaCha's feed-forward into the read, so there is no final instruction and no
shadow copy of the initial state. A double-round takes eight cycles, one
quarter-round per cycle: the arithmetic is one quarter-round wide per lane rather
than eight.

| | instrs/block | cycles, cache-resident | cycles, memory-bound |
| --- | ---: | ---: | ---: |
| `s1` | 75.5 | 492.5 | 470.5 |
| `s2` | **28.9 -62%** | **88.0 -82%** | **121.7 -74%** |

**3.87x** at the memory-bound point, and **5.60x** at the cache-resident one --
this row, like AES-GCM's S2, is the one that starts caring about working-set
size, because the stateful engine has moved the bottleneck to memory. Better than
AES-GCM gets from S2 (2.23x and 3.91x), and the best row this AEAD had until the
subgroup was widened to match its state: section 23.5 returns 4.98x on a sixth
of the area and without the 57,344 bits of context this row needs.

### 23.5 S3 at sixteen lanes: the subgroup width is the state width

Section 23.3's S3 uses four lanes because AES-GCM's does, and it returns 1.25x
where AES-GCM's returns 4.15x. That asymmetry was read for several drafts as a
property of the algorithm -- ChaCha20's diagonal step is a write-side state
move, so only its routing folds into arithmetic and not its arithmetic. The
reading is right about the mechanism and wrong about the conclusion, and the
thing it missed is that a subgroup does not have to be four lanes wide.

AES-GCM's block state is 128 bits, which is four 32-bit lanes. ChaCha20's is
512, which is sixteen. Matching the subgroup to the state rather than to the
other algorithm's subgroup gives:

    chacha.dr.sg16   rd, rs1              one aligned sixteen-lane subgroup
                                          holds one 512-bit state, lane i
                                          carrying word i, and one instruction
                                          advances a full double-round
    poly4.step.sg16  rd, rs1, rs2, rs3    the same subgroup absorbs a whole
                                          64-byte ChaCha block -- four Poly1305
                                          blocks -- in one instruction

Both are single-destination and hold no context between instructions.

| | instrs/block | cycles, cache-resident | cycles, memory-bound |
| --- | ---: | ---: | ---: |
| `s1` | 75.5 | 478.8 | 460.6 |
| `s3f`, four lanes | 90.5 | 487.6 **+1.8%** | 368.3 **-20.0%** |
| `s2`, stateful | 28.9 | 95.4 **-80.1%** | 121.8 **-73.6%** |
| **`sg16`, sixteen lanes** | **49.0** | **83.4 -82.6%** | **92.6 -79.9%** |

**4.98x against S1**, against S2's 3.78x and the four-lane S3's 1.25x. The tier
ordering this document reported for ChaCha20-Poly1305 inverts: S3 is its best
row, as it is AES-GCM's, and the two algorithms stop disagreeing.

What replaces the asymmetry is a rule with more in it. Both designs process 64
bytes per warp with about ten round instructions and one authentication
instruction; AES-GCM does it as four lanes on each of four 16-byte messages,
ChaCha20-Poly1305 as sixteen lanes on one 64-byte message. **The subgroup width
that works is the one that matches the algorithm's block state.** Section 23.5's
two rules survive intact -- S3 still pays when cross-lane traffic folds into
arithmetic -- but the width at which to ask the question is not a constant.

#### What it costs

| | ALMs | vs baseline | Vortex domain | PCIe domain |
| --- | ---: | ---: | ---: | ---: |
| baseline | 208,513 | | +0.001 | +0.002 |
| `s3f`, four lanes | 219,921 | +11,408 | +0.000 | **-0.352** |
| **`sg16`** | **223,209** | **+14,696** | **+0.000** | **+0.002** |
| `s2`, stateful | 299,907 | +91,394 | +0.000 | +0.001 |

**Six times cheaper than S2 and faster than it**, and the only one of the three
that closes both clock domains. The area difference is not subtle and it is not
a surprise: S2's 57,344 bits of per-(warp, lane) context are most of what it
costs, and this design does not have them.

Which is the claim to make carefully, because it is not "no state". There are
three kinds here and they are worth separating:

| | AES-GCM S3 | ChaCha `sg16` | ChaCha S2 |
| --- | ---: | ---: | ---: |
| architectural context, per (warp, lane) | 0 | **0** | 57,344 bits |
| internal working registers, per subgroup | 0 | **1,154 bits** | -- |
| survives between instructions | -- | no | **yes** |
| needs zeroize, owner, valid semantics | no | **no** | **yes** (section 24) |
| occupies its unit for more than a cycle | no | **yes** | yes |

`sg16` has no architectural context and so needs none of section 24's lifetime
apparatus, which is the security-relevant difference. It does have working
registers, and a unit that holds them cannot accept another warp's instruction
while it runs.

That last fact costs nothing here, which took building the alternative to find
out. `chacha.dr.sg16` was rewritten as an eight-stage pipeline accepting one
instruction per cycle, on the reasoning that ten blocking cycles per instruction
were keeping three other warps out. The pipelined version is 1.1% *slower* on
total cycles at four warps and 1.4% slower at eight, and the reason is in the
instruction mix: SYM instructions are 8% of the kernel and the unit runs at
about 13% occupancy. It was never the bottleneck.

What limits this row is that a warp's ten double-rounds are serially dependent.
While one warp waits out its own chain the others are waiting out theirs, so
blocking excludes nothing that was going to arrive. The pipeline bought 4,096
bits of stage registers and no cycles, and was reverted. Doubling the warp count
buys 12%, which is the part that does overlap.

The floor is therefore the per-warp latency times the chain length, divided by
whatever warp count is available to hide it -- not unit throughput. Shortening
`chacha.dr.sg16` below ten cycles, or giving a warp two independent blocks to
interleave, are the changes that would move it. Pipelining is not.

#### The encoding ran out

The four-bit SYM op_type space is full: all sixteen values are taken.
`chacha.dr.sg16` shares `cha.dr`'s slot, and the two are refused together by
`ci/gen_config.py` -- safe, because a stateful per-lane engine and a
sixteen-lane subgroup are competing answers to one question and no machine
carries both. Widening the field means editing 105 constants and every
functional unit in the machine.

This is a finding and not a workaround. A cryptographic extension of this size
does not fit four bits, and the instruction after this one has nowhere to go.


### 23.6 Two rules, and they are orthogonal

Every row below is one build per algorithm, the tier selected with `-i`, at the
same four payload sizes. Against each algorithm's own S1, at the memory-bound
point:

| | S0 | S1 | S2 | S3, four lanes | S3, matched width |
| --- | --- | --- | ---: | ---: | ---: |
| AES-GCM | yes | baseline | 2.23x | **4.15x** | -- |
| ChaCha20-Poly1305 | yes | 1.64x | 3.87x | 1.28x | **4.98x** |

AES-GCM's S3 already is at its matched width: its block state is 128 bits and
its subgroup is four 32-bit lanes. ChaCha20-Poly1305's is 512 bits, and section
23.5 is what happens when the subgroup is sixteen lanes instead of four.

**S3 is the best row for both algorithms**, which an earlier draft of this
section denied. It reported the optimum at a different tier for each and read
that asymmetry as the result -- AES to S3, ChaCha to S2. The asymmetry was in
the subgroup width, not in the algorithms: at four lanes ChaCha's S3 returns
1.28x, at sixteen it returns 4.98x, and nothing about the algorithm changed
between those two rows.

At the cache-resident point the stateful and subgroup rows pull further ahead --
3.91x for AES-GCM's S2, 5.60x for ChaCha's, 5.74x for `sg16` -- because those
are the tiers at which the bottleneck becomes memory. The S0 and S1 rows barely
move between the two points.

**Those speedups are each against their own baseline and must not be read across
the row.** AES-GCM's block is 16 bytes and ChaCha20's is 64, so a cycle count per
block means something four times different on each line. Normalised, at the
memory-bound point:

| | cycles/byte |
| --- | ---: |
| AES-GCM, `sw_ttable` | 70.86 |
| ChaCha20-Poly1305, `sw` | 12.31 |
| ChaCha20-Poly1305, `rori` | 12.03 |
| ChaCha20-Poly1305, S1 | 7.35 |
| ChaCha20-Poly1305, S3 fused | 5.76 |
| AES-GCM, S1 (`hw_s1`) | 3.86 |
| **ChaCha20-Poly1305, S2** | 1.90 |
| AES-GCM, S2 (`hw_s2`) | 1.73 |
| **ChaCha20-Poly1305, S3 sixteen-lane** | **1.45** |
| **AES-GCM, S3 (`hw_s3g`)** | **0.93** |

So the best AES-GCM row is **1.56x faster per byte** than the best
ChaCha20-Poly1305 row, which the per-block figures hide entirely -- 4.15x and
4.98x sit next to each other and read as ChaCha winning. It does not: a ChaCha
block is four times an AES-GCM one, so a speedup against its own baseline says
nothing about the comparison across the two.

The second observation is worth as much as the first, and it has to be stated in
both directions or it misleads. Software against software, ChaCha20-Poly1305 is
**5.8x faster per byte than AES-GCM** -- 12.31 against 70.86 -- which is the
result anyone would expect: ChaCha20 was designed to be fast without hardware
help. Software against *hardware*, ChaCha20-Poly1305's software row is **3.2x
slower per byte than AES-GCM's S1**, and that is the comparison that matters
here, because the S1 datapath is a handful of ALMs a SIMT machine may well
already carry. ChaCha20 is fast on general-purpose CPUs precisely because they
have wide SIMD and lack AES hardware; once the AES datapath exists, the
advantage inverts. An earlier draft quoted only the second figure and read it as
ChaCha20 being slow, which it is not.

**S2 pays in proportion to the state it evicts from the register file.** AES
holds four words of state and four of round key, and RV32 has room; its S2
removes instructions only, and returns 2.23x. ChaCha holds sixteen words plus
sixteen more for the feed-forward, which is the entire register file; its S2
removes instructions **and the largest spill source in the kernel**, and returns
3.87x. It is the only row in this document where instruction count and cycle count
move together, and that is why.

**S3 pays when the cross-lane traffic can be folded into arithmetic.** AES's
ShiftRows is a **read-side permutation** -- output column j takes byte r from
column (j+r)&3 and each lane writes only its own output -- so it folds into
`aesrm.sg4` as free wiring; GHASH's operands are spread one limb per lane, so the
gathering folds into `ghmul.sg4`. Together, 4.15x. ChaCha's diagonal step is a
**write-side state move**: a quarter-round produces four results in four
different lanes, which one write port cannot express, so only the routing folds
and the arithmetic stays where it was. 1.28x -- at four lanes.

The rule holds; the width at which to apply it does not follow from the other
algorithm. Give ChaCha20 a subgroup as wide as its state and the same
write-side move becomes expressible, because the four results of a
quarter-round land in four lanes the instruction already owns. 4.98x, section
23.5. A quarter of the area of the stateful engine that this document spent
sections 23.4 and 24 on, and none of its context.

These are rules a third algorithm can be measured against, which a list of
speedups is not.

### 23.7 Fitted, and the same mistake twice

The stateful ChaCha20 engine was built flat first: one quarter-round per cycle,
eight cycles per double-round. The Vortex clock fell to **-2.752 ns**, worse than
the GHASH engine's first attempt, with **all sixty** of the worst paths inside
`VX_sym_chacha` and none anywhere else.

The prediction written before that run was that it would pass, on the grounds
that this engine has no 64:1 lane mux with a whole field multiply hanging off it.
Two things were missed. The state word indices come from the step counter rather
than a genvar, so each lane does four **16:1** reads and four decoded writes; and
a quarter-round is **eight strictly dependent steps** -- add, xor-rotate, add,
xor-rotate, twice -- where an AES round is one S-box and an XOR tree deep. The
lane loop had been split and the arithmetic left whole, which is precisely what
the GHASH engine had done.

Splitting the quarter-round two deep restored **205.63 MHz**. Throughput stays
one quarter-round per cycle, so a double-round costs ten cycles rather than
eight, and rtlsim reads 188,196 cycles against the flat version's 189,168 -- the
two extra cycles are not merely cheap, they are below the noise.

The pipeline needed a bubble the schedule did not obviously want. Quarter-rounds
0-3 touch disjoint columns and 4-7 disjoint diagonals, but the last column round
**writes x[15] and the first diagonal round reads it**, so issuing them back to
back would read the stale word. A static check of the eight index sets found it
before the build; it would otherwise have been the third bug this month whose
instruction count, cycle count and timing were all correct and whose only symptom
was a wrong ciphertext.

Eight fitter runs now exist, and sorted by area they settle the PCIe question:

| ALMs | PCIe avst512 slack |
| ---: | ---: |
| 208,513 baseline | **+0.204** |
| 260,938 SG4 | -0.424 |
| 281,666 ChaCha S2, flat | -0.130 |
| 286,974 AES S2, reduced | -0.001 |
| 287,512 the same, seed 7 | -0.816 |
| 289,353 ChaCha S2, pipelined | -0.374 |
| 294,216 AES S2, single-cycle | -0.470 |
| **299,907 AES S2, pipelined** | **+0.236** |

There is no relationship. The **largest** design is the only one that closes, and
two builds 0.2% apart in area differ by 0.815 ns. The domain is a placement
lottery, and every statement in earlier sections attributing its failure to area
growth is withdrawn. It is fixable only on the FPGA project's side -- a pipeline
stage in the Qsys interconnect, or a LogicLock region for the PCIe shell.

The context model, by contrast, held on a second algorithm. ChaCha's context is
114,688 bits across two cores and the flat build's register increase was
**+117,386**, within 2.4%. Taken with the AES measurement -- 32,768 bits removed,
32,387 registers removed, within 1.2% -- **the flip-flop cost of an S2 design can
be computed from its context definition before any RTL is written.** The ALM
figure cannot: 310,000 was predicted and 281,666 measured, 9% out.

### 23.8 S3, pushed as far as it goes

Three attempts at the fused S3 row after the first measurement:

| change | effect |
| --- | --- |
| select r^k progressively instead of computing all four and choosing | helps |
| drop the six rotate descriptors, dead once the routing is fused | helps |
| outline the once-per-message AAD absorb behind `noinline` | **+13.9%, reverted** |

The first two cut static stack accesses from 213 to 176, below `s1`'s 189, and
simx by 10.1%. **rtlsim moved from 1.26x to 1.28x and no further**: dynamic loads
went *up*, 159,616 to 163,968, while stores fell 49,920 to 46,080. Static spill
sites again failed to predict dynamic load traffic, as they did in sections 17
and 21.6.

The third is worth keeping as a result. Outlining trades a long live range for an
**ABI spill at the call boundary**: the block loop must save and restore its
whole live set around a call that runs once per message. On a machine whose
cycles are set by load traffic, moving code out of a hot loop is not the same as
moving data out of it.

At the instruction level, `poly26.rsum.sg4` could take the incoming carry as a
third operand and fold the per-limb carry add into the reduction. It saves five
instructions per block-quad, 1.25 per block against an implementation that costs
90 -- under 1.4% -- for a three-source encoding and a wider PE. It was not built.

The real limit is neither implementation nor encoding. Block-parallel Poly1305
requires each lane to hold five limbs of its own r^{4-c}, and that is inherent to
the decomposition. The only way to remove those registers is to put them in a
context, and that is S2, which already returns 3.87x.

### 23.9 What this section got wrong

- **"Poly1305 barely has an S1."** Argued from a machine model that was wrong:
  the tree is not 2R1W and WGATHER already reads rs3. `poly26.mac` turned out to
  be the only instruction in this AEAD that matters.
- **"ChaCha-Poly S3 should not be built."** The probe does lose. The fused row
  wins by 20.5%.
- **"The fused S3 instructions should not be built either."** They are worth 22
  percentage points.
- **"The S3 probe makes loads 6.6x worse."** It was written with `l[5]`, `u[5]`
  and loop indices, and the compiler put them on the stack: 165.5 instructions
  per block and 926,336 loads. Scalarised to `l0..l4` it retires 111.2 and 164,736.
  The S1 `mac` path had been written with named scalars for exactly this reason
  and `ghash_step_sg4` had been scalarised for it before that. **A bad result that
  is internally consistent -- a full profile, a plausible mechanism, and the
  opposite sign to the prediction -- is the kind most worth re-checking against
  one's own implementation.**
- **"6.0x for S2."** Arithmetic error: the wrong block delta. It is 3.87x. The
  commit was amended from the raw rows rather than from the derived figure.
- One functional bug survived every performance measurement: the ChaCha engine's
  first RTL build indexed the key with `csel[2:0]` where it needed `csel-4`,
  rotating the eight key words by four. Instruction count, cycle count and timing
  were all correct; only the known-answer test failed.

