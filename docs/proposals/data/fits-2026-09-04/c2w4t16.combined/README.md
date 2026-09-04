# c2w4t16

| | |
| --- | --- |
| Cores | 2 |
| Warps | 4 |
| Threads per warp | 16 |
| Built | 2026-09-03 20:32:40 |
| Wall clock | 01:13:45 |
| Device | 1SG280HU1F50E1VG |
| Quartus | Version 19.2.0 Build 57 06/24/2019 SJ Pro Edition |
| FPGA project | ddr4a-board-pass-37-g08b5d33 |
| vortexCrypto | v3.0-592-gd97c021cd |

The rest of the profile is fixed by prepare_project.sh: RV32, one
cluster, F and D disabled, three-cycle I-cache and D-cache,
one platform-memory bank without interleaving, 200 MHz initial Vortex
clock with 100/125/200/250 MHz profiles in the bitstream. Only the
200 MHz profile is covered by timing analysis; the others are
reachable at runtime but were not signed off.

## Host runtime

The runtime must be built with the same profile as the bitstream:

```sh
DE10PRO_CONFIGS='-DVX_CFG_NUM_CLUSTERS=1 -DVX_CFG_NUM_CORES=2 -DVX_CFG_NUM_WARPS=4 -DVX_CFG_NUM_THREADS=16 -DVX_CFG_EXT_F_DISABLE=1 -DVX_CFG_EXT_D_DISABLE=1 -DVX_CFG_ICACHE_LATENCY=3 -DVX_CFG_DCACHE_LATENCY=3 -DVX_CFG_PLATFORM_MEMORY_NUM_BANKS=1 -DVX_CFG_PLATFORM_MEMORY_INTERLEAVE=0 -DVX_CFG_PLATFORM_CLOCK_RATE=200'
make -C sw/runtime de10pro CONFIGS="$DE10PRO_CONFIGS"
```

## Programming

From this directory:

```sh
./program.sh          # override the JTAG cable with CABLE=2
```

## Timing

The four worst clock domains; the full list is in
`vortex_g3x16_ddr4x4.sta.summary`.

```
Type  : Slow 900mV 100C Model Setup 'u_pcie_ddr4_system|dut|dut|hip|altera_avst512_iopll|altera_ep_g3x16_avst512_io_pll_s10_outclk0'
Slack : -0.397
TNS   : -16.077

Type  : Slow 900mV 100C Model Setup 'u_pcie_ddr4_system|emif_s10_ddr4a|emif_s10_ddr4a_phy_clk_l_1'
Slack : 0.041
TNS   : 0.000

Type  : Slow 900mV 100C Model Setup 'u_pcie_ddr4_system|emif_s10_ddr4a|emif_s10_ddr4a_phy_clk_l_2'
Slack : 0.078
TNS   : 0.000

Type  : Slow 900mV 100C Model Setup 'u_pcie_ddr4_system|vortex_iopll|vortex_iopll_outclk0'
Slack : 0.196
TNS   : 0.000

```

Clock domains with negative slack: **5**

Worst-case DDR4 EMIF margins, from the per-interface summaries:

| Interface | Worst setup margin (ns) | Path |
| --- | ---: | --- |
| emif_s10_ddr4a | 0.003 | Read Capture (1 Slow vid1 100C Model) |

## Resources

```
Fitter Status : Successful - Thu Sep  3 20:29:26 2026
Quartus Prime Version : 19.2.0 Build 57 06/24/2019 SJ Pro Edition
Revision Name : vortex_g3x16_ddr4x4
Top-level Entity Name : vortex_de10pro_top
Family : Stratix 10
Device : 1SG280HU1F50E1VG
Timing Models : Final
Logic utilization (in ALMs) : 238,526 / 933,120 ( 26 % )
Total dedicated logic registers : 429048
Total pins : 284 / 1,152 ( 25 % )
Total block memory bits : 5,005,888 / 240,046,080 ( 2 % )
Total RAM Blocks : 1,700 / 11,721 ( 15 % )
Total DSP Blocks : 152 / 5,760 ( 3 % )
Total DIB Channels : 0 / 75 ( 0 % )
Total HSSI RX channels : 16 / 96 ( 17 % )
Total HSSI TX channels : 16 / 96 ( 17 % )
Total PLLs : 23 / 184 ( 13 % )
```
