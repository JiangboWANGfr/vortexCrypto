#!/usr/bin/env bash

# Integrate vortexCrypto into the existing Gen3x16 + four-DDR4 Quartus
# baseline. This script regenerates Qsys output, but does not compile Quartus
# or program the board.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
VORTEX_HOME=$(realpath "$SCRIPT_DIR/../../../..")
PROJECT_DIR=${VX_DE10PRO_PROJECT_DIR:-$VORTEX_HOME/../fpga_proj/PCIE_DDR4_Vortex_G3X16}
QUARTUS_ROOT=${QUARTUS_ROOT:-/data/Quartus/tools/19.2/quartus}
PROJECT_NAME=vortex_g3x16_ddr4x4
SYSTEM_NAME=pcie_ddr4_system
NUM_CORES=${VX_DE10PRO_NUM_CORES:-1}
NUM_WARPS=${VX_DE10PRO_NUM_WARPS:-1}
NUM_THREADS=${VX_DE10PRO_NUM_THREADS:-1}
# The rate the IOPLL is solved for, and therefore the only one timing analysis
# covers. The bitstream still carries every profile in the reconfiguration MIF,
# so the runtime can switch away from it, just without a signed-off timing path.
CLOCK_MHZ=${VX_DE10PRO_CLOCK_MHZ:-200}
# Crypto execution units. These are `ifdef`-tested in VX_execute.sv, so a
# disabled unit means the macro is absent -- setting it to 0 would still enable
# the unit.
EXT_SYM=${VX_DE10PRO_EXT_SYM:-1}
EXT_AUTH=${VX_DE10PRO_EXT_AUTH:-1}
# Subgroup (four-lane) forms of the two units, section 20 and 21.5 of the crypto
# proposal. Off by default: they read across an aligned quad of lanes, so they
# elaborate only when the lane count is a multiple of four, and every recorded
# DE10-Pro result so far was built without them. Each requires its own parent
# unit, and the AUTH one additionally rides the SYM opcode arm in VX_decode.sv.
EXT_SYM_SG4=${VX_DE10PRO_EXT_SYM_SG4:-0}
EXT_AUTH_SG4=${VX_DE10PRO_EXT_AUTH_SG4:-0}
# Stateful per-lane engines, section 22 of the crypto proposal. Off by default
# for the same reason the subgroup forms are. Unlike those two these are
# independent of each other: they decode on different opcodes, so neither
# requires the other -- only its own parent unit.
EXT_SYM_S2=${VX_DE10PRO_EXT_SYM_S2:-0}
EXT_AUTH_S2=${VX_DE10PRO_EXT_AUTH_S2:-0}
# ChaCha20-Poly1305's extensions, section 23. All off by default. The two SG4
# ones require their own non-SG4 parent: chacha32.xr's route bit lives in an
# encoding the parent defines, and poly26.rsum.sg4 shares the Poly PE.
EXT_CHACHA=${VX_DE10PRO_EXT_CHACHA:-0}
EXT_POLY=${VX_DE10PRO_EXT_POLY:-0}
EXT_CHACHA_SG4=${VX_DE10PRO_EXT_CHACHA_SG4:-0}
EXT_POLY_SG4=${VX_DE10PRO_EXT_POLY_SG4:-0}
EXT_CHACHA_S2=${VX_DE10PRO_EXT_CHACHA_S2:-0}

if [[ ! "$NUM_CORES" =~ ^[1-9][0-9]*$ \
   || ! "$NUM_WARPS" =~ ^[1-9][0-9]*$ \
   || ! "$NUM_THREADS" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: core/warp/thread counts must be positive integers" >&2
    exit 1
fi

# Only the four rates in the reconfiguration MIF can be solved for, and the
# board manager's profile decode accepts exactly these.
case "$CLOCK_MHZ" in
    100|125|200|250) ;;
    *)
        echo "error: VX_DE10PRO_CLOCK_MHZ must be one of 100, 125, 200, 250" >&2
        exit 1
        ;;
esac

EXT_MACROS=()
EXT_INCLUDES=()
if [[ "$EXT_SYM" != 0 ]]; then
    EXT_MACROS+=('VX_CFG_EXT_SYM_ENABLE=1')
    EXT_INCLUDES+=("$VORTEX_HOME/hw/rtl/crypto/sym")
    if [[ "$EXT_SYM_SG4" != 0 ]]; then
        EXT_MACROS+=('VX_CFG_EXT_SYM_SG4_ENABLE=1')
    fi
    if [[ "$EXT_SYM_S2" != 0 ]]; then
        EXT_MACROS+=('VX_CFG_EXT_SYM_S2_ENABLE=1')
    fi
    if [[ "$EXT_CHACHA" != 0 ]]; then
        EXT_MACROS+=('VX_CFG_EXT_SYM_CHACHA_ENABLE=1')
    fi
    if [[ "$EXT_CHACHA_SG4" != 0 ]]; then
        EXT_MACROS+=('VX_CFG_EXT_SYM_CHACHA_SG4_ENABLE=1')
    fi
    if [[ "$EXT_CHACHA_S2" != 0 ]]; then
        EXT_MACROS+=('VX_CFG_EXT_SYM_CHACHA_S2_ENABLE=1')
    fi
fi
if [[ "$EXT_AUTH" != 0 ]]; then
    EXT_MACROS+=('VX_CFG_EXT_AUTH_ENABLE=1')
    EXT_INCLUDES+=("$VORTEX_HOME/hw/rtl/crypto/auth")
    # The multiply decodes on the SYM opcode arm, so without the SYM subgroup
    # macro its encoding is never reached and the datapath would be dead logic.
    if [[ "$EXT_AUTH_SG4" != 0 && "$EXT_SYM_SG4" != 0 ]]; then
        EXT_MACROS+=('VX_CFG_EXT_AUTH_SG4_ENABLE=1')
    fi
    if [[ "$EXT_AUTH_S2" != 0 ]]; then
        EXT_MACROS+=('VX_CFG_EXT_AUTH_S2_ENABLE=1')
    fi
    if [[ "$EXT_POLY" != 0 ]]; then
        EXT_MACROS+=('VX_CFG_EXT_AUTH_POLY_ENABLE=1')
    fi
    if [[ "$EXT_POLY_SG4" != 0 ]]; then
        EXT_MACROS+=('VX_CFG_EXT_AUTH_POLY_SG4_ENABLE=1')
    fi
fi
if [[ "$EXT_CHACHA_SG4" != 0 && "$EXT_CHACHA" == 0 ]]; then
    echo "error: VX_DE10PRO_EXT_CHACHA_SG4 requires VX_DE10PRO_EXT_CHACHA" >&2
    exit 1
fi
if [[ "$EXT_POLY_SG4" != 0 && "$EXT_POLY" == 0 ]]; then
    echo "error: VX_DE10PRO_EXT_POLY_SG4 requires VX_DE10PRO_EXT_POLY" >&2
    exit 1
fi
if [[ "$EXT_AUTH_SG4" != 0 && "$EXT_SYM_SG4" == 0 ]]; then
    echo "error: VX_DE10PRO_EXT_AUTH_SG4 requires VX_DE10PRO_EXT_SYM_SG4" >&2
    exit 1
fi

if [[ ! -d "$PROJECT_DIR" ]]; then
    echo "error: FPGA project directory does not exist: $PROJECT_DIR" >&2
    exit 1
fi
PROJECT_DIR=$(realpath "$PROJECT_DIR")

PROJECT_QSF=$PROJECT_DIR/$PROJECT_NAME.qsf
SYSTEM_FILE=$PROJECT_DIR/$SYSTEM_NAME.qsys
PCIE_DUT_IP=$PROJECT_DIR/ip/pcie_example_design/pcie_example_design_DUT.ip
PCIE_DUT_OUTPUT_DIR=$PROJECT_DIR/ip/pcie_example_design/pcie_example_design_DUT
PCIE_DUT_QIP=$PCIE_DUT_OUTPUT_DIR/pcie_example_design_DUT.qip
QSYS_SCRIPT=$QUARTUS_ROOT/sopc_builder/bin/qsys-script
QSYS_GENERATE=$QUARTUS_ROOT/sopc_builder/bin/qsys-generate
COMPONENT_TEMPLATE=$SCRIPT_DIR/vortex_shell_hw.tcl.in
INTEGRATION_SCRIPT=$SCRIPT_DIR/integrate_vortex.tcl
VORTEX_SHELL=$VORTEX_HOME/hw/rtl/afu/de10pro/vortex_shell.sv
BOARD_MGMT_COMPONENT=$PROJECT_DIR/rtl/board_mgmt/de10pro_board_manager_hw.tcl
MEM_DRAIN_COMPONENT=$PROJECT_DIR/rtl/board_mgmt/de10pro_vortex_mem_drain_hw.tcl

for required_file in \
    "$PROJECT_QSF" \
    "$SYSTEM_FILE" \
    "$PCIE_DUT_IP" \
    "$COMPONENT_TEMPLATE" \
    "$INTEGRATION_SCRIPT" \
    "$BOARD_MGMT_COMPONENT" \
    "$MEM_DRAIN_COMPONENT" \
    "$VORTEX_HOME/VX_config.toml" \
    "$VORTEX_HOME/VX_types.toml" \
    "$VORTEX_SHELL"; do
    if [[ ! -f "$required_file" ]]; then
        echo "error: required file is missing: $required_file" >&2
        exit 1
    fi
done

for required_tool in "$QSYS_SCRIPT" "$QSYS_GENERATE"; do
    if [[ ! -x "$required_tool" ]]; then
        echo "error: required Quartus tool is missing: $required_tool" >&2
        exit 1
    fi
done

GENERATED_DIR=$PROJECT_DIR/generated/vortexcrypto
CONFIG_DIR=$GENERATED_DIR/config
FILELIST=$GENERATED_DIR/sources.f
QSF_FRAGMENT=$GENERATED_DIR/vortex_sources.qsf
COMPONENT_FILE=$GENERATED_DIR/vortex_shell_hw.tcl
DYNCLK_MIF=$PROJECT_DIR/generated/dynclk/vortex_iopll_profiles.mif
mkdir -p "$CONFIG_DIR"

CONFIG_FLAGS="-DSYNTHESIS=1 -DQUARTUS=1 -DNDEBUG=1 -DVX_CFG_XLEN=32 -DVX_CFG_XLEN_32=1 -DVX_CFG_NUM_CLUSTERS=1 -DVX_CFG_NUM_CORES=$NUM_CORES -DVX_CFG_NUM_WARPS=$NUM_WARPS -DVX_CFG_NUM_THREADS=$NUM_THREADS -DVX_CFG_EXT_F_DISABLE=1 -DVX_CFG_EXT_D_DISABLE=1 -DVX_CFG_ICACHE_LATENCY=3 -DVX_CFG_DCACHE_LATENCY=3 -DVX_CFG_PLATFORM_MEMORY_NUM_BANKS=1 -DVX_CFG_PLATFORM_MEMORY_INTERLEAVE=0 -DVX_CFG_PLATFORM_CLOCK_RATE=$CLOCK_MHZ"
if [[ ${#EXT_MACROS[@]} -gt 0 ]]; then
    for macro in "${EXT_MACROS[@]}"; do
        CONFIG_FLAGS+=" -D$macro"
    done
fi

XLEN=32 python3 "$VORTEX_HOME/ci/gen_config.py" \
    --config "$VORTEX_HOME/VX_config.toml" \
    --cflags "$CONFIG_FLAGS" \
    --format verilog \
    --output "$CONFIG_DIR/VX_config.vh"

XLEN=32 python3 "$VORTEX_HOME/ci/gen_config.py" \
    --config "$VORTEX_HOME/VX_types.toml" \
    --cflags "$CONFIG_FLAGS" \
    --format verilog \
    --resolved \
    --output "$CONFIG_DIR/VX_types.vh"

"$VORTEX_HOME/hw/scripts/gen_sources.sh" \
    -DSYNTHESIS=1 \
    -DQUARTUS=1 \
    -DNDEBUG=1 \
    -DVX_CFG_XLEN=32 \
    -DVX_CFG_XLEN_32=1 \
    -DVX_CFG_NUM_CLUSTERS=1 \
    -DVX_CFG_NUM_CORES="$NUM_CORES" \
    -DVX_CFG_NUM_WARPS="$NUM_WARPS" \
    -DVX_CFG_NUM_THREADS="$NUM_THREADS" \
    -DVX_CFG_EXT_F_DISABLE=1 \
    -DVX_CFG_EXT_D_DISABLE=1 \
    -DVX_CFG_ICACHE_LATENCY=3 \
    -DVX_CFG_DCACHE_LATENCY=3 \
    -DVX_CFG_PLATFORM_MEMORY_NUM_BANKS=1 \
    -DVX_CFG_PLATFORM_MEMORY_INTERLEAVE=0 \
    -DVX_CFG_PLATFORM_CLOCK_RATE="$CLOCK_MHZ" \
    ${EXT_MACROS[@]+"${EXT_MACROS[@]/#/-D}"} \
    ${EXT_INCLUDES[@]+"${EXT_INCLUDES[@]/#/-I}"} \
    -I"$CONFIG_DIR" \
    -I"$VORTEX_HOME/hw/rtl" \
    -I"$VORTEX_HOME/hw/rtl/libs" \
    -I"$VORTEX_HOME/hw/rtl/interfaces" \
    -I"$VORTEX_HOME/hw/rtl/fpu" \
    -I"$VORTEX_HOME/hw/rtl/core" \
    -I"$VORTEX_HOME/hw/rtl/mem" \
    -I"$VORTEX_HOME/hw/rtl/cache" \
    -I"$VORTEX_HOME/hw/rtl/afu/de10pro" \
    -O"$FILELIST"

{
    echo "# Generated by vortexCrypto/hw/syn/altera/de10pro/prepare_project.sh"
    while IFS= read -r entry; do
        case "$entry" in
            +define+*)
                printf 'set_global_assignment -name VERILOG_MACRO "%s"\n' "${entry#+define+}"
                ;;
            +incdir+*)
                printf 'set_global_assignment -name SEARCH_PATH "%s"\n' "${entry#+incdir+}"
                ;;
            */hw/rtl/afu/de10pro/vortex_shell.sv)
                ;;
            *.sv)
                printf 'set_global_assignment -name SYSTEMVERILOG_FILE "%s"\n' "$entry"
                ;;
            *.v)
                printf 'set_global_assignment -name VERILOG_FILE "%s"\n' "$entry"
                ;;
            '')
                ;;
            *)
                echo "error: unsupported source-list entry: $entry" >&2
                exit 1
                ;;
        esac
    done < "$FILELIST"
} > "$QSF_FRAGMENT"

awk -v shell="$VORTEX_SHELL" '
    { gsub(/@VORTEX_SHELL@/, shell); print }
' "$COMPONENT_TEMPLATE" > "$COMPONENT_FILE"

if ! grep -Fq 'source generated/vortexcrypto/vortex_sources.qsf' "$PROJECT_QSF"; then
    echo "error: $PROJECT_QSF does not source the generated Vortex assignments" >&2
    exit 1
fi

for macro in \
    'VX_CFG_XLEN=32' \
    'VX_CFG_NUM_CLUSTERS=1' \
    "VX_CFG_NUM_CORES=$NUM_CORES" \
    "VX_CFG_NUM_WARPS=$NUM_WARPS" \
    "VX_CFG_NUM_THREADS=$NUM_THREADS" \
    'VX_CFG_EXT_F_DISABLE=1' \
    'VX_CFG_EXT_D_DISABLE=1' \
    'VX_CFG_ICACHE_LATENCY=3' \
    'VX_CFG_DCACHE_LATENCY=3' \
    'VX_CFG_PLATFORM_MEMORY_NUM_BANKS=1' \
    'VX_CFG_PLATFORM_MEMORY_INTERLEAVE=0' \
    "VX_CFG_PLATFORM_CLOCK_RATE=$CLOCK_MHZ" \
    ${EXT_MACROS[@]+"${EXT_MACROS[@]}"}; do
    if ! grep -Fq "VERILOG_MACRO \"$macro\"" "$QSF_FRAGMENT"; then
        echo "error: missing generated macro: $macro" >&2
        exit 1
    fi
done

# Platform Designer only looks for *_hw.tcl directly inside each search-path
# entry, so every directory holding a component must be listed explicitly.
SEARCH_PATH="$PROJECT_DIR,$PROJECT_DIR/rtl/board_mgmt,$GENERATED_DIR,\$"
(
    cd "$PROJECT_DIR"
    "$QSYS_SCRIPT" \
        --quartus-project="$PROJECT_NAME" \
        --rev="$PROJECT_NAME" \
        --system-file="$SYSTEM_NAME.qsys" \
        --search-path="$SEARCH_PATH" \
        --cmd="set vx_de10pro_project_dir {$PROJECT_DIR}; \
               set vortex_clock_mhz $CLOCK_MHZ.0" \
        --script="$INTEGRATION_SCRIPT"
)

# save_system freezes every instance into a generic component, so the IOPLL's
# desired frequency can no longer be set through the integration script once the
# instance exists, and recreating the instance would drop the dynamic-clock MIF
# parameters that only the profile flow installs. Patch the child IP instead and
# let qsys-generate re-solve the M and C counters, which is what derive_pll_clocks
# reads and therefore what timing analysis signs off.
mapfile -t IOPLL_IP_RELS < <(
    grep -Eo 'ip/pcie_ddr4_system/pcie_ddr4_system_vortex_iopll(_[0-9]+)?\.ip' \
        "$SYSTEM_FILE" | sort -u
)
if [[ ${#IOPLL_IP_RELS[@]} -ne 1 ]]; then
    echo "error: expected one Vortex IOPLL child IP in $SYSTEM_FILE" >&2
    exit 1
fi
IOPLL_IP=$PROJECT_DIR/${IOPLL_IP_RELS[0]}
DESIRED_MHZ=$CLOCK_MHZ.0 perl -0pi -e \
    's{(<ipxact:parameter parameterId="gui_output_clock_frequency0".*?<ipxact:value>)[^<]*(</ipxact:value>)}{$1$ENV{DESIRED_MHZ}$2}s' \
    "$IOPLL_IP"
if ! grep -A3 -F 'parameterId="gui_output_clock_frequency0"' "$IOPLL_IP" \
     | grep -Fq "<ipxact:value>$CLOCK_MHZ.0</ipxact:value>"; then
    echo "error: could not set the Vortex IOPLL frequency in $IOPLL_IP" >&2
    exit 1
fi
# qsys-generate treats an existing output directory as up to date and skips the
# IP, so the frequency above would only take effect on some later run. Drop the
# directory to force the solver to run against it now.
rm -rf "${IOPLL_IP%.ip}"

(
    cd "$PROJECT_DIR"
    "$QSYS_GENERATE" "$SYSTEM_NAME.qsys" \
        --synthesis=VERILOG \
        --quartus-project="$PROJECT_NAME" \
        --rev="$PROJECT_NAME" \
        --search-path="$SEARCH_PATH"
)

# Check what the solver actually produced, not what it was asked for. The
# desired frequency is only an input; derive_pll_clocks reads these counters,
# so they are what timing analysis signs off. Asserting the input instead would
# pass while the fabric still ran at the old rate.
IOPLL_PARAMS=$(find "${IOPLL_IP%.ip}" -name '*_parameters.tcl' -type f | sort | head -1)
if [[ -z $IOPLL_PARAMS ]]; then
    echo "error: the Vortex IOPLL did not regenerate: no parameters file" >&2
    exit 1
fi
IOPLL_MULT=$(sed -n 's/.*outclk0 multiply_by \([0-9]\+\).*/\1/p' "$IOPLL_PARAMS" | head -1)
IOPLL_DIV=$(sed -n 's/.*outclk0 divide_by \([0-9]\+\).*/\1/p' "$IOPLL_PARAMS" | head -1)
# The board feeds this PLL a 50 MHz reference; integrate_vortex.tcl sets it.
if [[ -z $IOPLL_MULT || -z $IOPLL_DIV ]] \
   || (( 50 * IOPLL_MULT % IOPLL_DIV != 0 )) \
   || (( 50 * IOPLL_MULT / IOPLL_DIV != CLOCK_MHZ )); then
    echo "error: the Vortex IOPLL solved to 50 x ${IOPLL_MULT:-?}/${IOPLL_DIV:-?} MHz," \
         "not $CLOCK_MHZ MHz" >&2
    exit 1
fi

if [[ ! -f "$PCIE_DUT_QIP" || "$PCIE_DUT_IP" -nt "$PCIE_DUT_QIP" ]]; then
    "$QSYS_GENERATE" "$PCIE_DUT_IP" \
        --synthesis=VERILOG \
        --output-directory="$PCIE_DUT_OUTPUT_DIR" \
        --family='Stratix 10' \
        --part=1SG280HU1F50E1VG
fi

mapfile -t VORTEX_SHELL_IP_RELS < <(
    grep -Eo 'ip/pcie_ddr4_system/pcie_ddr4_system_vortex_shell_[0-9]+\.ip' \
        "$SYSTEM_FILE" | sort -u
)
mapfile -t BOARD_MANAGER_IP_RELS < <(
    grep -Eo 'ip/pcie_ddr4_system/pcie_ddr4_system_board_manager_[0-9]+\.ip' \
        "$SYSTEM_FILE" | sort -u
)
mapfile -t MEM_DRAIN_IP_RELS < <(
    grep -Eo 'ip/pcie_ddr4_system/pcie_ddr4_system_vortex_mem_drain_[0-9]+\.ip' \
        "$SYSTEM_FILE" | sort -u
)
mapfile -t RECONFIG_IP_RELS < <(
    grep -Eo 'ip/pcie_ddr4_system/pcie_ddr4_system_vortex_iopll_reconfig(_[0-9]+)?\.ip' \
        "$SYSTEM_FILE" | sort -u
)
mapfile -t VORTEX_IOPLL_IP_RELS < <(
    grep -Eo 'ip/pcie_ddr4_system/pcie_ddr4_system_vortex_iopll(_[0-9]+)?\.ip' \
        "$SYSTEM_FILE" | sort -u
)
mapfile -t VORTEX_RESET_CONTROLLER_IP_RELS < <(
    grep -Eo 'ip/pcie_ddr4_system/pcie_ddr4_system_vortex_reset_controller(_[0-9]+)?\.ip' \
        "$SYSTEM_FILE" | sort -u
)
if [[ ${#VORTEX_SHELL_IP_RELS[@]} -ne 1 ]]; then
    echo "error: expected one active Vortex shell child IP in $SYSTEM_FILE" >&2
    exit 1
fi
if [[ ${#BOARD_MANAGER_IP_RELS[@]} -ne 1 ]]; then
    echo "error: expected one active board-manager child IP in $SYSTEM_FILE" >&2
    exit 1
fi
if [[ ${#MEM_DRAIN_IP_RELS[@]} -ne 1 ]]; then
    echo "error: expected one active memory-drain child IP in $SYSTEM_FILE" >&2
    exit 1
fi
if [[ ${#RECONFIG_IP_RELS[@]} -ne 1 ]]; then
    echo "error: expected one active PLL-reconfiguration child IP in $SYSTEM_FILE" >&2
    exit 1
fi
if [[ ${#VORTEX_IOPLL_IP_RELS[@]} -ne 1 ]]; then
    echo "error: expected one active Vortex IOPLL child IP in $SYSTEM_FILE" >&2
    exit 1
fi
if [[ ${#VORTEX_RESET_CONTROLLER_IP_RELS[@]} -ne 1 ]]; then
    echo "error: expected one active Vortex reset-controller child IP in $SYSTEM_FILE" >&2
    exit 1
fi
VORTEX_SHELL_IP=$PROJECT_DIR/${VORTEX_SHELL_IP_RELS[0]}
BOARD_MANAGER_IP=$PROJECT_DIR/${BOARD_MANAGER_IP_RELS[0]}
MEM_DRAIN_IP=$PROJECT_DIR/${MEM_DRAIN_IP_RELS[0]}
RECONFIG_IP=$PROJECT_DIR/${RECONFIG_IP_RELS[0]}
VORTEX_IOPLL_IP=$PROJECT_DIR/${VORTEX_IOPLL_IP_RELS[0]}
VORTEX_RESET_CONTROLLER_IP=$PROJECT_DIR/${VORTEX_RESET_CONTROLLER_IP_RELS[0]}

for generated_ip in \
    "$VORTEX_IOPLL_IP" \
    "$RECONFIG_IP" \
    "$VORTEX_RESET_CONTROLLER_IP"; do
    if [[ ! -f "$generated_ip" ]]; then
        echo "error: generated integration child IP is missing: $generated_ip" >&2
        exit 1
    fi
done

VORTEX_RESET_CONTROLLER_OUTPUT_REL=${VORTEX_RESET_CONTROLLER_IP_RELS[0]%.ip}
VORTEX_RESET_CONTROLLER_OUTPUT_NAME=${VORTEX_RESET_CONTROLLER_OUTPUT_REL##*/}
VORTEX_RESET_CONTROLLER_WRAPPER=$PROJECT_DIR/$VORTEX_RESET_CONTROLLER_OUTPUT_REL/synth/$VORTEX_RESET_CONTROLLER_OUTPUT_NAME.v
mapfile -t VORTEX_RESET_SYNCHRONIZER_RTLS < <(
    find "$PROJECT_DIR/$VORTEX_RESET_CONTROLLER_OUTPUT_REL" \
        -path '*/synth/altera_reset_synchronizer.v' -type f | sort
)
if [[ ! -f "$VORTEX_RESET_CONTROLLER_WRAPPER" ]] \
   || [[ ${#VORTEX_RESET_SYNCHRONIZER_RTLS[@]} -ne 1 ]]; then
    echo "error: generated Vortex reset synchronizer RTL is incomplete" >&2
    exit 1
fi
if ! grep -Eq 'parameter[[:space:]]+OUTPUT_RESET_SYNC_EDGES[[:space:]]*=[[:space:]]*"deassert"' \
        "$VORTEX_RESET_CONTROLLER_WRAPPER" \
   || ! grep -Eq 'parameter[[:space:]]+SYNC_DEPTH[[:space:]]*=[[:space:]]*3' \
        "$VORTEX_RESET_CONTROLLER_WRAPPER" \
   || ! grep -Fq 'always @(posedge clk or posedge reset_in)' \
        "${VORTEX_RESET_SYNCHRONIZER_RTLS[0]}"; then
    echo "error: Vortex reset must assert asynchronously and deassert through a three-stage synchronizer" >&2
    exit 1
fi

# Quartus 19.2 stores the validated MIF path as an absolute filename in child
# IP metadata. The generated HDL uses a local copy, so normalize every value
# for this MIF to the tracked project-relative source path.
PORTABLE_MIF=generated/dynclk/vortex_iopll_profiles.mif \
    perl -0pi -e \
    's{(<ipxact:value>)(?:[^<]*/)?vortex_iopll_profiles\.mif(</ipxact:value>)}{$1$ENV{PORTABLE_MIF}$2}g' \
    "$VORTEX_IOPLL_IP" "$RECONFIG_IP"

for portable_ip in "$VORTEX_IOPLL_IP" "$RECONFIG_IP"; do
    portable_value="<ipxact:value>generated/dynclk/vortex_iopll_profiles.mif</ipxact:value>"
    if [[ $(grep -Fc "$portable_value" "$portable_ip") -lt 1 ]] \
       || grep -F 'vortex_iopll_profiles.mif' "$portable_ip" \
          | grep -Fqv "$portable_value"; then
        echo "error: non-portable dynamic-clock MIF path remains in $portable_ip" >&2
        exit 1
    fi
done

# Qsys may change a child-IP filename suffix when an instance is refreshed.
# Replace the complete child-IP assignment set with the active logical views.
mapfile -t SYSTEM_IP_RELS < <(
    grep -Eo 'ip/pcie_ddr4_system/[^"< ]+\.ip' "$SYSTEM_FILE" | sort -u
)
if [[ ${#SYSTEM_IP_RELS[@]} -eq 0 ]]; then
    echo "error: no active child IPs found in $SYSTEM_FILE" >&2
    exit 1
fi
QSF_TMP=$(mktemp "$PROJECT_QSF.XXXXXX")
trap 'rm -f "$QSF_TMP"' EXIT
awk '!/^set_global_assignment -name IP_FILE ip\/pcie_ddr4_system\//' \
    "$PROJECT_QSF" > "$QSF_TMP"
for system_ip_rel in "${SYSTEM_IP_RELS[@]}"; do
    printf 'set_global_assignment -name IP_FILE %s\n' "$system_ip_rel" \
        >> "$QSF_TMP"
done
chmod --reference="$PROJECT_QSF" "$QSF_TMP"
mv "$QSF_TMP" "$PROJECT_QSF"
trap - EXIT

QSYS_ASSIGNMENT="set_global_assignment -name QSYS_FILE pcie_ddr4_system.qsys"
if [[ $(grep -Fxc "$QSYS_ASSIGNMENT" "$PROJECT_QSF") -ne 1 ]]; then
    echo "error: expected exactly one QSF assignment: $QSYS_ASSIGNMENT" >&2
    exit 1
fi
if [[ $(grep -Ec '^set_global_assignment -name IP_FILE ip/pcie_ddr4_system/.*\.ip$' \
          "$PROJECT_QSF") -ne ${#SYSTEM_IP_RELS[@]} ]]; then
    echo "error: QSF child-IP assignment count does not match $SYSTEM_FILE" >&2
    exit 1
fi
for system_ip_rel in "${SYSTEM_IP_RELS[@]}"; do
    assignment="set_global_assignment -name IP_FILE $system_ip_rel"
    if [[ $(grep -Fxc "$assignment" "$PROJECT_QSF") -ne 1 ]]; then
        echo "error: active child IP is missing from QSF: $system_ip_rel" >&2
        exit 1
    fi
done
if [[ ! -f "$VORTEX_SHELL_IP" ]]; then
    echo "error: generated Vortex child IP is missing: $VORTEX_SHELL_IP" >&2
    exit 1
fi
if [[ ! -f "$BOARD_MANAGER_IP" ]]; then
    echo "error: generated board-manager child IP is missing: $BOARD_MANAGER_IP" >&2
    exit 1
fi
if [[ ! -f "$MEM_DRAIN_IP" ]]; then
    echo "error: generated memory-drain child IP is missing: $MEM_DRAIN_IP" >&2
    exit 1
fi
if [[ ! -f "$DYNCLK_MIF" ]]; then
    echo "error: generated dynamic-clock MIF is missing: $DYNCLK_MIF" >&2
    exit 1
fi
mapfile -t DYNCLK_PROFILES < <(
    sed -n 's/.*--END_OF_CONFIG:\([[:alnum:]_]*\).*/\1/p' "$DYNCLK_MIF"
)
if [[ "${DYNCLK_PROFILES[*]}" != "f100 f125 f200 f250" ]]; then
    echo "error: dynamic-clock MIF profiles are '${DYNCLK_PROFILES[*]}'" >&2
    exit 1
fi

RECONFIG_OUTPUT_REL=${RECONFIG_IP_RELS[0]%.ip}
RECONFIG_OUTPUT_NAME=${RECONFIG_OUTPUT_REL##*/}
RECONFIG_REPORT=$PROJECT_DIR/$RECONFIG_OUTPUT_REL/${RECONFIG_OUTPUT_NAME}_generation.rpt
if [[ ! -f "$RECONFIG_REPORT" ]]; then
    echo "error: generated PLL-reconfiguration report is missing: $RECONFIG_REPORT" >&2
    exit 1
fi
for expected_report_line in \
    'MIF_ADDRESS_0: 0' \
    'MIF_ADDRESS_1: 48' \
    'MIF_ADDRESS_2: 96' \
    'MIF_ADDRESS_3: 144' \
    'The MIF file is valid.'; do
    if ! grep -Fq "$expected_report_line" "$RECONFIG_REPORT"; then
        echo "error: PLL-reconfiguration report lacks: $expected_report_line" >&2
        exit 1
    fi
done
if [[ ! -f "$PCIE_DUT_QIP" ]]; then
    echo "error: generated PCIe DUT QIP is missing: $PCIE_DUT_QIP" >&2
    exit 1
fi
if grep -Fq 'QIP_FILE pcie_ddr4_system/pcie_ddr4_system.qip' "$PROJECT_QSF"; then
    echo "error: generated QIP and QSYS source mechanisms must not be mixed" >&2
    exit 1
fi

git -C "$VORTEX_HOME" describe --always --dirty \
    > "$GENERATED_DIR/VORTEX_SOURCE_REVISION"

echo "Prepared: $PROJECT_DIR"
echo "Profile: RV32, $NUM_CORES core(s), $NUM_WARPS warp(s), $NUM_THREADS thread(s), DDR4A"
echo "Control window: BAR0 + 0x1000"
echo "Board manager: BAR0 + 0x2000"
echo "Vortex clocks: 100/125/200/250 MHz in one SOF; initial $CLOCK_MHZ MHz, the"
echo "               only rate timing analysis covers"
echo "Source fragment: $QSF_FRAGMENT"
echo "Quartus compilation and board programming were not invoked."
