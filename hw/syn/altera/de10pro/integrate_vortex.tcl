package require -exact qsys 19.2

# The Vortex fabric clock, in MHz. This is the rate the IOPLL is solved for and
# therefore the one timing analysis signs off; the runtime can still switch
# between every profile in the reconfiguration MIF. prepare_project.sh passes
# the value it also compiles into VX_CFG_PLATFORM_CLOCK_RATE, so the two cannot
# drift; the default here only applies when this script is run by hand.
if {![info exists vortex_clock_mhz]} {
    set vortex_clock_mhz 200.0
}

proc instance_exists {name} {
    return [expr {[lsearch -exact [get_instances] $name] >= 0}]
}

proc connection_exists {name} {
    return [expr {[lsearch -exact [get_connections] $name] >= 0}]
}

proc add_connection_once {start_interface end_interface} {
    set connection "$start_interface/$end_interface"
    if {![connection_exists $connection]} {
        add_connection $start_interface $end_interface
    }
}

proc remove_connection_if_present {start_interface end_interface} {
    set connection "$start_interface/$end_interface"
    if {[connection_exists $connection]} {
        remove_connection $connection
    }
}

proc read_mif_profiles {path} {
    if {![file exists $path]} {
        return {}
    }
    set stream [open $path r]
    set contents [read $stream]
    close $stream
    set profiles {}
    foreach line [split $contents "\n"] {
        if {[regexp -- {--END_OF_CONFIG:([A-Za-z0-9_]+)} \
                $line match profile]} {
            lappend profiles $profile
        }
    }
    return $profiles
}

proc assert_mif_profiles {path expected} {
    set actual [read_mif_profiles $path]
    if {![string equal $actual $expected]} {
        error "unexpected dynamic-clock profiles in $path: $actual"
    }
}

proc wait_for_mif_profiles {path expected} {
    for {set attempt 0} {$attempt < 200} {incr attempt} {
        if {[string equal [read_mif_profiles $path] $expected]} {
            return
        }
        after 25
    }
    error "dynamic-clock MIF did not reach '$expected': [read_mif_profiles $path]"
}

proc read_ip_parameter_value {path parameter} {
    if {![file exists $path]} {
        error "generated IP file is missing: $path"
    }
    set stream [open $path r]
    set contents [read $stream]
    close $stream
    set marker "parameterId=\"$parameter\""
    set in_parameter 0
    foreach line [split $contents "\n"] {
        if {!$in_parameter && [string first $marker $line] >= 0} {
            set in_parameter 1
        } elseif {$in_parameter} {
            if {[regexp -- {<ipxact:value>([^<]*)</ipxact:value>} \
                    $line match value]} {
                return $value
            }
            if {[string first {</ipxact:parameter>} $line] >= 0} {
                break
            }
        }
    }
    error "parameter $parameter is missing from $path"
}

proc get_effective_instance_parameter_value {name parameter} {
    set class_name [get_instance_property $name CLASS_NAME]
    if {![string equal $class_name altera_generic_component]} {
        return [get_instance_parameter_value $name $parameter]
    }
    set ip_file [get_instance_property $name FILE]
    return [read_ip_parameter_value $ip_file $parameter]
}

proc assert_reconfig_parameters {name mif_abs mif_rel} {
    set expected_addresses {0 48 96 144}
    for {set index 0} {$index < 4} {incr index} {
        set parameter MIF_ADDRESS_$index
        set actual [get_effective_instance_parameter_value $name $parameter]
        set expected [lindex $expected_addresses $index]
        if {$actual != $expected} {
            error "unexpected $parameter for $name: $actual"
        }
    }
    set validated [get_effective_instance_parameter_value \
        $name validated_mif_filename]
    if {![string equal $validated $mif_abs]
     && ![string equal $validated $mif_rel]} {
        error "unexpected validated MIF for $name: $validated"
    }
}

proc reconfig_matches {name mif_abs mif_rel} {
    if {![instance_exists $name]} {
        return 0
    }
    return [expr {![catch {
        assert_reconfig_parameters $name $mif_abs $mif_rel
    }]}]
}

proc add_cdc {name data_width address_width max_burst command_depth response_depth} {
    if {[instance_exists $name]} {
        return
    }
    add_instance $name altera_avalon_mm_clock_crossing_bridge 19.1
    set_instance_parameter_value $name DATA_WIDTH $data_width
    set_instance_parameter_value $name SYMBOL_WIDTH 8
    set_instance_parameter_value $name ADDRESS_WIDTH $address_width
    set_instance_parameter_value $name USE_AUTO_ADDRESS_WIDTH 0
    set_instance_parameter_value $name ADDRESS_UNITS SYMBOLS
    set_instance_parameter_value $name MAX_BURST_SIZE $max_burst
    set_instance_parameter_value $name COMMAND_FIFO_DEPTH $command_depth
    set_instance_parameter_value $name RESPONSE_FIFO_DEPTH $response_depth
    set_instance_parameter_value $name MASTER_SYNC_DEPTH 2
    set_instance_parameter_value $name SLAVE_SYNC_DEPTH 2
    set_instance_parameter_value $name SYNC_RESET 0
}

set required_instances {
    DUT
    BAR_INTERPRETER
    ddr4_ingress_pipe_ddr4a
    ddr4_clock_crossing_bridge_ddr4a
}

foreach instance $required_instances {
    if {![instance_exists $instance]} {
        error "required Qsys instance is missing: $instance"
    }
}

if {![info exists vx_de10pro_project_dir]} {
    error "vx_de10pro_project_dir must identify the FPGA project"
}
set project_dir $vx_de10pro_project_dir
set mif_rel {generated/dynclk/vortex_iopll_profiles.mif}
set mif_abs [file join $project_dir $mif_rel]
file mkdir [file dirname $mif_abs]

set configure_vortex_shell 0
if {[instance_exists vortex_shell_0]} {
    set vortex_shell_interfaces [get_instance_interfaces vortex_shell_0]
    set refresh_vortex_shell 0
    if {[lsearch -exact $vortex_shell_interfaces clock_control] < 0} {
        set refresh_vortex_shell 1
    } else {
        set shell_associated_clock \
            [get_instance_interface_property vortex_shell_0 clock_control associatedClock]
        if {![string equal $shell_associated_clock ""]} {
            set refresh_vortex_shell 1
        }
    }
    if {$refresh_vortex_shell} {
        remove_instance vortex_shell_0
    }
}
if {![instance_exists vortex_shell_0]} {
    add_instance vortex_shell_0 vortex_shell 1.0
    set configure_vortex_shell 1
}
if {$configure_vortex_shell} {
    set_instance_parameter_value vortex_shell_0 C_CTRL_ADDR_WIDTH 20
    set_instance_parameter_value vortex_shell_0 C_CTRL_DATA_WIDTH 32
    set_instance_parameter_value vortex_shell_0 C_MEM_ADDR_WIDTH 33
    set_instance_parameter_value vortex_shell_0 C_MEM_DATA_WIDTH 512
    set_instance_parameter_value vortex_shell_0 C_MEM_BURST_WIDTH 5
}

set configure_board_manager 0
if {[instance_exists board_manager_0]} {
    set board_manager_interfaces [get_instance_interfaces board_manager_0]
    set refresh_board_manager 0
    foreach interface {clock_control pll_status memory_drain} {
        if {[lsearch -exact $board_manager_interfaces $interface] < 0} {
            set refresh_board_manager 1
        } else {
            set associated_clock [get_instance_interface_property \
                board_manager_0 $interface associatedClock]
            if {![string equal $associated_clock ""]} {
                set refresh_board_manager 1
            }
        }
    }
    if {$refresh_board_manager} {
        remove_instance board_manager_0
    }
}
if {![instance_exists board_manager_0]} {
    add_instance board_manager_0 de10pro_board_manager 1.0
    set configure_board_manager 1
}
if {$configure_board_manager} {
    set_instance_parameter_value board_manager_0 MGMT_CLK_HZ 50000000
    set_instance_parameter_value board_manager_0 TELEMETRY_POLL_CYCLES 5000000
}

if {![instance_exists mgmt_clk_bridge]} {
    add_instance mgmt_clk_bridge altera_clock_bridge 19.1
    set_instance_parameter_value mgmt_clk_bridge EXPLICIT_CLOCK_RATE 50000000
    set_instance_parameter_value mgmt_clk_bridge NUM_CLOCK_OUTPUTS 1
}

if {![instance_exists pll_ref_clk_bridge]} {
    add_instance pll_ref_clk_bridge altera_clock_bridge 19.1
    set_instance_parameter_value pll_ref_clk_bridge EXPLICIT_CLOCK_RATE 50000000
    set_instance_parameter_value pll_ref_clk_bridge NUM_CLOCK_OUTPUTS 1
}

if {[instance_exists vortex_reset_bridge]} {
    remove_instance vortex_reset_bridge
}
foreach reset_bridge {mgmt_reset_bridge pll_ref_reset_bridge} {
    if {![instance_exists $reset_bridge]} {
        add_instance $reset_bridge altera_reset_bridge 19.1
        set_instance_parameter_value $reset_bridge ACTIVE_LOW_RESET 0
        set_instance_parameter_value $reset_bridge SYNCHRONOUS_EDGES deassert
        set_instance_parameter_value $reset_bridge NUM_RESET_OUTPUTS 1
        set_instance_parameter_value $reset_bridge USE_RESET_REQUEST 0
    }
}

set refresh_vortex_reset_controller 0
if {[instance_exists vortex_reset_controller]} {
    foreach {parameter expected} {
        NUM_RESET_INPUTS 1
        OUTPUT_RESET_SYNC_EDGES deassert
        SYNC_DEPTH 3
        RESET_REQUEST_PRESENT 0
    } {
        set actual [get_effective_instance_parameter_value \
            vortex_reset_controller $parameter]
        if {![string equal -nocase $actual $expected]} {
            set refresh_vortex_reset_controller 1
        }
    }
    if {$refresh_vortex_reset_controller} {
        remove_instance vortex_reset_controller
    }
}
if {![instance_exists vortex_reset_controller]} {
    add_instance vortex_reset_controller altera_reset_controller 19.1
    set_instance_parameter_value vortex_reset_controller NUM_RESET_INPUTS 1
    set_instance_parameter_value vortex_reset_controller \
        OUTPUT_RESET_SYNC_EDGES deassert
    set_instance_parameter_value vortex_reset_controller SYNC_DEPTH 3
    set_instance_parameter_value vortex_reset_controller \
        RESET_REQUEST_PRESENT 0
}

set expected_profiles {f100 f125 f200 f250}
set mif_tmp_abs [file join $project_dir \
    generated/dynclk/vortex_iopll_profiles.new.mif]
set rebuild_dynamic_clock 0
if {![string equal [read_mif_profiles $mif_abs] $expected_profiles]} {
    set rebuild_dynamic_clock 1
}

if {[instance_exists profile_pll]} {
    remove_instance profile_pll
}
if {$rebuild_dynamic_clock} {
    if {[file exists $mif_tmp_abs]} {
        file delete -force $mif_tmp_abs
    }

    add_instance profile_pll altera_iopll 19.1
    set_instance_parameter_value profile_pll gui_en_reconf 1
    set_instance_parameter_value profile_pll gui_reference_clock_frequency 50.0
    set_instance_parameter_value profile_pll gui_number_of_clocks 1
    set_instance_parameter_value profile_pll gui_use_locked 1
    set_instance_parameter_value profile_pll gui_operation_mode direct
    set_instance_parameter_value profile_pll gui_pll_mode {Integer-N PLL}

    set_instance_parameter_value profile_pll gui_output_clock_frequency0 100.0
    set_instance_parameter_value profile_pll gui_mif_config_name f100
    set_instance_parameter_value profile_pll gui_mif_gen_options {Generate New MIF File}
    set_instance_parameter_value profile_pll gui_new_mif_file_path $mif_tmp_abs
    validate_system
    if {![invoke_instance_display_action profile_pll {Create MIF File}]} {
        error {failed to start dynamic-clock profile f100 creation}
    }
    wait_for_mif_profiles $mif_tmp_abs {f100}

    set_instance_parameter_value profile_pll gui_mif_gen_options {Add Configuration to Existing MIF File}
    set_instance_parameter_value profile_pll gui_existing_mif_file_path $mif_tmp_abs
    foreach {frequency name expected} {
        125.0 f125 {f100 f125}
        200.0 f200 {f100 f125 f200}
        250.0 f250 {f100 f125 f200 f250}
    } {
        set_instance_parameter_value profile_pll gui_output_clock_frequency0 $frequency
        set_instance_parameter_value profile_pll gui_mif_config_name $name
        validate_system
        if {![invoke_instance_display_action profile_pll {Append to MIF File}]} {
            error "failed to start dynamic-clock profile $name append"
        }
        wait_for_mif_profiles $mif_tmp_abs $expected
    }

    assert_mif_profiles $mif_tmp_abs $expected_profiles
    file rename -force $mif_tmp_abs $mif_abs
    remove_instance profile_pll
}

assert_mif_profiles $mif_abs $expected_profiles

if {[instance_exists vortex_iopll_reconfig]
 && ![reconfig_matches vortex_iopll_reconfig $mif_abs $mif_rel]} {
    remove_instance vortex_iopll_reconfig
}

# Only reached on a fresh system file. Changing the rate of an IOPLL that
# already exists cannot be done from here: save_system freezes every instance
# into a generic component, which no longer carries the altera_iopll gui_*
# parameters, and removing the instance to recreate it would drop the
# dynamic-clock MIF parameters that only the profile flow installs. For the
# usual case prepare_project.sh patches the child IP between this script and
# qsys-generate.
if {![instance_exists vortex_iopll]} {
    add_instance vortex_iopll altera_iopll 19.1
    set_instance_parameter_value vortex_iopll gui_en_reconf 1
    set_instance_parameter_value vortex_iopll gui_reference_clock_frequency 50.0
    set_instance_parameter_value vortex_iopll gui_number_of_clocks 1
    set_instance_parameter_value vortex_iopll \
        gui_output_clock_frequency0 $vortex_clock_mhz
    set_instance_parameter_value vortex_iopll gui_use_locked 1
    set_instance_parameter_value vortex_iopll gui_operation_mode direct
    set_instance_parameter_value vortex_iopll gui_pll_mode {Integer-N PLL}
}

if {![instance_exists vortex_iopll_reconfig]} {
    add_instance vortex_iopll_reconfig altera_iopll_reconfig 19.1
    set_instance_parameter_value vortex_iopll_reconfig gui_advanced_reconfig 0
    set_instance_parameter_value vortex_iopll_reconfig gui_cal_mode 0
    set_instance_parameter_value vortex_iopll_reconfig gui_avalon_addr_width 10
    set_instance_parameter_value vortex_iopll_reconfig gui_reconfig_mif_filename $mif_rel
    set_instance_parameter_value vortex_iopll_reconfig gui_wait_for_lock 1
    set_instance_parameter_value vortex_iopll_reconfig gui_copy_mif 1
    validate_system
}
assert_reconfig_parameters vortex_iopll_reconfig $mif_abs $mif_rel

add_cdc board_mgmt_cdc 32 8 1 4 4
add_cdc vortex_ctrl_cdc 32 12 1 4 4
add_cdc vortex_mem_cdc 512 33 16 32 512

if {![instance_exists vortex_mem_drain_0]} {
    add_instance vortex_mem_drain_0 de10pro_vortex_mem_drain 1.0
    set_instance_parameter_value vortex_mem_drain_0 ADDRESS_WIDTH 33
    set_instance_parameter_value vortex_mem_drain_0 DATA_WIDTH 512
    set_instance_parameter_value vortex_mem_drain_0 BURSTCOUNT_WIDTH 5
    set_instance_parameter_value vortex_mem_drain_0 OUTSTANDING_WIDTH 16
    set_instance_parameter_value vortex_mem_drain_0 QUIET_CYCLES 8
}

remove_connection_if_present DUT.coreclkout_hip vortex_shell_0.clock
remove_connection_if_present DUT.app_nreset_status vortex_shell_0.reset
remove_connection_if_present BAR_INTERPRETER.bri_master vortex_shell_0.ctrl
remove_connection_if_present vortex_shell_0.avalon_master ddr4_ingress_pipe_ddr4a.s0
remove_connection_if_present vortex_mem_cdc.m0 ddr4_ingress_pipe_ddr4a.s0

set_interface_property mgmt_clk_50_b2c EXPORT_OF mgmt_clk_bridge.in_clk
set_interface_property vortex_refclk_50_b3i EXPORT_OF pll_ref_clk_bridge.in_clk
set_interface_property mgmt_reset_req EXPORT_OF mgmt_reset_bridge.in_reset
set_interface_property pll_ref_reset_req EXPORT_OF pll_ref_reset_bridge.in_reset
set_interface_property vortex_reset_req EXPORT_OF vortex_reset_controller.reset_in0
set_interface_property board_management EXPORT_OF board_manager_0.board_io

add_connection_once mgmt_clk_bridge.out_clk mgmt_reset_bridge.clk
add_connection_once mgmt_clk_bridge.out_clk vortex_iopll_reconfig.mgmt_clk
add_connection_once mgmt_clk_bridge.out_clk board_manager_0.clock
add_connection_once mgmt_clk_bridge.out_clk board_mgmt_cdc.m0_clk

add_connection_once pll_ref_clk_bridge.out_clk pll_ref_reset_bridge.clk
add_connection_once pll_ref_clk_bridge.out_clk vortex_iopll.refclk
add_connection_once pll_ref_reset_bridge.out_reset vortex_iopll.reset

add_connection_once mgmt_reset_bridge.out_reset vortex_iopll_reconfig.mgmt_reset
add_connection_once mgmt_reset_bridge.out_reset board_manager_0.reset
add_connection_once mgmt_reset_bridge.out_reset board_mgmt_cdc.m0_reset

add_connection_once vortex_iopll.reconfig_to_pll vortex_iopll_reconfig.reconfig_to_pll
add_connection_once vortex_iopll.reconfig_from_pll vortex_iopll_reconfig.reconfig_from_pll
add_connection_once board_manager_0.reconfig vortex_iopll_reconfig.mgmt_avalon_slave
set_connection_parameter_value board_manager_0.reconfig/vortex_iopll_reconfig.mgmt_avalon_slave baseAddress 0x000

add_connection_once vortex_iopll.outclk0 vortex_reset_controller.clk
add_connection_once vortex_iopll.outclk0 vortex_shell_0.clock
add_connection_once vortex_iopll.outclk0 vortex_ctrl_cdc.m0_clk
add_connection_once vortex_iopll.outclk0 vortex_mem_cdc.s0_clk
add_connection_once vortex_iopll.outclk0 board_manager_0.vortex_clock
add_connection_once vortex_iopll.locked board_manager_0.pll_status
add_connection_once vortex_reset_controller.reset_out vortex_shell_0.reset
add_connection_once vortex_reset_controller.reset_out vortex_ctrl_cdc.m0_reset
add_connection_once vortex_reset_controller.reset_out vortex_mem_cdc.s0_reset
add_connection_once board_manager_0.clock_control vortex_shell_0.clock_control
add_connection_once board_manager_0.memory_drain vortex_mem_drain_0.drain

add_connection_once DUT.coreclkout_hip board_mgmt_cdc.s0_clk
add_connection_once DUT.app_nreset_status board_mgmt_cdc.s0_reset
add_connection_once DUT.coreclkout_hip vortex_ctrl_cdc.s0_clk
add_connection_once DUT.app_nreset_status vortex_ctrl_cdc.s0_reset
add_connection_once DUT.coreclkout_hip vortex_mem_cdc.m0_clk
add_connection_once DUT.app_nreset_status vortex_mem_cdc.m0_reset
add_connection_once DUT.coreclkout_hip vortex_mem_drain_0.clock
add_connection_once DUT.app_nreset_status vortex_mem_drain_0.reset

add_connection_once BAR_INTERPRETER.bri_master board_mgmt_cdc.s0
set_connection_parameter_value BAR_INTERPRETER.bri_master/board_mgmt_cdc.s0 baseAddress 0x2000
add_connection_once board_mgmt_cdc.m0 board_manager_0.csr
set_connection_parameter_value board_mgmt_cdc.m0/board_manager_0.csr baseAddress 0x0000

add_connection_once BAR_INTERPRETER.bri_master vortex_ctrl_cdc.s0
set_connection_parameter_value BAR_INTERPRETER.bri_master/vortex_ctrl_cdc.s0 baseAddress 0x1000
add_connection_once vortex_ctrl_cdc.m0 vortex_shell_0.ctrl
set_connection_parameter_value vortex_ctrl_cdc.m0/vortex_shell_0.ctrl baseAddress 0x0000

add_connection_once vortex_shell_0.avalon_master vortex_mem_cdc.s0
set_connection_parameter_value vortex_shell_0.avalon_master/vortex_mem_cdc.s0 baseAddress 0x0000
add_connection_once vortex_mem_cdc.m0 vortex_mem_drain_0.s0
set_connection_parameter_value vortex_mem_cdc.m0/vortex_mem_drain_0.s0 baseAddress 0x0000
add_connection_once vortex_mem_drain_0.m0 ddr4_ingress_pipe_ddr4a.s0
set_connection_parameter_value vortex_mem_drain_0.m0/ddr4_ingress_pipe_ddr4a.s0 baseAddress 0x0000

validate_system

set required_connections {
    {BAR_INTERPRETER.bri_master/board_mgmt_cdc.s0 0x2000}
    {BAR_INTERPRETER.bri_master/vortex_ctrl_cdc.s0 0x1000}
    {board_mgmt_cdc.m0/board_manager_0.csr 0x0000}
    {vortex_ctrl_cdc.m0/vortex_shell_0.ctrl 0x0000}
    {vortex_shell_0.avalon_master/vortex_mem_cdc.s0 0x0000}
    {vortex_mem_cdc.m0/vortex_mem_drain_0.s0 0x0000}
    {vortex_mem_drain_0.m0/ddr4_ingress_pipe_ddr4a.s0 0x0000}
}

foreach connection_and_base $required_connections {
    set connection [lindex $connection_and_base 0]
    set expected_base [lindex $connection_and_base 1]
    if {![connection_exists $connection]} {
        error "required connection is missing: $connection"
    }
    set actual_base [get_connection_parameter_value $connection baseAddress]
    if {$actual_base != $expected_base} {
        error "unexpected base address for $connection: $actual_base"
    }
}

set vortex_mem_connections [get_connections vortex_shell_0.avalon_master]
if {[llength $vortex_mem_connections] != 1
 || ![connection_exists vortex_shell_0.avalon_master/vortex_mem_cdc.s0]} {
    error "Vortex memory master must connect only through vortex_mem_cdc"
}

set cdc_mem_connections [get_connections vortex_mem_cdc.m0]
if {[llength $cdc_mem_connections] != 1
 || ![connection_exists vortex_mem_cdc.m0/vortex_mem_drain_0.s0]} {
    error "Vortex memory CDC must connect only through vortex_mem_drain_0"
}

set drain_mem_connections [get_connections vortex_mem_drain_0.m0]
if {[llength $drain_mem_connections] != 1
 || ![connection_exists vortex_mem_drain_0.m0/ddr4_ingress_pipe_ddr4a.s0]} {
    error "Vortex memory drain must connect only to the DDR4A ingress pipeline"
}

validate_system
save_system
