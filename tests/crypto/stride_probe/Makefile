ROOT_DIR := $(realpath ../../..)
include $(ROOT_DIR)/config.mk

PROJECT := stride_probe

SRC_DIR := $(VORTEX_HOME)/tests/crypto/$(PROJECT)

SRCS := $(SRC_DIR)/main.cpp

VX_SRCS := $(SRC_DIR)/kernel.cpp

# NOT in ../Makefile's TESTS list, and deliberately. The family cases in
# ci/testcases/crypto.yaml run at the shipped shape, where NUM_THREADS equals
# DCACHE_NUM_WAYS and no set can be oversubscribed -- the probe would report a
# flat line and gate nothing. Run it by hand, at a shape with more lanes than
# ways:
#
#   ./ci/blackbox.sh --driver=rtlsim --app=crypto/stride_probe --threads=16 \
#                    --args="-m ways"
#
# Default is the stride sweep: n_alias fixed at every lane and alias_stride
# stepped across the way span, cheap enough to finish in seconds. The knee
# sweep (-m ways) is the diagnostic one -- alias_stride fixed at vx_start.S's
# 8192 and the number of lanes sharing one D-cache set swept 1..NUM_THREADS.
# What the knee means is in the header of kernel.cpp.
OPTS ?= -m stride -i 64 -w 16 -r 1

KERNEL_LIB := vortex2

include ../common.mk
