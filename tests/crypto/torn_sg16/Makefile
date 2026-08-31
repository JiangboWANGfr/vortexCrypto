ROOT_DIR := $(realpath ../../..)
include $(ROOT_DIR)/config.mk

PROJECT := torn_sg16

SRC_DIR := $(VORTEX_HOME)/tests/crypto/$(PROJECT)

SRCS := $(SRC_DIR)/main.cpp

VX_SRCS := $(SRC_DIR)/kernel.cpp

# NOT in ../Makefile's TESTS list. This program is expected to be rejected, so
# a harness that treats a non-zero exit as failure would report it backwards.
# ci/crypto_torn_sg16.sh runs it and inverts the sense.

KERNEL_LIB := vortex2

include ../common.mk
