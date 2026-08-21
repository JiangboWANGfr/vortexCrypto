ROOT_DIR := $(realpath ../../..)
include $(ROOT_DIR)/config.mk

PROJECT := poly16_probe

SRC_DIR := $(VORTEX_HOME)/tests/crypto/$(PROJECT)

SRCS := $(SRC_DIR)/main.cpp

VX_SRCS := $(SRC_DIR)/kernel.cpp

# NOT in ../Makefile's TESTS list. This program is probe for poly4.step.sg16; compares against a host reference.
# a harness that treats a non-zero exit as failure would report it backwards.
# ci/crypto_poly16_probe.sh runs it and inverts the sense.

KERNEL_LIB := vortex2

include ../common.mk
