ROOT_DIR := $(realpath ../../..)
include $(ROOT_DIR)/config.mk

PROJECT := chacha_poly

SRC_DIR := $(VORTEX_HOME)/tests/crypto/$(PROJECT)

SRCS := $(SRC_DIR)/main.cpp

VX_SRCS := $(SRC_DIR)/kernel.cpp

# 64 bytes per message, the same as aes_gcm's -n64 -b4. Sized for CI, not for
# measurement; the recorded point is in docs/proposals/crypto_isa_proposal.md.
OPTS ?= -n64 -b1

KERNEL_LIB := vortex2

include ../common.mk
