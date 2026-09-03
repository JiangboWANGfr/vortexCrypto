include ../common.mk

DESTDIR ?= $(CURDIR)/..

CONFIG_FILE := $(DESTDIR)/de10pro_config.stamp
SRC_DIR := $(VORTEX_HOME)/sw/runtime/de10pro

CXXFLAGS += -std=c++17 -Wall -Wextra -pedantic -Wfatal-errors -Werror
CXXFLAGS += -I$(INC_DIR) -I$(ROOT_DIR)/sw -I$(SW_COMMON_DIR) -I$(RT_COMMON_DIR) -I$(SRC_DIR)
CXXFLAGS += -DVX_CFG_XLEN=$(XLEN) -DVX_CFG_XLEN_$(XLEN)
CXXFLAGS += -fPIC
CXXFLAGS += $(CONFIGS)

LDFLAGS += -shared -pthread

SRCS := $(SRC_DIR)/vortex.cpp $(SRC_DIR)/driver.cpp \
	$(SRC_DIR)/board_manager.cpp
PROJECT := libvortex-de10pro.so
BOARDCTL := vortex-de10pro-boardctl
BOARDCTL_SRCS := $(SRC_DIR)/boardctl.cpp $(SRC_DIR)/driver.cpp \
	$(SRC_DIR)/board_manager.cpp
RESET := vortex-de10pro-reset
RESET_SRCS := $(SRC_DIR)/reset.cpp $(SRC_DIR)/driver.cpp

ifdef DEBUG
	CXXFLAGS += -g -O0
else
	CXXFLAGS += -O2 -DNDEBUG
endif

.PHONY: all force clean

all: $(DESTDIR)/$(PROJECT) $(DESTDIR)/$(BOARDCTL) $(DESTDIR)/$(RESET)

$(DESTDIR)/$(PROJECT): $(SRCS) $(CONFIG_FILE)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LDFLAGS) -o $@

$(DESTDIR)/$(BOARDCTL): $(BOARDCTL_SRCS) $(CONFIG_FILE)
	$(CXX) $(CXXFLAGS) $(BOARDCTL_SRCS) -pthread -o $@

$(DESTDIR)/$(RESET): $(RESET_SRCS) $(CONFIG_FILE)
	$(CXX) $(CXXFLAGS) $(RESET_SRCS) -pthread -o $@

$(CONFIG_FILE): force
	@mkdir -p $(@D)
	@TMP=$@.tmp.$$$$ ; \
	 printf '%s\n' "$(CXXFLAGS)" > $$TMP ; \
	 if ! cmp -s $$TMP $@ 2>/dev/null; then \
	   mv -f $$TMP $@ ; \
	 else \
	   rm -f $$TMP ; \
	 fi

clean:
	rm -f $(DESTDIR)/$(PROJECT) $(DESTDIR)/$(BOARDCTL) $(CONFIG_FILE)
