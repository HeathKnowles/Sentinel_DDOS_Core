# Sentinel DDoS Core - Root Makefile
#
# Builds all components and the main pipeline binary.
#
# Targets:
#   all        - Build everything
#   libs       - Build only the static libraries
#   pipeline   - Build the main pipeline binary
#   kernel     - Build the kernel module (requires kernel headers)
#   loader     - Build the userspace loader
#   clean      - Remove all build artifacts
#   install    - Install pipeline binary to /usr/local/bin
#   test       - Run basic sanity tests
#
# Prerequisites:
#   - GCC, make
#   - Linux kernel headers (for proxy module)
#   - libcurl-dev (for SDN controller)
#   - libm (math, usually built-in)

CC       ?= gcc
CFLAGS   := -Wall -Wextra -O2 -std=c11 -I.
LDFLAGS  :=
LDLIBS   := -lm -lcurl -lpthread -lssl -lcrypto

PREFIX   ?= /usr/local

# Component directories
FE_DIR   := featureextractor
DE_DIR   := decisionengine
SDN_DIR  := sdncontrolplane
PROXY_DIR := proxy
FEEDBACK_DIR := feedback
WS_DIR   := websocket

# Libraries
FE_LIB   := $(FE_DIR)/libfeatureextractor.a
DE_LIB   := $(DE_DIR)/libdecisionengine.a
SDN_LIB  := $(SDN_DIR)/libsdncontrolplane.a
FB_LIB   := $(FEEDBACK_DIR)/libfeedback.a
WS_LIB   := $(WS_DIR)/libwebsocket.a
ALL_LIBS := $(FE_LIB) $(DE_LIB) $(SDN_LIB) $(FB_LIB) $(WS_LIB)

# Main binary
PIPELINE := sentinel_pipeline

.PHONY: all libs pipeline kernel loader feedback clean install test help

all: libs pipeline

help:
	@echo "Sentinel DDoS Core - Build System"
	@echo ""
	@echo "  make              Build all components + pipeline binary"
	@echo "  make libs         Build only the static libraries"
	@echo "  make pipeline     Build the pipeline daemon"
	@echo "  make kernel       Build the kernel module (.ko)"
	@echo "  make loader       Build the userspace loader"
	@echo "  make feedback     Build the feedback library"
	@echo "  make clean        Remove all build artifacts"
	@echo "  make install      Install pipeline to $(PREFIX)/bin"
	@echo "  make test         Run sanity checks"

# ---- libraries ----

libs: $(ALL_LIBS)

$(FE_LIB):
	$(MAKE) -C $(FE_DIR)

$(DE_LIB):
	$(MAKE) -C $(DE_DIR)

$(SDN_LIB):
	$(MAKE) -C $(SDN_DIR)

$(FB_LIB):
	$(MAKE) -C $(FEEDBACK_DIR)

$(WS_LIB):
	$(MAKE) -C $(WS_DIR)

# ---- pipeline binary ----

pipeline: $(PIPELINE)

$(PIPELINE): sentinel_pipeline.c $(ALL_LIBS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(ALL_LIBS) $(LDLIBS)

# ---- kernel module ----

kernel:
	$(MAKE) -C $(PROXY_DIR) kernel_module

# ---- userspace loader ----

loader:
	$(MAKE) -C $(PROXY_DIR) userspace_loader

# ---- feedback ----

feedback:
	$(MAKE) -C $(FEEDBACK_DIR)

# ---- clean ----

clean:
	$(MAKE) -C $(FE_DIR) clean
	$(MAKE) -C $(DE_DIR) clean
	$(MAKE) -C $(SDN_DIR) clean
	-$(MAKE) -C $(FEEDBACK_DIR) clean 2>/dev/null
	-$(MAKE) -C $(WS_DIR) clean 2>/dev/null
	-$(MAKE) -C $(PROXY_DIR) clean 2>/dev/null
	rm -f $(PIPELINE)

# ---- install ----

install: $(PIPELINE)
	install -d $(PREFIX)/bin
	install -m 755 $(PIPELINE) $(PREFIX)/bin/

# ---- test ----

test: $(PIPELINE)
	@echo "=== Sanity checks ==="
	@echo -n "Pipeline binary exists... "
	@test -f $(PIPELINE) && echo "OK" || echo "FAIL"
	@echo -n "Libraries built... "
	@test -f $(FE_LIB) -a -f $(DE_LIB) -a -f $(SDN_LIB) -a -f $(FB_LIB) && echo "OK" || echo "FAIL"
	@echo "=== Done ==="
