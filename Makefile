# Sentinel DDoS Core - Root Makefile (Tier-1 stack)
#
# Single 'make' builds libs + pipeline binary. core/ is headers-only (no build).
# proxy/ is optional (build XDP object via make kernel).
#
# Targets:
#   all        - Build libraries and pipeline binary
#   libs       - Build static libraries only
#   pipeline   - Build main pipeline daemon
#   kernel     - Build XDP eBPF object (proxy/)
#   clean      - Remove all build artifacts
#   install    - Install pipeline to $(PREFIX)/bin
#   test       - Sanity checks

CC       ?= gcc
CFLAGS   := -Wall -Wextra -Werror -O3 -march=native -std=c11 -I. -I./core -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS  :=
LDLIBS   := -lm -lcurl -lpthread -lssl -lcrypto

PREFIX   ?= /usr/local

FE_DIR    := featureextractor
DE_DIR    := decisionengine
SDN_DIR   := sdncontrolplane
FEEDBACK_DIR := feedback
WS_DIR    := websocket
PROXY_DIR := proxy

FE_LIB   := $(FE_DIR)/libfeatureextractor.a
DE_LIB   := $(DE_DIR)/libdecisionengine.a
SDN_LIB  := $(SDN_DIR)/libsdncontrolplane.a
FB_LIB   := $(FEEDBACK_DIR)/libfeedback.a
WS_LIB   := $(WS_DIR)/libwebsocket.a
ALL_LIBS := $(FE_LIB) $(DE_LIB) $(SDN_LIB) $(FB_LIB) $(WS_LIB)

PIPELINE := sentinel_pipeline

.PHONY: all libs pipeline kernel loader clean install test help

all: libs pipeline

help:
	@echo "Sentinel DDoS Core - Build System"
	@echo ""
	@echo "  make              Build all components + pipeline binary"
	@echo "  make libs         Build only the static libraries"
	@echo "  make pipeline     Build the pipeline daemon"
	@echo "  make kernel       Build the XDP eBPF object (proxy/sentinel_xdp.o)"
	@echo "  make loader       Alias of 'make kernel'"
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

# ---- pipeline binary (requires all libs; core/ is -I only). Use -MMD for .h deps. ----

pipeline: $(PIPELINE)

PIPELINE_OBJ := sentinel_pipeline.o
PIPELINE_D   := sentinel_pipeline.d
-include $(PIPELINE_D)

$(PIPELINE_OBJ): sentinel_pipeline.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ sentinel_pipeline.c

$(PIPELINE): $(PIPELINE_OBJ) $(ALL_LIBS)
	$(CC) $(LDFLAGS) -o $@ $(PIPELINE_OBJ) $(ALL_LIBS) $(LDLIBS)

# ---- kernel module ----

kernel:
	$(MAKE) -C $(PROXY_DIR)

# ---- userspace loader ----

loader:
	$(MAKE) kernel

# ---- feedback ----

feedback:
	$(MAKE) -C $(FEEDBACK_DIR)

# ---- clean ----

clean:
	$(MAKE) -C $(FE_DIR) clean
	$(MAKE) -C $(DE_DIR) clean
	$(MAKE) -C $(SDN_DIR) clean
	$(MAKE) -C $(FEEDBACK_DIR) clean
	$(MAKE) -C $(WS_DIR) clean
	-$(MAKE) -C $(PROXY_DIR) clean 2>/dev/null
	rm -f $(PIPELINE) $(PIPELINE_OBJ) $(PIPELINE_D) $(TEST_EXE)

# ---- install ----

install: $(PIPELINE)
	install -d $(PREFIX)/bin
	install -m 755 $(PIPELINE) $(PREFIX)/bin/

# ---- test ----
TEST_EXE := tests/integration_test
TEST_SRC := tests/integration_test.c

$(TEST_EXE): $(TEST_SRC) $(ALL_LIBS)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(ALL_LIBS) $(LDLIBS)

test: $(PIPELINE) $(TEST_EXE)
	@echo "=== Sanity checks ==="
	@echo -n "Pipeline binary... "
	@test -f $(PIPELINE) && echo "OK" || (echo "FAIL"; exit 1)
	@echo -n "Libraries... "
	@test -f $(FE_LIB) && test -f $(DE_LIB) && test -f $(SDN_LIB) && test -f $(FB_LIB) && test -f $(WS_LIB) && echo "OK" || (echo "FAIL"; exit 1)
	@echo "=== Integration Tests ==="
	@./$(TEST_EXE)
	@echo "=== Done ==="
