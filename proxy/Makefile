#
# Sentinel DDoS Core - XDP eBPF Makefile
#
# Builds the eBPF kernel program for zero-copy AF_XDP.
# No legacy Netfilter modules here.
#

BPF_TARGET   := sentinel_xdp.o
BPF_SOURCES  := sentinel_xdp.c

CC := clang-18

# Basic BPF compilation flags
BPF_CFLAGS := -target bpf
BPF_CFLAGS += -Wall -Wextra -O2 -g
BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu

all: $(BPF_TARGET)

$(BPF_TARGET): $(BPF_SOURCES)
	@echo "Building XDP eBPF program..."
	$(CC) $(BPF_CFLAGS) -c $< -o $@
	@echo "XDP BPF object built: $@"

clean:
	@echo "Cleaning BPF artifacts..."
	rm -f $(BPF_TARGET)
	@echo "Clean complete"

.PHONY: all clean
