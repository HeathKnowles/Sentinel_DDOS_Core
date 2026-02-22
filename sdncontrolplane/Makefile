# Sentinel DDoS Core - SDN Control Plane
# Builds libsdncontrolplane.a
# Requires: libcurl-dev

CC       ?= gcc
AR       ?= ar
CFLAGS   := -Wall -Wextra -O2 -std=c11 -I../core
LDLIBS   := -lcurl

SRCS     := sdn_controller.c
OBJS     := $(SRCS:.c=.o)
LIB      := libsdncontrolplane.a

.PHONY: all clean check-deps

all: check-deps $(LIB)

check-deps:
	@pkg-config --exists libcurl 2>/dev/null || \
	  (echo "ERROR: libcurl-dev not found. Install with:" && \
	   echo "  Arch: pacman -S curl" && \
	   echo "  Debian/Ubuntu: apt install libcurl4-openssl-dev" && \
	   echo "  Fedora: dnf install libcurl-devel" && \
	   exit 1)

CFLAGS   += -MMD -MP
DEPS     := $(SRCS:.c=.d)
-include $(DEPS)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(shell pkg-config --cflags libcurl 2>/dev/null) -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(LIB)
