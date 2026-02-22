# Sentinel DDoS Core - Decision Engine (with -MMD for .h dependency tracking)

CC       ?= gcc
AR       ?= ar
CFLAGS   := -Wall -Wextra -O2 -std=c11 -I../core -MMD -MP
LDLIBS   := -lm

SRCS     := decision_engine.c
OBJS     := $(SRCS:.c=.o)
DEPS     := $(SRCS:.c=.d)
LIB      := libdecisionengine.a

-include $(DEPS)

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(LIB)
