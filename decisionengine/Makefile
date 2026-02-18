# Sentinel DDoS Core - Decision Engine
# Builds libdecisionengine.a

CC       ?= gcc
AR       ?= ar
CFLAGS   := -Wall -Wextra -O2 -std=c11 -I../core
LDLIBS   := -lm

SRCS     := decision_engine.c
OBJS     := $(SRCS:.c=.o)
LIB      := libdecisionengine.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(LIB)
