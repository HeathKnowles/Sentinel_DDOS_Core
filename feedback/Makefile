# Sentinel DDoS Core - Feedback Loop
# Builds libfeedback.a

CC       ?= gcc
AR       ?= ar
CFLAGS   := -Wall -Wextra -O2 -std=c11 -I../core -MMD -MP
LDLIBS   := -lm

SRCS     := feedback.c
OBJS     := $(SRCS:.c=.o)
DEPS     := $(SRCS:.c=.d)
LIB      := libfeedback.a

-include $(DEPS)

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(LIB)
