# Sentinel DDoS Core - Feedback Loop
# Builds libfeedback.a

CC       ?= gcc
AR       ?= ar
CFLAGS   := -Wall -Wextra -O2 -std=c11 -I../core
LDLIBS   := -lm

SRCS     := feedback.c
OBJS     := $(SRCS:.c=.o)
LIB      := libfeedback.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(LIB)
