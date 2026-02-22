# Feature Extractor (with -MMD for .h dependency tracking)
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I.. -MMD -MP
AR      = ar
TARGET  = libfeatureextractor.a

SRCS    = feature_extractor.c
OBJS    = $(SRCS:.c=.o)
DEPS    = $(SRCS:.c=.d)

-include $(DEPS)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

.PHONY: all clean
