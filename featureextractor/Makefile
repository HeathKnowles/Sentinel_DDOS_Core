# Feature Extractor
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I.. -lm
AR      = ar
TARGET  = libfeatureextractor.a

SRCS    = feature_extractor.c
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c feature_extractor.h ../core/sentinel_types.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
