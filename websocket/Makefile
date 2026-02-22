# Sentinel DDoS Core - WebSocket Server Makefile

CC       ?= gcc
CFLAGS   := -Wall -Wextra -O2 -std=c11 -I../core -pthread -MMD -MP
LDFLAGS  := -lssl -lcrypto
AR       := ar
ARFLAGS  := rcs

SOURCES  := websocket_server.c
OBJECTS  := $(SOURCES:.c=.o)
DEPS     := $(SOURCES:.c=.d)
TARGET   := libwebsocket.a

-include $(DEPS)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(DEPS) $(TARGET)
