# Sentinel DDoS Core - WebSocket Server Makefile

CC       ?= gcc
CFLAGS   := -Wall -Wextra -O2 -std=c11 -I../core -pthread
LDFLAGS  := -lssl -lcrypto
AR       := ar
ARFLAGS  := rcs

SOURCES  := websocket_server.c
OBJECTS  := $(SOURCES:.c=.o)
TARGET   := libwebsocket.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
