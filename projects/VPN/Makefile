PROJECT := VPN
BUILD   := build
SRC     := src

CC      := gcc
CSTD    := -std=c99
CPPFLAGS:= -D_GNU_SOURCE -I$(SRC)/common
CFLAGS  := $(CSTD) -pedantic-errors -Wall -Wextra -g
LDLIBS  := -lcrypto

COMMON  := $(SRC)/common/tun.c \
           $(SRC)/common/udp.c \
           $(SRC)/common/aead_openssl.c \
           $(SRC)/common/packet.c \
           $(SRC)/common/util.c

SERVER  := $(SRC)/server/vpn_server.c
CLIENT  := $(SRC)/client/vpn_client.c

SERVER_BIN := $(BUILD)/vpn_server
CLIENT_BIN := $(BUILD)/vpn_client

.PHONY: all clean dirs install lint test

all: dirs $(SERVER_BIN) $(CLIENT_BIN)

dirs:
	mkdir -p $(BUILD)
	mkdir -p $(BUILD)/common $(BUILD)/server $(BUILD)/client

$(BUILD)/%.o: $(SRC)/%.c
	@echo "Compiling $<..."
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SERVER_BIN): $(COMMON:$(SRC)/%.c=$(BUILD)/%.o) $(SERVER:$(SRC)/%.c=$(BUILD)/%.o)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(CLIENT_BIN): $(COMMON:$(SRC)/%.c=$(BUILD)/%.o) $(CLIENT:$(SRC)/%.c=$(BUILD)/%.o)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

install:
	mkdir -p /usr/local/bin
	cp $(SERVER_BIN) /usr/local/bin/vpn_server
	cp $(CLIENT_BIN) /usr/local/bin/vpn_client
	@echo "Installed vpn_server and vpn_client to /usr/local/bin"

lint:
	@echo "Running code lint (gcc -Wall -Wextra -pedantic)..."
	$(CC) $(CPPFLAGS) $(CFLAGS) -fsyntax-only $(COMMON) $(SERVER) $(CLIENT)

test:
	@echo "Running integration tests..."
	@echo "Note: Sudo privileges required for network namespaces."
	@if [ -f scripts/test_vpn.sh ]; then sudo ./scripts/test_vpn.sh; else echo "Test script not found"; fi

clean:
	rm -rf $(BUILD)
	@echo "Cleaned build artifacts."

# To make, run 'make' in the VPN directory