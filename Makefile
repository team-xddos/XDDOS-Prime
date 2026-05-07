# ─────────────────────────────────────────────
# rawudp - Makefile
# Reconstructed from ELF binary metadata
# Original compiler: GCC 13.3.0 (Ubuntu 24.04)
# ─────────────────────────────────────────────

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lpthread

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

SRC     = $(SRC_DIR)/rawudp.c
OBJ     = $(BUILD_DIR)/rawudp.o
TARGET  = $(BIN_DIR)/rawudp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Quick build (single command, matches original compilation)
quick:
	$(CC) $(CFLAGS) $(SRC) -o rawudp $(LDFLAGS)
