CC = gcc
CFLAGS = -Wall -O2 -Iinclude -I.
LIBS = -lbcrypt

# Directories
SRC_DIR = src
INC_DIR = include
CRYPTO_DIR = $(SRC_DIR)/crypto
BUILDER_DIR = $(SRC_DIR)/builder
STUB_DIR = $(SRC_DIR)/stub
UTILS_DIR = $(SRC_DIR)/utils

# Sources
CRYPTO_SRC = $(CRYPTO_DIR)/aes.c $(CRYPTO_DIR)/monocypher.c
STUB_SRC = $(STUB_DIR)/client_stub.c $(CRYPTO_SRC)
BUILDER_SRC = $(BUILDER_DIR)/builder.c $(CRYPTO_SRC)

all: cryptext.exe

# 1. Build the utility for binary-to-C conversion
bin2c.exe: $(UTILS_DIR)/bin2c.c
	$(CC) $(CFLAGS) $(UTILS_DIR)/bin2c.c -o bin2c.exe

# 2. Build the client stub
stub.exe: $(STUB_SRC)
	$(CC) $(CFLAGS) $(STUB_SRC) -o stub.exe

# 3. Embed stub into header
stub_data.h: stub.exe bin2c.exe
	./bin2c.exe stub.exe stub_data.h

# 4. Build the final builder
cryptext.exe: $(BUILDER_SRC) stub_data.h
	$(CC) $(CFLAGS) $(BUILDER_SRC) $(LIBS) -o cryptext.exe

clean:
	del /f cryptext.exe stub.exe stub_data.h bin2c.exe
