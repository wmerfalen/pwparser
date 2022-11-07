BIN=build/pwp
CC=gcc
FLAGS=-Wall -O3
BUILD_DIR=build
LIB_TEST=$(BUILD_DIR)/libtest

main:
	$(CC) $(FLAGS) main.c -o $(BIN)

lib:
	$(CC) $(FLAGS) src/lib/test-libpwparser.c -o $(LIB_TEST)

all: build

build:
	mkdir -p ./build
