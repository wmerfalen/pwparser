BIN=build/pwp
CC=gcc
FLAGS=-Wall -Werror -Wl,--fatal-warnings
RELEASE_FLAGS=-O3
BUILD_DIR=build
LIB_TEST=$(BUILD_DIR)/libtest
DEBUG_FLAGS=-g

libtest: build
	$(CC) $(DEBUG_FLAGS) $(FLAGS) src/lib/test-libpwparser.c -o $(LIB_TEST)

all: build
	$(CC) $(FLAGS) src/lib/test-libpwparser.c -o $(LIB_TEST)

build:
	mkdir -p ./build
