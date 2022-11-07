CC=gcc
FLAGS=-Wall -Werror -Wl,--fatal-warnings
RELEASE_FLAGS=-O3
DEBUG_FLAGS=-g -DDEBUG=1
makeFileDir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SRC_DIR=$(makeFileDir)/src
BUILD_DIR=$(makeFileDir)/build
BIN=$(BUILD_DIR)/pwp
LIB_TEST=$(BUILD_DIR)/libtest
LIB_INCLUDES=-I$(SRC_DIR)/lib
TEST_SIMPLE_PARSE=$(BUILD_DIR)/test-simple-parse
TEST_PLUCK_PARSE=$(BUILD_DIR)/test-pluck-parse
TESTS=$(makeFileDir)/tests

test: libtest-simple-parse libtest-pluck-parse
	$(TEST_SIMPLE_PARSE) /etc/passwd && $(TEST_PLUCK_PARSE) /etc/passwd

libtest-simple-parse: build
	$(CC) $(DEBUG_FLAGS) $(FLAGS) $(LIB_INCLUDES) $(TESTS)/simple-parse.c -o $(TEST_SIMPLE_PARSE)

libtest-pluck-parse: build
	$(CC) $(DEBUG_FLAGS) $(FLAGS) $(LIB_INCLUDES) $(TESTS)/pluck-parse.c -o $(TEST_PLUCK_PARSE)

all: build
	$(CC) $(FLAGS) src/lib/test-libpwparser.c -o $(LIB_TEST)

build:
	mkdir -p ./build
