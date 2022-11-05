BIN=build/pwp
CC=gcc
FLAGS=-Wall -O3


all: build
	$(CC) $(FLAGS) main.c -o $(BIN)

build:
	mkdir -p ./build
