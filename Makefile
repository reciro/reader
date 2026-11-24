CC = gcc
CFLAGS = -g -Wall -Wextra
OUTPUT = binary/reader
FILE = src/main.c src/hash.c
INCLUDES = src

all: main run

main: $(FILE)
	$(CC) $(FILE) $(CFLAGS) -o $(OUTPUT) -I $(INCLUDES)

run: main
	./binary/reader

clean: 
	rm $(OUTPUT)

.PHONY: main run clean
