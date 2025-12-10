CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -O2
SRC = src/main.c src/bloom.c src/tinylfu.c src/counting_bloom.c
TARGET = test_runner

all: test

test: $(TARGET)
	./$(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all test clean
