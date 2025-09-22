CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -fno-pic -fno-pie
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
TARGET = $(notdir $(CURDIR))

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
