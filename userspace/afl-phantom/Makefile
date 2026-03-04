CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -I../../kernel
TARGET  = afl-phantom

all: $(TARGET)

$(TARGET): afl_phantom.c afl_phantom.h
	$(CC) $(CFLAGS) -o $@ afl_phantom.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
