CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -I../../kernel
TARGET  = phantom-fuzz

all: $(TARGET)

$(TARGET): phantom_fuzz.c
	$(CC) $(CFLAGS) -o $@ phantom_fuzz.c -lm

clean:
	rm -f $(TARGET)

.PHONY: all clean
