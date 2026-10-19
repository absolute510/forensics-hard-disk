CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

cforensics: cforensics.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f cforensics cforensics.exe

.PHONY: clean
