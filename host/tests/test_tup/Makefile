CC = gcc 
HOST = ../..
CFLAGS = -Wall -Wextra -g -I$(HOST)
TARGETS = test_tup 

all: $(TARGETS) 

test_tup: test_tup.c $(HOST)/protocol.c $(HOST)/device.c
	$(CC) $(CFLAGS) -o $@ $^ 

clean: 
	rm -f $(TARGETS)