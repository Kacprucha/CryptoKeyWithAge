CC = gcc 
HOST = ../..
CFLAGS = -Wall -Wextra -g -I$(HOST)
TARGETS = test_protocol 

all: $(TARGETS) 

test_protocol: test_protocol.c $(HOST)/protocol.c
	$(CC) $(CFLAGS) -o $@ $^ 

clean: 
	rm -f $(TARGETS)