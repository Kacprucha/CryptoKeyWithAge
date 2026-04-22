CC = gcc 
HOST = ../..
CFLAGS = -Wall -Wextra -g -I$(HOST)
TARGETS = test_random 

all: $(TARGETS) 

test_random: test_random.c $(HOST)/protocol.c $(HOST)/device.c
	$(CC) $(CFLAGS) -o $@ $^ 

clean: 
	rm -f $(TARGETS)