CC = gcc 
HOST = ../..
CFLAGS = -Wall -Wextra -g -I$(HOST)
TARGETS = test_frame 

all: $(TARGETS) 

test_frame: test_frame.c $(HOST)/protocol.c $(HOST)/device.c
	$(CC) $(CFLAGS) -o $@ $^ 

clean: 
	rm -f $(TARGETS)