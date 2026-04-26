CC = gcc 
HOST = ../..
CFLAGS = -Wall -Wextra -g -I$(HOST)
LDLIBS  = -lmbedcrypto
TARGETS = test_ecdh 

all: $(TARGETS) 

test_ecdh: test_ecdh.c $(HOST)/protocol.c $(HOST)/device.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean: 
	rm -f $(TARGETS)