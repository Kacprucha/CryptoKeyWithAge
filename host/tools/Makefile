CC = gcc 
HOST = ..
CFLAGS = -Wall -Wextra -g -I$(HOST)
TARGETS = tool_config 

all: $(TARGETS) 

tool_config: tool_config.c $(HOST)/protocol.c $(HOST)/device.c
	$(CC) $(CFLAGS) -o $@ $^ 

clean: 
	rm -f $(TARGETS)