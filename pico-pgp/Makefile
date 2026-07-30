CC = gcc
CFLAGS = -Wall -Wextra -O2 -g \
           -I. \
           -I/usr/include/mbedtls
LDFLAGS = -lmbedcrypto -lmbedtls -lmbedx509

SRCS = main.c \
       cmd/encrypt.c \
       cmd/decrypt.c \
       cmd/get_pub_key.c \
       pgp/pkesk.c \
       pgp/kdf.c \
       device/device.c \
	device/protocol.c \
	device/device_tup.c \
       benchmarks/timing.h

pico-pgp: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

TEST_SRCS = test/test_crypto.c \
            pgp/kdf.c \
            pgp/keywrap.c

test: $(TEST_SRCS)
	$(CC) $(CFLAGS) -o test_crypto $^ $(LDFLAGS)
	./test_crypto

BENCH_SRCS = benchmarks/bench_pgp.c \
            cmd/encrypt.c \
            cmd/decrypt.c \
            pgp/pkesk.c \
            pgp/kdf.c \
            device/device.c \
	        device/protocol.c \
	        device/device_tup.c \
            benchmarks/timing.h

bench: $(BENCH_SRCS)
	$(CC) $(CFLAGS) -o benchmarks/bench_pgp $^ $(LDFLAGS)

clean:
	rm -f pico-pgp test_crypto

.PHONY: test clean