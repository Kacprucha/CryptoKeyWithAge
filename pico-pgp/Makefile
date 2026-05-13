CC = gcc
CFLAGS = -Wall -Wextra -O2 -g \
           -I. -I./pgp -I./device \
           $(shell pkg-config --cflags mbedtls)
LDFLAGS = $(shell pkg-config --libs mbedtls) \
           -lmbedcrypto -lmbedtls -lmbedx509

SRCS = main.c \
       cmd/encrypt.c \
       cmd/decrypt.c \
       pgp/packet.c \
       pgp/kdf.c \
       pgp/keywrap.c \
       pgp/seipd.c \
       pgp/mpi.c \
       device/device.c \
	   device/protocol.c \
	   device/device_tup.c

pico-pgp: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

TEST_SRCS = test/test_crypto.c \
            pgp/kdf.c \
            pgp/keywrap.c

test: $(TEST_SRCS)
	$(CC) $(CFLAGS) -o test_crypto $^ $(LDFLAGS)
	./test_crypto

BENCH_SRCS = benchmarks/bench_pgp.c \
            pgp/kdf.c \
			pgp/keywrap.c \
			pgp/seipd.c \
            pgp/packet.c \
			pgp/mpi.c \
            device/device.c \
			device/protocol.c

bench: $(BENCH_SRCS)
	$(CC) $(CFLAGS) -o benchmarks/bench_pgp $^ $(LDFLAGS)

clean:
	rm -f pico-pgp test_crypto

.PHONY: test clean