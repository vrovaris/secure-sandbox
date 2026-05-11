CC = gcc
CFLAGS = -Wall -Wextra -g

all: payload infinite membomb syscall_attempt test_payload

payload: payload.c
	$(CC) $(CFLAGS) -static -o payload payload.c

infinite: infinite.c
	$(CC) $(CFLAGS) -static -o infinite infinite.c

membomb: membomb.c
	$(CC) $(CFLAGS) -static -o membomb membomb.c

syscall_attempt: syscall_attempt.c
	$(CC) $(CFLAGS) -static -o syscall_attempt syscall_attempt.c

test_payload: test_payload.c
	$(CC) $(CFLAGS) -static -o test_payload test_payload.c

clean:
	rm -f payload infinite membomb syscall_attempt test_payload namespace
