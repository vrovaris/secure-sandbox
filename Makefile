CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -g
OBJ = src/main.o src/sandbox.o src/seccomp.o src/cgroup.o

# 1. Build BOTH hermes and test_payload by default
all: hermes test_payload

hermes: $(OBJ)
	$(CC) $(CFLAGS) -o hermes $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 2. Point to the correct tests directory
test_payload: src/tests/test_payload.c
	$(CC) $(CFLAGS) -static -o test_payload src/tests/test_payload.c

clean:
	rm -f hermes src/*.o test_payload
