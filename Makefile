CC = gcc
CFLAGS = -Wall -Wextra -g

all: hermes payload

hermes: hermes.c
	$(CC) $(CFLAGS) -o hermes hermes.c

payload: payload.c
	$(CC) $(CFLAGS) -o payload payload.c

clean:
	rm -f hermes payload
