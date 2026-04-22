CC = gcc
CFLAGS = -Wall -Wextra -g

all: hermes payload infinite membomb

hermes: hermes.c
	$(CC) $(CFLAGS) -o hermes hermes.c

payload: payload.c
	$(CC) $(CFLAGS) -o payload payload.c

infinite: infinite.c
	$(CC) $(CFLAGS) -o infinite infinite.c

membomb: membomb.c
	$(CC) $(CFLAGS) -o membomb membomb.c


BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

git:
ifndef m
	$(error You must provide a message. Use: make git m="your message")
endif
	git add .
	git commit -m "$(if $(m),$(m),Automated commit from Makefile)"
	git push origin $(BRANCH)

clean:
	rm -f hermes payload
