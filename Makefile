CC=gcc
CFLAGS=-Wall -Wextra -O2
LIBS=-lnetfilter_queue -pthread

all: firewall

firewall: dynas_firewall.c
	$(CC) $(CFLAGS) -o firewall dynas_firewall.c $(LIBS)

clean:
	rm -f firewall
