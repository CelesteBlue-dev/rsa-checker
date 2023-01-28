CC=gcc
CFLAGS=-O0 -Wall -static-libgcc
LDFLAGS=-lgmp
SOURCES=rsa.c main.c
EXECUTABLE=rsa
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)
