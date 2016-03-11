CC = gcc
LD = $(CC)
RM = rm

CFLAGS = -g -Wall -O2 -std=c99 -D_POSIX_SOURCE
LIBS = -lgnutls

OBJECTS = x509lint.o checks.o messages.o

x509lint: $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	$(RM) -f x509lint *.o

checks.o: checks.c checks.h
x509lint.o: x509lint.c checks.h messages.h
messages.o: messages.c checks.h
