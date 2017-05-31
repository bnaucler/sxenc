CC = cc
TARGET = sxenc
SOURCE = *.c
DESTDIR = /usr/bin
CFLAGS ?= -Wall -g -O2

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

install:
	cp $(TARGET) $(DESTDIR)
