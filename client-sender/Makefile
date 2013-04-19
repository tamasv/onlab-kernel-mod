CC    = gcc
FLAGS        = 
CFLAGS       = -fPIC -g
DEBUGFLAGS   = -O0 -D _DEBUG
RELEASEFLAGS = -O2 -D NDEBUG -combine -fwhole-program

TARGET  = libdnscc_crypt.so
SOURCES = dnscc_crypt_lib.c ../lib/d3des.c
HEADERS = d3des.h
LIBDNS_OBJECTS = dnscc_crypt_lib.o d3des.o
FREADLIB_OBJECTS = ../lib/freadlib.o

PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin

all: libdnscc_crypt.so freadlib.so

libdnscc_crypt.so: $(LIBDNS_OBJECTS)
	    $(CC) $(FLAGS) $(CFLAGS) $(DEBUGFLAGS) -shared -o libdnscc_crypt.so $(LIBDNS_OBJECTS)
freadlib.so: ../lib/freadlib.o
	    $(CC) $(FLAGS) $(CFLAGS) $(DEBUGFLAGS) -shared -o freadlib.so $(FREADLIB_OBJECTS)

