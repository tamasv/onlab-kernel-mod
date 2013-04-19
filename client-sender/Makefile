CC    = gcc
FLAGS        = 
CFLAGS       = -fPIC -g
DEBUGFLAGS   = -O0 -D _DEBUG
RELEASEFLAGS = -O2 -D NDEBUG -combine -fwhole-program

TARGET  = libdnscc_crypt.so
SOURCES = dnscc_crypt_lib.c d3des.c
HEADERS = d3des.h
OBJECTS = dnscc_crypt_lib.o d3des.o

PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin

all: $(TARGET)

$(TARGET): $(OBJECTS)
	    $(CC) $(FLAGS) $(CFLAGS) $(DEBUGFLAGS) -shared -o $(TARGET) $(OBJECTS)
