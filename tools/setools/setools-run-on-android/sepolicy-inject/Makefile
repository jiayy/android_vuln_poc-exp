PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib/x86_64-linux-gnu
INCDIR ?= $(PREFIX)/include

CFLAGS ?= -g -Wall -Werror -Wshadow -O2 -pipe -fno-strict-aliasing -std=c99 -D_GNU_SOURCE -I$(INCDIR)
LDLIBS=$(LIBDIR)/libsepol.a

all: sepolicy-inject

sepolicy-inject: sepolicy-inject.c tokenize.c
