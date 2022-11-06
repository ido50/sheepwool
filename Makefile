.PHONY: clean install uninstall

include Makefile.configure

LDADD_STATIC    =
BINDIR          = /var/www/cgi-bin
OBJS            = compats.o database.o library.o server.o main.o
DEPS_PKG        = sqlite3 lua53 libmagic libsass libcurl libmicrohttpd tidy
STATIC_PKG     != [ -z "$(LDADD_STATIC)" ] || echo "--static"
CFLAGS_PKG     != pkg-config --cflags $(DEPS_PKG)
LDADD_PKG      != pkg-config --libs $(STATIC_PKG) $(DEPS_PKG)
VERSION         = 6.0.0
LDADD          += $(LDADD_PKG) $(LDADD_CRYPT) $(LDADD_B64_NTOP)
CFLAGS         += -Ideps $(CFLAGS_PKG) -DVERSION=\"$(VERSION)\" -O0

all: sheepwool

etlua.c: etlua.header
	@wget -O- https://raw.githubusercontent.com/leafo/etlua/8dda2e5aeb4413446172a562a9a374b700054836/etlua.lua \
		| xd -detlua | cat etlua.header - > etlua.c

sheepwool: $(OBJS) etlua.c
	$(CC) $(CFLAGS) $(LDADD_STATIC) -o $@ $(OBJS) $(LDFLAGS) $(LDADD)

install: all
	mkdir -p $(BINDIR)
	$(INSTALL_PROGRAM) sheepwool $(BINDIR)

uninstall:
	rm -f $(BINDIR)/sheepwool

clean:
	rm -f sheepwool $(OBJS)
