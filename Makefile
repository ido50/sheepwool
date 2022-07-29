.PHONY: clean install uninstall

include Makefile.configure

LDADD_STATIC    =
BINDIR          = /var/www/cgi-bin
OBJS            = compats.o main.o server.o fsbuild.o lua_registry.o database.o
DEPS_PKG        = sqlite3 lua53 libmagic libsass libcurl libmicrohttpd
STATIC_PKG     != [ -z "$(LDADD_STATIC)" ] || echo "--static"
CFLAGS_PKG     != pkg-config --cflags $(DEPS_PKG)
LDADD_PKG      != pkg-config --libs $(STATIC_PKG) $(DEPS_PKG)
VERSION         = 6.0.0
LDADD          += $(LDADD_PKG) $(LDADD_CRYPT) $(LDADD_B64_NTOP) $(LDADD_INOTIFYTOOLS)
CFLAGS         += -Ideps $(CFLAGS_PKG) -DVERSION=\"$(VERSION)\" -O0

all: sheepwool

sheepwool: $(OBJS)
	$(CC) $(CFLAGS) $(LDADD_STATIC) -o $@ $(OBJS) $(LDFLAGS) $(LDADD)

install: all
	mkdir -p $(BINDIR)
	$(INSTALL_PROGRAM) sheepwool $(BINDIR)

uninstall:
	rm -f $(BINDIR)/sheepwool

clean:
	rm -f sheepwool $(OBJS)
