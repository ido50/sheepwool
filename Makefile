.PHONY: clean install uninstall

include Makefile.configure

LDADD_STATIC    =
BINDIR          = /var/www/cgi-bin
OBJS            = compats.o main.o sheepwool.o strdup.o strsplit.o
DEPS_PKG        = sqlite3 kcgi lua53 libmagic libsass libcurl
STATIC_PKG     != [ -z "$(LDADD_STATIC)" ] || echo "--static"
CFLAGS_PKG     != pkg-config --cflags $(DEPS_PKG)
LDADD_PKG      != pkg-config --libs $(STATIC_PKG) $(DEPS_PKG)
VERSION         = 5.0.0
LDADD          += $(LDADD_PKG) $(LDADD_CRYPT)
CFLAGS         += -Ideps $(CFLAGS_PKG) -DVERSION=\"$(VERSION)\"

all: sheepwool

etlua.h:
	wget -O- https://raw.githubusercontent.com/leafo/etlua/v1.3.0/etlua.lua | xd -detlua > etlua.c

sheepwool: etlua.h $(OBJS)
	$(CC) -std=c99 $(LDADD_STATIC) -o $@ $(OBJS) $(LDFLAGS) $(LDADD)

install: all
	mkdir -p $(BINDIR)
	$(INSTALL_PROGRAM) sheepwool $(BINDIR)

uninstall:
	rm -f $(BINDIR)/sheepwool

clean:
	rm -f sheepwool $(OBJS)
