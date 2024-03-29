bin_PROGRAMS = sheepwool

sheepwool_CFLAGS = $(LIBPCRE_CFLAGS) $(LIBBROTLIENC_CFLAGS) $(LIBCONFIG_CFLAGS) $(LIBMAGIC_CFLAGS) $(LIBEVENT_FLAGS)
sheepwool_LDADD = $(LIBPCRE_LIBS) $(LIBBROTLIENC_LIBS) $(LIBCONFIG_LIBS) $(LIBMAGIC_LIBS) $(LIBEVENT_LIBS)
sheepwool_SOURCES = cmdline.c xsinit.c psgi.c html.c compress.c cache.c file.c sheepwool.c

.ggo.c:
	gengetopt --input=$<

cmdline.c: cmdline.ggo

xsinit.c:
	perl -MExtUtils::Embed -e xsinit -- -o xsinit.c
