# All the executables we want to compile
bin_PROGRAMS = sheepwool

sheepwool_CFLAGS = $(LIBMAGIC_CFLAGS) $(LIBMICRHTTPD_FLAGS)
sheepwool_LDADD = $(LIBMAGIC_LIBS) $(LIBMICROHTTPD_LIBS)
sheepwool_SOURCES = main.c cmdline.c list.c hash.c str-utils.c

.ggo.c:
	gengetopt --input=$<

cmdline.c: cmdline.ggo
