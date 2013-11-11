INCLUDES =  -I./include -I$(top_srcdir)/common
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

lib_LTLIBRARIES = libutil.la

libutil_la_SOURCES = \
  ./src/random.c ./src/hash.c

pkginclude_HEADERS = \
    ./include/nicira-ext.h ./include/openflow-netlink.h ./include/random.h    \
    ./include/openflow-ext.h ./include/packets.h ./include/hash.h \
    ./include/openflow-common.h ./include/openflow-10.h ./include/openflow-131.h ./include/private-ext.h \
    ./include/xtoxll.h
