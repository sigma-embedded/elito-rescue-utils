LIBS = -lccgi
AM_CFLAGS = -D_GNU_SOURCE -std=gnu99 -Wall -W

abs_top_srcdir := $(abspath  $(dir $(firstword ${MAKEFILE_LIST})))
abs_top_builddir := $(abspath .)

VPATH  = ${abs_top_srcdir}

prefix = /usr/local
wwwdir = ${prefix}/www
cgidir = ${wwwdir}/cgi-bin
bindir = ${prefix}/bin

all:	image-update.cgi

image-update.cgi:	cgi/main.c
	$(CC) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

$(DESTDIR)$(cgidir) $(DESTDIR)$(bindir) $(DESTDIR)$(wwwdir):
	install -d -m 0755 $@

install-exec:	image-update.cgi | $(DESTDIR)$(cgidir)
	install -p -m 0755 $^ $(DESTDIR)$(cgidir)/

install-data:	| $(DESTDIR)$(wwwdir) $(DESTDIR)$(bindir)
	install -p -m 0644 cgi/index.html $(DESTDIR)$(wwwdir)/

install-scripts:| $(DESTDIR)$(wwwdir) $(DESTDIR)$(bindir)
	install -p -m 0755 cgi/elito-stream-decode-wrap $(DESTDIR)$(bindir)/elito-stream-decode-wrap
	install -p -m 0755 blockdevice	$(DESTDIR)$(bindir)/rescue-blockdevice
	install -p -m 0755 tcp-stream	$(DESTDIR)$(bindir)/rescue-tcp-stream

install:	install-exec install-data install-scripts

clean:
	rm -f image-update.cgi
