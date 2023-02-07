# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=1:0:0

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = -fPIC -Wall $(PCSC_CFLAGS) $(TALLOC_CFLAGS) $(LIBOSMOCORE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

lib_LTLIBRARIES = libosmo-mslookup.la

libosmo_mslookup_la_SOURCES = \
	mdns.c \
	mdns_msg.c \
	mdns_rfc.c \
	mdns_sock.c \
	mslookup.c \
	mslookup_client.c \
	mslookup_client_fake.c \
	mslookup_client_mdns.c \
	$(NULL)

libosmo_mslookup_la_LDFLAGS = -version-info $(LIBVERSION)
libosmo_mslookup_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(TALLOC_LIBS) \
	$(NULL)

bin_PROGRAMS = osmo-mslookup-client
osmo_mslookup_client_SOURCES = osmo-mslookup-client.c
osmo_mslookup_client_LDADD = \
	libosmo-mslookup.la \
	$(LIBOSMOCORE_LIBS) \
	$(TALLOC_LIBS) \
	$(NULL)
osmo_mslookup_client_CFLAGS = $(TALLOC_CFLAGS) $(LIBOSMOCORE_CFLAGS)
