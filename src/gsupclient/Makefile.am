# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=0:0:0

AM_CFLAGS = -Wall $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)/include \
	    $(TALLOC_CFLAGS) $(LIBOSMOCORE_CFLAGS) $(LIBOSMOABIS_CFLAGS)

lib_LTLIBRARIES = libosmo-gsup-client.la

libosmo_gsup_client_la_SOURCES = \
	ipa_name.c \
	gsup_client.c \
	gsup_req.c \
	$(NULL)

libosmo_gsup_client_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined
libosmo_gsup_client_la_LIBADD = $(TALLOC_LIBS) $(LIBOSMOCORE_LIBS) $(LIBOSMOABIS_LIBS)

noinst_PROGRAMS = gsup-test-client

gsup_test_client_SOURCES = gsup_test_client.c
gsup_test_client_LDADD = $(TALLOC_LIBS) $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) \
			 libosmo-gsup-client.la
