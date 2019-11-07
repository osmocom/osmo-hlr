AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/src \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	run.sh \
	osmo-hlr-1.cfg \
	osmo-hlr-2.cfg \
	$(NULL)

noinst_PROGRAMS = \
	fake_msc \
	$(NULL)

fake_msc_SOURCES = \
	fake_msc.c \
	$(NULL)

fake_msc_LDADD = \
	$(top_builddir)/src/gsupclient/libosmo-gsup-client.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)

run:
	$(srcdir)/run.sh $(srcdir) $(builddir)
