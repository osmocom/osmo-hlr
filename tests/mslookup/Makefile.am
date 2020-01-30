AM_CPPFLAGS = \
	$(all_includes) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	-I$(top_srcdir)/include \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	mdns_test.err \
	mslookup_client_mdns_test.err \
	mslookup_client_test.err \
	mslookup_test.err \
	$(NULL)

check_PROGRAMS = \
	mdns_test \
	mslookup_client_test \
	mslookup_test \
	$(NULL)

mslookup_test_SOURCES = \
	mslookup_test.c \
	$(NULL)
mslookup_test_LDADD = \
	$(top_builddir)/src/mslookup/libosmo-mslookup.la \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

mslookup_client_test_SOURCES = \
	mslookup_client_test.c \
	$(NULL)
mslookup_client_test_LDADD = \
	$(top_builddir)/src/mslookup/libosmo-mslookup.la \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

mdns_test_SOURCES = \
	mdns_test.c \
	$(NULL)
mdns_test_LDADD = \
	$(top_builddir)/src/mslookup/libosmo-mslookup.la \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

if ENABLE_MSLOOKUP_CLIENT_MDNS_TEST
check_PROGRAMS += mslookup_client_mdns_test

mslookup_client_mdns_test_SOURCES = \
	mslookup_client_mdns_test.c \
	$(NULL)
mslookup_client_mdns_test_LDADD = \
	$(top_builddir)/src/mslookup/libosmo-mslookup.la \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)
endif

.PHONY: update_exp
update_exp:
	for i in $(check_PROGRAMS); do \
		echo "Updating $$i.err"; \
		$(builddir)/$$i 2>"$(srcdir)/$$i.err"; \
	done
