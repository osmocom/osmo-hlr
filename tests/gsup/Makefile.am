AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	gsup_test.ok \
	gsup_test.err \
	$(NULL)

check_PROGRAMS = \
	gsup_test \
	$(NULL)

gsup_test_SOURCES = \
	gsup_test.c \
	$(NULL)

gsup_test_LDADD = \
	$(top_builddir)/src/gsupclient/libosmo-gsup-client.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/gsup_test >"$(srcdir)/gsup_test.ok" 2>"$(srcdir)/gsup_test.err"
