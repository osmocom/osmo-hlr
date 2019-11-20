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
	gsup_server_test.ok \
	gsup_server_test.err \
	$(NULL)

noinst_PROGRAMS = \
	gsup_server_test \
	$(NULL)

gsup_server_test_SOURCES = \
	gsup_server_test.c \
	$(NULL)

gsup_server_test_LDADD = \
	$(top_srcdir)/src/gsup_server.c \
	$(top_srcdir)/src/gsup_router.c \
	$(top_srcdir)/src/gsupclient/ipa_name.c \
	$(top_srcdir)/src/gsupclient/gsup_req.c \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/gsup_server_test >"$(srcdir)/gsup_server_test.ok" 2>"$(srcdir)/gsup_server_test.err"
