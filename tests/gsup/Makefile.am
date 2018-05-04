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
	$(NULL)

EXTRA_DIST = \
	gsup_test.ok \
	gsup_test.err \
	$(NULL)

noinst_PROGRAMS = \
	gsup_test \
	$(NULL)

gsup_test_SOURCES = \
	gsup_test.c \
	$(NULL)

gsup_test_LDADD = \
	$(top_srcdir)/src/luop.c \
	$(top_srcdir)/src/gsup_server.c \
	$(top_srcdir)/src/gsup_router.c \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/gsup_test >"$(srcdir)/gsup_test.ok" 2>"$(srcdir)/gsup_test.err"
