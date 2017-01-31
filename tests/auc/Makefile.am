AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/src \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(NULL)

EXTRA_DIST = \
	auc_3g_test.ok \
	auc_3g_test.err \
	$(NULL)

noinst_PROGRAMS = \
	auc_3g_test \
	$(NULL)

auc_3g_test_SOURCES = \
	auc_3g_test.c \
	$(NULL)

auc_3g_test_LDADD = \
	$(top_srcdir)/src/auc.c \
	$(top_srcdir)/src/logging.c \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)
