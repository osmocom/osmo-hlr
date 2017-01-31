SUBDIRS = gen_ts_55_205_test_sets

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
	auc_ts_55_205_test_sets.ok \
	auc_ts_55_205_test_sets.err \
	$(NULL)


noinst_PROGRAMS = \
	auc_3g_test \
	auc_ts_55_205_test_sets \
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

auc_ts_55_205_test_sets_SOURCES = \
	$(builddir)/auc_ts_55_205_test_sets.c \
	$(NULL)

auc_ts_55_205_test_sets_LDADD = \
	$(top_srcdir)/src/auc.c \
	$(top_srcdir)/src/logging.c \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

auc_ts_55_205_test_sets.c: $(top_srcdir)/tests/auc/gen_ts_55_205_test_sets/*
	$(top_srcdir)/tests/auc/gen_ts_55_205_test_sets/pdftxt_2_c.py > $@

