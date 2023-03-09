SUBDIRS = gen_ts_55_205_test_sets

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	auc_test.ok \
	auc_test.err \
	auc_ts_55_205_test_sets.ok \
	auc_ts_55_205_test_sets.err \
	$(NULL)

check_PROGRAMS = auc_test auc_ts_55_205_test_sets

auc_test_SOURCES = \
	auc_test.c \
	$(NULL)

auc_test_LDADD = \
	$(top_builddir)/src/auc.o \
	$(top_builddir)/src/logging.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

auc_ts_55_205_test_sets_SOURCES = \
	$(builddir)/auc_ts_55_205_test_sets.c \
	$(NULL)

auc_ts_55_205_test_sets_LDADD = \
	$(top_builddir)/src/auc.o \
	$(top_builddir)/src/logging.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

auc_ts_55_205_test_sets.c: $(top_srcdir)/tests/auc/gen_ts_55_205_test_sets/*
	$(top_srcdir)/tests/auc/gen_ts_55_205_test_sets/pdftxt_2_c.py > $@

.PHONY: update_exp
update_exp:
	$(builddir)/auc_test >"$(srcdir)/auc_test.ok" 2>"$(srcdir)/auc_test.err"
	$(builddir)/auc_ts_55_205_test_sets >"$(srcdir)/auc_ts_55_205_test_sets.ok" 2>"$(srcdir)/auc_ts_55_205_test_sets.err"
