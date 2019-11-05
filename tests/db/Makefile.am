AM_CFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(SQLITE3_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	db_test.ok \
	db_test.err \
	$(NULL)

check_PROGRAMS = db_test

db_test_SOURCES = \
	db_test.c \
	$(NULL)

db_test_LDADD = \
	$(top_builddir)/src/logging.o \
	$(top_builddir)/src/db_auc.o \
	$(top_builddir)/src/db_hlr.o \
	$(top_builddir)/src/db.o \
	$(top_builddir)/src/global_title.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(SQLITE3_LIBS) \
	$(NULL)

if DB_SQLITE_DEBUG
db_test_LDADD += $(top_builddir)/src/db_debug.o
endif

.PHONY: db_test.db update_exp manual manual-nonverbose manual-gdb
db_test.db:
	rm -f db_test.db
	sqlite3 $(builddir)/db_test.db < $(top_srcdir)/sql/hlr.sql

update_exp: db_test.db
	cd $(builddir); ./db_test >"$(srcdir)/db_test.ok" 2>"$(srcdir)/db_test.err"

manual: db_test.db
	cd $(builddir); ./db_test -v

manual-nonverbose: db_test.db
	cd $(builddir); ./db_test

manual-gdb: db_test.db
	cd $(builddir); gdb -ex run --args ./db_test -v
