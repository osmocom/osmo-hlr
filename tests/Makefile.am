SUBDIRS = \
	auc \
	gsup_server \
	db \
	db_upgrade \
	mslookup \
	$(NULL)

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = \
	testsuite.at \
	$(srcdir)/package.m4 \
	$(TESTSUITE) \
	test_nodes.vty \
	test_subscriber.vty \
	test_subscriber.sql \
	test_subscriber.ctrl \
	$(NULL)

TESTSUITE = $(srcdir)/testsuite

DISTCLEANFILES = \
	atconfig \
	$(NULL)

if ENABLE_EXT_TESTS
python-tests:
# don't run vty and ctrl tests concurrently so that the ports don't conflict
	$(MAKE) vty-test
	$(MAKE) ctrl-test
	$(MAKE) db-upgrade-equivalence-test
else
python-tests:
	echo "Not running python-based external tests (determined at configure-time)"
endif

VTY_TEST_DB = hlr_vty_test.db
VTY_TEST ?= *.vty

# To update the VTY script from current application behavior,
# pass -u to vty_script_runner.py by doing:
#   make vty-test U=-u
vty-test:
	-rm -f $(VTY_TEST_DB)
	sqlite3 $(VTY_TEST_DB) < $(top_srcdir)/sql/hlr.sql
	sqlite3 $(VTY_TEST_DB) < $(srcdir)/test_subscriber.vty.sql
	osmo_verify_transcript_vty.py -v \
		-n OsmoHLR -p 4258 \
		-r "$(top_builddir)/src/osmo-hlr -c $(top_srcdir)/doc/examples/osmo-hlr.cfg -l $(VTY_TEST_DB)" \
		$(U) $(srcdir)/$(VTY_TEST)
	-rm -f $(VTY_TEST_DB) $(VTY_TEST_DB)-*

CTRL_TEST_DB = hlr_ctrl_test.db

# To update the CTRL script from current application behavior,
# pass -u to ctrl_script_runner.py by doing:
#   make ctrl-test U=-u
ctrl-test:
	-rm -f $(CTRL_TEST_DB)
	sqlite3 $(CTRL_TEST_DB) < $(top_srcdir)/sql/hlr.sql
	sqlite3 $(CTRL_TEST_DB) < $(srcdir)/test_subscriber.sql
	osmo_verify_transcript_ctrl.py -v \
		-p 4259 \
		-r "$(top_builddir)/src/osmo-hlr -c $(top_srcdir)/doc/examples/osmo-hlr.cfg -l $(CTRL_TEST_DB)" \
		$(U) $(srcdir)/*.ctrl
	-rm -f $(CTRL_TEST_DB)
	-rm $(CTRL_TEST_DB)-*

db-upgrade-equivalence-test:
	$(MAKE) -C db_upgrade upgrade-equivalence-test

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)
	$(MAKE) $(AM_MAKEFLAGS) python-tests

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
