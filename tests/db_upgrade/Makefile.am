EXTRA_DIST = \
	db_upgrade_test.sh \
	db_upgrade_test.err \
	db_upgrade_test.ok \
	hlr_db_v0.sql \
	osmo-hlr.cfg \
	create_subscribers.vty \
	$(NULL)

update_exp:
	$(srcdir)/db_upgrade_test.sh $(srcdir) $(builddir) >"$(srcdir)/db_upgrade_test.ok" 2>"$(srcdir)/db_upgrade_test.err"

upgrade-equivalence-test:
	$(srcdir)/db_upgrade_test.sh $(srcdir) $(builddir) do-equivalence-test
