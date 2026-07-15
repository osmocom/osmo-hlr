SUBDIRS = \
	systemd \
	dgsm \
	$(NULL)

EXTRA_DIST = osmo-hlr-db-upgrade.sh

install-data-hook:
	install -Dm755 $(srcdir)/osmo-hlr-db-upgrade.sh \
		-t $(DESTDIR)$(datadir)/osmocom/

uninstall-hook:
	@$(PRE_UNINSTALL)
	$(RM) $(DESTDIR)$(datadir)/osmocom/osmo-hlr-db-upgrade.sh
