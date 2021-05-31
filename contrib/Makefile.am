SUBDIRS = \
	systemd \
	dgsm \
	$(NULL)

EXTRA_DIST = osmo-hlr-post-upgrade.sh

install-data-hook:
	install -Dm755 $(srcdir)/osmo-hlr-post-upgrade.sh \
		-t $(DESTDIR)$(datadir)/osmocom/

uninstall-hook:
	@$(PRE_UNINSTALL)
	$(RM) $(DESTDIR)$(datadir)/osmocom/osmo-hlr-post-upgrade.sh
