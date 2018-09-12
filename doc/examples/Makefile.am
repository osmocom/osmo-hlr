osmoconfdir = $(sysconfdir)/osmocom
osmoconf_DATA = osmo-hlr.cfg

EXTRA_DIST = osmo-hlr.cfg

CFG_FILES = find $(srcdir) -name '*.cfg*' | sed -e 's,^$(srcdir),,'

dist-hook:
	for f in $$($(CFG_FILES)); do \
		j="$(distdir)/$$f" && \
		mkdir -p "$$(dirname $$j)" && \
		$(INSTALL_DATA) $(srcdir)/$$f $$j; \
	done

install-data-hook:
	for f in $$($(CFG_FILES)); do \
		j="$(DESTDIR)$(docdir)/examples/$$f" && \
		mkdir -p "$$(dirname $$j)" && \
		$(INSTALL_DATA) $(srcdir)/$$f $$j; \
	done

uninstall-hook:
	@$(PRE_UNINSTALL)
	for f in $$($(CFG_FILES)); do \
		j="$(DESTDIR)$(docdir)/examples/$$f" && \
		$(RM) $$j; \
	done
