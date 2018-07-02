EXTRA_DIST = \
	hlr_data.sql \
	hlr.sql \
	$(NULL)

sqldir = $(docdir)/sql
sql_DATA = $(srcdir)/hlr.sql $(srcdir)/hlr_data.sql


install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/osmocom

uninstall-hook:
	rm -rf $(DESTDIR)$(localstatedir)/lib/osmocom
