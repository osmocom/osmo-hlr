EXTRA_DIST = example_subscriber_add_update_delete.vty \
    example_subscriber_cs_ps_enabled.ctrl \
    example_subscriber_info.ctrl \
    osmohlr-usermanual.adoc \
    osmohlr-usermanual-docinfo.xml \
    osmohlr-vty-reference.xml \
    chapters/proxy_cache_attach.msc \
    chapters/proxy_cache_more_tuples.msc \
    chapters/proxy_cache_periodic_lu.msc \
    chapters/proxy_cache_tuple_cache_dry.msc \
    chapters/proxy_cache_umts_aka_resync.msc \
    regen_doc.sh \
    chapters \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmohlr-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc $(srcdir)/*.vty $(srcdir)/*.ctrl $(srcdir)/chapters/*.msc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmohlr-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-hlr
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif

TMP_DB = generated/hlr.db

update-examples: update-examples-ctrl update-examples-vty

.PHONY: found-update-deps
found-update-deps:
	@if [ ! -f "$(top_srcdir)/sql/hlr.sql" ]; then \
		echo "You need to define OSMO_HLR_PATH to point at an osmo-hlr.git"; \
		exit 1; \
	fi
	@if [ -z "$(shell which osmo-hlr)" ]; then \
		echo "osmo-hlr needs to be installed / available in the PATH"; \
		exit 1; \
	fi
	@if [ -z "$(shell which osmo_verify_transcript_ctrl.py)" ]; then \
		echo "You need to install git.osmocom.org/python/osmo-python-tests.git"; \
		exit 1; \
	fi
	@if [ -z "$(shell which osmo_verify_transcript_vty.py)" ]; then \
		echo "You need to install git.osmocom.org/python/osmo-python-tests.git"; \
		exit 1; \
	fi

update-examples-ctrl: found-update-deps
	mkdir -p generated
	rm -f "$(TMP_DB)"
	sqlite3 "$(TMP_DB)" < "$(top_srcdir)/sql/hlr.sql"
	sqlite3 "$(TMP_DB)" < "$(top_srcdir)/tests/test_subscriber.sql"
	osmo_verify_transcript_ctrl.py \
		-r "osmo-hlr -l $(TMP_DB) -c $(top_srcdir)/doc/examples/osmo-hlr.cfg" \
		-p 4259 --update *.ctrl

update-examples-vty: found-update-deps
	mkdir -p generated
	rm -f "$(TMP_DB)"
	sqlite3 "$(TMP_DB)" < "$(top_srcdir)/sql/hlr.sql"
	osmo_verify_transcript_vty.py \
		-r "osmo-hlr -l $(TMP_DB) -c $(top_srcdir)/doc/examples/osmo-hlr.cfg" \
		-p 4258 --update *.vty
