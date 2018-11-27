TOPDIR = ..

ASCIIDOC = osmohlr-usermanual.adoc
ASCIIDOC_DEPS = chapters/*.adoc *.vty *.ctrl
include $(TOPDIR)/build/Makefile.asciidoc.inc

VTY_REFERENCE = osmohlr-vty-reference.xml
include $(TOPDIR)/build/Makefile.vty-reference.inc

include $(TOPDIR)/build/Makefile.common.inc

OSMO_HLR_PATH ?= ../../osmo-hlr
TMP_DB = generated/hlr.db

update-examples: update-examples-ctrl update-examples-vty

.PHONY: found-update-deps
found-update-deps:
	@if [ ! -f "$(OSMO_HLR_PATH)/sql/hlr.sql" ]; then \
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
	sqlite3 "$(TMP_DB)" < "$(OSMO_HLR_PATH)/sql/hlr.sql"
	sqlite3 "$(TMP_DB)" < "$(OSMO_HLR_PATH)/tests/test_subscriber.sql"
	osmo_verify_transcript_ctrl.py \
	  -r "osmo-hlr -l $(TMP_DB) -c /n/s/osmo/src/osmo-hlr/doc/examples/osmo-hlr.cfg" \
	  -p 4259 --update *.ctrl

update-examples-vty: found-update-deps
	mkdir -p generated
	rm -f "$(TMP_DB)"
	sqlite3 "$(TMP_DB)" < "$(OSMO_HLR_PATH)/sql/hlr.sql"
	osmo_verify_transcript_vty.py \
	  -r "osmo-hlr -l $(TMP_DB) -c /n/s/osmo/src/osmo-hlr/doc/examples/osmo-hlr.cfg" \
	  -p 4258 --update *.vty
