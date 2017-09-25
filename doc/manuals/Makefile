# XSL stylesheets downloaded from http://docbook.sourceforge.net/release/xsl/current/html/
# Makefile from BitBake/OpenEmbedded manuals

topdir = .
hlr_reference = $(topdir)/osmohlr-vty-reference.xml
manuals = $(hlr_reference)
# types = pdf txt rtf ps xhtml html man tex texi dvi
# types = pdf txt
types = $(docbooktotypes)
docbooktotypes = pdf
# htmlcssfile =
# htmlcss =

TOPDIR := ..
ASCIIDOCS := osmohlr-usermanual

include $(TOPDIR)/build/Makefile.asciidoc.inc
include $(TOPDIR)/build/Makefile.inc

osmohlr-usermanual.pdf: chapters/*.adoc generated/docbook_vty.xml

clean:
	-rm -rf $(cleanfiles)
	-rm osmohlr-usermanual__*.svg
	-rm osmohlr-usermanual__*.png
	-rm osmohlr-usermanual.check

generated/docbook_vty.xml: osmohlr-vty-reference.xml vty/*xml ../common/vty_additions.xml ../vty_reference.xsl
	$(call command,xsltproc -o generated/combined1.xml \
		--stringparam with $(PWD)/../common/vty_additions.xml \
		$(MERGE_DOC) vty/hlr_vty_reference.xml, \
		XSLTPROC,Merging Common VTY)
	$(call command,xsltproc -o generated/combined2.xml \
		--stringparam with $(PWD)/../common/bsc_vty_additions.xml \
		$(MERGE_DOC) generated/combined1.xml, \
		XSLTPROC,Merging Common BSC VTY)
	$(call command,xsltproc -o generated/combined3.xml \
		--stringparam with $(PWD)/vty/hlr_vty_additions.xml \
		$(MERGE_DOC) generated/combined2.xml, \
		XSLTPROC,Merging HLR VTY)
	$(call command,xsltproc ../vty_reference.xsl generated/combined3.xml > generated/docbook_vty.xml, \
		XSLTPROC,Converting HLR VTY to DocBook)
