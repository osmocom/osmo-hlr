AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = \
	src \
	include \
	doc \
	sql \
	contrib \
	tests \
	$(NULL)

EXTRA_DIST = \
	.version \
	README.md \
	debian \
	git-version-gen \
	$(NULL)

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-gsup-client.pc \
		 libosmo-mslookup.pc

@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
