AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = \
	doc \
	src \
	include \
	sql \
	contrib \
	tests \
	$(NULL)

EXTRA_DIST = \
	.version \
	$(NULL)

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-gsup-client.pc

@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
