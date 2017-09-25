AC_INIT([osmo-hlr],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

dnl libtool init
LT_INIT

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip 1.9])

AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_CC
AC_PROG_INSTALL

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

PKG_CHECK_MODULES(TALLOC, [talloc >= 2.0.1])

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.9.5)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.9.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.9.0)
PKG_CHECK_MODULES(LIBOSMOCTRL, libosmoctrl)
PKG_CHECK_MODULES(LIBOSMOABIS, libosmoabis >= 0.3.2)

PKG_CHECK_MODULES(SQLITE3, sqlite3)

AC_CONFIG_MACRO_DIR([m4])

dnl checks for header files
AC_HEADER_STDC

AC_ARG_ENABLE([external_tests],
		AC_HELP_STRING([--enable-external-tests],
				[Include the VTY/CTRL tests in make check [default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
if test "x$enable_ext_tests" = "xyes" ; then
	AM_PATH_PYTHON
	AC_CHECK_PROG(OSMOTESTEXT_CHECK,osmotestvty.py,yes)
	 if test "x$OSMOTESTEXT_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install git://osmocom.org/python/osmo-python-tests to run the VTY/CTRL tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY/CTRL tests])
AC_MSG_RESULT([$enable_ext_tests])
AM_CONDITIONAL(ENABLE_EXT_TESTS, test "x$enable_ext_tests" = "xyes")

AC_OUTPUT(
	Makefile
	src/Makefile
	sql/Makefile
	tests/Makefile
	tests/auc/Makefile
	tests/auc/gen_ts_55_205_test_sets/Makefile
	tests/gsup_server/Makefile
	)
