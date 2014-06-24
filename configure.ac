AC_INIT([mod_auth_mellon],[0.8.0],[olav.morken@uninett.no])

# We require support for C99.
AC_PROG_CC_C99

AC_SUBST(NAMEVER, AC_PACKAGE_TARNAME()-AC_PACKAGE_VERSION())


# This section defines the --with-apxs2 option.
AC_ARG_WITH(
	[apxs2],
	[  --with-apxs2=PATH       Full path to the apxs2 executable.],
	[
		APXS2=${withval}
	],)


if test "x$APXS2" = "x"; then
   # The user didn't specify the --with-apxs2-option.

   # Search for apxs2 in the specified directories
   AC_PATH_PROG(APXS2, apxs2,,
		/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)

   if test "x$APXS2" = "x"; then
      # Didn't find apxs2 in any of the specified directories.
      # Search for apxs instead.
      AC_PATH_PROG(APXS2, apxs,,
		   /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)
   fi

fi

# Test if $APXS2 exists and is an executable.
if test ! -x "$APXS2"; then
   # $APXS2 isn't a executable file.
   AC_MSG_ERROR([
Could not find apxs2. Please spesify the path to apxs2
using the --with-apxs2=/full/path/to/apxs2 option.
The executable may also be named 'apxs'.
])
fi

# Replace any occurances of @APXS2@ with the value of $APXS2 in the Makefile.
AC_SUBST(APXS2)

# We need the lasso library for SAML2 communication.
PKG_CHECK_MODULES(LASSO, lasso)
saved_LIBS=$LIBS; LIBS="$LIBS $LASSO_LIBS";
AC_CHECK_LIB(lasso, lasso_server_new_from_buffers,
	     LASSO_CFLAGS="$LASSO_CFLAGS -DHAVE_lasso_server_new_from_buffers")
AC_CHECK_LIB(lasso, lasso_server_load_metadata,
             LASSO_CFLAGS="$LASSO_CFLAGS -DHAVE_lasso_server_load_metadata")
AC_CHECK_LIB(lasso, lasso_profile_set_signature_verify_hint,
             LASSO_CFLAGS="$LASSO_CFLAGS -DHAVE_lasso_profile_set_signature_verify_hint")
LIBS=$saved_LIBS;
AC_SUBST(LASSO_CFLAGS)
AC_SUBST(LASSO_LIBS)

# We need the curl library for HTTP-Artifact downloads.
PKG_CHECK_MODULES(CURL, libcurl)
AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LIBS)

# We also need openssl for its random number generator.
PKG_CHECK_MODULES(OPENSSL, openssl)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

# We need at least version 2.12 of GLib.
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.12])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)


# Create Makefile from Makefile.in
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
