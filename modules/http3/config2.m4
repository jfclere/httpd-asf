dnl Licensed to the Apache Software Foundation (ASF) under one or more
dnl contributor license agreements.  See the NOTICE file distributed with
dnl this work for additional information regarding copyright ownership.
dnl The ASF licenses this file to You under the Apache License, Version 2.0
dnl (the "License"); you may not use this file except in compliance with
dnl the License.  You may obtain a copy of the License at
dnl
dnl      http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

dnl #  start of module specific part
APACHE_MODPATH_INIT(http3)

dnl #  list of module object files
dnl #  Sources live under src/, src/quic/, src/quic/detail/;
dnl #  VPATH in Makefile.in resolves the subdirectory paths.
http3_objs="dnl
mod_http3.lo dnl
h3_callbacks.lo dnl
h3_config.lo dnl
h3_filter.lo dnl
h3_hooks.lo dnl
h3_io.lo dnl
h3_request.lo dnl
h3_server.lo dnl
h3_session.lo dnl
h3_socket.lo dnl
h3_socket_os.lo dnl
h3_stream.lo dnl
h3_threads.lo dnl
h3q.lo dnl
h3q_conn.lo dnl
h3q_stream.lo dnl
h3q_addr.lo dnl
h3q_tls.lo dnl
"

dnl
dnl APACHE_CHECK_NGHTTP3
dnl
dnl Configure for nghttp3, giving preference to
dnl "--with-nghttp3=<path>" if it was specified.
dnl
AC_DEFUN([APACHE_CHECK_NGHTTP3],[
  AC_CACHE_CHECK([for nghttp3], [ac_cv_nghttp3], [
    dnl initialise the variables we use
    ac_cv_nghttp3=no
    ap_nghttp3_found=""
    ap_nghttp3_base=""
    ap_nghttp3_libs=""

    dnl Determine the nghttp3 base directory, if any
    AC_MSG_CHECKING([for user-provided nghttp3 base directory])
    AC_ARG_WITH(nghttp3, APACHE_HELP_STRING(--with-nghttp3=PATH, nghttp3 installation directory), [
      dnl If --with-nghttp3 specifies a directory, we use that directory
      if test "x$withval" != "xyes" -a "x$withval" != "x"; then
        dnl This ensures $withval is actually a directory and that it is absolute
        ap_nghttp3_base="`cd $withval ; pwd`"
      fi
    ])
    if test "x$ap_nghttp3_base" = "x"; then
      AC_MSG_RESULT(none)
    else
      AC_MSG_RESULT($ap_nghttp3_base)
    fi

    dnl Run header and version checks
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    dnl Before doing anything else, load in pkg-config variables
    if test -n "$PKGCONFIG"; then
      saved_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      AC_MSG_CHECKING([for pkg-config along $PKG_CONFIG_PATH])
      if test "x$ap_nghttp3_base" != "x" ; then
        if test -f "${ap_nghttp3_base}/lib/pkgconfig/libnghttp3.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libnghttp3.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_nghttp3_base}/lib/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        elif test -f "${ap_nghttp3_base}/lib64/pkgconfig/libnghttp3.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libnghttp3.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_nghttp3_base}/lib64/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        fi
      fi
      ap_nghttp3_libs="`$PKGCONFIG --libs-only-l --silence-errors libnghttp3`"
      if test $? -eq 0; then
        ap_nghttp3_found="yes"
        pkglookup="`$PKGCONFIG --cflags-only-I libnghttp3`"
        APR_ADDTO(CPPFLAGS, [$pkglookup])
        APR_ADDTO(MOD_CFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG --libs-only-L libnghttp3`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG --libs-only-other libnghttp3`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
      fi
      PKG_CONFIG_PATH="$saved_PKG_CONFIG_PATH"
    fi

    dnl fall back to the user-supplied directory if not found via pkg-config
    if test "x$ap_nghttp3_base" != "x" -a "x$ap_nghttp3_found" = "x"; then
      APR_ADDTO(CPPFLAGS, [-I$ap_nghttp3_base/include])
      APR_ADDTO(MOD_CFLAGS, [-I$ap_nghttp3_base/include])
      APR_ADDTO(LDFLAGS, [-L$ap_nghttp3_base/lib])
      APR_ADDTO(MOD_LDFLAGS, [-L$ap_nghttp3_base/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
        APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ap_nghttp3_base/lib])
        APR_ADDTO(MOD_LDFLAGS, [$ap_platform_runtime_link_flag$ap_nghttp3_base/lib])
      fi
    fi

    AC_MSG_CHECKING([for nghttp3 version >= 1.0.0])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <nghttp3/version.h>]],[[
#if !defined(NGHTTP3_VERSION_NUM)
#error "Missing nghttp3 version"
#endif
#if NGHTTP3_VERSION_NUM < 0x010000
#error "Unsupported nghttp3 version " NGHTTP3_VERSION
#endif]])],
      [AC_MSG_RESULT(OK)
       ac_cv_nghttp3=yes],
      [AC_MSG_RESULT(FAILED)])

    if test "x$ac_cv_nghttp3" = "xyes"; then
      ap_nghttp3_libs="${ap_nghttp3_libs:--lnghttp3} `$apr_config --libs`"
      APR_ADDTO(MOD_LDFLAGS, [$ap_nghttp3_libs])
      APR_ADDTO(LIBS, [$ap_nghttp3_libs])

      dnl Run library and function checks
      liberrors=""
      AC_CHECK_HEADERS([nghttp3/nghttp3.h])
      AC_CHECK_FUNCS([nghttp3_conn_server_new], [], [liberrors="yes"])
      if test "x$liberrors" != "x"; then
        AC_MSG_WARN([nghttp3 library is unusable])
      fi
    else
      AC_MSG_WARN([nghttp3 version is too old])
    fi

    dnl restore
    CPPFLAGS="$saved_CPPFLAGS"
    LIBS="$saved_LIBS"
    LDFLAGS="$saved_LDFLAGS"
  ])
  if test "x$ac_cv_nghttp3" = "xyes"; then
    AC_DEFINE(HAVE_NGHTTP3, 1, [Define if nghttp3 is available])
  fi
])


dnl
dnl APACHE_CHECK_NGTCP2
dnl
dnl Configure for ngtcp2 + ngtcp2_crypto_ossl, giving preference to
dnl "--with-ngtcp2=<path>" if it was specified.
dnl
AC_DEFUN([APACHE_CHECK_NGTCP2],[
  AC_CACHE_CHECK([for ngtcp2], [ac_cv_ngtcp2], [
    ac_cv_ngtcp2=no
    ap_ngtcp2_found=""
    ap_ngtcp2_base=""
    ap_ngtcp2_libs=""

    AC_MSG_CHECKING([for user-provided ngtcp2 base directory])
    AC_ARG_WITH(ngtcp2, APACHE_HELP_STRING(--with-ngtcp2=PATH, ngtcp2 installation directory), [
      if test "x$withval" != "xyes" -a "x$withval" != "x"; then
        ap_ngtcp2_base="`cd $withval ; pwd`"
      fi
    ])
    if test "x$ap_ngtcp2_base" = "x"; then
      AC_MSG_RESULT(none)
    else
      AC_MSG_RESULT($ap_ngtcp2_base)
    fi

    saved_CPPFLAGS="$CPPFLAGS"
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    if test -n "$PKGCONFIG"; then
      saved_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      AC_MSG_CHECKING([for ngtcp2 pkg-config along $PKG_CONFIG_PATH])
      if test "x$ap_ngtcp2_base" != "x" ; then
        if test -f "${ap_ngtcp2_base}/lib/pkgconfig/libngtcp2.pc"; then
          PKG_CONFIG_PATH="${ap_ngtcp2_base}/lib/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        elif test -f "${ap_ngtcp2_base}/lib64/pkgconfig/libngtcp2.pc"; then
          PKG_CONFIG_PATH="${ap_ngtcp2_base}/lib64/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        fi
      fi
      ap_ngtcp2_libs="`$PKGCONFIG --libs-only-l --silence-errors libngtcp2 libngtcp2_crypto_ossl`"
      if test $? -eq 0; then
        ap_ngtcp2_found="yes"
        pkglookup="`$PKGCONFIG --cflags-only-I libngtcp2 libngtcp2_crypto_ossl`"
        APR_ADDTO(CPPFLAGS, [$pkglookup])
        APR_ADDTO(MOD_CFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG --libs-only-L libngtcp2 libngtcp2_crypto_ossl`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG --libs-only-other libngtcp2 libngtcp2_crypto_ossl`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
      fi
      PKG_CONFIG_PATH="$saved_PKG_CONFIG_PATH"
    fi

    if test "x$ap_ngtcp2_base" != "x" -a "x$ap_ngtcp2_found" = "x"; then
      APR_ADDTO(CPPFLAGS, [-I$ap_ngtcp2_base/include])
      APR_ADDTO(MOD_CFLAGS, [-I$ap_ngtcp2_base/include])
      APR_ADDTO(LDFLAGS, [-L$ap_ngtcp2_base/lib])
      APR_ADDTO(MOD_LDFLAGS, [-L$ap_ngtcp2_base/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
        APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ap_ngtcp2_base/lib])
        APR_ADDTO(MOD_LDFLAGS, [$ap_platform_runtime_link_flag$ap_ngtcp2_base/lib])
      fi
    fi

    AC_MSG_CHECKING([for ngtcp2 version >= 1.0.0])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <ngtcp2/version.h>]],[[
#if !defined(NGTCP2_VERSION_NUM)
#error "Missing ngtcp2 version"
#endif
#if NGTCP2_VERSION_NUM < 0x010000
#error "Unsupported ngtcp2 version " NGTCP2_VERSION
#endif]])],
      [AC_MSG_RESULT(OK)
       ac_cv_ngtcp2=yes],
      [AC_MSG_RESULT(FAILED)])

    if test "x$ac_cv_ngtcp2" = "xyes"; then
      ap_ngtcp2_libs="${ap_ngtcp2_libs:--lngtcp2 -lngtcp2_crypto_ossl}"
      APR_ADDTO(MOD_LDFLAGS, [$ap_ngtcp2_libs])
      APR_ADDTO(LIBS, [$ap_ngtcp2_libs])

      liberrors=""
      AC_CHECK_HEADERS([ngtcp2/ngtcp2.h])
      AC_CHECK_FUNCS([ngtcp2_conn_server_new], [], [liberrors="yes"])
      if test "x$liberrors" != "x"; then
        AC_MSG_WARN([ngtcp2 library is unusable])
      fi
    else
      AC_MSG_WARN([ngtcp2 version is too old])
    fi

    CPPFLAGS="$saved_CPPFLAGS"
    LIBS="$saved_LIBS"
    LDFLAGS="$saved_LDFLAGS"
  ])
  if test "x$ac_cv_ngtcp2" = "xyes"; then
    AC_DEFINE(HAVE_NGTCP2, 1, [Define if ngtcp2 is available])
  fi
])


dnl # hook module into the Autoconf mechanism (--enable-http3)
dnl # --with-quic-backend=openssl|ngtcp2  (default: ngtcp2)
APACHE_MODULE(http3, [HTTP/3 protocol handling in addition to HTTP protocol
handling. Implemented by mod_http3. This module requires libnghttp3,
OpenSSL, and a QUIC backend (ngtcp2 or OpenSSL QUIC).
See --with-nghttp3 and --with-ngtcp2 on how to manage non-standard
locations. Use --with-quic-backend to choose between ngtcp2 (default)
and openssl. This module is usually linked shared and requires
loading. ], $http3_objs, , no, [
    AC_ARG_WITH(quic-backend,
      APACHE_HELP_STRING(--with-quic-backend=TYPE, QUIC backend: ngtcp2 or openssl @<:@ngtcp2@:>@),
      [quic_backend=$withval],
      [quic_backend=ngtcp2])

    APACHE_CHECK_OPENSSL
    if test "$ac_cv_openssl" != "yes" ; then
        enable_http3=no
    fi

    if test "$enable_http3" != "no" ; then
        APACHE_CHECK_NGHTTP3
        if test "$ac_cv_nghttp3" != "yes" ; then
            enable_http3=no
        fi
    fi

    if test "$enable_http3" != "no" ; then
        if test "$quic_backend" = "openssl" ; then
            APR_ADDTO(MOD_CPPFLAGS, ["-DH3_OPENSSL"])
        else
            APACHE_CHECK_NGTCP2
            if test "$ac_cv_ngtcp2" = "yes" ; then
                APR_ADDTO(MOD_CPPFLAGS, ["-DH3_NGTCP2"])
            else
                enable_http3=no
            fi
        fi
    fi

    if test "$enable_http3" != "no" ; then
        APR_ADDTO(MOD_CFLAGS, [-I\$(top_srcdir)/$modpath_current/include])
        if test "x$enable_http3" = "xshared"; then
           # The only symbol which needs to be exported is the module
           # structure, so ask libtool to hide everything else:
           APR_ADDTO(MOD_HTTP3_LDADD, [-export-symbols-regex http3_module])
        fi
    fi
])


dnl #  end of module specific part
APACHE_MODPATH_FINISH
