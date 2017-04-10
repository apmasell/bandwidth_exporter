AC_INIT([bandwidth_exporter], [0.1], [andre@masella.name])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS(config.h)
AC_PROG_CXX_C_O
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(MHD, [ libmicrohttpd ])

AC_PATH_PROG(PCAP_CONFIG, [pcap-config], [ AC_MSG_ERROR(Cannot find pcap-config.) ])
PCAP_LIBS="`${PCAP_CONFIG} --libs`"
PCAP_FLAGS="`${PCAP_CONFIG} --cflags`"
AC_SUBST(PCAP_LIBS)
AC_SUBST(PCAP_FLAGS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
