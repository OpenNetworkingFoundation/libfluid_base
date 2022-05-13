AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CPPFLAGS = $(libevent_core_CFLAGS) $(libevent_pthreads_CFLAGS)
if TLS
AM_CPPFLAGS += $(libevent_openssl_CFLAGS)
endif

EXTRA_DIST = README.md

AM_CPPFLAGS += -std=gnu++0x

lib_LTLIBRARIES = libfluid_base.la
libfluid_base_la_SOURCES = fluid/base/EventLoop.hh fluid/base/EventLoop.cc\
						   fluid/base/BaseOFConnection.hh fluid/base/BaseOFConnection.cc\
						   fluid/base/BaseOFServer.hh fluid/base/BaseOFServer.cc\
						   fluid/base/BaseOFClient.hh fluid/base/BaseOFClient.cc\
						   fluid/base/BaseOFTunDev.hh fluid/base/BaseOFTunDev.cc\
						   fluid/OFConnection.hh fluid/OFConnection.cc\
						   fluid/OFServerSettings.hh fluid/OFServerSettings.cc\
						   fluid/OFServer.hh fluid/OFServer.cc fluid/base/of.hh\
						   fluid/OFClient.hh fluid/OFClient.cc\
						   fluid/OFTunDev.hh fluid/OFTunDev.cc\
						   fluid/TLS.hh fluid/TLS.cc
libfluid_base_la_LIBADD = $(libevent_core_LIBS) $(libevent_pthreads_LIBS)
if TLS
libfluid_base_la_LIBADD += $(libevent_openssl_LIBS)
endif

libfluid_base_includedir = $(includedir)
nobase_libfluid_base_include_HEADERS = fluid/base/EventLoop.hh\
							   		   fluid/base/BaseOFConnection.hh\
							   		   fluid/base/BaseOFServer.hh\
							   		   fluid/base/BaseOFClient.hh\
							   		   fluid/base/BaseOFTunDev.hh\
							   		   fluid/base/of.hh\
							   		   fluid/OFConnection.hh\
							   		   fluid/OFServerSettings.hh\
							   		   fluid/OFServer.hh\
							   		   fluid/OFClient.hh\
							   		   fluid/OFTunDev.hh\
							   		   fluid/TLS.hh

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libfluid_base.pc
