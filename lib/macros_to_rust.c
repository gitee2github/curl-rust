// http2


// http_proxy
#include "curl_setup.h"

#include "http_proxy.h"

// #if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)

#include <curl/curl.h>
#ifdef USE_HYPER
#include <hyper.h>
#endif
#include "sendf.h"
#include "http.h"
#include "url.h"
#include "select.h"
#include "progress.h"
#include "non-ascii.h"
#include "connect.h"
#include "curlx.h"
#include "vtls/vtls.h"
#include "transfer.h"
#include "multiif.h"

// start ftp ************************************************************
#ifndef CURL_DISABLE_FTP

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_UTSNAME_H
#include <sys/utsname.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include "urldata.h"
#include "if2ip.h"
#include "hostip.h"
#include "escape.h"
#include "ftp.h"
#include "fileinfo.h"
#include "ftplistparser.h"
#include "curl_range.h"
#include "curl_krb5.h"
#include "strtoofft.h"
#include "strerror.h"
#include "inet_ntop.h"
#include "inet_pton.h"
#include "parsedate.h" /* for the week day and month names */
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "strcase.h"
#include "speedcheck.h"
#include "warnless.h"
#include "socks.h"
// end ftp **************************************************************

// start ftplistparser **************************************************************
#ifndef CURL_DISABLE_FTP

#include "llist.h"
#include "curl_fnmatch.h
// end ftplistparser ************************************************************


/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

int get_CURL_DISABLE_PROXY(){
#ifdef CURL_DISABLE_PROXY
    return 1;
#else
    return 0;
#endif
}

// http_ntlm

// http_negotiate

// http_digest

// http_chunks

// http_aws_sigv4

// http

// ftplistparser
// none

// ftp
int get_CURL_DISABLE_FTP(){
#ifdef CURL_DISABLE_FTP
    return 1;
#else
    return 0;
#endif
}

int get_NI_MAXHOST(){
#ifdef NI_MAXHOST
    return 1;
#else
    return 0;
#endif
}

int get_INET_ADDRSTRLEN(){
#ifdef INET_ADDRSTRLEN
    return 1;
#else
    return 0;
#endif
}

int get_DEBUGBUILD(){
#ifdef DEBUGBUILD
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_VERBOSE_STRINGS(){
#ifdef CURL_DISABLE_VERBOSE_STRINGS
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_NETINET_IN_H(){
#ifdef HAVE_NETINET_IN_H
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_ARPA_INET_H(){
#ifdef HAVE_ARPA_INET_H
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_UTSNAME_H(){
#ifdef HAVE_UTSNAME_H
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_NETDB_H(){
#ifdef HAVE_NETDB_H
    return 1;
#else
    return 0;
#endif
}

int get___VMS(){
#ifdef __VMS
    return 1;
#else
    return 0;
#endif
}

int get_USE_SSL(){
#ifdef USE_SSL
    return 1;
#else
    return 0;
#endif
}

int get_ENABLE_IPV6(){
#ifdef ENABLE_IPV6
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_GSSAPI(){
#ifdef HAVE_GSSAPI
    return 1;
#else
    return 0;
#endif
}

int get_PF_INET6(){
#ifdef PF_INET6
    return 1;
#else
    return 0;
#endif
}

int get_CURL_FTP_HTTPSTYLE_HEAD(){
#ifdef CURL_FTP_HTTPSTYLE_HEAD
    return 1;
#else
    return 0;
#endif
}

int get__WIN32_WCE(){
#ifdef _WIN32_WCE
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DO_LINEEND_CONV(){
#ifdef CURL_DO_LINEEND_CONV
    return 1;
#else
    return 0;
#endif
}

int get_NETWARE(){
#ifdef NETWARE
    return 1;
#else
    return 0;
#endif
}

int get___NOVELL_LIBC__(){
#ifdef __NOVELL_LIBC__
    return 1;
#else
    return 0;
#endif
}

// bearssl

// gskit

// gtls

// keylog

// mbedtls

// mbedtls_threadlock

// nss

// mesalink

// openssl

// rustls

// vtls

// wolfssl
