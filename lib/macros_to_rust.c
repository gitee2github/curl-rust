// http2
#include "curl_setup.h"

#ifdef USE_NGHTTP2
#include <nghttp2/nghttp2.h>
#include "urldata.h"
#include "http2.h"
#include "http.h"
#include "sendf.h"
#include "select.h"
#include "curl_base64.h"
#include "strcase.h"
#include "multiif.h"
#include "url.h"
#include "connect.h"
#include "strtoofft.h"
#include "strdup.h"
#include "dynbuf.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define H2_BUFSIZE 32768

#if (NGHTTP2_VERSION_NUM < 0x010c00)
#error too old nghttp2 version, upgrade!
#endif

#ifdef CURL_DISABLE_VERBOSE_STRINGS
#define nghttp2_session_callbacks_set_error_callback(x,y)
#endif

#if (NGHTTP2_VERSION_NUM >= 0x010c00)
#define NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE 1
#endif

#define HTTP2_HUGE_WINDOW_SIZE (32 * 1024 * 1024) /* 32 MB */

#ifdef DEBUG_HTTP2
#define H2BUGF(x) x
#else
#define H2BUGF(x) do { } while(0)
#endif



#else /* !USE_NGHTTP2 */
/* Satisfy external references even if http2 is not compiled in. */
#include <curl/curl.h>

#endif /* USE_NGHTTP2 */
int get_USE_NGHTTP2(){
#ifdef USE_NGHTTP2
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
int get_DEBUG_HTTP2(){
#ifdef DEBUG_HTTP2
    return 1;
#else
    return 0;
#endif
}
int get_NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE(){
#ifdef NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE
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
// http_proxy
#include "curl_setup.h"

#include "http_proxy.h"

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)

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

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#endif /* CURL_DISABLE_PROXY */

int get_CURL_DISABLE_PROXY(){
#ifdef CURL_DISABLE_PROXY
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DISABLE_HTTP(){
#ifdef CURL_DISABLE_HTTP
    return 1;
#else
    return 0;
#endif
}
int get_USE_HYPER(){
#ifdef USE_HYPER
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
// http_ntlm
#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NTLM)

#define DEBUG_ME 0

#include "urldata.h"
#include "sendf.h"
#include "strcase.h"
#include "http_ntlm.h"
#include "curl_ntlm_core.h"
#include "curl_ntlm_wb.h"
#include "curl_base64.h"
#include "vauth/vauth.h"
#include "url.h"

/* SSL backend-specific #if branches in this file must be kept in the order
   documented in curl_ntlm_core. */
#if defined(USE_WINDOWS_SSPI)
#include "curl_sspi.h"
#endif

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if DEBUG_ME
# define DEBUG_OUT(x) x
#else
# define DEBUG_OUT(x) Curl_nop_stmt
#endif
#endif /* !CURL_DISABLE_HTTP && USE_NTLM */
int get_USE_NTLM(){
#ifdef USE_NTLM
    return 1;
#else
    return 0;
#endif
}
int get_USE_WINDOWS_SSPI(){
#ifdef USE_WINDOWS_SSPI
    return 1;
#else
    return 0;
#endif
}
int get_NTLM_WB_ENABLED(){
#ifdef NTLM_WB_ENABLED
    return 1;
#else
    return 0;
#endif
}
int get_SECPKG_ATTR_ENDPOINT_BINDINGS(){
#ifdef SECPKG_ATTR_ENDPOINT_BINDINGS
    return 1;
#else
    return 0;
#endif
}
// http_negotiate

// http_digest
#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_CRYPTO_AUTH)

#include "urldata.h"
#include "strcase.h"
#include "vauth/vauth.h"
#include "http_digest.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"
#endif 

int get_CURL_DISABLE_CRYPTO_AUTH(){
#ifdef CURL_DISABLE_CRYPTO_AUTH
    return 1;
#else
    return 0;
#endif
}

// http_chunks
#include "curl_setup.h"

#ifndef CURL_DISABLE_HTTP

#include "urldata.h" /* it includes http_chunks.h */
#include "sendf.h"   /* for the client write stuff */
#include "dynbuf.h"
#include "content_encoding.h"
#include "http.h"
#include "non-ascii.h" /* for Curl_convert_to_network prototype */
#include "strtoofft.h"
#include "warnless.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"
#endif /* CURL_DISABLE_HTTP */

int get_CURL_DOES_CONVERSIONS(){
#ifdef CURL_DOES_CONVERSIONS
    return 1;
#else
    return 0;
#endif
}

// http_aws_sigv4
// no macro

// http

#include "curl_setup.h"

#ifndef CURL_DISABLE_HTTP

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef USE_HYPER
#include <hyper.h>
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"
#include "formdata.h"
#include "mime.h"
#include "progress.h"
#include "curl_base64.h"
#include "cookie.h"
#include "vauth/vauth.h"
#include "vtls/vtls.h"
#include "http_digest.h"
#include "http_ntlm.h"
#include "curl_ntlm_wb.h"
#include "http_negotiate.h"
#include "http_aws_sigv4.h"
#include "url.h"
#include "share.h"
#include "hostip.h"
#include "http.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */
#include "strtoofft.h"
#include "multiif.h"
#include "strcase.h"
#include "content_encoding.h"
#include "http_proxy.h"
#include "warnless.h"
#include "non-ascii.h"
#include "http2.h"
#include "connect.h"
#include "strdup.h"
#include "altsvc.h"
#include "hsts.h"
#include "c-hyper.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"
#endif /* CURL_DISABLE_HTTP */

int get_USE_SPNEGO(){
#ifdef USE_SPNEGO
    return 1;
#else
    return 0;
#endif
}
int get_CURLDEBUG(){
#ifdef CURLDEBUG
    return 1;
#else
    return 0;
#endif
}
int get_USE_UNIX_SOCKETS(){
#ifdef USE_UNIX_SOCKETS
    return 1;
#else
    return 0;
#endif
}
int get_ENABLE_QUIC(){
#ifdef ENABLE_QUIC
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
int get_HAVE_LIBZ(){
#ifdef HAVE_LIBZ
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DISABLE_HTTP_AUTH(){
#ifdef CURL_DISABLE_HTTP_AUTH
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DISABLE_NETRC(){
#ifdef CURL_DISABLE_NETRC
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DISABLE_PARSEDATE(){
#ifdef CURL_DISABLE_PARSEDATE
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DISABLE_MIME(){
#ifdef CURL_DISABLE_MIME
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DISABLE_ALTSVC(){
#ifdef CURL_DISABLE_ALTSVC
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DISABLE_RTSP(){
#ifdef CURL_DISABLE_RTSP
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DISABLE_HSTS(){
#ifdef CURL_DISABLE_HSTS
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DISABLE_COOKIES(){
#ifdef CURL_DISABLE_COOKIES
    return 1;
#else
    return 0;
#endif
}

// ftplistparser

// ftp

// bearssl

// gskit

// gtls

// keylog
#include "curl_setup.h"

#include "vtls/keylog.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"
int get_WIN32(){
#ifdef WIN32
    return 1;
#else
    return 0;
#endif
}
// mbedtls

// mbedtls_threadlock

// nss

// mesalink

// openssl

// rustls

// vtls

// wolfssl
