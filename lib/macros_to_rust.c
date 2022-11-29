/******************************************************************************
 * Copyright (c) USTC(Suzhou) & Huawei Technologies Co., Ltd. 2022.
 * All rights reserved.
 * curl-rust licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of
 * the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF
 * ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wyf<wuyf21@mail.ustc.edu.cn>,
 * Create: 2022-10-31
 * Description: pass the values of macro to Rust side
 *****************************************************************************/


#include "curl_setup.h"

/* start http2 */
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
/* end http2 */
/* start http_proxy */
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
#else
#endif
/* end http_proxy */

/* start http_ntlm */
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
/* end http_ntlm */

/* start ftp */
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

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h" /* for HTTP proxy tunnel stuff */
#include "ftp.h"
#include "fileinfo.h"
#include "ftplistparser.h"
#include "curl_range.h"
#include "curl_krb5.h"
#include "strtoofft.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "connect.h"
#include "strerror.h"
#include "inet_ntop.h"
#include "inet_pton.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "multiif.h"
#include "url.h"
#include "strcase.h"
#include "speedcheck.h"
#include "warnless.h"
#include "http_proxy.h"
#include "non-ascii.h"
#include "socks.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifdef CURL_DISABLE_VERBOSE_STRINGS
#define ftp_pasv_verbose(a,b,c,d)  Curl_nop_stmt
#endif
#endif
/* end ftp */

/* start ftplistparser */
#ifndef CURL_DISABLE_FTP

#include <curl/curl.h>

#include "urldata.h"
#include "fileinfo.h"
#include "llist.h"
#include "strtoofft.h"
#include "ftp.h"
#include "ftplistparser.h"
#include "curl_fnmatch.h"
#include "curl_memory.h"
#include "multiif.h"
/* The last #include file should be: */
#include "memdebug.h"

/* allocs buffer which will contain one line of LIST command response */
#define FTP_BUFFER_ALLOCSIZE 160

#endif
/* end ftplistparser */

/* start keylog */
#include "vtls/keylog.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"
/* end keylog */

/* start http_digest */
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
/* end http_digest */
/* start http_chunks */
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
/* end http_chunks */

/* start http */
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
/* end http */


/* start vtls */
#include "curl_setup.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "urldata.h"

#include "vtls/vtls.h" /* generic SSL protos etc */
#include "slist.h"
#include "sendf.h"
#include "strcase.h"
#include "url.h"
#include "progress.h"
#include "share.h"
#include "multiif.h"
#include "timeval.h"
#include "curl_md5.h"
#include "warnless.h"
#include "curl_base64.h"
#include "curl_printf.h"
#include "strdup.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"
/* end vtls */

int get_USE_RECV_BEFORE_SEND_WORKAROUND()
{
#ifdef USE_RECV_BEFORE_SEND_WORKAROUND
    return 1;
#else
    return 0;
#endif
}
int get_USE_KERBEROS5()
{
#ifdef USE_KERBEROS5
    return 1;
#else
    return 0;
#endif
}

int get_USE_NGHTTP2()
{
#ifdef USE_NGHTTP2
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_VERBOSE_STRINGS()
{
#ifdef CURL_DISABLE_VERBOSE_STRINGS
    return 1;
#else
    return 0;
#endif
}

int get_DEBUG_HTTP2()
{
#ifdef DEBUG_HTTP2
    return 1;
#else
    return 0;
#endif
}

int get_NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE()
{
#ifdef NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE
    return 1;
#else
    return 0;
#endif
}

int get_DEBUGBUILD()
{
#ifdef DEBUGBUILD
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_PROXY()
{
#ifdef CURL_DISABLE_PROXY
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_HTTP()
{
#ifdef CURL_DISABLE_HTTP
    return 1;
#else
    return 0;
#endif
}

int get_USE_HYPER()
{
#ifdef USE_HYPER
    return 1;
#else
    return 0;
#endif
}

int get_USE_SSL()
{
#ifdef USE_SSL
    return 1;
#else
    return 0;
#endif
}

int get_USE_NTLM()
{
#ifdef USE_NTLM
    return 1;
#else
    return 0;
#endif
}
int get_USE_WINDOWS_SSPI()
{
#ifdef USE_WINDOWS_SSPI
    return 1;
#else
    return 0;
#endif
}
int get_NTLM_WB_ENABLED()
{
#ifdef NTLM_WB_ENABLED
    return 1;
#else
    return 0;
#endif
}
int get_SECPKG_ATTR_ENDPOINT_BINDINGS()
{
#ifdef SECPKG_ATTR_ENDPOINT_BINDINGS
    return 1;
#else
    return 0;
#endif
}


int get_CURL_DISABLE_CRYPTO_AUTH()
{
#ifdef CURL_DISABLE_CRYPTO_AUTH
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DOES_CONVERSIONS()
{
#ifdef CURL_DOES_CONVERSIONS
    return 1;
#else
    return 0;
#endif
}

int get_USE_SPNEGO()
{
#ifdef USE_SPNEGO
    return 1;
#else
    return 0;
#endif
}

int get_CURLDEBUG()
{
#ifdef CURLDEBUG
    return 1;
#else
    return 0;
#endif
}

int get_USE_UNIX_SOCKETS()
{
#ifdef USE_UNIX_SOCKETS
    return 1;
#else
    return 0;
#endif
}

int get_ENABLE_QUIC()
{
#ifdef ENABLE_QUIC
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DO_LINEEND_CONV()
{
#ifdef CURL_DO_LINEEND_CONV
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_LIBZ()
{
#ifdef HAVE_LIBZ
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_HTTP_AUTH()
{
#ifdef CURL_DISABLE_HTTP_AUTH
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_NETRC()
{
#ifdef CURL_DISABLE_NETRC
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_PARSEDATE()
{
#ifdef CURL_DISABLE_PARSEDATE
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_MIME()
{
#ifdef CURL_DISABLE_MIME
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_ALTSVC()
{
#ifdef CURL_DISABLE_ALTSVC
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_RTSP()
{
#ifdef CURL_DISABLE_RTSP
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_HSTS()
{
#ifdef CURL_DISABLE_HSTS
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_COOKIES()
{
#ifdef CURL_DISABLE_COOKIES
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_FTP()
{
#ifdef CURL_DISABLE_FTP
    return 1;
#else
    return 0;
#endif
}

int get_NI_MAXHOST()
{
#ifdef NI_MAXHOST
    return 1;
#else
    return 0;
#endif
}

int get_INET_ADDRSTRLEN()
{
#ifdef INET_ADDRSTRLEN
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_NETINET_IN_H()
{
#ifdef HAVE_NETINET_IN_H
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_ARPA_INET_H()
{
#ifdef HAVE_ARPA_INET_H
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_NET_IF_H()
{
#ifdef HAVE_NET_IF_H
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_SYS_IOCTL_H()
{
#ifdef HAVE_SYS_IOCTL_H
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_SYS_PARAM_H()
{
#ifdef HAVE_SYS_PARAM_H
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_UTSNAME_H()
{
#ifdef HAVE_UTSNAME_H
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_NETDB_H()
{
#ifdef HAVE_NETDB_H
    return 1;
#else
    return 0;
#endif
}

int get___VMS()
{
#ifdef __VMS
    return 1;
#else
    return 0;
#endif
}

int get_ENABLE_IPV6()
{
#ifdef ENABLE_IPV6
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_GSSAPI()
{
#ifdef HAVE_GSSAPI
    return 1;
#else
    return 0;
#endif
}

int get_PF_INET6()
{
#ifdef PF_INET6
    return 1;
#else
    return 0;
#endif
}

int get_CURL_FTP_HTTPSTYLE_HEAD()
{
#ifdef CURL_FTP_HTTPSTYLE_HEAD
    return 1;
#else
    return 0;
#endif
}

int get__WIN32_WCE()
{
#ifdef _WIN32_WCE
    return 1;
#else
    return 0;
#endif
}


int get_NETWARE()
{
#ifdef NETWARE
    return 1;
#else
    return 0;
#endif
}

int get___NOVELL_LIBC__()
{
#ifdef __NOVELL_LIBC__
    return 1;
#else
    return 0;
#endif
}

int get_WIN32()
{
#ifdef WIN32
    return 1;
#else
    return 0;
#endif
}

/* bearssl */
int get_USE_BEARSSL()
{
#ifdef USE_BEARSSL
    return 1;
#else
    return 0;
#endif
}
/* gskit */
int get_USE_GSKIT()
{
#ifdef USE_GSKIT
    return 1;
#else
    return 0;
#endif
}
/* gtls */
int get_USE_GNUTLS()
{
#ifdef USE_GNUTLS
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_GNUTLS_SRP()
{
#ifdef HAVE_GNUTLS_SRP
    return 1;
#else
    return 0;
#endif
}

int get_GNUTLS_FORCE_CLIENT_CERT()
{
#ifdef GNUTLS_FORCE_CLIENT_CERT
    return 1;
#else
    return 0;
#endif
}

int get_GNUTLS_NO_TICKETS()
{
#ifdef GNUTLS_NO_TICKETS
    return 1;
#else
    return 0;
#endif
}

/* mbedtls_threadlock */
int get_USE_MBEDTLS()
{
#ifdef USE_MBEDTLS
    return 1;
#else
    return 0;
#endif
}

int get_USE_THREADS_POSIX()
{
#ifdef USE_THREADS_POSIX
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_PTHREAD_H()
{
#ifdef HAVE_PTHREAD_H
    return 1;
#else
    return 0;
#endif
}

int get_USE_THREADS_WIN32()
{
#ifdef USE_THREADS_WIN32
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_PROCESS_H()
{
#ifdef HAVE_PROCESS_H
    return 1;
#else
    return 0;
#endif
}
/* nss */
int get_USE_NSS()
{
#ifdef USE_NSS
    return 1;
#else
    return 0;
#endif
}
/* mesalink */
int get_USE_MESALINK()
{
#ifdef USE_MESALINK
    return 1;
#else
    return 0;
#endif
}

/* rustls */
int get_USE_RUSTLS()
{
#ifdef USE_RUSTLS
    return 1;
#else
    return 0;
#endif
}
/* vtls */
int get_CURL_WITH_MULTI_SSL()
{
#ifdef CURL_WITH_MULTI_SSL
    return 1;
#else
    return 0;
#endif
}
int get_CURL_DEFAULT_SSL_BACKEND()
{
#ifdef CURL_DEFAULT_SSL_BACKEND
    return 1;
#else
    return 0;
#endif
}
/* wolfssl */
int get_USE_WOLFSSL()
{
#ifdef USE_WOLFSSL
    return 1;
#else
    return 0;
#endif
}
/* struct */
int get_USE_LIBPSL()
{
#ifdef USE_LIBPSL
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_SIGNAL()
{
#ifdef HAVE_SIGNAL
    return 1;
#else
    return 0;
#endif
}

int get_USE_CURL_ASYNC()
{
#ifdef USE_CURL_ASYNC
    return 1;
#else
    return 0;
#endif
}

int get_USE_OPENSSL()
{
#ifdef USE_OPENSSL
    return 1;
#else
    return 0;
#endif
}

int get_MSDOS()
{
#ifdef MSDOS
    return 1;
#else
    return 0;
#endif
}

int get___EMX__()
{
#ifdef __EMX__
    return 1;
#else
    return 0;
#endif
}

int get_USE_TLS_SRP()
{
#ifdef USE_TLS_SRP
    return 1;
#else
    return 0;
#endif
}

int get_CURL_DISABLE_DOH()
{
#ifdef CURL_DISABLE_DOH
    return 1;
#else
    return 0;
#endif
}

int get_USE_NGHTTP3()
{
#ifdef USE_NGHTTP3
    return 1;
#else
    return 0;
#endif
}

int get_ENABLE_WAKEUP()
{
#ifdef ENABLE_WAKEUP
    return 1;
#else
    return 0;
#endif
}


int get_USE_GSASL()
{
#ifdef USE_GSASL
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_STRUCT_SOCKADDR_STORAGE()
{
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
    return 1;
#else
    return 0;
#endif
}

int get_USE_LIBSSH2()
{
#ifdef USE_LIBSSH2
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_OPAQUE_RSA_DSA_DH()
{
#ifdef HAVE_OPAQUE_RSA_DSA_DH
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_X509_GET0_EXTENSIONS()
{
#ifdef HAVE_X509_GET0_EXTENSIONS
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_X509_GET0_SIGNATURE()
{
#ifdef HAVE_X509_GET0_SIGNATURE
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_KEYLOG_CALLBACK()
{
#ifdef HAVE_KEYLOG_CALLBACK
    return 1;
#else
    return 0;
#endif
}

int get_X509_V_FLAG_PARTIAL_CHAIN()
{
#ifdef X509_V_FLAG_PARTIAL_CHAIN
    return 1;
#else
    return 0;
#endif
}

int get_X509_V_FLAG_TRUSTED_FIRST()
{
#ifdef X509_V_FLAG_TRUSTED_FIRST
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_SSL_CTX_SET_EC_CURVES()
{
#ifdef HAVE_SSL_CTX_SET_EC_CURVES
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH()
{
#ifdef HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_SSL_CTX_SET_CIPHERSUITES()
{
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
    return 1;
#else
    return 0;
#endif
}

int get_USE_HTTP2()
{
#ifdef USE_HTTP2
    return 1;
#else
    return 0;
#endif
}

int get_HAS_NPN()
{
#ifdef HAS_NPN
    return 1;
#else
    return 0;
#endif
}

int get_SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS()
{
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    return 1;
#else
    return 0;
#endif
}

int get_SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG()
{
#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
    return 1;
#else
    return 0;
#endif
}

int get_SSL_OP_NO_COMPRESSION()
{
#ifdef SSL_OP_NO_COMPRESSION
    return 1;
#else
    return 0;
#endif
}

int get_SSL_OP_NO_TICKET()
{
#ifdef SSL_OP_NO_TICKET
    return 1;
#else
    return 0;
#endif
}

int get_SSL_MODE_RELEASE_BUFFERS()
{
#ifdef SSL_MODE_RELEASE_BUFFERS
    return 1;
#else
    return 0;
#endif
}

int get_USE_OPENSSL_SRP()
{
#ifdef HAVE_OPENSSL_SRP
/* the function exists */
#ifdef USE_TLS_SRP
/* the functionality is not disabled */
#define USE_OPENSSL_SRP
#endif
#endif
#ifdef USE_OPENSSL_SRP
    return 1;
#else
    return 0;
#endif
}

int get_SSL_CTRL_SET_TLSEXT_HOSTNAME()
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_RT_INNER_CONTENT_TYPE()
{
#ifdef SSL3_RT_INNER_CONTENT_TYPE
    return 1;
#else
    return 0;
#endif
}

int get_TLS1_1_VERSION()
{
#ifdef TLS1_1_VERSION
    return 1;
#else
    return 0;
#endif
}

int get_TLS1_2_VERSION()
{
#ifdef TLS1_2_VERSION
    return 1;
#else
    return 0;
#endif
}

int get_TLS1_3_VERSION()
{
#ifdef TLS1_3_VERSION
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_VERSION()
{
#ifdef SSL3_VERSION
    return 1;
#else
    return 0;
#endif
}

int get_SSL2_VERSION()
{
#ifdef SSL2_VERSION
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_RT_HEADER()
{
#ifdef SSL3_RT_HEADER
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_MT_MESSAGE_HASH()
{
#ifdef SSL3_MT_MESSAGE_HASH
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_MT_NEXT_PROTO()
{
#ifdef SSL3_MT_NEXT_PROTO
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_MT_KEY_UPDATE()
{
#ifdef SSL3_MT_KEY_UPDATE
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_MT_END_OF_EARLY_DATA()
{
#ifdef SSL3_MT_END_OF_EARLY_DATA
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_MT_SUPPLEMENTAL_DATA()
{
#ifdef SSL3_MT_SUPPLEMENTAL_DATA
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_MT_ENCRYPTED_EXTENSIONS()
{
#ifdef SSL3_MT_ENCRYPTED_EXTENSIONS
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_MT_CERTIFICATE_STATUS()
{
#ifdef SSL3_MT_CERTIFICATE_STATUS
    return 1;
#else
    return 0;
#endif
}

int get_SSL3_MT_NEWSESSION_TICKET()
{
#ifdef SSL3_MT_NEWSESSION_TICKET
    return 1;
#else
    return 0;
#endif
}

int get_SSL2_VERSION_MAJOR()
{
#ifdef SSL2_VERSION_MAJOR
    return 1;
#else
    return 0;
#endif
}

int get_SSL_CTRL_SET_MSG_CALLBACK()
{
#ifdef SSL_CTRL_SET_MSG_CALLBACK
    return 1;
#else
    return 0;
#endif
}

int get_OPENSSL_INIT_ENGINE_ALL_BUILTIN()
{
#ifdef OPENSSL_INIT_ENGINE_ALL_BUILTIN
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_OPAQUE_EVP_PKEY()
{
#ifdef HAVE_OPAQUE_EVP_PKEY
    return 1;
#else
    return 0;
#endif
}

int get_ENGINE_CTRL_GET_CMD_FROM_NAME()
{
#ifdef ENGINE_CTRL_GET_CMD_FROM_NAME
    return 1;
#else
    return 0;
#endif
}

int get_USE_OPENSSL_ENGINE()
{
#ifdef USE_OPENSSL_ENGINE
    return 1;
#else
    return 0;
#endif
}

int get_RANDOM_FILE()
{
#ifdef RANDOM_FILE
    return 1;
#else
    return 0;
#endif
}

int get_OPENSSL_IS_BORINGSSL()
{
#ifdef OPENSSL_IS_BORINGSSL
    return 1;
#else
    return 0;
#endif
}

int get_SSL_ERROR_WANT_EARLY()
{
#ifdef SSL_ERROR_WANT_EARLY
    return 1;
#else
    return 0;
#endif
}

int get_SSL_ERROR_WANT_ASYNC_JOB()
{
#ifdef SSL_ERROR_WANT_ASYNC_JOB
    return 1;
#else
    return 0;
#endif
}

int get_SSL_ERROR_WANT_ASYNC()
{
#ifdef SSL_ERROR_WANT_ASYNC
    return 1;
#else
    return 0;
#endif
}

int get_AVE_KEYLOG_CALLBACK()
{
#ifdef AVE_KEYLOG_CALLBACK
    return 1;
#else
    return 0;
#endif
}

int get_HAVE_ASSERT_H()
{
#ifdef HAVE_ASSERT_H
    return 1;
#else
    return 0;
#endif
}