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

// ftp

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
