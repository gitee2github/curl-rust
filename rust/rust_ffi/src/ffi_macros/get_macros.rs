extern "C" {
    // http2
    fn get_USE_NGHTTP2() -> i32;
    fn get_CURL_DISABLE_VERBOSE_STRINGS() -> i32;
    fn get_DEBUG_HTTP2() -> i32;
    fn get_NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE() -> i32;
    fn get_DEBUGBUILD() -> i32;
    // http_proxy
    fn get_CURL_DISABLE_PROXY() -> i32;
    fn get_CURL_DISABLE_HTTP() -> i32;
    fn get_USE_HYPER() -> i32;
    fn get_USE_SSL() -> i32;
    // http_ntlm
    fn get_USE_NTLM() -> i32;
    fn get_USE_WINDOWS_SSPI() -> i32;
    fn get_NTLM_WB_ENABLED() -> i32;
    fn get_SECPKG_ATTR_ENDPOINT_BINDINGS() -> i32;
    // http_negotiate

    // http_digest
    fn get_CURL_DISABLE_CRYPTO_AUTH() -> i32;
    // http_chunks
    fn get_CURL_DOES_CONVERSIONS() -> i32;
    // http_aws_sigv4
    // no macro
    // http
    fn get_USE_SPNEGO() -> i32;
    fn get_CURLDEBUG() -> i32;
    fn get_USE_UNIX_SOCKETS() -> i32;
    fn get_ENABLE_QUIC() -> i32;
    fn get_CURL_DO_LINEEND_CONV() -> i32;
    fn get_HAVE_LIBZ() -> i32;
    fn get_CURL_DISABLE_HTTP_AUTH() -> i32;
    fn get_CURL_DISABLE_NETRC() -> i32;
    fn get_CURL_DISABLE_PARSEDATE() -> i32;
    fn get_CURL_DISABLE_MIME() -> i32;
    fn get_CURL_DISABLE_ALTSVC() -> i32;
    fn get_CURL_DISABLE_RTSP() -> i32;
    fn get_CURL_DISABLE_HSTS() -> i32;
    fn get_CURL_DISABLE_COOKIES() -> i32;

    // ftplistparser

    // ftp

    // bearssl

    // gskit

    // gtls

    // keylog
    fn get_WIN32() -> i32;

    // mbedtls

    // mbedtls_threadlock

    // nss

    // mesalink

    // openssl

    // rustls

    // vtls

    // wolfssl
}
pub fn get_all_cfg() {
    // http2
    get_USE_NGHTTP2_add_cfg();
    get_CURL_DISABLE_VERBOSE_STRINGS_add_cfg();
    get_DEBUG_HTTP2_add_cfg();
    get_NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE_add_cfg();
    get_DEBUGBUILD_add_cfg();
    // http_proxy
    get_CURL_DISABLE_PROXY_add_cfg();
    get_CURL_DISABLE_HTTP_add_cfg();
    get_USE_HYPER_add_cfg();
    get_USE_SSL_add_cfg();
    // http_ntlm
    get_USE_NTLM_add_cfg();
    get_USE_WINDOWS_SSPI_add_cfg();
    get_NTLM_WB_ENABLED_add_cfg();
    get_SECPKG_ATTR_ENDPOINT_BINDINGS_add_cfg();
    // http_negotiate

    // http_digest
    get_CURL_DISABLE_CRYPTO_AUTH_add_cfg();
    // http_chunks
    get_CURL_DOES_CONVERSIONS_add_cfg();
    // http_aws_sigv4

    // http
    get_USE_SPNEGO_add_cfg();
    get_CURLDEBUG_add_cfg();
    get_USE_UNIX_SOCKETS_add_cfg();
    get_ENABLE_QUIC_add_cfg();
    get_CURL_DO_LINEEND_CONV_add_cfg();
    get_HAVE_LIBZ_add_cfg();
    get_CURL_DISABLE_HTTP_AUTH_add_cfg();
    get_CURL_DISABLE_NETRC_add_cfg();
    get_CURL_DISABLE_PARSEDATE_add_cfg();
    get_CURL_DISABLE_MIME_add_cfg();
    get_CURL_DISABLE_ALTSVC_add_cfg();
    get_CURL_DISABLE_RTSP_add_cfg();
    get_CURL_DISABLE_HSTS_add_cfg();
    get_CURL_DISABLE_COOKIES_add_cfg();

    // ftplistparser

    // ftp

    // bearssl

    // gskit

    // gtls

    // keylog
    get_WIN32_add_cfg();

    // mbedtls

    // mbedtls_threadlock

    // nss

    // mesalink

    // openssl

    // rustls

    // vtls

    // wolfssl
}

// http2
fn get_USE_NGHTTP2_add_cfg() {
    if unsafe { get_USE_NGHTTP2() } == 1 {
        println!("cargo:rustc-cfg=USE_NGHTTP2");
    }
}
fn get_CURL_DISABLE_VERBOSE_STRINGS_add_cfg() {
    if unsafe { get_CURL_DISABLE_VERBOSE_STRINGS() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_VERBOSE_STRINGS");
    }
}
fn get_DEBUG_HTTP2_add_cfg() {
    if unsafe { get_DEBUG_HTTP2() } == 1 {
        println!("cargo:rustc-cfg=DEBUG_HTTP2");
    }
}
fn get_NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE_add_cfg() {
    if unsafe { get_NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE() } == 1 {
        println!("cargo:rustc-cfg=NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE");
    }
}
fn get_DEBUGBUILD_add_cfg() {
    if unsafe { get_DEBUGBUILD() } == 1 {
        println!("cargo:rustc-cfg=DEBUGBUILD");
    }
}
// http_proxy
fn get_CURL_DISABLE_PROXY_add_cfg() {
    if unsafe { get_CURL_DISABLE_PROXY() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_PROXY");
    }
}
fn get_CURL_DISABLE_HTTP_add_cfg() {
    if unsafe { get_CURL_DISABLE_HTTP() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_HTTP");
    }
}
fn get_USE_HYPER_add_cfg() {
    if unsafe { get_USE_HYPER() } == 1 {
        println!("cargo:rustc-cfg=USE_HYPER");
    }
}
fn get_USE_SSL_add_cfg() {
    if unsafe { get_USE_SSL() } == 1 {
        println!("cargo:rustc-cfg=USE_SSL");
    }
}
// http_ntlm
fn get_USE_NTLM_add_cfg() {
    if unsafe { get_USE_NTLM() } == 1 {
        println!("cargo:rustc-cfg=USE_NTLM");
    }
}
fn get_USE_WINDOWS_SSPI_add_cfg() {
    if unsafe { get_USE_WINDOWS_SSPI() } == 1 {
        println!("cargo:rustc-cfg=USE_WINDOWS_SSPI");
    }
}
fn get_NTLM_WB_ENABLED_add_cfg() {
    if unsafe { get_NTLM_WB_ENABLED() } == 1 {
        println!("cargo:rustc-cfg=NTLM_WB_ENABLED");
    }
}
fn get_SECPKG_ATTR_ENDPOINT_BINDINGS_add_cfg() {
    if unsafe { get_SECPKG_ATTR_ENDPOINT_BINDINGS() } == 1 {
        println!("cargo:rustc-cfg=SECPKG_ATTR_ENDPOINT_BINDINGS");
    }
}
// http_negotiate

// http_digest
fn get_CURL_DISABLE_CRYPTO_AUTH_add_cfg() {
    if unsafe { get_CURL_DISABLE_CRYPTO_AUTH() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_CRYPTO_AUTH");
    }
}
// http_chunks
fn get_CURL_DOES_CONVERSIONS_add_cfg() {
    if unsafe { get_CURL_DOES_CONVERSIONS() } == 1 {
        println!("cargo:rustc-cfg=CURL_DOES_CONVERSIONS");
    }
}
// http_aws_sigv4

// http
fn get_USE_SPNEGO_add_cfg() {
    if unsafe { get_USE_SPNEGO() } == 1 {
        println!("cargo:rustc-cfg=USE_SPNEGO");
    }
}
fn get_CURLDEBUG_add_cfg() {
    if unsafe { get_CURLDEBUG() } == 1 {
        println!("cargo:rustc-cfg=CURLDEBUG");
    }
}
fn get_USE_UNIX_SOCKETS_add_cfg() {
    if unsafe { get_USE_UNIX_SOCKETS() } == 1 {
        println!("cargo:rustc-cfg=USE_UNIX_SOCKETS");
    }
}
fn get_ENABLE_QUIC_add_cfg() {
    if unsafe { get_ENABLE_QUIC() } == 1 {
        println!("cargo:rustc-cfg=ENABLE_QUIC");
    }
}
fn get_CURL_DO_LINEEND_CONV_add_cfg() {
    if unsafe { get_CURL_DO_LINEEND_CONV() } == 1 {
        println!("cargo:rustc-cfg=CURL_DO_LINEEND_CONV");
    }
}
fn get_HAVE_LIBZ_add_cfg() {
    if unsafe { get_HAVE_LIBZ() } == 1 {
        println!("cargo:rustc-cfg=HAVE_LIBZ");
    }
}
fn get_CURL_DISABLE_HTTP_AUTH_add_cfg() {
    if unsafe { get_CURL_DISABLE_HTTP_AUTH() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_HTTP_AUTH");
    }
}
fn get_CURL_DISABLE_NETRC_add_cfg() {
    if unsafe { get_CURL_DISABLE_NETRC() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_NETRC");
    }
}
fn get_CURL_DISABLE_PARSEDATE_add_cfg() {
    if unsafe { get_CURL_DISABLE_PARSEDATE() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_PARSEDATE");
    }
}
fn get_CURL_DISABLE_MIME_add_cfg() {
    if unsafe { get_CURL_DISABLE_MIME() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_MIME");
    }
}
fn get_CURL_DISABLE_ALTSVC_add_cfg() {
    if unsafe { get_CURL_DISABLE_ALTSVC() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_ALTSVC");
    }
}
fn get_CURL_DISABLE_RTSP_add_cfg() {
    if unsafe { get_CURL_DISABLE_RTSP() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_RTSP");
    }
}
fn get_CURL_DISABLE_HSTS_add_cfg() {
    if unsafe { get_CURL_DISABLE_HSTS() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_HSTS");
    }
}
fn get_CURL_DISABLE_COOKIES_add_cfg() {
    if unsafe { get_CURL_DISABLE_COOKIES() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_COOKIES");
    }
}

// ftplistparser

// ftp

// bearssl

// gskit

// gtls

// keylog
fn get_WIN32_add_cfg() {
    if unsafe { get_WIN32() } == 1 {
        println!("cargo:rustc-cfg=WIN32");
    }
}
// mbedtls

// mbedtls_threadlock

// nss

// mesalink

// openssl

// rustls

// vtls

// wolfssl