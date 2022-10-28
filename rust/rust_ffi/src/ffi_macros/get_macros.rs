extern "C" {
    // http2
    fn get_USE_NGHTTP2() -> i32;
    fn get_CURL_DISABLE_VERBOSE_STRINGS() -> i32;
    fn get_DEBUG_HTTP2() -> i32;
    fn get_NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE() -> i32;
    fn get_DEBUGBUILD() -> i32;
    
    fn get_USE_RECV_BEFORE_SEND_WORKAROUND() -> i32;
    fn get_USE_KERBEROS5() -> i32;
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

    fn get_HAVE_NET_IF_H() -> i32;
    fn get_HAVE_SYS_IOCTL_H() -> i32;
    fn get_HAVE_SYS_PARAM_H() -> i32;

    // ftplistparser

    // ftp
    fn get_CURL_DISABLE_FTP() -> i32;
    fn get_NI_MAXHOST() -> i32;
    fn get_INET_ADDRSTRLEN() -> i32;
    fn get_HAVE_NETINET_IN_H() -> i32;
    fn get_HAVE_ARPA_INET_H() -> i32;
    fn get_HAVE_UTSNAME_H() -> i32;
    fn get_HAVE_NETDB_H() -> i32;
    fn get___VMS() -> i32;
    fn get_ENABLE_IPV6() -> i32;
    fn get_HAVE_GSSAPI() -> i32;
    fn get_PF_INET6() -> i32;
    fn get_CURL_FTP_HTTPSTYLE_HEAD() -> i32;
    fn get__WIN32_WCE() -> i32;
    fn get_NETWARE() -> i32;
    fn get___NOVELL_LIBC__() -> i32;

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

    // struct
    fn get_USE_LIBPSL() -> i32;
    fn get_HAVE_SIGNAL() -> i32;
    fn get_USE_CURL_ASYNC() -> i32;
    fn get_USE_OPENSSL() -> i32;
    fn get_MSDOS() -> i32;
    fn get___EMX__() -> i32;
    fn get_USE_TLS_SRP() -> i32;
    fn get_CURL_DISABLE_DOH() -> i32;
    fn get_USE_NGHTTP3() -> i32;
    fn get_ENABLE_WAKEUP() -> i32;
    fn get_USE_GSASL() -> i32;
}
pub fn get_all_cfg() {
    // http2
    get_USE_NGHTTP2_add_cfg();
    get_CURL_DISABLE_VERBOSE_STRINGS_add_cfg();
    get_DEBUG_HTTP2_add_cfg();
    get_NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE_add_cfg();
    get_DEBUGBUILD_add_cfg();

    get_USE_RECV_BEFORE_SEND_WORKAROUND_add_cfg();
    get_USE_KERBEROS5_add_cfg();
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

    get_HAVE_NET_IF_H_add_cfg();
    get_HAVE_SYS_IOCTL_H_add_cfg();
    get_HAVE_SYS_PARAM_H_add_cfg();

    // ftplistparser

    // ftp
    get_CURL_DISABLE_FTP_add_cfg();
    get_NI_MAXHOST_add_cfg();
    get_INET_ADDRSTRLEN_add_cfg();
    get_HAVE_NETINET_IN_H_add_cfg();
    get_HAVE_ARPA_INET_H_add_cfg();
    get_HAVE_UTSNAME_H_add_cfg();
    get_HAVE_NETDB_H_add_cfg();
    get___VMS_add_cfg();
    get_ENABLE_IPV6_add_cfg();
    get_HAVE_GSSAPI_add_cfg();
    get_PF_INET6_add_cfg();
    get_CURL_FTP_HTTPSTYLE_HEAD_add_cfg();
    get__WIN32_WCE_add_cfg();
    get_NETWARE_add_cfg();
    get___NOVELL_LIBC___add_cfg();
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

    // struct
    get_USE_LIBPSL_add_cfg();
    get_HAVE_SIGNAL_add_cfg();
    get_USE_CURL_ASYNC_add_cfg();
    get_USE_OPENSSL_add_cfg();
    get_MSDOS_add_cfg();
    get___EMX___add_cfg();
    get_USE_TLS_SRP_add_cfg();
    get_CURL_DISABLE_DOH_add_cfg();
    get_USE_NGHTTP3_add_cfg();
    get_ENABLE_WAKEUP_add_cfg();
    get_USE_GSASL_add_cfg();
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
fn get_USE_RECV_BEFORE_SEND_WORKAROUND_add_cfg() {
    if unsafe { get_USE_RECV_BEFORE_SEND_WORKAROUND() } == 1 {
        println!("cargo:rustc-cfg=USE_RECV_BEFORE_SEND_WORKAROUND");
    }
}
fn get_USE_KERBEROS5_add_cfg() {
    if unsafe { get_USE_KERBEROS5() } == 1 {
        println!("cargo:rustc-cfg=USE_KERBEROS5");
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
fn get_HAVE_NET_IF_H_add_cfg() {
    if unsafe { get_HAVE_NET_IF_H() } == 1 {
        println!("cargo:rustc-cfg=HAVE_NET_IF_H");
    }
}
fn get_HAVE_SYS_IOCTL_H_add_cfg() {
    if unsafe { get_HAVE_SYS_IOCTL_H() } == 1 {
        println!("cargo:rustc-cfg=HAVE_SYS_IOCTL_H");
    }
}
fn get_HAVE_SYS_PARAM_H_add_cfg() {
    if unsafe { get_HAVE_SYS_PARAM_H() } == 1 {
        println!("cargo:rustc-cfg=HAVE_SYS_PARAM_H");
    }
}

// ftplistparser
// repeated

// ftp
fn get_CURL_DISABLE_FTP_add_cfg() {
    if unsafe { get_CURL_DISABLE_FTP() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_FTP");
    }
}

fn get_NI_MAXHOST_add_cfg() {
    if unsafe { get_NI_MAXHOST() } == 1 {
        println!("cargo:rustc-cfg=NI_MAXHOST");
    }
}

fn get_INET_ADDRSTRLEN_add_cfg() {
    if unsafe { get_INET_ADDRSTRLEN() } == 1 {
        println!("cargo:rustc-cfg=INET_ADDRSTRLEN");
    }
}
fn get_HAVE_NETINET_IN_H_add_cfg() {
    if unsafe { get_HAVE_NETINET_IN_H() } == 1 {
        println!("cargo:rustc-cfg=HAVE_NETINET_IN_H");
    }
}
fn get_HAVE_ARPA_INET_H_add_cfg() {
    if unsafe { get_HAVE_ARPA_INET_H() } == 1 {
        println!("cargo:rustc-cfg=HAVE_ARPA_INET_H");
    }
}
fn get_HAVE_UTSNAME_H_add_cfg() {
    if unsafe { get_HAVE_UTSNAME_H() } == 1 {
        println!("cargo:rustc-cfg=HAVE_UTSNAME_H");
    }
}
fn get_HAVE_NETDB_H_add_cfg() {
    if unsafe { get_HAVE_NETDB_H() } == 1 {
        println!("cargo:rustc-cfg=HAVE_NETDB_H");
    }
}
fn get___VMS_add_cfg() {
    if unsafe { get___VMS() } == 1 {
        println!("cargo:rustc-cfg=__VMS");
    }
}
fn get_ENABLE_IPV6_add_cfg() {
    if unsafe { get_ENABLE_IPV6() } == 1 {
        println!("cargo:rustc-cfg=ENABLE_IPV6");
    }
}
fn get_HAVE_GSSAPI_add_cfg() {
    if unsafe { get_HAVE_GSSAPI() } == 1 {
        println!("cargo:rustc-cfg=HAVE_GSSAPI");
    }
}
fn get_PF_INET6_add_cfg() {
    if unsafe { get_PF_INET6() } == 1 {
        println!("cargo:rustc-cfg=PF_INET6");
    }
}
fn get_CURL_FTP_HTTPSTYLE_HEAD_add_cfg() {
    if unsafe { get_CURL_FTP_HTTPSTYLE_HEAD() } == 1 {
        println!("cargo:rustc-cfg=CURL_FTP_HTTPSTYLE_HEAD");
    }
}
fn get__WIN32_WCE_add_cfg() {
    if unsafe { get__WIN32_WCE() } == 1 {
        println!("cargo:rustc-cfg=_WIN32_WCE");
    }
}
fn get_NETWARE_add_cfg() {
    if unsafe { get_NETWARE() } == 1 {
        println!("cargo:rustc-cfg=NETWARE");
    }
}
fn get___NOVELL_LIBC___add_cfg() {
    if unsafe { get___NOVELL_LIBC__() } == 1 {
        println!("cargo:rustc-cfg=__NOVELL_LIBC__");
    }
}
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

//struct
fn get_USE_LIBPSL_add_cfg() {
    if unsafe { get_USE_LIBPSL() } == 1 {
        println!("cargo:rustc-cfg=USE_LIBPSL");
    }
}

fn get_HAVE_SIGNAL_add_cfg() {
    if unsafe { get_HAVE_SIGNAL() } == 1 {
        println!("cargo:rustc-cfg=HAVE_SIGNAL");
    }
}

fn get_USE_CURL_ASYNC_add_cfg() {
    if unsafe { get_USE_CURL_ASYNC() } == 1 {
        println!("cargo:rustc-cfg=USE_CURL_ASYNC");
    }
}

fn get_USE_OPENSSL_add_cfg() {
    if unsafe { get_USE_OPENSSL() } == 1 {
        println!("cargo:rustc-cfg=USE_OPENSSL");
    }
}

fn get_MSDOS_add_cfg() {
    if unsafe { get_MSDOS() } == 1 {
        println!("cargo:rustc-cfg=MSDOS");
    }
}

fn get___EMX___add_cfg() {
    if unsafe { get___EMX__() } == 1 {
        println!("cargo:rustc-cfg=__EMX__");
    }
}

fn get_USE_TLS_SRP_add_cfg() {
    if unsafe { get_USE_TLS_SRP() } == 1 {
        println!("cargo:rustc-cfg=USE_TLS_SRP");
    }
}

fn get_CURL_DISABLE_DOH_add_cfg() {
    if unsafe { get_CURL_DISABLE_DOH() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_DOH");
    }
}

fn get_USE_NGHTTP3_add_cfg() {
    if unsafe { get_USE_NGHTTP3() } == 1 {
        println!("cargo:rustc-cfg=USE_NGHTTP3");
    }
}

fn get_ENABLE_WAKEUP_add_cfg() {
    if unsafe { get_ENABLE_WAKEUP() } == 1 {
        println!("cargo:rustc-cfg=ENABLE_WAKEUP");
    }
}

fn get_USE_GSASL_add_cfg() {
    if unsafe { get_USE_GSASL() } == 1 {
        println!("cargo:rustc-cfg=USE_GSASL");
    }
}
