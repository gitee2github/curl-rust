extern "C" {
    // http2

    // http_proxy
    fn get_CURL_DISABLE_PROXY() -> i32;
    // http_ntlm

    // http_negotiate

    // http_digest

    // http_chunks

    // http_aws_sigv4

    // http

    // ftplistparser

    // ftp
    fn get_CURL_DISABLE_FTP() -> i32;
    fn get_NI_MAXHOST() -> i32;
    fn get_INET_ADDRSTRLEN() -> i32;
    fn get_DEBUGBUILD() -> i32;
    fn get_CURL_DISABLE_VERBOSE_STRINGS() -> i32;
    fn get_HAVE_NETINET_IN_H() -> i32;
    fn get_HAVE_ARPA_INET_H() -> i32;
    fn get_HAVE_UTSNAME_H() -> i32;
    fn get_HAVE_NETDB_H() -> i32;
    fn get___VMS() -> i32;
    fn get_USE_SSL() -> i32;
    fn get_ENABLE_IPV6() -> i32;
    fn get_HAVE_GSSAPI() -> i32;
    fn get_PF_INET6() -> i32;
    fn get_CURL_FTP_HTTPSTYLE_HEAD() -> i32;
    fn get__WIN32_WCE() -> i32;
    fn get_CURL_DO_LINEEND_CONV() -> i32;
    fn get_NETWARE() -> i32;
    fn get___NOVELL_LIBC__() -> i32;

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
}
pub fn get_all_cfg() {
    // http2

    // http_proxy
    get_CURL_DISABLE_PROXY_add_cfg();
    // http_ntlm

    // http_negotiate

    // http_digest

    // http_chunks

    // http_aws_sigv4

    // http

    // ftplistparser

    // ftp
    get_CURL_DISABLE_FTP_add_cfg();
    get_NI_MAXHOST_add_cfg();
    get_INET_ADDRSTRLEN_add_cfg();
    get_DEBUGBUILD_add_cfg();
    get_CURL_DISABLE_VERBOSE_STRINGS_add_cfg();
    get_HAVE_NETINET_IN_H_add_cfg();
    get_HAVE_ARPA_INET_H_add_cfg();
    get_HAVE_UTSNAME_H_add_cfg();
    get_HAVE_NETDB_H_add_cfg();
    get___VMS_add_cfg();
    get_USE_SSL_add_cfg();
    get_ENABLE_IPV6_add_cfg();
    get_HAVE_GSSAPI_add_cfg();
    get_PF_INET6_add_cfg();
    get_CURL_FTP_HTTPSTYLE_HEAD_add_cfg();
    get__WIN32_WCE_add_cfg();
    get_CURL_DO_LINEEND_CONV_add_cfg();
    get_NETWARE_add_cfg();
    get___NOVELL_LIBC___add_cfg();
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
}

// http2

// http_proxy
fn get_CURL_DISABLE_PROXY_add_cfg() {
    if unsafe { get_CURL_DISABLE_PROXY() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_PROXY");
    }
}
// http_ntlm

// http_negotiate

// http_digest

// http_chunks

// http_aws_sigv4

// http

// ftplistparser

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

fn get_DEBUGBUILD_add_cfg() {
    if unsafe { get_DEBUGBUILD() } == 1 {
        println!("cargo:rustc-cfg=DEBUGBUILD");
    }
}
fn get_CURL_DISABLE_VERBOSE_STRINGS_add_cfg() {
    if unsafe { get_CURL_DISABLE_VERBOSE_STRINGS() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_VERBOSE_STRINGS");
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
fn get_USE_SSL_add_cfg() {
    if unsafe { get_USE_SSL() } == 1 {
        println!("cargo:rustc-cfg=USE_SSL");
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
    if unsafe { get_CURL_DISABLE_PROXY() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_PROXY");
    }
}
fn get__WIN32_WCE_add_cfg() {
    if unsafe { get__WIN32_WCE() } == 1 {
        println!("cargo:rustc-cfg=_WIN32_WCE");
    }
}
fn get_CURL_DO_LINEEND_CONV_add_cfg() {
    if unsafe { get_CURL_DO_LINEEND_CONV() } == 1 {
        println!("cargo:rustc-cfg=CURL_DO_LINEEND_CONV");
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

// mbedtls

// mbedtls_threadlock

// nss

// mesalink

// openssl

// rustls

// vtls

// wolfssl
