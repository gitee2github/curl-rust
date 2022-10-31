/******************************************************************************
 * Copyright (c) USTC(Suzhou) & Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * curl-rust licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wyf<wuyf21@mail.ustc.edu.cn>, 
 * Create: 2022-10-31
 * Description: get values of macro that the build of Rust code relies on from C side
 ******************************************************************************/
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
    fn get_HAVE_STRUCT_SOCKADDR_STORAGE() -> i32;
    fn get_USE_LIBSSH2() -> i32;
    // bearssl
    fn get_USE_BEARSSL() -> i32;
    // gskit
    fn get_USE_GSKIT() -> i32;
    // gtls
    fn get_USE_GNUTLS() -> i32;
    fn get_HAVE_GNUTLS_SRP() -> i32;
    fn get_GNUTLS_FORCE_CLIENT_CERT() -> i32;
    fn get_GNUTLS_NO_TICKETS() -> i32;
    // keylog
    fn get_WIN32() -> i32;

    // mbedtls
    fn get_USE_MBEDTLS() -> i32;
    fn get_USE_THREADS_POSIX() -> i32;
    fn get_HAVE_PTHREAD_H() -> i32;
    fn get_USE_THREADS_WIN32() -> i32;
    fn get_HAVE_PROCESS_H() -> i32;
    // mbedtls_threadlock

    // nss
    fn get_USE_NSS() -> i32;
    // mesalink
    fn get_USE_MESALINK() -> i32;
    // openssl

    // rustls
    fn get_USE_RUSTLS() -> i32;
    // vtls
    fn get_CURL_WITH_MULTI_SSL() -> i32;
    fn get_CURL_DEFAULT_SSL_BACKEND() -> i32;
    // wolfssl
    fn get_USE_WOLFSSL() -> i32;
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

    fn get_HAVE_OPAQUE_RSA_DSA_DH() -> i32;
    fn get_HAVE_X509_GET0_EXTENSIONS() -> i32;
    fn get_HAVE_X509_GET0_SIGNATURE() -> i32;
    fn get_HAVE_KEYLOG_CALLBACK() -> i32;
    fn get_X509_V_FLAG_PARTIAL_CHAIN() -> i32;
    fn get_X509_V_FLAG_TRUSTED_FIRST() -> i32;
    fn get_HAVE_SSL_CTX_SET_EC_CURVES() -> i32;
    fn get_HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH() -> i32;
    fn get_HAVE_SSL_CTX_SET_CIPHERSUITES() -> i32;
    fn get_USE_HTTP2() -> i32;
    fn get_HAS_NPN() -> i32;
    fn get_SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS() -> i32;
    fn get_SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG() -> i32;
    fn get_SSL_OP_NO_COMPRESSION() -> i32;
    fn get_SSL_OP_NO_TICKET() -> i32;
    fn get_SSL_MODE_RELEASE_BUFFERS() -> i32;
    fn get_USE_OPENSSL_SRP() -> i32;
    fn get_SSL_CTRL_SET_TLSEXT_HOSTNAME() -> i32;
    fn get_SSL3_RT_INNER_CONTENT_TYPE() -> i32;
    fn get_TLS1_1_VERSION() -> i32;
    fn get_TLS1_2_VERSION() -> i32;
    fn get_TLS1_3_VERSION() -> i32;
    fn get_SSL3_VERSION() -> i32;
    fn get_SSL2_VERSION() -> i32;
    fn get_SSL3_RT_HEADER() -> i32;
    fn get_SSL3_MT_MESSAGE_HASH() -> i32;
    fn get_SSL3_MT_NEXT_PROTO() -> i32;
    fn get_SSL3_MT_KEY_UPDATE() -> i32;
    fn get_SSL3_MT_END_OF_EARLY_DATA() -> i32;
    fn get_SSL3_MT_SUPPLEMENTAL_DATA() -> i32;
    fn get_SSL3_MT_ENCRYPTED_EXTENSIONS() -> i32;
    fn get_SSL3_MT_CERTIFICATE_STATUS() -> i32;
    fn get_SSL3_MT_NEWSESSION_TICKET() -> i32;
    fn get_SSL2_VERSION_MAJOR() -> i32;
    fn get_SSL_CTRL_SET_MSG_CALLBACK() -> i32;
    fn get_OPENSSL_INIT_ENGINE_ALL_BUILTIN() -> i32;
    fn get_HAVE_OPAQUE_EVP_PKEY() -> i32;
    fn get_ENGINE_CTRL_GET_CMD_FROM_NAME() -> i32;
    fn get_USE_OPENSSL_ENGINE() -> i32;
    fn get_RANDOM_FILE() -> i32;
    fn get_OPENSSL_IS_BORINGSSL() -> i32;
    fn get_SSL_ERROR_WANT_EARLY() -> i32;
    fn get_SSL_ERROR_WANT_ASYNC_JOB() -> i32;
    fn get_SSL_ERROR_WANT_ASYNC() -> i32;
    fn get_AVE_KEYLOG_CALLBACK() -> i32;

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
    get_HAVE_STRUCT_SOCKADDR_STORAGE_add_cfg();
    get_USE_LIBSSH2_add_cfg();
    // bearssl
    get_USE_BEARSSL_add_cfg();
    // gskit
    get_USE_GSKIT_add_cfg();
    // gtls
    get_USE_GNUTLS_add_cfg();
    get_HAVE_GNUTLS_SRP_add_cfg();
    get_GNUTLS_FORCE_CLIENT_CERT_add_cfg();
    get_GNUTLS_NO_TICKETS_add_cfg();
    // keylog
    get_WIN32_add_cfg();

    // mbedtls

    // mbedtls_threadlock
    get_USE_MBEDTLS_add_cfg();
    get_USE_THREADS_POSIX_add_cfg();
    get_HAVE_PTHREAD_H_add_cfg();
    get_USE_THREADS_WIN32_add_cfg();
    get_HAVE_PROCESS_H_add_cfg();
    // nss
    get_USE_NSS_add_cfg();
    // mesalink
    get_USE_MESALINK_add_cfg();
    // openssl

    // rustls
    get_USE_RUSTLS_add_cfg();
    // vtls
    get_CURL_WITH_MULTI_SSL_add_cfg();
    get_CURL_DEFAULT_SSL_BACKEND_add_cfg();
    // wolfssl
    get_USE_WOLFSSL_add_cfg();
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

    get_HAVE_OPAQUE_RSA_DSA_DH_add_cfg();
    get_HAVE_X509_GET0_EXTENSIONS_add_cfg();
    get_HAVE_X509_GET0_SIGNATURE_add_cfg();
    get_HAVE_KEYLOG_CALLBACK_add_cfg();
    get_X509_V_FLAG_PARTIAL_CHAIN_add_cfg();
    get_X509_V_FLAG_TRUSTED_FIRST_add_cfg();
    get_HAVE_SSL_CTX_SET_EC_CURVES_add_cfg();
    get_HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH_add_cfg();
    get_HAVE_SSL_CTX_SET_CIPHERSUITES_add_cfg();
    get_USE_HTTP2_add_cfg();
    get_HAS_NPN_add_cfg();
    get_SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS_add_cfg();
    get_SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG_add_cfg();
    get_SSL_OP_NO_COMPRESSION_add_cfg();
    get_SSL_OP_NO_TICKET_add_cfg();
    get_SSL_MODE_RELEASE_BUFFERS_add_cfg();
    get_USE_OPENSSL_SRP_add_cfg();
    get_SSL_CTRL_SET_TLSEXT_HOSTNAME_add_cfg();
    get_SSL3_RT_INNER_CONTENT_TYPE_add_cfg();
    get_TLS1_1_VERSION_add_cfg();
    get_TLS1_2_VERSION_add_cfg();
    get_TLS1_3_VERSION_add_cfg();
    get_SSL3_VERSION_add_cfg();
    get_SSL2_VERSION_add_cfg();
    get_SSL3_RT_HEADER_add_cfg();
    get_SSL3_MT_MESSAGE_HASH_add_cfg();
    get_SSL3_MT_NEXT_PROTO_add_cfg();
    get_SSL3_MT_KEY_UPDATE_add_cfg();
    get_SSL3_MT_END_OF_EARLY_DATA_add_cfg();
    get_SSL3_MT_SUPPLEMENTAL_DATA_add_cfg();
    get_SSL3_MT_ENCRYPTED_EXTENSIONS_add_cfg();
    get_SSL3_MT_CERTIFICATE_STATUS_add_cfg();
    get_SSL3_MT_NEWSESSION_TICKET_add_cfg();
    get_SSL2_VERSION_MAJOR_add_cfg();
    get_SSL_CTRL_SET_MSG_CALLBACK_add_cfg();
    get_OPENSSL_INIT_ENGINE_ALL_BUILTIN_add_cfg();
    get_HAVE_OPAQUE_EVP_PKEY_add_cfg();
    get_ENGINE_CTRL_GET_CMD_FROM_NAME_add_cfg();
    get_USE_OPENSSL_ENGINE_add_cfg();
    get_RANDOM_FILE_add_cfg();
    get_OPENSSL_IS_BORINGSSL_add_cfg();
    get_SSL_ERROR_WANT_EARLY_add_cfg();
    get_SSL_ERROR_WANT_ASYNC_JOB_add_cfg();
    get_SSL_ERROR_WANT_ASYNC_add_cfg();
    get_AVE_KEYLOG_CALLBACK_add_cfg();



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
fn get_HAVE_STRUCT_SOCKADDR_STORAGE_add_cfg() {
    if unsafe { get_HAVE_STRUCT_SOCKADDR_STORAGE() } == 1 {
        println!("cargo:rustc-cfg=HAVE_STRUCT_SOCKADDR_STORAGE");
    }
}
fn get_USE_LIBSSH2_add_cfg() {
    if unsafe { get_USE_LIBSSH2() } == 1 {
        println!("cargo:rustc-cfg=USE_LIBSSH2");
    }
}
// bearssl
fn get_USE_BEARSSL_add_cfg() {
    if unsafe { get_USE_BEARSSL() } == 1 {
        println!("cargo:rustc-cfg=USE_BEARSSL");
    }
}
// gskit
fn get_USE_GSKIT_add_cfg() {
    if unsafe { get_USE_GSKIT() } == 1 {
        println!("cargo:rustc-cfg=USE_GSKIT");
    }
}
// gtls
fn get_USE_GNUTLS_add_cfg() {
    if unsafe { get_USE_GNUTLS() } == 1 {
        println!("cargo:rustc-cfg=USE_GNUTLS");
    }
}
fn get_HAVE_GNUTLS_SRP_add_cfg() {
    if unsafe { get_HAVE_GNUTLS_SRP() } == 1 {
        println!("cargo:rustc-cfg=HAVE_GNUTLS_SRP");
    }
}
fn get_GNUTLS_FORCE_CLIENT_CERT_add_cfg() {
    if unsafe { get_GNUTLS_FORCE_CLIENT_CERT() } == 1 {
        println!("cargo:rustc-cfg=GNUTLS_FORCE_CLIENT_CERT");
    }
}
fn get_GNUTLS_NO_TICKETS_add_cfg() {
    if unsafe { get_GNUTLS_NO_TICKETS() } == 1 {
        println!("cargo:rustc-cfg=GNUTLS_NO_TICKETS");
    }
}
// keylog
fn get_WIN32_add_cfg() {
    if unsafe { get_WIN32() } == 1 {
        println!("cargo:rustc-cfg=WIN32");
    }
}
// mbedtls

// mbedtls_threadlock
fn get_USE_MBEDTLS_add_cfg() {
    if unsafe { get_USE_MBEDTLS() } == 1 {
        println!("cargo:rustc-cfg=USE_MBEDTLS");
    }
}
fn get_USE_THREADS_POSIX_add_cfg() {
    if unsafe { get_USE_THREADS_POSIX() } == 1 {
        println!("cargo:rustc-cfg=USE_THREADS_POSIX");
    }
}
fn get_HAVE_PTHREAD_H_add_cfg() {
    if unsafe { get_HAVE_PTHREAD_H() } == 1 {
        println!("cargo:rustc-cfg=HAVE_PTHREAD_H");
    }
}
fn get_USE_THREADS_WIN32_add_cfg() {
    if unsafe { get_USE_THREADS_WIN32() } == 1 {
        println!("cargo:rustc-cfg=USE_THREADS_WIN32");
    }
}
fn get_HAVE_PROCESS_H_add_cfg() {
    if unsafe { get_HAVE_PROCESS_H() } == 1 {
        println!("cargo:rustc-cfg=HAVE_PROCESS_H");
    }
}
// nss
fn get_USE_NSS_add_cfg() {
    if unsafe { get_USE_NSS() } == 1 {
        println!("cargo:rustc-cfg=USE_NSS");
    }
}
// mesalink
fn get_USE_MESALINK_add_cfg() {
    if unsafe { get_USE_MESALINK() } == 1 {
        println!("cargo:rustc-cfg=USE_MESALINK");
    }
}
// openssl

// rustls
fn get_USE_RUSTLS_add_cfg() {
    if unsafe { get_USE_RUSTLS() } == 1 {
        println!("cargo:rustc-cfg=USE_RUSTLS");
    }
}
// vtls
fn get_CURL_WITH_MULTI_SSL_add_cfg() {
    if unsafe { get_CURL_WITH_MULTI_SSL() } == 1 {
        println!("cargo:rustc-cfg=CURL_WITH_MULTI_SSL");
    }
}
fn get_CURL_DEFAULT_SSL_BACKEND_add_cfg() {
    if unsafe { get_CURL_DEFAULT_SSL_BACKEND() } == 1 {
        println!("cargo:rustc-cfg=CURL_DEFAULT_SSL_BACKEND");
    }
}
// wolfssl
fn get_USE_WOLFSSL_add_cfg() {
    if unsafe { get_USE_WOLFSSL() } == 1 {
        println!("cargo:rustc-cfg=USE_WOLFSSL");
    }
}
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

fn get_HAVE_OPAQUE_RSA_DSA_DH_add_cfg() {
    if unsafe { get_HAVE_OPAQUE_RSA_DSA_DH() } == 1 {
        println!("cargo:rustc-cfg=HAVE_OPAQUE_RSA_DSA_DH");
    }
}
fn get_HAVE_X509_GET0_EXTENSIONS_add_cfg() {
    if unsafe { get_HAVE_X509_GET0_EXTENSIONS() } == 1 {
        println!("cargo:rustc-cfg=HAVE_X509_GET0_EXTENSIONS");
    }
}
fn get_HAVE_X509_GET0_SIGNATURE_add_cfg() {
    if unsafe { get_HAVE_X509_GET0_SIGNATURE() } == 1 {
        println!("cargo:rustc-cfg=HAVE_X509_GET0_SIGNATURE");
    }
}
fn get_HAVE_KEYLOG_CALLBACK_add_cfg() {
    if unsafe { get_HAVE_KEYLOG_CALLBACK() } == 1 {
        println!("cargo:rustc-cfg=HAVE_KEYLOG_CALLBACK");
    }
}
fn get_X509_V_FLAG_PARTIAL_CHAIN_add_cfg() {
    if unsafe { get_X509_V_FLAG_PARTIAL_CHAIN() } == 1 {
        println!("cargo:rustc-cfg=X509_V_FLAG_PARTIAL_CHAIN");
    }
}
fn get_X509_V_FLAG_TRUSTED_FIRST_add_cfg() {
    if unsafe { get_X509_V_FLAG_TRUSTED_FIRST() } == 1 {
        println!("cargo:rustc-cfg=X509_V_FLAG_TRUSTED_FIRST");
    }
}
fn get_HAVE_SSL_CTX_SET_EC_CURVES_add_cfg() {
    if unsafe { get_HAVE_SSL_CTX_SET_EC_CURVES() } == 1 {
        println!("cargo:rustc-cfg=HAVE_SSL_CTX_SET_EC_CURVES");
    }
}
fn get_HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH_add_cfg() {
    if unsafe { get_HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH() } == 1 {
        println!("cargo:rustc-cfg=HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH");
    }
}
fn get_HAVE_SSL_CTX_SET_CIPHERSUITES_add_cfg() {
    if unsafe { get_HAVE_SSL_CTX_SET_CIPHERSUITES() } == 1 {
        println!("cargo:rustc-cfg=HAVE_SSL_CTX_SET_CIPHERSUITES");
    }
}
fn get_USE_HTTP2_add_cfg() {
    if unsafe { get_USE_HTTP2() } == 1 {
        println!("cargo:rustc-cfg=USE_HTTP2");
    }
}
fn get_HAS_NPN_add_cfg() {
    if unsafe { get_HAS_NPN() } == 1 {
        println!("cargo:rustc-cfg=HAS_NPN");
    }
}
fn get_SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS_add_cfg() {
    if unsafe { get_SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS() } == 1 {
        println!("cargo:rustc-cfg=SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS");
    }
}
fn get_SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG_add_cfg() {
    if unsafe { get_SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG() } == 1 {
        println!("cargo:rustc-cfg=SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG");
    }
}
fn get_SSL_OP_NO_COMPRESSION_add_cfg() {
    if unsafe { get_SSL_OP_NO_COMPRESSION() } == 1 {
        println!("cargo:rustc-cfg=SSL_OP_NO_COMPRESSION");
    }
}
fn get_SSL_OP_NO_TICKET_add_cfg() {
    if unsafe { get_SSL_OP_NO_TICKET() } == 1 {
        println!("cargo:rustc-cfg=SSL_OP_NO_TICKET");
    }
}
fn get_SSL_MODE_RELEASE_BUFFERS_add_cfg() {
    if unsafe { get_SSL_MODE_RELEASE_BUFFERS() } == 1 {
        println!("cargo:rustc-cfg=SSL_MODE_RELEASE_BUFFERS");
    }
}
fn get_USE_OPENSSL_SRP_add_cfg() {
    if unsafe { get_USE_OPENSSL_SRP() } == 1 {
        println!("cargo:rustc-cfg=USE_OPENSSL_SRP");
    }
}
fn get_SSL_CTRL_SET_TLSEXT_HOSTNAME_add_cfg() {
    if unsafe { get_SSL_CTRL_SET_TLSEXT_HOSTNAME() } == 1 {
        println!("cargo:rustc-cfg=SSL_CTRL_SET_TLSEXT_HOSTNAME");
    }
}
fn get_SSL3_RT_INNER_CONTENT_TYPE_add_cfg() {
    if unsafe { get_SSL3_RT_INNER_CONTENT_TYPE() } == 1 {
        println!("cargo:rustc-cfg=SSL3_RT_INNER_CONTENT_TYPE");
    }
}
fn get_TLS1_1_VERSION_add_cfg() {
    if unsafe { get_TLS1_1_VERSION() } == 1 {
        println!("cargo:rustc-cfg=TLS1_1_VERSION");
    }
}
fn get_TLS1_2_VERSION_add_cfg() {
    if unsafe { get_TLS1_2_VERSION() } == 1 {
        println!("cargo:rustc-cfg=TLS1_2_VERSION");
    }
}

fn get_TLS1_3_VERSION_add_cfg() {
    if unsafe { get_TLS1_3_VERSION() } == 1 {
        println!("cargo:rustc-cfg=TLS1_3_VERSION");
    }
}
fn get_SSL3_VERSION_add_cfg() {
    if unsafe { get_SSL3_VERSION() } == 1 {
        println!("cargo:rustc-cfg=SSL3_VERSION");
    }
}
fn get_SSL2_VERSION_add_cfg() {
    if unsafe { get_SSL2_VERSION() } == 1 {
        println!("cargo:rustc-cfg=SSL2_VERSION");
    }
}
fn get_SSL3_RT_HEADER_add_cfg() {
    if unsafe { get_SSL3_RT_HEADER() } == 1 {
        println!("cargo:rustc-cfg=SSL3_RT_HEADER");
    }
}
fn get_SSL3_MT_MESSAGE_HASH_add_cfg() {
    if unsafe { get_SSL3_MT_MESSAGE_HASH() } == 1 {
        println!("cargo:rustc-cfg=SSL3_MT_MESSAGE_HASH");
    }
}

fn get_SSL3_MT_NEXT_PROTO_add_cfg() {
    if unsafe { get_SSL3_MT_NEXT_PROTO() } == 1 {
        println!("cargo:rustc-cfg=SSL3_MT_NEXT_PROTO");
    }
}
fn get_SSL3_MT_KEY_UPDATE_add_cfg() {
    if unsafe { get_SSL3_MT_KEY_UPDATE() } == 1 {
        println!("cargo:rustc-cfg=SSL3_MT_KEY_UPDATE");
    }
}
fn get_SSL3_MT_END_OF_EARLY_DATA_add_cfg() {
    if unsafe { get_SSL3_MT_END_OF_EARLY_DATA() } == 1 {
        println!("cargo:rustc-cfg=SSL3_MT_END_OF_EARLY_DATA");
    }
}

fn get_SSL3_MT_SUPPLEMENTAL_DATA_add_cfg() {
    if unsafe { get_SSL3_MT_SUPPLEMENTAL_DATA() } == 1 {
        println!("cargo:rustc-cfg=SSL3_MT_SUPPLEMENTAL_DATA");
    }
}

fn get_SSL3_MT_ENCRYPTED_EXTENSIONS_add_cfg() {
    if unsafe { get_SSL3_MT_ENCRYPTED_EXTENSIONS() } == 1 {
        println!("cargo:rustc-cfg=SSL3_MT_ENCRYPTED_EXTENSIONS");
    }
}

fn get_SSL3_MT_CERTIFICATE_STATUS_add_cfg() {
    if unsafe { get_SSL3_MT_CERTIFICATE_STATUS() } == 1 {
        println!("cargo:rustc-cfg=SSL3_MT_CERTIFICATE_STATUS");
    }
}

fn get_SSL3_MT_NEWSESSION_TICKET_add_cfg() {
    if unsafe { get_SSL3_MT_NEWSESSION_TICKET() } == 1 {
        println!("cargo:rustc-cfg=SSL3_MT_NEWSESSION_TICKET");
    }
}

fn get_SSL2_VERSION_MAJOR_add_cfg() {
    if unsafe { get_SSL2_VERSION_MAJOR() } == 1 {
        println!("cargo:rustc-cfg=SSL2_VERSION_MAJOR");
    }
}

fn get_SSL_CTRL_SET_MSG_CALLBACK_add_cfg() {
    if unsafe { get_SSL_CTRL_SET_MSG_CALLBACK() } == 1 {
        println!("cargo:rustc-cfg=SSL_CTRL_SET_MSG_CALLBACK");
    }
}

fn get_OPENSSL_INIT_ENGINE_ALL_BUILTIN_add_cfg() {
    if unsafe { get_OPENSSL_INIT_ENGINE_ALL_BUILTIN() } == 1 {
        println!("cargo:rustc-cfg=OPENSSL_INIT_ENGINE_ALL_BUILTIN");
    }
}

fn get_HAVE_OPAQUE_EVP_PKEY_add_cfg() {
    if unsafe { get_HAVE_OPAQUE_EVP_PKEY() } == 1 {
        println!("cargo:rustc-cfg=HAVE_OPAQUE_EVP_PKEY");
    }
}
fn get_ENGINE_CTRL_GET_CMD_FROM_NAME_add_cfg() {
    if unsafe { get_ENGINE_CTRL_GET_CMD_FROM_NAME() } == 1 {
        println!("cargo:rustc-cfg=ENGINE_CTRL_GET_CMD_FROM_NAME");
    }
}
fn get_USE_OPENSSL_ENGINE_add_cfg() {
    if unsafe { get_USE_OPENSSL_ENGINE() } == 1 {
        println!("cargo:rustc-cfg=USE_OPENSSL_ENGINE");
    }
}
fn get_RANDOM_FILE_add_cfg() {
    if unsafe { get_RANDOM_FILE() } == 1 {
        println!("cargo:rustc-cfg=RANDOM_FILE");
    }
}
fn get_OPENSSL_IS_BORINGSSL_add_cfg() {
    if unsafe { get_OPENSSL_IS_BORINGSSL() } == 1 {
        println!("cargo:rustc-cfg=OPENSSL_IS_BORINGSSL");
    }
}
fn get_SSL_ERROR_WANT_EARLY_add_cfg() {
    if unsafe { get_SSL_ERROR_WANT_EARLY() } == 1 {
        println!("cargo:rustc-cfg=SSL_ERROR_WANT_EARLY");
    }
}
fn get_SSL_ERROR_WANT_ASYNC_JOB_add_cfg() {
    if unsafe { get_SSL_ERROR_WANT_ASYNC_JOB() } == 1 {
        println!("cargo:rustc-cfg=SSL_ERROR_WANT_ASYNC_JOB");
    }
}
fn get_SSL_ERROR_WANT_ASYNC_add_cfg() {
    if unsafe { get_SSL_ERROR_WANT_ASYNC() } == 1 {
        println!("cargo:rustc-cfg=SSL_ERROR_WANT_ASYNC");
    }
}
fn get_AVE_KEYLOG_CALLBACK_add_cfg() {
    if unsafe { get_AVE_KEYLOG_CALLBACK() } == 1 {
        println!("cargo:rustc-cfg=AVE_KEYLOG_CALLBACK");
    }
}