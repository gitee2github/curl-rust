#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(c_variadic, extern_types, label_break_value, register_tool, stmt_expr_attributes)]
#![register_tool(c2rust)]

#[macro_use]
extern crate libc;
extern crate c2rust_bitfields;
extern crate rust_ffi;

pub mod src {
    // #[cfg(not(CURL_DISABLE_FTP))]
    // pub mod ftp;
    #[cfg(not(CURL_DISABLE_FTP))]
    pub mod ftplistparser;
    #[cfg(all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_CRYPTO_AUTH)))]
    pub mod http_aws_sigv4;
    #[cfg(not(CURL_DISABLE_HTTP))]
    pub mod http_chunks;
    #[cfg(all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_CRYPTO_AUTH)))]
    pub mod http_digest;
    #[cfg(all(not(CURL_DISABLE_HTTP), USE_SPNEGO))]
    pub mod http_negotiate; // 回归测试成功，但有 3 个测试用例没有通过
    // #[cfg(not(CURL_DISABLE_HTTP))]
    // pub mod http;
    pub mod http2;
    #[cfg(all(not(CURL_DISABLE_HTTP), USE_NTLM))]
    pub mod http_ntlm;
    pub mod http_proxy;
    pub mod vtls {
        #[cfg(USE_BEARSSL)]
        pub mod bearssl; // 可以翻译，但安装方式不合理
        // pub mod gskit; // 缺少依赖，无法翻译
        #[cfg(USE_GNUTLS)]
        pub mod gtls;
        pub mod keylog;
        #[cfg(all(USE_MBEDTLS, any(all(USE_THREADS_POSIX, HAVE_PTHREAD_H), all(USE_THREADS_WIN32, HAVE_PROCESS_H))))]       
        pub mod mbedtls_threadlock;
        #[cfg(USE_MBEDTLS)]
        pub mod mbedtls;
        #[cfg(USE_MESALINK)]
        pub mod mesalink;
        #[cfg(USE_NSS)]
        pub mod nss;
        // #[cfg(USE_OPENSSL)]
        // pub mod openssl;
        #[cfg(USE_RUSTLS)]
        pub mod rustls; // 集成报错
        pub mod vtls;
        #[cfg(USE_WOLFSSL)]
        pub mod wolfssl;
    }
}
