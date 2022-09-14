#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(c_variadic, extern_types, label_break_value, register_tool)]
#![register_tool(c2rust)]

#[macro_use]
extern crate libc;
extern crate c2rust_bitfields;
extern crate rust_ffi;

pub mod src {
    // pub mod ftp;
    // pub mod ftplistparser;
    // pub mod http_aws_sigv4;
    pub mod http_chunks;
    pub mod http_digest;
    // pub mod http_negotiate;
    pub mod http_ntlm;
    pub mod http_proxy;
    // pub mod http;
    // pub mod http2;
    pub mod vtls {
        // pub mod bearssl;
        // pub mod gskit;
        // pub mod gtls;
        pub mod keylog;
        // pub mod mbedtls_threadlock;
        // pub mod mbedtls;
        // pub mod mesalink;
        // pub mod nss;
        // pub mod openssl;
        // pub mod rustls;
        // pub mod schannel_verify;
        // pub mod schannel;
        // pub mod sectransp;
        // pub mod vtls;
        // pub mod wolfssl;
    }
}
