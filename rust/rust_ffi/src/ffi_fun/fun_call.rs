use crate::src::ffi_alias::type_alias::*;
use crate::src::ffi_struct::struct_define::*;

extern "C" {
    // ftp.rs

    // ftplistparser.rs

    // http_aws_sigv4.rs

    // http_chunks.rs
    pub fn Curl_isxdigit(c: libc::c_int) -> libc::c_int;
    pub fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
    pub fn Curl_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    pub fn Curl_dyn_reset(s: *mut dynbuf);
    pub fn Curl_dyn_ptr(s: *const dynbuf) -> *mut libc::c_char;
    pub fn Curl_dyn_len(s: *const dynbuf) -> size_t;
    pub fn Curl_dyn_add(s: *mut dynbuf, str: *const libc::c_char) -> CURLcode;
    // fn Curl_client_write(
    //     data: *mut Curl_easy,
    //     type_0: libc::c_int,
    //     ptr: *mut libc::c_char,
    //     len: size_t,
    // ) -> CURLcode;
    // fn Curl_unencode_write(
    //     data: *mut Curl_easy,
    //     writer: *mut contenc_writer,
    //     buf: *const libc::c_char,
    //     nbytes: size_t,
    // ) -> CURLcode;
    pub fn curlx_strtoofft(
        str: *const libc::c_char,
        endp: *mut *mut libc::c_char,
        base: libc::c_int,
        num: *mut curl_off_t,
    ) -> CURLofft;
    pub fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    // http_digest.rs

    // http_negotiate.rs

    // http_ntlm.rs
    pub fn curl_strnequal(
        s1: *const libc::c_char,
        s2: *const libc::c_char,
        n: size_t,
    ) -> libc::c_int;
    pub fn Curl_isspace(c: libc::c_int) -> libc::c_int;
    pub fn curl_free(p: *mut libc::c_void);
    pub fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    // fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    // fn Curl_http_auth_cleanup_ntlm_wb(conn: *mut connectdata);
    // fn Curl_base64_encode(
    //     data: *mut Curl_easy,
    //     inputbuff: *const libc::c_char,
    //     insize: size_t,
    //     outptr: *mut *mut libc::c_char,
    //     outlen: *mut size_t,
    // ) -> CURLcode;
    pub fn Curl_base64_decode(
        src: *const libc::c_char,
        outptr: *mut *mut libc::c_uchar,
        outlen: *mut size_t,
    ) -> CURLcode;
    // fn Curl_auth_create_ntlm_type1_message(
    //     data: *mut Curl_easy,
    //     userp: *const libc::c_char,
    //     passwdp: *const libc::c_char,
    //     service: *const libc::c_char,
    //     host: *const libc::c_char,
    //     ntlm: *mut ntlmdata,
    //     out: *mut bufref,
    // ) -> CURLcode;
    // fn Curl_auth_decode_ntlm_type2_message(
    //     data: *mut Curl_easy,
    //     type2: *const bufref,
    //     ntlm: *mut ntlmdata,
    // ) -> CURLcode;
    // fn Curl_auth_create_ntlm_type3_message(
    //     data: *mut Curl_easy,
    //     userp: *const libc::c_char,
    //     passwdp: *const libc::c_char,
    //     ntlm: *mut ntlmdata,
    //     out: *mut bufref,
    // ) -> CURLcode;
    pub fn Curl_bufref_init(br: *mut bufref);
    pub fn Curl_bufref_set(
        br: *mut bufref,
        ptr: *const libc::c_void,
        len: size_t,
        dtor: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    );
    pub fn Curl_bufref_ptr(br: *const bufref) -> *const libc::c_uchar;
    pub fn Curl_bufref_len(br: *const bufref) -> size_t;
    pub fn Curl_bufref_free(br: *mut bufref);
    pub fn Curl_auth_cleanup_ntlm(ntlm: *mut ntlmdata);
    pub fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
    // http_proxy.rs

    // http.rs

    // http2.rs

    // vtls/bearssl.rs

    // vtls/gskit.rs

    // vtls/gtls.rs

    // vtls/keylog.rs
    pub fn curl_getenv(variable: *const libc::c_char) -> *mut libc::c_char;
    // fn fclose(__stream: *mut FILE) -> libc::c_int;
    // fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    // fn setvbuf(
    //     __stream: *mut FILE,
    //     __buf: *mut libc::c_char,
    //     __modes: libc::c_int,
    //     __n: size_t,
    // ) -> libc::c_int;
    pub fn fputs(__s: *const libc::c_char, __stream: *mut FILE) -> libc::c_int;
    pub fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    // vtls/mbedtls_threadlock.rs

    // vtls/mbedtls.rs

    // vtls/mesalink.rs

    // vtls/nss.rs

    // vtls/openssl.rs

    // vtls/rustls.rs

    // vtls/schannel_verify.rs

    // vtls/schannel.rs

    // vtls/sectransp.rs

    // vtls/vtls.rs

    // vtls/wolfssl.rs

}
