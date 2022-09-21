use crate::src::ffi_alias::type_alias::*;
use crate::src::ffi_struct::struct_define::*;

extern "C" {
    // ftp.rs

    // ftplistparser.rs

    // http_aws_sigv4.rs
    pub fn time(__timer: *mut time_t) -> time_t;
    pub fn strftime(
        __s: *mut libc::c_char,
        __maxsize: size_t,
        __format: *const libc::c_char,
        __tp: *const tm,
    ) -> size_t;
    pub fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    // pub fn Curl_http_method(
    //     data: *mut Curl_easy,
    //     conn: *mut connectdata,
    //     method: *mut *const libc::c_char,
    //     _: *mut Curl_HttpReq,
    // );
    pub fn Curl_raw_toupper(in_0: libc::c_char) -> libc::c_char;
    pub fn Curl_strntoupper(dest: *mut libc::c_char, src: *const libc::c_char, n: size_t);
    pub fn Curl_strntolower(dest: *mut libc::c_char, src: *const libc::c_char, n: size_t);
    pub fn Curl_memdup(src: *const libc::c_void, buffer_length: size_t) -> *mut libc::c_void;
    // static Curl_HMAC_SHA256: [HMAC_params; 1];
    pub fn Curl_hmacit(
        hashparams: *const HMAC_params,
        key: *const libc::c_uchar,
        keylen: size_t,
        data: *const libc::c_uchar,
        datalen: size_t,
        output: *mut libc::c_uchar,
    ) -> CURLcode;
    pub fn Curl_sha256it(outbuffer: *mut libc::c_uchar, input: *const libc::c_uchar, len: size_t);
    // pub fn Curl_checkheaders(
    //     data: *const Curl_easy,
    //     thisheader: *const libc::c_char,
    // ) -> *mut libc::c_char;
    pub fn Curl_gmtime(intime: time_t, store: *mut tm) -> CURLcode;
    // pub fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    pub fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    pub fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
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

    // http_proxy.rs

    // http.rs

    // http2.rs

    // vtls/bearssl.rs

    // vtls/gskit.rs

    // vtls/gtls.rs

    // vtls/keylog.rs
    pub fn curl_getenv(variable: *const libc::c_char) -> *mut libc::c_char;
    pub fn fclose(__stream: *mut FILE) -> libc::c_int;
    pub fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    pub fn setvbuf(
        __stream: *mut FILE,
        __buf: *mut libc::c_char,
        __modes: libc::c_int,
        __n: size_t,
    ) -> libc::c_int;
    pub fn fputs(__s: *const libc::c_char, __stream: *mut FILE) -> libc::c_int;
    pub fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    pub fn strlen(_: *const libc::c_char) -> libc::c_ulong;
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
