use ::libc;
use c2rust_bitfields::BitfieldStruct;
use rust_ffi::src::ffi_alias::type_alias::*;
// use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
extern "C" {
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn Curl_safe_strcasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
    ) -> libc::c_int;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type size_t = libc::c_ulong;
pub type curl_sslbackend = libc::c_uint;
pub const CURLSSLBACKEND_RUSTLS: curl_sslbackend = 14;
pub const CURLSSLBACKEND_BEARSSL: curl_sslbackend = 13;
pub const CURLSSLBACKEND_MESALINK: curl_sslbackend = 12;
pub const CURLSSLBACKEND_MBEDTLS: curl_sslbackend = 11;
pub const CURLSSLBACKEND_AXTLS: curl_sslbackend = 10;
pub const CURLSSLBACKEND_SECURETRANSPORT: curl_sslbackend = 9;
pub const CURLSSLBACKEND_SCHANNEL: curl_sslbackend = 8;
pub const CURLSSLBACKEND_WOLFSSL: curl_sslbackend = 7;
pub const CURLSSLBACKEND_POLARSSL: curl_sslbackend = 6;
pub const CURLSSLBACKEND_GSKIT: curl_sslbackend = 5;
pub const CURLSSLBACKEND_OBSOLETE4: curl_sslbackend = 4;
pub const CURLSSLBACKEND_NSS: curl_sslbackend = 3;
pub const CURLSSLBACKEND_GNUTLS: curl_sslbackend = 2;
pub const CURLSSLBACKEND_OPENSSL: curl_sslbackend = 1;
pub const CURLSSLBACKEND_NONE: curl_sslbackend = 0;
pub type bit = libc::c_uint;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_primary_config {
    pub version: libc::c_long,
    pub version_max: libc::c_long,
    pub CApath: *mut libc::c_char,
    pub CAfile: *mut libc::c_char,
    pub issuercert: *mut libc::c_char,
    pub clientcert: *mut libc::c_char,
    pub random_file: *mut libc::c_char,
    pub egdsocket: *mut libc::c_char,
    pub cipher_list: *mut libc::c_char,
    pub cipher_list13: *mut libc::c_char,
    pub pinned_key: *mut libc::c_char,
    pub cert_blob: *mut curl_blob,
    pub ca_info_blob: *mut curl_blob,
    pub issuercert_blob: *mut curl_blob,
    pub curves: *mut libc::c_char,
    #[bitfield(name = "verifypeer", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "verifyhost", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "verifystatus", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "sessionid", ty = "bit", bits = "3..=3")]
    pub verifypeer_verifyhost_verifystatus_sessionid: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_blob {
    pub data: *mut libc::c_void,
    pub len: size_t,
    pub flags: libc::c_uint,
}
pub type CURLcode = libc::c_uint;
pub const CURL_LAST: CURLcode = 99;
pub const CURLE_SSL_CLIENTCERT: CURLcode = 98;
pub const CURLE_PROXY: CURLcode = 97;
pub const CURLE_QUIC_CONNECT_ERROR: CURLcode = 96;
pub const CURLE_HTTP3: CURLcode = 95;
pub const CURLE_AUTH_ERROR: CURLcode = 94;
pub const CURLE_RECURSIVE_API_CALL: CURLcode = 93;
pub const CURLE_HTTP2_STREAM: CURLcode = 92;
pub const CURLE_SSL_INVALIDCERTSTATUS: CURLcode = 91;
pub const CURLE_SSL_PINNEDPUBKEYNOTMATCH: CURLcode = 90;
pub const CURLE_NO_CONNECTION_AVAILABLE: CURLcode = 89;
pub const CURLE_CHUNK_FAILED: CURLcode = 88;
pub const CURLE_FTP_BAD_FILE_LIST: CURLcode = 87;
pub const CURLE_RTSP_SESSION_ERROR: CURLcode = 86;
pub const CURLE_RTSP_CSEQ_ERROR: CURLcode = 85;
pub const CURLE_FTP_PRET_FAILED: CURLcode = 84;
pub const CURLE_SSL_ISSUER_ERROR: CURLcode = 83;
pub const CURLE_SSL_CRL_BADFILE: CURLcode = 82;
pub const CURLE_AGAIN: CURLcode = 81;
pub const CURLE_SSL_SHUTDOWN_FAILED: CURLcode = 80;
pub const CURLE_SSH: CURLcode = 79;
pub const CURLE_REMOTE_FILE_NOT_FOUND: CURLcode = 78;
pub const CURLE_SSL_CACERT_BADFILE: CURLcode = 77;
pub const CURLE_CONV_REQD: CURLcode = 76;
pub const CURLE_CONV_FAILED: CURLcode = 75;
pub const CURLE_TFTP_NOSUCHUSER: CURLcode = 74;
pub const CURLE_REMOTE_FILE_EXISTS: CURLcode = 73;
pub const CURLE_TFTP_UNKNOWNID: CURLcode = 72;
pub const CURLE_TFTP_ILLEGAL: CURLcode = 71;
pub const CURLE_REMOTE_DISK_FULL: CURLcode = 70;
pub const CURLE_TFTP_PERM: CURLcode = 69;
pub const CURLE_TFTP_NOTFOUND: CURLcode = 68;
pub const CURLE_LOGIN_DENIED: CURLcode = 67;
pub const CURLE_SSL_ENGINE_INITFAILED: CURLcode = 66;
pub const CURLE_SEND_FAIL_REWIND: CURLcode = 65;
pub const CURLE_USE_SSL_FAILED: CURLcode = 64;
pub const CURLE_FILESIZE_EXCEEDED: CURLcode = 63;
pub const CURLE_LDAP_INVALID_URL: CURLcode = 62;
pub const CURLE_BAD_CONTENT_ENCODING: CURLcode = 61;
pub const CURLE_PEER_FAILED_VERIFICATION: CURLcode = 60;
pub const CURLE_SSL_CIPHER: CURLcode = 59;
pub const CURLE_SSL_CERTPROBLEM: CURLcode = 58;
pub const CURLE_OBSOLETE57: CURLcode = 57;
pub const CURLE_RECV_ERROR: CURLcode = 56;
pub const CURLE_SEND_ERROR: CURLcode = 55;
pub const CURLE_SSL_ENGINE_SETFAILED: CURLcode = 54;
pub const CURLE_SSL_ENGINE_NOTFOUND: CURLcode = 53;
pub const CURLE_GOT_NOTHING: CURLcode = 52;
pub const CURLE_OBSOLETE51: CURLcode = 51;
pub const CURLE_OBSOLETE50: CURLcode = 50;
pub const CURLE_SETOPT_OPTION_SYNTAX: CURLcode = 49;
pub const CURLE_UNKNOWN_OPTION: CURLcode = 48;
pub const CURLE_TOO_MANY_REDIRECTS: CURLcode = 47;
pub const CURLE_OBSOLETE46: CURLcode = 46;
pub const CURLE_INTERFACE_FAILED: CURLcode = 45;
pub const CURLE_OBSOLETE44: CURLcode = 44;
pub const CURLE_BAD_FUNCTION_ARGUMENT: CURLcode = 43;
pub const CURLE_ABORTED_BY_CALLBACK: CURLcode = 42;
pub const CURLE_FUNCTION_NOT_FOUND: CURLcode = 41;
pub const CURLE_OBSOLETE40: CURLcode = 40;
pub const CURLE_LDAP_SEARCH_FAILED: CURLcode = 39;
pub const CURLE_LDAP_CANNOT_BIND: CURLcode = 38;
pub const CURLE_FILE_COULDNT_READ_FILE: CURLcode = 37;
pub const CURLE_BAD_DOWNLOAD_RESUME: CURLcode = 36;
pub const CURLE_SSL_CONNECT_ERROR: CURLcode = 35;
pub const CURLE_HTTP_POST_ERROR: CURLcode = 34;
pub const CURLE_RANGE_ERROR: CURLcode = 33;
pub const CURLE_OBSOLETE32: CURLcode = 32;
pub const CURLE_FTP_COULDNT_USE_REST: CURLcode = 31;
pub const CURLE_FTP_PORT_FAILED: CURLcode = 30;
pub const CURLE_OBSOLETE29: CURLcode = 29;
pub const CURLE_OPERATION_TIMEDOUT: CURLcode = 28;
pub const CURLE_OUT_OF_MEMORY: CURLcode = 27;
pub const CURLE_READ_ERROR: CURLcode = 26;
pub const CURLE_UPLOAD_FAILED: CURLcode = 25;
pub const CURLE_OBSOLETE24: CURLcode = 24;
pub const CURLE_WRITE_ERROR: CURLcode = 23;
pub const CURLE_HTTP_RETURNED_ERROR: CURLcode = 22;
pub const CURLE_QUOTE_ERROR: CURLcode = 21;
pub const CURLE_OBSOLETE20: CURLcode = 20;
pub const CURLE_FTP_COULDNT_RETR_FILE: CURLcode = 19;
pub const CURLE_PARTIAL_FILE: CURLcode = 18;
pub const CURLE_FTP_COULDNT_SET_TYPE: CURLcode = 17;
pub const CURLE_HTTP2: CURLcode = 16;
pub const CURLE_FTP_CANT_GET_HOST: CURLcode = 15;
pub const CURLE_FTP_WEIRD_227_FORMAT: CURLcode = 14;
pub const CURLE_FTP_WEIRD_PASV_REPLY: CURLcode = 13;
pub const CURLE_FTP_ACCEPT_TIMEOUT: CURLcode = 12;
pub const CURLE_FTP_WEIRD_PASS_REPLY: CURLcode = 11;
pub const CURLE_FTP_ACCEPT_FAILED: CURLcode = 10;
pub const CURLE_REMOTE_ACCESS_DENIED: CURLcode = 9;
pub const CURLE_WEIRD_SERVER_REPLY: CURLcode = 8;
pub const CURLE_COULDNT_CONNECT: CURLcode = 7;
pub const CURLE_COULDNT_RESOLVE_HOST: CURLcode = 6;
pub const CURLE_COULDNT_RESOLVE_PROXY: CURLcode = 5;
pub const CURLE_NOT_BUILT_IN: CURLcode = 4;
pub const CURLE_URL_MALFORMAT: CURLcode = 3;
pub const CURLE_FAILED_INIT: CURLcode = 2;
pub const CURLE_UNSUPPORTED_PROTOCOL: CURLcode = 1;
pub const CURLE_OK: CURLcode = 0;
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_malloc_callback = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type curl_strdup_callback =
    Option<unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_ssl_backend {
    pub id: curl_sslbackend,
    pub name: *const libc::c_char,
}
pub type CURLsslset = libc::c_uint;
pub const CURLSSLSET_NO_BACKENDS: CURLsslset = 3;
pub const CURLSSLSET_TOO_LATE: CURLsslset = 2;
pub const CURLSSLSET_UNKNOWN_BACKEND: CURLsslset = 1;
pub const CURLSSLSET_OK: CURLsslset = 0;
unsafe extern "C" fn blobdup(mut dest: *mut *mut curl_blob, mut src: *mut curl_blob) -> CURLcode {
    if !src.is_null() {
        let mut d: *mut curl_blob = 0 as *mut curl_blob;
        d = Curl_cmalloc.expect("non-null function pointer")(
            (::std::mem::size_of::<curl_blob>() as libc::c_ulong).wrapping_add((*src).len),
        ) as *mut curl_blob;
        if d.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*d).len = (*src).len;
        (*d).flags = 1 as libc::c_int as libc::c_uint;
        let ref mut fresh0 = (*d).data;
        *fresh0 = (d as *mut libc::c_char)
            .offset(::std::mem::size_of::<curl_blob>() as libc::c_ulong as isize)
            as *mut libc::c_void;
        memcpy((*d).data, (*src).data, (*src).len);
        *dest = d;
    }
    return CURLE_OK;
}
unsafe extern "C" fn blobcmp(mut first: *mut curl_blob, mut second: *mut curl_blob) -> bool {
    if first.is_null() && second.is_null() {
        return 1 as libc::c_int != 0;
    }
    if first.is_null() || second.is_null() {
        return 0 as libc::c_int != 0;
    }
    if (*first).len != (*second).len {
        return 0 as libc::c_int != 0;
    }
    return memcmp((*first).data, (*second).data, (*first).len) == 0;
}
unsafe extern "C" fn safecmp(mut a: *mut libc::c_char, mut b: *mut libc::c_char) -> bool {
    if !a.is_null() && !b.is_null() {
        return strcmp(a, b) == 0;
    } else {
        if a.is_null() && b.is_null() {
            return 1 as libc::c_int != 0;
        }
    }
    return 0 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_config_matches(
    mut data: *mut ssl_primary_config,
    mut needle: *mut ssl_primary_config,
) -> bool {
    if (*data).version == (*needle).version
        && (*data).version_max == (*needle).version_max
        && (*data).verifypeer() as libc::c_int == (*needle).verifypeer() as libc::c_int
        && (*data).verifyhost() as libc::c_int == (*needle).verifyhost() as libc::c_int
        && (*data).verifystatus() as libc::c_int == (*needle).verifystatus() as libc::c_int
        && blobcmp((*data).cert_blob, (*needle).cert_blob) as libc::c_int != 0
        && blobcmp((*data).ca_info_blob, (*needle).ca_info_blob) as libc::c_int != 0
        && blobcmp((*data).issuercert_blob, (*needle).issuercert_blob) as libc::c_int != 0
        && safecmp((*data).CApath, (*needle).CApath) as libc::c_int != 0
        && safecmp((*data).CAfile, (*needle).CAfile) as libc::c_int != 0
        && safecmp((*data).issuercert, (*needle).issuercert) as libc::c_int != 0
        && safecmp((*data).clientcert, (*needle).clientcert) as libc::c_int != 0
        && safecmp((*data).random_file, (*needle).random_file) as libc::c_int != 0
        && safecmp((*data).egdsocket, (*needle).egdsocket) as libc::c_int != 0
        && Curl_safe_strcasecompare((*data).cipher_list, (*needle).cipher_list) != 0
        && Curl_safe_strcasecompare((*data).cipher_list13, (*needle).cipher_list13) != 0
        && Curl_safe_strcasecompare((*data).curves, (*needle).curves) != 0
        && Curl_safe_strcasecompare((*data).pinned_key, (*needle).pinned_key) != 0
    {
        return 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_clone_primary_ssl_config(
    mut source: *mut ssl_primary_config,
    mut dest: *mut ssl_primary_config,
) -> bool {
    (*dest).version = (*source).version;
    (*dest).version_max = (*source).version_max;
    (*dest).set_verifypeer((*source).verifypeer());
    (*dest).set_verifyhost((*source).verifyhost());
    (*dest).set_verifystatus((*source).verifystatus());
    (*dest).set_sessionid((*source).sessionid());
    if blobdup(&mut (*dest).cert_blob, (*source).cert_blob) as u64 != 0 {
        return 0 as libc::c_int != 0;
    }
    if blobdup(&mut (*dest).ca_info_blob, (*source).ca_info_blob) as u64 != 0 {
        return 0 as libc::c_int != 0;
    }
    if blobdup(&mut (*dest).issuercert_blob, (*source).issuercert_blob) as u64 != 0 {
        return 0 as libc::c_int != 0;
    }
    if !((*source).CApath).is_null() {
        let ref mut fresh1 = (*dest).CApath;
        *fresh1 = Curl_cstrdup.expect("non-null function pointer")((*source).CApath);
        if ((*dest).CApath).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh2 = (*dest).CApath;
        *fresh2 = 0 as *mut libc::c_char;
    }
    if !((*source).CAfile).is_null() {
        let ref mut fresh3 = (*dest).CAfile;
        *fresh3 = Curl_cstrdup.expect("non-null function pointer")((*source).CAfile);
        if ((*dest).CAfile).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh4 = (*dest).CAfile;
        *fresh4 = 0 as *mut libc::c_char;
    }
    if !((*source).issuercert).is_null() {
        let ref mut fresh5 = (*dest).issuercert;
        *fresh5 = Curl_cstrdup.expect("non-null function pointer")((*source).issuercert);
        if ((*dest).issuercert).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh6 = (*dest).issuercert;
        *fresh6 = 0 as *mut libc::c_char;
    }
    if !((*source).clientcert).is_null() {
        let ref mut fresh7 = (*dest).clientcert;
        *fresh7 = Curl_cstrdup.expect("non-null function pointer")((*source).clientcert);
        if ((*dest).clientcert).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh8 = (*dest).clientcert;
        *fresh8 = 0 as *mut libc::c_char;
    }
    if !((*source).random_file).is_null() {
        let ref mut fresh9 = (*dest).random_file;
        *fresh9 = Curl_cstrdup.expect("non-null function pointer")((*source).random_file);
        if ((*dest).random_file).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh10 = (*dest).random_file;
        *fresh10 = 0 as *mut libc::c_char;
    }
    if !((*source).egdsocket).is_null() {
        let ref mut fresh11 = (*dest).egdsocket;
        *fresh11 = Curl_cstrdup.expect("non-null function pointer")((*source).egdsocket);
        if ((*dest).egdsocket).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh12 = (*dest).egdsocket;
        *fresh12 = 0 as *mut libc::c_char;
    }
    if !((*source).cipher_list).is_null() {
        let ref mut fresh13 = (*dest).cipher_list;
        *fresh13 = Curl_cstrdup.expect("non-null function pointer")((*source).cipher_list);
        if ((*dest).cipher_list).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh14 = (*dest).cipher_list;
        *fresh14 = 0 as *mut libc::c_char;
    }
    if !((*source).cipher_list13).is_null() {
        let ref mut fresh15 = (*dest).cipher_list13;
        *fresh15 = Curl_cstrdup.expect("non-null function pointer")((*source).cipher_list13);
        if ((*dest).cipher_list13).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh16 = (*dest).cipher_list13;
        *fresh16 = 0 as *mut libc::c_char;
    }
    if !((*source).pinned_key).is_null() {
        let ref mut fresh17 = (*dest).pinned_key;
        *fresh17 = Curl_cstrdup.expect("non-null function pointer")((*source).pinned_key);
        if ((*dest).pinned_key).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh18 = (*dest).pinned_key;
        *fresh18 = 0 as *mut libc::c_char;
    }
    if !((*source).curves).is_null() {
        let ref mut fresh19 = (*dest).curves;
        *fresh19 = Curl_cstrdup.expect("non-null function pointer")((*source).curves);
        if ((*dest).curves).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh20 = (*dest).curves;
        *fresh20 = 0 as *mut libc::c_char;
    }
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_free_primary_ssl_config(mut sslc: *mut ssl_primary_config) {
    Curl_cfree.expect("non-null function pointer")((*sslc).CApath as *mut libc::c_void);
    let ref mut fresh21 = (*sslc).CApath;
    *fresh21 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).CAfile as *mut libc::c_void);
    let ref mut fresh22 = (*sslc).CAfile;
    *fresh22 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).issuercert as *mut libc::c_void);
    let ref mut fresh23 = (*sslc).issuercert;
    *fresh23 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).clientcert as *mut libc::c_void);
    let ref mut fresh24 = (*sslc).clientcert;
    *fresh24 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).random_file as *mut libc::c_void);
    let ref mut fresh25 = (*sslc).random_file;
    *fresh25 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).egdsocket as *mut libc::c_void);
    let ref mut fresh26 = (*sslc).egdsocket;
    *fresh26 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).cipher_list as *mut libc::c_void);
    let ref mut fresh27 = (*sslc).cipher_list;
    *fresh27 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).cipher_list13 as *mut libc::c_void);
    let ref mut fresh28 = (*sslc).cipher_list13;
    *fresh28 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).pinned_key as *mut libc::c_void);
    let ref mut fresh29 = (*sslc).pinned_key;
    *fresh29 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).cert_blob as *mut libc::c_void);
    let ref mut fresh30 = (*sslc).cert_blob;
    *fresh30 = 0 as *mut curl_blob;
    Curl_cfree.expect("non-null function pointer")((*sslc).ca_info_blob as *mut libc::c_void);
    let ref mut fresh31 = (*sslc).ca_info_blob;
    *fresh31 = 0 as *mut curl_blob;
    Curl_cfree.expect("non-null function pointer")((*sslc).issuercert_blob as *mut libc::c_void);
    let ref mut fresh32 = (*sslc).issuercert_blob;
    *fresh32 = 0 as *mut curl_blob;
    Curl_cfree.expect("non-null function pointer")((*sslc).curves as *mut libc::c_void);
    let ref mut fresh33 = (*sslc).curves;
    *fresh33 = 0 as *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_backend() -> libc::c_int {
    return CURLSSLBACKEND_NONE as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn curl_global_sslset(
    mut id: curl_sslbackend,
    mut name: *const libc::c_char,
    mut avail: *mut *mut *const curl_ssl_backend,
) -> CURLsslset {
    return CURLSSLSET_NO_BACKENDS;
}
