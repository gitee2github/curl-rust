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
 * Author: pnext<pnext@mail.ustc.edu.cn>, 
 * Create: 2022-10-31
 * Description: type alias that ffi needed
 ******************************************************************************/
use crate::src::ffi_struct::struct_define::*;
use c2rust_bitfields::BitfieldStruct;
// use rust_project::src::vtls::vtls::*;

// ---------------------Extern C------------------------------------------------------------------------------
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    // ftp.rs
    pub type Curl_URL;
    pub type thread_data;
    // pub type altsvcinfo;
    pub type TELNET;
    pub type smb_request;
    pub type ldapreqinfo;
    // pub type contenc_writer;
    pub type psl_ctx_st;
    // pub type Curl_share;
    // pub type curl_pushheaders;
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    // pub type ftp_parselist_data;
    // pub type http_connect_state;

    // mbedtls ftp 
    // pub type ssl_backend_data;

    // http2.rs
    pub type nghttp2_session_callbacks;

    // http_ntlm.rs
    // pub type hsts;

    // mbedtls.rs
    pub type mbedtls_pk_info_t;
    pub type mbedtls_ssl_key_cert;
    pub type mbedtls_ssl_transform;
    pub type mbedtls_ssl_handshake_params;

    // gnutls gtls.rs
    pub type gnutls_srp_client_credentials_st;
    pub type gnutls_certificate_credentials_st;
    pub type gnutls_session_int;
    pub type gnutls_pubkey_st;
    pub type gnutls_x509_crt_int;
    pub type gnutls_ocsp_resp_int;

    // wolfssl.rs 
    pub type WOLFSSL;
    pub type WOLFSSL_CTX;
    pub type WOLFSSL_SESSION;
    pub type WOLFSSL_X509;
    pub type WOLFSSL_STACK;
    pub type WOLFSSL_CERT_MANAGER;
    pub type WOLFSSL_METHOD;
    pub type DRBG;

    // nss.rs
    pub type PK11GenericObjectStr;
    pub type PRFilePrivate;
    pub type PRLock;
    pub type NSSInitContextStr;
    pub type PK11ContextStr;
    pub type PK11SlotInfoStr;
    pub type NSSCertificateStr;
    pub type NSSTrustDomainStr;
    pub type NSSUTILPreSlotInfoStr;
    pub type PRDir;

    // rustls.rs
    pub type rustls_connection;
    pub type rustls_client_config;
    pub type rustls_client_config_builder;
    pub type rustls_root_cert_store;
    pub type rustls_slice_slice_bytes;
    
    // openssl.rs
    pub type x509_st;
    pub type ssl_st;
    pub type ssl_ctx_st;
    pub type stack_st_void;
    pub type evp_md_ctx_st;
    pub type evp_md_st;
    pub type engine_st;
    pub type ssl_session_st;
    pub type X509_pubkey_st;
    pub type ocsp_response_st;
    pub type ocsp_basic_response_st;
    pub type ocsp_cert_id_st;
    pub type stack_st_X509;
    pub type stack_st;
    pub type x509_store_st;
    pub type bio_st;
    pub type bio_method_st;
    pub type X509_name_st;
    pub type X509_name_entry_st;
    pub type stack_st_GENERAL_NAME;
    pub type ASN1_VALUE_st;
    pub type asn1_object_st;
    pub type evp_pkey_st;
    pub type bignum_st;
    pub type dh_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type stack_st_X509_EXTENSION;
    pub type X509_extension_st;
    pub type ssl_cipher_st;
    pub type x509_store_ctx_st;
    pub type x509_lookup_st;
    pub type x509_lookup_method_st;
    pub type evp_cipher_st;
    pub type X509_crl_st;
    pub type stack_st_X509_INFO;
    pub type ui_method_st;
    pub type ui_string_st;
    pub type ui_st;
    pub type PKCS12_st;
    pub type ssl_method_st;
    pub type ossl_init_settings_st;
    
    // mesalink.rs
    pub type MESALINK_SSL;
    pub type MESALINK_CTX;
    pub type MESALINK_METHOD;

    // http_negotiate.rs
    pub type gss_name_struct;
    pub type gss_ctx_id_struct;
    pub type Curl_sec_client_mech;

    // other option
    pub type Gsasl_session;
    pub type Gsasl;

    // option hyper
    pub type hyper_waker;
    pub type hyper_task;
    pub type hyper_executor;
    pub type hyper_clientconn;
    pub type hyper_clientconn_options;
    pub type hyper_context;
    pub type hyper_error;
    pub type hyper_headers;
    pub type hyper_io;
    pub type hyper_request;
    // option quiche
    pub type Http3Config;
    pub type Http3Connection;
    pub type Connection;
    pub type Config;

    // option libssh2
    pub type _LIBSSH2_KNOWNHOSTS;
    pub type _LIBSSH2_AGENT;
    pub type _LIBSSH2_SFTP_HANDLE;
    pub type _LIBSSH2_SFTP;
    pub type _LIBSSH2_CHANNEL;
    pub type _LIBSSH2_SESSION;

    // ssh
    pub type ssh_session_struct;
    pub type ssh_scp_struct;
    pub type ssh_key_struct;
    pub type ssh_channel_struct;
    pub type sftp_ext_struct;
    pub type ssh_buffer_struct;
    pub type ssh_string_struct;

    // Statics
    // vtls.rs
    pub static mut Curl_cfree: curl_free_callback;
    pub static mut Curl_cmalloc: curl_malloc_callback;
    pub static mut Curl_cstrdup: curl_strdup_callback;
    // ftp.rs
    pub static Curl_wkday: [*const libc::c_char; 7];
    pub static Curl_month: [*const libc::c_char; 12];
    pub static mut Curl_ccalloc: curl_calloc_callback;
    // ftplistparser.rs
    pub static mut Curl_crealloc: curl_realloc_callback;
    // http_aws_sigv4.rs
    pub static Curl_HMAC_SHA256: [HMAC_params; 1];
    // http.rs
    pub static mut Curl_ssl: *const Curl_ssl;
    // vtls.rs
    pub static Curl_ssl_mbedtls: Curl_ssl;
    pub static Curl_ssl_gnutls: Curl_ssl;
    pub static Curl_ssl_wolfssl: Curl_ssl;
    pub static Curl_ssl_nss: Curl_ssl;
    pub static Curl_ssl_rustls: Curl_ssl;
    pub static Curl_ssl_mesalink: Curl_ssl;
    pub static Curl_ssl_openssl: Curl_ssl;
    pub static Curl_ssl_bearssl: Curl_ssl;

    pub static mut gnutls_free: gnutls_free_function;
    pub static mut stderr: *mut FILE;

    // bearssl.rs
    pub static br_sha256_vtable: br_hash_class;
}

// ---------------------Type Alias----------------------------------------------------------------------------
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
// vtls.rs
pub type curl_sslbackend = libc::c_uint;
pub type bit = libc::c_uint;
pub type CURLcode = libc::c_uint;
pub type curl_malloc_callback = Option::<
    unsafe extern "C" fn(size_t) -> *mut libc::c_void,
>;
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
pub type CURLsslset = libc::c_uint;
// ftp.rs
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __time_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type int32_t = __int32_t;
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;
pub type curl_socklen_t = socklen_t;
pub type curl_off_t = libc::c_long;
pub type CURLproxycode = libc::c_uint;
pub type wildcard_dtor = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type Curl_llist_dtor = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> (),
>;
pub type wildcard_states = libc::c_uint;
pub type trailers_state = libc::c_uint;
pub type Curl_HttpReq = libc::c_uint;
pub type CURLU = Curl_URL;
pub type curl_read_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_char, size_t, size_t, *mut libc::c_void) -> size_t,
>;
pub type expire_id = libc::c_uint;
pub type Curl_hash_dtor = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type comp_function = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t, *mut libc::c_void, size_t) -> size_t,
>;
pub type hash_function = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t, size_t) -> size_t,
>;
pub type timediff_t = curl_off_t;
pub type curl_trailer_callback = Option::<
    unsafe extern "C" fn(*mut *mut curl_slist, *mut libc::c_void) -> libc::c_int,
>;
pub type multidone_func = Option::<
    unsafe extern "C" fn(*mut Curl_easy, CURLcode) -> libc::c_int,
>;
pub type curl_resolver_start_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type curl_fnmatch_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        *const libc::c_char,
    ) -> libc::c_int,
>;
pub type curl_chunk_end_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_long,
>;
pub type curl_chunk_bgn_callback = Option::<
    unsafe extern "C" fn(
        *const libc::c_void,
        *mut libc::c_void,
        libc::c_int,
    ) -> libc::c_long,
>;
pub type Curl_RtspReq = libc::c_uint;
pub type curl_usessl = libc::c_uint;
pub type CURL_NETRC_OPTION = libc::c_uint;
pub type curl_sshkeycallback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        *const curl_khkey,
        *const curl_khkey,
        curl_khmatch,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type curl_khmatch = libc::c_uint;
pub type curl_khtype = libc::c_uint;
pub type CURL = Curl_easy;
pub type curl_ftpccc = libc::c_uint;
pub type curl_ftpauth = libc::c_uint;
pub type curl_ftpfile = libc::c_uint;
pub type curl_ssl_ctx_callback = Option::<
    unsafe extern "C" fn(*mut CURL, *mut libc::c_void, *mut libc::c_void) -> CURLcode,
>;
pub type curl_proxytype = libc::c_uint;
pub type curl_TimeCond = libc::c_uint;
pub type mimestate = libc::c_uint;
pub type curl_seek_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, curl_off_t, libc::c_int) -> libc::c_int,
>;
pub type mimekind = libc::c_uint;
pub type curl_conv_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_char, size_t) -> CURLcode,
>;
pub type curl_closesocket_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, curl_socket_t) -> libc::c_int,
>;
pub type curl_socket_t = libc::c_int;
pub type curl_opensocket_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        curlsocktype,
        *mut curl_sockaddr,
    ) -> curl_socket_t,
>;
pub type curlsocktype = libc::c_uint;
pub type curl_sockopt_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, curl_socket_t, curlsocktype) -> libc::c_int,
>;
pub type curl_ioctl_callback = Option::<
    unsafe extern "C" fn(*mut CURL, libc::c_int, *mut libc::c_void) -> curlioerr,
>;
pub type curlioerr = libc::c_uint;
pub type curl_debug_callback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        curl_infotype,
        *mut libc::c_char,
        size_t,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type curl_infotype = libc::c_uint;
pub type curl_xferinfo_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        curl_off_t,
        curl_off_t,
        curl_off_t,
        curl_off_t,
    ) -> libc::c_int,
>;
pub type curl_progress_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        libc::c_double,
        libc::c_double,
        libc::c_double,
        libc::c_double,
    ) -> libc::c_int,
>;
pub type curl_write_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_char, size_t, size_t, *mut libc::c_void) -> size_t,
>;
pub type curl_pp_transfer = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type C2RustUnnamed_0 = libc::c_uint;
pub type upgrade101 = libc::c_uint;
pub type expect100 = libc::c_uint;
pub type C2RustUnnamed_1 = libc::c_uint;
pub type psl_ctx_t = psl_ctx_st;
pub type curl_multi_timer_callback = Option::<
    unsafe extern "C" fn(*mut CURLM, libc::c_long, *mut libc::c_void) -> libc::c_int,
>;
pub type CURLM = Curl_multi;
pub type curl_push_callback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        *mut CURL,
        size_t,
        *mut curl_pushheaders,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type curl_socket_callback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        curl_socket_t,
        libc::c_int,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type C2RustUnnamed_2 = libc::c_uint;
pub type CURLMSG = libc::c_uint;
pub type CURLMstate = libc::c_uint;
pub type C2RustUnnamed_4 = libc::c_uint;
pub type keeponval = libc::c_uint;
pub type mqttstate = libc::c_uint;
pub type smb_conn_state = libc::c_uint;
pub type saslstate = libc::c_uint;
pub type smtpstate = libc::c_uint;
pub type pop3state = libc::c_uint;
pub type imapstate = libc::c_uint;
pub type sshstate = libc::c_int;
pub type Curl_recv = unsafe extern "C" fn(
    *mut Curl_easy,
    libc::c_int,
    *mut libc::c_char,
    size_t,
    *mut CURLcode,
) -> ssize_t;
pub type Curl_send = unsafe extern "C" fn(
    *mut Curl_easy,
    libc::c_int,
    *const libc::c_void,
    size_t,
    *mut CURLcode,
) -> ssize_t;
pub type ftpstate = libc::c_uint;
pub type ssl_connect_state = libc::c_uint;
pub type ssl_connection_state = libc::c_uint;
pub type ChunkyState = libc::c_uint;
pub type connect_t = libc::c_uint;
pub type curlfiletype = libc::c_uint;
pub type curl_calloc_callback = Option::<
    unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void,
>;
pub type uint16_t = __uint16_t;
pub type in_addr_t = uint32_t;
pub type in_port_t = uint16_t;
pub type resolve_t = libc::c_int;
pub type ftpport = libc::c_uint;
pub type if2ip_result_t = libc::c_uint;
pub type urlreject = libc::c_uint;
pub type timerid = libc::c_uint;
pub type CURLofft = libc::c_uint;
pub type dupstring = libc::c_uint;
// ftplistparser.rs
pub type curl_realloc_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
>;
pub type ftpl_C2RustUnnamed_10 = libc::c_uint;
pub type ftpl_C2RustUnnamed_11 = libc::c_uint;
pub type C2RustUnnamed_12 = libc::c_uint;
pub type pl_winNT_mainstate = libc::c_uint;
// http_aws_sigv4.rs
pub type HMAC_hfinal_func = Option::<
    unsafe extern "C" fn(*mut libc::c_uchar, *mut libc::c_void) -> (),
>;
pub type HMAC_hupdate_func = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_uchar, libc::c_uint) -> (),
>;
pub type HMAC_hinit_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;

// http.rs
pub type curl_unlock_function = Option::<
    unsafe extern "C" fn(*mut CURL, curl_lock_data, *mut libc::c_void) -> (),
>;

pub type curl_lock_function = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        curl_lock_data,
        curl_lock_access,
        *mut libc::c_void,
    ) -> (),
>;
// http_digest.rs

//http2.rs
pub type nghttp2_data_source_read_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        int32_t,
        *mut uint8_t,
        size_t,
        *mut uint32_t,
        *mut nghttp2_data_source,
        *mut libc::c_void,
    ) -> ssize_t,
>;
pub type nghttp2_send_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const uint8_t,
        size_t,
        libc::c_int,
        *mut libc::c_void,
    ) -> ssize_t,
>;
pub type nghttp2_on_frame_recv_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const nghttp2_frame,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type nghttp2_on_data_chunk_recv_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        uint8_t,
        int32_t,
        *const uint8_t,
        size_t,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type nghttp2_on_stream_close_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        int32_t,
        uint32_t,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type nghttp2_on_begin_headers_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const nghttp2_frame,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type nghttp2_on_header_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const nghttp2_frame,
        *const uint8_t,
        size_t,
        *const uint8_t,
        size_t,
        uint8_t,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type nghttp2_error_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const libc::c_char,
        size_t,
        *mut libc::c_void,
    ) -> libc::c_int,
>;

// ----------------------Statics------------------------------------------------------------------------------
// pub static mut keylog_file_fp: *mut FILE = 0 as *const FILE as *mut FILE;

// ----------------------Constants----------------------------------------------------------------------------
// vtls.rs
// curl_sslbackend
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
// CURLcode
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
// CURLsslset
pub const CURLSSLSET_NO_BACKENDS: CURLsslset = 3;
pub const CURLSSLSET_TOO_LATE: CURLsslset = 2;
pub const CURLSSLSET_UNKNOWN_BACKEND: CURLsslset = 1;
pub const CURLSSLSET_OK: CURLsslset = 0;
// ftp.rs
// CURLproxycode
pub const CURLPX_LAST: CURLproxycode = 34;
pub const CURLPX_USER_REJECTED: CURLproxycode = 33;
pub const CURLPX_UNKNOWN_MODE: CURLproxycode = 32;
pub const CURLPX_UNKNOWN_FAIL: CURLproxycode = 31;
pub const CURLPX_SEND_REQUEST: CURLproxycode = 30;
pub const CURLPX_SEND_CONNECT: CURLproxycode = 29;
pub const CURLPX_SEND_AUTH: CURLproxycode = 28;
pub const CURLPX_RESOLVE_HOST: CURLproxycode = 27;
pub const CURLPX_REQUEST_FAILED: CURLproxycode = 26;
pub const CURLPX_REPLY_UNASSIGNED: CURLproxycode = 25;
pub const CURLPX_REPLY_TTL_EXPIRED: CURLproxycode = 24;
pub const CURLPX_REPLY_NOT_ALLOWED: CURLproxycode = 23;
pub const CURLPX_REPLY_NETWORK_UNREACHABLE: CURLproxycode = 22;
pub const CURLPX_REPLY_HOST_UNREACHABLE: CURLproxycode = 21;
pub const CURLPX_REPLY_GENERAL_SERVER_FAILURE: CURLproxycode = 20;
pub const CURLPX_REPLY_CONNECTION_REFUSED: CURLproxycode = 19;
pub const CURLPX_REPLY_COMMAND_NOT_SUPPORTED: CURLproxycode = 18;
pub const CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: CURLproxycode = 17;
pub const CURLPX_RECV_REQACK: CURLproxycode = 16;
pub const CURLPX_RECV_CONNECT: CURLproxycode = 15;
pub const CURLPX_RECV_AUTH: CURLproxycode = 14;
pub const CURLPX_RECV_ADDRESS: CURLproxycode = 13;
pub const CURLPX_NO_AUTH: CURLproxycode = 12;
pub const CURLPX_LONG_USER: CURLproxycode = 11;
pub const CURLPX_LONG_PASSWD: CURLproxycode = 10;
pub const CURLPX_LONG_HOSTNAME: CURLproxycode = 9;
pub const CURLPX_IDENTD_DIFFER: CURLproxycode = 8;
pub const CURLPX_IDENTD: CURLproxycode = 7;
pub const CURLPX_GSSAPI_PROTECTION: CURLproxycode = 6;
pub const CURLPX_GSSAPI_PERMSG: CURLproxycode = 5;
pub const CURLPX_GSSAPI: CURLproxycode = 4;
pub const CURLPX_CLOSED: CURLproxycode = 3;
pub const CURLPX_BAD_VERSION: CURLproxycode = 2;
pub const CURLPX_BAD_ADDRESS_TYPE: CURLproxycode = 1;
pub const CURLPX_OK: CURLproxycode = 0;
// wildcard_states
pub const CURLWC_DONE: wildcard_states = 7;
pub const CURLWC_ERROR: wildcard_states = 6;
pub const CURLWC_SKIP: wildcard_states = 5;
pub const CURLWC_CLEAN: wildcard_states = 4;
pub const CURLWC_DOWNLOADING: wildcard_states = 3;
pub const CURLWC_MATCHING: wildcard_states = 2;
pub const CURLWC_INIT: wildcard_states = 1;
pub const CURLWC_CLEAR: wildcard_states = 0;
// trailers_state
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
// Curl_HttpReq
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
// expire_id
pub const EXPIRE_LAST: expire_id = 13;
pub const EXPIRE_QUIC: expire_id = 12;
pub const EXPIRE_TOOFAST: expire_id = 11;
pub const EXPIRE_TIMEOUT: expire_id = 10;
pub const EXPIRE_SPEEDCHECK: expire_id = 9;
pub const EXPIRE_RUN_NOW: expire_id = 8;
pub const EXPIRE_MULTI_PENDING: expire_id = 7;
pub const EXPIRE_HAPPY_EYEBALLS: expire_id = 6;
pub const EXPIRE_HAPPY_EYEBALLS_DNS: expire_id = 5;
pub const EXPIRE_DNS_PER_NAME2: expire_id = 4;
pub const EXPIRE_DNS_PER_NAME: expire_id = 3;
pub const EXPIRE_CONNECTTIMEOUT: expire_id = 2;
pub const EXPIRE_ASYNC_NAME: expire_id = 1;
pub const EXPIRE_100_TIMEOUT: expire_id = 0;
// Curl_RtspReq
pub const RTSPREQ_LAST: Curl_RtspReq = 12;
pub const RTSPREQ_RECEIVE: Curl_RtspReq = 11;
pub const RTSPREQ_RECORD: Curl_RtspReq = 10;
pub const RTSPREQ_SET_PARAMETER: Curl_RtspReq = 9;
pub const RTSPREQ_GET_PARAMETER: Curl_RtspReq = 8;
pub const RTSPREQ_TEARDOWN: Curl_RtspReq = 7;
pub const RTSPREQ_PAUSE: Curl_RtspReq = 6;
pub const RTSPREQ_PLAY: Curl_RtspReq = 5;
pub const RTSPREQ_SETUP: Curl_RtspReq = 4;
pub const RTSPREQ_ANNOUNCE: Curl_RtspReq = 3;
pub const RTSPREQ_DESCRIBE: Curl_RtspReq = 2;
pub const RTSPREQ_OPTIONS: Curl_RtspReq = 1;
pub const RTSPREQ_NONE: Curl_RtspReq = 0;
// curl_usessl
pub const CURLUSESSL_LAST: curl_usessl = 4;
pub const CURLUSESSL_ALL: curl_usessl = 3;
pub const CURLUSESSL_CONTROL: curl_usessl = 2;
pub const CURLUSESSL_TRY: curl_usessl = 1;
pub const CURLUSESSL_NONE: curl_usessl = 0;
// CURL_NETRC_OPTION
pub const CURL_NETRC_LAST: CURL_NETRC_OPTION = 3;
pub const CURL_NETRC_REQUIRED: CURL_NETRC_OPTION = 2;
pub const CURL_NETRC_OPTIONAL: CURL_NETRC_OPTION = 1;
pub const CURL_NETRC_IGNORED: CURL_NETRC_OPTION = 0;
// curl_khmatch
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
// curl_khtype
pub const CURLKHTYPE_ED25519: curl_khtype = 5;
pub const CURLKHTYPE_ECDSA: curl_khtype = 4;
pub const CURLKHTYPE_DSS: curl_khtype = 3;
pub const CURLKHTYPE_RSA: curl_khtype = 2;
pub const CURLKHTYPE_RSA1: curl_khtype = 1;
pub const CURLKHTYPE_UNKNOWN: curl_khtype = 0;
// curl_ftpccc
pub const CURLFTPSSL_CCC_LAST: curl_ftpccc = 3;
pub const CURLFTPSSL_CCC_ACTIVE: curl_ftpccc = 2;
pub const CURLFTPSSL_CCC_PASSIVE: curl_ftpccc = 1;
pub const CURLFTPSSL_CCC_NONE: curl_ftpccc = 0;
// curl_ftpauth
pub const CURLFTPAUTH_LAST: curl_ftpauth = 3;
pub const CURLFTPAUTH_TLS: curl_ftpauth = 2;
pub const CURLFTPAUTH_SSL: curl_ftpauth = 1;
pub const CURLFTPAUTH_DEFAULT: curl_ftpauth = 0;
// curl_ftpfile
pub const FTPFILE_SINGLECWD: curl_ftpfile = 3;
pub const FTPFILE_NOCWD: curl_ftpfile = 2;
pub const FTPFILE_MULTICWD: curl_ftpfile = 1;
// curl_proxytype
pub const CURLPROXY_SOCKS5_HOSTNAME: curl_proxytype = 7;
pub const CURLPROXY_SOCKS4A: curl_proxytype = 6;
pub const CURLPROXY_SOCKS5: curl_proxytype = 5;
pub const CURLPROXY_SOCKS4: curl_proxytype = 4;
pub const CURLPROXY_HTTPS: curl_proxytype = 2;
pub const CURLPROXY_HTTP_1_0: curl_proxytype = 1;
pub const CURLPROXY_HTTP: curl_proxytype = 0;
// curl_TimeCond
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
// mimestate
pub const MIMESTATE_LAST: mimestate = 9;
pub const MIMESTATE_END: mimestate = 8;
pub const MIMESTATE_CONTENT: mimestate = 7;
pub const MIMESTATE_BOUNDARY2: mimestate = 6;
pub const MIMESTATE_BOUNDARY1: mimestate = 5;
pub const MIMESTATE_BODY: mimestate = 4;
pub const MIMESTATE_EOH: mimestate = 3;
pub const MIMESTATE_USERHEADERS: mimestate = 2;
pub const MIMESTATE_CURLHEADERS: mimestate = 1;
pub const MIMESTATE_BEGIN: mimestate = 0;
// mimekind
pub const MIMEKIND_LAST: mimekind = 5;
pub const MIMEKIND_MULTIPART: mimekind = 4;
pub const MIMEKIND_CALLBACK: mimekind = 3;
pub const MIMEKIND_FILE: mimekind = 2;
pub const MIMEKIND_DATA: mimekind = 1;
pub const MIMEKIND_NONE: mimekind = 0;
// curlsocktype
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
// curlioerr
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
// curl_infotype
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
// curl_pp_transfer
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
// C2RustUnnamed_0
pub const HTTPSEND_BODY: C2RustUnnamed_0 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_0 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_0 = 0;

// upgrade101
pub const UPGR101_WORKING: upgrade101 = 3;
pub const UPGR101_RECEIVED: upgrade101 = 2;
pub const UPGR101_REQUESTED: upgrade101 = 1;
pub const UPGR101_INIT: upgrade101 = 0;

// expect100
pub const EXP100_FAILED: expect100 = 3;
pub const EXP100_SENDING_REQUEST: expect100 = 2;
pub const EXP100_AWAITING_CONTINUE: expect100 = 1;
pub const EXP100_SEND_DATA: expect100 = 0;

// C2RustUnnamed_1
pub const HEADER_ALLBAD: C2RustUnnamed_1 = 2;
pub const HEADER_PARTHEADER: C2RustUnnamed_1 = 1;
pub const HEADER_NORMAL: C2RustUnnamed_1 = 0;

// C2RustUnnamed_2
pub const HCACHE_SHARED: C2RustUnnamed_2 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_2 = 1;
pub const HCACHE_NONE: C2RustUnnamed_2 = 0;

// CURLMSG
pub const CURLMSG_LAST: CURLMSG = 2;
pub const CURLMSG_DONE: CURLMSG = 1;
pub const CURLMSG_NONE: CURLMSG = 0;

// CURLMstate
pub const MSTATE_LAST: CURLMstate = 17;
pub const MSTATE_MSGSENT: CURLMstate = 16;
pub const MSTATE_COMPLETED: CURLMstate = 15;
pub const MSTATE_DONE: CURLMstate = 14;
pub const MSTATE_RATELIMITING: CURLMstate = 13;
pub const MSTATE_PERFORMING: CURLMstate = 12;
pub const MSTATE_DID: CURLMstate = 11;
pub const MSTATE_DOING_MORE: CURLMstate = 10;
pub const MSTATE_DOING: CURLMstate = 9;
pub const MSTATE_DO: CURLMstate = 8;
pub const MSTATE_PROTOCONNECTING: CURLMstate = 7;
pub const MSTATE_PROTOCONNECT: CURLMstate = 6;
pub const MSTATE_TUNNELING: CURLMstate = 5;
pub const MSTATE_CONNECTING: CURLMstate = 4;
pub const MSTATE_RESOLVING: CURLMstate = 3;
pub const MSTATE_CONNECT: CURLMstate = 2;
pub const MSTATE_PENDING: CURLMstate = 1;
pub const MSTATE_INIT: CURLMstate = 0;

// C2RustUnnamed_4
pub const TUNNEL_EXIT: C2RustUnnamed_4 = 3;
pub const TUNNEL_COMPLETE: C2RustUnnamed_4 = 2;
pub const TUNNEL_CONNECT: C2RustUnnamed_4 = 1;
pub const TUNNEL_INIT: C2RustUnnamed_4 = 0;

// keeponval
pub const KEEPON_IGNORE: keeponval = 2;
pub const KEEPON_CONNECT: keeponval = 1;
pub const KEEPON_DONE: keeponval = 0;

// mqttstate
pub const MQTT_NOSTATE: mqttstate = 7;
pub const MQTT_PUB_REMAIN: mqttstate = 6;
pub const MQTT_PUBWAIT: mqttstate = 5;
pub const MQTT_SUBACK_COMING: mqttstate = 4;
pub const MQTT_SUBACK: mqttstate = 3;
pub const MQTT_CONNACK: mqttstate = 2;
pub const MQTT_REMAINING_LENGTH: mqttstate = 1;
pub const MQTT_FIRST: mqttstate = 0;

// smb_conn_state
pub const SMB_CONNECTED: smb_conn_state = 4;
pub const SMB_SETUP: smb_conn_state = 3;
pub const SMB_NEGOTIATE: smb_conn_state = 2;
pub const SMB_CONNECTING: smb_conn_state = 1;
pub const SMB_NOT_CONNECTED: smb_conn_state = 0;

// saslstate
pub const SASL_FINAL: saslstate = 17;
pub const SASL_CANCEL: saslstate = 16;
pub const SASL_GSASL: saslstate = 15;
pub const SASL_OAUTH2_RESP: saslstate = 14;
pub const SASL_OAUTH2: saslstate = 13;
pub const SASL_GSSAPI_NO_DATA: saslstate = 12;
pub const SASL_GSSAPI_TOKEN: saslstate = 11;
pub const SASL_GSSAPI: saslstate = 10;
pub const SASL_NTLM_TYPE2MSG: saslstate = 9;
pub const SASL_NTLM: saslstate = 8;
pub const SASL_DIGESTMD5_RESP: saslstate = 7;
pub const SASL_DIGESTMD5: saslstate = 6;
pub const SASL_CRAMMD5: saslstate = 5;
pub const SASL_EXTERNAL: saslstate = 4;
pub const SASL_LOGIN_PASSWD: saslstate = 3;
pub const SASL_LOGIN: saslstate = 2;
pub const SASL_PLAIN: saslstate = 1;
pub const SASL_STOP: saslstate = 0;

// smtpstate
pub const SMTP_LAST: smtpstate = 13;
pub const SMTP_QUIT: smtpstate = 12;
pub const SMTP_POSTDATA: smtpstate = 11;
pub const SMTP_DATA: smtpstate = 10;
pub const SMTP_RCPT: smtpstate = 9;
pub const SMTP_MAIL: smtpstate = 8;
pub const SMTP_COMMAND: smtpstate = 7;
pub const SMTP_AUTH: smtpstate = 6;
pub const SMTP_UPGRADETLS: smtpstate = 5;
pub const SMTP_STARTTLS: smtpstate = 4;
pub const SMTP_HELO: smtpstate = 3;
pub const SMTP_EHLO: smtpstate = 2;
pub const SMTP_SERVERGREET: smtpstate = 1;
pub const SMTP_STOP: smtpstate = 0;

// pop3state
pub const POP3_LAST: pop3state = 11;
pub const POP3_QUIT: pop3state = 10;
pub const POP3_COMMAND: pop3state = 9;
pub const POP3_PASS: pop3state = 8;
pub const POP3_USER: pop3state = 7;
pub const POP3_APOP: pop3state = 6;
pub const POP3_AUTH: pop3state = 5;
pub const POP3_UPGRADETLS: pop3state = 4;
pub const POP3_STARTTLS: pop3state = 3;
pub const POP3_CAPA: pop3state = 2;
pub const POP3_SERVERGREET: pop3state = 1;
pub const POP3_STOP: pop3state = 0;

// imapstate
pub const IMAP_LAST: imapstate = 15;
pub const IMAP_LOGOUT: imapstate = 14;
pub const IMAP_SEARCH: imapstate = 13;
pub const IMAP_APPEND_FINAL: imapstate = 12;
pub const IMAP_APPEND: imapstate = 11;
pub const IMAP_FETCH_FINAL: imapstate = 10;
pub const IMAP_FETCH: imapstate = 9;
pub const IMAP_SELECT: imapstate = 8;
pub const IMAP_LIST: imapstate = 7;
pub const IMAP_LOGIN: imapstate = 6;
pub const IMAP_AUTHENTICATE: imapstate = 5;
pub const IMAP_UPGRADETLS: imapstate = 4;
pub const IMAP_STARTTLS: imapstate = 3;
pub const IMAP_CAPABILITY: imapstate = 2;
pub const IMAP_SERVERGREET: imapstate = 1;
pub const IMAP_STOP: imapstate = 0;

// sshstate
pub const SSH_LAST: sshstate = 60;
pub const SSH_QUIT: sshstate = 59;
pub const SSH_SESSION_FREE: sshstate = 58;
pub const SSH_SESSION_DISCONNECT: sshstate = 57;
pub const SSH_SCP_CHANNEL_FREE: sshstate = 56;
pub const SSH_SCP_WAIT_CLOSE: sshstate = 55;
pub const SSH_SCP_WAIT_EOF: sshstate = 54;
pub const SSH_SCP_SEND_EOF: sshstate = 53;
pub const SSH_SCP_DONE: sshstate = 52;
pub const SSH_SCP_DOWNLOAD: sshstate = 51;
pub const SSH_SCP_DOWNLOAD_INIT: sshstate = 50;
pub const SSH_SCP_UPLOAD_INIT: sshstate = 49;
pub const SSH_SCP_TRANS_INIT: sshstate = 48;
pub const SSH_SFTP_SHUTDOWN: sshstate = 47;
pub const SSH_SFTP_CLOSE: sshstate = 46;
pub const SSH_SFTP_DOWNLOAD_STAT: sshstate = 45;
pub const SSH_SFTP_DOWNLOAD_INIT: sshstate = 44;
pub const SSH_SFTP_READDIR_DONE: sshstate = 43;
pub const SSH_SFTP_READDIR_BOTTOM: sshstate = 42;
pub const SSH_SFTP_READDIR_LINK: sshstate = 41;
pub const SSH_SFTP_READDIR: sshstate = 40;
pub const SSH_SFTP_READDIR_INIT: sshstate = 39;
pub const SSH_SFTP_CREATE_DIRS_MKDIR: sshstate = 38;
pub const SSH_SFTP_CREATE_DIRS: sshstate = 37;
pub const SSH_SFTP_CREATE_DIRS_INIT: sshstate = 36;
pub const SSH_SFTP_UPLOAD_INIT: sshstate = 35;
pub const SSH_SFTP_TRANS_INIT: sshstate = 34;
pub const SSH_SFTP_FILETIME: sshstate = 33;
pub const SSH_SFTP_GETINFO: sshstate = 32;
pub const SSH_SFTP_QUOTE_STATVFS: sshstate = 31;
pub const SSH_SFTP_QUOTE_UNLINK: sshstate = 30;
pub const SSH_SFTP_QUOTE_RMDIR: sshstate = 29;
pub const SSH_SFTP_QUOTE_RENAME: sshstate = 28;
pub const SSH_SFTP_QUOTE_MKDIR: sshstate = 27;
pub const SSH_SFTP_QUOTE_SYMLINK: sshstate = 26;
pub const SSH_SFTP_QUOTE_SETSTAT: sshstate = 25;
pub const SSH_SFTP_QUOTE_STAT: sshstate = 24;
pub const SSH_SFTP_NEXT_QUOTE: sshstate = 23;
pub const SSH_SFTP_QUOTE: sshstate = 22;
pub const SSH_SFTP_POSTQUOTE_INIT: sshstate = 21;
pub const SSH_SFTP_QUOTE_INIT: sshstate = 20;
pub const SSH_SFTP_REALPATH: sshstate = 19;
pub const SSH_SFTP_INIT: sshstate = 18;
pub const SSH_AUTH_DONE: sshstate = 17;
pub const SSH_AUTH_GSSAPI: sshstate = 16;
pub const SSH_AUTH_KEY: sshstate = 15;
pub const SSH_AUTH_KEY_INIT: sshstate = 14;
pub const SSH_AUTH_HOST: sshstate = 13;
pub const SSH_AUTH_HOST_INIT: sshstate = 12;
pub const SSH_AUTH_AGENT: sshstate = 11;
pub const SSH_AUTH_AGENT_LIST: sshstate = 10;
pub const SSH_AUTH_AGENT_INIT: sshstate = 9;
pub const SSH_AUTH_PASS: sshstate = 8;
pub const SSH_AUTH_PASS_INIT: sshstate = 7;
pub const SSH_AUTH_PKEY: sshstate = 6;
pub const SSH_AUTH_PKEY_INIT: sshstate = 5;
pub const SSH_AUTHLIST: sshstate = 4;
pub const SSH_HOSTKEY: sshstate = 3;
pub const SSH_S_STARTUP: sshstate = 2;
pub const SSH_INIT: sshstate = 1;
pub const SSH_STOP: sshstate = 0;
pub const SSH_NO_STATE: sshstate = -1;

// ftpstate
pub const FTP_LAST: ftpstate = 35;
pub const FTP_QUIT: ftpstate = 34;
pub const FTP_STOR: ftpstate = 33;
pub const FTP_RETR: ftpstate = 32;
pub const FTP_LIST: ftpstate = 31;
pub const FTP_PASV: ftpstate = 30;
pub const FTP_PRET: ftpstate = 29;
pub const FTP_PORT: ftpstate = 28;
pub const FTP_RETR_REST: ftpstate = 27;
pub const FTP_REST: ftpstate = 26;
pub const FTP_STOR_SIZE: ftpstate = 25;
pub const FTP_RETR_SIZE: ftpstate = 24;
pub const FTP_SIZE: ftpstate = 23;
pub const FTP_STOR_TYPE: ftpstate = 22;
pub const FTP_RETR_TYPE: ftpstate = 21;
pub const FTP_LIST_TYPE: ftpstate = 20;
pub const FTP_TYPE: ftpstate = 19;
pub const FTP_MDTM: ftpstate = 18;
pub const FTP_MKD: ftpstate = 17;
pub const FTP_CWD: ftpstate = 16;
pub const FTP_POSTQUOTE: ftpstate = 15;
pub const FTP_STOR_PREQUOTE: ftpstate = 14;
pub const FTP_RETR_PREQUOTE: ftpstate = 13;
pub const FTP_QUOTE: ftpstate = 12;
pub const FTP_NAMEFMT: ftpstate = 11;
pub const FTP_SYST: ftpstate = 10;
pub const FTP_PWD: ftpstate = 9;
pub const FTP_CCC: ftpstate = 8;
pub const FTP_PROT: ftpstate = 7;
pub const FTP_PBSZ: ftpstate = 6;
pub const FTP_ACCT: ftpstate = 5;
pub const FTP_PASS: ftpstate = 4;
pub const FTP_USER: ftpstate = 3;
pub const FTP_AUTH: ftpstate = 2;
pub const FTP_WAIT220: ftpstate = 1;
pub const FTP_STOP: ftpstate = 0;

// ssl_connect_state
pub const ssl_connect_done: ssl_connect_state = 5;
pub const ssl_connect_3: ssl_connect_state = 4;
pub const ssl_connect_2_writing: ssl_connect_state = 3;
pub const ssl_connect_2_reading: ssl_connect_state = 2;
pub const ssl_connect_2: ssl_connect_state = 1;
pub const ssl_connect_1: ssl_connect_state = 0;

// ssl_connection_state
pub const ssl_connection_complete: ssl_connection_state = 2;
pub const ssl_connection_negotiating: ssl_connection_state = 1;
pub const ssl_connection_none: ssl_connection_state = 0;

// C2RustUnnamed_6
pub type C2RustUnnamed_6 = libc::c_uint;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;

// ChunkyState
pub const CHUNK_TRAILER_POSTCR: ChunkyState = 7;
pub const CHUNK_TRAILER_CR: ChunkyState = 6;
pub const CHUNK_TRAILER: ChunkyState = 5;
pub const CHUNK_STOP: ChunkyState = 4;
pub const CHUNK_POSTLF: ChunkyState = 3;
pub const CHUNK_DATA: ChunkyState = 2;
pub const CHUNK_LF: ChunkyState = 1;
pub const CHUNK_HEX: ChunkyState = 0;

// connect_t
pub const CONNECT_DONE: connect_t = 17;
pub const CONNECT_REQ_READ_MORE: connect_t = 16;
pub const CONNECT_REQ_READ: connect_t = 15;
pub const CONNECT_REQ_SENDING: connect_t = 14;
pub const CONNECT_REQ_SEND: connect_t = 13;
pub const CONNECT_RESOLVE_REMOTE: connect_t = 12;
pub const CONNECT_RESOLVED: connect_t = 11;
pub const CONNECT_RESOLVING: connect_t = 10;
pub const CONNECT_REQ_INIT: connect_t = 9;
pub const CONNECT_AUTH_READ: connect_t = 8;
pub const CONNECT_AUTH_SEND: connect_t = 7;
pub const CONNECT_AUTH_INIT: connect_t = 6;
pub const CONNECT_GSSAPI_INIT: connect_t = 5;
pub const CONNECT_SOCKS_READ: connect_t = 4;
pub const CONNECT_SOCKS_READ_INIT: connect_t = 3;
pub const CONNECT_SOCKS_SEND: connect_t = 2;
pub const CONNECT_SOCKS_INIT: connect_t = 1;
pub const CONNECT_INIT: connect_t = 0;

// curlfiletype
pub const CURLFILETYPE_UNKNOWN: curlfiletype = 8;
pub const CURLFILETYPE_DOOR: curlfiletype = 7;
pub const CURLFILETYPE_SOCKET: curlfiletype = 6;
pub const CURLFILETYPE_NAMEDPIPE: curlfiletype = 5;
pub const CURLFILETYPE_DEVICE_CHAR: curlfiletype = 4;
pub const CURLFILETYPE_DEVICE_BLOCK: curlfiletype = 3;
pub const CURLFILETYPE_SYMLINK: curlfiletype = 2;
pub const CURLFILETYPE_DIRECTORY: curlfiletype = 1;
pub const CURLFILETYPE_FILE: curlfiletype = 0;

// resolve_t
pub const CURLRESOLV_PENDING: resolve_t = 1;
pub const CURLRESOLV_RESOLVED: resolve_t = 0;
pub const CURLRESOLV_ERROR: resolve_t = -1;
pub const CURLRESOLV_TIMEDOUT: resolve_t = -2;

// ftpport
pub const DONE: ftpport = 2;
pub const PORT: ftpport = 1;
pub const EPRT: ftpport = 0;
pub const IF2IP_FOUND: if2ip_result_t = 2;
pub const IF2IP_AF_NOT_SUPPORTED: if2ip_result_t = 1;
pub const IF2IP_NOT_FOUND: if2ip_result_t = 0;

// urlreject
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;

// timerid
pub const TIMER_LAST: timerid = 11;
pub const TIMER_REDIRECT: timerid = 10;
pub const TIMER_STARTACCEPT: timerid = 9;
pub const TIMER_POSTRANSFER: timerid = 8;
pub const TIMER_STARTTRANSFER: timerid = 7;
pub const TIMER_PRETRANSFER: timerid = 6;
pub const TIMER_APPCONNECT: timerid = 5;
pub const TIMER_CONNECT: timerid = 4;
pub const TIMER_NAMELOOKUP: timerid = 3;
pub const TIMER_STARTSINGLE: timerid = 2;
pub const TIMER_STARTOP: timerid = 1;
pub const TIMER_NONE: timerid = 0;

// CURLofft
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;

// dupstring
pub const STRING_LAST: dupstring = 80;
pub const STRING_AWS_SIGV4: dupstring = 79;
pub const STRING_COPYPOSTFIELDS: dupstring = 78;
pub const STRING_LASTZEROTERMINATED: dupstring = 77;
pub const STRING_SSL_EC_CURVES: dupstring = 76;
pub const STRING_DNS_LOCAL_IP6: dupstring = 75;
pub const STRING_DNS_LOCAL_IP4: dupstring = 74;
pub const STRING_DNS_INTERFACE: dupstring = 73;
pub const STRING_DNS_SERVERS: dupstring = 72;
pub const STRING_SASL_AUTHZID: dupstring = 71;
pub const STRING_HSTS: dupstring = 70;
pub const STRING_ALTSVC: dupstring = 69;
pub const STRING_DOH: dupstring = 68;
pub const STRING_TARGET: dupstring = 67;
pub const STRING_UNIX_SOCKET_PATH: dupstring = 66;
pub const STRING_BEARER: dupstring = 65;
pub const STRING_TLSAUTH_PASSWORD_PROXY: dupstring = 64;
pub const STRING_TLSAUTH_PASSWORD: dupstring = 63;
pub const STRING_TLSAUTH_USERNAME_PROXY: dupstring = 62;
pub const STRING_TLSAUTH_USERNAME: dupstring = 61;
pub const STRING_MAIL_AUTH: dupstring = 60;
pub const STRING_MAIL_FROM: dupstring = 59;
pub const STRING_SERVICE_NAME: dupstring = 58;
pub const STRING_PROXY_SERVICE_NAME: dupstring = 57;
pub const STRING_SSH_KNOWNHOSTS: dupstring = 56;
pub const STRING_SSH_HOST_PUBLIC_KEY_MD5: dupstring = 55;
pub const STRING_SSH_PUBLIC_KEY: dupstring = 54;
pub const STRING_SSH_PRIVATE_KEY: dupstring = 53;
pub const STRING_RTSP_TRANSPORT: dupstring = 52;
pub const STRING_RTSP_STREAM_URI: dupstring = 51;
pub const STRING_RTSP_SESSION_ID: dupstring = 50;
pub const STRING_NOPROXY: dupstring = 49;
pub const STRING_PROXYPASSWORD: dupstring = 48;
pub const STRING_PROXYUSERNAME: dupstring = 47;
pub const STRING_OPTIONS: dupstring = 46;
pub const STRING_PASSWORD: dupstring = 45;
pub const STRING_USERNAME: dupstring = 44;
pub const STRING_SSL_ENGINE: dupstring = 43;
pub const STRING_SSL_ISSUERCERT_PROXY: dupstring = 42;
pub const STRING_SSL_ISSUERCERT: dupstring = 41;
pub const STRING_SSL_CRLFILE_PROXY: dupstring = 40;
pub const STRING_SSL_CRLFILE: dupstring = 39;
pub const STRING_USERAGENT: dupstring = 38;
pub const STRING_SSL_RANDOM_FILE: dupstring = 37;
pub const STRING_SSL_EGDSOCKET: dupstring = 36;
pub const STRING_SSL_CIPHER13_LIST_PROXY: dupstring = 35;
pub const STRING_SSL_CIPHER13_LIST: dupstring = 34;
pub const STRING_SSL_CIPHER_LIST_PROXY: dupstring = 33;
pub const STRING_SSL_CIPHER_LIST: dupstring = 32;
pub const STRING_SSL_PINNEDPUBLICKEY_PROXY: dupstring = 31;
pub const STRING_SSL_PINNEDPUBLICKEY: dupstring = 30;
pub const STRING_SSL_CAFILE_PROXY: dupstring = 29;
pub const STRING_SSL_CAFILE: dupstring = 28;
pub const STRING_SSL_CAPATH_PROXY: dupstring = 27;
pub const STRING_SSL_CAPATH: dupstring = 26;
pub const STRING_SET_URL: dupstring = 25;
pub const STRING_SET_REFERER: dupstring = 24;
pub const STRING_SET_RANGE: dupstring = 23;
pub const STRING_PRE_PROXY: dupstring = 22;
pub const STRING_PROXY: dupstring = 21;
pub const STRING_NETRC_FILE: dupstring = 20;
pub const STRING_KRB_LEVEL: dupstring = 19;
pub const STRING_KEY_TYPE_PROXY: dupstring = 18;
pub const STRING_KEY_TYPE: dupstring = 17;
pub const STRING_KEY_PASSWD_PROXY: dupstring = 16;
pub const STRING_KEY_PASSWD: dupstring = 15;
pub const STRING_KEY_PROXY: dupstring = 14;
pub const STRING_KEY: dupstring = 13;
pub const STRING_FTPPORT: dupstring = 12;
pub const STRING_FTP_ALTERNATIVE_TO_USER: dupstring = 11;
pub const STRING_FTP_ACCOUNT: dupstring = 10;
pub const STRING_ENCODING: dupstring = 9;
pub const STRING_DEVICE: dupstring = 8;
pub const STRING_DEFAULT_PROTOCOL: dupstring = 7;
pub const STRING_CUSTOMREQUEST: dupstring = 6;
pub const STRING_COOKIEJAR: dupstring = 5;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const STRING_CERT: dupstring = 0;

// ftpl_C2RustUnnamed_10
pub const PL_WINNT_FILENAME_WINEOL: ftpl_C2RustUnnamed_10 = 2;
pub const PL_WINNT_FILENAME_CONTENT: ftpl_C2RustUnnamed_10 = 1;
pub const PL_WINNT_FILENAME_PRESPACE: ftpl_C2RustUnnamed_10 = 0;

// ftpl_C2RustUnnamed_11
pub const PL_WINNT_DIRORSIZE_CONTENT: ftpl_C2RustUnnamed_11 = 1;
pub const PL_WINNT_DIRORSIZE_PRESPACE: ftpl_C2RustUnnamed_11 = 0;

// C2RustUnnamed_12
pub const PL_WINNT_TIME_TIME: C2RustUnnamed_12 = 1;
pub const PL_WINNT_TIME_PRESPACE: C2RustUnnamed_12 = 0;

// pl_winNT_mainstate
pub const PL_WINNT_FILENAME: pl_winNT_mainstate = 3;
pub const PL_WINNT_DIRORSIZE: pl_winNT_mainstate = 2;
pub const PL_WINNT_TIME: pl_winNT_mainstate = 1;
pub const PL_WINNT_DATE: pl_winNT_mainstate = 0;

// 没有整理
pub type C2RustUnnamed_14 = libc::c_uint;
pub const PL_UNIX_SYMLINK_WINDOWSEOL: C2RustUnnamed_14 = 7;
pub const PL_UNIX_SYMLINK_TARGET: C2RustUnnamed_14 = 6;
pub const PL_UNIX_SYMLINK_PRETARGET4: C2RustUnnamed_14 = 5;
pub const PL_UNIX_SYMLINK_PRETARGET3: C2RustUnnamed_14 = 4;
pub const PL_UNIX_SYMLINK_PRETARGET2: C2RustUnnamed_14 = 3;
pub const PL_UNIX_SYMLINK_PRETARGET1: C2RustUnnamed_14 = 2;
pub const PL_UNIX_SYMLINK_NAME: C2RustUnnamed_14 = 1;
pub const PL_UNIX_SYMLINK_PRESPACE: C2RustUnnamed_14 = 0;
pub type C2RustUnnamed_15 = libc::c_uint;
pub const PL_UNIX_FILENAME_WINDOWSEOL: C2RustUnnamed_15 = 2;
pub const PL_UNIX_FILENAME_NAME: C2RustUnnamed_15 = 1;
pub const PL_UNIX_FILENAME_PRESPACE: C2RustUnnamed_15 = 0;
pub type C2RustUnnamed_16 = libc::c_uint;
pub const PL_UNIX_TIME_PART3: C2RustUnnamed_16 = 5;
pub const PL_UNIX_TIME_PREPART3: C2RustUnnamed_16 = 4;
pub const PL_UNIX_TIME_PART2: C2RustUnnamed_16 = 3;
pub const PL_UNIX_TIME_PREPART2: C2RustUnnamed_16 = 2;
pub const PL_UNIX_TIME_PART1: C2RustUnnamed_16 = 1;
pub const PL_UNIX_TIME_PREPART1: C2RustUnnamed_16 = 0;
pub type C2RustUnnamed_17 = libc::c_uint;
pub const PL_UNIX_SIZE_NUMBER: C2RustUnnamed_17 = 1;
pub const PL_UNIX_SIZE_PRESPACE: C2RustUnnamed_17 = 0;
pub type C2RustUnnamed_18 = libc::c_uint;
pub const PL_UNIX_GROUP_NAME: C2RustUnnamed_18 = 1;
pub const PL_UNIX_GROUP_PRESPACE: C2RustUnnamed_18 = 0;
pub type C2RustUnnamed_19 = libc::c_uint;
pub const PL_UNIX_USER_PARSING: C2RustUnnamed_19 = 1;
pub const PL_UNIX_USER_PRESPACE: C2RustUnnamed_19 = 0;
pub type C2RustUnnamed_20 = libc::c_uint;
pub const PL_UNIX_HLINKS_NUMBER: C2RustUnnamed_20 = 1;
pub const PL_UNIX_HLINKS_PRESPACE: C2RustUnnamed_20 = 0;
pub type C2RustUnnamed_21 = libc::c_uint;
pub const PL_UNIX_TOTALSIZE_READING: C2RustUnnamed_21 = 1;
pub const PL_UNIX_TOTALSIZE_INIT: C2RustUnnamed_21 = 0;
pub type pl_unix_mainstate = libc::c_uint;
pub const PL_UNIX_SYMLINK: pl_unix_mainstate = 9;
pub const PL_UNIX_FILENAME: pl_unix_mainstate = 8;
pub const PL_UNIX_TIME: pl_unix_mainstate = 7;
pub const PL_UNIX_SIZE: pl_unix_mainstate = 6;
pub const PL_UNIX_GROUP: pl_unix_mainstate = 5;
pub const PL_UNIX_USER: pl_unix_mainstate = 4;
pub const PL_UNIX_HLINKS: pl_unix_mainstate = 3;
pub const PL_UNIX_PERMISSION: pl_unix_mainstate = 2;
pub const PL_UNIX_FILETYPE: pl_unix_mainstate = 1;
pub const PL_UNIX_TOTALSIZE: pl_unix_mainstate = 0;
pub type C2RustUnnamed_22 = libc::c_uint;
pub const OS_TYPE_WIN_NT: C2RustUnnamed_22 = 2;
pub const OS_TYPE_UNIX: C2RustUnnamed_22 = 1;
pub const OS_TYPE_UNKNOWN: C2RustUnnamed_22 = 0;

// http_proxy.rs

// CHUNKcode
pub type CHUNKcode = libc::c_int;
pub const CHUNKE_LAST: CHUNKcode = 7;
pub const CHUNKE_PASSTHRU_ERROR: CHUNKcode = 6;
pub const CHUNKE_OUT_OF_MEMORY: CHUNKcode = 5;
pub const CHUNKE_BAD_ENCODING: CHUNKcode = 4;
pub const CHUNKE_BAD_CHUNK: CHUNKcode = 3;
pub const CHUNKE_ILLEGAL_HEX: CHUNKcode = 2;
pub const CHUNKE_TOO_LONG_HEX: CHUNKcode = 1;
pub const CHUNKE_OK: CHUNKcode = 0;
pub const CHUNKE_STOP: CHUNKcode = -1;

// http.rs

// curl_lock_data
pub type curl_lock_data = libc::c_uint;
pub const CURL_LOCK_DATA_LAST: curl_lock_data = 7;
pub const CURL_LOCK_DATA_PSL: curl_lock_data = 6;
pub const CURL_LOCK_DATA_CONNECT: curl_lock_data = 5;
pub const CURL_LOCK_DATA_SSL_SESSION: curl_lock_data = 4;
pub const CURL_LOCK_DATA_DNS: curl_lock_data = 3;
pub const CURL_LOCK_DATA_COOKIE: curl_lock_data = 2;
pub const CURL_LOCK_DATA_SHARE: curl_lock_data = 1;
pub const CURL_LOCK_DATA_NONE: curl_lock_data = 0;

// curl_lock_access
pub type curl_lock_access = libc::c_uint;
pub const CURL_LOCK_ACCESS_LAST: curl_lock_access = 3;
pub const CURL_LOCK_ACCESS_SINGLE: curl_lock_access = 2;
pub const CURL_LOCK_ACCESS_SHARED: curl_lock_access = 1;
pub const CURL_LOCK_ACCESS_NONE: curl_lock_access = 0;

// http_C2RustUnnamed_7
pub type http_C2RustUnnamed_7 = libc::c_uint;
pub const CURL_HTTP_VERSION_LAST: http_C2RustUnnamed_7 = 31;
pub const CURL_HTTP_VERSION_3: http_C2RustUnnamed_7 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: http_C2RustUnnamed_7 = 5;
pub const CURL_HTTP_VERSION_2TLS: http_C2RustUnnamed_7 = 4;
pub const CURL_HTTP_VERSION_2_0: http_C2RustUnnamed_7 = 3;
pub const CURL_HTTP_VERSION_1_1: http_C2RustUnnamed_7 = 2;
pub const CURL_HTTP_VERSION_1_0: http_C2RustUnnamed_7 = 1;
pub const CURL_HTTP_VERSION_NONE: http_C2RustUnnamed_7 = 0;

// CURLSHcode
pub type CURLSHcode = libc::c_uint;
pub const CURLSHE_LAST: CURLSHcode = 6;
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;
pub const CURLSHE_NOMEM: CURLSHcode = 4;
pub const CURLSHE_INVALID: CURLSHcode = 3;
pub const CURLSHE_IN_USE: CURLSHcode = 2;
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;
pub const CURLSHE_OK: CURLSHcode = 0;

// CURLUcode
pub type CURLUcode = libc::c_uint;
pub const CURLUE_NO_FRAGMENT: CURLUcode = 17;
pub const CURLUE_NO_QUERY: CURLUcode = 16;
pub const CURLUE_NO_PORT: CURLUcode = 15;
pub const CURLUE_NO_HOST: CURLUcode = 14;
pub const CURLUE_NO_OPTIONS: CURLUcode = 13;
pub const CURLUE_NO_PASSWORD: CURLUcode = 12;
pub const CURLUE_NO_USER: CURLUcode = 11;
pub const CURLUE_NO_SCHEME: CURLUcode = 10;
pub const CURLUE_UNKNOWN_PART: CURLUcode = 9;
pub const CURLUE_USER_NOT_ALLOWED: CURLUcode = 8;
pub const CURLUE_OUT_OF_MEMORY: CURLUcode = 7;
pub const CURLUE_URLDECODE: CURLUcode = 6;
pub const CURLUE_UNSUPPORTED_SCHEME: CURLUcode = 5;
pub const CURLUE_BAD_PORT_NUMBER: CURLUcode = 4;
pub const CURLUE_MALFORMED_INPUT: CURLUcode = 3;
pub const CURLUE_BAD_PARTPOINTER: CURLUcode = 2;
pub const CURLUE_BAD_HANDLE: CURLUcode = 1;
pub const CURLUE_OK: CURLUcode = 0;

// CURLUPart
pub type CURLUPart = libc::c_uint;
pub const CURLUPART_ZONEID: CURLUPart = 10;
pub const CURLUPART_FRAGMENT: CURLUPart = 9;
pub const CURLUPART_QUERY: CURLUPart = 8;
pub const CURLUPART_PATH: CURLUPart = 7;
pub const CURLUPART_PORT: CURLUPart = 6;
pub const CURLUPART_HOST: CURLUPart = 5;
pub const CURLUPART_OPTIONS: CURLUPart = 4;
pub const CURLUPART_PASSWORD: CURLUPart = 3;
pub const CURLUPART_USER: CURLUPart = 2;
pub const CURLUPART_SCHEME: CURLUPart = 1;
pub const CURLUPART_URL: CURLUPart = 0;

// mimestrategy
pub type mimestrategy = libc::c_uint;
pub const MIMESTRATEGY_LAST: mimestrategy = 2;
pub const MIMESTRATEGY_FORM: mimestrategy = 1;
pub const MIMESTRATEGY_MAIL: mimestrategy = 0;

// proxy_use
pub const HEADER_CONNECT: proxy_use = 2;
pub const HEADER_PROXY: proxy_use = 1;
pub const HEADER_SERVER: proxy_use = 0;
pub type proxy_use = libc::c_uint;

// alpnid
pub type alpnid = libc::c_uint;
pub const ALPN_h3: alpnid = 32;
pub const ALPN_h2: alpnid = 16;
pub const ALPN_h1: alpnid = 8;
pub const ALPN_none: alpnid = 0;

// statusline
pub const STATUS_DONE: statusline = 1;
pub type statusline = libc::c_uint;
pub const STATUS_BAD: statusline = 2;
pub const STATUS_UNKNOWN: statusline = 0;

// http2.rs
pub type CURLMcode = libc::c_int;
pub const CURLM_LAST: CURLMcode = 11;
pub const CURLM_BAD_FUNCTION_ARGUMENT: CURLMcode = 10;
pub const CURLM_WAKEUP_FAILURE: CURLMcode = 9;
pub const CURLM_RECURSIVE_API_CALL: CURLMcode = 8;
pub const CURLM_ADDED_ALREADY: CURLMcode = 7;
pub const CURLM_UNKNOWN_OPTION: CURLMcode = 6;
pub const CURLM_BAD_SOCKET: CURLMcode = 5;
pub const CURLM_INTERNAL_ERROR: CURLMcode = 4;
pub const CURLM_OUT_OF_MEMORY: CURLMcode = 3;
pub const CURLM_BAD_EASY_HANDLE: CURLMcode = 2;
pub const CURLM_BAD_HANDLE: CURLMcode = 1;
pub const CURLM_OK: CURLMcode = 0;
pub const CURLM_CALL_MULTI_PERFORM: CURLMcode = -1;

pub type http2_C2RustUnnamed_6 = libc::c_int;
pub const NGHTTP2_ERR_FLOODED: http2_C2RustUnnamed_6 = -904;
pub const NGHTTP2_ERR_BAD_CLIENT_MAGIC: http2_C2RustUnnamed_6 = -903;
pub const NGHTTP2_ERR_CALLBACK_FAILURE: http2_C2RustUnnamed_6 = -902;
pub const NGHTTP2_ERR_NOMEM: http2_C2RustUnnamed_6 = -901;
pub const NGHTTP2_ERR_FATAL: http2_C2RustUnnamed_6 = -900;
pub const NGHTTP2_ERR_TOO_MANY_SETTINGS: http2_C2RustUnnamed_6 = -537;
pub const NGHTTP2_ERR_SETTINGS_EXPECTED: http2_C2RustUnnamed_6 = -536;
pub const NGHTTP2_ERR_CANCEL: http2_C2RustUnnamed_6 = -535;
pub const NGHTTP2_ERR_INTERNAL: http2_C2RustUnnamed_6 = -534;
pub const NGHTTP2_ERR_REFUSED_STREAM: http2_C2RustUnnamed_6 = -533;
pub const NGHTTP2_ERR_HTTP_MESSAGING: http2_C2RustUnnamed_6 = -532;
pub const NGHTTP2_ERR_HTTP_HEADER: http2_C2RustUnnamed_6 = -531;
pub const NGHTTP2_ERR_SESSION_CLOSING: http2_C2RustUnnamed_6 = -530;
pub const NGHTTP2_ERR_DATA_EXIST: http2_C2RustUnnamed_6 = -529;
pub const NGHTTP2_ERR_PUSH_DISABLED: http2_C2RustUnnamed_6 = -528;
pub const NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS: http2_C2RustUnnamed_6 = -527;
pub const NGHTTP2_ERR_PAUSE: http2_C2RustUnnamed_6 = -526;
pub const NGHTTP2_ERR_INSUFF_BUFSIZE: http2_C2RustUnnamed_6 = -525;
pub const NGHTTP2_ERR_FLOW_CONTROL: http2_C2RustUnnamed_6 = -524;
pub const NGHTTP2_ERR_HEADER_COMP: http2_C2RustUnnamed_6 = -523;
pub const NGHTTP2_ERR_FRAME_SIZE_ERROR: http2_C2RustUnnamed_6 = -522;
pub const NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE: http2_C2RustUnnamed_6 = -521;
pub const NGHTTP2_ERR_INVALID_STATE: http2_C2RustUnnamed_6 = -519;
pub const NGHTTP2_ERR_INVALID_HEADER_BLOCK: http2_C2RustUnnamed_6 = -518;
pub const NGHTTP2_ERR_GOAWAY_ALREADY_SENT: http2_C2RustUnnamed_6 = -517;
pub const NGHTTP2_ERR_START_STREAM_NOT_ALLOWED: http2_C2RustUnnamed_6 = -516;
pub const NGHTTP2_ERR_DEFERRED_DATA_EXIST: http2_C2RustUnnamed_6 = -515;
pub const NGHTTP2_ERR_INVALID_STREAM_STATE: http2_C2RustUnnamed_6 = -514;
pub const NGHTTP2_ERR_INVALID_STREAM_ID: http2_C2RustUnnamed_6 = -513;
pub const NGHTTP2_ERR_STREAM_SHUT_WR: http2_C2RustUnnamed_6 = -512;
pub const NGHTTP2_ERR_STREAM_CLOSING: http2_C2RustUnnamed_6 = -511;
pub const NGHTTP2_ERR_STREAM_CLOSED: http2_C2RustUnnamed_6 = -510;
pub const NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE: http2_C2RustUnnamed_6 = -509;
pub const NGHTTP2_ERR_DEFERRED: http2_C2RustUnnamed_6 = -508;
pub const NGHTTP2_ERR_EOF: http2_C2RustUnnamed_6 = -507;
pub const NGHTTP2_ERR_INVALID_FRAME: http2_C2RustUnnamed_6 = -506;
pub const NGHTTP2_ERR_PROTO: http2_C2RustUnnamed_6 = -505;
pub const NGHTTP2_ERR_WOULDBLOCK: http2_C2RustUnnamed_6 = -504;
pub const NGHTTP2_ERR_UNSUPPORTED_VERSION: http2_C2RustUnnamed_6 = -503;
pub const NGHTTP2_ERR_BUFFER_ERROR: http2_C2RustUnnamed_6 = -502;
pub const NGHTTP2_ERR_INVALID_ARGUMENT: http2_C2RustUnnamed_6 = -501;

pub type http2_C2RustUnnamed_7 = libc::c_uint;
pub const NGHTTP2_NV_FLAG_NO_COPY_VALUE: http2_C2RustUnnamed_7 = 4;
pub const NGHTTP2_NV_FLAG_NO_COPY_NAME: http2_C2RustUnnamed_7 = 2;
pub const NGHTTP2_NV_FLAG_NO_INDEX: http2_C2RustUnnamed_7 = 1;
pub const NGHTTP2_NV_FLAG_NONE: http2_C2RustUnnamed_7 = 0;

pub type http2_C2RustUnnamed_8 = libc::c_uint;
pub const NGHTTP2_PRIORITY_UPDATE: http2_C2RustUnnamed_8 = 16;
pub const NGHTTP2_ORIGIN: http2_C2RustUnnamed_8 = 12;
pub const NGHTTP2_ALTSVC: http2_C2RustUnnamed_8 = 10;
pub const NGHTTP2_CONTINUATION: http2_C2RustUnnamed_8 = 9;
pub const NGHTTP2_WINDOW_UPDATE: http2_C2RustUnnamed_8 = 8;
pub const NGHTTP2_GOAWAY: http2_C2RustUnnamed_8 = 7;
pub const NGHTTP2_PING: http2_C2RustUnnamed_8 = 6;
pub const NGHTTP2_PUSH_PROMISE: http2_C2RustUnnamed_8 = 5;
pub const NGHTTP2_SETTINGS: http2_C2RustUnnamed_8 = 4;
pub const NGHTTP2_RST_STREAM: http2_C2RustUnnamed_8 = 3;
pub const NGHTTP2_PRIORITY: http2_C2RustUnnamed_8 = 2;
pub const NGHTTP2_HEADERS: http2_C2RustUnnamed_8 = 1;
pub const NGHTTP2_DATA: http2_C2RustUnnamed_8 = 0;

pub type http2_C2RustUnnamed_9 = libc::c_uint;
pub const NGHTTP2_FLAG_PRIORITY: http2_C2RustUnnamed_9 = 32;
pub const NGHTTP2_FLAG_PADDED: http2_C2RustUnnamed_9 = 8;
pub const NGHTTP2_FLAG_ACK: http2_C2RustUnnamed_9 = 1;
pub const NGHTTP2_FLAG_END_HEADERS: http2_C2RustUnnamed_9 = 4;
pub const NGHTTP2_FLAG_END_STREAM: http2_C2RustUnnamed_9 = 1;
pub const NGHTTP2_FLAG_NONE: http2_C2RustUnnamed_9 = 0;

pub type nghttp2_settings_id = libc::c_uint;
pub const NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES: nghttp2_settings_id = 9;
pub const NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL: nghttp2_settings_id = 8;
pub const NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE: nghttp2_settings_id = 6;
pub const NGHTTP2_SETTINGS_MAX_FRAME_SIZE: nghttp2_settings_id = 5;
pub const NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE: nghttp2_settings_id = 4;
pub const NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS: nghttp2_settings_id = 3;
pub const NGHTTP2_SETTINGS_ENABLE_PUSH: nghttp2_settings_id = 2;
pub const NGHTTP2_SETTINGS_HEADER_TABLE_SIZE: nghttp2_settings_id = 1;

pub type http2_C2RustUnnamed_10 = libc::c_uint;
pub const NGHTTP2_HTTP_1_1_REQUIRED: http2_C2RustUnnamed_10 = 13;
pub const NGHTTP2_INADEQUATE_SECURITY: http2_C2RustUnnamed_10 = 12;
pub const NGHTTP2_ENHANCE_YOUR_CALM: http2_C2RustUnnamed_10 = 11;
pub const NGHTTP2_CONNECT_ERROR: http2_C2RustUnnamed_10 = 10;
pub const NGHTTP2_COMPRESSION_ERROR: http2_C2RustUnnamed_10 = 9;
pub const NGHTTP2_CANCEL: http2_C2RustUnnamed_10 = 8;
pub const NGHTTP2_REFUSED_STREAM: http2_C2RustUnnamed_10 = 7;
pub const NGHTTP2_FRAME_SIZE_ERROR: http2_C2RustUnnamed_10 = 6;
pub const NGHTTP2_STREAM_CLOSED: http2_C2RustUnnamed_10 = 5;
pub const NGHTTP2_SETTINGS_TIMEOUT: http2_C2RustUnnamed_10 = 4;
pub const NGHTTP2_FLOW_CONTROL_ERROR: http2_C2RustUnnamed_10 = 3;
pub const NGHTTP2_INTERNAL_ERROR: http2_C2RustUnnamed_10 = 2;
pub const NGHTTP2_PROTOCOL_ERROR: http2_C2RustUnnamed_10 = 1;
pub const NGHTTP2_NO_ERROR: http2_C2RustUnnamed_10 = 0;

pub type http2_C2RustUnnamed_11 = libc::c_uint;
pub const NGHTTP2_DATA_FLAG_NO_COPY: http2_C2RustUnnamed_11 = 4;
pub const NGHTTP2_DATA_FLAG_NO_END_STREAM: http2_C2RustUnnamed_11 = 2;
pub const NGHTTP2_DATA_FLAG_EOF: http2_C2RustUnnamed_11 = 1;
pub const NGHTTP2_DATA_FLAG_NONE: http2_C2RustUnnamed_11 = 0;

pub type nghttp2_headers_category = libc::c_uint;
pub const NGHTTP2_HCAT_HEADERS: nghttp2_headers_category = 3;
pub const NGHTTP2_HCAT_PUSH_RESPONSE: nghttp2_headers_category = 2;
pub const NGHTTP2_HCAT_RESPONSE: nghttp2_headers_category = 1;
pub const NGHTTP2_HCAT_REQUEST: nghttp2_headers_category = 0;

pub const HEADERINST_TE_TRAILERS: header_instruction = 2;
pub const HEADERINST_IGNORE: header_instruction = 1;
pub type header_instruction = libc::c_uint;
pub const HEADERINST_FORWARD: header_instruction = 0;

// mbedtls ftp 
pub type __pid_t = libc::c_int;
pub type pid_t = __pid_t;

pub type curl_hstswrite_callback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        *mut curl_hstsentry,
        *mut curl_index,
        *mut libc::c_void,
    ) -> CURLSTScode,
>;
pub type CURLSTScode = libc::c_uint;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        *mut curl_hstsentry,
        *mut libc::c_void,
    ) -> CURLSTScode,
>;


pub type curlntlm = libc::c_uint;
pub const NTLMSTATE_LAST: curlntlm = 4;
pub const NTLMSTATE_TYPE3: curlntlm = 3;
pub const NTLMSTATE_TYPE2: curlntlm = 2;
pub const NTLMSTATE_TYPE1: curlntlm = 1;
pub const NTLMSTATE_NONE: curlntlm = 0;

// new http.rs
pub type CURLINFO = libc::c_uint;
pub const CURLINFO_LASTONE: CURLINFO = 60;
pub const CURLINFO_REFERER: CURLINFO = 1048636;
pub const CURLINFO_PROXY_ERROR: CURLINFO = 2097211;
pub const CURLINFO_EFFECTIVE_METHOD: CURLINFO = 1048634;
pub const CURLINFO_RETRY_AFTER: CURLINFO = 6291513;
pub const CURLINFO_APPCONNECT_TIME_T: CURLINFO = 6291512;
pub const CURLINFO_REDIRECT_TIME_T: CURLINFO = 6291511;
pub const CURLINFO_STARTTRANSFER_TIME_T: CURLINFO = 6291510;
pub const CURLINFO_PRETRANSFER_TIME_T: CURLINFO = 6291509;
pub const CURLINFO_CONNECT_TIME_T: CURLINFO = 6291508;
pub const CURLINFO_NAMELOOKUP_TIME_T: CURLINFO = 6291507;
pub const CURLINFO_TOTAL_TIME_T: CURLINFO = 6291506;
pub const CURLINFO_SCHEME: CURLINFO = 1048625;
pub const CURLINFO_PROTOCOL: CURLINFO = 2097200;
pub const CURLINFO_PROXY_SSL_VERIFYRESULT: CURLINFO = 2097199;
pub const CURLINFO_HTTP_VERSION: CURLINFO = 2097198;
pub const CURLINFO_TLS_SSL_PTR: CURLINFO = 4194349;
pub const CURLINFO_ACTIVESOCKET: CURLINFO = 5242924;
pub const CURLINFO_TLS_SESSION: CURLINFO = 4194347;
pub const CURLINFO_LOCAL_PORT: CURLINFO = 2097194;
pub const CURLINFO_LOCAL_IP: CURLINFO = 1048617;
pub const CURLINFO_PRIMARY_PORT: CURLINFO = 2097192;
pub const CURLINFO_RTSP_CSEQ_RECV: CURLINFO = 2097191;
pub const CURLINFO_RTSP_SERVER_CSEQ: CURLINFO = 2097190;
pub const CURLINFO_RTSP_CLIENT_CSEQ: CURLINFO = 2097189;
pub const CURLINFO_RTSP_SESSION_ID: CURLINFO = 1048612;
pub const CURLINFO_CONDITION_UNMET: CURLINFO = 2097187;
pub const CURLINFO_CERTINFO: CURLINFO = 4194338;
pub const CURLINFO_APPCONNECT_TIME: CURLINFO = 3145761;
pub const CURLINFO_PRIMARY_IP: CURLINFO = 1048608;
pub const CURLINFO_REDIRECT_URL: CURLINFO = 1048607;
pub const CURLINFO_FTP_ENTRY_PATH: CURLINFO = 1048606;
pub const CURLINFO_LASTSOCKET: CURLINFO = 2097181;
pub const CURLINFO_COOKIELIST: CURLINFO = 4194332;
pub const CURLINFO_SSL_ENGINES: CURLINFO = 4194331;
pub const CURLINFO_NUM_CONNECTS: CURLINFO = 2097178;
pub const CURLINFO_OS_ERRNO: CURLINFO = 2097177;
pub const CURLINFO_PROXYAUTH_AVAIL: CURLINFO = 2097176;
pub const CURLINFO_HTTPAUTH_AVAIL: CURLINFO = 2097175;
pub const CURLINFO_HTTP_CONNECTCODE: CURLINFO = 2097174;
pub const CURLINFO_PRIVATE: CURLINFO = 1048597;
pub const CURLINFO_REDIRECT_COUNT: CURLINFO = 2097172;
pub const CURLINFO_REDIRECT_TIME: CURLINFO = 3145747;
pub const CURLINFO_CONTENT_TYPE: CURLINFO = 1048594;
pub const CURLINFO_STARTTRANSFER_TIME: CURLINFO = 3145745;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD_T: CURLINFO = 6291472;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD: CURLINFO = 3145744;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD_T: CURLINFO = 6291471;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD: CURLINFO = 3145743;
pub const CURLINFO_FILETIME_T: CURLINFO = 6291470;
pub const CURLINFO_FILETIME: CURLINFO = 2097166;
pub const CURLINFO_SSL_VERIFYRESULT: CURLINFO = 2097165;
pub const CURLINFO_REQUEST_SIZE: CURLINFO = 2097164;
pub const CURLINFO_HEADER_SIZE: CURLINFO = 2097163;
pub const CURLINFO_SPEED_UPLOAD_T: CURLINFO = 6291466;
pub const CURLINFO_SPEED_UPLOAD: CURLINFO = 3145738;
pub const CURLINFO_SPEED_DOWNLOAD_T: CURLINFO = 6291465;
pub const CURLINFO_SPEED_DOWNLOAD: CURLINFO = 3145737;
pub const CURLINFO_SIZE_DOWNLOAD_T: CURLINFO = 6291464;
pub const CURLINFO_SIZE_DOWNLOAD: CURLINFO = 3145736;
pub const CURLINFO_SIZE_UPLOAD_T: CURLINFO = 6291463;
pub const CURLINFO_SIZE_UPLOAD: CURLINFO = 3145735;
pub const CURLINFO_PRETRANSFER_TIME: CURLINFO = 3145734;
pub const CURLINFO_CONNECT_TIME: CURLINFO = 3145733;
pub const CURLINFO_NAMELOOKUP_TIME: CURLINFO = 3145732;
pub const CURLINFO_TOTAL_TIME: CURLINFO = 3145731;
pub const CURLINFO_RESPONSE_CODE: CURLINFO = 2097154;
pub const CURLINFO_EFFECTIVE_URL: CURLINFO = 1048577;
pub const CURLINFO_NONE: CURLINFO = 0;

// http2

// mbedtls vtls.rs
pub type vtls_C2RustUnnamed_6 = libc::c_uint;
pub const CURL_SSLVERSION_LAST: vtls_C2RustUnnamed_6 = 8;
pub const CURL_SSLVERSION_TLSv1_3: vtls_C2RustUnnamed_6 = 7;
pub const CURL_SSLVERSION_TLSv1_2: vtls_C2RustUnnamed_6 = 6;
pub const CURL_SSLVERSION_TLSv1_1: vtls_C2RustUnnamed_6 = 5;
pub const CURL_SSLVERSION_TLSv1_0: vtls_C2RustUnnamed_6 = 4;
pub const CURL_SSLVERSION_SSLv3: vtls_C2RustUnnamed_6 = 3;
pub const CURL_SSLVERSION_SSLv2: vtls_C2RustUnnamed_6 = 2;
pub const CURL_SSLVERSION_TLSv1: vtls_C2RustUnnamed_6 = 1;
pub const CURL_SSLVERSION_DEFAULT: vtls_C2RustUnnamed_6 = 0;
pub type vtls_C2RustUnnamed_7 = libc::c_uint;
pub const CURL_SSLVERSION_MAX_LAST: vtls_C2RustUnnamed_7 = 524288;
pub const CURL_SSLVERSION_MAX_TLSv1_3: vtls_C2RustUnnamed_7 = 458752;
pub const CURL_SSLVERSION_MAX_TLSv1_2: vtls_C2RustUnnamed_7 = 393216;
pub const CURL_SSLVERSION_MAX_TLSv1_1: vtls_C2RustUnnamed_7 = 327680;
pub const CURL_SSLVERSION_MAX_TLSv1_0: vtls_C2RustUnnamed_7 = 262144;
pub const CURL_SSLVERSION_MAX_DEFAULT: vtls_C2RustUnnamed_7 = 65536;
pub const CURL_SSLVERSION_MAX_NONE: vtls_C2RustUnnamed_7 = 0;
// mbedtls_threadlock.rs
pub type __uint64_t = libc::c_ulong;
pub type __pthread_list_t = __pthread_internal_list;

// mbedtls.rs
pub type mbedtls_mpi_uint = uint64_t;
pub type uint64_t = __uint64_t;
pub type mbedtls_ecp_group_id = libc::c_uint;
pub const MBEDTLS_ECP_DP_CURVE448: mbedtls_ecp_group_id = 13;
pub const MBEDTLS_ECP_DP_SECP256K1: mbedtls_ecp_group_id = 12;
pub const MBEDTLS_ECP_DP_SECP224K1: mbedtls_ecp_group_id = 11;
pub const MBEDTLS_ECP_DP_SECP192K1: mbedtls_ecp_group_id = 10;
pub const MBEDTLS_ECP_DP_CURVE25519: mbedtls_ecp_group_id = 9;
pub const MBEDTLS_ECP_DP_BP512R1: mbedtls_ecp_group_id = 8;
pub const MBEDTLS_ECP_DP_BP384R1: mbedtls_ecp_group_id = 7;
pub const MBEDTLS_ECP_DP_BP256R1: mbedtls_ecp_group_id = 6;
pub const MBEDTLS_ECP_DP_SECP521R1: mbedtls_ecp_group_id = 5;
pub const MBEDTLS_ECP_DP_SECP384R1: mbedtls_ecp_group_id = 4;
pub const MBEDTLS_ECP_DP_SECP256R1: mbedtls_ecp_group_id = 3;
pub const MBEDTLS_ECP_DP_SECP224R1: mbedtls_ecp_group_id = 2;
pub const MBEDTLS_ECP_DP_SECP192R1: mbedtls_ecp_group_id = 1;
pub const MBEDTLS_ECP_DP_NONE: mbedtls_ecp_group_id = 0;
pub type mbedtls_pk_type_t = libc::c_uint;
pub const MBEDTLS_PK_RSASSA_PSS: mbedtls_pk_type_t = 6;
pub const MBEDTLS_PK_RSA_ALT: mbedtls_pk_type_t = 5;
pub const MBEDTLS_PK_ECDSA: mbedtls_pk_type_t = 4;
pub const MBEDTLS_PK_ECKEY_DH: mbedtls_pk_type_t = 3;
pub const MBEDTLS_PK_ECKEY: mbedtls_pk_type_t = 2;
pub const MBEDTLS_PK_RSA: mbedtls_pk_type_t = 1;
pub const MBEDTLS_PK_NONE: mbedtls_pk_type_t = 0;
pub type mbedtls_md_type_t = libc::c_uint;
pub const MBEDTLS_MD_RIPEMD160: mbedtls_md_type_t = 9;
pub const MBEDTLS_MD_SHA512: mbedtls_md_type_t = 8;
pub const MBEDTLS_MD_SHA384: mbedtls_md_type_t = 7;
pub const MBEDTLS_MD_SHA256: mbedtls_md_type_t = 6;
pub const MBEDTLS_MD_SHA224: mbedtls_md_type_t = 5;
pub const MBEDTLS_MD_SHA1: mbedtls_md_type_t = 4;
pub const MBEDTLS_MD_MD5: mbedtls_md_type_t = 3;
pub const MBEDTLS_MD_MD4: mbedtls_md_type_t = 2;
pub const MBEDTLS_MD_MD2: mbedtls_md_type_t = 1;
pub const MBEDTLS_MD_NONE: mbedtls_md_type_t = 0;
pub type mbedtls_x509_buf = mbedtls_asn1_buf;
pub type mbedtls_x509_name = mbedtls_asn1_named_data;
pub type mbedtls_x509_sequence = mbedtls_asn1_sequence;
pub type mbedtls_time_t = time_t;
pub type mbedtls_ssl_get_timer_t = unsafe extern "C" fn(
    *mut libc::c_void,
) -> libc::c_int;
pub type mbedtls_ssl_set_timer_t = unsafe extern "C" fn(
    *mut libc::c_void,
    uint32_t,
    uint32_t,
) -> ();
pub type mbedtls_ssl_recv_timeout_t = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_uchar,
    size_t,
    uint32_t,
) -> libc::c_int;
pub type mbedtls_ssl_recv_t = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_uchar,
    size_t,
) -> libc::c_int;
pub type mbedtls_ssl_send_t = unsafe extern "C" fn(
    *mut libc::c_void,
    *const libc::c_uchar,
    size_t,
) -> libc::c_int;
pub type mbedtls_entropy_f_source_ptr = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_uchar,
        size_t,
        *mut size_t,
    ) -> libc::c_int,
>;


// gnutls gtls.rs
pub type gtls_C2RustUnnamed = libc::c_uint;
pub const MSG_CMSG_CLOEXEC: gtls_C2RustUnnamed = 1073741824;
pub const MSG_FASTOPEN: gtls_C2RustUnnamed = 536870912;
pub const MSG_ZEROCOPY: gtls_C2RustUnnamed = 67108864;
pub const MSG_BATCH: gtls_C2RustUnnamed = 262144;
pub const MSG_WAITFORONE: gtls_C2RustUnnamed = 65536;
pub const MSG_MORE: gtls_C2RustUnnamed = 32768;
pub const MSG_NOSIGNAL: gtls_C2RustUnnamed = 16384;
pub const MSG_ERRQUEUE: gtls_C2RustUnnamed = 8192;
pub const MSG_RST: gtls_C2RustUnnamed = 4096;
pub const MSG_CONFIRM: gtls_C2RustUnnamed = 2048;
pub const MSG_SYN: gtls_C2RustUnnamed = 1024;
pub const MSG_FIN: gtls_C2RustUnnamed = 512;
pub const MSG_WAITALL: gtls_C2RustUnnamed = 256;
pub const MSG_EOR: gtls_C2RustUnnamed = 128;
pub const MSG_DONTWAIT: gtls_C2RustUnnamed = 64;
pub const MSG_TRUNC: gtls_C2RustUnnamed = 32;
pub const MSG_PROXY: gtls_C2RustUnnamed = 16;
pub const MSG_CTRUNC: gtls_C2RustUnnamed = 8;
pub const MSG_DONTROUTE: gtls_C2RustUnnamed = 4;
pub const MSG_PEEK: gtls_C2RustUnnamed = 2;
pub const MSG_OOB: gtls_C2RustUnnamed = 1;

pub type CURL_TLSAUTH = libc::c_uint;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;

pub type gnutls_srp_client_credentials_t = *mut gnutls_srp_client_credentials_st;
pub type gnutls_certificate_credentials_t = *mut gnutls_certificate_credentials_st;
pub type gnutls_session_t = *mut gnutls_session_int;

pub type gnutls_cipher_algorithm = libc::c_uint;
pub const GNUTLS_CIPHER_TWOFISH_PGP_CFB: gnutls_cipher_algorithm = 208;
pub const GNUTLS_CIPHER_AES256_PGP_CFB: gnutls_cipher_algorithm = 207;
pub const GNUTLS_CIPHER_AES192_PGP_CFB: gnutls_cipher_algorithm = 206;
pub const GNUTLS_CIPHER_AES128_PGP_CFB: gnutls_cipher_algorithm = 205;
pub const GNUTLS_CIPHER_SAFER_SK128_PGP_CFB: gnutls_cipher_algorithm = 204;
pub const GNUTLS_CIPHER_BLOWFISH_PGP_CFB: gnutls_cipher_algorithm = 203;
pub const GNUTLS_CIPHER_CAST5_PGP_CFB: gnutls_cipher_algorithm = 202;
pub const GNUTLS_CIPHER_3DES_PGP_CFB: gnutls_cipher_algorithm = 201;
pub const GNUTLS_CIPHER_IDEA_PGP_CFB: gnutls_cipher_algorithm = 200;
pub const GNUTLS_CIPHER_AES_192_GCM: gnutls_cipher_algorithm = 39;
pub const GNUTLS_CIPHER_AES_256_SIV: gnutls_cipher_algorithm = 38;
pub const GNUTLS_CIPHER_AES_128_SIV: gnutls_cipher_algorithm = 37;
pub const GNUTLS_CIPHER_CHACHA20_32: gnutls_cipher_algorithm = 36;
pub const GNUTLS_CIPHER_CHACHA20_64: gnutls_cipher_algorithm = 35;
pub const GNUTLS_CIPHER_GOST28147_TC26Z_CNT: gnutls_cipher_algorithm = 34;
pub const GNUTLS_CIPHER_AES_256_XTS: gnutls_cipher_algorithm = 33;
pub const GNUTLS_CIPHER_AES_128_XTS: gnutls_cipher_algorithm = 32;
pub const GNUTLS_CIPHER_AES_256_CFB8: gnutls_cipher_algorithm = 31;
pub const GNUTLS_CIPHER_AES_192_CFB8: gnutls_cipher_algorithm = 30;
pub const GNUTLS_CIPHER_AES_128_CFB8: gnutls_cipher_algorithm = 29;
pub const GNUTLS_CIPHER_GOST28147_CPD_CFB: gnutls_cipher_algorithm = 28;
pub const GNUTLS_CIPHER_GOST28147_CPC_CFB: gnutls_cipher_algorithm = 27;
pub const GNUTLS_CIPHER_GOST28147_CPB_CFB: gnutls_cipher_algorithm = 26;
pub const GNUTLS_CIPHER_GOST28147_CPA_CFB: gnutls_cipher_algorithm = 25;
pub const GNUTLS_CIPHER_GOST28147_TC26Z_CFB: gnutls_cipher_algorithm = 24;
pub const GNUTLS_CIPHER_CHACHA20_POLY1305: gnutls_cipher_algorithm = 23;
pub const GNUTLS_CIPHER_AES_256_CCM_8: gnutls_cipher_algorithm = 22;
pub const GNUTLS_CIPHER_AES_128_CCM_8: gnutls_cipher_algorithm = 21;
pub const GNUTLS_CIPHER_AES_256_CCM: gnutls_cipher_algorithm = 20;
pub const GNUTLS_CIPHER_AES_128_CCM: gnutls_cipher_algorithm = 19;
pub const GNUTLS_CIPHER_DES_CBC: gnutls_cipher_algorithm = 18;
pub const GNUTLS_CIPHER_RC2_40_CBC: gnutls_cipher_algorithm = 17;
pub const GNUTLS_CIPHER_CAMELLIA_256_GCM: gnutls_cipher_algorithm = 16;
pub const GNUTLS_CIPHER_CAMELLIA_128_GCM: gnutls_cipher_algorithm = 15;
pub const GNUTLS_CIPHER_ESTREAM_SALSA20_256: gnutls_cipher_algorithm = 14;
pub const GNUTLS_CIPHER_SALSA20_256: gnutls_cipher_algorithm = 13;
pub const GNUTLS_CIPHER_CAMELLIA_192_CBC: gnutls_cipher_algorithm = 12;
pub const GNUTLS_CIPHER_AES_256_GCM: gnutls_cipher_algorithm = 11;
pub const GNUTLS_CIPHER_AES_128_GCM: gnutls_cipher_algorithm = 10;
pub const GNUTLS_CIPHER_AES_192_CBC: gnutls_cipher_algorithm = 9;
pub const GNUTLS_CIPHER_CAMELLIA_256_CBC: gnutls_cipher_algorithm = 8;
pub const GNUTLS_CIPHER_CAMELLIA_128_CBC: gnutls_cipher_algorithm = 7;
pub const GNUTLS_CIPHER_ARCFOUR_40: gnutls_cipher_algorithm = 6;
pub const GNUTLS_CIPHER_AES_256_CBC: gnutls_cipher_algorithm = 5;
pub const GNUTLS_CIPHER_AES_128_CBC: gnutls_cipher_algorithm = 4;
pub const GNUTLS_CIPHER_3DES_CBC: gnutls_cipher_algorithm = 3;
pub const GNUTLS_CIPHER_ARCFOUR_128: gnutls_cipher_algorithm = 2;
pub const GNUTLS_CIPHER_NULL: gnutls_cipher_algorithm = 1;
pub const GNUTLS_CIPHER_UNKNOWN: gnutls_cipher_algorithm = 0;
pub type gnutls_cipher_algorithm_t = gnutls_cipher_algorithm;
pub type gnutls_kx_algorithm_t = libc::c_uint;
pub const GNUTLS_KX_VKO_GOST_12: gnutls_kx_algorithm_t = 16;
pub const GNUTLS_KX_RSA_PSK: gnutls_kx_algorithm_t = 15;
pub const GNUTLS_KX_ECDHE_PSK: gnutls_kx_algorithm_t = 14;
pub const GNUTLS_KX_ECDHE_ECDSA: gnutls_kx_algorithm_t = 13;
pub const GNUTLS_KX_ECDHE_RSA: gnutls_kx_algorithm_t = 12;
pub const GNUTLS_KX_ANON_ECDH: gnutls_kx_algorithm_t = 11;
pub const GNUTLS_KX_DHE_PSK: gnutls_kx_algorithm_t = 10;
pub const GNUTLS_KX_PSK: gnutls_kx_algorithm_t = 9;
pub const GNUTLS_KX_SRP_DSS: gnutls_kx_algorithm_t = 8;
pub const GNUTLS_KX_SRP_RSA: gnutls_kx_algorithm_t = 7;
pub const GNUTLS_KX_RSA_EXPORT: gnutls_kx_algorithm_t = 6;
pub const GNUTLS_KX_SRP: gnutls_kx_algorithm_t = 5;
pub const GNUTLS_KX_ANON_DH: gnutls_kx_algorithm_t = 4;
pub const GNUTLS_KX_DHE_RSA: gnutls_kx_algorithm_t = 3;
pub const GNUTLS_KX_DHE_DSS: gnutls_kx_algorithm_t = 2;
pub const GNUTLS_KX_RSA: gnutls_kx_algorithm_t = 1;
pub const GNUTLS_KX_UNKNOWN: gnutls_kx_algorithm_t = 0;
pub type gnutls_credentials_type_t = libc::c_uint;
pub const GNUTLS_CRD_IA: gnutls_credentials_type_t = 5;
pub const GNUTLS_CRD_PSK: gnutls_credentials_type_t = 4;
pub const GNUTLS_CRD_SRP: gnutls_credentials_type_t = 3;
pub const GNUTLS_CRD_ANON: gnutls_credentials_type_t = 2;
pub const GNUTLS_CRD_CERTIFICATE: gnutls_credentials_type_t = 1;
pub type gnutls_mac_algorithm_t = libc::c_uint;
pub const GNUTLS_MAC_SHAKE_256: gnutls_mac_algorithm_t = 210;
pub const GNUTLS_MAC_SHAKE_128: gnutls_mac_algorithm_t = 209;
pub const GNUTLS_MAC_GOST28147_TC26Z_IMIT: gnutls_mac_algorithm_t = 208;
pub const GNUTLS_MAC_AES_GMAC_256: gnutls_mac_algorithm_t = 207;
pub const GNUTLS_MAC_AES_GMAC_192: gnutls_mac_algorithm_t = 206;
pub const GNUTLS_MAC_AES_GMAC_128: gnutls_mac_algorithm_t = 205;
pub const GNUTLS_MAC_AES_CMAC_256: gnutls_mac_algorithm_t = 204;
pub const GNUTLS_MAC_AES_CMAC_128: gnutls_mac_algorithm_t = 203;
pub const GNUTLS_MAC_UMAC_128: gnutls_mac_algorithm_t = 202;
pub const GNUTLS_MAC_UMAC_96: gnutls_mac_algorithm_t = 201;
pub const GNUTLS_MAC_AEAD: gnutls_mac_algorithm_t = 200;
pub const GNUTLS_MAC_STREEBOG_512: gnutls_mac_algorithm_t = 17;
pub const GNUTLS_MAC_STREEBOG_256: gnutls_mac_algorithm_t = 16;
pub const GNUTLS_MAC_GOSTR_94: gnutls_mac_algorithm_t = 15;
pub const GNUTLS_MAC_MD5_SHA1: gnutls_mac_algorithm_t = 14;
pub const GNUTLS_MAC_SHA3_512: gnutls_mac_algorithm_t = 13;
pub const GNUTLS_MAC_SHA3_384: gnutls_mac_algorithm_t = 12;
pub const GNUTLS_MAC_SHA3_256: gnutls_mac_algorithm_t = 11;
pub const GNUTLS_MAC_SHA3_224: gnutls_mac_algorithm_t = 10;
pub const GNUTLS_MAC_SHA224: gnutls_mac_algorithm_t = 9;
pub const GNUTLS_MAC_SHA512: gnutls_mac_algorithm_t = 8;
pub const GNUTLS_MAC_SHA384: gnutls_mac_algorithm_t = 7;
pub const GNUTLS_MAC_SHA256: gnutls_mac_algorithm_t = 6;
pub const GNUTLS_MAC_MD2: gnutls_mac_algorithm_t = 5;
pub const GNUTLS_MAC_RMD160: gnutls_mac_algorithm_t = 4;
pub const GNUTLS_MAC_SHA1: gnutls_mac_algorithm_t = 3;
pub const GNUTLS_MAC_MD5: gnutls_mac_algorithm_t = 2;
pub const GNUTLS_MAC_NULL: gnutls_mac_algorithm_t = 1;
pub const GNUTLS_MAC_UNKNOWN: gnutls_mac_algorithm_t = 0;
pub type gnutls_digest_algorithm_t = libc::c_uint;
pub const GNUTLS_DIG_SHAKE_256: gnutls_digest_algorithm_t = 210;
pub const GNUTLS_DIG_SHAKE_128: gnutls_digest_algorithm_t = 209;
pub const GNUTLS_DIG_STREEBOG_512: gnutls_digest_algorithm_t = 17;
pub const GNUTLS_DIG_STREEBOG_256: gnutls_digest_algorithm_t = 16;
pub const GNUTLS_DIG_GOSTR_94: gnutls_digest_algorithm_t = 15;
pub const GNUTLS_DIG_MD5_SHA1: gnutls_digest_algorithm_t = 14;
pub const GNUTLS_DIG_SHA3_512: gnutls_digest_algorithm_t = 13;
pub const GNUTLS_DIG_SHA3_384: gnutls_digest_algorithm_t = 12;
pub const GNUTLS_DIG_SHA3_256: gnutls_digest_algorithm_t = 11;
pub const GNUTLS_DIG_SHA3_224: gnutls_digest_algorithm_t = 10;
pub const GNUTLS_DIG_SHA224: gnutls_digest_algorithm_t = 9;
pub const GNUTLS_DIG_SHA512: gnutls_digest_algorithm_t = 8;
pub const GNUTLS_DIG_SHA384: gnutls_digest_algorithm_t = 7;
pub const GNUTLS_DIG_SHA256: gnutls_digest_algorithm_t = 6;
pub const GNUTLS_DIG_MD2: gnutls_digest_algorithm_t = 5;
pub const GNUTLS_DIG_RMD160: gnutls_digest_algorithm_t = 4;
pub const GNUTLS_DIG_SHA1: gnutls_digest_algorithm_t = 3;
pub const GNUTLS_DIG_MD5: gnutls_digest_algorithm_t = 2;
pub const GNUTLS_DIG_NULL: gnutls_digest_algorithm_t = 1;
pub const GNUTLS_DIG_UNKNOWN: gnutls_digest_algorithm_t = 0;
pub type gnutls_alert_description_t = libc::c_uint;
pub const GNUTLS_A_MAX: gnutls_alert_description_t = 120;
pub const GNUTLS_A_NO_APPLICATION_PROTOCOL: gnutls_alert_description_t = 120;
pub const GNUTLS_A_CERTIFICATE_REQUIRED: gnutls_alert_description_t = 116;
pub const GNUTLS_A_UNKNOWN_PSK_IDENTITY: gnutls_alert_description_t = 115;
pub const GNUTLS_A_UNRECOGNIZED_NAME: gnutls_alert_description_t = 112;
pub const GNUTLS_A_CERTIFICATE_UNOBTAINABLE: gnutls_alert_description_t = 111;
pub const GNUTLS_A_UNSUPPORTED_EXTENSION: gnutls_alert_description_t = 110;
pub const GNUTLS_A_MISSING_EXTENSION: gnutls_alert_description_t = 109;
pub const GNUTLS_A_NO_RENEGOTIATION: gnutls_alert_description_t = 100;
pub const GNUTLS_A_USER_CANCELED: gnutls_alert_description_t = 90;
pub const GNUTLS_A_INAPPROPRIATE_FALLBACK: gnutls_alert_description_t = 86;
pub const GNUTLS_A_INTERNAL_ERROR: gnutls_alert_description_t = 80;
pub const GNUTLS_A_INSUFFICIENT_SECURITY: gnutls_alert_description_t = 71;
pub const GNUTLS_A_PROTOCOL_VERSION: gnutls_alert_description_t = 70;
pub const GNUTLS_A_EXPORT_RESTRICTION: gnutls_alert_description_t = 60;
pub const GNUTLS_A_DECRYPT_ERROR: gnutls_alert_description_t = 51;
pub const GNUTLS_A_DECODE_ERROR: gnutls_alert_description_t = 50;
pub const GNUTLS_A_ACCESS_DENIED: gnutls_alert_description_t = 49;
pub const GNUTLS_A_UNKNOWN_CA: gnutls_alert_description_t = 48;
pub const GNUTLS_A_ILLEGAL_PARAMETER: gnutls_alert_description_t = 47;
pub const GNUTLS_A_CERTIFICATE_UNKNOWN: gnutls_alert_description_t = 46;
pub const GNUTLS_A_CERTIFICATE_EXPIRED: gnutls_alert_description_t = 45;
pub const GNUTLS_A_CERTIFICATE_REVOKED: gnutls_alert_description_t = 44;
pub const GNUTLS_A_UNSUPPORTED_CERTIFICATE: gnutls_alert_description_t = 43;
pub const GNUTLS_A_BAD_CERTIFICATE: gnutls_alert_description_t = 42;
pub const GNUTLS_A_SSL3_NO_CERTIFICATE: gnutls_alert_description_t = 41;
pub const GNUTLS_A_HANDSHAKE_FAILURE: gnutls_alert_description_t = 40;
pub const GNUTLS_A_DECOMPRESSION_FAILURE: gnutls_alert_description_t = 30;
pub const GNUTLS_A_RECORD_OVERFLOW: gnutls_alert_description_t = 22;
pub const GNUTLS_A_DECRYPTION_FAILED: gnutls_alert_description_t = 21;
pub const GNUTLS_A_BAD_RECORD_MAC: gnutls_alert_description_t = 20;
pub const GNUTLS_A_UNEXPECTED_MESSAGE: gnutls_alert_description_t = 10;
pub const GNUTLS_A_CLOSE_NOTIFY: gnutls_alert_description_t = 0;
pub type gtls_C2RustUnnamed_10 = libc::c_uint;
pub const GNUTLS_CERT_UNKNOWN_CRIT_EXTENSIONS: gtls_C2RustUnnamed_10 = 2097152;
pub const GNUTLS_CERT_INVALID_OCSP_STATUS: gtls_C2RustUnnamed_10 = 1048576;
pub const GNUTLS_CERT_MISSING_OCSP_STATUS: gtls_C2RustUnnamed_10 = 524288;
pub const GNUTLS_CERT_PURPOSE_MISMATCH: gtls_C2RustUnnamed_10 = 262144;
pub const GNUTLS_CERT_MISMATCH: gtls_C2RustUnnamed_10 = 131072;
pub const GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE: gtls_C2RustUnnamed_10 = 65536;
pub const GNUTLS_CERT_REVOCATION_DATA_ISSUED_IN_FUTURE: gtls_C2RustUnnamed_10 = 32768;
pub const GNUTLS_CERT_UNEXPECTED_OWNER: gtls_C2RustUnnamed_10 = 16384;
pub const GNUTLS_CERT_REVOCATION_DATA_SUPERSEDED: gtls_C2RustUnnamed_10 = 4096;
pub const GNUTLS_CERT_SIGNATURE_FAILURE: gtls_C2RustUnnamed_10 = 2048;
pub const GNUTLS_CERT_EXPIRED: gtls_C2RustUnnamed_10 = 1024;
pub const GNUTLS_CERT_NOT_ACTIVATED: gtls_C2RustUnnamed_10 = 512;
pub const GNUTLS_CERT_INSECURE_ALGORITHM: gtls_C2RustUnnamed_10 = 256;
pub const GNUTLS_CERT_SIGNER_NOT_CA: gtls_C2RustUnnamed_10 = 128;
pub const GNUTLS_CERT_SIGNER_NOT_FOUND: gtls_C2RustUnnamed_10 = 64;
pub const GNUTLS_CERT_REVOKED: gtls_C2RustUnnamed_10 = 32;
pub const GNUTLS_CERT_INVALID: gtls_C2RustUnnamed_10 = 2;
pub type gnutls_close_request_t = libc::c_uint;
pub const GNUTLS_SHUT_WR: gnutls_close_request_t = 1;
pub const GNUTLS_SHUT_RDWR: gnutls_close_request_t = 0;
pub type gnutls_protocol_t = libc::c_uint;
pub const GNUTLS_VERSION_UNKNOWN: gnutls_protocol_t = 255;
pub const GNUTLS_TLS_VERSION_MAX: gnutls_protocol_t = 5;
pub const GNUTLS_DTLS_VERSION_MAX: gnutls_protocol_t = 202;
pub const GNUTLS_DTLS_VERSION_MIN: gnutls_protocol_t = 200;
pub const GNUTLS_DTLS1_2: gnutls_protocol_t = 202;
pub const GNUTLS_DTLS1_0: gnutls_protocol_t = 201;
pub const GNUTLS_DTLS0_9: gnutls_protocol_t = 200;
pub const GNUTLS_TLS1_3: gnutls_protocol_t = 5;
pub const GNUTLS_TLS1_2: gnutls_protocol_t = 4;
pub const GNUTLS_TLS1_1: gnutls_protocol_t = 3;
pub const GNUTLS_TLS1: gnutls_protocol_t = 2;
pub const GNUTLS_TLS1_0: gnutls_protocol_t = 2;
pub const GNUTLS_SSL3: gnutls_protocol_t = 1;
pub type gnutls_x509_crt_fmt_t = libc::c_uint;
pub const GNUTLS_X509_FMT_PEM: gnutls_x509_crt_fmt_t = 1;
pub const GNUTLS_X509_FMT_DER: gnutls_x509_crt_fmt_t = 0;
pub type gnutls_pk_algorithm_t = libc::c_uint;
pub const GNUTLS_PK_MAX: gnutls_pk_algorithm_t = 12;
pub const GNUTLS_PK_EDDSA_ED448: gnutls_pk_algorithm_t = 12;
pub const GNUTLS_PK_ECDH_X448: gnutls_pk_algorithm_t = 11;
pub const GNUTLS_PK_GOST_12_512: gnutls_pk_algorithm_t = 10;
pub const GNUTLS_PK_GOST_12_256: gnutls_pk_algorithm_t = 9;
pub const GNUTLS_PK_GOST_01: gnutls_pk_algorithm_t = 8;
pub const GNUTLS_PK_EDDSA_ED25519: gnutls_pk_algorithm_t = 7;
pub const GNUTLS_PK_RSA_PSS: gnutls_pk_algorithm_t = 6;
pub const GNUTLS_PK_ECDH_X25519: gnutls_pk_algorithm_t = 5;
pub const GNUTLS_PK_ECDSA: gnutls_pk_algorithm_t = 4;
pub const GNUTLS_PK_DH: gnutls_pk_algorithm_t = 3;
pub const GNUTLS_PK_DSA: gnutls_pk_algorithm_t = 2;
pub const GNUTLS_PK_RSA: gnutls_pk_algorithm_t = 1;
pub const GNUTLS_PK_UNKNOWN: gnutls_pk_algorithm_t = 0;
pub type gnutls_transport_ptr_t = *mut libc::c_void;
pub type gnutls_server_name_type_t = libc::c_uint;
pub const GNUTLS_NAME_DNS: gnutls_server_name_type_t = 1;
pub type gnutls_pubkey_t = *mut gnutls_pubkey_st;
pub type gnutls_x509_crt_t = *mut gnutls_x509_crt_int;
pub type gnutls_free_function = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type gnutls_pull_func = Option::<
    unsafe extern "C" fn(gnutls_transport_ptr_t, *mut libc::c_void, size_t) -> ssize_t,
>;
pub type gnutls_push_func = Option::<
    unsafe extern "C" fn(gnutls_transport_ptr_t, *const libc::c_void, size_t) -> ssize_t,
>;
pub type gnutls_pkcs_encrypt_flags_t = libc::c_uint;
pub const GNUTLS_PKCS_PBES2_GOST_CPD: gnutls_pkcs_encrypt_flags_t = 32768;
pub const GNUTLS_PKCS_PBES2_GOST_CPC: gnutls_pkcs_encrypt_flags_t = 16384;
pub const GNUTLS_PKCS_PBES2_GOST_CPB: gnutls_pkcs_encrypt_flags_t = 8192;
pub const GNUTLS_PKCS_PBES2_GOST_CPA: gnutls_pkcs_encrypt_flags_t = 4096;
pub const GNUTLS_PKCS_PBES2_GOST_TC26Z: gnutls_pkcs_encrypt_flags_t = 2048;
pub const GNUTLS_PKCS_PBES1_DES_MD5: gnutls_pkcs_encrypt_flags_t = 1024;
pub const GNUTLS_PKCS_PBES2_DES: gnutls_pkcs_encrypt_flags_t = 512;
pub const GNUTLS_PKCS_NULL_PASSWORD: gnutls_pkcs_encrypt_flags_t = 256;
pub const GNUTLS_PKCS_PBES2_AES_256: gnutls_pkcs_encrypt_flags_t = 128;
pub const GNUTLS_PKCS_PBES2_AES_192: gnutls_pkcs_encrypt_flags_t = 64;
pub const GNUTLS_PKCS_PBES2_AES_128: gnutls_pkcs_encrypt_flags_t = 32;
pub const GNUTLS_PKCS_PBES2_3DES: gnutls_pkcs_encrypt_flags_t = 16;
pub const GNUTLS_PKCS_PKCS12_RC2_40: gnutls_pkcs_encrypt_flags_t = 8;
pub const GNUTLS_PKCS_PKCS12_ARCFOUR: gnutls_pkcs_encrypt_flags_t = 4;
pub const GNUTLS_PKCS_PKCS12_3DES: gnutls_pkcs_encrypt_flags_t = 2;
pub const GNUTLS_PKCS_PLAIN: gnutls_pkcs_encrypt_flags_t = 1;
pub type gnutls_rnd_level = libc::c_uint;
pub const GNUTLS_RND_KEY: gnutls_rnd_level = 2;
pub const GNUTLS_RND_RANDOM: gnutls_rnd_level = 1;
pub const GNUTLS_RND_NONCE: gnutls_rnd_level = 0;
pub type gnutls_rnd_level_t = gnutls_rnd_level;

pub type gnutls_ocsp_resp_t = *mut gnutls_ocsp_resp_int;
pub const GNUTLS_OCSP_CERT_UNKNOWN: gnutls_ocsp_cert_status_t = 2;
pub const GNUTLS_X509_CRLREASON_AACOMPROMISE: gnutls_x509_crl_reason_t = 10;
pub const GNUTLS_X509_CRLREASON_PRIVILEGEWITHDRAWN: gnutls_x509_crl_reason_t = 9;
pub const GNUTLS_X509_CRLREASON_REMOVEFROMCRL: gnutls_x509_crl_reason_t = 8;
pub const GNUTLS_X509_CRLREASON_CERTIFICATEHOLD: gnutls_x509_crl_reason_t = 6;
pub const GNUTLS_X509_CRLREASON_CESSATIONOFOPERATION: gnutls_x509_crl_reason_t = 5;
pub const GNUTLS_X509_CRLREASON_SUPERSEDED: gnutls_x509_crl_reason_t = 4;
pub const GNUTLS_X509_CRLREASON_AFFILIATIONCHANGED: gnutls_x509_crl_reason_t = 3;
pub const GNUTLS_X509_CRLREASON_CACOMPROMISE: gnutls_x509_crl_reason_t = 2;
pub const GNUTLS_X509_CRLREASON_KEYCOMPROMISE: gnutls_x509_crl_reason_t = 1;
pub const GNUTLS_X509_CRLREASON_UNSPECIFIED: gnutls_x509_crl_reason_t = 0;
pub type gnutls_x509_crl_reason_t = libc::c_uint;
pub const GNUTLS_OCSP_CERT_REVOKED: gnutls_ocsp_cert_status_t = 1;
pub const GNUTLS_OCSP_CERT_GOOD: gnutls_ocsp_cert_status_t = 0;
pub type gnutls_ocsp_cert_status_t = libc::c_uint;
pub type gnutls_ocsp_resp_const_t = *const gnutls_ocsp_resp_int;

// wolfssl.rs
// pub type SSL = WOLFSSL;
pub type SSL_CTX = WOLFSSL_CTX;
pub type word32 = libc::c_uint;
pub type byte = libc::c_uchar;
pub const WOLFSSL_ERROR_WANT_WRITE: wolf_C2RustUnnamed_8 = 3;
pub const WOLFSSL_ERROR_WANT_READ: wolf_C2RustUnnamed_8 = 2;
pub const WOLFSSL_ERROR_ZERO_RETURN: wolf_C2RustUnnamed_8 = 6;
pub type SSL_SESSION = WOLFSSL_SESSION;
pub type X509 = WOLFSSL_X509;
pub const ASN_NO_SIGNER_E: wolf_C2RustUnnamed_10 = -188;
pub const DOMAIN_NAME_MISMATCH: wolfSSL_ErrorCodes = -322;
pub const WOLFSSL_SUCCESS: wolf_C2RustUnnamed_8 = 1;
pub const WOLFSSL_TLSV1_2: wolf_C2RustUnnamed_9 = 3;
pub const WOLFSSL_TLSV1_1: wolf_C2RustUnnamed_9 = 2;
pub const WOLFSSL_TLSV1: wolf_C2RustUnnamed_9 = 1;
pub const WOLFSSL_SSLV3: wolf_C2RustUnnamed_9 = 0;
pub const WOLFSSL_FAILURE: wolf_C2RustUnnamed_8 = 0;
pub type VerifyCallback = Option::<
    unsafe extern "C" fn(libc::c_int, *mut WOLFSSL_X509_STORE_CTX) -> libc::c_int,
>;
pub const WOLFSSL_VERIFY_NONE: wolf_C2RustUnnamed_8 = 0;
pub const WOLFSSL_VERIFY_PEER: wolf_C2RustUnnamed_8 = 1;
pub const WOLFSSL_FILETYPE_ASN1: wolf_C2RustUnnamed_8 = 2;
pub const WOLFSSL_FILETYPE_PEM: wolf_C2RustUnnamed_8 = 1;
pub type SSL_METHOD = WOLFSSL_METHOD;
pub type wolf_C2RustUnnamed_8 = libc::c_int;
pub const WOLF_PEM_BUFSIZE: wolf_C2RustUnnamed_8 = 1024;
pub const WOLFSSL_R_SSLV3_ALERT_BAD_CERTIFICATE: wolf_C2RustUnnamed_8 = 104;
pub const WOLFSSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN: wolf_C2RustUnnamed_8 = 103;
pub const WOLFSSL_R_TLSV1_ALERT_UNKNOWN_CA: wolf_C2RustUnnamed_8 = 102;
pub const WOLFSSL_R_SSL_HANDSHAKE_FAILURE: wolf_C2RustUnnamed_8 = 101;
pub const WOLFSSL_OP_NO_SSLv2: wolf_C2RustUnnamed_8 = 8;
pub const WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: wolf_C2RustUnnamed_8 = 4;
pub const WOLFSSL_RECEIVED_SHUTDOWN: wolf_C2RustUnnamed_8 = 2;
pub const WOLFSSL_SENT_SHUTDOWN: wolf_C2RustUnnamed_8 = 1;
pub const WOLFSSL_ERROR_SSL: wolf_C2RustUnnamed_8 = 85;
pub const WOLFSSL_ERROR_WANT_X509_LOOKUP: wolf_C2RustUnnamed_8 = 83;
pub const WOLFSSL_ERROR_SYSCALL: wolf_C2RustUnnamed_8 = 5;
pub const WOLFSSL_ERROR_WANT_ACCEPT: wolf_C2RustUnnamed_8 = 8;
pub const WOLFSSL_ERROR_WANT_CONNECT: wolf_C2RustUnnamed_8 = 7;
pub const WOLFSSL_SESS_CACHE_NO_INTERNAL: wolf_C2RustUnnamed_8 = 768;
pub const WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE: wolf_C2RustUnnamed_8 = 512;
pub const WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP: wolf_C2RustUnnamed_8 = 256;
pub const WOLFSSL_SESS_CACHE_NO_AUTO_CLEAR: wolf_C2RustUnnamed_8 = 8;
pub const WOLFSSL_SESS_CACHE_BOTH: wolf_C2RustUnnamed_8 = 3;
pub const WOLFSSL_SESS_CACHE_SERVER: wolf_C2RustUnnamed_8 = 2;
pub const WOLFSSL_SESS_CACHE_CLIENT: wolf_C2RustUnnamed_8 = 1;
pub const WOLFSSL_SESS_CACHE_OFF: wolf_C2RustUnnamed_8 = 0;
pub const WOLFSSL_VERIFY_FAIL_EXCEPT_PSK: wolf_C2RustUnnamed_8 = 8;
pub const WOLFSSL_VERIFY_CLIENT_ONCE: wolf_C2RustUnnamed_8 = 4;
pub const WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT: wolf_C2RustUnnamed_8 = 2;
pub const WOLFSSL_FILETYPE_RAW: wolf_C2RustUnnamed_8 = 3;
pub const WOLFSSL_FILETYPE_DEFAULT: wolf_C2RustUnnamed_8 = 2;
pub const WOLFSSL_FATAL_ERROR: wolf_C2RustUnnamed_8 = -1;
pub const WOLFSSL_UNKNOWN: wolf_C2RustUnnamed_8 = -2;
pub const WOLFSSL_NOT_IMPLEMENTED: wolf_C2RustUnnamed_8 = -3;
pub const WOLFSSL_BAD_FILE: wolf_C2RustUnnamed_8 = -4;
pub const WOLFSSL_BAD_FILETYPE: wolf_C2RustUnnamed_8 = -5;
pub const WOLFSSL_BAD_PATH: wolf_C2RustUnnamed_8 = -6;
pub const WOLFSSL_BAD_STAT: wolf_C2RustUnnamed_8 = -7;
pub const WOLFSSL_BAD_CERTTYPE: wolf_C2RustUnnamed_8 = -8;
pub const WOLFSSL_ALPN_NOT_FOUND: wolf_C2RustUnnamed_8 = -9;
pub const WOLFSSL_SHUTDOWN_NOT_DONE: wolf_C2RustUnnamed_8 = 2;
pub const WOLFSSL_ERROR_NONE: wolf_C2RustUnnamed_8 = 0;
pub type wolf_C2RustUnnamed_9 = libc::c_uint;
pub const WOLFSSL_CHAIN_CA: wolf_C2RustUnnamed_9 = 2;
pub const WOLFSSL_USER_CA: wolf_C2RustUnnamed_9 = 1;
pub const WOLFSSL_TLSV1_3: wolf_C2RustUnnamed_9 = 4;
pub type wolf_C2RustUnnamed_10 = libc::c_int;
pub const MIN_CODE_E: wolf_C2RustUnnamed_10 = -300;
pub const WC_LAST_E: wolf_C2RustUnnamed_10 = -247;
pub const EXTKEYUSAGE_E: wolf_C2RustUnnamed_10 = -247;
pub const ECC_PRIVATEONLY_E: wolf_C2RustUnnamed_10 = -246;
pub const ASYNC_OP_E: wolf_C2RustUnnamed_10 = -245;
pub const BAD_PATH_ERROR: wolf_C2RustUnnamed_10 = -244;
pub const DH_CHECK_PUB_E: wolf_C2RustUnnamed_10 = -243;
pub const ECC_CDH_KAT_FIPS_E: wolf_C2RustUnnamed_10 = -242;
pub const WC_CLEANUP_E: wolf_C2RustUnnamed_10 = -241;
pub const BAD_KEYWRAP_IV_E: wolf_C2RustUnnamed_10 = -240;
pub const BAD_KEYWRAP_ALG_E: wolf_C2RustUnnamed_10 = -239;
pub const ASN_PATHLEN_INV_E: wolf_C2RustUnnamed_10 = -238;
pub const ASN_PATHLEN_SIZE_E: wolf_C2RustUnnamed_10 = -237;
pub const MISSING_RNG_E: wolf_C2RustUnnamed_10 = -236;
pub const ASN_COUNTRY_SIZE_E: wolf_C2RustUnnamed_10 = -235;
pub const WC_KEY_SIZE_E: wolf_C2RustUnnamed_10 = -234;
pub const HASH_TYPE_E: wolf_C2RustUnnamed_10 = -232;
pub const SIG_TYPE_E: wolf_C2RustUnnamed_10 = -231;
pub const BAD_COND_E: wolf_C2RustUnnamed_10 = -230;
pub const SIG_VERIFY_E: wolf_C2RustUnnamed_10 = -229;
pub const WC_INIT_E: wolf_C2RustUnnamed_10 = -228;
pub const CERTPOLICIES_E: wolf_C2RustUnnamed_10 = -227;
pub const KEYUSAGE_E: wolf_C2RustUnnamed_10 = -226;
pub const AKID_E: wolf_C2RustUnnamed_10 = -225;
pub const SKID_E: wolf_C2RustUnnamed_10 = -224;
pub const ASN_NO_KEYUSAGE: wolf_C2RustUnnamed_10 = -223;
pub const ASN_NO_AKID: wolf_C2RustUnnamed_10 = -222;
pub const ASN_NO_SKID: wolf_C2RustUnnamed_10 = -221;
pub const SRP_BAD_KEY_E: wolf_C2RustUnnamed_10 = -220;
pub const SRP_VERIFY_E: wolf_C2RustUnnamed_10 = -219;
pub const SRP_CALL_ORDER_E: wolf_C2RustUnnamed_10 = -218;
pub const ECC_OUT_OF_RANGE_E: wolf_C2RustUnnamed_10 = -217;
pub const ECC_PRIV_KEY_E: wolf_C2RustUnnamed_10 = -216;
pub const ECC_INF_E: wolf_C2RustUnnamed_10 = -215;
pub const IS_POINT_E: wolf_C2RustUnnamed_10 = -214;
pub const MAC_CMP_FAILED_E: wolf_C2RustUnnamed_10 = -213;
pub const THREAD_STORE_SET_E: wolf_C2RustUnnamed_10 = -212;
pub const THREAD_STORE_KEY_E: wolf_C2RustUnnamed_10 = -211;
pub const AESGCM_KAT_FIPS_E: wolf_C2RustUnnamed_10 = -210;
pub const DRBG_CONT_FIPS_E: wolf_C2RustUnnamed_10 = -209;
pub const DRBG_KAT_FIPS_E: wolf_C2RustUnnamed_10 = -208;
pub const RSA_KAT_FIPS_E: wolf_C2RustUnnamed_10 = -207;
pub const HMAC_KAT_FIPS_E: wolf_C2RustUnnamed_10 = -206;
pub const DES3_KAT_FIPS_E: wolf_C2RustUnnamed_10 = -205;
pub const AES_KAT_FIPS_E: wolf_C2RustUnnamed_10 = -204;
pub const IN_CORE_FIPS_E: wolf_C2RustUnnamed_10 = -203;
pub const LENGTH_ONLY_E: wolf_C2RustUnnamed_10 = -202;
pub const RSA_PAD_E: wolf_C2RustUnnamed_10 = -201;
pub const HMAC_MIN_KEYLEN_E: wolf_C2RustUnnamed_10 = -200;
pub const RNG_FAILURE_E: wolf_C2RustUnnamed_10 = -199;
pub const ASN_NAME_INVALID_E: wolf_C2RustUnnamed_10 = -198;
pub const FIPS_NOT_ALLOWED_E: wolf_C2RustUnnamed_10 = -197;
pub const PKCS7_RECIP_E: wolf_C2RustUnnamed_10 = -196;
pub const PKCS7_OID_E: wolf_C2RustUnnamed_10 = -195;
pub const REQ_ATTRIBUTE_E: wolf_C2RustUnnamed_10 = -194;
pub const BAD_PADDING_E: wolf_C2RustUnnamed_10 = -193;
pub const BAD_STATE_E: wolf_C2RustUnnamed_10 = -192;
pub const ASN_OCSP_CONFIRM_E: wolf_C2RustUnnamed_10 = -191;
pub const ASN_CRL_NO_SIGNER_E: wolf_C2RustUnnamed_10 = -190;
pub const ASN_CRL_CONFIRM_E: wolf_C2RustUnnamed_10 = -189;
pub const BAD_ALIGN_E: wolf_C2RustUnnamed_10 = -187;
pub const DECOMPRESS_E: wolf_C2RustUnnamed_10 = -186;
pub const DECOMPRESS_INIT_E: wolf_C2RustUnnamed_10 = -185;
pub const COMPRESS_E: wolf_C2RustUnnamed_10 = -184;
pub const COMPRESS_INIT_E: wolf_C2RustUnnamed_10 = -183;
pub const ASYNC_INIT_E: wolf_C2RustUnnamed_10 = -182;
pub const AES_CCM_AUTH_E: wolf_C2RustUnnamed_10 = -181;
pub const AES_GCM_AUTH_E: wolf_C2RustUnnamed_10 = -180;
pub const BAD_OCSP_RESPONDER: wolf_C2RustUnnamed_10 = -178;
pub const ALT_NAME_E: wolf_C2RustUnnamed_10 = -177;
pub const NO_PASSWORD: wolf_C2RustUnnamed_10 = -176;
pub const UNICODE_SIZE_E: wolf_C2RustUnnamed_10 = -175;
pub const NOT_COMPILED_IN: wolf_C2RustUnnamed_10 = -174;
pub const BAD_FUNC_ARG: wolf_C2RustUnnamed_10 = -173;
pub const ECC_CURVE_OID_E: wolf_C2RustUnnamed_10 = -172;
pub const ASN_ECC_KEY_E: wolf_C2RustUnnamed_10 = -171;
pub const ECC_BAD_ARG_E: wolf_C2RustUnnamed_10 = -170;
pub const ASN_CRIT_EXT_E: wolf_C2RustUnnamed_10 = -160;
pub const ASN_NTRU_KEY_E: wolf_C2RustUnnamed_10 = -159;
pub const ASN_DH_KEY_E: wolf_C2RustUnnamed_10 = -158;
pub const ASN_SIG_KEY_E: wolf_C2RustUnnamed_10 = -157;
pub const ASN_SIG_HASH_E: wolf_C2RustUnnamed_10 = -156;
pub const ASN_SIG_CONFIRM_E: wolf_C2RustUnnamed_10 = -155;
pub const ASN_INPUT_E: wolf_C2RustUnnamed_10 = -154;
pub const ASN_TIME_E: wolf_C2RustUnnamed_10 = -153;
pub const ASN_SIG_OID_E: wolf_C2RustUnnamed_10 = -152;
pub const ASN_AFTER_DATE_E: wolf_C2RustUnnamed_10 = -151;
pub const ASN_BEFORE_DATE_E: wolf_C2RustUnnamed_10 = -150;
pub const ASN_DATE_SZ_E: wolf_C2RustUnnamed_10 = -149;
pub const ASN_UNKNOWN_OID_E: wolf_C2RustUnnamed_10 = -148;
pub const ASN_BITSTR_E: wolf_C2RustUnnamed_10 = -147;
pub const ASN_EXPECT_0_E: wolf_C2RustUnnamed_10 = -146;
pub const ASN_TAG_NULL_E: wolf_C2RustUnnamed_10 = -145;
pub const ASN_OBJECT_ID_E: wolf_C2RustUnnamed_10 = -144;
pub const ASN_RSA_KEY_E: wolf_C2RustUnnamed_10 = -143;
pub const ASN_GETINT_E: wolf_C2RustUnnamed_10 = -142;
pub const ASN_VERSION_E: wolf_C2RustUnnamed_10 = -141;
pub const ASN_PARSE_E: wolf_C2RustUnnamed_10 = -140;
pub const EXTENSIONS_E: wolf_C2RustUnnamed_10 = -139;
pub const CA_TRUE_E: wolf_C2RustUnnamed_10 = -138;
pub const ISSUER_E: wolf_C2RustUnnamed_10 = -137;
pub const SUBJECT_E: wolf_C2RustUnnamed_10 = -136;
pub const DATE_E: wolf_C2RustUnnamed_10 = -135;
pub const PUBLIC_KEY_E: wolf_C2RustUnnamed_10 = -134;
pub const ALGO_ID_E: wolf_C2RustUnnamed_10 = -133;
pub const BUFFER_E: wolf_C2RustUnnamed_10 = -132;
pub const RSA_BUFFER_E: wolf_C2RustUnnamed_10 = -131;
pub const RSA_WRONG_TYPE_E: wolf_C2RustUnnamed_10 = -130;
pub const VAR_STATE_CHANGE_E: wolf_C2RustUnnamed_10 = -126;
pub const MEMORY_E: wolf_C2RustUnnamed_10 = -125;
pub const MP_ZERO_E: wolf_C2RustUnnamed_10 = -121;
pub const MP_CMP_E: wolf_C2RustUnnamed_10 = -120;
pub const MP_INVMOD_E: wolf_C2RustUnnamed_10 = -119;
pub const MP_MOD_E: wolf_C2RustUnnamed_10 = -118;
pub const MP_MULMOD_E: wolf_C2RustUnnamed_10 = -117;
pub const MP_MUL_E: wolf_C2RustUnnamed_10 = -116;
pub const MP_ADD_E: wolf_C2RustUnnamed_10 = -115;
pub const MP_SUB_E: wolf_C2RustUnnamed_10 = -114;
pub const MP_TO_E: wolf_C2RustUnnamed_10 = -113;
pub const MP_EXPTMOD_E: wolf_C2RustUnnamed_10 = -112;
pub const MP_READ_E: wolf_C2RustUnnamed_10 = -111;
pub const MP_INIT_E: wolf_C2RustUnnamed_10 = -110;
pub const WC_NOT_PENDING_E: wolf_C2RustUnnamed_10 = -109;
pub const WC_PENDING_E: wolf_C2RustUnnamed_10 = -108;
pub const WC_TIMEOUT_E: wolf_C2RustUnnamed_10 = -107;
pub const BAD_MUTEX_E: wolf_C2RustUnnamed_10 = -106;
pub const RAN_BLOCK_E: wolf_C2RustUnnamed_10 = -105;
pub const CRYPTGEN_E: wolf_C2RustUnnamed_10 = -104;
pub const WINCRYPT_E: wolf_C2RustUnnamed_10 = -103;
pub const READ_RAN_E: wolf_C2RustUnnamed_10 = -102;
pub const OPEN_RAN_E: wolf_C2RustUnnamed_10 = -101;
pub const MAX_CODE_E: wolf_C2RustUnnamed_10 = -100;
pub type wolfSSL_ErrorCodes = libc::c_int;
pub const HRR_COOKIE_ERROR: wolfSSL_ErrorCodes = -505;
pub const POST_HAND_AUTH_ERROR: wolfSSL_ErrorCodes = -504;
pub const KEY_SHARE_ERROR: wolfSSL_ErrorCodes = -503;
pub const COMPRESSION_ERROR: wolfSSL_ErrorCodes = -502;
pub const MATCH_SUITE_ERROR: wolfSSL_ErrorCodes = -501;
pub const UNSUPPORTED_SUITE: wolfSSL_ErrorCodes = -500;
pub const UNSUPPORTED_EXTENSION: wolfSSL_ErrorCodes = -429;
pub const EXT_MISSING: wolfSSL_ErrorCodes = -428;
pub const ALERT_COUNT_E: wolfSSL_ErrorCodes = -427;
pub const MCAST_HIGHWATER_CB_E: wolfSSL_ErrorCodes = -426;
pub const INVALID_PARAMETER: wolfSSL_ErrorCodes = -425;
pub const EXT_NOT_ALLOWED: wolfSSL_ErrorCodes = -424;
pub const BAD_BINDER: wolfSSL_ErrorCodes = -423;
pub const MISSING_HANDSHAKE_DATA: wolfSSL_ErrorCodes = -422;
pub const BAD_KEY_SHARE_DATA: wolfSSL_ErrorCodes = -421;
pub const INVALID_CERT_CTX_E: wolfSSL_ErrorCodes = -420;
pub const WRITE_DUP_WRITE_E: wolfSSL_ErrorCodes = -419;
pub const WRITE_DUP_READ_E: wolfSSL_ErrorCodes = -418;
pub const HTTP_TIMEOUT: wolfSSL_ErrorCodes = -417;
pub const DECODE_E: wolfSSL_ErrorCodes = -416;
pub const DTLS_POOL_SZ_E: wolfSSL_ErrorCodes = -415;
pub const EXT_MASTER_SECRET_NEEDED_E: wolfSSL_ErrorCodes = -414;
pub const CTX_INIT_MUTEX_E: wolfSSL_ErrorCodes = -413;
pub const INPUT_SIZE_E: wolfSSL_ErrorCodes = -412;
pub const DTLS_EXPORT_VER_E: wolfSSL_ErrorCodes = -411;
pub const ECC_KEY_SIZE_E: wolfSSL_ErrorCodes = -410;
pub const RSA_KEY_SIZE_E: wolfSSL_ErrorCodes = -409;
pub const OCSP_WANT_READ: wolfSSL_ErrorCodes = -408;
pub const OCSP_INVALID_STATUS: wolfSSL_ErrorCodes = -407;
pub const BAD_CERTIFICATE_STATUS_ERROR: wolfSSL_ErrorCodes = -406;
pub const UNKNOWN_ALPN_PROTOCOL_NAME_E: wolfSSL_ErrorCodes = -405;
pub const HANDSHAKE_SIZE_ERROR: wolfSSL_ErrorCodes = -404;
pub const RSA_SIGN_FAULT: wolfSSL_ErrorCodes = -403;
pub const SNI_ABSENT_ERROR: wolfSSL_ErrorCodes = -402;
pub const DH_KEY_SIZE_E: wolfSSL_ErrorCodes = -401;
pub const BAD_TICKET_ENCRYPT: wolfSSL_ErrorCodes = -400;
pub const BAD_TICKET_MSG_SZ: wolfSSL_ErrorCodes = -399;
pub const BAD_TICKET_KEY_CB_SZ: wolfSSL_ErrorCodes = -398;
pub const SOCKET_PEER_CLOSED_E: wolfSSL_ErrorCodes = -397;
pub const SNI_UNSUPPORTED: wolfSSL_ErrorCodes = -396;
pub const DUPLICATE_MSG_E: wolfSSL_ErrorCodes = -395;
pub const SANITY_MSG_E: wolfSSL_ErrorCodes = -394;
pub const NO_CHANGE_CIPHER_E: wolfSSL_ErrorCodes = -393;
pub const SESSION_SECRET_CB_E: wolfSSL_ErrorCodes = -392;
pub const SCR_DIFFERENT_CERT_E: wolfSSL_ErrorCodes = -391;
pub const SESSION_TICKET_EXPECT_E: wolfSSL_ErrorCodes = -390;
pub const SESSION_TICKET_LEN_E: wolfSSL_ErrorCodes = -389;
pub const SECURE_RENEGOTIATION_E: wolfSSL_ErrorCodes = -388;
pub const SEND_OOB_READ_E: wolfSSL_ErrorCodes = -387;
pub const EXTKEYUSE_AUTH_E: wolfSSL_ErrorCodes = -386;
pub const KEYUSE_ENCIPHER_E: wolfSSL_ErrorCodes = -385;
pub const KEYUSE_SIGNATURE_E: wolfSSL_ErrorCodes = -383;
pub const UNKNOWN_MAX_FRAG_LEN_E: wolfSSL_ErrorCodes = -382;
pub const UNKNOWN_SNI_HOST_NAME_E: wolfSSL_ErrorCodes = -381;
pub const CACHE_MATCH_ERROR: wolfSSL_ErrorCodes = -380;
pub const FWRITE_ERROR: wolfSSL_ErrorCodes = -379;
pub const NO_PEER_VERIFY: wolfSSL_ErrorCodes = -378;
pub const GEN_COOKIE_E: wolfSSL_ErrorCodes = -377;
pub const RECV_OVERFLOW_E: wolfSSL_ErrorCodes = -376;
pub const SANITY_CIPHER_E: wolfSSL_ErrorCodes = -375;
pub const BAD_KEA_TYPE_E: wolfSSL_ErrorCodes = -374;
pub const OUT_OF_ORDER_E: wolfSSL_ErrorCodes = -373;
pub const SSL_NO_PEM_HEADER: wolfSSL_ErrorCodes = -372;
pub const SUITES_ERROR: wolfSSL_ErrorCodes = -371;
pub const SEQUENCE_ERROR: wolfSSL_ErrorCodes = -370;
pub const COOKIE_ERROR: wolfSSL_ErrorCodes = -369;
pub const MAX_CHAIN_ERROR: wolfSSL_ErrorCodes = -368;
pub const OCSP_LOOKUP_FAIL: wolfSSL_ErrorCodes = -367;
pub const OCSP_CERT_UNKNOWN: wolfSSL_ErrorCodes = -366;
pub const OCSP_NEED_URL: wolfSSL_ErrorCodes = -365;
pub const THREAD_CREATE_E: wolfSSL_ErrorCodes = -364;
pub const MONITOR_SETUP_E: wolfSSL_ErrorCodes = -363;
pub const CRL_MISSING: wolfSSL_ErrorCodes = -362;
pub const CRL_CERT_REVOKED: wolfSSL_ErrorCodes = -361;
pub const OCSP_CERT_REVOKED: wolfSSL_ErrorCodes = -360;
pub const BAD_CERT_MANAGER_ERROR: wolfSSL_ErrorCodes = -359;
pub const NOT_CA_ERROR: wolfSSL_ErrorCodes = -357;
pub const ECC_SHARED_ERROR: wolfSSL_ErrorCodes = -355;
pub const ECC_EXPORT_ERROR: wolfSSL_ErrorCodes = -354;
pub const ECC_MAKEKEY_ERROR: wolfSSL_ErrorCodes = -353;
pub const ECC_PEERKEY_ERROR: wolfSSL_ErrorCodes = -352;
pub const ECC_CURVE_ERROR: wolfSSL_ErrorCodes = -351;
pub const ECC_CURVETYPE_ERROR: wolfSSL_ErrorCodes = -350;
pub const NTRU_DECRYPT_ERROR: wolfSSL_ErrorCodes = -349;
pub const NTRU_ENCRYPT_ERROR: wolfSSL_ErrorCodes = -348;
pub const NTRU_DRBG_ERROR: wolfSSL_ErrorCodes = -347;
pub const NTRU_KEY_ERROR: wolfSSL_ErrorCodes = -346;
pub const NO_PEER_CERT: wolfSSL_ErrorCodes = -345;
pub const SIDE_ERROR: wolfSSL_ErrorCodes = -344;
pub const ZERO_RETURN: wolfSSL_ErrorCodes = -343;
pub const PEER_KEY_ERROR: wolfSSL_ErrorCodes = -342;
pub const LENGTH_ERROR: wolfSSL_ErrorCodes = -341;
pub const SETITIMER_ERROR: wolfSSL_ErrorCodes = -340;
pub const SIGACT_ERROR: wolfSSL_ErrorCodes = -339;
pub const GETITIMER_ERROR: wolfSSL_ErrorCodes = -338;
pub const GETTIME_ERROR: wolfSSL_ErrorCodes = -337;
pub const ZLIB_DECOMPRESS_ERROR: wolfSSL_ErrorCodes = -336;
pub const ZLIB_COMPRESS_ERROR: wolfSSL_ErrorCodes = -335;
pub const ZLIB_INIT_ERROR: wolfSSL_ErrorCodes = -334;
pub const PSK_KEY_ERROR: wolfSSL_ErrorCodes = -333;
pub const SERVER_HINT_ERROR: wolfSSL_ErrorCodes = -332;
pub const CLIENT_ID_ERROR: wolfSSL_ErrorCodes = -331;
pub const VERIFY_SIGN_ERROR: wolfSSL_ErrorCodes = -330;
pub const VERIFY_CERT_ERROR: wolfSSL_ErrorCodes = -329;
pub const BUFFER_ERROR: wolfSSL_ErrorCodes = -328;
pub const WANT_WRITE: wolfSSL_ErrorCodes = -327;
pub const VERSION_ERROR: wolfSSL_ErrorCodes = -326;
pub const NOT_READY_ERROR: wolfSSL_ErrorCodes = -324;
pub const WANT_READ: wolfSSL_ErrorCodes = -323;
pub const BAD_HELLO: wolfSSL_ErrorCodes = -321;
pub const BUILD_MSG_ERROR: wolfSSL_ErrorCodes = -320;
pub const NO_DH_PARAMS: wolfSSL_ErrorCodes = -319;
pub const RSA_PRIVATE_ERROR: wolfSSL_ErrorCodes = -318;
pub const NO_PRIVATE_KEY: wolfSSL_ErrorCodes = -317;
pub const NO_PEER_KEY: wolfSSL_ErrorCodes = -316;
pub const FREAD_ERROR: wolfSSL_ErrorCodes = -315;
pub const ENCRYPT_ERROR: wolfSSL_ErrorCodes = -314;
pub const FATAL_ERROR: wolfSSL_ErrorCodes = -313;
pub const DECRYPT_ERROR: wolfSSL_ErrorCodes = -312;
pub const UNKNOWN_RECORD_TYPE: wolfSSL_ErrorCodes = -311;
pub const INCOMPLETE_DATA: wolfSSL_ErrorCodes = -310;
pub const SOCKET_NODATA: wolfSSL_ErrorCodes = -309;
pub const SOCKET_ERROR_E: wolfSSL_ErrorCodes = -308;
pub const UNKNOWN_HANDSHAKE_TYPE: wolfSSL_ErrorCodes = -307;
pub const PARSE_ERROR: wolfSSL_ErrorCodes = -306;
pub const VERIFY_MAC_ERROR: wolfSSL_ErrorCodes = -305;
pub const VERIFY_FINISHED_ERROR: wolfSSL_ErrorCodes = -304;
pub const MEMORY_ERROR: wolfSSL_ErrorCodes = -303;
pub const PREFIX_ERROR: wolfSSL_ErrorCodes = -302;
pub const INPUT_CASE_ERROR: wolfSSL_ErrorCodes = -301;

// nss.rs
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type PK11GenericObject = PK11GenericObjectStr;
pub type PRDescIdentity = PRIntn;
pub type PRIntn = libc::c_int;
pub type PRReservedFN = Option::<unsafe extern "C" fn(*mut PRFileDesc) -> PRIntn>;
pub type PRConnectcontinueFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, PRInt16) -> PRStatus,
>;
pub type PRInt16 = libc::c_short;
pub type PRStatus = libc::c_int;
pub const PR_SUCCESS: PRStatus = 0;
pub const PR_FAILURE: PRStatus = -1;
pub type PRSendfileFN = Option::<
    unsafe extern "C" fn(
        *mut PRFileDesc,
        *mut PRSendFileData,
        PRTransmitFileFlags,
        PRIntervalTime,
    ) -> PRInt32,
>;
pub type PRIntervalTime = PRUint32;
pub type PRUint32 = libc::c_uint;
pub type PRTransmitFileFlags = libc::c_uint;
pub const PR_TRANSMITFILE_CLOSE_SOCKET: PRTransmitFileFlags = 1;
pub const PR_TRANSMITFILE_KEEP_OPEN: PRTransmitFileFlags = 0;
pub type PRInt32 = libc::c_int;
pub type PRSize = size_t;
pub type PRSetsocketoptionFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *const PRSocketOptionData) -> PRStatus,
>;
pub type PRUint16 = libc::c_ushort;
pub type PRUint64 = libc::c_ulong;
pub type PRUint8 = libc::c_uchar;
pub type PRBool = PRIntn;
pub type PRUintn = libc::c_uint;
pub type PRSockOption = libc::c_uint;
pub const PR_SockOpt_Last: PRSockOption = 17;
pub const PR_SockOpt_Reuseport: PRSockOption = 16;
pub const PR_SockOpt_Broadcast: PRSockOption = 15;
pub const PR_SockOpt_MaxSegment: PRSockOption = 14;
pub const PR_SockOpt_NoDelay: PRSockOption = 13;
pub const PR_SockOpt_McastLoopback: PRSockOption = 12;
pub const PR_SockOpt_McastTimeToLive: PRSockOption = 11;
pub const PR_SockOpt_McastInterface: PRSockOption = 10;
pub const PR_SockOpt_DropMember: PRSockOption = 9;
pub const PR_SockOpt_AddMember: PRSockOption = 8;
pub const PR_SockOpt_IpTypeOfService: PRSockOption = 7;
pub const PR_SockOpt_IpTimeToLive: PRSockOption = 6;
pub const PR_SockOpt_SendBufferSize: PRSockOption = 5;
pub const PR_SockOpt_RecvBufferSize: PRSockOption = 4;
pub const PR_SockOpt_Keepalive: PRSockOption = 3;
pub const PR_SockOpt_Reuseaddr: PRSockOption = 2;
pub const PR_SockOpt_Linger: PRSockOption = 1;
pub const PR_SockOpt_Nonblocking: PRSockOption = 0;
pub type PRGetsocketoptionFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *mut PRSocketOptionData) -> PRStatus,
>;
pub type PRGetpeernameFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *mut PRNetAddr) -> PRStatus,
>;
pub type PRGetsocknameFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *mut PRNetAddr) -> PRStatus,
>;
pub type PRTransmitfileFN = Option::<
    unsafe extern "C" fn(
        *mut PRFileDesc,
        *mut PRFileDesc,
        *const libc::c_void,
        PRInt32,
        PRTransmitFileFlags,
        PRIntervalTime,
    ) -> PRInt32,
>;
pub type PRAcceptreadFN = Option::<
    unsafe extern "C" fn(
        *mut PRFileDesc,
        *mut *mut PRFileDesc,
        *mut *mut PRNetAddr,
        *mut libc::c_void,
        PRInt32,
        PRIntervalTime,
    ) -> PRInt32,
>;
pub type PRPollFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, PRInt16, *mut PRInt16) -> PRInt16,
>;
pub type PRSendtoFN = Option::<
    unsafe extern "C" fn(
        *mut PRFileDesc,
        *const libc::c_void,
        PRInt32,
        PRIntn,
        *const PRNetAddr,
        PRIntervalTime,
    ) -> PRInt32,
>;
pub type PRRecvfromFN = Option::<
    unsafe extern "C" fn(
        *mut PRFileDesc,
        *mut libc::c_void,
        PRInt32,
        PRIntn,
        *mut PRNetAddr,
        PRIntervalTime,
    ) -> PRInt32,
>;
pub type PRSendFN = Option::<
    unsafe extern "C" fn(
        *mut PRFileDesc,
        *const libc::c_void,
        PRInt32,
        PRIntn,
        PRIntervalTime,
    ) -> PRInt32,
>;
pub type PRRecvFN = Option::<
    unsafe extern "C" fn(
        *mut PRFileDesc,
        *mut libc::c_void,
        PRInt32,
        PRIntn,
        PRIntervalTime,
    ) -> PRInt32,
>;
pub type PRShutdownFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, PRIntn) -> PRStatus,
>;
pub type PRListenFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, PRIntn) -> PRStatus,
>;
pub type PRBindFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *const PRNetAddr) -> PRStatus,
>;
pub type PRAcceptFN = Option::<
    unsafe extern "C" fn(
        *mut PRFileDesc,
        *mut PRNetAddr,
        PRIntervalTime,
    ) -> *mut PRFileDesc,
>;
pub type PRConnectFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *const PRNetAddr, PRIntervalTime) -> PRStatus,
>;
pub type PRWritevFN = Option::<
    unsafe extern "C" fn(
        *mut PRFileDesc,
        *const PRIOVec,
        PRInt32,
        PRIntervalTime,
    ) -> PRInt32,
>;
pub type PRFileInfo64FN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *mut PRFileInfo64) -> PRStatus,
>;
pub type PRTime = PRInt64;
pub type PRInt64 = libc::c_long;
pub type PROffset64 = PRInt64;
pub type PRFileType = libc::c_uint;
pub const PR_FILE_OTHER: PRFileType = 3;
pub const PR_FILE_DIRECTORY: PRFileType = 2;
pub const PR_FILE_FILE: PRFileType = 1;
pub type PRFileInfoFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *mut PRFileInfo) -> PRStatus,
>;
pub type PROffset32 = PRInt32;
pub type PRSeek64FN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, PROffset64, PRSeekWhence) -> PROffset64,
>;
pub type PRSeekWhence = libc::c_uint;
pub const PR_SEEK_END: PRSeekWhence = 2;
pub const PR_SEEK_CUR: PRSeekWhence = 1;
pub const PR_SEEK_SET: PRSeekWhence = 0;
pub type PRSeekFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, PROffset32, PRSeekWhence) -> PROffset32,
>;
pub type PRFsyncFN = Option::<unsafe extern "C" fn(*mut PRFileDesc) -> PRStatus>;
pub type PRAvailable64FN = Option::<unsafe extern "C" fn(*mut PRFileDesc) -> PRInt64>;
pub type PRAvailableFN = Option::<unsafe extern "C" fn(*mut PRFileDesc) -> PRInt32>;
pub type PRWriteFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *const libc::c_void, PRInt32) -> PRInt32,
>;
pub type PRReadFN = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *mut libc::c_void, PRInt32) -> PRInt32,
>;
pub type PRCloseFN = Option::<unsafe extern "C" fn(*mut PRFileDesc) -> PRStatus>;
pub type PRDescType = libc::c_uint;
pub const PR_DESC_PIPE: PRDescType = 5;
pub const PR_DESC_LAYERED: PRDescType = 4;
pub const PR_DESC_SOCKET_UDP: PRDescType = 3;
pub const PR_DESC_SOCKET_TCP: PRDescType = 2;
pub const PR_DESC_FILE: PRDescType = 1;
pub type SECStatus = _SECStatus;
pub type _SECStatus = libc::c_int;
pub const SECSuccess: _SECStatus = 0;
pub const SECFailure: _SECStatus = -1;
pub const SECWouldBlock: _SECStatus = -2;
pub type PRErrorCode = PRInt32;
pub type NSSInitContext = NSSInitContextStr;
pub type NSSInitParameters = NSSInitParametersStr;
pub type SECItem = SECItemStr;
pub type SECItemType = libc::c_uint;
pub const siBMPString: SECItemType = 15;
pub const siUTF8String: SECItemType = 14;
pub const siVisibleString: SECItemType = 13;
pub const siGeneralizedTime: SECItemType = 12;
pub const siUTCTime: SECItemType = 11;
pub const siUnsignedInteger: SECItemType = 10;
pub const siDEROID: SECItemType = 9;
pub const siAsciiString: SECItemType = 8;
pub const siAsciiNameString: SECItemType = 7;
pub const siEncodedNameBuffer: SECItemType = 6;
pub const siDERNameBuffer: SECItemType = 5;
pub const siEncodedCertBuffer: SECItemType = 4;
pub const siDERCertBuffer: SECItemType = 3;
pub const siCipherDataBuffer: SECItemType = 2;
pub const siClearDataBuffer: SECItemType = 1;
pub const siBuffer: SECItemType = 0;
pub type PK11Context = PK11ContextStr;
pub type SECOidTag = libc::c_uint;
pub const SEC_OID_TOTAL: SECOidTag = 364;
pub const SEC_OID_EXT_KEY_USAGE_IPSEC_USER: SECOidTag = 363;
pub const SEC_OID_EXT_KEY_USAGE_IPSEC_TUNNEL: SECOidTag = 362;
pub const SEC_OID_EXT_KEY_USAGE_IPSEC_END: SECOidTag = 361;
pub const SEC_OID_IPSEC_IKE_INTERMEDIATE: SECOidTag = 360;
pub const SEC_OID_IPSEC_IKE_END: SECOidTag = 359;
pub const SEC_OID_EXT_KEY_USAGE_IPSEC_IKE: SECOidTag = 358;
pub const SEC_OID_X509_ANY_EXT_KEY_USAGE: SECOidTag = 357;
pub const SEC_OID_TLS13_KEA_ANY: SECOidTag = 356;
pub const SEC_OID_CURVE25519: SECOidTag = 355;
pub const SEC_OID_TLS_DHE_CUSTOM: SECOidTag = 354;
pub const SEC_OID_TLS_FFDHE_8192: SECOidTag = 353;
pub const SEC_OID_TLS_FFDHE_6144: SECOidTag = 352;
pub const SEC_OID_TLS_FFDHE_4096: SECOidTag = 351;
pub const SEC_OID_TLS_FFDHE_3072: SECOidTag = 350;
pub const SEC_OID_TLS_FFDHE_2048: SECOidTag = 349;
pub const SEC_OID_TLS_DHE_PSK: SECOidTag = 348;
pub const SEC_OID_TLS_ECDHE_PSK: SECOidTag = 347;
pub const SEC_OID_CHACHA20_POLY1305: SECOidTag = 346;
pub const SEC_OID_APPLY_SSL_POLICY: SECOidTag = 345;
pub const SEC_OID_TLS_DH_ANON_EXPORT: SECOidTag = 344;
pub const SEC_OID_TLS_DH_DSS_EXPORT: SECOidTag = 343;
pub const SEC_OID_TLS_DH_RSA_EXPORT: SECOidTag = 342;
pub const SEC_OID_TLS_DHE_DSS_EXPORT: SECOidTag = 341;
pub const SEC_OID_TLS_DHE_RSA_EXPORT: SECOidTag = 340;
pub const SEC_OID_TLS_RSA_EXPORT: SECOidTag = 339;
pub const SEC_OID_TLS_ECDH_ANON: SECOidTag = 338;
pub const SEC_OID_TLS_ECDH_RSA: SECOidTag = 337;
pub const SEC_OID_TLS_ECDH_ECDSA: SECOidTag = 336;
pub const SEC_OID_TLS_ECDHE_RSA: SECOidTag = 335;
pub const SEC_OID_TLS_ECDHE_ECDSA: SECOidTag = 334;
pub const SEC_OID_TLS_DH_ANON: SECOidTag = 333;
pub const SEC_OID_TLS_DH_DSS: SECOidTag = 332;
pub const SEC_OID_TLS_DH_RSA: SECOidTag = 331;
pub const SEC_OID_TLS_DHE_DSS: SECOidTag = 330;
pub const SEC_OID_TLS_DHE_RSA: SECOidTag = 329;
pub const SEC_OID_TLS_RSA: SECOidTag = 328;
pub const SEC_OID_HMAC_MD5: SECOidTag = 327;
pub const SEC_OID_NULL_CIPHER: SECOidTag = 326;
pub const SEC_OID_RC4_56: SECOidTag = 325;
pub const SEC_OID_RC4_40: SECOidTag = 324;
pub const SEC_OID_DES_40_CBC: SECOidTag = 323;
pub const SEC_OID_RC2_40_CBC: SECOidTag = 322;
pub const SEC_OID_IDEA_CBC: SECOidTag = 321;
pub const SEC_OID_AES_256_GCM: SECOidTag = 320;
pub const SEC_OID_AES_192_GCM: SECOidTag = 319;
pub const SEC_OID_AES_128_GCM: SECOidTag = 318;
pub const SEC_OID_AVA_NAME: SECOidTag = 317;
pub const SEC_OID_MS_EXT_KEY_USAGE_CTL_SIGNING: SECOidTag = 316;
pub const SEC_OID_NIST_DSA_SIGNATURE_WITH_SHA256_DIGEST: SECOidTag = 315;
pub const SEC_OID_NIST_DSA_SIGNATURE_WITH_SHA224_DIGEST: SECOidTag = 314;
pub const SEC_OID_BUSINESS_CATEGORY: SECOidTag = 313;
pub const SEC_OID_EV_INCORPORATION_COUNTRY: SECOidTag = 312;
pub const SEC_OID_EV_INCORPORATION_STATE: SECOidTag = 311;
pub const SEC_OID_EV_INCORPORATION_LOCALITY: SECOidTag = 310;
pub const SEC_OID_SHA224: SECOidTag = 309;
pub const SEC_OID_PKCS1_SHA224_WITH_RSA_ENCRYPTION: SECOidTag = 308;
pub const SEC_OID_PKCS1_RSA_PSS_SIGNATURE: SECOidTag = 307;
pub const SEC_OID_PKCS1_PSPECIFIED: SECOidTag = 306;
pub const SEC_OID_PKCS1_MGF1: SECOidTag = 305;
pub const SEC_OID_PKCS1_RSA_OAEP_ENCRYPTION: SECOidTag = 304;
pub const SEC_OID_X509_ANY_POLICY: SECOidTag = 303;
pub const SEC_OID_SEED_CBC: SECOidTag = 302;
pub const SEC_OID_ISO_SHA1_WITH_RSA_SIGNATURE: SECOidTag = 301;
pub const SEC_OID_PKIX_CA_REPOSITORY: SECOidTag = 300;
pub const SEC_OID_PKIX_TIMESTAMPING: SECOidTag = 299;
pub const SEC_OID_HMAC_SHA512: SECOidTag = 298;
pub const SEC_OID_HMAC_SHA384: SECOidTag = 297;
pub const SEC_OID_HMAC_SHA256: SECOidTag = 296;
pub const SEC_OID_HMAC_SHA224: SECOidTag = 295;
pub const SEC_OID_HMAC_SHA1: SECOidTag = 294;
pub const SEC_OID_PKCS5_PBMAC1: SECOidTag = 293;
pub const SEC_OID_PKCS5_PBES2: SECOidTag = 292;
pub const SEC_OID_PKCS5_PBKDF2: SECOidTag = 291;
pub const SEC_OID_CAMELLIA_256_CBC: SECOidTag = 290;
pub const SEC_OID_CAMELLIA_192_CBC: SECOidTag = 289;
pub const SEC_OID_CAMELLIA_128_CBC: SECOidTag = 288;
pub const SEC_OID_X509_SUBJECT_INFO_ACCESS: SECOidTag = 287;
pub const SEC_OID_X509_INHIBIT_ANY_POLICY: SECOidTag = 286;
pub const SEC_OID_X509_FRESHEST_CRL: SECOidTag = 285;
pub const SEC_OID_X509_CERT_ISSUER: SECOidTag = 284;
pub const SEC_OID_X509_ISSUING_DISTRIBUTION_POINT: SECOidTag = 283;
pub const SEC_OID_X509_DELTA_CRL_INDICATOR: SECOidTag = 282;
pub const SEC_OID_X509_HOLD_INSTRUCTION_CODE: SECOidTag = 281;
pub const SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE: SECOidTag = 280;
pub const SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE: SECOidTag = 279;
pub const SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE: SECOidTag = 278;
pub const SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE: SECOidTag = 277;
pub const SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST: SECOidTag = 276;
pub const SEC_OID_ANSIX962_ECDSA_SIGNATURE_RECOMMENDED_DIGEST: SECOidTag = 275;
pub const SEC_OID_PKCS9_EXTENSION_REQUEST: SECOidTag = 274;
pub const SEC_OID_PKIX_CA_ISSUERS: SECOidTag = 273;
pub const SEC_OID_AVA_PSEUDONYM: SECOidTag = 272;
pub const SEC_OID_AVA_HOUSE_IDENTIFIER: SECOidTag = 271;
pub const SEC_OID_AVA_GENERATION_QUALIFIER: SECOidTag = 270;
pub const SEC_OID_AVA_INITIALS: SECOidTag = 269;
pub const SEC_OID_AVA_GIVEN_NAME: SECOidTag = 268;
pub const SEC_OID_AVA_POST_OFFICE_BOX: SECOidTag = 267;
pub const SEC_OID_AVA_POSTAL_CODE: SECOidTag = 266;
pub const SEC_OID_AVA_POSTAL_ADDRESS: SECOidTag = 265;
pub const SEC_OID_AVA_TITLE: SECOidTag = 264;
pub const SEC_OID_AVA_STREET_ADDRESS: SECOidTag = 263;
pub const SEC_OID_AVA_SERIAL_NUMBER: SECOidTag = 262;
pub const SEC_OID_AVA_SURNAME: SECOidTag = 261;
pub const SEC_OID_NETSCAPE_AOLSCREENNAME: SECOidTag = 260;
pub const SEC_OID_SECG_EC_SECT571R1: SECOidTag = 259;
pub const SEC_OID_SECG_EC_SECT571K1: SECOidTag = 258;
pub const SEC_OID_SECG_EC_SECT409R1: SECOidTag = 257;
pub const SEC_OID_SECG_EC_SECT409K1: SECOidTag = 256;
pub const SEC_OID_SECG_EC_SECT283R1: SECOidTag = 255;
pub const SEC_OID_SECG_EC_SECT283K1: SECOidTag = 254;
pub const SEC_OID_SECG_EC_SECT239K1: SECOidTag = 253;
pub const SEC_OID_SECG_EC_SECT233R1: SECOidTag = 252;
pub const SEC_OID_SECG_EC_SECT233K1: SECOidTag = 251;
pub const SEC_OID_SECG_EC_SECT193R2: SECOidTag = 250;
pub const SEC_OID_SECG_EC_SECT193R1: SECOidTag = 249;
pub const SEC_OID_SECG_EC_SECT163R2: SECOidTag = 248;
pub const SEC_OID_SECG_EC_SECT163R1: SECOidTag = 247;
pub const SEC_OID_SECG_EC_SECT163K1: SECOidTag = 246;
pub const SEC_OID_SECG_EC_SECT131R2: SECOidTag = 245;
pub const SEC_OID_SECG_EC_SECT131R1: SECOidTag = 244;
pub const SEC_OID_SECG_EC_SECT113R2: SECOidTag = 243;
pub const SEC_OID_SECG_EC_SECT113R1: SECOidTag = 242;
pub const SEC_OID_ANSIX962_EC_C2TNB431R1: SECOidTag = 241;
pub const SEC_OID_ANSIX962_EC_C2PNB368W1: SECOidTag = 240;
pub const SEC_OID_ANSIX962_EC_C2TNB359V1: SECOidTag = 239;
pub const SEC_OID_ANSIX962_EC_C2PNB304W1: SECOidTag = 238;
pub const SEC_OID_ANSIX962_EC_C2PNB272W1: SECOidTag = 237;
pub const SEC_OID_ANSIX962_EC_C2ONB239V5: SECOidTag = 236;
pub const SEC_OID_ANSIX962_EC_C2ONB239V4: SECOidTag = 235;
pub const SEC_OID_ANSIX962_EC_C2TNB239V3: SECOidTag = 234;
pub const SEC_OID_ANSIX962_EC_C2TNB239V2: SECOidTag = 233;
pub const SEC_OID_ANSIX962_EC_C2TNB239V1: SECOidTag = 232;
pub const SEC_OID_ANSIX962_EC_C2PNB208W1: SECOidTag = 231;
pub const SEC_OID_ANSIX962_EC_C2ONB191V5: SECOidTag = 230;
pub const SEC_OID_ANSIX962_EC_C2ONB191V4: SECOidTag = 229;
pub const SEC_OID_ANSIX962_EC_C2TNB191V3: SECOidTag = 228;
pub const SEC_OID_ANSIX962_EC_C2TNB191V2: SECOidTag = 227;
pub const SEC_OID_ANSIX962_EC_C2TNB191V1: SECOidTag = 226;
pub const SEC_OID_ANSIX962_EC_C2PNB176V1: SECOidTag = 225;
pub const SEC_OID_ANSIX962_EC_C2PNB163V3: SECOidTag = 224;
pub const SEC_OID_ANSIX962_EC_C2PNB163V2: SECOidTag = 223;
pub const SEC_OID_ANSIX962_EC_C2PNB163V1: SECOidTag = 222;
pub const SEC_OID_SECG_EC_SECP521R1: SECOidTag = 221;
pub const SEC_OID_SECG_EC_SECP384R1: SECOidTag = 220;
pub const SEC_OID_SECG_EC_SECP256K1: SECOidTag = 219;
pub const SEC_OID_SECG_EC_SECP224R1: SECOidTag = 218;
pub const SEC_OID_SECG_EC_SECP224K1: SECOidTag = 217;
pub const SEC_OID_SECG_EC_SECP192K1: SECOidTag = 216;
pub const SEC_OID_SECG_EC_SECP160R2: SECOidTag = 215;
pub const SEC_OID_SECG_EC_SECP160R1: SECOidTag = 214;
pub const SEC_OID_SECG_EC_SECP160K1: SECOidTag = 213;
pub const SEC_OID_SECG_EC_SECP128R2: SECOidTag = 212;
pub const SEC_OID_SECG_EC_SECP128R1: SECOidTag = 211;
pub const SEC_OID_SECG_EC_SECP112R2: SECOidTag = 210;
pub const SEC_OID_SECG_EC_SECP112R1: SECOidTag = 209;
pub const SEC_OID_ANSIX962_EC_PRIME256V1: SECOidTag = 208;
pub const SEC_OID_ANSIX962_EC_PRIME239V3: SECOidTag = 207;
pub const SEC_OID_ANSIX962_EC_PRIME239V2: SECOidTag = 206;
pub const SEC_OID_ANSIX962_EC_PRIME239V1: SECOidTag = 205;
pub const SEC_OID_ANSIX962_EC_PRIME192V3: SECOidTag = 204;
pub const SEC_OID_ANSIX962_EC_PRIME192V2: SECOidTag = 203;
pub const SEC_OID_ANSIX962_EC_PRIME192V1: SECOidTag = 202;
pub const SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE: SECOidTag = 201;
pub const SEC_OID_ANSIX962_EC_PUBLIC_KEY: SECOidTag = 200;
pub const SEC_OID_AES_256_KEY_WRAP: SECOidTag = 199;
pub const SEC_OID_AES_192_KEY_WRAP: SECOidTag = 198;
pub const SEC_OID_AES_128_KEY_WRAP: SECOidTag = 197;
pub const SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION: SECOidTag = 196;
pub const SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION: SECOidTag = 195;
pub const SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION: SECOidTag = 194;
pub const SEC_OID_SHA512: SECOidTag = 193;
pub const SEC_OID_SHA384: SECOidTag = 192;
pub const SEC_OID_SHA256: SECOidTag = 191;
pub const SEC_OID_MS_SMIME_ENCRYPTION_KEY_PREFERENCE: SECOidTag = 190;
pub const SEC_OID_SDN702_DSA_SIGNATURE: SECOidTag = 189;
pub const SEC_OID_AES_256_CBC: SECOidTag = 188;
pub const SEC_OID_AES_256_ECB: SECOidTag = 187;
pub const SEC_OID_AES_192_CBC: SECOidTag = 186;
pub const SEC_OID_AES_192_ECB: SECOidTag = 185;
pub const SEC_OID_AES_128_CBC: SECOidTag = 184;
pub const SEC_OID_AES_128_ECB: SECOidTag = 183;
pub const SEC_OID_SMIME_ENCRYPTION_KEY_PREFERENCE: SECOidTag = 182;
pub const SEC_OID_CMS_RC2_KEY_WRAP: SECOidTag = 181;
pub const SEC_OID_CMS_3DES_KEY_WRAP: SECOidTag = 180;
pub const SEC_OID_CMS_EPHEMERAL_STATIC_DIFFIE_HELLMAN: SECOidTag = 179;
pub const SEC_OID_NS_CERT_EXT_SCOPE_OF_USE: SECOidTag = 178;
pub const SEC_OID_CERT_RENEWAL_LOCATOR: SECOidTag = 177;
pub const SEC_OID_NETSCAPE_RECOVERY_REQUEST: SECOidTag = 176;
pub const SEC_OID_NETSCAPE_NICKNAME: SECOidTag = 175;
pub const SEC_OID_X942_DIFFIE_HELMAN_KEY: SECOidTag = 174;
pub const SEC_OID_BOGUS_KEY_USAGE: SECOidTag = 173;
pub const SEC_OID_PKCS9_LOCAL_KEY_ID: SECOidTag = 172;
pub const SEC_OID_PKCS9_FRIENDLY_NAME: SECOidTag = 171;
pub const SEC_OID_PKCS9_X509_CRL: SECOidTag = 170;
pub const SEC_OID_PKCS9_SDSI_CERT: SECOidTag = 169;
pub const SEC_OID_PKCS9_X509_CERT: SECOidTag = 168;
pub const SEC_OID_PKCS12_V1_SAFE_CONTENTS_BAG_ID: SECOidTag = 167;
pub const SEC_OID_PKCS12_V1_SECRET_BAG_ID: SECOidTag = 166;
pub const SEC_OID_PKCS12_V1_CRL_BAG_ID: SECOidTag = 165;
pub const SEC_OID_PKCS12_V1_CERT_BAG_ID: SECOidTag = 164;
pub const SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID: SECOidTag = 163;
pub const SEC_OID_PKCS12_V1_KEY_BAG_ID: SECOidTag = 162;
pub const SEC_OID_PKCS12_PKCS8_SHROUDED_KEY_BAG_ID: SECOidTag = 161;
pub const SEC_OID_PKCS12_SAFE_CONTENTS_ID: SECOidTag = 160;
pub const SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC: SECOidTag = 159;
pub const SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC: SECOidTag = 158;
pub const SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC: SECOidTag = 157;
pub const SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC: SECOidTag = 156;
pub const SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4: SECOidTag = 155;
pub const SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4: SECOidTag = 154;
pub const SEC_OID_FORTEZZA_SKIPJACK: SECOidTag = 153;
pub const SEC_OID_NETSCAPE_SMIME_KEA: SECOidTag = 152;
pub const SEC_OID_OCSP_RESPONDER: SECOidTag = 151;
pub const SEC_OID_EXT_KEY_USAGE_TIME_STAMP: SECOidTag = 150;
pub const SEC_OID_EXT_KEY_USAGE_EMAIL_PROTECT: SECOidTag = 149;
pub const SEC_OID_EXT_KEY_USAGE_CODE_SIGN: SECOidTag = 148;
pub const SEC_OID_EXT_KEY_USAGE_CLIENT_AUTH: SECOidTag = 147;
pub const SEC_OID_EXT_KEY_USAGE_SERVER_AUTH: SECOidTag = 146;
pub const SEC_OID_PKIX_REGINFO_CERT_REQUEST: SECOidTag = 145;
pub const SEC_OID_PKIX_REGINFO_UTF8_PAIRS: SECOidTag = 144;
pub const SEC_OID_PKIX_REGCTRL_PROTOCOL_ENC_KEY: SECOidTag = 143;
pub const SEC_OID_PKIX_REGCTRL_OLD_CERT_ID: SECOidTag = 142;
pub const SEC_OID_PKIX_REGCTRL_PKI_ARCH_OPTIONS: SECOidTag = 141;
pub const SEC_OID_PKIX_REGCTRL_PKIPUBINFO: SECOidTag = 140;
pub const SEC_OID_PKIX_REGCTRL_AUTHENTICATOR: SECOidTag = 139;
pub const SEC_OID_PKIX_REGCTRL_REGTOKEN: SECOidTag = 138;
pub const SEC_OID_PKIX_OCSP_SERVICE_LOCATOR: SECOidTag = 137;
pub const SEC_OID_PKIX_OCSP_ARCHIVE_CUTOFF: SECOidTag = 136;
pub const SEC_OID_PKIX_OCSP_NO_CHECK: SECOidTag = 135;
pub const SEC_OID_PKIX_OCSP_RESPONSE: SECOidTag = 134;
pub const SEC_OID_PKIX_OCSP_CRL: SECOidTag = 133;
pub const SEC_OID_PKIX_OCSP_NONCE: SECOidTag = 132;
pub const SEC_OID_PKIX_OCSP_BASIC_RESPONSE: SECOidTag = 131;
pub const SEC_OID_PKIX_OCSP: SECOidTag = 130;
pub const SEC_OID_PKIX_USER_NOTICE_QUALIFIER: SECOidTag = 129;
pub const SEC_OID_PKIX_CPS_POINTER_QUALIFIER: SECOidTag = 128;
pub const SEC_OID_VERISIGN_USER_NOTICES: SECOidTag = 127;
pub const SEC_OID_BOGUS_DSA_SIGNATURE_WITH_SHA1_DIGEST: SECOidTag = 126;
pub const SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST: SECOidTag = 125;
pub const SEC_OID_ANSIX9_DSA_SIGNATURE: SECOidTag = 124;
pub const SEC_OID_PKCS12_RSA_SIGNATURE_WITH_SHA1_DIGEST: SECOidTag = 123;
pub const SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_TRIPLE_DES: SECOidTag = 122;
pub const SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_40_BIT_RC4: SECOidTag = 121;
pub const SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_128_BIT_RC4: SECOidTag = 120;
pub const SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC: SECOidTag = 119;
pub const SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC: SECOidTag = 118;
pub const SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC: SECOidTag = 117;
pub const SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4: SECOidTag = 116;
pub const SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4: SECOidTag = 115;
pub const SEC_OID_PKCS12_SDSI_CERT_BAG: SECOidTag = 114;
pub const SEC_OID_PKCS12_X509_CERT_CRL_BAG: SECOidTag = 113;
pub const SEC_OID_PKCS12_SECRET_BAG_ID: SECOidTag = 112;
pub const SEC_OID_PKCS12_CERT_AND_CRL_BAG_ID: SECOidTag = 111;
pub const SEC_OID_PKCS12_KEY_BAG_ID: SECOidTag = 110;
pub const SEC_OID_PKCS12_PKCS8_KEY_SHROUDING: SECOidTag = 109;
pub const SEC_OID_PKCS12_ENVELOPING_IDS: SECOidTag = 108;
pub const SEC_OID_PKCS12_SIGNATURE_IDS: SECOidTag = 107;
pub const SEC_OID_PKCS12_PBE_IDS: SECOidTag = 106;
pub const SEC_OID_PKCS12_OIDS: SECOidTag = 105;
pub const SEC_OID_PKCS12_CERT_BAG_IDS: SECOidTag = 104;
pub const SEC_OID_PKCS12_BAG_IDS: SECOidTag = 103;
pub const SEC_OID_PKCS12_ESPVK_IDS: SECOidTag = 102;
pub const SEC_OID_PKCS12_MODE_IDS: SECOidTag = 101;
pub const SEC_OID_PKCS12: SECOidTag = 100;
pub const SEC_OID_RFC1274_MAIL: SECOidTag = 99;
pub const SEC_OID_RFC1274_UID: SECOidTag = 98;
pub const SEC_OID_X500_RSA_ENCRYPTION: SECOidTag = 97;
pub const SEC_OID_X509_INVALID_DATE: SECOidTag = 96;
pub const SEC_OID_X509_REASON_CODE: SECOidTag = 95;
pub const SEC_OID_X509_CRL_NUMBER: SECOidTag = 94;
pub const SEC_OID_X509_AUTH_INFO_ACCESS: SECOidTag = 93;
pub const SEC_OID_X509_EXT_KEY_USAGE: SECOidTag = 92;
pub const SEC_OID_X509_AUTH_KEY_ID: SECOidTag = 91;
pub const SEC_OID_X509_POLICY_CONSTRAINTS: SECOidTag = 90;
pub const SEC_OID_X509_POLICY_MAPPINGS: SECOidTag = 89;
pub const SEC_OID_X509_CERTIFICATE_POLICIES: SECOidTag = 88;
pub const SEC_OID_X509_CRL_DIST_POINTS: SECOidTag = 87;
pub const SEC_OID_X509_NAME_CONSTRAINTS: SECOidTag = 86;
pub const SEC_OID_X509_BASIC_CONSTRAINTS: SECOidTag = 85;
pub const SEC_OID_X509_ISSUER_ALT_NAME: SECOidTag = 84;
pub const SEC_OID_X509_SUBJECT_ALT_NAME: SECOidTag = 83;
pub const SEC_OID_X509_PRIVATE_KEY_USAGE_PERIOD: SECOidTag = 82;
pub const SEC_OID_X509_KEY_USAGE: SECOidTag = 81;
pub const SEC_OID_X509_SUBJECT_KEY_ID: SECOidTag = 80;
pub const SEC_OID_X509_SUBJECT_DIRECTORY_ATTR: SECOidTag = 79;
pub const SEC_OID_NS_KEY_USAGE_GOVT_APPROVED: SECOidTag = 78;
pub const SEC_OID_NS_CERT_EXT_CERT_RENEWAL_TIME: SECOidTag = 77;
pub const SEC_OID_NS_CERT_EXT_LOST_PASSWORD_URL: SECOidTag = 76;
pub const SEC_OID_NS_CERT_EXT_COMMENT: SECOidTag = 75;
pub const SEC_OID_NS_CERT_EXT_SSL_SERVER_NAME: SECOidTag = 74;
pub const SEC_OID_NS_CERT_EXT_USER_PICTURE: SECOidTag = 73;
pub const SEC_OID_NS_CERT_EXT_ENTITY_LOGO: SECOidTag = 72;
pub const SEC_OID_NS_CERT_EXT_HOMEPAGE_URL: SECOidTag = 71;
pub const SEC_OID_NS_CERT_EXT_CA_POLICY_URL: SECOidTag = 70;
pub const SEC_OID_NS_CERT_EXT_CERT_RENEWAL_URL: SECOidTag = 69;
pub const SEC_OID_NS_CERT_EXT_CA_CERT_URL: SECOidTag = 68;
pub const SEC_OID_NS_CERT_EXT_CA_CRL_URL: SECOidTag = 67;
pub const SEC_OID_NS_CERT_EXT_CA_REVOCATION_URL: SECOidTag = 66;
pub const SEC_OID_NS_CERT_EXT_REVOCATION_URL: SECOidTag = 65;
pub const SEC_OID_NS_CERT_EXT_BASE_URL: SECOidTag = 64;
pub const SEC_OID_NS_CERT_EXT_CERT_TYPE: SECOidTag = 63;
pub const SEC_OID_NS_CERT_EXT_SUBJECT_LOGO: SECOidTag = 62;
pub const SEC_OID_NS_CERT_EXT_ISSUER_LOGO: SECOidTag = 61;
pub const SEC_OID_NS_CERT_EXT_NETSCAPE_OK: SECOidTag = 60;
pub const SEC_OID_MISSI_ALT_KEA: SECOidTag = 59;
pub const SEC_OID_MISSI_KEA: SECOidTag = 58;
pub const SEC_OID_MISSI_DSS: SECOidTag = 57;
pub const SEC_OID_MISSI_KEA_DSS: SECOidTag = 56;
pub const SEC_OID_MISSI_DSS_OLD: SECOidTag = 55;
pub const SEC_OID_MISSI_KEA_DSS_OLD: SECOidTag = 54;
pub const SEC_OID_NS_TYPE_CERT_SEQUENCE: SECOidTag = 53;
pub const SEC_OID_NS_TYPE_HTML: SECOidTag = 52;
pub const SEC_OID_NS_TYPE_URL: SECOidTag = 51;
pub const SEC_OID_NS_TYPE_JPEG: SECOidTag = 50;
pub const SEC_OID_NS_TYPE_GIF: SECOidTag = 49;
pub const SEC_OID_AVA_DC: SECOidTag = 48;
pub const SEC_OID_AVA_DN_QUALIFIER: SECOidTag = 47;
pub const SEC_OID_AVA_ORGANIZATIONAL_UNIT_NAME: SECOidTag = 46;
pub const SEC_OID_AVA_ORGANIZATION_NAME: SECOidTag = 45;
pub const SEC_OID_AVA_STATE_OR_PROVINCE: SECOidTag = 44;
pub const SEC_OID_AVA_LOCALITY: SECOidTag = 43;
pub const SEC_OID_AVA_COUNTRY_NAME: SECOidTag = 42;
pub const SEC_OID_AVA_COMMON_NAME: SECOidTag = 41;
pub const SEC_OID_PKCS9_SMIME_CAPABILITIES: SECOidTag = 40;
pub const SEC_OID_PKCS9_EXTENDED_CERTIFICATE_ATTRIBUTES: SECOidTag = 39;
pub const SEC_OID_PKCS9_UNSTRUCTURED_ADDRESS: SECOidTag = 38;
pub const SEC_OID_PKCS9_CHALLENGE_PASSWORD: SECOidTag = 37;
pub const SEC_OID_PKCS9_COUNTER_SIGNATURE: SECOidTag = 36;
pub const SEC_OID_PKCS9_SIGNING_TIME: SECOidTag = 35;
pub const SEC_OID_PKCS9_MESSAGE_DIGEST: SECOidTag = 34;
pub const SEC_OID_PKCS9_CONTENT_TYPE: SECOidTag = 33;
pub const SEC_OID_PKCS9_UNSTRUCTURED_NAME: SECOidTag = 32;
pub const SEC_OID_PKCS9_EMAIL_ADDRESS: SECOidTag = 31;
pub const SEC_OID_PKCS7_ENCRYPTED_DATA: SECOidTag = 30;
pub const SEC_OID_PKCS7_DIGESTED_DATA: SECOidTag = 29;
pub const SEC_OID_PKCS7_SIGNED_ENVELOPED_DATA: SECOidTag = 28;
pub const SEC_OID_PKCS7_ENVELOPED_DATA: SECOidTag = 27;
pub const SEC_OID_PKCS7_SIGNED_DATA: SECOidTag = 26;
pub const SEC_OID_PKCS7_DATA: SECOidTag = 25;
pub const SEC_OID_PKCS7: SECOidTag = 24;
pub const SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC: SECOidTag = 23;
pub const SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC: SECOidTag = 22;
pub const SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC: SECOidTag = 21;
pub const SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION: SECOidTag = 20;
pub const SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION: SECOidTag = 19;
pub const SEC_OID_PKCS1_MD4_WITH_RSA_ENCRYPTION: SECOidTag = 18;
pub const SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION: SECOidTag = 17;
pub const SEC_OID_PKCS1_RSA_ENCRYPTION: SECOidTag = 16;
pub const SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE: SECOidTag = 15;
pub const SEC_OID_DES_EDE: SECOidTag = 14;
pub const SEC_OID_DES_MAC: SECOidTag = 13;
pub const SEC_OID_DES_CFB: SECOidTag = 12;
pub const SEC_OID_DES_OFB: SECOidTag = 11;
pub const SEC_OID_DES_CBC: SECOidTag = 10;
pub const SEC_OID_DES_ECB: SECOidTag = 9;
pub const SEC_OID_RC5_CBC_PAD: SECOidTag = 8;
pub const SEC_OID_DES_EDE3_CBC: SECOidTag = 7;
pub const SEC_OID_RC4: SECOidTag = 6;
pub const SEC_OID_RC2_CBC: SECOidTag = 5;
pub const SEC_OID_SHA1: SECOidTag = 4;
pub const SEC_OID_MD5: SECOidTag = 3;
pub const SEC_OID_MD4: SECOidTag = 2;
pub const SEC_OID_MD2: SECOidTag = 1;
pub const SEC_OID_UNKNOWN: SECOidTag = 0;
pub const SSL_ERROR_REVOKED_CERT_ALERT: nss_C2RustUnnamed_19 = -12270;
pub const SSL_ERROR_EXPIRED_CERT_ALERT: nss_C2RustUnnamed_19 = -12269;
pub const SSL_ERROR_BAD_CERT_ALERT: nss_C2RustUnnamed_19 = -12271;
pub type PRLanguageCode = PRUint32;
pub type CERTCertificate = CERTCertificateStr;
pub type CERTCertDistrust = CERTCertDistrustStr;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_ULONG = libc::c_ulong;
pub type PK11SlotInfo = PK11SlotInfoStr;
pub type CERTAuthKeyID = CERTAuthKeyIDStr;
pub type CERTGeneralName = CERTGeneralNameStr;
pub type PRCList = PRCListStr;
pub type OtherName = OtherNameStr;
pub type CERTName = CERTNameStr;
pub type CERTRDN = CERTRDNStr;
pub type CERTAVA = CERTAVAStr;
pub type PRUword = libc::c_ulong;
pub type CERTGeneralNameType = CERTGeneralNameTypeEnum;
pub type CERTGeneralNameTypeEnum = libc::c_uint;
pub const certRegisterID: CERTGeneralNameTypeEnum = 9;
pub const certIPAddress: CERTGeneralNameTypeEnum = 8;
pub const certURI: CERTGeneralNameTypeEnum = 7;
pub const certEDIPartyName: CERTGeneralNameTypeEnum = 6;
pub const certDirectoryName: CERTGeneralNameTypeEnum = 5;
pub const certX400Address: CERTGeneralNameTypeEnum = 4;
pub const certDNSName: CERTGeneralNameTypeEnum = 3;
pub const certRFC822Name: CERTGeneralNameTypeEnum = 2;
pub const certOtherName: CERTGeneralNameTypeEnum = 1;
pub type CERTSubjectList = CERTSubjectListStr;
pub type CERTSubjectNode = CERTSubjectNodeStr;
pub type CERTCertTrust = CERTCertTrustStr;
pub type CERTOKDomainName = CERTOKDomainNameStr;
pub type CERTCertDBHandle = NSSTrustDomainStr;
pub type CERTCertExtension = CERTCertExtensionStr;
pub type CERTSubjectPublicKeyInfo = CERTSubjectPublicKeyInfoStr;
pub type SECAlgorithmID = SECAlgorithmIDStr;
pub type CERTValidity = CERTValidityStr;
pub type CERTSignedData = CERTSignedDataStr;
pub type SECKEYPublicKey = SECKEYPublicKeyStr;
pub type SECKEYECPublicKey = SECKEYECPublicKeyStr;
pub type ECPointEncoding = libc::c_uint;
pub const ECPoint_Undefined: ECPointEncoding = 2;
pub const ECPoint_XOnly: ECPointEncoding = 1;
pub const ECPoint_Uncompressed: ECPointEncoding = 0;
pub type SECKEYECParams = SECItem;
pub type SECKEYFortezzaPublicKey = SECKEYFortezzaPublicKeyStr;
pub type SECKEYPQGParams = SECKEYPQGParamsStr;
pub type SECKEYKEAPublicKey = SECKEYKEAPublicKeyStr;
pub type SECKEYKEAParams = SECKEYKEAParamsStr;
pub type SECKEYDHPublicKey = SECKEYDHPublicKeyStr;
pub type SECKEYDSAPublicKey = SECKEYDSAPublicKeyStr;
pub type SECKEYRSAPublicKey = SECKEYRSAPublicKeyStr;
pub type KeyType = libc::c_uint;
pub const rsaOaepKey: KeyType = 8;
pub const rsaPssKey: KeyType = 7;
pub const ecKey: KeyType = 6;
pub const keaKey: KeyType = 5;
pub const dhKey: KeyType = 4;
pub const fortezzaKey: KeyType = 3;
pub const dsaKey: KeyType = 2;
pub const rsaKey: KeyType = 1;
pub const nullKey: KeyType = 0;
pub const SECEqual: _SECComparison = 0;
pub type SECComparison = _SECComparison;
pub type _SECComparison = libc::c_int;
pub const SECGreaterThan: _SECComparison = 1;
pub const SECLessThan: _SECComparison = -1;
pub type SECCertUsage = SECCertUsageEnum;
pub type SECCertUsageEnum = libc::c_uint;
pub const certUsageIPsec: SECCertUsageEnum = 12;
pub const certUsageAnyCA: SECCertUsageEnum = 11;
pub const certUsageStatusResponder: SECCertUsageEnum = 10;
pub const certUsageProtectedObjectSigner: SECCertUsageEnum = 9;
pub const certUsageVerifyCA: SECCertUsageEnum = 8;
pub const certUsageUserCertImport: SECCertUsageEnum = 7;
pub const certUsageObjectSigner: SECCertUsageEnum = 6;
pub const certUsageEmailRecipient: SECCertUsageEnum = 5;
pub const certUsageEmailSigner: SECCertUsageEnum = 4;
pub const certUsageSSLCA: SECCertUsageEnum = 3;
pub const certUsageSSLServerWithStepUp: SECCertUsageEnum = 2;
pub const certUsageSSLServer: SECCertUsageEnum = 1;
pub const certUsageSSLClient: SECCertUsageEnum = 0;
pub type PRInt8 = libc::c_schar;
pub type PRTimeParamFn = Option::<
    unsafe extern "C" fn(*const PRExplodedTime) -> PRTimeParameters,
>;
pub type SSLCipherSuiteInfo = SSLCipherSuiteInfoStr;
pub type SSLHashType = libc::c_uint;
pub const ssl_hash_sha512: SSLHashType = 6;
pub const ssl_hash_sha384: SSLHashType = 5;
pub const ssl_hash_sha256: SSLHashType = 4;
pub const ssl_hash_sha224: SSLHashType = 3;
pub const ssl_hash_sha1: SSLHashType = 2;
pub const ssl_hash_md5: SSLHashType = 1;
pub const ssl_hash_none: SSLHashType = 0;
pub type SSLAuthType = libc::c_uint;
pub const ssl_auth_size: SSLAuthType = 11;
pub const ssl_auth_tls13_any: SSLAuthType = 10;
pub const ssl_auth_psk: SSLAuthType = 9;
pub const ssl_auth_rsa_pss: SSLAuthType = 8;
pub const ssl_auth_rsa_sign: SSLAuthType = 7;
pub const ssl_auth_ecdh_ecdsa: SSLAuthType = 6;
pub const ssl_auth_ecdh_rsa: SSLAuthType = 5;
pub const ssl_auth_ecdsa: SSLAuthType = 4;
pub const ssl_auth_kea: SSLAuthType = 3;
pub const ssl_auth_dsa: SSLAuthType = 2;
pub const ssl_auth_rsa_decrypt: SSLAuthType = 1;
pub const ssl_auth_null: SSLAuthType = 0;
pub type SSLMACAlgorithm = libc::c_uint;
pub const ssl_hmac_sha384: SSLMACAlgorithm = 7;
pub const ssl_mac_aead: SSLMACAlgorithm = 6;
pub const ssl_hmac_sha256: SSLMACAlgorithm = 5;
pub const ssl_hmac_sha: SSLMACAlgorithm = 4;
pub const ssl_hmac_md5: SSLMACAlgorithm = 3;
pub const ssl_mac_sha: SSLMACAlgorithm = 2;
pub const ssl_mac_md5: SSLMACAlgorithm = 1;
pub const ssl_mac_null: SSLMACAlgorithm = 0;
pub type SSLCipherAlgorithm = libc::c_uint;
pub const ssl_calg_chacha20: SSLCipherAlgorithm = 11;
pub const ssl_calg_aes_gcm: SSLCipherAlgorithm = 10;
pub const ssl_calg_seed: SSLCipherAlgorithm = 9;
pub const ssl_calg_camellia: SSLCipherAlgorithm = 8;
pub const ssl_calg_aes: SSLCipherAlgorithm = 7;
pub const ssl_calg_fortezza: SSLCipherAlgorithm = 6;
pub const ssl_calg_idea: SSLCipherAlgorithm = 5;
pub const ssl_calg_3des: SSLCipherAlgorithm = 4;
pub const ssl_calg_des: SSLCipherAlgorithm = 3;
pub const ssl_calg_rc2: SSLCipherAlgorithm = 2;
pub const ssl_calg_rc4: SSLCipherAlgorithm = 1;
pub const ssl_calg_null: SSLCipherAlgorithm = 0;
pub type SSLKEAType = libc::c_uint;
pub const ssl_kea_size: SSLKEAType = 8;
pub const ssl_kea_tls13_any: SSLKEAType = 7;
pub const ssl_kea_dh_psk: SSLKEAType = 6;
pub const ssl_kea_ecdh_psk: SSLKEAType = 5;
pub const ssl_kea_ecdh: SSLKEAType = 4;
pub const ssl_kea_fortezza: SSLKEAType = 3;
pub const ssl_kea_dh: SSLKEAType = 2;
pub const ssl_kea_rsa: SSLKEAType = 1;
pub const ssl_kea_null: SSLKEAType = 0;
pub type SSLChannelInfo = SSLChannelInfoStr;
pub type SSLNamedGroup = libc::c_uint;
pub const ssl_grp_ffdhe_custom: SSLNamedGroup = 65538;
pub const ssl_grp_none: SSLNamedGroup = 65537;
pub const ssl_grp_ffdhe_8192: SSLNamedGroup = 260;
pub const ssl_grp_ffdhe_6144: SSLNamedGroup = 259;
pub const ssl_grp_ffdhe_4096: SSLNamedGroup = 258;
pub const ssl_grp_ffdhe_3072: SSLNamedGroup = 257;
pub const ssl_grp_ffdhe_2048: SSLNamedGroup = 256;
pub const ssl_grp_ec_curve25519: SSLNamedGroup = 29;
pub const ssl_grp_ec_secp521r1: SSLNamedGroup = 25;
pub const ssl_grp_ec_secp384r1: SSLNamedGroup = 24;
pub const ssl_grp_ec_secp256r1: SSLNamedGroup = 23;
pub const ssl_grp_ec_secp256k1: SSLNamedGroup = 22;
pub const ssl_grp_ec_secp224r1: SSLNamedGroup = 21;
pub const ssl_grp_ec_secp224k1: SSLNamedGroup = 20;
pub const ssl_grp_ec_secp192r1: SSLNamedGroup = 19;
pub const ssl_grp_ec_secp192k1: SSLNamedGroup = 18;
pub const ssl_grp_ec_secp160r2: SSLNamedGroup = 17;
pub const ssl_grp_ec_secp160r1: SSLNamedGroup = 16;
pub const ssl_grp_ec_secp160k1: SSLNamedGroup = 15;
pub const ssl_grp_ec_sect571r1: SSLNamedGroup = 14;
pub const ssl_grp_ec_sect571k1: SSLNamedGroup = 13;
pub const ssl_grp_ec_sect409r1: SSLNamedGroup = 12;
pub const ssl_grp_ec_sect409k1: SSLNamedGroup = 11;
pub const ssl_grp_ec_sect283r1: SSLNamedGroup = 10;
pub const ssl_grp_ec_sect283k1: SSLNamedGroup = 9;
pub const ssl_grp_ec_sect239k1: SSLNamedGroup = 8;
pub const ssl_grp_ec_sect233r1: SSLNamedGroup = 7;
pub const ssl_grp_ec_sect233k1: SSLNamedGroup = 6;
pub const ssl_grp_ec_sect193r2: SSLNamedGroup = 5;
pub const ssl_grp_ec_sect193r1: SSLNamedGroup = 4;
pub const ssl_grp_ec_sect163r2: SSLNamedGroup = 3;
pub const ssl_grp_ec_sect163r1: SSLNamedGroup = 2;
pub const ssl_grp_ec_sect163k1: SSLNamedGroup = 1;
pub type SSLSignatureScheme = libc::c_uint;
pub const ssl_sig_rsa_pkcs1_sha1md5: SSLSignatureScheme = 65793;
pub const ssl_sig_ecdsa_sha1: SSLSignatureScheme = 515;
pub const ssl_sig_dsa_sha512: SSLSignatureScheme = 1538;
pub const ssl_sig_dsa_sha384: SSLSignatureScheme = 1282;
pub const ssl_sig_dsa_sha256: SSLSignatureScheme = 1026;
pub const ssl_sig_dsa_sha1: SSLSignatureScheme = 514;
pub const ssl_sig_rsa_pss_pss_sha512: SSLSignatureScheme = 2059;
pub const ssl_sig_rsa_pss_pss_sha384: SSLSignatureScheme = 2058;
pub const ssl_sig_rsa_pss_pss_sha256: SSLSignatureScheme = 2057;
pub const ssl_sig_ed448: SSLSignatureScheme = 2056;
pub const ssl_sig_ed25519: SSLSignatureScheme = 2055;
pub const ssl_sig_rsa_pss_rsae_sha512: SSLSignatureScheme = 2054;
pub const ssl_sig_rsa_pss_rsae_sha384: SSLSignatureScheme = 2053;
pub const ssl_sig_rsa_pss_rsae_sha256: SSLSignatureScheme = 2052;
pub const ssl_sig_ecdsa_secp521r1_sha512: SSLSignatureScheme = 1539;
pub const ssl_sig_ecdsa_secp384r1_sha384: SSLSignatureScheme = 1283;
pub const ssl_sig_ecdsa_secp256r1_sha256: SSLSignatureScheme = 1027;
pub const ssl_sig_rsa_pkcs1_sha512: SSLSignatureScheme = 1537;
pub const ssl_sig_rsa_pkcs1_sha384: SSLSignatureScheme = 1281;
pub const ssl_sig_rsa_pkcs1_sha256: SSLSignatureScheme = 1025;
pub const ssl_sig_rsa_pkcs1_sha1: SSLSignatureScheme = 513;
pub const ssl_sig_none: SSLSignatureScheme = 0;
pub type SSLCompressionMethod = libc::c_uint;
pub const ssl_compression_deflate: SSLCompressionMethod = 1;
pub const ssl_compression_null: SSLCompressionMethod = 0;
pub const SSL_ERROR_BAD_CERT_DOMAIN: nss_C2RustUnnamed_19 = -12276;
pub type SSLExtensionType = libc::c_uint;
pub const ssl_tls13_encrypted_sni_xtn: SSLExtensionType = 65486;
pub const ssl_tls13_short_header_xtn: SSLExtensionType = 65283;
pub const ssl_delegated_credentials_xtn: SSLExtensionType = 65282;
pub const ssl_renegotiation_info_xtn: SSLExtensionType = 65281;
pub const ssl_next_proto_nego_xtn: SSLExtensionType = 13172;
pub const ssl_tls13_key_share_xtn: SSLExtensionType = 51;
pub const ssl_signature_algorithms_cert_xtn: SSLExtensionType = 50;
pub const ssl_tls13_post_handshake_auth_xtn: SSLExtensionType = 49;
pub const ssl_tls13_certificate_authorities_xtn: SSLExtensionType = 47;
pub const ssl_tls13_ticket_early_data_info_xtn: SSLExtensionType = 46;
pub const ssl_tls13_psk_key_exchange_modes_xtn: SSLExtensionType = 45;
pub const ssl_tls13_cookie_xtn: SSLExtensionType = 44;
pub const ssl_tls13_supported_versions_xtn: SSLExtensionType = 43;
pub const ssl_tls13_early_data_xtn: SSLExtensionType = 42;
pub const ssl_tls13_pre_shared_key_xtn: SSLExtensionType = 41;
pub const ssl_session_ticket_xtn: SSLExtensionType = 35;
pub const ssl_record_size_limit_xtn: SSLExtensionType = 28;
pub const ssl_extended_master_secret_xtn: SSLExtensionType = 23;
pub const ssl_padding_xtn: SSLExtensionType = 21;
pub const ssl_signed_cert_timestamp_xtn: SSLExtensionType = 18;
pub const ssl_app_layer_protocol_xtn: SSLExtensionType = 16;
pub const ssl_use_srtp_xtn: SSLExtensionType = 14;
pub const ssl_signature_algorithms_xtn: SSLExtensionType = 13;
pub const ssl_ec_point_formats_xtn: SSLExtensionType = 11;
pub const ssl_supported_groups_xtn: SSLExtensionType = 10;
pub const ssl_cert_status_xtn: SSLExtensionType = 5;
pub const ssl_server_name_xtn: SSLExtensionType = 0;
pub type SSLCanFalseStartCallback = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *mut libc::c_void, *mut PRBool) -> SECStatus,
>;
pub type PROsfd = PRInt32;
pub type SECKEYPrivateKey = SECKEYPrivateKeyStr;
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;
pub type PK11ObjectType = libc::c_uint;
pub const PK11_TypeSymKey: PK11ObjectType = 4;
pub const PK11_TypeCert: PK11ObjectType = 3;
pub const PK11_TypePubKey: PK11ObjectType = 2;
pub const PK11_TypePrivKey: PK11ObjectType = 1;
pub const PK11_TypeGeneric: PK11ObjectType = 0;
pub type SSLGetClientAuthData = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut PRFileDesc,
        *mut CERTDistNames,
        *mut *mut CERTCertificate,
        *mut *mut SECKEYPrivateKey,
    ) -> SECStatus,
>;
pub type CERTDistNames = CERTDistNamesStr;
pub const SEC_ERROR_UNKNOWN_CERT: nss_C2RustUnnamed_20 = -8077;
pub const SEC_ERROR_BAD_PASSWORD: nss_C2RustUnnamed_20 = -8177;
pub type SECMODModule = SECMODModuleStr;
pub type CK_BYTE = libc::c_uchar;
pub type SECMODModuleID = libc::c_ulong;
pub type PK11PreSlotInfo = NSSUTILPreSlotInfoStr;
pub const SEC_ERROR_BAD_KEY: nss_C2RustUnnamed_20 = -8178;
pub type CK_OBJECT_CLASS = CK_ULONG;
pub type CK_VOID_PTR = *mut libc::c_void;
pub type CK_BBOOL = CK_BYTE;
pub type CERTSignedCrl = CERTSignedCrlStr;
pub type CERTCrl = CERTCrlStr;
pub type CERTCrlEntry = CERTCrlEntryStr;
pub type PRDirFlags = libc::c_uint;
pub const PR_SKIP_HIDDEN: PRDirFlags = 4;
pub const PR_SKIP_BOTH: PRDirFlags = 3;
pub const PR_SKIP_DOT_DOT: PRDirFlags = 2;
pub const PR_SKIP_DOT: PRDirFlags = 1;
pub const PR_SKIP_NONE: PRDirFlags = 0;
pub const SSL_NEXT_PROTO_NEGOTIATED: SSLNextProtoState = 1;
pub const SSL_NEXT_PROTO_SELECTED: SSLNextProtoState = 3;
pub const SSL_NEXT_PROTO_NO_OVERLAP: SSLNextProtoState = 2;
pub const SSL_NEXT_PROTO_NO_SUPPORT: SSLNextProtoState = 0;
pub const SSL_NEXT_PROTO_EARLY_VALUE: SSLNextProtoState = 4;
pub type SSLNextProtoState = libc::c_uint;
pub type SSLHandshakeCallback = Option::<
    unsafe extern "C" fn(*mut PRFileDesc, *mut libc::c_void) -> (),
>;
pub type SSLBadCertHandler = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut PRFileDesc) -> SECStatus,
>;
pub type SECItemArray = SECItemArrayStr;
pub type SSLAuthCertificate = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut PRFileDesc, PRBool, PRBool) -> SECStatus,
>;
pub type SSLVersionRange = SSLVersionRangeStr;
pub type SSLProtocolVariant = libc::c_uint;
pub const ssl_variant_datagram: SSLProtocolVariant = 1;
pub const ssl_variant_stream: SSLProtocolVariant = 0;
pub type PK11PasswordFunc = Option::<
    unsafe extern "C" fn(
        *mut PK11SlotInfo,
        PRBool,
        *mut libc::c_void,
    ) -> *mut libc::c_char,
>;
pub type PRThreadPriority = libc::c_uint;
pub const PR_PRIORITY_LAST: PRThreadPriority = 3;
pub const PR_PRIORITY_URGENT: PRThreadPriority = 3;
pub const PR_PRIORITY_HIGH: PRThreadPriority = 2;
pub const PR_PRIORITY_NORMAL: PRThreadPriority = 1;
pub const PR_PRIORITY_LOW: PRThreadPriority = 0;
pub const PR_PRIORITY_FIRST: PRThreadPriority = 0;
pub type PRThreadType = libc::c_uint;
pub const PR_SYSTEM_THREAD: PRThreadType = 1;
pub const PR_USER_THREAD: PRThreadType = 0;
pub type nss_C2RustUnnamed_19 = libc::c_int;
pub const SSL_ERROR_END_OF_LIST: nss_C2RustUnnamed_19 = -12102;
pub const SSL_ERROR_DC_EXPIRED: nss_C2RustUnnamed_19 = -12103;
pub const SSL_ERROR_DC_INVALID_KEY_USAGE: nss_C2RustUnnamed_19 = -12104;
pub const SSL_ERROR_DC_BAD_SIGNATURE: nss_C2RustUnnamed_19 = -12105;
pub const SSL_ERROR_DC_CERT_VERIFY_ALG_MISMATCH: nss_C2RustUnnamed_19 = -12106;
pub const SSL_ERROR_RX_CERTIFICATE_REQUIRED_ALERT: nss_C2RustUnnamed_19 = -12107;
pub const SSL_ERROR_MISSING_POST_HANDSHAKE_AUTH_EXTENSION: nss_C2RustUnnamed_19 = -12108;
pub const SSL_ERROR_RX_UNEXPECTED_RECORD_TYPE: nss_C2RustUnnamed_19 = -12109;
pub const SSL_ERROR_MISSING_ESNI_EXTENSION: nss_C2RustUnnamed_19 = -12110;
pub const SSL_ERROR_RX_MALFORMED_ESNI_EXTENSION: nss_C2RustUnnamed_19 = -12111;
pub const SSL_ERROR_RX_MALFORMED_ESNI_KEYS: nss_C2RustUnnamed_19 = -12112;
pub const SSL_ERROR_DH_KEY_TOO_LONG: nss_C2RustUnnamed_19 = -12113;
pub const SSL_ERROR_RX_MALFORMED_DTLS_ACK: nss_C2RustUnnamed_19 = -12114;
pub const SSL_ERROR_BAD_RESUMPTION_TOKEN_ERROR: nss_C2RustUnnamed_19 = -12115;
pub const SSL_ERROR_HANDSHAKE_FAILED: nss_C2RustUnnamed_19 = -12116;
pub const SSL_ERROR_TOO_MANY_KEY_UPDATES: nss_C2RustUnnamed_19 = -12117;
pub const SSL_ERROR_RX_MALFORMED_KEY_UPDATE: nss_C2RustUnnamed_19 = -12118;
pub const SSL_ERROR_RX_UNEXPECTED_KEY_UPDATE: nss_C2RustUnnamed_19 = -12119;
pub const SSL_ERROR_MISSING_COOKIE_EXTENSION: nss_C2RustUnnamed_19 = -12120;
pub const SSL_ERROR_NO_TIMERS_FOUND: nss_C2RustUnnamed_19 = -12121;
pub const SSL_ERROR_APP_CALLBACK_ERROR: nss_C2RustUnnamed_19 = -12122;
pub const SSL_ERROR_APPLICATION_ABORT: nss_C2RustUnnamed_19 = -12123;
pub const SSL_ERROR_UNSUPPORTED_EXPERIMENTAL_API: nss_C2RustUnnamed_19 = -12124;
pub const SSL_ERROR_RX_MALFORMED_END_OF_EARLY_DATA: nss_C2RustUnnamed_19 = -12125;
pub const SSL_ERROR_RX_UNEXPECTED_END_OF_EARLY_DATA: nss_C2RustUnnamed_19 = -12126;
pub const SSL_ERROR_TOO_MUCH_EARLY_DATA: nss_C2RustUnnamed_19 = -12127;
pub const SSL_ERROR_DOWNGRADE_WITH_EARLY_DATA: nss_C2RustUnnamed_19 = -12128;
pub const SSL_ERROR_MISSING_PSK_KEY_EXCHANGE_MODES: nss_C2RustUnnamed_19 = -12129;
pub const SSL_ERROR_MALFORMED_PSK_KEY_EXCHANGE_MODES: nss_C2RustUnnamed_19 = -12130;
pub const SSL_ERROR_MISSING_SIGNATURE_ALGORITHMS_EXTENSION: nss_C2RustUnnamed_19 = -12131;
pub const SSL_ERROR_BAD_2ND_CLIENT_HELLO: nss_C2RustUnnamed_19 = -12132;
pub const SSL_ERROR_RX_MALFORMED_HELLO_RETRY_REQUEST: nss_C2RustUnnamed_19 = -12133;
pub const SSL_ERROR_RX_UNEXPECTED_HELLO_RETRY_REQUEST: nss_C2RustUnnamed_19 = -12134;
pub const SSL_ERROR_TOO_MANY_RECORDS: nss_C2RustUnnamed_19 = -12135;
pub const SSL_ERROR_MISSING_SUPPORTED_GROUPS_EXTENSION: nss_C2RustUnnamed_19 = -12136;
pub const SSL_ERROR_RX_UNEXPECTED_EXTENSION: nss_C2RustUnnamed_19 = -12137;
pub const SSL_ERROR_MISSING_ALPN_EXTENSION: nss_C2RustUnnamed_19 = -12138;
pub const SSL_ERROR_END_OF_EARLY_DATA_ALERT: nss_C2RustUnnamed_19 = -12139;
pub const SSL_ERROR_MALFORMED_EARLY_DATA: nss_C2RustUnnamed_19 = -12140;
pub const SSL_ERROR_MALFORMED_PRE_SHARED_KEY: nss_C2RustUnnamed_19 = -12141;
pub const SSL_ERROR_RX_MALFORMED_ENCRYPTED_EXTENSIONS: nss_C2RustUnnamed_19 = -12142;
pub const SSL_ERROR_EXTENSION_DISALLOWED_FOR_VERSION: nss_C2RustUnnamed_19 = -12143;
pub const SSL_ERROR_KEY_EXCHANGE_FAILURE: nss_C2RustUnnamed_19 = -12144;
pub const SSL_ERROR_MISSING_EXTENSION_ALERT: nss_C2RustUnnamed_19 = -12145;
pub const SSL_ERROR_RX_UNEXPECTED_ENCRYPTED_EXTENSIONS: nss_C2RustUnnamed_19 = -12146;
pub const SSL_ERROR_RX_MALFORMED_DHE_KEY_SHARE: nss_C2RustUnnamed_19 = -12147;
pub const SSL_ERROR_RX_MALFORMED_ECDHE_KEY_SHARE: nss_C2RustUnnamed_19 = -12148;
pub const SSL_ERROR_MISSING_KEY_SHARE: nss_C2RustUnnamed_19 = -12149;
pub const SSL_ERROR_RX_MALFORMED_KEY_SHARE: nss_C2RustUnnamed_19 = -12150;
pub const SSL_ERROR_UNEXPECTED_EXTENDED_MASTER_SECRET: nss_C2RustUnnamed_19 = -12151;
pub const SSL_ERROR_MISSING_EXTENDED_MASTER_SECRET: nss_C2RustUnnamed_19 = -12152;
pub const SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM: nss_C2RustUnnamed_19 = -12153;
pub const SSL_ERROR_NO_SUPPORTED_SIGNATURE_ALGORITHM: nss_C2RustUnnamed_19 = -12154;
pub const SSL_ERROR_RX_SHORT_DTLS_READ: nss_C2RustUnnamed_19 = -12155;
pub const SSL_ERROR_WEAK_SERVER_CERT_KEY: nss_C2RustUnnamed_19 = -12156;
pub const SSL_ERROR_INAPPROPRIATE_FALLBACK_ALERT: nss_C2RustUnnamed_19 = -12157;
pub const SSL_ERROR_NEXT_PROTOCOL_NO_PROTOCOL: nss_C2RustUnnamed_19 = -12158;
pub const SSL_ERROR_NEXT_PROTOCOL_NO_CALLBACK: nss_C2RustUnnamed_19 = -12159;
pub const SSL_ERROR_INCORRECT_SIGNATURE_ALGORITHM: nss_C2RustUnnamed_19 = -12160;
pub const SSL_ERROR_DIGEST_FAILURE: nss_C2RustUnnamed_19 = -12161;
pub const SSL_ERROR_UNSUPPORTED_HASH_ALGORITHM: nss_C2RustUnnamed_19 = -12162;
pub const SSL_ERROR_RX_UNEXPECTED_CERT_STATUS: nss_C2RustUnnamed_19 = -12163;
pub const SSL_ERROR_FEATURE_NOT_SUPPORTED_FOR_VERSION: nss_C2RustUnnamed_19 = -12164;
pub const SSL_ERROR_RX_UNEXPECTED_HELLO_VERIFY_REQUEST: nss_C2RustUnnamed_19 = -12165;
pub const SSL_ERROR_RX_MALFORMED_HELLO_VERIFY_REQUEST: nss_C2RustUnnamed_19 = -12166;
pub const SSL_ERROR_CIPHER_DISALLOWED_FOR_VERSION: nss_C2RustUnnamed_19 = -12167;
pub const SSL_ERROR_INVALID_VERSION_RANGE: nss_C2RustUnnamed_19 = -12168;
pub const SSL_ERROR_FEATURE_NOT_SUPPORTED_FOR_CLIENTS: nss_C2RustUnnamed_19 = -12169;
pub const SSL_ERROR_FEATURE_NOT_SUPPORTED_FOR_SERVERS: nss_C2RustUnnamed_19 = -12170;
pub const SSL_ERROR_FEATURE_NOT_SUPPORTED_FOR_SSL2: nss_C2RustUnnamed_19 = -12171;
pub const SSL_ERROR_NEXT_PROTOCOL_DATA_INVALID: nss_C2RustUnnamed_19 = -12172;
pub const SSL_ERROR_WEAK_SERVER_EPHEMERAL_DH_KEY: nss_C2RustUnnamed_19 = -12173;
pub const SSL_ERROR_RX_UNEXPECTED_UNCOMPRESSED_RECORD: nss_C2RustUnnamed_19 = -12174;
pub const SSL_ERROR_UNSAFE_NEGOTIATION: nss_C2RustUnnamed_19 = -12175;
pub const SSL_ERROR_RENEGOTIATION_NOT_ALLOWED: nss_C2RustUnnamed_19 = -12176;
pub const SSL_ERROR_DECOMPRESSION_FAILURE: nss_C2RustUnnamed_19 = -12177;
pub const SSL_ERROR_RX_MALFORMED_NEW_SESSION_TICKET: nss_C2RustUnnamed_19 = -12178;
pub const SSL_ERROR_RX_UNEXPECTED_NEW_SESSION_TICKET: nss_C2RustUnnamed_19 = -12179;
pub const SSL_ERROR_BAD_CERT_HASH_VALUE_ALERT: nss_C2RustUnnamed_19 = -12180;
pub const SSL_ERROR_BAD_CERT_STATUS_RESPONSE_ALERT: nss_C2RustUnnamed_19 = -12181;
pub const SSL_ERROR_UNRECOGNIZED_NAME_ALERT: nss_C2RustUnnamed_19 = -12182;
pub const SSL_ERROR_CERTIFICATE_UNOBTAINABLE_ALERT: nss_C2RustUnnamed_19 = -12183;
pub const SSL_ERROR_UNSUPPORTED_EXTENSION_ALERT: nss_C2RustUnnamed_19 = -12184;
pub const SSL_ERROR_SERVER_CACHE_NOT_CONFIGURED: nss_C2RustUnnamed_19 = -12185;
pub const SSL_ERROR_NO_RENEGOTIATION_ALERT: nss_C2RustUnnamed_19 = -12186;
pub const SSL_ERROR_USER_CANCELED_ALERT: nss_C2RustUnnamed_19 = -12187;
pub const SSL_ERROR_INTERNAL_ERROR_ALERT: nss_C2RustUnnamed_19 = -12188;
pub const SSL_ERROR_INSUFFICIENT_SECURITY_ALERT: nss_C2RustUnnamed_19 = -12189;
pub const SSL_ERROR_PROTOCOL_VERSION_ALERT: nss_C2RustUnnamed_19 = -12190;
pub const SSL_ERROR_EXPORT_RESTRICTION_ALERT: nss_C2RustUnnamed_19 = -12191;
pub const SSL_ERROR_DECRYPT_ERROR_ALERT: nss_C2RustUnnamed_19 = -12192;
pub const SSL_ERROR_DECODE_ERROR_ALERT: nss_C2RustUnnamed_19 = -12193;
pub const SSL_ERROR_ACCESS_DENIED_ALERT: nss_C2RustUnnamed_19 = -12194;
pub const SSL_ERROR_UNKNOWN_CA_ALERT: nss_C2RustUnnamed_19 = -12195;
pub const SSL_ERROR_RECORD_OVERFLOW_ALERT: nss_C2RustUnnamed_19 = -12196;
pub const SSL_ERROR_DECRYPTION_FAILED_ALERT: nss_C2RustUnnamed_19 = -12197;
pub const SSL_ERROR_SESSION_NOT_FOUND: nss_C2RustUnnamed_19 = -12198;
pub const SSL_ERROR_NO_TRUSTED_SSL_CLIENT_CA: nss_C2RustUnnamed_19 = -12199;
pub const SSL_ERROR_CERT_KEA_MISMATCH: nss_C2RustUnnamed_19 = -12200;
pub const SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE: nss_C2RustUnnamed_19 = -12201;
pub const SSL_ERROR_HANDSHAKE_NOT_COMPLETED: nss_C2RustUnnamed_19 = -12202;
pub const SSL_ERROR_NO_COMPRESSION_OVERLAP: nss_C2RustUnnamed_19 = -12203;
pub const SSL_ERROR_TOKEN_SLOT_NOT_FOUND: nss_C2RustUnnamed_19 = -12204;
pub const SSL_ERROR_TOKEN_INSERTION_REMOVAL: nss_C2RustUnnamed_19 = -12205;
pub const SSL_ERROR_NO_SERVER_KEY_FOR_ALG: nss_C2RustUnnamed_19 = -12206;
pub const SSL_ERROR_SESSION_KEY_GEN_FAILURE: nss_C2RustUnnamed_19 = -12207;
pub const SSL_ERROR_INIT_CIPHER_SUITE_FAILURE: nss_C2RustUnnamed_19 = -12208;
pub const SSL_ERROR_IV_PARAM_FAILURE: nss_C2RustUnnamed_19 = -12209;
pub const SSL_ERROR_PUB_KEY_SIZE_LIMIT_EXCEEDED: nss_C2RustUnnamed_19 = -12210;
pub const SSL_ERROR_SYM_KEY_UNWRAP_FAILURE: nss_C2RustUnnamed_19 = -12211;
pub const SSL_ERROR_SYM_KEY_CONTEXT_FAILURE: nss_C2RustUnnamed_19 = -12212;
pub const SSL_ERROR_MAC_COMPUTATION_FAILURE: nss_C2RustUnnamed_19 = -12213;
pub const SSL_ERROR_SHA_DIGEST_FAILURE: nss_C2RustUnnamed_19 = -12214;
pub const SSL_ERROR_MD5_DIGEST_FAILURE: nss_C2RustUnnamed_19 = -12215;
pub const SSL_ERROR_SOCKET_WRITE_FAILURE: nss_C2RustUnnamed_19 = -12216;
pub const SSL_ERROR_DECRYPTION_FAILURE: nss_C2RustUnnamed_19 = -12217;
pub const SSL_ERROR_ENCRYPTION_FAILURE: nss_C2RustUnnamed_19 = -12218;
pub const SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE: nss_C2RustUnnamed_19 = -12219;
pub const SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE: nss_C2RustUnnamed_19 = -12220;
pub const SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE: nss_C2RustUnnamed_19 = -12221;
pub const SSL_ERROR_SIGN_HASHES_FAILURE: nss_C2RustUnnamed_19 = -12222;
pub const SSL_ERROR_GENERATE_RANDOM_FAILURE: nss_C2RustUnnamed_19 = -12223;
pub const SSL_ERROR_CERTIFICATE_UNKNOWN_ALERT: nss_C2RustUnnamed_19 = -12224;
pub const SSL_ERROR_UNSUPPORTED_CERT_ALERT: nss_C2RustUnnamed_19 = -12225;
pub const SSL_ERROR_ILLEGAL_PARAMETER_ALERT: nss_C2RustUnnamed_19 = -12226;
pub const SSL_ERROR_HANDSHAKE_FAILURE_ALERT: nss_C2RustUnnamed_19 = -12227;
pub const SSL_ERROR_DECOMPRESSION_FAILURE_ALERT: nss_C2RustUnnamed_19 = -12228;
pub const SSL_ERROR_HANDSHAKE_UNEXPECTED_ALERT: nss_C2RustUnnamed_19 = -12229;
pub const SSL_ERROR_CLOSE_NOTIFY_ALERT: nss_C2RustUnnamed_19 = -12230;
pub const SSL_ERROR_RX_UNKNOWN_ALERT: nss_C2RustUnnamed_19 = -12231;
pub const SSL_ERROR_RX_UNKNOWN_HANDSHAKE: nss_C2RustUnnamed_19 = -12232;
pub const SSL_ERROR_RX_UNKNOWN_RECORD_TYPE: nss_C2RustUnnamed_19 = -12233;
pub const SSL_ERROR_RX_UNEXPECTED_APPLICATION_DATA: nss_C2RustUnnamed_19 = -12234;
pub const SSL_ERROR_RX_UNEXPECTED_HANDSHAKE: nss_C2RustUnnamed_19 = -12235;
pub const SSL_ERROR_RX_UNEXPECTED_ALERT: nss_C2RustUnnamed_19 = -12236;
pub const SSL_ERROR_RX_UNEXPECTED_CHANGE_CIPHER: nss_C2RustUnnamed_19 = -12237;
pub const SSL_ERROR_RX_UNEXPECTED_FINISHED: nss_C2RustUnnamed_19 = -12238;
pub const SSL_ERROR_RX_UNEXPECTED_CLIENT_KEY_EXCH: nss_C2RustUnnamed_19 = -12239;
pub const SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY: nss_C2RustUnnamed_19 = -12240;
pub const SSL_ERROR_RX_UNEXPECTED_HELLO_DONE: nss_C2RustUnnamed_19 = -12241;
pub const SSL_ERROR_RX_UNEXPECTED_CERT_REQUEST: nss_C2RustUnnamed_19 = -12242;
pub const SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH: nss_C2RustUnnamed_19 = -12243;
pub const SSL_ERROR_RX_UNEXPECTED_CERTIFICATE: nss_C2RustUnnamed_19 = -12244;
pub const SSL_ERROR_RX_UNEXPECTED_SERVER_HELLO: nss_C2RustUnnamed_19 = -12245;
pub const SSL_ERROR_RX_UNEXPECTED_CLIENT_HELLO: nss_C2RustUnnamed_19 = -12246;
pub const SSL_ERROR_RX_UNEXPECTED_HELLO_REQUEST: nss_C2RustUnnamed_19 = -12247;
pub const SSL_ERROR_RX_MALFORMED_APPLICATION_DATA: nss_C2RustUnnamed_19 = -12248;
pub const SSL_ERROR_RX_MALFORMED_HANDSHAKE: nss_C2RustUnnamed_19 = -12249;
pub const SSL_ERROR_RX_MALFORMED_ALERT: nss_C2RustUnnamed_19 = -12250;
pub const SSL_ERROR_RX_MALFORMED_CHANGE_CIPHER: nss_C2RustUnnamed_19 = -12251;
pub const SSL_ERROR_RX_MALFORMED_FINISHED: nss_C2RustUnnamed_19 = -12252;
pub const SSL_ERROR_RX_MALFORMED_CLIENT_KEY_EXCH: nss_C2RustUnnamed_19 = -12253;
pub const SSL_ERROR_RX_MALFORMED_CERT_VERIFY: nss_C2RustUnnamed_19 = -12254;
pub const SSL_ERROR_RX_MALFORMED_HELLO_DONE: nss_C2RustUnnamed_19 = -12255;
pub const SSL_ERROR_RX_MALFORMED_CERT_REQUEST: nss_C2RustUnnamed_19 = -12256;
pub const SSL_ERROR_RX_MALFORMED_SERVER_KEY_EXCH: nss_C2RustUnnamed_19 = -12257;
pub const SSL_ERROR_RX_MALFORMED_CERTIFICATE: nss_C2RustUnnamed_19 = -12258;
pub const SSL_ERROR_RX_MALFORMED_SERVER_HELLO: nss_C2RustUnnamed_19 = -12259;
pub const SSL_ERROR_RX_MALFORMED_CLIENT_HELLO: nss_C2RustUnnamed_19 = -12260;
pub const SSL_ERROR_RX_MALFORMED_HELLO_REQUEST: nss_C2RustUnnamed_19 = -12261;
pub const SSL_ERROR_TX_RECORD_TOO_LONG: nss_C2RustUnnamed_19 = -12262;
pub const SSL_ERROR_RX_RECORD_TOO_LONG: nss_C2RustUnnamed_19 = -12263;
pub const SSL_ERROR_BAD_BLOCK_PADDING: nss_C2RustUnnamed_19 = -12264;
pub const SSL_ERROR_NO_CIPHERS_SUPPORTED: nss_C2RustUnnamed_19 = -12265;
pub const SSL_ERROR_UNKNOWN_CIPHER_SUITE: nss_C2RustUnnamed_19 = -12266;
pub const SSL_ERROR_FORTEZZA_PQG: nss_C2RustUnnamed_19 = -12267;
pub const SSL_ERROR_SSL_DISABLED: nss_C2RustUnnamed_19 = -12268;
pub const SSL_ERROR_BAD_MAC_ALERT: nss_C2RustUnnamed_19 = -12272;
pub const SSL_ERROR_BAD_MAC_READ: nss_C2RustUnnamed_19 = -12273;
pub const SSL_ERROR_SSL2_DISABLED: nss_C2RustUnnamed_19 = -12274;
pub const SSL_ERROR_POST_WARNING: nss_C2RustUnnamed_19 = -12275;
pub const SSL_ERROR_WRONG_CERTIFICATE: nss_C2RustUnnamed_19 = -12277;
pub const SSL_ERROR_UNUSED_10: nss_C2RustUnnamed_19 = -12278;
pub const SSL_ERROR_UNSUPPORTED_VERSION: nss_C2RustUnnamed_19 = -12279;
pub const SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE: nss_C2RustUnnamed_19 = -12280;
pub const SSL_ERROR_BAD_SERVER: nss_C2RustUnnamed_19 = -12281;
pub const SSL_ERROR_BAD_CLIENT: nss_C2RustUnnamed_19 = -12282;
pub const SSL_ERROR_UNUSED_5: nss_C2RustUnnamed_19 = -12283;
pub const SSL_ERROR_BAD_CERTIFICATE: nss_C2RustUnnamed_19 = -12284;
pub const SSL_ERROR_NO_CERTIFICATE: nss_C2RustUnnamed_19 = -12285;
pub const SSL_ERROR_NO_CYPHER_OVERLAP: nss_C2RustUnnamed_19 = -12286;
pub const SSL_ERROR_US_ONLY_SERVER: nss_C2RustUnnamed_19 = -12287;
pub const SSL_ERROR_EXPORT_ONLY_SERVER: nss_C2RustUnnamed_19 = -12288;
pub type nss_C2RustUnnamed_20 = libc::c_int;
pub const SEC_ERROR_END_OF_LIST: nss_C2RustUnnamed_20 = -8013;
pub const SEC_ERROR_APPLICATION_CALLBACK_ERROR: nss_C2RustUnnamed_20 = -8014;
pub const SEC_ERROR_LEGACY_DATABASE: nss_C2RustUnnamed_20 = -8015;
pub const SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED: nss_C2RustUnnamed_20 = -8016;
pub const SEC_ERROR_BAD_CRL_DP_URL: nss_C2RustUnnamed_20 = -8017;
pub const SEC_ERROR_UNKNOWN_PKCS11_ERROR: nss_C2RustUnnamed_20 = -8018;
pub const SEC_ERROR_LOCKED_PASSWORD: nss_C2RustUnnamed_20 = -8019;
pub const SEC_ERROR_EXPIRED_PASSWORD: nss_C2RustUnnamed_20 = -8020;
pub const SEC_ERROR_CRL_IMPORT_FAILED: nss_C2RustUnnamed_20 = -8021;
pub const SEC_ERROR_BAD_INFO_ACCESS_METHOD: nss_C2RustUnnamed_20 = -8022;
pub const SEC_ERROR_PKCS11_DEVICE_ERROR: nss_C2RustUnnamed_20 = -8023;
pub const SEC_ERROR_PKCS11_FUNCTION_FAILED: nss_C2RustUnnamed_20 = -8024;
pub const SEC_ERROR_PKCS11_GENERAL_ERROR: nss_C2RustUnnamed_20 = -8025;
pub const SEC_ERROR_LIBPKIX_INTERNAL: nss_C2RustUnnamed_20 = -8026;
pub const SEC_ERROR_BAD_INFO_ACCESS_LOCATION: nss_C2RustUnnamed_20 = -8027;
pub const SEC_ERROR_FAILED_TO_ENCODE_DATA: nss_C2RustUnnamed_20 = -8028;
pub const SEC_ERROR_BAD_LDAP_RESPONSE: nss_C2RustUnnamed_20 = -8029;
pub const SEC_ERROR_BAD_HTTP_RESPONSE: nss_C2RustUnnamed_20 = -8030;
pub const SEC_ERROR_UNKNOWN_AIA_LOCATION_TYPE: nss_C2RustUnnamed_20 = -8031;
pub const SEC_ERROR_POLICY_VALIDATION_FAILED: nss_C2RustUnnamed_20 = -8032;
pub const SEC_ERROR_INVALID_POLICY_MAPPING: nss_C2RustUnnamed_20 = -8033;
pub const SEC_ERROR_OUT_OF_SEARCH_LIMITS: nss_C2RustUnnamed_20 = -8034;
pub const SEC_ERROR_OCSP_BAD_SIGNATURE: nss_C2RustUnnamed_20 = -8035;
pub const SEC_ERROR_OCSP_RESPONDER_CERT_INVALID: nss_C2RustUnnamed_20 = -8036;
pub const SEC_ERROR_TOKEN_NOT_LOGGED_IN: nss_C2RustUnnamed_20 = -8037;
pub const SEC_ERROR_NOT_INITIALIZED: nss_C2RustUnnamed_20 = -8038;
pub const SEC_ERROR_CRL_ALREADY_EXISTS: nss_C2RustUnnamed_20 = -8039;
pub const SEC_ERROR_NO_EVENT: nss_C2RustUnnamed_20 = -8040;
pub const SEC_ERROR_INCOMPATIBLE_PKCS11: nss_C2RustUnnamed_20 = -8041;
pub const SEC_ERROR_UNKNOWN_OBJECT_TYPE: nss_C2RustUnnamed_20 = -8042;
pub const SEC_ERROR_CRL_UNKNOWN_CRITICAL_EXTENSION: nss_C2RustUnnamed_20 = -8043;
pub const SEC_ERROR_CRL_V1_CRITICAL_EXTENSION: nss_C2RustUnnamed_20 = -8044;
pub const SEC_ERROR_CRL_INVALID_VERSION: nss_C2RustUnnamed_20 = -8045;
pub const SEC_ERROR_REVOKED_CERTIFICATE_OCSP: nss_C2RustUnnamed_20 = -8046;
pub const SEC_ERROR_REVOKED_CERTIFICATE_CRL: nss_C2RustUnnamed_20 = -8047;
pub const SEC_ERROR_OCSP_INVALID_SIGNING_CERT: nss_C2RustUnnamed_20 = -8048;
pub const SEC_ERROR_UNRECOGNIZED_OID: nss_C2RustUnnamed_20 = -8049;
pub const SEC_ERROR_UNSUPPORTED_EC_POINT_FORM: nss_C2RustUnnamed_20 = -8050;
pub const SEC_ERROR_UNSUPPORTED_ELLIPTIC_CURVE: nss_C2RustUnnamed_20 = -8051;
pub const SEC_ERROR_EXTRA_INPUT: nss_C2RustUnnamed_20 = -8052;
pub const SEC_ERROR_BUSY: nss_C2RustUnnamed_20 = -8053;
pub const SEC_ERROR_REUSED_ISSUER_AND_SERIAL: nss_C2RustUnnamed_20 = -8054;
pub const SEC_ERROR_CRL_NOT_FOUND: nss_C2RustUnnamed_20 = -8055;
pub const SEC_ERROR_BAD_TEMPLATE: nss_C2RustUnnamed_20 = -8056;
pub const SEC_ERROR_MODULE_STUCK: nss_C2RustUnnamed_20 = -8057;
pub const SEC_ERROR_UNSUPPORTED_MESSAGE_TYPE: nss_C2RustUnnamed_20 = -8058;
pub const SEC_ERROR_DIGEST_NOT_FOUND: nss_C2RustUnnamed_20 = -8059;
pub const SEC_ERROR_OCSP_OLD_RESPONSE: nss_C2RustUnnamed_20 = -8060;
pub const SEC_ERROR_OCSP_FUTURE_RESPONSE: nss_C2RustUnnamed_20 = -8061;
pub const SEC_ERROR_OCSP_UNAUTHORIZED_RESPONSE: nss_C2RustUnnamed_20 = -8062;
pub const SEC_ERROR_OCSP_MALFORMED_RESPONSE: nss_C2RustUnnamed_20 = -8063;
pub const SEC_ERROR_OCSP_NO_DEFAULT_RESPONDER: nss_C2RustUnnamed_20 = -8064;
pub const SEC_ERROR_OCSP_NOT_ENABLED: nss_C2RustUnnamed_20 = -8065;
pub const SEC_ERROR_OCSP_UNKNOWN_CERT: nss_C2RustUnnamed_20 = -8066;
pub const SEC_ERROR_OCSP_UNKNOWN_RESPONSE_STATUS: nss_C2RustUnnamed_20 = -8067;
pub const SEC_ERROR_OCSP_UNAUTHORIZED_REQUEST: nss_C2RustUnnamed_20 = -8068;
pub const SEC_ERROR_OCSP_REQUEST_NEEDS_SIG: nss_C2RustUnnamed_20 = -8069;
pub const SEC_ERROR_OCSP_TRY_SERVER_LATER: nss_C2RustUnnamed_20 = -8070;
pub const SEC_ERROR_OCSP_SERVER_ERROR: nss_C2RustUnnamed_20 = -8071;
pub const SEC_ERROR_OCSP_MALFORMED_REQUEST: nss_C2RustUnnamed_20 = -8072;
pub const SEC_ERROR_OCSP_BAD_HTTP_RESPONSE: nss_C2RustUnnamed_20 = -8073;
pub const SEC_ERROR_OCSP_UNKNOWN_RESPONSE_TYPE: nss_C2RustUnnamed_20 = -8074;
pub const SEC_ERROR_CERT_BAD_ACCESS_LOCATION: nss_C2RustUnnamed_20 = -8075;
pub const SEC_ERROR_UNKNOWN_SIGNER: nss_C2RustUnnamed_20 = -8076;
pub const SEC_ERROR_CRL_NOT_YET_VALID: nss_C2RustUnnamed_20 = -8078;
pub const SEC_ERROR_KRL_NOT_YET_VALID: nss_C2RustUnnamed_20 = -8079;
pub const SEC_ERROR_CERT_NOT_IN_NAME_SPACE: nss_C2RustUnnamed_20 = -8080;
pub const SEC_ERROR_CKL_CONFLICT: nss_C2RustUnnamed_20 = -8081;
pub const SEC_ERROR_OLD_KRL: nss_C2RustUnnamed_20 = -8082;
pub const SEC_ERROR_JS_DEL_MOD_FAILURE: nss_C2RustUnnamed_20 = -8083;
pub const SEC_ERROR_JS_ADD_MOD_FAILURE: nss_C2RustUnnamed_20 = -8084;
pub const SEC_ERROR_JS_INVALID_DLL: nss_C2RustUnnamed_20 = -8085;
pub const SEC_ERROR_JS_INVALID_MODULE_NAME: nss_C2RustUnnamed_20 = -8086;
pub const SEC_ERROR_CANNOT_MOVE_SENSITIVE_KEY: nss_C2RustUnnamed_20 = -8087;
pub const SEC_ERROR_NOT_FORTEZZA_ISSUER: nss_C2RustUnnamed_20 = -8088;
pub const SEC_ERROR_BAD_NICKNAME: nss_C2RustUnnamed_20 = -8089;
pub const SEC_ERROR_RETRY_OLD_PASSWORD: nss_C2RustUnnamed_20 = -8090;
pub const SEC_ERROR_INVALID_PASSWORD: nss_C2RustUnnamed_20 = -8091;
pub const SEC_ERROR_KEYGEN_FAIL: nss_C2RustUnnamed_20 = -8092;
pub const SEC_ERROR_PKCS12_KEY_DATABASE_NOT_INITIALIZED: nss_C2RustUnnamed_20 = -8093;
pub const SEC_ERROR_PKCS12_UNABLE_TO_READ: nss_C2RustUnnamed_20 = -8094;
pub const SEC_ERROR_PKCS12_UNABLE_TO_WRITE: nss_C2RustUnnamed_20 = -8095;
pub const SEC_ERROR_PKCS12_UNABLE_TO_EXPORT_KEY: nss_C2RustUnnamed_20 = -8096;
pub const SEC_ERROR_PKCS12_UNABLE_TO_LOCATE_OBJECT_BY_NAME: nss_C2RustUnnamed_20 = -8097;
pub const SEC_ERROR_PKCS12_IMPORTING_CERT_CHAIN: nss_C2RustUnnamed_20 = -8098;
pub const SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY: nss_C2RustUnnamed_20 = -8099;
pub const SEC_ERROR_CERT_ADDR_MISMATCH: nss_C2RustUnnamed_20 = -8100;
pub const SEC_ERROR_INADEQUATE_CERT_TYPE: nss_C2RustUnnamed_20 = -8101;
pub const SEC_ERROR_INADEQUATE_KEY_USAGE: nss_C2RustUnnamed_20 = -8102;
pub const SEC_ERROR_MESSAGE_SEND_ABORTED: nss_C2RustUnnamed_20 = -8103;
pub const SEC_ERROR_PKCS12_DUPLICATE_DATA: nss_C2RustUnnamed_20 = -8104;
pub const SEC_ERROR_USER_CANCELLED: nss_C2RustUnnamed_20 = -8105;
pub const SEC_ERROR_PKCS12_CERT_COLLISION: nss_C2RustUnnamed_20 = -8106;
pub const SEC_ERROR_PKCS12_PRIVACY_PASSWORD_INCORRECT: nss_C2RustUnnamed_20 = -8107;
pub const SEC_ERROR_PKCS12_UNSUPPORTED_VERSION: nss_C2RustUnnamed_20 = -8108;
pub const SEC_ERROR_PKCS12_UNSUPPORTED_PBE_ALGORITHM: nss_C2RustUnnamed_20 = -8109;
pub const SEC_ERROR_PKCS12_CORRUPT_PFX_STRUCTURE: nss_C2RustUnnamed_20 = -8110;
pub const SEC_ERROR_PKCS12_UNSUPPORTED_TRANSPORT_MODE: nss_C2RustUnnamed_20 = -8111;
pub const SEC_ERROR_PKCS12_UNSUPPORTED_MAC_ALGORITHM: nss_C2RustUnnamed_20 = -8112;
pub const SEC_ERROR_PKCS12_INVALID_MAC: nss_C2RustUnnamed_20 = -8113;
pub const SEC_ERROR_PKCS12_DECODING_PFX: nss_C2RustUnnamed_20 = -8114;
pub const SEC_ERROR_IMPORTING_CERTIFICATES: nss_C2RustUnnamed_20 = -8115;
pub const SEC_ERROR_EXPORTING_CERTIFICATES: nss_C2RustUnnamed_20 = -8116;
pub const SEC_ERROR_BAD_EXPORT_ALGORITHM: nss_C2RustUnnamed_20 = -8117;
pub const XP_JAVA_CERT_NOT_EXISTS_ERROR: nss_C2RustUnnamed_20 = -8118;
pub const XP_JAVA_DELETE_PRIVILEGE_ERROR: nss_C2RustUnnamed_20 = -8119;
pub const XP_JAVA_REMOVE_PRINCIPAL_ERROR: nss_C2RustUnnamed_20 = -8120;
pub const SEC_ERROR_BAGGAGE_NOT_CREATED: nss_C2RustUnnamed_20 = -8121;
pub const SEC_ERROR_SAFE_NOT_CREATED: nss_C2RustUnnamed_20 = -8122;
pub const SEC_ERROR_KEY_NICKNAME_COLLISION: nss_C2RustUnnamed_20 = -8123;
pub const SEC_ERROR_CERT_NICKNAME_COLLISION: nss_C2RustUnnamed_20 = -8124;
pub const SEC_ERROR_NO_SLOT_SELECTED: nss_C2RustUnnamed_20 = -8125;
pub const SEC_ERROR_READ_ONLY: nss_C2RustUnnamed_20 = -8126;
pub const SEC_ERROR_NO_TOKEN: nss_C2RustUnnamed_20 = -8127;
pub const SEC_ERROR_NO_MODULE: nss_C2RustUnnamed_20 = -8128;
pub const SEC_ERROR_NEED_RANDOM: nss_C2RustUnnamed_20 = -8129;
pub const SEC_ERROR_KRL_INVALID: nss_C2RustUnnamed_20 = -8130;
pub const SEC_ERROR_REVOKED_KEY: nss_C2RustUnnamed_20 = -8131;
pub const SEC_ERROR_KRL_BAD_SIGNATURE: nss_C2RustUnnamed_20 = -8132;
pub const SEC_ERROR_KRL_EXPIRED: nss_C2RustUnnamed_20 = -8133;
pub const SEC_ERROR_NO_KRL: nss_C2RustUnnamed_20 = -8134;
pub const XP_SEC_FORTEZZA_PERSON_ERROR: nss_C2RustUnnamed_20 = -8135;
pub const XP_SEC_FORTEZZA_BAD_PIN: nss_C2RustUnnamed_20 = -8136;
pub const XP_SEC_FORTEZZA_NO_MORE_INFO: nss_C2RustUnnamed_20 = -8137;
pub const XP_SEC_FORTEZZA_PERSON_NOT_FOUND: nss_C2RustUnnamed_20 = -8138;
pub const XP_SEC_FORTEZZA_MORE_INFO: nss_C2RustUnnamed_20 = -8139;
pub const XP_SEC_FORTEZZA_NONE_SELECTED: nss_C2RustUnnamed_20 = -8140;
pub const XP_SEC_FORTEZZA_NO_CARD: nss_C2RustUnnamed_20 = -8141;
pub const XP_SEC_FORTEZZA_BAD_CARD: nss_C2RustUnnamed_20 = -8142;
pub const SEC_ERROR_DECRYPTION_DISALLOWED: nss_C2RustUnnamed_20 = -8143;
pub const SEC_ERROR_UNSUPPORTED_KEYALG: nss_C2RustUnnamed_20 = -8144;
pub const SEC_ERROR_PKCS7_BAD_SIGNATURE: nss_C2RustUnnamed_20 = -8145;
pub const SEC_ERROR_PKCS7_KEYALG_MISMATCH: nss_C2RustUnnamed_20 = -8146;
pub const SEC_ERROR_NOT_A_RECIPIENT: nss_C2RustUnnamed_20 = -8147;
pub const SEC_ERROR_NO_RECIPIENT_CERTS_QUERY: nss_C2RustUnnamed_20 = -8148;
pub const SEC_ERROR_NO_EMAIL_CERT: nss_C2RustUnnamed_20 = -8149;
pub const SEC_ERROR_OLD_CRL: nss_C2RustUnnamed_20 = -8150;
pub const SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION: nss_C2RustUnnamed_20 = -8151;
pub const SEC_ERROR_INVALID_KEY: nss_C2RustUnnamed_20 = -8152;
pub const SEC_INTERNAL_ONLY: nss_C2RustUnnamed_20 = -8153;
pub const SEC_ERROR_CERT_USAGES_INVALID: nss_C2RustUnnamed_20 = -8154;
pub const SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID: nss_C2RustUnnamed_20 = -8155;
pub const SEC_ERROR_CA_CERT_INVALID: nss_C2RustUnnamed_20 = -8156;
pub const SEC_ERROR_EXTENSION_NOT_FOUND: nss_C2RustUnnamed_20 = -8157;
pub const SEC_ERROR_EXTENSION_VALUE_INVALID: nss_C2RustUnnamed_20 = -8158;
pub const SEC_ERROR_CRL_INVALID: nss_C2RustUnnamed_20 = -8159;
pub const SEC_ERROR_CRL_BAD_SIGNATURE: nss_C2RustUnnamed_20 = -8160;
pub const SEC_ERROR_CRL_EXPIRED: nss_C2RustUnnamed_20 = -8161;
pub const SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE: nss_C2RustUnnamed_20 = -8162;
pub const SEC_ERROR_CERT_NO_RESPONSE: nss_C2RustUnnamed_20 = -8163;
pub const SEC_ERROR_CERT_NOT_VALID: nss_C2RustUnnamed_20 = -8164;
pub const SEC_ERROR_CERT_VALID: nss_C2RustUnnamed_20 = -8165;
pub const SEC_ERROR_NO_KEY: nss_C2RustUnnamed_20 = -8166;
pub const SEC_ERROR_FILING_KEY: nss_C2RustUnnamed_20 = -8167;
pub const SEC_ERROR_ADDING_CERT: nss_C2RustUnnamed_20 = -8168;
pub const SEC_ERROR_DUPLICATE_CERT_NAME: nss_C2RustUnnamed_20 = -8169;
pub const SEC_ERROR_DUPLICATE_CERT: nss_C2RustUnnamed_20 = -8170;
pub const SEC_ERROR_UNTRUSTED_CERT: nss_C2RustUnnamed_20 = -8171;
pub const SEC_ERROR_UNTRUSTED_ISSUER: nss_C2RustUnnamed_20 = -8172;
pub const SEC_ERROR_NO_MEMORY: nss_C2RustUnnamed_20 = -8173;
pub const SEC_ERROR_BAD_DATABASE: nss_C2RustUnnamed_20 = -8174;
pub const SEC_ERROR_NO_NODELOCK: nss_C2RustUnnamed_20 = -8175;
pub const SEC_ERROR_RETRY_PASSWORD: nss_C2RustUnnamed_20 = -8176;
pub const SEC_ERROR_UNKNOWN_ISSUER: nss_C2RustUnnamed_20 = -8179;
pub const SEC_ERROR_REVOKED_CERTIFICATE: nss_C2RustUnnamed_20 = -8180;
pub const SEC_ERROR_EXPIRED_CERTIFICATE: nss_C2RustUnnamed_20 = -8181;
pub const SEC_ERROR_BAD_SIGNATURE: nss_C2RustUnnamed_20 = -8182;
pub const SEC_ERROR_BAD_DER: nss_C2RustUnnamed_20 = -8183;
pub const SEC_ERROR_INVALID_TIME: nss_C2RustUnnamed_20 = -8184;
pub const SEC_ERROR_INVALID_AVA: nss_C2RustUnnamed_20 = -8185;
pub const SEC_ERROR_INVALID_ALGORITHM: nss_C2RustUnnamed_20 = -8186;
pub const SEC_ERROR_INVALID_ARGS: nss_C2RustUnnamed_20 = -8187;
pub const SEC_ERROR_INPUT_LEN: nss_C2RustUnnamed_20 = -8188;
pub const SEC_ERROR_OUTPUT_LEN: nss_C2RustUnnamed_20 = -8189;
pub const SEC_ERROR_BAD_DATA: nss_C2RustUnnamed_20 = -8190;
pub const SEC_ERROR_LIBRARY_FAILURE: nss_C2RustUnnamed_20 = -8191;
pub const SEC_ERROR_IO: nss_C2RustUnnamed_20 = -8192;
// rustls.rs

pub type uintptr_t = libc::c_ulong;
pub type rustls_result = libc::c_uint;
pub const RUSTLS_RESULT_CERT_SCT_UNKNOWN_LOG: rustls_result = 7323;
pub const RUSTLS_RESULT_CERT_SCT_UNSUPPORTED_VERSION: rustls_result = 7322;
pub const RUSTLS_RESULT_CERT_SCT_TIMESTAMP_IN_FUTURE: rustls_result = 7321;
pub const RUSTLS_RESULT_CERT_SCT_INVALID_SIGNATURE: rustls_result = 7320;
pub const RUSTLS_RESULT_CERT_SCT_MALFORMED: rustls_result = 7319;
pub const RUSTLS_RESULT_CERT_UNSUPPORTED_SIGNATURE_ALGORITHM: rustls_result = 7318;
pub const RUSTLS_RESULT_CERT_UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_PUBLIC_KEY: rustls_result = 7317;
pub const RUSTLS_RESULT_CERT_UNSUPPORTED_CRITICAL_EXTENSION: rustls_result = 7316;
pub const RUSTLS_RESULT_CERT_UNSUPPORTED_CERT_VERSION: rustls_result = 7315;
pub const RUSTLS_RESULT_CERT_UNKNOWN_ISSUER: rustls_result = 7314;
pub const RUSTLS_RESULT_CERT_REQUIRED_EKU_NOT_FOUND: rustls_result = 7313;
pub const RUSTLS_RESULT_CERT_SIGNATURE_ALGORITHM_MISMATCH: rustls_result = 7312;
pub const RUSTLS_RESULT_CERT_PATH_LEN_CONSTRAINT_VIOLATED: rustls_result = 7311;
pub const RUSTLS_RESULT_CERT_NAME_CONSTRAINT_VIOLATION: rustls_result = 7310;
pub const RUSTLS_RESULT_CERT_INVALID_SIGNATURE_FOR_PUBLIC_KEY: rustls_result = 7309;
pub const RUSTLS_RESULT_CERT_INVALID_CERT_VALIDITY: rustls_result = 7308;
pub const RUSTLS_RESULT_CERT_EXTENSION_VALUE_INVALID: rustls_result = 7307;
pub const RUSTLS_RESULT_CERT_END_ENTITY_USED_AS_CA: rustls_result = 7306;
pub const RUSTLS_RESULT_CERT_NOT_VALID_YET: rustls_result = 7305;
pub const RUSTLS_RESULT_CERT_NOT_VALID_FOR_NAME: rustls_result = 7304;
pub const RUSTLS_RESULT_CERT_EXPIRED: rustls_result = 7303;
pub const RUSTLS_RESULT_CERT_CA_USED_AS_END_ENTITY: rustls_result = 7302;
pub const RUSTLS_RESULT_CERT_BAD_DER_TIME: rustls_result = 7301;
pub const RUSTLS_RESULT_CERT_BAD_DER: rustls_result = 7300;
pub const RUSTLS_RESULT_ALERT_UNKNOWN: rustls_result = 7234;
pub const RUSTLS_RESULT_ALERT_NO_APPLICATION_PROTOCOL: rustls_result = 7233;
pub const RUSTLS_RESULT_ALERT_CERTIFICATE_REQUIRED: rustls_result = 7232;
pub const RUSTLS_RESULT_ALERT_UNKNOWN_PSK_IDENTITY: rustls_result = 7231;
pub const RUSTLS_RESULT_ALERT_BAD_CERTIFICATE_HASH_VALUE: rustls_result = 7230;
pub const RUSTLS_RESULT_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE: rustls_result = 7229;
pub const RUSTLS_RESULT_ALERT_UNRECOGNISED_NAME: rustls_result = 7228;
pub const RUSTLS_RESULT_ALERT_CERTIFICATE_UNOBTAINABLE: rustls_result = 7227;
pub const RUSTLS_RESULT_ALERT_UNSUPPORTED_EXTENSION: rustls_result = 7226;
pub const RUSTLS_RESULT_ALERT_MISSING_EXTENSION: rustls_result = 7225;
pub const RUSTLS_RESULT_ALERT_NO_RENEGOTIATION: rustls_result = 7224;
pub const RUSTLS_RESULT_ALERT_USER_CANCELED: rustls_result = 7223;
pub const RUSTLS_RESULT_ALERT_INAPPROPRIATE_FALLBACK: rustls_result = 7222;
pub const RUSTLS_RESULT_ALERT_INTERNAL_ERROR: rustls_result = 7221;
pub const RUSTLS_RESULT_ALERT_INSUFFICIENT_SECURITY: rustls_result = 7220;
pub const RUSTLS_RESULT_ALERT_PROTOCOL_VERSION: rustls_result = 7219;
pub const RUSTLS_RESULT_ALERT_EXPORT_RESTRICTION: rustls_result = 7218;
pub const RUSTLS_RESULT_ALERT_DECRYPT_ERROR: rustls_result = 7217;
pub const RUSTLS_RESULT_ALERT_DECODE_ERROR: rustls_result = 7216;
pub const RUSTLS_RESULT_ALERT_ACCESS_DENIED: rustls_result = 7215;
pub const RUSTLS_RESULT_ALERT_UNKNOWN_CA: rustls_result = 7214;
pub const RUSTLS_RESULT_ALERT_ILLEGAL_PARAMETER: rustls_result = 7213;
pub const RUSTLS_RESULT_ALERT_CERTIFICATE_UNKNOWN: rustls_result = 7212;
pub const RUSTLS_RESULT_ALERT_CERTIFICATE_EXPIRED: rustls_result = 7211;
pub const RUSTLS_RESULT_ALERT_CERTIFICATE_REVOKED: rustls_result = 7210;
pub const RUSTLS_RESULT_ALERT_UNSUPPORTED_CERTIFICATE: rustls_result = 7209;
pub const RUSTLS_RESULT_ALERT_BAD_CERTIFICATE: rustls_result = 7208;
pub const RUSTLS_RESULT_ALERT_NO_CERTIFICATE: rustls_result = 7207;
pub const RUSTLS_RESULT_ALERT_HANDSHAKE_FAILURE: rustls_result = 7206;
pub const RUSTLS_RESULT_ALERT_DECOMPRESSION_FAILURE: rustls_result = 7205;
pub const RUSTLS_RESULT_ALERT_RECORD_OVERFLOW: rustls_result = 7204;
pub const RUSTLS_RESULT_ALERT_DECRYPTION_FAILED: rustls_result = 7203;
pub const RUSTLS_RESULT_ALERT_BAD_RECORD_MAC: rustls_result = 7202;
pub const RUSTLS_RESULT_ALERT_UNEXPECTED_MESSAGE: rustls_result = 7201;
pub const RUSTLS_RESULT_ALERT_CLOSE_NOTIFY: rustls_result = 7200;
pub const RUSTLS_RESULT_GENERAL: rustls_result = 7112;
pub const RUSTLS_RESULT_CORRUPT_MESSAGE_PAYLOAD: rustls_result = 7111;
pub const RUSTLS_RESULT_INAPPROPRIATE_HANDSHAKE_MESSAGE: rustls_result = 7110;
pub const RUSTLS_RESULT_INAPPROPRIATE_MESSAGE: rustls_result = 7109;
pub const RUSTLS_RESULT_PEER_MISBEHAVED_ERROR: rustls_result = 7108;
pub const RUSTLS_RESULT_PEER_INCOMPATIBLE_ERROR: rustls_result = 7107;
pub const RUSTLS_RESULT_NO_APPLICATION_PROTOCOL: rustls_result = 7106;
pub const RUSTLS_RESULT_PEER_SENT_OVERSIZED_RECORD: rustls_result = 7105;
pub const RUSTLS_RESULT_HANDSHAKE_NOT_COMPLETE: rustls_result = 7104;
pub const RUSTLS_RESULT_FAILED_TO_GET_CURRENT_TIME: rustls_result = 7103;
pub const RUSTLS_RESULT_DECRYPT_ERROR: rustls_result = 7102;
pub const RUSTLS_RESULT_NO_CERTIFICATES_PRESENTED: rustls_result = 7101;
pub const RUSTLS_RESULT_CORRUPT_MESSAGE: rustls_result = 7100;
pub const RUSTLS_RESULT_INVALID_PARAMETER: rustls_result = 7009;
pub const RUSTLS_RESULT_NOT_FOUND: rustls_result = 7008;
pub const RUSTLS_RESULT_INSUFFICIENT_SIZE: rustls_result = 7007;
pub const RUSTLS_RESULT_PRIVATE_KEY_PARSE_ERROR: rustls_result = 7006;
pub const RUSTLS_RESULT_CERTIFICATE_PARSE_ERROR: rustls_result = 7005;
pub const RUSTLS_RESULT_PANIC: rustls_result = 7004;
pub const RUSTLS_RESULT_INVALID_DNS_NAME_ERROR: rustls_result = 7003;
pub const RUSTLS_RESULT_NULL_PARAMETER: rustls_result = 7002;
pub const RUSTLS_RESULT_IO: rustls_result = 7001;
pub const RUSTLS_RESULT_OK: rustls_result = 7000;
pub type rustls_verify_server_cert_user_data = *mut libc::c_void;
pub type rustls_verify_server_cert_callback = Option::<
    unsafe extern "C" fn(
        rustls_verify_server_cert_user_data,
        *const rustls_verify_server_cert_params,
    ) -> rustls_result,
>;
pub type rustls_io_result = libc::c_int;
pub type rustls_read_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut uint8_t,
        size_t,
        *mut size_t,
    ) -> rustls_io_result,
>;
pub type rustls_write_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const uint8_t,
        size_t,
        *mut size_t,
    ) -> rustls_io_result,
>;

// openssl.rs
pub type SSL = ssl_st;
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    *mut CRYPTO_EX_DATA,
    *const CRYPTO_EX_DATA,
    *mut libc::c_void,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> libc::c_int;
pub type CRYPTO_EX_new = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
pub type EVP_MD_CTX = evp_md_ctx_st;
pub type EVP_MD = evp_md_st;
pub type ENGINE = engine_st;
pub type X509_PUBKEY = X509_pubkey_st;
pub type OCSP_RESPONSE = ocsp_response_st;
pub type OCSP_BASICRESP = ocsp_basic_response_st;
pub type ASN1_GENERALIZEDTIME = asn1_string_st;
pub type OCSP_CERTID = ocsp_cert_id_st;
pub type OPENSSL_STACK = stack_st;
pub type X509_STORE = x509_store_st;
pub type BIO = bio_st;
pub type pem_password_cb = unsafe extern "C" fn(
    *mut libc::c_char,
    libc::c_int,
    libc::c_int,
    *mut libc::c_void,
) -> libc::c_int;
pub type BIO_METHOD = bio_method_st;
pub type X509_NAME = X509_name_st;
pub type BUF_MEM = buf_mem_st;
pub type ASN1_STRING = asn1_string_st;
pub type X509_NAME_ENTRY = X509_name_entry_st;
pub type GENERAL_NAMES = stack_st_GENERAL_NAME;
pub type ASN1_IA5STRING = asn1_string_st;
pub type ASN1_TYPE = asn1_type_st;
pub type ASN1_VALUE = ASN1_VALUE_st;
pub type ASN1_UTF8STRING = asn1_string_st;
pub type ASN1_VISIBLESTRING = asn1_string_st;
pub type ASN1_UTCTIME = asn1_string_st;
pub type ASN1_UNIVERSALSTRING = asn1_string_st;
pub type ASN1_BMPSTRING = asn1_string_st;
pub type ASN1_GENERALSTRING = asn1_string_st;
pub type ASN1_T61STRING = asn1_string_st;
pub type ASN1_PRINTABLESTRING = asn1_string_st;
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type ASN1_BIT_STRING = asn1_string_st;
pub type ASN1_ENUMERATED = asn1_string_st;
pub type ASN1_INTEGER = asn1_string_st;
pub type ASN1_OBJECT = asn1_object_st;
pub type ASN1_BOOLEAN = libc::c_int;
pub type EDIPARTYNAME = EDIPartyName_st;
pub type OTHERNAME = otherName_st;
pub type GENERAL_NAME = GENERAL_NAME_st;
pub type ASN1_TIME = asn1_string_st;
pub type EVP_PKEY = evp_pkey_st;
pub type BIGNUM = bignum_st;
pub type DH = dh_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type X509_EXTENSION = X509_extension_st;
pub type X509_ALGOR = X509_algor_st;
pub type numcert_t = libc::c_int;
pub type SSL_CIPHER = ssl_cipher_st;
pub type SSL_CTX_keylog_cb_func = Option::<
    unsafe extern "C" fn(*const SSL, *const libc::c_char) -> (),
>;
pub type SSL_verify_cb = Option::<
    unsafe extern "C" fn(libc::c_int, *mut X509_STORE_CTX) -> libc::c_int,
>;
pub type X509_STORE_CTX = x509_store_ctx_st;
pub type X509_LOOKUP = x509_lookup_st;
pub type X509_LOOKUP_METHOD = x509_lookup_method_st;
pub type X509_INFO = X509_info_st;
pub type EVP_CIPHER_INFO = evp_cipher_info_st;
pub type EVP_CIPHER = evp_cipher_st;
pub type X509_PKEY = private_key_st;
pub type X509_CRL = X509_crl_st;
pub type sk_X509_INFO_freefunc = Option::<unsafe extern "C" fn(*mut X509_INFO) -> ()>;
pub type OPENSSL_sk_freefunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type UI_METHOD = ui_method_st;
pub type UI_STRING = ui_string_st;
pub type UI = ui_st;
pub const UIT_VERIFY: UI_string_types = 2;
pub const UIT_PROMPT: UI_string_types = 1;
pub type UI_string_types = libc::c_uint;
pub const UIT_ERROR: UI_string_types = 5;
pub const UIT_INFO: UI_string_types = 4;
pub const UIT_BOOLEAN: UI_string_types = 3;
pub const UIT_NONE: UI_string_types = 0;
pub type sk_X509_freefunc = Option::<unsafe extern "C" fn(*mut X509) -> ()>;
pub type PKCS12 = PKCS12_st;
pub type SSL_CTX_npn_select_cb_func = Option::<
    unsafe extern "C" fn(
        *mut SSL,
        *mut *mut libc::c_uchar,
        *mut libc::c_uchar,
        *const libc::c_uchar,
        libc::c_uint,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type ctx_option_t = libc::c_long;
pub type OPENSSL_INIT_SETTINGS = ossl_init_settings_st;



// mesalink.rs
pub const MESALINK_SUCCESS: mesalink_constant_t = 1;
pub const MESALINK_FILETYPE_ASN1: mesalink_constant_t = 2;
pub const MESALINK_FILETYPE_PEM: mesalink_constant_t = 1;
pub const MESALINK_SSL_VERIFY_NONE: mesalink_verify_mode_t = 0;
pub const MESALINK_SSL_VERIFY_PEER: mesalink_verify_mode_t = 1;
pub type mesalink_verify_mode_t = libc::c_uint;
pub const MESALINK_SSL_VERIFY_FAIL_IF_NO_PEER_CERT: mesalink_verify_mode_t = 2;
pub type mesalink_constant_t = libc::c_int;
pub const MESALINK_SSL_EARLY_DATA_ACCEPTED: mesalink_constant_t = 2;
pub const MESALINK_SSL_EARLY_DATA_REJECTED: mesalink_constant_t = 1;
pub const MESALINK_SSL_EARLY_DATA_NOT_SENT: mesalink_constant_t = 0;
pub const MESALINK_SSL_SESS_CACHE_BOTH: mesalink_constant_t = 3;
pub const MESALINK_SSL_SESS_CACHE_SERVER: mesalink_constant_t = 2;
pub const MESALINK_SSL_SESS_CACHE_CLIENT: mesalink_constant_t = 1;
pub const MESALINK_SSL_SESS_CACHE_OFF: mesalink_constant_t = 0;
pub const MESALINK_FILETYPE_RAW: mesalink_constant_t = 3;
pub const MESALINK_FILETYPE_DEFAULT: mesalink_constant_t = 2;
pub const MESALINK_ERROR: mesalink_constant_t = -1;
pub const MESALINK_FAILURE: mesalink_constant_t = 0;

pub const MESALINK_ERROR_WANT_WRITE: mesa_C2RustUnnamed_9 = 3;
pub const MESALINK_ERROR_WANT_READ: mesa_C2RustUnnamed_9 = 2;
pub const IO_ERROR_CONNECTION_ABORTED: mesa_C2RustUnnamed_9 = 33554437;
pub const MESALINK_ERROR_ZERO_RETURN: mesa_C2RustUnnamed_9 = 1;
pub const TLS_ERROR_WEBPKI_ERRORS: mesa_C2RustUnnamed_9 = 50334208;
pub const MESALINK_ERROR_WANT_CONNECT: mesa_C2RustUnnamed_9 = 7;
pub type mesa_C2RustUnnamed_9 = libc::c_uint;
pub const UNDEFINED_ERROR: mesa_C2RustUnnamed_9 = 4008636142;
pub const TLS_ERROR_PEER_SENT_OVERSIZED_RECORD: mesa_C2RustUnnamed_9 = 50335744;
pub const TLS_ERROR_HANDSHAKE_NOT_COMPLETE: mesa_C2RustUnnamed_9 = 50335488;
pub const TLS_ERROR_INVALID_DNS_NAME: mesa_C2RustUnnamed_9 = 50335232;
pub const TLS_ERROR_FAILED_TO_GET_CURRENT_TIME: mesa_C2RustUnnamed_9 = 50334976;
pub const TLS_ERROR_GENERAL: mesa_C2RustUnnamed_9 = 50334720;
pub const TLS_ERROR_INVALID_SCT: mesa_C2RustUnnamed_9 = 50334464;
pub const TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM: mesa_C2RustUnnamed_9 = 50334227;
pub const TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_PUBLIC_KEY: mesa_C2RustUnnamed_9 = 50334226;
pub const TLS_ERROR_WEBPKI_UNSUPPORTED_CRITICAL_EXTENSION: mesa_C2RustUnnamed_9 = 50334225;
pub const TLS_ERROR_WEBPKI_UNSUPPORTED_CERT_VERSION: mesa_C2RustUnnamed_9 = 50334224;
pub const TLS_ERROR_WEBPKI_UNKNOWN_ISSUER: mesa_C2RustUnnamed_9 = 50334223;
pub const TLS_ERROR_WEBPKI_REQUIRED_EKU_NOT_FOUND: mesa_C2RustUnnamed_9 = 50334222;
pub const TLS_ERROR_WEBPKI_SIGNATURE_ALGORITHM_MISMATCH: mesa_C2RustUnnamed_9 = 50334221;
pub const TLS_ERROR_WEBPKI_PATH_LEN_CONSTRAINT_VIOLATED: mesa_C2RustUnnamed_9 = 50334220;
pub const TLS_ERROR_WEBPKI_NAME_CONSTRAINT_VIOLATION: mesa_C2RustUnnamed_9 = 50334219;
pub const TLS_ERROR_WEBPKI_INVALID_SIGNATURE_FOR_PUBLIC_KEY: mesa_C2RustUnnamed_9 = 50334218;
pub const TLS_ERROR_WEBPKI_INVALID_CERT_VALIDITY: mesa_C2RustUnnamed_9 = 50334217;
pub const TLS_ERROR_WEBPKI_EXTENSION_VALUE_INVALID: mesa_C2RustUnnamed_9 = 50334216;
pub const TLS_ERROR_WEBPKI_END_ENTITY_USED_AS_CA: mesa_C2RustUnnamed_9 = 50334215;
pub const TLS_ERROR_WEBPKI_CERT_NOT_VALID_YET: mesa_C2RustUnnamed_9 = 50334214;
pub const TLS_ERROR_WEBPKI_CERT_NOT_VALID_FOR_NAME: mesa_C2RustUnnamed_9 = 50334213;
pub const TLS_ERROR_WEBPKI_CERT_EXPIRED: mesa_C2RustUnnamed_9 = 50334212;
pub const TLS_ERROR_WEBPKI_CA_USED_AS_END_ENTITY: mesa_C2RustUnnamed_9 = 50334211;
pub const TLS_ERROR_WEBPKI_BAD_DER_TIME: mesa_C2RustUnnamed_9 = 50334210;
pub const TLS_ERROR_WEBPKI_BAD_DER: mesa_C2RustUnnamed_9 = 50334209;
pub const TLS_ERROR_ALERT_RECEIVED_UNKNOWN: mesa_C2RustUnnamed_9 = 50334207;
pub const TLS_ERROR_ALERT_RECEIVED_NO_APPLICATION_PROTOCOL: mesa_C2RustUnnamed_9 = 50333986;
pub const TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REQUIRED: mesa_C2RustUnnamed_9 = 50333985;
pub const TLS_ERROR_ALERT_RECEIVED_UNKNOWN_PSK_IDENTITY: mesa_C2RustUnnamed_9 = 50333984;
pub const TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_HASH_VALUE: mesa_C2RustUnnamed_9 = 50333983;
pub const TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_STATUS_RESPONSE: mesa_C2RustUnnamed_9 = 50333982;
pub const TLS_ERROR_ALERT_RECEIVED_UNRECOGNISED_NAME: mesa_C2RustUnnamed_9 = 50333981;
pub const TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNOBTAINABLE: mesa_C2RustUnnamed_9 = 50333980;
pub const TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_EXTENSION: mesa_C2RustUnnamed_9 = 50333979;
pub const TLS_ERROR_ALERT_RECEIVED_MISSING_EXTENSION: mesa_C2RustUnnamed_9 = 50333978;
pub const TLS_ERROR_ALERT_RECEIVED_NO_RENEGOTIATION: mesa_C2RustUnnamed_9 = 50333977;
pub const TLS_ERROR_ALERT_RECEIVED_USER_CANCELED: mesa_C2RustUnnamed_9 = 50333976;
pub const TLS_ERROR_ALERT_RECEIVED_INAPPROPRIATE_FALLBACK: mesa_C2RustUnnamed_9 = 50333975;
pub const TLS_ERROR_ALERT_RECEIVED_INTERNAL_ERROR: mesa_C2RustUnnamed_9 = 50333974;
pub const TLS_ERROR_ALERT_RECEIVED_INSUFFICIENT_SECURITY: mesa_C2RustUnnamed_9 = 50333973;
pub const TLS_ERROR_ALERT_RECEIVED_PROTOCOL_VERSION: mesa_C2RustUnnamed_9 = 50333972;
pub const TLS_ERROR_ALERT_RECEIVED_EXPORT_RESTRICTION: mesa_C2RustUnnamed_9 = 50333971;
pub const TLS_ERROR_ALERT_RECEIVED_DECRYPT_ERROR: mesa_C2RustUnnamed_9 = 50333970;
pub const TLS_ERROR_ALERT_RECEIVED_DECODE_ERROR: mesa_C2RustUnnamed_9 = 50333969;
pub const TLS_ERROR_ALERT_RECEIVED_ACCESS_DENIED: mesa_C2RustUnnamed_9 = 50333968;
pub const TLS_ERROR_ALERT_RECEIVED_UNKNOWN_CA: mesa_C2RustUnnamed_9 = 50333967;
pub const TLS_ERROR_ALERT_RECEIVED_ILLEGAL_PARAMETER: mesa_C2RustUnnamed_9 = 50333966;
pub const TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNKNOWN: mesa_C2RustUnnamed_9 = 50333965;
pub const TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_EXPIRED: mesa_C2RustUnnamed_9 = 50333964;
pub const TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REVOKED: mesa_C2RustUnnamed_9 = 50333963;
pub const TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_CERTIFICATE: mesa_C2RustUnnamed_9 = 50333962;
pub const TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE: mesa_C2RustUnnamed_9 = 50333961;
pub const TLS_ERROR_ALERT_RECEIVED_NO_CERTIFICATE: mesa_C2RustUnnamed_9 = 50333960;
pub const TLS_ERROR_ALERT_RECEIVED_HANDSHAKE_FAILURE: mesa_C2RustUnnamed_9 = 50333959;
pub const TLS_ERROR_ALERT_RECEIVED_DECOMPRESSION_FAILURE: mesa_C2RustUnnamed_9 = 50333958;
pub const TLS_ERROR_ALERT_RECEIVED_RECORD_OVERFLOW: mesa_C2RustUnnamed_9 = 50333957;
pub const TLS_ERROR_ALERT_RECEIVED_DECRYPTION_FAILED: mesa_C2RustUnnamed_9 = 50333956;
pub const TLS_ERROR_ALERT_RECEIVED_BAD_RECORD_MAC: mesa_C2RustUnnamed_9 = 50333955;
pub const TLS_ERROR_ALERT_RECEIVED_UNEXPECTED_MESSAGE: mesa_C2RustUnnamed_9 = 50333954;
pub const TLS_ERROR_ALERT_RECEIVED_CLOSE_NOTIFY: mesa_C2RustUnnamed_9 = 50333953;
pub const TLS_ERROR_ALERT_RECEIVED_ERRORS: mesa_C2RustUnnamed_9 = 50333952;
pub const TLS_ERROR_PEER_MISBEHAVED_ERROR: mesa_C2RustUnnamed_9 = 50333696;
pub const TLS_ERROR_PEER_INCOMPATIBLE_ERROR: mesa_C2RustUnnamed_9 = 50333440;
pub const TLS_ERROR_DECRYPT_ERROR: mesa_C2RustUnnamed_9 = 50333184;
pub const TLS_ERROR_NO_CERTIFICATES_PRESENTED: mesa_C2RustUnnamed_9 = 50332928;
pub const TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_HANDSHAKE: mesa_C2RustUnnamed_9 = 50332675;
pub const TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_CHANGE_CIPHER_SPEC: mesa_C2RustUnnamed_9 = 50332674;
pub const TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_ALERT: mesa_C2RustUnnamed_9 = 50332673;
pub const TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD: mesa_C2RustUnnamed_9 = 50332672;
pub const TLS_ERROR_CORRUPT_MESSAGE: mesa_C2RustUnnamed_9 = 50332416;
pub const TLS_ERROR_INAPPROPRIATE_HANDSHAKE_MESSAGE: mesa_C2RustUnnamed_9 = 50332160;
pub const TLS_ERROR_INAPPROPRIATE_MESSAGE: mesa_C2RustUnnamed_9 = 50331904;
pub const IO_ERROR_UNEXPECTED_EOF: mesa_C2RustUnnamed_9 = 33554450;
pub const IO_ERROR_OTHER: mesa_C2RustUnnamed_9 = 33554449;
pub const IO_ERROR_INTERRUPTED: mesa_C2RustUnnamed_9 = 33554448;
pub const IO_ERROR_WRITE_ZERO: mesa_C2RustUnnamed_9 = 33554447;
pub const IO_ERROR_TIMED_OUT: mesa_C2RustUnnamed_9 = 33554446;
pub const IO_ERROR_INVALID_DATA: mesa_C2RustUnnamed_9 = 33554445;
pub const IO_ERROR_INVALID_INPUT: mesa_C2RustUnnamed_9 = 33554444;
pub const IO_ERROR_WOULD_BLOCK: mesa_C2RustUnnamed_9 = 33554443;
pub const IO_ERROR_ALREADY_EXISTS: mesa_C2RustUnnamed_9 = 33554442;
pub const IO_ERROR_BROKEN_PIPE: mesa_C2RustUnnamed_9 = 33554441;
pub const IO_ERROR_ADDR_NOT_AVAILABLE: mesa_C2RustUnnamed_9 = 33554440;
pub const IO_ERROR_ADDR_IN_USE: mesa_C2RustUnnamed_9 = 33554439;
pub const IO_ERROR_NOT_CONNECTED: mesa_C2RustUnnamed_9 = 33554438;
pub const IO_ERROR_CONNECTION_RESET: mesa_C2RustUnnamed_9 = 33554436;
pub const IO_ERROR_CONNECTION_REFUSED: mesa_C2RustUnnamed_9 = 33554435;
pub const IO_ERROR_PERMISSION_DENIED: mesa_C2RustUnnamed_9 = 33554434;
pub const IO_ERROR_NOT_FOUND: mesa_C2RustUnnamed_9 = 33554433;
pub const MESALINK_ERROR_LOCK: mesa_C2RustUnnamed_9 = 228;
pub const MESALINK_ERROR_PANIC: mesa_C2RustUnnamed_9 = 227;
pub const MESALINK_ERROR_BAD_FUNC_ARG: mesa_C2RustUnnamed_9 = 226;
pub const MESALINK_ERROR_MALFORMED_OBJECT: mesa_C2RustUnnamed_9 = 225;
pub const MESALINK_ERROR_NULL_POINTER: mesa_C2RustUnnamed_9 = 224;
pub const MESALINK_ERROR_SSL: mesa_C2RustUnnamed_9 = 85;
pub const MESALINK_ERROR_SYSCALL: mesa_C2RustUnnamed_9 = 5;
pub const MESALINK_ERROR_WANT_ACCEPT: mesa_C2RustUnnamed_9 = 8;
pub const MESALINK_ERROR_NONE: mesa_C2RustUnnamed_9 = 0;

//http_negotiate.rs
pub type gss_buffer_desc = gss_buffer_desc_struct;
pub type gss_name_t = *mut gss_name_struct;
pub type gss_ctx_id_t = *mut gss_ctx_id_struct;
pub type OM_uint32 = gss_uint32;
pub type gss_uint32 = uint32_t;
pub type curlnegotiate = libc::c_uint;
pub const GSS_AUTHSUCC: curlnegotiate = 4;
pub const GSS_AUTHDONE: curlnegotiate = 3;
pub const GSS_AUTHSENT: curlnegotiate = 2;
pub const GSS_AUTHRECV: curlnegotiate = 1;
pub const GSS_AUTHNONE: curlnegotiate = 0;
pub type protection_level = libc::c_uint;
pub const PROT_LAST: protection_level = 6;
pub const PROT_CMD: protection_level = 5;
pub const PROT_PRIVATE: protection_level = 4;
pub const PROT_CONFIDENTIAL: protection_level = 3;
pub const PROT_SAFE: protection_level = 2;
pub const PROT_CLEAR: protection_level = 1;
pub const PROT_NONE: protection_level = 0;
// bearssl.rs
pub type int16_t = __int16_t;
pub type __int16_t = libc::c_short;
pub type br_ecdsa_vrfy = Option::<
    unsafe extern "C" fn(
        *const br_ec_impl,
        *const libc::c_void,
        size_t,
        *const br_ec_public_key,
        *const libc::c_void,
        size_t,
    ) -> uint32_t,
>;
pub type br_rsa_pkcs1_vrfy = Option::<
    unsafe extern "C" fn(
        *const libc::c_uchar,
        size_t,
        *const libc::c_uchar,
        size_t,
        *const br_rsa_public_key,
        *mut libc::c_uchar,
    ) -> uint32_t,
>;
pub type br_x509_time_check = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        uint32_t,
        uint32_t,
        uint32_t,
        uint32_t,
    ) -> libc::c_int,
>;
pub type br_hash_class = br_hash_class_;
pub type br_sha384_context = br_sha512_context;
pub type br_sha224_context = br_sha256_context;
pub type br_x509_class = br_x509_class_;
pub type br_ssl_client_context = br_ssl_client_context_;
pub type br_rsa_public = Option::<
    unsafe extern "C" fn(
        *mut libc::c_uchar,
        size_t,
        *const br_rsa_public_key,
    ) -> uint32_t,
>;
pub type br_ecdsa_sign = Option::<
    unsafe extern "C" fn(
        *const br_ec_impl,
        *const br_hash_class,
        *const libc::c_void,
        *const br_ec_private_key,
        *mut libc::c_void,
    ) -> size_t,
>;
pub type br_ssl_client_certificate_class = br_ssl_client_certificate_class_;
pub type br_rsa_pkcs1_sign = Option::<
    unsafe extern "C" fn(
        *const libc::c_uchar,
        *const libc::c_uchar,
        size_t,
        *const br_rsa_private_key,
        *mut libc::c_uchar,
    ) -> uint32_t,
>;
pub type br_sslrec_out_ccm_class = br_sslrec_out_ccm_class_;
pub type br_block_ctrcbc_class = br_block_ctrcbc_class_;
pub type br_sslrec_out_class = br_sslrec_out_class_;
pub type br_sslrec_in_ccm_class = br_sslrec_in_ccm_class_;
pub type br_sslrec_in_class = br_sslrec_in_class_;
pub type br_sslrec_out_chapol_class = br_sslrec_out_chapol_class_;
pub type br_poly1305_run = Option::<
    unsafe extern "C" fn(
        *const libc::c_void,
        *const libc::c_void,
        *mut libc::c_void,
        size_t,
        *const libc::c_void,
        size_t,
        *mut libc::c_void,
        br_chacha20_run,
        libc::c_int,
    ) -> (),
>;
pub type br_chacha20_run = Option::<
    unsafe extern "C" fn(
        *const libc::c_void,
        *const libc::c_void,
        uint32_t,
        *mut libc::c_void,
        size_t,
    ) -> uint32_t,
>;
pub type br_sslrec_in_chapol_class = br_sslrec_in_chapol_class_;
pub type br_sslrec_out_gcm_class = br_sslrec_out_gcm_class_;
pub type br_ghash = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_void,
        *const libc::c_void,
        size_t,
    ) -> (),
>;
pub type br_block_ctr_class = br_block_ctr_class_;
pub type br_sslrec_in_gcm_class = br_sslrec_in_gcm_class_;
pub type br_sslrec_out_cbc_class = br_sslrec_out_cbc_class_;
pub type br_block_cbcenc_class = br_block_cbcenc_class_;
pub type br_sslrec_in_cbc_class = br_sslrec_in_cbc_class_;
pub type br_block_cbcdec_class = br_block_cbcdec_class_;
pub type br_tls_prf_impl = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        size_t,
        *const libc::c_void,
        size_t,
        *const libc::c_char,
        size_t,
        *const br_tls_prf_seed_chunk,
    ) -> (),
>;
pub type br_prng_class = br_prng_class_;
pub type br_prng_seeder = Option::<
    unsafe extern "C" fn(*mut *const br_prng_class) -> libc::c_int,
>;

// option hyper
pub type Curl_datastream = Option::<
    unsafe extern "C" fn(
        *mut Curl_easy,
        *mut connectdata,
        *mut libc::c_int,
        *mut bool,
        libc::c_int,
    ) -> CURLcode,
>;
pub type hyper_code = libc::c_uint;
pub const HYPERE_INVALID_PEER_MESSAGE: hyper_code = 6;
pub const HYPERE_FEATURE_NOT_ENABLED: hyper_code = 5;
pub const HYPERE_ABORTED_BY_CALLBACK: hyper_code = 4;
pub const HYPERE_UNEXPECTED_EOF: hyper_code = 3;
pub const HYPERE_INVALID_ARG: hyper_code = 2;
pub const HYPERE_ERROR: hyper_code = 1;
pub const HYPERE_OK: hyper_code = 0;
pub type hyper_task_return_type = libc::c_uint;
pub const HYPER_TASK_BUF: hyper_task_return_type = 4;
pub const HYPER_TASK_RESPONSE: hyper_task_return_type = 3;
pub const HYPER_TASK_CLIENTCONN: hyper_task_return_type = 2;
pub const HYPER_TASK_ERROR: hyper_task_return_type = 1;
pub const HYPER_TASK_EMPTY: hyper_task_return_type = 0;
pub type hyper_io_read_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut hyper_context,
        *mut uint8_t,
        size_t,
    ) -> size_t,
>;
pub type hyper_io_write_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut hyper_context,
        *const uint8_t,
        size_t,
    ) -> size_t,
>;

// option libssh2
pub type LIBSSH2_SFTP_ATTRIBUTES = _LIBSSH2_SFTP_ATTRIBUTES;
pub type libssh2_uint64_t = libc::c_ulonglong;
pub type LIBSSH2_KNOWNHOSTS = _LIBSSH2_KNOWNHOSTS;
pub type LIBSSH2_AGENT = _LIBSSH2_AGENT;
pub type LIBSSH2_SFTP_HANDLE = _LIBSSH2_SFTP_HANDLE;
pub type LIBSSH2_SFTP = _LIBSSH2_SFTP;
pub type LIBSSH2_CHANNEL = _LIBSSH2_CHANNEL;
pub type LIBSSH2_SESSION = _LIBSSH2_SESSION;

// option quiche
pub type __int64_t = libc::c_long;
pub type int64_t = __int64_t;
pub type quiche_h3_config = Http3Config;
pub type quiche_h3_conn = Http3Connection;
pub type quiche_conn = Connection;
pub type quiche_config = Config;

// ssh
pub type ssh_key = *mut ssh_key_struct;
pub type ssh_session = *mut ssh_session_struct;
pub type ssh_scp = *mut ssh_scp_struct;
pub type sftp_session = *mut sftp_session_struct;
pub type ssh_channel = *mut ssh_channel_struct;
pub type sftp_request_queue = *mut sftp_request_queue_struct;
pub type sftp_message = *mut sftp_message_struct;
pub type sftp_ext = *mut sftp_ext_struct;
pub type ssh_buffer = *mut ssh_buffer_struct;
pub type sftp_packet = *mut sftp_packet_struct;
pub type sftp_file = *mut sftp_file_struct;
pub type ssh_string = *mut ssh_string_struct;
pub type sftp_dir = *mut sftp_dir_struct;
pub type sftp_attributes = *mut sftp_attributes_struct;
