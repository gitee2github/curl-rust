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
 * Description: extern C struct definitions that ffi needed
 ******************************************************************************/
use c2rust_bitfields::BitfieldStruct;
use crate::src::ffi_alias::type_alias::*;

// extern "C" {
//     pub type ssl_backend_data;
// }

// openssl + wolfssl
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssl_backend_data {
    pub logger: *mut Curl_easy,
    pub ctx: *mut SSL_CTX,
    pub handle: *mut SSL,
    pub wolf_handle: *mut WOLFSSL,
    pub server_cert: *mut X509,
    //bearssl
    pub bear_ctx: br_ssl_client_context,
    pub x509: x509_context,
    pub buf: [libc::c_uchar; 33178],
    pub anchors: *mut br_x509_trust_anchor,
    pub anchors_len: size_t,
    pub protocols: [*const libc::c_char; 2],
    pub active: bool,
    pub pending_write: size_t,
    //gnutls
    pub session: gnutls_session_t,
    pub cred: gnutls_certificate_credentials_t,
    pub srp_client_cred: gnutls_srp_client_credentials_t,
    //mbedtls
    pub ctr_drbg: mbedtls_ctr_drbg_context,
    pub entropy: mbedtls_entropy_context,
    pub ssl: mbedtls_ssl_context,
    pub server_fd: libc::c_int,
    pub cacert: mbedtls_x509_crt,
    pub clicert: mbedtls_x509_crt,
    pub crl: mbedtls_x509_crl,
    pub pk: mbedtls_pk_context,
    pub config: mbedtls_ssl_config,
    pub mbedtls_protocols: [*const libc::c_char; 3],
    //mesalink
    pub mesalink_ctx: *mut MESALINK_CTX,
    pub mesalink_handle: *mut MESALINK_SSL,
    //nss
    pub nss_handle: *mut PRFileDesc,
    pub client_nickname: *mut libc::c_char,
    pub data: *mut Curl_easy,
    pub obj_list: Curl_llist,
    pub obj_clicert: *mut PK11GenericObject,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
// vtls.rs
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

#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_ssl_backend {
    pub id: curl_sslbackend,
    pub name: *const libc::c_char,
}
// ftp.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)] 
// cfg __USE_MISC
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub tm_gmtoff: libc::c_long,
    pub tm_zone: *const libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_easy {
    pub magic: libc::c_uint,
    pub next: *mut Curl_easy,
    pub prev: *mut Curl_easy,
    pub conn: *mut connectdata,
    pub connect_queue: Curl_llist_element,
    pub conn_queue: Curl_llist_element,
    pub mstate: CURLMstate,
    pub result: CURLcode,
    pub msg: Curl_message,
    pub sockets: [curl_socket_t; 5],
    pub actions: [libc::c_uchar; 5],
    pub numsocks: libc::c_int,
    pub dns: Names,
    pub multi: *mut Curl_multi,
    pub multi_easy: *mut Curl_multi,
    pub share: *mut Curl_share,
    #[cfg(USE_LIBPSL)]
    pub psl: *mut PslCache,
    pub req: SingleRequest,
    pub set: UserDefined,
    pub cookies: *mut CookieInfo,
    #[cfg(not(CURL_DISABLE_HSTS))]
    pub hsts: *mut hsts, 
    #[cfg(not(CURL_DISABLE_ALTSVC))]
    pub asi: *mut altsvcinfo,
    pub progress: Progress,
    pub state: UrlState,
    #[cfg(not(CURL_DISABLE_FTP))]
    pub wildcard: WildcardData,
    pub info: PureInfo,
    pub tsi: curl_tlssessioninfo,
    #[cfg(USE_HYPER)] 
    pub hyp: hyptransfer,
}
#[cfg(USE_HYPER)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hyptransfer {
    pub write_waker: *mut hyper_waker,
    pub read_waker: *mut hyper_waker,
    pub exec: *const hyper_executor,
    pub endtask: *mut hyper_task,
    pub exp100_waker: *mut hyper_waker,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_tlssessioninfo {
    pub backend: curl_sslbackend,
    pub internals: *mut libc::c_void,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct PureInfo {
    pub httpcode: libc::c_int,
    pub httpproxycode: libc::c_int,
    pub httpversion: libc::c_int,
    pub filetime: time_t,
    pub header_size: curl_off_t,
    pub request_size: curl_off_t,
    pub proxyauthavail: libc::c_ulong,
    pub httpauthavail: libc::c_ulong,
    pub numconnects: libc::c_long,
    pub contenttype: *mut libc::c_char,
    pub wouldredirect: *mut libc::c_char,
    pub retry_after: curl_off_t,
    pub conn_primary_ip: [libc::c_char; 46],
    pub conn_primary_port: libc::c_int,
    pub conn_local_ip: [libc::c_char; 46],
    pub conn_local_port: libc::c_int,
    pub conn_scheme: *const libc::c_char,
    pub conn_protocol: libc::c_uint,
    pub certs: curl_certinfo,
    pub pxcode: CURLproxycode,
    #[bitfield(name = "timecond", ty = "bit", bits = "0..=0")]
    pub timecond: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_certinfo {
    pub num_of_certs: libc::c_int,
    pub certinfo: *mut *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut libc::c_char,
    pub next: *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WildcardData {
    pub state: wildcard_states,
    pub path: *mut libc::c_char,
    pub pattern: *mut libc::c_char,
    pub filelist: Curl_llist,
    pub protdata: *mut libc::c_void,
    pub dtor: wildcard_dtor,
    pub customptr: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist {
    pub head: *mut Curl_llist_element,
    pub tail: *mut Curl_llist_element,
    pub dtor: Curl_llist_dtor,
    pub size: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist_element {
    pub ptr: *mut libc::c_void,
    pub prev: *mut Curl_llist_element,
    pub next: *mut Curl_llist_element,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct UrlState {
    pub conn_cache: *mut conncache,
    pub keeps_speed: curltime,
    pub lastconnect_id: libc::c_long,
    pub headerb: dynbuf,
    pub buffer: *mut libc::c_char,
    pub ulbuf: *mut libc::c_char,
    pub current_speed: curl_off_t,
    pub first_host: *mut libc::c_char,
    pub retrycount: libc::c_int,
    pub first_remote_port: libc::c_int,
    pub session: *mut Curl_ssl_session,
    pub sessionage: libc::c_long,
    pub tempwrite: [tempbuf; 3],
    pub tempcount: libc::c_uint,
    pub os_errno: libc::c_int,
    pub scratch: *mut libc::c_char,
    pub followlocation: libc::c_long,
    #[cfg(HAVE_SIGNAL)]
    pub prev_signal: Option::<unsafe extern "C" fn(libc::c_int) -> ()>,
    pub digest: digestdata,
    pub proxydigest: digestdata,
    pub authhost: auth,
    pub authproxy: auth,
    #[cfg(USE_CURL_ASYNC)]
    pub async_0: Curl_async,
    #[cfg(USE_OPENSSL)]
    pub engine: *mut libc::c_void,
    pub expiretime: curltime,
    pub timenode: Curl_tree,
    pub timeoutlist: Curl_llist,
    pub expires: [time_node; 13],
    pub most_recent_ftp_entrypath: *mut libc::c_char,
    pub httpwant: libc::c_uchar,
    pub httpversion: libc::c_uchar,
    #[cfg(all(not(WIN32), not(MSDOS), not(__EMX__)))]
    #[bitfield(name = "prev_block_had_trailing_cr", ty = "bit", bits = "0..=0")]
    pub prev_block_had_trailing_cr: [u8; 1],
    #[bitfield(padding)]
    #[cfg(all(not(WIN32), not(MSDOS), not(__EMX__)))]
    pub c2rust_padding: [u8; 5],
    #[cfg(all(not(WIN32), not(MSDOS), not(__EMX__)))]
    pub crlf_conversions: curl_off_t,
    pub range: *mut libc::c_char,
    pub resume_from: curl_off_t,
    pub rtsp_next_client_CSeq: libc::c_long,
    pub rtsp_next_server_CSeq: libc::c_long,
    pub rtsp_CSeq_recv: libc::c_long,
    pub infilesize: curl_off_t,
    pub drain: size_t,
    pub fread_func: curl_read_callback,
    pub in_0: *mut libc::c_void,
    pub stream_depends_on: *mut Curl_easy,
    pub stream_weight: libc::c_int,
    pub uh: *mut CURLU,
    pub up: urlpieces,
    pub httpreq: Curl_HttpReq,
    pub url: *mut libc::c_char,
    pub referer: *mut libc::c_char,
    pub cookielist: *mut curl_slist,
    pub resolve: *mut curl_slist,
    #[cfg(not(CURL_DISABLE_HTTP))]
    pub trailers_bytes_sent: size_t,
    #[cfg(not(CURL_DISABLE_HTTP))]
    pub trailers_buf: dynbuf,
    pub trailers_state: trailers_state,
    #[cfg(USE_HYPER)]
    pub hconnect: bool,
    #[cfg(USE_HYPER)]
    pub hresult: CURLcode,
    pub aptr: dynamically_allocated_data,
    #[cfg(not(CURLDEBUG))]
    #[bitfield(name = "multi_owned_by_easy", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "this_is_a_follow", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "refused_stream", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "errorbuf", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "allow_port", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "authproblem", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "ftp_trying_alternative", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "wildcardmatch", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "expect100header", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "disableexpect", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "use_range", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "rangestringalloc", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "done", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "previouslypending", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "cookie_engine", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "list_only", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "url_alloc", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "referer_alloc", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "wildcard_resolve", ty = "bit", bits = "20..=20")]
    // pub multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve: [u8; 3],
    pub c2rust_abbr: [u8; 3],
    #[cfg(CURLDEBUG)]
    #[bitfield(name = "conncache_lock", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "multi_owned_by_easy", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "this_is_a_follow", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "refused_stream", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "errorbuf", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "allow_port", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "authproblem", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "ftp_trying_alternative", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "wildcardmatch", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "expect100header", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "disableexpect", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "use_range", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "rangestringalloc", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "done", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "previouslypending", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "cookie_engine", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "list_only", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "url_alloc", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "referer_alloc", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "wildcard_resolve", ty = "bit", bits = "21..=21")]
    pub c2rust_abbr: [u8; 3],
    #[bitfield(padding)]
    pub c2rust_padding_0: [u8; 5],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynamically_allocated_data {
    pub proxyuserpwd: *mut libc::c_char,
    pub uagent: *mut libc::c_char,
    pub accept_encoding: *mut libc::c_char,
    pub userpwd: *mut libc::c_char,
    pub rangeline: *mut libc::c_char,
    pub ref_0: *mut libc::c_char,
    pub host: *mut libc::c_char,
    pub cookiehost: *mut libc::c_char,
    pub rtsp_transport: *mut libc::c_char,
    pub te: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
    pub proxyuser: *mut libc::c_char,
    pub proxypasswd: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynbuf {
    pub bufr: *mut libc::c_char,
    pub leng: size_t,
    pub allc: size_t,
    pub toobig: size_t,
    #[cfg(DEBUGBUILD)]
    pub init: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct urlpieces {
    pub scheme: *mut libc::c_char,
    pub hostname: *mut libc::c_char,
    pub port: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub password: *mut libc::c_char,
    pub options: *mut libc::c_char,
    pub path: *mut libc::c_char,
    pub query: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct time_node {
    pub list: Curl_llist_element,
    pub time: curltime,
    pub eid: expire_id,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curltime {
    pub tv_sec: time_t,
    pub tv_usec: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_tree {
    pub smaller: *mut Curl_tree,
    pub larger: *mut Curl_tree,
    pub samen: *mut Curl_tree,
    pub samep: *mut Curl_tree,
    pub key: curltime,
    pub payload: *mut libc::c_void,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct Curl_async {
    pub hostname: *mut libc::c_char,
    pub dns: *mut Curl_dns_entry,
    pub tdata: *mut thread_data,
    pub resolver: *mut libc::c_void,
    pub port: libc::c_int,
    pub status: libc::c_int,
    #[bitfield(name = "done", ty = "bit", bits = "0..=0")]
    pub done: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_dns_entry {
    pub addr: *mut Curl_addrinfo,
    pub timestamp: time_t,
    pub inuse: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_addrinfo {
    pub ai_flags: libc::c_int,
    pub ai_family: libc::c_int,
    pub ai_socktype: libc::c_int,
    pub ai_protocol: libc::c_int,
    pub ai_addrlen: curl_socklen_t,
    pub ai_canonname: *mut libc::c_char,
    pub ai_addr: *mut sockaddr,
    pub ai_next: *mut Curl_addrinfo,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct auth {
    pub want: libc::c_ulong,
    pub picked: libc::c_ulong,
    pub avail: libc::c_ulong,
    #[bitfield(name = "done", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "multipass", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "iestyle", ty = "bit", bits = "2..=2")]
    pub done_multipass_iestyle: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct digestdata {
    pub nonce: *mut libc::c_char,
    pub cnonce: *mut libc::c_char,
    pub realm: *mut libc::c_char,
    pub algo: libc::c_int,
    pub opaque: *mut libc::c_char,
    pub qop: *mut libc::c_char,
    pub algorithm: *mut libc::c_char,
    pub nc: libc::c_int,
    #[bitfield(name = "stale", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "userhash", ty = "bit", bits = "1..=1")]
    pub stale_userhash: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tempbuf {
    pub b: dynbuf,
    pub type_0: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_ssl_session {
    pub name: *mut libc::c_char,
    pub conn_to_host: *mut libc::c_char,
    pub scheme: *const libc::c_char,
    pub sessionid: *mut libc::c_void,
    pub idsize: size_t,
    pub age: libc::c_long,
    pub remote_port: libc::c_int,
    pub conn_to_port: libc::c_int,
    pub ssl_config: ssl_primary_config,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conncache {
    pub hash: Curl_hash,
    pub num_conn: size_t,
    pub next_connection_id: libc::c_long,
    pub last_cleanup: curltime,
    pub closure_handle: *mut Curl_easy,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_hash {
    pub table: *mut Curl_llist,
    pub hash_func: hash_function,
    pub comp_func: comp_function,
    pub dtor: Curl_hash_dtor,
    pub slots: libc::c_int,
    pub size: size_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct Progress {
    pub lastshow: time_t,
    pub size_dl: curl_off_t,
    pub size_ul: curl_off_t,
    pub downloaded: curl_off_t,
    pub uploaded: curl_off_t,
    pub current_speed: curl_off_t,
    pub width: libc::c_int,
    pub flags: libc::c_int,
    pub timespent: timediff_t,
    pub dlspeed: curl_off_t,
    pub ulspeed: curl_off_t,
    pub t_nslookup: timediff_t,
    pub t_connect: timediff_t,
    pub t_appconnect: timediff_t,
    pub t_pretransfer: timediff_t,
    pub t_starttransfer: timediff_t,
    pub t_redirect: timediff_t,
    pub start: curltime,
    pub t_startsingle: curltime,
    pub t_startop: curltime,
    pub t_acceptdata: curltime,
    pub ul_limit_start: curltime,
    pub ul_limit_size: curl_off_t,
    pub dl_limit_start: curltime,
    pub dl_limit_size: curl_off_t,
    pub speeder: [curl_off_t; 6],
    pub speeder_time: [curltime; 6],
    pub speeder_c: libc::c_int,
    #[bitfield(name = "callback", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_t_startransfer_set", ty = "bit", bits = "1..=1")]
    pub callback_is_t_startransfer_set: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CookieInfo {
    pub cookies: [*mut Cookie; 256],
    pub filename: *mut libc::c_char,
    pub numcookies: libc::c_long,
    pub running: bool,
    pub newsession: bool,
    pub lastct: libc::c_int,
    pub next_expiration: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cookie {
    pub next: *mut Cookie,
    pub name: *mut libc::c_char,
    pub value: *mut libc::c_char,
    pub path: *mut libc::c_char,
    pub spath: *mut libc::c_char,
    pub domain: *mut libc::c_char,
    pub expires: curl_off_t,
    pub expirestr: *mut libc::c_char,
    pub version: *mut libc::c_char,
    pub maxage: *mut libc::c_char,
    pub tailmatch: bool,
    pub secure: bool,
    pub livecookie: bool,
    pub httponly: bool,
    pub creationtime: libc::c_int,
    pub prefix: libc::c_uchar,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct UserDefined {
    pub err: *mut FILE,
    pub debugdata: *mut libc::c_void,
    pub errorbuffer: *mut libc::c_char,
    pub proxyport: libc::c_long,
    pub out: *mut libc::c_void,
    pub in_set: *mut libc::c_void,
    pub writeheader: *mut libc::c_void,
    pub rtp_out: *mut libc::c_void,
    pub use_port: libc::c_long,
    pub httpauth: libc::c_ulong,
    pub proxyauth: libc::c_ulong,
    pub socks5auth: libc::c_ulong,
    pub maxredirs: libc::c_long,
    pub keep_post: libc::c_int,
    pub postfields: *mut libc::c_void,
    pub seek_func: curl_seek_callback,
    pub postfieldsize: curl_off_t,
    pub localport: libc::c_ushort,
    pub localportrange: libc::c_int,
    pub fwrite_func: curl_write_callback,
    pub fwrite_header: curl_write_callback,
    pub fwrite_rtp: curl_write_callback,
    pub fread_func_set: curl_read_callback,
    pub fprogress: curl_progress_callback,
    pub fxferinfo: curl_xferinfo_callback,
    pub fdebug: curl_debug_callback,
    pub ioctl_func: curl_ioctl_callback,
    pub fsockopt: curl_sockopt_callback,
    pub sockopt_client: *mut libc::c_void,
    pub fopensocket: curl_opensocket_callback,
    pub opensocket_client: *mut libc::c_void,
    pub fclosesocket: curl_closesocket_callback,
    pub closesocket_client: *mut libc::c_void,
    pub seek_client: *mut libc::c_void,
    pub convfromnetwork: curl_conv_callback,
    pub convtonetwork: curl_conv_callback,
    pub convfromutf8: curl_conv_callback,
    #[cfg(not(CURL_DISABLE_HSTS))]
    pub hsts_read: curl_hstsread_callback,
    #[cfg(not(CURL_DISABLE_HSTS))]
    pub hsts_read_userp: *mut libc::c_void,
    #[cfg(not(CURL_DISABLE_HSTS))]
    pub hsts_write: curl_hstswrite_callback,
    #[cfg(not(CURL_DISABLE_HSTS))]
    pub hsts_write_userp: *mut libc::c_void,
    pub progress_client: *mut libc::c_void,
    pub ioctl_client: *mut libc::c_void,
    pub timeout: libc::c_long,
    pub connecttimeout: libc::c_long,
    pub accepttimeout: libc::c_long,
    pub happy_eyeballs_timeout: libc::c_long,
    pub server_response_timeout: libc::c_long,
    pub maxage_conn: libc::c_long,
    pub tftp_blksize: libc::c_long,
    pub filesize: curl_off_t,
    pub low_speed_limit: libc::c_long,
    pub low_speed_time: libc::c_long,
    pub max_send_speed: curl_off_t,
    pub max_recv_speed: curl_off_t,
    pub set_resume_from: curl_off_t,
    pub headers: *mut curl_slist,
    pub proxyheaders: *mut curl_slist,
    pub httppost: *mut curl_httppost,
    pub mimepost: curl_mimepart,
    pub quote: *mut curl_slist,
    pub postquote: *mut curl_slist,
    pub prequote: *mut curl_slist,
    pub source_quote: *mut curl_slist,
    pub source_prequote: *mut curl_slist,
    pub source_postquote: *mut curl_slist,
    pub telnet_options: *mut curl_slist,
    pub resolve: *mut curl_slist,
    pub connect_to: *mut curl_slist,
    pub timecondition: curl_TimeCond,
    pub proxytype: curl_proxytype,
    pub timevalue: time_t,
    pub method: Curl_HttpReq,
    pub httpwant: libc::c_uchar,
    pub ssl: ssl_config_data,
    #[cfg(not(CURL_DISABLE_PROXY))]
    pub proxy_ssl: ssl_config_data,
    pub general_ssl: ssl_general_config,
    pub dns_cache_timeout: libc::c_long,
    pub buffer_size: libc::c_long,
    pub upload_buffer_size: libc::c_uint,
    pub private_data: *mut libc::c_void,
    pub http200aliases: *mut curl_slist,
    pub ipver: libc::c_uchar,
    pub max_filesize: curl_off_t,
    #[cfg(not(CURL_DISABLE_FTP))]
    pub ftp_filemethod: curl_ftpfile,
    #[cfg(not(CURL_DISABLE_FTP))]
    pub ftpsslauth: curl_ftpauth,
    #[cfg(not(CURL_DISABLE_FTP))]
    pub ftp_ccc: curl_ftpccc,
    pub ftp_create_missing_dirs: libc::c_int,
    pub ssh_keyfunc: curl_sshkeycallback,
    pub ssh_keyfunc_userp: *mut libc::c_void,
    #[cfg(not(CURL_DISABLE_NETRC))]
    pub use_netrc: CURL_NETRC_OPTION,
    pub use_ssl: curl_usessl,
    pub new_file_perms: libc::c_long,
    pub new_directory_perms: libc::c_long,
    pub ssh_auth_types: libc::c_long,
    pub str_0: [*mut libc::c_char; 80],
    pub blobs: [*mut curl_blob; 8],
    pub scope_id: libc::c_uint,
    pub allowed_protocols: libc::c_long,
    pub redir_protocols: libc::c_long,
    pub mail_rcpt: *mut curl_slist,
    pub rtspreq: Curl_RtspReq,
    pub rtspversion: libc::c_long,
    pub chunk_bgn: curl_chunk_bgn_callback,
    pub chunk_end: curl_chunk_end_callback,
    pub fnmatch: curl_fnmatch_callback,
    pub fnmatch_data: *mut libc::c_void,
    pub gssapi_delegation: libc::c_long,
    pub tcp_keepidle: libc::c_long,
    pub tcp_keepintvl: libc::c_long,
    pub maxconnects: size_t,
    pub expect_100_timeout: libc::c_long,
    pub stream_depends_on: *mut Curl_easy,
    pub stream_weight: libc::c_int,
    pub stream_dependents: *mut Curl_http2_dep,
    pub resolver_start: curl_resolver_start_callback,
    pub resolver_start_client: *mut libc::c_void,
    pub upkeep_interval_ms: libc::c_long,
    pub fmultidone: multidone_func,
    pub dohfor: *mut Curl_easy,
    pub uh: *mut CURLU,
    pub trailer_data: *mut libc::c_void,
    pub trailer_callback: curl_trailer_callback,
    #[cfg(all(not(CURL_DISABLE_FTP), not(HAVE_GSSAPI)))]
    #[bitfield(name = "is_fread_set", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_fwrite_set", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "free_referer", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tftp_no_options", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "sep_headers", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "cookiesession", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "crlf", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "strip_path_slash", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ssh_compression", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "get_filetime", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "tunnel_thru_httpproxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "remote_append", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "list_only", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "ftp_use_port", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "ftp_use_pret", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "ftp_skip_ip", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "hide_progress", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "http_fail_on_error", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "http_keep_sending_on_error", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "http_follow_location", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "http_transfer_encoding", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "allow_auth_to_other_hosts", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "include_header", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "http_set_referer", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "http_auto_referer", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "opt_no_body", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "upload", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "verbose", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "krb", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "reuse_forbid", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "reuse_fresh", ty = "bit", bits = "33..=33")]
    #[bitfield(name = "no_signal", ty = "bit", bits = "34..=34")]
    #[bitfield(name = "tcp_nodelay", ty = "bit", bits = "35..=35")]
    #[bitfield(name = "ignorecl", ty = "bit", bits = "36..=36")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "37..=37")]
    #[bitfield(name = "http_te_skip", ty = "bit", bits = "38..=38")]
    #[bitfield(name = "http_ce_skip", ty = "bit", bits = "39..=39")]
    #[bitfield(name = "proxy_transfer_mode", ty = "bit", bits = "40..=40")]
    #[bitfield(name = "sasl_ir", ty = "bit", bits = "41..=41")]
    #[bitfield(name = "wildcard_enabled", ty = "bit", bits = "42..=42")]
    #[bitfield(name = "tcp_keepalive", ty = "bit", bits = "43..=43")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "44..=44")]
    #[bitfield(name = "ssl_enable_npn", ty = "bit", bits = "45..=45")]
    #[bitfield(name = "ssl_enable_alpn", ty = "bit", bits = "46..=46")]
    #[bitfield(name = "path_as_is", ty = "bit", bits = "47..=47")]
    #[bitfield(name = "pipewait", ty = "bit", bits = "48..=48")]
    #[bitfield(name = "suppress_connect_headers", ty = "bit", bits = "49..=49")]
    #[bitfield(name = "dns_shuffle_addresses", ty = "bit", bits = "50..=50")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "51..=51")]
    #[bitfield(name = "haproxyprotocol", ty = "bit", bits = "52..=52")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "53..=53")]
    #[bitfield(name = "disallow_username_in_url", ty = "bit", bits = "54..=54")]
    #[bitfield(name = "doh", ty = "bit", bits = "55..=55")]
    #[bitfield(name = "doh_get", ty = "bit", bits = "56..=56")]
    #[bitfield(name = "doh_verifypeer", ty = "bit", bits = "57..=57")]
    #[bitfield(name = "doh_verifyhost", ty = "bit", bits = "58..=58")]
    #[bitfield(name = "doh_verifystatus", ty = "bit", bits = "59..=59")]
    #[bitfield(name = "http09_allowed", ty = "bit", bits = "60..=60")]
    #[bitfield(name = "mail_rcpt_allowfails", ty = "bit", bits = "61..=61")]
    // pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails:
    pub c2rust_abbr: [u8; 8],
    #[cfg(all(CURL_DISABLE_FTP, not(HAVE_GSSAPI)))]
    #[bitfield(name = "is_fread_set", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_fwrite_set", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "free_referer", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tftp_no_options", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "sep_headers", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "cookiesession", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "crlf", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "strip_path_slash", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ssh_compression", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "get_filetime", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "tunnel_thru_httpproxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "remote_append", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "list_only", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "hide_progress", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "http_fail_on_error", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "http_keep_sending_on_error", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "http_follow_location", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "http_transfer_encoding", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "allow_auth_to_other_hosts", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "include_header", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "http_set_referer", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "http_auto_referer", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "opt_no_body", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "upload", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "verbose", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "krb", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "reuse_forbid", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "reuse_fresh", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "no_signal", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "tcp_nodelay", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "ignorecl", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "http_te_skip", ty = "bit", bits = "33..=33")]
    #[bitfield(name = "http_ce_skip", ty = "bit", bits = "34..=34")]
    #[bitfield(name = "proxy_transfer_mode", ty = "bit", bits = "35..=35")]
    #[bitfield(name = "sasl_ir", ty = "bit", bits = "36..=36")]
    #[bitfield(name = "wildcard_enabled", ty = "bit", bits = "37..=37")]
    #[bitfield(name = "tcp_keepalive", ty = "bit", bits = "38..=38")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "39..=39")]
    #[bitfield(name = "ssl_enable_npn", ty = "bit", bits = "40..=40")]
    #[bitfield(name = "ssl_enable_alpn", ty = "bit", bits = "41..=41")]
    #[bitfield(name = "path_as_is", ty = "bit", bits = "42..=42")]
    #[bitfield(name = "pipewait", ty = "bit", bits = "43..=43")]
    #[bitfield(name = "suppress_connect_headers", ty = "bit", bits = "44..=44")]
    #[bitfield(name = "dns_shuffle_addresses", ty = "bit", bits = "45..=45")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "46..=46")]
    #[bitfield(name = "haproxyprotocol", ty = "bit", bits = "47..=47")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "48..=48")]
    #[bitfield(name = "disallow_username_in_url", ty = "bit", bits = "49..=49")]
    #[bitfield(name = "doh", ty = "bit", bits = "50..=50")]
    #[bitfield(name = "doh_get", ty = "bit", bits = "51..=51")]
    #[bitfield(name = "doh_verifypeer", ty = "bit", bits = "52..=52")]
    #[bitfield(name = "doh_verifyhost", ty = "bit", bits = "53..=53")]
    #[bitfield(name = "doh_verifystatus", ty = "bit", bits = "54..=54")]
    #[bitfield(name = "http09_allowed", ty = "bit", bits = "55..=55")]
    #[bitfield(name = "mail_rcpt_allowfails", ty = "bit", bits = "56..=56")]
    // pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails:
        // [u8; 8],
    pub c2rust_abbr: [u8; 8],
    #[cfg(all(not(CURL_DISABLE_FTP), HAVE_GSSAPI))]
    #[bitfield(name = "is_fread_set", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_fwrite_set", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "free_referer", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tftp_no_options", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "sep_headers", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "cookiesession", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "crlf", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "strip_path_slash", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ssh_compression", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "get_filetime", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "tunnel_thru_httpproxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "remote_append", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "list_only", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "ftp_use_port", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "ftp_use_pret", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "ftp_skip_ip", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "hide_progress", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "http_fail_on_error", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "http_keep_sending_on_error", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "http_follow_location", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "http_transfer_encoding", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "allow_auth_to_other_hosts", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "include_header", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "http_set_referer", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "http_auto_referer", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "opt_no_body", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "upload", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "verbose", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "krb", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "reuse_forbid", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "reuse_fresh", ty = "bit", bits = "33..=33")]
    #[bitfield(name = "no_signal", ty = "bit", bits = "34..=34")]
    #[bitfield(name = "tcp_nodelay", ty = "bit", bits = "35..=35")]
    #[bitfield(name = "ignorecl", ty = "bit", bits = "36..=36")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "37..=37")]
    #[bitfield(name = "http_te_skip", ty = "bit", bits = "38..=38")]
    #[bitfield(name = "http_ce_skip", ty = "bit", bits = "39..=39")]
    #[bitfield(name = "proxy_transfer_mode", ty = "bit", bits = "40..=40")]
    #[bitfield(name = "socks5_gssapi_nec", ty = "bit", bits = "41..=41")]
    #[bitfield(name = "sasl_ir", ty = "bit", bits = "42..=42")]
    #[bitfield(name = "wildcard_enabled", ty = "bit", bits = "43..=43")]
    #[bitfield(name = "tcp_keepalive", ty = "bit", bits = "44..=44")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "45..=45")]
    #[bitfield(name = "ssl_enable_npn", ty = "bit", bits = "46..=46")]
    #[bitfield(name = "ssl_enable_alpn", ty = "bit", bits = "47..=47")]
    #[bitfield(name = "path_as_is", ty = "bit", bits = "48..=48")]
    #[bitfield(name = "pipewait", ty = "bit", bits = "49..=49")]
    #[bitfield(name = "suppress_connect_headers", ty = "bit", bits = "50..=50")]
    #[bitfield(name = "dns_shuffle_addresses", ty = "bit", bits = "51..=51")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "52..=52")]
    #[bitfield(name = "haproxyprotocol", ty = "bit", bits = "53..=53")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "54..=54")]
    #[bitfield(name = "disallow_username_in_url", ty = "bit", bits = "55..=55")]
    #[bitfield(name = "doh", ty = "bit", bits = "56..=56")]
    #[bitfield(name = "doh_get", ty = "bit", bits = "57..=57")]
    #[bitfield(name = "doh_verifypeer", ty = "bit", bits = "58..=58")]
    #[bitfield(name = "doh_verifyhost", ty = "bit", bits = "59..=59")]
    #[bitfield(name = "doh_verifystatus", ty = "bit", bits = "60..=60")]
    #[bitfield(name = "http09_allowed", ty = "bit", bits = "61..=61")]
    #[bitfield(name = "mail_rcpt_allowfails", ty = "bit", bits = "62..=62")]
    pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_socks5_gssapi_nec_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails:
        [u8; 8],
    #[cfg(all(CURL_DISABLE_FTP, HAVE_GSSAPI))]
    #[bitfield(name = "is_fread_set", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_fwrite_set", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "free_referer", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tftp_no_options", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "sep_headers", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "cookiesession", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "crlf", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "strip_path_slash", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ssh_compression", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "get_filetime", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "tunnel_thru_httpproxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "remote_append", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "list_only", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "hide_progress", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "http_fail_on_error", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "http_keep_sending_on_error", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "http_follow_location", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "http_transfer_encoding", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "allow_auth_to_other_hosts", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "include_header", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "http_set_referer", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "http_auto_referer", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "opt_no_body", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "upload", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "verbose", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "krb", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "reuse_forbid", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "reuse_fresh", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "no_signal", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "tcp_nodelay", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "ignorecl", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "http_te_skip", ty = "bit", bits = "33..=33")]
    #[bitfield(name = "http_ce_skip", ty = "bit", bits = "34..=34")]
    #[bitfield(name = "proxy_transfer_mode", ty = "bit", bits = "35..=35")]
    #[bitfield(name = "socks5_gssapi_nec", ty = "bit", bits = "36..=36")]
    #[bitfield(name = "sasl_ir", ty = "bit", bits = "37..=37")]
    #[bitfield(name = "wildcard_enabled", ty = "bit", bits = "38..=38")]
    #[bitfield(name = "tcp_keepalive", ty = "bit", bits = "39..=39")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "40..=40")]
    #[bitfield(name = "ssl_enable_npn", ty = "bit", bits = "41..=41")]
    #[bitfield(name = "ssl_enable_alpn", ty = "bit", bits = "42..=42")]
    #[bitfield(name = "path_as_is", ty = "bit", bits = "43..=43")]
    #[bitfield(name = "pipewait", ty = "bit", bits = "44..=44")]
    #[bitfield(name = "suppress_connect_headers", ty = "bit", bits = "45..=45")]
    #[bitfield(name = "dns_shuffle_addresses", ty = "bit", bits = "46..=46")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "47..=47")]
    #[bitfield(name = "haproxyprotocol", ty = "bit", bits = "48..=48")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "49..=49")]
    #[bitfield(name = "disallow_username_in_url", ty = "bit", bits = "50..=50")]
    #[bitfield(name = "doh", ty = "bit", bits = "51..=51")]
    #[bitfield(name = "doh_get", ty = "bit", bits = "52..=52")]
    #[bitfield(name = "doh_verifypeer", ty = "bit", bits = "53..=53")]
    #[bitfield(name = "doh_verifyhost", ty = "bit", bits = "54..=54")]
    #[bitfield(name = "doh_verifystatus", ty = "bit", bits = "55..=55")]
    #[bitfield(name = "http09_allowed", ty = "bit", bits = "56..=56")]
    #[bitfield(name = "mail_rcpt_allowfails", ty = "bit", bits = "57..=57")]
    // pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_socks5_gssapi_nec_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails:
        // [u8; 8],
    pub c2rust_abbr: [u8; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_http2_dep {
    pub next: *mut Curl_http2_dep,
    pub data: *mut Curl_easy,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_khkey {
    pub key: *const libc::c_char,
    pub len: size_t,
    pub keytype: curl_khtype,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssl_general_config {
    pub max_ssl_sessions: size_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_config_data {
    pub primary: ssl_primary_config,
    pub certverifyresult: libc::c_long,
    pub CRLfile: *mut libc::c_char,
    pub fsslctx: curl_ssl_ctx_callback,
    pub fsslctxp: *mut libc::c_void,
    pub cert_type: *mut libc::c_char,
    pub key: *mut libc::c_char,
    pub key_blob: *mut curl_blob,
    pub key_type: *mut libc::c_char,
    pub key_passwd: *mut libc::c_char,
    #[cfg(USE_TLS_SRP)]
    pub username: *mut libc::c_char,
    #[cfg(USE_TLS_SRP)]
    pub password: *mut libc::c_char,
    #[cfg(USE_TLS_SRP)]
    pub authtype: CURL_TLSAUTH,
    #[bitfield(name = "certinfo", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "falsestart", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "enable_beast", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "no_revoke", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "no_partialchain", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "revoke_best_effort", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "native_ca_store", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "auto_client_cert", ty = "bit", bits = "7..=7")]
    // pub certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert: [u8; 1],
    pub c2rust_abbr: [u8; 1],
    #[bitfield(padding)]
    #[cfg(USE_TLS_SRP)]
    pub c2rust_padding: [u8; 3],
    #[cfg(not(USE_TLS_SRP))]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_mimepart {
    pub easy: *mut Curl_easy,
    pub parent: *mut curl_mime,
    pub nextpart: *mut curl_mimepart,
    pub kind: mimekind,
    pub flags: libc::c_uint,
    pub data: *mut libc::c_char,
    pub readfunc: curl_read_callback,
    pub seekfunc: curl_seek_callback,
    pub freefunc: curl_free_callback,
    pub arg: *mut libc::c_void,
    pub fp: *mut FILE,
    pub curlheaders: *mut curl_slist,
    pub userheaders: *mut curl_slist,
    pub mimetype: *mut libc::c_char,
    pub filename: *mut libc::c_char,
    pub name: *mut libc::c_char,
    pub datasize: curl_off_t,
    pub state: mime_state,
    pub encoder: *const mime_encoder,
    pub encstate: mime_encoder_state,
    pub lastreadstatus: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder_state {
    pub pos: size_t,
    pub bufbeg: size_t,
    pub bufend: size_t,
    pub buf: [libc::c_char; 256],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder {
    pub name: *const libc::c_char,
    pub encodefunc: Option::<
        unsafe extern "C" fn(
            *mut libc::c_char,
            size_t,
            bool,
            *mut curl_mimepart,
        ) -> size_t,
    >,
    pub sizefunc: Option::<unsafe extern "C" fn(*mut curl_mimepart) -> curl_off_t>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_state {
    pub state: mimestate,
    pub ptr: *mut libc::c_void,
    pub offset: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_mime {
    pub easy: *mut Curl_easy,
    pub parent: *mut curl_mimepart,
    pub firstpart: *mut curl_mimepart,
    pub lastpart: *mut curl_mimepart,
    pub boundary: [libc::c_char; 41],
    pub state: mime_state,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_httppost {
    pub next: *mut curl_httppost,
    pub name: *mut libc::c_char,
    pub namelength: libc::c_long,
    pub contents: *mut libc::c_char,
    pub contentslength: libc::c_long,
    pub buffer: *mut libc::c_char,
    pub bufferlength: libc::c_long,
    pub contenttype: *mut libc::c_char,
    pub contentheader: *mut curl_slist,
    pub more: *mut curl_httppost,
    pub flags: libc::c_long,
    pub showfilename: *mut libc::c_char,
    pub userp: *mut libc::c_void,
    pub contentlen: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_sockaddr {
    pub family: libc::c_int,
    pub socktype: libc::c_int,
    pub protocol: libc::c_int,
    pub addrlen: libc::c_uint,
    pub addr: sockaddr,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct SingleRequest {
    pub size: curl_off_t,
    pub maxdownload: curl_off_t,
    pub bytecount: curl_off_t,
    pub writebytecount: curl_off_t,
    pub headerbytecount: curl_off_t,
    pub deductheadercount: curl_off_t,
    pub pendingheader: curl_off_t,
    pub start: curltime,
    pub now: curltime,
    pub badheader: C2RustUnnamed_1,
    pub headerline: libc::c_int,
    pub str_0: *mut libc::c_char,
    pub offset: curl_off_t,
    pub httpcode: libc::c_int,
    pub keepon: libc::c_int,
    pub start100: curltime,
    pub exp100: expect100,
    pub upgr101: upgrade101,
    pub writer_stack: *mut contenc_writer,
    pub timeofdoc: time_t,
    pub bodywrites: libc::c_long,
    pub location: *mut libc::c_char,
    pub newurl: *mut libc::c_char,
    pub upload_present: ssize_t,
    pub upload_fromhere: *mut libc::c_char,
    pub p: C2RustUnnamed,
    #[cfg(not(CURL_DISABLE_DOH))]
    pub doh: *mut dohdata,
    #[bitfield(name = "header", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "content_range", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "upload_done", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "ignorebody", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "http_bodyless", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "chunk", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "ignore_cl", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "upload_chunky", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "getheader", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "forbidchunk", ty = "bit", bits = "9..=9")]
    // pub header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk: [u8; 2],
    pub c2rust_abbr: [u8; 2],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dohdata {
    pub headers: *mut curl_slist,
    pub probe: [dnsprobe; 2],
    pub pending: libc::c_uint,
    pub port: libc::c_int,
    pub host: *const libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dnsprobe {
    pub easy: *mut CURL,
    pub dnstype: libc::c_int,
    pub dohbuffer: [libc::c_uchar; 512],
    pub dohlen: size_t,
    pub serverdoh: dynbuf,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub file: *mut FILEPROTO,
    pub ftp: *mut FTP,
    pub http: *mut HTTP,
    pub imap: *mut IMAP,
    pub ldap: *mut ldapreqinfo,
    pub mqtt: *mut MQTT,
    pub pop3: *mut POP3,
    pub rtsp: *mut RTSP,
    pub smb: *mut smb_request,
    pub smtp: *mut SMTP,
    pub ssh: *mut SSHPROTO,
    pub telnet: *mut TELNET,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SSHPROTO {
    pub path: *mut libc::c_char,
    #[cfg(USE_LIBSSH2)]
    pub readdir_link: dynbuf,
    #[cfg(USE_LIBSSH2)]
    pub readdir: dynbuf,
    #[cfg(USE_LIBSSH2)]
    pub readdir_filename: *mut libc::c_char,
    #[cfg(USE_LIBSSH2)]
    pub readdir_longentry: *mut libc::c_char,
    #[cfg(USE_LIBSSH2)]
    pub quote_attrs: LIBSSH2_SFTP_ATTRIBUTES,
    #[cfg(USE_LIBSSH2)]
    pub readdir_attrs: LIBSSH2_SFTP_ATTRIBUTES,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _LIBSSH2_SFTP_ATTRIBUTES {
    pub flags: libc::c_ulong,
    pub filesize: libssh2_uint64_t,
    pub uid: libc::c_ulong,
    pub gid: libc::c_ulong,
    pub permissions: libc::c_ulong,
    pub atime: libc::c_ulong,
    pub mtime: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SMTP {
    pub transfer: curl_pp_transfer,
    pub custom: *mut libc::c_char,
    pub rcpt: *mut curl_slist,
    pub rcpt_had_ok: bool,
    pub trailing_crlf: bool,
    pub rcpt_last_error: libc::c_int,
    pub eob: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct RTSP {
    pub http_wrapper: HTTP,
    pub CSeq_sent: libc::c_long,
    pub CSeq_recv: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HTTP {
    pub sendit: *mut curl_mimepart,
    pub postsize: curl_off_t,
    pub postdata: *const libc::c_char,
    pub p_pragma: *const libc::c_char,
    pub form: curl_mimepart,
    pub backup: back,
    pub sending: C2RustUnnamed_0,
    #[cfg(not(CURL_DISABLE_HTTP))]
    pub send_buffer: dynbuf,
    #[cfg(USE_NGHTTP2)]
    pub stream_id: int32_t,
    #[cfg(USE_NGHTTP2)]
    pub bodystarted: bool,
    #[cfg(USE_NGHTTP2)]
    pub header_recvbuf: dynbuf,
    #[cfg(USE_NGHTTP2)]
    pub nread_header_recvbuf: size_t,
    #[cfg(USE_NGHTTP2)]
    pub trailer_recvbuf: dynbuf,
    #[cfg(USE_NGHTTP2)]
    pub status_code: libc::c_int,
    #[cfg(USE_NGHTTP2)]
    pub pausedata: *const uint8_t,
    #[cfg(USE_NGHTTP2)]
    pub pauselen: size_t,
    #[cfg(USE_NGHTTP2)]
    pub close_handled: bool,
    #[cfg(USE_NGHTTP2)]
    pub push_headers: *mut *mut libc::c_char,
    #[cfg(USE_NGHTTP2)]
    pub push_headers_used: size_t,
    #[cfg(USE_NGHTTP2)]
    pub push_headers_alloc: size_t,
    #[cfg(USE_NGHTTP2)]
    pub error: uint32_t,
    #[cfg(any(USE_NGHTTP2, USE_NGHTTP3))]
    pub closed: bool,
    #[cfg(any(USE_NGHTTP2, USE_NGHTTP3))]
    pub mem: *mut libc::c_char,
    #[cfg(any(USE_NGHTTP2, USE_NGHTTP3))]
    pub len: size_t,
    #[cfg(any(USE_NGHTTP2, USE_NGHTTP3))]
    pub memlen: size_t,
    #[cfg(any(USE_NGHTTP2, ENABLE_QUIC))]
    pub upload_mem: *const uint8_t,
    #[cfg(any(USE_NGHTTP2, ENABLE_QUIC))]
    pub upload_len: size_t,
    #[cfg(any(USE_NGHTTP2, ENABLE_QUIC))]
    pub upload_left: curl_off_t,
    #[cfg(ENABLE_QUIC)]
    pub stream3_id: int64_t,
    #[cfg(ENABLE_QUIC)]
    pub firstheader: bool,
    #[cfg(ENABLE_QUIC)]
    pub firstbody: bool,
    #[cfg(ENABLE_QUIC)]
    pub h3req: bool,
    #[cfg(ENABLE_QUIC)]
    pub upload_done: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct back {
    pub fread_func: curl_read_callback,
    pub fread_in: *mut libc::c_void,
    pub postdata: *const libc::c_char,
    pub postsize: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POP3 {
    pub transfer: curl_pp_transfer,
    pub id: *mut libc::c_char,
    pub custom: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct MQTT {
    pub sendleftovers: *mut libc::c_char,
    pub nsend: size_t,
    pub npacket: size_t,
    pub firstbyte: libc::c_uchar,
    pub remaining_length: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAP {
    pub transfer: curl_pp_transfer,
    pub mailbox: *mut libc::c_char,
    pub uidvalidity: *mut libc::c_char,
    pub uid: *mut libc::c_char,
    pub mindex: *mut libc::c_char,
    pub section: *mut libc::c_char,
    pub partial: *mut libc::c_char,
    pub query: *mut libc::c_char,
    pub custom: *mut libc::c_char,
    pub custom_params: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FTP {
    pub path: *mut libc::c_char,
    pub pathalloc: *mut libc::c_char,
    pub transfer: curl_pp_transfer,
    pub downloadsize: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FILEPROTO {
    pub path: *mut libc::c_char,
    pub freepath: *mut libc::c_char,
    pub fd: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PslCache {
    pub psl: *const psl_ctx_t,
    pub expires: time_t,
    pub dynamic: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_multi {
    pub magic: libc::c_uint,
    pub easyp: *mut Curl_easy,
    pub easylp: *mut Curl_easy,
    pub num_easy: libc::c_int,
    pub num_alive: libc::c_int,
    pub msglist: Curl_llist,
    pub pending: Curl_llist,
    pub socket_cb: curl_socket_callback,
    pub socket_userp: *mut libc::c_void,
    pub push_cb: curl_push_callback,
    pub push_userp: *mut libc::c_void,
    pub hostcache: Curl_hash,
    #[cfg(USE_LIBPSL)]
    pub psl: PslCache,
    pub timetree: *mut Curl_tree,
    pub sockhash: Curl_hash,
    pub conn_cache: conncache,
    pub maxconnects: libc::c_long,
    pub max_host_connections: libc::c_long,
    pub max_total_connections: libc::c_long,
    pub timer_cb: curl_multi_timer_callback,
    pub timer_userp: *mut libc::c_void,
    pub timer_lastcall: curltime,
    pub max_concurrent_streams: libc::c_uint,
    #[cfg(ENABLE_WAKEUP)]
    pub wakeup_pair: [curl_socket_t; 2],
    pub multiplexing: bool,
    pub recheckstate: bool,
    pub in_callback: bool,
    pub ipv6_works: bool,
    #[cfg(USE_OPENSSL)]
    pub ssl_seeded: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Names {
    pub hostcache: *mut Curl_hash,
    pub hostcachetype: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_message {
    pub list: Curl_llist_element,
    pub extmsg: CURLMsg,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CURLMsg {
    pub msg: CURLMSG,
    pub easy_handle: *mut CURL,
    pub data: C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub whatever: *mut libc::c_void,
    pub result: CURLcode,
}
#[derive(Copy, Clone)]
#[repr(C)]
#[cfg(USE_GSASL)]
pub struct gsasldata {
    pub ctx: *mut Gsasl,
    pub client: *mut Gsasl_session,
}
#[derive(Copy, Clone)]
#[repr(C)]
#[cfg(USE_QUICHE)]
pub struct quicsocket {
    pub cfg: *mut quiche_config,
    pub conn: *mut quiche_conn,
    pub h3c: *mut quiche_h3_conn,
    pub h3config: *mut quiche_h3_config,
    pub scid: [uint8_t; 20],
    pub sockfd: curl_socket_t,
    pub version: uint32_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct connectdata {
    pub cnnct: connstate,
    pub bundle_node: Curl_llist_element,
    pub chunk: Curl_chunker,
    pub fclosesocket: curl_closesocket_callback,
    pub closesocket_client: *mut libc::c_void,
    pub connection_id: libc::c_long,
    pub dns_entry: *mut Curl_dns_entry,
    pub ip_addr: *mut Curl_addrinfo,
    pub tempaddr: [*mut Curl_addrinfo; 2],
    pub scope_id: libc::c_uint,
    pub transport: C2RustUnnamed_6,
    #[cfg(ENABLE_QUIC)]
    pub hequic: [quicsocket; 2],
    #[cfg(ENABLE_QUIC)]
    pub quic: *mut quicsocket,
    pub host: hostname,
    pub hostname_resolve: *mut libc::c_char,
    pub secondaryhostname: *mut libc::c_char,
    pub conn_to_host: hostname,
    #[cfg(not(CURL_DISABLE_PROXY))]
    pub socks_proxy: proxy_info,
    #[cfg(not(CURL_DISABLE_PROXY))]
    pub http_proxy: proxy_info,
    pub port: libc::c_int,
    pub remote_port: libc::c_int,
    pub conn_to_port: libc::c_int,
    pub secondary_port: libc::c_ushort,
    pub primary_ip: [libc::c_char; 46],
    pub ip_version: libc::c_uchar,
    pub user: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
    pub options: *mut libc::c_char,
    pub sasl_authzid: *mut libc::c_char,
    pub httpversion: libc::c_uchar,
    pub now: curltime,
    pub created: curltime,
    pub lastused: curltime,
    pub sock: [curl_socket_t; 2],
    pub tempsock: [curl_socket_t; 2],
    pub tempfamily: [libc::c_int; 2],
    pub recv: [Option::<Curl_recv>; 2],
    pub send: [Option::<Curl_send>; 2],
    pub ssl: [ssl_connect_data; 2],
    #[cfg(not(CURL_DISABLE_PROXY))]
    pub proxy_ssl: [ssl_connect_data; 2],
    #[cfg(USE_SSL)]
    pub ssl_extra: *mut libc::c_void,
    pub ssl_config: ssl_primary_config,
    #[cfg(not(CURL_DISABLE_PROXY))]
    pub proxy_ssl_config: ssl_primary_config,
    pub bits: ConnectBits,
    pub num_addr: libc::c_int,
    pub connecttime: curltime,
    pub timeoutms_per_addr: [timediff_t; 2],
    pub handler: *const Curl_handler,
    pub given: *const Curl_handler,
    pub keepalive: curltime,
    pub sockfd: curl_socket_t,
    pub writesockfd: curl_socket_t,
    #[cfg(HAVE_GSSAPI)]
    #[bitfield(name = "sec_complete", ty = "bit", bits = "0..=0")]   
    pub sec_complete: [u8; 1],
    #[cfg(HAVE_GSSAPI)]
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
    #[cfg(HAVE_GSSAPI)]
    pub command_prot: protection_level,
    #[cfg(HAVE_GSSAPI)]
    pub data_prot: protection_level,
    #[cfg(HAVE_GSSAPI)]
    pub request_data_prot: protection_level,
    #[cfg(HAVE_GSSAPI)]
    pub buffer_size: size_t,
    #[cfg(HAVE_GSSAPI)]
    pub in_buffer: krb5buffer,
    #[cfg(HAVE_GSSAPI)]
    pub app_data: *mut libc::c_void,
    #[cfg(HAVE_GSSAPI)]
    pub mech: *const Curl_sec_client_mech,
    #[cfg(HAVE_GSSAPI)]
    pub local_addr: sockaddr_in,
    #[cfg(USE_KERBEROS5)]
    pub krb5: kerberos5data,
    pub easyq: Curl_llist,
    pub seek_func: curl_seek_callback,
    pub seek_client: *mut libc::c_void,
    #[cfg(USE_GSASL)]
    pub gsasl: gsasldata,
    #[cfg(USE_NTLM)]
    pub http_ntlm_state: curlntlm,
    #[cfg(USE_NTLM)]
    pub proxy_ntlm_state: curlntlm,
    #[cfg(USE_NTLM)]
    pub ntlm: ntlmdata,
    #[cfg(USE_NTLM)]
    pub proxyntlm: ntlmdata,
    #[cfg(USE_SPNEGO)]
    pub http_negotiate_state: curlnegotiate,
    #[cfg(USE_SPNEGO)]
    pub proxy_negotiate_state: curlnegotiate,
    #[cfg(USE_SPNEGO)]
    pub negotiate: negotiatedata,
    #[cfg(USE_SPNEGO)]
    pub proxyneg: negotiatedata,
    pub trailer: dynbuf,
    pub proto: C2RustUnnamed_5,
    pub connect_state: *mut http_connect_state,
    pub bundle: *mut connectbundle,
    #[cfg(USE_UNIX_SOCKETS)]
    pub unix_domain_socket: *mut libc::c_char,
    #[cfg(USE_HYPER)]
    pub datastream: Curl_datastream,
    pub localdev: *mut libc::c_char,
    pub localportrange: libc::c_int,
    pub cselect_bits: libc::c_int,
    pub waitfor: libc::c_int,
    pub negnpn: libc::c_int,
    #[cfg(HAVE_GSSAPI)]
    pub socks5_gssapi_enctype: libc::c_int,
    pub localport: libc::c_ushort,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connectbundle {
    pub multiuse: libc::c_int,
    pub num_connections: size_t,
    pub conn_list: Curl_llist,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct http_connect_state {
    pub http_proxy: HTTP,
    pub prot_save: *mut HTTP,
    pub rcvbuf: dynbuf,
    pub req: dynbuf,
    pub nsend: size_t,
    pub keepon: keeponval,
    pub cl: curl_off_t,
    pub tunnel_state: C2RustUnnamed_4,
    #[bitfield(name = "chunked_encoding", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "close_connection", ty = "bit", bits = "1..=1")]
    pub chunked_encoding_close_connection: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_5 {
    pub ftpc: ftp_conn,
    pub httpc: http_conn,
    pub sshc: ssh_conn,
    pub tftpc: *mut tftp_state_data,
    pub imapc: imap_conn,
    pub pop3c: pop3_conn,
    pub smtpc: smtp_conn,
    pub rtspc: rtsp_conn,
    pub smbc: smb_conn,
    pub rtmp: *mut libc::c_void,
    pub ldapc: *mut ldapconninfo,
    pub mqtt: mqtt_conn,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mqtt_conn {
    pub state: mqttstate,
    pub nextstate: mqttstate,
    pub packetid: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct smb_conn {
    pub state: smb_conn_state,
    pub user: *mut libc::c_char,
    pub domain: *mut libc::c_char,
    pub share: *mut libc::c_char,
    pub challenge: [libc::c_uchar; 8],
    pub session_key: libc::c_uint,
    pub uid: libc::c_ushort,
    pub recv_buf: *mut libc::c_char,
    pub upload_size: size_t,
    pub send_size: size_t,
    pub sent: size_t,
    pub got: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rtsp_conn {
    pub rtp_buf: *mut libc::c_char,
    pub rtp_bufsize: ssize_t,
    pub rtp_channel: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct smtp_conn {
    pub pp: pingpong,
    pub state: smtpstate,
    pub ssldone: bool,
    pub domain: *mut libc::c_char,
    pub sasl: SASL,
    pub tls_supported: bool,
    pub size_supported: bool,
    pub utf8_supported: bool,
    pub auth_supported: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SASL {
    pub params: *const SASLproto,
    pub state: saslstate,
    pub authmechs: libc::c_ushort,
    pub prefmech: libc::c_ushort,
    pub authused: libc::c_ushort,
    pub resetprefs: bool,
    pub mutual_auth: bool,
    pub force_ir: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SASLproto {
    pub service: *const libc::c_char,
    pub contcode: libc::c_int,
    pub finalcode: libc::c_int,
    pub maxirlen: size_t,
    pub sendauth: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *const libc::c_char,
            *const libc::c_char,
        ) -> CURLcode,
    >,
    pub sendcont: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *const libc::c_char,
        ) -> CURLcode,
    >,
    pub getmessage: Option::<
        unsafe extern "C" fn(*mut libc::c_char, *mut *mut libc::c_char) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pingpong {
    pub cache: *mut libc::c_char,
    pub cache_size: size_t,
    pub nread_resp: size_t,
    pub linestart_resp: *mut libc::c_char,
    pub pending_resp: bool,
    pub sendthis: *mut libc::c_char,
    pub sendleft: size_t,
    pub sendsize: size_t,
    pub response: curltime,
    pub response_time: timediff_t,
    pub sendbuf: dynbuf,
    pub statemachine: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
    >,
    pub endofresp: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut libc::c_char,
            size_t,
            *mut libc::c_int,
        ) -> bool,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pop3_conn {
    pub pp: pingpong,
    pub state: pop3state,
    pub ssldone: bool,
    pub tls_supported: bool,
    pub eob: size_t,
    pub strip: size_t,
    pub sasl: SASL,
    pub authtypes: libc::c_uint,
    pub preftype: libc::c_uint,
    pub apoptimestamp: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct imap_conn {
    pub pp: pingpong,
    pub state: imapstate,
    pub ssldone: bool,
    pub preauth: bool,
    pub sasl: SASL,
    pub preftype: libc::c_uint,
    pub cmdid: libc::c_uint,
    pub resptag: [libc::c_char; 5],
    pub tls_supported: bool,
    pub login_disabled: bool,
    pub ir_supported: bool,
    pub mailbox: *mut libc::c_char,
    pub mailbox_uidvalidity: *mut libc::c_char,
    pub dyn_0: dynbuf,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_request_queue_struct {
    pub next: sftp_request_queue,
    pub message: sftp_message,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_message_struct {
    pub sftp: sftp_session,
    pub packet_type: uint8_t,
    pub payload: ssh_buffer,
    pub id: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_session_struct {
    pub session: ssh_session,
    pub channel: ssh_channel,
    pub server_version: libc::c_int,
    pub client_version: libc::c_int,
    pub version: libc::c_int,
    pub queue: sftp_request_queue,
    pub id_counter: uint32_t,
    pub errnum: libc::c_int,
    pub handles: *mut *mut libc::c_void,
    pub ext: sftp_ext,
    pub read_packet: sftp_packet,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_packet_struct {
    pub sftp: sftp_session,
    pub type_0: uint8_t,
    pub payload: ssh_buffer,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_file_struct {
    pub sftp: sftp_session,
    pub name: *mut libc::c_char,
    pub offset: uint64_t,
    pub handle: ssh_string,
    pub eof: libc::c_int,
    pub nonblocking: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_dir_struct {
    pub sftp: sftp_session,
    pub name: *mut libc::c_char,
    pub handle: ssh_string,
    pub buffer: ssh_buffer,
    pub count: uint32_t,
    pub eof: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_attributes_struct {
    pub name: *mut libc::c_char,
    pub longname: *mut libc::c_char,
    pub flags: uint32_t,
    pub type_0: uint8_t,
    pub size: uint64_t,
    pub uid: uint32_t,
    pub gid: uint32_t,
    pub owner: *mut libc::c_char,
    pub group: *mut libc::c_char,
    pub permissions: uint32_t,
    pub atime64: uint64_t,
    pub atime: uint32_t,
    pub atime_nseconds: uint32_t,
    pub createtime: uint64_t,
    pub createtime_nseconds: uint32_t,
    pub mtime64: uint64_t,
    pub mtime: uint32_t,
    pub mtime_nseconds: uint32_t,
    pub acl: ssh_string,
    pub extended_count: uint32_t,
    pub extended_type: ssh_string,
    pub extended_data: ssh_string,
}
#[derive(Copy, Clone)]
#[repr(C)]
// 没有 HAVE_LIBSSH2_AGENT_API 和 USE_WOLFSSH
pub struct ssh_conn {
    pub authlist: *const libc::c_char,
    pub passphrase: *const libc::c_char,
    pub rsa_pub: *mut libc::c_char,
    pub rsa: *mut libc::c_char,
    pub authed: bool,
    pub acceptfail: bool,
    pub state: sshstate,
    pub nextstate: sshstate,
    pub actualcode: CURLcode,
    pub quote_item: *mut curl_slist,
    pub quote_path1: *mut libc::c_char,
    pub quote_path2: *mut libc::c_char,
    pub homedir: *mut libc::c_char,
    pub readdir_line: *mut libc::c_char,
    pub secondCreateDirs: libc::c_int,
    pub orig_waitfor: libc::c_int,
    pub slash_pos: *mut libc::c_char,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub readdir_linkPath: *mut libc::c_char,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub readdir_len: size_t,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub readdir_totalLen: size_t,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub readdir_currLen: size_t,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub kbd_state: libc::c_uint,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub privkey: ssh_key,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub pubkey: ssh_key,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub auth_methods: libc::c_int,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub ssh_session: ssh_session,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub scp_session: ssh_scp,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub sftp_session: sftp_session,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub sftp_file: sftp_file,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub sftp_dir: sftp_dir,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub sftp_recv_state: libc::c_uint,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub sftp_file_index: libc::c_int,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub readdir_attrs: sftp_attributes,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub readdir_link_attrs: sftp_attributes,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub quote_attrs: sftp_attributes,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub readdir_filename: *const libc::c_char,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub readdir_longentry: *const libc::c_char,
    #[cfg(all(USE_LIBSSH, not(USE_LIBSSH2)))]
    pub readdir_tmp: *mut libc::c_char,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2))]
    pub ssh_session: *mut LIBSSH2_SESSION,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2))]
    pub ssh_channel: *mut LIBSSH2_CHANNEL,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2))]
    pub sftp_session: *mut LIBSSH2_SFTP,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2))]
    pub sftp_handle: *mut LIBSSH2_SFTP_HANDLE,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2, not(CURL_DISABLE_PROXY)))]
    pub tls_recv: Option::<Curl_recv>,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2, not(CURL_DISABLE_PROXY)))]
    pub tls_send: Option::<Curl_send>,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2))]
    pub ssh_agent: *mut LIBSSH2_AGENT,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2))]
    pub sshagent_identity: *mut libssh2_agent_publickey,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2))]
    pub sshagent_prev_identity: *mut libssh2_agent_publickey,
    #[cfg(all(not(USE_LIBSSH), USE_LIBSSH2))]
    pub kh: *mut LIBSSH2_KNOWNHOSTS,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct http_conn {
    #[cfg(USE_NGHTTP2)]
    pub binsettings: [uint8_t; 80],
    #[cfg(USE_NGHTTP2)]
    pub binlen: size_t,
    #[cfg(USE_NGHTTP2)]
    pub trnsfr: *mut Curl_easy,
    #[cfg(USE_NGHTTP2)]
    pub h2: *mut nghttp2_session,
    #[cfg(USE_NGHTTP2)]
    pub send_underlying: Option::<Curl_send>,
    #[cfg(USE_NGHTTP2)]
    pub recv_underlying: Option::<Curl_recv>,
    #[cfg(USE_NGHTTP2)]
    pub inbuf: *mut libc::c_char,
    #[cfg(USE_NGHTTP2)]
    pub inbuflen: size_t,
    #[cfg(USE_NGHTTP2)]
    pub nread_inbuf: size_t,
    #[cfg(USE_NGHTTP2)]
    pub pause_stream_id: int32_t,
    #[cfg(USE_NGHTTP2)]
    pub drain_total: size_t,
    #[cfg(USE_NGHTTP2)]
    pub settings: h2settings,
    #[cfg(USE_NGHTTP2)]
    pub local_settings: [nghttp2_settings_entry; 3],
    #[cfg(USE_NGHTTP2)]
    pub local_settings_num: size_t,
    #[cfg(not(USE_NGHTTP2))]
    pub unused: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_settings_entry {
    pub settings_id: int32_t,
    pub value: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct h2settings {
    pub max_concurrent_streams: uint32_t,
    pub enable_push: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftp_conn {
    pub pp: pingpong,
    pub entrypath: *mut libc::c_char,
    pub file: *mut libc::c_char,
    pub dirs: *mut *mut libc::c_char,
    pub dirdepth: libc::c_int,
    pub dont_check: bool,
    pub ctl_valid: bool,
    pub cwddone: bool,
    pub cwdcount: libc::c_int,
    pub cwdfail: bool,
    pub wait_data_conn: bool,
    pub newport: libc::c_ushort,
    pub newhost: *mut libc::c_char,
    pub prevpath: *mut libc::c_char,
    pub transfertype: libc::c_char,
    pub count1: libc::c_int,
    pub count2: libc::c_int,
    pub count3: libc::c_int,
    pub state: ftpstate,
    pub state_saved: ftpstate,
    pub retr_size_saved: curl_off_t,
    pub server_os: *mut libc::c_char,
    pub known_filesize: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_handler {
    pub scheme: *const libc::c_char,
    pub setup_connection: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
    >,
    pub do_it: Option::<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub done: Option::<unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode>,
    pub do_more: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_int) -> CURLcode,
    >,
    pub connect_it: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
    >,
    pub connecting: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
    >,
    pub doing: Option::<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub proto_getsock: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut curl_socket_t,
        ) -> libc::c_int,
    >,
    pub doing_getsock: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut curl_socket_t,
        ) -> libc::c_int,
    >,
    pub domore_getsock: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut curl_socket_t,
        ) -> libc::c_int,
    >,
    pub perform_getsock: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut curl_socket_t,
        ) -> libc::c_int,
    >,
    pub disconnect: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
    >,
    pub readwrite: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut ssize_t,
            *mut bool,
        ) -> CURLcode,
    >,
    pub connection_check: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            libc::c_uint,
        ) -> libc::c_uint,
    >,
    pub attach: Option::<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> ()>,
    pub defport: libc::c_int,
    pub protocol: libc::c_uint,
    pub family: libc::c_uint,
    pub flags: libc::c_uint,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ConnectBits {
    pub tcpconnect: [bool; 2],
    #[cfg(not(CURL_DISABLE_PROXY))]
    pub proxy_ssl_connected: [bool; 2],
    #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_FTP), not(CURL_DISABLE_NETRC)))]
    #[bitfield(name = "httpproxy", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "socksproxy", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "proxy_user_passwd", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tunnel_proxy", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "proxy_connect_closed", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "close", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "reuse", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "altused", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "proxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "do_more", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "retry", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "authneg", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "ftp_use_data_ssl", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "ftp_use_control_ssl", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "netrc", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "bound", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "doh", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "33..=33")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "34..=34")]
    // pub httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect: [u8; 5],
    pub c2rust_abbr: [u8; 5],
    #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_FTP), not(CURL_DISABLE_NETRC)))]
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],  
    #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_FTP), CURL_DISABLE_NETRC))]
    #[bitfield(name = "httpproxy", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "socksproxy", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "proxy_user_passwd", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tunnel_proxy", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "proxy_connect_closed", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "close", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "reuse", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "altused", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "proxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "do_more", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "retry", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "authneg", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "ftp_use_data_ssl", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "ftp_use_control_ssl", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "bound", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "doh", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "33..=33")]
    pub c2rust_abbr: [u8; 5],
    #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_FTP), CURL_DISABLE_NETRC))]
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
    #[cfg(all(not(CURL_DISABLE_PROXY), CURL_DISABLE_FTP, not(CURL_DISABLE_NETRC)))]
    #[bitfield(name = "httpproxy", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "socksproxy", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "proxy_user_passwd", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tunnel_proxy", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "proxy_connect_closed", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "close", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "reuse", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "altused", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "proxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "do_more", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "retry", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "authneg", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "netrc", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "bound", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "doh", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "30..=30")]
    pub c2rust_abbr: [u8; 4],
    #[cfg(all(not(CURL_DISABLE_PROXY), CURL_DISABLE_FTP, CURL_DISABLE_NETRC))]
    #[bitfield(name = "httpproxy", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "socksproxy", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "proxy_user_passwd", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tunnel_proxy", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "proxy_connect_closed", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "close", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "reuse", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "altused", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "proxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "do_more", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "retry", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "authneg", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "bound", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "doh", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "29..=29")]
    pub c2rust_abbr: [u8; 4],
    #[cfg(all(CURL_DISABLE_PROXY, not(CURL_DISABLE_FTP), not(CURL_DISABLE_NETRC)))]
    #[bitfield(name = "close", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "reuse", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "altused", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "proxy", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "do_more", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "retry", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "authneg", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "ftp_use_data_ssl", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "ftp_use_control_ssl", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "netrc", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "bound", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "doh", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "29..=29")]
    pub c2rust_abbr: [u8; 4],
    #[cfg(all(CURL_DISABLE_PROXY, not(CURL_DISABLE_FTP), not(CURL_DISABLE_NETRC)))]
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 2],
    #[cfg(all(CURL_DISABLE_PROXY, not(CURL_DISABLE_FTP), CURL_DISABLE_NETRC))]
    #[bitfield(name = "close", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "reuse", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "altused", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "proxy", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "do_more", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "retry", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "authneg", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "ftp_use_data_ssl", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "ftp_use_control_ssl", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "bound", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "doh", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "28..=28")]
    pub c2rust_abbr: [u8; 4],
    #[cfg(all(CURL_DISABLE_PROXY, not(CURL_DISABLE_FTP), CURL_DISABLE_NETRC))]
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 2],
    #[cfg(all(CURL_DISABLE_PROXY, CURL_DISABLE_FTP, not(CURL_DISABLE_NETRC)))]
    #[bitfield(name = "close", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "reuse", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "altused", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "proxy", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "do_more", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "retry", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "authneg", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "netrc", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "bound", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "doh", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "25..=25")]
    pub c2rust_abbr: [u8; 4],
    #[cfg(all(CURL_DISABLE_PROXY, CURL_DISABLE_FTP, not(CURL_DISABLE_NETRC)))]
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 2],
    #[cfg(all(CURL_DISABLE_PROXY, CURL_DISABLE_FTP, CURL_DISABLE_NETRC))]
    #[bitfield(name = "close", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "reuse", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "altused", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "proxy", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "do_more", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "retry", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "authneg", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "bound", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "doh", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "24..=24")]
    pub c2rust_abbr: [u8; 4],
    #[cfg(all(CURL_DISABLE_PROXY, CURL_DISABLE_FTP, CURL_DISABLE_NETRC))]
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 2],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_connect_data {
    pub state: ssl_connection_state,
    pub connecting_state: ssl_connect_state,
    #[cfg(USE_SSL)]
    pub backend: *mut ssl_backend_data,
    #[bitfield(name = "use_0", ty = "bit", bits = "0..=0")]
    pub use_0: [u8; 1],
    #[bitfield(padding)]
    #[cfg(USE_SSL)]
    pub c2rust_padding: [u8; 7],
    #[bitfield(padding)]
    #[cfg(not(USE_SSL))]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct proxy_info {
    pub host: hostname,
    pub port: libc::c_long,
    pub proxytype: curl_proxytype,
    pub user: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostname {
    pub rawalloc: *mut libc::c_char,
    pub encalloc: *mut libc::c_char,
    pub name: *mut libc::c_char,
    pub dispname: *const libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_chunker {
    pub datasize: curl_off_t,
    pub state: ChunkyState,
    pub hexindex: libc::c_uchar,
    pub hexbuffer: [libc::c_char; 17],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connstate {
    pub state: connect_t,
    pub outstanding: ssize_t,
    pub outp: *mut libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_fileinfo {
    pub filename: *mut libc::c_char,
    pub filetype: curlfiletype,
    pub time: time_t,
    pub perm: libc::c_uint,
    pub uid: libc::c_int,
    pub gid: libc::c_int,
    pub size: curl_off_t,
    pub hardlinks: libc::c_long,
    pub strings: C2RustUnnamed_7,
    pub flags: libc::c_uint,
    pub b_data: *mut libc::c_char,
    pub b_size: size_t,
    pub b_used: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_7 {
    pub time: *mut libc::c_char,
    pub perm: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub group: *mut libc::c_char,
    pub target: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_8 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_sockaddr_storage {
    pub buffer: C2RustUnnamed_9,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_9 {
    pub sa: sockaddr,
    pub sa_in: sockaddr_in,
    #[cfg(ENABLE_IPV6)]
    pub sa_in6: sockaddr_in6,
    #[cfg(HAVE_STRUCT_SOCKADDR_STORAGE)]
    pub sa_stor: sockaddr_storage,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_sockaddr_ex {
    pub family: libc::c_int,
    pub socktype: libc::c_int,
    pub protocol: libc::c_int,
    pub addrlen: libc::c_uint,
    pub _sa_ex_u: C2RustUnnamed_10,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_10 {
    pub addr: sockaddr,
    pub buff: Curl_sockaddr_storage,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftp_wc {
    pub parser: *mut ftp_parselist_data,
    pub backup: C2RustUnnamed_11,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_11 {
    pub write_function: curl_write_callback,
    pub file_descriptor: *mut FILE,
}

// ftplistparser.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftp_parselist_data {
    pub os_type: C2RustUnnamed_22,
    pub state: ftpl_C2RustUnnamed_8,
    pub error: CURLcode,
    pub file_data: *mut fileinfo,
    pub item_length: libc::c_uint,
    pub item_offset: size_t,
    pub offsets: ftpl_C2RustUnnamed_7,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftpl_C2RustUnnamed_7 {
    pub filename: size_t,
    pub user: size_t,
    pub group: size_t,
    pub time: size_t,
    pub perm: size_t,
    pub symlink_target: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fileinfo {
    pub info: curl_fileinfo,
    pub list: Curl_llist_element,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union ftpl_C2RustUnnamed_8 {
    pub UNIX: C2RustUnnamed_13,
    pub NT: ftpl_C2RustUnnamed_9,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftpl_C2RustUnnamed_9 {
    pub main: pl_winNT_mainstate,
    pub sub: pl_winNT_substate,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pl_winNT_substate {
    pub time: C2RustUnnamed_12,
    pub dirorsize: ftpl_C2RustUnnamed_11,
    pub filename: ftpl_C2RustUnnamed_10,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_13 {
    pub main: pl_unix_mainstate,
    pub sub: pl_unix_substate,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pl_unix_substate {
    pub total_dirsize: C2RustUnnamed_21,
    pub hlinks: C2RustUnnamed_20,
    pub user: C2RustUnnamed_19,
    pub group: C2RustUnnamed_18,
    pub size: C2RustUnnamed_17,
    pub time: C2RustUnnamed_16,
    pub filename: C2RustUnnamed_15,
    pub symlink: C2RustUnnamed_14,
}
// http_aws_sigv4.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_params {
    pub hmac_hinit: HMAC_hinit_func,
    pub hmac_hupdate: HMAC_hupdate_func,
    pub hmac_hfinal: HMAC_hfinal_func,
    pub hmac_ctxtsize: libc::c_uint,
    pub hmac_maxkeylen: libc::c_uint,
    pub hmac_resultlen: libc::c_uint,
}
// http_chunks.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct contenc_writer {
    pub handler: *const content_encoding,
    pub downstream: *mut contenc_writer,
    pub params: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct content_encoding {
    pub name: *const libc::c_char,
    pub alias: *const libc::c_char,
    pub init_writer: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> CURLcode,
    >,
    pub unencode_write: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut contenc_writer,
            *const libc::c_char,
            size_t,
        ) -> CURLcode,
    >,
    pub close_writer: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> (),
    >,
    pub paramsize: size_t,
}

// http.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct altsvcinfo {
    pub filename: *mut libc::c_char,
    pub list: Curl_llist,
    pub flags: libc::c_long,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_share {
    pub magic: libc::c_uint,
    pub specifier: libc::c_uint,
    pub dirty: libc::c_uint,
    pub lockfunc: curl_lock_function,
    pub unlockfunc: curl_unlock_function,
    pub clientdata: *mut libc::c_void,
    pub conn_cache: conncache,
    pub hostcache: Curl_hash,
    #[cfg(all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_COOKIES)))]
    pub cookies: *mut CookieInfo,
    #[cfg(USE_LIBPSL)]
    pub psl: PslCache,
    pub sslsession: *mut Curl_ssl_session,
    pub max_ssl_sessions: size_t,
    pub sessionage: libc::c_long,
}

// http2.rs
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct curl_pushheaders {
    pub data: *mut Curl_easy,
    pub frame: *const nghttp2_push_promise,
}

#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_push_promise {
    pub hd: nghttp2_frame_hd,
    pub padlen: size_t,
    pub nva: *mut nghttp2_nv,
    pub nvlen: size_t,
    pub promised_stream_id: int32_t,
    pub reserved: uint8_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_nv {
    pub name: *mut uint8_t,
    pub value: *mut uint8_t,
    pub namelen: size_t,
    pub valuelen: size_t,
    pub flags: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_frame_hd {
    pub length: size_t,
    pub stream_id: int32_t,
    pub type_0: uint8_t,
    pub flags: uint8_t,
    pub reserved: uint8_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_info {
    pub age: libc::c_int,
    pub version_num: libc::c_int,
    pub version_str: *const libc::c_char,
    pub proto_str: *const libc::c_char,
}

#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub union nghttp2_data_source {
    pub fd: libc::c_int,
    pub ptr: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_data_provider {
    pub source: nghttp2_data_source,
    pub read_callback: nghttp2_data_source_read_callback,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_data {
    pub hd: nghttp2_frame_hd,
    pub padlen: size_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_priority_spec {
    pub stream_id: int32_t,
    pub weight: int32_t,
    pub exclusive: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_headers {
    pub hd: nghttp2_frame_hd,
    pub padlen: size_t,
    pub pri_spec: nghttp2_priority_spec,
    pub nva: *mut nghttp2_nv,
    pub nvlen: size_t,
    pub cat: nghttp2_headers_category,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_priority {
    pub hd: nghttp2_frame_hd,
    pub pri_spec: nghttp2_priority_spec,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_rst_stream {
    pub hd: nghttp2_frame_hd,
    pub error_code: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_settings {
    pub hd: nghttp2_frame_hd,
    pub niv: size_t,
    pub iv: *mut nghttp2_settings_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_ping {
    pub hd: nghttp2_frame_hd,
    pub opaque_data: [uint8_t; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_goaway {
    pub hd: nghttp2_frame_hd,
    pub last_stream_id: int32_t,
    pub error_code: uint32_t,
    pub opaque_data: *mut uint8_t,
    pub opaque_data_len: size_t,
    pub reserved: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_window_update {
    pub hd: nghttp2_frame_hd,
    pub window_size_increment: int32_t,
    pub reserved: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub struct nghttp2_extension {
    pub hd: nghttp2_frame_hd,
    pub payload: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
// #[cfg(USE_NGHTTP2)]
pub union nghttp2_frame {
    pub hd: nghttp2_frame_hd,
    pub data: nghttp2_data,
    pub headers: nghttp2_headers,
    pub priority: nghttp2_priority,
    pub rst_stream: nghttp2_rst_stream,
    pub settings: nghttp2_settings,
    pub push_promise: nghttp2_push_promise,
    pub ping: nghttp2_ping,
    pub goaway: nghttp2_goaway,
    pub window_update: nghttp2_window_update,
    pub ext: nghttp2_extension,
}

// mbedtls ftp 
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_index {
    pub index: size_t,
    pub total: size_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct curl_hstsentry {
    pub name: *mut libc::c_char,
    pub namelen: size_t,
    #[bitfield(name = "includeSubDomains", ty = "libc::c_uint", bits = "0..=0")]
    pub includeSubDomains: [u8; 1],
    pub expire: [libc::c_char; 18],
}

#[derive(Copy, Clone)]
#[repr(C)]
#[cfg(USE_NTLM)]
pub struct ntlmdata {
    pub flags: libc::c_uint,
    pub nonce: [libc::c_uchar; 8],
    pub target_info_len: libc::c_uint,
    pub target_info: *mut libc::c_void,
    #[cfg(NTLM_WB_ENABLED)]
    pub ntlm_auth_hlpr_socket: curl_socket_t,
    #[cfg(NTLM_WB_ENABLED)]
    pub ntlm_auth_hlpr_pid: pid_t,
    #[cfg(NTLM_WB_ENABLED)]
    pub challenge: *mut libc::c_char,
    #[cfg(NTLM_WB_ENABLED)]
    pub response: *mut libc::c_char,
}
// http_ntlm.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bufref {
    pub dtor: Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub ptr: *const libc::c_uchar,
    pub len: size_t,
    #[cfg(CURLDEBUG)]
    pub signature: libc::c_int,
}

// new http.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_ssl {
    pub info: curl_ssl_backend,
    pub supports: libc::c_uint,
    pub sizeof_ssl_backend_data: size_t,
    pub init: Option::<unsafe extern "C" fn() -> libc::c_int>,
    pub cleanup: Option::<unsafe extern "C" fn() -> ()>,
    pub version: Option::<unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t>,
    pub check_cxn: Option::<unsafe extern "C" fn(*mut connectdata) -> libc::c_int>,
    pub shut_down: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub data_pending: Option::<
        unsafe extern "C" fn(*const connectdata, libc::c_int) -> bool,
    >,
    pub random: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_uchar, size_t) -> CURLcode,
    >,
    pub cert_status_request: Option::<unsafe extern "C" fn() -> bool>,
    pub connect_blocking: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, libc::c_int) -> CURLcode,
    >,
    pub connect_nonblocking: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            libc::c_int,
            *mut bool,
        ) -> CURLcode,
    >,
    pub getsock: Option::<
        unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> libc::c_int,
    >,
    pub get_internals: Option::<
        unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
    >,
    pub close_one: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, libc::c_int) -> (),
    >,
    pub close_all: Option::<unsafe extern "C" fn(*mut Curl_easy) -> ()>,
    pub session_free: Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub set_engine: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *const libc::c_char) -> CURLcode,
    >,
    pub set_engine_default: Option::<unsafe extern "C" fn(*mut Curl_easy) -> CURLcode>,
    pub engines_list: Option::<unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist>,
    pub false_start: Option::<unsafe extern "C" fn() -> bool>,
    pub sha256sum: Option::<
        unsafe extern "C" fn(
            *const libc::c_uchar,
            size_t,
            *mut libc::c_uchar,
            size_t,
        ) -> CURLcode,
    >,
    pub associate_connection: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, libc::c_int) -> (),
    >,
    pub disassociate_connection: Option::<
        unsafe extern "C" fn(*mut Curl_easy, libc::c_int) -> (),
    >,
}
// mbedtls_threadlock.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: libc::c_int,
    pub __count: libc::c_uint,
    pub __owner: libc::c_int,
    pub __nusers: libc::c_uint,
    pub __kind: libc::c_int,
    pub __spins: libc::c_short,
    pub __elision: libc::c_short,
    pub __list: __pthread_list_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutexattr_t {
    pub __size: [libc::c_char; 4],
    pub __align: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [libc::c_char; 40],
    pub __align: libc::c_long,
}
// mbedtls.rs
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ssl_backend_data {
//     pub ctr_drbg: mbedtls_ctr_drbg_context,
//     pub entropy: mbedtls_entropy_context,
//     pub ssl: mbedtls_ssl_context,
//     pub server_fd: libc::c_int,
//     pub cacert: mbedtls_x509_crt,
//     pub clicert: mbedtls_x509_crt,
//     pub crl: mbedtls_x509_crl,
//     pub pk: mbedtls_pk_context,
//     pub config: mbedtls_ssl_config,
//     pub protocols: [*const libc::c_char; 3],
// }
// 需要加宏
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ssl_backend_data {
//     pub session: gnutls_session_t,
//     pub cred: gnutls_certificate_credentials_t,
//     pub srp_client_cred: gnutls_srp_client_credentials_t,
// }

// wolfssl
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ssl_backend_data {
//     pub ctx: *mut SSL_CTX,
//     pub handle: *mut SSL,
// }

// nss
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ssl_backend_data {
//     pub handle: *mut PRFileDesc,
//     pub client_nickname: *mut libc::c_char,
//     pub data: *mut Curl_easy,
//     pub obj_list: Curl_llist,
//     pub obj_clicert: *mut PK11GenericObject,
// }

//rustls
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ssl_backend_data {
//     pub config: *const rustls_client_config,
//     pub conn: *mut rustls_connection,
//     pub data_pending: bool,
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ssl_backend_data {
//     pub handle: *mut PRFileDesc,
//     pub client_nickname: *mut libc::c_char,
//     pub data: *mut Curl_easy,
//     pub obj_list: Curl_llist,
//     pub obj_clicert: *mut PK11GenericObject,
// }

//openssl
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ssl_backend_data {
//     pub logger: *mut Curl_easy,
//     pub ctx: *mut SSL_CTX,
//     pub handle: *mut SSL,
//     pub server_cert: *mut X509,
// }

#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct mbedtls_ssl_config {
    pub ciphersuite_list: [*const libc::c_int; 4],
    pub f_dbg: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            libc::c_int,
            *const libc::c_char,
            libc::c_int,
            *const libc::c_char,
        ) -> (),
    >,
    pub p_dbg: *mut libc::c_void,
    pub f_rng: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *mut libc::c_uchar,
            size_t,
        ) -> libc::c_int,
    >,
    pub p_rng: *mut libc::c_void,
    pub f_get_cache: Option::<
        unsafe extern "C" fn(*mut libc::c_void, *mut mbedtls_ssl_session) -> libc::c_int,
    >,
    pub f_set_cache: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *const mbedtls_ssl_session,
        ) -> libc::c_int,
    >,
    pub p_cache: *mut libc::c_void,
    pub f_sni: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *mut mbedtls_ssl_context,
            *const libc::c_uchar,
            size_t,
        ) -> libc::c_int,
    >,
    pub p_sni: *mut libc::c_void,
    pub f_vrfy: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *mut mbedtls_x509_crt,
            libc::c_int,
            *mut uint32_t,
        ) -> libc::c_int,
    >,
    pub p_vrfy: *mut libc::c_void,
    pub f_psk: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *mut mbedtls_ssl_context,
            *const libc::c_uchar,
            size_t,
        ) -> libc::c_int,
    >,
    pub p_psk: *mut libc::c_void,
    pub f_cookie_write: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *mut *mut libc::c_uchar,
            *mut libc::c_uchar,
            *const libc::c_uchar,
            size_t,
        ) -> libc::c_int,
    >,
    pub f_cookie_check: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *const libc::c_uchar,
            size_t,
            *const libc::c_uchar,
            size_t,
        ) -> libc::c_int,
    >,
    pub p_cookie: *mut libc::c_void,
    pub f_ticket_write: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *const mbedtls_ssl_session,
            *mut libc::c_uchar,
            *const libc::c_uchar,
            *mut size_t,
            *mut uint32_t,
        ) -> libc::c_int,
    >,
    pub f_ticket_parse: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *mut mbedtls_ssl_session,
            *mut libc::c_uchar,
            size_t,
        ) -> libc::c_int,
    >,
    pub p_ticket: *mut libc::c_void,
    pub f_export_keys: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *const libc::c_uchar,
            *const libc::c_uchar,
            size_t,
            size_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub p_export_keys: *mut libc::c_void,
    pub cert_profile: *const mbedtls_x509_crt_profile,
    pub key_cert: *mut mbedtls_ssl_key_cert,
    pub ca_chain: *mut mbedtls_x509_crt,
    pub ca_crl: *mut mbedtls_x509_crl,
    pub sig_hashes: *const libc::c_int,
    pub curve_list: *const mbedtls_ecp_group_id,
    pub dhm_P: mbedtls_mpi,
    pub dhm_G: mbedtls_mpi,
    pub psk: *mut libc::c_uchar,
    pub psk_len: size_t,
    pub psk_identity: *mut libc::c_uchar,
    pub psk_identity_len: size_t,
    pub alpn_list: *mut *const libc::c_char,
    pub read_timeout: uint32_t,
    pub hs_timeout_min: uint32_t,
    pub hs_timeout_max: uint32_t,
    pub renego_max_records: libc::c_int,
    pub renego_period: [libc::c_uchar; 8],
    pub badmac_limit: libc::c_uint,
    pub dhm_min_bitlen: libc::c_uint,
    pub max_major_ver: libc::c_uchar,
    pub max_minor_ver: libc::c_uchar,
    pub min_major_ver: libc::c_uchar,
    pub min_minor_ver: libc::c_uchar,
    #[bitfield(name = "endpoint", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "transport", ty = "libc::c_uint", bits = "1..=1")]
    #[bitfield(name = "authmode", ty = "libc::c_uint", bits = "2..=3")]
    #[bitfield(name = "allow_legacy_renegotiation", ty = "libc::c_uint", bits = "4..=5")]
    #[bitfield(name = "arc4_disabled", ty = "libc::c_uint", bits = "6..=6")]
    #[bitfield(name = "mfl_code", ty = "libc::c_uint", bits = "7..=9")]
    #[bitfield(name = "encrypt_then_mac", ty = "libc::c_uint", bits = "10..=10")]
    #[bitfield(name = "extended_ms", ty = "libc::c_uint", bits = "11..=11")]
    #[bitfield(name = "anti_replay", ty = "libc::c_uint", bits = "12..=12")]
    #[bitfield(name = "cbc_record_splitting", ty = "libc::c_uint", bits = "13..=13")]
    #[bitfield(name = "disable_renegotiation", ty = "libc::c_uint", bits = "14..=14")]
    #[bitfield(name = "trunc_hmac", ty = "libc::c_uint", bits = "15..=15")]
    #[bitfield(name = "session_tickets", ty = "libc::c_uint", bits = "16..=16")]
    #[bitfield(name = "fallback", ty = "libc::c_uint", bits = "17..=17")]
    #[bitfield(name = "cert_req_ca_list", ty = "libc::c_uint", bits = "18..=18")]
    // pub endpoint_transport_authmode_allow_legacy_renegotiation_arc4_disabled_mfl_code_encrypt_then_mac_extended_ms_anti_replay_cbc_record_splitting_disable_renegotiation_trunc_hmac_session_tickets_fallback_cert_req_ca_list: [u8; 3],
    pub c2rust_abbr: [u8; 3],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 1],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_mpi {
    pub s: libc::c_int,
    pub n: size_t,
    pub p: *mut mbedtls_mpi_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_x509_crl {
    pub raw: mbedtls_x509_buf,
    pub tbs: mbedtls_x509_buf,
    pub version: libc::c_int,
    pub sig_oid: mbedtls_x509_buf,
    pub issuer_raw: mbedtls_x509_buf,
    pub issuer: mbedtls_x509_name,
    pub this_update: mbedtls_x509_time,
    pub next_update: mbedtls_x509_time,
    pub entry: mbedtls_x509_crl_entry,
    pub crl_ext: mbedtls_x509_buf,
    pub sig_oid2: mbedtls_x509_buf,
    pub sig: mbedtls_x509_buf,
    pub sig_md: mbedtls_md_type_t,
    pub sig_pk: mbedtls_pk_type_t,
    pub sig_opts: *mut libc::c_void,
    pub next: *mut mbedtls_x509_crl,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_asn1_buf {
    pub tag: libc::c_int,
    pub len: size_t,
    pub p: *mut libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_x509_crl_entry {
    pub raw: mbedtls_x509_buf,
    pub serial: mbedtls_x509_buf,
    pub revocation_date: mbedtls_x509_time,
    pub entry_ext: mbedtls_x509_buf,
    pub next: *mut mbedtls_x509_crl_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_x509_time {
    pub year: libc::c_int,
    pub mon: libc::c_int,
    pub day: libc::c_int,
    pub hour: libc::c_int,
    pub min: libc::c_int,
    pub sec: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_asn1_named_data {
    pub oid: mbedtls_asn1_buf,
    pub val: mbedtls_asn1_buf,
    pub next: *mut mbedtls_asn1_named_data,
    pub next_merged: libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_x509_crt {
    pub raw: mbedtls_x509_buf,
    pub tbs: mbedtls_x509_buf,
    pub version: libc::c_int,
    pub serial: mbedtls_x509_buf,
    pub sig_oid: mbedtls_x509_buf,
    pub issuer_raw: mbedtls_x509_buf,
    pub subject_raw: mbedtls_x509_buf,
    pub issuer: mbedtls_x509_name,
    pub subject: mbedtls_x509_name,
    pub valid_from: mbedtls_x509_time,
    pub valid_to: mbedtls_x509_time,
    pub pk: mbedtls_pk_context,
    pub issuer_id: mbedtls_x509_buf,
    pub subject_id: mbedtls_x509_buf,
    pub v3_ext: mbedtls_x509_buf,
    pub subject_alt_names: mbedtls_x509_sequence,
    pub ext_types: libc::c_int,
    pub ca_istrue: libc::c_int,
    pub max_pathlen: libc::c_int,
    pub key_usage: libc::c_uint,
    pub ext_key_usage: mbedtls_x509_sequence,
    pub ns_cert_type: libc::c_uchar,
    pub sig: mbedtls_x509_buf,
    pub sig_md: mbedtls_md_type_t,
    pub sig_pk: mbedtls_pk_type_t,
    pub sig_opts: *mut libc::c_void,
    pub next: *mut mbedtls_x509_crt,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_asn1_sequence {
    pub buf: mbedtls_asn1_buf,
    pub next: *mut mbedtls_asn1_sequence,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_pk_context {
    pub pk_info: *const mbedtls_pk_info_t,
    pub pk_ctx: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_x509_crt_profile {
    pub allowed_mds: uint32_t,
    pub allowed_pks: uint32_t,
    pub allowed_curves: uint32_t,
    pub rsa_min_bitlen: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_ssl_session {
    pub start: mbedtls_time_t,
    pub ciphersuite: libc::c_int,
    pub compression: libc::c_int,
    pub id_len: size_t,
    pub id: [libc::c_uchar; 32],
    pub master: [libc::c_uchar; 48],
    pub peer_cert: *mut mbedtls_x509_crt,
    pub verify_result: uint32_t,
    pub ticket: *mut libc::c_uchar,
    pub ticket_len: size_t,
    pub ticket_lifetime: uint32_t,
    pub mfl_code: libc::c_uchar,
    pub trunc_hmac: libc::c_int,
    pub encrypt_then_mac: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_ssl_context {
    pub conf: *const mbedtls_ssl_config,
    pub state: libc::c_int,
    pub renego_status: libc::c_int,
    pub renego_records_seen: libc::c_int,
    pub major_ver: libc::c_int,
    pub minor_ver: libc::c_int,
    pub badmac_seen: libc::c_uint,
    pub f_send: Option::<mbedtls_ssl_send_t>,
    pub f_recv: Option::<mbedtls_ssl_recv_t>,
    pub f_recv_timeout: Option::<mbedtls_ssl_recv_timeout_t>,
    pub p_bio: *mut libc::c_void,
    pub session_in: *mut mbedtls_ssl_session,
    pub session_out: *mut mbedtls_ssl_session,
    pub session: *mut mbedtls_ssl_session,
    pub session_negotiate: *mut mbedtls_ssl_session,
    pub handshake: *mut mbedtls_ssl_handshake_params,
    pub transform_in: *mut mbedtls_ssl_transform,
    pub transform_out: *mut mbedtls_ssl_transform,
    pub transform: *mut mbedtls_ssl_transform,
    pub transform_negotiate: *mut mbedtls_ssl_transform,
    pub p_timer: *mut libc::c_void,
    pub f_set_timer: Option::<mbedtls_ssl_set_timer_t>,
    pub f_get_timer: Option::<mbedtls_ssl_get_timer_t>,
    pub in_buf: *mut libc::c_uchar,
    pub in_ctr: *mut libc::c_uchar,
    pub in_hdr: *mut libc::c_uchar,
    pub in_len: *mut libc::c_uchar,
    pub in_iv: *mut libc::c_uchar,
    pub in_msg: *mut libc::c_uchar,
    pub in_offt: *mut libc::c_uchar,
    pub in_msgtype: libc::c_int,
    pub in_msglen: size_t,
    pub in_left: size_t,
    pub in_epoch: uint16_t,
    pub next_record_offset: size_t,
    pub in_window_top: uint64_t,
    pub in_window: uint64_t,
    pub in_hslen: size_t,
    pub nb_zero: libc::c_int,
    pub keep_current_message: libc::c_int,
    pub disable_datagram_packing: uint8_t,
    pub out_buf: *mut libc::c_uchar,
    pub out_ctr: *mut libc::c_uchar,
    pub out_hdr: *mut libc::c_uchar,
    pub out_len: *mut libc::c_uchar,
    pub out_iv: *mut libc::c_uchar,
    pub out_msg: *mut libc::c_uchar,
    pub out_msgtype: libc::c_int,
    pub out_msglen: size_t,
    pub out_left: size_t,
    pub cur_out_ctr: [libc::c_uchar; 8],
    pub mtu: uint16_t,
    pub split_done: libc::c_schar,
    pub client_auth: libc::c_int,
    pub hostname: *mut libc::c_char,
    pub alpn_chosen: *const libc::c_char,
    pub cli_id: *mut libc::c_uchar,
    pub cli_id_len: size_t,
    pub secure_renegotiation: libc::c_int,
    pub verify_data_len: size_t,
    pub own_verify_data: [libc::c_char; 12],
    pub peer_verify_data: [libc::c_char; 12],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_entropy_context {
    pub accumulator_started: libc::c_int,
    pub accumulator: mbedtls_sha512_context,
    pub source_count: libc::c_int,
    pub source: [mbedtls_entropy_source_state; 20],
    pub havege_data: mbedtls_havege_state,
    pub mutex: mbedtls_threading_mutex_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_threading_mutex_t {
    pub mutex: pthread_mutex_t,
    pub is_valid: libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_havege_state {
    pub PT1: libc::c_int,
    pub PT2: libc::c_int,
    pub offset: [libc::c_int; 2],
    pub pool: [libc::c_int; 1024],
    pub WALK: [libc::c_int; 8192],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_entropy_source_state {
    pub f_source: mbedtls_entropy_f_source_ptr,
    pub p_source: *mut libc::c_void,
    pub size: size_t,
    pub threshold: size_t,
    pub strong: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_sha512_context {
    pub total: [uint64_t; 2],
    pub state: [uint64_t; 8],
    pub buffer: [libc::c_uchar; 128],
    pub is384: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_ctr_drbg_context {
    pub counter: [libc::c_uchar; 16],
    pub reseed_counter: libc::c_int,
    pub prediction_resistance: libc::c_int,
    pub entropy_len: size_t,
    pub reseed_interval: libc::c_int,
    pub aes_ctx: mbedtls_aes_context,
    pub f_entropy: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *mut libc::c_uchar,
            size_t,
        ) -> libc::c_int,
    >,
    pub p_entropy: *mut libc::c_void,
    pub mutex: mbedtls_threading_mutex_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mbedtls_aes_context {
    pub nr: libc::c_int,
    pub rk: *mut uint32_t,
    pub buf: [uint32_t; 68],
}


// gnutls http2.rs
// gnutls gtls.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct gnutls_datum_t {
    pub data: *mut libc::c_uchar,
    pub size: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha256_ctx {
    pub state: [uint32_t; 8],
    pub count: uint64_t,
    pub block: [uint8_t; 64],
    pub index: libc::c_uint,
}


// gnutls vtls.rs
// gnutls ftp.rs
// gnutls ftplistparser.rs

#[derive(Copy, Clone)]
#[repr(C)]
pub struct hsts {
    pub list: Curl_llist,
    pub filename: *mut libc::c_char,
    pub flags: libc::c_uint,
}
// wolfssl.rs

#[derive(Copy, Clone)]
#[repr(C)]
pub struct wc_Sha256 {
    pub digest: [word32; 8],
    pub buffer: [word32; 16],
    pub buffLen: word32,
    pub loLen: word32,
    pub hiLen: word32,
    pub heap: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_asn1Element {
    pub header: *const libc::c_char,
    pub beg: *const libc::c_char,
    pub end: *const libc::c_char,
    pub class: libc::c_uchar,
    pub tag: libc::c_uchar,
    pub constructed: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_X509certificate {
    pub certificate: Curl_asn1Element,
    pub version: Curl_asn1Element,
    pub serialNumber: Curl_asn1Element,
    pub signatureAlgorithm: Curl_asn1Element,
    pub signature: Curl_asn1Element,
    pub issuer: Curl_asn1Element,
    pub notBefore: Curl_asn1Element,
    pub notAfter: Curl_asn1Element,
    pub subject: Curl_asn1Element,
    pub subjectPublicKeyInfo: Curl_asn1Element,
    pub subjectPublicKeyAlgorithm: Curl_asn1Element,
    pub subjectPublicKey: Curl_asn1Element,
    pub issuerUniqueID: Curl_asn1Element,
    pub subjectUniqueID: Curl_asn1Element,
    pub extensions: Curl_asn1Element,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WOLFSSL_X509_STORE_CTX {
    pub store: *mut WOLFSSL_X509_STORE,
    pub current_cert: *mut WOLFSSL_X509,
    pub chain: *mut WOLFSSL_STACK,
    pub param: *mut WOLFSSL_X509_VERIFY_PARAM,
    pub domain: *mut libc::c_char,
    pub ex_data: *mut libc::c_void,
    pub userCtx: *mut libc::c_void,
    pub error: libc::c_int,
    pub error_depth: libc::c_int,
    pub discardSessionCerts: libc::c_int,
    pub totalCerts: libc::c_int,
    pub certs: *mut WOLFSSL_BUFFER_INFO,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WOLFSSL_BUFFER_INFO {
    pub buffer: *mut libc::c_uchar,
    pub length: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WOLFSSL_X509_VERIFY_PARAM {
    pub check_time: time_t,
    pub flags: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WOLFSSL_X509_STORE {
    pub cache: libc::c_int,
    pub cm: *mut WOLFSSL_CERT_MANAGER,
    pub lookup: WOLFSSL_X509_LOOKUP,
    pub isDynamic: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WOLFSSL_X509_LOOKUP {
    pub store: *mut WOLFSSL_X509_STORE,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WC_RNG {
    pub seed: OS_Seed,
    pub heap: *mut libc::c_void,
    pub drbg: *mut DRBG,
    pub status: byte,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct OS_Seed {
    pub fd: libc::c_int,
}

// nss.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRFileDesc {
    pub methods: *const PRIOMethods,
    pub secret: *mut PRFilePrivate,
    pub lower: *mut PRFileDesc,
    pub higher: *mut PRFileDesc,
    pub dtor: Option::<unsafe extern "C" fn(*mut PRFileDesc) -> ()>,
    pub identity: PRDescIdentity,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRIOMethods {
    pub file_type: PRDescType,
    pub close: PRCloseFN,
    pub read: PRReadFN,
    pub write: PRWriteFN,
    pub available: PRAvailableFN,
    pub available64: PRAvailable64FN,
    pub fsync: PRFsyncFN,
    pub seek: PRSeekFN,
    pub seek64: PRSeek64FN,
    pub fileInfo: PRFileInfoFN,
    pub fileInfo64: PRFileInfo64FN,
    pub writev: PRWritevFN,
    pub connect: PRConnectFN,
    pub accept: PRAcceptFN,
    pub bind: PRBindFN,
    pub listen: PRListenFN,
    pub shutdown: PRShutdownFN,
    pub recv: PRRecvFN,
    pub send: PRSendFN,
    pub recvfrom: PRRecvfromFN,
    pub sendto: PRSendtoFN,
    pub poll: PRPollFN,
    pub acceptread: PRAcceptreadFN,
    pub transmitfile: PRTransmitfileFN,
    pub getsockname: PRGetsocknameFN,
    pub getpeername: PRGetpeernameFN,
    pub reserved_fn_6: PRReservedFN,
    pub reserved_fn_5: PRReservedFN,
    pub getsocketoption: PRGetsocketoptionFN,
    pub setsocketoption: PRSetsocketoptionFN,
    pub sendfile: PRSendfileFN,
    pub connectcontinue: PRConnectcontinueFN,
    pub reserved_fn_3: PRReservedFN,
    pub reserved_fn_2: PRReservedFN,
    pub reserved_fn_1: PRReservedFN,
    pub reserved_fn_0: PRReservedFN,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRSendFileData {
    pub fd: *mut PRFileDesc,
    pub file_offset: PRUint32,
    pub file_nbytes: PRSize,
    pub header: *const libc::c_void,
    pub hlen: PRInt32,
    pub trailer: *const libc::c_void,
    pub tlen: PRInt32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRSocketOptionData {
    pub option: PRSockOption,
    pub value: nss_C2RustUnnamed_5,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union nss_C2RustUnnamed_5 {
    pub ip_ttl: PRUintn,
    pub mcast_ttl: PRUintn,
    pub tos: PRUintn,
    pub non_blocking: PRBool,
    pub reuse_addr: PRBool,
    pub reuse_port: PRBool,
    pub keep_alive: PRBool,
    pub mcast_loopback: PRBool,
    pub no_delay: PRBool,
    pub broadcast: PRBool,
    pub max_segment: PRSize,
    pub recv_buffer_size: PRSize,
    pub send_buffer_size: PRSize,
    pub linger: PRLinger,
    pub add_member: PRMcastRequest,
    pub drop_member: PRMcastRequest,
    pub mcast_if: PRNetAddr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union PRNetAddr {
    pub raw: nss_C2RustUnnamed_10,
    pub inet: nss_C2RustUnnamed_9,
    pub ipv6: nss_C2RustUnnamed_7,
    pub local: nss_C2RustUnnamed_6,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nss_C2RustUnnamed_6 {
    pub family: PRUint16,
    pub path: [libc::c_char; 104],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nss_C2RustUnnamed_7 {
    pub family: PRUint16,
    pub port: PRUint16,
    pub flowinfo: PRUint32,
    pub ip: PRIPv6Addr,
    pub scope_id: PRUint32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRIPv6Addr {
    pub _S6_un: nss_C2RustUnnamed_8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union nss_C2RustUnnamed_8 {
    pub _S6_u8: [PRUint8; 16],
    pub _S6_u16: [PRUint16; 8],
    pub _S6_u32: [PRUint32; 4],
    pub _S6_u64: [PRUint64; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nss_C2RustUnnamed_9 {
    pub family: PRUint16,
    pub port: PRUint16,
    pub ip: PRUint32,
    pub pad: [libc::c_char; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nss_C2RustUnnamed_10 {
    pub family: PRUint16,
    pub data: [libc::c_char; 14],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRMcastRequest {
    pub mcaddr: PRNetAddr,
    pub ifaddr: PRNetAddr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRLinger {
    pub polarity: PRBool,
    pub linger: PRIntervalTime,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRIOVec {
    pub iov_base: *mut libc::c_char,
    pub iov_len: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRFileInfo64 {
    pub type_0: PRFileType,
    pub size: PROffset64,
    pub creationTime: PRTime,
    pub modifyTime: PRTime,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRFileInfo {
    pub type_0: PRFileType,
    pub size: PROffset32,
    pub creationTime: PRTime,
    pub modifyTime: PRTime,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cipher_s {
    pub name: *const libc::c_char,
    pub num: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct NSSInitParametersStr {
    pub length: libc::c_uint,
    pub passwordRequired: PRBool,
    pub minPWLen: libc::c_int,
    pub manufactureID: *mut libc::c_char,
    pub libraryDescription: *mut libc::c_char,
    pub cryptoTokenDescription: *mut libc::c_char,
    pub dbTokenDescription: *mut libc::c_char,
    pub FIPSTokenDescription: *mut libc::c_char,
    pub cryptoSlotDescription: *mut libc::c_char,
    pub dbSlotDescription: *mut libc::c_char,
    pub FIPSSlotDescription: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ptr_list_wrap {
    pub ptr: *mut libc::c_void,
    pub node: Curl_llist_element,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECItemStr {
    pub type_0: SECItemType,
    pub data: *mut libc::c_uchar,
    pub len: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTCertificateStr {
    pub arena: *mut PLArenaPool,
    pub subjectName: *mut libc::c_char,
    pub issuerName: *mut libc::c_char,
    pub signatureWrap: CERTSignedData,
    pub derCert: SECItem,
    pub derIssuer: SECItem,
    pub derSubject: SECItem,
    pub derPublicKey: SECItem,
    pub certKey: SECItem,
    pub version: SECItem,
    pub serialNumber: SECItem,
    pub signature: SECAlgorithmID,
    pub issuer: CERTName,
    pub validity: CERTValidity,
    pub subject: CERTName,
    pub subjectPublicKeyInfo: CERTSubjectPublicKeyInfo,
    pub issuerID: SECItem,
    pub subjectID: SECItem,
    pub extensions: *mut *mut CERTCertExtension,
    pub emailAddr: *mut libc::c_char,
    pub dbhandle: *mut CERTCertDBHandle,
    pub subjectKeyID: SECItem,
    pub keyIDGenerated: PRBool,
    pub keyUsage: libc::c_uint,
    pub rawKeyUsage: libc::c_uint,
    pub keyUsagePresent: PRBool,
    pub nsCertType: PRUint32,
    pub keepSession: PRBool,
    pub timeOK: PRBool,
    pub domainOK: *mut CERTOKDomainName,
    pub isperm: PRBool,
    pub istemp: PRBool,
    pub nickname: *mut libc::c_char,
    pub dbnickname: *mut libc::c_char,
    pub nssCertificate: *mut NSSCertificateStr,
    pub trust: *mut CERTCertTrust,
    pub referenceCount: libc::c_int,
    pub subjectList: *mut CERTSubjectList,
    pub authKeyID: *mut CERTAuthKeyID,
    pub isRoot: PRBool,
    pub options: nss_C2RustUnnamed_15,
    pub series: libc::c_int,
    pub slot: *mut PK11SlotInfo,
    pub pkcs11ID: CK_OBJECT_HANDLE,
    pub ownSlot: PRBool,
    pub distrust: *mut CERTCertDistrust,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTCertDistrustStr {
    pub serverDistrustAfter: SECItem,
    pub emailDistrustAfter: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union nss_C2RustUnnamed_15 {
    pub apointer: *mut libc::c_void,
    pub bits: nss_C2RustUnnamed_16,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct nss_C2RustUnnamed_16 {
    #[bitfield(name = "hasUnsupportedCriticalExt", ty = "libc::c_uint", bits = "0..=0")]
    pub hasUnsupportedCriticalExt: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTAuthKeyIDStr {
    pub keyID: SECItem,
    pub authCertIssuer: *mut CERTGeneralName,
    pub authCertSerialNumber: SECItem,
    pub DERAuthCertIssuer: *mut *mut SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTGeneralNameStr {
    pub type_0: CERTGeneralNameType,
    pub name: nss_C2RustUnnamed_17,
    pub derDirectoryName: SECItem,
    pub l: PRCList,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRCListStr {
    pub next: *mut PRCList,
    pub prev: *mut PRCList,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union nss_C2RustUnnamed_17 {
    pub directoryName: CERTName,
    pub OthName: OtherName,
    pub other: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct OtherNameStr {
    pub name: SECItem,
    pub oid: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTNameStr {
    pub arena: *mut PLArenaPool,
    pub rdns: *mut *mut CERTRDN,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTRDNStr {
    pub avas: *mut *mut CERTAVA,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTAVAStr {
    pub type_0: SECItem,
    pub value: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PLArenaPool {
    pub first: PLArena,
    pub current: *mut PLArena,
    pub arenasize: PRUint32,
    pub mask: PRUword,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PLArena {
    pub next: *mut PLArena,
    pub base: PRUword,
    pub limit: PRUword,
    pub avail: PRUword,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTSubjectListStr {
    pub arena: *mut PLArenaPool,
    pub ncerts: libc::c_int,
    pub emailAddr: *mut libc::c_char,
    pub head: *mut CERTSubjectNode,
    pub tail: *mut CERTSubjectNode,
    pub entry: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTSubjectNodeStr {
    pub next: *mut CERTSubjectNodeStr,
    pub prev: *mut CERTSubjectNodeStr,
    pub certKey: SECItem,
    pub keyID: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTCertTrustStr {
    pub sslFlags: libc::c_uint,
    pub emailFlags: libc::c_uint,
    pub objectSigningFlags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTOKDomainNameStr {
    pub next: *mut CERTOKDomainName,
    pub name: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTCertExtensionStr {
    pub id: SECItem,
    pub critical: SECItem,
    pub value: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTSubjectPublicKeyInfoStr {
    pub arena: *mut PLArenaPool,
    pub algorithm: SECAlgorithmID,
    pub subjectPublicKey: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECAlgorithmIDStr {
    pub algorithm: SECItem,
    pub parameters: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTValidityStr {
    pub arena: *mut PLArenaPool,
    pub notBefore: SECItem,
    pub notAfter: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTSignedDataStr {
    pub data: SECItem,
    pub signatureAlgorithm: SECAlgorithmID,
    pub signature: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYPublicKeyStr {
    pub arena: *mut PLArenaPool,
    pub keyType: KeyType,
    pub pkcs11Slot: *mut PK11SlotInfo,
    pub pkcs11ID: CK_OBJECT_HANDLE,
    pub u: nss_C2RustUnnamed_18,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union nss_C2RustUnnamed_18 {
    pub rsa: SECKEYRSAPublicKey,
    pub dsa: SECKEYDSAPublicKey,
    pub dh: SECKEYDHPublicKey,
    pub kea: SECKEYKEAPublicKey,
    pub fortezza: SECKEYFortezzaPublicKey,
    pub ec: SECKEYECPublicKey,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYECPublicKeyStr {
    pub DEREncodedParams: SECKEYECParams,
    pub size: libc::c_int,
    pub publicValue: SECItem,
    pub encoding: ECPointEncoding,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYFortezzaPublicKeyStr {
    pub KEAversion: libc::c_int,
    pub DSSversion: libc::c_int,
    pub KMID: [libc::c_uchar; 8],
    pub clearance: SECItem,
    pub KEApriviledge: SECItem,
    pub DSSpriviledge: SECItem,
    pub KEAKey: SECItem,
    pub DSSKey: SECItem,
    pub params: SECKEYPQGParams,
    pub keaParams: SECKEYPQGParams,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYPQGParamsStr {
    pub arena: *mut PLArenaPool,
    pub prime: SECItem,
    pub subPrime: SECItem,
    pub base: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYKEAPublicKeyStr {
    pub params: SECKEYKEAParams,
    pub publicValue: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYKEAParamsStr {
    pub arena: *mut PLArenaPool,
    pub hash: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYDHPublicKeyStr {
    pub arena: *mut PLArenaPool,
    pub prime: SECItem,
    pub base: SECItem,
    pub publicValue: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYDSAPublicKeyStr {
    pub params: SECKEYPQGParams,
    pub publicValue: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYRSAPublicKeyStr {
    pub arena: *mut PLArenaPool,
    pub modulus: SECItem,
    pub publicExponent: SECItem,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRExplodedTime {
    pub tm_usec: PRInt32,
    pub tm_sec: PRInt32,
    pub tm_min: PRInt32,
    pub tm_hour: PRInt32,
    pub tm_mday: PRInt32,
    pub tm_month: PRInt32,
    pub tm_year: PRInt16,
    pub tm_wday: PRInt8,
    pub tm_yday: PRInt16,
    pub tm_params: PRTimeParameters,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRTimeParameters {
    pub tp_gmt_offset: PRInt32,
    pub tp_dst_offset: PRInt32,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct SSLCipherSuiteInfoStr {
    pub length: PRUint16,
    pub cipherSuite: PRUint16,
    pub cipherSuiteName: *const libc::c_char,
    pub authAlgorithmName: *const libc::c_char,
    pub authAlgorithm: SSLAuthType,
    pub keaTypeName: *const libc::c_char,
    pub keaType: SSLKEAType,
    pub symCipherName: *const libc::c_char,
    pub symCipher: SSLCipherAlgorithm,
    pub symKeyBits: PRUint16,
    pub symKeySpace: PRUint16,
    pub effectiveKeyBits: PRUint16,
    pub macAlgorithmName: *const libc::c_char,
    pub macAlgorithm: SSLMACAlgorithm,
    pub macBits: PRUint16,
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 1],
    #[bitfield(name = "isFIPS", ty = "PRUintn", bits = "0..=0")]
    #[bitfield(name = "isExportable", ty = "PRUintn", bits = "1..=1")]
    #[bitfield(name = "nonStandard", ty = "PRUintn", bits = "2..=2")]
    #[bitfield(name = "reservedBits", ty = "PRUintn", bits = "16..=44")]
    pub isFIPS_isExportable_nonStandard_reservedBits: [u8; 5],
    pub authType: SSLAuthType,
    pub kdfHash: SSLHashType,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SSLChannelInfoStr {
    pub length: PRUint32,
    pub protocolVersion: PRUint16,
    pub cipherSuite: PRUint16,
    pub authKeyBits: PRUint32,
    pub keaKeyBits: PRUint32,
    pub creationTime: PRUint32,
    pub lastAccessTime: PRUint32,
    pub expirationTime: PRUint32,
    pub sessionIDLength: PRUint32,
    pub sessionID: [PRUint8; 32],
    pub compressionMethodName: *const libc::c_char,
    pub compressionMethod: SSLCompressionMethod,
    pub extendedMasterSecretUsed: PRBool,
    pub earlyDataAccepted: PRBool,
    pub keaType: SSLKEAType,
    pub keaGroup: SSLNamedGroup,
    pub symCipher: SSLCipherAlgorithm,
    pub macAlgorithm: SSLMACAlgorithm,
    pub authType: SSLAuthType,
    pub signatureScheme: SSLSignatureScheme,
    pub originalKeaGroup: SSLNamedGroup,
    pub resumed: PRBool,
    pub peerDelegCred: PRBool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECKEYPrivateKeyStr {
    pub arena: *mut PLArenaPool,
    pub keyType: KeyType,
    pub pkcs11Slot: *mut PK11SlotInfo,
    pub pkcs11ID: CK_OBJECT_HANDLE,
    pub pkcs11IsTemp: PRBool,
    pub wincx: *mut libc::c_void,
    pub staticflags: PRUint32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTDistNamesStr {
    pub arena: *mut PLArenaPool,
    pub nnames: libc::c_int,
    pub names: *mut SECItem,
    pub head: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECMODModuleStr {
    pub arena: *mut PLArenaPool,
    pub internal: PRBool,
    pub loaded: PRBool,
    pub isFIPS: PRBool,
    pub dllName: *mut libc::c_char,
    pub commonName: *mut libc::c_char,
    pub library: *mut libc::c_void,
    pub functionList: *mut libc::c_void,
    pub refLock: *mut PRLock,
    pub refCount: libc::c_int,
    pub slots: *mut *mut PK11SlotInfo,
    pub slotCount: libc::c_int,
    pub slotInfo: *mut PK11PreSlotInfo,
    pub slotInfoCount: libc::c_int,
    pub moduleID: SECMODModuleID,
    pub isThreadSafe: PRBool,
    pub ssl: [libc::c_ulong; 2],
    pub libraryParams: *mut libc::c_char,
    pub moduleDBFunc: *mut libc::c_void,
    pub parent: *mut SECMODModule,
    pub isCritical: PRBool,
    pub isModuleDB: PRBool,
    pub moduleDBOnly: PRBool,
    pub trustOrder: libc::c_int,
    pub cipherOrder: libc::c_int,
    pub evControlMask: libc::c_ulong,
    pub cryptokiVersion: CK_VERSION,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub type_0: CK_ATTRIBUTE_TYPE,
    pub pValue: CK_VOID_PTR,
    pub ulValueLen: CK_ULONG,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTSignedCrlStr {
    pub arena: *mut PLArenaPool,
    pub crl: CERTCrl,
    pub reserved1: *mut libc::c_void,
    pub reserved2: PRBool,
    pub isperm: PRBool,
    pub istemp: PRBool,
    pub referenceCount: libc::c_int,
    pub dbhandle: *mut CERTCertDBHandle,
    pub signatureWrap: CERTSignedData,
    pub url: *mut libc::c_char,
    pub derCrl: *mut SECItem,
    pub slot: *mut PK11SlotInfo,
    pub pkcs11ID: CK_OBJECT_HANDLE,
    pub opaque: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTCrlStr {
    pub arena: *mut PLArenaPool,
    pub version: SECItem,
    pub signatureAlg: SECAlgorithmID,
    pub derName: SECItem,
    pub name: CERTName,
    pub lastUpdate: SECItem,
    pub nextUpdate: SECItem,
    pub entries: *mut *mut CERTCrlEntry,
    pub extensions: *mut *mut CERTCertExtension,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CERTCrlEntryStr {
    pub serialNumber: SECItem,
    pub revocationDate: SECItem,
    pub extensions: *mut *mut CERTCertExtension,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PRDirEntry {
    pub name: *const libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SECItemArrayStr {
    pub items: *mut SECItem,
    pub len: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SSLVersionRangeStr {
    pub min: PRUint16,
    pub max: PRUint16,
}
// rustls.rs

#[derive(Copy, Clone)]
#[repr(C)]
pub struct rustls_slice_bytes {
    pub data: *const uint8_t,
    pub len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rustls_str {
    pub data: *const libc::c_char,
    pub len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rustls_verify_server_cert_params {
    pub end_entity_cert_der: rustls_slice_bytes,
    pub intermediate_certs_der: *const rustls_slice_slice_bytes,
    pub roots: *const rustls_root_cert_store,
    pub dns_name: rustls_str,
    pub ocsp_response: rustls_slice_bytes,
}

// openssl.rs

#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
    pub flags: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union openssl_C2RustUnnamed_11 {
    pub ptr: *mut libc::c_char,
    pub otherName: *mut OTHERNAME,
    pub rfc822Name: *mut ASN1_IA5STRING,
    pub dNSName: *mut ASN1_IA5STRING,
    pub x400Address: *mut ASN1_TYPE,
    pub directoryName: *mut X509_NAME,
    pub ediPartyName: *mut EDIPARTYNAME,
    pub uniformResourceIdentifier: *mut ASN1_IA5STRING,
    pub iPAddress: *mut ASN1_OCTET_STRING,
    pub registeredID: *mut ASN1_OBJECT,
    pub ip: *mut ASN1_OCTET_STRING,
    pub dirn: *mut X509_NAME,
    pub ia5: *mut ASN1_IA5STRING,
    pub rid: *mut ASN1_OBJECT,
    pub other: *mut ASN1_TYPE,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_type_st {
    pub type_0: libc::c_int,
    pub value: openssl_C2RustUnnamed_12,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union openssl_C2RustUnnamed_12 {
    pub ptr: *mut libc::c_char,
    pub boolean: ASN1_BOOLEAN,
    pub asn1_string: *mut ASN1_STRING,
    pub object: *mut ASN1_OBJECT,
    pub integer: *mut ASN1_INTEGER,
    pub enumerated: *mut ASN1_ENUMERATED,
    pub bit_string: *mut ASN1_BIT_STRING,
    pub octet_string: *mut ASN1_OCTET_STRING,
    pub printablestring: *mut ASN1_PRINTABLESTRING,
    pub t61string: *mut ASN1_T61STRING,
    pub ia5string: *mut ASN1_IA5STRING,
    pub generalstring: *mut ASN1_GENERALSTRING,
    pub bmpstring: *mut ASN1_BMPSTRING,
    pub universalstring: *mut ASN1_UNIVERSALSTRING,
    pub utctime: *mut ASN1_UTCTIME,
    pub generalizedtime: *mut ASN1_GENERALIZEDTIME,
    pub visiblestring: *mut ASN1_VISIBLESTRING,
    pub utf8string: *mut ASN1_UTF8STRING,
    pub set: *mut ASN1_STRING,
    pub sequence: *mut ASN1_STRING,
    pub asn1_value: *mut ASN1_VALUE,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EDIPartyName_st {
    pub nameAssigner: *mut ASN1_STRING,
    pub partyName: *mut ASN1_STRING,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct otherName_st {
    pub type_id: *mut ASN1_OBJECT,
    pub value: *mut ASN1_TYPE,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GENERAL_NAME_st {
    pub type_0: libc::c_int,
    pub d: openssl_C2RustUnnamed_11,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_info_st {
    pub x509: *mut X509,
    pub crl: *mut X509_CRL,
    pub x_pkey: *mut X509_PKEY,
    pub enc_cipher: EVP_CIPHER_INFO,
    pub enc_len: libc::c_int,
    pub enc_data: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_info_st {
    pub cipher: *const EVP_CIPHER,
    pub iv: [libc::c_uchar; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct private_key_st {
    pub version: libc::c_int,
    pub enc_algor: *mut X509_ALGOR,
    pub enc_pkey: *mut ASN1_OCTET_STRING,
    pub dec_pkey: *mut EVP_PKEY,
    pub key_length: libc::c_int,
    pub key_data: *mut libc::c_char,
    pub key_free: libc::c_int,
    pub cipher: EVP_CIPHER_INFO,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct openssl_C2RustUnnamed_13 {
    pub cert_id: *const libc::c_char,
    pub cert: *mut X509,
}

// http_negotiate.rs

#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
// #[cfg(USE_SPNEGO)]
pub struct negotiatedata {
    #[cfg(HAVE_GSSAPI)]
    pub status: OM_uint32,
    #[cfg(HAVE_GSSAPI)]
    pub context: gss_ctx_id_t,
    #[cfg(HAVE_GSSAPI)]
    pub spn: gss_name_t,
    #[cfg(HAVE_GSSAPI)]
    pub output_token: gss_buffer_desc,
    // USE_WINDOWS_SSPI
    // SECPKG_ATTR_ENDPOINT_BINDINGS
    #[bitfield(name = "noauthpersist", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "havenoauthpersist", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "havenegdata", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "havemultiplerequests", ty = "bit", bits = "3..=3")]
    pub noauthpersist_havenoauthpersist_havenegdata_havemultiplerequests: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct gss_buffer_desc_struct {
    pub length: size_t,
    pub value: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
#[cfg(USE_KERBEROS5)]
pub struct kerberos5data {
    pub context: gss_ctx_id_t,
    pub spn: gss_name_t,
}

#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct krb5buffer {
    pub data: *mut libc::c_void,
    pub size: size_t,
    pub index: size_t,
    #[bitfield(name = "eof_flag", ty = "bit", bits = "0..=0")]
    pub eof_flag: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
// bearssl.rs
// bear
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ssl_backend_data {
//     pub ctx: br_ssl_client_context,
//     pub x509: x509_context,
//     pub buf: [libc::c_uchar; 33178],
//     pub anchors: *mut br_x509_trust_anchor,
//     pub anchors_len: size_t,
//     pub protocols: [*const libc::c_char; 2],
//     pub active: bool,
//     pub pending_write: size_t,
// }
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_x509_trust_anchor {
    pub dn: br_x500_name,
    pub flags: libc::c_uint,
    pub pkey: br_x509_pkey,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_x509_pkey {
    pub key_type: libc::c_uchar,
    pub key: bear_C2RustUnnamed_6,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_6 {
    pub rsa: br_rsa_public_key,
    pub ec: br_ec_public_key,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ec_public_key {
    pub curve: libc::c_int,
    pub q: *mut libc::c_uchar,
    pub qlen: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_rsa_public_key {
    pub n: *mut libc::c_uchar,
    pub nlen: size_t,
    pub e: *mut libc::c_uchar,
    pub elen: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_x500_name {
    pub data: *mut libc::c_uchar,
    pub len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_context {
    pub vtable: *const br_x509_class,
    pub minimal: br_x509_minimal_context,
    pub verifyhost: bool,
    pub verifypeer: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_x509_minimal_context {
    pub vtable: *const br_x509_class,
    pub pkey: br_x509_pkey,
    pub cpu: bear_C2RustUnnamed_7,
    pub dp_stack: [uint32_t; 31],
    pub rp_stack: [uint32_t; 31],
    pub err: libc::c_int,
    pub server_name: *const libc::c_char,
    pub key_usages: libc::c_uchar,
    pub days: uint32_t,
    pub seconds: uint32_t,
    pub cert_length: uint32_t,
    pub num_certs: uint32_t,
    pub hbuf: *const libc::c_uchar,
    pub hlen: size_t,
    pub pad: [libc::c_uchar; 256],
    pub ee_pkey_data: [libc::c_uchar; 520],
    pub pkey_data: [libc::c_uchar; 520],
    pub cert_signer_key_type: libc::c_uchar,
    pub cert_sig_hash_oid: uint16_t,
    pub cert_sig_hash_len: libc::c_uchar,
    pub cert_sig: [libc::c_uchar; 512],
    pub cert_sig_len: uint16_t,
    pub min_rsa_size: int16_t,
    pub trust_anchors: *const br_x509_trust_anchor,
    pub trust_anchors_num: size_t,
    pub do_mhash: libc::c_uchar,
    pub mhash: br_multihash_context,
    pub tbs_hash: [libc::c_uchar; 64],
    pub do_dn_hash: libc::c_uchar,
    pub dn_hash_impl: *const br_hash_class,
    pub dn_hash: br_hash_compat_context,
    pub current_dn_hash: [libc::c_uchar; 64],
    pub next_dn_hash: [libc::c_uchar; 64],
    pub saved_dn_hash: [libc::c_uchar; 64],
    pub name_elts: *mut br_name_element,
    pub num_name_elts: size_t,
    pub itime_ctx: *mut libc::c_void,
    pub itime: br_x509_time_check,
    pub irsa: br_rsa_pkcs1_vrfy,
    pub iecdsa: br_ecdsa_vrfy,
    pub iec: *const br_ec_impl,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ec_impl {
    pub supported_curves: uint32_t,
    pub generator: Option::<
        unsafe extern "C" fn(libc::c_int, *mut size_t) -> *const libc::c_uchar,
    >,
    pub order: Option::<
        unsafe extern "C" fn(libc::c_int, *mut size_t) -> *const libc::c_uchar,
    >,
    pub xoff: Option::<unsafe extern "C" fn(libc::c_int, *mut size_t) -> size_t>,
    pub mul: Option::<
        unsafe extern "C" fn(
            *mut libc::c_uchar,
            size_t,
            *const libc::c_uchar,
            size_t,
            libc::c_int,
        ) -> uint32_t,
    >,
    pub mulgen: Option::<
        unsafe extern "C" fn(
            *mut libc::c_uchar,
            *const libc::c_uchar,
            size_t,
            libc::c_int,
        ) -> size_t,
    >,
    pub muladd: Option::<
        unsafe extern "C" fn(
            *mut libc::c_uchar,
            *const libc::c_uchar,
            size_t,
            *const libc::c_uchar,
            size_t,
            *const libc::c_uchar,
            size_t,
            libc::c_int,
        ) -> uint32_t,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_name_element {
    pub oid: *const libc::c_uchar,
    pub buf: *mut libc::c_char,
    pub len: size_t,
    pub status: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union br_hash_compat_context {
    pub vtable: *const br_hash_class,
    pub md5: br_md5_context,
    pub sha1: br_sha1_context,
    pub sha224: br_sha224_context,
    pub sha256: br_sha256_context,
    pub sha384: br_sha384_context,
    pub sha512: br_sha512_context,
    pub md5sha1: br_md5sha1_context,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_md5sha1_context {
    pub vtable: *const br_hash_class,
    pub buf: [libc::c_uchar; 64],
    pub count: uint64_t,
    pub val_md5: [uint32_t; 4],
    pub val_sha1: [uint32_t; 5],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_hash_class_ {
    pub context_size: size_t,
    pub desc: uint32_t,
    pub init: Option::<unsafe extern "C" fn(*mut *const br_hash_class) -> ()>,
    pub update: Option::<
        unsafe extern "C" fn(
            *mut *const br_hash_class,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
    pub out: Option::<
        unsafe extern "C" fn(*const *const br_hash_class, *mut libc::c_void) -> (),
    >,
    pub state: Option::<
        unsafe extern "C" fn(*const *const br_hash_class, *mut libc::c_void) -> uint64_t,
    >,
    pub set_state: Option::<
        unsafe extern "C" fn(
            *mut *const br_hash_class,
            *const libc::c_void,
            uint64_t,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sha512_context {
    pub vtable: *const br_hash_class,
    pub buf: [libc::c_uchar; 128],
    pub count: uint64_t,
    pub val: [uint64_t; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sha256_context {
    pub vtable: *const br_hash_class,
    pub buf: [libc::c_uchar; 64],
    pub count: uint64_t,
    pub val: [uint32_t; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sha1_context {
    pub vtable: *const br_hash_class,
    pub buf: [libc::c_uchar; 64],
    pub count: uint64_t,
    pub val: [uint32_t; 5],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_md5_context {
    pub vtable: *const br_hash_class,
    pub buf: [libc::c_uchar; 64],
    pub count: uint64_t,
    pub val: [uint32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_multihash_context {
    pub buf: [libc::c_uchar; 128],
    pub count: uint64_t,
    pub val_32: [uint32_t; 25],
    pub val_64: [uint64_t; 16],
    pub impl_0: [*const br_hash_class; 6],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bear_C2RustUnnamed_7 {
    pub dp: *mut uint32_t,
    pub rp: *mut uint32_t,
    pub ip: *const libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_x509_class_ {
    pub context_size: size_t,
    pub start_chain: Option::<
        unsafe extern "C" fn(*mut *const br_x509_class, *const libc::c_char) -> (),
    >,
    pub start_cert: Option::<
        unsafe extern "C" fn(*mut *const br_x509_class, uint32_t) -> (),
    >,
    pub append: Option::<
        unsafe extern "C" fn(
            *mut *const br_x509_class,
            *const libc::c_uchar,
            size_t,
        ) -> (),
    >,
    pub end_cert: Option::<unsafe extern "C" fn(*mut *const br_x509_class) -> ()>,
    pub end_chain: Option::<
        unsafe extern "C" fn(*mut *const br_x509_class) -> libc::c_uint,
    >,
    pub get_pkey: Option::<
        unsafe extern "C" fn(
            *const *const br_x509_class,
            *mut libc::c_uint,
        ) -> *const br_x509_pkey,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ssl_client_context_ {
    pub eng: br_ssl_engine_context,
    pub min_clienthello_len: uint16_t,
    pub hashes: uint32_t,
    pub server_curve: libc::c_int,
    pub client_auth_vtable: *mut *const br_ssl_client_certificate_class,
    pub auth_type: libc::c_uchar,
    pub hash_id: libc::c_uchar,
    pub client_auth: bear_C2RustUnnamed_8,
    pub irsapub: br_rsa_public,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_8 {
    pub vtable: *const br_ssl_client_certificate_class,
    pub single_rsa: br_ssl_client_certificate_rsa_context,
    pub single_ec: br_ssl_client_certificate_ec_context,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ssl_client_certificate_ec_context {
    pub vtable: *const br_ssl_client_certificate_class,
    pub chain: *const br_x509_certificate,
    pub chain_len: size_t,
    pub sk: *const br_ec_private_key,
    pub allowed_usages: libc::c_uint,
    pub issuer_key_type: libc::c_uint,
    pub mhash: *const br_multihash_context,
    pub iec: *const br_ec_impl,
    pub iecdsa: br_ecdsa_sign,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ec_private_key {
    pub curve: libc::c_int,
    pub x: *mut libc::c_uchar,
    pub xlen: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_x509_certificate {
    pub data: *mut libc::c_uchar,
    pub data_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ssl_client_certificate_class_ {
    pub context_size: size_t,
    pub start_name_list: Option::<
        unsafe extern "C" fn(*mut *const br_ssl_client_certificate_class) -> (),
    >,
    pub start_name: Option::<
        unsafe extern "C" fn(*mut *const br_ssl_client_certificate_class, size_t) -> (),
    >,
    pub append_name: Option::<
        unsafe extern "C" fn(
            *mut *const br_ssl_client_certificate_class,
            *const libc::c_uchar,
            size_t,
        ) -> (),
    >,
    pub end_name: Option::<
        unsafe extern "C" fn(*mut *const br_ssl_client_certificate_class) -> (),
    >,
    pub end_name_list: Option::<
        unsafe extern "C" fn(*mut *const br_ssl_client_certificate_class) -> (),
    >,
    pub choose: Option::<
        unsafe extern "C" fn(
            *mut *const br_ssl_client_certificate_class,
            *const br_ssl_client_context,
            uint32_t,
            *mut br_ssl_client_certificate,
        ) -> (),
    >,
    pub do_keyx: Option::<
        unsafe extern "C" fn(
            *mut *const br_ssl_client_certificate_class,
            *mut libc::c_uchar,
            *mut size_t,
        ) -> uint32_t,
    >,
    pub do_sign: Option::<
        unsafe extern "C" fn(
            *mut *const br_ssl_client_certificate_class,
            libc::c_int,
            size_t,
            *mut libc::c_uchar,
            size_t,
        ) -> size_t,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ssl_client_certificate {
    pub auth_type: libc::c_int,
    pub hash_id: libc::c_int,
    pub chain: *const br_x509_certificate,
    pub chain_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ssl_client_certificate_rsa_context {
    pub vtable: *const br_ssl_client_certificate_class,
    pub chain: *const br_x509_certificate,
    pub chain_len: size_t,
    pub sk: *const br_rsa_private_key,
    pub irsasign: br_rsa_pkcs1_sign,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_rsa_private_key {
    pub n_bitlen: uint32_t,
    pub p: *mut libc::c_uchar,
    pub plen: size_t,
    pub q: *mut libc::c_uchar,
    pub qlen: size_t,
    pub dp: *mut libc::c_uchar,
    pub dplen: size_t,
    pub dq: *mut libc::c_uchar,
    pub dqlen: size_t,
    pub iq: *mut libc::c_uchar,
    pub iqlen: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ssl_engine_context {
    pub err: libc::c_int,
    pub ibuf: *mut libc::c_uchar,
    pub obuf: *mut libc::c_uchar,
    pub ibuf_len: size_t,
    pub obuf_len: size_t,
    pub max_frag_len: uint16_t,
    pub log_max_frag_len: libc::c_uchar,
    pub peer_log_max_frag_len: libc::c_uchar,
    pub ixa: size_t,
    pub ixb: size_t,
    pub ixc: size_t,
    pub oxa: size_t,
    pub oxb: size_t,
    pub oxc: size_t,
    pub iomode: libc::c_uchar,
    pub incrypt: libc::c_uchar,
    pub shutdown_recv: libc::c_uchar,
    pub record_type_in: libc::c_uchar,
    pub record_type_out: libc::c_uchar,
    pub version_in: uint16_t,
    pub version_out: uint16_t,
    pub in_0: bear_C2RustUnnamed_23,
    pub out: bear_C2RustUnnamed_10,
    pub application_data: libc::c_uchar,
    pub rng: br_hmac_drbg_context,
    pub rng_init_done: libc::c_int,
    pub rng_os_rand_done: libc::c_int,
    pub version_min: uint16_t,
    pub version_max: uint16_t,
    pub suites_buf: [uint16_t; 48],
    pub suites_num: libc::c_uchar,
    pub server_name: [libc::c_char; 256],
    pub client_random: [libc::c_uchar; 32],
    pub server_random: [libc::c_uchar; 32],
    pub session: br_ssl_session_parameters,
    pub ecdhe_curve: libc::c_uchar,
    pub ecdhe_point: [libc::c_uchar; 133],
    pub ecdhe_point_len: libc::c_uchar,
    pub reneg: libc::c_uchar,
    pub saved_finished: [libc::c_uchar; 24],
    pub flags: uint32_t,
    pub cpu: bear_C2RustUnnamed_9,
    pub dp_stack: [uint32_t; 32],
    pub rp_stack: [uint32_t; 32],
    pub pad: [libc::c_uchar; 512],
    pub hbuf_in: *mut libc::c_uchar,
    pub hbuf_out: *mut libc::c_uchar,
    pub saved_hbuf_out: *mut libc::c_uchar,
    pub hlen_in: size_t,
    pub hlen_out: size_t,
    pub hsrun: Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub action: libc::c_uchar,
    pub alert: libc::c_uchar,
    pub close_received: libc::c_uchar,
    pub mhash: br_multihash_context,
    pub x509ctx: *mut *const br_x509_class,
    pub chain: *const br_x509_certificate,
    pub chain_len: size_t,
    pub cert_cur: *const libc::c_uchar,
    pub cert_len: size_t,
    pub protocol_names: *mut *const libc::c_char,
    pub protocol_names_num: uint16_t,
    pub selected_protocol: uint16_t,
    pub prf10: br_tls_prf_impl,
    pub prf_sha256: br_tls_prf_impl,
    pub prf_sha384: br_tls_prf_impl,
    pub iaes_cbcenc: *const br_block_cbcenc_class,
    pub iaes_cbcdec: *const br_block_cbcdec_class,
    pub iaes_ctr: *const br_block_ctr_class,
    pub iaes_ctrcbc: *const br_block_ctrcbc_class,
    pub ides_cbcenc: *const br_block_cbcenc_class,
    pub ides_cbcdec: *const br_block_cbcdec_class,
    pub ighash: br_ghash,
    pub ichacha: br_chacha20_run,
    pub ipoly: br_poly1305_run,
    pub icbc_in: *const br_sslrec_in_cbc_class,
    pub icbc_out: *const br_sslrec_out_cbc_class,
    pub igcm_in: *const br_sslrec_in_gcm_class,
    pub igcm_out: *const br_sslrec_out_gcm_class,
    pub ichapol_in: *const br_sslrec_in_chapol_class,
    pub ichapol_out: *const br_sslrec_out_chapol_class,
    pub iccm_in: *const br_sslrec_in_ccm_class,
    pub iccm_out: *const br_sslrec_out_ccm_class,
    pub iec: *const br_ec_impl,
    pub irsavrfy: br_rsa_pkcs1_vrfy,
    pub iecdsa: br_ecdsa_vrfy,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_out_ccm_class_ {
    pub inner: br_sslrec_out_class,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_out_ccm_class,
            *const br_block_ctrcbc_class,
            *const libc::c_void,
            size_t,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_block_ctrcbc_class_ {
    pub context_size: size_t,
    pub block_size: libc::c_uint,
    pub log_block_size: libc::c_uint,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_block_ctrcbc_class,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            *const *const br_block_ctrcbc_class,
            *mut libc::c_void,
            *mut libc::c_void,
            *mut libc::c_void,
            size_t,
        ) -> (),
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            *const *const br_block_ctrcbc_class,
            *mut libc::c_void,
            *mut libc::c_void,
            *mut libc::c_void,
            size_t,
        ) -> (),
    >,
    pub ctr: Option::<
        unsafe extern "C" fn(
            *const *const br_block_ctrcbc_class,
            *mut libc::c_void,
            *mut libc::c_void,
            size_t,
        ) -> (),
    >,
    pub mac: Option::<
        unsafe extern "C" fn(
            *const *const br_block_ctrcbc_class,
            *mut libc::c_void,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_out_class_ {
    pub context_size: size_t,
    pub max_plaintext: Option::<
        unsafe extern "C" fn(
            *const *const br_sslrec_out_class,
            *mut size_t,
            *mut size_t,
        ) -> (),
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_out_class,
            libc::c_int,
            libc::c_uint,
            *mut libc::c_void,
            *mut size_t,
        ) -> *mut libc::c_uchar,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_in_ccm_class_ {
    pub inner: br_sslrec_in_class,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_in_ccm_class,
            *const br_block_ctrcbc_class,
            *const libc::c_void,
            size_t,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_in_class_ {
    pub context_size: size_t,
    pub check_length: Option::<
        unsafe extern "C" fn(*const *const br_sslrec_in_class, size_t) -> libc::c_int,
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_in_class,
            libc::c_int,
            libc::c_uint,
            *mut libc::c_void,
            *mut size_t,
        ) -> *mut libc::c_uchar,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_out_chapol_class_ {
    pub inner: br_sslrec_out_class,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_out_chapol_class,
            br_chacha20_run,
            br_poly1305_run,
            *const libc::c_void,
            *const libc::c_void,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_in_chapol_class_ {
    pub inner: br_sslrec_in_class,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_in_chapol_class,
            br_chacha20_run,
            br_poly1305_run,
            *const libc::c_void,
            *const libc::c_void,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_out_gcm_class_ {
    pub inner: br_sslrec_out_class,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_out_gcm_class,
            *const br_block_ctr_class,
            *const libc::c_void,
            size_t,
            br_ghash,
            *const libc::c_void,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_block_ctr_class_ {
    pub context_size: size_t,
    pub block_size: libc::c_uint,
    pub log_block_size: libc::c_uint,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_block_ctr_class,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
    pub run: Option::<
        unsafe extern "C" fn(
            *const *const br_block_ctr_class,
            *const libc::c_void,
            uint32_t,
            *mut libc::c_void,
            size_t,
        ) -> uint32_t,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_in_gcm_class_ {
    pub inner: br_sslrec_in_class,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_in_gcm_class,
            *const br_block_ctr_class,
            *const libc::c_void,
            size_t,
            br_ghash,
            *const libc::c_void,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_out_cbc_class_ {
    pub inner: br_sslrec_out_class,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_out_cbc_class,
            *const br_block_cbcenc_class,
            *const libc::c_void,
            size_t,
            *const br_hash_class,
            *const libc::c_void,
            size_t,
            size_t,
            *const libc::c_void,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_block_cbcenc_class_ {
    pub context_size: size_t,
    pub block_size: libc::c_uint,
    pub log_block_size: libc::c_uint,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_block_cbcenc_class,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
    pub run: Option::<
        unsafe extern "C" fn(
            *const *const br_block_cbcenc_class,
            *mut libc::c_void,
            *mut libc::c_void,
            size_t,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_in_cbc_class_ {
    pub inner: br_sslrec_in_class,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_sslrec_in_cbc_class,
            *const br_block_cbcdec_class,
            *const libc::c_void,
            size_t,
            *const br_hash_class,
            *const libc::c_void,
            size_t,
            size_t,
            *const libc::c_void,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_block_cbcdec_class_ {
    pub context_size: size_t,
    pub block_size: libc::c_uint,
    pub log_block_size: libc::c_uint,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_block_cbcdec_class,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
    pub run: Option::<
        unsafe extern "C" fn(
            *const *const br_block_cbcdec_class,
            *mut libc::c_void,
            *mut libc::c_void,
            size_t,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_tls_prf_seed_chunk {
    pub data: *const libc::c_void,
    pub len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bear_C2RustUnnamed_9 {
    pub dp: *mut uint32_t,
    pub rp: *mut uint32_t,
    pub ip: *const libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_ssl_session_parameters {
    pub session_id: [libc::c_uchar; 32],
    pub session_id_len: libc::c_uchar,
    pub version: uint16_t,
    pub cipher_suite: uint16_t,
    pub master_secret: [libc::c_uchar; 48],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_hmac_drbg_context {
    pub vtable: *const br_prng_class,
    pub K: [libc::c_uchar; 64],
    pub V: [libc::c_uchar; 64],
    pub digest_class: *const br_hash_class,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_prng_class_ {
    pub context_size: size_t,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut *const br_prng_class,
            *const libc::c_void,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
    pub generate: Option::<
        unsafe extern "C" fn(*mut *const br_prng_class, *mut libc::c_void, size_t) -> (),
    >,
    pub update: Option::<
        unsafe extern "C" fn(
            *mut *const br_prng_class,
            *const libc::c_void,
            size_t,
        ) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_10 {
    pub vtable: *const br_sslrec_out_class,
    pub clear: br_sslrec_out_clear_context,
    pub cbc: br_sslrec_out_cbc_context,
    pub gcm: br_sslrec_gcm_context,
    pub chapol: br_sslrec_chapol_context,
    pub ccm: br_sslrec_ccm_context,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_ccm_context {
    pub vtable: bear_C2RustUnnamed_14,
    pub seq: uint64_t,
    pub bc: bear_C2RustUnnamed_11,
    pub iv: [libc::c_uchar; 4],
    pub tag_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_11 {
    pub vtable: *const br_block_ctrcbc_class,
    pub aes: br_aes_gen_ctrcbc_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union br_aes_gen_ctrcbc_keys {
    pub vtable: *const br_block_ctrcbc_class,
    pub c_big: br_aes_big_ctrcbc_keys,
    pub c_small: br_aes_small_ctrcbc_keys,
    pub c_ct: br_aes_ct_ctrcbc_keys,
    pub c_ct64: br_aes_ct64_ctrcbc_keys,
    pub c_x86ni: br_aes_x86ni_ctrcbc_keys,
    pub c_pwr8: br_aes_pwr8_ctrcbc_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_pwr8_ctrcbc_keys {
    pub vtable: *const br_block_ctrcbc_class,
    pub skey: bear_C2RustUnnamed_12,
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_12 {
    pub skni: [libc::c_uchar; 240],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_x86ni_ctrcbc_keys {
    pub vtable: *const br_block_ctrcbc_class,
    pub skey: bear_C2RustUnnamed_13,
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_13 {
    pub skni: [libc::c_uchar; 240],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_ct64_ctrcbc_keys {
    pub vtable: *const br_block_ctrcbc_class,
    pub skey: [uint64_t; 30],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_ct_ctrcbc_keys {
    pub vtable: *const br_block_ctrcbc_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_small_ctrcbc_keys {
    pub vtable: *const br_block_ctrcbc_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_big_ctrcbc_keys {
    pub vtable: *const br_block_ctrcbc_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_14 {
    pub gen: *const libc::c_void,
    pub in_0: *const br_sslrec_in_ccm_class,
    pub out: *const br_sslrec_out_ccm_class,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_chapol_context {
    pub vtable: bear_C2RustUnnamed_15,
    pub seq: uint64_t,
    pub key: [libc::c_uchar; 32],
    pub iv: [libc::c_uchar; 12],
    pub ichacha: br_chacha20_run,
    pub ipoly: br_poly1305_run,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_15 {
    pub gen: *const libc::c_void,
    pub in_0: *const br_sslrec_in_chapol_class,
    pub out: *const br_sslrec_out_chapol_class,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_gcm_context {
    pub vtable: bear_C2RustUnnamed_19,
    pub seq: uint64_t,
    pub bc: bear_C2RustUnnamed_16,
    pub gh: br_ghash,
    pub iv: [libc::c_uchar; 4],
    pub h: [libc::c_uchar; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_16 {
    pub vtable: *const br_block_ctr_class,
    pub aes: br_aes_gen_ctr_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union br_aes_gen_ctr_keys {
    pub vtable: *const br_block_ctr_class,
    pub c_big: br_aes_big_ctr_keys,
    pub c_small: br_aes_small_ctr_keys,
    pub c_ct: br_aes_ct_ctr_keys,
    pub c_ct64: br_aes_ct64_ctr_keys,
    pub c_x86ni: br_aes_x86ni_ctr_keys,
    pub c_pwr8: br_aes_pwr8_ctr_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_pwr8_ctr_keys {
    pub vtable: *const br_block_ctr_class,
    pub skey: bear_C2RustUnnamed_17,
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_17 {
    pub skni: [libc::c_uchar; 240],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_x86ni_ctr_keys {
    pub vtable: *const br_block_ctr_class,
    pub skey: bear_C2RustUnnamed_18,
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_18 {
    pub skni: [libc::c_uchar; 240],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_ct64_ctr_keys {
    pub vtable: *const br_block_ctr_class,
    pub skey: [uint64_t; 30],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_ct_ctr_keys {
    pub vtable: *const br_block_ctr_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_small_ctr_keys {
    pub vtable: *const br_block_ctr_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_big_ctr_keys {
    pub vtable: *const br_block_ctr_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_19 {
    pub gen: *const libc::c_void,
    pub in_0: *const br_sslrec_in_gcm_class,
    pub out: *const br_sslrec_out_gcm_class,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_out_cbc_context {
    pub vtable: *const br_sslrec_out_cbc_class,
    pub seq: uint64_t,
    pub bc: bear_C2RustUnnamed_20,
    pub mac: br_hmac_key_context,
    pub mac_len: size_t,
    pub iv: [libc::c_uchar; 16],
    pub explicit_IV: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_hmac_key_context {
    pub dig_vtable: *const br_hash_class,
    pub ksi: [libc::c_uchar; 64],
    pub kso: [libc::c_uchar; 64],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_20 {
    pub vtable: *const br_block_cbcenc_class,
    pub aes: br_aes_gen_cbcenc_keys,
    pub des: br_des_gen_cbcenc_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union br_des_gen_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub tab: br_des_tab_cbcenc_keys,
    pub ct: br_des_ct_cbcenc_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_des_ct_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub skey: [uint32_t; 96],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_des_tab_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub skey: [uint32_t; 96],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union br_aes_gen_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub c_big: br_aes_big_cbcenc_keys,
    pub c_small: br_aes_small_cbcenc_keys,
    pub c_ct: br_aes_ct_cbcenc_keys,
    pub c_ct64: br_aes_ct64_cbcenc_keys,
    pub c_x86ni: br_aes_x86ni_cbcenc_keys,
    pub c_pwr8: br_aes_pwr8_cbcenc_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_pwr8_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub skey: bear_C2RustUnnamed_21,
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_21 {
    pub skni: [libc::c_uchar; 240],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_x86ni_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub skey: bear_C2RustUnnamed_22,
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_22 {
    pub skni: [libc::c_uchar; 240],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_ct64_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub skey: [uint64_t; 30],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_ct_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_small_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_big_cbcenc_keys {
    pub vtable: *const br_block_cbcenc_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_out_clear_context {
    pub vtable: *const br_sslrec_out_class,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_23 {
    pub vtable: *const br_sslrec_in_class,
    pub cbc: br_sslrec_in_cbc_context,
    pub gcm: br_sslrec_gcm_context,
    pub chapol: br_sslrec_chapol_context,
    pub ccm: br_sslrec_ccm_context,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_sslrec_in_cbc_context {
    pub vtable: *const br_sslrec_in_cbc_class,
    pub seq: uint64_t,
    pub bc: bear_C2RustUnnamed_24,
    pub mac: br_hmac_key_context,
    pub mac_len: size_t,
    pub iv: [libc::c_uchar; 16],
    pub explicit_IV: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_24 {
    pub vtable: *const br_block_cbcdec_class,
    pub aes: br_aes_gen_cbcdec_keys,
    pub des: br_des_gen_cbcdec_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union br_des_gen_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub c_tab: br_des_tab_cbcdec_keys,
    pub c_ct: br_des_ct_cbcdec_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_des_ct_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub skey: [uint32_t; 96],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_des_tab_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub skey: [uint32_t; 96],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union br_aes_gen_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub c_big: br_aes_big_cbcdec_keys,
    pub c_small: br_aes_small_cbcdec_keys,
    pub c_ct: br_aes_ct_cbcdec_keys,
    pub c_ct64: br_aes_ct64_cbcdec_keys,
    pub c_x86ni: br_aes_x86ni_cbcdec_keys,
    pub c_pwr8: br_aes_pwr8_cbcdec_keys,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_pwr8_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub skey: bear_C2RustUnnamed_25,
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_25 {
    pub skni: [libc::c_uchar; 240],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_x86ni_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub skey: bear_C2RustUnnamed_26,
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bear_C2RustUnnamed_26 {
    pub skni: [libc::c_uchar; 240],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_ct64_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub skey: [uint64_t; 30],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_ct_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_small_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_aes_big_cbcdec_keys {
    pub vtable: *const br_block_cbcdec_class,
    pub skey: [uint32_t; 60],
    pub num_rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_x509_decoder_context {
    pub pkey: br_x509_pkey,
    pub cpu: C2RustUnnamed_30,
    pub dp_stack: [uint32_t; 32],
    pub rp_stack: [uint32_t; 32],
    pub err: libc::c_int,
    pub pad: [libc::c_uchar; 256],
    pub decoded: libc::c_uchar,
    pub notbefore_days: uint32_t,
    pub notbefore_seconds: uint32_t,
    pub notafter_days: uint32_t,
    pub notafter_seconds: uint32_t,
    pub isCA: libc::c_uchar,
    pub copy_dn: libc::c_uchar,
    pub append_dn_ctx: *mut libc::c_void,
    pub append_dn: Option::<
        unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> (),
    >,
    pub hbuf: *const libc::c_uchar,
    pub hlen: size_t,
    pub pkey_data: [libc::c_uchar; 520],
    pub signer_key_type: libc::c_uchar,
    pub signer_hash_id: libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_30 {
    pub dp: *mut uint32_t,
    pub rp: *mut uint32_t,
    pub ip: *const libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct br_pem_decoder_context {
    pub cpu: C2RustUnnamed_31,
    pub dp_stack: [uint32_t; 32],
    pub rp_stack: [uint32_t; 32],
    pub err: libc::c_int,
    pub hbuf: *const libc::c_uchar,
    pub hlen: size_t,
    pub dest: Option::<
        unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> (),
    >,
    pub dest_ctx: *mut libc::c_void,
    pub event: libc::c_uchar,
    pub name: [libc::c_char; 128],
    pub buf: [libc::c_uchar; 255],
    pub ptr: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_31 {
    pub dp: *mut uint32_t,
    pub rp: *mut uint32_t,
    pub ip: *const libc::c_uchar,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct cafile_source {
    pub type_0: libc::c_int,
    pub data: *const libc::c_char,
    pub len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cafile_parser {
    pub err: CURLcode,
    pub in_cert: bool,
    pub xc: br_x509_decoder_context,
    pub anchors: *mut br_x509_trust_anchor,
    pub anchors_len: size_t,
    pub dn: [libc::c_uchar; 1024],
    pub dn_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct libssh2_agent_publickey {
    pub magic: libc::c_uint,
    pub node: *mut libc::c_void,
    pub blob: *mut libc::c_uchar,
    pub blob_len: size_t,
    pub comment: *mut libc::c_char,
}

