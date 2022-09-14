use crate::src::ffi_alias::type_alias::*;
use c2rust_bitfields::BitfieldStruct;

// http_ntlm.rs + http_digest.rs + http_proxy.rs + http_chuncks.rs + vtls/keylog.rs
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct _IO_FILE {
//     pub _flags: libc::c_int,
//     pub _IO_read_ptr: *mut libc::c_char,
//     pub _IO_read_end: *mut libc::c_char,
//     pub _IO_read_base: *mut libc::c_char,
//     pub _IO_write_base: *mut libc::c_char,
//     pub _IO_write_ptr: *mut libc::c_char,
//     pub _IO_write_end: *mut libc::c_char,
//     pub _IO_buf_base: *mut libc::c_char,
//     pub _IO_buf_end: *mut libc::c_char,
//     pub _IO_save_base: *mut libc::c_char,
//     pub _IO_backup_base: *mut libc::c_char,
//     pub _IO_save_end: *mut libc::c_char,
//     pub _markers: *mut _IO_marker,
//     pub _chain: *mut _IO_FILE,
//     pub _fileno: libc::c_int,
//     pub _flags2: libc::c_int,
//     pub _old_offset: __off_t,
//     pub _cur_column: libc::c_ushort,
//     pub _vtable_offset: libc::c_schar,
//     pub _shortbuf: [libc::c_char; 1],
//     pub _lock: *mut libc::c_void,
//     pub _offset: __off64_t,
//     pub _codecvt: *mut _IO_codecvt,
//     pub _wide_data: *mut _IO_wide_data,
//     pub _freeres_list: *mut _IO_FILE,
//     pub _freeres_buf: *mut libc::c_void,
//     pub __pad5: size_t,
//     pub _mode: libc::c_int,
//     pub _unused2: [libc::c_char; 20],
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct Curl_easy {
//     pub magic: libc::c_uint,
//     pub next: *mut Curl_easy,
//     pub prev: *mut Curl_easy,
//     pub conn: *mut connectdata,
//     pub connect_queue: Curl_llist_element,
//     pub conn_queue: Curl_llist_element,
//     pub mstate: CURLMstate,
//     pub result: CURLcode,
//     pub msg: Curl_message,
//     pub sockets: [curl_socket_t; 5],
//     pub actions: [libc::c_uchar; 5],
//     pub numsocks: libc::c_int,
//     pub dns: Names,
//     pub multi: *mut Curl_multi,
//     pub multi_easy: *mut Curl_multi,
//     pub share: *mut Curl_share,
//     pub req: SingleRequest,
//     pub set: UserDefined,
//     pub cookies: *mut CookieInfo,
//     pub hsts: *mut hsts,
//     pub asi: *mut altsvcinfo,
//     pub progress: Progress,
//     pub state: UrlState,
//     pub wildcard: WildcardData,
//     pub info: PureInfo,
//     pub tsi: curl_tlssessioninfo,
// }
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
// #[derive(Copy, Clone, BitfieldStruct)]
// #[repr(C)]
// pub struct UrlState {
//     pub conn_cache: *mut conncache,
//     pub keeps_speed: curltime,
//     pub lastconnect_id: libc::c_long,
//     pub headerb: dynbuf,
//     pub buffer: *mut libc::c_char,
//     pub ulbuf: *mut libc::c_char,
//     pub current_speed: curl_off_t,
//     pub first_host: *mut libc::c_char,
//     pub retrycount: libc::c_int,
//     pub first_remote_port: libc::c_int,
//     pub session: *mut Curl_ssl_session,
//     pub sessionage: libc::c_long,
//     pub tempwrite: [tempbuf; 3],
//     pub tempcount: libc::c_uint,
//     pub os_errno: libc::c_int,
//     pub scratch: *mut libc::c_char,
//     pub followlocation: libc::c_long,
//     pub prev_signal: Option::<unsafe extern "C" fn(libc::c_int) -> ()>,
//     pub digest: digestdata,
//     pub proxydigest: digestdata,
//     pub authhost: auth,
//     pub authproxy: auth,
//     pub async_0: Curl_async,
//     pub engine: *mut libc::c_void,
//     pub expiretime: curltime,
//     pub timenode: Curl_tree,
//     pub timeoutlist: Curl_llist,
//     pub expires: [time_node; 13],
//     pub most_recent_ftp_entrypath: *mut libc::c_char,
//     pub httpwant: libc::c_uchar,
//     pub httpversion: libc::c_uchar,
//     #[bitfield(name = "prev_block_had_trailing_cr", ty = "bit", bits = "0..=0")]
//     pub prev_block_had_trailing_cr: [u8; 1],
//     #[bitfield(padding)]
//     pub c2rust_padding: [u8; 5],
//     pub crlf_conversions: curl_off_t,
//     pub range: *mut libc::c_char,
//     pub resume_from: curl_off_t,
//     pub rtsp_next_client_CSeq: libc::c_long,
//     pub rtsp_next_server_CSeq: libc::c_long,
//     pub rtsp_CSeq_recv: libc::c_long,
//     pub infilesize: curl_off_t,
//     pub drain: size_t,
//     pub fread_func: curl_read_callback,
//     pub in_0: *mut libc::c_void,
//     pub stream_depends_on: *mut Curl_easy,
//     pub stream_weight: libc::c_int,
//     pub uh: *mut CURLU,
//     pub up: urlpieces,
//     pub httpreq: Curl_HttpReq,
//     pub url: *mut libc::c_char,
//     pub referer: *mut libc::c_char,
//     pub cookielist: *mut curl_slist,
//     pub resolve: *mut curl_slist,
//     pub trailers_bytes_sent: size_t,
//     pub trailers_buf: dynbuf,
//     pub trailers_state: trailers_state,
//     pub aptr: dynamically_allocated_data,
//     #[bitfield(name = "multi_owned_by_easy", ty = "bit", bits = "0..=0")]
//     #[bitfield(name = "this_is_a_follow", ty = "bit", bits = "1..=1")]
//     #[bitfield(name = "refused_stream", ty = "bit", bits = "2..=2")]
//     #[bitfield(name = "errorbuf", ty = "bit", bits = "3..=3")]
//     #[bitfield(name = "allow_port", ty = "bit", bits = "4..=4")]
//     #[bitfield(name = "authproblem", ty = "bit", bits = "5..=5")]
//     #[bitfield(name = "ftp_trying_alternative", ty = "bit", bits = "6..=6")]
//     #[bitfield(name = "wildcardmatch", ty = "bit", bits = "7..=7")]
//     #[bitfield(name = "expect100header", ty = "bit", bits = "8..=8")]
//     #[bitfield(name = "disableexpect", ty = "bit", bits = "9..=9")]
//     #[bitfield(name = "use_range", ty = "bit", bits = "10..=10")]
//     #[bitfield(name = "rangestringalloc", ty = "bit", bits = "11..=11")]
//     #[bitfield(name = "done", ty = "bit", bits = "12..=12")]
//     #[bitfield(name = "stream_depends_e", ty = "bit", bits = "13..=13")]
//     #[bitfield(name = "previouslypending", ty = "bit", bits = "14..=14")]
//     #[bitfield(name = "cookie_engine", ty = "bit", bits = "15..=15")]
//     #[bitfield(name = "prefer_ascii", ty = "bit", bits = "16..=16")]
//     #[bitfield(name = "list_only", ty = "bit", bits = "17..=17")]
//     #[bitfield(name = "url_alloc", ty = "bit", bits = "18..=18")]
//     #[bitfield(name = "referer_alloc", ty = "bit", bits = "19..=19")]
//     #[bitfield(name = "wildcard_resolve", ty = "bit", bits = "20..=20")]
//     pub multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve: [u8; 3],
//     #[bitfield(padding)]
//     pub c2rust_padding_0: [u8; 5],
// }
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
// #[derive(Copy, Clone, BitfieldStruct)]
// #[repr(C)]
// pub struct Curl_async {
//     pub hostname: *mut libc::c_char,
//     pub dns: *mut Curl_dns_entry,
//     pub tdata: *mut thread_data,
//     pub resolver: *mut libc::c_void,
//     pub port: libc::c_int,
//     pub status: libc::c_int,
//     #[bitfield(name = "done", ty = "bit", bits = "0..=0")]
//     pub done: [u8; 1],
//     #[bitfield(padding)]
//     pub c2rust_padding: [u8; 7],
// }
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct Curl_ssl_session {
//     pub name: *mut libc::c_char,
//     pub conn_to_host: *mut libc::c_char,
//     pub scheme: *const libc::c_char,
//     pub sessionid: *mut libc::c_void,
//     pub idsize: size_t,
//     pub age: libc::c_long,
//     pub remote_port: libc::c_int,
//     pub conn_to_port: libc::c_int,
//     pub ssl_config: ssl_primary_config,
// }
// #[derive(Copy, Clone, BitfieldStruct)]
// #[repr(C)]
// pub struct ssl_primary_config {
//     pub version: libc::c_long,
//     pub version_max: libc::c_long,
//     pub CApath: *mut libc::c_char,
//     pub CAfile: *mut libc::c_char,
//     pub issuercert: *mut libc::c_char,
//     pub clientcert: *mut libc::c_char,
//     pub random_file: *mut libc::c_char,
//     pub egdsocket: *mut libc::c_char,
//     pub cipher_list: *mut libc::c_char,
//     pub cipher_list13: *mut libc::c_char,
//     pub pinned_key: *mut libc::c_char,
//     pub cert_blob: *mut curl_blob,
//     pub ca_info_blob: *mut curl_blob,
//     pub issuercert_blob: *mut curl_blob,
//     pub curves: *mut libc::c_char,
//     #[bitfield(name = "verifypeer", ty = "bit", bits = "0..=0")]
//     #[bitfield(name = "verifyhost", ty = "bit", bits = "1..=1")]
//     #[bitfield(name = "verifystatus", ty = "bit", bits = "2..=2")]
//     #[bitfield(name = "sessionid", ty = "bit", bits = "3..=3")]
//     pub verifypeer_verifyhost_verifystatus_sessionid: [u8; 1],
//     #[bitfield(padding)]
//     pub c2rust_padding: [u8; 7],
// }
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_blob {
    pub data: *mut libc::c_void,
    pub len: size_t,
    pub flags: libc::c_uint,
}
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct conncache {
//     pub hash: Curl_hash,
//     pub num_conn: size_t,
//     pub next_connection_id: libc::c_long,
//     pub last_cleanup: curltime,
//     pub closure_handle: *mut Curl_easy,
// }
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
// #[derive(Copy, Clone, BitfieldStruct)]
// #[repr(C)]
// pub struct UserDefined {
//     pub err: *mut FILE,
//     pub debugdata: *mut libc::c_void,
//     pub errorbuffer: *mut libc::c_char,
//     pub proxyport: libc::c_long,
//     pub out: *mut libc::c_void,
//     pub in_set: *mut libc::c_void,
//     pub writeheader: *mut libc::c_void,
//     pub rtp_out: *mut libc::c_void,
//     pub use_port: libc::c_long,
//     pub httpauth: libc::c_ulong,
//     pub proxyauth: libc::c_ulong,
//     pub socks5auth: libc::c_ulong,
//     pub maxredirs: libc::c_long,
//     pub keep_post: libc::c_int,
//     pub postfields: *mut libc::c_void,
//     pub seek_func: curl_seek_callback,
//     pub postfieldsize: curl_off_t,
//     pub localport: libc::c_ushort,
//     pub localportrange: libc::c_int,
//     pub fwrite_func: curl_write_callback,
//     pub fwrite_header: curl_write_callback,
//     pub fwrite_rtp: curl_write_callback,
//     pub fread_func_set: curl_read_callback,
//     pub fprogress: curl_progress_callback,
//     pub fxferinfo: curl_xferinfo_callback,
//     pub fdebug: curl_debug_callback,
//     pub ioctl_func: curl_ioctl_callback,
//     pub fsockopt: curl_sockopt_callback,
//     pub sockopt_client: *mut libc::c_void,
//     pub fopensocket: curl_opensocket_callback,
//     pub opensocket_client: *mut libc::c_void,
//     pub fclosesocket: curl_closesocket_callback,
//     pub closesocket_client: *mut libc::c_void,
//     pub seek_client: *mut libc::c_void,
//     pub convfromnetwork: curl_conv_callback,
//     pub convtonetwork: curl_conv_callback,
//     pub convfromutf8: curl_conv_callback,
//     pub hsts_read: curl_hstsread_callback,
//     pub hsts_read_userp: *mut libc::c_void,
//     pub hsts_write: curl_hstswrite_callback,
//     pub hsts_write_userp: *mut libc::c_void,
//     pub progress_client: *mut libc::c_void,
//     pub ioctl_client: *mut libc::c_void,
//     pub timeout: libc::c_long,
//     pub connecttimeout: libc::c_long,
//     pub accepttimeout: libc::c_long,
//     pub happy_eyeballs_timeout: libc::c_long,
//     pub server_response_timeout: libc::c_long,
//     pub maxage_conn: libc::c_long,
//     pub tftp_blksize: libc::c_long,
//     pub filesize: curl_off_t,
//     pub low_speed_limit: libc::c_long,
//     pub low_speed_time: libc::c_long,
//     pub max_send_speed: curl_off_t,
//     pub max_recv_speed: curl_off_t,
//     pub set_resume_from: curl_off_t,
//     pub headers: *mut curl_slist,
//     pub proxyheaders: *mut curl_slist,
//     pub httppost: *mut curl_httppost,
//     pub mimepost: curl_mimepart,
//     pub quote: *mut curl_slist,
//     pub postquote: *mut curl_slist,
//     pub prequote: *mut curl_slist,
//     pub source_quote: *mut curl_slist,
//     pub source_prequote: *mut curl_slist,
//     pub source_postquote: *mut curl_slist,
//     pub telnet_options: *mut curl_slist,
//     pub resolve: *mut curl_slist,
//     pub connect_to: *mut curl_slist,
//     pub timecondition: curl_TimeCond,
//     pub proxytype: curl_proxytype,
//     pub timevalue: time_t,
//     pub method: Curl_HttpReq,
//     pub httpwant: libc::c_uchar,
//     pub ssl: ssl_config_data,
//     pub proxy_ssl: ssl_config_data,
//     pub general_ssl: ssl_general_config,
//     pub dns_cache_timeout: libc::c_long,
//     pub buffer_size: libc::c_long,
//     pub upload_buffer_size: libc::c_uint,
//     pub private_data: *mut libc::c_void,
//     pub http200aliases: *mut curl_slist,
//     pub ipver: libc::c_uchar,
//     pub max_filesize: curl_off_t,
//     pub ftp_filemethod: curl_ftpfile,
//     pub ftpsslauth: curl_ftpauth,
//     pub ftp_ccc: curl_ftpccc,
//     pub ftp_create_missing_dirs: libc::c_int,
//     pub ssh_keyfunc: curl_sshkeycallback,
//     pub ssh_keyfunc_userp: *mut libc::c_void,
//     pub use_netrc: CURL_NETRC_OPTION,
//     pub use_ssl: curl_usessl,
//     pub new_file_perms: libc::c_long,
//     pub new_directory_perms: libc::c_long,
//     pub ssh_auth_types: libc::c_long,
//     pub str_0: [*mut libc::c_char; 80],
//     pub blobs: [*mut curl_blob; 8],
//     pub scope_id: libc::c_uint,
//     pub allowed_protocols: libc::c_long,
//     pub redir_protocols: libc::c_long,
//     pub mail_rcpt: *mut curl_slist,
//     pub rtspreq: Curl_RtspReq,
//     pub rtspversion: libc::c_long,
//     pub chunk_bgn: curl_chunk_bgn_callback,
//     pub chunk_end: curl_chunk_end_callback,
//     pub fnmatch: curl_fnmatch_callback,
//     pub fnmatch_data: *mut libc::c_void,
//     pub gssapi_delegation: libc::c_long,
//     pub tcp_keepidle: libc::c_long,
//     pub tcp_keepintvl: libc::c_long,
//     pub maxconnects: size_t,
//     pub expect_100_timeout: libc::c_long,
//     pub stream_depends_on: *mut Curl_easy,
//     pub stream_weight: libc::c_int,
//     pub stream_dependents: *mut Curl_http2_dep,
//     pub resolver_start: curl_resolver_start_callback,
//     pub resolver_start_client: *mut libc::c_void,
//     pub upkeep_interval_ms: libc::c_long,
//     pub fmultidone: multidone_func,
//     pub dohfor: *mut Curl_easy,
//     pub uh: *mut CURLU,
//     pub trailer_data: *mut libc::c_void,
//     pub trailer_callback: curl_trailer_callback,
//     #[bitfield(name = "is_fread_set", ty = "bit", bits = "0..=0")]
//     #[bitfield(name = "is_fwrite_set", ty = "bit", bits = "1..=1")]
//     #[bitfield(name = "free_referer", ty = "bit", bits = "2..=2")]
//     #[bitfield(name = "tftp_no_options", ty = "bit", bits = "3..=3")]
//     #[bitfield(name = "sep_headers", ty = "bit", bits = "4..=4")]
//     #[bitfield(name = "cookiesession", ty = "bit", bits = "5..=5")]
//     #[bitfield(name = "crlf", ty = "bit", bits = "6..=6")]
//     #[bitfield(name = "strip_path_slash", ty = "bit", bits = "7..=7")]
//     #[bitfield(name = "ssh_compression", ty = "bit", bits = "8..=8")]
//     #[bitfield(name = "get_filetime", ty = "bit", bits = "9..=9")]
//     #[bitfield(name = "tunnel_thru_httpproxy", ty = "bit", bits = "10..=10")]
//     #[bitfield(name = "prefer_ascii", ty = "bit", bits = "11..=11")]
//     #[bitfield(name = "remote_append", ty = "bit", bits = "12..=12")]
//     #[bitfield(name = "list_only", ty = "bit", bits = "13..=13")]
//     #[bitfield(name = "ftp_use_port", ty = "bit", bits = "14..=14")]
//     #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "15..=15")]
//     #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "16..=16")]
//     #[bitfield(name = "ftp_use_pret", ty = "bit", bits = "17..=17")]
//     #[bitfield(name = "ftp_skip_ip", ty = "bit", bits = "18..=18")]
//     #[bitfield(name = "hide_progress", ty = "bit", bits = "19..=19")]
//     #[bitfield(name = "http_fail_on_error", ty = "bit", bits = "20..=20")]
//     #[bitfield(name = "http_keep_sending_on_error", ty = "bit", bits = "21..=21")]
//     #[bitfield(name = "http_follow_location", ty = "bit", bits = "22..=22")]
//     #[bitfield(name = "http_transfer_encoding", ty = "bit", bits = "23..=23")]
//     #[bitfield(name = "allow_auth_to_other_hosts", ty = "bit", bits = "24..=24")]
//     #[bitfield(name = "include_header", ty = "bit", bits = "25..=25")]
//     #[bitfield(name = "http_set_referer", ty = "bit", bits = "26..=26")]
//     #[bitfield(name = "http_auto_referer", ty = "bit", bits = "27..=27")]
//     #[bitfield(name = "opt_no_body", ty = "bit", bits = "28..=28")]
//     #[bitfield(name = "upload", ty = "bit", bits = "29..=29")]
//     #[bitfield(name = "verbose", ty = "bit", bits = "30..=30")]
//     #[bitfield(name = "krb", ty = "bit", bits = "31..=31")]
//     #[bitfield(name = "reuse_forbid", ty = "bit", bits = "32..=32")]
//     #[bitfield(name = "reuse_fresh", ty = "bit", bits = "33..=33")]
//     #[bitfield(name = "no_signal", ty = "bit", bits = "34..=34")]
//     #[bitfield(name = "tcp_nodelay", ty = "bit", bits = "35..=35")]
//     #[bitfield(name = "ignorecl", ty = "bit", bits = "36..=36")]
//     #[bitfield(name = "connect_only", ty = "bit", bits = "37..=37")]
//     #[bitfield(name = "http_te_skip", ty = "bit", bits = "38..=38")]
//     #[bitfield(name = "http_ce_skip", ty = "bit", bits = "39..=39")]
//     #[bitfield(name = "proxy_transfer_mode", ty = "bit", bits = "40..=40")]
//     #[bitfield(name = "sasl_ir", ty = "bit", bits = "41..=41")]
//     #[bitfield(name = "wildcard_enabled", ty = "bit", bits = "42..=42")]
//     #[bitfield(name = "tcp_keepalive", ty = "bit", bits = "43..=43")]
//     #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "44..=44")]
//     #[bitfield(name = "ssl_enable_npn", ty = "bit", bits = "45..=45")]
//     #[bitfield(name = "ssl_enable_alpn", ty = "bit", bits = "46..=46")]
//     #[bitfield(name = "path_as_is", ty = "bit", bits = "47..=47")]
//     #[bitfield(name = "pipewait", ty = "bit", bits = "48..=48")]
//     #[bitfield(name = "suppress_connect_headers", ty = "bit", bits = "49..=49")]
//     #[bitfield(name = "dns_shuffle_addresses", ty = "bit", bits = "50..=50")]
//     #[bitfield(name = "stream_depends_e", ty = "bit", bits = "51..=51")]
//     #[bitfield(name = "haproxyprotocol", ty = "bit", bits = "52..=52")]
//     #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "53..=53")]
//     #[bitfield(name = "disallow_username_in_url", ty = "bit", bits = "54..=54")]
//     #[bitfield(name = "doh", ty = "bit", bits = "55..=55")]
//     #[bitfield(name = "doh_get", ty = "bit", bits = "56..=56")]
//     #[bitfield(name = "doh_verifypeer", ty = "bit", bits = "57..=57")]
//     #[bitfield(name = "doh_verifyhost", ty = "bit", bits = "58..=58")]
//     #[bitfield(name = "doh_verifystatus", ty = "bit", bits = "59..=59")]
//     #[bitfield(name = "http09_allowed", ty = "bit", bits = "60..=60")]
//     #[bitfield(name = "mail_rcpt_allowfails", ty = "bit", bits = "61..=61")]
//     pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails: [u8; 8],
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct Curl_http2_dep {
//     pub next: *mut Curl_http2_dep,
//     pub data: *mut Curl_easy,
// }
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
// #[derive(Copy, Clone, BitfieldStruct)]
// #[repr(C)]
// pub struct ssl_config_data {
//     pub primary: ssl_primary_config,
//     pub certverifyresult: libc::c_long,
//     pub CRLfile: *mut libc::c_char,
//     pub fsslctx: curl_ssl_ctx_callback,
//     pub fsslctxp: *mut libc::c_void,
//     pub cert_type: *mut libc::c_char,
//     pub key: *mut libc::c_char,
//     pub key_blob: *mut curl_blob,
//     pub key_type: *mut libc::c_char,
//     pub key_passwd: *mut libc::c_char,
//     pub username: *mut libc::c_char,
//     pub password: *mut libc::c_char,
//     pub authtype: CURL_TLSAUTH,
//     #[bitfield(name = "certinfo", ty = "bit", bits = "0..=0")]
//     #[bitfield(name = "falsestart", ty = "bit", bits = "1..=1")]
//     #[bitfield(name = "enable_beast", ty = "bit", bits = "2..=2")]
//     #[bitfield(name = "no_revoke", ty = "bit", bits = "3..=3")]
//     #[bitfield(name = "no_partialchain", ty = "bit", bits = "4..=4")]
//     #[bitfield(name = "revoke_best_effort", ty = "bit", bits = "5..=5")]
//     #[bitfield(name = "native_ca_store", ty = "bit", bits = "6..=6")]
//     #[bitfield(name = "auto_client_cert", ty = "bit", bits = "7..=7")]
//     pub certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert: [u8; 1],
//     #[bitfield(padding)]
//     pub c2rust_padding: [u8; 3],
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct curl_mimepart {
//     pub easy: *mut Curl_easy,
//     pub parent: *mut curl_mime,
//     pub nextpart: *mut curl_mimepart,
//     pub kind: mimekind,
//     pub flags: libc::c_uint,
//     pub data: *mut libc::c_char,
//     pub readfunc: curl_read_callback,
//     pub seekfunc: curl_seek_callback,
//     pub freefunc: curl_free_callback,
//     pub arg: *mut libc::c_void,
//     pub fp: *mut FILE,
//     pub curlheaders: *mut curl_slist,
//     pub userheaders: *mut curl_slist,
//     pub mimetype: *mut libc::c_char,
//     pub filename: *mut libc::c_char,
//     pub name: *mut libc::c_char,
//     pub datasize: curl_off_t,
//     pub state: mime_state,
//     pub encoder: *const mime_encoder,
//     pub encstate: mime_encoder_state,
//     pub lastreadstatus: size_t,
// }
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder_state {
    pub pos: size_t,
    pub bufbeg: size_t,
    pub bufend: size_t,
    pub buf: [libc::c_char; 256],
}
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct mime_encoder {
//     pub name: *const libc::c_char,
//     pub encodefunc: Option::<
//         unsafe extern "C" fn(
//             *mut libc::c_char,
//             size_t,
//             bool,
//             *mut curl_mimepart,
//         ) -> size_t,
//     >,
//     pub sizefunc: Option::<unsafe extern "C" fn(*mut curl_mimepart) -> curl_off_t>,
// }
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_state {
    pub state: mimestate,
    pub ptr: *mut libc::c_void,
    pub offset: curl_off_t,
}
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct curl_mime {
//     pub easy: *mut Curl_easy,
//     pub parent: *mut curl_mimepart,
//     pub firstpart: *mut curl_mimepart,
//     pub lastpart: *mut curl_mimepart,
//     pub boundary: [libc::c_char; 41],
//     pub state: mime_state,
// }
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
pub struct curl_sockaddr {
    pub family: libc::c_int,
    pub socktype: libc::c_int,
    pub protocol: libc::c_int,
    pub addrlen: libc::c_uint,
    pub addr: sockaddr,
}
// #[derive(Copy, Clone, BitfieldStruct)]
// #[repr(C)]
// pub struct SingleRequest {
//     pub size: curl_off_t,
//     pub maxdownload: curl_off_t,
//     pub bytecount: curl_off_t,
//     pub writebytecount: curl_off_t,
//     pub headerbytecount: curl_off_t,
//     pub deductheadercount: curl_off_t,
//     pub pendingheader: curl_off_t,
//     pub start: curltime,
//     pub now: curltime,
//     pub badheader: C2RustUnnamed_1,
//     pub headerline: libc::c_int,
//     pub str_0: *mut libc::c_char,
//     pub offset: curl_off_t,
//     pub httpcode: libc::c_int,
//     pub keepon: libc::c_int,
//     pub start100: curltime,
//     pub exp100: expect100,
//     pub upgr101: upgrade101,
//     pub writer_stack: *mut contenc_writer,
//     pub timeofdoc: time_t,
//     pub bodywrites: libc::c_long,
//     pub location: *mut libc::c_char,
//     pub newurl: *mut libc::c_char,
//     pub upload_present: ssize_t,
//     pub upload_fromhere: *mut libc::c_char,
//     pub p: C2RustUnnamed,
//     pub doh: *mut dohdata,
//     #[bitfield(name = "header", ty = "bit", bits = "0..=0")]
//     #[bitfield(name = "content_range", ty = "bit", bits = "1..=1")]
//     #[bitfield(name = "upload_done", ty = "bit", bits = "2..=2")]
//     #[bitfield(name = "ignorebody", ty = "bit", bits = "3..=3")]
//     #[bitfield(name = "http_bodyless", ty = "bit", bits = "4..=4")]
//     #[bitfield(name = "chunk", ty = "bit", bits = "5..=5")]
//     #[bitfield(name = "ignore_cl", ty = "bit", bits = "6..=6")]
//     #[bitfield(name = "upload_chunky", ty = "bit", bits = "7..=7")]
//     #[bitfield(name = "getheader", ty = "bit", bits = "8..=8")]
//     #[bitfield(name = "forbidchunk", ty = "bit", bits = "9..=9")]
//     pub header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk: [u8; 2],
//     #[bitfield(padding)]
//     pub c2rust_padding: [u8; 6],
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct dohdata {
//     pub headers: *mut curl_slist,
//     pub probe: [dnsprobe; 2],
//     pub pending: libc::c_uint,
//     pub port: libc::c_int,
//     pub host: *const libc::c_char,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct dnsprobe {
//     pub easy: *mut CURL,
//     pub dnstype: libc::c_int,
//     pub dohbuffer: [libc::c_uchar; 512],
//     pub dohlen: size_t,
//     pub serverdoh: dynbuf,
// }
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SSHPROTO {
    pub path: *mut libc::c_char,
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct RTSP {
//     pub http_wrapper: HTTP,
//     pub CSeq_sent: libc::c_long,
//     pub CSeq_recv: libc::c_long,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct HTTP {
//     pub sendit: *mut curl_mimepart,
//     pub postsize: curl_off_t,
//     pub postdata: *const libc::c_char,
//     pub p_pragma: *const libc::c_char,
//     pub form: curl_mimepart,
//     pub backup: back,
//     pub sending: C2RustUnnamed_0,
//     pub send_buffer: dynbuf,
//     pub stream_id: int32_t,
//     pub bodystarted: bool,
//     pub header_recvbuf: dynbuf,
//     pub nread_header_recvbuf: size_t,
//     pub trailer_recvbuf: dynbuf,
//     pub status_code: libc::c_int,
//     pub pausedata: *const uint8_t,
//     pub pauselen: size_t,
//     pub close_handled: bool,
//     pub push_headers: *mut *mut libc::c_char,
//     pub push_headers_used: size_t,
//     pub push_headers_alloc: size_t,
//     pub error: uint32_t,
//     pub closed: bool,
//     pub mem: *mut libc::c_char,
//     pub len: size_t,
//     pub memlen: size_t,
//     pub upload_mem: *const uint8_t,
//     pub upload_len: size_t,
//     pub upload_left: curl_off_t,
// }
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct contenc_writer {
//     pub handler: *const content_encoding,
//     pub downstream: *mut contenc_writer,
//     pub params: *mut libc::c_void,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct content_encoding {
//     pub name: *const libc::c_char,
//     pub alias: *const libc::c_char,
//     pub init_writer: Option::<
//         unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> CURLcode,
//     >,
//     pub unencode_write: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut contenc_writer,
//             *const libc::c_char,
//             size_t,
//         ) -> CURLcode,
//     >,
//     pub close_writer: Option::<
//         unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> (),
//     >,
//     pub paramsize: size_t,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct Curl_multi {
//     pub magic: libc::c_uint,
//     pub easyp: *mut Curl_easy,
//     pub easylp: *mut Curl_easy,
//     pub num_easy: libc::c_int,
//     pub num_alive: libc::c_int,
//     pub msglist: Curl_llist,
//     pub pending: Curl_llist,
//     pub socket_cb: curl_socket_callback,
//     pub socket_userp: *mut libc::c_void,
//     pub push_cb: curl_push_callback,
//     pub push_userp: *mut libc::c_void,
//     pub hostcache: Curl_hash,
//     pub timetree: *mut Curl_tree,
//     pub sockhash: Curl_hash,
//     pub conn_cache: conncache,
//     pub maxconnects: libc::c_long,
//     pub max_host_connections: libc::c_long,
//     pub max_total_connections: libc::c_long,
//     pub timer_cb: curl_multi_timer_callback,
//     pub timer_userp: *mut libc::c_void,
//     pub timer_lastcall: curltime,
//     pub max_concurrent_streams: libc::c_uint,
//     pub wakeup_pair: [curl_socket_t; 2],
//     pub multiplexing: bool,
//     pub recheckstate: bool,
//     pub in_callback: bool,
//     pub ipv6_works: bool,
//     pub ssl_seeded: bool,
// }
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Names {
    pub hostcache: *mut Curl_hash,
    pub hostcachetype: C2RustUnnamed_2,
}
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct Curl_message {
//     pub list: Curl_llist_element,
//     pub extmsg: CURLMsg,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct CURLMsg {
//     pub msg: CURLMSG,
//     pub easy_handle: *mut CURL,
//     pub data: C2RustUnnamed_3,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct connectdata {
//     pub cnnct: connstate,
//     pub bundle_node: Curl_llist_element,
//     pub chunk: Curl_chunker,
//     pub fclosesocket: curl_closesocket_callback,
//     pub closesocket_client: *mut libc::c_void,
//     pub connection_id: libc::c_long,
//     pub dns_entry: *mut Curl_dns_entry,
//     pub ip_addr: *mut Curl_addrinfo,
//     pub tempaddr: [*mut Curl_addrinfo; 2],
//     pub scope_id: libc::c_uint,
//     pub transport: C2RustUnnamed_5,
//     pub host: hostname,
//     pub hostname_resolve: *mut libc::c_char,
//     pub secondaryhostname: *mut libc::c_char,
//     pub conn_to_host: hostname,
//     pub socks_proxy: proxy_info,
//     pub http_proxy: proxy_info,
//     pub port: libc::c_int,
//     pub remote_port: libc::c_int,
//     pub conn_to_port: libc::c_int,
//     pub secondary_port: libc::c_ushort,
//     pub primary_ip: [libc::c_char; 46],
//     pub ip_version: libc::c_uchar,
//     pub user: *mut libc::c_char,
//     pub passwd: *mut libc::c_char,
//     pub options: *mut libc::c_char,
//     pub sasl_authzid: *mut libc::c_char,
//     pub httpversion: libc::c_uchar,
//     pub now: curltime,
//     pub created: curltime,
//     pub lastused: curltime,
//     pub sock: [curl_socket_t; 2],
//     pub tempsock: [curl_socket_t; 2],
//     pub tempfamily: [libc::c_int; 2],
//     pub recv: [Option::<Curl_recv>; 2],
//     pub send: [Option::<Curl_send>; 2],
//     pub ssl: [ssl_connect_data; 2],
//     pub proxy_ssl: [ssl_connect_data; 2],
//     pub ssl_extra: *mut libc::c_void,
//     pub ssl_config: ssl_primary_config,
//     pub proxy_ssl_config: ssl_primary_config,
//     pub bits: ConnectBits,
//     pub num_addr: libc::c_int,
//     pub connecttime: curltime,
//     pub timeoutms_per_addr: [timediff_t; 2],
//     pub handler: *const Curl_handler,
//     pub given: *const Curl_handler,
//     pub keepalive: curltime,
//     pub sockfd: curl_socket_t,
//     pub writesockfd: curl_socket_t,
//     pub easyq: Curl_llist,
//     pub seek_func: curl_seek_callback,
//     pub seek_client: *mut libc::c_void,
//     pub http_ntlm_state: curlntlm,
//     pub proxy_ntlm_state: curlntlm,
//     pub ntlm: ntlmdata,
//     pub proxyntlm: ntlmdata,
//     pub trailer: dynbuf,
//     pub proto: C2RustUnnamed_4,
//     pub connect_state: *mut http_connect_state,
//     pub bundle: *mut connectbundle,
//     pub unix_domain_socket: *mut libc::c_char,
//     pub localdev: *mut libc::c_char,
//     pub localportrange: libc::c_int,
//     pub cselect_bits: libc::c_int,
//     pub waitfor: libc::c_int,
//     pub negnpn: libc::c_int,
//     pub localport: libc::c_ushort,
// }
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connectbundle {
    pub multiuse: libc::c_int,
    pub num_connections: size_t,
    pub conn_list: Curl_llist,
}
// #[derive(Copy, Clone, BitfieldStruct)]
// #[repr(C)]
// pub struct http_connect_state {
//     pub http_proxy: HTTP,
//     pub prot_save: *mut HTTP,
//     pub rcvbuf: dynbuf,
//     pub req: dynbuf,
//     pub nsend: size_t,
//     pub keepon: keeponval,
//     pub cl: curl_off_t,
//     pub tunnel_state: C2RustUnnamed_4,
//     #[bitfield(name = "chunked_encoding", ty = "bit", bits = "0..=0")]
//     #[bitfield(name = "close_connection", ty = "bit", bits = "1..=1")]
//     pub chunked_encoding_close_connection: [u8; 1],
//     #[bitfield(padding)]
//     pub c2rust_padding: [u8; 3],
// }
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct smtp_conn {
//     pub pp: pingpong,
//     pub state: smtpstate,
//     pub ssldone: bool,
//     pub domain: *mut libc::c_char,
//     pub sasl: SASL,
//     pub tls_supported: bool,
//     pub size_supported: bool,
//     pub utf8_supported: bool,
//     pub auth_supported: bool,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct SASL {
//     pub params: *const SASLproto,
//     pub state: saslstate,
//     pub authmechs: libc::c_ushort,
//     pub prefmech: libc::c_ushort,
//     pub authused: libc::c_ushort,
//     pub resetprefs: bool,
//     pub mutual_auth: bool,
//     pub force_ir: bool,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct SASLproto {
//     pub service: *const libc::c_char,
//     pub contcode: libc::c_int,
//     pub finalcode: libc::c_int,
//     pub maxirlen: size_t,
//     pub sendauth: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             *const libc::c_char,
//             *const libc::c_char,
//         ) -> CURLcode,
//     >,
//     pub sendcont: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             *const libc::c_char,
//         ) -> CURLcode,
//     >,
//     pub getmessage: Option::<
//         unsafe extern "C" fn(*mut libc::c_char, *mut *mut libc::c_char) -> (),
//     >,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct pingpong {
//     pub cache: *mut libc::c_char,
//     pub cache_size: size_t,
//     pub nread_resp: size_t,
//     pub linestart_resp: *mut libc::c_char,
//     pub pending_resp: bool,
//     pub sendthis: *mut libc::c_char,
//     pub sendleft: size_t,
//     pub sendsize: size_t,
//     pub response: curltime,
//     pub response_time: timediff_t,
//     pub sendbuf: dynbuf,
//     pub statemachine: Option::<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
//     >,
//     pub endofresp: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             *mut libc::c_char,
//             size_t,
//             *mut libc::c_int,
//         ) -> bool,
//     >,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct pop3_conn {
//     pub pp: pingpong,
//     pub state: pop3state,
//     pub ssldone: bool,
//     pub tls_supported: bool,
//     pub eob: size_t,
//     pub strip: size_t,
//     pub sasl: SASL,
//     pub authtypes: libc::c_uint,
//     pub preftype: libc::c_uint,
//     pub apoptimestamp: *mut libc::c_char,
// }
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct imap_conn {
//     pub pp: pingpong,
//     pub state: imapstate,
//     pub ssldone: bool,
//     pub preauth: bool,
//     pub sasl: SASL,
//     pub preftype: libc::c_uint,
//     pub cmdid: libc::c_uint,
//     pub resptag: [libc::c_char; 5],
//     pub tls_supported: bool,
//     pub login_disabled: bool,
//     pub ir_supported: bool,
//     pub mailbox: *mut libc::c_char,
//     pub mailbox_uidvalidity: *mut libc::c_char,
//     pub dyn_0: dynbuf,
// }
#[derive(Copy, Clone)]
#[repr(C)]
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
}
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct http_conn {
//     pub binsettings: [uint8_t; 80],
//     pub binlen: size_t,
//     pub trnsfr: *mut Curl_easy,
//     pub h2: *mut nghttp2_session,
//     pub send_underlying: Option::<Curl_send>,
//     pub recv_underlying: Option::<Curl_recv>,
//     pub inbuf: *mut libc::c_char,
//     pub inbuflen: size_t,
//     pub nread_inbuf: size_t,
//     pub pause_stream_id: int32_t,
//     pub drain_total: size_t,
//     pub settings: h2settings,
//     pub local_settings: [nghttp2_settings_entry; 3],
//     pub local_settings_num: size_t,
// }
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_settings_entry {
    pub settings_id: int32_t,
    pub value: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct h2settings {
    pub max_concurrent_streams: uint32_t,
    pub enable_push: bool,
}
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ftp_conn {
//     pub pp: pingpong,
//     pub entrypath: *mut libc::c_char,
//     pub file: *mut libc::c_char,
//     pub dirs: *mut *mut libc::c_char,
//     pub dirdepth: libc::c_int,
//     pub dont_check: bool,
//     pub ctl_valid: bool,
//     pub cwddone: bool,
//     pub cwdcount: libc::c_int,
//     pub cwdfail: bool,
//     pub wait_data_conn: bool,
//     pub newport: libc::c_ushort,
//     pub newhost: *mut libc::c_char,
//     pub prevpath: *mut libc::c_char,
//     pub transfertype: libc::c_char,
//     pub count1: libc::c_int,
//     pub count2: libc::c_int,
//     pub count3: libc::c_int,
//     pub state: ftpstate,
//     pub state_saved: ftpstate,
//     pub retr_size_saved: curl_off_t,
//     pub server_os: *mut libc::c_char,
//     pub known_filesize: curl_off_t,
// }
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ntlmdata {
    pub flags: libc::c_uint,
    pub nonce: [libc::c_uchar; 8],
    pub target_info_len: libc::c_uint,
    pub target_info: *mut libc::c_void,
    pub ntlm_auth_hlpr_socket: curl_socket_t,
    pub ntlm_auth_hlpr_pid: pid_t,
    pub challenge: *mut libc::c_char,
    pub response: *mut libc::c_char,
}
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct Curl_handler {
//     pub scheme: *const libc::c_char,
//     pub setup_connection: Option::<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
//     >,
//     pub do_it: Option::<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
//     pub done: Option::<unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode>,
//     pub do_more: Option::<
//         unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_int) -> CURLcode,
//     >,
//     pub connect_it: Option::<
//         unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
//     >,
//     pub connecting: Option::<
//         unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
//     >,
//     pub doing: Option::<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
//     pub proto_getsock: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             *mut curl_socket_t,
//         ) -> libc::c_int,
//     >,
//     pub doing_getsock: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             *mut curl_socket_t,
//         ) -> libc::c_int,
//     >,
//     pub domore_getsock: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             *mut curl_socket_t,
//         ) -> libc::c_int,
//     >,
//     pub perform_getsock: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             *mut curl_socket_t,
//         ) -> libc::c_int,
//     >,
//     pub disconnect: Option::<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
//     >,
//     pub readwrite: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             *mut ssize_t,
//             *mut bool,
//         ) -> CURLcode,
//     >,
//     pub connection_check: Option::<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             libc::c_uint,
//         ) -> libc::c_uint,
//     >,
//     pub attach: Option::<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> ()>,
//     pub defport: libc::c_int,
//     pub protocol: libc::c_uint,
//     pub family: libc::c_uint,
//     pub flags: libc::c_uint,
// }
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ConnectBits {
    pub tcpconnect: [bool; 2],
    pub proxy_ssl_connected: [bool; 2],
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
    pub httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect:
        [u8; 5],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
// #[derive(Copy, Clone, BitfieldStruct)]
// #[repr(C)]
// pub struct ssl_connect_data {
//     pub state: ssl_connection_state,
//     pub connecting_state: ssl_connect_state,
//     pub backend: *mut ssl_backend_data,
//     #[bitfield(name = "use_0", ty = "bit", bits = "0..=0")]
//     pub use_0: [u8; 1],
//     #[bitfield(padding)]
//     pub c2rust_padding: [u8; 7],
// }
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
pub struct bufref {
    pub dtor: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub ptr: *const libc::c_uchar,
    pub len: size_t,
}
