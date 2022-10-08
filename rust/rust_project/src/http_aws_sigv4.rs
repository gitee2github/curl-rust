use ::libc;
use c2rust_bitfields::BitfieldStruct;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
extern "C" {
    // pub type _IO_wide_data;
    // pub type _IO_codecvt;
    // pub type _IO_marker;
    // pub type Curl_URL;
    // pub type thread_data;
    // pub type altsvcinfo;
    // pub type TELNET;
    // pub type smb_request;
    // pub type ldapreqinfo;
    // pub type contenc_writer;
    // pub type Curl_share;
    // pub type curl_pushheaders;
    // pub type http_connect_state;
    // pub type ldapconninfo;
    // pub type tftp_state_data;
    // pub type nghttp2_session;
    // fn time(__timer: *mut time_t) -> time_t;
    // fn strftime(
    //     __s: *mut libc::c_char,
    //     __maxsize: size_t,
    //     __format: *const libc::c_char,
    //     __tp: *const tm,
    // ) -> size_t;
    // fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    // fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    // fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    // fn Curl_http_method(
    //     data: *mut Curl_easy,
    //     conn: *mut connectdata,
    //     method: *mut *const libc::c_char,
    //     _: *mut Curl_HttpReq,
    // );
    // fn Curl_raw_toupper(in_0: libc::c_char) -> libc::c_char;
    // fn Curl_strntoupper(dest: *mut libc::c_char, src: *const libc::c_char, n: size_t);
    // fn Curl_strntolower(dest: *mut libc::c_char, src: *const libc::c_char, n: size_t);
    // fn Curl_memdup(src: *const libc::c_void, buffer_length: size_t) -> *mut libc::c_void;
    
    // fn Curl_hmacit(
    //     hashparams: *const HMAC_params,
    //     key: *const libc::c_uchar,
    //     keylen: size_t,
    //     data: *const libc::c_uchar,
    //     datalen: size_t,
    //     output: *mut libc::c_uchar,
    // ) -> CURLcode;
    // fn Curl_sha256it(outbuffer: *mut libc::c_uchar, input: *const libc::c_uchar, len: size_t);
    // fn Curl_checkheaders(
    //     data: *const Curl_easy,
    //     thisheader: *const libc::c_char,
    // ) -> *mut libc::c_char;
    // fn Curl_gmtime(intime: time_t, store: *mut tm) -> CURLcode;
    // fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    // fn curl_msnprintf(
    //     buffer: *mut libc::c_char,
    //     maxlength: size_t,
    //     format: *const libc::c_char,
    //     _: ...
    // ) -> libc::c_int;
    // fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
    static Curl_HMAC_SHA256: [HMAC_params; 1];
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
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
// pub type FILE = _IO_FILE;
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
//     pub asi: *mut altsvcinfo,
//     pub progress: Progress,
//     pub state: UrlState,
//     pub wildcard: WildcardData,
//     pub info: PureInfo,
//     pub tsi: curl_tlssessioninfo,
// }
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
//     pub prev_signal: Option<unsafe extern "C" fn(libc::c_int) -> ()>,
//     pub digest: digestdata,
//     pub proxydigest: digestdata,
//     pub authhost: auth,
//     pub authproxy: auth,
//     pub async_0: Curl_async,
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
//     pub multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve:
//         [u8; 3],
//     #[bitfield(padding)]
//     pub c2rust_padding_0: [u8; 5],
// }
// pub type CURLU = Curl_URL;
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct conncache {
//     pub hash: Curl_hash,
//     pub num_conn: size_t,
//     pub next_connection_id: libc::c_long,
//     pub last_cleanup: curltime,
//     pub closure_handle: *mut Curl_easy,
// }
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
//     pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails:
//         [u8; 8],
// }
// pub type curl_trailer_callback =
//     Option<unsafe extern "C" fn(*mut *mut curl_slist, *mut libc::c_void) -> libc::c_int>;
// pub type multidone_func = Option<unsafe extern "C" fn(*mut Curl_easy, CURLcode) -> libc::c_int>;
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct Curl_http2_dep {
//     pub next: *mut Curl_http2_dep,
//     pub data: *mut Curl_easy,
// }
// pub type curl_sshkeycallback = Option<
//     unsafe extern "C" fn(
//         *mut CURL,
//         *const curl_khkey,
//         *const curl_khkey,
//         curl_khmatch,
//         *mut libc::c_void,
//     ) -> libc::c_int,
// >;
// pub type CURL = Curl_easy;
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
//     #[bitfield(name = "certinfo", ty = "bit", bits = "0..=0")]
//     #[bitfield(name = "falsestart", ty = "bit", bits = "1..=1")]
//     #[bitfield(name = "enable_beast", ty = "bit", bits = "2..=2")]
//     #[bitfield(name = "no_revoke", ty = "bit", bits = "3..=3")]
//     #[bitfield(name = "no_partialchain", ty = "bit", bits = "4..=4")]
//     #[bitfield(name = "revoke_best_effort", ty = "bit", bits = "5..=5")]
//     #[bitfield(name = "native_ca_store", ty = "bit", bits = "6..=6")]
//     #[bitfield(name = "auto_client_cert", ty = "bit", bits = "7..=7")]
//     pub certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert:
//         [u8; 1],
//     #[bitfield(padding)]
//     pub c2rust_padding: [u8; 7],
// }
// pub type curl_ssl_ctx_callback =
//     Option<unsafe extern "C" fn(*mut CURL, *mut libc::c_void, *mut libc::c_void) -> CURLcode>;
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct mime_encoder {
//     pub name: *const libc::c_char,
//     pub encodefunc:
//         Option<unsafe extern "C" fn(*mut libc::c_char, size_t, bool, *mut curl_mimepart) -> size_t>,
//     pub sizefunc: Option<unsafe extern "C" fn(*mut curl_mimepart) -> curl_off_t>,
// }
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
// pub type curl_opensocket_callback = Option<
//     unsafe extern "C" fn(*mut libc::c_void, curlsocktype, *mut curl_sockaddr) -> curl_socket_t,
// >;
// pub type curl_ioctl_callback =
//     Option<unsafe extern "C" fn(*mut CURL, libc::c_int, *mut libc::c_void) -> curlioerr>;
// pub type curl_debug_callback = Option<
//     unsafe extern "C" fn(
//         *mut CURL,
//         curl_infotype,
//         *mut libc::c_char,
//         size_t,
//         *mut libc::c_void,
//     ) -> libc::c_int,
// >;
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
//     pub header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk:
//         [u8; 2],
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub union C2RustUnnamed {
//     pub file: *mut FILEPROTO,
//     pub ftp: *mut FTP,
//     pub http: *mut HTTP,
//     pub imap: *mut IMAP,
//     pub ldap: *mut ldapreqinfo,
//     pub mqtt: *mut MQTT,
//     pub pop3: *mut POP3,
//     pub rtsp: *mut RTSP,
//     pub smb: *mut smb_request,
//     pub smtp: *mut SMTP,
//     pub ssh: *mut SSHPROTO,
//     pub telnet: *mut TELNET,
// }
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
// }
// pub type curl_multi_timer_callback =
//     Option<unsafe extern "C" fn(*mut CURLM, libc::c_long, *mut libc::c_void) -> libc::c_int>;
// pub type CURLM = Curl_multi;
// pub type curl_push_callback = Option<
//     unsafe extern "C" fn(
//         *mut CURL,
//         *mut CURL,
//         size_t,
//         *mut curl_pushheaders,
//         *mut libc::c_void,
//     ) -> libc::c_int,
// >;
// pub type curl_socket_callback = Option<
//     unsafe extern "C" fn(
//         *mut CURL,
//         curl_socket_t,
//         libc::c_int,
//         *mut libc::c_void,
//         *mut libc::c_void,
//     ) -> libc::c_int,
// >;
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
// pub union C2RustUnnamed_3 {
//     pub whatever: *mut libc::c_void,
//     pub result: CURLcode,
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
//     pub recv: [Option<Curl_recv>; 2],
//     pub send: [Option<Curl_send>; 2],
//     pub ssl: [ssl_connect_data; 2],
//     pub proxy_ssl: [ssl_connect_data; 2],
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub union C2RustUnnamed_4 {
//     pub ftpc: ftp_conn,
//     pub httpc: http_conn,
//     pub sshc: ssh_conn,
//     pub tftpc: *mut tftp_state_data,
//     pub imapc: imap_conn,
//     pub pop3c: pop3_conn,
//     pub smtpc: smtp_conn,
//     pub rtspc: rtsp_conn,
//     pub smbc: smb_conn,
//     pub rtmp: *mut libc::c_void,
//     pub ldapc: *mut ldapconninfo,
//     pub mqtt: mqtt_conn,
// }
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
//     pub sendauth: Option<
//         unsafe extern "C" fn(
//             *mut Curl_easy,
//             *mut connectdata,
//             *const libc::c_char,
//             *const libc::c_char,
//         ) -> CURLcode,
//     >,
//     pub sendcont: Option<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *const libc::c_char) -> CURLcode,
//     >,
//     pub getmessage: Option<unsafe extern "C" fn(*mut libc::c_char, *mut *mut libc::c_char) -> ()>,
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
//     pub statemachine: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode>,
//     pub endofresp: Option<
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct http_conn {
//     pub binsettings: [uint8_t; 80],
//     pub binlen: size_t,
//     pub trnsfr: *mut Curl_easy,
//     pub h2: *mut nghttp2_session,
//     pub send_underlying: Option<Curl_send>,
//     pub recv_underlying: Option<Curl_recv>,
//     pub inbuf: *mut libc::c_char,
//     pub inbuflen: size_t,
//     pub nread_inbuf: size_t,
//     pub pause_stream_id: int32_t,
//     pub drain_total: size_t,
//     pub settings: h2settings,
//     pub local_settings: [nghttp2_settings_entry; 3],
//     pub local_settings_num: size_t,
// }
// pub type Curl_recv = unsafe extern "C" fn(
//     *mut Curl_easy,
//     libc::c_int,
//     *mut libc::c_char,
//     size_t,
//     *mut CURLcode,
// ) -> ssize_t;
// pub type Curl_send = unsafe extern "C" fn(
//     *mut Curl_easy,
//     libc::c_int,
//     *const libc::c_void,
//     size_t,
//     *mut CURLcode,
// ) -> ssize_t;
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
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct Curl_handler {
//     pub scheme: *const libc::c_char,
//     pub setup_connection:
//         Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode>,
//     pub do_it: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
//     pub done: Option<unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode>,
//     pub do_more: Option<unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_int) -> CURLcode>,
//     pub connect_it: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
//     pub connecting: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
//     pub doing: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
//     pub proto_getsock: Option<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> libc::c_int,
//     >,
//     pub doing_getsock: Option<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> libc::c_int,
//     >,
//     pub domore_getsock: Option<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> libc::c_int,
//     >,
//     pub perform_getsock: Option<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> libc::c_int,
//     >,
//     pub disconnect:
//         Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode>,
//     pub readwrite: Option<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut ssize_t, *mut bool) -> CURLcode,
//     >,
//     pub connection_check: Option<
//         unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, libc::c_uint) -> libc::c_uint,
//     >,
//     pub attach: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> ()>,
//     pub defport: libc::c_int,
//     pub protocol: libc::c_uint,
//     pub family: libc::c_uint,
//     pub flags: libc::c_uint,
// }
// #[derive(Copy, Clone, BitfieldStruct)]
// #[repr(C)]
// pub struct ssl_connect_data {
//     pub state: ssl_connection_state,
//     pub connecting_state: ssl_connect_state,
//     #[bitfield(name = "use_0", ty = "bit", bits = "0..=0")]
//     pub use_0: [u8; 1],
//     #[bitfield(padding)]
//     pub c2rust_padding: [u8; 3],
// }
unsafe extern "C" fn sha256_to_hex(
    mut dst: *mut libc::c_char,
    mut sha: *mut libc::c_uchar,
    mut dst_l: size_t,
) {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 32 as libc::c_int {
        curl_msnprintf(
            dst.offset((i * 2 as libc::c_int) as isize),
            dst_l.wrapping_sub((i * 2 as libc::c_int) as libc::c_ulong),
            b"%02x\0" as *const u8 as *const libc::c_char,
            *sha.offset(i as isize) as libc::c_int,
        );
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_output_aws_sigv4(
    mut data: *mut Curl_easy,
    mut proxy: bool,
) -> CURLcode {
    let mut current_block: u64;
    let mut ret: CURLcode = CURLE_OUT_OF_MEMORY;
    let mut conn: *mut connectdata = (*data).conn;
    let mut len: size_t = 0;
    let mut tmp0: *const libc::c_char = 0 as *const libc::c_char;
    let mut tmp1: *const libc::c_char = 0 as *const libc::c_char;
    let mut provider0_low: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut provider0_up: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut provider1_low: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut provider1_mid: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut region: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut service: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hostname: *const libc::c_char = (*conn).host.name;
    let mut clock: time_t = 0;
    let mut tm: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: 0 as *const libc::c_char,
    };
    let mut timestamp: [libc::c_char; 17] = [0; 17];
    let mut date: [libc::c_char; 9] = [0; 9];
    let mut content_type: *const libc::c_char =
        Curl_checkheaders(data, b"Content-Type\0" as *const u8 as *const libc::c_char);
    let mut canonical_headers: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut signed_headers: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut httpreq: Curl_HttpReq = HTTPREQ_GET;
    let mut method: *const libc::c_char = 0 as *const libc::c_char;
    let mut post_data: *const libc::c_char = (if !((*data).set.postfields).is_null() {
        (*data).set.postfields
    } else {
        b"\0" as *const u8 as *const libc::c_char as *const libc::c_void
    }) as *const libc::c_char;
    let mut sha_hash: [libc::c_uchar; 32] = [0; 32];
    let mut sha_hex: [libc::c_char; 65] = [0; 65];
    let mut canonical_request: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut request_type: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut credential_scope: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut str_to_sign: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut user: *const libc::c_char = if !((*data).state.aptr.user).is_null() {
        (*data).state.aptr.user as *const libc::c_char
    } else {
        b"\0" as *const u8 as *const libc::c_char
    };
    let mut passwd: *const libc::c_char = if !((*data).state.aptr.passwd).is_null() {
        (*data).state.aptr.passwd as *const libc::c_char
    } else {
        b"\0" as *const u8 as *const libc::c_char
    };
    let mut secret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp_sign0: [libc::c_uchar; 32] = [
        0 as libc::c_int as libc::c_uchar,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut tmp_sign1: [libc::c_uchar; 32] = [
        0 as libc::c_int as libc::c_uchar,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut auth_headers: *mut libc::c_char = 0 as *mut libc::c_char;
    if !(Curl_checkheaders(data, b"Authorization\0" as *const u8 as *const libc::c_char)).is_null()
    {
        return CURLE_OK;
    }
    tmp0 = if !((*data).set.str_0[STRING_AWS_SIGV4 as libc::c_int as usize]).is_null() {
        (*data).set.str_0[STRING_AWS_SIGV4 as libc::c_int as usize] as *const libc::c_char
    } else {
        b"aws:amz\0" as *const u8 as *const libc::c_char
    };
    tmp1 = strchr(tmp0, ':' as i32);
    len = if !tmp1.is_null() {
        tmp1.offset_from(tmp0) as libc::c_long as size_t
    } else {
        strlen(tmp0)
    };
    if len < 1 as libc::c_int as libc::c_ulong {
        Curl_infof(
            data,
            b"first provider can't be empty\0" as *const u8 as *const libc::c_char,
        );
        ret = CURLE_BAD_FUNCTION_ARGUMENT;
    } else {
        provider0_low = Curl_cmalloc.expect("non-null function pointer")(
            len.wrapping_add(1 as libc::c_int as libc::c_ulong),
        ) as *mut libc::c_char;
        provider0_up = Curl_cmalloc.expect("non-null function pointer")(
            len.wrapping_add(1 as libc::c_int as libc::c_ulong),
        ) as *mut libc::c_char;
        if !(provider0_low.is_null() || provider0_up.is_null()) {
            Curl_strntolower(provider0_low, tmp0, len);
            *provider0_low.offset(len as isize) = '\0' as i32 as libc::c_char;
            Curl_strntoupper(provider0_up, tmp0, len);
            *provider0_up.offset(len as isize) = '\0' as i32 as libc::c_char;
            if !tmp1.is_null() {
                tmp0 = tmp1.offset(1 as libc::c_int as isize);
                tmp1 = strchr(tmp0, ':' as i32);
                len = if !tmp1.is_null() {
                    tmp1.offset_from(tmp0) as libc::c_long as size_t
                } else {
                    strlen(tmp0)
                };
                if len < 1 as libc::c_int as libc::c_ulong {
                    Curl_infof(
                        data,
                        b"second provider can't be empty\0" as *const u8 as *const libc::c_char,
                    );
                    ret = CURLE_BAD_FUNCTION_ARGUMENT;
                    current_block = 16896850163988546332;
                } else {
                    provider1_low = Curl_cmalloc.expect("non-null function pointer")(
                        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                    ) as *mut libc::c_char;
                    provider1_mid = Curl_cmalloc.expect("non-null function pointer")(
                        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                    ) as *mut libc::c_char;
                    if provider1_low.is_null() || provider1_mid.is_null() {
                        current_block = 16896850163988546332;
                    } else {
                        Curl_strntolower(provider1_low, tmp0, len);
                        *provider1_low.offset(len as isize) = '\0' as i32 as libc::c_char;
                        Curl_strntolower(provider1_mid, tmp0, len);
                        *provider1_mid.offset(0 as libc::c_int as isize) =
                            Curl_raw_toupper(*provider1_mid.offset(0 as libc::c_int as isize));
                        *provider1_mid.offset(len as isize) = '\0' as i32 as libc::c_char;
                        if !tmp1.is_null() {
                            tmp0 = tmp1.offset(1 as libc::c_int as isize);
                            tmp1 = strchr(tmp0, ':' as i32);
                            len = if !tmp1.is_null() {
                                tmp1.offset_from(tmp0) as libc::c_long as size_t
                            } else {
                                strlen(tmp0)
                            };
                            if len < 1 as libc::c_int as libc::c_ulong {
                                Curl_infof(
                                    data,
                                    b"region can't be empty\0" as *const u8 as *const libc::c_char,
                                );
                                ret = CURLE_BAD_FUNCTION_ARGUMENT;
                                current_block = 16896850163988546332;
                            } else {
                                region = Curl_memdup(
                                    tmp0 as *const libc::c_void,
                                    len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                                ) as *mut libc::c_char;
                                if region.is_null() {
                                    current_block = 16896850163988546332;
                                } else {
                                    *region.offset(len as isize) = '\0' as i32 as libc::c_char;
                                    if !tmp1.is_null() {
                                        tmp0 = tmp1.offset(1 as libc::c_int as isize);
                                        service =
                                            Curl_cstrdup.expect("non-null function pointer")(tmp0);
                                        if service.is_null() {
                                            current_block = 16896850163988546332;
                                        } else if strlen(service)
                                            < 1 as libc::c_int as libc::c_ulong
                                        {
                                            Curl_infof(
                                                data,
                                                b"service can't be empty\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                            ret = CURLE_BAD_FUNCTION_ARGUMENT;
                                            current_block = 16896850163988546332;
                                        } else {
                                            current_block = 11052029508375673978;
                                        }
                                    } else {
                                        current_block = 11052029508375673978;
                                    }
                                }
                            }
                        } else {
                            current_block = 11052029508375673978;
                        }
                    }
                }
            } else {
                provider1_low = Curl_memdup(
                    provider0_low as *const libc::c_void,
                    len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                ) as *mut libc::c_char;
                provider1_mid = Curl_memdup(
                    provider0_low as *const libc::c_void,
                    len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                ) as *mut libc::c_char;
                if provider1_low.is_null() || provider1_mid.is_null() {
                    current_block = 16896850163988546332;
                } else {
                    *provider1_mid.offset(0 as libc::c_int as isize) =
                        Curl_raw_toupper(*provider1_mid.offset(0 as libc::c_int as isize));
                    current_block = 11052029508375673978;
                }
            }
            match current_block {
                16896850163988546332 => {}
                _ => {
                    if service.is_null() {
                        tmp0 = hostname;
                        tmp1 = strchr(tmp0, '.' as i32);
                        len = tmp1.offset_from(tmp0) as libc::c_long as size_t;
                        if tmp1.is_null() || len < 1 as libc::c_int as libc::c_ulong {
                            Curl_infof(
                                data,
                                b"service missing in parameters or hostname\0" as *const u8
                                    as *const libc::c_char,
                            );
                            ret = CURLE_URL_MALFORMAT;
                            current_block = 16896850163988546332;
                        } else {
                            service = Curl_memdup(
                                tmp0 as *const libc::c_void,
                                len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                            ) as *mut libc::c_char;
                            if service.is_null() {
                                current_block = 16896850163988546332;
                            } else {
                                *service.offset(len as isize) = '\0' as i32 as libc::c_char;
                                if region.is_null() {
                                    tmp0 = tmp1.offset(1 as libc::c_int as isize);
                                    tmp1 = strchr(tmp0, '.' as i32);
                                    len = tmp1.offset_from(tmp0) as libc::c_long as size_t;
                                    if tmp1.is_null() || len < 1 as libc::c_int as libc::c_ulong {
                                        Curl_infof(
                                            data,
                                            b"region missing in parameters or hostname\0"
                                                as *const u8
                                                as *const libc::c_char,
                                        );
                                        ret = CURLE_URL_MALFORMAT;
                                        current_block = 16896850163988546332;
                                    } else {
                                        region = Curl_memdup(
                                            tmp0 as *const libc::c_void,
                                            len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                                        )
                                            as *mut libc::c_char;
                                        if region.is_null() {
                                            current_block = 16896850163988546332;
                                        } else {
                                            *region.offset(len as isize) =
                                                '\0' as i32 as libc::c_char;
                                            current_block = 6040267449472925966;
                                        }
                                    }
                                } else {
                                    current_block = 6040267449472925966;
                                }
                            }
                        }
                    } else {
                        current_block = 6040267449472925966;
                    }
                    match current_block {
                        16896850163988546332 => {}
                        _ => {
                            time(&mut clock);
                            ret = Curl_gmtime(clock, &mut tm);
                            if !(ret as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint) {
                                if !(strftime(
                                    timestamp.as_mut_ptr(),
                                    ::std::mem::size_of::<[libc::c_char; 17]>() as libc::c_ulong,
                                    b"%Y%m%dT%H%M%SZ\0" as *const u8 as *const libc::c_char,
                                    &mut tm,
                                ) == 0)
                                {
                                    memcpy(
                                        date.as_mut_ptr() as *mut libc::c_void,
                                        timestamp.as_mut_ptr() as *const libc::c_void,
                                        ::std::mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong,
                                    );
                                    date[(::std::mem::size_of::<[libc::c_char; 9]>()
                                        as libc::c_ulong)
                                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                        as usize] = 0 as libc::c_int as libc::c_char;
                                    if !content_type.is_null() {
                                        content_type = strchr(content_type, ':' as i32);
                                        if content_type.is_null() {
                                            ret = CURLE_FAILED_INIT;
                                            current_block = 16896850163988546332;
                                        } else {
                                            content_type = content_type.offset(1);
                                            while *content_type as libc::c_int == ' ' as i32
                                                || *content_type as libc::c_int == '\t' as i32
                                            {
                                                content_type = content_type.offset(1);
                                            }
                                            canonical_headers = curl_maprintf(
                                                b"content-type:%s\nhost:%s\nx-%s-date:%s\n\0"
                                                    as *const u8
                                                    as *const libc::c_char,
                                                content_type,
                                                hostname,
                                                provider1_low,
                                                timestamp.as_mut_ptr(),
                                            );
                                            signed_headers = curl_maprintf(
                                                b"content-type;host;x-%s-date\0" as *const u8
                                                    as *const libc::c_char,
                                                provider1_low,
                                            );
                                            current_block = 5248622017361056354;
                                        }
                                    } else {
                                        canonical_headers = curl_maprintf(
                                            b"host:%s\nx-%s-date:%s\n\0" as *const u8
                                                as *const libc::c_char,
                                            hostname,
                                            provider1_low,
                                            timestamp.as_mut_ptr(),
                                        );
                                        signed_headers = curl_maprintf(
                                            b"host;x-%s-date\0" as *const u8 as *const libc::c_char,
                                            provider1_low,
                                        );
                                        current_block = 5248622017361056354;
                                    }
                                    match current_block {
                                        16896850163988546332 => {}
                                        _ => {
                                            if !(canonical_headers.is_null()
                                                || signed_headers.is_null())
                                            {
                                                Curl_sha256it(
                                                    sha_hash.as_mut_ptr(),
                                                    post_data as *const libc::c_uchar,
                                                    strlen(post_data),
                                                );
                                                sha256_to_hex(
                                                    sha_hex.as_mut_ptr(),
                                                    sha_hash.as_mut_ptr(),
                                                    ::std::mem::size_of::<[libc::c_char; 65]>()
                                                        as libc::c_ulong,
                                                );
                                                Curl_http_method(
                                                    data,
                                                    conn,
                                                    &mut method,
                                                    &mut httpreq,
                                                );
                                                canonical_request = curl_maprintf(
                                                    b"%s\n%s\n%s\n%s\n%s\n%s\0" as *const u8
                                                        as *const libc::c_char,
                                                    method,
                                                    (*data).state.up.path,
                                                    if !((*data).state.up.query).is_null() {
                                                        (*data).state.up.query
                                                            as *const libc::c_char
                                                    } else {
                                                        b"\0" as *const u8 as *const libc::c_char
                                                    },
                                                    canonical_headers,
                                                    signed_headers,
                                                    sha_hex.as_mut_ptr(),
                                                );
                                                if !canonical_request.is_null() {
                                                    request_type = curl_maprintf(
                                                        b"%s4_request\0" as *const u8
                                                            as *const libc::c_char,
                                                        provider0_low,
                                                    );
                                                    if !request_type.is_null() {
                                                        credential_scope = curl_maprintf(
                                                            b"%s/%s/%s/%s\0" as *const u8
                                                                as *const libc::c_char,
                                                            date.as_mut_ptr(),
                                                            region,
                                                            service,
                                                            request_type,
                                                        );
                                                        if !credential_scope.is_null() {
                                                            Curl_sha256it(
                                                                sha_hash.as_mut_ptr(),
                                                                canonical_request
                                                                    as *mut libc::c_uchar,
                                                                strlen(canonical_request),
                                                            );
                                                            sha256_to_hex(
                                                                sha_hex.as_mut_ptr(),
                                                                sha_hash.as_mut_ptr(),
                                                                ::std::mem::size_of::<
                                                                    [libc::c_char; 65],
                                                                >(
                                                                )
                                                                    as libc::c_ulong,
                                                            );
                                                            str_to_sign = curl_maprintf(
                                                                b"%s4-HMAC-SHA256\n%s\n%s\n%s\0"
                                                                    as *const u8
                                                                    as *const libc::c_char,
                                                                provider0_up,
                                                                timestamp.as_mut_ptr(),
                                                                credential_scope,
                                                                sha_hex.as_mut_ptr(),
                                                            );
                                                            if !str_to_sign.is_null() {
                                                                secret = curl_maprintf(
                                                                    b"%s4%s\0" as *const u8
                                                                        as *const libc::c_char,
                                                                    provider0_up,
                                                                    passwd,
                                                                );
                                                                if !secret.is_null() {
                                                                    ret = Curl_hmacit(
                                                                        Curl_HMAC_SHA256.as_ptr(),
                                                                        secret
                                                                            as *mut libc::c_uchar,
                                                                        strlen(secret)
                                                                            as libc::c_uint
                                                                            as size_t,
                                                                        date.as_mut_ptr()
                                                                            as *mut libc::c_uchar,
                                                                        strlen(date.as_mut_ptr())
                                                                            as libc::c_uint
                                                                            as size_t,
                                                                        tmp_sign0.as_mut_ptr(),
                                                                    );
                                                                    if !(ret as libc::c_uint
                                                                        != CURLE_OK as libc::c_int
                                                                            as libc::c_uint)
                                                                    {
                                                                        ret = Curl_hmacit(
                                                                            Curl_HMAC_SHA256.as_ptr(),
                                                                            tmp_sign0.as_mut_ptr(),
                                                                            ::std::mem::size_of::<[libc::c_uchar; 32]>()
                                                                                as libc::c_ulong as libc::c_uint as size_t,
                                                                            region as *mut libc::c_uchar,
                                                                            strlen(region) as libc::c_uint as size_t,
                                                                            tmp_sign1.as_mut_ptr(),
                                                                        );
                                                                        if !(ret as libc::c_uint
                                                                            != CURLE_OK
                                                                                as libc::c_int
                                                                                as libc::c_uint)
                                                                        {
                                                                            ret = Curl_hmacit(
                                                                                Curl_HMAC_SHA256.as_ptr(),
                                                                                tmp_sign1.as_mut_ptr(),
                                                                                ::std::mem::size_of::<[libc::c_uchar; 32]>()
                                                                                    as libc::c_ulong as libc::c_uint as size_t,
                                                                                service as *mut libc::c_uchar,
                                                                                strlen(service) as libc::c_uint as size_t,
                                                                                tmp_sign0.as_mut_ptr(),
                                                                            );
                                                                            if !(ret
                                                                                as libc::c_uint
                                                                                != CURLE_OK
                                                                                    as libc::c_int
                                                                                    as libc::c_uint)
                                                                            {
                                                                                ret = Curl_hmacit(
                                                                                    Curl_HMAC_SHA256.as_ptr(),
                                                                                    tmp_sign0.as_mut_ptr(),
                                                                                    ::std::mem::size_of::<[libc::c_uchar; 32]>()
                                                                                        as libc::c_ulong as libc::c_uint as size_t,
                                                                                    request_type as *mut libc::c_uchar,
                                                                                    strlen(request_type) as libc::c_uint as size_t,
                                                                                    tmp_sign1.as_mut_ptr(),
                                                                                );
                                                                                if !(ret as libc::c_uint
                                                                                    != CURLE_OK as libc::c_int as libc::c_uint)
                                                                                {
                                                                                    ret = Curl_hmacit(
                                                                                        Curl_HMAC_SHA256.as_ptr(),
                                                                                        tmp_sign1.as_mut_ptr(),
                                                                                        ::std::mem::size_of::<[libc::c_uchar; 32]>()
                                                                                            as libc::c_ulong as libc::c_uint as size_t,
                                                                                        str_to_sign as *mut libc::c_uchar,
                                                                                        strlen(str_to_sign) as libc::c_uint as size_t,
                                                                                        tmp_sign0.as_mut_ptr(),
                                                                                    );
                                                                                    if !(ret as libc::c_uint
                                                                                        != CURLE_OK as libc::c_int as libc::c_uint)
                                                                                    {
                                                                                        sha256_to_hex(
                                                                                            sha_hex.as_mut_ptr(),
                                                                                            tmp_sign0.as_mut_ptr(),
                                                                                            ::std::mem::size_of::<[libc::c_char; 65]>() as libc::c_ulong,
                                                                                        );
                                                                                        auth_headers = curl_maprintf(
                                                                                            b"Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\nX-%s-Date: %s\r\n\0"
                                                                                                as *const u8 as *const libc::c_char,
                                                                                            provider0_up,
                                                                                            user,
                                                                                            credential_scope,
                                                                                            signed_headers,
                                                                                            sha_hex.as_mut_ptr(),
                                                                                            provider1_mid,
                                                                                            timestamp.as_mut_ptr(),
                                                                                        );
                                                                                        if !auth_headers.is_null() {
                                                                                            Curl_cfree
                                                                                                .expect(
                                                                                                    "non-null function pointer",
                                                                                                )((*data).state.aptr.userpwd as *mut libc::c_void);
                                                                                            let ref mut fresh0 = (*data).state.aptr.userpwd;
                                                                                            *fresh0 = 0 as *mut libc::c_char;
                                                                                            let ref mut fresh1 = (*data).state.aptr.userpwd;
                                                                                            *fresh1 = auth_headers;
                                                                                            let ref mut fresh2 = (*data).state.authhost;
                                                                                            (*fresh2).set_done(1 as libc::c_int as bit);
                                                                                            ret = CURLE_OK;
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(provider0_low as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(provider0_up as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(provider1_low as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(provider1_mid as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(region as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(service as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(canonical_headers as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(signed_headers as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(canonical_request as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(request_type as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(credential_scope as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(str_to_sign as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(secret as *mut libc::c_void);
    return ret;
}
