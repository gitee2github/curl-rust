use ::libc;
use c2rust_bitfields::BitfieldStruct;
use rust_ffi::src::ffi_alias::type_alias::*;
// use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
extern "C" {
    // pub type _IO_wide_data;
    // pub type _IO_codecvt;
    // pub type _IO_marker;
    // pub type Curl_URL;
    // pub type thread_data;
    pub type altsvcinfo;
    // pub type TELNET;
    // pub type smb_request;
    // pub type ldapreqinfo;
    // pub type contenc_writer;
    // pub type Curl_share;
    // pub type curl_pushheaders;
    // pub type ldapconninfo;
    // pub type tftp_state_data;
    // pub type nghttp2_session;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn curl_strnequal(s1: *const libc::c_char, s2: *const libc::c_char, n: size_t) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn Curl_httpchunk_init(data: *mut Curl_easy);
    fn Curl_httpchunk_read(
        data: *mut Curl_easy,
        datap: *mut libc::c_char,
        length: ssize_t,
        wrote: *mut ssize_t,
        passthru: *mut CURLcode,
    ) -> CHUNKcode;
    fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn Curl_dyn_free(s: *mut dynbuf);
    fn Curl_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    fn Curl_dyn_add(s: *mut dynbuf, str: *const libc::c_char) -> CURLcode;
    fn Curl_dyn_addf(s: *mut dynbuf, fmt: *const libc::c_char, _: ...) -> CURLcode;
    fn Curl_dyn_reset(s: *mut dynbuf);
    fn Curl_dyn_ptr(s: *const dynbuf) -> *mut libc::c_char;
    fn Curl_dyn_len(s: *const dynbuf) -> size_t;
    fn Curl_compareheader(
        headerline: *const libc::c_char,
        header: *const libc::c_char,
        content: *const libc::c_char,
    ) -> bool;
    fn Curl_copy_header_value(header: *const libc::c_char) -> *mut libc::c_char;
    fn Curl_checkProxyheaders(
        data: *mut Curl_easy,
        conn: *const connectdata,
        thisheader: *const libc::c_char,
    ) -> *mut libc::c_char;
    fn Curl_buffer_send(
        in_0: *mut dynbuf,
        data: *mut Curl_easy,
        bytes_written: *mut curl_off_t,
        included_body_bytes: curl_off_t,
        socketindex: libc::c_int,
    ) -> CURLcode;
    fn Curl_add_custom_headers(
        data: *mut Curl_easy,
        is_connect: bool,
        req: *mut dynbuf,
    ) -> CURLcode;
    fn Curl_http_input_auth(
        data: *mut Curl_easy,
        proxy: bool,
        auth: *const libc::c_char,
    ) -> CURLcode;
    fn Curl_http_auth_act(data: *mut Curl_easy) -> CURLcode;
    fn Curl_http_output_auth(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        request: *const libc::c_char,
        httpreq: Curl_HttpReq,
        path: *const libc::c_char,
        proxytunnel: bool,
    ) -> CURLcode;
    fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_failf(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_client_write(
        data: *mut Curl_easy,
        type_0: libc::c_int,
        ptr: *mut libc::c_char,
        len: size_t,
    ) -> CURLcode;
    fn Curl_read(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        buf: *mut libc::c_char,
        buffersize: size_t,
        n: *mut ssize_t,
    ) -> CURLcode;
    fn Curl_write(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        mem: *const libc::c_void,
        len: size_t,
        written: *mut ssize_t,
    ) -> CURLcode;
    fn Curl_debug(
        data: *mut Curl_easy,
        type_0: curl_infotype,
        ptr: *mut libc::c_char,
        size: size_t,
    ) -> libc::c_int;
    fn Curl_pgrsUpdate(data: *mut Curl_easy) -> libc::c_int;
    fn Curl_timeleft(data: *mut Curl_easy, nowp: *mut curltime, duringconnect: bool) -> timediff_t;
    fn Curl_closesocket(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sock: curl_socket_t,
    ) -> libc::c_int;
    fn Curl_conncontrol(conn: *mut connectdata, closeit: libc::c_int);
    fn Curl_conn_data_pending(conn: *mut connectdata, sockindex: libc::c_int) -> bool;
    fn curlx_strtoofft(
        str: *const libc::c_char,
        endp: *mut *mut libc::c_char,
        base: libc::c_int,
        num: *mut curl_off_t,
    ) -> CURLofft;
    fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn Curl_fillreadbuffer(data: *mut Curl_easy, bytes: size_t, nreadp: *mut size_t) -> CURLcode;
    fn Curl_get_upload_buffer(data: *mut Curl_easy) -> CURLcode;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_ccalloc: curl_calloc_callback;
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
    pub req: SingleRequest,
    pub set: UserDefined,
    pub cookies: *mut CookieInfo,
    pub asi: *mut altsvcinfo,
    pub progress: Progress,
    pub state: UrlState,
    pub wildcard: WildcardData,
    pub info: PureInfo,
    pub tsi: curl_tlssessioninfo,
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
    pub prev_signal: Option<unsafe extern "C" fn(libc::c_int) -> ()>,
    pub digest: digestdata,
    pub proxydigest: digestdata,
    pub authhost: auth,
    pub authproxy: auth,
    pub async_0: Curl_async,
    pub expiretime: curltime,
    pub timenode: Curl_tree,
    pub timeoutlist: Curl_llist,
    pub expires: [time_node; 13],
    pub most_recent_ftp_entrypath: *mut libc::c_char,
    pub httpwant: libc::c_uchar,
    pub httpversion: libc::c_uchar,
    #[bitfield(name = "prev_block_had_trailing_cr", ty = "bit", bits = "0..=0")]
    pub prev_block_had_trailing_cr: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 5],
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
    pub trailers_bytes_sent: size_t,
    pub trailers_buf: dynbuf,
    pub trailers_state: trailers_state,
    pub aptr: dynamically_allocated_data,
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
    pub multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve:
        [u8; 3],
    #[bitfield(padding)]
    pub c2rust_padding_0: [u8; 5],
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conncache {
    pub hash: Curl_hash,
    pub num_conn: size_t,
    pub next_connection_id: libc::c_long,
    pub last_cleanup: curltime,
    pub closure_handle: *mut Curl_easy,
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
    pub proxy_ssl: ssl_config_data,
    pub general_ssl: ssl_general_config,
    pub dns_cache_timeout: libc::c_long,
    pub buffer_size: libc::c_long,
    pub upload_buffer_size: libc::c_uint,
    pub private_data: *mut libc::c_void,
    pub http200aliases: *mut curl_slist,
    pub ipver: libc::c_uchar,
    pub max_filesize: curl_off_t,
    pub ftp_filemethod: curl_ftpfile,
    pub ftpsslauth: curl_ftpauth,
    pub ftp_ccc: curl_ftpccc,
    pub ftp_create_missing_dirs: libc::c_int,
    pub ssh_keyfunc: curl_sshkeycallback,
    pub ssh_keyfunc_userp: *mut libc::c_void,
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
    pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails:
        [u8; 8],
}
// pub type curl_trailer_callback =
//     Option<unsafe extern "C" fn(*mut *mut curl_slist, *mut libc::c_void) -> libc::c_int>;
pub type multidone_func = Option<unsafe extern "C" fn(*mut Curl_easy, CURLcode) -> libc::c_int>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_http2_dep {
    pub next: *mut Curl_http2_dep,
    pub data: *mut Curl_easy,
}
pub type curl_sshkeycallback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        *const curl_khkey,
        *const curl_khkey,
        curl_khmatch,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type CURL = Curl_easy;
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
    #[bitfield(name = "certinfo", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "falsestart", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "enable_beast", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "no_revoke", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "no_partialchain", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "revoke_best_effort", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "native_ca_store", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "auto_client_cert", ty = "bit", bits = "7..=7")]
    pub certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert:
        [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type curl_ssl_ctx_callback =
    Option<unsafe extern "C" fn(*mut CURL, *mut libc::c_void, *mut libc::c_void) -> CURLcode>;
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
pub struct mime_encoder {
    pub name: *const libc::c_char,
    pub encodefunc:
        Option<unsafe extern "C" fn(*mut libc::c_char, size_t, bool, *mut curl_mimepart) -> size_t>,
    pub sizefunc: Option<unsafe extern "C" fn(*mut curl_mimepart) -> curl_off_t>,
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
// pub type curl_opensocket_callback = Option<
//     unsafe extern "C" fn(*mut libc::c_void, curlsocktype, *mut curl_sockaddr) -> curl_socket_t,
// >;
pub type curl_ioctl_callback =
    Option<unsafe extern "C" fn(*mut CURL, libc::c_int, *mut libc::c_void) -> curlioerr>;
pub type curl_debug_callback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        curl_infotype,
        *mut libc::c_char,
        size_t,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
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
    pub header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk:
        [u8; 2],
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
    pub send_buffer: dynbuf,
    pub stream_id: int32_t,
    pub bodystarted: bool,
    pub header_recvbuf: dynbuf,
    pub nread_header_recvbuf: size_t,
    pub trailer_recvbuf: dynbuf,
    pub status_code: libc::c_int,
    pub pausedata: *const uint8_t,
    pub pauselen: size_t,
    pub close_handled: bool,
    pub push_headers: *mut *mut libc::c_char,
    pub push_headers_used: size_t,
    pub push_headers_alloc: size_t,
    pub error: uint32_t,
    pub closed: bool,
    pub mem: *mut libc::c_char,
    pub len: size_t,
    pub memlen: size_t,
    pub upload_mem: *const uint8_t,
    pub upload_len: size_t,
    pub upload_left: curl_off_t,
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
    pub wakeup_pair: [curl_socket_t; 2],
    pub multiplexing: bool,
    pub recheckstate: bool,
    pub in_callback: bool,
    pub ipv6_works: bool,
}
pub type curl_multi_timer_callback =
    Option<unsafe extern "C" fn(*mut CURLM, libc::c_long, *mut libc::c_void) -> libc::c_int>;
pub type CURLM = Curl_multi;
pub type curl_push_callback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        *mut CURL,
        size_t,
        *mut curl_pushheaders,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type curl_socket_callback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        curl_socket_t,
        libc::c_int,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
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
    pub host: hostname,
    pub hostname_resolve: *mut libc::c_char,
    pub secondaryhostname: *mut libc::c_char,
    pub conn_to_host: hostname,
    pub socks_proxy: proxy_info,
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
    pub recv: [Option<Curl_recv>; 2],
    pub send: [Option<Curl_send>; 2],
    pub ssl: [ssl_connect_data; 2],
    pub proxy_ssl: [ssl_connect_data; 2],
    pub ssl_config: ssl_primary_config,
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
    pub easyq: Curl_llist,
    pub seek_func: curl_seek_callback,
    pub seek_client: *mut libc::c_void,
    pub trailer: dynbuf,
    pub proto: C2RustUnnamed_5,
    pub connect_state: *mut http_connect_state,
    pub bundle: *mut connectbundle,
    pub unix_domain_socket: *mut libc::c_char,
    pub localdev: *mut libc::c_char,
    pub localportrange: libc::c_int,
    pub cselect_bits: libc::c_int,
    pub waitfor: libc::c_int,
    pub negnpn: libc::c_int,
    pub localport: libc::c_ushort,
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
    pub sendauth: Option<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *const libc::c_char,
            *const libc::c_char,
        ) -> CURLcode,
    >,
    pub sendcont: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *const libc::c_char) -> CURLcode,
    >,
    pub getmessage: Option<unsafe extern "C" fn(*mut libc::c_char, *mut *mut libc::c_char) -> ()>,
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
    pub statemachine: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode>,
    pub endofresp: Option<
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
pub struct http_conn {
    pub binsettings: [uint8_t; 80],
    pub binlen: size_t,
    pub trnsfr: *mut Curl_easy,
    pub h2: *mut nghttp2_session,
    pub send_underlying: Option<Curl_send>,
    pub recv_underlying: Option<Curl_recv>,
    pub inbuf: *mut libc::c_char,
    pub inbuflen: size_t,
    pub nread_inbuf: size_t,
    pub pause_stream_id: int32_t,
    pub drain_total: size_t,
    pub settings: h2settings,
    pub local_settings: [nghttp2_settings_entry; 3],
    pub local_settings_num: size_t,
}
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
    pub setup_connection:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode>,
    pub do_it: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub done: Option<unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode>,
    pub do_more: Option<unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_int) -> CURLcode>,
    pub connect_it: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub connecting: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub doing: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub proto_getsock: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> libc::c_int,
    >,
    pub doing_getsock: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> libc::c_int,
    >,
    pub domore_getsock: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> libc::c_int,
    >,
    pub perform_getsock: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> libc::c_int,
    >,
    pub disconnect:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode>,
    pub readwrite: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut ssize_t, *mut bool) -> CURLcode,
    >,
    pub connection_check: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, libc::c_uint) -> libc::c_uint,
    >,
    pub attach: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> ()>,
    pub defport: libc::c_int,
    pub protocol: libc::c_uint,
    pub family: libc::c_uint,
    pub flags: libc::c_uint,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_connect_data {
    pub state: ssl_connection_state,
    pub connecting_state: ssl_connect_state,
    #[bitfield(name = "use_0", ty = "bit", bits = "0..=0")]
    pub use_0: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
unsafe extern "C" fn https_proxy_connect(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_proxy_connect(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    if (*conn).http_proxy.proxytype as libc::c_uint
        == CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    {
        let result: CURLcode = https_proxy_connect(data, sockindex);
        if result as u64 != 0 {
            return result;
        }
        if !(*conn).bits.proxy_ssl_connected[sockindex as usize] {
            return result;
        }
    }
    if ((*conn).bits).tunnel_proxy() as libc::c_int != 0
        && ((*conn).bits).httpproxy() as libc::c_int != 0
    {
        let mut hostname: *const libc::c_char = 0 as *const libc::c_char;
        let mut remote_port: libc::c_int = 0;
        let mut result_0: CURLcode = CURLE_OK;
        if ((*conn).bits).conn_to_host() != 0 {
            hostname = (*conn).conn_to_host.name;
        } else if sockindex == 1 as libc::c_int {
            hostname = (*conn).secondaryhostname;
        } else {
            hostname = (*conn).host.name;
        }
        if sockindex == 1 as libc::c_int {
            remote_port = (*conn).secondary_port as libc::c_int;
        } else if ((*conn).bits).conn_to_port() != 0 {
            remote_port = (*conn).conn_to_port;
        } else {
            remote_port = (*conn).remote_port;
        }
        result_0 = Curl_proxyCONNECT(data, sockindex, hostname, remote_port);
        if CURLE_OK as libc::c_int as libc::c_uint != result_0 as libc::c_uint {
            return result_0;
        }
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
        );
        let ref mut fresh0 = (*data).state.aptr.proxyuserpwd;
        *fresh0 = 0 as *mut libc::c_char;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_complete(mut conn: *mut connectdata) -> bool {
    return ((*conn).connect_state).is_null()
        || (*(*conn).connect_state).tunnel_state as libc::c_uint
            >= TUNNEL_COMPLETE as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_ongoing(mut conn: *mut connectdata) -> bool {
    return !((*conn).connect_state).is_null()
        && (*(*conn).connect_state).tunnel_state as libc::c_uint
            <= TUNNEL_COMPLETE as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_getsock(mut conn: *mut connectdata) -> libc::c_int {
    let mut http: *mut HTTP = 0 as *mut HTTP;
    http = &mut (*(*conn).connect_state).http_proxy;
    if (*http).sending as libc::c_uint == HTTPSEND_REQUEST as libc::c_int as libc::c_uint {
        return (1 as libc::c_int) << 16 as libc::c_int + 0 as libc::c_int;
    }
    return (1 as libc::c_int) << 0 as libc::c_int;
}
unsafe extern "C" fn connect_init(mut data: *mut Curl_easy, mut reinit: bool) -> CURLcode {
    let mut s: *mut http_connect_state = 0 as *mut http_connect_state;
    let mut conn: *mut connectdata = (*data).conn;
    if !reinit {
        let mut result: CURLcode = CURLE_OK;
        result = Curl_get_upload_buffer(data);
        if result as u64 != 0 {
            return result;
        }
        s = Curl_ccalloc.expect("non-null function pointer")(
            1 as libc::c_int as size_t,
            ::std::mem::size_of::<http_connect_state>() as libc::c_ulong,
        ) as *mut http_connect_state;
        if s.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        Curl_infof(
            data,
            b"allocate connect buffer!\0" as *const u8 as *const libc::c_char,
        );
        let ref mut fresh1 = (*conn).connect_state;
        *fresh1 = s;
        Curl_dyn_init(&mut (*s).rcvbuf, 16384 as libc::c_int as size_t);
        let ref mut fresh2 = (*s).prot_save;
        *fresh2 = (*data).req.p.http;
        let ref mut fresh3 = (*data).req.p.http;
        *fresh3 = &mut (*s).http_proxy;
        Curl_conncontrol(conn, 0 as libc::c_int);
    } else {
        s = (*conn).connect_state;
        Curl_dyn_reset(&mut (*s).rcvbuf);
    }
    (*s).tunnel_state = TUNNEL_INIT;
    (*s).keepon = KEEPON_CONNECT;
    (*s).cl = 0 as libc::c_int as curl_off_t;
    (*s).set_close_connection(0 as libc::c_int as bit);
    return CURLE_OK;
}
unsafe extern "C" fn connect_done(mut data: *mut Curl_easy) {
    let mut conn: *mut connectdata = (*data).conn;
    let mut s: *mut http_connect_state = (*conn).connect_state;
    if (*s).tunnel_state as libc::c_uint != TUNNEL_EXIT as libc::c_int as libc::c_uint {
        (*s).tunnel_state = TUNNEL_EXIT;
        Curl_dyn_free(&mut (*s).rcvbuf);
        Curl_dyn_free(&mut (*s).req);
        let ref mut fresh4 = (*data).req.p.http;
        *fresh4 = (*s).prot_save;
        let ref mut fresh5 = (*s).prot_save;
        *fresh5 = 0 as *mut HTTP;
        Curl_infof(
            data,
            b"CONNECT phase completed!\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn CONNECT_host(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut hostname: *const libc::c_char,
    mut remote_port: libc::c_int,
    mut connecthostp: *mut *mut libc::c_char,
    mut hostp: *mut *mut libc::c_char,
) -> CURLcode {
    let mut hostheader: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ipv6_ip: bool = ((*conn).bits).ipv6_ip() != 0;
    if hostname != (*conn).host.name as *const libc::c_char {
        ipv6_ip = !(strchr(hostname, ':' as i32)).is_null();
    }
    hostheader = curl_maprintf(
        b"%s%s%s:%d\0" as *const u8 as *const libc::c_char,
        if ipv6_ip as libc::c_int != 0 {
            b"[\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        hostname,
        if ipv6_ip as libc::c_int != 0 {
            b"]\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        remote_port,
    );
    if hostheader.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if (Curl_checkProxyheaders(data, conn, b"Host\0" as *const u8 as *const libc::c_char)).is_null()
    {
        host = curl_maprintf(
            b"Host: %s\r\n\0" as *const u8 as *const libc::c_char,
            hostheader,
        );
        if host.is_null() {
            Curl_cfree.expect("non-null function pointer")(hostheader as *mut libc::c_void);
            return CURLE_OUT_OF_MEMORY;
        }
    }
    *connecthostp = hostheader;
    *hostp = host;
    return CURLE_OK;
}
unsafe extern "C" fn CONNECT(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut hostname: *const libc::c_char,
    mut remote_port: libc::c_int,
) -> CURLcode {
    let mut subversion: libc::c_int = 0 as libc::c_int;
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut tunnelsocket: curl_socket_t = (*conn).sock[sockindex as usize];
    let mut s: *mut http_connect_state = (*conn).connect_state;
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut linep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut perline: size_t = 0;
    if Curl_connect_complete(conn) {
        return CURLE_OK;
    }
    let ref mut fresh6 = (*conn).bits;
    (*fresh6).set_proxy_connect_closed(0 as libc::c_int as bit);
    loop {
        let mut check: timediff_t = 0;
        if TUNNEL_INIT as libc::c_int as libc::c_uint == (*s).tunnel_state as libc::c_uint {
            let mut req: *mut dynbuf = &mut (*s).req;
            let mut hostheader: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
            Curl_infof(
                data,
                b"Establish HTTP proxy tunnel to %s:%d\0" as *const u8 as *const libc::c_char,
                hostname,
                remote_port,
            );
            Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
            let ref mut fresh7 = (*data).req.newurl;
            *fresh7 = 0 as *mut libc::c_char;
            Curl_dyn_init(req, (1024 as libc::c_int * 1024 as libc::c_int) as size_t);
            result = CONNECT_host(
                data,
                conn,
                hostname,
                remote_port,
                &mut hostheader,
                &mut host,
            );
            if result as u64 != 0 {
                return result;
            }
            result = Curl_http_output_auth(
                data,
                conn,
                b"CONNECT\0" as *const u8 as *const libc::c_char,
                HTTPREQ_GET,
                hostheader,
                1 as libc::c_int != 0,
            );
            if result as u64 == 0 {
                let mut httpv: *const libc::c_char = if (*conn).http_proxy.proxytype as libc::c_uint
                    == CURLPROXY_HTTP_1_0 as libc::c_int as libc::c_uint
                {
                    b"1.0\0" as *const u8 as *const libc::c_char
                } else {
                    b"1.1\0" as *const u8 as *const libc::c_char
                };
                result = Curl_dyn_addf(
                    req,
                    b"CONNECT %s HTTP/%s\r\n%s%s\0" as *const u8 as *const libc::c_char,
                    hostheader,
                    httpv,
                    if !host.is_null() {
                        host as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                    if !((*data).state.aptr.proxyuserpwd).is_null() {
                        (*data).state.aptr.proxyuserpwd as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                );
                if result as u64 == 0
                    && (Curl_checkProxyheaders(
                        data,
                        conn,
                        b"User-Agent\0" as *const u8 as *const libc::c_char,
                    ))
                    .is_null()
                    && !((*data).set.str_0[STRING_USERAGENT as libc::c_int as usize]).is_null()
                {
                    result = Curl_dyn_addf(
                        req,
                        b"User-Agent: %s\r\n\0" as *const u8 as *const libc::c_char,
                        (*data).set.str_0[STRING_USERAGENT as libc::c_int as usize],
                    );
                }
                if result as u64 == 0
                    && (Curl_checkProxyheaders(
                        data,
                        conn,
                        b"Proxy-Connection\0" as *const u8 as *const libc::c_char,
                    ))
                    .is_null()
                {
                    result = Curl_dyn_add(
                        req,
                        b"Proxy-Connection: Keep-Alive\r\n\0" as *const u8 as *const libc::c_char,
                    );
                }
                if result as u64 == 0 {
                    result = Curl_add_custom_headers(data, 1 as libc::c_int != 0, req);
                }
                if result as u64 == 0 {
                    result = Curl_dyn_add(req, b"\r\n\0" as *const u8 as *const libc::c_char);
                }
                if result as u64 == 0 {
                    result = Curl_buffer_send(
                        req,
                        data,
                        &mut (*data).info.request_size,
                        0 as libc::c_int as curl_off_t,
                        sockindex,
                    );
                }
                if result as u64 != 0 {
                    Curl_failf(
                        data,
                        b"Failed sending CONNECT to proxy\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            Curl_cfree.expect("non-null function pointer")(host as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")(hostheader as *mut libc::c_void);
            if result as u64 != 0 {
                return result;
            }
            (*s).tunnel_state = TUNNEL_CONNECT;
        }
        check = Curl_timeleft(data, 0 as *mut curltime, 1 as libc::c_int != 0);
        if check <= 0 as libc::c_int as libc::c_long {
            Curl_failf(
                data,
                b"Proxy CONNECT aborted due to timeout\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OPERATION_TIMEDOUT;
        }
        if !Curl_conn_data_pending(conn, sockindex) && (*http).sending as u64 == 0 {
            return CURLE_OK;
        }
        if (*http).sending as libc::c_uint == HTTPSEND_REQUEST as libc::c_int as libc::c_uint {
            if (*s).nsend == 0 {
                let mut fillcount: size_t = 0;
                let ref mut fresh8 = (*k).upload_fromhere;
                *fresh8 = (*data).state.ulbuf;
                result = Curl_fillreadbuffer(
                    data,
                    (*data).set.upload_buffer_size as size_t,
                    &mut fillcount,
                );
                if result as u64 != 0 {
                    return result;
                }
                (*s).nsend = fillcount;
            }
            if (*s).nsend != 0 {
                let mut bytes_written: ssize_t = 0;
                result = Curl_write(
                    data,
                    (*conn).writesockfd,
                    (*k).upload_fromhere as *const libc::c_void,
                    (*s).nsend,
                    &mut bytes_written,
                );
                if result as u64 == 0 {
                    result = Curl_debug(
                        data,
                        CURLINFO_HEADER_OUT,
                        (*k).upload_fromhere,
                        bytes_written as size_t,
                    ) as CURLcode;
                }
                let ref mut fresh9 = (*s).nsend;
                *fresh9 = (*fresh9 as libc::c_ulong).wrapping_sub(bytes_written as libc::c_ulong)
                    as size_t as size_t;
                let ref mut fresh10 = (*k).upload_fromhere;
                *fresh10 = (*fresh10).offset(bytes_written as isize);
                return result;
            }
            (*http).sending = HTTPSEND_NADA;
        }
        let mut error: libc::c_int = 0 as libc::c_int;
        while (*s).keepon as u64 != 0 {
            let mut gotbytes: ssize_t = 0;
            let mut byte: libc::c_char = 0;
            result = Curl_read(
                data,
                tunnelsocket,
                &mut byte,
                1 as libc::c_int as size_t,
                &mut gotbytes,
            );
            if result as libc::c_uint == CURLE_AGAIN as libc::c_int as libc::c_uint {
                return CURLE_OK;
            }
            if Curl_pgrsUpdate(data) != 0 {
                return CURLE_ABORTED_BY_CALLBACK;
            }
            if result as u64 != 0 {
                (*s).keepon = KEEPON_DONE;
                break;
            } else if gotbytes <= 0 as libc::c_int as libc::c_long {
                if (*data).set.proxyauth != 0
                    && (*data).state.authproxy.avail != 0
                    && !((*data).state.aptr.proxyuserpwd).is_null()
                {
                    let ref mut fresh11 = (*conn).bits;
                    (*fresh11).set_proxy_connect_closed(1 as libc::c_int as bit);
                    Curl_infof(
                        data,
                        b"Proxy CONNECT connection closed\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    error = 1 as libc::c_int;
                    Curl_failf(
                        data,
                        b"Proxy CONNECT aborted\0" as *const u8 as *const libc::c_char,
                    );
                }
                (*s).keepon = KEEPON_DONE;
                break;
            } else if (*s).keepon as libc::c_uint == KEEPON_IGNORE as libc::c_int as libc::c_uint {
                if (*s).cl != 0 {
                    let ref mut fresh12 = (*s).cl;
                    *fresh12 -= 1;
                    if !((*s).cl <= 0 as libc::c_int as libc::c_long) {
                        continue;
                    }
                    (*s).keepon = KEEPON_DONE;
                    (*s).tunnel_state = TUNNEL_COMPLETE;
                    break;
                } else {
                    let mut r: CHUNKcode = CHUNKE_OK;
                    let mut extra: CURLcode = CURLE_OK;
                    let mut tookcareof: ssize_t = 0 as libc::c_int as ssize_t;
                    r = Curl_httpchunk_read(
                        data,
                        &mut byte,
                        1 as libc::c_int as ssize_t,
                        &mut tookcareof,
                        &mut extra,
                    );
                    if r as libc::c_int == CHUNKE_STOP as libc::c_int {
                        Curl_infof(
                            data,
                            b"chunk reading DONE\0" as *const u8 as *const libc::c_char,
                        );
                        (*s).keepon = KEEPON_DONE;
                        (*s).tunnel_state = TUNNEL_COMPLETE;
                    }
                }
            } else {
                if Curl_dyn_addn(
                    &mut (*s).rcvbuf,
                    &mut byte as *mut libc::c_char as *const libc::c_void,
                    1 as libc::c_int as size_t,
                ) as u64
                    != 0
                {
                    Curl_failf(
                        data,
                        b"CONNECT response too large!\0" as *const u8 as *const libc::c_char,
                    );
                    return CURLE_RECV_ERROR;
                }
                if byte as libc::c_int != 0xa as libc::c_int {
                    continue;
                }
                linep = Curl_dyn_ptr(&mut (*s).rcvbuf);
                perline = Curl_dyn_len(&mut (*s).rcvbuf);
                result = CURLE_OK as libc::c_int as CURLcode;
                if result as u64 != 0 {
                    return result;
                }
                Curl_debug(data, CURLINFO_HEADER_IN, linep, perline);
                if ((*data).set).suppress_connect_headers() == 0 {
                    let mut writetype: libc::c_int = (1 as libc::c_int) << 1 as libc::c_int;
                    if ((*data).set).include_header() != 0 {
                        writetype |= (1 as libc::c_int) << 0 as libc::c_int;
                    }
                    result = Curl_client_write(data, writetype, linep, perline);
                    if result as u64 != 0 {
                        return result;
                    }
                }
                let ref mut fresh13 = (*data).info.header_size;
                *fresh13 += perline as libc::c_long;
                if '\r' as i32 == *linep.offset(0 as libc::c_int as isize) as libc::c_int
                    || '\n' as i32 == *linep.offset(0 as libc::c_int as isize) as libc::c_int
                {
                    if 407 as libc::c_int == (*k).httpcode && ((*data).state).authproblem() == 0 {
                        (*s).keepon = KEEPON_IGNORE;
                        if (*s).cl != 0 {
                            Curl_infof(
                                data,
                                b"Ignore %ld bytes of response-body\0" as *const u8
                                    as *const libc::c_char,
                                (*s).cl,
                            );
                        } else if (*s).chunked_encoding() != 0 {
                            let mut r_0: CHUNKcode = CHUNKE_OK;
                            let mut extra_0: CURLcode = CURLE_OK;
                            Curl_infof(
                                data,
                                b"Ignore chunked response-body\0" as *const u8
                                    as *const libc::c_char,
                            );
                            (*k).set_ignorebody(1 as libc::c_int as bit);
                            if *linep.offset(1 as libc::c_int as isize) as libc::c_int
                                == '\n' as i32
                            {
                                linep = linep.offset(1);
                            }
                            r_0 = Curl_httpchunk_read(
                                data,
                                linep.offset(1 as libc::c_int as isize),
                                1 as libc::c_int as ssize_t,
                                &mut gotbytes,
                                &mut extra_0,
                            );
                            if r_0 as libc::c_int == CHUNKE_STOP as libc::c_int {
                                Curl_infof(
                                    data,
                                    b"chunk reading DONE\0" as *const u8 as *const libc::c_char,
                                );
                                (*s).keepon = KEEPON_DONE;
                                (*s).tunnel_state = TUNNEL_COMPLETE;
                            }
                        } else {
                            (*s).keepon = KEEPON_DONE;
                        }
                    } else {
                        (*s).keepon = KEEPON_DONE;
                    }
                    if (*s).keepon as libc::c_uint == KEEPON_DONE as libc::c_int as libc::c_uint
                        && (*s).cl == 0
                    {
                        (*s).tunnel_state = TUNNEL_COMPLETE;
                    }
                } else {
                    if curl_strnequal(
                        b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char,
                        linep,
                        strlen(b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char),
                    ) != 0
                        && 401 as libc::c_int == (*k).httpcode
                        || curl_strnequal(
                            b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char,
                            linep,
                            strlen(b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char),
                        ) != 0
                            && 407 as libc::c_int == (*k).httpcode
                    {
                        let mut proxy: bool = if (*k).httpcode == 407 as libc::c_int {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        } != 0;
                        let mut auth: *mut libc::c_char = Curl_copy_header_value(linep);
                        if auth.is_null() {
                            return CURLE_OUT_OF_MEMORY;
                        }
                        result = Curl_http_input_auth(data, proxy, auth);
                        Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
                        if result as u64 != 0 {
                            return result;
                        }
                    } else if curl_strnequal(
                        b"Content-Length:\0" as *const u8 as *const libc::c_char,
                        linep,
                        strlen(b"Content-Length:\0" as *const u8 as *const libc::c_char),
                    ) != 0
                    {
                        if (*k).httpcode / 100 as libc::c_int == 2 as libc::c_int {
                            Curl_infof(
                                data,
                                b"Ignoring Content-Length in CONNECT %03d response\0" as *const u8
                                    as *const libc::c_char,
                                (*k).httpcode,
                            );
                        } else {
                            curlx_strtoofft(
                                linep.offset(strlen(
                                    b"Content-Length:\0" as *const u8 as *const libc::c_char,
                                ) as isize),
                                0 as *mut *mut libc::c_char,
                                10 as libc::c_int,
                                &mut (*s).cl,
                            );
                        }
                    } else if Curl_compareheader(
                        linep,
                        b"Connection:\0" as *const u8 as *const libc::c_char,
                        b"close\0" as *const u8 as *const libc::c_char,
                    ) {
                        (*s).set_close_connection(1 as libc::c_int as bit);
                    } else if curl_strnequal(
                        b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
                        linep,
                        strlen(b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char),
                    ) != 0
                    {
                        if (*k).httpcode / 100 as libc::c_int == 2 as libc::c_int {
                            Curl_infof(
                                data,
                                b"Ignoring Transfer-Encoding in CONNECT %03d response\0"
                                    as *const u8
                                    as *const libc::c_char,
                                (*k).httpcode,
                            );
                        } else if Curl_compareheader(
                            linep,
                            b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
                            b"chunked\0" as *const u8 as *const libc::c_char,
                        ) {
                            Curl_infof(
                                data,
                                b"CONNECT responded chunked\0" as *const u8 as *const libc::c_char,
                            );
                            (*s).set_chunked_encoding(1 as libc::c_int as bit);
                            Curl_httpchunk_init(data);
                        }
                    } else if Curl_compareheader(
                        linep,
                        b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
                        b"close\0" as *const u8 as *const libc::c_char,
                    ) {
                        (*s).set_close_connection(1 as libc::c_int as bit);
                    } else if 2 as libc::c_int
                        == sscanf(
                            linep,
                            b"HTTP/1.%d %d\0" as *const u8 as *const libc::c_char,
                            &mut subversion as *mut libc::c_int,
                            &mut (*k).httpcode as *mut libc::c_int,
                        )
                    {
                        (*data).info.httpproxycode = (*k).httpcode;
                    }
                    Curl_dyn_reset(&mut (*s).rcvbuf);
                }
            }
        }
        if Curl_pgrsUpdate(data) != 0 {
            return CURLE_ABORTED_BY_CALLBACK;
        }
        if error != 0 {
            return CURLE_RECV_ERROR;
        }
        if (*data).info.httpproxycode / 100 as libc::c_int != 2 as libc::c_int {
            result = Curl_http_auth_act(data);
            if result as u64 != 0 {
                return result;
            }
            if ((*conn).bits).close() != 0 {
                (*s).set_close_connection(1 as libc::c_int as bit);
            }
        }
        if (*s).close_connection() as libc::c_int != 0 && !((*data).req.newurl).is_null() {
            Curl_closesocket(data, conn, (*conn).sock[sockindex as usize]);
            (*conn).sock[sockindex as usize] = -(1 as libc::c_int);
            break;
        } else {
            if !((*data).req.newurl).is_null()
                && TUNNEL_COMPLETE as libc::c_int as libc::c_uint
                    == (*s).tunnel_state as libc::c_uint
            {
                connect_init(data, 1 as libc::c_int != 0);
            }
            if ((*data).req.newurl).is_null() {
                break;
            }
        }
    }
    if (*data).info.httpproxycode / 100 as libc::c_int != 2 as libc::c_int {
        if (*s).close_connection() as libc::c_int != 0 && !((*data).req.newurl).is_null() {
            let ref mut fresh14 = (*conn).bits;
            (*fresh14).set_proxy_connect_closed(1 as libc::c_int as bit);
            Curl_infof(
                data,
                b"Connect me again please\0" as *const u8 as *const libc::c_char,
            );
            connect_done(data);
        } else {
            Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
            let ref mut fresh15 = (*data).req.newurl;
            *fresh15 = 0 as *mut libc::c_char;
            Curl_conncontrol(conn, 2 as libc::c_int);
            Curl_closesocket(data, conn, (*conn).sock[sockindex as usize]);
            (*conn).sock[sockindex as usize] = -(1 as libc::c_int);
        }
        (*s).tunnel_state = TUNNEL_INIT;
        if ((*conn).bits).proxy_connect_closed() != 0 {
            return CURLE_OK;
        }
        Curl_dyn_free(&mut (*s).rcvbuf);
        Curl_failf(
            data,
            b"Received HTTP code %d from proxy after CONNECT\0" as *const u8 as *const libc::c_char,
            (*data).req.httpcode,
        );
        return CURLE_RECV_ERROR;
    }
    (*s).tunnel_state = TUNNEL_COMPLETE;
    Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
    );
    let ref mut fresh16 = (*data).state.aptr.proxyuserpwd;
    *fresh16 = 0 as *mut libc::c_char;
    let ref mut fresh17 = (*data).state.aptr.proxyuserpwd;
    *fresh17 = 0 as *mut libc::c_char;
    let ref mut fresh18 = (*data).state.authproxy;
    (*fresh18).set_done(1 as libc::c_int as bit);
    let ref mut fresh19 = (*data).state.authproxy;
    (*fresh19).set_multipass(0 as libc::c_int as bit);
    Curl_infof(
        data,
        b"Proxy replied %d to CONNECT request\0" as *const u8 as *const libc::c_char,
        (*data).info.httpproxycode,
    );
    let ref mut fresh20 = (*data).req;
    (*fresh20).set_ignorebody(0 as libc::c_int as bit);
    let ref mut fresh21 = (*conn).bits;
    (*fresh21).set_rewindaftersend(0 as libc::c_int as bit);
    Curl_dyn_free(&mut (*s).rcvbuf);
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_free(mut data: *mut Curl_easy) {
    let mut conn: *mut connectdata = (*data).conn;
    let mut s: *mut http_connect_state = (*conn).connect_state;
    if !s.is_null() {
        Curl_cfree.expect("non-null function pointer")(s as *mut libc::c_void);
        let ref mut fresh22 = (*conn).connect_state;
        *fresh22 = 0 as *mut http_connect_state;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_proxyCONNECT(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut hostname: *const libc::c_char,
    mut remote_port: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if ((*conn).connect_state).is_null() {
        result = connect_init(data, 0 as libc::c_int != 0);
        if result as u64 != 0 {
            return result;
        }
    }
    result = CONNECT(data, sockindex, hostname, remote_port);
    if result as libc::c_uint != 0 || Curl_connect_complete(conn) as libc::c_int != 0 {
        connect_done(data);
    }
    return result;
}
