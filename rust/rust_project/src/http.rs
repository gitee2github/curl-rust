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
    // pub type TELNET;
    // pub type smb_request;
    // pub type ldapreqinfo;
    // pub type curl_pushheaders;
    // pub type ldapconninfo;
    // pub type tftp_state_data;
    // pub type nghttp2_session;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn time(__timer: *mut time_t) -> time_t;
    fn Curl_isdigit(c: libc::c_int) -> libc::c_int;
    fn Curl_isspace(c: libc::c_int) -> libc::c_int;
    fn curl_strnequal(s1: *const libc::c_char, s2: *const libc::c_char, n: size_t) -> libc::c_int;
    fn curl_mime_headers(
        part: *mut curl_mimepart,
        headers: *mut curl_slist,
        take_ownership: libc::c_int,
    ) -> CURLcode;
    fn curl_url_cleanup(handle: *mut CURLU);
    fn curl_url_dup(in_0: *mut CURLU) -> *mut CURLU;
    fn curl_url_get(
        handle: *mut CURLU,
        what: CURLUPart,
        part: *mut *mut libc::c_char,
        flags: libc::c_uint,
    ) -> CURLUcode;
    fn curl_url_set(
        handle: *mut CURLU,
        what: CURLUPart,
        part: *const libc::c_char,
        flags: libc::c_uint,
    ) -> CURLUcode;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
        -> *mut libc::c_void;
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strstr(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn Curl_dyn_free(s: *mut dynbuf);
    fn Curl_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    fn Curl_dyn_add(s: *mut dynbuf, str: *const libc::c_char) -> CURLcode;
    fn Curl_dyn_addf(s: *mut dynbuf, fmt: *const libc::c_char, _: ...) -> CURLcode;
    fn Curl_dyn_reset(s: *mut dynbuf);
    fn Curl_dyn_ptr(s: *const dynbuf) -> *mut libc::c_char;
    fn Curl_dyn_len(s: *const dynbuf) -> size_t;
    fn Curl_mime_initpart(part: *mut curl_mimepart, easy: *mut Curl_easy);
    fn Curl_mime_cleanpart(part: *mut curl_mimepart);
    fn Curl_mime_prepare_headers(
        part: *mut curl_mimepart,
        contenttype: *const libc::c_char,
        disposition: *const libc::c_char,
        strategy: mimestrategy,
    ) -> CURLcode;
    fn Curl_mime_size(part: *mut curl_mimepart) -> curl_off_t;
    fn Curl_mime_read(
        buffer: *mut libc::c_char,
        size: size_t,
        nitems: size_t,
        instream: *mut libc::c_void,
    ) -> size_t;
    fn Curl_mime_rewind(part: *mut curl_mimepart) -> CURLcode;
    fn Curl_getformdata(
        data: *mut Curl_easy,
        _: *mut curl_mimepart,
        post: *mut curl_httppost,
        fread_func: curl_read_callback,
    ) -> CURLcode;
    fn Curl_rtsp_parseheader(data: *mut Curl_easy, header: *mut libc::c_char) -> CURLcode;
    fn Curl_cookie_freelist(cookies: *mut Cookie);
    fn Curl_cookie_getlist(
        c: *mut CookieInfo,
        host: *const libc::c_char,
        path: *const libc::c_char,
        secure: bool,
    ) -> *mut Cookie;
    fn Curl_cookie_add(
        data: *mut Curl_easy,
        c: *mut CookieInfo,
        header: bool,
        noexpiry: bool,
        lineptr: *mut libc::c_char,
        domain: *const libc::c_char,
        path: *const libc::c_char,
        secure: bool,
    ) -> *mut Cookie;
    fn Curl_checkheaders(
        data: *const Curl_easy,
        thisheader: *const libc::c_char,
    ) -> *mut libc::c_char;
    fn Curl_readrewind(data: *mut Curl_easy) -> CURLcode;
    fn Curl_meets_timecondition(data: *mut Curl_easy, timeofdoc: time_t) -> bool;
    fn Curl_get_upload_buffer(data: *mut Curl_easy) -> CURLcode;
    fn Curl_done_sending(data: *mut Curl_easy, k: *mut SingleRequest) -> CURLcode;
    fn Curl_setup_transfer(
        data: *mut Curl_easy,
        sockindex: libc::c_int,
        size: curl_off_t,
        getheader: bool,
        writesockindex: libc::c_int,
    );
    fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_failf(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_client_write(
        data: *mut Curl_easy,
        type_0: libc::c_int,
        ptr: *mut libc::c_char,
        len: size_t,
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
    fn Curl_pgrsSetDownloadSize(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetUploadSize(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetUploadCounter(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsUpdate(data: *mut Curl_easy) -> libc::c_int;
    fn Curl_base64_encode(
        data: *mut Curl_easy,
        inputbuff: *const libc::c_char,
        insize: size_t,
        outptr: *mut *mut libc::c_char,
        outlen: *mut size_t,
    ) -> CURLcode;
    fn Curl_auth_is_digest_supported() -> bool;
    fn Curl_input_digest(
        data: *mut Curl_easy,
        proxy: bool,
        header: *const libc::c_char,
    ) -> CURLcode;
    fn Curl_output_digest(
        data: *mut Curl_easy,
        proxy: bool,
        request: *const libc::c_uchar,
        uripath: *const libc::c_uchar,
    ) -> CURLcode;
    fn Curl_output_aws_sigv4(data: *mut Curl_easy, proxy: bool) -> CURLcode;
    fn Curl_share_lock(_: *mut Curl_easy, _: curl_lock_data, _: curl_lock_access) -> CURLSHcode;
    fn Curl_share_unlock(_: *mut Curl_easy, _: curl_lock_data) -> CURLSHcode;
    static Curl_wkday: [*const libc::c_char; 7];
    static Curl_month: [*const libc::c_char; 12];
    fn Curl_gmtime(intime: time_t, store: *mut tm) -> CURLcode;
    fn Curl_getdate_capped(p: *const libc::c_char) -> time_t;
    fn curlx_strtoofft(
        str: *const libc::c_char,
        endp: *mut *mut libc::c_char,
        base: libc::c_int,
        num: *mut curl_off_t,
    ) -> CURLofft;
    fn Curl_expire_done(data: *mut Curl_easy, id: expire_id);
    fn Curl_set_in_callback(data: *mut Curl_easy, value: bool);
    fn Curl_strcasecompare(first: *const libc::c_char, second: *const libc::c_char) -> libc::c_int;
    fn Curl_strncasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
        max: size_t,
    ) -> libc::c_int;
    fn Curl_raw_toupper(in_0: libc::c_char) -> libc::c_char;
    fn Curl_build_unencoding_stack(
        data: *mut Curl_easy,
        enclist: *const libc::c_char,
        maybechunked: libc::c_int,
    ) -> CURLcode;
    fn Curl_unencode_cleanup(data: *mut Curl_easy);
    fn Curl_proxy_connect(data: *mut Curl_easy, sockindex: libc::c_int) -> CURLcode;
    fn Curl_connect_ongoing(conn: *mut connectdata) -> bool;
    fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    fn curlx_uitous(uinum: libc::c_uint) -> libc::c_ushort;
    fn Curl_http2_request_upgrade(req: *mut dynbuf, data: *mut Curl_easy) -> CURLcode;
    fn Curl_http2_setup(data: *mut Curl_easy, conn: *mut connectdata) -> CURLcode;
    fn Curl_http2_switched(
        data: *mut Curl_easy,
        ptr: *const libc::c_char,
        nread: size_t,
    ) -> CURLcode;
    fn Curl_http2_setup_conn(conn: *mut connectdata);
    fn Curl_http2_setup_req(data: *mut Curl_easy);
    fn Curl_http2_done(data: *mut Curl_easy, premature: bool);
    fn Curl_conncontrol(conn: *mut connectdata, closeit: libc::c_int);
    fn Curl_altsvc_parse(
        data: *mut Curl_easy,
        altsvc: *mut altsvcinfo,
        value: *const libc::c_char,
        srcalpn: alpnid,
        srchost: *const libc::c_char,
        srcport: libc::c_ushort,
    ) -> CURLcode;
    fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
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
    pub init_writer: Option<unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> CURLcode>,
    pub unencode_write: Option<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut contenc_writer,
            *const libc::c_char,
            size_t,
        ) -> CURLcode,
    >,
    pub close_writer: Option<unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> ()>,
    pub paramsize: size_t,
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
    pub cookies: *mut CookieInfo,
    pub sslsession: *mut Curl_ssl_session,
    pub max_ssl_sessions: size_t,
    pub sessionage: libc::c_long,
}
pub type curl_unlock_function =
    Option<unsafe extern "C" fn(*mut CURL, curl_lock_data, *mut libc::c_void) -> ()>;
pub type curl_lock_function = Option<
    unsafe extern "C" fn(*mut CURL, curl_lock_data, curl_lock_access, *mut libc::c_void) -> (),
>;
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
#[no_mangle]
pub static mut Curl_handler_http: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTP\0" as *const u8 as *const libc::c_char,
            setup_connection: Some(
                http_setup_conn
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
            done: Some(
                Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                Curl_http_connect as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: None,
            doing: None,
            proto_getsock: None,
            doing_getsock: Some(
                http_getsock_do
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: None,
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 80 as libc::c_int,
            protocol: ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint,
            family: ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint,
            flags: ((1 as libc::c_int) << 7 as libc::c_int
                | (1 as libc::c_int) << 13 as libc::c_int) as libc::c_uint,
        };
        init
    }
};
unsafe extern "C" fn http_setup_conn(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut http: *mut HTTP = 0 as *mut HTTP;
    http = Curl_ccalloc.expect("non-null function pointer")(
        1 as libc::c_int as size_t,
        ::std::mem::size_of::<HTTP>() as libc::c_ulong,
    ) as *mut HTTP;
    if http.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_mime_initpart(&mut (*http).form, data);
    let ref mut fresh0 = (*data).req.p.http;
    *fresh0 = http;
    if (*data).state.httpwant as libc::c_int == CURL_HTTP_VERSION_3 as libc::c_int {
        if (*(*conn).handler).flags & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
        {
            (*conn).transport = TRNSPRT_QUIC;
        } else {
            Curl_failf(
                data,
                b"HTTP/3 requested for non-HTTPS URL\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_URL_MALFORMAT;
        }
    } else {
        if (*conn).easyq.size == 0 {
            Curl_http2_setup_conn(conn);
        }
        Curl_http2_setup_req(data);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_checkProxyheaders(
    mut data: *mut Curl_easy,
    mut conn: *const connectdata,
    mut thisheader: *const libc::c_char,
) -> *mut libc::c_char {
    let mut head: *mut curl_slist = 0 as *mut curl_slist;
    let mut thislen: size_t = strlen(thisheader);
    head = if ((*conn).bits).proxy() as libc::c_int != 0
        && ((*data).set).sep_headers() as libc::c_int != 0
    {
        (*data).set.proxyheaders
    } else {
        (*data).set.headers
    };
    while !head.is_null() {
        if Curl_strncasecompare((*head).data, thisheader, thislen) != 0
            && (*((*head).data).offset(thislen as isize) as libc::c_int == ':' as i32
                || *((*head).data).offset(thislen as isize) as libc::c_int == ';' as i32)
        {
            return (*head).data;
        }
        head = (*head).next;
    }
    return 0 as *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_copy_header_value(
    mut header: *const libc::c_char,
) -> *mut libc::c_char {
    let mut start: *const libc::c_char = 0 as *const libc::c_char;
    let mut end: *const libc::c_char = 0 as *const libc::c_char;
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    while *header as libc::c_int != 0 && *header as libc::c_int != ':' as i32 {
        header = header.offset(1);
    }
    if *header != 0 {
        header = header.offset(1);
    }
    start = header;
    while *start as libc::c_int != 0 && Curl_isspace(*start as libc::c_uchar as libc::c_int) != 0 {
        start = start.offset(1);
    }
    end = strchr(start, '\r' as i32);
    if end.is_null() {
        end = strchr(start, '\n' as i32);
    }
    if end.is_null() {
        end = strchr(start, '\0' as i32);
    }
    if end.is_null() {
        return 0 as *mut libc::c_char;
    }
    while end > start && Curl_isspace(*end as libc::c_uchar as libc::c_int) != 0 {
        end = end.offset(-1);
    }
    len = (end.offset_from(start) as libc::c_long + 1 as libc::c_int as libc::c_long) as size_t;
    value = Curl_cmalloc.expect("non-null function pointer")(
        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) as *mut libc::c_char;
    if value.is_null() {
        return 0 as *mut libc::c_char;
    }
    memcpy(
        value as *mut libc::c_void,
        start as *const libc::c_void,
        len,
    );
    *value.offset(len as isize) = 0 as libc::c_int as libc::c_char;
    return value;
}
unsafe extern "C" fn http_output_basic(mut data: *mut Curl_easy, mut proxy: bool) -> CURLcode {
    let mut size: size_t = 0 as libc::c_int as size_t;
    let mut authorization: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut userp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut user: *const libc::c_char = 0 as *const libc::c_char;
    let mut pwd: *const libc::c_char = 0 as *const libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    if proxy {
        userp = &mut (*data).state.aptr.proxyuserpwd;
        user = (*data).state.aptr.proxyuser;
        pwd = (*data).state.aptr.proxypasswd;
    } else {
        userp = &mut (*data).state.aptr.userpwd;
        user = (*data).state.aptr.user;
        pwd = (*data).state.aptr.passwd;
    }
    out = curl_maprintf(
        b"%s:%s\0" as *const u8 as *const libc::c_char,
        user,
        if !pwd.is_null() {
            pwd
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    if out.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_base64_encode(data, out, strlen(out), &mut authorization, &mut size);
    if !(result as u64 != 0) {
        if authorization.is_null() {
            result = CURLE_REMOTE_ACCESS_DENIED;
        } else {
            Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
            *userp = curl_maprintf(
                b"%sAuthorization: Basic %s\r\n\0" as *const u8 as *const libc::c_char,
                if proxy as libc::c_int != 0 {
                    b"Proxy-\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                authorization,
            );
            Curl_cfree.expect("non-null function pointer")(authorization as *mut libc::c_void);
            if (*userp).is_null() {
                result = CURLE_OUT_OF_MEMORY;
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void);
    return result;
}
unsafe extern "C" fn http_output_bearer(mut data: *mut Curl_easy) -> CURLcode {
    let mut userp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    userp = &mut (*data).state.aptr.userpwd;
    Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
    *userp = curl_maprintf(
        b"Authorization: Bearer %s\r\n\0" as *const u8 as *const libc::c_char,
        (*data).set.str_0[STRING_BEARER as libc::c_int as usize],
    );
    if (*userp).is_null() {
        result = CURLE_OUT_OF_MEMORY;
    }
    return result;
}
unsafe extern "C" fn pickoneauth(mut pick: *mut auth, mut mask: libc::c_ulong) -> bool {
    let mut picked: bool = false;
    let mut avail: libc::c_ulong = (*pick).avail & (*pick).want & mask;
    picked = 1 as libc::c_int != 0;
    if avail & (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 7 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 7 as libc::c_int;
    } else {
        (*pick).picked = ((1 as libc::c_int) << 30 as libc::c_int) as libc::c_ulong;
        picked = 0 as libc::c_int != 0;
    }
    (*pick).avail = 0 as libc::c_int as libc::c_ulong;
    return picked;
}
unsafe extern "C" fn http_perhapsrewind(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut bytessent: curl_off_t = 0;
    let mut expectsend: curl_off_t = -(1 as libc::c_int) as curl_off_t;
    if http.is_null() {
        return CURLE_OK;
    }
    match (*data).state.httpreq as libc::c_uint {
        0 | 5 => return CURLE_OK,
        _ => {}
    }
    bytessent = (*data).req.writebytecount;
    // 解决clippy错误
    if ((*conn).bits).authneg() != 0 || ((*conn).bits).protoconnstart() == 0 {
        expectsend = 0 as libc::c_int as curl_off_t;
    // } else if ((*conn).bits).protoconnstart() == 0 {
    //     expectsend = 0 as libc::c_int as curl_off_t;
    } else {
        match (*data).state.httpreq as libc::c_uint {
            1 | 4 => {
                if (*data).state.infilesize != -(1 as libc::c_int) as libc::c_long {
                    expectsend = (*data).state.infilesize;
                }
            }
            2 | 3 => {
                expectsend = (*http).postsize;
            }
            _ => {}
        }
    }
    let ref mut fresh1 = (*conn).bits;
    (*fresh1).set_rewindaftersend(0 as libc::c_int as bit);
    if expectsend == -(1 as libc::c_int) as libc::c_long || expectsend > bytessent {
        Curl_conncontrol(conn, 2 as libc::c_int);
        (*data).req.size = 0 as libc::c_int as curl_off_t;
    }
    if bytessent != 0 {
        return Curl_readrewind(data);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_auth_act(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut pickhost: bool = 0 as libc::c_int != 0;
    let mut pickproxy: bool = 0 as libc::c_int != 0;
    let mut result: CURLcode = CURLE_OK;
    let mut authmask: libc::c_ulong = !(0 as libc::c_ulong);
    if ((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null() {
        authmask &= !((1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int);
    }
    if 100 as libc::c_int <= (*data).req.httpcode && 199 as libc::c_int >= (*data).req.httpcode {
        return CURLE_OK;
    }
    if ((*data).state).authproblem() != 0 {
        return (if ((*data).set).http_fail_on_error() as libc::c_int != 0 {
            CURLE_HTTP_RETURNED_ERROR as libc::c_int
        } else {
            CURLE_OK as libc::c_int
        }) as CURLcode;
    }
    if (((*conn).bits).user_passwd() as libc::c_int != 0
        || !((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null())
        && ((*data).req.httpcode == 401 as libc::c_int
            || ((*conn).bits).authneg() as libc::c_int != 0
                && (*data).req.httpcode < 300 as libc::c_int)
    {
        pickhost = pickoneauth(&mut (*data).state.authhost, authmask);
        if !pickhost {
            let ref mut fresh2 = (*data).state;
            (*fresh2).set_authproblem(1 as libc::c_int as bit);
        }
        if (*data).state.authhost.picked == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
            && (*conn).httpversion as libc::c_int > 11 as libc::c_int
        {
            Curl_infof(
                data,
                b"Forcing HTTP/1.1 for NTLM\0" as *const u8 as *const libc::c_char,
            );
            Curl_conncontrol(conn, 1 as libc::c_int);
            (*data).state.httpwant = CURL_HTTP_VERSION_1_1 as libc::c_int as libc::c_uchar;
        }
    }
    if ((*conn).bits).proxy_user_passwd() as libc::c_int != 0
        && ((*data).req.httpcode == 407 as libc::c_int
            || ((*conn).bits).authneg() as libc::c_int != 0
                && (*data).req.httpcode < 300 as libc::c_int)
    {
        pickproxy = pickoneauth(
            &mut (*data).state.authproxy,
            authmask & !((1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int),
        );
        if !pickproxy {
            let ref mut fresh3 = (*data).state;
            (*fresh3).set_authproblem(1 as libc::c_int as bit);
        }
    }
    if pickhost as libc::c_int != 0 || pickproxy as libc::c_int != 0 {
        if (*data).state.httpreq as libc::c_uint != HTTPREQ_GET as libc::c_int as libc::c_uint
            && (*data).state.httpreq as libc::c_uint != HTTPREQ_HEAD as libc::c_int as libc::c_uint
            && ((*conn).bits).rewindaftersend() == 0
        {
            result = http_perhapsrewind(data, conn);
            if result as u64 != 0 {
                return result;
            }
        }
        Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
        let ref mut fresh4 = (*data).req.newurl;
        *fresh4 = 0 as *mut libc::c_char;
        let ref mut fresh5 = (*data).req.newurl;
        *fresh5 = Curl_cstrdup.expect("non-null function pointer")((*data).state.url);
        if ((*data).req.newurl).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else if (*data).req.httpcode < 300 as libc::c_int
        && ((*data).state.authhost).done() == 0
        && ((*conn).bits).authneg() as libc::c_int != 0
    {
        if (*data).state.httpreq as libc::c_uint != HTTPREQ_GET as libc::c_int as libc::c_uint
            && (*data).state.httpreq as libc::c_uint != HTTPREQ_HEAD as libc::c_int as libc::c_uint
        {
            let ref mut fresh6 = (*data).req.newurl;
            *fresh6 = Curl_cstrdup.expect("non-null function pointer")((*data).state.url);
            if ((*data).req.newurl).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let ref mut fresh7 = (*data).state.authhost;
            (*fresh7).set_done(1 as libc::c_int as bit);
        }
    }
    if http_should_fail(data) {
        Curl_failf(
            data,
            b"The requested URL returned error: %d\0" as *const u8 as *const libc::c_char,
            (*data).req.httpcode,
        );
        result = CURLE_HTTP_RETURNED_ERROR;
    }
    return result;
}
unsafe extern "C" fn output_auth_headers(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut authstatus: *mut auth,
    mut request: *const libc::c_char,
    mut path: *const libc::c_char,
    mut proxy: bool,
) -> CURLcode {
    let mut auth: *const libc::c_char = 0 as *const libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    if (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 7 as libc::c_int {
        auth = b"AWS_SIGV4\0" as *const u8 as *const libc::c_char;
        result = Curl_output_aws_sigv4(data, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int {
        auth = b"Digest\0" as *const u8 as *const libc::c_char;
        result = Curl_output_digest(
            data,
            proxy,
            request as *const libc::c_uchar,
            path as *const libc::c_uchar,
        );
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int {
        if proxy as libc::c_int != 0
            && ((*conn).bits).proxy_user_passwd() as libc::c_int != 0
            && (Curl_checkProxyheaders(
                data,
                conn,
                b"Proxy-authorization\0" as *const u8 as *const libc::c_char,
            ))
            .is_null()
            || !proxy
                && ((*conn).bits).user_passwd() as libc::c_int != 0
                && (Curl_checkheaders(data, b"Authorization\0" as *const u8 as *const libc::c_char))
                    .is_null()
        {
            auth = b"Basic\0" as *const u8 as *const libc::c_char;
            result = http_output_basic(data, proxy);
            if result as u64 != 0 {
                return result;
            }
        }
        (*authstatus).set_done(1 as libc::c_int as bit);
    }
    if (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int {
        if !proxy
            && !((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null()
            && (Curl_checkheaders(data, b"Authorization\0" as *const u8 as *const libc::c_char))
                .is_null()
        {
            auth = b"Bearer\0" as *const u8 as *const libc::c_char;
            result = http_output_bearer(data);
            if result as u64 != 0 {
                return result;
            }
        }
        (*authstatus).set_done(1 as libc::c_int as bit);
    }
    if !auth.is_null() {
        Curl_infof(
            data,
            b"%s auth using %s with user '%s'\0" as *const u8 as *const libc::c_char,
            if proxy as libc::c_int != 0 {
                b"Proxy\0" as *const u8 as *const libc::c_char
            } else {
                b"Server\0" as *const u8 as *const libc::c_char
            },
            auth,
            if proxy as libc::c_int != 0 {
                if !((*data).state.aptr.proxyuser).is_null() {
                    (*data).state.aptr.proxyuser as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                }
            } else if !((*data).state.aptr.user).is_null() {
                (*data).state.aptr.user as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        (*authstatus).set_multipass(
            (if (*authstatus).done() == 0 {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }) as bit,
        );
    } else {
        (*authstatus).set_multipass(0 as libc::c_int as bit);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_output_auth(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut request: *const libc::c_char,
    mut httpreq: Curl_HttpReq,
    mut path: *const libc::c_char,
    mut proxytunnel: bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut authhost: *mut auth = 0 as *mut auth;
    let mut authproxy: *mut auth = 0 as *mut auth;
    authhost = &mut (*data).state.authhost;
    authproxy = &mut (*data).state.authproxy;
    if ((*conn).bits).httpproxy() as libc::c_int != 0
        && ((*conn).bits).proxy_user_passwd() as libc::c_int != 0
        || ((*conn).bits).user_passwd() as libc::c_int != 0
        || !((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null()
    {
    } else {
        (*authhost).set_done(1 as libc::c_int as bit);
        (*authproxy).set_done(1 as libc::c_int as bit);
        return CURLE_OK;
    }
    if (*authhost).want != 0 && (*authhost).picked == 0 {
        (*authhost).picked = (*authhost).want;
    }
    if (*authproxy).want != 0 && (*authproxy).picked == 0 {
        (*authproxy).picked = (*authproxy).want;
    }
    if ((*conn).bits).httpproxy() as libc::c_int != 0
        && ((*conn).bits).tunnel_proxy() == proxytunnel as bit
    {
        result = output_auth_headers(data, conn, authproxy, request, path, 1 as libc::c_int != 0);
        if result as u64 != 0 {
            return result;
        }
    } else {
        (*authproxy).set_done(1 as libc::c_int as bit);
    }
    if ((*data).state).this_is_a_follow() == 0
        || ((*conn).bits).netrc() as libc::c_int != 0
        || ((*data).state.first_host).is_null()
        || ((*data).set).allow_auth_to_other_hosts() as libc::c_int != 0
        || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0
    {
        result = output_auth_headers(data, conn, authhost, request, path, 0 as libc::c_int != 0);
    } else {
        (*authhost).set_done(1 as libc::c_int as bit);
    }
    if ((*authhost).multipass() as libc::c_int != 0 && (*authhost).done() == 0
        || (*authproxy).multipass() as libc::c_int != 0 && (*authproxy).done() == 0)
        && httpreq as libc::c_uint != HTTPREQ_GET as libc::c_int as libc::c_uint
        && httpreq as libc::c_uint != HTTPREQ_HEAD as libc::c_int as libc::c_uint
    {
        let ref mut fresh8 = (*conn).bits;
        (*fresh8).set_authneg(1 as libc::c_int as bit);
    } else {
        let ref mut fresh9 = (*conn).bits;
        (*fresh9).set_authneg(0 as libc::c_int as bit);
    }
    return result;
}
unsafe extern "C" fn is_valid_auth_separator(mut ch: libc::c_char) -> libc::c_int {
    return (ch as libc::c_int == '\0' as i32
        || ch as libc::c_int == ',' as i32
        || Curl_isspace(ch as libc::c_uchar as libc::c_int) != 0) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_input_auth(
    mut data: *mut Curl_easy,
    mut proxy: bool,
    mut auth: *const libc::c_char,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut availp: *mut libc::c_ulong = 0 as *mut libc::c_ulong;
    let mut authp: *mut auth = 0 as *mut auth;
    if proxy {
        availp = &mut (*data).info.proxyauthavail;
        authp = &mut (*data).state.authproxy;
    } else {
        availp = &mut (*data).info.httpauthavail;
        authp = &mut (*data).state.authhost;
    }
    while *auth != 0 {
        if curl_strnequal(
            b"Digest\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"Digest\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(6 as libc::c_int as isize)) != 0
        {
            if (*authp).avail & (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int
                != 0 as libc::c_int as libc::c_ulong
            {
                Curl_infof(
                    data,
                    b"Ignoring duplicate digest auth header.\0" as *const u8 as *const libc::c_char,
                );
            } else if Curl_auth_is_digest_supported() {
                let mut result: CURLcode = CURLE_OK;
                *availp |= (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int;
                (*authp).avail |= (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int;
                result = Curl_input_digest(data, proxy, auth);
                if result as u64 != 0 {
                    Curl_infof(
                        data,
                        b"Authentication problem. Ignoring this.\0" as *const u8
                            as *const libc::c_char,
                    );
                    let ref mut fresh10 = (*data).state;
                    (*fresh10).set_authproblem(1 as libc::c_int as bit);
                }
            }
        } else if curl_strnequal(
            b"Basic\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"Basic\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(5 as libc::c_int as isize)) != 0
        {
            *availp |= (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
            (*authp).avail |= (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
            if (*authp).picked == (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int {
                (*authp).avail = 0 as libc::c_int as libc::c_ulong;
                Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8 as *const libc::c_char,
                );
                let ref mut fresh11 = (*data).state;
                (*fresh11).set_authproblem(1 as libc::c_int as bit);
            }
        } else if curl_strnequal(
            b"Bearer\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"Bearer\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(6 as libc::c_int as isize)) != 0
        {
            *availp |= (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int;
            (*authp).avail |= (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int;
            if (*authp).picked == (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int {
                (*authp).avail = 0 as libc::c_int as libc::c_ulong;
                Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8 as *const libc::c_char,
                );
                let ref mut fresh12 = (*data).state;
                (*fresh12).set_authproblem(1 as libc::c_int as bit);
            }
        }
        while *auth as libc::c_int != 0 && *auth as libc::c_int != ',' as i32 {
            auth = auth.offset(1);
        }
        if *auth as libc::c_int == ',' as i32 {
            auth = auth.offset(1);
        }
        while *auth as libc::c_int != 0 && Curl_isspace(*auth as libc::c_uchar as libc::c_int) != 0
        {
            auth = auth.offset(1);
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn http_should_fail(mut data: *mut Curl_easy) -> bool {
    let mut httpcode: libc::c_int = 0;
    httpcode = (*data).req.httpcode;
    if ((*data).set).http_fail_on_error() == 0 {
        return 0 as libc::c_int != 0;
    }
    if httpcode < 400 as libc::c_int {
        return 0 as libc::c_int != 0;
    }
    if (*data).state.resume_from != 0
        && (*data).state.httpreq as libc::c_uint == HTTPREQ_GET as libc::c_int as libc::c_uint
        && httpcode == 416 as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    if httpcode != 401 as libc::c_int && httpcode != 407 as libc::c_int {
        return 1 as libc::c_int != 0;
    }
    if httpcode == 401 as libc::c_int && ((*(*data).conn).bits).user_passwd() == 0 {
        return 1 as libc::c_int != 0;
    }
    if httpcode == 407 as libc::c_int && ((*(*data).conn).bits).proxy_user_passwd() == 0 {
        return 1 as libc::c_int != 0;
    }
    return ((*data).state).authproblem() != 0;
}
unsafe extern "C" fn readmoredata(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
    mut nitems: size_t,
    mut userp: *mut libc::c_void,
) -> size_t {
    let mut data: *mut Curl_easy = userp as *mut Curl_easy;
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut fullsize: size_t = size.wrapping_mul(nitems);
    if (*http).postsize == 0 {
        return 0 as libc::c_int as size_t;
    }
    let ref mut fresh13 = (*data).req;
    (*fresh13).set_forbidchunk(
        (if (*http).sending as libc::c_uint == HTTPSEND_REQUEST as libc::c_int as libc::c_uint {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        }) as bit,
    );
    if (*data).set.max_send_speed != 0
        && (*data).set.max_send_speed < fullsize as curl_off_t
        && (*data).set.max_send_speed < (*http).postsize
    {
        fullsize = (*data).set.max_send_speed as size_t;
    } else if (*http).postsize <= fullsize as curl_off_t {
        memcpy(
            buffer as *mut libc::c_void,
            (*http).postdata as *const libc::c_void,
            (*http).postsize as size_t,
        );
        fullsize = (*http).postsize as size_t;
        if (*http).backup.postsize != 0 {
            let ref mut fresh14 = (*http).postdata;
            *fresh14 = (*http).backup.postdata;
            (*http).postsize = (*http).backup.postsize;
            let ref mut fresh15 = (*data).state.fread_func;
            *fresh15 = (*http).backup.fread_func;
            let ref mut fresh16 = (*data).state.in_0;
            *fresh16 = (*http).backup.fread_in;
            let ref mut fresh17 = (*http).sending;
            *fresh17 += 1;
            (*http).backup.postsize = 0 as libc::c_int as curl_off_t;
        } else {
            (*http).postsize = 0 as libc::c_int as curl_off_t;
        }
        return fullsize;
    }
    memcpy(
        buffer as *mut libc::c_void,
        (*http).postdata as *const libc::c_void,
        fullsize,
    );
    let ref mut fresh18 = (*http).postdata;
    *fresh18 = (*fresh18).offset(fullsize as isize);
    let ref mut fresh19 = (*http).postsize;
    *fresh19 = (*fresh19 as libc::c_ulong).wrapping_sub(fullsize) as curl_off_t as curl_off_t;
    return fullsize;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_buffer_send(
    mut in_0: *mut dynbuf,
    mut data: *mut Curl_easy,
    mut bytes_written: *mut curl_off_t,
    mut included_body_bytes: curl_off_t,
    mut socketindex: libc::c_int,
) -> CURLcode {
    let mut amount: ssize_t = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: size_t = 0;
    let mut conn: *mut connectdata = (*data).conn;
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut sendsize: size_t = 0;
    let mut sockfd: curl_socket_t = 0;
    let mut headersize: size_t = 0;
    sockfd = (*conn).sock[socketindex as usize];
    ptr = Curl_dyn_ptr(in_0);
    size = Curl_dyn_len(in_0);
    headersize = size.wrapping_sub(included_body_bytes as size_t);
    result = CURLE_OK as libc::c_int as CURLcode;
    if result as u64 != 0 {
        Curl_dyn_free(in_0);
        return result;
    }
    if ((*(*conn).handler).flags & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
        || (*conn).http_proxy.proxytype as libc::c_uint
            == CURLPROXY_HTTPS as libc::c_int as libc::c_uint)
        && (*conn).httpversion as libc::c_int != 20 as libc::c_int
    {
        if (*data).set.max_send_speed != 0 && included_body_bytes > (*data).set.max_send_speed {
            let mut overflow: curl_off_t = included_body_bytes - (*data).set.max_send_speed;
            sendsize = size.wrapping_sub(overflow as size_t);
        } else {
            sendsize = size;
        }
        result = Curl_get_upload_buffer(data);
        if result as u64 != 0 {
            Curl_dyn_free(in_0);
            return result;
        }
        if sendsize > (*data).set.upload_buffer_size as size_t {
            sendsize = (*data).set.upload_buffer_size as size_t;
        }
        memcpy(
            (*data).state.ulbuf as *mut libc::c_void,
            ptr as *const libc::c_void,
            sendsize,
        );
        ptr = (*data).state.ulbuf;
    } else if (*data).set.max_send_speed != 0 && included_body_bytes > (*data).set.max_send_speed {
        let mut overflow_0: curl_off_t = included_body_bytes - (*data).set.max_send_speed;
        sendsize = size.wrapping_sub(overflow_0 as size_t);
    } else {
        sendsize = size;
    }
    result = Curl_write(
        data,
        sockfd,
        ptr as *const libc::c_void,
        sendsize,
        &mut amount,
    );
    if result as u64 == 0 {
        let mut headlen: size_t = if amount as size_t > headersize {
            headersize
        } else {
            amount as size_t
        };
        let mut bodylen: size_t = (amount as libc::c_ulong).wrapping_sub(headlen);
        Curl_debug(data, CURLINFO_HEADER_OUT, ptr, headlen);
        if bodylen != 0 {
            Curl_debug(
                data,
                CURLINFO_DATA_OUT,
                ptr.offset(headlen as isize),
                bodylen,
            );
        }
        *bytes_written += amount;
        if !http.is_null() {
            let ref mut fresh20 = (*data).req.writebytecount;
            *fresh20 =
                (*fresh20 as libc::c_ulong).wrapping_add(bodylen) as curl_off_t as curl_off_t;
            Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount);
            if amount as size_t != size {
                size = (size as libc::c_ulong).wrapping_sub(amount as libc::c_ulong) as size_t
                    as size_t;
                ptr = (Curl_dyn_ptr(in_0)).offset(amount as isize);
                let ref mut fresh21 = (*http).backup.fread_func;
                *fresh21 = (*data).state.fread_func;
                let ref mut fresh22 = (*http).backup.fread_in;
                *fresh22 = (*data).state.in_0;
                let ref mut fresh23 = (*http).backup.postdata;
                *fresh23 = (*http).postdata;
                (*http).backup.postsize = (*http).postsize;
                let ref mut fresh24 = (*data).state.fread_func;
                *fresh24 = ::std::mem::transmute::<
                    Option<
                        unsafe extern "C" fn(
                            *mut libc::c_char,
                            size_t,
                            size_t,
                            *mut libc::c_void,
                        ) -> size_t,
                    >,
                    curl_read_callback,
                >(Some(
                    readmoredata
                        as unsafe extern "C" fn(
                            *mut libc::c_char,
                            size_t,
                            size_t,
                            *mut libc::c_void,
                        ) -> size_t,
                ));
                let ref mut fresh25 = (*data).state.in_0;
                *fresh25 = data as *mut libc::c_void;
                let ref mut fresh26 = (*http).postdata;
                *fresh26 = ptr;
                (*http).postsize = size as curl_off_t;
                (*data).req.pendingheader = headersize.wrapping_sub(headlen) as curl_off_t;
                (*http).send_buffer = *in_0;
                (*http).sending = HTTPSEND_REQUEST;
                return CURLE_OK;
            }
            (*http).sending = HTTPSEND_BODY;
        } else if amount as size_t != size {
            return CURLE_SEND_ERROR;
        }
    }
    Curl_dyn_free(in_0);
    (*data).req.pendingheader = 0 as libc::c_int as curl_off_t;
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_compareheader(
    mut headerline: *const libc::c_char,
    mut header: *const libc::c_char,
    mut content: *const libc::c_char,
) -> bool {
    let mut hlen: size_t = strlen(header);
    let mut clen: size_t = 0;
    let mut len: size_t = 0;
    let mut start: *const libc::c_char = 0 as *const libc::c_char;
    let mut end: *const libc::c_char = 0 as *const libc::c_char;
    if Curl_strncasecompare(headerline, header, hlen) == 0 {
        return 0 as libc::c_int != 0;
    }
    start = &*headerline.offset(hlen as isize) as *const libc::c_char;
    while *start as libc::c_int != 0 && Curl_isspace(*start as libc::c_uchar as libc::c_int) != 0 {
        start = start.offset(1);
    }
    end = strchr(start, '\r' as i32);
    if end.is_null() {
        end = strchr(start, '\n' as i32);
        if end.is_null() {
            end = strchr(start, '\0' as i32);
        }
    }
    len = end.offset_from(start) as libc::c_long as size_t;
    clen = strlen(content);
    while len >= clen {
        if Curl_strncasecompare(start, content, clen) != 0 {
            return 1 as libc::c_int != 0;
        }
        len = len.wrapping_sub(1);
        start = start.offset(1);
    }
    return 0 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_connect(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    Curl_conncontrol(conn, 0 as libc::c_int);
    result = Curl_proxy_connect(data, 0 as libc::c_int);
    if result as u64 != 0 {
        return result;
    }
    if ((*conn).bits).proxy_connect_closed() != 0 {
        return CURLE_OK;
    }
    if (*conn).http_proxy.proxytype as libc::c_uint
        == CURLPROXY_HTTPS as libc::c_int as libc::c_uint
        && !(*conn).bits.proxy_ssl_connected[0 as libc::c_int as usize]
    {
        return CURLE_OK;
    }
    if Curl_connect_ongoing(conn) {
        return CURLE_OK;
    }
    if ((*data).set).haproxyprotocol() != 0 {
        result = add_haproxy_protocol_header(data);
        if result as u64 != 0 {
            return result;
        }
    }
    if (*(*conn).given).protocol & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0 {
        result = CURLE_COULDNT_CONNECT;
        if result as u64 != 0 {
            return result;
        }
    } else {
        *done = 1 as libc::c_int != 0;
    }
    return CURLE_OK;
}
unsafe extern "C" fn http_getsock_do(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> libc::c_int {
    *socks.offset(0 as libc::c_int as isize) = (*conn).sock[0 as libc::c_int as usize];
    return (1 as libc::c_int) << 16 as libc::c_int + 0 as libc::c_int;
}
unsafe extern "C" fn add_haproxy_protocol_header(mut data: *mut Curl_easy) -> CURLcode {
    let mut req: dynbuf = dynbuf {
        bufr: 0 as *mut libc::c_char,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    let mut result: CURLcode = CURLE_OK;
    let mut tcp_version: *const libc::c_char = 0 as *const libc::c_char;
    Curl_dyn_init(&mut req, 2048 as libc::c_int as size_t);
    if !((*(*data).conn).unix_domain_socket).is_null() {
        result = Curl_dyn_add(
            &mut req,
            b"PROXY UNKNOWN\r\n\0" as *const u8 as *const libc::c_char,
        );
    } else {
        tcp_version = if ((*(*data).conn).bits).ipv6() as libc::c_int != 0 {
            b"TCP6\0" as *const u8 as *const libc::c_char
        } else {
            b"TCP4\0" as *const u8 as *const libc::c_char
        };
        result = Curl_dyn_addf(
            &mut req as *mut dynbuf,
            b"PROXY %s %s %s %i %i\r\n\0" as *const u8 as *const libc::c_char,
            tcp_version,
            ((*data).info.conn_local_ip).as_mut_ptr(),
            ((*data).info.conn_primary_ip).as_mut_ptr(),
            (*data).info.conn_local_port,
            (*data).info.conn_primary_port,
        );
    }
    if result as u64 == 0 {
        result = Curl_buffer_send(
            &mut req,
            data,
            &mut (*data).info.request_size,
            0 as libc::c_int as curl_off_t,
            0 as libc::c_int,
        );
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut http: *mut HTTP = (*data).req.p.http;
    let ref mut fresh27 = (*data).state.authhost;
    (*fresh27).set_multipass(0 as libc::c_int as bit);
    let ref mut fresh28 = (*data).state.authproxy;
    (*fresh28).set_multipass(0 as libc::c_int as bit);
    Curl_unencode_cleanup(data);
    let ref mut fresh29 = (*conn).seek_func;
    *fresh29 = (*data).set.seek_func;
    let ref mut fresh30 = (*conn).seek_client;
    *fresh30 = (*data).set.seek_client;
    if http.is_null() {
        return CURLE_OK;
    }
    Curl_dyn_free(&mut (*http).send_buffer);
    Curl_http2_done(data, premature);
    Curl_mime_cleanpart(&mut (*http).form);
    Curl_dyn_reset(&mut (*data).state.headerb);
    if status as u64 != 0 {
        return status;
    }
    if !premature
        && ((*conn).bits).retry() == 0
        && ((*data).set).connect_only() == 0
        && (*data).req.bytecount + (*data).req.headerbytecount - (*data).req.deductheadercount
            <= 0 as libc::c_int as libc::c_long
    {
        Curl_failf(
            data,
            b"Empty reply from server\0" as *const u8 as *const libc::c_char,
        );
        Curl_conncontrol(conn, 2 as libc::c_int);
        return CURLE_GOT_NOTHING;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_use_http_1_1plus(
    mut data: *const Curl_easy,
    mut conn: *const connectdata,
) -> bool {
    if (*data).state.httpversion as libc::c_int == 10 as libc::c_int
        || (*conn).httpversion as libc::c_int == 10 as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    if (*data).state.httpwant as libc::c_int == CURL_HTTP_VERSION_1_0 as libc::c_int
        && (*conn).httpversion as libc::c_int <= 10 as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    return (*data).state.httpwant as libc::c_int == CURL_HTTP_VERSION_NONE as libc::c_int
        || (*data).state.httpwant as libc::c_int >= CURL_HTTP_VERSION_1_1 as libc::c_int;
}
unsafe extern "C" fn get_http_string(
    mut data: *const Curl_easy,
    mut conn: *const connectdata,
) -> *const libc::c_char {
    if !((*conn).proto.httpc.h2).is_null() {
        return b"2\0" as *const u8 as *const libc::c_char;
    }
    if Curl_use_http_1_1plus(data, conn) {
        return b"1.1\0" as *const u8 as *const libc::c_char;
    }
    return b"1.0\0" as *const u8 as *const libc::c_char;
}
unsafe extern "C" fn expect100(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let ref mut fresh31 = (*data).state;
    (*fresh31).set_expect100header(0 as libc::c_int as bit);
    if ((*data).state).disableexpect() == 0
        && Curl_use_http_1_1plus(data, conn) as libc::c_int != 0
        && ((*conn).httpversion as libc::c_int) < 20 as libc::c_int
    {
        let mut ptr: *const libc::c_char =
            Curl_checkheaders(data, b"Expect\0" as *const u8 as *const libc::c_char);
        if !ptr.is_null() {
            let ref mut fresh32 = (*data).state;
            (*fresh32).set_expect100header(Curl_compareheader(
                ptr,
                b"Expect:\0" as *const u8 as *const libc::c_char,
                b"100-continue\0" as *const u8 as *const libc::c_char,
            ) as bit);
        } else {
            result = Curl_dyn_add(
                req,
                b"Expect: 100-continue\r\n\0" as *const u8 as *const libc::c_char,
            );
            if result as u64 == 0 {
                let ref mut fresh33 = (*data).state;
                (*fresh33).set_expect100header(1 as libc::c_int as bit);
            }
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_compile_trailers(
    mut trailers: *mut curl_slist,
    mut b: *mut dynbuf,
    mut handle: *mut Curl_easy,
) -> CURLcode {
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    let mut endofline_native: *const libc::c_char = 0 as *const libc::c_char;
    let mut endofline_network: *const libc::c_char = 0 as *const libc::c_char;
    if ((*handle).state).prefer_ascii() as libc::c_int != 0
        || ((*handle).set).crlf() as libc::c_int != 0
    {
        endofline_native = b"\n\0" as *const u8 as *const libc::c_char;
        endofline_network = b"\n\0" as *const u8 as *const libc::c_char;
    } else {
        endofline_native = b"\r\n\0" as *const u8 as *const libc::c_char;
        endofline_network = b"\r\n\0" as *const u8 as *const libc::c_char;
    }
    while !trailers.is_null() {
        ptr = strchr((*trailers).data, ':' as i32);
        if !ptr.is_null() && *ptr.offset(1 as libc::c_int as isize) as libc::c_int == ' ' as i32 {
            result = Curl_dyn_add(b, (*trailers).data);
            if result as u64 != 0 {
                return result;
            }
            result = Curl_dyn_add(b, endofline_native);
            if result as u64 != 0 {
                return result;
            }
        } else {
            Curl_infof(
                handle,
                b"Malformatted trailing header ! Skipping trailer.\0" as *const u8
                    as *const libc::c_char,
            );
        }
        trailers = (*trailers).next;
    }
    result = Curl_dyn_add(b, endofline_network);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_add_custom_headers(
    mut data: *mut Curl_easy,
    mut is_connect: bool,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut h: [*mut curl_slist; 2] = [0 as *mut curl_slist; 2];
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    let mut numlists: libc::c_int = 1 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut proxy: proxy_use = HEADER_SERVER;
    if is_connect {
        proxy = HEADER_CONNECT;
    } else {
        proxy = (if ((*conn).bits).httpproxy() as libc::c_int != 0
            && ((*conn).bits).tunnel_proxy() == 0
        {
            HEADER_PROXY as libc::c_int
        } else {
            HEADER_SERVER as libc::c_int
        }) as proxy_use;
    }
    match proxy as libc::c_uint {
        0 => {
            h[0 as libc::c_int as usize] = (*data).set.headers;
        }
        1 => {
            h[0 as libc::c_int as usize] = (*data).set.headers;
            if ((*data).set).sep_headers() != 0 {
                h[1 as libc::c_int as usize] = (*data).set.proxyheaders;
                numlists += 1;
            }
        }
        2 => {
            if ((*data).set).sep_headers() != 0 {
                h[0 as libc::c_int as usize] = (*data).set.proxyheaders;
            } else {
                h[0 as libc::c_int as usize] = (*data).set.headers;
            }
        }
        _ => {}
    }
    i = 0 as libc::c_int;
    while i < numlists {
        headers = h[i as usize];
        while !headers.is_null() {
            let mut semicolonp: *mut libc::c_char = 0 as *mut libc::c_char;
            ptr = strchr((*headers).data, ':' as i32);
            if ptr.is_null() {
                let mut optr: *mut libc::c_char = 0 as *mut libc::c_char;
                ptr = strchr((*headers).data, ';' as i32);
                if !ptr.is_null() {
                    optr = ptr;
                    ptr = ptr.offset(1);
                    while *ptr as libc::c_int != 0
                        && Curl_isspace(*ptr as libc::c_uchar as libc::c_int) != 0
                    {
                        ptr = ptr.offset(1);
                    }
                    if *ptr != 0 {
                        optr = 0 as *mut libc::c_char;
                    } else {
                        ptr = ptr.offset(-1);
                        if *ptr as libc::c_int == ';' as i32 {
                            semicolonp =
                                Curl_cstrdup.expect("non-null function pointer")((*headers).data);
                            if semicolonp.is_null() {
                                Curl_dyn_free(req);
                                return CURLE_OUT_OF_MEMORY;
                            }
                            *semicolonp
                                .offset(
                                    ptr.offset_from((*headers).data) as libc::c_long as isize,
                                ) = ':' as i32 as libc::c_char;
                            optr = &mut *semicolonp
                                .offset(ptr.offset_from((*headers).data) as libc::c_long as isize)
                                as *mut libc::c_char;
                        }
                    }
                    ptr = optr;
                }
            }
            if !ptr.is_null() {
                ptr = ptr.offset(1);
                while *ptr as libc::c_int != 0
                    && Curl_isspace(*ptr as libc::c_uchar as libc::c_int) != 0
                {
                    ptr = ptr.offset(1);
                }
                if *ptr as libc::c_int != 0 || !semicolonp.is_null() {
                    let mut result: CURLcode = CURLE_OK;
                    let mut compare: *mut libc::c_char = if !semicolonp.is_null() {
                        semicolonp
                    } else {
                        (*headers).data
                    };
                    if !(!((*data).state.aptr.host).is_null()
                        && curl_strnequal(
                            b"Host:\0" as *const u8 as *const libc::c_char,
                            compare,
                            strlen(b"Host:\0" as *const u8 as *const libc::c_char),
                        ) != 0)
                    {
                        if !((*data).state.httpreq as libc::c_uint
                            == HTTPREQ_POST_FORM as libc::c_int as libc::c_uint
                            && curl_strnequal(
                                b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                compare,
                                strlen(b"Content-Type:\0" as *const u8 as *const libc::c_char),
                            ) != 0)
                        {
                            if !((*data).state.httpreq as libc::c_uint
                                == HTTPREQ_POST_MIME as libc::c_int as libc::c_uint
                                && curl_strnequal(
                                    b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                    compare,
                                    strlen(b"Content-Type:\0" as *const u8 as *const libc::c_char),
                                ) != 0)
                            {
                                if !(((*conn).bits).authneg() as libc::c_int != 0
                                    && curl_strnequal(
                                        b"Content-Length:\0" as *const u8 as *const libc::c_char,
                                        compare,
                                        strlen(
                                            b"Content-Length:\0" as *const u8
                                                as *const libc::c_char,
                                        ),
                                    ) != 0)
                                {
                                    if !(!((*data).state.aptr.te).is_null()
                                        && curl_strnequal(
                                            b"Connection:\0" as *const u8 as *const libc::c_char,
                                            compare,
                                            strlen(
                                                b"Connection:\0" as *const u8
                                                    as *const libc::c_char,
                                            ),
                                        ) != 0)
                                    {
                                        if !((*conn).httpversion as libc::c_int
                                            >= 20 as libc::c_int
                                            && curl_strnequal(
                                                b"Transfer-Encoding:\0" as *const u8
                                                    as *const libc::c_char,
                                                compare,
                                                strlen(
                                                    b"Transfer-Encoding:\0" as *const u8
                                                        as *const libc::c_char,
                                                ),
                                            ) != 0)
                                        {
                                            if !((curl_strnequal(
                                                b"Authorization:\0" as *const u8
                                                    as *const libc::c_char,
                                                compare,
                                                strlen(
                                                    b"Authorization:\0" as *const u8
                                                        as *const libc::c_char,
                                                ),
                                            ) != 0
                                                || curl_strnequal(
                                                    b"Cookie:\0" as *const u8
                                                        as *const libc::c_char,
                                                    compare,
                                                    strlen(
                                                        b"Cookie:\0" as *const u8
                                                            as *const libc::c_char,
                                                    ),
                                                ) != 0)
                                                && (((*data).state).this_is_a_follow()
                                                    as libc::c_int
                                                    != 0
                                                    && !((*data).state.first_host).is_null()
                                                    && ((*data).set).allow_auth_to_other_hosts()
                                                        == 0
                                                    && Curl_strcasecompare(
                                                        (*data).state.first_host,
                                                        (*conn).host.name,
                                                    ) == 0))
                                            {
                                                result = Curl_dyn_addf(
                                                    req,
                                                    b"%s\r\n\0" as *const u8 as *const libc::c_char,
                                                    compare,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !semicolonp.is_null() {
                        Curl_cfree.expect("non-null function pointer")(
                            semicolonp as *mut libc::c_void,
                        );
                    }
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            headers = (*headers).next;
        }
        i += 1;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_add_timecondition(
    mut data: *mut Curl_easy,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut tm: *const tm = 0 as *const tm;
    let mut keeptime: tm = tm {
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
    let mut result: CURLcode = CURLE_OK;
    let mut datestr: [libc::c_char; 80] = [0; 80];
    let mut condp: *const libc::c_char = 0 as *const libc::c_char;
    if (*data).set.timecondition as libc::c_uint
        == CURL_TIMECOND_NONE as libc::c_int as libc::c_uint
    {
        return CURLE_OK;
    }
    result = Curl_gmtime((*data).set.timevalue, &mut keeptime);
    if result as u64 != 0 {
        Curl_failf(
            data,
            b"Invalid TIMEVALUE\0" as *const u8 as *const libc::c_char,
        );
        return result;
    }
    tm = &mut keeptime;
    match (*data).set.timecondition as libc::c_uint {
        1 => {
            condp = b"If-Modified-Since\0" as *const u8 as *const libc::c_char;
        }
        2 => {
            condp = b"If-Unmodified-Since\0" as *const u8 as *const libc::c_char;
        }
        3 => {
            condp = b"Last-Modified\0" as *const u8 as *const libc::c_char;
        }
        _ => return CURLE_BAD_FUNCTION_ARGUMENT,
    }
    if !(Curl_checkheaders(data, condp)).is_null() {
        return CURLE_OK;
    }
    curl_msnprintf(
        datestr.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong,
        b"%s: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8 as *const libc::c_char,
        condp,
        Curl_wkday[(if (*tm).tm_wday != 0 {
            (*tm).tm_wday - 1 as libc::c_int
        } else {
            6 as libc::c_int
        }) as usize],
        (*tm).tm_mday,
        Curl_month[(*tm).tm_mon as usize],
        (*tm).tm_year + 1900 as libc::c_int,
        (*tm).tm_hour,
        (*tm).tm_min,
        (*tm).tm_sec,
    );
    result = Curl_dyn_add(req, datestr.as_mut_ptr());
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_method(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut method: *mut *const libc::c_char,
    mut reqp: *mut Curl_HttpReq,
) {
    let mut httpreq: Curl_HttpReq = (*data).state.httpreq;
    let mut request: *const libc::c_char = 0 as *const libc::c_char;
    if (*(*conn).handler).protocol
        & ((1 as libc::c_int) << 0 as libc::c_int
            | (1 as libc::c_int) << 1 as libc::c_int
            | (1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint
        != 0
        && ((*data).set).upload() as libc::c_int != 0
    {
        httpreq = HTTPREQ_PUT;
    }
    if !((*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize]).is_null() {
        request = (*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize];
    } else if ((*data).set).opt_no_body() != 0 {
        request = b"HEAD\0" as *const u8 as *const libc::c_char;
    } else {
        match httpreq as libc::c_uint {
            1 | 2 | 3 => {
                request = b"POST\0" as *const u8 as *const libc::c_char;
            }
            4 => {
                request = b"PUT\0" as *const u8 as *const libc::c_char;
            }
            5 => {
                request = b"HEAD\0" as *const u8 as *const libc::c_char;
            }
            0 | _ => {
                request = b"GET\0" as *const u8 as *const libc::c_char;
            }
        }
    }
    *method = request;
    *reqp = httpreq;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_useragent(mut data: *mut Curl_easy) -> CURLcode {
    if !(Curl_checkheaders(data, b"User-Agent\0" as *const u8 as *const libc::c_char)).is_null() {
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.uagent as *mut libc::c_void,
        );
        let ref mut fresh34 = (*data).state.aptr.uagent;
        *fresh34 = 0 as *mut libc::c_char;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_host(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    if ((*data).state).this_is_a_follow() == 0 {
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.first_host as *mut libc::c_void,
        );
        let ref mut fresh35 = (*data).state.first_host;
        *fresh35 = Curl_cstrdup.expect("non-null function pointer")((*conn).host.name);
        if ((*data).state.first_host).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*data).state.first_remote_port = (*conn).remote_port;
    }
    Curl_cfree.expect("non-null function pointer")((*data).state.aptr.host as *mut libc::c_void);
    let ref mut fresh36 = (*data).state.aptr.host;
    *fresh36 = 0 as *mut libc::c_char;
    ptr = Curl_checkheaders(data, b"Host\0" as *const u8 as *const libc::c_char);
    if !ptr.is_null()
        && (((*data).state).this_is_a_follow() == 0
            || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0)
    {
        let mut cookiehost: *mut libc::c_char = Curl_copy_header_value(ptr);
        if cookiehost.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *cookiehost == 0 {
            Curl_cfree.expect("non-null function pointer")(cookiehost as *mut libc::c_void);
        } else {
            if *cookiehost as libc::c_int == '[' as i32 {
                let mut closingbracket: *mut libc::c_char = 0 as *mut libc::c_char;
                memmove(
                    cookiehost as *mut libc::c_void,
                    cookiehost.offset(1 as libc::c_int as isize) as *const libc::c_void,
                    (strlen(cookiehost)).wrapping_sub(1 as libc::c_int as libc::c_ulong),
                );
                closingbracket = strchr(cookiehost, ']' as i32);
                if !closingbracket.is_null() {
                    *closingbracket = 0 as libc::c_int as libc::c_char;
                }
            } else {
                let mut startsearch: libc::c_int = 0 as libc::c_int;
                let mut colon: *mut libc::c_char =
                    strchr(cookiehost.offset(startsearch as isize), ':' as i32);
                if !colon.is_null() {
                    *colon = 0 as libc::c_int as libc::c_char;
                }
            }
            Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.cookiehost as *mut libc::c_void,
            );
            let ref mut fresh37 = (*data).state.aptr.cookiehost;
            *fresh37 = 0 as *mut libc::c_char;
            let ref mut fresh38 = (*data).state.aptr.cookiehost;
            *fresh38 = cookiehost;
        }
        if strcmp(b"Host:\0" as *const u8 as *const libc::c_char, ptr) != 0 {
            let ref mut fresh39 = (*data).state.aptr.host;
            *fresh39 = curl_maprintf(
                b"Host:%s\r\n\0" as *const u8 as *const libc::c_char,
                &*ptr.offset(5 as libc::c_int as isize) as *const libc::c_char,
            );
            if ((*data).state.aptr.host).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else {
            let ref mut fresh40 = (*data).state.aptr.host;
            *fresh40 = 0 as *mut libc::c_char;
        }
    } else {
        let mut host: *const libc::c_char = (*conn).host.name;
        if (*(*conn).given).protocol & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0
            && (*conn).remote_port == 443 as libc::c_int
            || (*(*conn).given).protocol & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
                != 0
                && (*conn).remote_port == 80 as libc::c_int
        {
            let ref mut fresh41 = (*data).state.aptr.host;
            *fresh41 = curl_maprintf(
                b"Host: %s%s%s\r\n\0" as *const u8 as *const libc::c_char,
                if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                    b"[\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                host,
                if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                    b"]\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
            );
        } else {
            let ref mut fresh42 = (*data).state.aptr.host;
            *fresh42 = curl_maprintf(
                b"Host: %s%s%s:%d\r\n\0" as *const u8 as *const libc::c_char,
                if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                    b"[\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                host,
                if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                    b"]\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                (*conn).remote_port,
            );
        }
        if ((*data).state.aptr.host).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_target(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut path: *const libc::c_char = (*data).state.up.path;
    let mut query: *const libc::c_char = (*data).state.up.query;
    if !((*data).set.str_0[STRING_TARGET as libc::c_int as usize]).is_null() {
        path = (*data).set.str_0[STRING_TARGET as libc::c_int as usize];
        query = 0 as *const libc::c_char;
    }
    if ((*conn).bits).httpproxy() as libc::c_int != 0 && ((*conn).bits).tunnel_proxy() == 0 {
        let mut uc: CURLUcode = CURLUE_OK;
        let mut url: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut h: *mut CURLU = curl_url_dup((*data).state.uh);
        if h.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if (*conn).host.dispname != (*conn).host.name as *const libc::c_char {
            uc = curl_url_set(
                h,
                CURLUPART_HOST,
                (*conn).host.name,
                0 as libc::c_int as libc::c_uint,
            );
            if uc as u64 != 0 {
                curl_url_cleanup(h);
                return CURLE_OUT_OF_MEMORY;
            }
        }
        uc = curl_url_set(
            h,
            CURLUPART_FRAGMENT,
            0 as *const libc::c_char,
            0 as libc::c_int as libc::c_uint,
        );
        if uc as u64 != 0 {
            curl_url_cleanup(h);
            return CURLE_OUT_OF_MEMORY;
        }
        if Curl_strcasecompare(
            b"http\0" as *const u8 as *const libc::c_char,
            (*data).state.up.scheme,
        ) != 0
        {
            uc = curl_url_set(
                h,
                CURLUPART_USER,
                0 as *const libc::c_char,
                0 as libc::c_int as libc::c_uint,
            );
            if uc as u64 != 0 {
                curl_url_cleanup(h);
                return CURLE_OUT_OF_MEMORY;
            }
            uc = curl_url_set(
                h,
                CURLUPART_PASSWORD,
                0 as *const libc::c_char,
                0 as libc::c_int as libc::c_uint,
            );
            if uc as u64 != 0 {
                curl_url_cleanup(h);
                return CURLE_OUT_OF_MEMORY;
            }
        }
        uc = curl_url_get(
            h,
            CURLUPART_URL,
            &mut url,
            ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint,
        );
        if uc as u64 != 0 {
            curl_url_cleanup(h);
            return CURLE_OUT_OF_MEMORY;
        }
        curl_url_cleanup(h);
        result = Curl_dyn_add(
            r,
            if !((*data).set.str_0[STRING_TARGET as libc::c_int as usize]).is_null() {
                (*data).set.str_0[STRING_TARGET as libc::c_int as usize]
            } else {
                url
            },
        );
        Curl_cfree.expect("non-null function pointer")(url as *mut libc::c_void);
        if result as u64 != 0 {
            return result;
        }
        if Curl_strcasecompare(
            b"ftp\0" as *const u8 as *const libc::c_char,
            (*data).state.up.scheme,
        ) != 0
        {
            if ((*data).set).proxy_transfer_mode() != 0 {
                let mut type_0: *mut libc::c_char =
                    strstr(path, b";type=\0" as *const u8 as *const libc::c_char);
                if !type_0.is_null()
                    && *type_0.offset(6 as libc::c_int as isize) as libc::c_int != 0
                    && *type_0.offset(7 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
                {
                    match Curl_raw_toupper(*type_0.offset(6 as libc::c_int as isize)) as libc::c_int
                    {
                        65 | 68 | 73 => {}
                        _ => {
                            type_0 = 0 as *mut libc::c_char;
                        }
                    }
                }
                if type_0.is_null() {
                    result = Curl_dyn_addf(
                        r,
                        b";type=%c\0" as *const u8 as *const libc::c_char,
                        if ((*data).state).prefer_ascii() as libc::c_int != 0 {
                            'a' as i32
                        } else {
                            'i' as i32
                        },
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
        }
    } else {
        result = Curl_dyn_add(r, path);
        if result as u64 != 0 {
            return result;
        }
        if !query.is_null() {
            result = Curl_dyn_addf(r, b"?%s\0" as *const u8 as *const libc::c_char, query);
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_body(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut httpreq: Curl_HttpReq,
    mut tep: *mut *const libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    let mut http: *mut HTTP = (*data).req.p.http;
    (*http).postsize = 0 as libc::c_int as curl_off_t;
    match httpreq as libc::c_uint {
        3 => {
            let ref mut fresh43 = (*http).sendit;
            *fresh43 = &mut (*data).set.mimepost;
        }
        2 => {
            Curl_mime_cleanpart(&mut (*http).form);
            result = Curl_getformdata(
                data,
                &mut (*http).form,
                (*data).set.httppost,
                (*data).state.fread_func,
            );
            if result as u64 != 0 {
                return result;
            }
            let ref mut fresh44 = (*http).sendit;
            *fresh44 = &mut (*http).form;
        }
        _ => {
            let ref mut fresh45 = (*http).sendit;
            *fresh45 = 0 as *mut curl_mimepart;
        }
    }
    if !((*http).sendit).is_null() {
        let mut cthdr: *const libc::c_char =
            Curl_checkheaders(data, b"Content-Type\0" as *const u8 as *const libc::c_char);
        (*(*http).sendit).flags |= ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint;
        if !cthdr.is_null() {
            cthdr = cthdr.offset(13 as libc::c_int as isize);
            while *cthdr as libc::c_int == ' ' as i32 {
                cthdr = cthdr.offset(1);
            }
        } else if (*(*http).sendit).kind as libc::c_uint
            == MIMEKIND_MULTIPART as libc::c_int as libc::c_uint
        {
            cthdr = b"multipart/form-data\0" as *const u8 as *const libc::c_char;
        }
        curl_mime_headers((*http).sendit, (*data).set.headers, 0 as libc::c_int);
        result = Curl_mime_prepare_headers(
            (*http).sendit,
            cthdr,
            0 as *const libc::c_char,
            MIMESTRATEGY_FORM,
        );
        curl_mime_headers((*http).sendit, 0 as *mut curl_slist, 0 as libc::c_int);
        if result as u64 == 0 {
            result = Curl_mime_rewind((*http).sendit);
        }
        if result as u64 != 0 {
            return result;
        }
        (*http).postsize = Curl_mime_size((*http).sendit);
    }
    ptr = Curl_checkheaders(
        data,
        b"Transfer-Encoding\0" as *const u8 as *const libc::c_char,
    );
    if !ptr.is_null() {
        let ref mut fresh46 = (*data).req;
        (*fresh46).set_upload_chunky(Curl_compareheader(
            ptr,
            b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
            b"chunked\0" as *const u8 as *const libc::c_char,
        ) as bit);
    } else {
        if (*(*conn).handler).protocol
            & ((1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 1 as libc::c_int)
                as libc::c_uint
            != 0
            && ((httpreq as libc::c_uint == HTTPREQ_POST_MIME as libc::c_int as libc::c_uint
                || httpreq as libc::c_uint == HTTPREQ_POST_FORM as libc::c_int as libc::c_uint)
                && (*http).postsize < 0 as libc::c_int as libc::c_long
                || (((*data).set).upload() as libc::c_int != 0
                    || httpreq as libc::c_uint == HTTPREQ_POST as libc::c_int as libc::c_uint)
                    && (*data).state.infilesize == -(1 as libc::c_int) as libc::c_long)
        {
            if !(((*conn).bits).authneg() != 0) {
                if Curl_use_http_1_1plus(data, conn) {
                    if ((*conn).httpversion as libc::c_int) < 20 as libc::c_int {
                        let ref mut fresh47 = (*data).req;
                        (*fresh47).set_upload_chunky(1 as libc::c_int as bit);
                    }
                } else {
                    Curl_failf(
                        data,
                        b"Chunky upload is not supported by HTTP 1.0\0" as *const u8
                            as *const libc::c_char,
                    );
                    return CURLE_UPLOAD_FAILED;
                }
            }
        } else {
            let ref mut fresh48 = (*data).req;
            (*fresh48).set_upload_chunky(0 as libc::c_int as bit);
        }
        if ((*data).req).upload_chunky() != 0 {
            *tep = b"Transfer-Encoding: chunked\r\n\0" as *const u8 as *const libc::c_char;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_bodysend(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    let mut included_body: curl_off_t = 0 as libc::c_int as curl_off_t;
    let mut result: CURLcode = CURLE_OK;
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    match httpreq as libc::c_uint {
        4 => {
            if ((*conn).bits).authneg() != 0 {
                (*http).postsize = 0 as libc::c_int as curl_off_t;
            } else {
                (*http).postsize = (*data).state.infilesize;
            }
            if (*http).postsize != -(1 as libc::c_int) as libc::c_long
                && ((*data).req).upload_chunky() == 0
                && (((*conn).bits).authneg() as libc::c_int != 0
                    || (Curl_checkheaders(
                        data,
                        b"Content-Length\0" as *const u8 as *const libc::c_char,
                    ))
                    .is_null())
            {
                result = Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*http).postsize,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            if (*http).postsize != 0 {
                result = expect100(data, conn, r);
                if result as u64 != 0 {
                    return result;
                }
            }
            result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
            if result as u64 != 0 {
                return result;
            }
            Curl_pgrsSetUploadSize(data, (*http).postsize);
            result = Curl_buffer_send(
                r,
                data,
                &mut (*data).info.request_size,
                0 as libc::c_int as curl_off_t,
                0 as libc::c_int,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failed sending PUT request\0" as *const u8 as *const libc::c_char,
                );
            } else {
                Curl_setup_transfer(
                    data,
                    0 as libc::c_int,
                    -(1 as libc::c_int) as curl_off_t,
                    1 as libc::c_int != 0,
                    if (*http).postsize != 0 {
                        0 as libc::c_int
                    } else {
                        -(1 as libc::c_int)
                    },
                );
            }
            if result as u64 != 0 {
                return result;
            }
        }
        2 | 3 => {
            if ((*conn).bits).authneg() != 0 {
                result = Curl_dyn_add(
                    r,
                    b"Content-Length: 0\r\n\r\n\0" as *const u8 as *const libc::c_char,
                );
                if result as u64 != 0 {
                    return result;
                }
                result = Curl_buffer_send(
                    r,
                    data,
                    &mut (*data).info.request_size,
                    0 as libc::c_int as curl_off_t,
                    0 as libc::c_int,
                );
                if result as u64 != 0 {
                    Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    Curl_setup_transfer(
                        data,
                        0 as libc::c_int,
                        -(1 as libc::c_int) as curl_off_t,
                        1 as libc::c_int != 0,
                        -(1 as libc::c_int),
                    );
                }
            } else {
                (*data).state.infilesize = (*http).postsize;
                if (*http).postsize != -(1 as libc::c_int) as libc::c_long
                    && ((*data).req).upload_chunky() == 0
                    && (((*conn).bits).authneg() as libc::c_int != 0
                        || (Curl_checkheaders(
                            data,
                            b"Content-Length\0" as *const u8 as *const libc::c_char,
                        ))
                        .is_null())
                {
                    result = Curl_dyn_addf(
                        r,
                        b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                        (*http).postsize,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
                let mut hdr: *mut curl_slist = 0 as *mut curl_slist;
                hdr = (*(*http).sendit).curlheaders;
                while !hdr.is_null() {
                    result = Curl_dyn_addf(
                        r,
                        b"%s\r\n\0" as *const u8 as *const libc::c_char,
                        (*hdr).data,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                    hdr = (*hdr).next;
                }
                ptr = Curl_checkheaders(data, b"Expect\0" as *const u8 as *const libc::c_char);
                if !ptr.is_null() {
                    let ref mut fresh49 = (*data).state;
                    (*fresh49).set_expect100header(Curl_compareheader(
                        ptr,
                        b"Expect:\0" as *const u8 as *const libc::c_char,
                        b"100-continue\0" as *const u8 as *const libc::c_char,
                    ) as bit);
                } else if (*http).postsize
                    > (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long
                    || (*http).postsize < 0 as libc::c_int as libc::c_long
                {
                    result = expect100(data, conn, r);
                    if result as u64 != 0 {
                        return result;
                    }
                } else {
                    let ref mut fresh50 = (*data).state;
                    (*fresh50).set_expect100header(0 as libc::c_int as bit);
                }
                result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
                if result as u64 != 0 {
                    return result;
                }
                Curl_pgrsSetUploadSize(data, (*http).postsize);
                let ref mut fresh51 = (*data).state.fread_func;
                *fresh51 = ::std::mem::transmute::<
                    Option<
                        unsafe extern "C" fn(
                            *mut libc::c_char,
                            size_t,
                            size_t,
                            *mut libc::c_void,
                        ) -> size_t,
                    >,
                    curl_read_callback,
                >(Some(
                    Curl_mime_read
                        as unsafe extern "C" fn(
                            *mut libc::c_char,
                            size_t,
                            size_t,
                            *mut libc::c_void,
                        ) -> size_t,
                ));
                let ref mut fresh52 = (*data).state.in_0;
                *fresh52 = (*http).sendit as *mut libc::c_void;
                (*http).sending = HTTPSEND_BODY;
                result = Curl_buffer_send(
                    r,
                    data,
                    &mut (*data).info.request_size,
                    0 as libc::c_int as curl_off_t,
                    0 as libc::c_int,
                );
                if result as u64 != 0 {
                    Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    Curl_setup_transfer(
                        data,
                        0 as libc::c_int,
                        -(1 as libc::c_int) as curl_off_t,
                        1 as libc::c_int != 0,
                        if (*http).postsize != 0 {
                            0 as libc::c_int
                        } else {
                            -(1 as libc::c_int)
                        },
                    );
                }
                if result as u64 != 0 {
                    return result;
                }
            }
        }
        1 => {
            if ((*conn).bits).authneg() != 0 {
                (*http).postsize = 0 as libc::c_int as curl_off_t;
            } else {
                (*http).postsize = (*data).state.infilesize;
            }
            if (*http).postsize != -(1 as libc::c_int) as libc::c_long
                && ((*data).req).upload_chunky() == 0
                && (((*conn).bits).authneg() as libc::c_int != 0
                    || (Curl_checkheaders(
                        data,
                        b"Content-Length\0" as *const u8 as *const libc::c_char,
                    ))
                    .is_null())
            {
                result = Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*http).postsize,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            if (Curl_checkheaders(data, b"Content-Type\0" as *const u8 as *const libc::c_char))
                .is_null()
            {
                result = Curl_dyn_add(
                    r,
                    b"Content-Type: application/x-www-form-urlencoded\r\n\0" as *const u8
                        as *const libc::c_char,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            ptr = Curl_checkheaders(data, b"Expect\0" as *const u8 as *const libc::c_char);
            if !ptr.is_null() {
                let ref mut fresh53 = (*data).state;
                (*fresh53).set_expect100header(Curl_compareheader(
                    ptr,
                    b"Expect:\0" as *const u8 as *const libc::c_char,
                    b"100-continue\0" as *const u8 as *const libc::c_char,
                ) as bit);
            } else if (*http).postsize > (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long
                || (*http).postsize < 0 as libc::c_int as libc::c_long
            {
                result = expect100(data, conn, r);
                if result as u64 != 0 {
                    return result;
                }
            } else {
                let ref mut fresh54 = (*data).state;
                (*fresh54).set_expect100header(0 as libc::c_int as bit);
            }
            if !((*data).set.postfields).is_null() {
                if (*conn).httpversion as libc::c_int != 20 as libc::c_int
                    && ((*data).state).expect100header() == 0
                    && (*http).postsize < (64 as libc::c_int * 1024 as libc::c_int) as libc::c_long
                {
                    result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
                    if result as u64 != 0 {
                        return result;
                    }
                    if ((*data).req).upload_chunky() == 0 {
                        result =
                            Curl_dyn_addn(r, (*data).set.postfields, (*http).postsize as size_t);
                        included_body = (*http).postsize;
                    } else {
                        if (*http).postsize != 0 {
                            let mut chunk: [libc::c_char; 16] = [0; 16];
                            curl_msnprintf(
                                chunk.as_mut_ptr(),
                                ::std::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
                                b"%x\r\n\0" as *const u8 as *const libc::c_char,
                                (*http).postsize as libc::c_int,
                            );
                            result = Curl_dyn_add(r, chunk.as_mut_ptr());
                            if result as u64 == 0 {
                                included_body = ((*http).postsize as libc::c_ulong)
                                    .wrapping_add(strlen(chunk.as_mut_ptr()))
                                    as curl_off_t;
                                result = Curl_dyn_addn(
                                    r,
                                    (*data).set.postfields,
                                    (*http).postsize as size_t,
                                );
                                if result as u64 == 0 {
                                    result = Curl_dyn_add(
                                        r,
                                        b"\r\n\0" as *const u8 as *const libc::c_char,
                                    );
                                }
                                included_body += 2 as libc::c_int as libc::c_long;
                            }
                        }
                        if result as u64 == 0 {
                            result =
                                Curl_dyn_add(r, b"0\r\n\r\n\0" as *const u8 as *const libc::c_char);
                            included_body += 5 as libc::c_int as libc::c_long;
                        }
                    }
                    if result as u64 != 0 {
                        return result;
                    }
                    Curl_pgrsSetUploadSize(data, (*http).postsize);
                } else {
                    let ref mut fresh55 = (*http).postdata;
                    *fresh55 = (*data).set.postfields as *const libc::c_char;
                    (*http).sending = HTTPSEND_BODY;
                    let ref mut fresh56 = (*data).state.fread_func;
                    *fresh56 = ::std::mem::transmute::<
                        Option<
                            unsafe extern "C" fn(
                                *mut libc::c_char,
                                size_t,
                                size_t,
                                *mut libc::c_void,
                            ) -> size_t,
                        >,
                        curl_read_callback,
                    >(Some(
                        readmoredata
                            as unsafe extern "C" fn(
                                *mut libc::c_char,
                                size_t,
                                size_t,
                                *mut libc::c_void,
                            ) -> size_t,
                    ));
                    let ref mut fresh57 = (*data).state.in_0;
                    *fresh57 = data as *mut libc::c_void;
                    Curl_pgrsSetUploadSize(data, (*http).postsize);
                    result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
                    if result as u64 != 0 {
                        return result;
                    }
                }
            } else {
                result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
                if result as u64 != 0 {
                    return result;
                }
                if ((*data).req).upload_chunky() as libc::c_int != 0
                    && ((*conn).bits).authneg() as libc::c_int != 0
                {
                    result = Curl_dyn_add(
                        r,
                        b"0\r\n\r\n\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                } else if (*data).state.infilesize != 0 {
                    Curl_pgrsSetUploadSize(
                        data,
                        if (*http).postsize != 0 {
                            (*http).postsize
                        } else {
                            -(1 as libc::c_int) as libc::c_long
                        },
                    );
                    if ((*conn).bits).authneg() == 0 {
                        let ref mut fresh58 = (*http).postdata;
                        *fresh58 =
                            &mut (*http).postdata as *mut *const libc::c_char as *mut libc::c_char;
                    }
                }
            }
            result = Curl_buffer_send(
                r,
                data,
                &mut (*data).info.request_size,
                included_body,
                0 as libc::c_int,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failed sending HTTP POST request\0" as *const u8 as *const libc::c_char,
                );
            } else {
                Curl_setup_transfer(
                    data,
                    0 as libc::c_int,
                    -(1 as libc::c_int) as curl_off_t,
                    1 as libc::c_int != 0,
                    if !((*http).postdata).is_null() {
                        0 as libc::c_int
                    } else {
                        -(1 as libc::c_int)
                    },
                );
            }
        }
        _ => {
            result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
            if result as u64 != 0 {
                return result;
            }
            result = Curl_buffer_send(
                r,
                data,
                &mut (*data).info.request_size,
                0 as libc::c_int as curl_off_t,
                0 as libc::c_int,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failed sending HTTP request\0" as *const u8 as *const libc::c_char,
                );
            } else {
                Curl_setup_transfer(
                    data,
                    0 as libc::c_int,
                    -(1 as libc::c_int) as curl_off_t,
                    1 as libc::c_int != 0,
                    -(1 as libc::c_int),
                );
            }
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_cookies(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut addcookies: *mut libc::c_char = 0 as *mut libc::c_char;
    if !((*data).set.str_0[STRING_COOKIE as libc::c_int as usize]).is_null()
        && (Curl_checkheaders(data, b"Cookie\0" as *const u8 as *const libc::c_char)).is_null()
    {
        addcookies = (*data).set.str_0[STRING_COOKIE as libc::c_int as usize];
    }
    if !((*data).cookies).is_null() || !addcookies.is_null() {
        let mut co: *mut Cookie = 0 as *mut Cookie;
        let mut count: libc::c_int = 0 as libc::c_int;
        if !((*data).cookies).is_null() && ((*data).state).cookie_engine() as libc::c_int != 0 {
            let mut host: *const libc::c_char = if !((*data).state.aptr.cookiehost).is_null() {
                (*data).state.aptr.cookiehost
            } else {
                (*conn).host.name
            };
            let secure_context: bool = if (*(*conn).handler).protocol
                & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
                != 0
                || Curl_strcasecompare(b"localhost\0" as *const u8 as *const libc::c_char, host)
                    != 0
                || strcmp(host, b"127.0.0.1\0" as *const u8 as *const libc::c_char) == 0
                || strcmp(host, b"[::1]\0" as *const u8 as *const libc::c_char) == 0
            {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            } != 0;
            Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
            co = Curl_cookie_getlist((*data).cookies, host, (*data).state.up.path, secure_context);
            Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
        }
        if !co.is_null() {
            let mut store: *mut Cookie = co;
            while !co.is_null() {
                if !((*co).value).is_null() {
                    if 0 as libc::c_int == count {
                        result = Curl_dyn_add(r, b"Cookie: \0" as *const u8 as *const libc::c_char);
                        if result as u64 != 0 {
                            break;
                        }
                    }
                    result = Curl_dyn_addf(
                        r,
                        b"%s%s=%s\0" as *const u8 as *const libc::c_char,
                        if count != 0 {
                            b"; \0" as *const u8 as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                        (*co).name,
                        (*co).value,
                    );
                    if result as u64 != 0 {
                        break;
                    }
                    count += 1;
                }
                co = (*co).next;
            }
            Curl_cookie_freelist(store);
        }
        if !addcookies.is_null() && result as u64 == 0 {
            if count == 0 {
                result = Curl_dyn_add(r, b"Cookie: \0" as *const u8 as *const libc::c_char);
            }
            if result as u64 == 0 {
                result = Curl_dyn_addf(
                    r,
                    b"%s%s\0" as *const u8 as *const libc::c_char,
                    if count != 0 {
                        b"; \0" as *const u8 as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                    addcookies,
                );
                count += 1;
            }
        }
        if count != 0 && result as u64 == 0 {
            result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
        }
        if result as u64 != 0 {
            return result;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_range(
    mut data: *mut Curl_easy,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    if ((*data).state).use_range() != 0 {
        if (httpreq as libc::c_uint == HTTPREQ_GET as libc::c_int as libc::c_uint
            || httpreq as libc::c_uint == HTTPREQ_HEAD as libc::c_int as libc::c_uint)
            && (Curl_checkheaders(data, b"Range\0" as *const u8 as *const libc::c_char)).is_null()
        {
            Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.rangeline as *mut libc::c_void,
            );
            let ref mut fresh59 = (*data).state.aptr.rangeline;
            *fresh59 = curl_maprintf(
                b"Range: bytes=%s\r\n\0" as *const u8 as *const libc::c_char,
                (*data).state.range,
            );
        } else if (httpreq as libc::c_uint == HTTPREQ_POST as libc::c_int as libc::c_uint
            || httpreq as libc::c_uint == HTTPREQ_PUT as libc::c_int as libc::c_uint)
            && (Curl_checkheaders(data, b"Content-Range\0" as *const u8 as *const libc::c_char))
                .is_null()
        {
            Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.rangeline as *mut libc::c_void,
            );
            if (*data).set.set_resume_from < 0 as libc::c_int as libc::c_long {
                let ref mut fresh60 = (*data).state.aptr.rangeline;
                *fresh60 = curl_maprintf(
                    b"Content-Range: bytes 0-%ld/%ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*data).state.infilesize - 1 as libc::c_int as libc::c_long,
                    (*data).state.infilesize,
                );
            } else if (*data).state.resume_from != 0 {
                let mut total_expected_size: curl_off_t =
                    (*data).state.resume_from + (*data).state.infilesize;
                let ref mut fresh61 = (*data).state.aptr.rangeline;
                *fresh61 = curl_maprintf(
                    b"Content-Range: bytes %s%ld/%ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*data).state.range,
                    total_expected_size - 1 as libc::c_int as libc::c_long,
                    total_expected_size,
                );
            } else {
                let ref mut fresh62 = (*data).state.aptr.rangeline;
                *fresh62 = curl_maprintf(
                    b"Content-Range: bytes %s/%ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*data).state.range,
                    (*data).state.infilesize,
                );
            }
            if ((*data).state.aptr.rangeline).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_resume(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    if (HTTPREQ_POST as libc::c_int as libc::c_uint == httpreq as libc::c_uint
        || HTTPREQ_PUT as libc::c_int as libc::c_uint == httpreq as libc::c_uint)
        && (*data).state.resume_from != 0
    {
        if (*data).state.resume_from < 0 as libc::c_int as libc::c_long {
            (*data).state.resume_from = 0 as libc::c_int as curl_off_t;
        }
        if (*data).state.resume_from != 0 && ((*data).state).this_is_a_follow() == 0 {
            let mut seekerr: libc::c_int = 2 as libc::c_int;
            if ((*conn).seek_func).is_some() {
                Curl_set_in_callback(data, 1 as libc::c_int != 0);
                seekerr = ((*conn).seek_func).expect("non-null function pointer")(
                    (*conn).seek_client,
                    (*data).state.resume_from,
                    0 as libc::c_int,
                );
                Curl_set_in_callback(data, 0 as libc::c_int != 0);
            }
            if seekerr != 0 as libc::c_int {
                let mut passed: curl_off_t = 0 as libc::c_int as curl_off_t;
                if seekerr != 2 as libc::c_int {
                    Curl_failf(
                        data,
                        b"Could not seek stream\0" as *const u8 as *const libc::c_char,
                    );
                    return CURLE_READ_ERROR;
                }
                loop {
                    let mut readthisamountnow: size_t =
                        if (*data).state.resume_from - passed > (*data).set.buffer_size {
                            (*data).set.buffer_size as size_t
                        } else {
                            curlx_sotouz((*data).state.resume_from - passed)
                        };
                    let mut actuallyread: size_t = ((*data).state.fread_func)
                        .expect("non-null function pointer")(
                        (*data).state.buffer,
                        1 as libc::c_int as size_t,
                        readthisamountnow,
                        (*data).state.in_0,
                    );
                    passed = (passed as libc::c_ulong).wrapping_add(actuallyread) as curl_off_t
                        as curl_off_t;
                    if actuallyread == 0 as libc::c_int as libc::c_ulong
                        || actuallyread > readthisamountnow
                    {
                        Curl_failf(
                            data,
                            b"Could only read %ld bytes from the input\0" as *const u8
                                as *const libc::c_char,
                            passed,
                        );
                        return CURLE_READ_ERROR;
                    }
                    if !(passed < (*data).state.resume_from) {
                        break;
                    }
                }
            }
            if (*data).state.infilesize > 0 as libc::c_int as libc::c_long {
                let ref mut fresh63 = (*data).state.infilesize;
                *fresh63 -= (*data).state.resume_from;
                if (*data).state.infilesize <= 0 as libc::c_int as libc::c_long {
                    Curl_failf(
                        data,
                        b"File already completely uploaded\0" as *const u8 as *const libc::c_char,
                    );
                    return CURLE_PARTIAL_FILE;
                }
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_firstwrite(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut done: *mut bool,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    if ((*data).req).ignore_cl() != 0 {
        let ref mut fresh64 = (*k).maxdownload;
        *fresh64 = -(1 as libc::c_int) as curl_off_t;
        (*k).size = *fresh64;
    } else if (*k).size != -(1 as libc::c_int) as libc::c_long {
        if (*data).set.max_filesize != 0 && (*k).size > (*data).set.max_filesize {
            Curl_failf(
                data,
                b"Maximum file size exceeded\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_FILESIZE_EXCEEDED;
        }
        Curl_pgrsSetDownloadSize(data, (*k).size);
    }
    if !((*data).req.newurl).is_null() {
        if ((*conn).bits).close() != 0 {
            (*k).keepon &= !((1 as libc::c_int) << 0 as libc::c_int);
            *done = 1 as libc::c_int != 0;
            return CURLE_OK;
        }
        (*k).set_ignorebody(1 as libc::c_int as bit);
        Curl_infof(
            data,
            b"Ignoring the response-body\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*data).state.resume_from != 0
        && (*k).content_range() == 0
        && (*data).state.httpreq as libc::c_uint == HTTPREQ_GET as libc::c_int as libc::c_uint
        && (*k).ignorebody() == 0
    {
        if (*k).size == (*data).state.resume_from {
            Curl_infof(
                data,
                b"The entire document is already downloaded\0" as *const u8 as *const libc::c_char,
            );
            Curl_conncontrol(conn, 1 as libc::c_int);
            (*k).keepon &= !((1 as libc::c_int) << 0 as libc::c_int);
            *done = 1 as libc::c_int != 0;
            return CURLE_OK;
        }
        Curl_failf(
            data,
            b"HTTP server doesn't seem to support byte ranges. Cannot resume.\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_RANGE_ERROR;
    }
    if (*data).set.timecondition as libc::c_uint != 0 && ((*data).state.range).is_null() {
        if !Curl_meets_timecondition(data, (*k).timeofdoc) {
            *done = 1 as libc::c_int != 0;
            (*data).info.httpcode = 304 as libc::c_int;
            Curl_infof(
                data,
                b"Simulate a HTTP 304 response!\0" as *const u8 as *const libc::c_char,
            );
            Curl_conncontrol(conn, 1 as libc::c_int);
            return CURLE_OK;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_transferencode(mut data: *mut Curl_easy) -> CURLcode {
    if (Curl_checkheaders(data, b"TE\0" as *const u8 as *const libc::c_char)).is_null()
        && ((*data).set).http_transfer_encoding() as libc::c_int != 0
    {
        let mut cptr: *mut libc::c_char =
            Curl_checkheaders(data, b"Connection\0" as *const u8 as *const libc::c_char);
        Curl_cfree.expect("non-null function pointer")((*data).state.aptr.te as *mut libc::c_void);
        let ref mut fresh65 = (*data).state.aptr.te;
        *fresh65 = 0 as *mut libc::c_char;
        if !cptr.is_null() {
            cptr = Curl_copy_header_value(cptr);
            if cptr.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
        let ref mut fresh66 = (*data).state.aptr.te;
        *fresh66 = curl_maprintf(
            b"Connection: %s%sTE\r\nTE: gzip\r\n\0" as *const u8 as *const libc::c_char,
            if !cptr.is_null() {
                cptr as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if !cptr.is_null() && *cptr as libc::c_int != 0 {
                b", \0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        Curl_cfree.expect("non-null function pointer")(cptr as *mut libc::c_void);
        if ((*data).state.aptr.te).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut result: CURLcode = CURLE_OK;
    let mut http: *mut HTTP = 0 as *mut HTTP;
    let mut httpreq: Curl_HttpReq = HTTPREQ_GET;
    let mut te: *const libc::c_char = b"\0" as *const u8 as *const libc::c_char;
    let mut request: *const libc::c_char = 0 as *const libc::c_char;
    let mut httpstring: *const libc::c_char = 0 as *const libc::c_char;
    let mut req: dynbuf = dynbuf {
        bufr: 0 as *mut libc::c_char,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    let mut altused: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p_accept: *const libc::c_char = 0 as *const libc::c_char;
    *done = 1 as libc::c_int != 0;
    if (*conn).transport as libc::c_uint != TRNSPRT_QUIC as libc::c_int as libc::c_uint {
        if ((*conn).httpversion as libc::c_int) < 20 as libc::c_int {
            match (*conn).negnpn {
                3 => {
                    (*conn).httpversion = 20 as libc::c_int as libc::c_uchar;
                    result = Curl_http2_switched(
                        data,
                        0 as *const libc::c_char,
                        0 as libc::c_int as size_t,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
                2 => {}
                _ => {
                    if (*data).state.httpwant as libc::c_int
                        == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE as libc::c_int
                    {
                        if ((*conn).bits).httpproxy() as libc::c_int != 0
                            && ((*conn).bits).tunnel_proxy() == 0
                        {
                            Curl_infof(
                                data,
                                b"Ignoring HTTP/2 prior knowledge due to proxy\0" as *const u8
                                    as *const libc::c_char,
                            );
                        } else {
                            (*conn).httpversion = 20 as libc::c_int as libc::c_uchar;
                            result = Curl_http2_switched(
                                data,
                                0 as *const libc::c_char,
                                0 as libc::c_int as size_t,
                            );
                            if result as u64 != 0 {
                                return result;
                            }
                        }
                    }
                }
            }
        } else {
            result = Curl_http2_setup(data, conn);
            if result as u64 != 0 {
                return result;
            }
        }
    }
    http = (*data).req.p.http;
    result = Curl_http_host(data, conn);
    if result as u64 != 0 {
        return result;
    }
    result = Curl_http_useragent(data);
    if result as u64 != 0 {
        return result;
    }
    Curl_http_method(data, conn, &mut request, &mut httpreq);
    let mut pq: *mut libc::c_char = 0 as *mut libc::c_char;
    if !((*data).state.up.query).is_null() {
        pq = curl_maprintf(
            b"%s?%s\0" as *const u8 as *const libc::c_char,
            (*data).state.up.path,
            (*data).state.up.query,
        );
        if pq.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    result = Curl_http_output_auth(
        data,
        conn,
        request,
        httpreq,
        if !pq.is_null() {
            pq
        } else {
            (*data).state.up.path
        },
        0 as libc::c_int != 0,
    );
    Curl_cfree.expect("non-null function pointer")(pq as *mut libc::c_void);
    if result as u64 != 0 {
        return result;
    }
    Curl_cfree.expect("non-null function pointer")((*data).state.aptr.ref_0 as *mut libc::c_void);
    let ref mut fresh67 = (*data).state.aptr.ref_0;
    *fresh67 = 0 as *mut libc::c_char;
    if !((*data).state.referer).is_null()
        && (Curl_checkheaders(data, b"Referer\0" as *const u8 as *const libc::c_char)).is_null()
    {
        let ref mut fresh68 = (*data).state.aptr.ref_0;
        *fresh68 = curl_maprintf(
            b"Referer: %s\r\n\0" as *const u8 as *const libc::c_char,
            (*data).state.referer,
        );
        if ((*data).state.aptr.ref_0).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if (Curl_checkheaders(
        data,
        b"Accept-Encoding\0" as *const u8 as *const libc::c_char,
    ))
    .is_null()
        && !((*data).set.str_0[STRING_ENCODING as libc::c_int as usize]).is_null()
    {
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
        );
        let ref mut fresh69 = (*data).state.aptr.accept_encoding;
        *fresh69 = 0 as *mut libc::c_char;
        let ref mut fresh70 = (*data).state.aptr.accept_encoding;
        *fresh70 = curl_maprintf(
            b"Accept-Encoding: %s\r\n\0" as *const u8 as *const libc::c_char,
            (*data).set.str_0[STRING_ENCODING as libc::c_int as usize],
        );
        if ((*data).state.aptr.accept_encoding).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
        );
        let ref mut fresh71 = (*data).state.aptr.accept_encoding;
        *fresh71 = 0 as *mut libc::c_char;
    }
    result = Curl_transferencode(data);
    if result as u64 != 0 {
        return result;
    }
    result = Curl_http_body(data, conn, httpreq, &mut te);
    if result as u64 != 0 {
        return result;
    }
    p_accept =
        if !(Curl_checkheaders(data, b"Accept\0" as *const u8 as *const libc::c_char)).is_null() {
            0 as *const libc::c_char
        } else {
            b"Accept: */*\r\n\0" as *const u8 as *const libc::c_char
        };
    result = Curl_http_resume(data, conn, httpreq);
    if result as u64 != 0 {
        return result;
    }
    result = Curl_http_range(data, httpreq);
    if result as u64 != 0 {
        return result;
    }
    httpstring = get_http_string(data, conn);
    Curl_dyn_init(
        &mut req,
        (1024 as libc::c_int * 1024 as libc::c_int) as size_t,
    );
    Curl_dyn_reset(&mut (*data).state.headerb);
    result = Curl_dyn_addf(
        &mut req as *mut dynbuf,
        b"%s \0" as *const u8 as *const libc::c_char,
        request,
    );
    if result as u64 == 0 {
        result = Curl_http_target(data, conn, &mut req);
    }
    if result as u64 != 0 {
        Curl_dyn_free(&mut req);
        return result;
    }
    if ((*conn).bits).altused() as libc::c_int != 0
        && (Curl_checkheaders(data, b"Alt-Used\0" as *const u8 as *const libc::c_char)).is_null()
    {
        altused = curl_maprintf(
            b"Alt-Used: %s:%d\r\n\0" as *const u8 as *const libc::c_char,
            (*conn).conn_to_host.name,
            (*conn).conn_to_port,
        );
        if altused.is_null() {
            Curl_dyn_free(&mut req);
            return CURLE_OUT_OF_MEMORY;
        }
    }
    result = Curl_dyn_addf(
        &mut req as *mut dynbuf,
        b" HTTP/%s\r\n%s%s%s%s%s%s%s%s%s%s%s%s\0" as *const u8 as *const libc::c_char,
        httpstring,
        if !((*data).state.aptr.host).is_null() {
            (*data).state.aptr.host as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).state.aptr.proxyuserpwd).is_null() {
            (*data).state.aptr.proxyuserpwd as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).state.aptr.userpwd).is_null() {
            (*data).state.aptr.userpwd as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if ((*data).state).use_range() as libc::c_int != 0
            && !((*data).state.aptr.rangeline).is_null()
        {
            (*data).state.aptr.rangeline as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).set.str_0[STRING_USERAGENT as libc::c_int as usize]).is_null()
            && *(*data).set.str_0[STRING_USERAGENT as libc::c_int as usize] as libc::c_int != 0
            && !((*data).state.aptr.uagent).is_null()
        {
            (*data).state.aptr.uagent as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !p_accept.is_null() {
            p_accept
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).state.aptr.te).is_null() {
            (*data).state.aptr.te as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).set.str_0[STRING_ENCODING as libc::c_int as usize]).is_null()
            && *(*data).set.str_0[STRING_ENCODING as libc::c_int as usize] as libc::c_int != 0
            && !((*data).state.aptr.accept_encoding).is_null()
        {
            (*data).state.aptr.accept_encoding as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).state.referer).is_null() && !((*data).state.aptr.ref_0).is_null() {
            (*data).state.aptr.ref_0 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if ((*conn).bits).httpproxy() as libc::c_int != 0
            && ((*conn).bits).tunnel_proxy() == 0
            && (Curl_checkheaders(
                data,
                b"Proxy-Connection\0" as *const u8 as *const libc::c_char,
            ))
            .is_null()
            && (Curl_checkProxyheaders(
                data,
                conn,
                b"Proxy-Connection\0" as *const u8 as *const libc::c_char,
            ))
            .is_null()
        {
            b"Proxy-Connection: Keep-Alive\r\n\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        te,
        if !altused.is_null() {
            altused as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    Curl_cfree.expect("non-null function pointer")((*data).state.aptr.userpwd as *mut libc::c_void);
    let ref mut fresh72 = (*data).state.aptr.userpwd;
    *fresh72 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
    );
    let ref mut fresh73 = (*data).state.aptr.proxyuserpwd;
    *fresh73 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")(altused as *mut libc::c_void);
    if result as u64 != 0 {
        Curl_dyn_free(&mut req);
        return result;
    }
    if (*(*conn).handler).flags & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint == 0
        && (*conn).httpversion as libc::c_int != 20 as libc::c_int
        && (*data).state.httpwant as libc::c_int == CURL_HTTP_VERSION_2_0 as libc::c_int
    {
        result = Curl_http2_request_upgrade(&mut req, data);
        if result as u64 != 0 {
            Curl_dyn_free(&mut req);
            return result;
        }
    }
    result = Curl_http_cookies(data, conn, &mut req);
    if result as u64 == 0 {
        result = Curl_add_timecondition(data, &mut req);
    }
    if result as u64 == 0 {
        result = Curl_add_custom_headers(data, 0 as libc::c_int != 0, &mut req);
    }
    if result as u64 == 0 {
        let ref mut fresh74 = (*http).postdata;
        *fresh74 = 0 as *const libc::c_char;
        if httpreq as libc::c_uint == HTTPREQ_GET as libc::c_int as libc::c_uint
            || httpreq as libc::c_uint == HTTPREQ_HEAD as libc::c_int as libc::c_uint
        {
            Curl_pgrsSetUploadSize(data, 0 as libc::c_int as curl_off_t);
        }
        result = Curl_http_bodysend(data, conn, &mut req, httpreq);
    }
    if result as u64 != 0 {
        Curl_dyn_free(&mut req);
        return result;
    }
    if (*http).postsize > -(1 as libc::c_int) as libc::c_long
        && (*http).postsize <= (*data).req.writebytecount
        && (*http).sending as libc::c_uint != HTTPSEND_REQUEST as libc::c_int as libc::c_uint
    {
        let ref mut fresh75 = (*data).req;
        (*fresh75).set_upload_done(1 as libc::c_int as bit);
    }
    if (*data).req.writebytecount != 0 {
        Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount);
        if Curl_pgrsUpdate(data) != 0 {
            result = CURLE_ABORTED_BY_CALLBACK;
        }
        if (*http).postsize == 0 {
            Curl_infof(
                data,
                b"upload completely sent off: %ld out of %ld bytes\0" as *const u8
                    as *const libc::c_char,
                (*data).req.writebytecount,
                (*http).postsize,
            );
            let ref mut fresh76 = (*data).req;
            (*fresh76).set_upload_done(1 as libc::c_int as bit);
            (*data).req.keepon &= !((1 as libc::c_int) << 1 as libc::c_int);
            (*data).req.exp100 = EXP100_SEND_DATA;
            Curl_expire_done(data, EXPIRE_100_TIMEOUT);
        }
    }
    if (*conn).httpversion as libc::c_int == 20 as libc::c_int
        && ((*data).req).upload_chunky() as libc::c_int != 0
    {
        let ref mut fresh77 = (*data).req;
        (*fresh77).set_upload_chunky(0 as libc::c_int as bit);
    }
    return result;
}
unsafe extern "C" fn checkprefixmax(
    mut prefix: *const libc::c_char,
    mut buffer: *const libc::c_char,
    mut len: size_t,
) -> bool {
    let mut ch: size_t = if strlen(prefix) < len {
        strlen(prefix)
    } else {
        len
    };
    return curl_strnequal(prefix, buffer, ch) != 0;
}
unsafe extern "C" fn checkhttpprefix(
    mut data: *mut Curl_easy,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> statusline {
    let mut head: *mut curl_slist = (*data).set.http200aliases;
    let mut rc: statusline = STATUS_BAD;
    let mut onmatch: statusline = (if len >= 5 as libc::c_int as libc::c_ulong {
        STATUS_DONE as libc::c_int
    } else {
        STATUS_UNKNOWN as libc::c_int
    }) as statusline;
    while !head.is_null() {
        if checkprefixmax((*head).data, s, len) {
            rc = onmatch;
            break;
        } else {
            head = (*head).next;
        }
    }
    if rc as libc::c_uint != STATUS_DONE as libc::c_int as libc::c_uint
        && checkprefixmax(b"HTTP/\0" as *const u8 as *const libc::c_char, s, len) as libc::c_int
            != 0
    {
        rc = onmatch;
    }
    return rc;
}
unsafe extern "C" fn checkrtspprefix(
    mut data: *mut Curl_easy,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> statusline {
    let mut result: statusline = STATUS_BAD;
    let mut onmatch: statusline = (if len >= 5 as libc::c_int as libc::c_ulong {
        STATUS_DONE as libc::c_int
    } else {
        STATUS_UNKNOWN as libc::c_int
    }) as statusline;
    if checkprefixmax(b"RTSP/\0" as *const u8 as *const libc::c_char, s, len) {
        result = onmatch;
    }
    return result;
}
unsafe extern "C" fn checkprotoprefix(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> statusline {
    if (*(*conn).handler).protocol & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint != 0
    {
        return checkrtspprefix(data, s, len);
    }
    return checkhttpprefix(data, s, len);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_header(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut headp: *mut libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut k: *mut SingleRequest = &mut (*data).req;
    if (*k).http_bodyless() == 0
        && ((*data).set).ignorecl() == 0
        && curl_strnequal(
            b"Content-Length:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Content-Length:\0" as *const u8 as *const libc::c_char),
        ) != 0
    {
        let mut contentlength: curl_off_t = 0;
        let mut offt: CURLofft = curlx_strtoofft(
            headp.offset(strlen(b"Content-Length:\0" as *const u8 as *const libc::c_char) as isize),
            0 as *mut *mut libc::c_char,
            10 as libc::c_int,
            &mut contentlength,
        );
        if offt as libc::c_uint == CURL_OFFT_OK as libc::c_int as libc::c_uint {
            (*k).size = contentlength;
            (*k).maxdownload = (*k).size;
        } else if offt as libc::c_uint == CURL_OFFT_FLOW as libc::c_int as libc::c_uint {
            if (*data).set.max_filesize != 0 {
                Curl_failf(
                    data,
                    b"Maximum file size exceeded\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_FILESIZE_EXCEEDED;
            }
            Curl_conncontrol(conn, 2 as libc::c_int);
            Curl_infof(
                data,
                b"Overflow Content-Length: value!\0" as *const u8 as *const libc::c_char,
            );
        } else {
            Curl_failf(
                data,
                b"Invalid Content-Length: value\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_WEIRD_SERVER_REPLY;
        }
    } else if curl_strnequal(
        b"Content-Type:\0" as *const u8 as *const libc::c_char,
        headp,
        strlen(b"Content-Type:\0" as *const u8 as *const libc::c_char),
    ) != 0
    {
        let mut contenttype: *mut libc::c_char = Curl_copy_header_value(headp);
        if contenttype.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *contenttype == 0 {
            Curl_cfree.expect("non-null function pointer")(contenttype as *mut libc::c_void);
        } else {
            Curl_cfree.expect("non-null function pointer")(
                (*data).info.contenttype as *mut libc::c_void,
            );
            let ref mut fresh78 = (*data).info.contenttype;
            *fresh78 = 0 as *mut libc::c_char;
            let ref mut fresh79 = (*data).info.contenttype;
            *fresh79 = contenttype;
        }
    } else if (*conn).httpversion as libc::c_int == 10 as libc::c_int
        && ((*conn).bits).httpproxy() as libc::c_int != 0
        && Curl_compareheader(
            headp,
            b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
            b"keep-alive\0" as *const u8 as *const libc::c_char,
        ) as libc::c_int
            != 0
    {
        Curl_conncontrol(conn, 0 as libc::c_int);
        Curl_infof(
            data,
            b"HTTP/1.0 proxy connection set to keep alive!\0" as *const u8 as *const libc::c_char,
        );
    } else if (*conn).httpversion as libc::c_int == 11 as libc::c_int
        && ((*conn).bits).httpproxy() as libc::c_int != 0
        && Curl_compareheader(
            headp,
            b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
            b"close\0" as *const u8 as *const libc::c_char,
        ) as libc::c_int
            != 0
    {
        Curl_conncontrol(conn, 1 as libc::c_int);
        Curl_infof(
            data,
            b"HTTP/1.1 proxy connection set close!\0" as *const u8 as *const libc::c_char,
        );
    } else if (*conn).httpversion as libc::c_int == 10 as libc::c_int
        && Curl_compareheader(
            headp,
            b"Connection:\0" as *const u8 as *const libc::c_char,
            b"keep-alive\0" as *const u8 as *const libc::c_char,
        ) as libc::c_int
            != 0
    {
        Curl_conncontrol(conn, 0 as libc::c_int);
        Curl_infof(
            data,
            b"HTTP/1.0 connection set to keep alive!\0" as *const u8 as *const libc::c_char,
        );
    } else if Curl_compareheader(
        headp,
        b"Connection:\0" as *const u8 as *const libc::c_char,
        b"close\0" as *const u8 as *const libc::c_char,
    ) {
        Curl_conncontrol(conn, 2 as libc::c_int);
    } else if (*k).http_bodyless() == 0
        && curl_strnequal(
            b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char),
        ) != 0
    {
        result = Curl_build_unencoding_stack(
            data,
            headp.offset(
                strlen(b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char) as isize,
            ),
            1 as libc::c_int,
        );
        if result as u64 != 0 {
            return result;
        }
        if (*k).chunk() == 0 {
            Curl_conncontrol(conn, 1 as libc::c_int);
            (*k).set_ignore_cl(1 as libc::c_int as bit);
        }
    } else if (*k).http_bodyless() == 0
        && curl_strnequal(
            b"Content-Encoding:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Content-Encoding:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && !((*data).set.str_0[STRING_ENCODING as libc::c_int as usize]).is_null()
    {
        result = Curl_build_unencoding_stack(
            data,
            headp.offset(
                strlen(b"Content-Encoding:\0" as *const u8 as *const libc::c_char) as isize,
            ),
            0 as libc::c_int,
        );
        if result as u64 != 0 {
            return result;
        }
    } else if curl_strnequal(
        b"Retry-After:\0" as *const u8 as *const libc::c_char,
        headp,
        strlen(b"Retry-After:\0" as *const u8 as *const libc::c_char),
    ) != 0
    {
        let mut retry_after: curl_off_t = 0 as libc::c_int as curl_off_t;
        let mut date: time_t = Curl_getdate_capped(
            headp.offset(strlen(b"Retry-After:\0" as *const u8 as *const libc::c_char) as isize),
        );
        if -(1 as libc::c_int) as libc::c_long == date {
            curlx_strtoofft(
                headp
                    .offset(strlen(b"Retry-After:\0" as *const u8 as *const libc::c_char) as isize),
                0 as *mut *mut libc::c_char,
                10 as libc::c_int,
                &mut retry_after,
            );
        } else {
            retry_after = date - time(0 as *mut time_t);
        }
        (*data).info.retry_after = retry_after;
    } else if (*k).http_bodyless() == 0
        && curl_strnequal(
            b"Content-Range:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Content-Range:\0" as *const u8 as *const libc::c_char),
        ) != 0
    {
        let mut ptr: *mut libc::c_char =
            headp.offset(strlen(b"Content-Range:\0" as *const u8 as *const libc::c_char) as isize);
        while *ptr as libc::c_int != 0
            && Curl_isdigit(*ptr as libc::c_uchar as libc::c_int) == 0
            && *ptr as libc::c_int != '*' as i32
        {
            ptr = ptr.offset(1);
        }
        if Curl_isdigit(*ptr as libc::c_uchar as libc::c_int) != 0 {
            if curlx_strtoofft(
                ptr,
                0 as *mut *mut libc::c_char,
                10 as libc::c_int,
                &mut (*k).offset,
            ) as u64
                == 0
            {
                if (*data).state.resume_from == (*k).offset {
                    (*k).set_content_range(1 as libc::c_int as bit);
                }
            }
        } else {
            (*data).state.resume_from = 0 as libc::c_int as curl_off_t;
        }
    } else if !((*data).cookies).is_null()
        && ((*data).state).cookie_engine() as libc::c_int != 0
        && curl_strnequal(
            b"Set-Cookie:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Set-Cookie:\0" as *const u8 as *const libc::c_char),
        ) != 0
    {
        let mut host: *const libc::c_char = if !((*data).state.aptr.cookiehost).is_null() {
            (*data).state.aptr.cookiehost
        } else {
            (*conn).host.name
        };
        let secure_context: bool = if (*(*conn).handler).protocol
            & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
            != 0
            || Curl_strcasecompare(b"localhost\0" as *const u8 as *const libc::c_char, host) != 0
            || strcmp(host, b"127.0.0.1\0" as *const u8 as *const libc::c_char) == 0
            || strcmp(host, b"[::1]\0" as *const u8 as *const libc::c_char) == 0
        {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        } != 0;
        Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
        Curl_cookie_add(
            data,
            (*data).cookies,
            1 as libc::c_int != 0,
            0 as libc::c_int != 0,
            headp.offset(strlen(b"Set-Cookie:\0" as *const u8 as *const libc::c_char) as isize),
            host,
            (*data).state.up.path,
            secure_context,
        );
        Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    } else if (*k).http_bodyless() == 0
        && curl_strnequal(
            b"Last-Modified:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Last-Modified:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && ((*data).set.timecondition as libc::c_uint != 0
            || ((*data).set).get_filetime() as libc::c_int != 0)
    {
        (*k).timeofdoc = Curl_getdate_capped(
            headp.offset(strlen(b"Last-Modified:\0" as *const u8 as *const libc::c_char) as isize),
        );
        if ((*data).set).get_filetime() != 0 {
            (*data).info.filetime = (*k).timeofdoc;
        }
    } else if curl_strnequal(
        b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char,
        headp,
        strlen(b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char),
    ) != 0
        && 401 as libc::c_int == (*k).httpcode
        || curl_strnequal(
            b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char),
        ) != 0
            && 407 as libc::c_int == (*k).httpcode
    {
        let mut proxy: bool = if (*k).httpcode == 407 as libc::c_int {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        } != 0;
        let mut auth: *mut libc::c_char = Curl_copy_header_value(headp);
        if auth.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = Curl_http_input_auth(data, proxy, auth);
        Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
        if result as u64 != 0 {
            return result;
        }
    } else if (*k).httpcode >= 300 as libc::c_int
        && (*k).httpcode < 400 as libc::c_int
        && curl_strnequal(
            b"Location:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Location:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && ((*data).req.location).is_null()
    {
        let mut location: *mut libc::c_char = Curl_copy_header_value(headp);
        if location.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *location == 0 {
            Curl_cfree.expect("non-null function pointer")(location as *mut libc::c_void);
        } else {
            let ref mut fresh80 = (*data).req.location;
            *fresh80 = location;
            if ((*data).set).http_follow_location() != 0 {
                let ref mut fresh81 = (*data).req.newurl;
                *fresh81 = Curl_cstrdup.expect("non-null function pointer")((*data).req.location);
                if ((*data).req.newurl).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                result = http_perhapsrewind(data, conn);
                if result as u64 != 0 {
                    return result;
                }
            }
        }
    } else if !((*data).asi).is_null()
        && curl_strnequal(
            b"Alt-Svc:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Alt-Svc:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && ((*(*conn).handler).flags & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
            != 0
            || 0 as libc::c_int != 0)
    {
        let mut id: alpnid = (if (*conn).httpversion as libc::c_int == 20 as libc::c_int {
            ALPN_h2 as libc::c_int
        } else {
            ALPN_h1 as libc::c_int
        }) as alpnid;
        result = Curl_altsvc_parse(
            data,
            (*data).asi,
            headp.offset(strlen(b"Alt-Svc:\0" as *const u8 as *const libc::c_char) as isize),
            id,
            (*conn).host.name,
            curlx_uitous((*conn).remote_port as libc::c_uint),
        );
        if result as u64 != 0 {
            return result;
        }
    } else if (*(*conn).handler).protocol
        & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
        != 0
    {
        result = Curl_rtsp_parseheader(data, headp);
        if result as u64 != 0 {
            return result;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_statusline(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    (*data).info.httpcode = (*k).httpcode;
    (*data).info.httpversion = (*conn).httpversion as libc::c_int;
    if (*data).state.httpversion == 0
        || (*data).state.httpversion as libc::c_int > (*conn).httpversion as libc::c_int
    {
        (*data).state.httpversion = (*conn).httpversion;
    }
    if (*data).state.resume_from != 0
        && (*data).state.httpreq as libc::c_uint == HTTPREQ_GET as libc::c_int as libc::c_uint
        && (*k).httpcode == 416 as libc::c_int
    {
        (*k).set_ignorebody(1 as libc::c_int as bit);
    }
    if (*conn).httpversion as libc::c_int == 10 as libc::c_int {
        Curl_infof(
            data,
            b"HTTP 1.0, assume close after body\0" as *const u8 as *const libc::c_char,
        );
        Curl_conncontrol(conn, 1 as libc::c_int);
    } else if (*conn).httpversion as libc::c_int == 20 as libc::c_int
        || (*k).upgr101 as libc::c_uint == UPGR101_REQUESTED as libc::c_int as libc::c_uint
            && (*k).httpcode == 101 as libc::c_int
    {
        (*(*conn).bundle).multiuse = 2 as libc::c_int;
    } else {
        (*conn).httpversion as libc::c_int >= 11 as libc::c_int && ((*conn).bits).close() == 0;
    }
    (*k).set_http_bodyless(
        ((*k).httpcode >= 100 as libc::c_int && (*k).httpcode < 200 as libc::c_int) as libc::c_int
            as bit,
    );
    let mut current_block_25: u64;
    match (*k).httpcode {
        304 => {
            if (*data).set.timecondition as u64 != 0 {
                let ref mut fresh82 = (*data).info;
                (*fresh82).set_timecond(1 as libc::c_int as bit);
            }
            current_block_25 = 14741359113768901450;
        }
        204 => {
            current_block_25 = 14741359113768901450;
        }
        _ => {
            current_block_25 = 14763689060501151050;
        }
    }
    match current_block_25 {
        14741359113768901450 => {
            (*k).size = 0 as libc::c_int as curl_off_t;
            (*k).maxdownload = 0 as libc::c_int as curl_off_t;
            (*k).set_http_bodyless(1 as libc::c_int as bit);
        }
        _ => {}
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_readwrite_headers(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut nread: *mut ssize_t,
    mut stop_reading: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut onread: ssize_t = *nread;
    let mut ostr: *mut libc::c_char = (*k).str_0;
    let mut headp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut str_start: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end_ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    loop {
        let mut rest_length: size_t = 0;
        let mut full_length: size_t = 0;
        let mut writetype: libc::c_int = 0;
        str_start = (*k).str_0;
        end_ptr = memchr(
            str_start as *const libc::c_void,
            0xa as libc::c_int,
            *nread as libc::c_ulong,
        ) as *mut libc::c_char;
        if end_ptr.is_null() {
            result = Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                *nread as size_t,
            );
            if result as u64 != 0 {
                return result;
            }
            if !((*k).headerline == 0) {
                break;
            }
            let mut st: statusline = checkprotoprefix(
                data,
                conn,
                Curl_dyn_ptr(&mut (*data).state.headerb),
                Curl_dyn_len(&mut (*data).state.headerb),
            );
            if !(st as libc::c_uint == STATUS_BAD as libc::c_int as libc::c_uint) {
                break;
            }
            (*k).set_header(0 as libc::c_int as bit);
            (*k).badheader = HEADER_ALLBAD;
            Curl_conncontrol(conn, 2 as libc::c_int);
            if ((*data).set).http09_allowed() == 0 {
                Curl_failf(
                    data,
                    b"Received HTTP/0.9 when not allowed\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_UNSUPPORTED_PROTOCOL;
            }
            break;
        } else {
            rest_length = (end_ptr.offset_from((*k).str_0) as libc::c_long
                + 1 as libc::c_int as libc::c_long) as size_t;
            *nread -= rest_length as ssize_t;
            let ref mut fresh83 = (*k).str_0;
            *fresh83 = end_ptr.offset(1 as libc::c_int as isize);
            full_length = ((*k).str_0).offset_from(str_start) as libc::c_long as size_t;
            result = Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                full_length,
            );
            if result as u64 != 0 {
                return result;
            }
            if (*k).headerline == 0 {
                let mut st_0: statusline = checkprotoprefix(
                    data,
                    conn,
                    Curl_dyn_ptr(&mut (*data).state.headerb),
                    Curl_dyn_len(&mut (*data).state.headerb),
                );
                if st_0 as libc::c_uint == STATUS_BAD as libc::c_int as libc::c_uint {
                    Curl_conncontrol(conn, 2 as libc::c_int);
                    if ((*data).set).http09_allowed() == 0 {
                        Curl_failf(
                            data,
                            b"Received HTTP/0.9 when not allowed\0" as *const u8
                                as *const libc::c_char,
                        );
                        return CURLE_UNSUPPORTED_PROTOCOL;
                    }
                    (*k).set_header(0 as libc::c_int as bit);
                    if *nread != 0 {
                        (*k).badheader = HEADER_PARTHEADER;
                    } else {
                        (*k).badheader = HEADER_ALLBAD;
                        *nread = onread;
                        let ref mut fresh84 = (*k).str_0;
                        *fresh84 = ostr;
                        return CURLE_OK;
                    }
                    break;
                }
            }
            headp = Curl_dyn_ptr(&mut (*data).state.headerb);
            if 0xa as libc::c_int == *headp as libc::c_int
                || 0xd as libc::c_int == *headp as libc::c_int
            {
                let mut headerlen: size_t = 0;
                if '\r' as i32 == *headp as libc::c_int {
                    headp = headp.offset(1);
                }
                if '\n' as i32 == *headp as libc::c_int {
                    headp = headp.offset(1);
                }
                if 100 as libc::c_int <= (*k).httpcode && 199 as libc::c_int >= (*k).httpcode {
                    match (*k).httpcode {
                        100 => {
                            (*k).set_header(1 as libc::c_int as bit);
                            (*k).headerline = 0 as libc::c_int;
                            if (*k).exp100 as libc::c_uint
                                > EXP100_SEND_DATA as libc::c_int as libc::c_uint
                            {
                                (*k).exp100 = EXP100_SEND_DATA;
                                (*k).keepon |= (1 as libc::c_int) << 1 as libc::c_int;
                                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                            }
                        }
                        101 => {
                            if (*k).upgr101 as libc::c_uint
                                == UPGR101_REQUESTED as libc::c_int as libc::c_uint
                            {
                                Curl_infof(
                                    data,
                                    b"Received 101\0" as *const u8 as *const libc::c_char,
                                );
                                (*k).upgr101 = UPGR101_RECEIVED;
                                (*k).set_header(1 as libc::c_int as bit);
                                (*k).headerline = 0 as libc::c_int;
                                result = Curl_http2_switched(data, (*k).str_0, *nread as size_t);
                                if result as u64 != 0 {
                                    return result;
                                }
                                *nread = 0 as libc::c_int as ssize_t;
                            } else {
                                (*k).set_header(0 as libc::c_int as bit);
                            }
                        }
                        _ => {
                            (*k).set_header(1 as libc::c_int as bit);
                            (*k).headerline = 0 as libc::c_int;
                        }
                    }
                } else {
                    (*k).set_header(0 as libc::c_int as bit);
                    if (*k).size == -(1 as libc::c_int) as libc::c_long
                        && (*k).chunk() == 0
                        && ((*conn).bits).close() == 0
                        && (*conn).httpversion as libc::c_int == 11 as libc::c_int
                        && (*(*conn).handler).protocol
                            & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
                            == 0
                        && (*data).state.httpreq as libc::c_uint
                            != HTTPREQ_HEAD as libc::c_int as libc::c_uint
                    {
                        Curl_infof(
                            data,
                            b"no chunk, no close, no size. Assume close to signal end\0"
                                as *const u8 as *const libc::c_char,
                        );
                        Curl_conncontrol(conn, 2 as libc::c_int);
                    }
                }
                writetype = (1 as libc::c_int) << 1 as libc::c_int;
                if ((*data).set).include_header() != 0 {
                    writetype |= (1 as libc::c_int) << 0 as libc::c_int;
                }
                headerlen = Curl_dyn_len(&mut (*data).state.headerb);
                result = Curl_client_write(
                    data,
                    writetype,
                    Curl_dyn_ptr(&mut (*data).state.headerb),
                    headerlen,
                );
                if result as u64 != 0 {
                    return result;
                }
                let ref mut fresh85 = (*data).info.header_size;
                *fresh85 += headerlen as libc::c_long;
                let ref mut fresh86 = (*data).req.headerbytecount;
                *fresh86 += headerlen as libc::c_long;
                if http_should_fail(data) {
                    Curl_failf(
                        data,
                        b"The requested URL returned error: %d\0" as *const u8
                            as *const libc::c_char,
                        (*k).httpcode,
                    );
                    return CURLE_HTTP_RETURNED_ERROR;
                }
                (*data).req.deductheadercount =
                    if 100 as libc::c_int <= (*k).httpcode && 199 as libc::c_int >= (*k).httpcode {
                        (*data).req.headerbytecount
                    } else {
                        0 as libc::c_int as libc::c_long
                    };
                result = Curl_http_auth_act(data);
                if result as u64 != 0 {
                    return result;
                }
                if (*k).httpcode >= 300 as libc::c_int {
                    if ((*conn).bits).authneg() == 0
                        && ((*conn).bits).close() == 0
                        && ((*conn).bits).rewindaftersend() == 0
                    {
                        match (*data).state.httpreq as libc::c_uint {
                            4 | 1 | 2 | 3 => {
                                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                                if (*k).upload_done() == 0 {
                                    if (*k).httpcode == 417 as libc::c_int
                                        && ((*data).state).expect100header() as libc::c_int != 0
                                    {
                                        Curl_infof(
                                            data,
                                            b"Got 417 while waiting for a 100\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        let ref mut fresh87 = (*data).state;
                                        (*fresh87).set_disableexpect(1 as libc::c_int as bit);
                                        let ref mut fresh88 = (*data).req.newurl;
                                        *fresh88 = Curl_cstrdup.expect("non-null function pointer")(
                                            (*data).state.url,
                                        );
                                        Curl_done_sending(data, k);
                                    } else if ((*data).set).http_keep_sending_on_error() != 0 {
                                        Curl_infof(
                                            data,
                                            b"HTTP error before end of send, keep sending\0"
                                                as *const u8
                                                as *const libc::c_char,
                                        );
                                        if (*k).exp100 as libc::c_uint
                                            > EXP100_SEND_DATA as libc::c_int as libc::c_uint
                                        {
                                            (*k).exp100 = EXP100_SEND_DATA;
                                            (*k).keepon |= (1 as libc::c_int) << 1 as libc::c_int;
                                        }
                                    } else {
                                        Curl_infof(
                                            data,
                                            b"HTTP error before end of send, stop sending\0"
                                                as *const u8
                                                as *const libc::c_char,
                                        );
                                        Curl_conncontrol(conn, 2 as libc::c_int);
                                        result = Curl_done_sending(data, k);
                                        if result as u64 != 0 {
                                            return result;
                                        }
                                        (*k).set_upload_done(1 as libc::c_int as bit);
                                        if ((*data).state).expect100header() != 0 {
                                            (*k).exp100 = EXP100_FAILED;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if ((*conn).bits).rewindaftersend() != 0 {
                        Curl_infof(
                            data,
                            b"Keep sending data to get tossed away!\0" as *const u8
                                as *const libc::c_char,
                        );
                        (*k).keepon |= (1 as libc::c_int) << 1 as libc::c_int;
                    }
                }
                // 解决clippy错误
                if (*k).header() == 0 {
                    if ((*data).set).opt_no_body() != 0
                        || (*(*conn).handler).protocol
                            & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
                            != 0
                            && (*data).set.rtspreq as libc::c_uint
                                == RTSPREQ_DESCRIBE as libc::c_int as libc::c_uint
                            && (*k).size <= -(1 as libc::c_int) as libc::c_long
                    {
                        *stop_reading = 1 as libc::c_int != 0;
                    // } else if (*(*conn).handler).protocol
                    //     & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
                    //     != 0
                    //     && (*data).set.rtspreq as libc::c_uint
                    //         == RTSPREQ_DESCRIBE as libc::c_int as libc::c_uint
                    //     && (*k).size <= -(1 as libc::c_int) as libc::c_long
                    // {
                    //     *stop_reading = 1 as libc::c_int != 0;
                    } else if (*k).chunk() != 0 {
                        let ref mut fresh89 = (*k).size;
                        *fresh89 = -(1 as libc::c_int) as curl_off_t;
                        (*k).maxdownload = *fresh89;
                    }
                    if -(1 as libc::c_int) as libc::c_long != (*k).size {
                        Curl_pgrsSetDownloadSize(data, (*k).size);
                        (*k).maxdownload = (*k).size;
                    }
                    if 0 as libc::c_int as libc::c_long == (*k).maxdownload
                        && !((*(*conn).handler).protocol
                            & ((1 as libc::c_int) << 0 as libc::c_int
                                | (1 as libc::c_int) << 1 as libc::c_int)
                                as libc::c_uint
                            != 0
                            && (*conn).httpversion as libc::c_int == 20 as libc::c_int)
                    {
                        *stop_reading = 1 as libc::c_int != 0;
                    }
                    if *stop_reading {
                        (*k).keepon &= !((1 as libc::c_int) << 0 as libc::c_int);
                    }
                    Curl_debug(data, CURLINFO_HEADER_IN, str_start, headerlen);
                    break;
                } else {
                    Curl_dyn_reset(&mut (*data).state.headerb);
                }
            } else {
                let ref mut fresh90 = (*k).headerline;
                let fresh91 = *fresh90;
                *fresh90 = *fresh90 + 1;
                if fresh91 == 0 {
                    let mut httpversion_major: libc::c_int = 0;
                    let mut rtspversion_major: libc::c_int = 0;
                    let mut nc: libc::c_int = 0 as libc::c_int;
                    if (*(*conn).handler).protocol
                        & ((1 as libc::c_int) << 0 as libc::c_int
                            | (1 as libc::c_int) << 1 as libc::c_int)
                            as libc::c_uint
                        != 0
                    {
                        let mut separator: libc::c_char = 0;
                        let mut twoorthree: [libc::c_char; 2] = [0; 2];
                        let mut httpversion: libc::c_int = 0 as libc::c_int;
                        let mut digit4: libc::c_char = 0 as libc::c_int as libc::c_char;
                        nc = sscanf(
                            headp,
                            b" HTTP/%1d.%1d%c%3d%c\0" as *const u8 as *const libc::c_char,
                            &mut httpversion_major as *mut libc::c_int,
                            &mut httpversion as *mut libc::c_int,
                            &mut separator as *mut libc::c_char,
                            &mut (*k).httpcode as *mut libc::c_int,
                            &mut digit4 as *mut libc::c_char,
                        );
                        if nc == 1 as libc::c_int
                            && httpversion_major >= 2 as libc::c_int
                            && 2 as libc::c_int
                                == sscanf(
                                    headp,
                                    b" HTTP/%1[23] %d\0" as *const u8 as *const libc::c_char,
                                    twoorthree.as_mut_ptr(),
                                    &mut (*k).httpcode as *mut libc::c_int,
                                )
                        {
                            (*conn).httpversion = 0 as libc::c_int as libc::c_uchar;
                            nc = 4 as libc::c_int;
                            separator = ' ' as i32 as libc::c_char;
                        } else if Curl_isdigit(digit4 as libc::c_uchar as libc::c_int) != 0 {
                            Curl_failf(
                                data,
                                b"Unsupported response code in HTTP response\0" as *const u8
                                    as *const libc::c_char,
                            );
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                        if nc >= 4 as libc::c_int && ' ' as i32 == separator as libc::c_int {
                            httpversion += 10 as libc::c_int * httpversion_major;
                            match httpversion {
                                10 | 11 | 20 => {
                                    (*conn).httpversion = httpversion as libc::c_uchar;
                                }
                                _ => {
                                    Curl_failf(
                                        data,
                                        b"Unsupported HTTP version (%u.%d) in response\0"
                                            as *const u8
                                            as *const libc::c_char,
                                        httpversion / 10 as libc::c_int,
                                        httpversion % 10 as libc::c_int,
                                    );
                                    return CURLE_UNSUPPORTED_PROTOCOL;
                                }
                            }
                            if (*k).upgr101 as libc::c_uint
                                == UPGR101_RECEIVED as libc::c_int as libc::c_uint
                            {
                                if (*conn).httpversion as libc::c_int != 20 as libc::c_int {
                                    Curl_infof(
                                        data,
                                        b"Lying server, not serving HTTP/2\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                            }
                            if ((*conn).httpversion as libc::c_int) < 20 as libc::c_int {
                                (*(*conn).bundle).multiuse = -(1 as libc::c_int);
                                Curl_infof(
                                    data,
                                    b"Mark bundle as not supporting multiuse\0" as *const u8
                                        as *const libc::c_char,
                                );
                            }
                        } else if nc == 0 {
                            nc = sscanf(
                                headp,
                                b" HTTP %3d\0" as *const u8 as *const libc::c_char,
                                &mut (*k).httpcode as *mut libc::c_int,
                            );
                            (*conn).httpversion = 10 as libc::c_int as libc::c_uchar;
                            if nc == 0 {
                                let mut check: statusline = checkhttpprefix(
                                    data,
                                    Curl_dyn_ptr(&mut (*data).state.headerb),
                                    Curl_dyn_len(&mut (*data).state.headerb),
                                );
                                if check as libc::c_uint
                                    == STATUS_DONE as libc::c_int as libc::c_uint
                                {
                                    nc = 1 as libc::c_int;
                                    (*k).httpcode = 200 as libc::c_int;
                                    (*conn).httpversion = 10 as libc::c_int as libc::c_uchar;
                                }
                            }
                        } else {
                            Curl_failf(
                                data,
                                b"Unsupported HTTP version in response\0" as *const u8
                                    as *const libc::c_char,
                            );
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                    } else if (*(*conn).handler).protocol
                        & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
                        != 0
                    {
                        let mut separator_0: libc::c_char = 0;
                        let mut rtspversion: libc::c_int = 0;
                        nc = sscanf(
                            headp,
                            b" RTSP/%1d.%1d%c%3d\0" as *const u8 as *const libc::c_char,
                            &mut rtspversion_major as *mut libc::c_int,
                            &mut rtspversion as *mut libc::c_int,
                            &mut separator_0 as *mut libc::c_char,
                            &mut (*k).httpcode as *mut libc::c_int,
                        );
                        if nc == 4 as libc::c_int && ' ' as i32 == separator_0 as libc::c_int {
                            (*conn).httpversion = 11 as libc::c_int as libc::c_uchar;
                        } else {
                            nc = 0 as libc::c_int;
                        }
                    }
                    if nc != 0 {
                        result = Curl_http_statusline(data, conn);
                        if result as u64 != 0 {
                            return result;
                        }
                    } else {
                        (*k).set_header(0 as libc::c_int as bit);
                        break;
                    }
                }
                result = CURLE_OK as libc::c_int as CURLcode;
                if result as u64 != 0 {
                    return result;
                }
                result = Curl_http_header(data, conn, headp);
                if result as u64 != 0 {
                    return result;
                }
                writetype = (1 as libc::c_int) << 1 as libc::c_int;
                if ((*data).set).include_header() != 0 {
                    writetype |= (1 as libc::c_int) << 0 as libc::c_int;
                }
                Curl_debug(
                    data,
                    CURLINFO_HEADER_IN,
                    headp,
                    Curl_dyn_len(&mut (*data).state.headerb),
                );
                result = Curl_client_write(
                    data,
                    writetype,
                    headp,
                    Curl_dyn_len(&mut (*data).state.headerb),
                );
                if result as u64 != 0 {
                    return result;
                }
                let ref mut fresh92 = (*data).info.header_size;
                *fresh92 = (*fresh92 as libc::c_ulong)
                    .wrapping_add(Curl_dyn_len(&mut (*data).state.headerb))
                    as curl_off_t as curl_off_t;
                let ref mut fresh93 = (*data).req.headerbytecount;
                *fresh93 = (*fresh93 as libc::c_ulong)
                    .wrapping_add(Curl_dyn_len(&mut (*data).state.headerb))
                    as curl_off_t as curl_off_t;
                Curl_dyn_reset(&mut (*data).state.headerb);
            }
            if !(*(*k).str_0 != 0) {
                break;
            }
        }
    }
    return CURLE_OK;
}
