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
 * Description: extern C function declarations that ffi needed
 ******************************************************************************/
 use crate::src::ffi_alias::type_alias::*;
 use crate::src::ffi_struct::struct_define::*;
 
 extern "C" {
     // keylog.rs
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
 
     // vtls.rs
     pub fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
     pub fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
     pub fn Curl_safe_strcasecompare(
         first: *const libc::c_char,
         second: *const libc::c_char,
     ) -> libc::c_int;
 
     // ftp.rs
     pub fn Curl_sec_read_msg(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         _: *mut libc::c_char,
         _: protection_level,
     ) -> libc::c_int;
     pub fn Curl_sec_end(_: *mut connectdata);
     pub fn Curl_sec_login(_: *mut Curl_easy, _: *mut connectdata) -> CURLcode;
     pub fn Curl_sec_request_prot(conn: *mut connectdata, level: *const libc::c_char)
         -> libc::c_int;
     pub fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
     pub fn strncpy(
         _: *mut libc::c_char,
         _: *const libc::c_char,
         _: libc::c_ulong,
     ) -> *mut libc::c_char;
     pub fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong)
         -> libc::c_int;
     pub fn bind(__fd: libc::c_int, __addr: *const sockaddr, __len: socklen_t) -> libc::c_int;
     pub fn getsockname(
         __fd: libc::c_int,
         __addr: *mut sockaddr,
         __len: *mut socklen_t,
     ) -> libc::c_int;
     pub fn listen(__fd: libc::c_int, __n: libc::c_int) -> libc::c_int;
     pub fn accept(
         __fd: libc::c_int,
         __addr: *mut sockaddr,
         __addr_len: *mut socklen_t,
     ) -> libc::c_int;
     pub fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
     pub fn Curl_isdigit(c: libc::c_int) -> libc::c_int;
     pub fn __errno_location() -> *mut libc::c_int;
     pub fn strtol(
         _: *const libc::c_char,
         _: *mut *mut libc::c_char,
         _: libc::c_int,
     ) -> libc::c_long;
     pub fn strtoul(
         _: *const libc::c_char,
         _: *mut *mut libc::c_char,
         _: libc::c_int,
     ) -> libc::c_ulong;
     pub fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
     pub fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
     pub fn strstr(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
     pub fn curl_easy_strerror(_: CURLcode) -> *const libc::c_char;
     pub fn inet_pton(
         __af: libc::c_int,
         __cp: *const libc::c_char,
         __buf: *mut libc::c_void,
     ) -> libc::c_int;
     pub fn inet_ntop(
         __af: libc::c_int,
         __cp: *const libc::c_void,
         __buf: *mut libc::c_char,
         __len: socklen_t,
     ) -> *const libc::c_char;
     pub fn Curl_now() -> curltime;
     pub fn Curl_timediff(t1: curltime, t2: curltime) -> timediff_t;
     pub fn Curl_llist_remove(_: *mut Curl_llist, _: *mut Curl_llist_element, _: *mut libc::c_void);
     pub fn Curl_resolver_wait_resolv(
         data: *mut Curl_easy,
         dnsentry: *mut *mut Curl_dns_entry,
     ) -> CURLcode;
     pub fn Curl_resolv(
         data: *mut Curl_easy,
         hostname: *const libc::c_char,
         port: libc::c_int,
         allowDOH: bool,
         dnsentry: *mut *mut Curl_dns_entry,
     ) -> resolve_t;
     pub fn Curl_resolv_unlock(data: *mut Curl_easy, dns: *mut Curl_dns_entry);
     pub fn Curl_printable_address(
         ip: *const Curl_addrinfo,
         buf: *mut libc::c_char,
         bufsize: size_t,
     );
     pub fn Curl_pp_statemach(
         data: *mut Curl_easy,
         pp: *mut pingpong,
         block: bool,
         disconnecting: bool,
     ) -> CURLcode;
     pub fn Curl_pp_init(data: *mut Curl_easy, pp: *mut pingpong);
     pub fn Curl_pp_setup(pp: *mut pingpong);
     pub fn Curl_pp_state_timeout(
         data: *mut Curl_easy,
         pp: *mut pingpong,
         disconnecting: bool,
     ) -> timediff_t;
     pub fn Curl_pp_sendf(
         data: *mut Curl_easy,
         pp: *mut pingpong,
         fmt: *const libc::c_char,
         _: ...
     ) -> CURLcode;
     pub fn Curl_pp_readresp(
         data: *mut Curl_easy,
         sockfd: curl_socket_t,
         pp: *mut pingpong,
         code: *mut libc::c_int,
         size: *mut size_t,
     ) -> CURLcode;
     pub fn Curl_pp_flushsend(data: *mut Curl_easy, pp: *mut pingpong) -> CURLcode;
     pub fn Curl_pp_disconnect(pp: *mut pingpong) -> CURLcode;
     pub fn Curl_pp_getsock(
         data: *mut Curl_easy,
         pp: *mut pingpong,
         socks: *mut curl_socket_t,
     ) -> libc::c_int;
     pub fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
     pub fn Curl_failf(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
     pub fn Curl_client_write(
         data: *mut Curl_easy,
         type_0: libc::c_int,
         ptr: *mut libc::c_char,
         len: size_t,
     ) -> CURLcode;
     pub fn Curl_ipv6_scope(sa: *const sockaddr) -> libc::c_uint;
     pub fn Curl_if2ip(
         af: libc::c_int,
         remote_scope: libc::c_uint,
         local_scope_id: libc::c_uint,
         interf: *const libc::c_char,
         buf: *mut libc::c_char,
         buf_size: libc::c_int,
     ) -> if2ip_result_t;
     pub fn Curl_pgrsSetDownloadSize(data: *mut Curl_easy, size: curl_off_t);
     pub fn Curl_pgrsSetUploadSize(data: *mut Curl_easy, size: curl_off_t);
     pub fn Curl_pgrsSetDownloadCounter(data: *mut Curl_easy, size: curl_off_t);
     pub fn Curl_pgrsSetUploadCounter(data: *mut Curl_easy, size: curl_off_t);
     pub fn Curl_pgrsUpdate(data: *mut Curl_easy) -> libc::c_int;
     pub fn Curl_pgrsTime(data: *mut Curl_easy, timer: timerid) -> curltime;
     pub fn Curl_setup_transfer(
         data: *mut Curl_easy,
         sockindex: libc::c_int,
         size: curl_off_t,
         getheader: bool,
         writesockindex: libc::c_int,
     );
     pub fn Curl_urldecode(
         data: *mut Curl_easy,
         string: *const libc::c_char,
         length: size_t,
         ostring: *mut *mut libc::c_char,
         olen: *mut size_t,
         ctrl: urlreject,
     ) -> CURLcode;
     // definitions in ftplistparser.rs
     pub fn Curl_ftp_parselist(
         buffer: *mut libc::c_char,
         size: size_t,
         nmemb: size_t,
         connptr: *mut libc::c_void,
     ) -> size_t;
     pub fn Curl_ftp_parselist_geterror(pl_data: *mut ftp_parselist_data) -> CURLcode;
     pub fn Curl_ftp_parselist_data_alloc() -> *mut ftp_parselist_data;
     pub fn Curl_ftp_parselist_data_free(pl_data: *mut *mut ftp_parselist_data);
     pub fn Curl_range(data: *mut Curl_easy) -> CURLcode;
     pub fn curlx_strtoofft(
         str: *const libc::c_char,
         endp: *mut *mut libc::c_char,
         base: libc::c_int,
         num: *mut curl_off_t,
     ) -> CURLofft;
     pub fn Curl_strcasecompare(
         first: *const libc::c_char,
         second: *const libc::c_char,
     ) -> libc::c_int;
     pub fn Curl_raw_toupper(in_0: libc::c_char) -> libc::c_char;
     pub fn Curl_is_connected(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         sockindex: libc::c_int,
         connected: *mut bool,
     ) -> CURLcode;
     pub fn Curl_connecthost(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         host: *const Curl_dns_entry,
     ) -> CURLcode;
     pub fn Curl_timeleft(
         data: *mut Curl_easy,
         nowp: *mut curltime,
         duringconnect: bool,
     ) -> timediff_t;
     pub fn Curl_socket(
         data: *mut Curl_easy,
         ai: *const Curl_addrinfo,
         addr: *mut Curl_sockaddr_ex,
         sockfd: *mut curl_socket_t,
     ) -> CURLcode;
     pub fn curlx_nonblock(sockfd: curl_socket_t, nonblock: libc::c_int) -> libc::c_int;
     pub fn Curl_conninfo_remote(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         sockfd: curl_socket_t,
     );
     pub fn Curl_closesocket(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         sock: curl_socket_t,
     ) -> libc::c_int;
     #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
     pub fn Curl_conncontrol(conn: *mut connectdata, closeit: libc::c_int);
     #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
     pub fn Curl_conncontrol(
         conn: *mut connectdata,
         closeit: libc::c_int,
         reason: *const libc::c_char,
     );
     pub fn Curl_conn_data_pending(conn: *mut connectdata, sockindex: libc::c_int) -> bool;
     pub fn Curl_strerror(
         err: libc::c_int,
         buf: *mut libc::c_char,
         buflen: size_t,
     ) -> *const libc::c_char;
     pub fn Curl_socket_check(
         readfd: curl_socket_t,
         readfd2: curl_socket_t,
         writefd: curl_socket_t,
         timeout_ms: timediff_t,
     ) -> libc::c_int;
     pub fn Curl_gmtime(intime: time_t, store: *mut tm) -> CURLcode;
     pub fn Curl_getdate_capped(p: *const libc::c_char) -> time_t;
     pub fn Curl_expire(data: *mut Curl_easy, milli: timediff_t, _: expire_id);
     pub fn Curl_set_in_callback(data: *mut Curl_easy, value: bool);
     pub fn curlx_ultous(ulnum: libc::c_ulong) -> libc::c_ushort;
     pub fn curlx_sltosi(slnum: libc::c_long) -> libc::c_int;
     pub fn curlx_sotouz(sonum: curl_off_t) -> size_t;
     pub fn Curl_proxyCONNECT(
         data: *mut Curl_easy,
         tunnelsocket: libc::c_int,
         hostname: *const libc::c_char,
         remote_port: libc::c_int,
     ) -> CURLcode;
     pub fn Curl_proxy_connect(data: *mut Curl_easy, sockindex: libc::c_int) -> CURLcode;
     pub fn Curl_connect_ongoing(conn: *mut connectdata) -> bool;
     pub fn Curl_SOCKS_getsock(
         conn: *mut connectdata,
         sock: *mut curl_socket_t,
         sockindex: libc::c_int,
     ) -> libc::c_int;
     pub fn curl_msnprintf(
         buffer: *mut libc::c_char,
         maxlength: size_t,
         format: *const libc::c_char,
         _: ...
     ) -> libc::c_int;
     pub fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
     pub fn Curl_isalnum(c: libc::c_int) -> libc::c_int;
     pub fn Curl_isspace(c: libc::c_int) -> libc::c_int;
     pub fn Curl_llist_insert_next(
         _: *mut Curl_llist,
         _: *mut Curl_llist_element,
         _: *const libc::c_void,
         node: *mut Curl_llist_element,
     );
     pub fn Curl_fileinfo_alloc() -> *mut fileinfo;
     pub fn Curl_fileinfo_cleanup(finfo: *mut fileinfo);
     pub fn Curl_fnmatch(
         ptr: *mut libc::c_void,
         pattern: *const libc::c_char,
         string: *const libc::c_char,
     ) -> libc::c_int;
     // http_aws_sigv4.rs
     pub fn time(__timer: *mut time_t) -> time_t;
     pub fn strftime(
         __s: *mut libc::c_char,
         __maxsize: size_t,
         __format: *const libc::c_char,
         __tp: *const tm,
     ) -> size_t;
     pub fn Curl_http_method(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         method: *mut *const libc::c_char,
         _: *mut Curl_HttpReq,
     );
     pub fn Curl_strntoupper(dest: *mut libc::c_char, src: *const libc::c_char, n: size_t);
     pub fn Curl_strntolower(dest: *mut libc::c_char, src: *const libc::c_char, n: size_t);
     pub fn Curl_memdup(src: *const libc::c_void, buffer_length: size_t) -> *mut libc::c_void;
     pub fn Curl_sha256it(outbuffer: *mut libc::c_uchar, input: *const libc::c_uchar, len: size_t);
     pub fn Curl_hmacit(
         hashparams: *const HMAC_params,
         key: *const libc::c_uchar,
         keylen: size_t,
         data: *const libc::c_uchar,
         datalen: size_t,
         output: *mut libc::c_uchar,
     ) -> CURLcode;
     pub fn Curl_checkheaders(
         data: *const Curl_easy,
         thisheader: *const libc::c_char,
     ) -> *mut libc::c_char;
     // http_proxy.rs
     pub fn curl_strnequal(
         s1: *const libc::c_char,
         s2: *const libc::c_char,
         n: size_t,
     ) -> libc::c_int;
     pub fn Curl_httpchunk_init(data: *mut Curl_easy);
     pub fn Curl_httpchunk_read(
         data: *mut Curl_easy,
         datap: *mut libc::c_char,
         length: ssize_t,
         wrote: *mut ssize_t,
         passthru: *mut CURLcode,
     ) -> CHUNKcode;
     pub fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
     pub fn Curl_dyn_free(s: *mut dynbuf);
     pub fn Curl_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
     pub fn Curl_dyn_add(s: *mut dynbuf, str: *const libc::c_char) -> CURLcode;
     pub fn Curl_dyn_addf(s: *mut dynbuf, fmt: *const libc::c_char, _: ...) -> CURLcode;
     pub fn Curl_dyn_reset(s: *mut dynbuf);
     pub fn Curl_dyn_ptr(s: *const dynbuf) -> *mut libc::c_char;
     pub fn Curl_dyn_len(s: *const dynbuf) -> size_t;
     pub fn Curl_compareheader(
         headerline: *const libc::c_char,
         header: *const libc::c_char,
         content: *const libc::c_char,
     ) -> bool;
     pub fn Curl_copy_header_value(header: *const libc::c_char) -> *mut libc::c_char;
     pub fn Curl_checkProxyheaders(
         data: *mut Curl_easy,
         conn: *const connectdata,
         thisheader: *const libc::c_char,
     ) -> *mut libc::c_char;
     pub fn Curl_buffer_send(
         in_0: *mut dynbuf,
         data: *mut Curl_easy,
         bytes_written: *mut curl_off_t,
         included_body_bytes: curl_off_t,
         socketindex: libc::c_int,
     ) -> CURLcode;
     pub fn Curl_http_input_auth(
         data: *mut Curl_easy,
         proxy: bool,
         auth: *const libc::c_char,
     ) -> CURLcode;
     pub fn Curl_http_auth_act(data: *mut Curl_easy) -> CURLcode;
     pub fn Curl_http_output_auth(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         request: *const libc::c_char,
         httpreq: Curl_HttpReq,
         path: *const libc::c_char,
         proxytunnel: bool,
     ) -> CURLcode;
     pub fn Curl_read(
         data: *mut Curl_easy,
         sockfd: curl_socket_t,
         buf: *mut libc::c_char,
         buffersize: size_t,
         n: *mut ssize_t,
     ) -> CURLcode;
     pub fn Curl_write(
         data: *mut Curl_easy,
         sockfd: curl_socket_t,
         mem: *const libc::c_void,
         len: size_t,
         written: *mut ssize_t,
     ) -> CURLcode;
     pub fn Curl_debug(
         data: *mut Curl_easy,
         type_0: curl_infotype,
         ptr: *mut libc::c_char,
         size: size_t,
     ) -> libc::c_int;
     pub fn Curl_fillreadbuffer(
         data: *mut Curl_easy,
         bytes: size_t,
         nreadp: *mut size_t,
     ) -> CURLcode;
     pub fn Curl_get_upload_buffer(data: *mut Curl_easy) -> CURLcode;
     pub fn Curl_isxdigit(c: libc::c_int) -> libc::c_int;
     pub fn Curl_unencode_write(
         data: *mut Curl_easy,
         writer: *mut contenc_writer,
         buf: *const libc::c_char,
         nbytes: size_t,
     ) -> CURLcode;
 
     // http.rs
     pub fn curl_url_cleanup(handle: *mut CURLU);
     pub fn curl_url_dup(in_0: *mut CURLU) -> *mut CURLU;
     pub fn curl_url_get(
         handle: *mut CURLU,
         what: CURLUPart,
         part: *mut *mut libc::c_char,
         flags: libc::c_uint,
     ) -> CURLUcode;
     pub fn curl_url_set(
         handle: *mut CURLU,
         what: CURLUPart,
         part: *const libc::c_char,
         flags: libc::c_uint,
     ) -> CURLUcode;
     pub fn memmove(
         _: *mut libc::c_void,
         _: *const libc::c_void,
         _: libc::c_ulong,
     ) -> *mut libc::c_void;
     pub fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
     pub fn curl_mime_headers(
         part: *mut curl_mimepart,
         headers: *mut curl_slist,
         take_ownership: libc::c_int,
     ) -> CURLcode;
     pub fn Curl_mime_initpart(part: *mut curl_mimepart, easy: *mut Curl_easy);
     pub fn Curl_mime_cleanpart(part: *mut curl_mimepart);
     pub fn Curl_mime_prepare_headers(
         part: *mut curl_mimepart,
         contenttype: *const libc::c_char,
         disposition: *const libc::c_char,
         strategy: mimestrategy,
     ) -> CURLcode;
     pub fn Curl_mime_size(part: *mut curl_mimepart) -> curl_off_t;
     pub fn Curl_mime_read(
         buffer: *mut libc::c_char,
         size: size_t,
         nitems: size_t,
         instream: *mut libc::c_void,
     ) -> size_t;
     pub fn Curl_mime_rewind(part: *mut curl_mimepart) -> CURLcode;
     pub fn Curl_cookie_freelist(cookies: *mut Cookie);
     pub fn Curl_cookie_getlist(
         c: *mut CookieInfo,
         host: *const libc::c_char,
         path: *const libc::c_char,
         secure: bool,
     ) -> *mut Cookie;
     pub fn Curl_cookie_add(
         data: *mut Curl_easy,
         c: *mut CookieInfo,
         header: bool,
         noexpiry: bool,
         lineptr: *mut libc::c_char,
         domain: *const libc::c_char,
         path: *const libc::c_char,
         secure: bool,
     ) -> *mut Cookie;
     pub fn Curl_getformdata(
         data: *mut Curl_easy,
         _: *mut curl_mimepart,
         post: *mut curl_httppost,
         fread_func: curl_read_callback,
     ) -> CURLcode;
     pub fn Curl_rtsp_parseheader(data: *mut Curl_easy, header: *mut libc::c_char) -> CURLcode;
     pub fn Curl_readrewind(data: *mut Curl_easy) -> CURLcode;
     pub fn Curl_meets_timecondition(data: *mut Curl_easy, timeofdoc: time_t) -> bool;
     pub fn Curl_done_sending(data: *mut Curl_easy, k: *mut SingleRequest) -> CURLcode;
     pub fn Curl_base64_encode(
         data: *mut Curl_easy,
         inputbuff: *const libc::c_char,
         insize: size_t,
         outptr: *mut *mut libc::c_char,
         outlen: *mut size_t,
     ) -> CURLcode;
     pub fn Curl_auth_is_digest_supported() -> bool;
     pub fn Curl_input_digest(
         data: *mut Curl_easy,
         proxy: bool,
         header: *const libc::c_char,
     ) -> CURLcode;
     pub fn Curl_output_digest(
         data: *mut Curl_easy,
         proxy: bool,
         request: *const libc::c_uchar,
         uripath: *const libc::c_uchar,
     ) -> CURLcode;
     pub fn Curl_output_aws_sigv4(data: *mut Curl_easy, proxy: bool) -> CURLcode;
     pub fn Curl_share_lock(_: *mut Curl_easy, _: curl_lock_data, _: curl_lock_access)
         -> CURLSHcode;
     pub fn Curl_share_unlock(_: *mut Curl_easy, _: curl_lock_data) -> CURLSHcode;
     pub fn Curl_expire_done(data: *mut Curl_easy, id: expire_id);
     pub fn Curl_strncasecompare(
         first: *const libc::c_char,
         second: *const libc::c_char,
         max: size_t,
     ) -> libc::c_int;
     pub fn Curl_build_unencoding_stack(
         data: *mut Curl_easy,
         enclist: *const libc::c_char,
         maybechunked: libc::c_int,
     ) -> CURLcode;
     pub fn Curl_unencode_cleanup(data: *mut Curl_easy);
     pub fn curlx_uitous(uinum: libc::c_uint) -> libc::c_ushort;
     pub fn Curl_http2_request_upgrade(req: *mut dynbuf, data: *mut Curl_easy) -> CURLcode;
     pub fn Curl_http2_setup(data: *mut Curl_easy, conn: *mut connectdata) -> CURLcode;
     pub fn Curl_http2_switched(
         data: *mut Curl_easy,
         ptr: *const libc::c_char,
         nread: size_t,
     ) -> CURLcode;
     pub fn Curl_http2_setup_conn(conn: *mut connectdata);
     pub fn Curl_http2_setup_req(data: *mut Curl_easy);
     pub fn Curl_http2_done(data: *mut Curl_easy, premature: bool);
     pub fn Curl_altsvc_parse(
         data: *mut Curl_easy,
         altsvc: *mut altsvcinfo,
         value: *const libc::c_char,
         srcalpn: alpnid,
         srchost: *const libc::c_char,
         srcport: libc::c_ushort,
     ) -> CURLcode;
     // http_digest.rs
     pub fn Curl_auth_decode_digest_http_message(
         chlg: *const libc::c_char,
         digest: *mut digestdata,
     ) -> CURLcode;
     pub fn Curl_auth_create_digest_http_message(
         data: *mut Curl_easy,
         userp: *const libc::c_char,
         passwdp: *const libc::c_char,
         request: *const libc::c_uchar,
         uri: *const libc::c_uchar,
         digest: *mut digestdata,
         outptr: *mut *mut libc::c_char,
         outlen: *mut size_t,
     ) -> CURLcode;
     pub fn Curl_auth_digest_cleanup(digest: *mut digestdata);
 
     // http2.rs
     pub fn curl_easy_duphandle(curl: *mut CURL) -> *mut CURL;
     pub fn curl_url() -> *mut CURLU;
     pub fn nghttp2_session_callbacks_new(
         callbacks_ptr: *mut *mut nghttp2_session_callbacks,
     ) -> libc::c_int;
     pub fn nghttp2_session_callbacks_del(callbacks: *mut nghttp2_session_callbacks);
     pub fn nghttp2_session_callbacks_set_send_callback(
         cbs: *mut nghttp2_session_callbacks,
         send_callback_0: nghttp2_send_callback,
     );
     pub fn nghttp2_session_callbacks_set_on_frame_recv_callback(
         cbs: *mut nghttp2_session_callbacks,
         on_frame_recv_callback: nghttp2_on_frame_recv_callback,
     );
     pub fn nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
         cbs: *mut nghttp2_session_callbacks,
         on_data_chunk_recv_callback: nghttp2_on_data_chunk_recv_callback,
     );
     pub fn nghttp2_session_callbacks_set_on_stream_close_callback(
         cbs: *mut nghttp2_session_callbacks,
         on_stream_close_callback: nghttp2_on_stream_close_callback,
     );
     pub fn nghttp2_session_callbacks_set_on_begin_headers_callback(
         cbs: *mut nghttp2_session_callbacks,
         on_begin_headers_callback: nghttp2_on_begin_headers_callback,
     );
     pub fn nghttp2_session_callbacks_set_on_header_callback(
         cbs: *mut nghttp2_session_callbacks,
         on_header_callback: nghttp2_on_header_callback,
     );
     pub fn nghttp2_session_callbacks_set_error_callback(
         cbs: *mut nghttp2_session_callbacks,
         error_callback_0: nghttp2_error_callback,
     );
     pub fn nghttp2_session_client_new(
         session_ptr: *mut *mut nghttp2_session,
         callbacks: *const nghttp2_session_callbacks,
         user_data: *mut libc::c_void,
     ) -> libc::c_int;
     pub fn nghttp2_session_del(session: *mut nghttp2_session);
     pub fn nghttp2_session_send(session: *mut nghttp2_session) -> libc::c_int;
     pub fn nghttp2_session_mem_recv(
         session: *mut nghttp2_session,
         in_0: *const uint8_t,
         inlen: size_t,
     ) -> ssize_t;
     pub fn nghttp2_session_resume_data(
         session: *mut nghttp2_session,
         stream_id: int32_t,
     ) -> libc::c_int;
     pub fn nghttp2_session_want_read(session: *mut nghttp2_session) -> libc::c_int;
     pub fn nghttp2_session_want_write(session: *mut nghttp2_session) -> libc::c_int;
     pub fn nghttp2_session_get_stream_user_data(
         session: *mut nghttp2_session,
         stream_id: int32_t,
     ) -> *mut libc::c_void;
     pub fn nghttp2_session_set_stream_user_data(
         session: *mut nghttp2_session,
         stream_id: int32_t,
         stream_user_data: *mut libc::c_void,
     ) -> libc::c_int;
     pub fn nghttp2_session_get_remote_settings(
         session: *mut nghttp2_session,
         id: nghttp2_settings_id,
     ) -> uint32_t;
     pub fn nghttp2_session_upgrade2(
         session: *mut nghttp2_session,
         settings_payload: *const uint8_t,
         settings_payloadlen: size_t,
         head_request: libc::c_int,
         stream_user_data: *mut libc::c_void,
     ) -> libc::c_int;
     pub fn nghttp2_pack_settings_payload(
         buf: *mut uint8_t,
         buflen: size_t,
         iv: *const nghttp2_settings_entry,
         niv: size_t,
     ) -> ssize_t;
     pub fn nghttp2_strerror(lib_error_code: libc::c_int) -> *const libc::c_char;
     pub fn nghttp2_http2_strerror(error_code: uint32_t) -> *const libc::c_char;
     pub fn nghttp2_priority_spec_init(
         pri_spec: *mut nghttp2_priority_spec,
         stream_id: int32_t,
         weight: int32_t,
         exclusive: libc::c_int,
     );
     pub fn nghttp2_submit_request(
         session: *mut nghttp2_session,
         pri_spec: *const nghttp2_priority_spec,
         nva: *const nghttp2_nv,
         nvlen: size_t,
         data_prd: *const nghttp2_data_provider,
         stream_user_data: *mut libc::c_void,
     ) -> int32_t;
     pub fn nghttp2_submit_priority(
         session: *mut nghttp2_session,
         flags: uint8_t,
         stream_id: int32_t,
         pri_spec: *const nghttp2_priority_spec,
     ) -> libc::c_int;
     pub fn nghttp2_submit_rst_stream(
         session: *mut nghttp2_session,
         flags: uint8_t,
         stream_id: int32_t,
         error_code: uint32_t,
     ) -> libc::c_int;
     pub fn nghttp2_submit_settings(
         session: *mut nghttp2_session,
         flags: uint8_t,
         iv: *const nghttp2_settings_entry,
         niv: size_t,
     ) -> libc::c_int;
     pub fn nghttp2_submit_ping(
         session: *mut nghttp2_session,
         flags: uint8_t,
         opaque_data: *const uint8_t,
     ) -> libc::c_int;
     pub fn nghttp2_session_check_request_allowed(session: *mut nghttp2_session) -> libc::c_int;
     pub fn nghttp2_session_set_local_window_size(
         session: *mut nghttp2_session,
         flags: uint8_t,
         stream_id: int32_t,
         window_size: int32_t,
     ) -> libc::c_int;
    pub fn nghttp2_session_get_stream_local_window_size(
        session: *mut nghttp2_session,
        stream_id: int32_t,
    ) -> int32_t;
     pub fn nghttp2_is_fatal(lib_error_code: libc::c_int) -> libc::c_int;
     pub fn nghttp2_version(least_version: libc::c_int) -> *mut nghttp2_info;
     pub fn Curl_http(data: *mut Curl_easy, done: *mut bool) -> CURLcode;
     pub fn Curl_http_done(data: *mut Curl_easy, _: CURLcode, premature: bool) -> CURLcode;
     pub fn Curl_base64url_encode(
         data: *mut Curl_easy,
         inputbuff: *const libc::c_char,
         insize: size_t,
         outptr: *mut *mut libc::c_char,
         outlen: *mut size_t,
     ) -> CURLcode;
     pub fn Curl_multi_add_perform(
         multi: *mut Curl_multi,
         data: *mut Curl_easy,
         conn: *mut connectdata,
     ) -> CURLMcode;
     pub fn Curl_multi_max_concurrent_streams(multi: *mut Curl_multi) -> libc::c_uint;
     pub fn Curl_close(datap: *mut *mut Curl_easy) -> CURLcode;
     pub fn Curl_connalive(conn: *mut connectdata) -> bool;
     pub fn Curl_saferealloc(ptr: *mut libc::c_void, size: size_t) -> *mut libc::c_void;
 
     // mbedtls ftp
 
     pub fn Curl_ssl_connect(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         sockindex: libc::c_int,
     ) -> CURLcode;
     pub fn Curl_ssl_close(data: *mut Curl_easy, conn: *mut connectdata, sockindex: libc::c_int);
     pub fn Curl_ssl_shutdown(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         sockindex: libc::c_int,
     ) -> CURLcode;
 
     // http_ntlm.rs
     pub fn curl_free(p: *mut libc::c_void);
     pub fn Curl_http_auth_cleanup_ntlm_wb(conn: *mut connectdata);
     pub fn Curl_base64_decode(
         src: *const libc::c_char,
         outptr: *mut *mut libc::c_uchar,
         outlen: *mut size_t,
     ) -> CURLcode;
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
     #[cfg(USE_NTLM)]
     pub fn Curl_auth_create_ntlm_type1_message(
         data: *mut Curl_easy,
         userp: *const libc::c_char,
         passwdp: *const libc::c_char,
         service: *const libc::c_char,
         host: *const libc::c_char,
         ntlm: *mut ntlmdata,
         out: *mut bufref,
     ) -> CURLcode;
     #[cfg(USE_NTLM)]
     pub fn Curl_auth_decode_ntlm_type2_message(
         data: *mut Curl_easy,
         type2: *const bufref,
         ntlm: *mut ntlmdata,
     ) -> CURLcode;
     #[cfg(USE_NTLM)]
     pub fn Curl_auth_create_ntlm_type3_message(
         data: *mut Curl_easy,
         userp: *const libc::c_char,
         passwdp: *const libc::c_char,
         ntlm: *mut ntlmdata,
         out: *mut bufref,
     ) -> CURLcode;
     #[cfg(USE_NTLM)]
     pub fn Curl_auth_cleanup_ntlm(ntlm: *mut ntlmdata);
 
     // new http_proxy.rs
     pub fn Curl_ssl_connect_nonblocking(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         isproxy: bool,
         sockindex: libc::c_int,
         done: *mut bool,
     ) -> CURLcode;
 
     // http.rs
     pub fn Curl_auth_is_ntlm_supported() -> bool;
     pub fn Curl_input_ntlm(
         data: *mut Curl_easy,
         proxy: bool,
         header: *const libc::c_char,
     ) -> CURLcode;
     pub fn Curl_output_ntlm(data: *mut Curl_easy, proxy: bool) -> CURLcode;
     pub fn Curl_input_ntlm_wb(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         proxy: bool,
         header: *const libc::c_char,
     ) -> CURLcode;
     pub fn Curl_output_ntlm_wb(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         proxy: bool,
     ) -> CURLcode;
     pub fn Curl_hsts_parse(
         h: *mut hsts,
         hostname: *const libc::c_char,
         sts: *const libc::c_char,
     ) -> CURLcode;
     pub fn Curl_auth_is_spnego_supported() -> bool;
     pub fn Curl_input_negotiate(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         proxy: bool,
         header: *const libc::c_char,
     ) -> CURLcode;
     pub fn Curl_output_negotiate(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         proxy: bool,
     ) -> CURLcode;
 
     // mbedtls vtls.rs
     pub fn fread(
         _: *mut libc::c_void,
         _: libc::c_ulong,
         _: libc::c_ulong,
         _: *mut FILE,
     ) -> libc::c_ulong;
     pub fn fseek(__stream: *mut FILE, __off: libc::c_long, __whence: libc::c_int) -> libc::c_int;
     pub fn ftell(__stream: *mut FILE) -> libc::c_long;
 
     pub fn curl_slist_free_all(_: *mut curl_slist);
     pub fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
 
     pub fn Curl_slist_append_nodup(
         list: *mut curl_slist,
         data: *mut libc::c_char,
     ) -> *mut curl_slist;
     pub fn Curl_recv_plain(
         data: *mut Curl_easy,
         num: libc::c_int,
         buf: *mut libc::c_char,
         len: size_t,
         code: *mut CURLcode,
     ) -> ssize_t;
     pub fn Curl_send_plain(
         data: *mut Curl_easy,
         num: libc::c_int,
         mem: *const libc::c_void,
         len: size_t,
         code: *mut CURLcode,
     ) -> ssize_t;
 
     // mbedtls_threadlock.rs
     pub fn pthread_mutex_init(
         __mutex: *mut pthread_mutex_t,
         __mutexattr: *const pthread_mutexattr_t,
     ) -> libc::c_int;
     pub fn pthread_mutex_destroy(__mutex: *mut pthread_mutex_t) -> libc::c_int;
     pub fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
     pub fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
 
     // mbedtls.rs
     pub fn mbedtls_version_get_number() -> libc::c_uint;
     pub fn mbedtls_net_send(
         ctx: *mut libc::c_void,
         buf: *const libc::c_uchar,
         len: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_net_recv(
         ctx: *mut libc::c_void,
         buf: *mut libc::c_uchar,
         len: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_session_free(session: *mut mbedtls_ssl_session);
     pub fn mbedtls_ssl_session_init(session: *mut mbedtls_ssl_session);
     pub fn mbedtls_ssl_config_free(conf: *mut mbedtls_ssl_config);
     pub fn mbedtls_ssl_config_defaults(
         conf: *mut mbedtls_ssl_config,
         endpoint: libc::c_int,
         transport: libc::c_int,
         preset: libc::c_int,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_config_init(conf: *mut mbedtls_ssl_config);
     pub fn mbedtls_ssl_free(ssl: *mut mbedtls_ssl_context);
     pub fn mbedtls_ssl_write(
         ssl: *mut mbedtls_ssl_context,
         buf: *const libc::c_uchar,
         len: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_read(
         ssl: *mut mbedtls_ssl_context,
         buf: *mut libc::c_uchar,
         len: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_handshake(ssl: *mut mbedtls_ssl_context) -> libc::c_int;
     pub fn mbedtls_ssl_get_session(
         ssl: *const mbedtls_ssl_context,
         session: *mut mbedtls_ssl_session,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_get_peer_cert(ssl: *const mbedtls_ssl_context) -> *const mbedtls_x509_crt;
     pub fn mbedtls_ssl_get_ciphersuite(ssl: *const mbedtls_ssl_context) -> *const libc::c_char;
     pub fn mbedtls_ssl_get_verify_result(ssl: *const mbedtls_ssl_context) -> uint32_t;
     pub fn mbedtls_ssl_get_bytes_avail(ssl: *const mbedtls_ssl_context) -> size_t;
     pub fn mbedtls_ssl_conf_renegotiation(
         conf: *mut mbedtls_ssl_config,
         renegotiation: libc::c_int,
     );
     pub fn mbedtls_ssl_conf_session_tickets(
         conf: *mut mbedtls_ssl_config,
         use_tickets: libc::c_int,
     );
     pub fn mbedtls_ssl_conf_min_version(
         conf: *mut mbedtls_ssl_config,
         major: libc::c_int,
         minor: libc::c_int,
     );
     pub fn mbedtls_ssl_conf_max_version(
         conf: *mut mbedtls_ssl_config,
         major: libc::c_int,
         minor: libc::c_int,
     );
     pub fn mbedtls_ssl_get_alpn_protocol(ssl: *const mbedtls_ssl_context) -> *const libc::c_char;
     pub fn mbedtls_ssl_conf_alpn_protocols(
         conf: *mut mbedtls_ssl_config,
         protos: *mut *const libc::c_char,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_set_hostname(
         ssl: *mut mbedtls_ssl_context,
         hostname: *const libc::c_char,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_conf_own_cert(
         conf: *mut mbedtls_ssl_config,
         own_cert: *mut mbedtls_x509_crt,
         pk_key: *mut mbedtls_pk_context,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_conf_ca_chain(
         conf: *mut mbedtls_ssl_config,
         ca_chain: *mut mbedtls_x509_crt,
         ca_crl: *mut mbedtls_x509_crl,
     );
     pub fn mbedtls_ssl_conf_cert_profile(
         conf: *mut mbedtls_ssl_config,
         profile: *const mbedtls_x509_crt_profile,
     );
     pub fn mbedtls_ssl_conf_ciphersuites(
         conf: *mut mbedtls_ssl_config,
         ciphersuites: *const libc::c_int,
     );
     pub fn mbedtls_ssl_set_session(
         ssl: *mut mbedtls_ssl_context,
         session: *const mbedtls_ssl_session,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_set_bio(
         ssl: *mut mbedtls_ssl_context,
         p_bio: *mut libc::c_void,
         f_send: Option<mbedtls_ssl_send_t>,
         f_recv: Option<mbedtls_ssl_recv_t>,
         f_recv_timeout: Option<mbedtls_ssl_recv_timeout_t>,
     );
     pub fn mbedtls_ssl_conf_rng(
         conf: *mut mbedtls_ssl_config,
         f_rng: Option<
             unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_uchar, size_t) -> libc::c_int,
         >,
         p_rng: *mut libc::c_void,
     );
     pub fn mbedtls_ssl_conf_authmode(conf: *mut mbedtls_ssl_config, authmode: libc::c_int);
     pub fn mbedtls_ssl_setup(
         ssl: *mut mbedtls_ssl_context,
         conf: *const mbedtls_ssl_config,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_init(ssl: *mut mbedtls_ssl_context);
     pub fn mbedtls_pk_init(ctx: *mut mbedtls_pk_context);
     pub fn mbedtls_pk_free(ctx: *mut mbedtls_pk_context);
     pub fn mbedtls_pk_can_do(
         ctx: *const mbedtls_pk_context,
         type_0: mbedtls_pk_type_t,
     ) -> libc::c_int;
     pub fn mbedtls_pk_parse_key(
         ctx: *mut mbedtls_pk_context,
         key: *const libc::c_uchar,
         keylen: size_t,
         pwd: *const libc::c_uchar,
         pwdlen: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_pk_parse_keyfile(
         ctx: *mut mbedtls_pk_context,
         path: *const libc::c_char,
         password: *const libc::c_char,
     ) -> libc::c_int;
     pub fn mbedtls_pk_write_pubkey_der(
         ctx: *mut mbedtls_pk_context,
         buf: *mut libc::c_uchar,
         size: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_ssl_list_ciphersuites() -> *const libc::c_int;
     pub fn mbedtls_x509_crl_parse_file(
         chain: *mut mbedtls_x509_crl,
         path: *const libc::c_char,
     ) -> libc::c_int;
     pub fn mbedtls_x509_crl_init(crl: *mut mbedtls_x509_crl);
     pub fn mbedtls_x509_crl_free(crl: *mut mbedtls_x509_crl);
     pub fn mbedtls_x509_crt_parse_der(
         chain: *mut mbedtls_x509_crt,
         buf: *const libc::c_uchar,
         buflen: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_x509_crt_parse(
         chain: *mut mbedtls_x509_crt,
         buf: *const libc::c_uchar,
         buflen: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_x509_crt_parse_file(
         chain: *mut mbedtls_x509_crt,
         path: *const libc::c_char,
     ) -> libc::c_int;
     pub fn mbedtls_x509_crt_parse_path(
         chain: *mut mbedtls_x509_crt,
         path: *const libc::c_char,
     ) -> libc::c_int;
     pub fn mbedtls_x509_crt_info(
         buf: *mut libc::c_char,
         size: size_t,
         prefix: *const libc::c_char,
         crt: *const mbedtls_x509_crt,
     ) -> libc::c_int;
     pub fn mbedtls_x509_crt_init(crt: *mut mbedtls_x509_crt);
     pub fn mbedtls_x509_crt_free(crt: *mut mbedtls_x509_crt);
     pub fn mbedtls_strerror(errnum: libc::c_int, buffer: *mut libc::c_char, buflen: size_t);
     pub fn mbedtls_entropy_init(ctx: *mut mbedtls_entropy_context);
     pub fn mbedtls_entropy_free(ctx: *mut mbedtls_entropy_context);
     pub fn mbedtls_entropy_func(
         data: *mut libc::c_void,
         output: *mut libc::c_uchar,
         len: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_ctr_drbg_init(ctx: *mut mbedtls_ctr_drbg_context);
     pub fn mbedtls_ctr_drbg_seed(
         ctx: *mut mbedtls_ctr_drbg_context,
         f_entropy: Option<
             unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_uchar, size_t) -> libc::c_int,
         >,
         p_entropy: *mut libc::c_void,
         custom: *const libc::c_uchar,
         len: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_ctr_drbg_free(ctx: *mut mbedtls_ctr_drbg_context);
     pub fn mbedtls_ctr_drbg_random(
         p_rng: *mut libc::c_void,
         output: *mut libc::c_uchar,
         output_len: size_t,
     ) -> libc::c_int;
     pub fn mbedtls_sha256_ret(
         input: *const libc::c_uchar,
         ilen: size_t,
         output: *mut libc::c_uchar,
         is224: libc::c_int,
     ) -> libc::c_int;
     pub fn Curl_multiuse_state(data: *mut Curl_easy, bundlestate: libc::c_int);
     pub fn Curl_mbedtlsthreadlock_thread_setup() -> libc::c_int;
     pub fn Curl_mbedtlsthreadlock_thread_cleanup() -> libc::c_int;
     pub fn Curl_mbedtlsthreadlock_lock_function(n: libc::c_int) -> libc::c_int;
     pub fn Curl_mbedtlsthreadlock_unlock_function(n: libc::c_int) -> libc::c_int;
 
     // gnutls gnutls.rs
     pub fn send(
         __fd: libc::c_int,
         __buf: *const libc::c_void,
         __n: size_t,
         __flags: libc::c_int,
     ) -> ssize_t;
     pub fn recv(
         __fd: libc::c_int,
         __buf: *mut libc::c_void,
         __n: size_t,
         __flags: libc::c_int,
     ) -> ssize_t;
     pub fn gnutls_pk_algorithm_get_name(algorithm: gnutls_pk_algorithm_t) -> *const libc::c_char;
     pub fn gnutls_init(session: *mut gnutls_session_t, flags: libc::c_uint) -> libc::c_int;
     pub fn gnutls_deinit(session: gnutls_session_t);
     pub fn gnutls_bye(session: gnutls_session_t, how: gnutls_close_request_t) -> libc::c_int;
     pub fn gnutls_handshake(session: gnutls_session_t) -> libc::c_int;
     pub fn gnutls_alert_get(session: gnutls_session_t) -> gnutls_alert_description_t;
     pub fn gnutls_alert_get_name(alert: gnutls_alert_description_t) -> *const libc::c_char;
     pub fn gnutls_cipher_get(session: gnutls_session_t) -> gnutls_cipher_algorithm_t;
     pub fn gnutls_kx_get(session: gnutls_session_t) -> gnutls_kx_algorithm_t;
     pub fn gnutls_mac_get(session: gnutls_session_t) -> gnutls_mac_algorithm_t;
     pub fn gnutls_error_is_fatal(error: libc::c_int) -> libc::c_int;
     pub fn gnutls_strerror(error: libc::c_int) -> *const libc::c_char;
     pub fn gnutls_record_send(
         session: gnutls_session_t,
         data: *const libc::c_void,
         data_size: size_t,
     ) -> ssize_t;
     pub fn gnutls_record_recv(
         session: gnutls_session_t,
         data: *mut libc::c_void,
         data_size: size_t,
     ) -> ssize_t;
     pub fn gnutls_record_get_direction(session: gnutls_session_t) -> libc::c_int;
     pub fn gnutls_record_check_pending(session: gnutls_session_t) -> size_t;
     pub fn gnutls_server_name_set(
         session: gnutls_session_t,
         type_0: gnutls_server_name_type_t,
         name: *const libc::c_void,
         name_length: size_t,
     ) -> libc::c_int;
     pub fn gnutls_alpn_get_selected_protocol(
         session: gnutls_session_t,
         protocol: *mut gnutls_datum_t,
     ) -> libc::c_int;
     pub fn gnutls_alpn_set_protocols(
         session: gnutls_session_t,
         protocols: *const gnutls_datum_t,
         protocols_size: libc::c_uint,
         flags: libc::c_uint,
     ) -> libc::c_int;
     pub fn gnutls_priority_set_direct(
         session: gnutls_session_t,
         priorities: *const libc::c_char,
         err_pos: *mut *const libc::c_char,
     ) -> libc::c_int;
     pub fn gnutls_set_default_priority(session: gnutls_session_t) -> libc::c_int;
     pub fn gnutls_cipher_suite_get_name(
         kx_algorithm: gnutls_kx_algorithm_t,
         cipher_algorithm: gnutls_cipher_algorithm_t,
         mac_algorithm: gnutls_mac_algorithm_t,
     ) -> *const libc::c_char;
     pub fn gnutls_protocol_get_version(session: gnutls_session_t) -> gnutls_protocol_t;
     pub fn gnutls_protocol_get_name(version: gnutls_protocol_t) -> *const libc::c_char;
     pub fn gnutls_session_set_data(
         session: gnutls_session_t,
         session_data: *const libc::c_void,
         session_data_size: size_t,
     ) -> libc::c_int;
     pub fn gnutls_session_get_data(
         session: gnutls_session_t,
         session_data: *mut libc::c_void,
         session_data_size: *mut size_t,
     ) -> libc::c_int;
     pub fn gnutls_check_version(req_version: *const libc::c_char) -> *const libc::c_char;
     pub fn gnutls_credentials_set(
         session: gnutls_session_t,
         type_0: gnutls_credentials_type_t,
         cred: *mut libc::c_void,
     ) -> libc::c_int;
     pub fn gnutls_certificate_free_credentials(sc: gnutls_certificate_credentials_t);
     pub fn gnutls_certificate_allocate_credentials(
         res: *mut gnutls_certificate_credentials_t,
     ) -> libc::c_int;
     pub fn gnutls_certificate_set_verify_flags(
         res: gnutls_certificate_credentials_t,
         flags: libc::c_uint,
     );
     pub fn gnutls_certificate_set_x509_trust_file(
         cred: gnutls_certificate_credentials_t,
         cafile: *const libc::c_char,
         type_0: gnutls_x509_crt_fmt_t,
     ) -> libc::c_int;
     pub fn gnutls_certificate_set_x509_trust_dir(
         cred: gnutls_certificate_credentials_t,
         ca_dir: *const libc::c_char,
         type_0: gnutls_x509_crt_fmt_t,
     ) -> libc::c_int;
     pub fn gnutls_certificate_set_x509_crl_file(
         res: gnutls_certificate_credentials_t,
         crlfile: *const libc::c_char,
         type_0: gnutls_x509_crt_fmt_t,
     ) -> libc::c_int;
     pub fn gnutls_certificate_set_x509_key_file(
         res: gnutls_certificate_credentials_t,
         certfile: *const libc::c_char,
         keyfile: *const libc::c_char,
         type_0: gnutls_x509_crt_fmt_t,
     ) -> libc::c_int;
     pub fn gnutls_certificate_set_x509_key_file2(
         res: gnutls_certificate_credentials_t,
         certfile: *const libc::c_char,
         keyfile: *const libc::c_char,
         type_0: gnutls_x509_crt_fmt_t,
         pass: *const libc::c_char,
         flags: libc::c_uint,
     ) -> libc::c_int;
     pub fn gnutls_ocsp_status_request_enable_client(
         session: gnutls_session_t,
         responder_id: *mut gnutls_datum_t,
         responder_id_size: size_t,
         request_extensions: *mut gnutls_datum_t,
     ) -> libc::c_int;
     pub fn gnutls_ocsp_status_request_get(
         session: gnutls_session_t,
         response: *mut gnutls_datum_t,
     ) -> libc::c_int;
     pub fn gnutls_ocsp_status_request_is_checked(
         session: gnutls_session_t,
         flags: libc::c_uint,
     ) -> libc::c_uint;
     pub fn gnutls_global_init() -> libc::c_int;
     pub fn gnutls_global_deinit();
     static mut gnutls_free: gnutls_free_function;
     pub fn gnutls_transport_set_ptr(session: gnutls_session_t, ptr: gnutls_transport_ptr_t);
     pub fn gnutls_transport_set_push_function(
         session: gnutls_session_t,
         push_func: gnutls_push_func,
     );
     pub fn gnutls_transport_set_pull_function(
         session: gnutls_session_t,
         pull_func: gnutls_pull_func,
     );
     pub fn gnutls_srp_free_client_credentials(sc: gnutls_srp_client_credentials_t);
     pub fn gnutls_srp_allocate_client_credentials(
         sc: *mut gnutls_srp_client_credentials_t,
     ) -> libc::c_int;
     pub fn gnutls_srp_set_client_credentials(
         res: gnutls_srp_client_credentials_t,
         username: *const libc::c_char,
         password: *const libc::c_char,
     ) -> libc::c_int;
     pub fn gnutls_certificate_get_peers(
         session: gnutls_session_t,
         list_size: *mut libc::c_uint,
     ) -> *const gnutls_datum_t;
     pub fn gnutls_certificate_verify_peers2(
         session: gnutls_session_t,
         status: *mut libc::c_uint,
     ) -> libc::c_int;
     pub fn gnutls_pubkey_export(
         key: gnutls_pubkey_t,
         format: gnutls_x509_crt_fmt_t,
         output_data: *mut libc::c_void,
         output_data_size: *mut size_t,
     ) -> libc::c_int;
     pub fn gnutls_x509_crt_init(cert: *mut gnutls_x509_crt_t) -> libc::c_int;
     pub fn gnutls_x509_crt_deinit(cert: gnutls_x509_crt_t);
     pub fn gnutls_x509_crt_import(
         cert: gnutls_x509_crt_t,
         data: *const gnutls_datum_t,
         format: gnutls_x509_crt_fmt_t,
     ) -> libc::c_int;
     pub fn gnutls_x509_crt_get_issuer_dn2(
         cert: gnutls_x509_crt_t,
         dn: *mut gnutls_datum_t,
     ) -> libc::c_int;
     pub fn gnutls_x509_crt_get_dn2(cert: gnutls_x509_crt_t, dn: *mut gnutls_datum_t)
         -> libc::c_int;
     pub fn gnutls_x509_crt_get_dn_by_oid(
         cert: gnutls_x509_crt_t,
         oid: *const libc::c_char,
         indx: libc::c_uint,
         raw_flag: libc::c_uint,
         buf: *mut libc::c_void,
         buf_size: *mut size_t,
     ) -> libc::c_int;
     pub fn gnutls_x509_crt_check_hostname(
         cert: gnutls_x509_crt_t,
         hostname: *const libc::c_char,
     ) -> libc::c_uint;
     pub fn gnutls_x509_crt_get_version(cert: gnutls_x509_crt_t) -> libc::c_int;
     pub fn gnutls_x509_crt_get_activation_time(cert: gnutls_x509_crt_t) -> time_t;
     pub fn gnutls_x509_crt_get_expiration_time(cert: gnutls_x509_crt_t) -> time_t;
     pub fn gnutls_x509_crt_get_pk_algorithm(
         cert: gnutls_x509_crt_t,
         bits: *mut libc::c_uint,
     ) -> libc::c_int;
     pub fn gnutls_x509_crt_check_issuer(
         cert: gnutls_x509_crt_t,
         issuer: gnutls_x509_crt_t,
     ) -> libc::c_uint;
     pub fn gnutls_pubkey_import_x509(
         key: gnutls_pubkey_t,
         crt: gnutls_x509_crt_t,
         flags: libc::c_uint,
     ) -> libc::c_int;
     pub fn gnutls_pubkey_deinit(key: gnutls_pubkey_t);
     pub fn gnutls_pubkey_init(key: *mut gnutls_pubkey_t) -> libc::c_int;
     pub fn gnutls_rnd(
         level: gnutls_rnd_level_t,
         data: *mut libc::c_void,
         len: size_t,
     ) -> libc::c_int;
     pub fn nettle_sha256_digest(ctx: *mut sha256_ctx, length: size_t, digest: *mut uint8_t);
     pub fn nettle_sha256_update(ctx: *mut sha256_ctx, length: size_t, data: *const uint8_t);
     pub fn nettle_sha256_init(ctx: *mut sha256_ctx);
     pub fn Curl_extract_certinfo(
         data: *mut Curl_easy,
         certnum: libc::c_int,
         beg: *const libc::c_char,
         end: *const libc::c_char,
     ) -> CURLcode;
 
     pub fn gnutls_ocsp_resp_init(resp: *mut gnutls_ocsp_resp_t) -> libc::c_int;
     pub fn gnutls_ocsp_resp_deinit(resp: gnutls_ocsp_resp_t);
     pub fn gnutls_ocsp_resp_import(
         resp: gnutls_ocsp_resp_t,
         data: *const gnutls_datum_t,
     ) -> libc::c_int;
     pub fn gnutls_ocsp_resp_get_single(
         resp: gnutls_ocsp_resp_const_t,
         indx: libc::c_uint,
         digest: *mut gnutls_digest_algorithm_t,
         issuer_name_hash: *mut gnutls_datum_t,
         issuer_key_hash: *mut gnutls_datum_t,
         serial_number: *mut gnutls_datum_t,
         cert_status: *mut libc::c_uint,
         this_update: *mut time_t,
         next_update: *mut time_t,
         revocation_time: *mut time_t,
         revocation_reason: *mut libc::c_uint,
     ) -> libc::c_int;
 
     // wolfssl.rs
 
     // pub fn Curl_none_check_cxn(conn: *mut connectdata) -> libc::c_int;
     // pub fn Curl_none_close_all(data: *mut Curl_easy);
     // pub fn Curl_none_set_engine(
     //     data: *mut Curl_easy,
     //     engine: *const libc::c_char,
     // ) -> CURLcode;
     // pub fn Curl_none_set_engine_default(data: *mut Curl_easy) -> CURLcode;
     // pub fn Curl_none_engines_list(data: *mut Curl_easy) -> *mut curl_slist;
     // pub fn Curl_none_false_start() -> bool;
     // pub fn Curl_ssl_getsock(
     //     conn: *mut connectdata,
     //     socks: *mut curl_socket_t,
     // ) -> libc::c_int;
     // pub fn Curl_ssl_sessionid_lock(data: *mut Curl_easy);
     // pub fn Curl_ssl_sessionid_unlock(data: *mut Curl_easy);
     // pub fn Curl_ssl_getsessionid(
     //     data: *mut Curl_easy,
     //     conn: *mut connectdata,
     //     isProxy: bool,
     //     ssl_sessionid: *mut *mut libc::c_void,
     //     idsize: *mut size_t,
     //     sockindex: libc::c_int,
     // ) -> bool;
     // pub fn Curl_ssl_addsessionid(
     //     data: *mut Curl_easy,
     //     conn: *mut connectdata,
     //     isProxy: bool,
     //     ssl_sessionid: *mut libc::c_void,
     //     idsize: size_t,
     //     sockindex: libc::c_int,
     // ) -> CURLcode;
     // pub fn Curl_ssl_delsessionid(data: *mut Curl_easy, ssl_sessionid: *mut libc::c_void);
     // pub fn Curl_pin_peer_pubkey(
     //     data: *mut Curl_easy,
     //     pinnedpubkey: *const libc::c_char,
     //     pubkey: *const libc::c_uchar,
     //     pubkeylen: size_t,
     // ) -> CURLcode;
     // pub fn Curl_tls_keylog_open();
     // pub fn Curl_tls_keylog_close();
     // pub fn Curl_tls_keylog_enabled() -> bool;
     // pub fn Curl_tls_keylog_write(
     //     label: *const libc::c_char,
     //     client_random: *const libc::c_uchar,
     //     secret: *const libc::c_uchar,
     //     secretlen: size_t,
     // ) -> bool;
     pub fn Curl_parseX509(
         cert: *mut Curl_X509certificate,
         beg: *const libc::c_char,
         end: *const libc::c_char,
     ) -> libc::c_int;
     pub fn wolfSSL_CTX_set_verify(
         _: *mut WOLFSSL_CTX,
         _: libc::c_int,
         verify_callback: VerifyCallback,
     );
     pub fn wolfSSL_CTX_use_PrivateKey_file(
         _: *mut WOLFSSL_CTX,
         _: *const libc::c_char,
         _: libc::c_int,
     ) -> libc::c_int;
     pub fn wolfSSL_CTX_use_certificate_file(
         _: *mut WOLFSSL_CTX,
         _: *const libc::c_char,
         _: libc::c_int,
     ) -> libc::c_int;
     pub fn wolfSSL_CTX_load_verify_locations(
         _: *mut WOLFSSL_CTX,
         _: *const libc::c_char,
         _: *const libc::c_char,
     ) -> libc::c_int;
     pub fn wolfSSL_CTX_set_cipher_list(_: *mut WOLFSSL_CTX, _: *const libc::c_char) -> libc::c_int;
     pub fn wolfSSL_CTX_SetMinVersion(ctx: *mut WOLFSSL_CTX, version: libc::c_int) -> libc::c_int;
     pub fn wolfSSL_CTX_new(_: *mut WOLFSSL_METHOD) -> *mut WOLFSSL_CTX;
     pub fn wolfTLSv1_2_client_method() -> *mut WOLFSSL_METHOD;
     pub fn wolfTLSv1_1_client_method() -> *mut WOLFSSL_METHOD;
     pub fn wolfSSLv23_client_method() -> *mut WOLFSSL_METHOD;
     pub fn wc_FreeRng(_: *mut WC_RNG) -> libc::c_int;
     pub fn wc_RNG_GenerateBlock(_: *mut WC_RNG, _: *mut byte, sz: word32) -> libc::c_int;
     pub fn wc_InitRng(_: *mut WC_RNG) -> libc::c_int;
     pub fn wolfSSL_pending(_: *mut WOLFSSL) -> libc::c_int;
     pub fn wolfSSL_lib_version() -> *const libc::c_char;
     pub fn wolfSSL_Cleanup() -> libc::c_int;
     pub fn wolfSSL_Init() -> libc::c_int;
     pub fn wolfSSL_check_domain_name(ssl: *mut WOLFSSL, dn: *const libc::c_char) -> libc::c_int;
     pub fn wolfSSL_new(_: *mut WOLFSSL_CTX) -> *mut WOLFSSL;
     pub fn wolfSSL_KeepArrays(_: *mut WOLFSSL);
     pub fn wolfSSL_set_session(ssl: *mut WOLFSSL, session: *mut WOLFSSL_SESSION) -> libc::c_int;
     pub fn wolfSSL_set_fd(_: *mut WOLFSSL, _: libc::c_int) -> libc::c_int;
     pub fn wolfSSL_connect(_: *mut WOLFSSL) -> libc::c_int;
     pub fn wolfSSL_want_read(_: *mut WOLFSSL) -> libc::c_int;
     pub fn wolfSSL_want_write(_: *mut WOLFSSL) -> libc::c_int;
     pub fn wolfSSL_GetVersion(ssl: *mut WOLFSSL) -> libc::c_int;
     pub fn wolfSSL_get_keys(
         _: *mut WOLFSSL,
         ms: *mut *mut libc::c_uchar,
         msLen: *mut libc::c_uint,
         sr: *mut *mut libc::c_uchar,
         srLen: *mut libc::c_uint,
         cr: *mut *mut libc::c_uchar,
         crLen: *mut libc::c_uint,
     ) -> libc::c_int;
     pub fn wolfSSL_FreeArrays(_: *mut WOLFSSL);
     pub fn wolfSSL_get_peer_certificate(ssl: *mut WOLFSSL) -> *mut WOLFSSL_X509;
     pub fn wolfSSL_X509_get_der(_: *mut WOLFSSL_X509, _: *mut libc::c_int) -> *const libc::c_uchar;
     pub fn wolfSSL_get_version(_: *mut WOLFSSL) -> *const libc::c_char;
     pub fn wolfSSL_get_cipher_name(ssl: *mut WOLFSSL) -> *const libc::c_char;
     pub fn wolfSSL_get_session(ssl: *mut WOLFSSL) -> *mut WOLFSSL_SESSION;
     pub fn wolfSSL_ERR_clear_error();
     pub fn wolfSSL_write(_: *mut WOLFSSL, _: *const libc::c_void, _: libc::c_int) -> libc::c_int;
     pub fn wolfSSL_ERR_error_string(_: libc::c_ulong, _: *mut libc::c_char) -> *mut libc::c_char;
     pub fn wolfSSL_get_error(_: *mut WOLFSSL, _: libc::c_int) -> libc::c_int;
     pub fn wolfSSL_read(_: *mut WOLFSSL, _: *mut libc::c_void, _: libc::c_int) -> libc::c_int;
     pub fn wolfSSL_shutdown(_: *mut WOLFSSL) -> libc::c_int;
     pub fn wolfSSL_free(_: *mut WOLFSSL);
     pub fn wolfSSL_CTX_free(_: *mut WOLFSSL_CTX);
     pub fn wc_InitSha256(_: *mut wc_Sha256) -> libc::c_int;
     pub fn wc_Sha256Update(_: *mut wc_Sha256, _: *const byte, _: word32) -> libc::c_int;
     pub fn wc_Sha256Final(_: *mut wc_Sha256, _: *mut byte) -> libc::c_int;
 
     // nss.rs
     pub fn __xstat(
         __ver: libc::c_int,
         __filename: *const libc::c_char,
         __stat_buf: *mut stat,
     ) -> libc::c_int;
     pub fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
     pub fn Curl_llist_destroy(_: *mut Curl_llist, _: *mut libc::c_void);
     // pub fn Curl_ssl_init_certinfo(data: *mut Curl_easy, num: libc::c_int) -> CURLcode;
     // pub fn Curl_pin_peer_pubkey(
     //     data: *mut Curl_easy,
     //     pinnedpubkey: *const libc::c_char,
     //     pubkey: *const libc::c_uchar,
     //     pubkeylen: size_t,
     // ) -> CURLcode;
     pub fn PR_ErrorToName(code: PRErrorCode) -> *const libc::c_char;
     pub fn PR_GetError() -> PRErrorCode;
     pub fn PR_Lock(lock: *mut PRLock);
     pub fn PR_ErrorToString(code: PRErrorCode, language: PRLanguageCode) -> *const libc::c_char;
     pub fn PR_Now() -> PRTime;
     pub fn PR_Free(ptr: *mut libc::c_void);
     pub fn PR_FormatTime(
         buf: *mut libc::c_char,
         buflen: libc::c_int,
         fmt: *const libc::c_char,
         time: *const PRExplodedTime,
     ) -> PRUint32;
     pub fn PR_GMTParameters(gmt: *const PRExplodedTime) -> PRTimeParameters;
     pub fn PR_ExplodeTime(usecs: PRTime, params: PRTimeParamFn, exploded: *mut PRExplodedTime);
     pub fn PR_Unlock(lock: *mut PRLock) -> PRStatus;
     pub fn PR_MillisecondsToInterval(milli: PRUint32) -> PRIntervalTime;
     pub fn PR_Init(type_0: PRThreadType, priority: PRThreadPriority, maxPTDs: PRUintn);
     pub fn PR_SetError(errorCode: PRErrorCode, oserr: PRInt32);
     pub fn PR_NewLock() -> *mut PRLock;
     pub fn PR_DestroyLock(lock: *mut PRLock);
     pub fn PR_SecondsToInterval(seconds: PRUint32) -> PRIntervalTime;
     pub fn PR_GetOpenFileInfo(fd: *mut PRFileDesc, info: *mut PRFileInfo) -> PRStatus;
     pub fn PR_OpenDir(name: *const libc::c_char) -> *mut PRDir;
     pub fn PR_CloseDir(dir: *mut PRDir) -> PRStatus;
     pub fn PR_Read(fd: *mut PRFileDesc, buf: *mut libc::c_void, amount: PRInt32) -> PRInt32;
     pub fn PR_ReadDir(dir: *mut PRDir, flags: PRDirFlags) -> *mut PRDirEntry;
     pub fn PR_GetDefaultIOMethods() -> *const PRIOMethods;
     pub fn PR_Close(fd: *mut PRFileDesc) -> PRStatus;
     pub fn PR_PushIOLayer(
         fd_stack: *mut PRFileDesc,
         id: PRDescIdentity,
         layer: *mut PRFileDesc,
     ) -> PRStatus;
     pub fn PR_CreateIOLayerStub(
         ident: PRDescIdentity,
         methods: *const PRIOMethods,
     ) -> *mut PRFileDesc;
     pub fn PR_GetUniqueIdentity(layer_name: *const libc::c_char) -> PRDescIdentity;
     pub fn PR_Open(name: *const libc::c_char, flags: PRIntn, mode: PRIntn) -> *mut PRFileDesc;
     pub fn PR_NewTCPSocket() -> *mut PRFileDesc;
     pub fn PR_Recv(
         fd: *mut PRFileDesc,
         buf: *mut libc::c_void,
         amount: PRInt32,
         flags: PRIntn,
         timeout: PRIntervalTime,
     ) -> PRInt32;
     pub fn PR_Send(
         fd: *mut PRFileDesc,
         buf: *const libc::c_void,
         amount: PRInt32,
         flags: PRIntn,
         timeout: PRIntervalTime,
     ) -> PRInt32;
     pub fn PR_SetSocketOption(fd: *mut PRFileDesc, data: *const PRSocketOptionData) -> PRStatus;
     pub fn NSS_ShutdownContext(_: *mut NSSInitContext) -> SECStatus;
     pub fn NSS_GetVersion() -> *const libc::c_char;
     pub fn PORT_Strdup(s: *const libc::c_char) -> *mut libc::c_char;
     pub fn NSS_InitContext(
         configdir: *const libc::c_char,
         certPrefix: *const libc::c_char,
         keyPrefix: *const libc::c_char,
         secmodName: *const libc::c_char,
         initParams: *mut NSSInitParameters,
         flags: PRUint32,
     ) -> *mut NSSInitContext;
     pub fn SSL_VersionRangeGetDefault(
         protocolVariant: SSLProtocolVariant,
         vrange: *mut SSLVersionRange,
     ) -> SECStatus;
     pub fn SSL_VersionRangeGetSupported(
         protocolVariant: SSLProtocolVariant,
         vrange: *mut SSLVersionRange,
     ) -> SECStatus;
     pub fn SSL_VersionRangeSet(fd: *mut PRFileDesc, vrange: *const SSLVersionRange) -> SECStatus;
     pub fn SSL_GetNumImplementedCiphers() -> PRUint16;
     pub fn SSL_GetImplementedCiphers() -> *const PRUint16;
     pub fn SSL_CipherPrefSet(fd: *mut PRFileDesc, cipher: PRInt32, enabled: PRBool) -> SECStatus;
     pub fn SSL_AuthCertificateHook(
         fd: *mut PRFileDesc,
         f: SSLAuthCertificate,
         arg: *mut libc::c_void,
     ) -> SECStatus;
     pub fn SSL_PeerStapledOCSPResponses(fd: *mut PRFileDesc) -> *const SECItemArray;
     pub fn SSL_AuthCertificate(
         arg: *mut libc::c_void,
         fd: *mut PRFileDesc,
         checkSig: PRBool,
         isServer: PRBool,
     ) -> SECStatus;
     pub fn SSL_BadCertHook(
         fd: *mut PRFileDesc,
         f: SSLBadCertHandler,
         arg: *mut libc::c_void,
     ) -> SECStatus;
     pub fn SSL_GetNextProto(
         fd: *mut PRFileDesc,
         state: *mut SSLNextProtoState,
         buf: *mut libc::c_uchar,
         bufLen: *mut libc::c_uint,
         bufLenMax: libc::c_uint,
     ) -> SECStatus;
     pub fn SECITEM_AllocItem(
         arena: *mut PLArenaPool,
         item: *mut SECItem,
         len: libc::c_uint,
     ) -> *mut SECItem;
     pub fn CERT_CacheCRL(dbhandle: *mut CERTCertDBHandle, newcrl: *mut SECItem) -> SECStatus;
     pub fn CERT_UncacheCRL(dbhandle: *mut CERTCertDBHandle, oldcrl: *mut SECItem) -> SECStatus;
     pub fn CERT_GetDefaultCertDB() -> *mut CERTCertDBHandle;
     pub fn SSL_ClearSessionCache();
     pub fn SSL_GetClientAuthDataHook(
         fd: *mut PRFileDesc,
         f: SSLGetClientAuthData,
         a: *mut libc::c_void,
     ) -> SECStatus;
     pub fn SSL_SetSockPeerID(fd: *mut PRFileDesc, peerID: *const libc::c_char) -> SECStatus;
     pub fn NSS_GetClientAuthData(
         arg: *mut libc::c_void,
         socket: *mut PRFileDesc,
         caNames: *mut CERTDistNamesStr,
         pRetCert: *mut *mut CERTCertificateStr,
         pRetKey: *mut *mut SECKEYPrivateKeyStr,
     ) -> SECStatus;
     pub fn SSL_ImportFD(model: *mut PRFileDesc, fd: *mut PRFileDesc) -> *mut PRFileDesc;
     pub fn SSL_SetPKCS11PinArg(fd: *mut PRFileDesc, a: *mut libc::c_void) -> SECStatus;
     pub fn SSL_OptionSet(fd: *mut PRFileDesc, option: PRInt32, val: PRIntn) -> SECStatus;
     pub fn SSL_SetCanFalseStartCallback(
         fd: *mut PRFileDesc,
         callback: SSLCanFalseStartCallback,
         arg: *mut libc::c_void,
     ) -> SECStatus;
     pub fn SSL_HandshakeNegotiatedExtension(
         socket: *mut PRFileDesc,
         extId: SSLExtensionType,
         yes: *mut PRBool,
     ) -> SECStatus;
     pub fn SSL_SetNextProtoNego(
         fd: *mut PRFileDesc,
         data: *const libc::c_uchar,
         length: libc::c_uint,
     ) -> SECStatus;
     pub fn SSL_ResetHandshake(fd: *mut PRFileDesc, asServer: PRBool) -> SECStatus;
     pub fn SSL_SetURL(fd: *mut PRFileDesc, url: *const libc::c_char) -> SECStatus;
     pub fn SSL_ForceHandshakeWithTimeout(fd: *mut PRFileDesc, timeout: PRIntervalTime)
         -> SECStatus;
     pub fn SSL_GetChannelInfo(
         fd: *mut PRFileDesc,
         info: *mut SSLChannelInfo,
         len: PRUintn,
     ) -> SECStatus;
     pub fn SSL_GetCipherSuiteInfo(
         cipherSuite: PRUint16,
         info: *mut SSLCipherSuiteInfo,
         len: PRUintn,
     ) -> SECStatus;
     pub fn CERT_NameToAscii(name: *mut CERTName) -> *mut libc::c_char;
     pub fn CERT_GetCommonName(name: *const CERTName) -> *mut libc::c_char;
     pub fn CERT_GetCertTimes(
         c: *const CERTCertificate,
         notBefore: *mut PRTime,
         notAfter: *mut PRTime,
     ) -> SECStatus;
     pub fn CERT_FindCertIssuer(
         cert: *mut CERTCertificate,
         validTime: PRTime,
         usage: SECCertUsage,
     ) -> *mut CERTCertificate;
     pub fn SSL_RevealPinArg(socket: *mut PRFileDesc) -> *mut libc::c_void;
     pub fn SECITEM_CompareItem(a: *const SECItem, b: *const SECItem) -> SECComparison;
     pub fn SSL_PeerCertificate(fd: *mut PRFileDesc) -> *mut CERTCertificate;
     pub fn SECKEY_DestroyPublicKey(key: *mut SECKEYPublicKey);
     pub fn CERT_ExtractPublicKey(cert: *mut CERTCertificate) -> *mut SECKEYPublicKey;
     pub fn CERT_DestroyCertificate(cert: *mut CERTCertificate);
     pub fn SSL_InvalidateSession(fd: *mut PRFileDesc) -> SECStatus;
     pub fn SECITEM_FreeItem(zap: *mut SECItem, freeit: PRBool);
     pub fn SSL_CipherPolicyGet(cipher: PRInt32, policy: *mut PRInt32) -> SECStatus;
     pub fn NSS_SetDomesticPolicy() -> SECStatus;
     pub fn SSL_HandshakeCallback(
         fd: *mut PRFileDesc,
         cb: SSLHandshakeCallback,
         client_data: *mut libc::c_void,
     ) -> SECStatus;
     pub fn SECMOD_LoadUserModule(
         moduleSpec: *mut libc::c_char,
         parent: *mut SECMODModule,
         recurse: PRBool,
     ) -> *mut SECMODModule;
     pub fn SECMOD_UnloadUserModule(mod_0: *mut SECMODModule) -> SECStatus;
     pub fn SECMOD_DestroyModule(module: *mut SECMODModule);
     pub fn SECMOD_WaitForAnyTokenEvent(
         mod_0: *mut SECMODModule,
         flags: libc::c_ulong,
         latency: PRIntervalTime,
     ) -> *mut PK11SlotInfo;
     pub fn PK11_FreeSlot(slot: *mut PK11SlotInfo);
     pub fn PK11_SetPasswordFunc(func: PK11PasswordFunc);
     pub fn PK11_Authenticate(
         slot: *mut PK11SlotInfo,
         loadCerts: PRBool,
         wincx: *mut libc::c_void,
     ) -> SECStatus;
     pub fn PK11_FindSlotByName(name: *const libc::c_char) -> *mut PK11SlotInfo;
     pub fn PK11_IsPresent(slot: *mut PK11SlotInfo) -> PRBool;
     pub fn PK11_GenerateRandom(data: *mut libc::c_uchar, len: libc::c_int) -> SECStatus;
     pub fn PK11_FindPrivateKeyFromCert(
         slot: *mut PK11SlotInfo,
         cert: *mut CERTCertificate,
         wincx: *mut libc::c_void,
     ) -> *mut SECKEYPrivateKey;
     pub fn PK11_DEREncodePublicKey(pubk: *const SECKEYPublicKey) -> *mut SECItem;
     pub fn PK11_FindCertFromNickname(
         nickname: *const libc::c_char,
         wincx: *mut libc::c_void,
     ) -> *mut CERTCertificate;
     pub fn PK11_FindCertFromDERCertItem(
         slot: *mut PK11SlotInfo,
         derCert: *const SECItem,
         wincx: *mut libc::c_void,
     ) -> *mut CERTCertificate;
     pub fn PK11_DestroyContext(context: *mut PK11Context, freeit: PRBool);
     pub fn PK11_CreateDigestContext(hashAlg: SECOidTag) -> *mut PK11Context;
     pub fn PK11_DigestOp(
         context: *mut PK11Context,
         in_0: *const libc::c_uchar,
         len: libc::c_uint,
     ) -> SECStatus;
     pub fn PK11_DigestFinal(
         context: *mut PK11Context,
         data: *mut libc::c_uchar,
         outLen: *mut libc::c_uint,
         length: libc::c_uint,
     ) -> SECStatus;
     pub fn PK11_ReadRawAttribute(
         type_0: PK11ObjectType,
         object: *mut libc::c_void,
         attr: CK_ATTRIBUTE_TYPE,
         item: *mut SECItem,
     ) -> SECStatus;
     pub fn PK11_DestroyGenericObject(object: *mut PK11GenericObject) -> SECStatus;
     pub fn PK11_CreateManagedGenericObject(
         slot: *mut PK11SlotInfo,
         pTemplate: *const CK_ATTRIBUTE,
         count: libc::c_int,
         token: PRBool,
     ) -> *mut PK11GenericObject;
     pub fn SEC_FindCrlByDERCert(
         handle: *mut CERTCertDBHandle,
         derCrl: *mut SECItem,
         type_0: libc::c_int,
     ) -> *mut CERTSignedCrl;
     pub fn SEC_DestroyCrl(crl: *mut CERTSignedCrl) -> SECStatus;
     pub fn ATOB_ConvertAsciiToItem(
         binary_item: *mut SECItem,
         ascii: *const libc::c_char,
     ) -> SECStatus;
     pub fn PR_ImportTCPSocket(osfd: PROsfd) -> *mut PRFileDesc;
     pub fn CERT_CacheOCSPResponseFromSideChannel(
         handle: *mut CERTCertDBHandle,
         cert: *mut CERTCertificate,
         time: PRTime,
         encodedResponse: *const SECItem,
         pwArg: *mut libc::c_void,
     ) -> SECStatus;
     pub fn curlx_uztosi(uznum: size_t) -> libc::c_int;
     pub fn curlx_uztoui(uznum: size_t) -> libc::c_uint;
     pub fn strpbrk(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
     pub fn Curl_llist_init(_: *mut Curl_llist, _: Curl_llist_dtor);
     // rustls.rs
     pub fn rustls_client_config_builder_dangerous_set_certificate_verifier(
         config: *mut rustls_client_config_builder,
         callback: rustls_verify_server_cert_callback,
     );
     pub fn rustls_client_config_builder_load_roots_from_file(
         config: *mut rustls_client_config_builder,
         filename: *const libc::c_char,
     ) -> rustls_result;
     pub fn rustls_client_config_builder_set_protocols(
         builder: *mut rustls_client_config_builder,
         protocols: *const rustls_slice_bytes,
         len: size_t,
     ) -> rustls_result;
     pub fn rustls_client_config_builder_set_enable_sni(
         config: *mut rustls_client_config_builder,
         enable: bool,
     );
     pub fn rustls_client_config_free(config: *const rustls_client_config);
     pub fn rustls_client_connection_new(
         config: *const rustls_client_config,
         hostname: *const libc::c_char,
         conn_out: *mut *mut rustls_connection,
     ) -> rustls_result;
     pub fn rustls_connection_set_userdata(
         conn: *mut rustls_connection,
         userdata: *mut libc::c_void,
     );
     pub fn rustls_connection_read_tls(
         conn: *mut rustls_connection,
         callback: rustls_read_callback,
         userdata: *mut libc::c_void,
         out_n: *mut size_t,
     ) -> rustls_io_result;
     pub fn rustls_connection_write_tls(
         conn: *mut rustls_connection,
         callback: rustls_write_callback,
         userdata: *mut libc::c_void,
         out_n: *mut size_t,
     ) -> rustls_io_result;
     pub fn rustls_connection_process_new_packets(conn: *mut rustls_connection) -> rustls_result;
     pub fn rustls_connection_wants_read(conn: *const rustls_connection) -> bool;
     pub fn rustls_connection_wants_write(conn: *const rustls_connection) -> bool;
     pub fn rustls_connection_is_handshaking(conn: *const rustls_connection) -> bool;
     pub fn rustls_version(buf: *mut libc::c_char, len: size_t) -> size_t;
     pub fn rustls_connection_send_close_notify(conn: *mut rustls_connection);
     pub fn rustls_connection_get_alpn_protocol(
         conn: *const rustls_connection,
         protocol_out: *mut *const uint8_t,
         protocol_out_len: *mut size_t,
     );
     pub fn rustls_connection_write(
         conn: *mut rustls_connection,
         buf: *const uint8_t,
         count: size_t,
         out_n: *mut size_t,
     ) -> rustls_result;
     pub fn rustls_connection_read(
         conn: *mut rustls_connection,
         buf: *mut uint8_t,
         count: size_t,
         out_n: *mut size_t,
     ) -> rustls_result;
     pub fn rustls_connection_free(conn: *mut rustls_connection);
     pub fn rustls_error(
         result: rustls_result,
         buf: *mut libc::c_char,
         len: size_t,
         out_n: *mut size_t,
     );
     pub fn rustls_result_is_cert_error(result: rustls_result) -> bool;
     pub fn rustls_client_config_builder_build(
         builder: *mut rustls_client_config_builder,
     ) -> *const rustls_client_config;
     pub fn rustls_client_config_builder_new() -> *mut rustls_client_config_builder;
     // pub fn Curl_none_init() -> libc::c_int;
     // pub fn Curl_none_cleanup();
     // pub fn Curl_none_check_cxn(conn: *mut connectdata) -> libc::c_int;
     // pub fn Curl_none_random(
     //     data: *mut Curl_easy,
     //     entropy: *mut libc::c_uchar,
     //     length: size_t,
     // ) -> CURLcode;
     // pub fn Curl_none_close_all(data: *mut Curl_easy);
     // pub fn Curl_none_session_free(ptr: *mut libc::c_void);
     // pub fn Curl_none_cert_status_request() -> bool;
     // pub fn Curl_none_set_engine(
     //     data: *mut Curl_easy,
     //     engine: *const libc::c_char,
     // ) -> CURLcode;
     // pub fn Curl_none_set_engine_default(data: *mut Curl_easy) -> CURLcode;
     // pub fn Curl_none_engines_list(data: *mut Curl_easy) -> *mut curl_slist;
     // pub fn Curl_none_false_start() -> bool;
 
     // mesalink.rs
     pub fn mesalink_SSL_CTX_use_PrivateKey_file(
         _: *mut MESALINK_CTX,
         _: *const libc::c_char,
         _: libc::c_int,
     ) -> libc::c_int;
     pub fn mesalink_library_init() -> libc::c_int;
     pub fn mesalink_TLSv1_2_client_method() -> *mut MESALINK_METHOD;
     pub fn mesalink_TLSv1_3_client_method() -> *mut MESALINK_METHOD;
     pub fn mesalink_SSL_CTX_new(_: *mut MESALINK_METHOD) -> *mut MESALINK_CTX;
     pub fn mesalink_SSL_CTX_load_verify_locations(
         _: *mut MESALINK_CTX,
         _: *const libc::c_char,
         _: *const libc::c_char,
     ) -> libc::c_int;
     pub fn mesalink_SSL_CTX_use_certificate_chain_file(
         _: *mut MESALINK_CTX,
         _: *const libc::c_char,
         _: libc::c_int,
     ) -> libc::c_int;
     pub fn mesalink_SSL_CTX_set_verify(
         _: *mut MESALINK_CTX,
         _: libc::c_int,
         cb: Option<unsafe extern "C" fn(libc::c_int, *mut MESALINK_CTX) -> libc::c_int>,
     ) -> libc::c_int;
     pub fn mesalink_SSL_new(_: *mut MESALINK_CTX) -> *mut MESALINK_SSL;
     pub fn mesalink_SSL_set_tlsext_host_name(
         _: *mut MESALINK_SSL,
         _: *const libc::c_char,
     ) -> libc::c_int;
     pub fn mesalink_SSL_set_fd(_: *mut MESALINK_SSL, _: libc::c_int) -> libc::c_int;
     pub fn mesalink_SSL_CTX_free(_: *mut MESALINK_CTX);
     pub fn mesalink_SSL_connect(_: *mut MESALINK_SSL) -> libc::c_int;
     pub fn mesalink_SSL_write(
         _: *mut MESALINK_SSL,
         _: *const libc::c_void,
         _: libc::c_int,
     ) -> libc::c_int;
     pub fn mesalink_SSL_get_cipher_name(_: *mut MESALINK_SSL) -> *const libc::c_char;
     pub fn mesalink_SSL_read(
         _: *mut MESALINK_SSL,
         _: *mut libc::c_void,
         _: libc::c_int,
     ) -> libc::c_int;
     pub fn mesalink_SSL_shutdown(_: *mut MESALINK_SSL) -> libc::c_int;
     pub fn mesalink_SSL_get_version(_: *const MESALINK_SSL) -> *const libc::c_char;
     pub fn mesalink_SSL_free(_: *mut MESALINK_SSL);
     pub fn mesalink_SSL_get_error(_: *const MESALINK_SSL, _: libc::c_int) -> libc::c_int;
     pub fn mesalink_ERR_error_string_n(
         e: libc::c_ulong,
         buf: *mut libc::c_char,
         len: size_t,
     ) -> *const libc::c_char;
     pub fn mesalink_ERR_print_errors_fp(_: *const FILE);
     // openssl.rs
     pub fn Curl_wait_ms(timeout_ms: timediff_t) -> libc::c_int;
     // pub fn Curl_none_false_start() -> bool;
     pub fn curl_slist_append(_: *mut curl_slist, _: *const libc::c_char) -> *mut curl_slist;
     // pub fn Curl_ssl_push_certinfo_len(
     //     data: *mut Curl_easy,
     //     certnum: libc::c_int,
     //     label: *const libc::c_char,
     //     value: *const libc::c_char,
     //     valuelen: size_t,
     // ) -> CURLcode;
     // pub fn Curl_ssl_sessionid_lock(data: *mut Curl_easy);
     // pub fn Curl_ssl_sessionid_unlock(data: *mut Curl_easy);
     // pub fn Curl_ssl_getsessionid(
     //     data: *mut Curl_easy,
     //     conn: *mut connectdata,
     //     isProxy: bool,
     //     ssl_sessionid: *mut *mut libc::c_void,
     //     idsize: *mut size_t,
     //     sockindex: libc::c_int,
     // ) -> bool;
     // pub fn Curl_ssl_addsessionid(
     //     data: *mut Curl_easy,
     //     conn: *mut connectdata,
     //     isProxy: bool,
     //     ssl_sessionid: *mut libc::c_void,
     //     idsize: size_t,
     //     sockindex: libc::c_int,
     // ) -> CURLcode;
     // pub fn Curl_ssl_delsessionid(data: *mut Curl_easy, ssl_sessionid: *mut libc::c_void);
     pub fn Curl_cert_hostcheck(
         match_pattern: *const libc::c_char,
         hostname: *const libc::c_char,
     ) -> libc::c_int;
     pub fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
     pub fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
     pub fn EVP_DigestUpdate(
         ctx: *mut EVP_MD_CTX,
         d: *const libc::c_void,
         cnt: size_t,
     ) -> libc::c_int;
     pub fn EVP_DigestFinal_ex(
         ctx: *mut EVP_MD_CTX,
         md: *mut libc::c_uchar,
         s: *mut libc::c_uint,
     ) -> libc::c_int;
     pub fn EVP_DigestInit(ctx: *mut EVP_MD_CTX, type_0: *const EVP_MD) -> libc::c_int;
     pub fn EVP_sha1() -> *const EVP_MD;
     pub fn EVP_sha256() -> *const EVP_MD;
     pub fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> libc::c_int;
     pub fn EVP_PKEY_get0_RSA(pkey: *mut EVP_PKEY) -> *mut rsa_st;
     pub fn EVP_PKEY_get1_RSA(pkey: *mut EVP_PKEY) -> *mut rsa_st;
     pub fn EVP_PKEY_get0_DSA(pkey: *mut EVP_PKEY) -> *mut dsa_st;
     pub fn EVP_PKEY_get0_DH(pkey: *mut EVP_PKEY) -> *mut dh_st;
     pub fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
     pub fn EVP_PKEY_copy_parameters(to: *mut EVP_PKEY, from: *const EVP_PKEY) -> libc::c_int;
     pub fn OPENSSL_init_ssl(opts: uint64_t, settings: *const OPENSSL_INIT_SETTINGS) -> libc::c_int;
     pub fn SSL_get_shutdown(ssl: *const SSL) -> libc::c_int;
     pub fn SSL_pending(s: *const SSL) -> libc::c_int;
     pub fn TLS_client_method() -> *const SSL_METHOD;
     pub fn SSL_CTX_new(meth: *const SSL_METHOD) -> *mut SSL_CTX;
     pub fn SSL_CTX_set_msg_callback(
         ctx: *mut SSL_CTX,
         cb: Option<
             unsafe extern "C" fn(
                 libc::c_int,
                 libc::c_int,
                 libc::c_int,
                 *const libc::c_void,
                 size_t,
                 *mut SSL,
                 *mut libc::c_void,
             ) -> (),
         >,
     );
     pub fn SSL_alert_desc_string_long(value: libc::c_int) -> *const libc::c_char;
     pub fn SSL_CTX_set_options(ctx: *mut SSL_CTX, op: libc::c_ulong) -> libc::c_ulong;
     pub fn SSL_CTX_set_next_proto_select_cb(
         s: *mut SSL_CTX,
         cb: SSL_CTX_npn_select_cb_func,
         arg: *mut libc::c_void,
     );
     pub fn SSL_CTX_set_alpn_protos(
         ctx: *mut SSL_CTX,
         protos: *const libc::c_uchar,
         protos_len: libc::c_uint,
     ) -> libc::c_int;
     pub fn SSL_CTX_set_default_passwd_cb_userdata(ctx: *mut SSL_CTX, u: *mut libc::c_void);
     pub fn SSL_CTX_set_default_passwd_cb(ctx: *mut SSL_CTX, cb: Option<pem_password_cb>);
     pub fn PEM_read_bio_X509_AUX(
         bp: *mut BIO,
         x: *mut *mut X509,
         cb: Option<pem_password_cb>,
         u: *mut libc::c_void,
     ) -> *mut X509;
     pub fn SSL_CTX_use_certificate_chain_file(
         ctx: *mut SSL_CTX,
         file: *const libc::c_char,
     ) -> libc::c_int;
     pub fn d2i_X509_bio(bp: *mut BIO, x509: *mut *mut X509) -> *mut X509;
     pub fn SSL_CTX_use_certificate_file(
         ctx: *mut SSL_CTX,
         file: *const libc::c_char,
         type_0: libc::c_int,
     ) -> libc::c_int;
     pub fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, x: *mut X509) -> libc::c_int;
     pub fn SSL_CTX_add_client_CA(ctx: *mut SSL_CTX, x: *mut X509) -> libc::c_int;
     pub fn OPENSSL_sk_pop(st: *mut OPENSSL_STACK) -> *mut libc::c_void;
     pub fn PEM_read_bio_PrivateKey(
         bp: *mut BIO,
         x: *mut *mut EVP_PKEY,
         cb: Option<pem_password_cb>,
         u: *mut libc::c_void,
     ) -> *mut EVP_PKEY;
     pub fn d2i_PrivateKey_bio(bp: *mut BIO, a: *mut *mut EVP_PKEY) -> *mut EVP_PKEY;
     pub fn SSL_CTX_use_PrivateKey_file(
         ctx: *mut SSL_CTX,
         file: *const libc::c_char,
         type_0: libc::c_int,
     ) -> libc::c_int;
     pub fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, pkey: *mut EVP_PKEY) -> libc::c_int;
     pub fn SSL_get_certificate(ssl: *const SSL) -> *mut X509;
     pub fn RSA_flags(r: *const RSA) -> libc::c_int;
     pub fn RSA_free(r: *mut RSA);
     pub fn SSL_get_privatekey(ssl: *const SSL) -> *mut evp_pkey_st;
     pub fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) -> libc::c_int;
     pub fn SSL_CTX_set_ciphersuites(ctx: *mut SSL_CTX, str: *const libc::c_char) -> libc::c_int;
     pub fn SSL_CTX_set_post_handshake_auth(ctx: *mut SSL_CTX, val: libc::c_int);
     pub fn SSL_CTX_set_srp_username(ctx: *mut SSL_CTX, name: *mut libc::c_char) -> libc::c_int;
     pub fn SSL_CTX_set_srp_password(ctx: *mut SSL_CTX, password: *mut libc::c_char) -> libc::c_int;
     pub fn SSL_CTX_set_cipher_list(_: *mut SSL_CTX, str: *const libc::c_char) -> libc::c_int;
     pub fn PEM_X509_INFO_read_bio(
         bp: *mut BIO,
         sk: *mut stack_st_X509_INFO,
         cb: Option<pem_password_cb>,
         u: *mut libc::c_void,
     ) -> *mut stack_st_X509_INFO;
     pub fn X509_STORE_add_cert(ctx: *mut X509_STORE, x: *mut X509) -> libc::c_int;
     pub fn X509_STORE_add_crl(ctx: *mut X509_STORE, x: *mut X509_CRL) -> libc::c_int;
     pub fn OPENSSL_sk_pop_free(
         st: *mut OPENSSL_STACK,
         func: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
     );
     pub fn X509_INFO_free(a: *mut X509_INFO);
     pub fn SSL_CTX_load_verify_locations(
         ctx: *mut SSL_CTX,
         CAfile: *const libc::c_char,
         CApath: *const libc::c_char,
     ) -> libc::c_int;
     pub fn X509_STORE_add_lookup(
         v: *mut X509_STORE,
         m: *mut X509_LOOKUP_METHOD,
     ) -> *mut X509_LOOKUP;
     pub fn X509_LOOKUP_file() -> *mut X509_LOOKUP_METHOD;
     pub fn X509_load_crl_file(
         ctx: *mut X509_LOOKUP,
         file: *const libc::c_char,
         type_0: libc::c_int,
     ) -> libc::c_int;
     pub fn X509_STORE_set_flags(ctx: *mut X509_STORE, flags: libc::c_ulong) -> libc::c_int;
     pub fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: libc::c_int, callback: SSL_verify_cb);
     pub fn SSL_CTX_set_keylog_callback(ctx: *mut SSL_CTX, cb: SSL_CTX_keylog_cb_func);
     pub fn SSL_CTX_ctrl(
         ctx: *mut SSL_CTX,
         cmd: libc::c_int,
         larg: libc::c_long,
         parg: *mut libc::c_void,
     ) -> libc::c_long;
     pub fn SSL_CTX_sess_set_new_cb(
         ctx: *mut SSL_CTX,
         new_session_cb: Option<unsafe extern "C" fn(*mut ssl_st, *mut SSL_SESSION) -> libc::c_int>,
     );
     pub fn SSL_get_ex_data(ssl: *const SSL, idx: libc::c_int) -> *mut libc::c_void;
     pub fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
     pub fn SSL_set_session(to: *mut SSL, session: *mut SSL_SESSION) -> libc::c_int;
     pub fn SSL_set_bio(s: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);
     pub fn BIO_f_ssl() -> *const BIO_METHOD;
     pub fn SSL_set_fd(s: *mut SSL, fd: libc::c_int) -> libc::c_int;
     pub fn SSL_connect(ssl: *mut SSL) -> libc::c_int;
     pub fn X509_get0_extensions(x: *const X509) -> *const stack_st_X509_EXTENSION;
     pub fn SSL_get_version(s: *const SSL) -> *const libc::c_char;
     pub fn SSL_CIPHER_get_name(c: *const SSL_CIPHER) -> *const libc::c_char;
     pub fn SSL_get_current_cipher(s: *const SSL) -> *const SSL_CIPHER;
     pub fn SSL_get0_alpn_selected(
         ssl: *const SSL,
         data: *mut *const libc::c_uchar,
         len: *mut libc::c_uint,
     );
     pub fn X509_get_version(x: *const X509) -> libc::c_long;
     pub fn X509_get_serialNumber(x: *mut X509) -> *mut ASN1_INTEGER;
     pub fn BIO_puts(bp: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
     pub fn X509_get0_signature(
         psig: *mut *const ASN1_BIT_STRING,
         palg: *mut *const X509_ALGOR,
         x: *const X509,
     );
     pub fn X509_PUBKEY_get0_param(
         ppkalg: *mut *mut ASN1_OBJECT,
         pk: *mut *const libc::c_uchar,
         ppklen: *mut libc::c_int,
         pa: *mut *mut X509_ALGOR,
         pub_0: *mut X509_PUBKEY,
     ) -> libc::c_int;
     pub fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> libc::c_int;
     pub fn X509_EXTENSION_get_object(ex: *mut X509_EXTENSION) -> *mut ASN1_OBJECT;
     pub fn i2t_ASN1_OBJECT(
         buf: *mut libc::c_char,
         buf_len: libc::c_int,
         a: *const ASN1_OBJECT,
     ) -> libc::c_int;
     pub fn ASN1_STRING_print(bp: *mut BIO, v: *const ASN1_STRING) -> libc::c_int;
     pub fn X509_EXTENSION_get_data(ne: *mut X509_EXTENSION) -> *mut ASN1_OCTET_STRING;
     pub fn X509_get_pubkey(x: *mut X509) -> *mut EVP_PKEY;
     pub fn RSA_get0_key(
         r: *const RSA,
         n: *mut *const BIGNUM,
         e: *mut *const BIGNUM,
         d: *mut *const BIGNUM,
     );
     pub fn BN_num_bits(a: *const BIGNUM) -> libc::c_int;
     pub fn DSA_get0_pqg(
         d: *const DSA,
         p: *mut *const BIGNUM,
         q: *mut *const BIGNUM,
         g: *mut *const BIGNUM,
     );
     pub fn DSA_get0_key(d: *const DSA, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);
     pub fn DH_get0_pqg(
         dh: *const DH,
         p: *mut *const BIGNUM,
         q: *mut *const BIGNUM,
         g: *mut *const BIGNUM,
     );
     pub fn DH_get0_key(dh: *const DH, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);
     pub fn BN_print(bio: *mut BIO, a: *const BIGNUM) -> libc::c_int;
     pub fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
     pub fn PEM_write_bio_X509(bp: *mut BIO, x: *mut X509) -> libc::c_int;
     pub fn X509_get0_notBefore(x: *const X509) -> *const ASN1_TIME;
     pub fn ASN1_TIME_print(fp: *mut BIO, a: *const ASN1_TIME) -> libc::c_int;
     pub fn X509_get0_notAfter(x: *const X509) -> *const ASN1_TIME;
     pub fn X509_get_ext_d2i(
         x: *const X509,
         nid: libc::c_int,
         crit: *mut libc::c_int,
         idx: *mut libc::c_int,
     ) -> *mut libc::c_void;
     pub fn X509_NAME_get_index_by_NID(
         name: *mut X509_NAME,
         nid: libc::c_int,
         lastpos: libc::c_int,
     ) -> libc::c_int;
     pub fn ASN1_STRING_type(x: *const ASN1_STRING) -> libc::c_int;
     pub fn ASN1_STRING_length(x: *const ASN1_STRING) -> libc::c_int;
     pub fn CRYPTO_malloc(
         num: size_t,
         file: *const libc::c_char,
         line: libc::c_int,
     ) -> *mut libc::c_void;
     pub fn ASN1_STRING_get0_data(x: *const ASN1_STRING) -> *const libc::c_uchar;
     pub fn ASN1_STRING_to_UTF8(
         out: *mut *mut libc::c_uchar,
         in_0: *const ASN1_STRING,
     ) -> libc::c_int;
     pub fn X509_NAME_ENTRY_get_data(ne: *const X509_NAME_ENTRY) -> *mut ASN1_STRING;
     pub fn X509_NAME_get_entry(name: *const X509_NAME, loc: libc::c_int) -> *mut X509_NAME_ENTRY;
     pub fn X509_get_subject_name(a: *const X509) -> *mut X509_NAME;
     pub fn CRYPTO_free(ptr: *mut libc::c_void, file: *const libc::c_char, line: libc::c_int);
     pub fn X509_NAME_print_ex(
         out: *mut BIO,
         nm: *const X509_NAME,
         indent: libc::c_int,
         flags: libc::c_ulong,
     ) -> libc::c_int;
     pub fn BIO_s_mem() -> *const BIO_METHOD;
     pub fn X509_get_issuer_name(a: *const X509) -> *mut X509_NAME;
     pub fn BIO_new_mem_buf(buf: *const libc::c_void, len: libc::c_int) -> *mut BIO;
     pub fn BIO_new(type_0: *const BIO_METHOD) -> *mut BIO;
     pub fn BIO_s_file() -> *const BIO_METHOD;
     pub fn BIO_ctrl(
         bp: *mut BIO,
         cmd: libc::c_int,
         larg: libc::c_long,
         parg: *mut libc::c_void,
     ) -> libc::c_long;
     pub fn PEM_read_bio_X509(
         bp: *mut BIO,
         x: *mut *mut X509,
         cb: Option<pem_password_cb>,
         u: *mut libc::c_void,
     ) -> *mut X509;
     pub fn BIO_free(a: *mut BIO) -> libc::c_int;
     pub fn SSL_get_verify_result(ssl: *const SSL) -> libc::c_long;
     pub fn X509_verify_cert_error_string(n: libc::c_long) -> *const libc::c_char;
     pub fn SSL_ctrl(
         ssl: *mut SSL,
         cmd: libc::c_int,
         larg: libc::c_long,
         parg: *mut libc::c_void,
     ) -> libc::c_long;
     pub fn SSL_get_peer_cert_chain(s: *const SSL) -> *mut stack_st_X509;
     pub fn SSL_CTX_get_cert_store(_: *const SSL_CTX) -> *mut X509_STORE;
     pub fn SSL_get_peer_certificate(s: *const SSL) -> *mut X509;
     pub fn OPENSSL_sk_num(_: *const OPENSSL_STACK) -> libc::c_int;
     pub fn OPENSSL_sk_value(_: *const OPENSSL_STACK, _: libc::c_int) -> *mut libc::c_void;
     pub fn i2d_X509_PUBKEY(a: *mut X509_PUBKEY, out: *mut *mut libc::c_uchar) -> libc::c_int;
     pub fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509_PUBKEY;
     pub fn X509_free(a: *mut X509);
     pub fn SSL_write(ssl: *mut SSL, buf: *const libc::c_void, num: libc::c_int) -> libc::c_int;
     pub fn SSL_get_error(s: *const SSL, ret_code: libc::c_int) -> libc::c_int;
     pub fn OpenSSL_version_num() -> libc::c_ulong;
     pub fn SSL_read(ssl: *mut SSL, buf: *mut libc::c_void, num: libc::c_int) -> libc::c_int;
     pub fn SSL_shutdown(s: *mut SSL) -> libc::c_int;
     pub fn SSL_set_connect_state(s: *mut SSL);
     pub fn SSL_free(ssl: *mut SSL);
     pub fn SSL_CTX_free(_: *mut SSL_CTX);
     pub fn SSL_SESSION_free(ses: *mut SSL_SESSION);
     pub fn SSL_set_ex_data(ssl: *mut SSL, idx: libc::c_int, data: *mut libc::c_void)
         -> libc::c_int;
     pub fn CRYPTO_get_ex_new_index(
         class_index: libc::c_int,
         argl: libc::c_long,
         argp: *mut libc::c_void,
         new_func: Option<CRYPTO_EX_new>,
         dup_func: Option<CRYPTO_EX_dup>,
         free_func: Option<CRYPTO_EX_free>,
     ) -> libc::c_int;
     pub fn RAND_bytes(buf: *mut libc::c_uchar, num: libc::c_int) -> libc::c_int;
     pub fn RAND_add(buf: *const libc::c_void, num: libc::c_int, randomness: libc::c_double);
     pub fn RAND_load_file(file: *const libc::c_char, max_bytes: libc::c_long) -> libc::c_int;
     pub fn RAND_file_name(file: *mut libc::c_char, num: size_t) -> *const libc::c_char;
     pub fn RAND_status() -> libc::c_int;
     pub fn GENERAL_NAMES_free(a: *mut GENERAL_NAMES);
     pub fn X509V3_EXT_print(
         out: *mut BIO,
         ext: *mut X509_EXTENSION,
         flag: libc::c_ulong,
         indent: libc::c_int,
     ) -> libc::c_int;
     pub fn X509_check_issued(issuer: *mut X509, subject: *mut X509) -> libc::c_int;
     pub fn ERR_get_error() -> libc::c_ulong;
     pub fn ERR_peek_error() -> libc::c_ulong;
     pub fn ERR_peek_last_error() -> libc::c_ulong;
     pub fn ERR_clear_error();
     pub fn ERR_error_string_n(e: libc::c_ulong, buf: *mut libc::c_char, len: size_t);
     pub fn PKCS12_free(a: *mut PKCS12);
     pub fn PKCS12_PBE_add();
     pub fn PKCS12_parse(
         p12: *mut PKCS12,
         pass: *const libc::c_char,
         pkey: *mut *mut EVP_PKEY,
         cert: *mut *mut X509,
         ca: *mut *mut stack_st_X509,
     ) -> libc::c_int;
     pub fn d2i_PKCS12_bio(bp: *mut BIO, p12: *mut *mut PKCS12) -> *mut PKCS12;
     pub fn OCSP_cert_to_id(
         dgst: *const EVP_MD,
         subject: *const X509,
         issuer: *const X509,
     ) -> *mut OCSP_CERTID;
     pub fn OCSP_response_status(resp: *mut OCSP_RESPONSE) -> libc::c_int;
     pub fn OCSP_response_get1_basic(resp: *mut OCSP_RESPONSE) -> *mut OCSP_BASICRESP;
     pub fn OCSP_resp_find_status(
         bs: *mut OCSP_BASICRESP,
         id: *mut OCSP_CERTID,
         status: *mut libc::c_int,
         reason: *mut libc::c_int,
         revtime: *mut *mut ASN1_GENERALIZEDTIME,
         thisupd: *mut *mut ASN1_GENERALIZEDTIME,
         nextupd: *mut *mut ASN1_GENERALIZEDTIME,
     ) -> libc::c_int;
     pub fn OCSP_check_validity(
         thisupd: *mut ASN1_GENERALIZEDTIME,
         nextupd: *mut ASN1_GENERALIZEDTIME,
         sec: libc::c_long,
         maxsec: libc::c_long,
     ) -> libc::c_int;
     pub fn OCSP_BASICRESP_free(a: *mut OCSP_BASICRESP);
     pub fn OCSP_RESPONSE_free(a: *mut OCSP_RESPONSE);
     pub fn d2i_OCSP_RESPONSE(
         a: *mut *mut OCSP_RESPONSE,
         in_0: *mut *const libc::c_uchar,
         len: libc::c_long,
     ) -> *mut OCSP_RESPONSE;
     pub fn OCSP_CERTID_free(a: *mut OCSP_CERTID);
     pub fn OCSP_response_status_str(s: libc::c_long) -> *const libc::c_char;
     pub fn OCSP_basic_verify(
         bs: *mut OCSP_BASICRESP,
         certs: *mut stack_st_X509,
         st: *mut X509_STORE,
         flags: libc::c_ulong,
     ) -> libc::c_int;
     pub fn OCSP_cert_status_str(s: libc::c_long) -> *const libc::c_char;
     pub fn OCSP_crl_reason_str(s: libc::c_long) -> *const libc::c_char;
     pub fn ENGINE_get_first() -> *mut ENGINE;
     pub fn ENGINE_get_next(e: *mut ENGINE) -> *mut ENGINE;
     pub fn ENGINE_by_id(id: *const libc::c_char) -> *mut ENGINE;
     pub fn ENGINE_ctrl(
         e: *mut ENGINE,
         cmd: libc::c_int,
         i: libc::c_long,
         p: *mut libc::c_void,
         f: Option<unsafe extern "C" fn() -> ()>,
     ) -> libc::c_int;
     pub fn ENGINE_ctrl_cmd(
         e: *mut ENGINE,
         cmd_name: *const libc::c_char,
         i: libc::c_long,
         p: *mut libc::c_void,
         f: Option<unsafe extern "C" fn() -> ()>,
         cmd_optional: libc::c_int,
     ) -> libc::c_int;
     pub fn ENGINE_free(e: *mut ENGINE) -> libc::c_int;
     pub fn ENGINE_get_id(e: *const ENGINE) -> *const libc::c_char;
     pub fn UI_OpenSSL() -> *mut UI_METHOD;
     pub fn ENGINE_load_private_key(
         e: *mut ENGINE,
         key_id: *const libc::c_char,
         ui_method: *mut UI_METHOD,
         callback_data: *mut libc::c_void,
     ) -> *mut EVP_PKEY;
     pub fn ENGINE_set_default(e: *mut ENGINE, flags: libc::c_uint) -> libc::c_int;
     pub fn ENGINE_init(e: *mut ENGINE) -> libc::c_int;
     pub fn ENGINE_finish(e: *mut ENGINE) -> libc::c_int;
     pub fn UI_get0_user_data(ui: *mut UI) -> *mut libc::c_void;
     pub fn UI_method_set_opener(
         method: *mut UI_METHOD,
         opener: Option<unsafe extern "C" fn(*mut UI) -> libc::c_int>,
     ) -> libc::c_int;
     pub fn UI_method_get_opener(
         method: *const UI_METHOD,
     ) -> Option<unsafe extern "C" fn(*mut UI) -> libc::c_int>;
     pub fn UI_method_set_closer(
         method: *mut UI_METHOD,
         closer: Option<unsafe extern "C" fn(*mut UI) -> libc::c_int>,
     ) -> libc::c_int;
     pub fn UI_method_get_closer(
         method: *const UI_METHOD,
     ) -> Option<unsafe extern "C" fn(*mut UI) -> libc::c_int>;
     pub fn UI_create_method(name: *const libc::c_char) -> *mut UI_METHOD;
     pub fn UI_destroy_method(ui_method: *mut UI_METHOD);
     pub fn UI_method_get_writer(
         method: *const UI_METHOD,
     ) -> Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> libc::c_int>;
     pub fn UI_method_set_writer(
         method: *mut UI_METHOD,
         writer: Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> libc::c_int>,
     ) -> libc::c_int;
     pub fn UI_method_get_reader(
         method: *const UI_METHOD,
     ) -> Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> libc::c_int>;
     pub fn UI_method_set_reader(
         method: *mut UI_METHOD,
         reader: Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> libc::c_int>,
     ) -> libc::c_int;
     pub fn UI_set_result(
         ui: *mut UI,
         uis: *mut UI_STRING,
         result: *const libc::c_char,
     ) -> libc::c_int;
     pub fn UI_get_string_type(uis: *mut UI_STRING) -> UI_string_types;
     pub fn UI_get_input_flags(uis: *mut UI_STRING) -> libc::c_int;
 
     // http_negotiate.rs
     pub fn Curl_auth_decode_spnego_message(
         data: *mut Curl_easy,
         user: *const libc::c_char,
         passwood: *const libc::c_char,
         service: *const libc::c_char,
         host: *const libc::c_char,
         chlg64: *const libc::c_char,
         nego: *mut negotiatedata,
     ) -> CURLcode;
     pub fn Curl_auth_create_spnego_message(
         data: *mut Curl_easy,
         nego: *mut negotiatedata,
         outptr: *mut *mut libc::c_char,
         outlen: *mut size_t,
     ) -> CURLcode;
     pub fn Curl_auth_cleanup_spnego(nego: *mut negotiatedata);
     // bearssl.rs
     pub fn br_ssl_engine_sendapp_ack(cc: *mut br_ssl_engine_context, len: size_t);
     pub fn br_ssl_engine_sendapp_buf(
         cc: *const br_ssl_engine_context,
         len: *mut size_t,
     ) -> *mut libc::c_uchar;
     pub fn br_ssl_engine_current_state(cc: *const br_ssl_engine_context) -> libc::c_uint;
     pub fn br_ssl_engine_set_buffer(
         cc: *mut br_ssl_engine_context,
         iobuf: *mut libc::c_void,
         iobuf_len: size_t,
         bidi: libc::c_int,
     );
     pub fn br_pem_decoder_event(ctx: *mut br_pem_decoder_context) -> libc::c_int;
     pub fn br_pem_decoder_push(
         ctx: *mut br_pem_decoder_context,
         data: *const libc::c_void,
         len: size_t,
     ) -> size_t;
     pub fn br_pem_decoder_init(ctx: *mut br_pem_decoder_context);
     pub fn br_ssl_client_reset(
         cc: *mut br_ssl_client_context,
         server_name: *const libc::c_char,
         resume_session: libc::c_int,
     ) -> libc::c_int;
     pub fn br_ssl_client_init_full(
         cc: *mut br_ssl_client_context,
         xc: *mut br_x509_minimal_context,
         trust_anchors: *const br_x509_trust_anchor,
         trust_anchors_num: size_t,
     );
     pub fn br_ssl_engine_close(cc: *mut br_ssl_engine_context);
     pub fn br_ssl_engine_flush(cc: *mut br_ssl_engine_context, force: libc::c_int);
     pub fn br_ssl_engine_recvrec_ack(cc: *mut br_ssl_engine_context, len: size_t);
     pub fn br_ssl_engine_recvrec_buf(
         cc: *const br_ssl_engine_context,
         len: *mut size_t,
     ) -> *mut libc::c_uchar;
     pub fn br_ssl_engine_sendrec_ack(cc: *mut br_ssl_engine_context, len: size_t);
     pub fn br_ssl_engine_sendrec_buf(
         cc: *const br_ssl_engine_context,
         len: *mut size_t,
     ) -> *mut libc::c_uchar;
     pub fn br_ssl_engine_recvapp_ack(cc: *mut br_ssl_engine_context, len: size_t);
     pub fn br_sha224_update(ctx: *mut br_sha224_context, data: *const libc::c_void, len: size_t);
     pub fn br_sha256_init(ctx: *mut br_sha256_context);
     pub fn br_sha256_out(ctx: *const br_sha256_context, out: *mut libc::c_void);
     pub fn br_ssl_engine_recvapp_buf(
         cc: *const br_ssl_engine_context,
         len: *mut size_t,
     ) -> *mut libc::c_uchar;
     pub fn br_x509_decoder_push(
         ctx: *mut br_x509_decoder_context,
         data: *const libc::c_void,
         len: size_t,
     );
     pub fn br_x509_decoder_init(
         ctx: *mut br_x509_decoder_context,
         append_dn_0: Option<
             unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> (),
         >,
         append_dn_ctx: *mut libc::c_void,
     );
     pub fn br_hmac_drbg_init(
         ctx: *mut br_hmac_drbg_context,
         digest_class: *const br_hash_class,
         seed: *const libc::c_void,
         seed_len: size_t,
     );
     pub fn br_hmac_drbg_generate(
         ctx: *mut br_hmac_drbg_context,
         out: *mut libc::c_void,
         len: size_t,
     );
     pub fn br_prng_seeder_system(name: *mut *const libc::c_char) -> br_prng_seeder;
     pub fn ferror(__stream: *mut FILE) -> libc::c_int;
 
     // option hyper
     pub fn hyper_clientconn_handshake(
         io: *mut hyper_io,
         options: *mut hyper_clientconn_options,
     ) -> *mut hyper_task;
     pub fn hyper_clientconn_send(
         conn: *mut hyper_clientconn,
         req: *mut hyper_request,
     ) -> *mut hyper_task;
     pub fn hyper_clientconn_free(conn: *mut hyper_clientconn);
     pub fn hyper_clientconn_options_new() -> *mut hyper_clientconn_options;
     pub fn hyper_clientconn_options_free(opts: *mut hyper_clientconn_options);
     pub fn hyper_clientconn_options_exec(
         opts: *mut hyper_clientconn_options,
         exec: *const hyper_executor,
     );
     pub fn hyper_error_free(err: *mut hyper_error);
     pub fn hyper_error_print(err: *const hyper_error, dst: *mut uint8_t, dst_len: size_t)
         -> size_t;
     pub fn hyper_request_new() -> *mut hyper_request;
     pub fn hyper_request_set_method(
         req: *mut hyper_request,
         method: *const uint8_t,
         method_len: size_t,
     ) -> hyper_code;
     pub fn hyper_request_set_uri(
         req: *mut hyper_request,
         uri: *const uint8_t,
         uri_len: size_t,
     ) -> hyper_code;
     pub fn hyper_request_set_version(req: *mut hyper_request, version: libc::c_int) -> hyper_code;
     pub fn hyper_request_headers(req: *mut hyper_request) -> *mut hyper_headers;
     pub fn hyper_io_new() -> *mut hyper_io;
     pub fn hyper_io_free(io: *mut hyper_io);
     pub fn hyper_io_set_userdata(io: *mut hyper_io, data: *mut libc::c_void);
     pub fn hyper_io_set_read(io: *mut hyper_io, func: hyper_io_read_callback);
     pub fn hyper_io_set_write(io: *mut hyper_io, func: hyper_io_write_callback);
     pub fn hyper_executor_new() -> *const hyper_executor;
     pub fn hyper_executor_free(exec: *const hyper_executor);
     pub fn hyper_executor_push(exec: *const hyper_executor, task: *mut hyper_task) -> hyper_code;
     pub fn hyper_executor_poll(exec: *const hyper_executor) -> *mut hyper_task;
     pub fn hyper_task_free(task: *mut hyper_task);
     pub fn hyper_task_value(task: *mut hyper_task) -> *mut libc::c_void;
     pub fn hyper_task_type(task: *mut hyper_task) -> hyper_task_return_type;
     pub fn hyper_waker_free(waker: *mut hyper_waker);
     pub fn Curl_hyper_recv(
         userp: *mut libc::c_void,
         ctx: *mut hyper_context,
         buf: *mut uint8_t,
         buflen: size_t,
     ) -> size_t;
     pub fn Curl_hyper_send(
         userp: *mut libc::c_void,
         ctx: *mut hyper_context,
         buf: *const uint8_t,
         buflen: size_t,
     ) -> size_t;
     pub fn Curl_hyper_stream(
         data: *mut Curl_easy,
         conn: *mut connectdata,
         didwhat: *mut libc::c_int,
         done: *mut bool,
         select_res: libc::c_int,
     ) -> CURLcode;
     pub fn Curl_hyper_header(
         data: *mut Curl_easy,
         headers: *mut hyper_headers,
         line: *const libc::c_char,
     ) -> CURLcode;
     pub fn Curl_hyper_done(_: *mut Curl_easy);
 
     // in http.rs, remove in future
     #[cfg(USE_HYPER)]
     pub fn Curl_add_custom_headers(
         data: *mut Curl_easy,
         is_connect: bool,
         headers: *mut libc::c_void,
     ) -> CURLcode;
 
     // http.rs function without hyper
     #[cfg(not(USE_HYPER))]
     pub fn Curl_add_custom_headers(
         data: *mut Curl_easy,
         is_connect: bool,
         req: *mut dynbuf,
     ) -> CURLcode;
 
     // ftp
     pub fn htons(__hostshort: uint16_t) -> uint16_t;
     pub fn ntohs(__netshort: uint16_t) -> uint16_t;
 
     //debug
     pub fn __assert_fail(
         __assertion: *const libc::c_char,
         __file: *const libc::c_char,
         __line: libc::c_uint,
         __function: *const libc::c_char,
     ) -> !;
     pub fn curl_dbg_free(ptr: *mut libc::c_void, line: libc::c_int, source: *const libc::c_char);
     pub fn curl_dbg_strdup(
         str: *const libc::c_char,
         line: libc::c_int,
         src: *const libc::c_char,
     ) -> *mut libc::c_char;
     pub fn curl_dbg_calloc(
         elements: size_t,
         size: size_t,
         line: libc::c_int,
         source: *const libc::c_char,
     ) -> *mut libc::c_void;
     pub fn curl_dbg_malloc(
         size: size_t,
         line: libc::c_int,
         source: *const libc::c_char,
     ) -> *mut libc::c_void;
     pub fn curl_dbg_fopen(
         file: *const libc::c_char,
         mode: *const libc::c_char,
         line: libc::c_int,
         source: *const libc::c_char,
     ) -> *mut FILE;
     pub fn curl_dbg_fclose(
         file: *mut FILE,
         line: libc::c_int,
         source: *const libc::c_char,
     ) -> libc::c_int;
     pub fn curl_dbg_recv(
         sockfd: libc::c_int,
         buf: *mut libc::c_void,
         len: size_t,
         flags: libc::c_int,
         line: libc::c_int,
         source: *const libc::c_char,
     ) -> ssize_t;
    pub fn curl_dbg_accept(
         s: curl_socket_t,
         a: *mut libc::c_void,
         alen: *mut libc::c_void,
         line: libc::c_int,
         source: *const libc::c_char,
     ) -> curl_socket_t;
    pub fn curl_dbg_realloc(
        ptr: *mut libc::c_void,
        size: size_t,
        line: libc::c_int,
        source: *const libc::c_char,
    ) -> *mut libc::c_void;
 }
 