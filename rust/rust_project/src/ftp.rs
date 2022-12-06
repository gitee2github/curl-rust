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
 * Author: Drug<zhangziyao21@mail.ustc.edu.cn>,
 * Create: 2022-10-31
 * Description: ftp
 ******************************************************************************/
 use ::libc;
 use rust_ffi::src::ffi_alias::type_alias::*;
 use rust_ffi::src::ffi_fun::fun_call::*;
 use rust_ffi::src::ffi_struct::struct_define::*;
 
 // TODO in_addr_t类型的条件编译
 
 #[inline]
 unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
     return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
         | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
         as __uint16_t;
 }
 #[no_mangle]
 pub static mut Curl_handler_ftp: Curl_handler = unsafe {
     {
         let mut init = Curl_handler {
             scheme: b"FTP\0" as *const u8 as *const libc::c_char,
             setup_connection: Some(
                 ftp_setup_connection
                     as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
             ),
             do_it: Some(ftp_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
             done: Some(
                 ftp_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
             ),
             do_more: Some(
                 ftp_do_more as unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_int) -> CURLcode,
             ),
             connect_it: Some(
                 ftp_connect as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),
             connecting: Some(
                 ftp_multi_statemach as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),
             doing: Some(ftp_doing as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
             proto_getsock: Some(
                 ftp_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> libc::c_int,
             ),
             doing_getsock: Some(
                 ftp_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> libc::c_int,
             ),
             domore_getsock: Some(
                 ftp_domore_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> libc::c_int,
             ),
             perform_getsock: None,
             disconnect: Some(
                 ftp_disconnect
                     as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
             ),
             readwrite: None,
             connection_check: None,
             attach: None,
             defport: 21 as libc::c_int,
             protocol: ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint,
             family: ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint,
             flags: ((1 as libc::c_int) << 1 as libc::c_int
                 | (1 as libc::c_int) << 2 as libc::c_int
                 | (1 as libc::c_int) << 5 as libc::c_int
                 | (1 as libc::c_int) << 6 as libc::c_int
                 | (1 as libc::c_int) << 11 as libc::c_int
                 | (1 as libc::c_int) << 12 as libc::c_int) as libc::c_uint,
         };
         init
     }
 };
 #[cfg(USE_SSL)]
 #[no_mangle]
 pub static mut Curl_handler_ftps: Curl_handler = unsafe {
     {
         let mut init = Curl_handler {
             scheme: b"FTPS\0" as *const u8 as *const libc::c_char,
             setup_connection: Some(
                 ftp_setup_connection
                     as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
             ),
             do_it: Some(
                 ftp_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),
             done: Some(
                 ftp_done
                     as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
             ),
             do_more: Some(
                 ftp_do_more
                     as unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_int) -> CURLcode,
             ),
             connect_it: Some(
                 ftp_connect
                     as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),
             connecting: Some(
                 ftp_multi_statemach
                     as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),
             doing: Some(
                 ftp_doing as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),
             proto_getsock: Some(
                 ftp_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> libc::c_int,
             ),
             doing_getsock: Some(
                 ftp_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> libc::c_int,
             ),
             domore_getsock: Some(
                 ftp_domore_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> libc::c_int,
             ),
             perform_getsock: None,
             disconnect: Some(
                 ftp_disconnect
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         bool,
                     ) -> CURLcode,
             ),
             readwrite: None,
             connection_check: None,
             attach: None,
             defport: 990 as libc::c_int,
             protocol: ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint,
             family: ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint,
             flags: ((1 as libc::c_int) << 0 as libc::c_int
                 | (1 as libc::c_int) << 1 as libc::c_int
                 | (1 as libc::c_int) << 2 as libc::c_int
                 | (1 as libc::c_int) << 5 as libc::c_int
                 | (1 as libc::c_int) << 6 as libc::c_int
                 | (1 as libc::c_int) << 12 as libc::c_int) as libc::c_uint,
         };
         init
     }
 };
 unsafe extern "C" fn close_secondarysocket(mut data: *mut Curl_easy, mut conn: *mut connectdata) {
     if -(1 as libc::c_int) != (*conn).sock[1 as libc::c_int as usize] {
         Curl_closesocket(data, conn, (*conn).sock[1 as libc::c_int as usize]);
         (*conn).sock[1 as libc::c_int as usize] = -(1 as libc::c_int);
     }
     (*conn).bits.tcpconnect[1 as libc::c_int as usize] = 0 as libc::c_int != 0;
     match() {
         #[cfg(not(CURL_DISABLE_PROXY))]
         _ => {
     (*conn).bits.proxy_ssl_connected[1 as libc::c_int as usize] = 0 as libc::c_int != 0;
 }
         #[cfg(CURL_DISABLE_PROXY)]
         _ => { }
     }
 }
 unsafe extern "C" fn freedirs(mut ftpc: *mut ftp_conn) {
     if !((*ftpc).dirs).is_null() {
         let mut i: libc::c_int = 0;
         i = 0 as libc::c_int;
         while i < (*ftpc).dirdepth {
             #[cfg(not(CURLDEBUG))]
             Curl_cfree.expect("non-null function pointer")(
                 *((*ftpc).dirs).offset(i as isize) as *mut libc::c_void
             );
             #[cfg(CURLDEBUG)]
             curl_dbg_free(
                 *((*ftpc).dirs).offset(i as isize) as *mut libc::c_void,
                 248 as libc::c_int,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
             let ref mut fresh0 = *((*ftpc).dirs).offset(i as isize);
             *fresh0 = 0 as *mut libc::c_char;
             i += 1;
         }
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")((*ftpc).dirs as *mut libc::c_void);
         #[cfg(CURLDEBUG)]
         curl_dbg_free(
             (*ftpc).dirs as *mut libc::c_void,
             251 as libc::c_int,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
         let ref mut fresh1 = (*ftpc).dirs;
         *fresh1 = 0 as *mut *mut libc::c_char;
         (*ftpc).dirdepth = 0 as libc::c_int;
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).file as *mut libc::c_void);
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*ftpc).file as *mut libc::c_void,
         255 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh2 = (*ftpc).file;
     *fresh2 = 0 as *mut libc::c_char;
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*ftpc).newhost as *mut libc::c_void,
         258 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh3 = (*ftpc).newhost;
     *fresh3 = 0 as *mut libc::c_char;
 }
 unsafe extern "C" fn AcceptServerConnect(mut data: *mut Curl_easy) -> CURLcode {
     let mut conn: *mut connectdata = (*data).conn;
     let mut sock: curl_socket_t = (*conn).sock[1 as libc::c_int as usize];
     let mut s: curl_socket_t = -(1 as libc::c_int);
     #[cfg(ENABLE_IPV6)]
     let mut add: Curl_sockaddr_storage = Curl_sockaddr_storage {
         buffer: C2RustUnnamed_9 {
             sa: sockaddr {
                 sa_family: 0,
                 sa_data: [0; 14],
             },
         },
     };
     #[cfg(not(ENABLE_IPV6))]
     let mut add: sockaddr_in = sockaddr_in {
         sin_family: 0,
         sin_port: 0,
         sin_addr: in_addr { s_addr: 0 },
         sin_zero: [0; 8],
     };
     #[cfg(ENABLE_IPV6)]
     let mut size: curl_socklen_t =
         ::std::mem::size_of::<Curl_sockaddr_storage>() as libc::c_ulong as curl_socklen_t;
     #[cfg(not(ENABLE_IPV6))]
     let mut size: curl_socklen_t = ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong
         as curl_socklen_t;
     #[cfg(ENABLE_IPV6)]
     if 0 as libc::c_int
         == getsockname(
             sock,
             &mut add as *mut Curl_sockaddr_storage as *mut sockaddr,
             &mut size,
         )
     {
         size = ::std::mem::size_of::<Curl_sockaddr_storage>() as libc::c_ulong as curl_socklen_t;
         match () {
             #[cfg(not(CURLDEBUG))]
             _ => {
                 s = accept(
                     sock,
                     &mut add as *mut Curl_sockaddr_storage as *mut sockaddr,
                     &mut size,
                 );
             }
             #[cfg(CURLDEBUG)]
             _ => {
                 s = curl_dbg_accept(
                     sock,
                     &mut add as *mut Curl_sockaddr_storage as *mut sockaddr as *mut libc::c_void,
                     &mut size as *mut curl_socklen_t as *mut libc::c_void,
                     284 as libc::c_int,
                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                 );
             }        
     }
 }
     #[cfg(not(ENABLE_IPV6))]
     if 0 as libc::c_int
         == getsockname(sock, &mut add as *mut sockaddr_in as *mut sockaddr, &mut size)
     {
         size = ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as curl_socklen_t;
         s = accept(sock, &mut add as *mut sockaddr_in as *mut sockaddr, &mut size);
     }
     Curl_closesocket(data, conn, sock);
     if -(1 as libc::c_int) == s {
         Curl_failf(
             data,
             b"Error accept()ing server connect\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_FTP_PORT_FAILED;
     }
     Curl_infof(
         data,
         b"Connection accepted from server\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh4 = (*conn).bits;
     (*fresh4).set_do_more(0 as libc::c_int as bit);
     (*conn).sock[1 as libc::c_int as usize] = s;
     curlx_nonblock(s, 1 as libc::c_int);
     let ref mut fresh5 = (*conn).bits;
     (*fresh5).set_sock_accepted(1 as libc::c_int as bit);
     if ((*data).set.fsockopt).is_some() {
         let mut error: libc::c_int = 0 as libc::c_int;
         Curl_set_in_callback(data, 1 as libc::c_int != 0);
         error = ((*data).set.fsockopt).expect("non-null function pointer")(
             (*data).set.sockopt_client,
             s,
             CURLSOCKTYPE_ACCEPT,
         );
         Curl_set_in_callback(data, 0 as libc::c_int != 0);
         if error != 0 {
             close_secondarysocket(data, conn);
             return CURLE_ABORTED_BY_CALLBACK;
         }
     }
     return CURLE_OK;
 }
 unsafe extern "C" fn ftp_timeleft_accept(mut data: *mut Curl_easy) -> timediff_t {
     let mut timeout_ms: timediff_t = 60000 as libc::c_int as timediff_t;
     let mut other: timediff_t = 0;
     let mut now: curltime = curltime {
         tv_sec: 0,
         tv_usec: 0,
     };
     if (*data).set.accepttimeout > 0 as libc::c_int as libc::c_long {
         timeout_ms = (*data).set.accepttimeout;
     }
     now = Curl_now();
     other = Curl_timeleft(data, &mut now, 0 as libc::c_int != 0);
     if other != 0 && other < timeout_ms {
         timeout_ms = other;
     } else {
         timeout_ms -= Curl_timediff(now, (*data).progress.t_acceptdata);
         if timeout_ms == 0 {
             return -(1 as libc::c_int) as timediff_t;
         }
     }
     return timeout_ms;
 }
 unsafe extern "C" fn ReceivedServerConnect(
     mut data: *mut Curl_easy,
     mut received: *mut bool,
 ) -> CURLcode {
     let mut conn: *mut connectdata = (*data).conn;
     let mut ctrl_sock: curl_socket_t = (*conn).sock[0 as libc::c_int as usize];
     let mut data_sock: curl_socket_t = (*conn).sock[1 as libc::c_int as usize];
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     let mut result: libc::c_int = 0;
     let mut timeout_ms: timediff_t = 0;
     let mut nread: ssize_t = 0;
     let mut ftpcode: libc::c_int = 0;
     *received = 0 as libc::c_int != 0;
     timeout_ms = ftp_timeleft_accept(data);
     Curl_infof(
         data,
         b"Checking for server connect\0" as *const u8 as *const libc::c_char,
     );
     if timeout_ms < 0 as libc::c_int as libc::c_long {
         Curl_failf(
             data,
             b"Accept timeout occurred while waiting server connect\0" as *const u8
                 as *const libc::c_char,
         );
         return CURLE_FTP_ACCEPT_TIMEOUT;
     }
     if (*pp).cache_size != 0
         && !((*pp).cache).is_null()
         && *((*pp).cache).offset(0 as libc::c_int as isize) as libc::c_int > '3' as i32
     {
         Curl_infof(
             data,
             b"There is negative response in cache while serv connect\0" as *const u8
                 as *const libc::c_char,
         );
         Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
         return CURLE_FTP_ACCEPT_FAILED;
     }
     result = Curl_socket_check(
         ctrl_sock,
         data_sock,
         -(1 as libc::c_int),
         0 as libc::c_int as timediff_t,
     );
     match result {
         -1 => {
             Curl_failf(
                 data,
                 b"Error while waiting for server connect\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_FTP_ACCEPT_FAILED;
         }
         0 => {}
         _ => {
             if result & (0x4 as libc::c_int) << 1 as libc::c_int != 0 {
                 Curl_infof(
                     data,
                     b"Ready to accept data connection from server\0" as *const u8
                         as *const libc::c_char,
                 );
                 *received = 1 as libc::c_int != 0;
             } else if result & 0x1 as libc::c_int != 0 {
                 Curl_infof(
                     data,
                     b"Ctrl conn has data while waiting for data conn\0" as *const u8
                         as *const libc::c_char,
                 );
                 Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
                 if ftpcode / 100 as libc::c_int > 3 as libc::c_int {
                     return CURLE_FTP_ACCEPT_FAILED;
                 }
                 return CURLE_WEIRD_SERVER_REPLY;
             }
         }
     }
     return CURLE_OK;
 }
 unsafe extern "C" fn InitiateTransfer(mut data: *mut Curl_easy) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     if ((*conn).bits).ftp_use_data_ssl() != 0 {
         Curl_infof(
             data,
             b"Doing the SSL/TLS handshake on the data stream\0" as *const u8 as *const libc::c_char,
         );
         // match () {
         //     #[cfg(USE_SSL)]
         //     _ => {
         //         result = Curl_ssl_connect(data, conn, 1 as libc::c_int);
         //     }
         //     #[cfg(not(USE_SSL))]
         //     _ => {
         //         result = CURLE_NOT_BUILT_IN;
         //     }
         // }
         result = Curl_ssl_connect(data, conn, 1 as libc::c_int);
         if result as u64 != 0 {
             return result;
         }
     }
     if (*conn).proto.ftpc.state_saved as libc::c_uint == FTP_STOR as libc::c_int as libc::c_uint {
         Curl_pgrsSetUploadSize(data, (*data).state.infilesize);
         Curl_setup_transfer(
             data,
             -(1 as libc::c_int),
             -(1 as libc::c_int) as curl_off_t,
             0 as libc::c_int != 0,
             1 as libc::c_int,
         );
     } else {
         Curl_setup_transfer(
             data,
             1 as libc::c_int,
             (*conn).proto.ftpc.retr_size_saved,
             0 as libc::c_int != 0,
             -(1 as libc::c_int),
         );
     }
     (*conn).proto.ftpc.pp.pending_resp = 1 as libc::c_int != 0;
     #[cfg(not(DEBUGBUILD))]
     _state(data, FTP_STOP);
 
     #[cfg(DEBUGBUILD)]
     _state(data, FTP_STOP, 470 as libc::c_int);
     return CURLE_OK;
 }
 unsafe extern "C" fn AllowServerConnect(
     mut data: *mut Curl_easy,
     mut connected: *mut bool,
 ) -> CURLcode {
     let mut timeout_ms: timediff_t = 0;
     let mut result: CURLcode = CURLE_OK;
     *connected = 0 as libc::c_int != 0;
     Curl_infof(
         data,
         b"Preparing for accepting server on data port\0" as *const u8 as *const libc::c_char,
     );
     Curl_pgrsTime(data, TIMER_STARTACCEPT);
     timeout_ms = ftp_timeleft_accept(data);
     if timeout_ms < 0 as libc::c_int as libc::c_long {
         Curl_failf(
             data,
             b"Accept timeout occurred while waiting server connect\0" as *const u8
                 as *const libc::c_char,
         );
         return CURLE_FTP_ACCEPT_TIMEOUT;
     }
     result = ReceivedServerConnect(data, connected);
     if result as u64 != 0 {
         return result;
     }
     if *connected {
         result = AcceptServerConnect(data);
         if result as u64 != 0 {
             return result;
         }
         result = InitiateTransfer(data);
         if result as u64 != 0 {
             return result;
         }
     } else if *connected as libc::c_int == 0 as libc::c_int {
         Curl_expire(
             data,
             if (*data).set.accepttimeout > 0 as libc::c_int as libc::c_long {
                 (*data).set.accepttimeout
             } else {
                 60000 as libc::c_int as libc::c_long
             },
             EXPIRE_100_TIMEOUT,
         );
     }
     return result;
 }
 unsafe extern "C" fn ftp_endofresp(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut line: *mut libc::c_char,
     mut len: size_t,
     mut code: *mut libc::c_int,
 ) -> bool {
     if len > 3 as libc::c_int as libc::c_ulong
         && (Curl_isdigit(*line.offset(0 as libc::c_int as isize) as libc::c_uchar as libc::c_int)
             != 0
             && Curl_isdigit(*line.offset(1 as libc::c_int as isize) as libc::c_uchar as libc::c_int)
                 != 0
             && Curl_isdigit(*line.offset(2 as libc::c_int as isize) as libc::c_uchar as libc::c_int)
                 != 0
             && ' ' as i32 == *line.offset(3 as libc::c_int as isize) as libc::c_int)
     {
         *code = curlx_sltosi(strtol(line, 0 as *mut *mut libc::c_char, 10 as libc::c_int));
         return 1 as libc::c_int != 0;
     }
     return 0 as libc::c_int != 0;
 }
 unsafe extern "C" fn ftp_readresp(
     mut data: *mut Curl_easy,
     mut sockfd: curl_socket_t,
     mut pp: *mut pingpong,
     mut ftpcode: *mut libc::c_int,
     mut size: *mut size_t,
 ) -> CURLcode {
     let mut code: libc::c_int = 0;
     let mut result: CURLcode = Curl_pp_readresp(data, sockfd, pp, &mut code, size);
     if cfg!(HAVE_GSSAPI) {
         let mut conn: *mut connectdata = (*data).conn;
         let buf: *mut libc::c_char = (*data).state.buffer;
         match code {
             631 => {
                 code = Curl_sec_read_msg(data, conn, buf, PROT_SAFE);
             }
             632 => {
                 code = Curl_sec_read_msg(data, conn, buf, PROT_PRIVATE);
             }
             633 => {
                 code = Curl_sec_read_msg(data, conn, buf, PROT_CONFIDENTIAL);
             }
             _ => {}
         }
     }
     (*data).info.httpcode = code;
     if !ftpcode.is_null() {
         *ftpcode = code;
     }
     if 421 as libc::c_int == code {
         Curl_infof(
             data,
             b"We got a 421 - timeout!\0" as *const u8 as *const libc::c_char,
         );
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_STOP);
 
         #[cfg(DEBUGBUILD)]
         _state(data, FTP_STOP, 596 as libc::c_int);
         return CURLE_OPERATION_TIMEDOUT;
     }
     return result;
 }
 #[no_mangle]
 pub unsafe extern "C" fn Curl_GetFTPResponse(
     mut data: *mut Curl_easy,
     mut nreadp: *mut ssize_t,
     mut ftpcode: *mut libc::c_int,
 ) -> CURLcode {
     let mut conn: *mut connectdata = (*data).conn;
     let mut sockfd: curl_socket_t = (*conn).sock[0 as libc::c_int as usize];
     let mut result: CURLcode = CURLE_OK;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     let mut nread: size_t = 0;
     let mut cache_skip: libc::c_int = 0 as libc::c_int;
     let mut value_to_be_ignored: libc::c_int = 0 as libc::c_int;
     if !ftpcode.is_null() {
         *ftpcode = 0 as libc::c_int;
     } else {
         ftpcode = &mut value_to_be_ignored;
     }
     *nreadp = 0 as libc::c_int as ssize_t;
     let mut current_block_20: u64;
     while *ftpcode == 0 && result as u64 == 0 {
         let mut timeout: timediff_t = Curl_pp_state_timeout(data, pp, 0 as libc::c_int != 0);
         let mut interval_ms: timediff_t = 0;
         if timeout <= 0 as libc::c_int as libc::c_long {
             Curl_failf(
                 data,
                 b"FTP response timeout\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_OPERATION_TIMEDOUT;
         }
         interval_ms = 1000 as libc::c_int as timediff_t;
         if timeout < interval_ms {
             interval_ms = timeout;
         }
         if !(!((*pp).cache).is_null() && cache_skip < 2 as libc::c_int) {
             if !Curl_conn_data_pending(conn, 0 as libc::c_int) {
                 match Curl_socket_check(
                     sockfd,
                     -(1 as libc::c_int),
                     -(1 as libc::c_int),
                     interval_ms,
                 ) {
                     -1 => {
                         current_block_20 = 3097724707645237320;
                         match current_block_20 {
                             3097724707645237320 => {
                                 Curl_failf(
                                     data,
                                     b"FTP response aborted due to select/poll error: %d\0"
                                         as *const u8
                                         as *const libc::c_char,
                                     *__errno_location(),
                                 );
                                 return CURLE_RECV_ERROR;
                             }
                             _ => {
                                 if Curl_pgrsUpdate(data) != 0 {
                                     return CURLE_ABORTED_BY_CALLBACK;
                                 }
                                 continue;
                             }
                         }
                     }
                     0 => {
                         current_block_20 = 16982823512181177793;
                         match current_block_20 {
                             3097724707645237320 => {
                                 Curl_failf(
                                     data,
                                     b"FTP response aborted due to select/poll error: %d\0"
                                         as *const u8
                                         as *const libc::c_char,
                                     *__errno_location(),
                                 );
                                 return CURLE_RECV_ERROR;
                             }
                             _ => {
                                 if Curl_pgrsUpdate(data) != 0 {
                                     return CURLE_ABORTED_BY_CALLBACK;
                                 }
                                 continue;
                             }
                         }
                     }
                     _ => {}
                 }
             }
         }
         result = ftp_readresp(data, sockfd, pp, ftpcode, &mut nread);
         if result as u64 != 0 {
             break;
         }
         if nread == 0 && !((*pp).cache).is_null() {
             cache_skip += 1;
         } else {
             cache_skip = 0 as libc::c_int;
         }
         *nreadp = (*nreadp as libc::c_ulong).wrapping_add(nread) as ssize_t as ssize_t;
     }
     (*pp).pending_resp = 0 as libc::c_int != 0;
     return result;
 }
 static mut ftp_state_names: [*const libc::c_char; 35] = [
     b"STOP\0" as *const u8 as *const libc::c_char,
     b"WAIT220\0" as *const u8 as *const libc::c_char,
     b"AUTH\0" as *const u8 as *const libc::c_char,
     b"USER\0" as *const u8 as *const libc::c_char,
     b"PASS\0" as *const u8 as *const libc::c_char,
     b"ACCT\0" as *const u8 as *const libc::c_char,
     b"PBSZ\0" as *const u8 as *const libc::c_char,
     b"PROT\0" as *const u8 as *const libc::c_char,
     b"CCC\0" as *const u8 as *const libc::c_char,
     b"PWD\0" as *const u8 as *const libc::c_char,
     b"SYST\0" as *const u8 as *const libc::c_char,
     b"NAMEFMT\0" as *const u8 as *const libc::c_char,
     b"QUOTE\0" as *const u8 as *const libc::c_char,
     b"RETR_PREQUOTE\0" as *const u8 as *const libc::c_char,
     b"STOR_PREQUOTE\0" as *const u8 as *const libc::c_char,
     b"POSTQUOTE\0" as *const u8 as *const libc::c_char,
     b"CWD\0" as *const u8 as *const libc::c_char,
     b"MKD\0" as *const u8 as *const libc::c_char,
     b"MDTM\0" as *const u8 as *const libc::c_char,
     b"TYPE\0" as *const u8 as *const libc::c_char,
     b"LIST_TYPE\0" as *const u8 as *const libc::c_char,
     b"RETR_TYPE\0" as *const u8 as *const libc::c_char,
     b"STOR_TYPE\0" as *const u8 as *const libc::c_char,
     b"SIZE\0" as *const u8 as *const libc::c_char,
     b"RETR_SIZE\0" as *const u8 as *const libc::c_char,
     b"STOR_SIZE\0" as *const u8 as *const libc::c_char,
     b"REST\0" as *const u8 as *const libc::c_char,
     b"RETR_REST\0" as *const u8 as *const libc::c_char,
     b"PORT\0" as *const u8 as *const libc::c_char,
     b"PRET\0" as *const u8 as *const libc::c_char,
     b"PASV\0" as *const u8 as *const libc::c_char,
     b"LIST\0" as *const u8 as *const libc::c_char,
     b"RETR\0" as *const u8 as *const libc::c_char,
     b"STOR\0" as *const u8 as *const libc::c_char,
     b"QUIT\0" as *const u8 as *const libc::c_char,
 ];
 
 #[cfg(not(DEBUGBUILD))]
 unsafe extern "C" fn _state(mut data: *mut Curl_easy, mut newstate: ftpstate) {
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     (*ftpc).state = newstate;
 }
 #[cfg(DEBUGBUILD)]
 unsafe extern "C" fn _state(
     mut data: *mut Curl_easy,
     mut newstate: ftpstate,
     mut lineno: libc::c_int,
 ) {
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*ftpc).state as libc::c_uint != newstate as libc::c_uint {
         Curl_infof(
             data,
             b"FTP %p (line %d) state change from %s to %s\0" as *const u8 as *const libc::c_char,
             ftpc as *mut libc::c_void,
             lineno,
             ftp_state_names[(*ftpc).state as usize],
             ftp_state_names[newstate as usize],
         );
     }
     (*ftpc).state = newstate;
 }
 unsafe extern "C" fn ftp_state_user(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut result: CURLcode = Curl_pp_sendf(
         data,
         &mut (*conn).proto.ftpc.pp as *mut pingpong,
         b"USER %s\0" as *const u8 as *const libc::c_char,
         if !((*conn).user).is_null() {
             (*conn).user as *const libc::c_char
         } else {
             b"\0" as *const u8 as *const libc::c_char
         },
     );
     if result as u64 == 0 {
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_USER);
 
         #[cfg(DEBUGBUILD)]
         _state(data, FTP_USER, 787 as libc::c_int);
         let ref mut fresh6 = (*data).state;
         (*fresh6).set_ftp_trying_alternative(0 as libc::c_int as bit);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_pwd(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut result: CURLcode = Curl_pp_sendf(
         data,
         &mut (*conn).proto.ftpc.pp as *mut pingpong,
         b"%s\0" as *const u8 as *const libc::c_char,
         b"PWD\0" as *const u8 as *const libc::c_char,
     );
     if result as u64 == 0 {
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_PWD);
 
         #[cfg(DEBUGBUILD)]
         _state(data, FTP_PWD, 798 as libc::c_int);
     }
     return result;
 }
 unsafe extern "C" fn ftp_getsock(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut socks: *mut curl_socket_t,
 ) -> libc::c_int {
     return Curl_pp_getsock(data, &mut (*conn).proto.ftpc.pp, socks);
 }
 unsafe extern "C" fn ftp_domore_getsock(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut socks: *mut curl_socket_t,
 ) -> libc::c_int {
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*conn).cnnct.state as libc::c_uint >= CONNECT_SOCKS_INIT as libc::c_int as libc::c_uint
         && ((*conn).cnnct.state as libc::c_uint) < CONNECT_DONE as libc::c_int as libc::c_uint
     {
         #[cfg(not(CURL_DISABLE_PROXY))]
         return Curl_SOCKS_getsock(conn, socks, 1 as libc::c_int);
         #[cfg(CURL_DISABLE_PROXY)]
         return 0 as libc::c_int;
     }
     if FTP_STOP as libc::c_int as libc::c_uint == (*ftpc).state as libc::c_uint {
         let mut bits: libc::c_int = (1 as libc::c_int) << 0 as libc::c_int;
         let mut any: bool = 0 as libc::c_int != 0;
         *socks.offset(0 as libc::c_int as isize) = (*conn).sock[0 as libc::c_int as usize];
         if ((*data).set).ftp_use_port() == 0 {
             let mut s: libc::c_int = 0;
             let mut i: libc::c_int = 0;
             s = 1 as libc::c_int;
             i = 0 as libc::c_int;
             while i < 2 as libc::c_int {
                 if (*conn).tempsock[i as usize] != -(1 as libc::c_int) {
                     *socks.offset(s as isize) = (*conn).tempsock[i as usize];
                     let fresh7 = s;
                     s = s + 1;
                     bits |= (1 as libc::c_int) << 16 as libc::c_int + fresh7;
                     any = 1 as libc::c_int != 0;
                 }
                 i += 1;
             }
         }
         if !any {
             *socks.offset(1 as libc::c_int as isize) = (*conn).sock[1 as libc::c_int as usize];
             bits |= (1 as libc::c_int) << 16 as libc::c_int + 1 as libc::c_int
                 | (1 as libc::c_int) << 1 as libc::c_int;
         }
         return bits;
     }
     return Curl_pp_getsock(data, &mut (*conn).proto.ftpc.pp, socks);
 }
 unsafe extern "C" fn ftp_state_cwd(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*ftpc).cwddone {
         result = ftp_state_mdtm(data);
     } else {
         #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
         if (*data).set.ftp_filemethod as libc::c_uint
             != FTPFILE_NOCWD as libc::c_int as libc::c_uint
             || !((*ftpc).dirdepth != 0
                 && *(*((*ftpc).dirs).offset(0 as libc::c_int as isize))
                     .offset(0 as libc::c_int as isize) as libc::c_int
                     == '/' as i32)
         {
         } else {
             __assert_fail(
                 b"(data->set.ftp_filemethod != FTPFILE_NOCWD) || !(ftpc->dirdepth && ftpc->dirs[0][0] == '/')\0"
                     as *const u8 as *const libc::c_char,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
                 875 as libc::c_int as libc::c_uint,
                 (*::std::mem::transmute::<
                     &[u8; 65],
                     &[libc::c_char; 65],
                 >(b"CURLcode ftp_state_cwd(struct Curl_easy *, struct connectdata *)\0"))
                     .as_ptr(),
             );
         }
         (*ftpc).count2 = 0 as libc::c_int;
         (*ftpc).count3 = if (*data).set.ftp_create_missing_dirs == 2 as libc::c_int {
             1 as libc::c_int
         } else {
             0 as libc::c_int
         };
         if ((*conn).bits).reuse() as libc::c_int != 0
             && !((*ftpc).entrypath).is_null()
             && !((*ftpc).dirdepth != 0
                 && *(*((*ftpc).dirs).offset(0 as libc::c_int as isize))
                     .offset(0 as libc::c_int as isize) as libc::c_int
                     == '/' as i32)
         {
             (*ftpc).cwdcount = 0 as libc::c_int;
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"CWD %s\0" as *const u8 as *const libc::c_char,
                 (*ftpc).entrypath,
             );
             if result as u64 == 0 {
                 #[cfg(not(DEBUGBUILD))]
                 _state(data, FTP_CWD);
 
                 #[cfg(DEBUGBUILD)]
                 _state(data, FTP_CWD, 894 as libc::c_int);
             }
         } else if (*ftpc).dirdepth != 0 {
             (*ftpc).cwdcount = 1 as libc::c_int;
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"CWD %s\0" as *const u8 as *const libc::c_char,
                 *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
             );
             if result as u64 == 0 {
                 #[cfg(not(DEBUGBUILD))]
                 _state(data, FTP_CWD);
 
                 #[cfg(DEBUGBUILD)]
                 _state(data, FTP_CWD, 904 as libc::c_int);
             }
         } else {
             result = ftp_state_mdtm(data);
         }
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_use_port(mut data: *mut Curl_easy, mut fcmd: ftpport) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut portsock: curl_socket_t = -(1 as libc::c_int);
     let mut myhost: [libc::c_char; 47] = *::std::mem::transmute::<
         &[u8; 47],
         &mut [libc::c_char; 47],
     >(
         b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
     );
     let mut ss: Curl_sockaddr_storage = Curl_sockaddr_storage {
         buffer: C2RustUnnamed_9 {
             sa: sockaddr {
                 sa_family: 0,
                 sa_data: [0; 14],
             },
         },
     };
     let mut res: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
     let mut ai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
     let mut sslen: curl_socklen_t = 0;
     let mut hbuf: [libc::c_char; 1025] = [0; 1025];
     let mut sa: *mut sockaddr = &mut ss as *mut Curl_sockaddr_storage as *mut sockaddr;
     let sa4: *mut sockaddr_in = sa as *mut libc::c_void as *mut sockaddr_in;
     #[cfg(ENABLE_IPV6)]
     let sa6: *mut sockaddr_in6 = sa as *mut libc::c_void as *mut sockaddr_in6;
     static mut mode: [[libc::c_char; 5]; 2] = unsafe {
         [
             *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"EPRT\0"),
             *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"PORT\0"),
         ]
     };
     let mut rc: resolve_t = CURLRESOLV_RESOLVED;
     let mut error: libc::c_int = 0;
     let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut string_ftpport: *mut libc::c_char =
         (*data).set.str_0[STRING_FTPPORT as libc::c_int as usize];
     let mut h: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
     let mut port_min: libc::c_ushort = 0 as libc::c_int as libc::c_ushort;
     let mut port_max: libc::c_ushort = 0 as libc::c_int as libc::c_ushort;
     let mut port: libc::c_ushort = 0;
     let mut possibly_non_local: bool = 1 as libc::c_int != 0;
     let mut buffer: [libc::c_char; 256] = [0; 256];
     let mut addr: *mut libc::c_char = 0 as *mut libc::c_char;
     if !((*data).set.str_0[STRING_FTPPORT as libc::c_int as usize]).is_null()
         && strlen((*data).set.str_0[STRING_FTPPORT as libc::c_int as usize])
             > 1 as libc::c_int as libc::c_ulong
     {
         #[cfg(ENABLE_IPV6)]
         let mut addrlen: size_t = if 46 as libc::c_int as libc::c_ulong > strlen(string_ftpport) {
             46 as libc::c_int as libc::c_ulong
         } else {
             strlen(string_ftpport)
         };
         #[cfg(not(ENABLE_IPV6))]
         let mut addrlen: size_t = if 16 as libc::c_int as libc::c_ulong
             > strlen(string_ftpport)
         {
             16 as libc::c_int as libc::c_ulong
         } else {
             strlen(string_ftpport)
         };
         let mut ip_start: *mut libc::c_char = string_ftpport;
         let mut ip_end: *mut libc::c_char = 0 as *mut libc::c_char;
         let mut port_start: *mut libc::c_char = 0 as *mut libc::c_char;
         let mut port_sep: *mut libc::c_char = 0 as *mut libc::c_char;
         match () {
             #[cfg(not(CURLDEBUG))]
             _ => {
                 addr = Curl_ccalloc.expect("non-null function pointer")(
                     addrlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                     1 as libc::c_int as size_t,
                 ) as *mut libc::c_char;
             }
             #[cfg(CURLDEBUG)]
             _ => {
                 addr = curl_dbg_calloc(
                     addrlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                     1 as libc::c_int as size_t,
                     972 as libc::c_int,
                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                 ) as *mut libc::c_char;
             }
         }
         
         if addr.is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
         let flag: bool = if cfg!(ENABLE_IPV6) {
             *string_ftpport as libc::c_int == '[' as i32
         } else {
             false
         };
         if flag
         {
             ip_start = string_ftpport.offset(1 as libc::c_int as isize);
             ip_end = strchr(string_ftpport, ']' as i32);
             if !ip_end.is_null() {
                 strncpy(
                     addr,
                     ip_start,
                     ip_end.offset_from(ip_start) as libc::c_long as libc::c_ulong,
                 );
             }
         } else if *string_ftpport as libc::c_int == ':' as i32 {
             ip_end = string_ftpport;
         } else {
             ip_end = strchr(string_ftpport, ':' as i32);
             if !ip_end.is_null() {
                 #[cfg(ENABLE_IPV6)]
                 if inet_pton(10 as libc::c_int, string_ftpport, sa6 as *mut libc::c_void)
                     == 1 as libc::c_int
                 {
                     port_max = 0 as libc::c_int as libc::c_ushort;
                     port_min = port_max;
                     strcpy(addr, string_ftpport);
                     ip_end = 0 as *mut libc::c_char;
                 } else {
                     strncpy(
                         addr,
                         string_ftpport,
                         ip_end.offset_from(ip_start) as libc::c_long as libc::c_ulong,
                     );
                 }
                 #[cfg(not(ENABLE_IPV6))]
                 strncpy(
                     addr,
                     string_ftpport,
                     ip_end.offset_from(ip_start) as libc::c_long as libc::c_ulong,
                 );
             } else {
                 strcpy(addr, string_ftpport);
             }
         }
         if !ip_end.is_null() {
             port_start = strchr(ip_end, ':' as i32);
             if !port_start.is_null() {
                 port_min = curlx_ultous(strtoul(
                     port_start.offset(1 as libc::c_int as isize),
                     0 as *mut *mut libc::c_char,
                     10 as libc::c_int,
                 ));
                 port_sep = strchr(port_start, '-' as i32);
                 if !port_sep.is_null() {
                     port_max = curlx_ultous(strtoul(
                         port_sep.offset(1 as libc::c_int as isize),
                         0 as *mut *mut libc::c_char,
                         10 as libc::c_int,
                     ));
                 } else {
                     port_max = port_min;
                 }
             }
         }
         if port_min as libc::c_int > port_max as libc::c_int {
             port_max = 0 as libc::c_int as libc::c_ushort;
             port_min = port_max;
         }
         if *addr as libc::c_int != '\0' as i32 {
             match Curl_if2ip(
                 (*(*conn).ip_addr).ai_family,
                 Curl_ipv6_scope((*(*conn).ip_addr).ai_addr),
                 (*conn).scope_id,
                 addr,
                 hbuf.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as libc::c_int,
             ) as libc::c_uint
             {
                 0 => {
                     host = addr;
                 }
                 1 => return CURLE_FTP_PORT_FAILED,
                 2 => {
                     host = hbuf.as_mut_ptr();
                 }
                 _ => {}
             }
         } else {
             host = 0 as *mut libc::c_char;
         }
     }
     if host.is_null() {
         let mut r: *const libc::c_char = 0 as *const libc::c_char;
         sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as libc::c_ulong as curl_socklen_t;
         if getsockname((*conn).sock[0 as libc::c_int as usize], sa, &mut sslen) != 0 {
             Curl_failf(
                 data,
                 b"getsockname() failed: %s\0" as *const u8 as *const libc::c_char,
                 Curl_strerror(
                     *__errno_location(),
                     buffer.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                 ),
             );
             #[cfg(not(CURLDEBUG))]
             Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void);
            
             #[cfg(CURLDEBUG)]        
             curl_dbg_free(
                 addr as *mut libc::c_void,
                 1063 as libc::c_int,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_FTP_PORT_FAILED;
         }
         match (*sa).sa_family as libc::c_int {
             #[cfg(ENABLE_IPV6)]
             10 => {
                 r = inet_ntop(
                     (*sa).sa_family as libc::c_int,
                     &mut (*sa6).sin6_addr as *mut in6_addr as *const libc::c_void,
                     hbuf.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong
                         as curl_socklen_t,
                 );
             }
             _ => {
                 r = inet_ntop(
                     (*sa).sa_family as libc::c_int,
                     &mut (*sa4).sin_addr as *mut in_addr as *const libc::c_void,
                     hbuf.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong
                         as curl_socklen_t,
                 );
             }
         }
         if r.is_null() {
             return CURLE_FTP_PORT_FAILED;
         }
         host = hbuf.as_mut_ptr();
         possibly_non_local = 0 as libc::c_int != 0;
     }
     rc = Curl_resolv(data, host, 0 as libc::c_int, 0 as libc::c_int != 0, &mut h);
     if rc as libc::c_int == CURLRESOLV_PENDING as libc::c_int {
         Curl_resolver_wait_resolv(data, &mut h);
     }
     if !h.is_null() {
         res = (*h).addr;
         Curl_resolv_unlock(data, h);
     } else {
         res = 0 as *mut Curl_addrinfo;
     }
     if res.is_null() {
         Curl_failf(
             data,
             b"failed to resolve the address provided to PORT: %s\0" as *const u8
                 as *const libc::c_char,
             host,
         );
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
             addr as *mut libc::c_void,
             1097 as libc::c_int,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_FTP_PORT_FAILED;
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         addr as *mut libc::c_void,
         1101 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     host = 0 as *mut libc::c_char;
     portsock = -(1 as libc::c_int);
     error = 0 as libc::c_int;
     ai = res;
     while !ai.is_null() {
         result = Curl_socket(data, ai, 0 as *mut Curl_sockaddr_ex, &mut portsock);
         if !(result as u64 != 0) {
             break;
         }
         error = *__errno_location();
         ai = (*ai).ai_next;
     }
     if ai.is_null() {
         Curl_failf(
             data,
             b"socket failure: %s\0" as *const u8 as *const libc::c_char,
             Curl_strerror(
                 error,
                 buffer.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
             ),
         );
         return CURLE_FTP_PORT_FAILED;
     }
     memcpy(
         sa as *mut libc::c_void,
         (*ai).ai_addr as *const libc::c_void,
         (*ai).ai_addrlen as libc::c_ulong,
     );
     sslen = (*ai).ai_addrlen;
     port = port_min;
     while port as libc::c_int <= port_max as libc::c_int {
         if (*sa).sa_family as libc::c_int == 2 as libc::c_int {
             (*sa4).sin_port = htons(port);
         } else {
             match () {
                 #[cfg(ENABLE_IPV6)]
                 _ => {
                     (*sa6).sin6_port = htons(port);
                 }
                 #[cfg(not(ENABLE_IPV6))]
                 _ => { }
             }
         }
         if !(bind(portsock, sa, sslen) != 0) {
             break;
         }
         error = *__errno_location();
         if possibly_non_local as libc::c_int != 0 && error == 99 as libc::c_int {
             Curl_infof(
                 data,
                 b"bind(port=%hu) on non-local address failed: %s\0" as *const u8
                     as *const libc::c_char,
                 port as libc::c_int,
                 Curl_strerror(
                     error,
                     buffer.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                 ),
             );
             sslen =
                 ::std::mem::size_of::<Curl_sockaddr_storage>() as libc::c_ulong as curl_socklen_t;
             if getsockname((*conn).sock[0 as libc::c_int as usize], sa, &mut sslen) != 0 {
                 Curl_failf(
                     data,
                     b"getsockname() failed: %s\0" as *const u8 as *const libc::c_char,
                     Curl_strerror(
                         *__errno_location(),
                         buffer.as_mut_ptr(),
                         ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                     ),
                 );
                 Curl_closesocket(data, conn, portsock);
                 return CURLE_FTP_PORT_FAILED;
             }
             port = port_min;
             possibly_non_local = 0 as libc::c_int != 0;
         } else {
             if error != 98 as libc::c_int && error != 13 as libc::c_int {
                 Curl_failf(
                     data,
                     b"bind(port=%hu) failed: %s\0" as *const u8 as *const libc::c_char,
                     port as libc::c_int,
                     Curl_strerror(
                         error,
                         buffer.as_mut_ptr(),
                         ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                     ),
                 );
                 Curl_closesocket(data, conn, portsock);
                 return CURLE_FTP_PORT_FAILED;
             }
             port = port.wrapping_add(1);
         }
     }
     if port as libc::c_int > port_max as libc::c_int {
         Curl_failf(
             data,
             b"bind() failed, we ran out of ports!\0" as *const u8 as *const libc::c_char,
         );
         Curl_closesocket(data, conn, portsock);
         return CURLE_FTP_PORT_FAILED;
     }
     sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as libc::c_ulong as curl_socklen_t;
     if getsockname(portsock, sa, &mut sslen) != 0 {
         Curl_failf(
             data,
             b"getsockname() failed: %s\0" as *const u8 as *const libc::c_char,
             Curl_strerror(
                 *__errno_location(),
                 buffer.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
             ),
         );
         Curl_closesocket(data, conn, portsock);
         return CURLE_FTP_PORT_FAILED;
     }
     if listen(portsock, 1 as libc::c_int) != 0 {
         Curl_failf(
             data,
             b"socket failure: %s\0" as *const u8 as *const libc::c_char,
             Curl_strerror(
                 *__errno_location(),
                 buffer.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
             ),
         );
         Curl_closesocket(data, conn, portsock);
         return CURLE_FTP_PORT_FAILED;
     }
     Curl_printable_address(
         ai,
         myhost.as_mut_ptr(),
         ::std::mem::size_of::<[libc::c_char; 47]>() as libc::c_ulong,
     );
     #[cfg(ENABLE_IPV6)]
     if ((*conn).bits).ftp_use_eprt() == 0 && ((*conn).bits).ipv6() as libc::c_int != 0 {
         let ref mut fresh8 = (*conn).bits;
         (*fresh8).set_ftp_use_eprt(1 as libc::c_int as bit);
     }
     while fcmd as libc::c_uint != DONE as libc::c_int as libc::c_uint {
         if !(((*conn).bits).ftp_use_eprt() == 0
             && EPRT as libc::c_int as libc::c_uint == fcmd as libc::c_uint)
         {
             if !(PORT as libc::c_int as libc::c_uint == fcmd as libc::c_uint
                 && (*sa).sa_family as libc::c_int != 2 as libc::c_int)
             {
                 match (*sa).sa_family as libc::c_int {
                     2 => {
                         port = __bswap_16((*sa4).sin_port);
                         if EPRT as libc::c_int as libc::c_uint == fcmd as libc::c_uint {
                             result = Curl_pp_sendf(
                                 data,
                                 &mut (*ftpc).pp as *mut pingpong,
                                 b"%s |%d|%s|%hu|\0" as *const u8 as *const libc::c_char,
                                 (mode[fcmd as usize]).as_ptr(),
                                 if (*sa).sa_family as libc::c_int == 2 as libc::c_int {
                                     1 as libc::c_int
                                 } else {
                                     2 as libc::c_int
                                 },
                                 myhost.as_mut_ptr(),
                                 port as libc::c_int,
                             );
                             if result as u64 != 0 {
                                 Curl_failf(
                                     data,
                                     b"Failure sending EPRT command: %s\0" as *const u8
                                         as *const libc::c_char,
                                     curl_easy_strerror(result),
                                 );
                                 Curl_closesocket(data, conn, portsock);
                                 (*ftpc).count1 = PORT as libc::c_int;
                                 #[cfg(not(DEBUGBUILD))]
                                 _state(data, FTP_STOP);
 
                                 #[cfg(DEBUGBUILD)]
                                 _state(data, FTP_STOP, 1250 as libc::c_int);
                                 return result;
                             }
                             break;
                         } else if PORT as libc::c_int as libc::c_uint == fcmd as libc::c_uint {
                             let mut target: [libc::c_char; 67] = [0; 67];
                             let mut source: *mut libc::c_char = myhost.as_mut_ptr();
                             let mut dest: *mut libc::c_char = target.as_mut_ptr();
                             while !source.is_null() && *source as libc::c_int != 0 {
                                 if *source as libc::c_int == '.' as i32 {
                                     *dest = ',' as i32 as libc::c_char;
                                 } else {
                                     *dest = *source;
                                 }
                                 dest = dest.offset(1);
                                 source = source.offset(1);
                             }
                             *dest = 0 as libc::c_int as libc::c_char;
                             curl_msnprintf(
                                 dest,
                                 20 as libc::c_int as size_t,
                                 b",%d,%d\0" as *const u8 as *const libc::c_char,
                                 port as libc::c_int >> 8 as libc::c_int,
                                 port as libc::c_int & 0xff as libc::c_int,
                             );
                             result = Curl_pp_sendf(
                                 data,
                                 &mut (*ftpc).pp as *mut pingpong,
                                 b"%s %s\0" as *const u8 as *const libc::c_char,
                                 (mode[fcmd as usize]).as_ptr(),
                                 target.as_mut_ptr(),
                             );
                             if result as u64 != 0 {
                                 Curl_failf(
                                     data,
                                     b"Failure sending PORT command: %s\0" as *const u8
                                         as *const libc::c_char,
                                     curl_easy_strerror(result),
                                 );
                                 Curl_closesocket(data, conn, portsock);
                                 #[cfg(not(DEBUGBUILD))]
                                 _state(data, FTP_STOP);
 
                                 #[cfg(DEBUGBUILD)]
                                 _state(data, FTP_STOP, 1279 as libc::c_int);
                                 return result;
                             }
                             break;
                         }
                     }
                     #[cfg(ENABLE_IPV6)]
                     10 => {
                         port = __bswap_16((*sa6).sin6_port);
                         if EPRT as libc::c_int as libc::c_uint == fcmd as libc::c_uint {
                             result = Curl_pp_sendf(
                                 data,
                                 &mut (*ftpc).pp as *mut pingpong,
                                 b"%s |%d|%s|%hu|\0" as *const u8 as *const libc::c_char,
                                 (mode[fcmd as usize]).as_ptr(),
                                 if (*sa).sa_family as libc::c_int == 2 as libc::c_int {
                                     1 as libc::c_int
                                 } else {
                                     2 as libc::c_int
                                 },
                                 myhost.as_mut_ptr(),
                                 port as libc::c_int,
                             );
                             if result as u64 != 0 {
                                 Curl_failf(
                                     data,
                                     b"Failure sending EPRT command: %s\0" as *const u8
                                         as *const libc::c_char,
                                     curl_easy_strerror(result),
                                 );
                                 Curl_closesocket(data, conn, portsock);
                                 (*ftpc).count1 = PORT as libc::c_int;
                                 #[cfg(not(DEBUGBUILD))]
                                 _state(data, FTP_STOP);
 
                                 #[cfg(DEBUGBUILD)]
                                 _state(data, FTP_STOP, 1250 as libc::c_int);
                                 return result;
                             }
                             break;
                         } else if PORT as libc::c_int as libc::c_uint == fcmd as libc::c_uint {
                             let mut target: [libc::c_char; 67] = [0; 67];
                             let mut source: *mut libc::c_char = myhost.as_mut_ptr();
                             let mut dest: *mut libc::c_char = target.as_mut_ptr();
                             while !source.is_null() && *source as libc::c_int != 0 {
                                 if *source as libc::c_int == '.' as i32 {
                                     *dest = ',' as i32 as libc::c_char;
                                 } else {
                                     *dest = *source;
                                 }
                                 dest = dest.offset(1);
                                 source = source.offset(1);
                             }
                             *dest = 0 as libc::c_int as libc::c_char;
                             curl_msnprintf(
                                 dest,
                                 20 as libc::c_int as size_t,
                                 b",%d,%d\0" as *const u8 as *const libc::c_char,
                                 port as libc::c_int >> 8 as libc::c_int,
                                 port as libc::c_int & 0xff as libc::c_int,
                             );
                             result = Curl_pp_sendf(
                                 data,
                                 &mut (*ftpc).pp as *mut pingpong,
                                 b"%s %s\0" as *const u8 as *const libc::c_char,
                                 (mode[fcmd as usize]).as_ptr(),
                                 target.as_mut_ptr(),
                             );
                             if result as u64 != 0 {
                                 Curl_failf(
                                     data,
                                     b"Failure sending PORT command: %s\0" as *const u8
                                         as *const libc::c_char,
                                     curl_easy_strerror(result),
                                 );
                                 Curl_closesocket(data, conn, portsock);
                                 #[cfg(not(DEBUGBUILD))]
                                 _state(data, FTP_STOP);
 
                                 #[cfg(DEBUGBUILD)]
                                 _state(data, FTP_STOP, 1279 as libc::c_int);
                                 return result;
                             }
                             break;
                         }
                     }
                     _ => {}
                 }
             }
         }
         fcmd += 1;
     }
     (*ftpc).count1 = fcmd as libc::c_int;
     close_secondarysocket(data, conn);
     (*conn).sock[1 as libc::c_int as usize] = portsock;
     (*conn).bits.tcpconnect[1 as libc::c_int as usize] = 1 as libc::c_int != 0;
     #[cfg(not(DEBUGBUILD))]
     _state(data, FTP_PORT);
 
     #[cfg(DEBUGBUILD)]
     _state(data, FTP_PORT, 1305 as libc::c_int);
     return result;
 }
 unsafe extern "C" fn ftp_state_use_pasv(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut result: CURLcode = CURLE_OK;
     static mut mode: [[libc::c_char; 5]; 2] = unsafe {
         [
             *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"EPSV\0"),
             *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"PASV\0"),
         ]
     };
     let mut modeoff: libc::c_int = 0;
     #[cfg(PF_INET6)]
     if ((*conn).bits).ftp_use_epsv() == 0 && ((*conn).bits).ipv6() as libc::c_int != 0 {
         let ref mut fresh9 = (*conn).bits;
         (*fresh9).set_ftp_use_epsv(1 as libc::c_int as bit);
     }
     modeoff = if ((*conn).bits).ftp_use_epsv() as libc::c_int != 0 {
         0 as libc::c_int
     } else {
         1 as libc::c_int
     };
     result = Curl_pp_sendf(
         data,
         &mut (*ftpc).pp as *mut pingpong,
         b"%s\0" as *const u8 as *const libc::c_char,
         (mode[modeoff as usize]).as_ptr(),
     );
     if result as u64 == 0 {
         (*ftpc).count1 = modeoff;
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_PASV);
 
         #[cfg(DEBUGBUILD)]
         _state(data, FTP_PASV, 1343 as libc::c_int);
         Curl_infof(
             data,
             b"Connect data stream passively\0" as *const u8 as *const libc::c_char,
         );
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_prepare_transfer(mut data: *mut Curl_easy) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     if (*ftp).transfer as libc::c_uint != PPTRANSFER_BODY as libc::c_int as libc::c_uint {
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_RETR_PREQUOTE);
 
         #[cfg(DEBUGBUILD)]
         _state(data, FTP_RETR_PREQUOTE, 1366 as libc::c_int);
         result = ftp_state_quote(data, 1 as libc::c_int != 0, FTP_RETR_PREQUOTE);
     } else if ((*data).set).ftp_use_port() != 0 {
         result = ftp_state_use_port(data, EPRT);
     } else if ((*data).set).ftp_use_pret() != 0 {
         let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
         if ((*conn).proto.ftpc.file).is_null() {
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"PRET %s\0" as *const u8 as *const libc::c_char,
                 if !((*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize]).is_null() {
                     (*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize]
                         as *const libc::c_char
                 } else if ((*data).state).list_only() as libc::c_int != 0 {
                     b"NLST\0" as *const u8 as *const libc::c_char
                 } else {
                     b"LIST\0" as *const u8 as *const libc::c_char
                 },
             );
         } else if ((*data).set).upload() != 0 {
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"PRET STOR %s\0" as *const u8 as *const libc::c_char,
                 (*conn).proto.ftpc.file,
             );
         } else {
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"PRET RETR %s\0" as *const u8 as *const libc::c_char,
                 (*conn).proto.ftpc.file,
             );
         }
         if result as u64 == 0 {
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_PRET);
 
             #[cfg(DEBUGBUILD)]
             _state(data, FTP_PRET, 1391 as libc::c_int);
         }
     } else {
         result = ftp_state_use_pasv(data, conn);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_rest(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*ftp).transfer as libc::c_uint != PPTRANSFER_BODY as libc::c_int as libc::c_uint
         && !((*ftpc).file).is_null()
     {
         result = Curl_pp_sendf(
             data,
             &mut (*ftpc).pp as *mut pingpong,
             b"REST %d\0" as *const u8 as *const libc::c_char,
             0 as libc::c_int,
         );
         if result as u64 == 0 {
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_REST);
 
             #[cfg(DEBUGBUILD)]
             _state(data, FTP_REST, 1413 as libc::c_int);
         }
     } else {
         result = ftp_state_prepare_transfer(data);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_size(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*ftp).transfer as libc::c_uint == PPTRANSFER_INFO as libc::c_int as libc::c_uint
         && !((*ftpc).file).is_null()
     {
         result = Curl_pp_sendf(
             data,
             &mut (*ftpc).pp as *mut pingpong,
             b"SIZE %s\0" as *const u8 as *const libc::c_char,
             (*ftpc).file,
         );
         if result as u64 == 0 {
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_SIZE);
 
             #[cfg(DEBUGBUILD)]
             _state(data, FTP_SIZE, 1434 as libc::c_int);
         }
     } else {
         result = ftp_state_rest(data, conn);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_list(mut data: *mut Curl_easy) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut lstArg: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut cmd: *mut libc::c_char = 0 as *mut libc::c_char;
     if (*data).set.ftp_filemethod as libc::c_uint == FTPFILE_NOCWD as libc::c_int as libc::c_uint
         && !((*ftp).path).is_null()
     {
         let mut slashPos: *const libc::c_char = 0 as *const libc::c_char;
         let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;
         result = Curl_urldecode(
             data,
             (*ftp).path,
             0 as libc::c_int as size_t,
             &mut rawPath,
             0 as *mut size_t,
             REJECT_CTRL,
         );
         if result as u64 != 0 {
             return result;
         }
         slashPos = strrchr(rawPath, '/' as i32);
         if !slashPos.is_null() {
             let mut n: size_t = slashPos.offset_from(rawPath) as libc::c_long as size_t;
             if n == 0 as libc::c_int as libc::c_ulong {
                 n = n.wrapping_add(1);
             }
             lstArg = rawPath;
             *lstArg.offset(n as isize) = '\0' as i32 as libc::c_char;
         } else {
             #[cfg(not(CURLDEBUG))]
             Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);
 
             #[cfg(CURLDEBUG)]
             curl_dbg_free(
                 rawPath as *mut libc::c_void,
                 1484 as libc::c_int,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
         }
     }
     cmd = curl_maprintf(
         b"%s%s%s\0" as *const u8 as *const libc::c_char,
         if !((*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize]).is_null() {
             (*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize] as *const libc::c_char
         } else if ((*data).state).list_only() as libc::c_int != 0 {
             b"NLST\0" as *const u8 as *const libc::c_char
         } else {
             b"LIST\0" as *const u8 as *const libc::c_char
         },
         if !lstArg.is_null() {
             b" \0" as *const u8 as *const libc::c_char
         } else {
             b"\0" as *const u8 as *const libc::c_char
         },
         if !lstArg.is_null() {
             lstArg as *const libc::c_char
         } else {
             b"\0" as *const u8 as *const libc::c_char
         },
     );
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(lstArg as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         lstArg as *mut libc::c_void,
         1493 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     if cmd.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     result = Curl_pp_sendf(
         data,
         &mut (*conn).proto.ftpc.pp as *mut pingpong,
         b"%s\0" as *const u8 as *const libc::c_char,
         cmd,
     );
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(cmd as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         cmd as *mut libc::c_void,
         1499 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     if result as u64 == 0 {
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_LIST);
 
         #[cfg(DEBUGBUILD)]
         _state(data, FTP_LIST, 1502 as libc::c_int);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_retr_prequote(mut data: *mut Curl_easy) -> CURLcode {
     return ftp_state_quote(data, 1 as libc::c_int != 0, FTP_RETR_PREQUOTE);
 }
 unsafe extern "C" fn ftp_state_stor_prequote(mut data: *mut Curl_easy) -> CURLcode {
     return ftp_state_quote(data, 1 as libc::c_int != 0, FTP_STOR_PREQUOTE);
 }
 unsafe extern "C" fn ftp_state_type(mut data: *mut Curl_easy) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if ((*data).set).opt_no_body() as libc::c_int != 0
         && !((*ftpc).file).is_null()
         && ftp_need_type(conn, ((*data).state).prefer_ascii() != 0) != 0
     {
         (*ftp).transfer = PPTRANSFER_INFO;
         result = ftp_nb_type(data, conn, ((*data).state).prefer_ascii() != 0, FTP_TYPE);
         if result as u64 != 0 {
             return result;
         }
     } else {
         result = ftp_state_size(data, conn);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_mdtm(mut data: *mut Curl_easy) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (((*data).set).get_filetime() as libc::c_int != 0
         || (*data).set.timecondition as libc::c_uint != 0)
         && !((*ftpc).file).is_null()
     {
         result = Curl_pp_sendf(
             data,
             &mut (*ftpc).pp as *mut pingpong,
             b"MDTM %s\0" as *const u8 as *const libc::c_char,
             (*ftpc).file,
         );
         if result as u64 == 0 {
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_MDTM);
 
             #[cfg(DEBUGBUILD)]
             _state(data, FTP_MDTM, 1566 as libc::c_int);
         }
     } else {
         result = ftp_state_type(data);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_ul_setup(
     mut data: *mut Curl_easy,
     mut sizechecked: bool,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut append: bool = ((*data).set).remote_append() != 0;
     if (*data).state.resume_from != 0 && !sizechecked
         || (*data).state.resume_from > 0 as libc::c_int as libc::c_long
             && sizechecked as libc::c_int != 0
     {
         let mut seekerr: libc::c_int = 0 as libc::c_int;
         if (*data).state.resume_from < 0 as libc::c_int as libc::c_long {
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"SIZE %s\0" as *const u8 as *const libc::c_char,
                 (*ftpc).file,
             );
             if result as u64 == 0 {
                 #[cfg(not(DEBUGBUILD))]
                 _state(data, FTP_STOR_SIZE);
 
                 #[cfg(DEBUGBUILD)]
                 _state(data, FTP_STOR_SIZE, 1605 as libc::c_int);
             }
             return result;
         }
         append = 1 as libc::c_int != 0;
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
                 return CURLE_FTP_COULDNT_USE_REST;
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
                         b"Failed to read data\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_FTP_COULDNT_USE_REST;
                 }
                 if !(passed < (*data).state.resume_from) {
                     break;
                 }
             }
         }
         if (*data).state.infilesize > 0 as libc::c_int as libc::c_long {
             let ref mut fresh10 = (*data).state.infilesize;
             *fresh10 -= (*data).state.resume_from;
             if (*data).state.infilesize <= 0 as libc::c_int as libc::c_long {
                 Curl_infof(
                     data,
                     b"File already completely uploaded\0" as *const u8 as *const libc::c_char,
                 );
                 Curl_setup_transfer(
                     data,
                     -(1 as libc::c_int),
                     -(1 as libc::c_int) as curl_off_t,
                     0 as libc::c_int != 0,
                     -(1 as libc::c_int),
                 );
                 (*ftp).transfer = PPTRANSFER_NONE;
                 #[cfg(not(DEBUGBUILD))]
                 _state(data, FTP_STOP);
 
                 #[cfg(DEBUGBUILD)]
                 _state(data, FTP_STOP, 1660 as libc::c_int);
                 return CURLE_OK;
             }
         }
     }
     result = Curl_pp_sendf(
         data,
         &mut (*ftpc).pp as *mut pingpong,
         if append as libc::c_int != 0 {
             b"APPE %s\0" as *const u8 as *const libc::c_char
         } else {
             b"STOR %s\0" as *const u8 as *const libc::c_char
         },
         (*ftpc).file,
     );
     if result as u64 == 0 {
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_STOR);
 
         #[cfg(DEBUGBUILD)]
         _state(data, FTP_STOR, 1670 as libc::c_int);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_quote(
     mut data: *mut Curl_easy,
     mut init: bool,
     mut instate: ftpstate,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut quote: bool = 0 as libc::c_int != 0;
     let mut item: *mut curl_slist = 0 as *mut curl_slist;
     match instate as libc::c_uint {
         13 | 14 => {
             item = (*data).set.prequote;
         }
         15 => {
             item = (*data).set.postquote;
         }
         12 | _ => {
             item = (*data).set.quote;
         }
     }
     if init {
         (*ftpc).count1 = 0 as libc::c_int;
     } else {
         let ref mut fresh11 = (*ftpc).count1;
         *fresh11 += 1;
     }
     if !item.is_null() {
         let mut i: libc::c_int = 0 as libc::c_int;
         while i < (*ftpc).count1 && !item.is_null() {
             item = (*item).next;
             i += 1;
         }
         if !item.is_null() {
             let mut cmd: *mut libc::c_char = (*item).data;
             if *cmd.offset(0 as libc::c_int as isize) as libc::c_int == '*' as i32 {
                 cmd = cmd.offset(1);
                 (*ftpc).count2 = 1 as libc::c_int;
             } else {
                 (*ftpc).count2 = 0 as libc::c_int;
             }
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"%s\0" as *const u8 as *const libc::c_char,
                 cmd,
             );
             if result as u64 != 0 {
                 return result;
             }
             #[cfg(not(DEBUGBUILD))]
             _state(data, instate);
 
     #[cfg(DEBUGBUILD)]
             _state(data, instate, 1731 as libc::c_int);
             quote = 1 as libc::c_int != 0;
         }
     }
     if !quote {
         match instate as libc::c_uint {
             13 => {
                 if (*ftp).transfer as libc::c_uint != PPTRANSFER_BODY as libc::c_int as libc::c_uint
                 {
                     #[cfg(not(DEBUGBUILD))]
                     _state(data, FTP_STOP);
 
     #[cfg(DEBUGBUILD)]
                     _state(data, FTP_STOP, 1745 as libc::c_int);
                 } else if (*ftpc).known_filesize != -(1 as libc::c_int) as libc::c_long {
                     Curl_pgrsSetDownloadSize(data, (*ftpc).known_filesize);
                     result = ftp_state_retr(data, (*ftpc).known_filesize);
                 } else if ((*data).set).ignorecl() as libc::c_int != 0
                     || ((*data).state).prefer_ascii() as libc::c_int != 0
                 {
                     result = Curl_pp_sendf(
                         data,
                         &mut (*ftpc).pp as *mut pingpong,
                         b"RETR %s\0" as *const u8 as *const libc::c_char,
                         (*ftpc).file,
                     );
                     if result as u64 == 0 {
                         #[cfg(not(DEBUGBUILD))]
                         _state(data, FTP_RETR);
 
     #[cfg(DEBUGBUILD)]
                         _state(data, FTP_RETR, 1767 as libc::c_int);
                     }
                 } else {
                     result = Curl_pp_sendf(
                         data,
                         &mut (*ftpc).pp as *mut pingpong,
                         b"SIZE %s\0" as *const u8 as *const libc::c_char,
                         (*ftpc).file,
                     );
                     if result as u64 == 0 {
                         #[cfg(not(DEBUGBUILD))]
                         _state(data, FTP_RETR_SIZE);
 
     #[cfg(DEBUGBUILD)]
                         _state(data, FTP_RETR_SIZE, 1772 as libc::c_int);
                     }
                 }
             }
             14 => {
                 result = ftp_state_ul_setup(data, 0 as libc::c_int != 0);
             }
             15 => {}
             12 | _ => {
                 result = ftp_state_cwd(data, conn);
             }
         }
     }
     return result;
 }
 unsafe extern "C" fn ftp_epsv_disable(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     // TODO 待验证
     #[cfg(not(CURL_DISABLE_PROXY))]
     let flag: bool = ((*conn).bits).ipv6() as libc::c_int != 0
             && !(((*conn).bits).tunnel_proxy() as libc::c_int != 0
                 || ((*conn).bits).socksproxy() as libc::c_int != 0);
     #[cfg(CURL_DISABLE_PROXY)]
     let flag: bool = ((*conn).bits).ipv6() as libc::c_int != 0;
     if flag
     {
         Curl_failf(
             data,
             b"Failed EPSV attempt, exiting\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_WEIRD_SERVER_REPLY;
     }
     Curl_infof(
         data,
         b"Failed EPSV attempt. Disabling EPSV\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh12 = (*conn).bits;
     (*fresh12).set_ftp_use_epsv(0 as libc::c_int as bit);
     let ref mut fresh13 = (*data).state;
     (*fresh13).set_errorbuf(0 as libc::c_int as bit);
     result = Curl_pp_sendf(
         data,
         &mut (*conn).proto.ftpc.pp as *mut pingpong,
         b"%s\0" as *const u8 as *const libc::c_char,
         b"PASV\0" as *const u8 as *const libc::c_char,
     );
     if result as u64 == 0 {
         let ref mut fresh14 = (*conn).proto.ftpc.count1;
         *fresh14 += 1;
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_PASV);
 
     #[cfg(DEBUGBUILD)]
         _state(data, FTP_PASV, 1814 as libc::c_int);
     }
     return result;
 }
 unsafe extern "C" fn control_address(mut conn: *mut connectdata) -> *mut libc::c_char {
     #[cfg(not(CURL_DISABLE_PROXY))]
     if ((*conn).bits).tunnel_proxy() as libc::c_int != 0
         || ((*conn).bits).socksproxy() as libc::c_int != 0
     {
         return (*conn).host.name;
     }
     return ((*conn).primary_ip).as_mut_ptr();
 }
 unsafe extern "C" fn ftp_state_pasv_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: libc::c_int,
 ) -> CURLcode {
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut result: CURLcode = CURLE_OK;
     let mut addr: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
     let mut rc: resolve_t = CURLRESOLV_RESOLVED;
     let mut connectport: libc::c_ushort = 0;
     let mut str: *mut libc::c_char =
         &mut *((*data).state.buffer).offset(4 as libc::c_int as isize) as *mut libc::c_char;
         #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
 
         #[cfg(CURLDEBUG)]
         curl_dbg_free(
         (*ftpc).newhost as *mut libc::c_void,
         1845 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh15 = (*ftpc).newhost;
     *fresh15 = 0 as *mut libc::c_char;
     if (*ftpc).count1 == 0 as libc::c_int && ftpcode == 229 as libc::c_int {
         let mut ptr: *mut libc::c_char = strchr(str, '(' as i32);
         if !ptr.is_null() {
             let mut num: libc::c_uint = 0;
             let mut separator: [libc::c_char; 4] = [0; 4];
             ptr = ptr.offset(1);
             if 5 as libc::c_int
                 == sscanf(
                     ptr,
                     b"%c%c%c%u%c\0" as *const u8 as *const libc::c_char,
                     &mut *separator.as_mut_ptr().offset(0 as libc::c_int as isize)
                         as *mut libc::c_char,
                     &mut *separator.as_mut_ptr().offset(1 as libc::c_int as isize)
                         as *mut libc::c_char,
                     &mut *separator.as_mut_ptr().offset(2 as libc::c_int as isize)
                         as *mut libc::c_char,
                     &mut num as *mut libc::c_uint,
                     &mut *separator.as_mut_ptr().offset(3 as libc::c_int as isize)
                         as *mut libc::c_char,
                 )
             {
                 let sep1: libc::c_char = separator[0 as libc::c_int as usize];
                 let mut i: libc::c_int = 0;
                 i = 1 as libc::c_int;
                 while i < 4 as libc::c_int {
                     if separator[i as usize] as libc::c_int != sep1 as libc::c_int {
                         ptr = 0 as *mut libc::c_char;
                         break;
                     } else {
                         i += 1;
                     }
                 }
                 if num > 0xffff as libc::c_int as libc::c_uint {
                     Curl_failf(
                         data,
                         b"Illegal port number in EPSV reply\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_FTP_WEIRD_PASV_REPLY;
                 }
                 if !ptr.is_null() {
                     (*ftpc).newport =
                         (num & 0xffff as libc::c_int as libc::c_uint) as libc::c_ushort;
                     match () {
                         #[cfg(not(CURLDEBUG))]
                         _ => {
                             (*ftpc).newhost =
                             Curl_cstrdup.expect("non-null function pointer")(control_address(conn));
                         }
                         #[cfg(CURLDEBUG)]
                         _ => {
                             (*ftpc).newhost = curl_dbg_strdup(
                                 control_address(conn),
                                 1878 as libc::c_int,
                                 b"ftp.c\0" as *const u8 as *const libc::c_char,
                             );
                         }
                     }
                     
                     if ((*ftpc).newhost).is_null() {
                         return CURLE_OUT_OF_MEMORY;
                     }
                 }
             } else {
                 ptr = 0 as *mut libc::c_char;
             }
         }
         if ptr.is_null() {
             Curl_failf(
                 data,
                 b"Weirdly formatted EPSV reply\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_FTP_WEIRD_PASV_REPLY;
         }
     } else if (*ftpc).count1 == 1 as libc::c_int && ftpcode == 227 as libc::c_int {
         let mut ip: [libc::c_uint; 4] = [
             0 as libc::c_int as libc::c_uint,
             0 as libc::c_int as libc::c_uint,
             0 as libc::c_int as libc::c_uint,
             0 as libc::c_int as libc::c_uint,
         ];
         let mut port: [libc::c_uint; 2] = [
             0 as libc::c_int as libc::c_uint,
             0 as libc::c_int as libc::c_uint,
         ];
         while *str != 0 {
             if 6 as libc::c_int
                 == sscanf(
                     str,
                     b"%u,%u,%u,%u,%u,%u\0" as *const u8 as *const libc::c_char,
                     &mut *ip.as_mut_ptr().offset(0 as libc::c_int as isize) as *mut libc::c_uint,
                     &mut *ip.as_mut_ptr().offset(1 as libc::c_int as isize) as *mut libc::c_uint,
                     &mut *ip.as_mut_ptr().offset(2 as libc::c_int as isize) as *mut libc::c_uint,
                     &mut *ip.as_mut_ptr().offset(3 as libc::c_int as isize) as *mut libc::c_uint,
                     &mut *port.as_mut_ptr().offset(0 as libc::c_int as isize) as *mut libc::c_uint,
                     &mut *port.as_mut_ptr().offset(1 as libc::c_int as isize) as *mut libc::c_uint,
                 )
             {
                 break;
             }
             str = str.offset(1);
         }
         if *str == 0
             || ip[0 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
             || ip[1 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
             || ip[2 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
             || ip[3 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
             || port[0 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
             || port[1 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
         {
             Curl_failf(
                 data,
                 b"Couldn't interpret the 227-response\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_FTP_WEIRD_227_FORMAT;
         }
         if ((*data).set).ftp_skip_ip() != 0 {
             Curl_infof(
                 data,
                 b"Skip %u.%u.%u.%u for data connection, re-use %s instead\0" as *const u8
                     as *const libc::c_char,
                 ip[0 as libc::c_int as usize],
                 ip[1 as libc::c_int as usize],
                 ip[2 as libc::c_int as usize],
                 ip[3 as libc::c_int as usize],
                 (*conn).host.name,
             );
             match () {
                 #[cfg(not(CURLDEBUG))]
                 _ => {
                     (*ftpc).newhost = Curl_cstrdup.expect("non-null function pointer")(control_address(conn));
     
                 }
                 #[cfg(CURLDEBUG)]
                 _ => {
                     (*ftpc).newhost = curl_dbg_strdup(
                         control_address(conn),
                         1927 as libc::c_int,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                 }
             }
             
             
         } else {
             let ref mut fresh18 = (*ftpc).newhost;
             *fresh18 = curl_maprintf(
                 b"%u.%u.%u.%u\0" as *const u8 as *const libc::c_char,
                 ip[0 as libc::c_int as usize],
                 ip[1 as libc::c_int as usize],
                 ip[2 as libc::c_int as usize],
                 ip[3 as libc::c_int as usize],
             );
         }
         if ((*ftpc).newhost).is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
         (*ftpc).newport = ((port[0 as libc::c_int as usize] << 8 as libc::c_int)
             .wrapping_add(port[1 as libc::c_int as usize])
             & 0xffff as libc::c_int as libc::c_uint) as libc::c_ushort;
     } else if (*ftpc).count1 == 0 as libc::c_int {
         return ftp_epsv_disable(data, conn);
     } else {
         Curl_failf(
             data,
             b"Bad PASV/EPSV response: %03d\0" as *const u8 as *const libc::c_char,
             ftpcode,
         );
         return CURLE_FTP_WEIRD_PASV_REPLY;
     }
     match () {
         #[cfg(not(CURL_DISABLE_PROXY))]
         _ => {
             if ((*conn).bits).proxy() != 0 {
                 let host_name: *const libc::c_char = if ((*conn).bits).socksproxy() as libc::c_int != 0 {
                     (*conn).socks_proxy.host.name
                 } else {
                     (*conn).http_proxy.host.name
                 };
                 rc = Curl_resolv(
                     data,
                     host_name,
                     (*conn).port,
                     0 as libc::c_int != 0,
                     &mut addr,
                 );
                 if rc as libc::c_int == CURLRESOLV_PENDING as libc::c_int {
                     Curl_resolver_wait_resolv(data, &mut addr);
                 }
                 connectport = (*conn).port as libc::c_ushort;
                 if addr.is_null() {
                     Curl_failf(
                         data,
                         b"Can't resolve proxy host %s:%hu\0" as *const u8 as *const libc::c_char,
                         host_name,
                         connectport as libc::c_int,
                     );
                     return CURLE_COULDNT_RESOLVE_PROXY;
                 }
             } else {
                 #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
                 if !((*ftpc).newhost).is_null() {
                 } else {
                     __assert_fail(
                         b"ftpc->newhost\0" as *const u8 as *const libc::c_char,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                         1973 as libc::c_int as libc::c_uint,
                         (*::std::mem::transmute::<&[u8; 54], &[libc::c_char; 54]>(
                             b"CURLcode ftp_state_pasv_resp(struct Curl_easy *, int)\0",
                         ))
                         .as_ptr(),
                     );
                 }
                 if ((*conn).bits).tcp_fastopen() as libc::c_int != 0
                     && ((*conn).bits).reuse() == 0
                     && *((*ftpc).newhost).offset(0 as libc::c_int as isize) == 0
                 {
                     Curl_conninfo_remote(data, conn, (*conn).sock[0 as libc::c_int as usize]);
                     #[cfg(not(CURLDEBUG))]
                     Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
                     
                     #[cfg(CURLDEBUG)]
                     curl_dbg_free(
                         (*ftpc).newhost as *mut libc::c_void,
                         1978 as libc::c_int,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                     let ref mut fresh19 = (*ftpc).newhost;
                     *fresh19 = 0 as *mut libc::c_char;
                     match () {
                         #[cfg(not(CURLDEBUG))]
                         _ => {
                             (*ftpc).newhost = Curl_cstrdup.expect("non-null function pointer")(control_address(conn));
                         }
                         #[cfg(CURLDEBUG)]
                         _ => {
                             (*ftpc).newhost = curl_dbg_strdup(
                                 control_address(conn),
                                 1979 as libc::c_int,
                                 b"ftp.c\0" as *const u8 as *const libc::c_char,
                             );
                         }
                     }
                     
                     if ((*ftpc).newhost).is_null() {
                         return CURLE_OUT_OF_MEMORY;
                     }
                 }
                 rc = Curl_resolv(
                     data,
                     (*ftpc).newhost,
                     (*ftpc).newport as libc::c_int,
                     0 as libc::c_int != 0,
                     &mut addr,
                 );
                 if rc as libc::c_int == CURLRESOLV_PENDING as libc::c_int {
                     Curl_resolver_wait_resolv(data, &mut addr);
                 }
                 connectport = (*ftpc).newport;
                 if addr.is_null() {
                     Curl_failf(
                         data,
                         b"Can't resolve new host %s:%hu\0" as *const u8 as *const libc::c_char,
                         (*ftpc).newhost,
                         connectport as libc::c_int,
                     );
                     return CURLE_FTP_CANT_GET_HOST;
                 }
             }
         }
         #[cfg(CURL_DISABLE_PROXY)]
         _ => {
             if ((*conn).bits).tcp_fastopen() as libc::c_int != 0
                 && ((*conn).bits).reuse() == 0
                 && *((*ftpc).newhost).offset(0 as libc::c_int as isize) == 0
             {
                 Curl_conninfo_remote(data, conn, (*conn).sock[0 as libc::c_int as usize]);
                 #[cfg(not(CURLDEBUG))]
                 Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
 
                 #[cfg(CURLDEBUG)]
                 Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
                 let ref mut fresh19 = (*ftpc).newhost;
                 *fresh19 = 0 as *mut libc::c_char;
                 let ref mut fresh20 = (*ftpc).newhost;
                 match () {
                     #[cfg(not(CURLDEBUG))]
                     _ => {
                         (*ftpc).newhost = Curl_cstrdup.expect("non-null function pointer")(control_address(conn));
                     }
                     #[cfg(CURLDEBUG)]
                     _ => {
                         (*ftpc).newhost = curl_dbg_strdup(
                             control_address(conn),
                             1979 as libc::c_int,
                             b"ftp.c\0" as *const u8 as *const libc::c_char,
                         );
                     }
                 }
                 if ((*ftpc).newhost).is_null() {
                     return CURLE_OUT_OF_MEMORY;
                 }
             }
             rc = Curl_resolv(
                 data,
                 (*ftpc).newhost,
                 (*ftpc).newport as libc::c_int,
                 0 as libc::c_int != 0,
                 &mut addr,
             );
             if rc as libc::c_int == CURLRESOLV_PENDING as libc::c_int {
                 Curl_resolver_wait_resolv(data, &mut addr);
             }
             connectport = (*ftpc).newport;
             if addr.is_null() {
                 Curl_failf(
                     data,
                     b"Can't resolve new host %s:%hu\0" as *const u8 as *const libc::c_char,
                     (*ftpc).newhost,
                     connectport as libc::c_int,
                 );
                 return CURLE_FTP_CANT_GET_HOST;
             }
         }
     }
     (*conn).bits.tcpconnect[1 as libc::c_int as usize] = 0 as libc::c_int != 0;
     result = Curl_connecthost(data, conn, addr);
     if result as u64 != 0 {
         Curl_resolv_unlock(data, addr);
         if (*ftpc).count1 == 0 as libc::c_int && ftpcode == 229 as libc::c_int {
             return ftp_epsv_disable(data, conn);
         }
         return result;
     }
     if ((*data).set).verbose() != 0 {
         #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
         ftp_pasv_verbose(
             data,
             (*addr).addr,
             (*ftpc).newhost,
             connectport as libc::c_int,
         );
     }
     Curl_resolv_unlock(data, addr);
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*conn).secondaryhostname as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*conn).secondaryhostname as *mut libc::c_void,
         2021 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh21 = (*conn).secondaryhostname;
     *fresh21 = 0 as *mut libc::c_char;
     (*conn).secondary_port = (*ftpc).newport;
     match () {
         #[cfg(not(CURLDEBUG))]
         _ => {
             (*conn).secondaryhostname = Curl_cstrdup.expect("non-null function pointer")((*ftpc).newhost);
 
         }
         #[cfg(CURLDEBUG)]
         _ => {
             (*conn).secondaryhostname = curl_dbg_strdup(
                 (*ftpc).newhost,
                 2023 as libc::c_int,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
         }
     }
     
     if ((*conn).secondaryhostname).is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     let ref mut fresh23 = (*conn).bits;
     (*fresh23).set_do_more(1 as libc::c_int as bit);
     #[cfg(not(DEBUGBUILD))]
     _state(data, FTP_STOP);
 
     #[cfg(DEBUGBUILD)]
     _state(data, FTP_STOP, 2028 as libc::c_int);
     return result;
 }
 unsafe extern "C" fn ftp_state_port_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: libc::c_int,
 ) -> CURLcode {
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut fcmd: ftpport = (*ftpc).count1 as ftpport;
     let mut result: CURLcode = CURLE_OK;
     if ftpcode / 100 as libc::c_int != 2 as libc::c_int {
         if EPRT as libc::c_int as libc::c_uint == fcmd as libc::c_uint {
             Curl_infof(
                 data,
                 b"disabling EPRT usage\0" as *const u8 as *const libc::c_char,
             );
             let ref mut fresh24 = (*conn).bits;
             (*fresh24).set_ftp_use_eprt(0 as libc::c_int as bit);
         }
         fcmd += 1;
         if fcmd as libc::c_uint == DONE as libc::c_int as libc::c_uint {
             Curl_failf(
                 data,
                 b"Failed to do PORT\0" as *const u8 as *const libc::c_char,
             );
             result = CURLE_FTP_PORT_FAILED;
         } else {
             result = ftp_state_use_port(data, fcmd);
         }
     } else {
         Curl_infof(
             data,
             b"Connect data stream actively\0" as *const u8 as *const libc::c_char,
         );
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
         _state(data, FTP_STOP, 2062 as libc::c_int);
         result = ftp_dophase_done(data, 0 as libc::c_int != 0);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_mdtm_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: libc::c_int,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     match ftpcode {
         213 => {
             let mut year: libc::c_int = 0;
             let mut month: libc::c_int = 0;
             let mut day: libc::c_int = 0;
             let mut hour: libc::c_int = 0;
             let mut minute: libc::c_int = 0;
             let mut second: libc::c_int = 0;
             if 6 as libc::c_int
                 == sscanf(
                     &mut *((*data).state.buffer).offset(4 as libc::c_int as isize)
                         as *mut libc::c_char,
                     b"%04d%02d%02d%02d%02d%02d\0" as *const u8 as *const libc::c_char,
                     &mut year as *mut libc::c_int,
                     &mut month as *mut libc::c_int,
                     &mut day as *mut libc::c_int,
                     &mut hour as *mut libc::c_int,
                     &mut minute as *mut libc::c_int,
                     &mut second as *mut libc::c_int,
                 )
             {
                 let mut timebuf: [libc::c_char; 24] = [0; 24];
                 curl_msnprintf(
                     timebuf.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 24]>() as libc::c_ulong,
                     b"%04d%02d%02d %02d:%02d:%02d GMT\0" as *const u8 as *const libc::c_char,
                     year,
                     month,
                     day,
                     hour,
                     minute,
                     second,
                 );
                 (*data).info.filetime = Curl_getdate_capped(timebuf.as_mut_ptr());
             }
            // #[cfg(CURL_FTP_HTTPSTYLE_HEAD)]
             if ((*data).set).opt_no_body() as libc::c_int != 0
                 && !((*ftpc).file).is_null()
                 && ((*data).set).get_filetime() as libc::c_int != 0
                 && (*data).info.filetime >= 0 as libc::c_int as libc::c_long
             {
                 let mut headerbuf: [libc::c_char; 128] = [0; 128];
                 let mut headerbuflen: libc::c_int = 0;
                 let mut filetime: time_t = (*data).info.filetime;
                 let mut buffer: tm = tm {
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
                 let mut tm: *const tm = &mut buffer;
                 result = Curl_gmtime(filetime, &mut buffer);
                 if result as u64 != 0 {
                     return result;
                 }
                 headerbuflen = curl_msnprintf(
                     headerbuf.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                     b"Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8
                         as *const libc::c_char,
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
                 result = Curl_client_write(
                     data,
                     (1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 1 as libc::c_int,
                     headerbuf.as_mut_ptr(),
                     headerbuflen as size_t,
                 );
                 if result as u64 != 0 {
                     return result;
                 }
             }
         }
         550 => {
             Curl_failf(
                 data,
                 b"Given file does not exist\0" as *const u8 as *const libc::c_char,
             );
             result = CURLE_REMOTE_FILE_NOT_FOUND;
         }
         _ => {
             Curl_infof(
                 data,
                 b"unsupported MDTM reply format\0" as *const u8 as *const libc::c_char,
             );
         }
     }
     if (*data).set.timecondition as u64 != 0 {
         if (*data).info.filetime > 0 as libc::c_int as libc::c_long
             && (*data).set.timevalue > 0 as libc::c_int as libc::c_long
         {
             match (*data).set.timecondition as libc::c_uint {
                 2 => {
                     if (*data).info.filetime > (*data).set.timevalue {
                         Curl_infof(
                             data,
                             b"The requested document is not old enough\0" as *const u8
                                 as *const libc::c_char,
                         );
                         (*ftp).transfer = PPTRANSFER_NONE;
                         let ref mut fresh26 = (*data).info;
                         (*fresh26).set_timecond(1 as libc::c_int as bit);
                         #[cfg(not(DEBUGBUILD))]
                         _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
                         _state(data, FTP_STOP, 2157 as libc::c_int);
                         return CURLE_OK;
                     }
                 }
                 1 | _ => {
                     if (*data).info.filetime <= (*data).set.timevalue {
                         Curl_infof(
                             data,
                             b"The requested document is not new enough\0" as *const u8
                                 as *const libc::c_char,
                         );
                         (*ftp).transfer = PPTRANSFER_NONE;
                         let ref mut fresh25 = (*data).info;
                         (*fresh25).set_timecond(1 as libc::c_int as bit);
                         #[cfg(not(DEBUGBUILD))]
                         _state(data, FTP_STOP);

                         #[cfg(DEBUGBUILD)]
                         _state(data, FTP_STOP, 2148 as libc::c_int);
                         return CURLE_OK;
                     }
                 }
             }
         } else {
             Curl_infof(
                 data,
                 b"Skipping time comparison\0" as *const u8 as *const libc::c_char,
             );
         }
     }
     if result as u64 == 0 {
         result = ftp_state_type(data);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_type_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: libc::c_int,
     mut instate: ftpstate,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     if ftpcode / 100 as libc::c_int != 2 as libc::c_int {
         Curl_failf(
             data,
             b"Couldn't set desired mode\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_FTP_COULDNT_SET_TYPE;
     }
     if ftpcode != 200 as libc::c_int {
         Curl_infof(
             data,
             b"Got a %03d response code instead of the assumed 200\0" as *const u8
                 as *const libc::c_char,
             ftpcode,
         );
     }
     if instate as libc::c_uint == FTP_TYPE as libc::c_int as libc::c_uint {
         result = ftp_state_size(data, conn);
     } else if instate as libc::c_uint == FTP_LIST_TYPE as libc::c_int as libc::c_uint {
         result = ftp_state_list(data);
     } else if instate as libc::c_uint == FTP_RETR_TYPE as libc::c_int as libc::c_uint {
         result = ftp_state_retr_prequote(data);
     } else if instate as libc::c_uint == FTP_STOR_TYPE as libc::c_int as libc::c_uint {
         result = ftp_state_stor_prequote(data);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_retr(
     mut data: *mut Curl_easy,
     mut filesize: curl_off_t,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*data).set.max_filesize != 0 && filesize > (*data).set.max_filesize {
         Curl_failf(
             data,
             b"Maximum file size exceeded\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_FILESIZE_EXCEEDED;
     }
     (*ftp).downloadsize = filesize;
     if (*data).state.resume_from != 0 {
         if filesize == -(1 as libc::c_int) as libc::c_long {
             Curl_infof(
                 data,
                 b"ftp server doesn't support SIZE\0" as *const u8 as *const libc::c_char,
             );
         } else if (*data).state.resume_from < 0 as libc::c_int as libc::c_long {
             if filesize < -(*data).state.resume_from {
                 Curl_failf(
                     data,
                     b"Offset (%ld) was beyond file size (%ld)\0" as *const u8
                         as *const libc::c_char,
                     (*data).state.resume_from,
                     filesize,
                 );
                 return CURLE_BAD_DOWNLOAD_RESUME;
             }
             (*ftp).downloadsize = -(*data).state.resume_from;
             (*data).state.resume_from = filesize - (*ftp).downloadsize;
         } else {
             if filesize < (*data).state.resume_from {
                 Curl_failf(
                     data,
                     b"Offset (%ld) was beyond file size (%ld)\0" as *const u8
                         as *const libc::c_char,
                     (*data).state.resume_from,
                     filesize,
                 );
                 return CURLE_BAD_DOWNLOAD_RESUME;
             }
             (*ftp).downloadsize = filesize - (*data).state.resume_from;
         }
         if (*ftp).downloadsize == 0 as libc::c_int as libc::c_long {
             Curl_setup_transfer(
                 data,
                 -(1 as libc::c_int),
                 -(1 as libc::c_int) as curl_off_t,
                 0 as libc::c_int != 0,
                 -(1 as libc::c_int),
             );
             Curl_infof(
                 data,
                 b"File already completely downloaded\0" as *const u8 as *const libc::c_char,
             );
             (*ftp).transfer = PPTRANSFER_NONE;
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_STOP);

             #[cfg(DEBUGBUILD)]
             _state(data, FTP_STOP, 2264 as libc::c_int);
             return CURLE_OK;
         }
         Curl_infof(
             data,
             b"Instructs server to resume from offset %ld\0" as *const u8 as *const libc::c_char,
             (*data).state.resume_from,
         );
         result = Curl_pp_sendf(
             data,
             &mut (*ftpc).pp as *mut pingpong,
             b"REST %ld\0" as *const u8 as *const libc::c_char,
             (*data).state.resume_from,
         );
         if result as u64 == 0 {
            #[cfg(not(DEBUGBUILD))]
            _state(data, FTP_RETR_REST);

	#[cfg(DEBUGBUILD)]
             _state(data, FTP_RETR_REST, 2275 as libc::c_int);
         }
     } else {
         result = Curl_pp_sendf(
             data,
             &mut (*ftpc).pp as *mut pingpong,
             b"RETR %s\0" as *const u8 as *const libc::c_char,
             (*ftpc).file,
         );
         if result as u64 == 0 {
            #[cfg(not(DEBUGBUILD))]
            _state(data, FTP_RETR);

	#[cfg(DEBUGBUILD)]
             _state(data, FTP_RETR, 2281 as libc::c_int);
         }
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_size_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: libc::c_int,
     mut instate: ftpstate,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut filesize: curl_off_t = -(1 as libc::c_int) as curl_off_t;
     let mut buf: *mut libc::c_char = (*data).state.buffer;
     if ftpcode == 213 as libc::c_int {
         let mut start: *mut libc::c_char =
             &mut *buf.offset(4 as libc::c_int as isize) as *mut libc::c_char;
         let mut fdigit: *mut libc::c_char = strchr(start, '\r' as i32);
         if !fdigit.is_null() {
             loop {
                 fdigit = fdigit.offset(-1);
                 if !(Curl_isdigit(*fdigit as libc::c_uchar as libc::c_int) != 0 && fdigit > start) {
                     break;
                 }
             }
             if Curl_isdigit(*fdigit as libc::c_uchar as libc::c_int) == 0 {
                 fdigit = fdigit.offset(1);
             }
         } else {
             fdigit = start;
         }
         curlx_strtoofft(
             fdigit,
             0 as *mut *mut libc::c_char,
             0 as libc::c_int,
             &mut filesize,
         );
     } else if ftpcode == 550 as libc::c_int {
         if instate as libc::c_uint != FTP_STOR_SIZE as libc::c_int as libc::c_uint {
             Curl_failf(
                 data,
                 b"The file does not exist\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_REMOTE_FILE_NOT_FOUND;
         }
     }
     if instate as libc::c_uint == FTP_SIZE as libc::c_int as libc::c_uint {
        // #[cfg(CURL_FTP_HTTPSTYLE_HEAD)]
         if -(1 as libc::c_int) as libc::c_long != filesize {
             let mut clbuf: [libc::c_char; 128] = [0; 128];
             let mut clbuflen: libc::c_int = curl_msnprintf(
                 clbuf.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                 b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                 filesize,
             );
             result = Curl_client_write(
                 data,
                 (1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 1 as libc::c_int,
                 clbuf.as_mut_ptr(),
                 clbuflen as size_t,
             );
             if result as u64 != 0 {
                 return result;
             }
         }
         Curl_pgrsSetDownloadSize(data, filesize);
         result = ftp_state_rest(data, (*data).conn);
     } else if instate as libc::c_uint == FTP_RETR_SIZE as libc::c_int as libc::c_uint {
         Curl_pgrsSetDownloadSize(data, filesize);
         result = ftp_state_retr(data, filesize);
     } else if instate as libc::c_uint == FTP_STOR_SIZE as libc::c_int as libc::c_uint {
         (*data).state.resume_from = filesize;
         result = ftp_state_ul_setup(data, 1 as libc::c_int != 0);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_rest_resp(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut ftpcode: libc::c_int,
     mut instate: ftpstate,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     match instate as libc::c_uint {
         27 => {
             if ftpcode != 350 as libc::c_int {
                 Curl_failf(
                     data,
                     b"Couldn't use REST\0" as *const u8 as *const libc::c_char,
                 );
                 result = CURLE_FTP_COULDNT_USE_REST;
             } else {
                 result = Curl_pp_sendf(
                     data,
                     &mut (*ftpc).pp as *mut pingpong,
                     b"RETR %s\0" as *const u8 as *const libc::c_char,
                     (*ftpc).file,
                 );
                 if result as u64 == 0 {
                    #[cfg(not(DEBUGBUILD))]
                    _state(data, FTP_RETR);

	#[cfg(DEBUGBUILD)]
                     _state(data, FTP_RETR, 2381 as libc::c_int);
                 }
             }
         }
         26 | _ => {
            // #[cfg(CURL_FTP_HTTPSTYLE_HEAD)]
             if ftpcode == 350 as libc::c_int {
                 let mut buffer: [libc::c_char; 24] =
                     *::std::mem::transmute::<&[u8; 24], &mut [libc::c_char; 24]>(
                         b"Accept-ranges: bytes\r\n\0\0",
                     );
                 result = Curl_client_write(
                     data,
                     (1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 1 as libc::c_int,
                     buffer.as_mut_ptr(),
                     strlen(buffer.as_mut_ptr()),
                 );
                 if result as u64 != 0 {
                     return result;
                 }
             }
             result = ftp_state_prepare_transfer(data);
         }
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_stor_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: libc::c_int,
     mut instate: ftpstate,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     if ftpcode >= 400 as libc::c_int {
         Curl_failf(
             data,
             b"Failed FTP upload: %0d\0" as *const u8 as *const libc::c_char,
             ftpcode,
         );
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
         _state(data, FTP_STOP, 2397 as libc::c_int);
         return CURLE_UPLOAD_FAILED;
     }
     (*conn).proto.ftpc.state_saved = instate;
     if ((*data).set).ftp_use_port() != 0 {
         let mut connected: bool = false;
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
         _state(data, FTP_STOP, 2408 as libc::c_int);
         result = AllowServerConnect(data, &mut connected);
         if result as u64 != 0 {
             return result;
         }
         if !connected {
             let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
             Curl_infof(
                 data,
                 b"Data conn was not available immediately\0" as *const u8 as *const libc::c_char,
             );
             (*ftpc).wait_data_conn = 1 as libc::c_int != 0;
         }
         return CURLE_OK;
     }
     return InitiateTransfer(data);
 }
 unsafe extern "C" fn ftp_state_get_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: libc::c_int,
     mut instate: ftpstate,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     if ftpcode == 150 as libc::c_int || ftpcode == 125 as libc::c_int {
         let mut size: curl_off_t = -(1 as libc::c_int) as curl_off_t;
         if instate as libc::c_uint != FTP_LIST as libc::c_int as libc::c_uint
             && ((*data).state).prefer_ascii() == 0
             && (*ftp).downloadsize < 1 as libc::c_int as libc::c_long
         {
             let mut bytes: *mut libc::c_char = 0 as *mut libc::c_char;
             let mut buf: *mut libc::c_char = (*data).state.buffer;
             bytes = strstr(buf, b" bytes\0" as *const u8 as *const libc::c_char);
             if !bytes.is_null() {
                 bytes = bytes.offset(-1);
                 let mut in_0: libc::c_long = bytes.offset_from(buf) as libc::c_long;
                 loop {
                     in_0 -= 1;
                     if !(in_0 != 0) {
                         break;
                     }
                     if '(' as i32 == *bytes as libc::c_int {
                         break;
                     }
                     if Curl_isdigit(*bytes as libc::c_uchar as libc::c_int) == 0 {
                         bytes = 0 as *mut libc::c_char;
                         break;
                     } else {
                         bytes = bytes.offset(-1);
                     }
                 }
                 if !bytes.is_null() {
                     bytes = bytes.offset(1);
                     curlx_strtoofft(
                         bytes,
                         0 as *mut *mut libc::c_char,
                         0 as libc::c_int,
                         &mut size,
                     );
                 }
             }
         } else if (*ftp).downloadsize > -(1 as libc::c_int) as libc::c_long {
             size = (*ftp).downloadsize;
         }
         if size > (*data).req.maxdownload
             && (*data).req.maxdownload > 0 as libc::c_int as libc::c_long
         {
             let ref mut fresh27 = (*data).req.size;
             *fresh27 = (*data).req.maxdownload;
             size = *fresh27;
         } else if instate as libc::c_uint != FTP_LIST as libc::c_int as libc::c_uint
             && ((*data).state).prefer_ascii() as libc::c_int != 0
         {
             size = -(1 as libc::c_int) as curl_off_t;
         }
         Curl_infof(
             data,
             b"Maxdownload = %ld\0" as *const u8 as *const libc::c_char,
             (*data).req.maxdownload,
         );
         if instate as libc::c_uint != FTP_LIST as libc::c_int as libc::c_uint {
             Curl_infof(
                 data,
                 b"Getting file with size: %ld\0" as *const u8 as *const libc::c_char,
                 size,
             );
         }
         (*conn).proto.ftpc.state_saved = instate;
         (*conn).proto.ftpc.retr_size_saved = size;
         if ((*data).set).ftp_use_port() != 0 {
             let mut connected: bool = false;
             result = AllowServerConnect(data, &mut connected);
             if result as u64 != 0 {
                 return result;
             }
             if !connected {
                 let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
                 Curl_infof(
                     data,
                     b"Data conn was not available immediately\0" as *const u8
                         as *const libc::c_char,
                 );
                 #[cfg(not(DEBUGBUILD))]
                 _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
                 _state(data, FTP_STOP, 2530 as libc::c_int);
                 (*ftpc).wait_data_conn = 1 as libc::c_int != 0;
             }
         } else {
             return InitiateTransfer(data);
         }
     } else if instate as libc::c_uint == FTP_LIST as libc::c_int as libc::c_uint
         && ftpcode == 450 as libc::c_int
     {
         (*ftp).transfer = PPTRANSFER_NONE;
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
         _state(data, FTP_STOP, 2541 as libc::c_int);
     } else {
         Curl_failf(
             data,
             b"RETR response: %03d\0" as *const u8 as *const libc::c_char,
             ftpcode,
         );
         return (if instate as libc::c_uint == FTP_RETR as libc::c_int as libc::c_uint
             && ftpcode == 550 as libc::c_int
         {
             CURLE_REMOTE_FILE_NOT_FOUND as libc::c_int
         } else {
             CURLE_FTP_COULDNT_RETR_FILE as libc::c_int
         }) as CURLcode;
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_loggedin(mut data: *mut Curl_easy) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     if ((*conn).bits).ftp_use_control_ssl() != 0 {
         result = Curl_pp_sendf(
             data,
             &mut (*conn).proto.ftpc.pp as *mut pingpong,
             b"PBSZ %d\0" as *const u8 as *const libc::c_char,
             0 as libc::c_int,
         );
         if result as u64 == 0 {
            #[cfg(not(DEBUGBUILD))]
            _state(data, FTP_PBSZ);

	#[cfg(DEBUGBUILD)]
             _state(data, FTP_PBSZ, 2577 as libc::c_int);
         }
     } else {
         result = ftp_state_pwd(data, conn);
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_user_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: libc::c_int,
     mut instate: ftpstate,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if ftpcode == 331 as libc::c_int
         && (*ftpc).state as libc::c_uint == FTP_USER as libc::c_int as libc::c_uint
     {
         result = Curl_pp_sendf(
             data,
             &mut (*ftpc).pp as *mut pingpong,
             b"PASS %s\0" as *const u8 as *const libc::c_char,
             if !((*conn).passwd).is_null() {
                 (*conn).passwd as *const libc::c_char
             } else {
                 b"\0" as *const u8 as *const libc::c_char
             },
         );
         if result as u64 == 0 {
            #[cfg(not(DEBUGBUILD))]
            _state(data, FTP_PASS);
            #[cfg(DEBUGBUILD)]
             _state(data, FTP_PASS, 2602 as libc::c_int);
         }
     } else if ftpcode / 100 as libc::c_int == 2 as libc::c_int {
         result = ftp_state_loggedin(data);
     } else if ftpcode == 332 as libc::c_int {
         if !((*data).set.str_0[STRING_FTP_ACCOUNT as libc::c_int as usize]).is_null() {
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"ACCT %s\0" as *const u8 as *const libc::c_char,
                 (*data).set.str_0[STRING_FTP_ACCOUNT as libc::c_int as usize],
             );
             if result as u64 == 0 {
                #[cfg(not(DEBUGBUILD))]
                _state(data, FTP_ACCT);

	#[cfg(DEBUGBUILD)]
                 _state(data, FTP_ACCT, 2614 as libc::c_int);
             }
         } else {
             Curl_failf(
                 data,
                 b"ACCT requested but none available\0" as *const u8 as *const libc::c_char,
             );
             result = CURLE_LOGIN_DENIED;
         }
     } else if !((*data).set.str_0[STRING_FTP_ALTERNATIVE_TO_USER as libc::c_int as usize]).is_null()
         && ((*data).state).ftp_trying_alternative() == 0
     {
         result = Curl_pp_sendf(
             data,
             &mut (*ftpc).pp as *mut pingpong,
             b"%s\0" as *const u8 as *const libc::c_char,
             (*data).set.str_0[STRING_FTP_ALTERNATIVE_TO_USER as libc::c_int as usize],
         );
         if result as u64 == 0 {
             let ref mut fresh28 = (*data).state;
             (*fresh28).set_ftp_trying_alternative(1 as libc::c_int as bit);
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_USER);

             #[cfg(DEBUGBUILD)]
             _state(data, FTP_USER, 2635 as libc::c_int);
         }
     } else {
         Curl_failf(
             data,
             b"Access denied: %03d\0" as *const u8 as *const libc::c_char,
             ftpcode,
         );
         result = CURLE_LOGIN_DENIED;
     }
     return result;
 }
 unsafe extern "C" fn ftp_state_acct_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: libc::c_int,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     if ftpcode != 230 as libc::c_int {
         Curl_failf(
             data,
             b"ACCT rejected by server: %03d\0" as *const u8 as *const libc::c_char,
             ftpcode,
         );
         result = CURLE_FTP_WEIRD_PASS_REPLY;
     } else {
         result = ftp_state_loggedin(data);
     }
     return result;
 }
 unsafe extern "C" fn ftp_statemachine(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut sock: curl_socket_t = (*conn).sock[0 as libc::c_int as usize];
     let mut ftpcode: libc::c_int = 0;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     static mut ftpauth: [[libc::c_char; 4]; 2] = unsafe {
         [
             *::std::mem::transmute::<&[u8; 4], &[libc::c_char; 4]>(b"SSL\0"),
             *::std::mem::transmute::<&[u8; 4], &[libc::c_char; 4]>(b"TLS\0"),
         ]
     };
     let mut nread: size_t = 0 as libc::c_int as size_t;
     if (*pp).sendleft != 0 {
         return Curl_pp_flushsend(data, pp);
     }
     result = ftp_readresp(data, sock, pp, &mut ftpcode, &mut nread);
     if result as u64 != 0 {
         return result;
     }
     if ftpcode != 0 {
        let mut current_block_187: u64;
         match (*ftpc).state as libc::c_uint {
             1 => {
                 if ftpcode == 230 as libc::c_int {
                     if (*data).set.use_ssl as libc::c_uint
                         <= CURLUSESSL_TRY as libc::c_int as libc::c_uint
                         || ((*conn).bits).ftp_use_control_ssl() as libc::c_int != 0
                     {
                         return ftp_state_user_resp(data, ftpcode, (*ftpc).state);
                     }
                 } else if ftpcode != 220 as libc::c_int {
                     Curl_failf(
                         data,
                         b"Got a %03d ftp-server response when 220 was expected\0" as *const u8
                             as *const libc::c_char,
                         ftpcode,
                     );
                     return CURLE_WEIRD_SERVER_REPLY;
                 }
                #[cfg(HAVE_GSSAPI)]
                if ((*data).set).krb() != 0 {
                    Curl_sec_request_prot(
                        conn,
                        b"private\0" as *const u8 as *const libc::c_char,
                    );
                    Curl_sec_request_prot(
                        conn,
                        (*data).set.str_0[STRING_KRB_LEVEL as libc::c_int as usize],
                    );
                    if Curl_sec_login(data, conn) as u64 != 0 {
                        Curl_infof(
                            data,
                            b"Logging in with password in cleartext!\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        Curl_infof(
                            data,
                            b"Authentication successful\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
                 if (*data).set.use_ssl as libc::c_uint != 0
                     && ((*conn).bits).ftp_use_control_ssl() == 0
                 {
                     (*ftpc).count3 = 0 as libc::c_int;
                     match (*data).set.ftpsslauth as libc::c_uint {
                         0 | 1 => {
                             (*ftpc).count2 = 1 as libc::c_int;
                             (*ftpc).count1 = 0 as libc::c_int;
                         }
                         2 => {
                             (*ftpc).count2 = -(1 as libc::c_int);
                             (*ftpc).count1 = 1 as libc::c_int;
                         }
                         _ => {
                             Curl_failf(
                                 data,
                                 b"unsupported parameter to CURLOPT_FTPSSLAUTH: %d\0" as *const u8
                                     as *const libc::c_char,
                                 (*data).set.ftpsslauth as libc::c_int,
                             );
                             return CURLE_UNKNOWN_OPTION;
                         }
                     }
                     result = Curl_pp_sendf(
                         data,
                         &mut (*ftpc).pp as *mut pingpong,
                         b"AUTH %s\0" as *const u8 as *const libc::c_char,
                         (ftpauth[(*ftpc).count1 as usize]).as_ptr(),
                     );
                     if result as u64 == 0 {
                        #[cfg(not(DEBUGBUILD))]
                        _state(data, FTP_AUTH);

	#[cfg(DEBUGBUILD)]
                         _state(data, FTP_AUTH, 2737 as libc::c_int);
                     }
                 } else {
                     result = ftp_state_user(data, conn);
                 }
             }
             2 => {
                 if (*pp).cache_size != 0 {
                     return CURLE_WEIRD_SERVER_REPLY;
                 }
                 if ftpcode == 234 as libc::c_int || ftpcode == 334 as libc::c_int {
                    // match () {
                    //     #[cfg(USE_SSL)]
                    //     _ => {
                    //         result = Curl_ssl_connect(data, conn, 0 as libc::c_int);
                    //     }
                    //     #[cfg(not(USE_SSL))]
                    //     _ => {
                    //         result = CURLE_NOT_BUILT_IN;
                    //     }
                    // }
                     result = Curl_ssl_connect(data, conn, 0 as libc::c_int);
                     if result as u64 == 0 {
                         let ref mut fresh29 = (*conn).bits;
                         (*fresh29).set_ftp_use_data_ssl(0 as libc::c_int as bit);
                         let ref mut fresh30 = (*conn).bits;
                         (*fresh30).set_ftp_use_control_ssl(1 as libc::c_int as bit);
                         result = ftp_state_user(data, conn);
                     }
                 } else if (*ftpc).count3 < 1 as libc::c_int {
                     let ref mut fresh31 = (*ftpc).count3;
                     *fresh31 += 1;
                     (*ftpc).count1 += (*ftpc).count2;
                     result = Curl_pp_sendf(
                         data,
                         &mut (*ftpc).pp as *mut pingpong,
                         b"AUTH %s\0" as *const u8 as *const libc::c_char,
                         (ftpauth[(*ftpc).count1 as usize]).as_ptr(),
                     );
                 } else if (*data).set.use_ssl as libc::c_uint
                     > CURLUSESSL_TRY as libc::c_int as libc::c_uint
                 {
                     result = CURLE_USE_SSL_FAILED;
                 } else {
                     result = ftp_state_user(data, conn);
                 }
             }
             3 | 4 => {
                 result = ftp_state_user_resp(data, ftpcode, (*ftpc).state);
             }
             5 => {
                 result = ftp_state_acct_resp(data, ftpcode);
             }
             6 => {
                 result = Curl_pp_sendf(
                     data,
                     &mut (*ftpc).pp as *mut pingpong,
                     b"PROT %c\0" as *const u8 as *const libc::c_char,
                     if (*data).set.use_ssl as libc::c_uint
                         == CURLUSESSL_CONTROL as libc::c_int as libc::c_uint
                     {
                         'C' as i32
                     } else {
                         'P' as i32
                     },
                 );
                 if result as u64 == 0 {
                    #[cfg(not(DEBUGBUILD))]
                    _state(data, FTP_PROT);

	#[cfg(DEBUGBUILD)]
                     _state(data, FTP_PROT, 2796 as libc::c_int);
                 }
             }
             7 => {
                 if ftpcode / 100 as libc::c_int == 2 as libc::c_int {
                     let ref mut fresh32 = (*conn).bits;
                     (*fresh32).set_ftp_use_data_ssl(
                         (if (*data).set.use_ssl as libc::c_uint
                             != CURLUSESSL_CONTROL as libc::c_int as libc::c_uint
                         {
                             1 as libc::c_int
                         } else {
                             0 as libc::c_int
                         }) as bit,
                     );
                 } else if (*data).set.use_ssl as libc::c_uint
                     > CURLUSESSL_CONTROL as libc::c_int as libc::c_uint
                 {
                     return CURLE_USE_SSL_FAILED;
                 }
                 if (*data).set.ftp_ccc as u64 != 0 {
                     result = Curl_pp_sendf(
                         data,
                         &mut (*ftpc).pp as *mut pingpong,
                         b"%s\0" as *const u8 as *const libc::c_char,
                         b"CCC\0" as *const u8 as *const libc::c_char,
                     );
                     if result as u64 == 0 {
                        #[cfg(not(DEBUGBUILD))]
                        _state(data, FTP_CCC);

	#[cfg(DEBUGBUILD)]
                         _state(data, FTP_CCC, 2815 as libc::c_int);
                     }
                 } else {
                     result = ftp_state_pwd(data, conn);
                 }
             }
             8 => {
                 if ftpcode < 500 as libc::c_int {
                    // match () {
                    //     #[cfg(USE_SSL)]
                    //     _ => {
                    //         result = Curl_ssl_shutdown(data, conn, 0 as libc::c_int);
                    //     }
                    //     #[cfg(not(USE_SSL))]
                    //     _ => {
                    //         result =CURLE_NOT_BUILT_IN;
                    //     }
                    // }
                     result = Curl_ssl_shutdown(data, conn, 0 as libc::c_int);
                     if result as u64 != 0 {
                         Curl_failf(
                             data,
                             b"Failed to clear the command channel (CCC)\0" as *const u8
                                 as *const libc::c_char,
                         );
                     }
                 }
                 if result as u64 == 0 {
                     result = ftp_state_pwd(data, conn);
                 }
             }
             9 => {
                 if ftpcode == 257 as libc::c_int {
                     let mut ptr: *mut libc::c_char = &mut *((*data).state.buffer)
                         .offset(4 as libc::c_int as isize)
                         as *mut libc::c_char;
                     let buf_size: size_t = (*data).set.buffer_size as size_t;
                     let mut dir: *mut libc::c_char = 0 as *mut libc::c_char;
                     let mut entry_extracted: bool = 0 as libc::c_int != 0;
                     match () {
                        #[cfg(not(CURLDEBUG))]
                        _ => {
                            dir = Curl_cmalloc.expect("non-null function pointer")(
                                nread.wrapping_add(1 as libc::c_int as libc::c_ulong),
                            ) as *mut libc::c_char;
                        }
                        #[cfg(CURLDEBUG)]
                        _ => {
                            dir = curl_dbg_malloc(
                                nread.wrapping_add(1 as libc::c_int as libc::c_ulong),
                                2841 as libc::c_int,
                                b"ftp.c\0" as *const u8 as *const libc::c_char,
                            ) as *mut libc::c_char;
                        }
                    }
                    
                     if dir.is_null() {
                         return CURLE_OUT_OF_MEMORY;
                     }
                     while ptr
                         < &mut *((*data).state.buffer).offset(buf_size as isize)
                             as *mut libc::c_char
                         && *ptr as libc::c_int != '\n' as i32
                        && *ptr as libc::c_int != '\0' as i32
                         && *ptr as libc::c_int != '"' as i32
                     {
                         ptr = ptr.offset(1);
                     }
                     if '"' as i32 == *ptr as libc::c_int {
                         let mut store: *mut libc::c_char = 0 as *mut libc::c_char;
                         ptr = ptr.offset(1);
                         store = dir;
                         while *ptr != 0 {
                             if '"' as i32 == *ptr as libc::c_int {
                                 if '"' as i32
                                     == *ptr.offset(1 as libc::c_int as isize) as libc::c_int
                                 {
                                     *store = *ptr.offset(1 as libc::c_int as isize);
                                     ptr = ptr.offset(1);
                                 } else {
                                     entry_extracted = 1 as libc::c_int != 0;
                                     break;
                                 }
                             } else {
                                 *store = *ptr;
                             }
                             store = store.offset(1);
                             ptr = ptr.offset(1);
                         }
                        *store = '\0' as i32 as libc::c_char;
                     }
                     if entry_extracted {
                         if ((*ftpc).server_os).is_null()
                             && *dir.offset(0 as libc::c_int as isize) as libc::c_int != '/' as i32
                         {
                             result = Curl_pp_sendf(
                                 data,
                                 &mut (*ftpc).pp as *mut pingpong,
                                 b"%s\0" as *const u8 as *const libc::c_char,
                                 b"SYST\0" as *const u8 as *const libc::c_char,
                             );
                             if result as u64 != 0 {
                                #[cfg(not(CURLDEBUG))]
                                Curl_cfree.expect("non-null function pointer")(
                                    dir as *mut libc::c_void,
                                );
	                            #[cfg(CURLDEBUG)]
                                 curl_dbg_free(
                                     dir as *mut libc::c_void,
                                     2899 as libc::c_int,
                                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                                 );
                                 return result;
                             }
                             #[cfg(not(CURLDEBUG))]
                             Curl_cfree.expect("non-null function pointer")(
                                (*ftpc).entrypath as *mut libc::c_void,
                            );
	                        #[cfg(CURLDEBUG)]
                             curl_dbg_free(
                                 (*ftpc).entrypath as *mut libc::c_void,
                                 2902 as libc::c_int,
                                 b"ftp.c\0" as *const u8 as *const libc::c_char,
                             );
                             let ref mut fresh33 = (*ftpc).entrypath;
                             *fresh33 = 0 as *mut libc::c_char;
                             let ref mut fresh34 = (*ftpc).entrypath;
                             *fresh34 = dir;
                             Curl_infof(
                                 data,
                                 b"Entry path is '%s'\0" as *const u8 as *const libc::c_char,
                                 (*ftpc).entrypath,
                             );
                             let ref mut fresh35 = (*data).state.most_recent_ftp_entrypath;
                             *fresh35 = (*ftpc).entrypath;
                             #[cfg(not(DEBUGBUILD))]
                             _state(data, FTP_SYST);

                             #[cfg(DEBUGBUILD)]
                             _state(data, FTP_SYST, 2907 as libc::c_int);
                             current_block_187 = 10490607306284298299;
                         } else {
                            #[cfg(not(CURLDEBUG))]
                            Curl_cfree.expect("non-null function pointer")(
                                (*ftpc).entrypath as *mut libc::c_void,
                            );
	                        #[cfg(CURLDEBUG)]
                             curl_dbg_free(
                                 (*ftpc).entrypath as *mut libc::c_void,
                                 2911 as libc::c_int,
                                 b"ftp.c\0" as *const u8 as *const libc::c_char,
                             );
                             let ref mut fresh36 = (*ftpc).entrypath;
                             *fresh36 = 0 as *mut libc::c_char;
                             let ref mut fresh37 = (*ftpc).entrypath;
                             *fresh37 = dir;
                             Curl_infof(
                                 data,
                                 b"Entry path is '%s'\0" as *const u8 as *const libc::c_char,
                                 (*ftpc).entrypath,
                             );
                             let ref mut fresh38 = (*data).state.most_recent_ftp_entrypath;
                             *fresh38 = (*ftpc).entrypath;
                            current_block_187 = 17917672080766325409;
                         }
                     } else {
                        #[cfg(not(CURLDEBUG))]
                        Curl_cfree.expect("non-null function pointer")(dir as *mut libc::c_void);

	                    #[cfg(CURLDEBUG)]
                         curl_dbg_free(
                             dir as *mut libc::c_void,
                             2919 as libc::c_int,
                             b"ftp.c\0" as *const u8 as *const libc::c_char,
                         );
                         Curl_infof(
                             data,
                             b"Failed to figure out path\0" as *const u8 as *const libc::c_char,
                         );
                        current_block_187 = 17917672080766325409;
                     }
                 } else {
                    current_block_187 = 17917672080766325409;
                 }
                match current_block_187 {
                    10490607306284298299 => {}
                     _ => {
                        #[cfg(not(DEBUGBUILD))]
                        _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
                         _state(data, FTP_STOP, 2923 as libc::c_int);
                         #[cfg(DEBUGBUILD)]
                         Curl_infof(
                             data,
                             b"protocol connect phase DONE\0" as *const u8 as *const libc::c_char,
                         );
                     }
                 }
             }
             10 => {
                 if ftpcode == 215 as libc::c_int {
                     let mut ptr_0: *mut libc::c_char = &mut *((*data).state.buffer)
                         .offset(4 as libc::c_int as isize)
                         as *mut libc::c_char;
                     let mut os: *mut libc::c_char = 0 as *mut libc::c_char;
                     let mut store_0: *mut libc::c_char = 0 as *mut libc::c_char;
                     match () {
                        #[cfg(not(CURLDEBUG))]
                        _ => {
                            os = Curl_cmalloc.expect("non-null function pointer")(
                                nread.wrapping_add(1 as libc::c_int as libc::c_ulong),
                            ) as *mut libc::c_char;
                        }
                        #[cfg(CURLDEBUG)]
                        _ => {
                            os = curl_dbg_malloc(
                                nread.wrapping_add(1 as libc::c_int as libc::c_ulong),
                                2933 as libc::c_int,
                                b"ftp.c\0" as *const u8 as *const libc::c_char,
                            ) as *mut libc::c_char;
                        }
                    }
                     
                     if os.is_null() {
                         return CURLE_OUT_OF_MEMORY;
                     }
                     while *ptr_0 as libc::c_int == ' ' as i32 {
                         ptr_0 = ptr_0.offset(1);
                     }
                     store_0 = os;
                     while *ptr_0 as libc::c_int != 0 && *ptr_0 as libc::c_int != ' ' as i32 {
                         let fresh39 = ptr_0;
                         ptr_0 = ptr_0.offset(1);
                         let fresh40 = store_0;
                         store_0 = store_0.offset(1);
                         *fresh40 = *fresh39;
                     }
                    *store_0 = '\0' as i32 as libc::c_char;
                     if Curl_strcasecompare(os, b"OS/400\0" as *const u8 as *const libc::c_char) != 0
                     {
                         result = Curl_pp_sendf(
                             data,
                             &mut (*ftpc).pp as *mut pingpong,
                             b"%s\0" as *const u8 as *const libc::c_char,
                             b"SITE NAMEFMT 1\0" as *const u8 as *const libc::c_char,
                         );
                         if result as u64 != 0 {
                            #[cfg(not(CURLDEBUG))]
                            Curl_cfree.expect("non-null function pointer")(os as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
                             curl_dbg_free(
                                 os as *mut libc::c_void,
                                 2952 as libc::c_int,
                                 b"ftp.c\0" as *const u8 as *const libc::c_char,
                             );
                             return result;
                         }
                         #[cfg(not(CURLDEBUG))]
                         Curl_cfree.expect("non-null function pointer")(
                            (*ftpc).server_os as *mut libc::c_void,
                        );
	#[cfg(CURLDEBUG)]
                         curl_dbg_free(
                             (*ftpc).server_os as *mut libc::c_void,
                             2956 as libc::c_int,
                             b"ftp.c\0" as *const u8 as *const libc::c_char,
                         );
                         let ref mut fresh41 = (*ftpc).server_os;
                         *fresh41 = 0 as *mut libc::c_char;
                         let ref mut fresh42 = (*ftpc).server_os;
                         *fresh42 = os;
                         #[cfg(not(DEBUGBUILD))]
                         _state(data, FTP_NAMEFMT);

	#[cfg(DEBUGBUILD)]
                         _state(data, FTP_NAMEFMT, 2958 as libc::c_int);
                         current_block_187 = 10490607306284298299;

                     } else {
                        #[cfg(not(CURLDEBUG))]
                        Curl_cfree.expect("non-null function pointer")(
                            (*ftpc).server_os as *mut libc::c_void,
                        );
	#[cfg(CURLDEBUG)]
                         curl_dbg_free(
                             (*ftpc).server_os as *mut libc::c_void,
                             2963 as libc::c_int,
                             b"ftp.c\0" as *const u8 as *const libc::c_char,
                         );
                         let ref mut fresh43 = (*ftpc).server_os;
                         *fresh43 = 0 as *mut libc::c_char;
                         let ref mut fresh44 = (*ftpc).server_os;
                         *fresh44 = os;
                        current_block_187 = 6938158527927677584;
                     }
                 } else {
                    current_block_187 = 6938158527927677584;
                 }
                match current_block_187 {
                    10490607306284298299 => {}
                     _ => {
                        #[cfg(not(DEBUGBUILD))]
                        _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
                         _state(data, FTP_STOP, 2970 as libc::c_int);
                         #[cfg(DEBUGBUILD)]
                         Curl_infof(
                             data,
                             b"protocol connect phase DONE\0" as *const u8 as *const libc::c_char,
                         );
                     }
                 }
             }
             11 => {
                 if ftpcode == 250 as libc::c_int {
                     ftp_state_pwd(data, conn);
                 } else {
                    #[cfg(not(DEBUGBUILD))]
                    _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
                     _state(data, FTP_STOP, 2981 as libc::c_int);
                     #[cfg(DEBUGBUILD)]
                     Curl_infof(
                         data,
                         b"protocol connect phase DONE\0" as *const u8 as *const libc::c_char,
                     );
                 }
             }
             12 | 15 | 13 | 14 => {
                 if ftpcode >= 400 as libc::c_int && (*ftpc).count2 == 0 {
                     Curl_failf(
                         data,
                         b"QUOT command failed with %03d\0" as *const u8 as *const libc::c_char,
                         ftpcode,
                     );
                     result = CURLE_QUOTE_ERROR;
                 } else {
                     result = ftp_state_quote(data, 0 as libc::c_int != 0, (*ftpc).state);
                 }
             }
             16 => {
                 if ftpcode / 100 as libc::c_int != 2 as libc::c_int {
                     if (*data).set.ftp_create_missing_dirs != 0
                         && (*ftpc).cwdcount != 0
                         && (*ftpc).count2 == 0
                     {
                         let ref mut fresh45 = (*ftpc).count2;
                         *fresh45 += 1;
                         result = Curl_pp_sendf(
                             data,
                             &mut (*ftpc).pp as *mut pingpong,
                             b"MKD %s\0" as *const u8 as *const libc::c_char,
                             *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
                         );
                         if result as u64 == 0 {
                            #[cfg(not(DEBUGBUILD))]
                            _state(data, FTP_MKD);

	#[cfg(DEBUGBUILD)]
                             _state(data, FTP_MKD, 3008 as libc::c_int);
                         }
                     } else {
                         Curl_failf(
                             data,
                             b"Server denied you to change to the given directory\0" as *const u8
                                 as *const libc::c_char,
                         );
                         (*ftpc).cwdfail = 1 as libc::c_int != 0;
                         result = CURLE_REMOTE_ACCESS_DENIED;
                     }
                 } else {
                     (*ftpc).count2 = 0 as libc::c_int;
                     let ref mut fresh46 = (*ftpc).cwdcount;
                     *fresh46 += 1;
                     if *fresh46 <= (*ftpc).dirdepth {
                         result = Curl_pp_sendf(
                             data,
                             &mut (*ftpc).pp as *mut pingpong,
                             b"CWD %s\0" as *const u8 as *const libc::c_char,
                             *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
                         );
                     } else {
                         result = ftp_state_mdtm(data);
                     }
                 }
             }
             17 => {
                 if ftpcode / 100 as libc::c_int != 2 as libc::c_int && {
                     let ref mut fresh47 = (*ftpc).count3;
                     let fresh48 = *fresh47;
                     *fresh47 = *fresh47 - 1;
                     fresh48 == 0
                 } {
                     Curl_failf(
                         data,
                         b"Failed to MKD dir: %03d\0" as *const u8 as *const libc::c_char,
                         ftpcode,
                     );
                     result = CURLE_REMOTE_ACCESS_DENIED;
                 } else {
                    #[cfg(not(DEBUGBUILD))]
                    _state(data, FTP_CWD);

	#[cfg(DEBUGBUILD)]
                     _state(data, FTP_CWD, 3037 as libc::c_int);
                     result = Curl_pp_sendf(
                         data,
                         &mut (*ftpc).pp as *mut pingpong,
                         b"CWD %s\0" as *const u8 as *const libc::c_char,
                         *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
                     );
                 }
             }
             18 => {
                 result = ftp_state_mdtm_resp(data, ftpcode);
             }
             19 | 20 | 21 | 22 => {
                 result = ftp_state_type_resp(data, ftpcode, (*ftpc).state);
             }
             23 | 24 | 25 => {
                 result = ftp_state_size_resp(data, ftpcode, (*ftpc).state);
             }
             26 | 27 => {
                 result = ftp_state_rest_resp(data, conn, ftpcode, (*ftpc).state);
             }
             29 => {
                 if ftpcode != 200 as libc::c_int {
                     Curl_failf(
                         data,
                         b"PRET command not accepted: %03d\0" as *const u8 as *const libc::c_char,
                         ftpcode,
                     );
                     return CURLE_FTP_PRET_FAILED;
                 }
                 result = ftp_state_use_pasv(data, conn);
             }
             30 => {
                 result = ftp_state_pasv_resp(data, ftpcode);
             }
             28 => {
                 result = ftp_state_port_resp(data, ftpcode);
             }
             31 | 32 => {
                 result = ftp_state_get_resp(data, ftpcode, (*ftpc).state);
             }
             33 => {
                 result = ftp_state_stor_resp(data, ftpcode, (*ftpc).state);
             }
             34 | _ => {
                #[cfg(not(DEBUGBUILD))]
                _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
                 _state(data, FTP_STOP, 3096 as libc::c_int);
             }
         }
     }
     return result;
 }
 unsafe extern "C" fn ftp_multi_statemach(
     mut data: *mut Curl_easy,
     mut done: *mut bool,
 ) -> CURLcode {
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut result: CURLcode = Curl_pp_statemach(
         data,
         &mut (*ftpc).pp,
         0 as libc::c_int != 0,
         0 as libc::c_int != 0,
     );
     *done = if (*ftpc).state as libc::c_uint == FTP_STOP as libc::c_int as libc::c_uint {
         1 as libc::c_int
     } else {
         0 as libc::c_int
     } != 0;
     return result;
 }
 unsafe extern "C" fn ftp_block_statemach(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     let mut result: CURLcode = CURLE_OK;
    // 解决clippy错误
    loop {
        if (*ftpc).state as libc::c_uint == FTP_STOP as libc::c_int as libc::c_uint {
            break;
        }
        // while (*ftpc).state as libc::c_uint != FTP_STOP as libc::c_int as libc::c_uint {
         result = Curl_pp_statemach(data, pp, 1 as libc::c_int != 0, 1 as libc::c_int != 0);
         if result as u64 != 0 {
             break;
         }
     }
     return result;
 }
 unsafe extern "C" fn ftp_connect(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     *done = 0 as libc::c_int != 0;
     #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
     Curl_conncontrol(conn, 0 as libc::c_int);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
     Curl_conncontrol(
         conn,
         0 as libc::c_int,
         b"FTP default\0" as *const u8 as *const libc::c_char,
     );
     (*pp).response_time = (120 as libc::c_int * 1000 as libc::c_int) as timediff_t;
     let ref mut fresh49 = (*pp).statemachine;
     *fresh49 = Some(
         ftp_statemachine as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
     );
     let ref mut fresh50 = (*pp).endofresp;
     *fresh50 = Some(
         ftp_endofresp
             as unsafe extern "C" fn(
                 *mut Curl_easy,
                 *mut connectdata,
                 *mut libc::c_char,
                 size_t,
                 *mut libc::c_int,
             ) -> bool,
     );
     if (*(*conn).handler).flags & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0 {
        // match () {
        //     #[cfg(USE_SSL)]
        //     _ => {
        //         result = Curl_ssl_connect(data, conn, 0 as libc::c_int);
        //     }
        //     #[cfg(not(USE_SSL))]
        //     _ => {
        //         result = CURLE_NOT_BUILT_IN;
        //     }
        // }
         result = Curl_ssl_connect(data, conn, 0 as libc::c_int);
         if result as u64 != 0 {
             return result;
         }
         let ref mut fresh51 = (*conn).bits;
         (*fresh51).set_ftp_use_control_ssl(1 as libc::c_int as bit);
     }
     Curl_pp_setup(pp);
     Curl_pp_init(data, pp);
     #[cfg(not(DEBUGBUILD))]
     _state(data, FTP_WAIT220);

	#[cfg(DEBUGBUILD)]
     _state(data, FTP_WAIT220, 3173 as libc::c_int);
     result = ftp_multi_statemach(data, done);
     return result;
 }
 unsafe extern "C" fn ftp_done(
     mut data: *mut Curl_easy,
     mut status: CURLcode,
     mut premature: bool,
 ) -> CURLcode {
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     let mut nread: ssize_t = 0;
     let mut ftpcode: libc::c_int = 0;
     let mut result: CURLcode = CURLE_OK;
     let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut pathLen: size_t = 0 as libc::c_int as size_t;
     if ftp.is_null() {
         return CURLE_OK;
     }
     let mut current_block_5: u64;
     match status as libc::c_uint {
         23 => {
            current_block_5 = 17258398194053458658;
         }
         36 | 13 | 30 | 10 | 12 | 17 | 19 | 18 | 25 | 9 | 63 | 78 | 0 => {
            current_block_5 = 17258398194053458658;
         }
         _ => {
            current_block_5 = 8000488408776534573;
         }
     }
     match current_block_5 {
        17258398194053458658 => {
             if !premature {
                 current_block_5 = 6057473163062296781;
             } else {
                current_block_5 = 8000488408776534573;
             }
         }
         _ => {}
     }
     match current_block_5 {
        8000488408776534573 => {
             (*ftpc).ctl_valid = 0 as libc::c_int != 0;
             (*ftpc).cwdfail = 1 as libc::c_int != 0;
             #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
             Curl_conncontrol(conn, 1 as libc::c_int);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
             Curl_conncontrol(
                 conn,
                 1 as libc::c_int,
                 b"FTP ended with bad error code\0" as *const u8 as *const libc::c_char,
             );
             result = status;
         }
         _ => {}
     }
     if ((*data).state).wildcardmatch() != 0 {
         if ((*data).set.chunk_end).is_some() && !((*ftpc).file).is_null() {
             Curl_set_in_callback(data, 1 as libc::c_int != 0);
             ((*data).set.chunk_end).expect("non-null function pointer")((*data).wildcard.customptr);
             Curl_set_in_callback(data, 0 as libc::c_int != 0);
         }
         (*ftpc).known_filesize = -(1 as libc::c_int) as curl_off_t;
     }
     if result as u64 == 0 {
         result = Curl_urldecode(
             data,
             (*ftp).path,
             0 as libc::c_int as size_t,
             &mut rawPath,
             &mut pathLen,
             REJECT_CTRL,
         );
     }
     if result as u64 != 0 {
         (*ftpc).ctl_valid = 0 as libc::c_int != 0;
         #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
         Curl_conncontrol(conn, 1 as libc::c_int);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
         Curl_conncontrol(
             conn,
             1 as libc::c_int,
             b"FTP: out of memory!\0" as *const u8 as *const libc::c_char,
         );
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
         curl_dbg_free(
             (*ftpc).prevpath as *mut libc::c_void,
             3256 as libc::c_int,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
         let ref mut fresh52 = (*ftpc).prevpath;
         *fresh52 = 0 as *mut libc::c_char;
     } else {
         if (*data).set.ftp_filemethod as libc::c_uint
             == FTPFILE_NOCWD as libc::c_int as libc::c_uint
             && *rawPath.offset(0 as libc::c_int as isize) as libc::c_int == '/' as i32
         {
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
             curl_dbg_free(
                 rawPath as *mut libc::c_void,
                 3261 as libc::c_int,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
         } else {
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
             curl_dbg_free(
                 (*ftpc).prevpath as *mut libc::c_void,
                 3263 as libc::c_int,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
             if !(*ftpc).cwdfail {
                 if (*data).set.ftp_filemethod as libc::c_uint
                     == FTPFILE_NOCWD as libc::c_int as libc::c_uint
                 {
                     pathLen = 0 as libc::c_int as size_t;
                 } else {
                     pathLen =
                         (pathLen as libc::c_ulong).wrapping_sub(if !((*ftpc).file).is_null() {
                             strlen((*ftpc).file)
                         } else {
                             0 as libc::c_int as libc::c_ulong
                         }) as size_t as size_t;
                 }
                *rawPath.offset(pathLen as isize) = '\0' as i32 as libc::c_char;
                 let ref mut fresh53 = (*ftpc).prevpath;
                 *fresh53 = rawPath;
             } else {
                #[cfg(not(CURLDEBUG))]
                Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
                 curl_dbg_free(
                     rawPath as *mut libc::c_void,
                     3275 as libc::c_int,
                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                 );
                 let ref mut fresh54 = (*ftpc).prevpath;
                 *fresh54 = 0 as *mut libc::c_char;
             }
         }
         if !((*ftpc).prevpath).is_null() {
             Curl_infof(
                 data,
                 b"Remembering we are in dir \"%s\"\0" as *const u8 as *const libc::c_char,
                 (*ftpc).prevpath,
             );
         }
     }
     freedirs(ftpc);
     if (*conn).sock[1 as libc::c_int as usize] != -(1 as libc::c_int) {
         if result as u64 == 0
             && (*ftpc).dont_check as libc::c_int != 0
             && (*data).req.maxdownload > 0 as libc::c_int as libc::c_long
         {
             result = Curl_pp_sendf(
                 data,
                 pp,
                 b"%s\0" as *const u8 as *const libc::c_char,
                 b"ABOR\0" as *const u8 as *const libc::c_char,
             );
             if result as u64 != 0 {
                 Curl_failf(
                     data,
                     b"Failure sending ABOR command: %s\0" as *const u8 as *const libc::c_char,
                     curl_easy_strerror(result),
                 );
                 (*ftpc).ctl_valid = 0 as libc::c_int != 0;
                 #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                 Curl_conncontrol(conn, 1 as libc::c_int);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                 Curl_conncontrol(
                     conn,
                     1 as libc::c_int,
                     b"ABOR command failed\0" as *const u8 as *const libc::c_char,
                 );
             }
         }
         if ((*conn).ssl[1 as libc::c_int as usize]).use_0() != 0 {
            #[cfg(USE_SSL)]
             Curl_ssl_close(data, conn, 1 as libc::c_int);
         }
         close_secondarysocket(data, conn);
     }
     if result as u64 == 0
         && (*ftp).transfer as libc::c_uint == PPTRANSFER_BODY as libc::c_int as libc::c_uint
         && (*ftpc).ctl_valid as libc::c_int != 0
         && (*pp).pending_resp as libc::c_int != 0
         && !premature
     {
         let mut old_time: timediff_t = (*pp).response_time;
         (*pp).response_time = (60 as libc::c_int * 1000 as libc::c_int) as timediff_t;
         (*pp).response = Curl_now();
         result = Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
         (*pp).response_time = old_time;
         if nread == 0
             && CURLE_OPERATION_TIMEDOUT as libc::c_int as libc::c_uint == result as libc::c_uint
         {
             Curl_failf(
                 data,
                 b"control connection looks dead\0" as *const u8 as *const libc::c_char,
             );
             (*ftpc).ctl_valid = 0 as libc::c_int != 0;
             #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
             Curl_conncontrol(conn, 1 as libc::c_int);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
             Curl_conncontrol(
                 conn,
                 1 as libc::c_int,
                 b"Timeout or similar in FTP DONE operation\0" as *const u8 as *const libc::c_char,
             );
         }
         if result as u64 != 0 {
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")((*ftp).pathalloc as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
             curl_dbg_free(
                 (*ftp).pathalloc as *mut libc::c_void,
                 3340 as libc::c_int,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
             let ref mut fresh55 = (*ftp).pathalloc;
             *fresh55 = 0 as *mut libc::c_char;
             return result;
         }
         if (*ftpc).dont_check as libc::c_int != 0
             && (*data).req.maxdownload > 0 as libc::c_int as libc::c_long
         {
             Curl_infof(
                 data,
                 b"partial download completed, closing connection\0" as *const u8
                     as *const libc::c_char,
             );
             #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
             Curl_conncontrol(conn, 1 as libc::c_int);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
             Curl_conncontrol(
                 conn,
                 1 as libc::c_int,
                 b"Partial download with no ability to check\0" as *const u8 as *const libc::c_char,
             );
             return result;
         }
         if !(*ftpc).dont_check {
             match ftpcode {
                 226 | 250 => {}
                 552 => {
                     Curl_failf(
                         data,
                         b"Exceeded storage allocation\0" as *const u8 as *const libc::c_char,
                     );
                     result = CURLE_REMOTE_DISK_FULL;
                 }
                 _ => {
                     Curl_failf(
                         data,
                         b"server did not report OK, got %d\0" as *const u8 as *const libc::c_char,
                         ftpcode,
                     );
                     result = CURLE_PARTIAL_FILE;
                 }
             }
         }
     }
     if !(result as libc::c_uint != 0 || premature as libc::c_int != 0) {
         if ((*data).set).upload() != 0 {
             if -(1 as libc::c_int) as libc::c_long != (*data).state.infilesize
                 && (*data).state.infilesize != (*data).req.writebytecount
                 && ((*data).set).crlf() == 0
                 && (*ftp).transfer as libc::c_uint == PPTRANSFER_BODY as libc::c_int as libc::c_uint
             {
                 Curl_failf(
                     data,
                     b"Uploaded unaligned file size (%ld out of %ld bytes)\0" as *const u8
                         as *const libc::c_char,
                     (*data).req.bytecount,
                     (*data).state.infilesize,
                 );
                 result = CURLE_PARTIAL_FILE;
             }
        } else {
            let flag: bool = if cfg!(CURL_DO_LINEEND_CONV) {
                -(1 as libc::c_int) as libc::c_long != (*data).req.size
             && (*data).req.size != (*data).req.bytecount
             && (*data).req.size + (*data).state.crlf_conversions != (*data).req.bytecount
             && (*data).req.maxdownload != (*data).req.bytecount
            } else {
                -(1 as libc::c_int) as libc::c_long != (*data).req.size
                && (*data).req.size != (*data).req.bytecount
                && (*data).req.maxdownload != (*data).req.bytecount
            };
            if flag
         {
             Curl_failf(
                 data,
                 b"Received only partial file: %ld bytes\0" as *const u8 as *const libc::c_char,
                 (*data).req.bytecount,
             );
             result = CURLE_PARTIAL_FILE;
         } else if !(*ftpc).dont_check
             && (*data).req.bytecount == 0
             && (*data).req.size > 0 as libc::c_int as libc::c_long
         {
             Curl_failf(
                 data,
                 b"No data was received!\0" as *const u8 as *const libc::c_char,
             );
             result = CURLE_FTP_COULDNT_RETR_FILE;
         }
     }
    }
     (*ftp).transfer = PPTRANSFER_BODY;
     (*ftpc).dont_check = 0 as libc::c_int != 0;
     if status as u64 == 0 && result as u64 == 0 && !premature && !((*data).set.postquote).is_null()
     {
         result = ftp_sendquote(data, conn, (*data).set.postquote);
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftp).pathalloc as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*ftp).pathalloc as *mut libc::c_void,
         3416 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh56 = (*ftp).pathalloc;
     *fresh56 = 0 as *mut libc::c_char;
     return result;
 }
 unsafe extern "C" fn ftp_sendquote(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut quote: *mut curl_slist,
 ) -> CURLcode {
     let mut item: *mut curl_slist = 0 as *mut curl_slist;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     item = quote;
     while !item.is_null() {
         if !((*item).data).is_null() {
             let mut nread: ssize_t = 0;
             let mut cmd: *mut libc::c_char = (*item).data;
             let mut acceptfail: bool = 0 as libc::c_int != 0;
             let mut result: CURLcode = CURLE_OK;
             let mut ftpcode: libc::c_int = 0 as libc::c_int;
             if *cmd.offset(0 as libc::c_int as isize) as libc::c_int == '*' as i32 {
                 cmd = cmd.offset(1);
                 acceptfail = 1 as libc::c_int != 0;
             }
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"%s\0" as *const u8 as *const libc::c_char,
                 cmd,
             );
             if result as u64 == 0 {
                 (*pp).response = Curl_now();
                 result = Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
             }
             if result as u64 != 0 {
                 return result;
             }
             if !acceptfail && ftpcode >= 400 as libc::c_int {
                 Curl_failf(
                     data,
                     b"QUOT string not accepted: %s\0" as *const u8 as *const libc::c_char,
                     cmd,
                 );
                 return CURLE_QUOTE_ERROR;
             }
         }
         item = (*item).next;
     }
     return CURLE_OK;
 }
 unsafe extern "C" fn ftp_need_type(
     mut conn: *mut connectdata,
     mut ascii_wanted: bool,
 ) -> libc::c_int {
     return ((*conn).proto.ftpc.transfertype as libc::c_int
         != (if ascii_wanted as libc::c_int != 0 {
             'A' as i32
         } else {
             'I' as i32
         })) as libc::c_int;
 }
 unsafe extern "C" fn ftp_nb_type(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut ascii: bool,
     mut newstate: ftpstate,
 ) -> CURLcode {
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut result: CURLcode = CURLE_OK;
     let mut want: libc::c_char = (if ascii as libc::c_int != 0 {
         'A' as i32
     } else {
         'I' as i32
     }) as libc::c_char;
     if (*ftpc).transfertype as libc::c_int == want as libc::c_int {
        #[cfg(not(DEBUGBUILD))]
        _state(data, newstate);

	#[cfg(DEBUGBUILD)]
        _state(data, newstate, 3506 as libc::c_int);
         return ftp_state_type_resp(data, 200 as libc::c_int, newstate);
     }
     result = Curl_pp_sendf(
         data,
         &mut (*ftpc).pp as *mut pingpong,
         b"TYPE %c\0" as *const u8 as *const libc::c_char,
         want as libc::c_int,
     );
     if result as u64 == 0 {
        #[cfg(not(DEBUGBUILD))]
        _state(data, newstate);

	#[cfg(DEBUGBUILD)]
         _state(data, newstate, 3512 as libc::c_int);
         (*ftpc).transfertype = want;
     }
     return result;
 }
#[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
 unsafe extern "C" fn ftp_pasv_verbose(
     mut data: *mut Curl_easy,
     mut ai: *mut Curl_addrinfo,
     mut newhost: *mut libc::c_char,
     mut port: libc::c_int,
 ) {
     let mut buf: [libc::c_char; 256] = [0; 256];
     Curl_printable_address(
         ai,
         buf.as_mut_ptr(),
         ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
     );
     Curl_infof(
         data,
         b"Connecting to %s (%s) port %d\0" as *const u8 as *const libc::c_char,
         newhost,
         buf.as_mut_ptr(),
         port,
     );
 }
 unsafe extern "C" fn ftp_do_more(
     mut data: *mut Curl_easy,
     mut completep: *mut libc::c_int,
 ) -> CURLcode {
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut result: CURLcode = CURLE_OK;
     let mut connected: bool = 0 as libc::c_int != 0;
     let mut complete: bool = 0 as libc::c_int != 0;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     if !(*conn).bits.tcpconnect[1 as libc::c_int as usize] {
        #[cfg(not(CURL_DISABLE_PROXY))]
         if Curl_connect_ongoing(conn) {
             result = Curl_proxyCONNECT(
                 data,
                 1 as libc::c_int,
                 0 as *const libc::c_char,
                 0 as libc::c_int,
             );
             return result;
         }
         result = Curl_is_connected(data, conn, 1 as libc::c_int, &mut connected);
         if connected {
            #[cfg(DEBUGBUILD)]
             Curl_infof(
                 data,
                 b"DO-MORE connected phase starts\0" as *const u8 as *const libc::c_char,
             );
         } else {
             if result as libc::c_uint != 0 && (*ftpc).count1 == 0 as libc::c_int {
                 *completep = -(1 as libc::c_int);
                 return ftp_epsv_disable(data, conn);
             }
             return result;
         }
     }
    match () {
        #[cfg(not(CURL_DISABLE_PROXY))]
        _ => {
     result = Curl_proxy_connect(data, 1 as libc::c_int);
     if result as u64 != 0 {
         return result;
     }
     if (*conn).http_proxy.proxytype as libc::c_uint
         == CURLPROXY_HTTPS as libc::c_int as libc::c_uint
         && !(*conn).bits.proxy_ssl_connected[1 as libc::c_int as usize]
     {
         return result;
     }
     if ((*conn).bits).tunnel_proxy() as libc::c_int != 0
         && ((*conn).bits).httpproxy() as libc::c_int != 0
         && Curl_connect_ongoing(conn) as libc::c_int != 0
     {
         return result;
     }
        }
        #[cfg(CURL_DISABLE_PROXY)]
        _ => { }
    }
     if (*ftpc).state as u64 != 0 {
         result = ftp_multi_statemach(data, &mut complete);
         *completep = complete as libc::c_int;
         if result as libc::c_uint != 0 || !(*ftpc).wait_data_conn {
             return result;
         }
         *completep = 0 as libc::c_int;
     }
     if (*ftp).transfer as libc::c_uint <= PPTRANSFER_INFO as libc::c_int as libc::c_uint {
         if (*ftpc).wait_data_conn as libc::c_int == 1 as libc::c_int {
             let mut serv_conned: bool = false;
             result = ReceivedServerConnect(data, &mut serv_conned);
             if result as u64 != 0 {
                 return result;
             }
             if serv_conned {
                 result = AcceptServerConnect(data);
                 (*ftpc).wait_data_conn = 0 as libc::c_int != 0;
                 if result as u64 == 0 {
                     result = InitiateTransfer(data);
                 }
                 if result as u64 != 0 {
                     return result;
                 }
                 *completep = 1 as libc::c_int;
             }
         } else if ((*data).set).upload() != 0 {
             result = ftp_nb_type(
                 data,
                 conn,
                 ((*data).state).prefer_ascii() != 0,
                 FTP_STOR_TYPE,
             );
             if result as u64 != 0 {
                 return result;
             }
             result = ftp_multi_statemach(data, &mut complete);
             if (*ftpc).wait_data_conn {
                 *completep = 0 as libc::c_int;
             } else {
                 *completep = complete as libc::c_int;
             }
         } else {
             (*ftp).downloadsize = -(1 as libc::c_int) as curl_off_t;
             result = Curl_range(data);
             if result as libc::c_uint == CURLE_OK as libc::c_int as libc::c_uint
                 && (*data).req.maxdownload >= 0 as libc::c_int as libc::c_long
             {
                 (*ftpc).dont_check = 1 as libc::c_int != 0;
             }
             if !(result as u64 != 0) {
                 if ((*data).state).list_only() as libc::c_int != 0 || ((*ftpc).file).is_null() {
                     if (*ftp).transfer as libc::c_uint
                         == PPTRANSFER_BODY as libc::c_int as libc::c_uint
                     {
                         result = ftp_nb_type(data, conn, 1 as libc::c_int != 0, FTP_LIST_TYPE);
                         if result as u64 != 0 {
                             return result;
                         }
                     }
                 } else {
                     result = ftp_nb_type(
                         data,
                         conn,
                         ((*data).state).prefer_ascii() != 0,
                         FTP_RETR_TYPE,
                     );
                     if result as u64 != 0 {
                         return result;
                     }
                 }
             }
             result = ftp_multi_statemach(data, &mut complete);
             *completep = complete as libc::c_int;
         }
         return result;
     }
     Curl_setup_transfer(
         data,
         -(1 as libc::c_int),
         -(1 as libc::c_int) as curl_off_t,
         0 as libc::c_int != 0,
         -(1 as libc::c_int),
     );
     if !(*ftpc).wait_data_conn {
         *completep = 1 as libc::c_int;
         #[cfg(DEBUGBUILD)]
         Curl_infof(
             data,
             b"DO-MORE phase ends with %d\0" as *const u8 as *const libc::c_char,
             result as libc::c_int,
         );
     }
     return result;
 }
 unsafe extern "C" fn ftp_perform(
     mut data: *mut Curl_easy,
     mut connected: *mut bool,
     mut dophase_done: *mut bool,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     #[cfg(DEBUGBUILD)]
     Curl_infof(
         data,
         b"DO phase starts\0" as *const u8 as *const libc::c_char,
     );
     if ((*data).set).opt_no_body() != 0 {
         let mut ftp: *mut FTP = (*data).req.p.ftp;
         (*ftp).transfer = PPTRANSFER_INFO;
     }
     *dophase_done = 0 as libc::c_int != 0;
     result = ftp_state_quote(data, 1 as libc::c_int != 0, FTP_QUOTE);
     if result as u64 != 0 {
         return result;
     }
     result = ftp_multi_statemach(data, dophase_done);
     *connected = (*conn).bits.tcpconnect[1 as libc::c_int as usize];
     Curl_infof(
         data,
         b"ftp_perform ends with SECONDARY: %d\0" as *const u8 as *const libc::c_char,
         *connected as libc::c_int,
     );
     #[cfg(DEBUGBUILD)]
     if *dophase_done {
         Curl_infof(
             data,
             b"DO phase is complete1\0" as *const u8 as *const libc::c_char,
         );
     }
     return result;
 }
 unsafe extern "C" fn wc_data_dtor(mut ptr: *mut libc::c_void) {
     let mut ftpwc: *mut ftp_wc = ptr as *mut ftp_wc;
     if !ftpwc.is_null() && !((*ftpwc).parser).is_null() {
         Curl_ftp_parselist_data_free(&mut (*ftpwc).parser);
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(ftpwc as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
     curl_dbg_free(
         ftpwc as *mut libc::c_void,
         3764 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
 }
 unsafe extern "C" fn init_wc_data(mut data: *mut Curl_easy) -> CURLcode {
     let mut last_slash: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut path: *mut libc::c_char = (*ftp).path;
     let mut wildcard: *mut WildcardData = &mut (*data).wildcard;
     let mut result: CURLcode = CURLE_OK;
     let mut ftpwc: *mut ftp_wc = 0 as *mut ftp_wc;
     last_slash = strrchr((*ftp).path, '/' as i32);
     if !last_slash.is_null() {
         last_slash = last_slash.offset(1);
        if *last_slash.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
             (*wildcard).state = CURLWC_CLEAN;
             result = ftp_parse_url_path(data);
             return result;
         }
         match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                (*wildcard).pattern = Curl_cstrdup.expect("non-null function pointer")(last_slash);

            }
            #[cfg(CURLDEBUG)]
            _ => {
                (*wildcard).pattern = curl_dbg_strdup(
                    last_slash,
                    3784 as libc::c_int,
                    b"ftp.c\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        
         if ((*wildcard).pattern).is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
        *last_slash.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
     } else if *path.offset(0 as libc::c_int as isize) != 0 {
         match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                (*wildcard).pattern = Curl_cstrdup.expect("non-null function pointer")(path);

            }
            #[cfg(CURLDEBUG)]
            _ => {
                (*wildcard).pattern = curl_dbg_strdup(
                    path,
                    3791 as libc::c_int,
                    b"ftp.c\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        
         if ((*wildcard).pattern).is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
        *path.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
     } else {
         (*wildcard).state = CURLWC_CLEAN;
         result = ftp_parse_url_path(data);
         return result;
     }
     match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            ftpwc = Curl_ccalloc.expect("non-null function pointer")(
                1 as libc::c_int as size_t,
                ::std::mem::size_of::<ftp_wc>() as libc::c_ulong,
            ) as *mut ftp_wc;
        }
        #[cfg(CURLDEBUG)]
        _ => {
            ftpwc = curl_dbg_calloc(
                1 as libc::c_int as size_t,
                ::std::mem::size_of::<ftp_wc>() as libc::c_ulong,
                3807 as libc::c_int,
                b"ftp.c\0" as *const u8 as *const libc::c_char,
            ) as *mut ftp_wc;
        }
    }
     
     if ftpwc.is_null() {
         result = CURLE_OUT_OF_MEMORY;
     } else {
         let ref mut fresh59 = (*ftpwc).parser;
         *fresh59 = Curl_ftp_parselist_data_alloc();
         if ((*ftpwc).parser).is_null() {
             result = CURLE_OUT_OF_MEMORY;
         } else {
             let ref mut fresh60 = (*wildcard).protdata;
             *fresh60 = ftpwc as *mut libc::c_void;
             let ref mut fresh61 = (*wildcard).dtor;
             *fresh61 = Some(wc_data_dtor as unsafe extern "C" fn(*mut libc::c_void) -> ());
             if (*data).set.ftp_filemethod as libc::c_uint
                 == FTPFILE_NOCWD as libc::c_int as libc::c_uint
             {
                 (*data).set.ftp_filemethod = FTPFILE_MULTICWD;
             }
             result = ftp_parse_url_path(data);
             if !(result as u64 != 0) {
                 match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {
                        (*wildcard).path = Curl_cstrdup.expect("non-null function pointer")((*ftp).path);
        
                    }
                    #[cfg(CURLDEBUG)]
                    _ => {
                        (*wildcard).path = curl_dbg_strdup(
                            (*ftp).path,
                            3833 as libc::c_int,
                            b"ftp.c\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
                
                 if ((*wildcard).path).is_null() {
                     result = CURLE_OUT_OF_MEMORY;
                 } else {
                     let ref mut fresh63 = (*ftpwc).backup.write_function;
                     *fresh63 = (*data).set.fwrite_func;
                     let ref mut fresh64 = (*data).set.fwrite_func;
                     *fresh64 = Some(
                         Curl_ftp_parselist
                             as unsafe extern "C" fn(
                                 *mut libc::c_char,
                                 size_t,
                                 size_t,
                                 *mut libc::c_void,
                             ) -> size_t,
                     );
                     let ref mut fresh65 = (*ftpwc).backup.file_descriptor;
                     *fresh65 = (*data).set.out as *mut FILE;
                     let ref mut fresh66 = (*data).set.out;
                     *fresh66 = data as *mut libc::c_void;
                     Curl_infof(
                         data,
                         b"Wildcard - Parsing started\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_OK;
                 }
             }
         }
     }
     if !ftpwc.is_null() {
         Curl_ftp_parselist_data_free(&mut (*ftpwc).parser);
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")(ftpwc as *mut libc::c_void);

	#[cfg(CURLDEBUG)]

         curl_dbg_free(
             ftpwc as *mut libc::c_void,
             3854 as libc::c_int,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*wildcard).pattern as *mut libc::c_void);

	#[cfg(CURLDEBUG)]

     curl_dbg_free(
         (*wildcard).pattern as *mut libc::c_void,
         3856 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh67 = (*wildcard).pattern;
     *fresh67 = 0 as *mut libc::c_char;
     let ref mut fresh68 = (*wildcard).dtor;
     *fresh68 = None;
     let ref mut fresh69 = (*wildcard).protdata;
     *fresh69 = 0 as *mut libc::c_void;
     return result;
 }
 unsafe extern "C" fn wc_statemach(mut data: *mut Curl_easy) -> CURLcode {
     let wildcard: *mut WildcardData = &mut (*data).wildcard;
     let mut conn: *mut connectdata = (*data).conn;
     let mut result: CURLcode = CURLE_OK;
     let mut current_block_53: u64;
     loop {
         match (*wildcard).state as libc::c_uint {
             1 => {
                 result = init_wc_data(data);
                 if (*wildcard).state as libc::c_uint == CURLWC_CLEAN as libc::c_int as libc::c_uint
                 {
                     return result;
                 }
                 (*wildcard).state = (if result as libc::c_uint != 0 {
                     CURLWC_ERROR as libc::c_int
                 } else {
                     CURLWC_MATCHING as libc::c_int
                 }) as wildcard_states;
                 return result;
             }
             2 => {
                 let mut ftpwc: *mut ftp_wc = (*wildcard).protdata as *mut ftp_wc;
                 let ref mut fresh70 = (*data).set.fwrite_func;
                 *fresh70 = (*ftpwc).backup.write_function;
                 let ref mut fresh71 = (*data).set.out;
                 *fresh71 = (*ftpwc).backup.file_descriptor as *mut libc::c_void;
                 let ref mut fresh72 = (*ftpwc).backup.write_function;
                 *fresh72 = None;
                 let ref mut fresh73 = (*ftpwc).backup.file_descriptor;
                 *fresh73 = 0 as *mut FILE;
                 (*wildcard).state = CURLWC_DOWNLOADING;
                 if Curl_ftp_parselist_geterror((*ftpwc).parser) as u64 != 0 {
                     (*wildcard).state = CURLWC_CLEAN;
                 } else if (*wildcard).filelist.size == 0 as libc::c_int as libc::c_ulong {
                     (*wildcard).state = CURLWC_CLEAN;
                     return CURLE_REMOTE_FILE_NOT_FOUND;
                 }
             }
             3 => {
                 let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
                 let mut finfo: *mut curl_fileinfo =
                     (*(*wildcard).filelist.head).ptr as *mut curl_fileinfo;
                 let mut ftp: *mut FTP = (*data).req.p.ftp;
                 let mut tmp_path: *mut libc::c_char = curl_maprintf(
                     b"%s%s\0" as *const u8 as *const libc::c_char,
                     (*wildcard).path,
                     (*finfo).filename,
                 );
                 if tmp_path.is_null() {
                     return CURLE_OUT_OF_MEMORY;
                 }
                 #[cfg(not(CURLDEBUG))]
                 Curl_cfree.expect("non-null function pointer")(
                    (*ftp).pathalloc as *mut libc::c_void,
                );
	#[cfg(CURLDEBUG)]
                 curl_dbg_free(
                     (*ftp).pathalloc as *mut libc::c_void,
                     3912 as libc::c_int,
                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                 );
                 let ref mut fresh74 = (*ftp).path;
                 *fresh74 = tmp_path;
                 let ref mut fresh75 = (*ftp).pathalloc;
                 *fresh75 = *fresh74;
                 Curl_infof(
                     data,
                     b"Wildcard - START of \"%s\"\0" as *const u8 as *const libc::c_char,
                     (*finfo).filename,
                 );
                 if ((*data).set.chunk_bgn).is_some() {
                     let mut userresponse: libc::c_long = 0;
                     Curl_set_in_callback(data, 1 as libc::c_int != 0);
                     userresponse = ((*data).set.chunk_bgn).expect("non-null function pointer")(
                         finfo as *const libc::c_void,
                         (*wildcard).customptr,
                         (*wildcard).filelist.size as libc::c_int,
                     );
                     Curl_set_in_callback(data, 0 as libc::c_int != 0);
                     match userresponse {
                         2 => {
                            current_block_53 = 3773843889947583363;
                             match current_block_53 {
                                8041137041727403147 => return CURLE_CHUNK_FAILED,
                                 _ => {
                                     Curl_infof(
                                         data,
                                         b"Wildcard - \"%s\" skipped by user\0" as *const u8
                                             as *const libc::c_char,
                                         (*finfo).filename,
                                     );
                                     (*wildcard).state = CURLWC_SKIP;
                                     continue;
                                 }
                             }
                         }
                         1 => {
                            current_block_53 = 8041137041727403147;
                             match current_block_53 {
                                8041137041727403147 => return CURLE_CHUNK_FAILED,
                                 _ => {
                                     Curl_infof(
                                         data,
                                         b"Wildcard - \"%s\" skipped by user\0" as *const u8
                                             as *const libc::c_char,
                                         (*finfo).filename,
                                     );
                                     (*wildcard).state = CURLWC_SKIP;
                                     continue;
                                 }
                             }
                         }
                         _ => {}
                     }
                 }
                 if (*finfo).filetype as libc::c_uint
                     != CURLFILETYPE_FILE as libc::c_int as libc::c_uint
                 {
                     (*wildcard).state = CURLWC_SKIP;
                 } else {
                     if (*finfo).flags & ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint
                         != 0
                     {
                         (*ftpc).known_filesize = (*finfo).size;
                     }
                     result = ftp_parse_url_path(data);
                     if result as u64 != 0 {
                         return result;
                     }
                     Curl_llist_remove(
                         &mut (*wildcard).filelist,
                         (*wildcard).filelist.head,
                         0 as *mut libc::c_void,
                     );
                     if (*wildcard).filelist.size == 0 as libc::c_int as libc::c_ulong {
                         (*wildcard).state = CURLWC_CLEAN;
                         return CURLE_OK;
                     }
                     return result;
                 }
             }
             5 => {
                 if ((*data).set.chunk_end).is_some() {
                     Curl_set_in_callback(data, 1 as libc::c_int != 0);
                     ((*data).set.chunk_end).expect("non-null function pointer")(
                         (*data).wildcard.customptr,
                     );
                     Curl_set_in_callback(data, 0 as libc::c_int != 0);
                 }
                 Curl_llist_remove(
                     &mut (*wildcard).filelist,
                     (*wildcard).filelist.head,
                     0 as *mut libc::c_void,
                 );
                 (*wildcard).state =
                     (if (*wildcard).filelist.size == 0 as libc::c_int as libc::c_ulong {
                         CURLWC_CLEAN as libc::c_int
                     } else {
                         CURLWC_DOWNLOADING as libc::c_int
                     }) as wildcard_states;
             }
             4 => {
                 let mut ftpwc_0: *mut ftp_wc = (*wildcard).protdata as *mut ftp_wc;
                 result = CURLE_OK;
                 if !ftpwc_0.is_null() {
                     result = Curl_ftp_parselist_geterror((*ftpwc_0).parser);
                 }
                 (*wildcard).state = (if result as libc::c_uint != 0 {
                     CURLWC_ERROR as libc::c_int
                 } else {
                     CURLWC_DONE as libc::c_int
                 }) as wildcard_states;
                 return result;
             }
             7 | 6 | 0 => {
                 if ((*wildcard).dtor).is_some() {
                     ((*wildcard).dtor).expect("non-null function pointer")((*wildcard).protdata);
                 }
                 return result;
             }
             _ => {}
         }
     }
 }
 unsafe extern "C" fn ftp_do(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     *done = 0 as libc::c_int != 0;
     (*ftpc).wait_data_conn = 0 as libc::c_int != 0;
     if ((*data).state).wildcardmatch() != 0 {
         result = wc_statemach(data);
         if (*data).wildcard.state as libc::c_uint == CURLWC_SKIP as libc::c_int as libc::c_uint
             || (*data).wildcard.state as libc::c_uint == CURLWC_DONE as libc::c_int as libc::c_uint
         {
             return CURLE_OK;
         }
         if result as u64 != 0 {
             return result;
         }
     } else {
         result = ftp_parse_url_path(data);
         if result as u64 != 0 {
             return result;
         }
     }
     result = ftp_regular_transfer(data, done);
     return result;
 }
 unsafe extern "C" fn ftp_quit(mut data: *mut Curl_easy, mut conn: *mut connectdata) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     if (*conn).proto.ftpc.ctl_valid {
         result = Curl_pp_sendf(
             data,
             &mut (*conn).proto.ftpc.pp as *mut pingpong,
             b"%s\0" as *const u8 as *const libc::c_char,
             b"QUIT\0" as *const u8 as *const libc::c_char,
         );
         if result as u64 != 0 {
             Curl_failf(
                 data,
                 b"Failure sending QUIT command: %s\0" as *const u8 as *const libc::c_char,
                 curl_easy_strerror(result),
             );
             (*conn).proto.ftpc.ctl_valid = 0 as libc::c_int != 0;
             #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
             Curl_conncontrol(conn, 1 as libc::c_int);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
             Curl_conncontrol(
                 conn,
                 1 as libc::c_int,
                 b"QUIT command failed\0" as *const u8 as *const libc::c_char,
             );
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_STOP);

	#[cfg(DEBUGBUILD)]
             _state(data, FTP_STOP, 4050 as libc::c_int);
             return result;
         }
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_QUIT);

         #[cfg(DEBUGBUILD)]
         _state(data, FTP_QUIT, 4054 as libc::c_int);
         result = ftp_block_statemach(data, conn);
     }
     return result;
 }
 unsafe extern "C" fn ftp_disconnect(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut dead_connection: bool,
 ) -> CURLcode {
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     if dead_connection {
         (*ftpc).ctl_valid = 0 as libc::c_int != 0;
     }
     ftp_quit(data, conn);
     if !((*ftpc).entrypath).is_null() {
         if (*data).state.most_recent_ftp_entrypath == (*ftpc).entrypath {
             let ref mut fresh76 = (*data).state.most_recent_ftp_entrypath;
             *fresh76 = 0 as *mut libc::c_char;
         }
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")((*ftpc).entrypath as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
         curl_dbg_free(
             (*ftpc).entrypath as *mut libc::c_void,
             4093 as libc::c_int,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
         let ref mut fresh77 = (*ftpc).entrypath;
         *fresh77 = 0 as *mut libc::c_char;
     }
     freedirs(ftpc);
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*ftpc).prevpath as *mut libc::c_void,
         4097 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh78 = (*ftpc).prevpath;
     *fresh78 = 0 as *mut libc::c_char;
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).server_os as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*ftpc).server_os as *mut libc::c_void,
         4098 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     let ref mut fresh79 = (*ftpc).server_os;
     *fresh79 = 0 as *mut libc::c_char;
     Curl_pp_disconnect(pp);
    #[cfg(HAVE_GSSAPI)]
    Curl_sec_end(conn);
     return CURLE_OK;
 }
 unsafe extern "C" fn ftp_parse_url_path(mut data: *mut Curl_easy) -> CURLcode {
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut slashPos: *const libc::c_char = 0 as *const libc::c_char;
     let mut fileName: *const libc::c_char = 0 as *const libc::c_char;
     let mut result: CURLcode = CURLE_OK;
     let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut pathLen: size_t = 0 as libc::c_int as size_t;
     (*ftpc).ctl_valid = 0 as libc::c_int != 0;
     (*ftpc).cwdfail = 0 as libc::c_int != 0;
     result = Curl_urldecode(
         data,
         (*ftp).path,
         0 as libc::c_int as size_t,
         &mut rawPath,
         &mut pathLen,
         REJECT_CTRL,
     );
     if result as u64 != 0 {
         return result;
     }
     match (*data).set.ftp_filemethod as libc::c_uint {
         2 => {
             if pathLen > 0 as libc::c_int as libc::c_ulong
                 && *rawPath.offset(pathLen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
                     as libc::c_int
                     != '/' as i32
             {
                 fileName = rawPath;
             }
         }
         3 => {
             slashPos = strrchr(rawPath, '/' as i32);
             if !slashPos.is_null() {
                 let mut dirlen: size_t = slashPos.offset_from(rawPath) as libc::c_long as size_t;
                 if dirlen == 0 as libc::c_int as libc::c_ulong {
                     dirlen = dirlen.wrapping_add(1);
                 }
                 
                 match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {
                        (*ftpc).dirs = Curl_ccalloc.expect("non-null function pointer")(
                            1 as libc::c_int as size_t,
                            ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                        ) as *mut *mut libc::c_char;
                    }
                    #[cfg(CURLDEBUG)]
                    _ => {
                        (*ftpc).dirs = curl_dbg_calloc(
                            1 as libc::c_int as size_t,
                            ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                            4153 as libc::c_int,
                            b"ftp.c\0" as *const u8 as *const libc::c_char,
                        ) as *mut *mut libc::c_char;
                    }
                }
                 
                 if ((*ftpc).dirs).is_null() {
                    #[cfg(not(CURLDEBUG))]
                    Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
                     curl_dbg_free(
                         rawPath as *mut libc::c_void,
                         4155 as libc::c_int,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_OUT_OF_MEMORY;
                 }
                 match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {
                        *((*ftpc).dirs).offset(0 as libc::c_int as isize) = Curl_ccalloc.expect("non-null function pointer")(
                            1 as libc::c_int as size_t,
                            dirlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                        ) as *mut libc::c_char;
                    }
                    #[cfg(CURLDEBUG)]
                    _ => {
                        *((*ftpc).dirs).offset(0 as libc::c_int as isize) = curl_dbg_calloc(
                            1 as libc::c_int as size_t,
                            dirlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                            4159 as libc::c_int,
                            b"ftp.c\0" as *const u8 as *const libc::c_char,
                        ) as *mut libc::c_char;
                    }
                }
                
                 if (*((*ftpc).dirs).offset(0 as libc::c_int as isize)).is_null() {
                    #[cfg(not(CURLDEBUG))]
                    Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

	#[cfg(CURLDEBUG)] 
                    curl_dbg_free(
                         rawPath as *mut libc::c_void,
                         4161 as libc::c_int,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_OUT_OF_MEMORY;
                 }
                 strncpy(
                     *((*ftpc).dirs).offset(0 as libc::c_int as isize),
                     rawPath,
                     dirlen,
                 );
                 (*ftpc).dirdepth = 1 as libc::c_int;
                 fileName = slashPos.offset(1 as libc::c_int as isize);
             } else {
                 fileName = rawPath;
             }
         }
         1 | _ => {
             let mut curPos: *const libc::c_char = rawPath;
             let mut dirAlloc: libc::c_int = 0 as libc::c_int;
             let mut str: *const libc::c_char = rawPath;
             while *str as libc::c_int != 0 as libc::c_int {
                 if *str as libc::c_int == '/' as i32 {
                     dirAlloc += 1;
                 }
                 str = str.offset(1);
             }
             if dirAlloc > 0 as libc::c_int {
                 match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {
                        (*ftpc).dirs = Curl_ccalloc.expect("non-null function pointer")(
                            dirAlloc as size_t,
                            ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                        ) as *mut *mut libc::c_char;
                    }
                    #[cfg(CURLDEBUG)]
                    _ => {
                        (*ftpc).dirs = curl_dbg_calloc(
                            dirAlloc as size_t,
                            ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                            4185 as libc::c_int,
                            b"ftp.c\0" as *const u8 as *const libc::c_char,
                        ) as *mut *mut libc::c_char;
                    }
                }
                
                 if ((*ftpc).dirs).is_null() {
                    #[cfg(not(CURLDEBUG))]
                    Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
                     curl_dbg_free(
                         rawPath as *mut libc::c_void,
                         4187 as libc::c_int,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_OUT_OF_MEMORY;
                 }
                 loop {
                     slashPos = strchr(curPos, '/' as i32);
                     if slashPos.is_null() {
                         break;
                     }
                     let mut compLen: size_t =
                         slashPos.offset_from(curPos) as libc::c_long as size_t;
                     if compLen == 0 as libc::c_int as libc::c_ulong
                         && (*ftpc).dirdepth == 0 as libc::c_int
                     {
                         compLen = compLen.wrapping_add(1);
                     }
                     if compLen > 0 as libc::c_int as libc::c_ulong {
                        #[cfg(not(CURLDEBUG))]
                        let mut comp: *mut libc::c_char =
                        Curl_ccalloc.expect("non-null function pointer")(
                            1 as libc::c_int as size_t,
                            compLen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                        ) as *mut libc::c_char;
	                    #[cfg(CURLDEBUG)]
                         let mut comp: *mut libc::c_char = curl_dbg_calloc(
                             1 as libc::c_int as size_t,
                             compLen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                             4203 as libc::c_int,
                             b"ftp.c\0" as *const u8 as *const libc::c_char,
                         )
                             as *mut libc::c_char;
                         if comp.is_null() {
                            #[cfg(not(CURLDEBUG))]
                            Curl_cfree.expect("non-null function pointer")(
                                rawPath as *mut libc::c_void,
                            );
	                        #[cfg(CURLDEBUG)]
                             curl_dbg_free(
                                 rawPath as *mut libc::c_void,
                                 4205 as libc::c_int,
                                 b"ftp.c\0" as *const u8 as *const libc::c_char,
                             );
                             return CURLE_OUT_OF_MEMORY;
                         }
                         strncpy(comp, curPos, compLen);
                         let ref mut fresh83 = (*ftpc).dirdepth;
                         let fresh84 = *fresh83;
                         *fresh83 = *fresh83 + 1;
                         let ref mut fresh85 = *((*ftpc).dirs).offset(fresh84 as isize);
                         *fresh85 = comp;
                     }
                     curPos = slashPos.offset(1 as libc::c_int as isize);
                 }
             }
             #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
             if (*ftpc).dirdepth <= dirAlloc {
             } else {
                 __assert_fail(
                     b"ftpc->dirdepth <= dirAlloc\0" as *const u8 as *const libc::c_char,
                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                     4214 as libc::c_int as libc::c_uint,
                     (*::std::mem::transmute::<&[u8; 48], &[libc::c_char; 48]>(
                         b"CURLcode ftp_parse_url_path(struct Curl_easy *)\0",
                     ))
                     .as_ptr(),
                 );
             }
             fileName = curPos;
         }
     }
     if !fileName.is_null() && *fileName as libc::c_int != 0 {
         match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                (*ftpc).file = Curl_cstrdup.expect("non-null function pointer")(fileName);

            }
            #[cfg(CURLDEBUG)]
            _ => {
                (*ftpc).file = curl_dbg_strdup(
                    fileName,
                    4221 as libc::c_int,
                    b"ftp.c\0" as *const u8 as *const libc::c_char,
                );
            }
        }
         
     } else {
         let ref mut fresh87 = (*ftpc).file;
         *fresh87 = 0 as *mut libc::c_char;
     }
     if ((*data).set).upload() as libc::c_int != 0
         && ((*ftpc).file).is_null()
         && (*ftp).transfer as libc::c_uint == PPTRANSFER_BODY as libc::c_int as libc::c_uint
     {
         Curl_failf(
             data,
             b"Uploading to a URL without a file name!\0" as *const u8 as *const libc::c_char,
         );
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
         curl_dbg_free(
             rawPath as *mut libc::c_void,
             4229 as libc::c_int,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_URL_MALFORMAT;
     }
     (*ftpc).cwddone = 0 as libc::c_int != 0;
     if (*data).set.ftp_filemethod as libc::c_uint == FTPFILE_NOCWD as libc::c_int as libc::c_uint
         && *rawPath.offset(0 as libc::c_int as isize) as libc::c_int == '/' as i32
     {
         (*ftpc).cwddone = 1 as libc::c_int != 0;
     } else {
         let mut oldPath: *const libc::c_char = if ((*conn).bits).reuse() as libc::c_int != 0 {
             (*ftpc).prevpath as *const libc::c_char
         } else {
             b"\0" as *const u8 as *const libc::c_char
         };
         if !oldPath.is_null() {
             let mut n: size_t = pathLen;
             if (*data).set.ftp_filemethod as libc::c_uint
                 == FTPFILE_NOCWD as libc::c_int as libc::c_uint
             {
                 n = 0 as libc::c_int as size_t;
             } else {
                 n = (n as libc::c_ulong).wrapping_sub(if !((*ftpc).file).is_null() {
                     strlen((*ftpc).file)
                 } else {
                     0 as libc::c_int as libc::c_ulong
                 }) as size_t as size_t;
             }
             if strlen(oldPath) == n && strncmp(rawPath, oldPath, n) == 0 {
                 Curl_infof(
                     data,
                     b"Request has same path as previous transfer\0" as *const u8
                         as *const libc::c_char,
                 );
                 (*ftpc).cwddone = 1 as libc::c_int != 0;
             }
         }
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

	#[cfg(CURLDEBUG)]
     curl_dbg_free(
         rawPath as *mut libc::c_void,
         4253 as libc::c_int,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     return CURLE_OK;
 }
 unsafe extern "C" fn ftp_dophase_done(mut data: *mut Curl_easy, mut connected: bool) -> CURLcode {
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if connected {
         let mut completed: libc::c_int = 0;
         let mut result: CURLcode = ftp_do_more(data, &mut completed);
         if result as u64 != 0 {
             close_secondarysocket(data, conn);
             return result;
         }
     }
     if (*ftp).transfer as libc::c_uint != PPTRANSFER_BODY as libc::c_int as libc::c_uint {
         Curl_setup_transfer(
             data,
             -(1 as libc::c_int),
             -(1 as libc::c_int) as curl_off_t,
             0 as libc::c_int != 0,
             -(1 as libc::c_int),
         );
     } else if !connected {
         let ref mut fresh88 = (*conn).bits;
         (*fresh88).set_do_more(1 as libc::c_int as bit);
     }
     (*ftpc).ctl_valid = 1 as libc::c_int != 0;
     return CURLE_OK;
 }
 unsafe extern "C" fn ftp_doing(mut data: *mut Curl_easy, mut dophase_done: *mut bool) -> CURLcode {
     let mut result: CURLcode = ftp_multi_statemach(data, dophase_done);
     if result as u64 != 0 {
        #[cfg(DEBUGBUILD)]
         Curl_infof(
             data,
             b"DO phase failed\0" as *const u8 as *const libc::c_char,
         );
     } else if *dophase_done {
         result = ftp_dophase_done(data, 0 as libc::c_int != 0);
         #[cfg(DEBUGBUILD)]
         Curl_infof(
             data,
             b"DO phase is complete2\0" as *const u8 as *const libc::c_char,
         );
     }
     return result;
 }
 unsafe extern "C" fn ftp_regular_transfer(
     mut data: *mut Curl_easy,
     mut dophase_done: *mut bool,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut connected: bool = 0 as libc::c_int != 0;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     (*data).req.size = -(1 as libc::c_int) as curl_off_t;
     Curl_pgrsSetUploadCounter(data, 0 as libc::c_int as curl_off_t);
     Curl_pgrsSetDownloadCounter(data, 0 as libc::c_int as curl_off_t);
     Curl_pgrsSetUploadSize(data, -(1 as libc::c_int) as curl_off_t);
     Curl_pgrsSetDownloadSize(data, -(1 as libc::c_int) as curl_off_t);
     (*ftpc).ctl_valid = 1 as libc::c_int != 0;
     result = ftp_perform(data, &mut connected, dophase_done);
     if result as u64 == 0 {
         if !*dophase_done {
             return CURLE_OK;
         }
         result = ftp_dophase_done(data, connected);
         if result as u64 != 0 {
             return result;
         }
     } else {
         freedirs(ftpc);
     }
     return result;
 }
 unsafe extern "C" fn ftp_setup_connection(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     let mut type_0: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut ftp: *mut FTP = 0 as *mut FTP;
     match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            ftp = Curl_ccalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<FTP>() as libc::c_ulong,
            1 as libc::c_int as size_t,
        ) as *mut FTP;
        }
        #[cfg(CURLDEBUG)]
        _ => {
            ftp = curl_dbg_calloc(
                ::std::mem::size_of::<FTP>() as libc::c_ulong,
                1 as libc::c_int as size_t,
                4358 as libc::c_int,
                b"ftp.c\0" as *const u8 as *const libc::c_char,
            ) as *mut FTP;
        }
    }
     
     let ref mut fresh89 = (*data).req.p.ftp;
     *fresh89 = ftp;
     if ftp.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     let ref mut fresh90 = (*ftp).path;
     *fresh90 = &mut *((*data).state.up.path).offset(1 as libc::c_int as isize) as *mut libc::c_char;
     type_0 = strstr((*ftp).path, b";type=\0" as *const u8 as *const libc::c_char);
     if type_0.is_null() {
         type_0 = strstr(
             (*conn).host.rawalloc,
             b";type=\0" as *const u8 as *const libc::c_char,
         );
     }
     if !type_0.is_null() {
         let mut command: libc::c_char = 0;
         *type_0 = 0 as libc::c_int as libc::c_char;
         command = Curl_raw_toupper(*type_0.offset(6 as libc::c_int as isize));
         match command as libc::c_int {
             65 => {
                 let ref mut fresh91 = (*data).state;
                 (*fresh91).set_prefer_ascii(1 as libc::c_int as bit);
             }
             68 => {
                 let ref mut fresh92 = (*data).state;
                 (*fresh92).set_list_only(1 as libc::c_int as bit);
             }
             73 | _ => {
                 let ref mut fresh93 = (*data).state;
                 (*fresh93).set_prefer_ascii(0 as libc::c_int as bit);
             }
         }
     }
     (*ftp).transfer = PPTRANSFER_BODY;
     (*ftp).downloadsize = 0 as libc::c_int as curl_off_t;
     (*conn).proto.ftpc.known_filesize = -(1 as libc::c_int) as curl_off_t;
     return CURLE_OK;
 }
 