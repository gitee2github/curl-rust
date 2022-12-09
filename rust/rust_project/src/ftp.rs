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
extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    unsafe{
     return (__bsx as i32 >> 8 as i32 & 0xff as i32
         | (__bsx as i32 & 0xff as i32) << 8 as i32)
         as __uint16_t;
     }
 }
 #[no_mangle]
 pub static mut Curl_handler_ftp: Curl_handler = unsafe {
     {
         let mut init = Curl_handler {
             scheme: b"FTP\0" as *const u8 as *const libc::c_char,/* scheme */
             setup_connection: Some(
                 ftp_setup_connection
                     as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
             ),/* setup_connection */
             do_it: Some(ftp_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),/* do_it */
             done: Some(
                 ftp_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
             ),/* done */
             do_more: Some(
                 ftp_do_more as unsafe extern "C" fn(*mut Curl_easy, *mut i32) -> CURLcode,
             ), /* do_more */
             connect_it: Some(
                 ftp_connect as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),/* connect_it */
             connecting: Some(
                 ftp_multi_statemach as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ), /* connecting */
             doing: Some(ftp_doing as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),/* doing */
             proto_getsock: Some(
                 ftp_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> i32,
             ),/* proto_getsock */
             doing_getsock: Some(
                 ftp_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> i32,
             ), /* doing_getsock */
             domore_getsock: Some(
                 ftp_domore_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> i32,
             ), /* domore_getsock */
             perform_getsock: None,/* perform_getsock */
             disconnect: Some(
                 ftp_disconnect
                     as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
             ), /* disconnect */
             readwrite: None,/* readwrite */
             connection_check: None,/* connection_check */
             attach: None, /* attach connection */
             defport: 21 as i32,/* defport */
             protocol: ((1 as i32) << 2 as i32) as u32, /* protocol */
             family: ((1 as i32) << 2 as i32) as u32, /* family */
             flags: ((1 as i32) << 1 as i32
                 | (1 as i32) << 2 as i32
                 | (1 as i32) << 5 as i32
                 | (1 as i32) << 6 as i32
                 | (1 as i32) << 11 as i32
                 | (1 as i32) << 12 as i32) as u32,
         }; /* flags */
         init
     }
 };
 #[cfg(USE_SSL)]
 #[no_mangle]
 pub static mut Curl_handler_ftps: Curl_handler = unsafe {
     {
         let mut init = Curl_handler {
             scheme: b"FTPS\0" as *const u8 as *const libc::c_char,/* scheme */
             setup_connection: Some(
                 ftp_setup_connection
                     as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
             ), /* setup_connection */
             do_it: Some(
                 ftp_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),/* do_it */
             done: Some(
                 ftp_done
                     as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
             ),/* done */
             do_more: Some(
                 ftp_do_more
                     as unsafe extern "C" fn(*mut Curl_easy, *mut i32) -> CURLcode,
             ),/* do_more */
             connect_it: Some(
                 ftp_connect
                     as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),/* connect_it */
             connecting: Some(
                 ftp_multi_statemach
                     as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ),/* connecting */
             doing: Some(
                 ftp_doing as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
             ), /* doing */
             proto_getsock: Some(
                 ftp_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> i32,
             ), /* proto_getsock */
             doing_getsock: Some(
                 ftp_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> i32,
             ),/* doing_getsock */
             domore_getsock: Some(
                 ftp_domore_getsock
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         *mut curl_socket_t,
                     ) -> i32,
             ),/* domore_getsock */
             perform_getsock: None,/* perform_getsock */
             disconnect: Some(
                 ftp_disconnect
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         bool,
                     ) -> CURLcode,
             ), /* disconnect */
             readwrite: None,/* readwrite */
             connection_check: None,/* connection_check */
             attach: None, /* attach connection */
             defport: 990 as i32, /* defport */
             protocol: ((1 as i32) << 3 as i32) as u32, /* protocol */
             family: ((1 as i32) << 2 as i32) as u32, /* family */
             flags: ((1 as i32) << 0 as i32
                 | (1 as i32) << 1 as i32
                 | (1 as i32) << 2 as i32
                 | (1 as i32) << 5 as i32
                 | (1 as i32) << 6 as i32
                 | (1 as i32) << 12 as i32) as u32,/* flags */
         };
         init
     }
 };
 extern "C" fn close_secondarysocket(mut data: *mut Curl_easy, mut conn: *mut connectdata) {
    unsafe{
    if -(1 as i32) != (*conn).sock[1 as usize] {
         Curl_closesocket(data, conn, (*conn).sock[1 as usize]);
         (*conn).sock[1 as usize] = -(1 as i32);
     }
     (*conn).bits.tcpconnect[1 as usize] = 0 as i32 != 0;
     match() {
         #[cfg(not(CURL_DISABLE_PROXY))]
         _ => {
     (*conn).bits.proxy_ssl_connected[1 as usize] = 0 as i32 != 0;
 }
         #[cfg(CURL_DISABLE_PROXY)]
         _ => { }
     }
    }
 }

/*
 * NOTE: back in the old days, we added code in the FTP code that made NOBODY
 * requests on files respond with headers passed to the client/stdout that
 * looked like HTTP ones.
 *
 * This approach is not very elegant, it causes confusion and is error-prone.
 * It is subject for removal at the next (or at least a future) soname bump.
 * Until then you can test the effects of the removal by undefining the
 * following define named CURL_FTP_HTTPSTYLE_HEAD.
 */
extern "C" fn freedirs(mut ftpc: *mut ftp_conn) {
    unsafe{
    if !((*ftpc).dirs).is_null() {
         let mut i: i32 = 0;
         i = 0 as i32;
         while i < (*ftpc).dirdepth {
             #[cfg(not(CURLDEBUG))]
             Curl_cfree.expect("non-null function pointer")(
                 *((*ftpc).dirs).offset(i as isize) as *mut libc::c_void
             );
             #[cfg(CURLDEBUG)]
             curl_dbg_free(
                 *((*ftpc).dirs).offset(i as isize) as *mut libc::c_void,
                 248 as i32,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
             *((*ftpc).dirs).offset(i as isize) = 0 as *mut libc::c_char;
             i += 1;
         }
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")((*ftpc).dirs as *mut libc::c_void);
         #[cfg(CURLDEBUG)]
         curl_dbg_free(
             (*ftpc).dirs as *mut libc::c_void,
             251 as i32,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
         (*ftpc).dirs = 0 as *mut *mut libc::c_char;
         (*ftpc).dirdepth = 0 as i32;
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).file as *mut libc::c_void);
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*ftpc).file as *mut libc::c_void,
         255 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     (*ftpc).file = 0 as *mut libc::c_char;
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*ftpc).newhost as *mut libc::c_void,
         258 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     /* no longer of any use */
     (*ftpc).newhost = 0 as *mut libc::c_char;
    }
 }
 
/***********************************************************************
 *
 * AcceptServerConnect()
 *
 * After connection request is received from the server this function is
 * called to accept the connection and close the listening socket
 *
 */
extern "C" fn AcceptServerConnect(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
     let mut conn: *mut connectdata = (*data).conn;
     let mut sock: curl_socket_t = (*conn).sock[1 as usize];
     let mut s: curl_socket_t = -(1 as i32);
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
         ::std::mem::size_of::<Curl_sockaddr_storage>() as curl_socklen_t;
     #[cfg(not(ENABLE_IPV6))]
     let mut size: curl_socklen_t = ::std::mem::size_of::<sockaddr_in>() as u64
         as curl_socklen_t;
     #[cfg(ENABLE_IPV6)]
     if 0 as i32
         == getsockname(
             sock,
             &mut add as *mut Curl_sockaddr_storage as *mut sockaddr,
             &mut size,
         )
     {
         size = ::std::mem::size_of::<Curl_sockaddr_storage>() as curl_socklen_t;
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
                     284 as i32,
                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                 );
             }        
     }
 }
     #[cfg(not(ENABLE_IPV6))]
     if 0 as i32
         == getsockname(sock, &mut add as *mut sockaddr_in as *mut sockaddr, &mut size)
     {
         size = ::std::mem::size_of::<sockaddr_in>() as curl_socklen_t;
         s = accept(sock, &mut add as *mut sockaddr_in as *mut sockaddr, &mut size);
     }
     Curl_closesocket(data, conn, sock);/* close the first socket */
     if -(1 as i32) == s {
         Curl_failf(
             data,
             b"Error accept()ing server connect\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_FTP_PORT_FAILED;
     }
     Curl_infof(
         data,
         b"Connection accepted from server\0" as *const u8 as *const libc::c_char,
     );/* when this happens within the DO state it is important that we mark us as
     not needing DO_MORE anymore */
     ((*conn).bits).set_do_more(0 as bit);
     (*conn).sock[1 as usize] = s;
     curlx_nonblock(s, 1 as i32);/* enable non-blocking */
     ((*conn).bits).set_sock_accepted(1 as bit);
     if ((*data).set.fsockopt).is_some() {
         let mut error: i32 = 0 as i32;
         Curl_set_in_callback(data, 1 as i32 != 0); /* activate callback for setting socket options */
         error = ((*data).set.fsockopt).expect("non-null function pointer")(
             (*data).set.sockopt_client,
             s,
             CURLSOCKTYPE_ACCEPT,
         );
         Curl_set_in_callback(data, 0 as i32 != 0);
         if error != 0 {
             close_secondarysocket(data, conn);
             return CURLE_ABORTED_BY_CALLBACK;
         }
     }
     return CURLE_OK;
    }
 }
 
/*
 * ftp_timeleft_accept() returns the amount of milliseconds left allowed for
 * waiting server to connect. If the value is negative, the timeout time has
 * already elapsed.
 *
 * The start time is stored in progress.t_acceptdata - as set with
 * Curl_pgrsTime(..., TIMER_STARTACCEPT);
 *
 */
extern "C" fn ftp_timeleft_accept(mut data: *mut Curl_easy) -> timediff_t {
    unsafe{
     let mut timeout_ms: timediff_t = 60000 as timediff_t;
     let mut other: timediff_t = 0;
     let mut now: curltime = curltime {
         tv_sec: 0,
         tv_usec: 0,
     };
     if (*data).set.accepttimeout > 0 as i64 {
         timeout_ms = (*data).set.accepttimeout;
     }
     now = Curl_now();
     /* check if the generic timeout possibly is set shorter */
     other = Curl_timeleft(data, &mut now, 0 as i32 != 0);
     if other != 0 && other < timeout_ms {
        /* note that this also works fine for when other happens to be negative
       due to it already having elapsed */
         timeout_ms = other;
     } else {
        /* subtract elapsed time */
         timeout_ms -= Curl_timediff(now, (*data).progress.t_acceptdata);
         if timeout_ms == 0 {
             /* avoid returning 0 as that means no timeout! */
             return -(1 as i32) as timediff_t;
         }
     }
     return timeout_ms;
    }
 }
 /***********************************************************************
 *
 * ReceivedServerConnect()
 *
 * After allowing server to connect to us from data port, this function
 * checks both data connection for connection establishment and ctrl
 * connection for a negative response regarding a failure in connecting
 *
 */
extern "C" fn ReceivedServerConnect(
    mut data: *mut Curl_easy,
    mut received: *mut bool,
) -> CURLcode {
   unsafe{
    let mut conn: *mut connectdata = (*data).conn;
    let mut ctrl_sock: curl_socket_t = (*conn).sock[0 as usize];
    let mut data_sock: curl_socket_t = (*conn).sock[1 as usize];
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    let mut result: i32 = 0;
    let mut timeout_ms: timediff_t = 0;
    let mut nread: ssize_t = 0;
    let mut ftpcode: i32 = 0;
    *received = 0 as i32 != 0;
    timeout_ms = ftp_timeleft_accept(data);
    Curl_infof(
        data,
        b"Checking for server connect\0" as *const u8 as *const libc::c_char,
    );
    if timeout_ms < 0 as i64 {
       /* if a timeout was already reached, bail out */
        Curl_failf(
            data,
            b"Accept timeout occurred while waiting server connect\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_FTP_ACCEPT_TIMEOUT;
    }
    /* First check whether there is a cached response from server */
 
    if (*pp).cache_size != 0
        && !((*pp).cache).is_null()
        && *((*pp).cache).offset(0 as isize) as i32 > '3' as i32
    {
       /* Data connection could not be established, let's return */
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
        -(1 as i32),
        0 as i32 as timediff_t,
    );
    /* see if the connection request is already here */
    match result {
        -1 => { /* error *//* let's die here */
            Curl_failf(
                data,
                b"Error while waiting for server connect\0" as *const u8 as *const libc::c_char,
            );/* let's die here */
            return CURLE_FTP_ACCEPT_FAILED;
        }
        0 => {} /* Server connect is not received yet */
        /* loop */
        _ => {
            if result & (0x4 as i32) << 1 as i32 != 0 {
                Curl_infof(
                    data,
                    b"Ready to accept data connection from server\0" as *const u8
                        as *const libc::c_char,
                );
                *received = 1 as i32 != 0;
            } else if result & 0x1 as i32 != 0 {
                Curl_infof(
                    data,
                    b"Ctrl conn has data while waiting for data conn\0" as *const u8
                        as *const libc::c_char,
                );
                Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
                if ftpcode / 100 as i32 > 3 as i32 {
                    return CURLE_FTP_ACCEPT_FAILED;
                }
                return CURLE_WEIRD_SERVER_REPLY;
            }
        }/* switch() */
    }
    return CURLE_OK;
   }
}

/***********************************************************************
 *
 * InitiateTransfer()
 *
 * After connection from server is accepted this function is called to
 * setup transfer parameters and initiate the data transfer.
 *
 */
extern "C" fn InitiateTransfer(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     if ((*conn).bits).ftp_use_data_ssl() != 0 {
        /* since we only have a plaintext TCP connection here, we must now
     * do the TLS stuff */
         Curl_infof(
             data,
             b"Doing the SSL/TLS handshake on the data stream\0" as *const u8 as *const libc::c_char,
         );
         // match () {
         //     #[cfg(USE_SSL)]
         //     _ => {
         //         result = Curl_ssl_connect(data, conn, 1 as i32);
         //     }
         //     #[cfg(not(USE_SSL))]
         //     _ => {
         //         result = CURLE_NOT_BUILT_IN;
         //     }
         // }
         result = Curl_ssl_connect(data, conn, 1 as i32);
         if result as u64 != 0 {
             return result;
         }
     }
     /* When we know we're uploading a specified file, we can get the file
       size prior to the actual upload. */
     if (*conn).proto.ftpc.state_saved as u32 == FTP_STOR as u32 {
         Curl_pgrsSetUploadSize(data, (*data).state.infilesize);
         /* set the SO_SNDBUF for the secondary socket for those who need it */
         Curl_setup_transfer(
             data,
             -(1 as i32),
             -(1 as i32) as curl_off_t,
             0 as i32 != 0,
             1 as i32,
         );
     } else {
        /* FTP download: */
         Curl_setup_transfer(
             data,
             1 as i32,
             (*conn).proto.ftpc.retr_size_saved,
             0 as i32 != 0,
             -(1 as i32),
         );
     }
     (*conn).proto.ftpc.pp.pending_resp = 1 as i32 != 0;/* expect server response */
     #[cfg(not(DEBUGBUILD))]
     _state(data, FTP_STOP);
 
     #[cfg(DEBUGBUILD)]
     _state(data, FTP_STOP, 470 as i32);
     return CURLE_OK;
    }
 }
 /***********************************************************************
 *
 * AllowServerConnect()
 *
 * When we've issue the PORT command, we have told the server to connect to
 * us. This function checks whether data connection is established if so it is
 * accepted.
 *
 */
extern "C" fn AllowServerConnect(
    mut data: *mut Curl_easy,
    mut connected: *mut bool,
) -> CURLcode {
   unsafe{
    let mut timeout_ms: timediff_t = 0;
    let mut result: CURLcode = CURLE_OK;
    *connected = 0 as i32 != 0;
    Curl_infof(
        data,
        b"Preparing for accepting server on data port\0" as *const u8 as *const libc::c_char,
    );
    /* Save the time we start accepting server connect */
    Curl_pgrsTime(data, TIMER_STARTACCEPT);
    timeout_ms = ftp_timeleft_accept(data);
    if timeout_ms < 0 as i64 {
       /* if a timeout was already reached, bail out */
        Curl_failf(
            data,
            b"Accept timeout occurred while waiting server connect\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_FTP_ACCEPT_TIMEOUT;
    }
     /* see if the connection request is already here */
    result = ReceivedServerConnect(data, connected);
    if result as u64 != 0 {
        return result;
    }
    /* Add timeout to multi handle and break out of the loop */
   
    if *connected {
        result = AcceptServerConnect(data);
        if result as u64 != 0 {
            return result;
        }
        result = InitiateTransfer(data);
        if result as u64 != 0 {
            return result;
        }
    } else if *connected as i32 == 0 as i32 {
        Curl_expire(
            data,
            if (*data).set.accepttimeout > 0 as i64 {
                (*data).set.accepttimeout
            } else {
                60000 as i64
            },
            EXPIRE_100_TIMEOUT,
        );
    }
    return result;
   }
}
extern "C" fn ftp_endofresp(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut line: *mut libc::c_char,
    mut len: size_t,
    mut code: *mut i32,
) -> bool {
   unsafe{
    if len > 3 as u64
        && (Curl_isdigit(*line.offset(0 as isize) as i32)
            != 0
            && Curl_isdigit(*line.offset(1 as isize) as i32)
                != 0
            && Curl_isdigit(*line.offset(2 as isize) as i32)
                != 0
            && ' ' as i32 == *line.offset(3 as isize) as i32)
    {
        *code = curlx_sltosi(strtol(line, 0 as *mut *mut libc::c_char, 10 as i32));
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
   }
}
extern "C" fn ftp_readresp(
    mut data: *mut Curl_easy,
    mut sockfd: curl_socket_t,
    mut pp: *mut pingpong,
    mut ftpcode: *mut i32, /* return the ftp-code if done */
    mut size: *mut size_t,/* size of the response */
) -> CURLcode {
   unsafe{
    let mut code: i32 = 0;
    let mut result: CURLcode = Curl_pp_readresp(data, sockfd, pp, &mut code, size);
    if cfg!(HAVE_GSSAPI) {
        let mut conn: *mut connectdata = (*data).conn;
        let buf: *mut libc::c_char = (*data).state.buffer;
        /* handle the security-oriented responses 6xx ***/
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
            _ => {} /* normal ftp stuff we pass through! */
        }
    }
    /* store the latest code for later retrieval */
    (*data).info.httpcode = code;
    if !ftpcode.is_null() {
        *ftpcode = code;
    }
    if 421 as i32 == code {
       /* 421 means "Service not available, closing control connection." and FTP
    * servers use it to signal that idle session timeout has been exceeded.
    * If we ignored the response, it could end up hanging in some cases.
    *
    * This response code can come at any point so having it treated
    * generically is a good idea.
    */
        Curl_infof(
            data,
            b"We got a 421 - timeout!\0" as *const u8 as *const libc::c_char,
        );
        #[cfg(not(DEBUGBUILD))]
        _state(data, FTP_STOP);

        #[cfg(DEBUGBUILD)]
        _state(data, FTP_STOP, 596 as i32);
        return CURLE_OPERATION_TIMEDOUT;
    }
    return result;
   }
}
/* --- parse FTP server responses --- */

/*
* Curl_GetFTPResponse() is a BLOCKING function to read the full response
* from a server after a command.
*
*/
#[no_mangle]
 pub extern "C" fn Curl_GetFTPResponse(
     mut data: *mut Curl_easy,
     mut nreadp: *mut ssize_t,/* return number of bytes read */
     mut ftpcode: *mut i32,/* return the ftp-code */
 ) -> CURLcode {
    unsafe{
        /*
   * We cannot read just one byte per read() and then go back to select() as
   * the OpenSSL read() doesn't grok that properly.
   *
   * Alas, read as much as possible, split up into lines, use the ending
   * line in a response or continue reading.  */

     let mut conn: *mut connectdata = (*data).conn;
     let mut sockfd: curl_socket_t = (*conn).sock[0 as usize];
     let mut result: CURLcode = CURLE_OK;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     let mut nread: size_t = 0;
     let mut cache_skip: i32 = 0 as i32;
     let mut value_to_be_ignored: i32 = 0 as i32;
     if !ftpcode.is_null() {
         *ftpcode = 0 as i32;/* 0 for errors */
     } else {
        /* make the pointer point to something for the rest of this function */
         ftpcode = &mut value_to_be_ignored;
     }
     *nreadp = 0 as ssize_t;
     let mut current_block_20: u64;
     while *ftpcode == 0 && result as u64 == 0 {
        /* check and reset timeout value every lap */
         let mut timeout: timediff_t = Curl_pp_state_timeout(data, pp, 0 as i32 != 0);
         let mut interval_ms: timediff_t = 0;
         if timeout <= 0 as i64 {
             Curl_failf(
                 data,
                 b"FTP response timeout\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_OPERATION_TIMEDOUT;/* already too little time */
         }
         interval_ms = 1000 as timediff_t;/* use 1 second timeout intervals */
         if timeout < interval_ms {
             interval_ms = timeout;
         }
         /*
     * Since this function is blocking, we need to wait here for input on the
     * connection and only then we call the response reading function. We do
     * timeout at least every second to make the timeout check run.
     *
     * A caution here is that the ftp_readresp() function has a cache that may
     * contain pieces of a response from the previous invoke and we need to
     * make sure we don't just wait for input while there is unhandled data in
     * that cache. But also, if the cache is there, we call ftp_readresp() and
     * the cache wasn't good enough to continue we must not just busy-loop
     * around this function.
     *
     */
         if !(!((*pp).cache).is_null() && cache_skip < 2 as i32) {
            /*
       * There's a cache left since before. We then skipping the wait for
       * socket action, unless this is the same cache like the previous round
       * as then the cache was deemed not enough to act on and we then need to
       * wait for more data anyway.
       */
             if !Curl_conn_data_pending(conn, 0 as i32) {
                 match Curl_socket_check(
                     sockfd,
                     -(1 as i32),
                     -(1 as i32),
                     interval_ms,
                 ) {
                     -1 => {/* select() error, stop reading */
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
                     0 => {/* timeout */
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
                         }/* just continue in our loop for the timeout duration */

                     }
                     _ => {}/* for clarity */
                 }
             }
         }
         result = ftp_readresp(data, sockfd, pp, ftpcode, &mut nread);
         if result as u64 != 0 {
             break;
         }
         if nread == 0 && !((*pp).cache).is_null() {
             cache_skip += 1;/* bump cache skip counter as on repeated skips we must wait for more
             data */
         } else {
             cache_skip = 0 as i32;
         }
         *nreadp = (*nreadp as u64).wrapping_add(nread) as ssize_t;
     }
     (*pp).pending_resp = 0 as i32 != 0; /* when we got data or there is no cache left, we reset the cache skip
     counter */
     return result;
    }
 }
  /* for debug purposes */
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
 /* This is the ONLY way to change FTP state! */
 #[cfg(not(DEBUGBUILD))]
extern "C" fn _state(mut data: *mut Curl_easy, mut newstate: ftpstate) {
    unsafe{
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     (*ftpc).state = newstate;
    }
 }
 #[cfg(DEBUGBUILD)]
extern "C" fn _state(
     mut data: *mut Curl_easy,
     mut newstate: ftpstate,
     mut lineno: i32,
 ) {
    unsafe{
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*ftpc).state as u32 != newstate as u32 {
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
 }
 /* For the FTP "protocol connect" and "doing" phases only */
extern "C" fn ftp_state_user(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
    unsafe{
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
         _state(data, FTP_USER, 787 as i32);
        //  let ref mut fresh6 = (*data).state;
         ((*data).state).set_ftp_trying_alternative(0 as bit);
     }
     return result;
    }
 }
 /* For the FTP "DO_MORE" phase only */
extern "C" fn ftp_state_pwd(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
    unsafe{
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
         _state(data, FTP_PWD, 798 as i32);
     }
     return result;
    }
 }
 /* For the FTP "protocol connect" and "doing" phases only */
extern "C" fn ftp_getsock(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut socks: *mut curl_socket_t,
 ) -> i32 {
    unsafe{
     return Curl_pp_getsock(data, &mut (*conn).proto.ftpc.pp, socks);
    }
 }
 /* For the FTP "DO_MORE" phase only */
extern "C" fn ftp_domore_getsock(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut socks: *mut curl_socket_t,
 ) -> i32 {
    unsafe{
        /* When in DO_MORE state, we could be either waiting for us to connect to a
   * remote site, or we could wait for that site to connect to us. Or just
   * handle ordinary commands.
   */
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*conn).cnnct.state as u32 >= CONNECT_SOCKS_INIT as u32
         && ((*conn).cnnct.state as u32) < CONNECT_DONE as u32
     { /* if stopped and still in this state, then we're also waiting for a
     connect on the secondary connection */
         #[cfg(not(CURL_DISABLE_PROXY))]
         return Curl_SOCKS_getsock(conn, socks, 1 as i32);
         #[cfg(CURL_DISABLE_PROXY)]
         return 0 as i32;
     }
     if FTP_STOP as u32 == (*ftpc).state as u32 {
         let mut bits: i32 = (1 as i32) << 0 as i32;
         let mut any: bool = 0 as i32 != 0;
         /* PORT is used to tell the server to connect to us, and during that we
         don't do happy eyeballs, but we do if we connect to the server */
         *socks.offset(0 as i32 as isize) = (*conn).sock[0 as usize];
         if ((*data).set).ftp_use_port() == 0 {
             let mut s: i32 = 0;
             let mut i: i32 = 0;
             s = 1 as i32;
             i = 0 as i32;
             while i < 2 as i32 {
                 if (*conn).tempsock[i as usize] != -(1 as i32) {
                     *socks.offset(s as isize) = (*conn).tempsock[i as usize];
                     let fresh7 = s;
                     s = s + 1;
                     bits |= (1 as i32) << 16 as i32 + fresh7;
                     any = 1 as i32 != 0;
                 }
                 i += 1;
             }
         }
         if !any {
             *socks.offset(1 as isize) = (*conn).sock[1 as usize];
             bits |= (1 as i32) << 16 as i32 + 1 as i32
                 | (1 as i32) << 1 as i32;
         }
         return bits;
     }
     return Curl_pp_getsock(data, &mut (*conn).proto.ftpc.pp, socks);
    }
 }

/* This is called after the FTP_QUOTE state is passed.

   ftp_state_cwd() sends the range of CWD commands to the server to change to
   the correct directory. It may also need to send MKD commands to create
   missing ones, if that option is enabled.
*/
extern "C" fn ftp_state_cwd(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*ftpc).cwddone {
        /* already done and fine */
         result = ftp_state_mdtm(data);
     } else {
         /* FTPFILE_NOCWD with full path: expect ftpc->cwddone! */
         #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
         if (*data).set.ftp_filemethod as u32
             != FTPFILE_NOCWD as u32
             || !((*ftpc).dirdepth != 0
                 && *(*((*ftpc).dirs).offset(0 as isize))
                     .offset(0 as isize) as i32
                     == '/' as i32)
         {
         } else {
             __assert_fail(
                 b"(data->set.ftp_filemethod != FTPFILE_NOCWD) || !(ftpc->dirdepth && ftpc->dirs[0][0] == '/')\0"
                     as *const u8 as *const libc::c_char,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
                 875 as u32,
                 (*::std::mem::transmute::<
                     &[u8; 65],
                     &[libc::c_char; 65],
                 >(b"CURLcode ftp_state_cwd(struct Curl_easy *, struct connectdata *)\0"))
                     .as_ptr(),
             );
         }
         (*ftpc).count2 = 0 as i32; /* count2 counts failed CWDs */
         /* count3 is set to allow a MKD to fail once. In the case when first CWD
       fails and then MKD fails (due to another session raced it to create the
       dir) this then allows for a second try to CWD to it */
         (*ftpc).count3 = if (*data).set.ftp_create_missing_dirs == 2 as i32 {
             1 as i32
         } else {
             0 as i32
         };
         /* no need to go to entrypath when we have an absolute path */
         if ((*conn).bits).reuse() as i32 != 0
             && !((*ftpc).entrypath).is_null()
             && !((*ftpc).dirdepth != 0
                 && *(*((*ftpc).dirs).offset(0 as isize))
                     .offset(0 as isize) as i32
                     == '/' as i32)
         {
            /* This is a re-used connection. Since we change directory to where the
         transfer is taking place, we must first get back to the original dir
         where we ended up after login: */
             (*ftpc).cwdcount = 0 as i32;
              /* we count this as the first path, then we add one
                             for all upcoming ones in the ftp->dirs[] array */
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
                 _state(data, FTP_CWD, 894 as i32);
             }
         } else if (*ftpc).dirdepth != 0 {
             (*ftpc).cwdcount = 1 as i32;
             /* issue the first CWD, the rest is sent when the CWD responses are
           received... */
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"CWD %s\0" as *const u8 as *const libc::c_char,
                 *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as i32) as isize),
             );
             if result as u64 == 0 {
                 #[cfg(not(DEBUGBUILD))]
                 _state(data, FTP_CWD);
 
                 #[cfg(DEBUGBUILD)]
                 _state(data, FTP_CWD, 904 as i32);
             }
         } else {
            /* No CWD necessary */
             result = ftp_state_mdtm(data);
         }
     }
     return result;
    }
 }
extern "C" fn ftp_state_use_port(mut data: *mut Curl_easy, mut fcmd: ftpport) -> CURLcode {
    unsafe{/* start with this */
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut portsock: curl_socket_t = -(1 as i32);
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
     let mut error: i32 = 0;
     let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut string_ftpport: *mut libc::c_char =
         (*data).set.str_0[STRING_FTPPORT as usize];
     let mut h: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
     let mut port_min: u16 = 0 as u16;
     let mut port_max: u16 = 0 as u16;
     let mut port: u16 = 0;
     let mut possibly_non_local: bool = 1 as i32 != 0;
     let mut buffer: [libc::c_char; 256] = [0; 256];
     let mut addr: *mut libc::c_char = 0 as *mut libc::c_char;
     /* Step 1, figure out what is requested,
   * accepted format :
   * (ipv4|ipv6|domain|interface)?(:port(-range)?)?
   */
     if !((*data).set.str_0[STRING_FTPPORT as usize]).is_null()
         && strlen((*data).set.str_0[STRING_FTPPORT as usize])
             > 1 as u64
     {
         #[cfg(ENABLE_IPV6)]
         let mut addrlen: size_t = if 46 as u64 > strlen(string_ftpport) {
             46 as u64
         } else {
             strlen(string_ftpport)
         };
         #[cfg(not(ENABLE_IPV6))]
         let mut addrlen: size_t = if 16 as u64
             > strlen(string_ftpport)
         {
             16 as u64
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
                     addrlen.wrapping_add(1 as u64),
                     1 as size_t,
                 ) as *mut libc::c_char;
             }
             #[cfg(CURLDEBUG)]
             _ => {
                 addr = curl_dbg_calloc(
                     addrlen.wrapping_add(1 as u64),
                     1 as size_t,
                     972 as i32,
                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                 ) as *mut libc::c_char;
             }
         }
         
         if addr.is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
         /* [ipv6]:port(-range) */
         let flag: bool = if cfg!(ENABLE_IPV6) {
             *string_ftpport as i32 == '[' as i32
         } else {
             false
         };
         if flag
         {
             ip_start = string_ftpport.offset(1 as isize);
             ip_end = strchr(string_ftpport, ']' as i32);
             if !ip_end.is_null() {
                 /* either ipv6 or (ipv4|domain|interface):port(-range) */
                 strncpy(
                     addr,
                     ip_start,
                     ip_end.offset_from(ip_start) as u64,
                 );
             }
         } else if *string_ftpport as i32 == ':' as i32 {/* :port */
             ip_end = string_ftpport;
         } else {
             ip_end = strchr(string_ftpport, ':' as i32);
             if !ip_end.is_null() {
                 #[cfg(ENABLE_IPV6)]
                 if inet_pton(10 as i32, string_ftpport, sa6 as *mut libc::c_void)
                     == 1 as i32
                 {
                     port_max = 0 as u16; /* ipv6 */
                     port_min = port_max;
                     strcpy(addr, string_ftpport);
                     ip_end = 0 as *mut libc::c_char;/* this got no port ! */
                 } else {
                    /* (ipv4|domain|interface):port(-range) */
                     strncpy(
                         addr,
                         string_ftpport,
                         ip_end.offset_from(ip_start) as u64,
                     );
                 }
                 #[cfg(not(ENABLE_IPV6))]
                 strncpy(
                     addr,
                     string_ftpport,
                     ip_end.offset_from(ip_start) as u64,
                 );
             } else {
                /* ipv4|interface */
                 strcpy(addr, string_ftpport);
             }
         }
         /* parse the port */
         if !ip_end.is_null() {
             port_start = strchr(ip_end, ':' as i32);
             if !port_start.is_null() {
                 port_min = curlx_ultous(strtoul(
                     port_start.offset(1 as isize),
                     0 as *mut *mut libc::c_char,
                     10 as i32,
                 ));
                 port_sep = strchr(port_start, '-' as i32);
                 if !port_sep.is_null() {
                     port_max = curlx_ultous(strtoul(
                         port_sep.offset(1 as isize),
                         0 as *mut *mut libc::c_char,
                         10 as i32,
                     ));
                 } else {
                     port_max = port_min;
                 }
             }
         }
         /* correct errors like:
     *  :1234-1230
     *  :-4711,  in this case port_min is (unsigned)-1,
     *           therefore port_min > port_max for all cases
     *           but port_max = (unsigned)-1
     */
         if port_min as i32 > port_max as i32 {
             port_max = 0 as u16;
             port_min = port_max;
         }
         if *addr as i32 != '\0' as i32 {
            /* attempt to get the address of the given interface name */
             match Curl_if2ip(
                 (*(*conn).ip_addr).ai_family,
                 Curl_ipv6_scope((*(*conn).ip_addr).ai_addr),
                 (*conn).scope_id,
                 addr,
                 hbuf.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 1025]>() as i32,
             ) as u32
             {/* not an interface, use the given string as host name instead */
         
                 0 => {
                     host = addr;
                 }
                 1 => return CURLE_FTP_PORT_FAILED,
                 2 => {
                     host = hbuf.as_mut_ptr();/* use the hbuf for host name */
                 }
                 _ => {}
             }
         } else {/* there was only a port(-range) given, default the host */
     
             host = 0 as *mut libc::c_char;
         }/* data->set.ftpport */
     }
     if host.is_null() {
         let mut r: *const libc::c_char = 0 as *const libc::c_char;
         /* not an interface and not a host name, get default by extracting
       the IP from the control connection */
         sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as curl_socklen_t;
         if getsockname((*conn).sock[0 as usize], sa, &mut sslen) != 0 {
             Curl_failf(
                 data,
                 b"getsockname() failed: %s\0" as *const u8 as *const libc::c_char,
                 Curl_strerror(
                     *__errno_location(),
                     buffer.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                 ),
             );
             #[cfg(not(CURLDEBUG))]
             Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void);
            
             #[cfg(CURLDEBUG)]        
             curl_dbg_free(
                 addr as *mut libc::c_void,
                 1063 as i32,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_FTP_PORT_FAILED;
         }
         match (*sa).sa_family as i32 {
             #[cfg(ENABLE_IPV6)]
             10 => {
                 r = inet_ntop(
                     (*sa).sa_family as i32,
                     &mut (*sa6).sin6_addr as *mut in6_addr as *const libc::c_void,
                     hbuf.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 1025]>() as u64
                         as curl_socklen_t,
                 );
             }
             _ => {
                 r = inet_ntop(
                     (*sa).sa_family as i32,
                     &mut (*sa4).sin_addr as *mut in_addr as *const libc::c_void,
                     hbuf.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 1025]>() as u64
                         as curl_socklen_t,
                 );
             }
         }
         if r.is_null() {
             return CURLE_FTP_PORT_FAILED;
         }
         host = hbuf.as_mut_ptr();/* use this host name */
         possibly_non_local = 0 as i32 != 0;/* we know it is local now */
     }
     /* resolv ip/host to ip */
     rc = Curl_resolv(data, host, 0 as i32, 0 as i32 != 0, &mut h);
     if rc as i32 == CURLRESOLV_PENDING as i32 {
         Curl_resolver_wait_resolv(data, &mut h);
     }
     if !h.is_null() {
         res = (*h).addr;/* when we return from this function, we can forget about this entry
         to we can unlock it now already */
         Curl_resolv_unlock(data, h); /* (h) */
     } else {
         res = 0 as *mut Curl_addrinfo;/* failure! */
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
             1097 as i32,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_FTP_PORT_FAILED;
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         addr as *mut libc::c_void,
         1101 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     host = 0 as *mut libc::c_char;/* step 2, create a socket for the requested address */
     portsock = -(1 as i32);
     error = 0 as i32;
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
                 ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
             ),
         );
         return CURLE_FTP_PORT_FAILED;
     }/* step 3, bind to a suitable local address */
     memcpy(
         sa as *mut libc::c_void,
         (*ai).ai_addr as *const libc::c_void,
         (*ai).ai_addrlen as u64,
     );
     sslen = (*ai).ai_addrlen;
     port = port_min;
     while port as i32 <= port_max as i32 {
         if (*sa).sa_family as i32 == 2 as i32 {
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
         } /* Try binding the given address. */
         if !(bind(portsock, sa, sslen) != 0) {
             break;
         }
          /* It failed. */
         error = *__errno_location();
         if possibly_non_local as i32 != 0 && error == 99 as i32 {
            /* The requested bind address is not local.  Use the address used for
            * the control connection instead and restart the port loop
            */
             Curl_infof(
                 data,
                 b"bind(port=%hu) on non-local address failed: %s\0" as *const u8
                     as *const libc::c_char,
                 port as i32,
                 Curl_strerror(
                     error,
                     buffer.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                 ),
             );
             sslen =
                 ::std::mem::size_of::<Curl_sockaddr_storage>() as curl_socklen_t;
             if getsockname((*conn).sock[0 as usize], sa, &mut sslen) != 0 {
                 Curl_failf(
                     data,
                     b"getsockname() failed: %s\0" as *const u8 as *const libc::c_char,
                     Curl_strerror(
                         *__errno_location(),
                         buffer.as_mut_ptr(),
                         ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                     ),
                 );
                 Curl_closesocket(data, conn, portsock);
                 return CURLE_FTP_PORT_FAILED;
             }
             port = port_min;
             possibly_non_local = 0 as i32 != 0;/* don't try this again */
         } else {
             if error != 98 as i32 && error != 13 as i32 {
                 Curl_failf(
                     data,
                     b"bind(port=%hu) failed: %s\0" as *const u8 as *const libc::c_char,
                     port as i32,
                     Curl_strerror(
                         error,
                         buffer.as_mut_ptr(),
                         ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                     ),
                 );
                 Curl_closesocket(data, conn, portsock);
                 return CURLE_FTP_PORT_FAILED;
             }
             port = port.wrapping_add(1);
         }
     }
     /* maybe all ports were in use already*/
     if port as i32 > port_max as i32 {
         Curl_failf(
             data,
             b"bind() failed, we ran out of ports!\0" as *const u8 as *const libc::c_char,
         );
         Curl_closesocket(data, conn, portsock);
         return CURLE_FTP_PORT_FAILED;
     }
     /* get the name again after the bind() so that we can extract the
     port number it uses now */
     sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as curl_socklen_t;
     if getsockname(portsock, sa, &mut sslen) != 0 {
         Curl_failf(
             data,
             b"getsockname() failed: %s\0" as *const u8 as *const libc::c_char,
             Curl_strerror(
                 *__errno_location(),
                 buffer.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
             ),
         );
         Curl_closesocket(data, conn, portsock);
         return CURLE_FTP_PORT_FAILED;
     }
      /* step 4, listen on the socket */
     if listen(portsock, 1 as i32) != 0 {
         Curl_failf(
             data,
             b"socket failure: %s\0" as *const u8 as *const libc::c_char,
             Curl_strerror(
                 *__errno_location(),
                 buffer.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
             ),
         );
         Curl_closesocket(data, conn, portsock);
         return CURLE_FTP_PORT_FAILED;
     }
     /* step 5, send the proper FTP command */
     /* get a plain printable version of the numerical address to work with
     below */
     Curl_printable_address(
         ai,
         myhost.as_mut_ptr(),
         ::std::mem::size_of::<[libc::c_char; 47]>() as u64,
     );
     #[cfg(ENABLE_IPV6)]
     if ((*conn).bits).ftp_use_eprt() == 0 && ((*conn).bits).ipv6() as i32 != 0 {
        /* EPRT is disabled but we are connected to a IPv6 host, so we ignore the
       request and enable EPRT again! */
         ((*conn).bits).set_ftp_use_eprt(1 as bit);
     }
     while fcmd as u32 != DONE as u32 {
         if !(((*conn).bits).ftp_use_eprt() == 0
             && EPRT as u32 == fcmd as u32)
         {/* if disabled, goto next */
             if !(PORT as u32 == fcmd as u32
                 && (*sa).sa_family as i32 != 2 as i32)
             { /* PORT is IPv4 only */
                 match (*sa).sa_family as i32 {
                     2 => {
                         port = __bswap_16((*sa4).sin_port);
                         if EPRT as u32 == fcmd as u32 {
                            /*
       * Two fine examples from RFC2428;
       *
       * EPRT |1|132.235.1.2|6275|
       *
       * EPRT |2|1080::8:800:200C:417A|5282|
       */

                             result = Curl_pp_sendf(
                                 data,
                                 &mut (*ftpc).pp as *mut pingpong,
                                 b"%s |%d|%s|%hu|\0" as *const u8 as *const libc::c_char,
                                 (mode[fcmd as usize]).as_ptr(),
                                 if (*sa).sa_family as i32 == 2 as i32 {
                                     1 as i32
                                 } else {
                                     2 as i32
                                 },
                                 myhost.as_mut_ptr(),
                                 port as i32,
                             );
                             if result as u64 != 0 {
                                 Curl_failf(
                                     data,
                                     b"Failure sending EPRT command: %s\0" as *const u8
                                         as *const libc::c_char,
                                     curl_easy_strerror(result),
                                 );
                                  /* don't retry using PORT */
                                 Curl_closesocket(data, conn, portsock);
                                  /* bail out */
                                 (*ftpc).count1 = PORT as i32;
                                 #[cfg(not(DEBUGBUILD))]
                                 _state(data, FTP_STOP);
 
                                 #[cfg(DEBUGBUILD)]
                                 _state(data, FTP_STOP, 1250 as i32);
                                 return result;
                             }
                             break;
                         } else if PORT as u32 == fcmd as u32 {
                             /* large enough for [IP address],[num],[num] */
                             let mut target: [libc::c_char; 67] = [0; 67];
                             let mut source: *mut libc::c_char = myhost.as_mut_ptr();
                             let mut dest: *mut libc::c_char = target.as_mut_ptr();
                             /* translate x.x.x.x to x,x,x,x */
                             while !source.is_null() && *source as i32 != 0 {
                                 if *source as i32 == '.' as i32 {
                                     *dest = ',' as i32 as libc::c_char;
                                 } else {
                                     *dest = *source;
                                 }
                                 dest = dest.offset(1);
                                 source = source.offset(1);
                             }
                             *dest = 0 as libc::c_char;
                             curl_msnprintf(
                                 dest,
                                 20 as size_t,
                                 b",%d,%d\0" as *const u8 as *const libc::c_char,
                                 port as i32 >> 8 as i32,
                                 port as i32 & 0xff as i32,
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
                                  /* bail out */
                                 #[cfg(not(DEBUGBUILD))]
                                 _state(data, FTP_STOP);
                                 #[cfg(DEBUGBUILD)]
                                 _state(data, FTP_STOP, 1279 as i32);
                                 return result;
                             }
                             break;
                         }
                     }
                     #[cfg(ENABLE_IPV6)]
                     10 => {
                         port = __bswap_16((*sa6).sin6_port);
                         if EPRT as u32 == fcmd as u32 {
                             result = Curl_pp_sendf(
                                 data,
                                 &mut (*ftpc).pp as *mut pingpong,
                                 b"%s |%d|%s|%hu|\0" as *const u8 as *const libc::c_char,
                                 (mode[fcmd as usize]).as_ptr(),
                                 if (*sa).sa_family as i32 == 2 as i32 {
                                     1 as i32
                                 } else {
                                     2 as i32
                                 },
                                 myhost.as_mut_ptr(),
                                 port as i32,
                             );
                             if result as u64 != 0 {
                                 Curl_failf(
                                     data,
                                     b"Failure sending EPRT command: %s\0" as *const u8
                                         as *const libc::c_char,
                                     curl_easy_strerror(result),
                                 );
                                 Curl_closesocket(data, conn, portsock);
                                 (*ftpc).count1 = PORT as i32;
                                 #[cfg(not(DEBUGBUILD))]
                                 _state(data, FTP_STOP);
 
                                 #[cfg(DEBUGBUILD)]
                                 _state(data, FTP_STOP, 1250 as i32);
                                 return result;
                             }
                             break;
                         } else if PORT as u32 == fcmd as u32 {
                             let mut target: [libc::c_char; 67] = [0; 67];
                             let mut source: *mut libc::c_char = myhost.as_mut_ptr();
                             let mut dest: *mut libc::c_char = target.as_mut_ptr();
                             while !source.is_null() && *source as i32 != 0 {
                                 if *source as i32 == '.' as i32 {
                                     *dest = ',' as i32 as libc::c_char;
                                 } else {
                                     *dest = *source;
                                 }
                                 dest = dest.offset(1);
                                 source = source.offset(1);
                             }
                             *dest = 0 as i32 as libc::c_char;
                             curl_msnprintf(
                                 dest,
                                 20 as size_t,
                                 b",%d,%d\0" as *const u8 as *const libc::c_char,
                                 port as i32 >> 8 as i32,
                                 port as i32 & 0xff as i32,
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
                                 _state(data, FTP_STOP, 1279 as i32);
                                 return result;
                             }
                             break;
                         }
                     }
                     _ => {}/* might as well skip this */
                 }
             }
         }
         fcmd += 1;
     }
     /* store which command was sent */
     (*ftpc).count1 = fcmd as i32;
     close_secondarysocket(data, conn);
     /* we set the secondary socket variable to this for now, it is only so that
     the cleanup function will close it in case we fail before the true
     secondary stuff is made */
     (*conn).sock[1 as usize] = portsock;
      /* this tcpconnect assignment below is a hackish work-around to make the
     multi interface with active FTP work - as it will not wait for a
     (passive) connect in Curl_is_connected().
     The *proper* fix is to make sure that the active connection from the
     server is done in a non-blocking way. Currently, it is still BLOCKING.
  */
     (*conn).bits.tcpconnect[1 as usize] = 1 as i32 != 0;
     #[cfg(not(DEBUGBUILD))]
     _state(data, FTP_PORT);
 
     #[cfg(DEBUGBUILD)]
     _state(data, FTP_PORT, 1305 as i32);
     return result;
    }
 }
extern "C" fn ftp_state_use_pasv(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
    unsafe{
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut result: CURLcode = CURLE_OK;
     /*
    Here's the executive summary on what to do:

    PASV is RFC959, expect:
    227 Entering Passive Mode (a1,a2,a3,a4,p1,p2)

    LPSV is RFC1639, expect:
    228 Entering Long Passive Mode (4,4,a1,a2,a3,a4,2,p1,p2)

    EPSV is RFC2428, expect:
    229 Entering Extended Passive Mode (|||port|)

  */
     static mut mode: [[libc::c_char; 5]; 2] = unsafe {
         [
             *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"EPSV\0"),
             *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"PASV\0"),
         ]
     };
     let mut modeoff: i32 = 0;
     #[cfg(PF_INET6)]
     if ((*conn).bits).ftp_use_epsv() == 0 && ((*conn).bits).ipv6() as i32 != 0 {
        /* EPSV is disabled but we are connected to a IPv6 host, so we ignore the
       request and enable EPSV again! */
         ((*conn).bits).set_ftp_use_epsv(1 as bit);
     }
     modeoff = if ((*conn).bits).ftp_use_epsv() as i32 != 0 {
         0 as i32
     } else {
         1 as i32
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
         _state(data, FTP_PASV, 1343 as i32);
         Curl_infof(
             data,
             b"Connect data stream passively\0" as *const u8 as *const libc::c_char,
         );
     }
     return result;
    }
 }
 /*
 * ftp_state_prepare_transfer() starts PORT, PASV or PRET etc.
 *
 * REST is the last command in the chain of commands when a "head"-like
 * request is made. Thus, if an actual transfer is to be made this is where we
 * take off for real.
 */
extern "C" fn ftp_state_prepare_transfer(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     if (*ftp).transfer as u32 != PPTRANSFER_BODY as u32 {
        /* doesn't transfer any data */

    /* still possibly do PRE QUOTE jobs */
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_RETR_PREQUOTE);
 
         #[cfg(DEBUGBUILD)]
         _state(data, FTP_RETR_PREQUOTE, 1366 as i32);
         result = ftp_state_quote(data, 1 as i32 != 0, FTP_RETR_PREQUOTE);
     } else if ((*data).set).ftp_use_port() != 0 {
         /* We have chosen to use the PORT (or similar) command */
         result = ftp_state_use_port(data, EPRT);
     } else if ((*data).set).ftp_use_pret() != 0 {
         /* The user has requested that we send a PRET command
         to prepare the server for the upcoming PASV */
         let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
         if ((*conn).proto.ftpc.file).is_null() {
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"PRET %s\0" as *const u8 as *const libc::c_char,
                 if !((*data).set.str_0[STRING_CUSTOMREQUEST as usize]).is_null() {
                     (*data).set.str_0[STRING_CUSTOMREQUEST as usize]
                         as *const libc::c_char
                 } else if ((*data).state).list_only() as i32 != 0 {
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
             _state(data, FTP_PRET, 1391 as i32);
         }
     } else {
         result = ftp_state_use_pasv(data, conn);
     }
     return result;
    }
 }
extern "C" fn ftp_state_rest(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*ftp).transfer as u32 != PPTRANSFER_BODY as u32
         && !((*ftpc).file).is_null()
     {/* if a "head"-like request is being made (on a file) */

    /* Determine if server can respond to REST command and therefore
       whether it supports range */
         result = Curl_pp_sendf(
             data,
             &mut (*ftpc).pp as *mut pingpong,
             b"REST %d\0" as *const u8 as *const libc::c_char,
             0 as i32,
         );
         if result as u64 == 0 {
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_REST);
 
             #[cfg(DEBUGBUILD)]
             _state(data, FTP_REST, 1413 as i32);
         }
     } else {
         result = ftp_state_prepare_transfer(data);
     }
     return result;
    }
 }
extern "C" fn ftp_state_size(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if (*ftp).transfer as u32 == PPTRANSFER_INFO as u32
         && !((*ftpc).file).is_null()
     {/* if a "head"-like request is being made (on a file) */

    /* we know ftpc->file is a valid pointer to a file name */
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
             _state(data, FTP_SIZE, 1434 as i32);
         }
     } else {
         result = ftp_state_rest(data, conn);
     }
     return result;
    }
 }
extern "C" fn ftp_state_list(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     /* If this output is to be machine-parsed, the NLST command might be better
     to use, since the LIST command output is not specified or standard in any
     way. It has turned out that the NLST list output is not the same on all
     servers either... */

  /*
     if FTPFILE_NOCWD was specified, we should add the path
     as argument for the LIST / NLST / or custom command.
     Whether the server will support this, is uncertain.

     The other ftp_filemethods will CWD into dir/dir/ first and
     then just do LIST (in that case: nothing to do here)
  */
     let mut lstArg: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut cmd: *mut libc::c_char = 0 as *mut libc::c_char;
     if (*data).set.ftp_filemethod as u32 == FTPFILE_NOCWD as u32
         && !((*ftp).path).is_null()
     {
         let mut slashPos: *const libc::c_char = 0 as *const libc::c_char;
         let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;
         result = Curl_urldecode(
             data,
             (*ftp).path,
             0 as i32 as size_t,
             &mut rawPath,
             0 as *mut size_t,
             REJECT_CTRL,
         );
         if result as u64 != 0 {
             return result;
         }
         slashPos = strrchr(rawPath, '/' as i32);
         if !slashPos.is_null() {
             /* chop off the file part if format is dir/file otherwise remove
         the trailing slash for dir/dir/ except for absolute path / */
             let mut n: size_t = slashPos.offset_from(rawPath) as size_t;
             if n == 0 as u64 {
                 n = n.wrapping_add(1);
             }
             lstArg = rawPath;
             *lstArg.offset(n as isize) = '\0' as libc::c_char;
         } else {
             #[cfg(not(CURLDEBUG))]
             Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);
 
             #[cfg(CURLDEBUG)]
             curl_dbg_free(
                 rawPath as *mut libc::c_void,
                 1484 as i32,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
         }
     }
     cmd = curl_maprintf(
         b"%s%s%s\0" as *const u8 as *const libc::c_char,
         if !((*data).set.str_0[STRING_CUSTOMREQUEST as usize]).is_null() {
             (*data).set.str_0[STRING_CUSTOMREQUEST as usize] as *const libc::c_char
         } else if ((*data).state).list_only() as i32 != 0 {
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
         1493 as i32,
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
         1499 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     if result as u64 == 0 {
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_LIST);
 
         #[cfg(DEBUGBUILD)]
         _state(data, FTP_LIST, 1502 as i32);
     }
     return result;
    }
 }
extern "C" fn ftp_state_retr_prequote(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{ /* We've sent the TYPE, now we must send the list of prequote strings */
     return ftp_state_quote(data, 1 as i32 != 0, FTP_RETR_PREQUOTE);
    }
 }
 extern "C" fn ftp_state_stor_prequote(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{/* We've sent the TYPE, now we must send the list of prequote strings */
     return ftp_state_quote(data, 1 as i32 != 0, FTP_STOR_PREQUOTE);
    }
 }
extern "C" fn ftp_state_type(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     /* If we have selected NOBODY and HEADER, it means that we only want file
     information. Which in FTP can't be much more than the file size and
     date. */
     if ((*data).set).opt_no_body() as i32 != 0
         && !((*ftpc).file).is_null()
         && ftp_need_type(conn, ((*data).state).prefer_ascii() != 0) != 0
     {/* The SIZE command is _not_ RFC 959 specified, and therefore many servers
       may not support it! It is however the only way we have to get a file's
       size! */
         (*ftp).transfer = PPTRANSFER_INFO;
          /* this means no actual transfer will be made */

    /* Some servers return different sizes for different modes, and thus we
       must set the proper type before we check the size */
         result = ftp_nb_type(data, conn, ((*data).state).prefer_ascii() != 0, FTP_TYPE);
         if result as u64 != 0 {
             return result;
         }
     } else {
         result = ftp_state_size(data, conn);
     }
     return result;
    }
 }
 /* This is called after the CWD commands have been done in the beginning of
   the DO phase */
extern "C" fn ftp_state_mdtm(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     /* Requested time of file or time-depended transfer? */
     if (((*data).set).get_filetime() as i32 != 0
         || (*data).set.timecondition as u32 != 0)
         && !((*ftpc).file).is_null()
     {/* we have requested to get the modified-time of the file, this is a white
       spot as the MDTM is not mentioned in RFC959 */
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
             _state(data, FTP_MDTM, 1566 as i32);
         }
     } else {
         result = ftp_state_type(data);
     }
     return result;
    }
 }
 /* This is called after the TYPE and possible quote commands have been sent */
extern "C" fn ftp_state_ul_setup(
     mut data: *mut Curl_easy,
     mut sizechecked: bool,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut append: bool = ((*data).set).remote_append() != 0;
     if (*data).state.resume_from != 0 && !sizechecked
         || (*data).state.resume_from > 0 as i64
             && sizechecked as i32 != 0
     {/* we're about to continue the uploading of a file */
    /* 1. get already existing file's size. We use the SIZE command for this
       which may not exist in the server!  The SIZE command is not in
       RFC959. */

    /* 2. This used to set REST. But since we can do append, we
       don't another ftp command. We just skip the source file
       offset and then we APPEND the rest on the file instead */

    /* 3. pass file-size number of bytes in the source file */
    /* 4. lower the infilesize counter */
    /* => transfer as usual */
         let mut seekerr: i32 = 0 as i32;
         if (*data).state.resume_from < 0 as i64 {
            /* Got no given size to start from, figure it out */
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
                 _state(data, FTP_STOR_SIZE, 1605 as i32);
             }
             return result;
         }
         /* enable append */
         append = 1 as i32 != 0;
         /* Let's read off the proper amount of bytes from the input. */
         if ((*conn).seek_func).is_some() {
             Curl_set_in_callback(data, 1 as i32 != 0);
             seekerr = ((*conn).seek_func).expect("non-null function pointer")(
                 (*conn).seek_client,
                 (*data).state.resume_from,
                 0 as i32,
             );
             Curl_set_in_callback(data, 0 as i32 != 0);
         }
         if seekerr != 0 as i32 {
             let mut passed: curl_off_t = 0 as curl_off_t;
             if seekerr != 2 as i32 {
                 Curl_failf(
                     data,
                     b"Could not seek stream\0" as *const u8 as *const libc::c_char,
                 );
                 return CURLE_FTP_COULDNT_USE_REST;
             }
             /* seekerr == CURL_SEEKFUNC_CANTSEEK (can't seek to offset) */
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
                     1 as size_t,
                     readthisamountnow,
                     (*data).state.in_0,
                 );
                 passed = (passed as u64).wrapping_add(actuallyread) as curl_off_t
                     as curl_off_t;
                 if actuallyread == 0 as u64
                     || actuallyread > readthisamountnow
                 {
                    /* this checks for greater-than only to make sure that the
             CURL_READFUNC_ABORT return code still aborts */
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
         /* now, decrease the size of the read */
         if (*data).state.infilesize > 0 as i64 {

             (*data).state.infilesize -= (*data).state.resume_from;
             if (*data).state.infilesize <= 0 as i64 {
                 Curl_infof(
                     data,
                     b"File already completely uploaded\0" as *const u8 as *const libc::c_char,
                 );
                  /* no data to transfer */
                 Curl_setup_transfer(
                     data,
                     -(1 as i32),
                     -(1 as i32) as curl_off_t,
                     0 as i32 != 0,
                     -(1 as i32),
                 );
                 /* Set ->transfer so that we won't get any error in
         * ftp_done() because we didn't transfer anything! */
                 (*ftp).transfer = PPTRANSFER_NONE;
                 #[cfg(not(DEBUGBUILD))]
                 _state(data, FTP_STOP);
 
                 #[cfg(DEBUGBUILD)]
                 _state(data, FTP_STOP, 1660 as i32);
                 return CURLE_OK;
             } /* we've passed, proceed as normal */
         }
     }/* resume_from */

     result = Curl_pp_sendf(
         data,
         &mut (*ftpc).pp as *mut pingpong,
         if append as i32 != 0 {
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
         _state(data, FTP_STOR, 1670 as i32);
     }
     return result;
    }
 }
extern "C" fn ftp_state_quote(
     mut data: *mut Curl_easy,
     mut init: bool,
     mut instate: ftpstate,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut quote: bool = 0 as i32 != 0;
     let mut item: *mut curl_slist = 0 as *mut curl_slist;
     match instate as u32 {
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
     /*
   * This state uses:
   * 'count1' to iterate over the commands to send
   * 'count2' to store whether to allow commands to fail
   */
     if init {
         (*ftpc).count1 = 0 as i32;
     } else {
        //  let ref mut fresh11 = (*ftpc).count1;
         (*ftpc).count1 += 1;
     }
     if !item.is_null() {
         let mut i: i32 = 0 as i32;
          /* Skip count1 items in the linked list */
         while i < (*ftpc).count1 && !item.is_null() {
             item = (*item).next;
             i += 1;
         }
         if !item.is_null() {
             let mut cmd: *mut libc::c_char = (*item).data;
             if *cmd.offset(0 as isize) as i32 == '*' as i32 {
                 cmd = cmd.offset(1);
                 (*ftpc).count2 = 1 as i32; /* the sent command is allowed to fail */
             } else {
                 (*ftpc).count2 = 0 as i32; /* failure means cancel operation */
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
             _state(data, instate, 1731 as i32);
             quote = 1 as i32 != 0;
         }
     }
     if !quote { /* No more quote to send, continue to ... */
         match instate as u32 {
             13 => {
                 if (*ftp).transfer as u32 != PPTRANSFER_BODY as u32
                 {
                     #[cfg(not(DEBUGBUILD))]
                     _state(data, FTP_STOP);
 
     #[cfg(DEBUGBUILD)]
                     _state(data, FTP_STOP, 1745 as i32);
                 } else if (*ftpc).known_filesize != -(1 as i32) as i64 {
                     Curl_pgrsSetDownloadSize(data, (*ftpc).known_filesize);
                     result = ftp_state_retr(data, (*ftpc).known_filesize);
                 } else if ((*data).set).ignorecl() as i32 != 0
                     || ((*data).state).prefer_ascii() as i32 != 0
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
                         _state(data, FTP_RETR, 1767 as i32);
                     }
                 } else {
                    /* 'ignorecl' is used to support download of growing files.  It
               prevents the state machine from requesting the file size from
               the server.  With an unknown file size the download continues
               until the server terminates it, otherwise the client stops if
               the received byte count exceeds the reported file size.  Set
               option CURLOPT_IGNORE_CONTENT_LENGTH to 1 to enable this
               behavior.

               In addition: asking for the size for 'TYPE A' transfers is not
               constructive since servers don't report the converted size. So
               skip it.
            */
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
                         _state(data, FTP_RETR_SIZE, 1772 as i32);
                     }
                 }
             }
             14 => {
                 result = ftp_state_ul_setup(data, 0 as i32 != 0);
             }
             15 => {}
             12 | _ => {
                 result = ftp_state_cwd(data, conn);
             }
         }
     }
     return result;
    }
 }
 /* called from ftp_state_pasv_resp to switch to PASV in case of EPSV
   problems */
extern "C" fn ftp_epsv_disable(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     // TODO 待验证
     #[cfg(not(CURL_DISABLE_PROXY))]
     let flag: bool = ((*conn).bits).ipv6() as i32 != 0
             && !(((*conn).bits).tunnel_proxy() as i32 != 0
                 || ((*conn).bits).socksproxy() as i32 != 0);
     #[cfg(CURL_DISABLE_PROXY)]
     let flag: bool = ((*conn).bits).ipv6() as i32 != 0;
     if flag
     {/* We can't disable EPSV when doing IPv6, so this is instead a fail */
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
     /* disable it for next transfer */
    //  let ref mut fresh12 = (*conn).bits;
     ((*conn).bits).set_ftp_use_epsv(0 as bit);
    //  let ref mut fresh13 = (*data).state;
     ((*data).state).set_errorbuf(0 as bit);
     /* allow error message to get
                                         rewritten */
     result = Curl_pp_sendf(
         data,
         &mut (*conn).proto.ftpc.pp as *mut pingpong,
         b"%s\0" as *const u8 as *const libc::c_char,
         b"PASV\0" as *const u8 as *const libc::c_char,
     );
     if result as u64 == 0 {
        //  let ref mut fresh14 = (*conn).proto.ftpc.count1;
         (*conn).proto.ftpc.count1 += 1;/* remain in/go to the FTP_PASV state */
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_PASV);
 
     #[cfg(DEBUGBUILD)]
         _state(data, FTP_PASV, 1814 as i32);
     }
     return result;
    }
 }
extern "C" fn control_address(mut conn: *mut connectdata) -> *mut libc::c_char {
    unsafe{ /* Returns the control connection IP address.
        If a proxy tunnel is used, returns the original host name instead, because
        the effective control connection address is the proxy address,
        not the ftp host. */
     #[cfg(not(CURL_DISABLE_PROXY))]
     if ((*conn).bits).tunnel_proxy() as i32 != 0
         || ((*conn).bits).socksproxy() as i32 != 0
     {
         return (*conn).host.name;
     }
     return ((*conn).primary_ip).as_mut_ptr();
    }
 }
extern "C" fn ftp_state_pasv_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: i32,
 ) -> CURLcode {
    unsafe{
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut result: CURLcode = CURLE_OK;
     let mut addr: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
     let mut rc: resolve_t = CURLRESOLV_RESOLVED;
     let mut connectport: u16 = 0;/* the local port connect() should use! */
     let mut str: *mut libc::c_char =
         &mut *((*data).state.buffer).offset(4 as isize) as *mut libc::c_char; /* start on the first letter */
         #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
 /* if we come here again, make sure the former name is cleared */
         #[cfg(CURLDEBUG)]
         curl_dbg_free(
         (*ftpc).newhost as *mut libc::c_void,
         1845 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
    //  let ref mut fresh15 = (*ftpc).newhost;
     (*ftpc).newhost = 0 as *mut libc::c_char;
     if (*ftpc).count1 == 0 as i32 && ftpcode == 229 as i32 {
         /* positive EPSV response */
         let mut ptr: *mut libc::c_char = strchr(str, '(' as i32);
         if !ptr.is_null() {
             let mut num: u32 = 0;
             let mut separator: [libc::c_char; 4] = [0; 4];
             ptr = ptr.offset(1);
             if 5 as i32
                 == sscanf(
                     ptr,
                     b"%c%c%c%u%c\0" as *const u8 as *const libc::c_char,
                     &mut *separator.as_mut_ptr().offset(0 as isize)
                         as *mut libc::c_char,
                     &mut *separator.as_mut_ptr().offset(1 as isize)
                         as *mut libc::c_char,
                     &mut *separator.as_mut_ptr().offset(2 as isize)
                         as *mut libc::c_char,
                     &mut num as *mut u32,
                     &mut *separator.as_mut_ptr().offset(3 as isize)
                         as *mut libc::c_char,
                 )
             {
                 let sep1: libc::c_char = separator[0 as usize];
                 let mut i: i32 = 0;
                 i = 1 as i32;
                 /* The four separators should be identical, or else this is an oddly
           formatted reply and we bail out immediately. */
                 while i < 4 as i32 {
                     if separator[i as usize] as i32 != sep1 as i32 {
                         ptr = 0 as *mut libc::c_char; /* set to NULL to signal error */
                         break;
                     } else {
                         i += 1;
                     }
                 }
                 if num > 0xffff as u32 {
                     Curl_failf(
                         data,
                         b"Illegal port number in EPSV reply\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_FTP_WEIRD_PASV_REPLY;
                 }
                 if !ptr.is_null() {
                     (*ftpc).newport =
                         (num & 0xffff as u32) as u16;
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
                                 1878 as i32,
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
     } else if (*ftpc).count1 == 1 as i32 && ftpcode == 227 as i32 {
         let mut ip: [u32; 4] = [
             0 as u32,
             0 as u32,
             0 as u32,
             0 as u32,
         ];
         let mut port: [u32; 2] = [
             0 as u32,
             0 as u32,
         ];
          /*
     * Scan for a sequence of six comma-separated numbers and use them as
     * IP+port indicators.
     *
     * Found reply-strings include:
     * "227 Entering Passive Mode (127,0,0,1,4,51)"
     * "227 Data transfer will passively listen to 127,0,0,1,4,51"
     * "227 Entering passive mode. 127,0,0,1,4,51"
     */
         while *str != 0 {
             if 6 as i32
                 == sscanf(
                     str,
                     b"%u,%u,%u,%u,%u,%u\0" as *const u8 as *const libc::c_char,
                     &mut *ip.as_mut_ptr().offset(0 as isize) as *mut u32,
                     &mut *ip.as_mut_ptr().offset(1 as isize) as *mut u32,
                     &mut *ip.as_mut_ptr().offset(2 as isize) as *mut u32,
                     &mut *ip.as_mut_ptr().offset(3 as isize) as *mut u32,
                     &mut *port.as_mut_ptr().offset(0 as isize) as *mut u32,
                     &mut *port.as_mut_ptr().offset(1 as isize) as *mut u32,
                 )
             {
                 break;
             }
             str = str.offset(1);
         }
         if *str == 0
             || ip[0 as usize] > 255 as u32
             || ip[1 as usize] > 255 as u32
             || ip[2 as usize] > 255 as u32
             || ip[3 as usize] > 255 as u32
             || port[0 as usize] > 255 as u32
             || port[1 as usize] > 255 as u32
         {
             Curl_failf(
                 data,
                 b"Couldn't interpret the 227-response\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_FTP_WEIRD_227_FORMAT;
         }
         /* we got OK from server */
         if ((*data).set).ftp_skip_ip() != 0 {
             /* told to ignore the remotely given IP but instead use the host we used
         for the control connection */
             Curl_infof(
                 data,
                 b"Skip %u.%u.%u.%u for data connection, re-use %s instead\0" as *const u8
                     as *const libc::c_char,
                 ip[0 as usize],
                 ip[1 as usize],
                 ip[2 as usize],
                 ip[3 as usize],
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
                         1927 as i32,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                 }
             }
             
             
         } else {
            //  let ref mut fresh18 = (*ftpc).newhost;
             (*ftpc).newhost = curl_maprintf(
                 b"%u.%u.%u.%u\0" as *const u8 as *const libc::c_char,
                 ip[0 as usize],
                 ip[1 as usize],
                 ip[2 as usize],
                 ip[3 as usize],
             );
         }
         if ((*ftpc).newhost).is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
         (*ftpc).newport = ((port[0 as usize] << 8 as i32)
             .wrapping_add(port[1 as usize])
             & 0xffff as u32) as u16;
     } else if (*ftpc).count1 == 0 as i32 {
        /* EPSV failed, move on to PASV */
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
                 /*
     * This connection uses a proxy and we need to connect to the proxy again
     * here. We don't want to rely on a former host lookup that might've
     * expired now, instead we remake the lookup here and now!
     */
                 let host_name: *const libc::c_char = if ((*conn).bits).socksproxy() as i32 != 0 {
                     (*conn).socks_proxy.host.name
                 } else {
                     (*conn).http_proxy.host.name
                 };
                 rc = Curl_resolv(
                     data,
                     host_name,
                     (*conn).port,
                     0 as i32 != 0,
                     &mut addr,
                 );
                  /* BLOCKING, ignores the return code but 'addr' will be NULL in
         case of failure */
                 if rc as i32 == CURLRESOLV_PENDING as i32 {
                     Curl_resolver_wait_resolv(data, &mut addr);
                 }
                 connectport = (*conn).port as u16;
                 /* we connect to the proxy's port */
                 if addr.is_null() {
                     Curl_failf(
                         data,
                         b"Can't resolve proxy host %s:%hu\0" as *const u8 as *const libc::c_char,
                         host_name,
                         connectport as i32,
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
                         1973 as i32 as u32,
                         (*::std::mem::transmute::<&[u8; 54], &[libc::c_char; 54]>(
                             b"CURLcode ftp_state_pasv_resp(struct Curl_easy *, int)\0",
                         ))
                         .as_ptr(),
                     );
                 }
                 /* postponed address resolution in case of tcp fastopen */
                 if ((*conn).bits).tcp_fastopen() as i32 != 0
                     && ((*conn).bits).reuse() == 0
                     && *((*ftpc).newhost).offset(0 as isize) == 0
                 {
                     Curl_conninfo_remote(data, conn, (*conn).sock[0 as usize]);
                     #[cfg(not(CURLDEBUG))]
                     Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
                     
                     #[cfg(CURLDEBUG)]
                     curl_dbg_free(
                         (*ftpc).newhost as *mut libc::c_void,
                         1978 as i32,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                    //  let ref mut fresh19 = (*ftpc).newhost;
                     (*ftpc).newhost = 0 as *mut libc::c_char;
                     match () {
                         #[cfg(not(CURLDEBUG))]
                         _ => {
                             (*ftpc).newhost = Curl_cstrdup.expect("non-null function pointer")(control_address(conn));
                         }
                         #[cfg(CURLDEBUG)]
                         _ => {
                             (*ftpc).newhost = curl_dbg_strdup(
                                 control_address(conn),
                                 1979 as i32,
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
                     (*ftpc).newport as i32,
                     0 as i32 != 0,
                     &mut addr,
                 );
                 /* BLOCKING */
                 if rc as i32 == CURLRESOLV_PENDING as i32 {
                     Curl_resolver_wait_resolv(data, &mut addr);
                 }
                 connectport = (*ftpc).newport;/* we connect to the remote port */
                 if addr.is_null() {
                     Curl_failf(
                         data,
                         b"Can't resolve new host %s:%hu\0" as *const u8 as *const libc::c_char,
                         (*ftpc).newhost,
                         connectport as i32,
                     );
                     return CURLE_FTP_CANT_GET_HOST;
                 }
             }
         }
         #[cfg(CURL_DISABLE_PROXY)]
         _ => {
             if ((*conn).bits).tcp_fastopen() as i32 != 0
                 && ((*conn).bits).reuse() == 0
                 && *((*ftpc).newhost).offset(0 as isize) == 0
             {
                 Curl_conninfo_remote(data, conn, (*conn).sock[0 as usize]);
                 #[cfg(not(CURLDEBUG))]
                 Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
 
                 #[cfg(CURLDEBUG)]
                 Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
                //  let ref mut fresh19 = (*ftpc).newhost;
                 (*ftpc).newhost = 0 as *mut libc::c_char;
                //  let ref mut fresh20 = (*ftpc).newhost;
                 match () {
                     #[cfg(not(CURLDEBUG))]
                     _ => {
                         (*ftpc).newhost = Curl_cstrdup.expect("non-null function pointer")(control_address(conn));
                     }
                     #[cfg(CURLDEBUG)]
                     _ => {
                         (*ftpc).newhost = curl_dbg_strdup(
                             control_address(conn),
                             1979 as i32,
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
                 (*ftpc).newport as i32,
                 0 as i32 != 0,
                 &mut addr,
             );
             if rc as i32 == CURLRESOLV_PENDING as i32 {
                 Curl_resolver_wait_resolv(data, &mut addr);
             }
             connectport = (*ftpc).newport;
             if addr.is_null() {
                 Curl_failf(
                     data,
                     b"Can't resolve new host %s:%hu\0" as *const u8 as *const libc::c_char,
                     (*ftpc).newhost,
                     connectport as i32,
                 );
                 return CURLE_FTP_CANT_GET_HOST;
             }
         }
     }
     (*conn).bits.tcpconnect[1 as usize] = 0 as i32 != 0;
     result = Curl_connecthost(data, conn, addr);
     if result as u64 != 0 {
         Curl_resolv_unlock(data, addr); /* we're done using this address */
         if (*ftpc).count1 == 0 as i32 && ftpcode == 229 as i32 {
             return ftp_epsv_disable(data, conn);
         }
         return result;
     }

  /*
   * When this is used from the multi interface, this might've returned with
   * the 'connected' set to FALSE and thus we are now awaiting a non-blocking
   * connect to connect.
   */

     if ((*data).set).verbose() != 0 {/* this just dumps information about this second connection */
         #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
         ftp_pasv_verbose(
             data,
             (*addr).addr,
             (*ftpc).newhost,
             connectport as i32,
         );
     }
     Curl_resolv_unlock(data, addr);/* we're done using this address */
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*conn).secondaryhostname as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*conn).secondaryhostname as *mut libc::c_void,
         2021 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
    //  let ref mut fresh21 = (*conn).secondaryhostname;
     (*conn).secondaryhostname = 0 as *mut libc::c_char;
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
                 2023 as i32,
                 b"ftp.c\0" as *const u8 as *const libc::c_char,
             );
         }
     }
     
     if ((*conn).secondaryhostname).is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
    //  let ref mut fresh23 = (*conn).bits;
     ((*conn).bits).set_do_more(1 as bit);
     #[cfg(not(DEBUGBUILD))]
     _state(data, FTP_STOP);
 
     #[cfg(DEBUGBUILD)]
     _state(data, FTP_STOP, 2028 as i32);/* this phase is completed */
     return result;
    }
 }
extern "C" fn ftp_state_port_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: i32,
 ) -> CURLcode {
    unsafe{
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut fcmd: ftpport = (*ftpc).count1 as ftpport;
     let mut result: CURLcode = CURLE_OK;
     /* The FTP spec tells a positive response should have code 200.
     Be more permissive here to tolerate deviant servers. */
     if ftpcode / 100 as i32 != 2 as i32 {/* the command failed */
         if EPRT as u32 == fcmd as u32 {
             Curl_infof(
                 data,
                 b"disabling EPRT usage\0" as *const u8 as *const libc::c_char,
             );
            //  let ref mut fresh24 = (*conn).bits;
             ((*conn).bits).set_ftp_use_eprt(0 as bit);
         }
         fcmd += 1;
         if fcmd as u32 == DONE as u32 {
             Curl_failf(
                 data,
                 b"Failed to do PORT\0" as *const u8 as *const libc::c_char,
             );
             result = CURLE_FTP_PORT_FAILED;
         } else {/* try next */
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
         _state(data, FTP_STOP, 2062 as i32);/* end of DO phase */
         result = ftp_dophase_done(data, 0 as i32 != 0);
     }
     return result;
    }
 }
extern "C" fn ftp_state_mdtm_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: i32,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     match ftpcode {
         213 => {
             /* we got a time. Format should be: "YYYYMMDDHHMMSS[.sss]" where the
         last .sss part is optional and means fractions of a second */
             let mut year: i32 = 0;
             let mut month: i32 = 0;
             let mut day: i32 = 0;
             let mut hour: i32 = 0;
             let mut minute: i32 = 0;
             let mut second: i32 = 0;
             if 6 as i32
                 == sscanf(
                     &mut *((*data).state.buffer).offset(4 as isize)
                         as *mut libc::c_char,
                     b"%04d%02d%02d%02d%02d%02d\0" as *const u8 as *const libc::c_char,
                     &mut year as *mut i32,
                     &mut month as *mut i32,
                     &mut day as *mut i32,
                     &mut hour as *mut i32,
                     &mut minute as *mut i32,
                     &mut second as *mut i32,
                 )
             { /* we have a time, reformat it */
                 let mut timebuf: [libc::c_char; 24] = [0; 24];
                 curl_msnprintf(
                     timebuf.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 24]>() as u64,
                     b"%04d%02d%02d %02d:%02d:%02d GMT\0" as *const u8 as *const libc::c_char,
                     year,
                     month,
                     day,
                     hour,
                     minute,
                     second,
                 );
                  /* now, convert this into a time() value: */
                 (*data).info.filetime = Curl_getdate_capped(timebuf.as_mut_ptr());
             }
            // #[cfg(CURL_FTP_HTTPSTYLE_HEAD)]
            /* If we asked for a time of the file and we actually got one as well,
         we "emulate" a HTTP-style header in our output. */
             if ((*data).set).opt_no_body() as i32 != 0
                 && !((*ftpc).file).is_null()
                 && ((*data).set).get_filetime() as i32 != 0
                 && (*data).info.filetime >= 0 as i64
             {
                 let mut headerbuf: [libc::c_char; 128] = [0; 128];
                 let mut headerbuflen: i32 = 0;
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
                 /* format: "Tue, 15 Nov 1994 12:45:26" */
                 headerbuflen = curl_msnprintf(
                     headerbuf.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 128]>() as u64,
                     b"Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8
                         as *const libc::c_char,
                     Curl_wkday[(if (*tm).tm_wday != 0 {
                         (*tm).tm_wday - 1 as i32
                     } else {
                         6 as i32
                     }) as usize],
                     (*tm).tm_mday,
                     Curl_month[(*tm).tm_mon as usize],
                     (*tm).tm_year + 1900 as i32,
                     (*tm).tm_hour,
                     (*tm).tm_min,
                     (*tm).tm_sec,
                 );
                 result = Curl_client_write(
                     data,
                     (1 as i32) << 0 as i32 | (1 as i32) << 1 as i32,
                     headerbuf.as_mut_ptr(),
                     headerbuflen as size_t,
                 );
                 if result as u64 != 0 {
                     return result;
                 }/* end of a ridiculous amount of conditionals */
             }
         }
         550 => {/* "No such file or directory" */
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
         if (*data).info.filetime > 0 as i64
             && (*data).set.timevalue > 0 as i64
         {
             match (*data).set.timecondition as u32 {
                 2 => {
                     if (*data).info.filetime > (*data).set.timevalue {
                         Curl_infof(
                             data,
                             b"The requested document is not old enough\0" as *const u8
                                 as *const libc::c_char,
                         );
                         (*ftp).transfer = PPTRANSFER_NONE;/* mark to not transfer data */
                        //  let ref mut fresh26 = (*data).info;
                         ((*data).info).set_timecond(1 as bit);
                         #[cfg(not(DEBUGBUILD))]
                         _state(data, FTP_STOP);

    #[cfg(DEBUGBUILD)]
                         _state(data, FTP_STOP, 2157 as i32);
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
                         (*ftp).transfer = PPTRANSFER_NONE;/* mark to not transfer data */
                        //  let ref mut fresh25 = (*data).info;
                         ((*data).info).set_timecond(1 as bit);
                         #[cfg(not(DEBUGBUILD))]
                         _state(data, FTP_STOP);

                         #[cfg(DEBUGBUILD)]
                         _state(data, FTP_STOP, 2148 as i32);
                         return CURLE_OK;
                     }
                 } /* switch */
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
 }
extern "C" fn ftp_state_type_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: i32,
     mut instate: ftpstate,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     if ftpcode / 100 as i32 != 2 as i32 {
         /* "sasserftpd" and "(u)r(x)bot ftpd" both responds with 226 after a
       successful 'TYPE I'. While that is not as RFC959 says, it is still a
       positive response code and we allow that. */
         Curl_failf(
             data,
             b"Couldn't set desired mode\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_FTP_COULDNT_SET_TYPE;
     }
     if ftpcode != 200 as i32 {
         Curl_infof(
             data,
             b"Got a %03d response code instead of the assumed 200\0" as *const u8
                 as *const libc::c_char,
             ftpcode,
         );
     }
     if instate as u32 == FTP_TYPE as u32 {
         result = ftp_state_size(data, conn);
     } else if instate as u32 == FTP_LIST_TYPE as u32 {
         result = ftp_state_list(data);
     } else if instate as u32 == FTP_RETR_TYPE as u32 {
         result = ftp_state_retr_prequote(data);
     } else if instate as u32 == FTP_STOR_TYPE as u32 {
         result = ftp_state_stor_prequote(data);
     }
     return result;
    }
 }
extern "C" fn ftp_state_retr(
     mut data: *mut Curl_easy,
     mut filesize: curl_off_t,
 ) -> CURLcode {
    unsafe{
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
         /* We always (attempt to) get the size of downloads, so it is done before
       this even when not doing resumes. */
         if filesize == -(1 as i32) as i64 {
             Curl_infof(
                 data,
                 b"ftp server doesn't support SIZE\0" as *const u8 as *const libc::c_char,
             );
             /* We couldn't get the size and therefore we can't know if there really
         is a part of the file left to get, although the server will just
         close the connection when we start the connection so it won't cause
         us any harm, just not make us exit as nicely. */
         } else if (*data).state.resume_from < 0 as i32 as i64 {
            /* We got a file size report, so we check that there actually is a
         part of the file left to get, or else we go home.  */
             if filesize < -(*data).state.resume_from {
                 /* We're supposed to download the last abs(from) bytes */
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
             /* Now store the number of bytes we are expected to download */
             (*ftp).downloadsize = filesize - (*data).state.resume_from;
         }
         if (*ftp).downloadsize == 0 as i64 {
             Curl_setup_transfer(
                 data,
                 -(1 as i32),
                 -(1 as i32) as curl_off_t,
                 0 as i32 != 0,
                 -(1 as i32),
             );
             Curl_infof(
                 data,
                 b"File already completely downloaded\0" as *const u8 as *const libc::c_char,
             );
             (*ftp).transfer = PPTRANSFER_NONE;
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_STOP);

             #[cfg(DEBUGBUILD)]
             _state(data, FTP_STOP, 2264 as i32);
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
             _state(data, FTP_RETR_REST, 2275 as i32);
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
             _state(data, FTP_RETR, 2281 as i32);
         }
     }
     return result;
    }
 }
extern "C" fn ftp_state_size_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: i32,
     mut instate: ftpstate,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut filesize: curl_off_t = -(1 as i32) as curl_off_t;
     let mut buf: *mut libc::c_char = (*data).state.buffer;
     /* get the size from the ascii string: */
     if ftpcode == 213 as i32 {
         /* To allow servers to prepend "rubbish" in the response string, we scan
       for all the digits at the end of the response and parse only those as a
       number. */
         let mut start: *mut libc::c_char =
             &mut *buf.offset(4 as isize) as *mut libc::c_char;
         let mut fdigit: *mut libc::c_char = strchr(start, '\r' as i32);
          /* ignores parsing errors, which will make the size remain unknown */
         if !fdigit.is_null() {
             loop {
                 fdigit = fdigit.offset(-1);
                 if !(Curl_isdigit(*fdigit as i32) != 0 && fdigit > start) {
                     break;
                 }
             }
             if Curl_isdigit(*fdigit as i32) == 0 {
                 fdigit = fdigit.offset(1);
             }
         } else {
             fdigit = start;
         }
         curlx_strtoofft(
             fdigit,
             0 as *mut *mut libc::c_char,
             0 as i32,
             &mut filesize,
         );
     } else if ftpcode == 550 as i32 {
        /* "No such file or directory" */
    /* allow a SIZE failure for (resumed) uploads, when probing what command
       to use */
         if instate as u32 != FTP_STOR_SIZE as u32 {
             Curl_failf(
                 data,
                 b"The file does not exist\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_REMOTE_FILE_NOT_FOUND;
         }
     }
     if instate as u32 == FTP_SIZE as u32 {
        // #[cfg(CURL_FTP_HTTPSTYLE_HEAD)]
         if -(1 as i32) as i64 != filesize {
             let mut clbuf: [libc::c_char; 128] = [0; 128];
             let mut clbuflen: i32 = curl_msnprintf(
                 clbuf.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 128]>() as u64,
                 b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                 filesize,
             );
             result = Curl_client_write(
                 data,
                 (1 as i32) << 0 as i32 | (1 as i32) << 1 as i32,
                 clbuf.as_mut_ptr(),
                 clbuflen as size_t,
             );
             if result as u64 != 0 {
                 return result;
             }
         }
         Curl_pgrsSetDownloadSize(data, filesize);
         result = ftp_state_rest(data, (*data).conn);
     } else if instate as u32 == FTP_RETR_SIZE as u32 {
         Curl_pgrsSetDownloadSize(data, filesize);
         result = ftp_state_retr(data, filesize);
     } else if instate as u32 == FTP_STOR_SIZE as u32 {
         (*data).state.resume_from = filesize;
         result = ftp_state_ul_setup(data, 1 as i32 != 0);
     }
     return result;
    }
 }
extern "C" fn ftp_state_rest_resp(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut ftpcode: i32,
     mut instate: ftpstate,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     match instate as u32 {
         27 => {
             if ftpcode != 350 as i32 {
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
                     _state(data, FTP_RETR, 2381 as i32);
                 }
             }
         }
         26 | _ => {
            // #[cfg(CURL_FTP_HTTPSTYLE_HEAD)]
             if ftpcode == 350 as i32 {
                 let mut buffer: [libc::c_char; 24] =
                     *::std::mem::transmute::<&[u8; 24], &mut [libc::c_char; 24]>(
                         b"Accept-ranges: bytes\r\n\0\0",
                     );
                 result = Curl_client_write(
                     data,
                     (1 as i32) << 0 as i32 | (1 as i32) << 1 as i32,
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
 }
extern "C" fn ftp_state_stor_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: i32,
     mut instate: ftpstate,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     if ftpcode >= 400 as i32 {
         Curl_failf(
             data,
             b"Failed FTP upload: %0d\0" as *const u8 as *const libc::c_char,
             ftpcode,
         );
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_STOP);
          /* oops, we never close the sockets! */

    #[cfg(DEBUGBUILD)]
         _state(data, FTP_STOP, 2397 as i32);
         return CURLE_UPLOAD_FAILED;
     }
     (*conn).proto.ftpc.state_saved = instate;
     /* PORT means we are now awaiting the server to connect to us. */
     if ((*data).set).ftp_use_port() != 0 {
         let mut connected: bool = false;
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_STOP);/* no longer in STOR state */

    #[cfg(DEBUGBUILD)]
         _state(data, FTP_STOP, 2408 as i32);
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
             (*ftpc).wait_data_conn = 1 as i32 != 0;
         }
         return CURLE_OK;
     }
     return InitiateTransfer(data);
    }
 }
 /* for LIST and RETR responses */
extern "C" fn ftp_state_get_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: i32,
     mut instate: ftpstate,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     if ftpcode == 150 as i32 || ftpcode == 125 as i32 {
        /*
      A;
      150 Opening BINARY mode data connection for /etc/passwd (2241
      bytes).  (ok, the file is being transferred)

      B:
      150 Opening ASCII mode data connection for /bin/ls

      C:
      150 ASCII data connection for /bin/ls (137.167.104.91,37445) (0 bytes).

      D:
      150 Opening ASCII mode data connection for [file] (0.0.0.0,0) (545 bytes)

      E:
      125 Data connection already open; Transfer starting. */
         let mut size: curl_off_t = -(1 as i32) as curl_off_t;/* default unknown size */
         /*
     * It appears that there are FTP-servers that return size 0 for files when
     * SIZE is used on the file while being in BINARY mode. To work around
     * that (stupid) behavior, we attempt to parse the RETR response even if
     * the SIZE returned size zero.
     *
     * Debugging help from Salvatore Sorrentino on February 26, 2003.
     */
         if instate as u32 != FTP_LIST as i32 as u32
             && ((*data).state).prefer_ascii() == 0
             && (*ftp).downloadsize < 1 as i64
         {
             /*
       * It seems directory listings either don't show the size or very
       * often uses size 0 anyway. ASCII transfers may very well turn out
       * that the transferred amount of data is not the same as this line
       * tells, why using this number in those cases only confuses us.
       *
       * Example D above makes this parsing a little tricky */
             let mut bytes: *mut libc::c_char = 0 as *mut libc::c_char;
             let mut buf: *mut libc::c_char = (*data).state.buffer;
             bytes = strstr(buf, b" bytes\0" as *const u8 as *const libc::c_char);
             if !bytes.is_null() {
                 /* this is a hint there is size information in there! ;-) */
                 bytes = bytes.offset(-1);
                 let mut in_0: i64 = bytes.offset_from(buf) as i64;
                 loop {
                     in_0 -= 1; /* scan for the left parenthesis and break there */
                     if !(in_0 != 0) {
                         break;
                     }/* skip only digits */
                     if '(' as i32 == *bytes as i32 {
                         break;
                     }
                     if Curl_isdigit(*bytes as u8 as i32) == 0 {
                         bytes = 0 as *mut libc::c_char;
                         break;
                     } else {
                         bytes = bytes.offset(-1);/* one more estep backwards */
                     }
                 }
                 /* if we have nothing but digits: */
                 if !bytes.is_null() {
                     bytes = bytes.offset(1); /* get the number! */
                     curlx_strtoofft(
                         bytes,
                         0 as *mut *mut libc::c_char,
                         0 as i32,
                         &mut size,
                     );
                 }
             }
         } else if (*ftp).downloadsize > -(1 as i32) as i64 {
             size = (*ftp).downloadsize;
         }
         if size > (*data).req.maxdownload
             && (*data).req.maxdownload > 0 as i64
         {
            //  let ref mut fresh27 = (*data).req.size;
             (*data).req.size = (*data).req.maxdownload;
             size = (*data).req.size;
         } else if instate as u32 != FTP_LIST as u32
             && ((*data).state).prefer_ascii() as i32 != 0
         {/* kludge for servers that understate ASCII mode file size */
             size = -(1 as i32) as curl_off_t;
         }
         Curl_infof(
             data,
             b"Maxdownload = %ld\0" as *const u8 as *const libc::c_char,
             (*data).req.maxdownload,
         );
         if instate as u32 != FTP_LIST as u32 {
             Curl_infof(
                 data,
                 b"Getting file with size: %ld\0" as *const u8 as *const libc::c_char,
                 size,
             );
         }
          /* FTP download: */
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
                 _state(data, FTP_STOP, 2530 as i32);
                 (*ftpc).wait_data_conn = 1 as i32 != 0;
             }
         } else {
             return InitiateTransfer(data);
         }
     } else if instate as u32 == FTP_LIST as u32
         && ftpcode == 450 as i32
     {/* simply no matching files in the dir listing */
         (*ftp).transfer = PPTRANSFER_NONE;/* don't download anything */
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_STOP); /* this phase is over */

    #[cfg(DEBUGBUILD)]
         _state(data, FTP_STOP, 2541 as i32);
     } else {
         Curl_failf(
             data,
             b"RETR response: %03d\0" as *const u8 as *const libc::c_char,
             ftpcode,
         );
         return (if instate as u32 == FTP_RETR as u32
             && ftpcode == 550 as i32
         {
             CURLE_REMOTE_FILE_NOT_FOUND as i32
         } else {
             CURLE_FTP_COULDNT_RETR_FILE as i32
         }) as CURLcode;
     }
     return result;
    }
 }
 /* after USER, PASS and ACCT */
extern "C" fn ftp_state_loggedin(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     if ((*conn).bits).ftp_use_control_ssl() != 0 {
        /* PBSZ = PROTECTION BUFFER SIZE.

    The 'draft-murray-auth-ftp-ssl' (draft 12, page 7) says:

    Specifically, the PROT command MUST be preceded by a PBSZ
    command and a PBSZ command MUST be preceded by a successful
    security data exchange (the TLS negotiation in this case)

    ... (and on page 8):

    Thus the PBSZ command must still be issued, but must have a
    parameter of '0' to indicate that no buffering is taking place
    and the data connection should not be encapsulated.
    */
         result = Curl_pp_sendf(
             data,
             &mut (*conn).proto.ftpc.pp as *mut pingpong,
             b"PBSZ %d\0" as *const u8 as *const libc::c_char,
             0 as i32,
         );
         if result as u64 == 0 {
            #[cfg(not(DEBUGBUILD))]
            _state(data, FTP_PBSZ);

    #[cfg(DEBUGBUILD)]
             _state(data, FTP_PBSZ, 2577 as i32);
         }
     } else {
         result = ftp_state_pwd(data, conn);
     }
     return result;
    }
 }
 /* for USER and PASS responses */
extern "C" fn ftp_state_user_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: i32,
     mut instate: ftpstate,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;/* no use for this yet */
     /* some need password anyway, and others just return 2xx ignored */
     if ftpcode == 331 as i32
         && (*ftpc).state as u32 == FTP_USER as u32
     {
        /* 331 Password required for ...
       (the server requires to send the user's password too) */
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
             _state(data, FTP_PASS, 2602 as i32);
         }
     } else if ftpcode / 100 as i32 == 2 as i32 {
          /* 230 User ... logged in.
       (the user logged in with or without password) */
         result = ftp_state_loggedin(data);
     } else if ftpcode == 332 as i32 {
        /* All other response codes, like:

    530 User ... access denied
    (the server denies to log the specified user) */
         if !((*data).set.str_0[STRING_FTP_ACCOUNT as usize]).is_null() {
            /* Ok, USER failed.  Let's try the supplied command. */
             result = Curl_pp_sendf(
                 data,
                 &mut (*ftpc).pp as *mut pingpong,
                 b"ACCT %s\0" as *const u8 as *const libc::c_char,
                 (*data).set.str_0[STRING_FTP_ACCOUNT as usize],
             );
             if result as u64 == 0 {
                #[cfg(not(DEBUGBUILD))]
                _state(data, FTP_ACCT);

    #[cfg(DEBUGBUILD)]
                 _state(data, FTP_ACCT, 2614 as i32);
             }
         } else {
             Curl_failf(
                 data,
                 b"ACCT requested but none available\0" as *const u8 as *const libc::c_char,
             );
             result = CURLE_LOGIN_DENIED;
         }
     } else if !((*data).set.str_0[STRING_FTP_ALTERNATIVE_TO_USER as usize]).is_null()
         && ((*data).state).ftp_trying_alternative() == 0
     {
         result = Curl_pp_sendf(
             data,
             &mut (*ftpc).pp as *mut pingpong,
             b"%s\0" as *const u8 as *const libc::c_char,
             (*data).set.str_0[STRING_FTP_ALTERNATIVE_TO_USER as usize],
         );
         if result as u64 == 0 {
            //  let ref mut fresh28 = (*data).state;
             ((*data).state).set_ftp_trying_alternative(1 as bit);
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_USER);

             #[cfg(DEBUGBUILD)]
             _state(data, FTP_USER, 2635 as i32);
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
 }
 /* for ACCT response */
extern "C" fn ftp_state_acct_resp(
     mut data: *mut Curl_easy,
     mut ftpcode: i32,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     if ftpcode != 230 as i32 {
         Curl_failf(
             data,
             b"ACCT rejected by server: %03d\0" as *const u8 as *const libc::c_char,
             ftpcode,
         );
         result = CURLE_FTP_WEIRD_PASS_REPLY;/* FIX */
     } else {
         result = ftp_state_loggedin(data);
     }
     return result;
    }
 }
//  unsafe extern "C" fn ftp_statemachine(
//      mut data: *mut Curl_easy,
//      mut conn: *mut connectdata,
//  ) -> CURLcode {
//      let mut result: CURLcode = CURLE_OK;
//      let mut sock: curl_socket_t = (*conn).sock[0 as libc::c_int as usize];
//      let mut ftpcode: libc::c_int = 0;
//      let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
//      let mut pp: *mut pingpong = &mut (*ftpc).pp;
//      static mut ftpauth: [[libc::c_char; 4]; 2] = unsafe {
//          [
//              *::std::mem::transmute::<&[u8; 4], &[libc::c_char; 4]>(b"SSL\0"),
//              *::std::mem::transmute::<&[u8; 4], &[libc::c_char; 4]>(b"TLS\0"),
//          ]
//      };
//      let mut nread: size_t = 0 as libc::c_int as size_t;
//      if (*pp).sendleft != 0 {
//          return Curl_pp_flushsend(data, pp);
//      }
//      result = ftp_readresp(data, sock, pp, &mut ftpcode, &mut nread);
//      if result as u64 != 0 {
//          return result;
//      }
//      if ftpcode != 0 {
//         let mut current_block_187: u64;
//          match (*ftpc).state as libc::c_uint {
//              1 => {
//                  if ftpcode == 230 as libc::c_int {
//                      if (*data).set.use_ssl as libc::c_uint
//                          <= CURLUSESSL_TRY as libc::c_int as libc::c_uint
//                          || ((*conn).bits).ftp_use_control_ssl() as libc::c_int != 0
//                      {
//                          return ftp_state_user_resp(data, ftpcode, (*ftpc).state);
//                      }
//                  } else if ftpcode != 220 as libc::c_int {
//                      Curl_failf(
//                          data,
//                          b"Got a %03d ftp-server response when 220 was expected\0" as *const u8
//                              as *const libc::c_char,
//                          ftpcode,
//                      );
//                      return CURLE_WEIRD_SERVER_REPLY;
//                  }
//                 #[cfg(HAVE_GSSAPI)]
//                 if ((*data).set).krb() != 0 {
//                     Curl_sec_request_prot(
//                         conn,
//                         b"private\0" as *const u8 as *const libc::c_char,
//                     );
//                     Curl_sec_request_prot(
//                         conn,
//                         (*data).set.str_0[STRING_KRB_LEVEL as libc::c_int as usize],
//                     );
//                     if Curl_sec_login(data, conn) as u64 != 0 {
//                         Curl_infof(
//                             data,
//                             b"Logging in with password in cleartext!\0" as *const u8
//                                 as *const libc::c_char,
//                         );
//                     } else {
//                         Curl_infof(
//                             data,
//                             b"Authentication successful\0" as *const u8
//                                 as *const libc::c_char,
//                         );
//                     }
//                 }
//                  if (*data).set.use_ssl as libc::c_uint != 0
//                      && ((*conn).bits).ftp_use_control_ssl() == 0
//                  {
//                      (*ftpc).count3 = 0 as libc::c_int;
//                      match (*data).set.ftpsslauth as libc::c_uint {
//                          0 | 1 => {
//                              (*ftpc).count2 = 1 as libc::c_int;
//                              (*ftpc).count1 = 0 as libc::c_int;
//                          }
//                          2 => {
//                              (*ftpc).count2 = -(1 as libc::c_int);
//                              (*ftpc).count1 = 1 as libc::c_int;
//                          }
//                          _ => {
//                              Curl_failf(
//                                  data,
//                                  b"unsupported parameter to CURLOPT_FTPSSLAUTH: %d\0" as *const u8
//                                      as *const libc::c_char,
//                                  (*data).set.ftpsslauth as libc::c_int,
//                              );
//                              return CURLE_UNKNOWN_OPTION;
//                          }
//                      }
//                      result = Curl_pp_sendf(
//                          data,
//                          &mut (*ftpc).pp as *mut pingpong,
//                          b"AUTH %s\0" as *const u8 as *const libc::c_char,
//                          (ftpauth[(*ftpc).count1 as usize]).as_ptr(),
//                      );
//                      if result as u64 == 0 {
//                         #[cfg(not(DEBUGBUILD))]
//                         _state(data, FTP_AUTH);

// 	#[cfg(DEBUGBUILD)]
//                          _state(data, FTP_AUTH, 2737 as libc::c_int);
//                      }
//                  } else {
//                      result = ftp_state_user(data, conn);
//                  }
//              }
//              2 => {
//                  if (*pp).cache_size != 0 {
//                      return CURLE_WEIRD_SERVER_REPLY;
//                  }
//                  if ftpcode == 234 as libc::c_int || ftpcode == 334 as libc::c_int {
//                     // match () {
//                     //     #[cfg(USE_SSL)]
//                     //     _ => {
//                     //         result = Curl_ssl_connect(data, conn, 0 as libc::c_int);
//                     //     }
//                     //     #[cfg(not(USE_SSL))]
//                     //     _ => {
//                     //         result = CURLE_NOT_BUILT_IN;
//                     //     }
//                     // }
//                      result = Curl_ssl_connect(data, conn, 0 as libc::c_int);
//                      if result as u64 == 0 {
//                          let ref mut fresh29 = (*conn).bits;
//                          (*fresh29).set_ftp_use_data_ssl(0 as libc::c_int as bit);
//                          let ref mut fresh30 = (*conn).bits;
//                          (*fresh30).set_ftp_use_control_ssl(1 as libc::c_int as bit);
//                          result = ftp_state_user(data, conn);
//                      }
//                  } else if (*ftpc).count3 < 1 as libc::c_int {
//                      let ref mut fresh31 = (*ftpc).count3;
//                      *fresh31 += 1;
//                      (*ftpc).count1 += (*ftpc).count2;
//                      result = Curl_pp_sendf(
//                          data,
//                          &mut (*ftpc).pp as *mut pingpong,
//                          b"AUTH %s\0" as *const u8 as *const libc::c_char,
//                          (ftpauth[(*ftpc).count1 as usize]).as_ptr(),
//                      );
//                  } else if (*data).set.use_ssl as libc::c_uint
//                      > CURLUSESSL_TRY as libc::c_int as libc::c_uint
//                  {
//                      result = CURLE_USE_SSL_FAILED;
//                  } else {
//                      result = ftp_state_user(data, conn);
//                  }
//              }
//              3 | 4 => {
//                  result = ftp_state_user_resp(data, ftpcode, (*ftpc).state);
//              }
//              5 => {
//                  result = ftp_state_acct_resp(data, ftpcode);
//              }
//              6 => {
//                  result = Curl_pp_sendf(
//                      data,
//                      &mut (*ftpc).pp as *mut pingpong,
//                      b"PROT %c\0" as *const u8 as *const libc::c_char,
//                      if (*data).set.use_ssl as libc::c_uint
//                          == CURLUSESSL_CONTROL as libc::c_int as libc::c_uint
//                      {
//                          'C' as i32
//                      } else {
//                          'P' as i32
//                      },
//                  );
//                  if result as u64 == 0 {
//                     #[cfg(not(DEBUGBUILD))]
//                     _state(data, FTP_PROT);

// 	#[cfg(DEBUGBUILD)]
//                      _state(data, FTP_PROT, 2796 as libc::c_int);
//                  }
//              }
//              7 => {
//                  if ftpcode / 100 as libc::c_int == 2 as libc::c_int {
//                      let ref mut fresh32 = (*conn).bits;
//                      (*fresh32).set_ftp_use_data_ssl(
//                          (if (*data).set.use_ssl as libc::c_uint
//                              != CURLUSESSL_CONTROL as libc::c_int as libc::c_uint
//                          {
//                              1 as libc::c_int
//                          } else {
//                              0 as libc::c_int
//                          }) as bit,
//                      );
//                  } else if (*data).set.use_ssl as libc::c_uint
//                      > CURLUSESSL_CONTROL as libc::c_int as libc::c_uint
//                  {
//                      return CURLE_USE_SSL_FAILED;
//                  }
//                  if (*data).set.ftp_ccc as u64 != 0 {
//                      result = Curl_pp_sendf(
//                          data,
//                          &mut (*ftpc).pp as *mut pingpong,
//                          b"%s\0" as *const u8 as *const libc::c_char,
//                          b"CCC\0" as *const u8 as *const libc::c_char,
//                      );
//                      if result as u64 == 0 {
//                         #[cfg(not(DEBUGBUILD))]
//                         _state(data, FTP_CCC);

// 	#[cfg(DEBUGBUILD)]
//                          _state(data, FTP_CCC, 2815 as libc::c_int);
//                      }
//                  } else {
//                      result = ftp_state_pwd(data, conn);
//                  }
//              }
//              8 => {
//                  if ftpcode < 500 as libc::c_int {
//                     // match () {
//                     //     #[cfg(USE_SSL)]
//                     //     _ => {
//                     //         result = Curl_ssl_shutdown(data, conn, 0 as libc::c_int);
//                     //     }
//                     //     #[cfg(not(USE_SSL))]
//                     //     _ => {
//                     //         result =CURLE_NOT_BUILT_IN;
//                     //     }
//                     // }
//                      result = Curl_ssl_shutdown(data, conn, 0 as libc::c_int);
//                      if result as u64 != 0 {
//                          Curl_failf(
//                              data,
//                              b"Failed to clear the command channel (CCC)\0" as *const u8
//                                  as *const libc::c_char,
//                          );
//                      }
//                  }
//                  if result as u64 == 0 {
//                      result = ftp_state_pwd(data, conn);
//                  }
//              }
//              9 => {
//                  if ftpcode == 257 as libc::c_int {
//                      let mut ptr: *mut libc::c_char = &mut *((*data).state.buffer)
//                          .offset(4 as libc::c_int as isize)
//                          as *mut libc::c_char;
//                      let buf_size: size_t = (*data).set.buffer_size as size_t;
//                      let mut dir: *mut libc::c_char = 0 as *mut libc::c_char;
//                      let mut entry_extracted: bool = 0 as libc::c_int != 0;
//                      match () {
//                         #[cfg(not(CURLDEBUG))]
//                         _ => {
//                             dir = Curl_cmalloc.expect("non-null function pointer")(
//                                 nread.wrapping_add(1 as libc::c_int as libc::c_ulong),
//                             ) as *mut libc::c_char;
//                         }
//                         #[cfg(CURLDEBUG)]
//                         _ => {
//                             dir = curl_dbg_malloc(
//                                 nread.wrapping_add(1 as libc::c_int as libc::c_ulong),
//                                 2841 as libc::c_int,
//                                 b"ftp.c\0" as *const u8 as *const libc::c_char,
//                             ) as *mut libc::c_char;
//                         }
//                     }
                    
//                      if dir.is_null() {
//                          return CURLE_OUT_OF_MEMORY;
//                      }
//                      while ptr
//                          < &mut *((*data).state.buffer).offset(buf_size as isize)
//                              as *mut libc::c_char
//                          && *ptr as libc::c_int != '\n' as i32
//                         && *ptr as libc::c_int != '\0' as i32
//                          && *ptr as libc::c_int != '"' as i32
//                      {
//                          ptr = ptr.offset(1);
//                      }
//                      if '"' as i32 == *ptr as libc::c_int {
//                          let mut store: *mut libc::c_char = 0 as *mut libc::c_char;
//                          ptr = ptr.offset(1);
//                          store = dir;
//                          while *ptr != 0 {
//                              if '"' as i32 == *ptr as libc::c_int {
//                                  if '"' as i32
//                                      == *ptr.offset(1 as libc::c_int as isize) as libc::c_int
//                                  {
//                                      *store = *ptr.offset(1 as libc::c_int as isize);
//                                      ptr = ptr.offset(1);
//                                  } else {
//                                      entry_extracted = 1 as libc::c_int != 0;
//                                      break;
//                                  }
//                              } else {
//                                  *store = *ptr;
//                              }
//                              store = store.offset(1);
//                              ptr = ptr.offset(1);
//                          }
//                         *store = '\0' as i32 as libc::c_char;
//                      }
//                      if entry_extracted {
//                          if ((*ftpc).server_os).is_null()
//                              && *dir.offset(0 as libc::c_int as isize) as libc::c_int != '/' as i32
//                          {
//                              result = Curl_pp_sendf(
//                                  data,
//                                  &mut (*ftpc).pp as *mut pingpong,
//                                  b"%s\0" as *const u8 as *const libc::c_char,
//                                  b"SYST\0" as *const u8 as *const libc::c_char,
//                              );
//                              if result as u64 != 0 {
//                                 #[cfg(not(CURLDEBUG))]
//                                 Curl_cfree.expect("non-null function pointer")(
//                                     dir as *mut libc::c_void,
//                                 );
// 	                            #[cfg(CURLDEBUG)]
//                                  curl_dbg_free(
//                                      dir as *mut libc::c_void,
//                                      2899 as libc::c_int,
//                                      b"ftp.c\0" as *const u8 as *const libc::c_char,
//                                  );
//                                  return result;
//                              }
//                              #[cfg(not(CURLDEBUG))]
//                              Curl_cfree.expect("non-null function pointer")(
//                                 (*ftpc).entrypath as *mut libc::c_void,
//                             );
// 	                        #[cfg(CURLDEBUG)]
//                              curl_dbg_free(
//                                  (*ftpc).entrypath as *mut libc::c_void,
//                                  2902 as libc::c_int,
//                                  b"ftp.c\0" as *const u8 as *const libc::c_char,
//                              );
//                              let ref mut fresh33 = (*ftpc).entrypath;
//                              *fresh33 = 0 as *mut libc::c_char;
//                              let ref mut fresh34 = (*ftpc).entrypath;
//                              *fresh34 = dir;
//                              Curl_infof(
//                                  data,
//                                  b"Entry path is '%s'\0" as *const u8 as *const libc::c_char,
//                                  (*ftpc).entrypath,
//                              );
//                              let ref mut fresh35 = (*data).state.most_recent_ftp_entrypath;
//                              *fresh35 = (*ftpc).entrypath;
//                              #[cfg(not(DEBUGBUILD))]
//                              _state(data, FTP_SYST);

//                              #[cfg(DEBUGBUILD)]
//                              _state(data, FTP_SYST, 2907 as libc::c_int);
//                              current_block_187 = 10490607306284298299;
//                          } else {
//                             #[cfg(not(CURLDEBUG))]
//                             Curl_cfree.expect("non-null function pointer")(
//                                 (*ftpc).entrypath as *mut libc::c_void,
//                             );
// 	                        #[cfg(CURLDEBUG)]
//                              curl_dbg_free(
//                                  (*ftpc).entrypath as *mut libc::c_void,
//                                  2911 as libc::c_int,
//                                  b"ftp.c\0" as *const u8 as *const libc::c_char,
//                              );
//                              let ref mut fresh36 = (*ftpc).entrypath;
//                              *fresh36 = 0 as *mut libc::c_char;
//                              let ref mut fresh37 = (*ftpc).entrypath;
//                              *fresh37 = dir;
//                              Curl_infof(
//                                  data,
//                                  b"Entry path is '%s'\0" as *const u8 as *const libc::c_char,
//                                  (*ftpc).entrypath,
//                              );
//                              let ref mut fresh38 = (*data).state.most_recent_ftp_entrypath;
//                              *fresh38 = (*ftpc).entrypath;
//                             current_block_187 = 17917672080766325409;
//                          }
//                      } else {
//                         #[cfg(not(CURLDEBUG))]
//                         Curl_cfree.expect("non-null function pointer")(dir as *mut libc::c_void);

// 	                    #[cfg(CURLDEBUG)]
//                          curl_dbg_free(
//                              dir as *mut libc::c_void,
//                              2919 as libc::c_int,
//                              b"ftp.c\0" as *const u8 as *const libc::c_char,
//                          );
//                          Curl_infof(
//                              data,
//                              b"Failed to figure out path\0" as *const u8 as *const libc::c_char,
//                          );
//                         current_block_187 = 17917672080766325409;
//                      }
//                  } else {
//                     current_block_187 = 17917672080766325409;
//                  }
//                 match current_block_187 {
//                     10490607306284298299 => {}
//                      _ => {
//                         #[cfg(not(DEBUGBUILD))]
//                         _state(data, FTP_STOP);

// 	#[cfg(DEBUGBUILD)]
//                          _state(data, FTP_STOP, 2923 as libc::c_int);
//                          #[cfg(DEBUGBUILD)]
//                          Curl_infof(
//                              data,
//                              b"protocol connect phase DONE\0" as *const u8 as *const libc::c_char,
//                          );
//                      }
//                  }
//              }
//              10 => {
//                  if ftpcode == 215 as libc::c_int {
//                      let mut ptr_0: *mut libc::c_char = &mut *((*data).state.buffer)
//                          .offset(4 as libc::c_int as isize)
//                          as *mut libc::c_char;
//                      let mut os: *mut libc::c_char = 0 as *mut libc::c_char;
//                      let mut store_0: *mut libc::c_char = 0 as *mut libc::c_char;
//                      match () {
//                         #[cfg(not(CURLDEBUG))]
//                         _ => {
//                             os = Curl_cmalloc.expect("non-null function pointer")(
//                                 nread.wrapping_add(1 as libc::c_int as libc::c_ulong),
//                             ) as *mut libc::c_char;
//                         }
//                         #[cfg(CURLDEBUG)]
//                         _ => {
//                             os = curl_dbg_malloc(
//                                 nread.wrapping_add(1 as libc::c_int as libc::c_ulong),
//                                 2933 as libc::c_int,
//                                 b"ftp.c\0" as *const u8 as *const libc::c_char,
//                             ) as *mut libc::c_char;
//                         }
//                     }
                     
//                      if os.is_null() {
//                          return CURLE_OUT_OF_MEMORY;
//                      }
//                      while *ptr_0 as libc::c_int == ' ' as i32 {
//                          ptr_0 = ptr_0.offset(1);
//                      }
//                      store_0 = os;
//                      while *ptr_0 as libc::c_int != 0 && *ptr_0 as libc::c_int != ' ' as i32 {
//                          let fresh39 = ptr_0;
//                          ptr_0 = ptr_0.offset(1);
//                          let fresh40 = store_0;
//                          store_0 = store_0.offset(1);
//                          *fresh40 = *fresh39;
//                      }
//                     *store_0 = '\0' as i32 as libc::c_char;
//                      if Curl_strcasecompare(os, b"OS/400\0" as *const u8 as *const libc::c_char) != 0
//                      {
//                          result = Curl_pp_sendf(
//                              data,
//                              &mut (*ftpc).pp as *mut pingpong,
//                              b"%s\0" as *const u8 as *const libc::c_char,
//                              b"SITE NAMEFMT 1\0" as *const u8 as *const libc::c_char,
//                          );
//                          if result as u64 != 0 {
//                             #[cfg(not(CURLDEBUG))]
//                             Curl_cfree.expect("non-null function pointer")(os as *mut libc::c_void);

// 	#[cfg(CURLDEBUG)]
//                              curl_dbg_free(
//                                  os as *mut libc::c_void,
//                                  2952 as libc::c_int,
//                                  b"ftp.c\0" as *const u8 as *const libc::c_char,
//                              );
//                              return result;
//                          }
//                          #[cfg(not(CURLDEBUG))]
//                          Curl_cfree.expect("non-null function pointer")(
//                             (*ftpc).server_os as *mut libc::c_void,
//                         );
// 	#[cfg(CURLDEBUG)]
//                          curl_dbg_free(
//                              (*ftpc).server_os as *mut libc::c_void,
//                              2956 as libc::c_int,
//                              b"ftp.c\0" as *const u8 as *const libc::c_char,
//                          );
//                          let ref mut fresh41 = (*ftpc).server_os;
//                          *fresh41 = 0 as *mut libc::c_char;
//                          let ref mut fresh42 = (*ftpc).server_os;
//                          *fresh42 = os;
//                          #[cfg(not(DEBUGBUILD))]
//                          _state(data, FTP_NAMEFMT);

// 	#[cfg(DEBUGBUILD)]
//                          _state(data, FTP_NAMEFMT, 2958 as libc::c_int);
//                          current_block_187 = 10490607306284298299;

//                      } else {
//                         #[cfg(not(CURLDEBUG))]
//                         Curl_cfree.expect("non-null function pointer")(
//                             (*ftpc).server_os as *mut libc::c_void,
//                         );
// 	#[cfg(CURLDEBUG)]
//                          curl_dbg_free(
//                              (*ftpc).server_os as *mut libc::c_void,
//                              2963 as libc::c_int,
//                              b"ftp.c\0" as *const u8 as *const libc::c_char,
//                          );
//                          let ref mut fresh43 = (*ftpc).server_os;
//                          *fresh43 = 0 as *mut libc::c_char;
//                          let ref mut fresh44 = (*ftpc).server_os;
//                          *fresh44 = os;
//                         current_block_187 = 6938158527927677584;
//                      }
//                  } else {
//                     current_block_187 = 6938158527927677584;
//                  }
//                 match current_block_187 {
//                     10490607306284298299 => {}
//                      _ => {
//                         #[cfg(not(DEBUGBUILD))]
//                         _state(data, FTP_STOP);

// 	#[cfg(DEBUGBUILD)]
//                          _state(data, FTP_STOP, 2970 as libc::c_int);
//                          #[cfg(DEBUGBUILD)]
//                          Curl_infof(
//                              data,
//                              b"protocol connect phase DONE\0" as *const u8 as *const libc::c_char,
//                          );
//                      }
//                  }
//              }
//              11 => {
//                  if ftpcode == 250 as libc::c_int {
//                      ftp_state_pwd(data, conn);
//                  } else {
//                     #[cfg(not(DEBUGBUILD))]
//                     _state(data, FTP_STOP);

// 	#[cfg(DEBUGBUILD)]
//                      _state(data, FTP_STOP, 2981 as libc::c_int);
//                      #[cfg(DEBUGBUILD)]
//                      Curl_infof(
//                          data,
//                          b"protocol connect phase DONE\0" as *const u8 as *const libc::c_char,
//                      );
//                  }
//              }
//              12 | 15 | 13 | 14 => {
//                  if ftpcode >= 400 as libc::c_int && (*ftpc).count2 == 0 {
//                      Curl_failf(
//                          data,
//                          b"QUOT command failed with %03d\0" as *const u8 as *const libc::c_char,
//                          ftpcode,
//                      );
//                      result = CURLE_QUOTE_ERROR;
//                  } else {
//                      result = ftp_state_quote(data, 0 as libc::c_int != 0, (*ftpc).state);
//                  }
//              }
//              16 => {
//                  if ftpcode / 100 as libc::c_int != 2 as libc::c_int {
//                      if (*data).set.ftp_create_missing_dirs != 0
//                          && (*ftpc).cwdcount != 0
//                          && (*ftpc).count2 == 0
//                      {
//                          let ref mut fresh45 = (*ftpc).count2;
//                          *fresh45 += 1;
//                          result = Curl_pp_sendf(
//                              data,
//                              &mut (*ftpc).pp as *mut pingpong,
//                              b"MKD %s\0" as *const u8 as *const libc::c_char,
//                              *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
//                          );
//                          if result as u64 == 0 {
//                             #[cfg(not(DEBUGBUILD))]
//                             _state(data, FTP_MKD);

// 	#[cfg(DEBUGBUILD)]
//                              _state(data, FTP_MKD, 3008 as libc::c_int);
//                          }
//                      } else {
//                          Curl_failf(
//                              data,
//                              b"Server denied you to change to the given directory\0" as *const u8
//                                  as *const libc::c_char,
//                          );
//                          (*ftpc).cwdfail = 1 as libc::c_int != 0;
//                          result = CURLE_REMOTE_ACCESS_DENIED;
//                      }
//                  } else {
//                      (*ftpc).count2 = 0 as libc::c_int;
//                      let ref mut fresh46 = (*ftpc).cwdcount;
//                      *fresh46 += 1;
//                      if *fresh46 <= (*ftpc).dirdepth {
//                          result = Curl_pp_sendf(
//                              data,
//                              &mut (*ftpc).pp as *mut pingpong,
//                              b"CWD %s\0" as *const u8 as *const libc::c_char,
//                              *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
//                          );
//                      } else {
//                          result = ftp_state_mdtm(data);
//                      }
//                  }
//              }
//              17 => {
//                  if ftpcode / 100 as libc::c_int != 2 as libc::c_int && {
//                      let ref mut fresh47 = (*ftpc).count3;
//                      let fresh48 = *fresh47;
//                      *fresh47 = *fresh47 - 1;
//                      fresh48 == 0
//                  } {
//                      Curl_failf(
//                          data,
//                          b"Failed to MKD dir: %03d\0" as *const u8 as *const libc::c_char,
//                          ftpcode,
//                      );
//                      result = CURLE_REMOTE_ACCESS_DENIED;
//                  } else {
//                     #[cfg(not(DEBUGBUILD))]
//                     _state(data, FTP_CWD);

// 	#[cfg(DEBUGBUILD)]
//                      _state(data, FTP_CWD, 3037 as libc::c_int);
//                      result = Curl_pp_sendf(
//                          data,
//                          &mut (*ftpc).pp as *mut pingpong,
//                          b"CWD %s\0" as *const u8 as *const libc::c_char,
//                          *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
//                      );
//                  }
//              }
//              18 => {
//                  result = ftp_state_mdtm_resp(data, ftpcode);
//              }
//              19 | 20 | 21 | 22 => {
//                  result = ftp_state_type_resp(data, ftpcode, (*ftpc).state);
//              }
//              23 | 24 | 25 => {
//                  result = ftp_state_size_resp(data, ftpcode, (*ftpc).state);
//              }
//              26 | 27 => {
//                  result = ftp_state_rest_resp(data, conn, ftpcode, (*ftpc).state);
//              }
//              29 => {
//                  if ftpcode != 200 as libc::c_int {
//                      Curl_failf(
//                          data,
//                          b"PRET command not accepted: %03d\0" as *const u8 as *const libc::c_char,
//                          ftpcode,
//                      );
//                      return CURLE_FTP_PRET_FAILED;
//                  }
//                  result = ftp_state_use_pasv(data, conn);
//              }
//              30 => {
//                  result = ftp_state_pasv_resp(data, ftpcode);
//              }
//              28 => {
//                  result = ftp_state_port_resp(data, ftpcode);
//              }
//              31 | 32 => {
//                  result = ftp_state_get_resp(data, ftpcode, (*ftpc).state);
//              }
//              33 => {
//                  result = ftp_state_stor_resp(data, ftpcode, (*ftpc).state);
//              }
//              34 | _ => {
//                 #[cfg(not(DEBUGBUILD))]
//                 _state(data, FTP_STOP);

// 	#[cfg(DEBUGBUILD)]
//                  _state(data, FTP_STOP, 3096 as libc::c_int);
//              }
//          }
//      }
//      return result;
//  }
 
extern "C" fn ftp_statemachine(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
   unsafe{
    let mut result: CURLcode = CURLE_OK;
    let mut sock: curl_socket_t = (*conn).sock[0 as usize];
    let mut ftpcode: i32 = 0;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    static mut ftpauth: [[libc::c_char; 4]; 2] = unsafe {
        [
            *::std::mem::transmute::<&[u8; 4], &[libc::c_char; 4]>(b"SSL\0"),
            *::std::mem::transmute::<&[u8; 4], &[libc::c_char; 4]>(b"TLS\0"),
        ]
    };
    let mut nread: size_t = 0 as size_t;
    if (*pp).sendleft != 0 {
        return Curl_pp_flushsend(data, pp);
    }
    result = ftp_readresp(data, sock, pp, &mut ftpcode, &mut nread);
    if result as u64 != 0 {
        return result;
    }
    if ftpcode != 0 {
       let mut current_block_187: u64;
        match (*ftpc).state as u32 {
            1 => {
                if ftpcode == 230 as i32 {
                    if (*data).set.use_ssl as u32
                        <= CURLUSESSL_TRY as u32
                        || ((*conn).bits).ftp_use_control_ssl() as i32 != 0
                    {
                        return ftp_state_user_resp(data, ftpcode, (*ftpc).state);
                    }
                } else if ftpcode != 220 as i32 {
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
                    /* If not anonymous login, try a secure login. Note that this
          procedure is still BLOCKING. */
                   Curl_sec_request_prot(
                       conn,
                       b"private\0" as *const u8 as *const libc::c_char,
                   );
                    /* We set private first as default, in case the line below fails to
          set a valid level */
                   Curl_sec_request_prot(
                       conn,
                       (*data).set.str_0[STRING_KRB_LEVEL as usize],
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
               /* We don't have a SSL/TLS control connection yet, but FTPS is
          requested. Try a FTPS connection now */
                if (*data).set.use_ssl as u32 != 0
                    && ((*conn).bits).ftp_use_control_ssl() == 0
                {
                    (*ftpc).count3 = 0 as i32;
                    match (*data).set.ftpsslauth as u32 {
                        0 | 1 => {
                            (*ftpc).count2 = 1 as i32; /* add one to get next */
                            (*ftpc).count1 = 0 as i32;
                        }
                        2 => {
                            (*ftpc).count2 = -(1 as i32);/* subtract one to get next */
                            (*ftpc).count1 = 1 as i32;
                        }
                        _ => {
                            Curl_failf(
                                data,
                                b"unsupported parameter to CURLOPT_FTPSSLAUTH: %d\0" as *const u8
                                    as *const libc::c_char,
                                (*data).set.ftpsslauth as i32,
                            );
                            return CURLE_UNKNOWN_OPTION; /* we don't know what to do */
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
                        _state(data, FTP_AUTH, 2737 as i32);
                    }
                } else {
                    result = ftp_state_user(data, conn);
                }
            }
            2 => {/* we have gotten the response to a previous AUTH command */
                if (*pp).cache_size != 0 {
                    return CURLE_WEIRD_SERVER_REPLY; /* Forbid pipelining in response. */
                }
                 /* RFC2228 (page 5) says:
      *
      * If the server is willing to accept the named security mechanism,
      * and does not require any security data, it must respond with
      * reply code 234/334.
      */
                if ftpcode == 234 as i32 || ftpcode == 334 as i32 {
                   // match () {
                   //     #[cfg(USE_SSL)]
                   //     _ => {
                   //         result = Curl_ssl_connect(data, conn, 0 as i32);
                   //     }
                   //     #[cfg(not(USE_SSL))]
                   //     _ => {
                   //         result = CURLE_NOT_BUILT_IN;
                   //     }
                   // }
                    result = Curl_ssl_connect(data, conn, 0 as i32);
                    if result as u64 == 0 {
                        ((*conn).bits).set_ftp_use_data_ssl(0 as bit);/* clear-text data */
                        ((*conn).bits).set_ftp_use_control_ssl(1 as bit);/* SSL on control */
                        result = ftp_state_user(data, conn);
                    }
                } else if (*ftpc).count3 < 1 as i32 {
                    (*ftpc).count3 += 1;
                    (*ftpc).count1 += (*ftpc).count2;/* get next attempt */
                    result = Curl_pp_sendf(
                        data,
                        &mut (*ftpc).pp as *mut pingpong,
                        b"AUTH %s\0" as *const u8 as *const libc::c_char,
                        (ftpauth[(*ftpc).count1 as usize]).as_ptr(),
                    );/* remain in this same state */
                } else if (*data).set.use_ssl as u32
                    > CURLUSESSL_TRY as u32
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
                    if (*data).set.use_ssl as u32
                        == CURLUSESSL_CONTROL as u32
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
                    _state(data, FTP_PROT, 2796 as i32);
                }
            }
            7 => {
                if ftpcode / 100 as i32 == 2 as i32 {
                    ((*conn).bits).set_ftp_use_data_ssl(
                        (if (*data).set.use_ssl as u32
                            != CURLUSESSL_CONTROL as u32
                        { 
                            1 as i32
                        } else {
                            0 as i32
                        }) as bit,
                    );
                } else if (*data).set.use_ssl as u32
                    > CURLUSESSL_CONTROL as u32
                { /* we failed and bails out */
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
                        _state(data, FTP_CCC, 2815 as i32);
                    }
                } else {
                    result = ftp_state_pwd(data, conn);
                }
            }
            8 => {
                if ftpcode < 500 as i32 {
                   /* First shut down the SSL layer (note: this call will block) */
                   // match () {
                   //     #[cfg(USE_SSL)]
                   //     _ => {
                   //         result = Curl_ssl_shutdown(data, conn, 0 as i32);
                   //     }
                   //     #[cfg(not(USE_SSL))]
                   //     _ => {
                   //         result =CURLE_NOT_BUILT_IN;
                   //     }
                   // }
                    result = Curl_ssl_shutdown(data, conn, 0 as i32);
                    if result as u64 != 0 {
                        Curl_failf(
                            data,
                            b"Failed to clear the command channel (CCC)\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
                if result as u64 == 0 {
                   /* Then continue as normal */
                    result = ftp_state_pwd(data, conn);
                }
            }
            9 => {
                if ftpcode == 257 as i32 {
                    let mut ptr: *mut libc::c_char = &mut *((*data).state.buffer)
                        .offset(4 as isize)
                        as *mut libc::c_char; /* start on the first letter */
                    let buf_size: size_t = (*data).set.buffer_size as size_t;
                    let mut dir: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut entry_extracted: bool = 0 as i32 != 0;
                    match () {
                       #[cfg(not(CURLDEBUG))]
                       _ => {
                           dir = Curl_cmalloc.expect("non-null function pointer")(
                               nread.wrapping_add(1 as u64),
                           ) as *mut libc::c_char;
                       }
                       #[cfg(CURLDEBUG)]
                       _ => {
                           dir = curl_dbg_malloc(
                               nread.wrapping_add(1 as u64),
                               2841 as i32,
                               b"ftp.c\0" as *const u8 as *const libc::c_char,
                           ) as *mut libc::c_char;
                       }
                   }
                   
                    if dir.is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                    /* Reply format is like
          257<space>[rubbish]"<directory-name>"<space><commentary> and the
          RFC959 says

          The directory name can contain any character; embedded
          double-quotes should be escaped by double-quotes (the
          "quote-doubling" convention).
       */
        /* scan for the first double-quote for non-standard responses */
                    while ptr
                        < &mut *((*data).state.buffer).offset(buf_size as isize)
                            as *mut libc::c_char
                        && *ptr as i32 != '\n' as i32
                       && *ptr as i32 != '\0' as i32
                        && *ptr as i32 != '"' as i32
                    {
                        ptr = ptr.offset(1);
                    }
                    if '"' as i32 == *ptr as i32 {
                       /* it started good */
                        let mut store: *mut libc::c_char = 0 as *mut libc::c_char;
                        ptr = ptr.offset(1);
                        store = dir;
                        while *ptr != 0 {
                            if '"' as i32 == *ptr as i32 {
                                if '"' as i32
                                    == *ptr.offset(1 as isize) as i32
                                { /* "quote-doubling" */
                                    *store = *ptr.offset(1 as isize);
                                    ptr = ptr.offset(1);
                                } else {
                                    /* end of path */
                                    entry_extracted = 1 as i32 != 0;
                                    break;/* get out of this loop */
                                }
                            } else {
                                *store = *ptr; /* null-terminate */
                            }
                            store = store.offset(1);
                            ptr = ptr.offset(1);
                        }
                       *store = '\0' as i32 as libc::c_char;
                    }
                    if entry_extracted {
                        /* If the path name does not look like an absolute path (i.e.: it
            does not start with a '/'), we probably need some server-dependent
            adjustments. For example, this is the case when connecting to
            an OS400 FTP server: this server supports two name syntaxes,
            the default one being incompatible with standard paths. In
            addition, this server switches automatically to the regular path
            syntax when one is encountered in a command: this results in
            having an entrypath in the wrong syntax when later used in CWD.
              The method used here is to check the server OS: we do it only
            if the path name looks strange to minimize overhead on other
            systems. */
                        if ((*ftpc).server_os).is_null()
                            && *dir.offset(0 as isize) as i32 != '/' as i32
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
                                    2899 as i32,
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
                                2902 as i32,
                                b"ftp.c\0" as *const u8 as *const libc::c_char,
                            );
                           //  let ref mut fresh33 = (*ftpc).entrypath;
                            (*ftpc).entrypath = 0 as *mut libc::c_char;
                           //  let ref mut fresh34 = (*ftpc).entrypath;
                            (*ftpc).entrypath = dir;/* remember this */
                            Curl_infof(
                                data,
                                b"Entry path is '%s'\0" as *const u8 as *const libc::c_char,
                                (*ftpc).entrypath,
                            );
                           //  let ref mut fresh35 = (*data).state.most_recent_ftp_entrypath;
                           /* also save it where getinfo can access it: */
                            (*data).state.most_recent_ftp_entrypath = (*ftpc).entrypath;
                            #[cfg(not(DEBUGBUILD))]
                            _state(data, FTP_SYST);

                            #[cfg(DEBUGBUILD)]
                            _state(data, FTP_SYST, 2907 as i32);
                            current_block_187 = 10490607306284298299;
                        } else {
                           #[cfg(not(CURLDEBUG))]
                           Curl_cfree.expect("non-null function pointer")(
                               (*ftpc).entrypath as *mut libc::c_void,
                           );
                           #[cfg(CURLDEBUG)]
                            curl_dbg_free(
                                (*ftpc).entrypath as *mut libc::c_void,
                                2911 as i32,
                                b"ftp.c\0" as *const u8 as *const libc::c_char,
                            );
                           //  let ref mut fresh36 = (*ftpc).entrypath;
                            (*ftpc).entrypath = 0 as *mut libc::c_char;
                           //  let ref mut fresh37 = (*ftpc).entrypath;
                            (*ftpc).entrypath = dir;
                            Curl_infof(
                                data,
                                b"Entry path is '%s'\0" as *const u8 as *const libc::c_char,
                                (*ftpc).entrypath,
                            );
                           //  let ref mut fresh38 = (*data).state.most_recent_ftp_entrypath;
                            /* also save it where getinfo can access it: */
                            (*data).state.most_recent_ftp_entrypath = (*ftpc).entrypath;
                           current_block_187 = 17917672080766325409;
                        }
                    } else {
                       #[cfg(not(CURLDEBUG))]
                       Curl_cfree.expect("non-null function pointer")(dir as *mut libc::c_void);

                       #[cfg(CURLDEBUG)]
                        curl_dbg_free(
                            dir as *mut libc::c_void,
                            2919 as i32,
                            b"ftp.c\0" as *const u8 as *const libc::c_char,
                        );
                        /* couldn't get the path */
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
                        _state(data, FTP_STOP, 2923 as i32); /* we are done with the CONNECT phase! */
                        #[cfg(DEBUGBUILD)]
                        Curl_infof(
                            data,
                            b"protocol connect phase DONE\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
            }
            10 => {
                if ftpcode == 215 as i32 {
                    let mut ptr_0: *mut libc::c_char = &mut *((*data).state.buffer)
                        .offset(4 as isize)
                        as *mut libc::c_char;
                    let mut os: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut store_0: *mut libc::c_char = 0 as *mut libc::c_char;
                    match () {
                       #[cfg(not(CURLDEBUG))]
                       _ => {
                           os = Curl_cmalloc.expect("non-null function pointer")(
                               nread.wrapping_add(1 as u64),
                           ) as *mut libc::c_char;
                       }
                       #[cfg(CURLDEBUG)]
                       _ => {
                           os = curl_dbg_malloc(
                               nread.wrapping_add(1 as u64),
                               2933 as i32,
                               b"ftp.c\0" as *const u8 as *const libc::c_char,
                           ) as *mut libc::c_char;
                       }
                   }
                    
                    if os.is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                    while *ptr_0 as i32 == ' ' as i32 {
                        ptr_0 = ptr_0.offset(1);
                    }
                    store_0 = os;
                    /* Reply format is like
          215<space><OS-name><space><commentary>
       */
                    while *ptr_0 as i32 != 0 && *ptr_0 as i32 != ' ' as i32 {
                       //  let fresh39 = ptr_0;
                        ptr_0 = ptr_0.offset(1);
                       //  let fresh40 = store_0;
                        store_0 = store_0.offset(1);
                        store_0 = ptr_0;/* null-terminate */
                    }
                     /* Check for special servers here. */
                   *store_0 = '\0' as libc::c_char;
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
                                2952 as i32,
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
                            2956 as i32,
                            b"ftp.c\0" as *const u8 as *const libc::c_char,
                        ); /* remember target server OS */
                       //  let ref mut fresh41 = (*ftpc).server_os;
                        (*ftpc).server_os = 0 as *mut libc::c_char;
                       //  let ref mut fresh42 = (*ftpc).server_os;
                        (*ftpc).server_os = os;
                        #[cfg(not(DEBUGBUILD))]
                        _state(data, FTP_NAMEFMT);

   #[cfg(DEBUGBUILD)]
                        _state(data, FTP_NAMEFMT, 2958 as i32);
                        current_block_187 = 10490607306284298299;

                    } else {
                       #[cfg(not(CURLDEBUG))]
                       Curl_cfree.expect("non-null function pointer")(
                           (*ftpc).server_os as *mut libc::c_void,
                       );
   #[cfg(CURLDEBUG)]
                        curl_dbg_free(
                            (*ftpc).server_os as *mut libc::c_void,
                            2963 as i32,
                            b"ftp.c\0" as *const u8 as *const libc::c_char,
                        );/* Nothing special for the target server. */
                        /* remember target server OS */
                       //  let ref mut fresh43 = (*ftpc).server_os;
                        (*ftpc).server_os = 0 as *mut libc::c_char;
                       //  let ref mut fresh44 = (*ftpc).server_os;
                        (*ftpc).server_os = os;
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
                        _state(data, FTP_STOP, 2970 as i32);/* we are done with the CONNECT phase! */
                        #[cfg(DEBUGBUILD)]
                        Curl_infof(
                            data,
                            b"protocol connect phase DONE\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
            }
            11 => {
                if ftpcode == 250 as i32 {  /* Name format change successful: reload initial path. */
                    ftp_state_pwd(data, conn);
                } else {
                   #[cfg(not(DEBUGBUILD))]
                   _state(data, FTP_STOP);

   #[cfg(DEBUGBUILD)]
                    _state(data, FTP_STOP, 2981 as i32);/* we are done with the CONNECT phase! */
                    #[cfg(DEBUGBUILD)]
                    Curl_infof(
                        data,
                        b"protocol connect phase DONE\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            12 | 15 | 13 | 14 => {
                if ftpcode >= 400 as i32 && (*ftpc).count2 == 0 { /* failure response code, and not allowed to fail */
                    Curl_failf(
                        data,
                        b"QUOT command failed with %03d\0" as *const u8 as *const libc::c_char,
                        ftpcode,
                    );
                    result = CURLE_QUOTE_ERROR;
                } else {
                    result = ftp_state_quote(data, 0 as i32 != 0, (*ftpc).state);
                }
            }
            16 => {
                if ftpcode / 100 as i32 != 2 as i32 {/* failure to CWD there */
                    if (*data).set.ftp_create_missing_dirs != 0
                        && (*ftpc).cwdcount != 0
                        && (*ftpc).count2 == 0
                    { /* try making it */
                       //  let ref mut fresh45 = (*ftpc).count2;
                        (*ftpc).count2 += 1;/* counter to prevent CWD-MKD loops */
                        result = Curl_pp_sendf(
                            data,
                            &mut (*ftpc).pp as *mut pingpong,
                            b"MKD %s\0" as *const u8 as *const libc::c_char,
                            *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as i32) as isize),
                        );
                        if result as u64 == 0 {
                           #[cfg(not(DEBUGBUILD))]
                           _state(data, FTP_MKD);

   #[cfg(DEBUGBUILD)]
                            _state(data, FTP_MKD, 3008 as i32);
                        }
                    } else { /* return failure */
                        Curl_failf(
                            data,
                            b"Server denied you to change to the given directory\0" as *const u8
                                as *const libc::c_char,
                        ); /* don't remember this path as we failed
                        to enter it */
                        (*ftpc).cwdfail = 1 as i32 != 0;
                        result = CURLE_REMOTE_ACCESS_DENIED;
                    }
                } else { /* success */
                    (*ftpc).count2 = 0 as i32;
                   //  let ref mut fresh46 = (*ftpc).cwdcount;
                    (*ftpc).cwdcount += 1;
                    if (*ftpc).cwdcount <= (*ftpc).dirdepth {
                        /* send next CWD */
                        result = Curl_pp_sendf(
                            data,
                            &mut (*ftpc).pp as *mut pingpong,
                            b"CWD %s\0" as *const u8 as *const libc::c_char,
                            *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as i32) as isize),
                        );
                    } else {
                        result = ftp_state_mdtm(data);
                    }
                }
            }
            17 => {
                if ftpcode / 100 as i32 != 2 as i32 && {
                    /* failure to MKD the dir */
                   //  let ref mut fresh47 = (*ftpc).count3;
                    let fresh48 = (*ftpc).count3;
                    (*ftpc).count3 = (*ftpc).count3 - 1;
                    fresh48 == 0
                } {
                    Curl_failf(
                        data,
                        b"Failed to MKD dir: %03d\0" as *const u8 as *const libc::c_char,
                        ftpcode,
                    );
                    result = CURLE_REMOTE_ACCESS_DENIED;
                } else {
                    /* send CWD */
                   #[cfg(not(DEBUGBUILD))]
                   _state(data, FTP_CWD);

   #[cfg(DEBUGBUILD)]
                    _state(data, FTP_CWD, 3037 as i32);
                    result = Curl_pp_sendf(
                        data,
                        &mut (*ftpc).pp as *mut pingpong,
                        b"CWD %s\0" as *const u8 as *const libc::c_char,
                        *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as i32) as isize),
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
                /* there only is this one standard OK return code. */
                if ftpcode != 200 as i32 {
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
                /* internal error */
               #[cfg(not(DEBUGBUILD))]
               _state(data, FTP_STOP);

   #[cfg(DEBUGBUILD)]
                _state(data, FTP_STOP, 3096 as i32);
            }/* if(ftpcode) */
        }
    }
    return result;
   }
}
/* called repeatedly until done from multi.c */

 
extern "C" fn ftp_multi_statemach(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
   unsafe{
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut result: CURLcode = Curl_pp_statemach(
        data,
        &mut (*ftpc).pp,
        0 as i32 != 0,
        0 as i32 != 0,
    );
     /* Check for the state outside of the Curl_socket_check() return code checks
    since at times we are in fact already in this state when this function
    gets called. */
    *done = if (*ftpc).state as u32 == FTP_STOP as u32 {
        1 as i32
    } else {
        0 as i32
    } != 0;
    return result;
   }
}

extern "C" fn ftp_block_statemach(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
   unsafe{
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    let mut result: CURLcode = CURLE_OK;
   // 解决clippy错误
   loop {
       if (*ftpc).state as u32 == FTP_STOP as u32 {
           break;
       }
       // while (*ftpc).state as u32 != FTP_STOP as i32 as u32 {
        result = Curl_pp_statemach(data, pp, 1 as i32 != 0, 1 as i32 != 0);
        if result as u64 != 0 {
            break;
        }
    }
    return result;
   }
}

/*
 * ftp_connect() should do everything that is to be considered a part of
 * the connection phase.
 *
 * The variable 'done' points to will be TRUE if the protocol-layer connect
 * phase is done when this function returns, or FALSE if not.
 *
 */
extern "C" fn ftp_connect(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode { /* see description above */
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     *done = 0 as i32 != 0;/* default to not done yet */
     #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
     Curl_conncontrol(conn, 0 as i32);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
     Curl_conncontrol(
         conn,
         0 as i32,
         b"FTP default\0" as *const u8 as *const libc::c_char,
     );/* We always support persistent connections on ftp */
     (*pp).response_time = (120 as i32 * 1000 as i32) as timediff_t;
    //  let ref mut fresh49 = (*pp).statemachine;
     (*pp).statemachine = Some(
         ftp_statemachine as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
     );
    //  let ref mut fresh50 = (*pp).endofresp;
     (*pp).endofresp = Some(
         ftp_endofresp
             as unsafe extern "C" fn(
                 *mut Curl_easy,
                 *mut connectdata,
                 *mut libc::c_char,
                 size_t,
                 *mut i32,
             ) -> bool,
     );
     if (*(*conn).handler).flags & ((1 as i32) << 0 as i32) as u32 != 0 {
        // match () {
        //     #[cfg(USE_SSL)]
        //     _ => {
        //         result = Curl_ssl_connect(data, conn, 0 as i32);
        //     }
        //     #[cfg(not(USE_SSL))]
        //     _ => {
        //         result = CURLE_NOT_BUILT_IN;
        //     }
        // }
         /* BLOCKING */
         result = Curl_ssl_connect(data, conn, 0 as i32);
         if result as u64 != 0 {
             return result;
         }
        //  let ref mut fresh51 = (*conn).bits;
         ((*conn).bits).set_ftp_use_control_ssl(1 as bit);
     }
     Curl_pp_setup(pp);/* once per transfer */
     Curl_pp_init(data, pp); /* init the generic pingpong data */
     #[cfg(not(DEBUGBUILD))]
     _state(data, FTP_WAIT220);
/* When we connect, we start in the state where we await the 220
     response */
    #[cfg(DEBUGBUILD)]
     _state(data, FTP_WAIT220, 3173 as i32);
     result = ftp_multi_statemach(data, done);
     return result;
    }
 }

/***********************************************************************
 *
 * ftp_done()
 *
 * The DONE function. This does what needs to be done after a single DO has
 * performed.
 *
 * Input argument is already checked for validity.
 */
extern "C" fn ftp_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
   unsafe{
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    let mut nread: ssize_t = 0;
    let mut ftpcode: i32 = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pathLen: size_t = 0 as size_t;
    if ftp.is_null() {
        return CURLE_OK;
    }
    let mut current_block_5: u64;
    match status as u32 {
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
       8000488408776534573 => {/* by default, an error means the control connection is
           wedged and should not be used anymore */
            (*ftpc).ctl_valid = 0 as i32 != 0;
            (*ftpc).cwdfail = 1 as i32 != 0;/* set this TRUE to prevent us to remember the
            current path, as this connection is going */
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as i32); /* use the already set error code */

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as i32,
                b"FTP ended with bad error code\0" as *const u8 as *const libc::c_char,
            );
            result = status;
        }
        _ => {}
    }
    if ((*data).state).wildcardmatch() != 0 {
        if ((*data).set.chunk_end).is_some() && !((*ftpc).file).is_null() {
            Curl_set_in_callback(data, 1 as i32 != 0);
            ((*data).set.chunk_end).expect("non-null function pointer")((*data).wildcard.customptr);
            Curl_set_in_callback(data, 0 as i32 != 0);
        }
        (*ftpc).known_filesize = -(1 as i32) as curl_off_t;
    }
    if result as u64 == 0 {
        result = Curl_urldecode(
            data,
            (*ftp).path,
            0 as size_t,
            &mut rawPath,
            &mut pathLen,
            REJECT_CTRL,
        );
    } /* get the url-decoded "raw" path */
    if result as u64 != 0 {
        /* We can limp along anyway (and should try to since we may already be in
    * the error path) */
        (*ftpc).ctl_valid = 0 as i32 != 0;/* mark control connection as bad */
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 1 as i32);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            1 as i32,
            b"FTP: out of memory!\0" as *const u8 as *const libc::c_char,
        );/* mark for connection closure */
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void);
/* no path remembering */
   #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*ftpc).prevpath as *mut libc::c_void,
            3256 as i32,
            b"ftp.c\0" as *const u8 as *const libc::c_char,
        );
       //  let ref mut fresh52 = (*ftpc).prevpath;
        (*ftpc).prevpath = 0 as *mut libc::c_char;
    } else {
       /* remember working directory for connection reuse */
        if (*data).set.ftp_filemethod as u32
            == FTPFILE_NOCWD as u32
            && *rawPath.offset(0 as isize) as i32 == '/' as i32
        {/* full path => no CWDs happened => keep ftpc->prevpath */
           #[cfg(not(CURLDEBUG))]
           Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

   #[cfg(CURLDEBUG)]
            curl_dbg_free(
                rawPath as *mut libc::c_void,
                3261 as i32,
                b"ftp.c\0" as *const u8 as *const libc::c_char,
            );
        } else {
           #[cfg(not(CURLDEBUG))]
           Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void);
           #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*ftpc).prevpath as *mut libc::c_void,
                3263 as i32,
                b"ftp.c\0" as *const u8 as *const libc::c_char,
            );
            if !(*ftpc).cwdfail {
                if (*data).set.ftp_filemethod as u32
                    == FTPFILE_NOCWD as u32
                {
                    pathLen = 0 as size_t;/* relative path => working directory is FTP home */
                } else {
                    pathLen =
                        (pathLen as u64).wrapping_sub(if !((*ftpc).file).is_null() {
                            strlen((*ftpc).file)
                        } else {
                            0 as u64
                        }) as size_t;/* file is url-decoded */
                }
               *rawPath.offset(pathLen as isize) = '\0' as libc::c_char;
               //  let ref mut fresh53 = (*ftpc).prevpath;
                (*ftpc).prevpath = rawPath;
            } else {
               #[cfg(not(CURLDEBUG))]
               Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

   #[cfg(CURLDEBUG)]
                curl_dbg_free(
                    rawPath as *mut libc::c_void,
                    3275 as i32,
                    b"ftp.c\0" as *const u8 as *const libc::c_char,
                );
               //  let ref mut fresh54 = (*ftpc).prevpath;
                (*ftpc).prevpath = 0 as *mut libc::c_char;/* no path */
            }
        }
        if !((*ftpc).prevpath).is_null() {
            Curl_infof(
                data,
                b"Remembering we are in dir \"%s\"\0" as *const u8 as *const libc::c_char,
                (*ftpc).prevpath,
            );
        }
    }/* free the dir tree and file parts */
    freedirs(ftpc);
    /* shut down the socket to inform the server we're done */
    if (*conn).sock[1 as usize] != -(1 as i32) {
        if result as u64 == 0
            && (*ftpc).dont_check as i32 != 0
            && (*data).req.maxdownload > 0 as i64
        { /* partial download completed */
            result = Curl_pp_sendf(
                data,
                pp,
                b"%s\0" as *const u8 as *const libc::c_char,
                b"ABOR\0" as *const u8 as *const libc::c_char,
            ); /* connection closure */
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failure sending ABOR command: %s\0" as *const u8 as *const libc::c_char,
                    curl_easy_strerror(result),
                );
                (*ftpc).ctl_valid = 0 as i32 != 0;/* mark control connection as bad */
                #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                Curl_conncontrol(conn, 1 as i32);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                Curl_conncontrol(
                    conn,
                    1 as i32,
                    b"ABOR command failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        if ((*conn).ssl[1 as usize]).use_0() != 0 {
            /* The secondary socket is using SSL so we must close down that part
        first before we close the socket for real */
           #[cfg(USE_SSL)]
            Curl_ssl_close(data, conn, 1 as i32);
        }/* Note that we keep "use" set to TRUE since that (next) connection is
        still requested to use SSL */
        close_secondarysocket(data, conn);
    }
    if result as u64 == 0
        && (*ftp).transfer as u32 == PPTRANSFER_BODY as u32
        && (*ftpc).ctl_valid as i32 != 0
        && (*pp).pending_resp as i32 != 0
        && !premature
    {/*
    * Let's see what the server says about the transfer we just performed,
    * but lower the timeout as sometimes this connection has died while the
    * data has been transferred. This happens when doing through NATs etc that
    * abandon old silent connections.
    */
        let mut old_time: timediff_t = (*pp).response_time;
        (*pp).response_time = (60 as i32 * 1000 as i32) as timediff_t;/* give it only a minute for now */
        (*pp).response = Curl_now();/* timeout relative now */
        result = Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
        (*pp).response_time = old_time;/* set this back to previous value */
        if nread == 0
            && CURLE_OPERATION_TIMEDOUT as u32 == result as u32
        {
            Curl_failf(
                data,
                b"control connection looks dead\0" as *const u8 as *const libc::c_char,
            );
            (*ftpc).ctl_valid = 0 as i32 != 0;/* mark control connection as bad */
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as i32);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as i32,
                b"Timeout or similar in FTP DONE operation\0" as *const u8 as *const libc::c_char,
            ); /* close */
        }
        if result as u64 != 0 {
           #[cfg(not(CURLDEBUG))]
           Curl_cfree.expect("non-null function pointer")((*ftp).pathalloc as *mut libc::c_void);

   #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*ftp).pathalloc as *mut libc::c_void,
                3340 as i32,
                b"ftp.c\0" as *const u8 as *const libc::c_char,
            );
           //  let ref mut fresh55 = (*ftp).pathalloc;
            (*ftp).pathalloc = 0 as *mut libc::c_char;
            return result;
        }
        if (*ftpc).dont_check as i32 != 0
            && (*data).req.maxdownload > 0 as i64
        { /* we have just sent ABOR and there is no reliable way to check if it was
           * successful or not; we have to close the connection now */
            Curl_infof(
                data,
                b"partial download completed, closing connection\0" as *const u8
                    as *const libc::c_char,
            );
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as i32);

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as i32,
                b"Partial download with no ability to check\0" as *const u8 as *const libc::c_char,
            );
            return result;
        }
        if !(*ftpc).dont_check {
           /* 226 Transfer complete, 250 Requested file action okay, completed. */
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
    if !(result as u32 != 0 || premature as i32 != 0) {
       /* the response code from the transfer showed an error already so no
      use checking further */
        if ((*data).set).upload() != 0 {
            if -(1 as i32) as i64 != (*data).state.infilesize
                && (*data).state.infilesize != (*data).req.writebytecount
                && ((*data).set).crlf() == 0
                && (*ftp).transfer as u32 == PPTRANSFER_BODY as u32
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
               -(1 as i32) as i64 != (*data).req.size
            && (*data).req.size != (*data).req.bytecount
            && (*data).req.size + (*data).state.crlf_conversions != (*data).req.bytecount
            && (*data).req.maxdownload != (*data).req.bytecount
           } else {
               -(1 as i32) as i64 != (*data).req.size
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
            && (*data).req.size > 0 as i64
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
    (*ftpc).dont_check = 0 as i32 != 0;
    if status as u64 == 0 && result as u64 == 0 && !premature && !((*data).set.postquote).is_null()
    {
        result = ftp_sendquote(data, conn, (*data).set.postquote);
    }
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")((*ftp).pathalloc as *mut libc::c_void);

   #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*ftp).pathalloc as *mut libc::c_void,
        3416 as i32,
        b"ftp.c\0" as *const u8 as *const libc::c_char,
    );
   //  let ref mut fresh56 = (*ftp).pathalloc;
    (*ftp).pathalloc = 0 as *mut libc::c_char;
    return result;
   }
}

/***********************************************************************
 *
 * ftp_sendquote()
 *
 * Where a 'quote' means a list of custom commands to send to the server.
 * The quote list is passed as an argument.
 *
 * BLOCKING
 */
extern "C" fn ftp_sendquote(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut quote: *mut curl_slist,
) -> CURLcode {
   unsafe{
    let mut item: *mut curl_slist = 0 as *mut curl_slist;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    item = quote;
    while !item.is_null() {
        if !((*item).data).is_null() {
            let mut nread: ssize_t = 0;
            let mut cmd: *mut libc::c_char = (*item).data;
            let mut acceptfail: bool = 0 as i32 != 0;
            let mut result: CURLcode = CURLE_OK;
            let mut ftpcode: i32 = 0 as i32;
            /* if a command starts with an asterisk, which a legal FTP command never
        can, the command will be allowed to fail without it causing any
        aborts or cancels etc. It will cause libcurl to act as if the command
        is successful, whatever the server reponds. */
            if *cmd.offset(0 as isize) as i32 == '*' as i32 {
                cmd = cmd.offset(1);
                acceptfail = 1 as i32 != 0;
            }
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"%s\0" as *const u8 as *const libc::c_char,
                cmd,
            );
            if result as u64 == 0 {
                (*pp).response = Curl_now(); /* timeout relative now */
                result = Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
            }
            if result as u64 != 0 {
                return result;
            }
            if !acceptfail && ftpcode >= 400 as i32 {
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
}
 /***********************************************************************
 *
 * ftp_need_type()
 *
 * Returns TRUE if we in the current situation should send TYPE
 */
 
extern "C" fn ftp_need_type(
    mut conn: *mut connectdata,
    mut ascii_wanted: bool,
) -> i32 {
   unsafe{
    return ((*conn).proto.ftpc.transfertype as i32
        != (if ascii_wanted as i32 != 0 {
            'A' as i32
        } else {
            'I' as i32
        })) as i32;
       }
}
/***********************************************************************
 *
 * ftp_nb_type()
 *
 * Set TYPE. We only deal with ASCII or BINARY so this function
 * sets one of them.
 * If the transfer type is not sent, simulate on OK response in newstate
 */
extern "C" fn ftp_nb_type(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut ascii: bool,
    mut newstate: ftpstate,
) -> CURLcode {
   unsafe{
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut result: CURLcode = CURLE_OK;
    let mut want: libc::c_char = (if ascii as i32 != 0 {
        'A' as i32
    } else {
        'I' as i32
    }) as libc::c_char;
    if (*ftpc).transfertype as i32 == want as i32 {
       #[cfg(not(DEBUGBUILD))]
       _state(data, newstate);
/* keep track of our current transfer type */
   #[cfg(DEBUGBUILD)]
       _state(data, newstate, 3506 as i32);
        return ftp_state_type_resp(data, 200 as i32, newstate);
    }
    result = Curl_pp_sendf(
        data,
        &mut (*ftpc).pp as *mut pingpong,
        b"TYPE %c\0" as *const u8 as *const libc::c_char,
        want as i32,
    );
    if result as u64 == 0 {
       #[cfg(not(DEBUGBUILD))]
       _state(data, newstate);

   #[cfg(DEBUGBUILD)]
        _state(data, newstate, 3512 as i32);
        (*ftpc).transfertype = want;
    }
    return result;
   }
}


/***************************************************************************
 *
 * ftp_pasv_verbose()
 *
 * This function only outputs some informationals about this second connection
 * when we've issued a PASV command before and thus we have connected to a
 * possibly new IP address.
 *
 */
#[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
extern "C" fn ftp_pasv_verbose(
     mut data: *mut Curl_easy,
     mut ai: *mut Curl_addrinfo,
     mut newhost: *mut libc::c_char,/* ascii version */
     mut port: i32,
 ) {
    unsafe{
     let mut buf: [libc::c_char; 256] = [0; 256];
     Curl_printable_address(
         ai,
         buf.as_mut_ptr(),
         ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
     );
     Curl_infof(
         data,
         b"Connecting to %s (%s) port %d\0" as *const u8 as *const libc::c_char,
         newhost,
         buf.as_mut_ptr(),
         port,
     );
    }
 }

/*
 * ftp_do_more()
 *
 * This function shall be called when the second FTP (data) connection is
 * connected.
 *
 * 'complete' can return 0 for incomplete, 1 for done and -1 for go back
 * (which basically is only for when PASV is being sent to retry a failed
 * EPSV).
 */
extern "C" fn ftp_do_more(
    mut data: *mut Curl_easy,
    mut completep: *mut i32,
) -> CURLcode {
   unsafe{
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut result: CURLcode = CURLE_OK;
    let mut connected: bool = 0 as i32 != 0;
    let mut complete: bool = 0 as i32 != 0;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    /* the ftp struct is inited in ftp_connect() */
    /* if the second connection isn't done yet, wait for it */
    if !(*conn).bits.tcpconnect[1 as i32 as usize] {
       #[cfg(not(CURL_DISABLE_PROXY))]
        if Curl_connect_ongoing(conn) {
           /* As we're in TUNNEL_CONNECT state now, we know the proxy name and port
        aren't used so we blank their arguments. */
            result = Curl_proxyCONNECT(
                data,
                1 as i32,
                0 as *const libc::c_char,
                0 as i32,
            );
            return result;
        }
        result = Curl_is_connected(data, conn, 1 as i32, &mut connected);
         /* Ready to do more? */
        if connected {
           #[cfg(DEBUGBUILD)]
            Curl_infof(
                data,
                b"DO-MORE connected phase starts\0" as *const u8 as *const libc::c_char,
            );
        } else {
            if result as u32 != 0 && (*ftpc).count1 == 0 as i32 {
                *completep = -(1 as i32);
                /* go back to DOING please */
       /* this is a EPSV connect failing, try PASV instead */
                return ftp_epsv_disable(data, conn);
            }
            return result;
        }
    }
   match () {
       #[cfg(not(CURL_DISABLE_PROXY))]
       _ => {
    result = Curl_proxy_connect(data, 1 as i32);
    if result as u64 != 0 {
        return result;
    }
    if (*conn).http_proxy.proxytype as u32
        == CURLPROXY_HTTPS as u32
        && !(*conn).bits.proxy_ssl_connected[1 as usize]
    {
        return result;
    }
    if ((*conn).bits).tunnel_proxy() as i32 != 0
        && ((*conn).bits).httpproxy() as i32 != 0
        && Curl_connect_ongoing(conn) as i32 != 0
    {
        return result;
    }
       }
       #[cfg(CURL_DISABLE_PROXY)]
       _ => { }
   }
    if (*ftpc).state as u64 != 0 {
       /* already in a state so skip the initial commands.
      They are only done to kickstart the do_more state */
        result = ftp_multi_statemach(data, &mut complete);
        *completep = complete as i32;
        /* if we got an error or if we don't wait for a data connection return
      immediately */
        if result as u32 != 0 || !(*ftpc).wait_data_conn {
            return result;
        }
        /* if we reach the end of the FTP state machine here, *complete will be
      TRUE but so is ftpc->wait_data_conn, which says we need to wait for the
      data connection and therefore we're not actually complete */
        *completep = 0 as i32;
    }
    if (*ftp).transfer as u32 <= PPTRANSFER_INFO as u32 {
        /* a transfer is about to take place, or if not a file name was given
      so we'll do a SIZE on it later and then we need the right TYPE first */
        if (*ftpc).wait_data_conn as i32 == 1 as i32 {
            let mut serv_conned: bool = false;
            result = ReceivedServerConnect(data, &mut serv_conned);
            if result as u64 != 0 {
                return result;/* Failed to accept data connection */
            }
            if serv_conned {
                /* It looks data connection is established */
                result = AcceptServerConnect(data);
                (*ftpc).wait_data_conn = 0 as i32 != 0;
                if result as u64 == 0 {
                    result = InitiateTransfer(data);
                }
                if result as u64 != 0 {
                    return result;
                }
                *completep = 1 as i32;/* this state is now complete when the server has
                connected back to us */
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
                /* if we reach the end of the FTP state machine here, *complete will be
          TRUE but so is ftpc->wait_data_conn, which says we need to wait for
          the data connection and therefore we're not actually complete */
                *completep = 0 as i32;
            } else {
                /* download */
                *completep = complete as i32;
            }
        } else {
            (*ftp).downloadsize = -(1 as i32) as curl_off_t;/* unknown as of yet */
            result = Curl_range(data);
            if result as u32 == CURLE_OK as u32
                && (*data).req.maxdownload >= 0 as i64
            { /* Don't check for successful transfer */
                (*ftpc).dont_check = 1 as i32 != 0;
            }
            if !(result as u64 != 0) {
                if ((*data).state).list_only() as i32 != 0 || ((*ftpc).file).is_null() {
                     /* The specified path ends with a slash, and therefore we think this
          is a directory that is requested, use LIST. But before that we
          need to set ASCII transfer mode. */
                   if (*ftp).transfer as u32
                        == PPTRANSFER_BODY as u32
                    {
                        /* But only if a body transfer was requested. */
                        result = ftp_nb_type(data, conn, 1 as i32 != 0, FTP_LIST_TYPE);
                        if result as u64 != 0 {
                            return result;
                        }
                        /* otherwise just fall through */
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
            *completep = complete as i32;
        }
        return result;
    }
     /* no data to transfer */
    Curl_setup_transfer(
        data,
        -(1 as i32),
        -(1 as i32) as curl_off_t,
        0 as i32 != 0,
        -(1 as i32),
    );
    if !(*ftpc).wait_data_conn {
        /* no waiting for the data connection so this is now complete */
        *completep = 1 as i32;
        #[cfg(DEBUGBUILD)]
        Curl_infof(
            data,
            b"DO-MORE phase ends with %d\0" as *const u8 as *const libc::c_char,
            result as i32,
        );
    }
    return result;
   }
}

/***********************************************************************
*
* ftp_perform()
*
* This is the actual DO function for FTP. Get a file/directory according to
* the options previously setup.
*/
extern "C" fn ftp_perform(
    mut data: *mut Curl_easy,
    mut connected: *mut bool,/* connect status after PASV / PORT */
    mut dophase_done: *mut bool,
) -> CURLcode {
   unsafe{
        /* this is FTP and no proxy */
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    #[cfg(DEBUGBUILD)]
    Curl_infof(
        data,
        b"DO phase starts\0" as *const u8 as *const libc::c_char,
    );
    if ((*data).set).opt_no_body() != 0 {
        /* requested no body means no transfer... */
        let mut ftp: *mut FTP = (*data).req.p.ftp;
        (*ftp).transfer = PPTRANSFER_INFO;
    }
    *dophase_done = 0 as i32 != 0;/* not done yet */
    /* start the first command in the DO phase */
    result = ftp_state_quote(data, 1 as i32 != 0, FTP_QUOTE);
    if result as u64 != 0 {
        return result;
    }
    /* run the state-machine */
    result = ftp_multi_statemach(data, dophase_done);
    *connected = (*conn).bits.tcpconnect[1 as usize];
    Curl_infof(
        data,
        b"ftp_perform ends with SECONDARY: %d\0" as *const u8 as *const libc::c_char,
        *connected as i32,
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
}

extern "C" fn wc_data_dtor(mut ptr: *mut libc::c_void) {
    unsafe{
     let mut ftpwc: *mut ftp_wc = ptr as *mut ftp_wc;
     if !ftpwc.is_null() && !((*ftpwc).parser).is_null() {
         Curl_ftp_parselist_data_free(&mut (*ftpwc).parser);
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(ftpwc as *mut libc::c_void);

    #[cfg(CURLDEBUG)]
     curl_dbg_free(
         ftpwc as *mut libc::c_void,
         3764 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
    }
 }
 
 extern "C" fn init_wc_data(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
     let mut last_slash: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut path: *mut libc::c_char = (*ftp).path;
     let mut wildcard: *mut WildcardData = &mut (*data).wildcard;
     let mut result: CURLcode = CURLE_OK;
     let mut ftpwc: *mut ftp_wc = 0 as *mut ftp_wc;
     last_slash = strrchr((*ftp).path, '/' as i32);
     if !last_slash.is_null() {
         last_slash = last_slash.offset(1);
        if *last_slash.offset(0 as isize) as i32 == '\0' as i32 {
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
                    3784 as i32,
                    b"ftp.c\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        
         if ((*wildcard).pattern).is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
        *last_slash.offset(0 as isize) = '\0' as libc::c_char;
     } else if *path.offset(0 as isize) != 0 {
         match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                (*wildcard).pattern = Curl_cstrdup.expect("non-null function pointer")(path);

            }
            #[cfg(CURLDEBUG)]
            _ => {
                (*wildcard).pattern = curl_dbg_strdup(
                    path,
                    3791 as i32,
                    b"ftp.c\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        
         if ((*wildcard).pattern).is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
        *path.offset(0 as isize) = '\0' as libc::c_char; /* cut file from path */
     } else {
         (*wildcard).state = CURLWC_CLEAN;/* only list */
         result = ftp_parse_url_path(data);
         return result;
     }
     match () {
        #[cfg(not(CURLDEBUG))]
        _ => {/* program continues only if URL is not ending with slash, allocate needed
            resources for wildcard transfer */
       
         /* allocate ftp protocol specific wildcard data */
            ftpwc = Curl_ccalloc.expect("non-null function pointer")(
                1 as size_t,
                ::std::mem::size_of::<ftp_wc>() as u64,
            ) as *mut ftp_wc;
        }
        #[cfg(CURLDEBUG)]
        _ => {
            ftpwc = curl_dbg_calloc(
                1 as size_t,
                ::std::mem::size_of::<ftp_wc>() as u64,
                3807 as i32,
                b"ftp.c\0" as *const u8 as *const libc::c_char,
            ) as *mut ftp_wc;
        }
    }
     'fail:loop{ 
     if ftpwc.is_null() {
         result = CURLE_OUT_OF_MEMORY;
         break 'fail;
     } else {/* INITIALIZE parselist structure */
        //  let ref mut fresh59 = (*ftpwc).parser;
         (*ftpwc).parser = Curl_ftp_parselist_data_alloc();
         if ((*ftpwc).parser).is_null() {
             result = CURLE_OUT_OF_MEMORY;
             break 'fail;
         } else {
            //  let ref mut fresh60 = (*wildcard).protdata;
             (*wildcard).protdata = ftpwc as *mut libc::c_void;
            //  let ref mut fresh61 = (*wildcard).dtor;
             (*wildcard).dtor = Some(wc_data_dtor as unsafe extern "C" fn(*mut libc::c_void) -> ());
             if (*data).set.ftp_filemethod as u32
                 == FTPFILE_NOCWD as u32
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
                            3833 as i32,
                            b"ftp.c\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
                
                 if ((*wildcard).path).is_null() {
                     result = CURLE_OUT_OF_MEMORY;
                     break 'fail;
                 } else {
                    //  let ref mut fresh63 = (*ftpwc).backup.write_function;
                     (*ftpwc).backup.write_function = (*data).set.fwrite_func;
                    //  let ref mut fresh64 = (*data).set.fwrite_func;
                     (*data).set.fwrite_func = Some(
                         Curl_ftp_parselist
                             as unsafe extern "C" fn(
                                 *mut libc::c_char,
                                 size_t,
                                 size_t,
                                 *mut libc::c_void,
                             ) -> size_t,
                     );
                    //  let ref mut fresh65 = (*ftpwc).backup.file_descriptor;
                     (*ftpwc).backup.file_descriptor = (*data).set.out as *mut FILE;
                    //  let ref mut fresh66 = (*data).set.out;
                     (*data).set.out = data as *mut libc::c_void;
                     Curl_infof(
                         data,
                         b"Wildcard - Parsing started\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_OK;
                 }
             }
             break 'fail;
         }
     }
     break 'fail;
    }
     if !ftpwc.is_null() {
         Curl_ftp_parselist_data_free(&mut (*ftpwc).parser);
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")(ftpwc as *mut libc::c_void);

    #[cfg(CURLDEBUG)]

         curl_dbg_free(
             ftpwc as *mut libc::c_void,
             3854 as i32,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*wildcard).pattern as *mut libc::c_void);

    #[cfg(CURLDEBUG)]

     curl_dbg_free(
         (*wildcard).pattern as *mut libc::c_void,
         3856 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
    //  let ref mut fresh67 = (*wildcard).pattern;
     (*wildcard).pattern = 0 as *mut libc::c_char;
    //  let ref mut fresh68 = (*wildcard).dtor;
     (*wildcard).dtor = None;
    //  let ref mut fresh69 = (*wildcard).protdata;
     (*wildcard).protdata = 0 as *mut libc::c_void;
     return result;
    }
}

extern "C" fn wc_statemach(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
     let wildcard: *mut WildcardData = &mut (*data).wildcard;
     let mut conn: *mut connectdata = (*data).conn;
     let mut result: CURLcode = CURLE_OK;
     let mut current_block_53: u64;
     loop {
         match (*wildcard).state as u32 {
             1 => {
                 result = init_wc_data(data);
                 if (*wildcard).state as u32 == CURLWC_CLEAN as u32
                 {
                     return result;/* only listing! */
                 }
                 (*wildcard).state = (if result as u32 != 0 {
                     CURLWC_ERROR as i32
                 } else {
                     CURLWC_MATCHING as i32
                 }) as wildcard_states;
                 return result;
             }
             2 => {
                /* In this state is LIST response successfully parsed, so lets restore
         previous WRITEFUNCTION callback and WRITEDATA pointer */
                 let mut ftpwc: *mut ftp_wc = (*wildcard).protdata as *mut ftp_wc;
                //  let ref mut fresh70 = (*data).set.fwrite_func;
                 (*data).set.fwrite_func = (*ftpwc).backup.write_function;
                //  let ref mut fresh71 = (*data).set.out;
                 (*data).set.out = (*ftpwc).backup.file_descriptor as *mut libc::c_void;
                //  let ref mut fresh72 = (*ftpwc).backup.write_function;
                 (*ftpwc).backup.write_function = None;
                //  let ref mut fresh73 = (*ftpwc).backup.file_descriptor;
                 (*ftpwc).backup.file_descriptor = 0 as *mut FILE;
                 (*wildcard).state = CURLWC_DOWNLOADING;
                 if Curl_ftp_parselist_geterror((*ftpwc).parser) as u64 != 0 {
                     /* error found in LIST parsing */
                     (*wildcard).state = CURLWC_CLEAN;
                 } else if (*wildcard).filelist.size == 0 as u64 {
                    /* no corresponding file */
                     (*wildcard).state = CURLWC_CLEAN;
                     return CURLE_REMOTE_FILE_NOT_FOUND;
                 }
             }
             3 => {
                 /* filelist has at least one file, lets get first one */
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
                     3912 as i32,
                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                 );
                 let ref mut fresh74 = (*ftp).path;
                 (*ftp).path = tmp_path;
                 let ref mut fresh75 = (*ftp).pathalloc;
                 (*ftp).pathalloc = (*ftp).path;
                 Curl_infof(
                     data,
                     b"Wildcard - START of \"%s\"\0" as *const u8 as *const libc::c_char,
                     (*finfo).filename,
                 );
                 if ((*data).set.chunk_bgn).is_some() {
                     let mut userresponse: i64 = 0;
                     Curl_set_in_callback(data, 1 as i32 != 0);
                     userresponse = ((*data).set.chunk_bgn).expect("non-null function pointer")(
                         finfo as *const libc::c_void,
                         (*wildcard).customptr,
                         (*wildcard).filelist.size as i32,
                     );
                     Curl_set_in_callback(data, 0 as i32 != 0);
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
                 if (*finfo).filetype as u32
                     != CURLFILETYPE_FILE as u32
                 {
                     (*wildcard).state = CURLWC_SKIP;
                 } else {
                     if (*finfo).flags & ((1 as i32) << 6 as i32) as u32
                         != 0
                     {
                         (*ftpc).known_filesize = (*finfo).size;
                     }
                     result = ftp_parse_url_path(data);
                     if result as u64 != 0 {
                         return result;
                     }/* we don't need the Curl_fileinfo of first file anymore */
                     Curl_llist_remove(
                         &mut (*wildcard).filelist,
                         (*wildcard).filelist.head,
                         0 as *mut libc::c_void,
                     );
                     if (*wildcard).filelist.size == 0 as u64 {/* remains only one file to down. */
                         (*wildcard).state = CURLWC_CLEAN;
                          /* after that will be ftp_do called once again and no transfer
           will be done because of CURLWC_CLEAN state */
                         return CURLE_OK;
                     }
                     return result;
                 }
             }
             5 => {
                 if ((*data).set.chunk_end).is_some() {
                     Curl_set_in_callback(data, 1 as i32 != 0);
                     ((*data).set.chunk_end).expect("non-null function pointer")(
                         (*data).wildcard.customptr,
                     );
                     Curl_set_in_callback(data, 0 as i32 != 0);
                 }
                 Curl_llist_remove(
                     &mut (*wildcard).filelist,
                     (*wildcard).filelist.head,
                     0 as *mut libc::c_void,
                 );
                 (*wildcard).state =
                     (if (*wildcard).filelist.size == 0 as u64 {
                         CURLWC_CLEAN as i32
                     } else {
                         CURLWC_DOWNLOADING as i32
                     }) as wildcard_states;
             }
             4 => {
                 let mut ftpwc_0: *mut ftp_wc = (*wildcard).protdata as *mut ftp_wc;
                 result = CURLE_OK;
                 if !ftpwc_0.is_null() {
                     result = Curl_ftp_parselist_geterror((*ftpwc_0).parser);
                 }
                 (*wildcard).state = (if result as u32 != 0 {
                     CURLWC_ERROR as i32
                 } else {
                     CURLWC_DONE as i32
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
    }/* UNREACHABLE */
 }
/***********************************************************************
 *
 * ftp_do()
 *
 * This function is registered as 'curl_do' function. It decodes the path
 * parts etc as a wrapper to the actual DO function (ftp_perform).
 *
 * The input argument is already checked for validity.
 */
extern "C" fn ftp_do(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     *done = 0 as i32 != 0;/* default to false */
     (*ftpc).wait_data_conn = 0 as i32 != 0;/* default to no such wait */
     if ((*data).state).wildcardmatch() != 0 {
         result = wc_statemach(data);
         if (*data).wildcard.state as u32 == CURLWC_SKIP as u32
             || (*data).wildcard.state as u32 == CURLWC_DONE as u32
         {/* do not call ftp_regular_transfer */
             return CURLE_OK;
         }
         if result as u64 != 0 {
             return result; /* error, loop or skipping the file */
         }
     } else {/* no wildcard FSM needed */
         result = ftp_parse_url_path(data);
         if result as u64 != 0 {
             return result;
         }
     }
     result = ftp_regular_transfer(data, done);
     return result;
    }
 }


//  unsafe extern "C" fn ftp_quit(mut data: *mut Curl_easy, mut conn: *mut connectdata) -> CURLcode {
//      let mut result: CURLcode = CURLE_OK;
//      if (*conn).proto.ftpc.ctl_valid {
//          result = Curl_pp_sendf(
//              data,
//              &mut (*conn).proto.ftpc.pp as *mut pingpong,
//              b"%s\0" as *const u8 as *const libc::c_char,
//              b"QUIT\0" as *const u8 as *const libc::c_char,
//          );
//          if result as u64 != 0 {
//              Curl_failf(
//                  data,
//                  b"Failure sending QUIT command: %s\0" as *const u8 as *const libc::c_char,
//                  curl_easy_strerror(result),
//              );
//              (*conn).proto.ftpc.ctl_valid = 0 as libc::c_int != 0;
//              #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
//              Curl_conncontrol(conn, 1 as libc::c_int);

// #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
//              Curl_conncontrol(
//                  conn,
//                  1 as libc::c_int,
//                  b"QUIT command failed\0" as *const u8 as *const libc::c_char,
//              );
//              #[cfg(not(DEBUGBUILD))]
//              _state(data, FTP_STOP);

// 	#[cfg(DEBUGBUILD)]
//              _state(data, FTP_STOP, 4050 as libc::c_int);
//              return result;
//          }
//          #[cfg(not(DEBUGBUILD))]
//          _state(data, FTP_QUIT);

//          #[cfg(DEBUGBUILD)]
//          _state(data, FTP_QUIT, 4054 as libc::c_int);
//          result = ftp_block_statemach(data, conn);
//      }
//      return result;
//  }
//  unsafe extern "C" fn ftp_disconnect(
//      mut data: *mut Curl_easy,
//      mut conn: *mut connectdata,
//      mut dead_connection: bool,
//  ) -> CURLcode {
//      let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
//      let mut pp: *mut pingpong = &mut (*ftpc).pp;
//      if dead_connection {
//          (*ftpc).ctl_valid = 0 as libc::c_int != 0;
//      }
//      ftp_quit(data, conn);
//      if !((*ftpc).entrypath).is_null() {
//          if (*data).state.most_recent_ftp_entrypath == (*ftpc).entrypath {
//              let ref mut fresh76 = (*data).state.most_recent_ftp_entrypath;
//              *fresh76 = 0 as *mut libc::c_char;
//          }
//          #[cfg(not(CURLDEBUG))]
//          Curl_cfree.expect("non-null function pointer")((*ftpc).entrypath as *mut libc::c_void);

// 	#[cfg(CURLDEBUG)]
//          curl_dbg_free(
//              (*ftpc).entrypath as *mut libc::c_void,
//              4093 as libc::c_int,
//              b"ftp.c\0" as *const u8 as *const libc::c_char,
//          );
//          let ref mut fresh77 = (*ftpc).entrypath;
//          *fresh77 = 0 as *mut libc::c_char;
//      }
//      freedirs(ftpc);
//      #[cfg(not(CURLDEBUG))]
//      Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void);

// 	#[cfg(CURLDEBUG)]
//      curl_dbg_free(
//          (*ftpc).prevpath as *mut libc::c_void,
//          4097 as libc::c_int,
//          b"ftp.c\0" as *const u8 as *const libc::c_char,
//      );
//      let ref mut fresh78 = (*ftpc).prevpath;
//      *fresh78 = 0 as *mut libc::c_char;
//      #[cfg(not(CURLDEBUG))]
//      Curl_cfree.expect("non-null function pointer")((*ftpc).server_os as *mut libc::c_void);

// 	#[cfg(CURLDEBUG)]
//      curl_dbg_free(
//          (*ftpc).server_os as *mut libc::c_void,
//          4098 as libc::c_int,
//          b"ftp.c\0" as *const u8 as *const libc::c_char,
//      );
//      let ref mut fresh79 = (*ftpc).server_os;
//      *fresh79 = 0 as *mut libc::c_char;
//      Curl_pp_disconnect(pp);
//     #[cfg(HAVE_GSSAPI)]
//     Curl_sec_end(conn);
//      return CURLE_OK;
//  }
//  unsafe extern "C" fn ftp_parse_url_path(mut data: *mut Curl_easy) -> CURLcode {
//      let mut ftp: *mut FTP = (*data).req.p.ftp;
//      let mut conn: *mut connectdata = (*data).conn;
//      let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
//      let mut slashPos: *const libc::c_char = 0 as *const libc::c_char;
//      let mut fileName: *const libc::c_char = 0 as *const libc::c_char;
//      let mut result: CURLcode = CURLE_OK;
//      let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;
//      let mut pathLen: size_t = 0 as libc::c_int as size_t;
//      (*ftpc).ctl_valid = 0 as libc::c_int != 0;
//      (*ftpc).cwdfail = 0 as libc::c_int != 0;
//      result = Curl_urldecode(
//          data,
//          (*ftp).path,
//          0 as libc::c_int as size_t,
//          &mut rawPath,
//          &mut pathLen,
//          REJECT_CTRL,
//      );
//      if result as u64 != 0 {
//          return result;
//      }
//      match (*data).set.ftp_filemethod as libc::c_uint {
//          2 => {
//              if pathLen > 0 as libc::c_int as libc::c_ulong
//                  && *rawPath.offset(pathLen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
//                      as libc::c_int
//                      != '/' as i32
//              {
//                  fileName = rawPath;
//              }
//          }
//          3 => {
//              slashPos = strrchr(rawPath, '/' as i32);
//              if !slashPos.is_null() {
//                  let mut dirlen: size_t = slashPos.offset_from(rawPath) as libc::c_long as size_t;
//                  if dirlen == 0 as libc::c_int as libc::c_ulong {
//                      dirlen = dirlen.wrapping_add(1);
//                  }
                 
//                  match () {
//                     #[cfg(not(CURLDEBUG))]
//                     _ => {
//                         (*ftpc).dirs = Curl_ccalloc.expect("non-null function pointer")(
//                             1 as libc::c_int as size_t,
//                             ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
//                         ) as *mut *mut libc::c_char;
//                     }
//                     #[cfg(CURLDEBUG)]
//                     _ => {
//                         (*ftpc).dirs = curl_dbg_calloc(
//                             1 as libc::c_int as size_t,
//                             ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
//                             4153 as libc::c_int,
//                             b"ftp.c\0" as *const u8 as *const libc::c_char,
//                         ) as *mut *mut libc::c_char;
//                     }
//                 }
                 
//                  if ((*ftpc).dirs).is_null() {
//                     #[cfg(not(CURLDEBUG))]
//                     Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

// 	#[cfg(CURLDEBUG)]
//                      curl_dbg_free(
//                          rawPath as *mut libc::c_void,
//                          4155 as libc::c_int,
//                          b"ftp.c\0" as *const u8 as *const libc::c_char,
//                      );
//                      return CURLE_OUT_OF_MEMORY;
//                  }
//                  match () {
//                     #[cfg(not(CURLDEBUG))]
//                     _ => {
//                         *((*ftpc).dirs).offset(0 as libc::c_int as isize) = Curl_ccalloc.expect("non-null function pointer")(
//                             1 as libc::c_int as size_t,
//                             dirlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
//                         ) as *mut libc::c_char;
//                     }
//                     #[cfg(CURLDEBUG)]
//                     _ => {
//                         *((*ftpc).dirs).offset(0 as libc::c_int as isize) = curl_dbg_calloc(
//                             1 as libc::c_int as size_t,
//                             dirlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
//                             4159 as libc::c_int,
//                             b"ftp.c\0" as *const u8 as *const libc::c_char,
//                         ) as *mut libc::c_char;
//                     }
//                 }
                
//                  if (*((*ftpc).dirs).offset(0 as libc::c_int as isize)).is_null() {
//                     #[cfg(not(CURLDEBUG))]
//                     Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

// 	#[cfg(CURLDEBUG)] 
//                     curl_dbg_free(
//                          rawPath as *mut libc::c_void,
//                          4161 as libc::c_int,
//                          b"ftp.c\0" as *const u8 as *const libc::c_char,
//                      );
//                      return CURLE_OUT_OF_MEMORY;
//                  }
//                  strncpy(
//                      *((*ftpc).dirs).offset(0 as libc::c_int as isize),
//                      rawPath,
//                      dirlen,
//                  );
//                  (*ftpc).dirdepth = 1 as libc::c_int;
//                  fileName = slashPos.offset(1 as libc::c_int as isize);
//              } else {
//                  fileName = rawPath;
//              }
//          }
//          1 | _ => {
//              let mut curPos: *const libc::c_char = rawPath;
//              let mut dirAlloc: libc::c_int = 0 as libc::c_int;
//              let mut str: *const libc::c_char = rawPath;
//              while *str as libc::c_int != 0 as libc::c_int {
//                  if *str as libc::c_int == '/' as i32 {
//                      dirAlloc += 1;
//                  }
//                  str = str.offset(1);
//              }
//              if dirAlloc > 0 as libc::c_int {
//                  match () {
//                     #[cfg(not(CURLDEBUG))]
//                     _ => {
//                         (*ftpc).dirs = Curl_ccalloc.expect("non-null function pointer")(
//                             dirAlloc as size_t,
//                             ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
//                         ) as *mut *mut libc::c_char;
//                     }
//                     #[cfg(CURLDEBUG)]
//                     _ => {
//                         (*ftpc).dirs = curl_dbg_calloc(
//                             dirAlloc as size_t,
//                             ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
//                             4185 as libc::c_int,
//                             b"ftp.c\0" as *const u8 as *const libc::c_char,
//                         ) as *mut *mut libc::c_char;
//                     }
//                 }
                
//                  if ((*ftpc).dirs).is_null() {
//                     #[cfg(not(CURLDEBUG))]
//                     Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

// 	#[cfg(CURLDEBUG)]
//                      curl_dbg_free(
//                          rawPath as *mut libc::c_void,
//                          4187 as libc::c_int,
//                          b"ftp.c\0" as *const u8 as *const libc::c_char,
//                      );
//                      return CURLE_OUT_OF_MEMORY;
//                  }
//                  loop {
//                      slashPos = strchr(curPos, '/' as i32);
//                      if slashPos.is_null() {
//                          break;
//                      }
//                      let mut compLen: size_t =
//                          slashPos.offset_from(curPos) as libc::c_long as size_t;
//                      if compLen == 0 as libc::c_int as libc::c_ulong
//                          && (*ftpc).dirdepth == 0 as libc::c_int
//                      {
//                          compLen = compLen.wrapping_add(1);
//                      }
//                      if compLen > 0 as libc::c_int as libc::c_ulong {
//                         #[cfg(not(CURLDEBUG))]
//                         let mut comp: *mut libc::c_char =
//                         Curl_ccalloc.expect("non-null function pointer")(
//                             1 as libc::c_int as size_t,
//                             compLen.wrapping_add(1 as libc::c_int as libc::c_ulong),
//                         ) as *mut libc::c_char;
// 	                    #[cfg(CURLDEBUG)]
//                          let mut comp: *mut libc::c_char = curl_dbg_calloc(
//                              1 as libc::c_int as size_t,
//                              compLen.wrapping_add(1 as libc::c_int as libc::c_ulong),
//                              4203 as libc::c_int,
//                              b"ftp.c\0" as *const u8 as *const libc::c_char,
//                          )
//                              as *mut libc::c_char;
//                          if comp.is_null() {
//                             #[cfg(not(CURLDEBUG))]
//                             Curl_cfree.expect("non-null function pointer")(
//                                 rawPath as *mut libc::c_void,
//                             );
// 	                        #[cfg(CURLDEBUG)]
//                              curl_dbg_free(
//                                  rawPath as *mut libc::c_void,
//                                  4205 as libc::c_int,
//                                  b"ftp.c\0" as *const u8 as *const libc::c_char,
//                              );
//                              return CURLE_OUT_OF_MEMORY;
//                          }
//                          strncpy(comp, curPos, compLen);
//                          let ref mut fresh83 = (*ftpc).dirdepth;
//                          let fresh84 = *fresh83;
//                          *fresh83 = *fresh83 + 1;
//                          let ref mut fresh85 = *((*ftpc).dirs).offset(fresh84 as isize);
//                          *fresh85 = comp;
//                      }
//                      curPos = slashPos.offset(1 as libc::c_int as isize);
//                  }
//              }
//              #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
//              if (*ftpc).dirdepth <= dirAlloc {
//              } else {
//                  __assert_fail(
//                      b"ftpc->dirdepth <= dirAlloc\0" as *const u8 as *const libc::c_char,
//                      b"ftp.c\0" as *const u8 as *const libc::c_char,
//                      4214 as libc::c_int as libc::c_uint,
//                      (*::std::mem::transmute::<&[u8; 48], &[libc::c_char; 48]>(
//                          b"CURLcode ftp_parse_url_path(struct Curl_easy *)\0",
//                      ))
//                      .as_ptr(),
//                  );
//              }
//              fileName = curPos;
//          }
//      }
//      if !fileName.is_null() && *fileName as libc::c_int != 0 {
//          match () {
//             #[cfg(not(CURLDEBUG))]
//             _ => {
//                 (*ftpc).file = Curl_cstrdup.expect("non-null function pointer")(fileName);

//             }
//             #[cfg(CURLDEBUG)]
//             _ => {
//                 (*ftpc).file = curl_dbg_strdup(
//                     fileName,
//                     4221 as libc::c_int,
//                     b"ftp.c\0" as *const u8 as *const libc::c_char,
//                 );
//             }
//         }
         
//      } else {
//          let ref mut fresh87 = (*ftpc).file;
//          *fresh87 = 0 as *mut libc::c_char;
//      }
//      if ((*data).set).upload() as libc::c_int != 0
//          && ((*ftpc).file).is_null()
//          && (*ftp).transfer as libc::c_uint == PPTRANSFER_BODY as libc::c_int as libc::c_uint
//      {
//          Curl_failf(
//              data,
//              b"Uploading to a URL without a file name!\0" as *const u8 as *const libc::c_char,
//          );
//          #[cfg(not(CURLDEBUG))]
//          Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

// 	#[cfg(CURLDEBUG)]
//          curl_dbg_free(
//              rawPath as *mut libc::c_void,
//              4229 as libc::c_int,
//              b"ftp.c\0" as *const u8 as *const libc::c_char,
//          );
//          return CURLE_URL_MALFORMAT;
//      }
//      (*ftpc).cwddone = 0 as libc::c_int != 0;
//      if (*data).set.ftp_filemethod as libc::c_uint == FTPFILE_NOCWD as libc::c_int as libc::c_uint
//          && *rawPath.offset(0 as libc::c_int as isize) as libc::c_int == '/' as i32
//      {
//          (*ftpc).cwddone = 1 as libc::c_int != 0;
//      } else {
//          let mut oldPath: *const libc::c_char = if ((*conn).bits).reuse() as libc::c_int != 0 {
//              (*ftpc).prevpath as *const libc::c_char
//          } else {
//              b"\0" as *const u8 as *const libc::c_char
//          };
//          if !oldPath.is_null() {
//              let mut n: size_t = pathLen;
//              if (*data).set.ftp_filemethod as libc::c_uint
//                  == FTPFILE_NOCWD as libc::c_int as libc::c_uint
//              {
//                  n = 0 as libc::c_int as size_t;
//              } else {
//                  n = (n as libc::c_ulong).wrapping_sub(if !((*ftpc).file).is_null() {
//                      strlen((*ftpc).file)
//                  } else {
//                      0 as libc::c_int as libc::c_ulong
//                  }) as size_t as size_t;
//              }
//              if strlen(oldPath) == n && strncmp(rawPath, oldPath, n) == 0 {
//                  Curl_infof(
//                      data,
//                      b"Request has same path as previous transfer\0" as *const u8
//                          as *const libc::c_char,
//                  );
//                  (*ftpc).cwddone = 1 as libc::c_int != 0;
//              }
//          }
//      }
//      #[cfg(not(CURLDEBUG))]
//      Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

// 	#[cfg(CURLDEBUG)]
//      curl_dbg_free(
//          rawPath as *mut libc::c_void,
//          4253 as libc::c_int,
//          b"ftp.c\0" as *const u8 as *const libc::c_char,
//      );
//      return CURLE_OK;
//  }
//  unsafe extern "C" fn ftp_dophase_done(mut data: *mut Curl_easy, mut connected: bool) -> CURLcode {
//      let mut conn: *mut connectdata = (*data).conn;
//      let mut ftp: *mut FTP = (*data).req.p.ftp;
//      let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
//      if connected {
//          let mut completed: libc::c_int = 0;
//          let mut result: CURLcode = ftp_do_more(data, &mut completed);
//          if result as u64 != 0 {
//              close_secondarysocket(data, conn);
//              return result;
//          }
//      }
//      if (*ftp).transfer as libc::c_uint != PPTRANSFER_BODY as libc::c_int as libc::c_uint {
//          Curl_setup_transfer(
//              data,
//              -(1 as libc::c_int),
//              -(1 as libc::c_int) as curl_off_t,
//              0 as libc::c_int != 0,
//              -(1 as libc::c_int),
//          );
//      } else if !connected {
//          let ref mut fresh88 = (*conn).bits;
//          (*fresh88).set_do_more(1 as libc::c_int as bit);
//      }
//      (*ftpc).ctl_valid = 1 as libc::c_int != 0;
//      return CURLE_OK;
//  }
//  unsafe extern "C" fn ftp_doing(mut data: *mut Curl_easy, mut dophase_done: *mut bool) -> CURLcode {
//      let mut result: CURLcode = ftp_multi_statemach(data, dophase_done);
//      if result as u64 != 0 {
//         #[cfg(DEBUGBUILD)]
//          Curl_infof(
//              data,
//              b"DO phase failed\0" as *const u8 as *const libc::c_char,
//          );
//      } else if *dophase_done {
//          result = ftp_dophase_done(data, 0 as libc::c_int != 0);
//          #[cfg(DEBUGBUILD)]
//          Curl_infof(
//              data,
//              b"DO phase is complete2\0" as *const u8 as *const libc::c_char,
//          );
//      }
//      return result;
//  }
//  unsafe extern "C" fn ftp_regular_transfer(
//      mut data: *mut Curl_easy,
//      mut dophase_done: *mut bool,
//  ) -> CURLcode {
//      let mut result: CURLcode = CURLE_OK;
//      let mut connected: bool = 0 as libc::c_int != 0;
//      let mut conn: *mut connectdata = (*data).conn;
//      let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
//      (*data).req.size = -(1 as libc::c_int) as curl_off_t;
//      Curl_pgrsSetUploadCounter(data, 0 as libc::c_int as curl_off_t);
//      Curl_pgrsSetDownloadCounter(data, 0 as libc::c_int as curl_off_t);
//      Curl_pgrsSetUploadSize(data, -(1 as libc::c_int) as curl_off_t);
//      Curl_pgrsSetDownloadSize(data, -(1 as libc::c_int) as curl_off_t);
//      (*ftpc).ctl_valid = 1 as libc::c_int != 0;
//      result = ftp_perform(data, &mut connected, dophase_done);
//      if result as u64 == 0 {
//          if !*dophase_done {
//              return CURLE_OK;
//          }
//          result = ftp_dophase_done(data, connected);
//          if result as u64 != 0 {
//              return result;
//          }
//      } else {
//          freedirs(ftpc);
//      }
//      return result;
//  }
//  unsafe extern "C" fn ftp_setup_connection(
//      mut data: *mut Curl_easy,
//      mut conn: *mut connectdata,
//  ) -> CURLcode {
//      let mut type_0: *mut libc::c_char = 0 as *mut libc::c_char;
//      let mut ftp: *mut FTP = 0 as *mut FTP;
//      match () {
//         #[cfg(not(CURLDEBUG))]
//         _ => {
//             ftp = Curl_ccalloc.expect("non-null function pointer")(
//             ::std::mem::size_of::<FTP>() as libc::c_ulong,
//             1 as libc::c_int as size_t,
//         ) as *mut FTP;
//         }
//         #[cfg(CURLDEBUG)]
//         _ => {
//             ftp = curl_dbg_calloc(
//                 ::std::mem::size_of::<FTP>() as libc::c_ulong,
//                 1 as libc::c_int as size_t,
//                 4358 as libc::c_int,
//                 b"ftp.c\0" as *const u8 as *const libc::c_char,
//             ) as *mut FTP;
//         }
//     }
     
//      let ref mut fresh89 = (*data).req.p.ftp;
//      *fresh89 = ftp;
//      if ftp.is_null() {
//          return CURLE_OUT_OF_MEMORY;
//      }
//      let ref mut fresh90 = (*ftp).path;
//      *fresh90 = &mut *((*data).state.up.path).offset(1 as libc::c_int as isize) as *mut libc::c_char;
//      type_0 = strstr((*ftp).path, b";type=\0" as *const u8 as *const libc::c_char);
//      if type_0.is_null() {
//          type_0 = strstr(
//              (*conn).host.rawalloc,
//              b";type=\0" as *const u8 as *const libc::c_char,
//          );
//      }
//      if !type_0.is_null() {
//          let mut command: libc::c_char = 0;
//          *type_0 = 0 as libc::c_int as libc::c_char;
//          command = Curl_raw_toupper(*type_0.offset(6 as libc::c_int as isize));
//          match command as libc::c_int {
//              65 => {
//                  let ref mut fresh91 = (*data).state;
//                  (*fresh91).set_prefer_ascii(1 as libc::c_int as bit);
//              }
//              68 => {
//                  let ref mut fresh92 = (*data).state;
//                  (*fresh92).set_list_only(1 as libc::c_int as bit);
//              }
//              73 | _ => {
//                  let ref mut fresh93 = (*data).state;
//                  (*fresh93).set_prefer_ascii(0 as libc::c_int as bit);
//              }
//          }
//      }
//      (*ftp).transfer = PPTRANSFER_BODY;
//      (*ftp).downloadsize = 0 as libc::c_int as curl_off_t;
//      (*conn).proto.ftpc.known_filesize = -(1 as libc::c_int) as curl_off_t;
//      return CURLE_OK;
//  }
 

/***********************************************************************
 *
 * ftp_quit()
 *
 * This should be called before calling sclose() on an ftp control connection
 * (not data connections). We should then wait for the response from the
 * server before returning. The calling code should then try to close the
 * connection.
 *
 */
extern "C" fn ftp_quit(mut data: *mut Curl_easy, mut conn: *mut connectdata) -> CURLcode {
    unsafe{
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
             (*conn).proto.ftpc.ctl_valid = 0 as i32 != 0;/* mark control connection as bad */
             #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
             Curl_conncontrol(conn, 1 as i32);/* mark for connection closure */

#[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
             Curl_conncontrol(
                 conn,
                 1 as i32,
                 b"QUIT command failed\0" as *const u8 as *const libc::c_char,
             );
             #[cfg(not(DEBUGBUILD))]
             _state(data, FTP_STOP);

    #[cfg(DEBUGBUILD)]
             _state(data, FTP_STOP, 4050 as i32);
             return result;
         }
         #[cfg(not(DEBUGBUILD))]
         _state(data, FTP_QUIT);

         #[cfg(DEBUGBUILD)]
         _state(data, FTP_QUIT, 4054 as i32);
         result = ftp_block_statemach(data, conn);
     }
     return result;
    }
 }

/***********************************************************************
 *
 * ftp_disconnect()
 *
 * Disconnect from an FTP server. Cleanup protocol-specific per-connection
 * resources. BLOCKING.
 */
extern "C" fn ftp_disconnect(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut dead_connection: bool,
 ) -> CURLcode {
    unsafe{
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut pp: *mut pingpong = &mut (*ftpc).pp;
     /* We cannot send quit unconditionally. If this connection is stale or
     bad in any way, sending quit and waiting around here will make the
     disconnect wait in vain and cause more problems than we need to.

     ftp_quit() will check the state of ftp->ctl_valid. If it's ok it
     will try to send the QUIT command, otherwise it will just return.
  */
     if dead_connection {
         (*ftpc).ctl_valid = 0 as i32 != 0;
     }
      /* The FTP session may or may not have been allocated/setup at this point! */
     ftp_quit(data, conn); /* ignore errors on the QUIT */
     if !((*ftpc).entrypath).is_null() {
         if (*data).state.most_recent_ftp_entrypath == (*ftpc).entrypath {
            //  let ref mut fresh76 = (*data).state.most_recent_ftp_entrypath;
             (*data).state.most_recent_ftp_entrypath = 0 as *mut libc::c_char;
         }
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")((*ftpc).entrypath as *mut libc::c_void);

    #[cfg(CURLDEBUG)]
         curl_dbg_free(
             (*ftpc).entrypath as *mut libc::c_void,
             4093 as i32,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
        //  let ref mut fresh77 = (*ftpc).entrypath;
         (*ftpc).entrypath = 0 as *mut libc::c_char;
     }
     freedirs(ftpc);
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void);

    #[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*ftpc).prevpath as *mut libc::c_void,
         4097 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
    //  let ref mut fresh78 = (*ftpc).prevpath;
     (*ftpc).prevpath = 0 as *mut libc::c_char;
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*ftpc).server_os as *mut libc::c_void);

    #[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*ftpc).server_os as *mut libc::c_void,
         4098 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
    //  let ref mut fresh79 = (*ftpc).server_os;
     (*ftpc).server_os = 0 as *mut libc::c_char;
     Curl_pp_disconnect(pp);
    #[cfg(HAVE_GSSAPI)]
    Curl_sec_end(conn);
     return CURLE_OK;
    }
 }

/***********************************************************************
 *
 * ftp_parse_url_path()
 *
 * Parse the URL path into separate path components.
 *
 */
extern "C" fn ftp_parse_url_path(mut data: *mut Curl_easy) -> CURLcode {
    unsafe{
        /* the ftp struct is already inited in ftp_connect() */
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     let mut slashPos: *const libc::c_char = 0 as *const libc::c_char;
     let mut fileName: *const libc::c_char = 0 as *const libc::c_char;
     let mut result: CURLcode = CURLE_OK;
     let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;/* url-decoded "raw" path */
     let mut pathLen: size_t = 0 as size_t;
     (*ftpc).ctl_valid = 0 as i32 != 0;
     (*ftpc).cwdfail = 0 as i32 != 0;
     /* url-decode ftp path before further evaluation */
     result = Curl_urldecode(
         data,
         (*ftp).path,
         0 as size_t,
         &mut rawPath,
         &mut pathLen,
         REJECT_CTRL,
     );
     if result as u64 != 0 {
         return result;
     }
     match (*data).set.ftp_filemethod as u32 {
         2 => {/* fastest, but less standard-compliant */
             if pathLen > 0 as u64
                 && *rawPath.offset(pathLen.wrapping_sub(1 as u64) as isize)
                     as i32
                     != '/' as i32
             {
                 fileName = rawPath; /* this is a full file path */
             } /*
             else: ftpc->file is not used anywhere other than for operations on
                   a file. In other words, never for directory operations.
                   So we can safely leave filename as NULL here and use it as a
                   argument in dir/file decisions.
           */
         }
         3 => {
             slashPos = strrchr(rawPath, '/' as i32);
             if !slashPos.is_null() {  /* get path before last slash, except for / */
                 let mut dirlen: size_t = slashPos.offset_from(rawPath) as i64 as size_t;
                 if dirlen == 0 as u64 {
                     dirlen = dirlen.wrapping_add(1);
                 }
                 
                 match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {
                        (*ftpc).dirs = Curl_ccalloc.expect("non-null function pointer")(
                            1 as size_t,
                            ::std::mem::size_of::<*mut libc::c_char>() as u64,
                        ) as *mut *mut libc::c_char;
                    }
                    #[cfg(CURLDEBUG)]
                    _ => {
                        (*ftpc).dirs = curl_dbg_calloc(
                            1 as i32 as size_t,
                            ::std::mem::size_of::<*mut libc::c_char>() as u64,
                            4153 as i32,
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
                         4155 as i32,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_OUT_OF_MEMORY;
                 }
                 match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {
                        *((*ftpc).dirs).offset(0 as isize) = Curl_ccalloc.expect("non-null function pointer")(
                            1 as size_t,
                            dirlen.wrapping_add(1 as u64),
                        ) as *mut libc::c_char;
                    }
                    #[cfg(CURLDEBUG)]
                    _ => {
                        *((*ftpc).dirs).offset(0 as isize) = curl_dbg_calloc(
                            1 as size_t,
                            dirlen.wrapping_add(1 as u64),
                            4159 as i32,
                            b"ftp.c\0" as *const u8 as *const libc::c_char,
                        ) as *mut libc::c_char;
                    }
                }
                
                 if (*((*ftpc).dirs).offset(0 as isize)).is_null() {
                    #[cfg(not(CURLDEBUG))]
                    Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

    #[cfg(CURLDEBUG)] 
                    curl_dbg_free(
                         rawPath as *mut libc::c_void,
                         4161 as i32,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_OUT_OF_MEMORY;
                 }
                 strncpy(
                     *((*ftpc).dirs).offset(0 as isize),
                     rawPath,
                     dirlen,
                 );
                 (*ftpc).dirdepth = 1 as i32; /* we consider it to be a single dir */
                 fileName = slashPos.offset(1 as isize);/* rest is file name */
             } else {
                 fileName = rawPath;/* file name only (or empty) */
             }
         }
         1 | _ => { /* allow pretty much anything */
             let mut curPos: *const libc::c_char = rawPath; /* current position: begin of next path component */
             let mut dirAlloc: i32 = 0 as i32; /* number of entries allocated for the 'dirs' array */
             let mut str: *const libc::c_char = rawPath;
             while *str as i32 != 0 as i32 {
                 if *str as i32 == '/' as i32 {
                     dirAlloc += 1;
                 }
                 str = str.offset(1);
             }
             if dirAlloc > 0 as i32 {
                 match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {
                        (*ftpc).dirs = Curl_ccalloc.expect("non-null function pointer")(
                            dirAlloc as size_t,
                            ::std::mem::size_of::<*mut libc::c_char>() as u64,
                        ) as *mut *mut libc::c_char;
                    }
                    #[cfg(CURLDEBUG)]
                    _ => {
                        (*ftpc).dirs = curl_dbg_calloc(
                            dirAlloc as size_t,
                            ::std::mem::size_of::<*mut libc::c_char>() as u64,
                            4185 as i32,
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
                         4187 as i32,
                         b"ftp.c\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_OUT_OF_MEMORY;
                 }
                 loop { /* parse the URL path into separate path components */
                     slashPos = strchr(curPos, '/' as i32);
                     if slashPos.is_null() {
                         break;
                     }
                     let mut compLen: size_t =
                         slashPos.offset_from(curPos) as size_t;
                          /* path starts with a slash: add that as a directory */
                     if compLen == 0 as u64
                         && (*ftpc).dirdepth == 0 as i32
                     {
                         compLen = compLen.wrapping_add(1);
                     }
                     /* we skip empty path components, like "x//y" since the FTP command
             CWD requires a parameter and a non-existent parameter a) doesn't
             work on many servers and b) has no effect on the others. */
                     if compLen > 0 as u64 {
                        #[cfg(not(CURLDEBUG))]
                        let mut comp: *mut libc::c_char =
                        Curl_ccalloc.expect("non-null function pointer")(
                            1 as size_t,
                            compLen.wrapping_add(1 as u64),
                        ) as *mut libc::c_char;
                        #[cfg(CURLDEBUG)]
                         let mut comp: *mut libc::c_char = curl_dbg_calloc(
                             1 as size_t,
                             compLen.wrapping_add(1 as u64),
                             4203 as i32,
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
                                 4205 as i32,
                                 b"ftp.c\0" as *const u8 as *const libc::c_char,
                             );
                             return CURLE_OUT_OF_MEMORY;
                         }
                         strncpy(comp, curPos, compLen);
                        //  let ref mut fresh83 = (*ftpc).dirdepth;
                         let fresh84 = (*ftpc).dirdepth;
                         (*ftpc).dirdepth = (*ftpc).dirdepth + 1;
                        //  let ref mut fresh85 = *((*ftpc).dirs).offset(fresh84 as isize);
                         *((*ftpc).dirs).offset(fresh84 as isize) = comp;
                     }
                     curPos = slashPos.offset(1 as isize);
                 }
             }
             #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
             if (*ftpc).dirdepth <= dirAlloc {
             } else {
                 __assert_fail(
                     b"ftpc->dirdepth <= dirAlloc\0" as *const u8 as *const libc::c_char,
                     b"ftp.c\0" as *const u8 as *const libc::c_char,
                     4214 as u32,
                     (*::std::mem::transmute::<&[u8; 48], &[libc::c_char; 48]>(
                         b"CURLcode ftp_parse_url_path(struct Curl_easy *)\0",
                     ))
                     .as_ptr(),
                 );
             }
             fileName = curPos;/* the rest is the file name (or empty) */
         }/* switch */
     }
     if !fileName.is_null() && *fileName as i32 != 0 {
         match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                (*ftpc).file = Curl_cstrdup.expect("non-null function pointer")(fileName);

            }
            #[cfg(CURLDEBUG)]
            _ => {
                (*ftpc).file = curl_dbg_strdup(
                    fileName,
                    4221 as i32,
                    b"ftp.c\0" as *const u8 as *const libc::c_char,
                );
            }
        }
         
     } else {
        //  let ref mut fresh87 = (*ftpc).file;
         (*ftpc).file = 0 as *mut libc::c_char;
     }
     if ((*data).set).upload() as i32 != 0
         && ((*ftpc).file).is_null()
         && (*ftp).transfer as u32 == PPTRANSFER_BODY as u32
     {/* We need a file name when uploading. Return error! */
         Curl_failf(
             data,
             b"Uploading to a URL without a file name!\0" as *const u8 as *const libc::c_char,
         );
         #[cfg(not(CURLDEBUG))]
         Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

    #[cfg(CURLDEBUG)]
         curl_dbg_free(
             rawPath as *mut libc::c_void,
             4229 as i32,
             b"ftp.c\0" as *const u8 as *const libc::c_char,
         );
         return CURLE_URL_MALFORMAT;
     }
     (*ftpc).cwddone = 0 as i32 != 0;/* default to not done */
     if (*data).set.ftp_filemethod as u32 == FTPFILE_NOCWD as u32
         && *rawPath.offset(0 as isize) as i32 == '/' as i32
     {/* skip CWD for absolute paths */
         (*ftpc).cwddone = 1 as i32 != 0;
     } else {/* newly created FTP connections are already in entry path */
         let mut oldPath: *const libc::c_char = if ((*conn).bits).reuse() as i32 != 0 {
             (*ftpc).prevpath as *const libc::c_char
         } else {
             b"\0" as *const u8 as *const libc::c_char
         };
         if !oldPath.is_null() {
             let mut n: size_t = pathLen;
             if (*data).set.ftp_filemethod as u32
                 == FTPFILE_NOCWD as u32
             {
                 n = 0 as size_t; /* CWD to entry for relative paths */
             } else {
                 n = (n as u64).wrapping_sub(if !((*ftpc).file).is_null() {
                     strlen((*ftpc).file)
                 } else {
                     0 as i32 as u64
                 }) as size_t as size_t;
             }
             if strlen(oldPath) == n && strncmp(rawPath, oldPath, n) == 0 {
                 Curl_infof(
                     data,
                     b"Request has same path as previous transfer\0" as *const u8
                         as *const libc::c_char,
                 );
                 (*ftpc).cwddone = 1 as i32 != 0;
             }
         }
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);

    #[cfg(CURLDEBUG)]
     curl_dbg_free(
         rawPath as *mut libc::c_void,
         4253 as i32,
         b"ftp.c\0" as *const u8 as *const libc::c_char,
     );
     return CURLE_OK;
    }
 }
 /* call this when the DO phase has completed */
extern "C" fn ftp_dophase_done(mut data: *mut Curl_easy, mut connected: bool) -> CURLcode {
    unsafe{
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftp: *mut FTP = (*data).req.p.ftp;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     if connected {
         let mut completed: i32 = 0;
         let mut result: CURLcode = ftp_do_more(data, &mut completed);
         if result as u64 != 0 {
             close_secondarysocket(data, conn);
             return result;
         }
     } /* no data to transfer */
     if (*ftp).transfer as u32 != PPTRANSFER_BODY as u32 {
         Curl_setup_transfer(
             data,
             -(1 as i32),
             -(1 as i32) as curl_off_t,
             0 as i32 != 0,
             -(1 as i32),
         );
     } else if !connected {/* since we didn't connect now, we want do_more to get called */
        //  let ref mut fresh88 = (*conn).bits;
         ((*conn).bits).set_do_more(1 as bit);
     }
     (*ftpc).ctl_valid = 1 as i32 != 0; /* seems good */
     return CURLE_OK;
    }
 }
 /* called from multi.c while DOing */
extern "C" fn ftp_doing(mut data: *mut Curl_easy, mut dophase_done: *mut bool) -> CURLcode {
    unsafe{
     let mut result: CURLcode = ftp_multi_statemach(data, dophase_done);
     if result as u64 != 0 {
        #[cfg(DEBUGBUILD)]
         Curl_infof(
             data,
             b"DO phase failed\0" as *const u8 as *const libc::c_char,
         );
     } else if *dophase_done {
         result = ftp_dophase_done(data, 0 as i32 != 0);
         #[cfg(DEBUGBUILD)]
         Curl_infof(
             data,
             b"DO phase is complete2\0" as *const u8 as *const libc::c_char,
         );
     }
     return result;
    }
 }

/***********************************************************************
 *
 * ftp_regular_transfer()
 *
 * The input argument is already checked for validity.
 *
 * Performs all commands done before a regular transfer between a local and a
 * remote host.
 *
 * ftp->ctl_valid starts out as FALSE, and gets set to TRUE if we reach the
 * ftp_done() function without finding any major problem.
 */
extern "C" fn ftp_regular_transfer(
     mut data: *mut Curl_easy,
     mut dophase_done: *mut bool,
 ) -> CURLcode {
    unsafe{
     let mut result: CURLcode = CURLE_OK;
     let mut connected: bool = 0 as i32 != 0;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
     (*data).req.size = -(1 as i32) as curl_off_t;/* make sure this is unknown at this point */
     Curl_pgrsSetUploadCounter(data, 0 as curl_off_t);
     Curl_pgrsSetDownloadCounter(data, 0 as curl_off_t);
     Curl_pgrsSetUploadSize(data, -(1 as i32) as curl_off_t);
     Curl_pgrsSetDownloadSize(data, -(1 as i32) as curl_off_t);
     (*ftpc).ctl_valid = 1 as i32 != 0;/* starts good */
     result = ftp_perform(data, &mut connected, dophase_done);/* have we connected after PASV/PORT */
     /* all commands in the DO-phase done? */
     if result as u64 == 0 {
         if !*dophase_done {
             return CURLE_OK; /* the DO phase has not completed yet */
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
 }
extern "C" fn ftp_setup_connection(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
    unsafe{
     let mut type_0: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut ftp: *mut FTP = 0 as *mut FTP;
     match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            ftp = Curl_ccalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<FTP>() as u64,
            1 as size_t,
        ) as *mut FTP;
        }
        #[cfg(CURLDEBUG)]
        _ => {
            ftp = curl_dbg_calloc(
                ::std::mem::size_of::<FTP>() as u64,
                1 as size_t,
                4358 as i32,
                b"ftp.c\0" as *const u8 as *const libc::c_char,
            ) as *mut FTP;
        }
    }
     
    //  let ref mut fresh89 = (*data).req.p.ftp;
     (*data).req.p.ftp = ftp;
     if ftp.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
    //  let ref mut fresh90 = (*ftp).path;
     (*ftp).path = &mut *((*data).state.up.path).offset(1 as isize) as *mut libc::c_char;
      /* don't include the initial slash */
      /* FTP URLs support an extension like ";type=<typecode>" that
   * we'll try to get now! */
     type_0 = strstr((*ftp).path, b";type=\0" as *const u8 as *const libc::c_char);
     if type_0.is_null() {
         type_0 = strstr(
             (*conn).host.rawalloc,
             b";type=\0" as *const u8 as *const libc::c_char,
         );
     }
     if !type_0.is_null() {
         let mut command: libc::c_char = 0;
         *type_0 = 0 as libc::c_char;  /* it was in the middle of the hostname */
         command = Curl_raw_toupper(*type_0.offset(6 as isize));
         match command as i32 {
             65 => { /* ASCII mode */
                //  let ref mut fresh91 = (*data).state;
                 ((*data).state).set_prefer_ascii(1 as bit);
             }
             68 => { /* directory mode */
                //  let ref mut fresh92 = (*data).state;
                 ((*data).state).set_list_only(1 as bit);
             }
             73 | _ => {/* binary mode */ /* switch off ASCII */
                 ((*data).state).set_prefer_ascii(0 as bit);
             }
         }
     }
     /* get some initial data into the ftp struct */
     (*ftp).transfer = PPTRANSFER_BODY;
     (*ftp).downloadsize = 0 as curl_off_t;
     (*conn).proto.ftpc.known_filesize = -(1 as i32) as curl_off_t; /* unknown size for now */
     return CURLE_OK;
    }/* CURL_DISABLE_FTP */
 }