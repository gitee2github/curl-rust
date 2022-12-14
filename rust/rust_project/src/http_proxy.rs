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
 * Description: http proxy
 ******************************************************************************/
 use ::libc;
 use rust_ffi::src::ffi_alias::type_alias::*;
 use rust_ffi::src::ffi_fun::fun_call::*;
 use rust_ffi::src::ffi_struct::struct_define::*;
 // use rust_fun::src::macro_fun::*;
 // use crate::src::vtls::vtls::*;
 // use crate::src::http::*;
 
 // TODO 调用的几个http.c里的函数有hyper版本，有可能需要用条件编译再加几行
 
 /*
  * Perform SSL initialization for HTTPS proxy.  Sets
  * proxy_ssl_connected connection bit when complete.  Can be
  * called multiple times.
  */
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 extern "C" fn https_proxy_connect(
     mut data: *mut Curl_easy,
     mut sockindex: i32,
 ) -> CURLcode {

     if cfg!(USE_SSL) {
         let mut conn: *mut connectdata = unsafe{(*data).conn};
         let mut result: CURLcode = CURLE_OK;
         #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
         if (*conn).http_proxy.proxytype as u32
             == CURLPROXY_HTTPS as u32
         {
         } else {
             __assert_fail(
                 b"conn->http_proxy.proxytype == CURLPROXY_HTTPS\0" as *const u8
                     as *const libc::c_char,
                 b"http_proxy.c\0" as *const u8 as *const libc::c_char,
                 60 as u32,
                 (*::std::mem::transmute::<&[u8; 54], &[libc::c_char; 54]>(
                     b"CURLcode https_proxy_connect(struct Curl_easy *, int)\0",
                 ))
                 .as_ptr(),
             );
         }
         if unsafe{!(*conn).bits.proxy_ssl_connected[sockindex as usize]} {
             /* perform SSL initialization for this socket */
             result = unsafe{Curl_ssl_connect_nonblocking(
                 data,
                 conn,
                 1 as i32 != 0,
                 sockindex,
                 &mut *((*conn).bits.proxy_ssl_connected)
                     .as_mut_ptr()
                     .offset(sockindex as isize),
             )};
             if result as u64 != 0 {
                  /* a failed connection is marked for closure to prevent (bad) re-use or
          similar */
                 #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                 Curl_conncontrol(
                     conn,
                     1 as i32,
                     b"TLS handshake failed\0" as *const u8 as *const libc::c_char,
                 );
                 #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                 unsafe{Curl_conncontrol(conn, 1 as i32);}
             }
         }
         return result;
     } else {
         return CURLE_NOT_BUILT_IN;
     }
 
 }
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 #[no_mangle]
 pub extern "C" fn Curl_proxy_connect(
     mut data: *mut Curl_easy,
     mut sockindex: i32,
 ) -> CURLcode {
     let mut conn: *mut connectdata = unsafe{(*data).conn};
     if unsafe{(*conn).http_proxy.proxytype as u32}
         == CURLPROXY_HTTPS as u32
     {
         let result: CURLcode = https_proxy_connect(data, sockindex);
         if result as u64 != 0 {
             return result;
         }
         if unsafe{!(*conn).bits.proxy_ssl_connected[sockindex as usize]} {
             return result; /* wait for HTTPS proxy SSL initialization to complete */
         }
     }
     if unsafe{ ((*conn).bits).tunnel_proxy() as i32} != 0
         && unsafe{((*conn).bits).httpproxy() as i32 }!= 0
     {
         if cfg!(not(CURL_DISABLE_PROXY)) {
             /* for [protocol] tunneled through HTTP proxy */
             let mut hostname: *const libc::c_char = 0 as *const libc::c_char;
             let mut remote_port: i32 = 0;
             let mut result_0: CURLcode = CURLE_OK;
             /* We want "seamless" operations through HTTP proxy tunnel */
 
     /* for the secondary socket (FTP), use the "connect to host"
      * but ignore the "connect to port" (use the secondary port)
      */
             if unsafe{((*conn).bits).conn_to_host() }!= 0 {
                 hostname = unsafe{(*conn).conn_to_host.name};
             } else if sockindex == 1 as i32 {
                 hostname = unsafe{(*conn).secondaryhostname};
             } else {
                 hostname = unsafe{(*conn).host.name};
             }
             if sockindex == 1 as i32 {
                 remote_port = unsafe{(*conn).secondary_port as i32};
             } else if unsafe{((*conn).bits).conn_to_port() }!= 0 {
                 remote_port = unsafe{(*conn).conn_to_port};
             } else {
                 remote_port = unsafe{(*conn).remote_port};
             }
             result_0 = Curl_proxyCONNECT(data, sockindex, hostname, remote_port);
             if CURLE_OK as u32 != result_0 as u32 {
                 return result_0;
             }
             #[cfg(not(CURLDEBUG))]
             unsafe{Curl_cfree.expect("non-null function pointer")(
                 (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
             );}
             #[cfg(CURLDEBUG)]
             unsafe{curl_dbg_free(
                 (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
                 120 as i32,
                 b"http_proxy.c\0" as *const u8 as *const libc::c_char,
             );
             // let ref mut fresh0 = (*data).state.aptr.proxyuserpwd;
             (*data).state.aptr.proxyuserpwd = 0 as *mut libc::c_char;}
         } else {
             return CURLE_NOT_BUILT_IN;
         }
     }
      /* no HTTP tunnel proxy, just return */
     return CURLE_OK;

 }
 
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 #[no_mangle]
 pub extern "C" fn Curl_connect_complete(mut conn: *mut connectdata) -> bool {
     unsafe{
     return ((*conn).connect_state).is_null()
         || (*(*conn).connect_state).tunnel_state as u32
             >= TUNNEL_COMPLETE as u32;
     }
 }
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 #[no_mangle]
 pub extern "C" fn Curl_connect_ongoing(mut conn: *mut connectdata) -> bool {
     unsafe{
     return !((*conn).connect_state).is_null()
         && (*(*conn).connect_state).tunnel_state as u32
             <= TUNNEL_COMPLETE as u32;
     }
 }
 /* when we've sent a CONNECT to a proxy, we should rather either wait for the
    socket to become readable to be able to get the response headers or if
    we're still sending the request, wait for write. */
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 #[no_mangle]
 pub extern "C" fn Curl_connect_getsock(mut conn: *mut connectdata) -> i32 {
     let mut http: *mut HTTP = 0 as *mut HTTP;
     #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
     if !conn.is_null() {
     } else {
        unsafe{
         __assert_fail(
             b"conn\0" as *const u8 as *const libc::c_char,
             b"http_proxy.c\0" as *const u8 as *const libc::c_char,
             147 as u32,
             (*::std::mem::transmute::<&[u8; 47], &[libc::c_char; 47]>(
                 b"int Curl_connect_getsock(struct connectdata *)\0",
             ))
             .as_ptr(),
         );}
     }
     #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
     if unsafe{ !((*conn).connect_state).is_null()} {
     } else {
        unsafe{
         __assert_fail(
             b"conn->connect_state\0" as *const u8 as *const libc::c_char,
             b"http_proxy.c\0" as *const u8 as *const libc::c_char,
             148 as u32,
             (*::std::mem::transmute::<&[u8; 47], &[libc::c_char; 47]>(
                 b"int Curl_connect_getsock(struct connectdata *)\0",
             ))
             .as_ptr(),
         );}
     }
     http = unsafe{&mut (*(*conn).connect_state).http_proxy};
     if unsafe{(*http).sending as u32} == HTTPSEND_REQUEST as u32 {
         return (1 as i32) << 16 as i32 + 0 as i32;
     }
     return (1 as i32) << 0 as i32;
 }
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 extern "C" fn connect_init(mut data: *mut Curl_easy, mut reinit: bool) -> CURLcode {
     let mut s: *mut http_connect_state = 0 as *mut http_connect_state;
     let mut conn: *mut connectdata = unsafe{(*data).conn};
     if !reinit {
         let mut result: CURLcode = CURLE_OK;
         #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
         if unsafe{((*conn).connect_state).is_null()}{
         } else {unsafe{
             __assert_fail(
                 b"!conn->connect_state\0" as *const u8 as *const libc::c_char,
                 b"http_proxy.c\0" as *const u8 as *const libc::c_char,
                 163 as u32,
                 (*::std::mem::transmute::<&[u8; 49], &[libc::c_char; 49]>(
                     b"CURLcode connect_init(struct Curl_easy *, _Bool)\0",
                 ))
                 .as_ptr(),
             );}
         }
          /* we might need the upload buffer for streaming a partial request */
         result = unsafe{Curl_get_upload_buffer(data)};
         if result as u64 != 0 {
             return result;
         }
         #[cfg(not(CURLDEBUG))]
         let news: *mut http_connect_state = unsafe{Curl_ccalloc.expect("non-null function pointer")(
             1 as size_t,
             ::std::mem::size_of::<http_connect_state>() as u64,
         ) as *mut http_connect_state};
         #[cfg(CURLDEBUG)]
         let news: *mut http_connect_state =unsafe{ curl_dbg_calloc(
             1 as size_t,
             ::std::mem::size_of::<http_connect_state>() as u64,
             169 as i32,
             b"http_proxy.c\0" as *const u8 as *const libc::c_char,
         ) as *mut http_connect_state};
         s = news;
         if s.is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
         unsafe{
         Curl_infof(
             data,
             b"allocate connect buffer!\0" as *const u8 as *const libc::c_char,
         );
         // let ref mut fresh1 = (*conn).connect_state;
         (*conn).connect_state = s;
         Curl_dyn_init(&mut (*s).rcvbuf, 16384 as size_t);
         // let ref mut fresh2 = (*s).prot_save;
         (*s).prot_save = (*data).req.p.http;
         // let ref mut fresh3 = (*data).req.p.http;
         (*data).req.p.http = &mut (*s).http_proxy;}
         #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
         unsafe{Curl_conncontrol(conn, 0 as i32);}
         #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
         unsafe{Curl_conncontrol(
             conn,
             0 as i32,
             b"HTTP proxy CONNECT\0" as *const u8 as *const libc::c_char,
         );}
         /* Curl_proxyCONNECT is based on a pointer to a struct HTTP at the
      * member conn->proto.http; we want [protocol] through HTTP and we have
      * to change the member temporarily for connecting to the HTTP
      * proxy. After Curl_proxyCONNECT we have to set back the member to the
      * original pointer
      *
      * This function might be called several times in the multi interface case
      * if the proxy's CONNECT response is not instant.
      */
     } else {
         #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
         if unsafe{!((*conn).connect_state).is_null()} {
         } else {
            unsafe{
             __assert_fail(
                 b"conn->connect_state\0" as *const u8 as *const libc::c_char,
                 b"http_proxy.c\0" as *const u8 as *const libc::c_char,
                 190 as u32,
                 (*::std::mem::transmute::<&[u8; 49], &[libc::c_char; 49]>(
                     b"CURLcode connect_init(struct Curl_easy *, _Bool)\0",
                 ))
                 .as_ptr(),
             );}
         }
         s = unsafe{(*conn).connect_state};
         unsafe{ Curl_dyn_reset(&mut (*s).rcvbuf);}
     }
     unsafe{
     (*s).tunnel_state = TUNNEL_INIT;
     (*s).keepon = KEEPON_CONNECT;
     (*s).cl = 0 as curl_off_t;
     (*s).set_close_connection(0 as bit);
     }
     return CURLE_OK;

 }
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 extern "C" fn connect_done(mut data: *mut Curl_easy) {
     let mut conn: *mut connectdata = unsafe{(*data).conn};
     let mut s: *mut http_connect_state = unsafe{(*conn).connect_state};
     if unsafe{(*s).tunnel_state as u32} != TUNNEL_EXIT as u32 {
        unsafe{
         (*s).tunnel_state = TUNNEL_EXIT;
         Curl_dyn_free(&mut (*s).rcvbuf);
         Curl_dyn_free(&mut (*s).req);
         // let ref mut fresh4 = (*data).req.p.http;
         (*data).req.p.http = (*s).prot_save;
         // let ref mut fresh5 = (*s).prot_save;
         /* retore the protocol pointer */
         (*s).prot_save = 0 as *mut HTTP;
         Curl_infof(
             data,
             b"CONNECT phase completed!\0" as *const u8 as *const libc::c_char,
         );}
     }
 }
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 extern "C" fn CONNECT_host(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut hostname: *const libc::c_char,
     mut remote_port: i32,
     mut connecthostp: *mut *mut libc::c_char,
     mut hostp: *mut *mut libc::c_char,
 ) -> CURLcode {
     let mut hostheader: *mut libc::c_char = 0 as *mut libc::c_char; /* for CONNECT */
     let mut host: *mut libc::c_char = 0 as *mut libc::c_char; /* Host: */
     let mut ipv6_ip: bool = unsafe{((*conn).bits).ipv6_ip() }!= 0;
     /* the hostname may be different */
     if hostname != unsafe{(*conn).host.name as *const libc::c_char }{
         ipv6_ip = unsafe{!(strchr(hostname, ':' as i32)).is_null()};
     }
     /* host:port with IPv6 support */
     hostheader = unsafe{curl_maprintf(
         b"%s%s%s:%d\0" as *const u8 as *const libc::c_char,
         if ipv6_ip as i32 != 0 {
             b"[\0" as *const u8 as *const libc::c_char
         } else {
             b"\0" as *const u8 as *const libc::c_char
         },
         hostname,
         if ipv6_ip as i32 != 0 {
             b"]\0" as *const u8 as *const libc::c_char
         } else {
             b"\0" as *const u8 as *const libc::c_char
         },
         remote_port,
     )};
     if hostheader.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     if unsafe{(Curl_checkProxyheaders(data, conn, b"Host\0" as *const u8 as *const libc::c_char)).is_null()}
     {
         host = unsafe{curl_maprintf(
             b"Host: %s\r\n\0" as *const u8 as *const libc::c_char,
             hostheader,
         )};
         if host.is_null() {
             #[cfg(not(CURLDEBUG))]
             unsafe{Curl_cfree.expect("non-null function pointer")(hostheader as *mut libc::c_void);}
             #[cfg(CURLDEBUG)]
             unsafe{curl_dbg_free(
                 hostheader as *mut libc::c_void,
                 240 as i32,
                 b"http_proxy.c\0" as *const u8 as *const libc::c_char,
             );}
             return CURLE_OUT_OF_MEMORY;
         }
     }
     unsafe{
     *connecthostp = hostheader;
     *hostp = host;}
     return CURLE_OK;
 }
//  #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP), not(USE_HYPER)))]
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP), not(USE_HYPER)))]
 extern "C" fn CONNECT(
     mut data: *mut Curl_easy,
     mut sockindex: i32,
     mut hostname: *const libc::c_char,
     mut remote_port: i32,
 ) -> CURLcode {
     let mut subversion: i32 = 0 as i32;
     let mut k: *mut SingleRequest = unsafe{&mut (*data).req};
     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = unsafe{(*data).conn};
     let mut tunnelsocket: curl_socket_t = unsafe{(*conn).sock[sockindex as usize]};
     let mut s: *mut http_connect_state =unsafe{ (*conn).connect_state};
     let mut http: *mut HTTP =unsafe{ (*data).req.p.http};
     let mut linep: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut perline: size_t = 0;
     if Curl_connect_complete(conn) {
         return CURLE_OK; /* CONNECT is already completed */
     }
     // let ref mut fresh6 = (*conn).bits;
     unsafe{((*conn).bits).set_proxy_connect_closed(0 as bit)};
     loop {
         let mut check: timediff_t = 0;
         if TUNNEL_INIT as u32 == unsafe{(*s).tunnel_state as u32} {
             /* BEGIN CONNECT PHASE */
             let mut req: *mut dynbuf = unsafe{&mut (*s).req};
             let mut hostheader: *mut libc::c_char = 0 as *mut libc::c_char;
             let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
             unsafe{Curl_infof(
                 data,
                 b"Establish HTTP proxy tunnel to %s:%d\0" as *const u8 as *const libc::c_char,
                 hostname,
                 remote_port,
             );}
             /* This only happens if we've looped here due to authentication
            reasons, and we don't really use the newly cloned URL here
            then. Just free() it. */
             #[cfg(not(CURLDEBUG))]
             unsafe{Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);}
             #[cfg(CURLDEBUG)]
             unsafe{curl_dbg_free(
                 (*data).req.newurl as *mut libc::c_void,
                 287 as i32,
                 b"http_proxy.c\0" as *const u8 as *const libc::c_char,
             );}
             // let ref mut fresh7 = (*data).req.newurl;
             unsafe{(*data).req.newurl = 0 as *mut libc::c_char;
              /* initialize send-buffer */
            Curl_dyn_init(req, (1024 as i32 * 1024 as i32) as size_t)};
             /* Setup the proxy-authorization header, if any */
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
             result = unsafe{Curl_http_output_auth(
                 data,
                 conn,
                 b"CONNECT\0" as *const u8 as *const libc::c_char,
                 HTTPREQ_GET,
                 hostheader,
                 1 as i32 != 0,
             )};
             if result as u64 == 0 {
                 let mut httpv: *const libc::c_char = if unsafe{ (*conn).http_proxy.proxytype as u32}
                     == CURLPROXY_HTTP_1_0 as u32
                 {
                     b"1.0\0" as *const u8 as *const libc::c_char
                 } else {
                     b"1.1\0" as *const u8 as *const libc::c_char
                 };
                 result = unsafe{Curl_dyn_addf(
                     req,
                     b"CONNECT %s HTTP/%s\r\n%s%s\0" as *const u8 as *const libc::c_char,
                     hostheader, /* Host: */
                     httpv,/* Proxy-Authorization */
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
                 )};
                 if result as u64 == 0
                     && unsafe{(Curl_checkProxyheaders(
                         data,
                         conn,
                         b"User-Agent\0" as *const u8 as *const libc::c_char,
                     ))
                     .is_null()}
                     && unsafe{!((*data).set.str_0[STRING_USERAGENT as usize]).is_null()}
                 {
                     result = unsafe{Curl_dyn_addf(
                         req,
                         b"User-Agent: %s\r\n\0" as *const u8 as *const libc::c_char,
                         (*data).set.str_0[STRING_USERAGENT as usize],
                     )};
                 }
                 if result as u64 == 0
                     && unsafe{(Curl_checkProxyheaders(
                         data,
                         conn,
                         b"Proxy-Connection\0" as *const u8 as *const libc::c_char,
                     ))
                     .is_null()}
                 { /* CRLF terminate the request */
                     result = unsafe{Curl_dyn_add(
                         req,
                         b"Proxy-Connection: Keep-Alive\r\n\0" as *const u8 as *const libc::c_char,
                     )};
                 }
                 if result as u64 == 0 {
                     /* Send the connect request to the proxy */
                     result = unsafe{Curl_add_custom_headers(data, 1 as i32 != 0, req)};
                 }
                 if result as u64 == 0 {
                     result = unsafe{Curl_dyn_add(req, b"\r\n\0" as *const u8 as *const libc::c_char)};
                 }
                 if result as u64 == 0 {
                     result = unsafe{Curl_buffer_send(
                         req,
                         data,
                         &mut (*data).info.request_size,
                         0 as curl_off_t,
                         sockindex,
                     )};
                 }
                 if result as u64 != 0 {
                    unsafe{Curl_failf(
                         data,
                         b"Failed sending CONNECT to proxy\0" as *const u8 as *const libc::c_char,
                     );}
                 }
             }
             #[cfg(not(CURLDEBUG))]
             unsafe{Curl_cfree.expect("non-null function pointer")(host as *mut libc::c_void);}
             #[cfg(CURLDEBUG)]
             unsafe{curl_dbg_free(
                 host as *mut libc::c_void,
                 340 as i32,
                 b"http_proxy.c\0" as *const u8 as *const libc::c_char,
             );}
             #[cfg(not(CURLDEBUG))]
             unsafe{Curl_cfree.expect("non-null function pointer")(hostheader as *mut libc::c_void);}
             #[cfg(CURLDEBUG)]
             unsafe{curl_dbg_free(
                 hostheader as *mut libc::c_void,
                 341 as i32,
                 b"http_proxy.c\0" as *const u8 as *const libc::c_char,
             );}
             if result as u64 != 0 {
                 return result;
             }
             unsafe{(*s).tunnel_state = TUNNEL_CONNECT;}/* END CONNECT PHASE */
         }
         check = unsafe{Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0)};
         if check <= 0 as i64 {
            unsafe{ Curl_failf(
                 data,
                 b"Proxy CONNECT aborted due to timeout\0" as *const u8 as *const libc::c_char,
             );}
             return CURLE_OPERATION_TIMEDOUT;
         }
         if unsafe{!Curl_conn_data_pending(conn, sockindex)} && unsafe{(*http).sending as u64 }== 0 {
             return CURLE_OK;  /* return so we'll be called again polling-style */
         }
         /* at this point, the tunnel_connecting phase is over. */
         if unsafe{(*http).sending as u32 }== HTTPSEND_REQUEST as u32 {
             if unsafe{(*s).nsend} == 0 {
                 let mut fillcount: size_t = 0;
                 // let ref mut fresh8 = (*k).upload_fromhere;
                 unsafe{(*k).upload_fromhere = (*data).state.ulbuf;
                 result = Curl_fillreadbuffer(
                     data,
                     (*data).set.upload_buffer_size as size_t,
                     &mut fillcount,
                 );}
                 if result as u64 != 0 {
                     return result;
                 }
                 unsafe{(*s).nsend = fillcount;}
             }
             if unsafe{(*s).nsend }!= 0 {
                 let mut bytes_written: ssize_t = 0; /* write to socket (send away data) */
                 result = unsafe{Curl_write(
                     data,
                     (*conn).writesockfd, /* socket to send to */
                     (*k).upload_fromhere as *const libc::c_void, /* buffer pointer */
                     (*s).nsend, /* buffer size */
                     &mut bytes_written, /* actually sent */
                 )};
                 if result as u64 == 0 {
                     /* send to debug callback! */
                     result = unsafe{Curl_debug(
                         data,
                         CURLINFO_HEADER_OUT,
                         (*k).upload_fromhere,
                         bytes_written as size_t,
                     ) as CURLcode};
                 }
                 // let ref mut fresh9 = (*s).nsend;
                 unsafe{(*s).nsend = ((*s).nsend as u64).wrapping_sub(bytes_written as u64)
                     as size_t as size_t;
                 // let ref mut fresh10 = (*k).upload_fromhere;
                 (*k).upload_fromhere = ((*k).upload_fromhere).offset(bytes_written as isize);}
                 return result;
             }
             unsafe{(*http).sending = HTTPSEND_NADA;}
              /* if nothing left to send, continue */
         }
          /* READING RESPONSE PHASE */
         let mut error: i32 = 0 as i32;
         while unsafe{(*s).keepon as u64} != 0 {
             let mut gotbytes: ssize_t = 0;
             let mut byte: libc::c_char = 0;
              /* Read one byte at a time to avoid a race condition. Wait at most one
            second before looping to ensure continuous pgrsUpdates. */
             result = unsafe{Curl_read(
                 data,
                 tunnelsocket,
                 &mut byte,
                 1 as size_t,
                 &mut gotbytes,
             )};
             if result as u32 == CURLE_AGAIN as u32 {
                  /* socket buffer drained, return */
                 return CURLE_OK;
             }
             if unsafe{Curl_pgrsUpdate(data)} != 0 {
                 return CURLE_ABORTED_BY_CALLBACK;
             }
             if result as u64 != 0 {
                unsafe{(*s).keepon = KEEPON_DONE;}
                 break;
             } else if gotbytes <= 0 as i64 {
                 if unsafe{(*data).set.proxyauth} != 0
                     && unsafe{(*data).state.authproxy.avail} != 0
                     && unsafe{!((*data).state.aptr.proxyuserpwd).is_null()}
                 { /* proxy auth was requested and there was proxy auth available,
                     then deem this as "mere" proxy disconnect */
                     // let ref mut fresh11 = (*conn).bits;
                     unsafe{((*conn).bits).set_proxy_connect_closed(1 as bit);
                     Curl_infof(
                         data,
                         b"Proxy CONNECT connection closed\0" as *const u8 as *const libc::c_char,
                     );}
                 } else {
                     error = 1 as i32;
                     unsafe{
                     Curl_failf(
                         data,
                         b"Proxy CONNECT aborted\0" as *const u8 as *const libc::c_char,
                     );}
                 }
                 unsafe{ (*s).keepon = KEEPON_DONE;}
                 break;
             } else if unsafe{(*s).keepon as u32} == KEEPON_IGNORE as u32 {
                 /* This means we are currently ignoring a response-body */
                 if unsafe{(*s).cl} != 0 {
                     // let ref mut fresh12 = (*s).cl;
                     /* A Content-Length based body: simply count down the counter
                and make sure to break out of the loop when we're done! */
                unsafe{(*s).cl -= 1;
                     if !((*s).cl <= 0 as i64) {
                         continue;
                     }
                     (*s).keepon = KEEPON_DONE;
                     (*s).tunnel_state = TUNNEL_COMPLETE;}
                     break;
                 } else {
                     /* chunked-encoded body, so we need to do the chunked dance
                properly to know when the end of the body is reached */
                     let mut r: CHUNKcode = CHUNKE_OK;
                     let mut extra: CURLcode = CURLE_OK;
                     let mut tookcareof: ssize_t = 0 as ssize_t;
                     /* now parse the chunked piece of data so that we can
                properly tell when the stream ends */
                     r = unsafe{Curl_httpchunk_read(
                         data,
                         &mut byte,
                         1 as ssize_t,
                         &mut tookcareof,
                         &mut extra,
                     )};
                     if r as i32 == CHUNKE_STOP as i32 {
                         /* we're done reading chunks! */
                         unsafe{
                         Curl_infof(
                             data,
                             b"chunk reading DONE\0" as *const u8 as *const libc::c_char,
                         );
                         (*s).keepon = KEEPON_DONE;
                          /* we did the full CONNECT treatment, go COMPLETE */
                         (*s).tunnel_state = TUNNEL_COMPLETE;
                        }
                     }
                 }
             } else {
                 if unsafe{Curl_dyn_addn(
                     &mut (*s).rcvbuf,
                     &mut byte as *mut libc::c_char as *const libc::c_void,
                     1 as size_t,
                 ) as u64}
                     != 0
                 {
                    unsafe{ Curl_failf(
                         data,
                         b"CONNECT response too large!\0" as *const u8 as *const libc::c_char,
                     );}
                     return CURLE_RECV_ERROR;
                 }
                      /* if this is not the end of a header line then continue */
                 if byte as i32 != 0xa as i32 {
                     continue;
                 }
                 linep = unsafe{Curl_dyn_ptr(&mut (*s).rcvbuf)};
                 perline = unsafe{Curl_dyn_len(&mut (*s).rcvbuf)};/* amount of bytes in this line */
                  /* convert from the network encoding */
                 result = CURLE_OK as CURLcode;
                  /* Curl_convert_from_network calls failf if unsuccessful */
                 if result as u64 != 0 {
                     return result;
                 }
                 /* output debug if that is requested */
                 unsafe{ Curl_debug(data, CURLINFO_HEADER_IN, linep, perline);
                 if ((*data).set).suppress_connect_headers() == 0 {
                      /* send the header to the callback */
                     let mut writetype: i32 = (1 as i32) << 1 as i32;
                     if ((*data).set).include_header() != 0 {
                         writetype |= (1 as i32) << 0 as i32;
                     }
                     result = Curl_client_write(data, writetype, linep, perline);
                     if result as u64 != 0 {
                         return result;
                     }
                 }
                 // let ref mut fresh13 = (*data).info.header_size;
                 (*data).info.header_size += perline as i64;
                }
                  /* Newlines are CRLF, so the CR is ignored as the line isn't
            really terminated until the LF comes. Treat a following CR
            as end-of-headers as well.*/
                 if '\r' as i32 == unsafe{*linep.offset(0 as isize) as i32}
                     || '\n' as i32 == unsafe{*linep.offset(0 as isize) as i32}
                 { /* end of response-headers from the proxy */
                     if 407 as i32 == unsafe{(*k).httpcode} && unsafe{((*data).state).authproblem()} == 0 {
                        unsafe{
                          /* If we get a 407 response code with content length
                when we have no auth problem, we must ignore the
                whole response-body */
                         (*s).keepon = KEEPON_IGNORE;
                         if (*s).cl != 0 {
                             Curl_infof(
                                 data,
                                 b"Ignore %ld bytes of response-body\0" as *const u8
                                     as *const libc::c_char,
                                 (*s).cl,
                             );
                               /* We set ignorebody true here since the chunked decoder
                  function will acknowledge that. Pay attention so that this is
                  cleared again when this function returns! */
                         } else if (*s).chunked_encoding() != 0 {
                             let mut r_0: CHUNKcode = CHUNKE_OK;
                             let mut extra_0: CURLcode = CURLE_OK;
                             Curl_infof(
                                 data,
                                 b"Ignore chunked response-body\0" as *const u8
                                     as *const libc::c_char,
                             );
                             (*k).set_ignorebody(1 as bit);
                             if *linep.offset(1 as isize) as i32
                                 == '\n' as i32
                             {
                                  /* this can only be a LF if the letter at index 0 was a CR */
                                 linep = linep.offset(1);
                             }
                             /* now parse the chunked piece of data so that we can properly
                  tell when the stream ends */
                             r_0 = Curl_httpchunk_read(
                                 data,
                                 linep.offset(1 as isize),
                                 1 as ssize_t,
                                 &mut gotbytes,
                                 &mut extra_0,
                             );
                             if r_0 as i32 == CHUNKE_STOP as i32 {
                                 /* we're done reading chunks! */
                                 Curl_infof(
                                     data,
                                     b"chunk reading DONE\0" as *const u8 as *const libc::c_char,
                                 );
                                 (*s).keepon = KEEPON_DONE;
                                  /* we did the full CONNECT treatment, go to COMPLETE */
                                 (*s).tunnel_state = TUNNEL_COMPLETE;
                                }
                         } else {
                               /* without content-length or chunked encoding, we
                  can't keep the connection alive since the close is
                  the end signal so we bail out at once instead */
                             (*s).keepon = KEEPON_DONE;
                         }
                        }
                        } else {
                            unsafe{
                         (*s).keepon = KEEPON_DONE;}
                     }
                     if unsafe{(*s).keepon as u32} == KEEPON_DONE as u32
                         && unsafe{(*s).cl }== 0
                     {   unsafe{
                         /* we did the full CONNECT treatment, go to COMPLETE */
                         (*s).tunnel_state = TUNNEL_COMPLETE;}
                     }
                     #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
                     if unsafe{(*s).keepon as u32} == KEEPON_IGNORE as u32
                         || unsafe{(*s).keepon as u32} == KEEPON_DONE as u32
                     {
                     } else {
                        unsafe{
                         __assert_fail(
                             b"s->keepon == KEEPON_IGNORE || s->keepon == KEEPON_DONE\0" as *const u8
                                 as *const libc::c_char,
                             b"http_proxy.c\0" as *const u8 as *const libc::c_char,
                             555 as u32,
                             (*::std::mem::transmute::<&[u8; 61], &[libc::c_char; 61]>(
                                 b"CURLcode CONNECT(struct Curl_easy *, int, const char *, int)\0",
                             ))
                             .as_ptr(),
                         );
                        }
                     }
                 } else {
                    unsafe{
                     if curl_strnequal(
                         b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char,
                         linep,
                         strlen(b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char),
                     ) != 0
                         && 401 as i32 == (*k).httpcode
                         || curl_strnequal(
                             b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char,
                             linep,
                             strlen(b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char),
                         ) != 0
                             && 407 as i32 == (*k).httpcode
                     {
                         let mut proxy: bool = if (*k).httpcode == 407 as i32 {
                             1 as i32
                         } else {
                             0 as i32
                         } != 0;
                         let mut auth: *mut libc::c_char = Curl_copy_header_value(linep);
                         if auth.is_null() {
                             return CURLE_OUT_OF_MEMORY;
                         }
                         result = Curl_http_input_auth(data, proxy, auth);
                         #[cfg(not(CURLDEBUG))]
                         Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
                         #[cfg(CURLDEBUG)]
                         curl_dbg_free(
                             auth as *mut libc::c_void,
                             571 as i32,
                             b"http_proxy.c\0" as *const u8 as *const libc::c_char,
                         );
                         if result as u64 != 0 {
                             return result;
                         }
                     } else if curl_strnequal(
                         b"Content-Length:\0" as *const u8 as *const libc::c_char,
                         linep,
                         strlen(b"Content-Length:\0" as *const u8 as *const libc::c_char),
                     ) != 0
                     {
                         if (*k).httpcode / 100 as i32 == 2 as i32 {
                              /* A client MUST ignore any Content-Length or Transfer-Encoding
                header fields received in a successful response to CONNECT.
                "Successful" described as: 2xx (Successful). RFC 7231 4.3.6 */
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
                                 10 as i32,
                                 &mut (*s).cl,
                             );
                         }
                     } else if Curl_compareheader(
                         linep,
                         b"Connection:\0" as *const u8 as *const libc::c_char,
                         b"close\0" as *const u8 as *const libc::c_char,
                     ) {
                         (*s).set_close_connection(1 as bit);
                     } else if curl_strnequal(
                         b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
                         linep,
                         strlen(b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char),
                     ) != 0
                     {
                         if (*k).httpcode / 100 as i32 == 2 as i32 {
                              /* A client MUST ignore any Content-Length or Transfer-Encoding
                header fields received in a successful response to CONNECT.
                "Successful" described as: 2xx (Successful). RFC 7231 4.3.6 */
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
                             );  /* init our chunky engine */
                             (*s).set_chunked_encoding(1 as i32 as bit);
                             Curl_httpchunk_init(data);
                         }
                     } else if Curl_compareheader(
                         linep,
                         b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
                         b"close\0" as *const u8 as *const libc::c_char,
                     ) {
                         (*s).set_close_connection(1 as i32 as bit);
                     } else if 2 as i32
                         == sscanf(
                             linep,
                             b"HTTP/1.%d %d\0" as *const u8 as *const libc::c_char,
                             &mut subversion as *mut i32,
                             &mut (*k).httpcode as *mut i32,
                         )
                     {/* store the HTTP code from the proxy */
                         (*data).info.httpproxycode = (*k).httpcode;
                     }
                     Curl_dyn_reset(&mut (*s).rcvbuf);
                    }
                 } /* while there's buffer left and loop is requested */
             }
         }
         if unsafe{Curl_pgrsUpdate(data)} != 0 {
             return CURLE_ABORTED_BY_CALLBACK;
         }
         if error != 0 {
             return CURLE_RECV_ERROR;
         }
         if unsafe{(*data).info.httpproxycode / 100 as i32 }!= 2 as i32 {
             /* Deal with the possibly already received authenticate
            headers. 'newurl' is set to a new URL if we must loop. */
             result = unsafe{Curl_http_auth_act(data)};
             if result as u64 != 0 {
                 return result;
             }
             if unsafe{ ((*conn).bits).close() }!= 0 {
                  /* the connection has been marked for closure, most likely in the
              Curl_http_auth_act() function and thus we can kill it at once
              below */
              unsafe{(*s).set_close_connection(1 as bit);}
             }
         }
         if unsafe{(*s).close_connection() as i32} != 0 && unsafe{!((*data).req.newurl).is_null()} {
            unsafe{
              /* Connection closed by server. Don't use it anymore */
             Curl_closesocket(data, conn, (*conn).sock[sockindex as usize]);
             (*conn).sock[sockindex as usize] = -(1 as i32);
            }
             break;
         } else {
             if unsafe{!((*data).req.newurl).is_null()}
                 && TUNNEL_COMPLETE as u32
                     == unsafe{(*s).tunnel_state as u32}
             {
                 connect_init(data, 1 as i32 != 0);
             }
             if unsafe{((*data).req.newurl).is_null()} {
                 break;
             }
         } /* END READING RESPONSE PHASE */
     }
      /* If we are supposed to continue and request a new URL, which basically
      * means the HTTP authentication is still going on so if the tunnel
      * is complete we start over in INIT state */
     if unsafe{(*data).info.httpproxycode / 100 as i32} != 2 as i32 {
         if unsafe{(*s).close_connection() as i32} != 0 && unsafe{!((*data).req.newurl).is_null()} {
             // let ref mut fresh14 = (*conn).bits;
             unsafe{((*conn).bits).set_proxy_connect_closed(1 as bit);
             Curl_infof(
                 data,
                 b"Connect me again please\0" as *const u8 as *const libc::c_char,
             );
             connect_done(data);
            }
         } else {
             #[cfg(not(CURLDEBUG))]
             unsafe{Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);}
             #[cfg(CURLDEBUG)]
             unsafe{curl_dbg_free(
                 (*data).req.newurl as *mut libc::c_void,
                 663 as i32,
                 b"http_proxy.c\0" as *const u8 as *const libc::c_char,
             );
             // let ref mut fresh15 = (*data).req.newurl;
             (*data).req.newurl = 0 as *mut libc::c_char;}
             #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
             unsafe{Curl_conncontrol(conn, 2 as i32);}
             #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
             unsafe{Curl_conncontrol(
                 conn,
                 2 as i32,
                 b"proxy CONNECT failure\0" as *const u8 as *const libc::c_char,
             );
             Curl_closesocket(data, conn, (*conn).sock[sockindex as usize]);
             (*conn).sock[sockindex as usize] = -(1 as i32);}
         }
         unsafe{(*s).tunnel_state = TUNNEL_INIT;}/* to back to init state */
         if unsafe{((*conn).bits).proxy_connect_closed()} != 0 {
              /* this is not an error, just part of the connection negotiation */
             return CURLE_OK;
         }
         unsafe{Curl_dyn_free(&mut (*s).rcvbuf);
         Curl_failf(
             data,
             b"Received HTTP code %d from proxy after CONNECT\0" as *const u8 as *const libc::c_char,
             (*data).req.httpcode,
         );}
         return CURLE_RECV_ERROR;
     }
     unsafe{(*s).tunnel_state = TUNNEL_COMPLETE;}
     /* If a proxy-authorization header was used for the proxy, then we should
      make sure that it isn't accidentally used for the document request
      after we've connected. So let's free and clear it here. */
     #[cfg(not(CURLDEBUG))]
     unsafe{Curl_cfree.expect("non-null function pointer")(
         (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
     );}
     #[cfg(CURLDEBUG)]
     unsafe{ curl_dbg_free(
         (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
         688 as i32,
         b"http_proxy.c\0" as *const u8 as *const libc::c_char,
     );
     // let ref mut fresh16 = (*data).state.aptr.proxyuserpwd;
     (*data).state.aptr.proxyuserpwd = 0 as *mut libc::c_char;
     // let ref mut fresh17 = (*data).state.aptr.proxyuserpwd;
     (*data).state.aptr.proxyuserpwd = 0 as *mut libc::c_char;
     // let ref mut fresh18 = (*data).state.authproxy;
     ((*data).state.authproxy).set_done(1 as bit);
     // let ref mut fresh19 = (*data).state.authproxy;
     ((*data).state.authproxy).set_multipass(0 as bit);
     Curl_infof(
         data,
         b"Proxy replied %d to CONNECT request\0" as *const u8 as *const libc::c_char,
         (*data).info.httpproxycode,
     );
     // let ref mut fresh20 = (*data).req;
     ((*data).req).set_ignorebody(0 as bit);/* put it (back) to non-ignore state */
     // let ref mut fresh21 = (*conn).bits;
     ((*conn).bits).set_rewindaftersend(0 as bit);/* make sure this isn't set for the
     document request  */
     Curl_dyn_free(&mut (*s).rcvbuf);}
     return CURLE_OK;
 }
 /* The Hyper version of CONNECT */
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP), USE_HYPER))]
 extern "C" fn CONNECT(
     mut data: *mut Curl_easy,
     mut sockindex: i32,
     mut hostname: *const libc::c_char,
     mut remote_port: i32,
 ) -> CURLcode {
     let mut current_block: u64;
     let mut conn: *mut connectdata = unsafe {(*data).conn};
     let mut h: *mut hyptransfer = unsafe {&mut (*data).hyp};
     let mut tunnelsocket: curl_socket_t = unsafe {(*conn).sock[sockindex as usize]};
     let mut s: *mut http_connect_state = unsafe {(*conn).connect_state};
     let mut result: CURLcode = CURLE_OUT_OF_MEMORY;
     let mut io: *mut hyper_io = 0 as *mut hyper_io;
     let mut req: *mut hyper_request = 0 as *mut hyper_request;
     let mut headers: *mut hyper_headers = 0 as *mut hyper_headers;
     let mut options: *mut hyper_clientconn_options = 0 as *mut hyper_clientconn_options;
     let mut handshake: *mut hyper_task = 0 as *mut hyper_task;
     let mut task: *mut hyper_task = 0 as *mut hyper_task; /* for the handshake */
     let mut sendtask: *mut hyper_task = 0 as *mut hyper_task;/* for the send */
     let mut client: *mut hyper_clientconn = 0 as *mut hyper_clientconn;
     let mut hypererr: *mut hyper_error = 0 as *mut hyper_error;
     let mut hostheader: *mut libc::c_char = 0 as *mut libc::c_char; /* for CONNECT */
     let mut host: *mut libc::c_char = 0 as *mut libc::c_char;/* Host: */
     if Curl_connect_complete(conn) {
         return CURLE_OK;/* CONNECT is already completed */
     }
     // let ref mut fresh6 = (*conn).bits;
     unsafe {((*conn).bits).set_proxy_connect_closed(0 as bit);}
     's_65: loop {
        unsafe {
         match (*s).tunnel_state as u32 {
             0 => {
                  /* BEGIN CONNECT PHASE */
                 io = hyper_io_new();
                 if io.is_null() {
                     Curl_failf(
                         data,
                         b"Couldn't create hyper IO\0" as *const u8 as *const libc::c_char,
                     );
                     current_block = 14523688961733284890;
                     break;
                 } else {
                      /* tell Hyper how to read/write network data */
                     hyper_io_set_userdata(io, data as *mut libc::c_void);
                     hyper_io_set_read(
                         io,
                         Some(
                             Curl_hyper_recv
                                 as unsafe extern "C" fn(
                                     *mut libc::c_void,
                                     *mut hyper_context,
                                     *mut uint8_t,
                                     size_t,
                                 ) -> size_t,
                         ),
                     );
                     hyper_io_set_write(
                         io,
                         Some(
                             Curl_hyper_send
                                 as unsafe extern "C" fn(
                                     *mut libc::c_void,
                                     *mut hyper_context,
                                     *const uint8_t,
                                     size_t,
                                 ) -> size_t,
                         ),
                     );
                     (*conn).sockfd = tunnelsocket;
                     (*data).state.hconnect = 1 as i32 != 0;
                     /* create an executor to poll futures */
                     if ((*h).exec).is_null() {
                         // let ref mut fresh7 = (*h).exec;
                         (*h).exec = hyper_executor_new();
                         if ((*h).exec).is_null() {
                             Curl_failf(
                                 data,
                                 b"Couldn't create hyper executor\0" as *const u8
                                     as *const libc::c_char,
                             );
                             current_block = 14523688961733284890;
                             break;
                         }
                     }
                     options = hyper_clientconn_options_new();
                     if options.is_null() {
                         Curl_failf(
                             data,
                             b"Couldn't create hyper client options\0" as *const u8
                                 as *const libc::c_char,
                         );
                         current_block = 14523688961733284890;
                         break;
                     } else {
                         hyper_clientconn_options_exec(options, (*h).exec);
                         /* "Both the `io` and the `options` are consumed in this function
          call" */
                         handshake = hyper_clientconn_handshake(io, options); /* ownership passed on */
                         if handshake.is_null() {
                             Curl_failf(
                                 data,
                                 b"Couldn't create hyper client handshake\0" as *const u8
                                     as *const libc::c_char,
                             );
                             current_block = 14523688961733284890;
                             break;
                         } else {
                             io = 0 as *mut hyper_io;
                             options = 0 as *mut hyper_clientconn_options;
                             if HYPERE_OK as u32
                                 != hyper_executor_push((*h).exec, handshake) as u32
                             {
                                 Curl_failf(
                                     data,
                                     b"Couldn't hyper_executor_push the handshake\0" as *const u8
                                         as *const libc::c_char,
                                 );
                                 current_block = 14523688961733284890;
                                 break;
                             } else {
                                 handshake = 0 as *mut hyper_task;
                                 task = hyper_executor_poll((*h).exec);
                                 if task.is_null() {
                                     Curl_failf(
                                         data,
                                         b"Couldn't hyper_executor_poll the handshake\0" as *const u8
                                             as *const libc::c_char,
                                     );
                                     current_block = 14523688961733284890;
                                     break;
                                 } else {
                                     client = hyper_task_value(task) as *mut hyper_clientconn;
                                     hyper_task_free(task);
                                     req = hyper_request_new();
                                     if req.is_null() {
                                         Curl_failf(
                                             data,
                                             b"Couldn't hyper_request_new\0" as *const u8
                                                 as *const libc::c_char,
                                         );
                                         current_block = 14523688961733284890;
                                         break;
                                     } else if hyper_request_set_method(
                                         req,
                                         b"CONNECT\0" as *const u8 as *const libc::c_char
                                             as *mut uint8_t,
                                         strlen(b"CONNECT\0" as *const u8 as *const libc::c_char),
                                     ) as u64
                                         != 0
                                     {
                                         Curl_failf(
                                             data,
                                             b"error setting method\0" as *const u8
                                                 as *const libc::c_char,
                                         );
                                         current_block = 14523688961733284890;
                                         break;
                                     } else {
                                         result = CONNECT_host(
                                             data,
                                             conn,
                                             hostname,
                                             remote_port,
                                             &mut hostheader,
                                             &mut host,
                                         );
                                         if result as u64 != 0 {
                                             current_block = 14523688961733284890;
                                             break;
                                         }
                                         if hyper_request_set_uri(
                                             req,
                                             hostheader as *mut uint8_t,
                                             strlen(hostheader),
                                         ) as u64
                                             != 0
                                         {
                                             Curl_failf(
                                                 data,
                                                 b"error setting path\0" as *const u8
                                                     as *const libc::c_char,
                                             );
                                             result = CURLE_OUT_OF_MEMORY;
                                         }
                                          /* Setup the proxy-authorization header, if any */
                                         result = Curl_http_output_auth(
                                             data,
                                             conn,
                                             b"CONNECT\0" as *const u8 as *const libc::c_char,
                                             HTTPREQ_GET,
                                             hostheader,
                                             1 as i32 != 0,
                                         );
                                         if result as u64 != 0 {
                                             current_block = 14523688961733284890;
                                             break;
                                         }
                                         Curl_cfree.expect("non-null function pointer")(
                                             hostheader as *mut libc::c_void,
                                         );
                                         hostheader = 0 as *mut libc::c_char;
                                          /* default is 1.1 */
                                         if (*conn).http_proxy.proxytype as u32
                                             == CURLPROXY_HTTP_1_0 as u32
                                             && HYPERE_OK as u32
                                                 != hyper_request_set_version(req, 10 as i32)
                                                     as u32
                                         {
                                             Curl_failf(
                                                 data,
                                                 b"error setting HTTP version\0" as *const u8
                                                     as *const libc::c_char,
                                             );
                                             current_block = 14523688961733284890;
                                             break;
                                         } else {
                                             headers = hyper_request_headers(req);
                                             if headers.is_null() {
                                                 Curl_failf(
                                                     data,
                                                     b"hyper_request_headers\0" as *const u8
                                                         as *const libc::c_char,
                                                 );
                                                 current_block = 14523688961733284890;
                                                 break;
                                             } else {
                                                 if !host.is_null()
                                                     && Curl_hyper_header(data, headers, host)
                                                         as u32
                                                         != 0
                                                 {
                                                     current_block = 14523688961733284890;
                                                     break;
                                                 }
                                                 Curl_cfree.expect("non-null function pointer")(
                                                     host as *mut libc::c_void,
                                                 );
                                                 host = 0 as *mut libc::c_char;
                                                 if !((*data).state.aptr.proxyuserpwd).is_null()
                                                     && Curl_hyper_header(
                                                         data,
                                                         headers,
                                                         (*data).state.aptr.proxyuserpwd,
                                                     )
                                                         as u32
                                                         != 0
                                                 {
                                                     current_block = 14523688961733284890;
                                                     break;
                                                 }
                                                 if (Curl_checkProxyheaders(
                                                     data,
                                                     conn,
                                                     b"User-Agent\0" as *const u8
                                                         as *const libc::c_char,
                                                 ))
                                                 .is_null()
                                                     && !((*data).set.str_0
                                                         [STRING_USERAGENT as usize])
                                                         .is_null()
                                                 {
                                                     let mut ua: dynbuf = dynbuf {
                                                         bufr: 0 as *mut libc::c_char,
                                                         leng: 0,
                                                         allc: 0,
                                                         toobig: 0,
                                                     };
                                                     Curl_dyn_init(
                                                         &mut ua,
                                                         (1024 as i32 * 1024 as i32)
                                                             as size_t,
                                                     );
                                                     result = Curl_dyn_addf(
                                                         &mut ua as *mut dynbuf,
                                                         b"User-Agent: %s\r\n\0" as *const u8
                                                             as *const libc::c_char,
                                                         (*data).set.str_0[STRING_USERAGENT
                                                             as i32
                                                             as usize],
                                                     );
                                                     if result as u64 != 0 {
                                                         current_block = 14523688961733284890;
                                                         break;
                                                     }
                                                     if Curl_hyper_header(
                                                         data,
                                                         headers,
                                                         Curl_dyn_ptr(&mut ua),
                                                     )
                                                         as u64
                                                         != 0
                                                     {
                                                         current_block = 14523688961733284890;
                                                         break;
                                                     }
                                                     Curl_dyn_free(&mut ua);
                                                 }
                                                 if (Curl_checkProxyheaders(
                                                     data,
                                                     conn,
                                                     b"Proxy-Connection\0" as *const u8
                                                         as *const libc::c_char,
                                                 ))
                                                 .is_null()
                                                     && Curl_hyper_header(
                                                         data,
                                                         headers,
                                                         b"Proxy-Connection: Keep-Alive\0"
                                                             as *const u8
                                                             as *const libc::c_char,
                                                     )
                                                         as u32
                                                         != 0
                                                 {
                                                     current_block = 14523688961733284890;
                                                     break;
                                                 }
                                                 if Curl_add_custom_headers(
                                                     data,
                                                     1 as i32 != 0,
                                                     headers as *mut libc::c_void,
                                                 )
                                                     as u64
                                                     != 0
                                                 {
                                                     current_block = 14523688961733284890;
                                                     break;
                                                 }
                                                 sendtask = hyper_clientconn_send(client, req);
                                                 if sendtask.is_null() {
                                                     Curl_failf(
                                                         data,
                                                         b"hyper_clientconn_send\0" as *const u8
                                                             as *const libc::c_char,
                                                     );
                                                     current_block = 14523688961733284890;
                                                     break;
                                                 } else if HYPERE_OK as u32
                                                     != hyper_executor_push((*h).exec, sendtask)
                                                         as u32
                                                 {
                                                     Curl_failf(
                                                         data,
                                                         b"Couldn't hyper_executor_push the send\0"
                                                             as *const u8
                                                             as *const libc::c_char,
                                                     );
                                                     current_block = 14523688961733284890;
                                                     break;
                                                 } else {
                                                     hyper_clientconn_free(client);
                                                     loop {
                                                         task = hyper_executor_poll((*h).exec);
                                                         if !task.is_null() {
                                                             let mut error: bool =
                                                                 hyper_task_type(task)
                                                                     as u32
                                                                     == HYPER_TASK_ERROR
                                                                         as u32;
                                                             if error {
                                                                 hypererr = hyper_task_value(task)
                                                                     as *mut hyper_error;
                                                             }
                                                             hyper_task_free(task);
                                                             if error {
                                                                 current_block =
                                                                     14523688961733284890;
                                                                 break 's_65;
                                                             }
                                                         }
                                                         if task.is_null() {
                                                             break;
                                                         }
                                                     }
                                                     (*s).tunnel_state = TUNNEL_CONNECT;
                                                 }
                                             }
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
                 current_block = 2945622622075328793;
             }
             1 => {
                 current_block = 2945622622075328793;
             }
             _ => {
                 current_block = 1841672684692190573;
             }
         }
         match current_block {
             2945622622075328793 => {
                 let mut didwhat: i32 = 0;
                 let mut done: bool = 0 as i32 != 0;
                 result = Curl_hyper_stream(
                     data,
                     conn,
                     &mut didwhat,
                     &mut done,
                     0x1 as i32 | 0x2 as i32,
                 );
                 if result as u64 != 0 {
                     current_block = 14523688961733284890;
                     break;
                 }
                 if done {
                     (*s).tunnel_state = TUNNEL_COMPLETE;
                     if !((*h).exec).is_null() {
                         hyper_executor_free((*h).exec);
                         // let ref mut fresh8 = (*h).exec;
                         (*h).exec = 0 as *const hyper_executor;
                     }
                     if !((*h).read_waker).is_null() {
                         hyper_waker_free((*h).read_waker);
                         // let ref mut fresh9 = (*h).read_waker;
                         (*h).read_waker = 0 as *mut hyper_waker;
                     }
                     if !((*h).write_waker).is_null() {
                         hyper_waker_free((*h).write_waker);
                         // let ref mut fresh10 = (*h).write_waker;
                         (*h).write_waker = 0 as *mut hyper_waker;
                     }
                 }
             }
             _ => {}
         }
         if ((*data).req.newurl).is_null() {
             current_block = 14027225908442187354;
             break;
         }
        }
        }
     match current_block {
         14027225908442187354 => {
             result = CURLE_OK;
             if unsafe {(*s).tunnel_state as u32} == TUNNEL_COMPLETE as u32 {
                unsafe {
                 (*data).info.httpproxycode = (*data).req.httpcode;}
                 if unsafe {(*data).info.httpproxycode / 100 as i32} != 2 as i32 {
                     if unsafe {((*conn).bits).close() as i32} != 0 &&unsafe { !((*data).req.newurl).is_null()}
                     {unsafe {
                         // let ref mut fresh11 = (*conn).bits;
                         ((*conn).bits).set_proxy_connect_closed(1 as bit);
                         Curl_infof(
                             data,
                             b"Connect me again please\0" as *const u8 as *const libc::c_char,
                         );
                         connect_done(data);
                        }
                     } else {
                        unsafe {
                         Curl_cfree.expect("non-null function pointer")(
                             (*data).req.newurl as *mut libc::c_void,
                         );
                         // let ref mut fresh12 = (*data).req.newurl;
                         (*data).req.newurl = 0 as *mut libc::c_char;
                         Curl_conncontrol(conn, 2 as i32);
                         Curl_closesocket(data, conn, (*conn).sock[sockindex as usize]);
                         (*conn).sock[sockindex as usize] = -(1 as i32);
                        }
                     }
                     unsafe {
                     (*s).tunnel_state = TUNNEL_INIT;}
                     if unsafe {((*conn).bits).proxy_connect_closed()} == 0 {
                        unsafe {
                         Curl_failf(
                             data,
                             b"Received HTTP code %d from proxy after CONNECT\0" as *const u8
                                 as *const libc::c_char,
                             (*data).req.httpcode,
                         );}
                         result = CURLE_RECV_ERROR;
                     }
                 }
             }
         }
         _ => {}
     }
     unsafe {
     Curl_cfree.expect("non-null function pointer")(host as *mut libc::c_void);
     Curl_cfree.expect("non-null function pointer")(hostheader as *mut libc::c_void);
     }
     if !io.is_null() {
        unsafe {
         hyper_io_free(io);
        }
     }
     if !options.is_null() {
        unsafe {
         hyper_clientconn_options_free(options);}
     }
     if !handshake.is_null() {
        unsafe {
         hyper_task_free(handshake);}
     }
     if !hypererr.is_null() {
         let mut errbuf: [uint8_t; 256] = [0; 256];
         let mut errlen: size_t = unsafe {hyper_error_print(
             hypererr,
             errbuf.as_mut_ptr(),
             ::std::mem::size_of::<[uint8_t; 256]>() as u64,
         )};
         unsafe {
         Curl_failf(
             data,
             b"Hyper: %.*s\0" as *const u8 as *const libc::c_char,
             errlen as i32,
             errbuf.as_mut_ptr(),
         );
         hyper_error_free(hypererr);}
     }
     return result;
 }
 
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 #[no_mangle]
 pub extern "C" fn Curl_connect_free(mut data: *mut Curl_easy) {
     let mut conn: *mut connectdata = unsafe{ (*data).conn};
     let mut s: *mut http_connect_state = unsafe{ (*conn).connect_state};
     if !s.is_null() {
         #[cfg(not(CURLDEBUG))]
         unsafe{ Curl_cfree.expect("non-null function pointer")(s as *mut libc::c_void);}
         #[cfg(CURLDEBUG)]
         unsafe{ curl_dbg_free(
             s as *mut libc::c_void,
             968 as i32,
             b"http_proxy.c\0" as *const u8 as *const libc::c_char,
         );
         // let ref mut fresh22 = (*conn).connect_state;
         (*conn).connect_state = 0 as *mut http_connect_state;}
     }

 }
 #[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
 #[no_mangle]
 pub extern "C" fn Curl_proxyCONNECT(
     mut data: *mut Curl_easy,
     mut sockindex: i32,
     mut hostname: *const libc::c_char,
     mut remote_port: i32,
 ) -> CURLcode {

     let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = unsafe{ (*data).conn};
     if unsafe{ ((*conn).connect_state).is_null() }{
         result = unsafe{ connect_init(data, 0 as i32 != 0)};
         if result as u64 != 0 {
             return result;
         }
     }
     result = unsafe{ CONNECT(data, sockindex, hostname, remote_port)};
     if result as u32 != 0 || unsafe{ Curl_connect_complete(conn) as i32} != 0 {
         connect_done(data);
     }
     return result;

 }
 
 /*
  * Curl_proxyCONNECT() requires that we're connected to a HTTP proxy. This
  * function will issue the necessary commands to get a seamless tunnel through
  * this proxy. After that, the socket can be used just as a normal socket.
  */
 #[cfg(any(CURL_DISABLE_PROXY, CURL_DISABLE_HTTP))]
 #[no_mangle]
 pub extern "C" fn Curl_proxyCONNECT(
     mut data: *mut Curl_easy,
     mut sockindex: i32,
     mut hostname: *const libc::c_char,
     mut remote_port: i32,
 ) -> CURLcode {
     unsafe{
     return CURLE_NOT_BUILT_IN;
     }
 }
 #[cfg(any(CURL_DISABLE_PROXY, CURL_DISABLE_HTTP))]
 #[no_mangle]
 pub extern "C" fn Curl_proxy_connect(
     mut data: *mut Curl_easy,
     mut sockindex: i32,
 ) -> CURLcode {
     unsafe{
     return CURLE_OK;
     }
 }
 #[cfg(any(CURL_DISABLE_PROXY, CURL_DISABLE_HTTP))]
 #[no_mangle]
 pub extern "C" fn Curl_connect_ongoing(mut conn: *mut connectdata) -> bool {
     unsafe{
     return false;
     }
 }
 #[cfg(any(CURL_DISABLE_PROXY, CURL_DISABLE_HTTP))]
 #[no_mangle]
 pub extern "C" fn Curl_connect_free(mut data: *mut Curl_easy) {}
 