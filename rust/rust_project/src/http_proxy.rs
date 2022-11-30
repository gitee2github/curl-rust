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

#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
unsafe extern "C" fn https_proxy_connect(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
) -> CURLcode {
    if cfg!(USE_SSL) {
    let mut conn: *mut connectdata = (*data).conn;
    let mut result: CURLcode = CURLE_OK;
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if (*conn).http_proxy.proxytype as libc::c_uint
        == CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"conn->http_proxy.proxytype == CURLPROXY_HTTPS\0" as *const u8
                as *const libc::c_char,
            b"http_proxy.c\0" as *const u8 as *const libc::c_char,
            60 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 54],
                &[libc::c_char; 54],
            >(b"CURLcode https_proxy_connect(struct Curl_easy *, int)\0"))
                .as_ptr(),
        );
    }
    if !(*conn).bits.proxy_ssl_connected[sockindex as usize] {
        result = Curl_ssl_connect_nonblocking(
            data,
            conn,
            1 as libc::c_int != 0,
            sockindex,
            &mut *((*conn).bits.proxy_ssl_connected)
                .as_mut_ptr()
                .offset(sockindex as isize),
        );
        if result as u64 != 0 {
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as libc::c_int,
                b"TLS handshake failed\0" as *const u8 as *const libc::c_char,
            );
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as libc::c_int);
        }
    }
    return result;
    } else {
        return CURLE_NOT_BUILT_IN;
}
}
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
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
        if cfg!(not(CURL_DISABLE_PROXY)) {
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
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
        );
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
            120 as libc::c_int,
            b"http_proxy.c\0" as *const u8 as *const libc::c_char,
        );
        let ref mut fresh0 = (*data).state.aptr.proxyuserpwd;
        *fresh0 = 0 as *mut libc::c_char;
        } else {
            return CURLE_NOT_BUILT_IN;
        }
    }
    return CURLE_OK;
}
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_complete(mut conn: *mut connectdata) -> bool {
    return ((*conn).connect_state).is_null()
        || (*(*conn).connect_state).tunnel_state as libc::c_uint
            >= TUNNEL_COMPLETE as libc::c_int as libc::c_uint;
}
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_ongoing(mut conn: *mut connectdata) -> bool {
    return !((*conn).connect_state).is_null()
        && (*(*conn).connect_state).tunnel_state as libc::c_uint
            <= TUNNEL_COMPLETE as libc::c_int as libc::c_uint;
}
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_getsock(mut conn: *mut connectdata) -> libc::c_int {
    let mut http: *mut HTTP = 0 as *mut HTTP;
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !conn.is_null() {} else {
        __assert_fail(
            b"conn\0" as *const u8 as *const libc::c_char,
            b"http_proxy.c\0" as *const u8 as *const libc::c_char,
            147 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 47],
                &[libc::c_char; 47],
            >(b"int Curl_connect_getsock(struct connectdata *)\0"))
                .as_ptr(),
        );
    }
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !((*conn).connect_state).is_null() {} else {
        __assert_fail(
            b"conn->connect_state\0" as *const u8 as *const libc::c_char,
            b"http_proxy.c\0" as *const u8 as *const libc::c_char,
            148 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 47],
                &[libc::c_char; 47],
            >(b"int Curl_connect_getsock(struct connectdata *)\0"))
                .as_ptr(),
        );
    }
    http = &mut (*(*conn).connect_state).http_proxy;
    if (*http).sending as libc::c_uint == HTTPSEND_REQUEST as libc::c_int as libc::c_uint {
        return (1 as libc::c_int) << 16 as libc::c_int + 0 as libc::c_int;
    }
    return (1 as libc::c_int) << 0 as libc::c_int;
}
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
unsafe extern "C" fn connect_init(mut data: *mut Curl_easy, mut reinit: bool) -> CURLcode {
    let mut s: *mut http_connect_state = 0 as *mut http_connect_state;
    let mut conn: *mut connectdata = (*data).conn;
    if !reinit {
        let mut result: CURLcode = CURLE_OK;
        #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
        if ((*conn).connect_state).is_null() {} else {
            __assert_fail(
                b"!conn->connect_state\0" as *const u8 as *const libc::c_char,
                b"http_proxy.c\0" as *const u8 as *const libc::c_char,
                163 as libc::c_int as libc::c_uint,
                (*::std::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"CURLcode connect_init(struct Curl_easy *, _Bool)\0"))
                    .as_ptr(),
            );
        }
        result = Curl_get_upload_buffer(data);
        if result as u64 != 0 {
            return result;
        }
        #[cfg(not(CURLDEBUG))]
        let news: *mut http_connect_state = Curl_ccalloc.expect("non-null function pointer")(
            1 as libc::c_int as size_t,
            ::std::mem::size_of::<http_connect_state>() as libc::c_ulong,
        ) as *mut http_connect_state;
        #[cfg(CURLDEBUG)]
        let news: *mut http_connect_state = curl_dbg_calloc(
            1 as libc::c_int as size_t,
            ::std::mem::size_of::<http_connect_state>() as libc::c_ulong,
            169 as libc::c_int,
            b"http_proxy.c\0" as *const u8 as *const libc::c_char,
        ) as *mut http_connect_state;
        s = news;
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
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 0 as libc::c_int);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            0 as libc::c_int,
            b"HTTP proxy CONNECT\0" as *const u8 as *const libc::c_char,
        );
    } else {
        #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
        if !((*conn).connect_state).is_null() {} else {
            __assert_fail(
                b"conn->connect_state\0" as *const u8 as *const libc::c_char,
                b"http_proxy.c\0" as *const u8 as *const libc::c_char,
                190 as libc::c_int as libc::c_uint,
                (*::std::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"CURLcode connect_init(struct Curl_easy *, _Bool)\0"))
                    .as_ptr(),
            );
        }
        s = (*conn).connect_state;
        Curl_dyn_reset(&mut (*s).rcvbuf);
    }
    (*s).tunnel_state = TUNNEL_INIT;
    (*s).keepon = KEEPON_CONNECT;
    (*s).cl = 0 as libc::c_int as curl_off_t;
    (*s).set_close_connection(0 as libc::c_int as bit);
    return CURLE_OK;
}
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
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
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
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
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(hostheader as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                hostheader as *mut libc::c_void,
                240 as libc::c_int,
                b"http_proxy.c\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OUT_OF_MEMORY;
        }
    }
    *connecthostp = hostheader;
    *hostp = host;
    return CURLE_OK;
}
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP), not(USE_HYPER)))]
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
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*data).req.newurl as *mut libc::c_void,
                287 as libc::c_int,
                b"http_proxy.c\0" as *const u8 as *const libc::c_char,
            );
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
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(host as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                host as *mut libc::c_void,
                340 as libc::c_int,
                b"http_proxy.c\0" as *const u8 as *const libc::c_char,
            );
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(hostheader as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                hostheader as *mut libc::c_void,
                341 as libc::c_int,
                b"http_proxy.c\0" as *const u8 as *const libc::c_char,
            );
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
                    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
                    if (*s).keepon as libc::c_uint
                        == KEEPON_IGNORE as libc::c_int as libc::c_uint
                        || (*s).keepon as libc::c_uint
                            == KEEPON_DONE as libc::c_int as libc::c_uint
                    {} else {
                        __assert_fail(
                            b"s->keepon == KEEPON_IGNORE || s->keepon == KEEPON_DONE\0"
                                as *const u8 as *const libc::c_char,
                            b"http_proxy.c\0" as *const u8 as *const libc::c_char,
                            555 as libc::c_int as libc::c_uint,
                            (*::std::mem::transmute::<
                                &[u8; 61],
                                &[libc::c_char; 61],
                            >(
                                b"CURLcode CONNECT(struct Curl_easy *, int, const char *, int)\0",
                            ))
                                .as_ptr(),
                        );
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
                        #[cfg(not(CURLDEBUG))]
                        Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
                        #[cfg(CURLDEBUG)]
                        curl_dbg_free(
                            auth as *mut libc::c_void,
                            571 as libc::c_int,
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
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*data).req.newurl as *mut libc::c_void,
                663 as libc::c_int,
                b"http_proxy.c\0" as *const u8 as *const libc::c_char,
            );
            let ref mut fresh15 = (*data).req.newurl;
            *fresh15 = 0 as *mut libc::c_char;
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 2 as libc::c_int);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                2 as libc::c_int,
                b"proxy CONNECT failure\0" as *const u8 as *const libc::c_char,
            );
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
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
        688 as libc::c_int,
        b"http_proxy.c\0" as *const u8 as *const libc::c_char,
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
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP), USE_HYPER))]
unsafe extern "C" fn CONNECT(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut hostname: *const libc::c_char,
    mut remote_port: libc::c_int,
) -> CURLcode {
    let mut current_block: u64;
    let mut conn: *mut connectdata = (*data).conn;
    let mut h: *mut hyptransfer = &mut (*data).hyp;
    let mut tunnelsocket: curl_socket_t = (*conn).sock[sockindex as usize];
    let mut s: *mut http_connect_state = (*conn).connect_state;
    let mut result: CURLcode = CURLE_OUT_OF_MEMORY;
    let mut io: *mut hyper_io = 0 as *mut hyper_io;
    let mut req: *mut hyper_request = 0 as *mut hyper_request;
    let mut headers: *mut hyper_headers = 0 as *mut hyper_headers;
    let mut options: *mut hyper_clientconn_options = 0 as *mut hyper_clientconn_options;
    let mut handshake: *mut hyper_task = 0 as *mut hyper_task;
    let mut task: *mut hyper_task = 0 as *mut hyper_task;
    let mut sendtask: *mut hyper_task = 0 as *mut hyper_task;
    let mut client: *mut hyper_clientconn = 0 as *mut hyper_clientconn;
    let mut hypererr: *mut hyper_error = 0 as *mut hyper_error;
    let mut hostheader: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    if Curl_connect_complete(conn) {
        return CURLE_OK;
    }
    let ref mut fresh6 = (*conn).bits;
    (*fresh6).set_proxy_connect_closed(0 as libc::c_int as bit);
    's_65: loop {
        match (*s).tunnel_state as libc::c_uint {
            0 => {
                io = hyper_io_new();
                if io.is_null() {
                    Curl_failf(
                        data,
                        b"Couldn't create hyper IO\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 14523688961733284890;
                    break;
                } else {
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
                    (*data).state.hconnect = 1 as libc::c_int != 0;
                    if ((*h).exec).is_null() {
                        let ref mut fresh7 = (*h).exec;
                        *fresh7 = hyper_executor_new();
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
                        handshake = hyper_clientconn_handshake(io, options);
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
                            if HYPERE_OK as libc::c_int as libc::c_uint
                                != hyper_executor_push((*h).exec, handshake) as libc::c_uint
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
                                        ) as u64 != 0
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
                                        ) as u64 != 0
                                        {
                                            Curl_failf(
                                                data,
                                                b"error setting path\0" as *const u8 as *const libc::c_char,
                                            );
                                            result = CURLE_OUT_OF_MEMORY;
                                        }
                                        result = Curl_http_output_auth(
                                            data,
                                            conn,
                                            b"CONNECT\0" as *const u8 as *const libc::c_char,
                                            HTTPREQ_GET,
                                            hostheader,
                                            1 as libc::c_int != 0,
                                        );
                                        if result as u64 != 0 {
                                            current_block = 14523688961733284890;
                                            break;
                                        }
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )(hostheader as *mut libc::c_void);
                                        hostheader = 0 as *mut libc::c_char;
                                        if (*conn).http_proxy.proxytype as libc::c_uint
                                            == CURLPROXY_HTTP_1_0 as libc::c_int as libc::c_uint
                                            && HYPERE_OK as libc::c_int as libc::c_uint
                                                != hyper_request_set_version(req, 10 as libc::c_int)
                                                    as libc::c_uint
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
                                                    && Curl_hyper_header(data, headers, host) as libc::c_uint
                                                        != 0
                                                {
                                                    current_block = 14523688961733284890;
                                                    break;
                                                }
                                                Curl_cfree
                                                    .expect(
                                                        "non-null function pointer",
                                                    )(host as *mut libc::c_void);
                                                host = 0 as *mut libc::c_char;
                                                if !((*data).state.aptr.proxyuserpwd).is_null()
                                                    && Curl_hyper_header(
                                                        data,
                                                        headers,
                                                        (*data).state.aptr.proxyuserpwd,
                                                    ) as libc::c_uint != 0
                                                {
                                                    current_block = 14523688961733284890;
                                                    break;
                                                }
                                                if (Curl_checkProxyheaders(
                                                    data,
                                                    conn,
                                                    b"User-Agent\0" as *const u8 as *const libc::c_char,
                                                ))
                                                    .is_null()
                                                    && !((*data)
                                                        .set
                                                        .str_0[STRING_USERAGENT as libc::c_int as usize])
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
                                                        (1024 as libc::c_int * 1024 as libc::c_int) as size_t,
                                                    );
                                                    result = Curl_dyn_addf(
                                                        &mut ua as *mut dynbuf,
                                                        b"User-Agent: %s\r\n\0" as *const u8 as *const libc::c_char,
                                                        (*data).set.str_0[STRING_USERAGENT as libc::c_int as usize],
                                                    );
                                                    if result as u64 != 0 {
                                                        current_block = 14523688961733284890;
                                                        break;
                                                    }
                                                    if Curl_hyper_header(data, headers, Curl_dyn_ptr(&mut ua))
                                                        as u64 != 0
                                                    {
                                                        current_block = 14523688961733284890;
                                                        break;
                                                    }
                                                    Curl_dyn_free(&mut ua);
                                                }
                                                if (Curl_checkProxyheaders(
                                                    data,
                                                    conn,
                                                    b"Proxy-Connection\0" as *const u8 as *const libc::c_char,
                                                ))
                                                    .is_null()
                                                    && Curl_hyper_header(
                                                        data,
                                                        headers,
                                                        b"Proxy-Connection: Keep-Alive\0" as *const u8
                                                            as *const libc::c_char,
                                                    ) as libc::c_uint != 0
                                                {
                                                    current_block = 14523688961733284890;
                                                    break;
                                                }
                                                if Curl_add_custom_headers(
                                                    data,
                                                    1 as libc::c_int != 0,
                                                    headers as *mut libc::c_void,
                                                ) as u64 != 0
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
                                                } else if HYPERE_OK as libc::c_int as libc::c_uint
                                                        != hyper_executor_push((*h).exec, sendtask) as libc::c_uint
                                                    {
                                                    Curl_failf(
                                                        data,
                                                        b"Couldn't hyper_executor_push the send\0" as *const u8
                                                            as *const libc::c_char,
                                                    );
                                                    current_block = 14523688961733284890;
                                                    break;
                                                } else {
                                                    hyper_clientconn_free(client);
                                                    loop {
                                                        task = hyper_executor_poll((*h).exec);
                                                        if !task.is_null() {
                                                            let mut error: bool = hyper_task_type(task) as libc::c_uint
                                                                == HYPER_TASK_ERROR as libc::c_int as libc::c_uint;
                                                            if error {
                                                                hypererr = hyper_task_value(task) as *mut hyper_error;
                                                            }
                                                            hyper_task_free(task);
                                                            if error {
                                                                current_block = 14523688961733284890;
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
                let mut didwhat: libc::c_int = 0;
                let mut done: bool = 0 as libc::c_int != 0;
                result = Curl_hyper_stream(
                    data,
                    conn,
                    &mut didwhat,
                    &mut done,
                    0x1 as libc::c_int | 0x2 as libc::c_int,
                );
                if result as u64 != 0 {
                    current_block = 14523688961733284890;
                    break;
                }
                if done {
                    (*s).tunnel_state = TUNNEL_COMPLETE;
                    if !((*h).exec).is_null() {
                        hyper_executor_free((*h).exec);
                        let ref mut fresh8 = (*h).exec;
                        *fresh8 = 0 as *const hyper_executor;
                    }
                    if !((*h).read_waker).is_null() {
                        hyper_waker_free((*h).read_waker);
                        let ref mut fresh9 = (*h).read_waker;
                        *fresh9 = 0 as *mut hyper_waker;
                    }
                    if !((*h).write_waker).is_null() {
                        hyper_waker_free((*h).write_waker);
                        let ref mut fresh10 = (*h).write_waker;
                        *fresh10 = 0 as *mut hyper_waker;
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
    match current_block {
        14027225908442187354 => {
            result = CURLE_OK;
            if (*s).tunnel_state as libc::c_uint
                == TUNNEL_COMPLETE as libc::c_int as libc::c_uint
            {
                (*data).info.httpproxycode = (*data).req.httpcode;
                if (*data).info.httpproxycode / 100 as libc::c_int != 2 as libc::c_int {
                    if ((*conn).bits).close() as libc::c_int != 0
                        && !((*data).req.newurl).is_null()
                    {
                        let ref mut fresh11 = (*conn).bits;
                        (*fresh11).set_proxy_connect_closed(1 as libc::c_int as bit);
                        Curl_infof(
                            data,
                            b"Connect me again please\0" as *const u8
                                as *const libc::c_char,
                        );
                        connect_done(data);
                    } else {
                        Curl_cfree
                            .expect(
                                "non-null function pointer",
                            )((*data).req.newurl as *mut libc::c_void);
                        let ref mut fresh12 = (*data).req.newurl;
                        *fresh12 = 0 as *mut libc::c_char;
                        Curl_conncontrol(conn, 2 as libc::c_int);
                        Curl_closesocket(data, conn, (*conn).sock[sockindex as usize]);
                        (*conn).sock[sockindex as usize] = -(1 as libc::c_int);
                    }
                    (*s).tunnel_state = TUNNEL_INIT;
                    if ((*conn).bits).proxy_connect_closed() == 0 {
                        Curl_failf(
                            data,
                            b"Received HTTP code %d from proxy after CONNECT\0"
                                as *const u8 as *const libc::c_char,
                            (*data).req.httpcode,
                        );
                        result = CURLE_RECV_ERROR;
                    }
                }
            }
        }
        _ => {}
    }
    Curl_cfree.expect("non-null function pointer")(host as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(hostheader as *mut libc::c_void);
    if !io.is_null() {
        hyper_io_free(io);
    }
    if !options.is_null() {
        hyper_clientconn_options_free(options);
    }
    if !handshake.is_null() {
        hyper_task_free(handshake);
    }
    if !hypererr.is_null() {
        let mut errbuf: [uint8_t; 256] = [0; 256];
        let mut errlen: size_t = hyper_error_print(
            hypererr,
            errbuf.as_mut_ptr(),
            ::std::mem::size_of::<[uint8_t; 256]>() as libc::c_ulong,
        );
        Curl_failf(
            data,
            b"Hyper: %.*s\0" as *const u8 as *const libc::c_char,
            errlen as libc::c_int,
            errbuf.as_mut_ptr(),
        );
        hyper_error_free(hypererr);
    }
    return result;
}
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_free(mut data: *mut Curl_easy) {
    let mut conn: *mut connectdata = (*data).conn;
    let mut s: *mut http_connect_state = (*conn).connect_state;
    if !s.is_null() {
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(s as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            s as *mut libc::c_void,
            968 as libc::c_int,
            b"http_proxy.c\0" as *const u8 as *const libc::c_char,
        );
        let ref mut fresh22 = (*conn).connect_state;
        *fresh22 = 0 as *mut http_connect_state;
    }
}
#[cfg(all(not(CURL_DISABLE_PROXY), not(CURL_DISABLE_HTTP)))]
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

#[cfg(any(CURL_DISABLE_PROXY, CURL_DISABLE_HTTP))]
#[no_mangle]
pub unsafe extern "C" fn Curl_proxyCONNECT(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut hostname: *const libc::c_char,
    mut remote_port: libc::c_int,
) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[cfg(any(CURL_DISABLE_PROXY, CURL_DISABLE_HTTP))]
#[no_mangle]
pub unsafe extern "C" fn Curl_proxy_connect(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
) -> CURLcode {
    return CURLE_OK;
}
#[cfg(any(CURL_DISABLE_PROXY, CURL_DISABLE_HTTP))]
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_ongoing(mut conn: *mut connectdata) -> bool {
    return false;
}
#[cfg(any(CURL_DISABLE_PROXY, CURL_DISABLE_HTTP))]
#[no_mangle]
pub unsafe extern "C" fn Curl_connect_free(mut data: *mut Curl_easy) {}
