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
 * Description: support http2
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

// TODO http2.c中有一个结构体定义curl_pushheaders和一个enum定义，可能需要放到这里来

#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_init_state(mut state: *mut UrlState) {
    unsafe {
        (*state).stream_weight = 16;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_init_userset(mut set: *mut UserDefined) {
    unsafe {
        (*set).stream_weight = 16;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sock: *mut curl_socket_t,
) -> i32 {
    unsafe {
        let mut c: *const http_conn = &mut (*conn).proto.httpc;
        let mut k: *mut SingleRequest = &mut (*data).req;
        let mut bitmap: i32 = 0;
        *sock.offset(0 as isize) = (*conn).sock[0 as usize];
        if (*k).keepon & (1) << 4 == 0 {
            bitmap |= (1) << 0;
        }
        if (*k).keepon & ((1) << 1 | (1) << 5) == (1) << 1
            || nghttp2_session_want_write((*c).h2) != 0
        {
            bitmap |= (1) << 16 + 0;
        }
        return bitmap;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_stream_free(http: *mut HTTP) {
    unsafe {
        if !http.is_null() {
            Curl_dyn_free(&mut (*http).header_recvbuf);
            while (*http).push_headers_used > 0 as u64 {
                Curl_cfree.expect("non-null function pointer")(
                    *((*http).push_headers).offset(
                        ((*http).push_headers_used).wrapping_sub(1 as u64) as isize,
                    ) as *mut libc::c_void,
                );
                let ref mut fresh0 = (*http).push_headers_used;
                *fresh0 = (*fresh0).wrapping_sub(1);
            }
            Curl_cfree.expect("non-null function pointer")(
                (*http).push_headers as *mut libc::c_void,
            );
            let ref mut fresh1 = (*http).push_headers;
            *fresh1 = 0 as *mut *mut i8;
        }
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_disconnect(
    data: *mut Curl_easy,
    conn: *mut connectdata,
    dead_connection: bool,
) -> CURLcode {
    unsafe {
        let c: *mut http_conn = &mut (*conn).proto.httpc;
        nghttp2_session_del((*c).h2);
        Curl_cfree.expect("non-null function pointer")((*c).inbuf as *mut libc::c_void);
        let ref mut fresh2 = (*c).inbuf;
        *fresh2 = 0 as *mut i8;
        return CURLE_OK;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_connisdead(data: *mut Curl_easy, conn: *mut connectdata) -> bool {
    unsafe {
        let mut sval: i32 = 0;
        let mut dead: bool = 1 != 0;
        if ((*conn).bits).close() != 0 {
            return 1 != 0;
        }
        sval = Curl_socket_check((*conn).sock[0 as usize], -(1), -(1), 0 as timediff_t);
        if sval == 0 {
            dead = 0 != 0;
        } else if sval & 0x4 != 0 {
            dead = 1 != 0;
        } else if sval & 0x1 != 0 {
            dead = !Curl_connalive(conn);
            if !dead {
                let mut result: CURLcode = CURLE_OK;
                let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
                let mut nread: ssize_t = -(1) as ssize_t;
                if ((*httpc).recv_underlying).is_some() {
                    nread = ((*httpc).recv_underlying).expect("non-null function pointer")(
                        data,
                        0,
                        (*httpc).inbuf,
                        32768 as size_t,
                        &mut result,
                    );
                }
                if nread != -(1) as i64 {
                    Curl_infof(
                        data,
                        b"%d bytes stray data read before trying h2 connection\0" as *const u8
                            as *const i8,
                        nread,
                    );
                    (*httpc).nread_inbuf = 0 as size_t;
                    (*httpc).inbuflen = nread as size_t;
                    if h2_process_pending_input(data, httpc, &mut result) < 0 {
                        dead = 1 != 0;
                    }
                } else {
                    dead = 1 != 0;
                }
            }
        }
        return dead;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn set_transfer(c: *mut http_conn, data: *mut Curl_easy) {
    unsafe {
        let ref mut fresh3 = (*c).trnsfr;
        *fresh3 = data;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn get_transfer(c: *mut http_conn) -> *mut Curl_easy {
    unsafe {
        return (*c).trnsfr;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_conncheck(
    data: *mut Curl_easy,
    conn: *mut connectdata,
    checks_to_perform: u32,
) -> u32 {
    unsafe {
        let mut ret_val: u32 = 0 as u32;
        let c: *mut http_conn = &mut (*conn).proto.httpc;
        let mut rc: i32 = 0;
        let mut send_frames: bool = 0 != 0;
        if checks_to_perform & ((1) << 0) as u32 != 0 {
            if http2_connisdead(data, conn) {
                ret_val |= ((1) << 0) as u32;
            }
        }
        if checks_to_perform & ((1) << 1) as u32 != 0 {
            let now: curltime = Curl_now();
            let elapsed: timediff_t = Curl_timediff(now, (*conn).keepalive);
            if elapsed > (*data).set.upkeep_interval_ms {
                rc = nghttp2_submit_ping((*c).h2, 0 as uint8_t, 0 as *const uint8_t);
                if rc == 0 {
                    send_frames = 1 != 0;
                } else {
                    Curl_failf(
                        data,
                        b"nghttp2_submit_ping() failed: %s(%d)\0" as *const u8
                            as *const i8,
                        nghttp2_strerror(rc),
                        rc,
                    );
                }
                (*conn).keepalive = now;
            }
        }
        if send_frames {
            set_transfer(c, data);
            rc = nghttp2_session_send((*c).h2);
            if rc != 0 {
                Curl_failf(
                    data,
                    b"nghttp2_session_send() failed: %s(%d)\0" as *const u8 as *const i8,
                    nghttp2_strerror(rc),
                    rc,
                );
            }
        }
        return ret_val;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_setup_req(data: *mut Curl_easy) {
    unsafe {
        let mut http: *mut HTTP = (*data).req.p.http;
        (*http).bodystarted = 0 != 0;
        (*http).status_code = -(1);
        let ref mut fresh4 = (*http).pausedata;
        *fresh4 = 0 as *const uint8_t;
        (*http).pauselen = 0 as size_t;
        (*http).closed = 0 != 0;
        (*http).close_handled = 0 != 0;
        let ref mut fresh5 = (*http).mem;
        *fresh5 = 0 as *mut i8;
        (*http).len = 0 as size_t;
        (*http).memlen = 0 as size_t;
        (*http).error = NGHTTP2_NO_ERROR as uint32_t;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_setup_conn(mut conn: *mut connectdata) {
    unsafe {
        (*conn).proto.httpc.settings.max_concurrent_streams = 100 as uint32_t;
    }
}
#[cfg(USE_NGHTTP2)]
static mut Curl_handler_http2: Curl_handler = {
    {
        let init = Curl_handler {
            scheme: b"HTTP\0" as *const u8 as *const i8,
            setup_connection: None,
            do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
            done: Some(
                Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: None,
            connecting: None,
            doing: None,
            proto_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            doing_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            domore_getsock: None,
            perform_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            disconnect: Some(
                http2_disconnect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
            ),
            readwrite: None,
            connection_check: Some(
                http2_conncheck
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        u32,
                    ) -> u32,
            ),
            attach: None,
            defport: 80,
            protocol: ((1) << 0) as u32,
            family: ((1) << 0) as u32,
            flags: ((1) << 9) as u32,
        };
        init
    }
};
#[cfg(USE_NGHTTP2)]
static mut Curl_handler_http2_ssl: Curl_handler = {
    {
        let init = Curl_handler {
            scheme: b"HTTPS\0" as *const u8 as *const i8,
            setup_connection: None,
            do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
            done: Some(
                Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: None,
            connecting: None,
            doing: None,
            proto_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            doing_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            domore_getsock: None,
            perform_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            disconnect: Some(
                http2_disconnect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
            ),
            readwrite: None,
            connection_check: Some(
                http2_conncheck
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        u32,
                    ) -> u32,
            ),
            attach: None,
            defport: 80,
            protocol: ((1) << 1) as u32,
            family: ((1) << 0) as u32,
            flags: ((1) << 0 | (1) << 9) as u32,
        };
        init
    }
};
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_ver(p: *mut i8, len: size_t) {
    unsafe {
        let h2: *mut nghttp2_info = nghttp2_version(0);
        curl_msnprintf(
            p,
            len,
            b"nghttp2/%s\0" as *const u8 as *const i8,
            (*h2).version_str,
        );
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn send_callback(
    h2: *mut nghttp2_session,
    mem: *const uint8_t,
    length: size_t,
    flags: i32,
    userp: *mut libc::c_void,
) -> ssize_t {
    unsafe {
        let conn: *mut connectdata = userp as *mut connectdata;
        let c: *mut http_conn = &mut (*conn).proto.httpc;
        let data: *mut Curl_easy = get_transfer(c);
        let mut written: ssize_t = 0;
        let mut result: CURLcode = CURLE_OK;
        if ((*c).send_underlying).is_none() {
            return NGHTTP2_ERR_CALLBACK_FAILURE as ssize_t;
        }
        written = ((*c).send_underlying).expect("non-null function pointer")(
            data,
            0,
            mem as *const libc::c_void,
            length,
            &mut result,
        );
        if result as u32 == CURLE_AGAIN as u32 {
            return NGHTTP2_ERR_WOULDBLOCK as ssize_t;
        }
        if written == -(1) as i64 {
            Curl_failf(
                data,
                b"Failed sending HTTP2 data\0" as *const u8 as *const i8,
            );
            return NGHTTP2_ERR_CALLBACK_FAILURE as ssize_t;
        }
        if written == 0 {
            return NGHTTP2_ERR_WOULDBLOCK as ssize_t;
        }
        return written;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn curl_pushheader_bynum(
    h: *mut curl_pushheaders,
    num: size_t,
) -> *mut i8 {
    unsafe {
        if h.is_null()
            || !(!((*h).data).is_null() && (*(*h).data).magic == 0xc0dedbad as u32)
        {
            return 0 as *mut i8;
        } else {
            let stream: *mut HTTP = (*(*h).data).req.p.http;
            if num < (*stream).push_headers_used {
                return *((*stream).push_headers).offset(num as isize);
            }
        }
        return 0 as *mut i8;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn curl_pushheader_byname(
    h: *mut curl_pushheaders,
    header: *const i8,
) -> *mut i8 {
    unsafe {
        if h.is_null()
            || !(!((*h).data).is_null() && (*(*h).data).magic == 0xc0dedbad as u32)
            || header.is_null()
            || *header.offset(0 as isize) == 0
            || strcmp(header, b":\0" as *const u8 as *const i8) == 0
            || !(strchr(header.offset(1 as isize), ':' as i32)).is_null()
        {
            return 0 as *mut i8;
        } else {
            let stream: *mut HTTP = (*(*h).data).req.p.http;
            let len: size_t = strlen(header);
            let mut i: size_t = 0;
            i = 0 as size_t;
            while i < (*stream).push_headers_used {
                if strncmp(header, *((*stream).push_headers).offset(i as isize), len) == 0 {
                    if !(*(*((*stream).push_headers).offset(i as isize)).offset(len as isize)
                        as i32
                        != ':' as i32)
                    {
                        return &mut *(*((*stream).push_headers).offset(i as isize))
                            .offset(len.wrapping_add(1 as u64) as isize)
                            as *mut i8;
                    }
                }
                i = i.wrapping_add(1);
            }
        }
        return 0 as *mut i8;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn drained_transfer(mut data: *mut Curl_easy, httpc: *mut http_conn) {
    unsafe {
        let ref mut fresh6 = (*httpc).drain_total;
        *fresh6 = (*fresh6 as u64).wrapping_sub((*data).state.drain) as size_t as size_t;
        (*data).state.drain = 0 as size_t;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn drain_this(data: *mut Curl_easy, httpc: *mut http_conn) {
    unsafe {
        let ref mut fresh7 = (*data).state.drain;
        *fresh7 = (*fresh7).wrapping_add(1);
        let ref mut fresh8 = (*httpc).drain_total;
        *fresh8 = (*fresh8).wrapping_add(1);
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn duphandle(data: *mut Curl_easy) -> *mut Curl_easy {
    unsafe {
        let mut second: *mut Curl_easy = curl_easy_duphandle(data);
        if !second.is_null() {
            let http: *mut HTTP = Curl_ccalloc.expect("non-null function pointer")(
                1 as size_t,
                ::std::mem::size_of::<HTTP>() as u64,
            ) as *mut HTTP;
            if http.is_null() {
                Curl_close(&mut second);
            } else {
                let ref mut fresh9 = (*second).req.p.http;
                *fresh9 = http;
                Curl_dyn_init(&mut (*http).header_recvbuf, (128 * 1024) as size_t);
                Curl_http2_setup_req(second);
                (*second).state.stream_weight = (*data).state.stream_weight;
            }
        }
        return second;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn set_transfer_url(data: *mut Curl_easy, hp: *mut curl_pushheaders) -> i32 {
    unsafe {
        let mut current_block: u64;
        let mut v: *const i8 = 0 as *const i8;
        let u: *mut CURLU = curl_url();
        let mut uc: CURLUcode = CURLUE_OK;
        let mut url: *mut i8 = 0 as *mut i8;
        let mut rc: i32 = 0;
        v = curl_pushheader_byname(hp, b":scheme\0" as *const u8 as *const i8);
        if !v.is_null() {
            uc = curl_url_set(u, CURLUPART_SCHEME, v, 0 as u32);
            if uc as u64 != 0 {
                rc = 1;
                current_block = 16884515596159613968;
            } else {
                current_block = 8515828400728868193;
            }
        } else {
            current_block = 8515828400728868193;
        }
        match current_block {
            8515828400728868193 => {
                v = curl_pushheader_byname(hp, b":authority\0" as *const u8 as *const i8);
                if !v.is_null() {
                    uc = curl_url_set(u, CURLUPART_HOST, v, 0 as u32);
                    if uc as u64 != 0 {
                        rc = 2;
                        current_block = 16884515596159613968;
                    } else {
                        current_block = 12349973810996921269;
                    }
                } else {
                    current_block = 12349973810996921269;
                }
                match current_block {
                    16884515596159613968 => {}
                    _ => {
                        v = curl_pushheader_byname(
                            hp,
                            b":path\0" as *const u8 as *const i8,
                        );
                        if !v.is_null() {
                            uc = curl_url_set(u, CURLUPART_PATH, v, 0 as u32);
                            if uc as u64 != 0 {
                                rc = 3;
                                current_block = 16884515596159613968;
                            } else {
                                current_block = 4808432441040389987;
                            }
                        } else {
                            current_block = 4808432441040389987;
                        }
                        match current_block {
                            16884515596159613968 => {}
                            _ => {
                                uc = curl_url_get(u, CURLUPART_URL, &mut url, 0 as u32);
                                if uc as u64 != 0 {
                                    rc = 4;
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        curl_url_cleanup(u);
        if rc != 0 {
            return rc;
        }
        if ((*data).state).url_alloc() != 0 {
            Curl_cfree.expect("non-null function pointer")((*data).state.url as *mut libc::c_void);
        }
        let ref mut fresh10 = (*data).state;
        (*fresh10).set_url_alloc(1 as bit);
        let ref mut fresh11 = (*data).state.url;
        *fresh11 = url;
        return 0;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn push_promise(
    data: *mut Curl_easy,
    conn: *mut connectdata,
    frame: *const nghttp2_push_promise,
) -> i32 {
    unsafe {
        let mut rv: i32 = 0;
        if ((*(*data).multi).push_cb).is_some() {
            let mut stream: *mut HTTP = 0 as *mut HTTP;
            let mut newstream: *mut HTTP = 0 as *mut HTTP;
            let mut heads: curl_pushheaders = curl_pushheaders {
                data: 0 as *mut Curl_easy,
                frame: 0 as *const nghttp2_push_promise,
            };
            let mut rc: CURLMcode = CURLM_OK;
            let mut httpc: *mut http_conn = 0 as *mut http_conn;
            let mut i: size_t = 0;
            let mut newhandle: *mut Curl_easy = duphandle(data);
            if newhandle.is_null() {
                Curl_infof(
                    data,
                    b"failed to duplicate handle\0" as *const u8 as *const i8,
                );
                rv = 1;
            } else {
                heads.data = data;
                heads.frame = frame;
                stream = (*data).req.p.http;
                if stream.is_null() {
                    Curl_failf(
                        data,
                        b"Internal NULL stream!\0" as *const u8 as *const i8,
                    );
                    Curl_close(&mut newhandle);
                    rv = 1;
                } else {
                    rv = set_transfer_url(newhandle, &mut heads);
                    if rv != 0 {
                        Curl_close(&mut newhandle);
                        rv = 1;
                    } else {
                        Curl_set_in_callback(data, 1 != 0);
                        rv = ((*(*data).multi).push_cb).expect("non-null function pointer")(
                            data,
                            newhandle,
                            (*stream).push_headers_used,
                            &mut heads,
                            (*(*data).multi).push_userp,
                        );
                        Curl_set_in_callback(data, 0 != 0);
                        i = 0 as size_t;
                        while i < (*stream).push_headers_used {
                            Curl_cfree.expect("non-null function pointer")(
                                *((*stream).push_headers).offset(i as isize) as *mut libc::c_void,
                            );
                            i = i.wrapping_add(1);
                        }
                        Curl_cfree.expect("non-null function pointer")(
                            (*stream).push_headers as *mut libc::c_void,
                        );
                        let ref mut fresh12 = (*stream).push_headers;
                        *fresh12 = 0 as *mut *mut i8;
                        (*stream).push_headers_used = 0 as size_t;
                        if rv != 0 {
                            http2_stream_free((*newhandle).req.p.http);
                            let ref mut fresh13 = (*newhandle).req.p.http;
                            *fresh13 = 0 as *mut HTTP;
                            Curl_close(&mut newhandle);
                        } else {
                            newstream = (*newhandle).req.p.http;
                            (*newstream).stream_id = (*frame).promised_stream_id;
                            (*newhandle).req.maxdownload = -(1) as curl_off_t;
                            (*newhandle).req.size = -(1) as curl_off_t;
                            rc = Curl_multi_add_perform((*data).multi, newhandle, conn);
                            if rc as u64 != 0 {
                                Curl_infof(
                                    data,
                                    b"failed to add handle to multi\0" as *const u8
                                        as *const i8,
                                );
                                http2_stream_free((*newhandle).req.p.http);
                                let ref mut fresh14 = (*newhandle).req.p.http;
                                *fresh14 = 0 as *mut HTTP;
                                Curl_close(&mut newhandle);
                                rv = 1;
                            } else {
                                httpc = &mut (*conn).proto.httpc;
                                rv = nghttp2_session_set_stream_user_data(
                                    (*httpc).h2,
                                    (*frame).promised_stream_id,
                                    newhandle as *mut libc::c_void,
                                );
                                if rv != 0 {
                                    Curl_infof(
                                        data,
                                        b"failed to set user_data for stream %d\0" as *const u8
                                            as *const i8,
                                        (*frame).promised_stream_id,
                                    );
                                    rv = 1;
                                } else {
                                    Curl_dyn_init(
                                        &mut (*newstream).header_recvbuf,
                                        (128 * 1024) as size_t,
                                    );
                                    Curl_dyn_init(
                                        &mut (*newstream).trailer_recvbuf,
                                        (128 * 1024) as size_t,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        } else {
            rv = 1;
        }
        return rv;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn multi_connchanged(mut multi: *mut Curl_multi) {
    unsafe {
        (*multi).recheckstate = 1 != 0;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn on_frame_recv(
    session: *mut nghttp2_session,
    frame: *const nghttp2_frame,
    userp: *mut libc::c_void,
) -> i32 {
    unsafe {
        let conn: *mut connectdata = userp as *mut connectdata;
        let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
        let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
        let mut stream: *mut HTTP = 0 as *mut HTTP;
        let data: *mut Curl_easy = get_transfer(httpc);
        let mut rv: i32 = 0;
        let mut left: size_t = 0;
        let mut ncopy: size_t = 0;
        let stream_id: int32_t = (*frame).hd.stream_id;
        let mut result: CURLcode = CURLE_OK;
        if stream_id == 0 {
            if (*frame).hd.type_0 as i32 == NGHTTP2_SETTINGS as i32 {
                let max_conn: uint32_t = (*httpc).settings.max_concurrent_streams;
                (*httpc).settings.max_concurrent_streams = nghttp2_session_get_remote_settings(
                    session,
                    NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
                );
                (*httpc).settings.enable_push =
                    nghttp2_session_get_remote_settings(session, NGHTTP2_SETTINGS_ENABLE_PUSH) != 0;
                if max_conn != (*httpc).settings.max_concurrent_streams {
                    Curl_infof(
                        data,
                        b"Connection state changed (MAX_CONCURRENT_STREAMS == %u)!\0" as *const u8
                            as *const i8,
                        (*httpc).settings.max_concurrent_streams,
                    );
                    multi_connchanged((*data).multi);
                }
            }
            return 0;
        }
        data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
        if data_s.is_null() {
            return 0;
        }
        stream = (*data_s).req.p.http;
        if stream.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        match (*frame).hd.type_0 {
            0 => {
                if !(*stream).bodystarted {
                    rv = nghttp2_submit_rst_stream(
                        session,
                        NGHTTP2_FLAG_NONE as uint8_t,
                        stream_id,
                        NGHTTP2_PROTOCOL_ERROR as uint32_t,
                    );
                    if nghttp2_is_fatal(rv) != 0 {
                        return NGHTTP2_ERR_CALLBACK_FAILURE;
                    }
                }
            }
            1 => {
                if !(*stream).bodystarted {
                    if (*stream).status_code == -(1) {
                        return NGHTTP2_ERR_CALLBACK_FAILURE;
                    }
                    if (*stream).status_code / 100 != 1 {
                        (*stream).bodystarted = 1 != 0;
                        (*stream).status_code = -(1);
                    }
                    result = Curl_dyn_add(
                        &mut (*stream).header_recvbuf,
                        b"\r\n\0" as *const u8 as *const i8,
                    );
                    if result as u64 != 0 {
                        return NGHTTP2_ERR_CALLBACK_FAILURE;
                    }
                    left = (Curl_dyn_len(&mut (*stream).header_recvbuf))
                        .wrapping_sub((*stream).nread_header_recvbuf);
                    ncopy = if (*stream).len < left {
                        (*stream).len
                    } else {
                        left
                    };
                    memcpy(
                        &mut *((*stream).mem).offset((*stream).memlen as isize) as *mut i8
                            as *mut libc::c_void,
                        (Curl_dyn_ptr(&mut (*stream).header_recvbuf))
                            .offset((*stream).nread_header_recvbuf as isize)
                            as *const libc::c_void,
                        ncopy,
                    );
                    let ref mut fresh15 = (*stream).nread_header_recvbuf;
                    *fresh15 = (*fresh15 as u64).wrapping_add(ncopy) as size_t as size_t;
                    let ref mut fresh16 = (*stream).len;
                    *fresh16 = (*fresh16 as u64).wrapping_sub(ncopy) as size_t as size_t;
                    let ref mut fresh17 = (*stream).memlen;
                    *fresh17 = (*fresh17 as u64).wrapping_add(ncopy) as size_t as size_t;
                    drain_this(data_s, httpc);
                    if get_transfer(httpc) != data_s {
                        Curl_expire(data_s, 0 as timediff_t, EXPIRE_RUN_NOW);
                    }
                }
            }
            5 => {
                rv = push_promise(data_s, conn, &(*frame).push_promise);
                if rv != 0 {
                    let mut h2: i32 = 0;
                    h2 = nghttp2_submit_rst_stream(
                        session,
                        NGHTTP2_FLAG_NONE as uint8_t,
                        (*frame).push_promise.promised_stream_id,
                        NGHTTP2_CANCEL as uint32_t,
                    );
                    if nghttp2_is_fatal(h2) != 0 {
                        return NGHTTP2_ERR_CALLBACK_FAILURE;
                    } else {
                        if rv == 2 {
                            return NGHTTP2_ERR_CALLBACK_FAILURE;
                        }
                    }
                }
            }
            _ => {}
        }
        return 0;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn on_data_chunk_recv(
    session: *mut nghttp2_session,
    flags: uint8_t,
    stream_id: int32_t,
    mem: *const uint8_t,
    len: size_t,
    userp: *mut libc::c_void,
) -> i32 {
    unsafe {
        let mut stream: *mut HTTP = 0 as *mut HTTP;
        let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
        let mut nread: size_t = 0;
        let conn: *mut connectdata = userp as *mut connectdata;
        let httpc: *mut http_conn = &mut (*conn).proto.httpc;
        data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
        if data_s.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        stream = (*data_s).req.p.http;
        if stream.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        nread = if (*stream).len < len {
            (*stream).len
        } else {
            len
        };
        memcpy(
            &mut *((*stream).mem).offset((*stream).memlen as isize) as *mut i8
                as *mut libc::c_void,
            mem as *const libc::c_void,
            nread,
        );
        let ref mut fresh18 = (*stream).len;
        *fresh18 = (*fresh18 as u64).wrapping_sub(nread) as size_t as size_t;
        let ref mut fresh19 = (*stream).memlen;
        *fresh19 = (*fresh19 as u64).wrapping_add(nread) as size_t as size_t;
        drain_this(data_s, &mut (*conn).proto.httpc);
        if get_transfer(httpc) != data_s {
            Curl_expire(data_s, 0 as timediff_t, EXPIRE_RUN_NOW);
        }
        if nread < len {
            let ref mut fresh20 = (*stream).pausedata;
            *fresh20 = mem.offset(nread as isize);
            (*stream).pauselen = len.wrapping_sub(nread);
            (*(*data_s).conn).proto.httpc.pause_stream_id = stream_id;
            return NGHTTP2_ERR_PAUSE;
        }
        if get_transfer(httpc) != data_s {
            (*(*data_s).conn).proto.httpc.pause_stream_id = stream_id;
            return NGHTTP2_ERR_PAUSE;
        }
        return 0;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn on_stream_close(
    session: *mut nghttp2_session,
    stream_id: int32_t,
    error_code: uint32_t,
    userp: *mut libc::c_void,
) -> i32 {
    unsafe {
        let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
        let mut stream: *mut HTTP = 0 as *mut HTTP;
        let conn: *mut connectdata = userp as *mut connectdata;
        let mut rv: i32 = 0;
        if stream_id != 0 {
            let mut httpc: *mut http_conn = 0 as *mut http_conn;
            data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
            if data_s.is_null() {
                return 0;
            }
            stream = (*data_s).req.p.http;
            if stream.is_null() {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            (*stream).closed = 1 != 0;
            httpc = &mut (*conn).proto.httpc;
            drain_this(data_s, httpc);
            Curl_expire(data_s, 0 as timediff_t, EXPIRE_RUN_NOW);
            (*stream).error = error_code;
            rv = nghttp2_session_set_stream_user_data(session, stream_id, 0 as *mut libc::c_void);
            if rv != 0 {
                Curl_infof(
                    data_s,
                    b"http/2: failed to clear user_data for stream %d!\0" as *const u8
                        as *const i8,
                    stream_id,
                );
            }
            if stream_id == (*httpc).pause_stream_id {
                (*httpc).pause_stream_id = 0;
            }
            (*stream).stream_id = 0;
        }
        return 0;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn on_begin_headers(
    session: *mut nghttp2_session,
    frame: *const nghttp2_frame,
    userp: *mut libc::c_void,
) -> i32 {
    unsafe {
        let mut stream: *mut HTTP = 0 as *mut HTTP;
        let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
        data_s =
            nghttp2_session_get_stream_user_data(session, (*frame).hd.stream_id) as *mut Curl_easy;
        if data_s.is_null() {
            return 0;
        }
        if (*frame).hd.type_0 as i32 != NGHTTP2_HEADERS as i32 {
            return 0 as i32;
        }
        stream = (*data_s).req.p.http;
        if stream.is_null() || !(*stream).bodystarted {
            return 0;
        }
        return 0;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn decode_status_code(value: *const uint8_t, len: size_t) -> i32 {
    unsafe {
        let mut i: i32 = 0;
        let mut res: i32 = 0;
        if len != 3 as u64 {
            return -(1);
        }
        res = 0;
        i = 0;
        while i < 3 {
            let c: i8 = *value.offset(i as isize) as i8;
            if (c as i32) < '0' as i32 || c as i32 > '9' as i32 {
                return -(1 as i32);
            }
            res *= 10 as i32;
            res += c as i32 - '0' as i32;
            i += 1;
        }
        return res;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn on_header(
    session: *mut nghttp2_session,
    frame: *const nghttp2_frame,
    name: *const uint8_t,
    namelen: size_t,
    value: *const uint8_t,
    valuelen: size_t,
    flags: uint8_t,
    userp: *mut libc::c_void,
) -> i32 {
    unsafe {
        let mut stream: *mut HTTP = 0 as *mut HTTP;
        let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
        let stream_id: int32_t = (*frame).hd.stream_id;
        let conn: *mut connectdata = userp as *mut connectdata;
        let httpc: *mut http_conn = &mut (*conn).proto.httpc;
        let mut result: CURLcode = CURLE_OK;
        data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
        if data_s.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        stream = (*data_s).req.p.http;
        if stream.is_null() {
            Curl_failf(
                data_s,
                b"Internal NULL stream!\0" as *const u8 as *const i8,
            );
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if (*frame).hd.type_0 as i32 == NGHTTP2_PUSH_PROMISE as i32 {
            let mut h: *mut i8 = 0 as *mut i8;
            if strcmp(
                b":authority\0" as *const u8 as *const i8,
                name as *const i8,
            ) == 0
            {
                let mut rc: i32 = 0;
                let check: *mut i8 = curl_maprintf(
                    b"%s:%d\0" as *const u8 as *const i8,
                    (*conn).host.name,
                    (*conn).remote_port,
                );
                if check.is_null() {
                    return NGHTTP2_ERR_CALLBACK_FAILURE;
                }
                if Curl_strcasecompare(check, value as *const i8) == 0
                    && ((*conn).remote_port != (*(*conn).given).defport
                        || Curl_strcasecompare((*conn).host.name, value as *const i8)
                            == 0)
                {
                    nghttp2_submit_rst_stream(
                        session,
                        NGHTTP2_FLAG_NONE as uint8_t,
                        stream_id,
                        NGHTTP2_PROTOCOL_ERROR as uint32_t,
                    );
                    rc = NGHTTP2_ERR_CALLBACK_FAILURE;
                }
                Curl_cfree.expect("non-null function pointer")(check as *mut libc::c_void);
                if rc != 0 {
                    return rc;
                }
            }
            if ((*stream).push_headers).is_null() {
                (*stream).push_headers_alloc = 10 as size_t;
                let ref mut fresh21 = (*stream).push_headers;
                *fresh21 = Curl_cmalloc.expect("non-null function pointer")(
                    ((*stream).push_headers_alloc)
                        .wrapping_mul(::std::mem::size_of::<*mut i8>() as u64),
                ) as *mut *mut i8;
                if ((*stream).push_headers).is_null() {
                    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                (*stream).push_headers_used = 0 as size_t;
            } else if (*stream).push_headers_used == (*stream).push_headers_alloc {
                let mut headp: *mut *mut i8 = 0 as *mut *mut i8;
                let ref mut fresh22 = (*stream).push_headers_alloc;
                *fresh22 = (*fresh22 as u64).wrapping_mul(2 as u64) as size_t
                    as size_t;
                headp = Curl_saferealloc(
                    (*stream).push_headers as *mut libc::c_void,
                    ((*stream).push_headers_alloc)
                        .wrapping_mul(::std::mem::size_of::<*mut i8>() as u64),
                ) as *mut *mut i8;
                if headp.is_null() {
                    let ref mut fresh23 = (*stream).push_headers;
                    *fresh23 = 0 as *mut *mut i8;
                    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                let ref mut fresh24 = (*stream).push_headers;
                *fresh24 = headp;
            }
            h = curl_maprintf(b"%s:%s\0" as *const u8 as *const i8, name, value);
            if !h.is_null() {
                let ref mut fresh25 = (*stream).push_headers_used;
                let fresh26 = *fresh25;
                *fresh25 = (*fresh25).wrapping_add(1);
                let ref mut fresh27 = *((*stream).push_headers).offset(fresh26 as isize);
                *fresh27 = h;
            }
            return 0;
        }
        if (*stream).bodystarted {
            result = Curl_dyn_addf(
                &mut (*stream).trailer_recvbuf as *mut dynbuf,
                b"%.*s: %.*s\r\n\0" as *const u8 as *const i8,
                namelen,
                name,
                valuelen,
                value,
            );
            if result as u64 != 0 {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            return 0;
        }
        if namelen
            == (::std::mem::size_of::<[i8; 8]>() as u64)
                .wrapping_sub(1 as u64)
            && memcmp(
                b":status\0" as *const u8 as *const i8 as *const libc::c_void,
                name as *const libc::c_void,
                namelen,
            ) == 0
        {
            (*stream).status_code = decode_status_code(value, valuelen);
            result = Curl_dyn_add(
                &mut (*stream).header_recvbuf,
                b"HTTP/2 \0" as *const u8 as *const i8,
            );
            if result as u64 != 0 {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            result = Curl_dyn_addn(
                &mut (*stream).header_recvbuf,
                value as *const libc::c_void,
                valuelen,
            );
            if result as u64 != 0 {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            result = Curl_dyn_add(
                &mut (*stream).header_recvbuf,
                b" \r\n\0" as *const u8 as *const i8,
            );
            if result as u64 != 0 {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            if get_transfer(httpc) != data_s {
                Curl_expire(data_s, 0 as timediff_t, EXPIRE_RUN_NOW);
            }
            return 0;
        }
        result = Curl_dyn_addn(
            &mut (*stream).header_recvbuf,
            name as *const libc::c_void,
            namelen,
        );
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        result = Curl_dyn_add(
            &mut (*stream).header_recvbuf,
            b": \0" as *const u8 as *const i8,
        );
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        result = Curl_dyn_addn(
            &mut (*stream).header_recvbuf,
            value as *const libc::c_void,
            valuelen,
        );
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        result = Curl_dyn_add(
            &mut (*stream).header_recvbuf,
            b"\r\n\0" as *const u8 as *const i8,
        );
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if get_transfer(httpc) != data_s {
            Curl_expire(data_s, 0 as timediff_t, EXPIRE_RUN_NOW);
        }
        return 0;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn data_source_read_callback(
    session: *mut nghttp2_session,
    stream_id: int32_t,
    buf: *mut uint8_t,
    length: size_t,
    data_flags: *mut uint32_t,
    source: *mut nghttp2_data_source,
    userp: *mut libc::c_void,
) -> ssize_t {
    unsafe {
        let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
        let mut stream: *mut HTTP = 0 as *mut HTTP;
        let mut nread: size_t = 0;
        if stream_id != 0 {
            data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
            if data_s.is_null() {
                return NGHTTP2_ERR_CALLBACK_FAILURE as ssize_t;
            }
            stream = (*data_s).req.p.http;
            if stream.is_null() {
                return NGHTTP2_ERR_CALLBACK_FAILURE as ssize_t;
            }
        } else {
            return NGHTTP2_ERR_INVALID_ARGUMENT as ssize_t;
        }
        nread = if (*stream).upload_len < length {
            (*stream).upload_len
        } else {
            length
        };
        if nread > 0 as u64 {
            memcpy(
                buf as *mut libc::c_void,
                (*stream).upload_mem as *const libc::c_void,
                nread,
            );
            let ref mut fresh28 = (*stream).upload_mem;
            *fresh28 = (*fresh28).offset(nread as isize);
            let ref mut fresh29 = (*stream).upload_len;
            *fresh29 = (*fresh29 as u64).wrapping_sub(nread) as size_t as size_t;
            if (*data_s).state.infilesize != -(1) as i64 {
                let ref mut fresh30 = (*stream).upload_left;
                *fresh30 =
                    (*fresh30 as u64).wrapping_sub(nread) as curl_off_t as curl_off_t;
            }
        }
        if (*stream).upload_left == 0 as i64 {
            *data_flags = NGHTTP2_DATA_FLAG_EOF as uint32_t;
        } else if nread == 0 as u64 {
            return NGHTTP2_ERR_DEFERRED as ssize_t;
        }
        return nread as ssize_t;
    }
}
#[cfg(all(USE_NGHTTP2, not(CURL_DISABLE_VERBOSE_STRINGS)))]
extern "C" fn error_callback(
    session: *mut nghttp2_session,
    msg: *const i8,
    len: size_t,
    userp: *mut libc::c_void,
) -> i32 {
    return 0;
}
#[cfg(USE_NGHTTP2)]
extern "C" fn populate_settings(data: *mut Curl_easy, mut httpc: *mut http_conn) {
    unsafe {
        let iv: *mut nghttp2_settings_entry = ((*httpc).local_settings).as_mut_ptr();
        (*iv.offset(0 as i32 as isize)).settings_id =
            NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS as i32;
        (*iv.offset(0 as i32 as isize)).value =
            Curl_multi_max_concurrent_streams((*data).multi);
        (*iv.offset(1 as i32 as isize)).settings_id =
            NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE as i32;
        (*iv.offset(1 as i32 as isize)).value =
            (32 as i32 * 1024 as i32 * 1024 as i32) as uint32_t;
        (*iv.offset(2 as i32 as isize)).settings_id =
            NGHTTP2_SETTINGS_ENABLE_PUSH as i32;
        (*iv.offset(2 as i32 as isize)).value =
            ((*(*data).multi).push_cb).is_some() as i32 as uint32_t;
        (*httpc).local_settings_num = 3 as i32 as size_t;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_done(data: *mut Curl_easy, premature: bool) {
    unsafe {
        let mut http: *mut HTTP = (*data).req.p.http;
        let mut httpc: *mut http_conn = &mut (*(*data).conn).proto.httpc;
        Curl_dyn_free(&mut (*http).header_recvbuf);
        Curl_dyn_free(&mut (*http).trailer_recvbuf);
        if !((*http).push_headers).is_null() {
            while (*http).push_headers_used > 0 as u64 {
                Curl_cfree.expect("non-null function pointer")(
                    *((*http).push_headers).offset(
                        ((*http).push_headers_used).wrapping_sub(1 as u64) as isize,
                    ) as *mut libc::c_void,
                );
                let ref mut fresh31 = (*http).push_headers_used;
                *fresh31 = (*fresh31).wrapping_sub(1);
            }
            Curl_cfree.expect("non-null function pointer")(
                (*http).push_headers as *mut libc::c_void,
            );
            let ref mut fresh32 = (*http).push_headers;
            *fresh32 = 0 as *mut *mut i8;
        }
        if (*(*(*data).conn).handler).protocol & ((1) << 0 | (1) << 1) as u32 == 0
            || ((*httpc).h2).is_null()
        {
            return;
        }
        if premature {
            set_transfer(httpc, data);
            if nghttp2_submit_rst_stream(
                (*httpc).h2,
                NGHTTP2_FLAG_NONE as uint8_t,
                (*http).stream_id,
                NGHTTP2_STREAM_CLOSED as uint32_t,
            ) == 0
            {
                nghttp2_session_send((*httpc).h2);
            }
            if (*http).stream_id == (*httpc).pause_stream_id {
                Curl_infof(
                    data,
                    b"stopped the pause stream!\0" as *const u8 as *const i8,
                );
                (*httpc).pause_stream_id = 0;
            }
        }
        if (*data).state.drain != 0 {
            drained_transfer(data, httpc);
        }
        if (*http).stream_id > 0 {
            let rv: i32 = nghttp2_session_set_stream_user_data(
                (*httpc).h2,
                (*http).stream_id,
                0 as *mut libc::c_void,
            );
            if rv != 0 {
                Curl_infof(
                    data,
                    b"http/2: failed to clear user_data for stream %d!\0" as *const u8
                        as *const i8,
                    (*http).stream_id,
                );
            }
            set_transfer(httpc, 0 as *mut Curl_easy);
            (*http).stream_id = 0;
        }
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_init(data: *mut Curl_easy, conn: *mut connectdata) -> CURLcode {
    unsafe {
        if ((*conn).proto.httpc.h2).is_null() {
            let mut rc: i32 = 0;
            let mut callbacks: *mut nghttp2_session_callbacks = 0 as *mut nghttp2_session_callbacks;
            let ref mut fresh33 = (*conn).proto.httpc.inbuf;
            *fresh33 = Curl_cmalloc.expect("non-null function pointer")(32768 as size_t)
                as *mut i8;
            if ((*conn).proto.httpc.inbuf).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            rc = nghttp2_session_callbacks_new(&mut callbacks);
            if rc != 0 {
                Curl_failf(
                    data,
                    b"Couldn't initialize nghttp2 callbacks!\0" as *const u8 as *const i8,
                );
                return CURLE_OUT_OF_MEMORY;
            }
            nghttp2_session_callbacks_set_send_callback(
                callbacks,
                Some(
                    send_callback
                        as extern "C" fn(
                            *mut nghttp2_session,
                            *const uint8_t,
                            size_t,
                            i32,
                            *mut libc::c_void,
                        ) -> ssize_t,
                ),
            );
            nghttp2_session_callbacks_set_on_frame_recv_callback(
                callbacks,
                Some(
                    on_frame_recv
                        as extern "C" fn(
                            *mut nghttp2_session,
                            *const nghttp2_frame,
                            *mut libc::c_void,
                        ) -> i32,
                ),
            );
            nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
                callbacks,
                Some(
                    on_data_chunk_recv
                        as extern "C" fn(
                            *mut nghttp2_session,
                            uint8_t,
                            int32_t,
                            *const uint8_t,
                            size_t,
                            *mut libc::c_void,
                        ) -> i32,
                ),
            );
            nghttp2_session_callbacks_set_on_stream_close_callback(
                callbacks,
                Some(
                    on_stream_close
                        as extern "C" fn(
                            *mut nghttp2_session,
                            int32_t,
                            uint32_t,
                            *mut libc::c_void,
                        ) -> i32,
                ),
            );
            nghttp2_session_callbacks_set_on_begin_headers_callback(
                callbacks,
                Some(
                    on_begin_headers
                        as extern "C" fn(
                            *mut nghttp2_session,
                            *const nghttp2_frame,
                            *mut libc::c_void,
                        ) -> i32,
                ),
            );
            nghttp2_session_callbacks_set_on_header_callback(
                callbacks,
                Some(
                    on_header
                        as extern "C" fn(
                            *mut nghttp2_session,
                            *const nghttp2_frame,
                            *const uint8_t,
                            size_t,
                            *const uint8_t,
                            size_t,
                            uint8_t,
                            *mut libc::c_void,
                        ) -> i32,
                ),
            );
            #[cfg(CURL_DISABLE_VERBOSE_STRINGS)]
            nghttp2_session_callbacks_set_error_callback(
                callbacks,
                Some(
                    error_callback
                        as extern "C" fn(
                            *mut nghttp2_session,
                            *const i8,
                            size_t,
                            *mut libc::c_void,
                        ) -> i32,
                ),
            );
            rc = nghttp2_session_client_new(
                &mut (*conn).proto.httpc.h2,
                callbacks,
                conn as *mut libc::c_void,
            );
            nghttp2_session_callbacks_del(callbacks);
            if rc != 0 {
                Curl_failf(
                    data,
                    b"Couldn't initialize nghttp2!\0" as *const u8 as *const i8,
                );
                return CURLE_OUT_OF_MEMORY;
            }
        }
        return CURLE_OK;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_request_upgrade(req: *mut dynbuf, data: *mut Curl_easy) -> CURLcode {
    unsafe {
        let mut result: CURLcode = CURLE_OK;
        let mut binlen: ssize_t = 0;
        let mut base64: *mut i8 = 0 as *mut i8;
        let mut blen: size_t = 0;
        let mut conn: *mut connectdata = (*data).conn;
        let mut k: *mut SingleRequest = &mut (*data).req;
        let binsettings: *mut uint8_t = ((*conn).proto.httpc.binsettings).as_mut_ptr();
        let httpc: *mut http_conn = &mut (*conn).proto.httpc;
        populate_settings(data, httpc);
        binlen = nghttp2_pack_settings_payload(
            binsettings,
            80 as size_t,
            ((*httpc).local_settings).as_mut_ptr(),
            (*httpc).local_settings_num,
        );
        if binlen <= 0 as i64 {
            Curl_failf(
                data,
                b"nghttp2 unexpectedly failed on pack_settings_payload\0" as *const u8
                    as *const i8,
            );
            Curl_dyn_free(req);
            return CURLE_FAILED_INIT;
        }
        (*conn).proto.httpc.binlen = binlen as size_t;
        result = Curl_base64url_encode(
            data,
            binsettings as *const i8,
            binlen as size_t,
            &mut base64,
            &mut blen,
        );
        if result as u64 != 0 {
            Curl_dyn_free(req);
            return result;
        }
        result = Curl_dyn_addf(
            req,
            b"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: %s\r\nHTTP2-Settings: %s\r\n\0"
                as *const u8 as *const i8,
            b"h2c\0" as *const u8 as *const i8,
            base64,
        );
        Curl_cfree.expect("non-null function pointer")(base64 as *mut libc::c_void);
        (*k).upgr101 = UPGR101_REQUESTED;
        return result;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn should_close_session(httpc: *mut http_conn) -> i32 {
    unsafe {
        return ((*httpc).drain_total == 0 as i32 as u64
            && nghttp2_session_want_read((*httpc).h2) == 0
            && nghttp2_session_want_write((*httpc).h2) == 0) as i32;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn h2_process_pending_input(
    data: *mut Curl_easy,
    httpc: *mut http_conn,
    err: *mut CURLcode,
) -> i32 {
    unsafe {
        let mut nread: ssize_t = 0;
        let mut inbuf: *mut i8 = 0 as *mut i8;
        let mut rv: ssize_t = 0;
        nread = ((*httpc).inbuflen).wrapping_sub((*httpc).nread_inbuf) as ssize_t;
        inbuf = ((*httpc).inbuf).offset((*httpc).nread_inbuf as isize);
        set_transfer(httpc, data);
        rv = nghttp2_session_mem_recv((*httpc).h2, inbuf as *const uint8_t, nread as size_t);
        if rv < 0 as i64 {
            Curl_failf(
                data,
                b"h2_process_pending_input: nghttp2_session_mem_recv() returned %zd:%s\0"
                    as *const u8 as *const i8,
                rv,
                nghttp2_strerror(rv as i32),
            );
            *err = CURLE_RECV_ERROR;
            return -(1);
        }
        if nread == rv {
            (*httpc).inbuflen = 0 as size_t;
            (*httpc).nread_inbuf = 0 as size_t;
        } else {
            let ref mut fresh34 = (*httpc).nread_inbuf;
            *fresh34 =
                (*fresh34 as u64).wrapping_add(rv as u64) as size_t as size_t;
        }
        rv = h2_session_send(data, (*httpc).h2) as ssize_t;
        if rv != 0 {
            *err = CURLE_SEND_ERROR;
            return -(1);
        }
        if nghttp2_session_check_request_allowed((*httpc).h2) == 0 {
            Curl_conncontrol((*data).conn, 1);
        }
        if should_close_session(httpc) != 0 {
            let stream: *mut HTTP = (*data).req.p.http;
            if (*stream).error != 0 {
                *err = CURLE_HTTP2;
            } else {
                Curl_conncontrol((*data).conn, 1);
                *err = CURLE_OK;
            }
            return -(1);
        }
        return 0;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_done_sending(
    data: *mut Curl_easy,
    conn: *mut connectdata,
) -> CURLcode {
    unsafe {
        let mut result: CURLcode = CURLE_OK;
        if (*conn).handler == &Curl_handler_http2_ssl as *const Curl_handler
            || (*conn).handler == &Curl_handler_http2 as *const Curl_handler
        {
            let mut stream: *mut HTTP = (*data).req.p.http;
            let httpc: *mut http_conn = &mut (*conn).proto.httpc;
            let h2: *mut nghttp2_session = (*httpc).h2;
            if (*stream).upload_left != 0 {
                (*stream).upload_left = 0 as curl_off_t;
                nghttp2_session_resume_data(h2, (*stream).stream_id);
                h2_process_pending_input(data, httpc, &mut result);
            }
            if nghttp2_session_want_write(h2) != 0 {
                let mut k: *mut SingleRequest = &mut (*data).req;
                let mut rv: i32 = 0;
                rv = h2_session_send(data, h2);
                if rv != 0 {
                    result = CURLE_SEND_ERROR;
                }
                if nghttp2_session_want_write(h2) != 0 {
                    (*k).keepon |= (1) << 1;
                }
            }
        }
        return result;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_handle_stream_close(
    conn: *mut connectdata,
    data: *mut Curl_easy,
    stream: *mut HTTP,
    err: *mut CURLcode,
) -> ssize_t {
    unsafe {
        let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
        if (*httpc).pause_stream_id == (*stream).stream_id {
            (*httpc).pause_stream_id = 0;
        }
        drained_transfer(data, httpc);
        if (*httpc).pause_stream_id == 0 {
            if h2_process_pending_input(data, httpc, err) != 0 {
                return -(1) as ssize_t;
            }
        }
        (*stream).closed = 0 != 0;
        if (*stream).error == NGHTTP2_REFUSED_STREAM as u32 {
            Curl_conncontrol(conn, 1);
            let ref mut fresh35 = (*data).state;
            (*fresh35).set_refused_stream(1 as bit);
            *err = CURLE_RECV_ERROR;
            return -(1) as ssize_t;
        } else {
            if (*stream).error != NGHTTP2_NO_ERROR as u32 {
                Curl_failf(
                    data,
                    b"HTTP/2 stream %d was not closed cleanly: %s (err %u)\0" as *const u8
                        as *const i8,
                    (*stream).stream_id,
                    nghttp2_http2_strerror((*stream).error),
                    (*stream).error,
                );
                *err = CURLE_HTTP2_STREAM;
                return -(1) as ssize_t;
            }
        }
        if !(*stream).bodystarted {
            Curl_failf(
            data,
            b"HTTP/2 stream %d was closed cleanly, but before getting  all response header fields, treated as error\0"
                as *const u8 as *const i8,
            (*stream).stream_id,
        );
            *err = CURLE_HTTP2_STREAM;
            return -(1) as ssize_t;
        }
        if Curl_dyn_len(&mut (*stream).trailer_recvbuf) != 0 {
            let mut trailp: *mut i8 = Curl_dyn_ptr(&mut (*stream).trailer_recvbuf);
            let mut lf: *mut i8 = 0 as *mut i8;
            loop {
                let mut len: size_t = 0 as size_t;
                let mut result: CURLcode = CURLE_OK;
                lf = strchr(trailp, '\n' as i32);
                if lf.is_null() {
                    break;
                }
                len = lf.offset(1 as isize).offset_from(trailp) as i64 as size_t;
                Curl_debug(data, CURLINFO_HEADER_IN, trailp, len);
                result = Curl_client_write(data, (1) << 1, trailp, len);
                if result as u64 != 0 {
                    *err = result;
                    return -(1) as ssize_t;
                }
                lf = lf.offset(1);
                trailp = lf;
                if lf.is_null() {
                    break;
                }
            }
        }
        (*stream).close_handled = 1 != 0;
        return 0 as ssize_t;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn h2_pri_spec(mut data: *mut Curl_easy, pri_spec: *mut nghttp2_priority_spec) {
    unsafe {
        let depstream: *mut HTTP = if !((*data).set.stream_depends_on).is_null() {
            (*(*data).set.stream_depends_on).req.p.http
        } else {
            0 as *mut HTTP
        };
        let depstream_id: int32_t = if !depstream.is_null() {
            (*depstream).stream_id
        } else {
            0
        };
        nghttp2_priority_spec_init(
            pri_spec,
            depstream_id,
            (*data).set.stream_weight,
            ((*data).set).stream_depends_e() as i32,
        );
        (*data).state.stream_weight = (*data).set.stream_weight;
        let ref mut fresh36 = (*data).state;
        (*fresh36).set_stream_depends_e(((*data).set).stream_depends_e());
        let ref mut fresh37 = (*data).state.stream_depends_on;
        *fresh37 = (*data).set.stream_depends_on;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn h2_session_send(data: *mut Curl_easy, h2: *mut nghttp2_session) -> i32 {
    unsafe {
        let stream: *mut HTTP = (*data).req.p.http;
        let httpc: *mut http_conn = &mut (*(*data).conn).proto.httpc;
        set_transfer(httpc, data);
        if (*data).set.stream_weight != (*data).state.stream_weight
            || ((*data).set).stream_depends_e() != ((*data).state).stream_depends_e()
            || (*data).set.stream_depends_on != (*data).state.stream_depends_on
        {
            let mut pri_spec: nghttp2_priority_spec = nghttp2_priority_spec {
                stream_id: 0,
                weight: 0,
                exclusive: 0,
            };
            let mut rv: i32 = 0;
            h2_pri_spec(data, &mut pri_spec);
            rv = nghttp2_submit_priority(
                h2,
                NGHTTP2_FLAG_NONE as uint8_t,
                (*stream).stream_id,
                &mut pri_spec,
            );
            if rv != 0 {
                return rv;
            }
        }
        return nghttp2_session_send(h2);
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_recv(
    data: *mut Curl_easy,
    sockindex: i32,
    mem: *mut i8,
    len: size_t,
    err: *mut CURLcode,
) -> ssize_t {
    unsafe {
        let mut nread: ssize_t = 0;
        let conn: *mut connectdata = (*data).conn;
        let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
        let mut stream: *mut HTTP = (*data).req.p.http;
        if should_close_session(httpc) != 0 {
            if ((*conn).bits).close() != 0 {
                *err = CURLE_OK;
                return 0 as ssize_t;
            }
            *err = CURLE_HTTP2;
            return -(1) as ssize_t;
        }
        let ref mut fresh38 = (*stream).upload_mem;
        *fresh38 = 0 as *const uint8_t;
        (*stream).upload_len = 0 as i32 as size_t;
        if (*stream).bodystarted as i32 != 0
            && (*stream).nread_header_recvbuf < Curl_dyn_len(&mut (*stream).header_recvbuf)
        {
            let left: size_t = (Curl_dyn_len(&mut (*stream).header_recvbuf))
                .wrapping_sub((*stream).nread_header_recvbuf);
            let ncopy: size_t = if len < left { len } else { left };
            memcpy(
                mem as *mut libc::c_void,
                (Curl_dyn_ptr(&mut (*stream).header_recvbuf))
                    .offset((*stream).nread_header_recvbuf as isize)
                    as *const libc::c_void,
                ncopy,
            );
            let ref mut fresh39 = (*stream).nread_header_recvbuf;
            *fresh39 = (*fresh39 as u64).wrapping_add(ncopy) as size_t as size_t;
            return ncopy as ssize_t;
        }
        if (*data).state.drain != 0 && (*stream).memlen != 0 {
            if mem != (*stream).mem {
                memmove(
                    mem as *mut libc::c_void,
                    (*stream).mem as *const libc::c_void,
                    (*stream).memlen,
                );
                (*stream).len = len.wrapping_sub((*stream).memlen);
                let ref mut fresh40 = (*stream).mem;
                *fresh40 = mem;
            }
            if (*httpc).pause_stream_id == (*stream).stream_id && ((*stream).pausedata).is_null() {
                (*httpc).pause_stream_id = 0;
                if h2_process_pending_input(data, httpc, err) != 0 {
                    return -(1) as ssize_t;
                }
            }
        } else if !((*stream).pausedata).is_null() {
            nread = (if len < (*stream).pauselen {
                len
            } else {
                (*stream).pauselen
            }) as ssize_t;
            memcpy(
                mem as *mut libc::c_void,
                (*stream).pausedata as *const libc::c_void,
                nread as u64,
            );
            let ref mut fresh41 = (*stream).pausedata;
            *fresh41 = (*fresh41).offset(nread as isize);
            let ref mut fresh42 = (*stream).pauselen;
            *fresh42 = (*fresh42 as u64).wrapping_sub(nread as u64) as size_t
                as size_t;
            if (*stream).pauselen == 0 as u64 {
                (*httpc).pause_stream_id = 0;
                let ref mut fresh43 = (*stream).pausedata;
                *fresh43 = 0 as *const uint8_t;
                (*stream).pauselen = 0 as size_t;
                if h2_process_pending_input(data, httpc, err) != 0 {
                    return -(1) as ssize_t;
                }
            }
            return nread;
        } else {
            if (*httpc).pause_stream_id != 0 {
                if (*stream).closed {
                    return 0 as ssize_t;
                }
                *err = CURLE_AGAIN;
                return -(1) as ssize_t;
            } else {
                let ref mut fresh44 = (*stream).mem;
                *fresh44 = mem;
                (*stream).len = len;
                (*stream).memlen = 0 as size_t;
                if (*httpc).inbuflen == 0 as u64 {
                    nread = ((*httpc).recv_underlying).expect("non-null function pointer")(
                        data,
                        0,
                        (*httpc).inbuf,
                        32768 as size_t,
                        err,
                    );
                    if nread == -(1) as i64 {
                        if *err as u32 != CURLE_AGAIN as u32 {
                            Curl_failf(
                                data,
                                b"Failed receiving HTTP2 data\0" as *const u8
                                    as *const i8,
                            );
                        } else if (*stream).closed {
                            return http2_handle_stream_close(conn, data, stream, err);
                        }
                        return -(1) as ssize_t;
                    }
                    if nread == 0 as i64 {
                        if !(*stream).closed {
                            Curl_failf(
                            data,
                            b"HTTP/2 stream %d was not closed cleanly before end of the underlying stream\0"
                                as *const u8 as *const i8,
                            (*stream).stream_id,
                        );
                            *err = CURLE_HTTP2_STREAM;
                            return -(1) as ssize_t;
                        }
                        *err = CURLE_OK;
                        return 0 as ssize_t;
                    }
                    (*httpc).inbuflen = nread as size_t;
                } else {
                    nread = ((*httpc).inbuflen).wrapping_sub((*httpc).nread_inbuf) as ssize_t;
                }
                if h2_process_pending_input(data, httpc, err) != 0 {
                    return -(1) as ssize_t;
                }
            }
        }
        if (*stream).memlen != 0 {
            let retlen: ssize_t = (*stream).memlen as ssize_t;
            (*stream).memlen = 0 as size_t;
            if !((*httpc).pause_stream_id == (*stream).stream_id) {
                if !(*stream).closed {
                    drained_transfer(data, httpc);
                } else {
                    Curl_expire(data, 0 as timediff_t, EXPIRE_RUN_NOW);
                }
            }
            return retlen;
        }
        if (*stream).closed {
            return http2_handle_stream_close(conn, data, stream, err);
        }
        *err = CURLE_AGAIN;
        return -(1) as ssize_t;
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn contains_trailers(mut p: *const i8, len: size_t) -> bool {
    unsafe {
        let mut end: *const i8 = p.offset(len as isize);
        loop {
            while p != end && (*p as i32 == ' ' as i32 || *p as i32 == '\t' as i32)
            {
                p = p.offset(1);
            }
            if p == end
                || (end.offset_from(p) as i64 as size_t)
                    < (::std::mem::size_of::<[i8; 9]>() as u64)
                        .wrapping_sub(1 as u64)
            {
                return 0 != 0;
            }
            if Curl_strncasecompare(
                b"trailers\0" as *const u8 as *const i8,
                p,
                (::std::mem::size_of::<[i8; 9]>() as u64)
                    .wrapping_sub(1 as u64),
            ) != 0
            {
                p = p.offset(
                    (::std::mem::size_of::<[i8; 9]>() as u64)
                        .wrapping_sub(1 as u64) as isize,
                );
                while p != end
                    && (*p as i32 == ' ' as i32 || *p as i32 == '\t' as i32)
                {
                    p = p.offset(1);
                }
                if p == end || *p as i32 == ',' as i32 {
                    return 1 as i32 != 0;
                }
            }
            while p != end && *p as i32 != ',' as i32 {
                p = p.offset(1);
            }
            if p == end {
                return 0 != 0;
            }
            p = p.offset(1);
        }
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn inspect_header(
    name: *const i8,
    namelen: size_t,
    value: *const i8,
    valuelen: size_t,
) -> header_instruction {
    unsafe {
        match namelen {
            2 => {
                if Curl_strncasecompare(b"te\0" as *const u8 as *const i8, name, namelen)
                    == 0
                {
                    return HEADERINST_FORWARD;
                }
                return (if contains_trailers(value, valuelen) as i32 != 0 {
                    HEADERINST_TE_TRAILERS as i32
                } else {
                    HEADERINST_IGNORE as i32
                }) as header_instruction;
            }
            7 => {
                return (if Curl_strncasecompare(
                    b"upgrade\0" as *const u8 as *const i8,
                    name,
                    namelen,
                ) != 0
                {
                    HEADERINST_IGNORE
                } else {
                    HEADERINST_FORWARD
                }) as header_instruction;
            }
            10 => {
                return (if Curl_strncasecompare(
                    b"connection\0" as *const u8 as *const i8,
                    name,
                    namelen,
                ) != 0
                    || Curl_strncasecompare(
                        b"keep-alive\0" as *const u8 as *const i8,
                        name,
                        namelen,
                    ) != 0
                {
                    HEADERINST_IGNORE
                } else {
                    HEADERINST_FORWARD
                }) as header_instruction;
            }
            16 => {
                return (if Curl_strncasecompare(
                    b"proxy-connection\0" as *const u8 as *const i8,
                    name,
                    namelen,
                ) != 0
                {
                    HEADERINST_IGNORE
                } else {
                    HEADERINST_FORWARD
                }) as header_instruction;
            }
            17 => {
                return (if Curl_strncasecompare(
                    b"transfer-encoding\0" as *const u8 as *const i8,
                    name,
                    namelen,
                ) != 0
                {
                    HEADERINST_IGNORE
                } else {
                    HEADERINST_FORWARD
                }) as header_instruction;
            }
            _ => return HEADERINST_FORWARD,
        };
    }
}
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_send(
    data: *mut Curl_easy,
    sockindex: i32,
    mem: *const libc::c_void,
    mut len: size_t,
    err: *mut CURLcode,
) -> ssize_t {
    unsafe {
        let current_block: u64;
        let mut rv: i32 = 0;
        let conn: *mut connectdata = (*data).conn;
        let httpc: *mut http_conn = &mut (*conn).proto.httpc;
        let mut stream: *mut HTTP = (*data).req.p.http;
        let mut nva: *mut nghttp2_nv = 0 as *mut nghttp2_nv;
        let mut nheader: size_t = 0;
        let mut i: size_t = 0;
        let mut authority_idx: size_t = 0;
        let mut hdbuf: *mut i8 = mem as *mut i8;
        let mut end: *mut i8 = 0 as *mut i8;
        let mut line_end: *mut i8 = 0 as *mut i8;
        let mut data_prd: nghttp2_data_provider = nghttp2_data_provider {
            source: nghttp2_data_source { fd: 0 },
            read_callback: None,
        };
        let mut stream_id: int32_t = 0;
        let h2: *mut nghttp2_session = (*httpc).h2;
        let mut pri_spec: nghttp2_priority_spec = nghttp2_priority_spec {
            stream_id: 0,
            weight: 0,
            exclusive: 0,
        };
        if (*stream).stream_id != -(1) {
            if (*stream).close_handled {
                Curl_infof(
                    data,
                    b"stream %d closed\0" as *const u8 as *const i8,
                    (*stream).stream_id,
                );
                *err = CURLE_HTTP2_STREAM;
                return -(1) as ssize_t;
            } else {
                if (*stream).closed {
                    return http2_handle_stream_close(conn, data, stream, err);
                }
            }
            let ref mut fresh45 = (*stream).upload_mem;
            *fresh45 = mem as *const uint8_t;
            (*stream).upload_len = len;
            rv = nghttp2_session_resume_data(h2, (*stream).stream_id);
            if nghttp2_is_fatal(rv) != 0 {
                *err = CURLE_SEND_ERROR;
                return -(1) as ssize_t;
            }
            rv = h2_session_send(data, h2);
            if nghttp2_is_fatal(rv) != 0 {
                *err = CURLE_SEND_ERROR;
                return -(1) as ssize_t;
            }
            len = (len as u64).wrapping_sub((*stream).upload_len) as size_t as size_t;
            let ref mut fresh46 = (*stream).upload_mem;
            *fresh46 = 0 as *const uint8_t;
            (*stream).upload_len = 0 as size_t;
            if should_close_session(httpc) != 0 {
                *err = CURLE_HTTP2;
                return -(1) as ssize_t;
            }
            if (*stream).upload_left != 0 {
                nghttp2_session_resume_data(h2, (*stream).stream_id);
            }
            return len as ssize_t;
        }
        nheader = 0 as size_t;
        i = 1 as size_t;
        while i < len {
            if *hdbuf.offset(i as isize) as i32 == '\n' as i32
                && *hdbuf.offset(i.wrapping_sub(1 as i32 as u64) as isize)
                    as i32
                    == '\r' as i32
            {
                nheader = nheader.wrapping_add(1);
                i = i.wrapping_add(1);
            }
            i = i.wrapping_add(1);
        }
        if !(nheader < 2 as u64) {
            nheader =
                (nheader as u64).wrapping_add(1 as u64) as size_t as size_t;
            nva = Curl_cmalloc.expect("non-null function pointer")(
                (::std::mem::size_of::<nghttp2_nv>() as u64).wrapping_mul(nheader),
            ) as *mut nghttp2_nv;
            if nva.is_null() {
                *err = CURLE_OUT_OF_MEMORY;
                return -(1) as ssize_t;
            }
            line_end = memchr(hdbuf as *const libc::c_void, '\r' as i32, len) as *mut i8;
            if !line_end.is_null() {
                end = memchr(
                    hdbuf as *const libc::c_void,
                    ' ' as i32,
                    line_end.offset_from(hdbuf) as i64 as u64,
                ) as *mut i8;
                if !(end.is_null() || end == hdbuf) {
                    let ref mut fresh47 = (*nva.offset(0 as isize)).name;
                    *fresh47 =
                        b":method\0" as *const u8 as *const i8 as *mut u8;
                    (*nva.offset(0 as isize)).namelen =
                        strlen((*nva.offset(0 as isize)).name as *mut i8);
                    let ref mut fresh48 = (*nva.offset(0 as isize)).value;
                    *fresh48 = hdbuf as *mut u8;
                    (*nva.offset(0 as isize)).valuelen =
                        end.offset_from(hdbuf) as i64 as size_t;
                    (*nva.offset(0 as isize)).flags = NGHTTP2_NV_FLAG_NONE as uint8_t;
                    if (*nva.offset(0 as isize)).namelen > 0xffff as u64
                        || (*nva.offset(0 as isize)).valuelen
                            > (0xffff as u64)
                                .wrapping_sub((*nva.offset(0 as isize)).namelen)
                    {
                        Curl_failf(
                            data,
                            b"Failed sending HTTP request: Header overflow\0" as *const u8
                                as *const i8,
                        );
                    } else {
                        hdbuf = end.offset(1 as isize);
                        end = 0 as *mut i8;
                        i = line_end.offset_from(hdbuf) as i64 as size_t;
                        while i != 0 {
                            if *hdbuf
                                .offset(i.wrapping_sub(1 as i32 as u64) as isize)
                                as i32
                                == ' ' as i32
                            {
                                end = &mut *hdbuf
                                    .offset(i.wrapping_sub(1 as u64) as isize)
                                    as *mut i8;
                                break;
                            } else {
                                i = i.wrapping_sub(1);
                            }
                        }
                        if !(end.is_null() || end == hdbuf) {
                            let ref mut fresh49 = (*nva.offset(1 as isize)).name;
                            *fresh49 = b":path\0" as *const u8 as *const i8
                                as *mut u8;
                            (*nva.offset(1 as isize)).namelen =
                                strlen((*nva.offset(1 as isize)).name as *mut i8);
                            let ref mut fresh50 = (*nva.offset(1 as isize)).value;
                            *fresh50 = hdbuf as *mut u8;
                            (*nva.offset(1 as isize)).valuelen =
                                end.offset_from(hdbuf) as i64 as size_t;
                            (*nva.offset(1 as isize)).flags = NGHTTP2_NV_FLAG_NONE as uint8_t;
                            if (*nva.offset(1 as isize)).namelen > 0xffff as u64
                                || (*nva.offset(1 as isize)).valuelen
                                    > (0xffff as u64)
                                        .wrapping_sub((*nva.offset(1 as isize)).namelen)
                            {
                                Curl_failf(
                                    data,
                                    b"Failed sending HTTP request: Header overflow\0" as *const u8
                                        as *const i8,
                                );
                            } else {
                                let ref mut fresh51 = (*nva.offset(2 as isize)).name;
                                *fresh51 = b":scheme\0" as *const u8 as *const i8
                                    as *mut u8;
                                (*nva.offset(2 as isize)).namelen =
                                    strlen((*nva.offset(2 as isize)).name as *mut i8);
                                if (*(*conn).handler).flags & ((1) << 0) as u32 != 0 {
                                    let ref mut fresh52 = (*nva.offset(2 as isize)).value;
                                    *fresh52 = b"https\0" as *const u8 as *const i8
                                        as *mut u8;
                                } else {
                                    let ref mut fresh53 = (*nva.offset(2 as isize)).value;
                                    *fresh53 = b"http\0" as *const u8 as *const i8
                                        as *mut u8;
                                }
                                (*nva.offset(2 as isize)).valuelen =
                                    strlen((*nva.offset(2 as isize)).value as *mut i8);
                                (*nva.offset(2 as isize)).flags = NGHTTP2_NV_FLAG_NONE as uint8_t;
                                if (*nva.offset(2 as isize)).namelen > 0xffff as u64
                                    || (*nva.offset(2 as isize)).valuelen
                                        > (0xffff as u64)
                                            .wrapping_sub((*nva.offset(2 as isize)).namelen)
                                {
                                    Curl_failf(
                                        data,
                                        b"Failed sending HTTP request: Header overflow\0"
                                            as *const u8
                                            as *const i8,
                                    );
                                } else {
                                    authority_idx = 0 as size_t;
                                    i = 3 as size_t;
                                    loop {
                                        if !(i < nheader) {
                                            current_block = 228501038991332163;
                                            break;
                                        }
                                        let mut hlen: size_t = 0;
                                        hdbuf = line_end.offset(2 as isize);
                                        line_end = memchr(
                                            hdbuf as *const libc::c_void,
                                            '\r' as i32,
                                            len.wrapping_sub(
                                                hdbuf.offset_from(mem as *mut i8)
                                                    as i64
                                                    as u64,
                                            ),
                                        )
                                            as *mut i8;
                                        if line_end.is_null() || line_end == hdbuf {
                                            current_block = 13424226081900325153;
                                            break;
                                        }
                                        if *hdbuf as i32 == ' ' as i32
                                            || *hdbuf as i32 == '\t' as i32
                                        {
                                            current_block = 13424226081900325153;
                                            break;
                                        }
                                        end = hdbuf;
                                        while end < line_end && *end as i32 != ':' as i32 {
                                            end = end.offset(1);
                                        }
                                        if end == hdbuf || end == line_end {
                                            current_block = 13424226081900325153;
                                            break;
                                        }
                                        hlen = end.offset_from(hdbuf) as i64 as size_t;
                                        if hlen == 4 as u64
                                            && Curl_strncasecompare(
                                                b"host\0" as *const u8 as *const i8,
                                                hdbuf,
                                                4 as size_t,
                                            ) != 0
                                        {
                                            authority_idx = i;
                                            let ref mut fresh54 = (*nva.offset(i as isize)).name;
                                            *fresh54 = b":authority\0" as *const u8
                                                as *const i8
                                                as *mut u8;
                                            (*nva.offset(i as isize)).namelen = strlen(
                                                (*nva.offset(i as isize)).name as *mut i8,
                                            );
                                        } else {
                                            (*nva.offset(i as isize)).namelen =
                                                end.offset_from(hdbuf) as i64 as size_t;
                                            Curl_strntolower(
                                                hdbuf,
                                                hdbuf,
                                                (*nva.offset(i as isize)).namelen,
                                            );
                                            let ref mut fresh55 = (*nva.offset(i as isize)).name;
                                            *fresh55 = hdbuf as *mut u8;
                                        }
                                        hdbuf = end.offset(1 as i32 as isize);
                                        while *hdbuf as i32 == ' ' as i32
                                            || *hdbuf as i32 == '\t' as i32
                                        {
                                            hdbuf = hdbuf.offset(1);
                                        }
                                        end = line_end;
                                        match inspect_header(
                                            (*nva.offset(i as isize)).name as *const i8,
                                            (*nva.offset(i as isize)).namelen,
                                            hdbuf,
                                            end.offset_from(hdbuf) as i64 as size_t,
                                        )
                                            as u32
                                        {
                                            1 => {
                                                nheader = nheader.wrapping_sub(1);
                                                continue;
                                            }
                                            2 => {
                                                let ref mut fresh56 =
                                                    (*nva.offset(i as isize)).value;
                                                *fresh56 = b"trailers\0" as *const u8
                                                    as *const i8
                                                    as *mut uint8_t;
                                                (*nva.offset(i as isize)).valuelen =
                                                    (::std::mem::size_of::<[i8; 9]>()
                                                        as u64)
                                                        .wrapping_sub(1 as u64);
                                            }
                                            _ => {
                                                let ref mut fresh57 =
                                                    (*nva.offset(i as isize)).value;
                                                *fresh57 = hdbuf as *mut u8;
                                                (*nva.offset(i as isize)).valuelen =
                                                    end.offset_from(hdbuf) as i64
                                                        as size_t;
                                            }
                                        }
                                        (*nva.offset(i as isize)).flags =
                                            NGHTTP2_NV_FLAG_NONE as uint8_t;
                                        if (*nva.offset(i as isize)).namelen
                                            > 0xffff as u64
                                            || (*nva.offset(i as isize)).valuelen
                                                > (0xffff as u64)
                                                    .wrapping_sub((*nva.offset(i as isize)).namelen)
                                        {
                                            Curl_failf(
                                                data,
                                                b"Failed sending HTTP request: Header overflow\0"
                                                    as *const u8
                                                    as *const i8,
                                            );
                                            current_block = 13424226081900325153;
                                            break;
                                        } else {
                                            i = i.wrapping_add(1);
                                        }
                                    }
                                    match current_block {
                                        13424226081900325153 => {}
                                        _ => {
                                            if authority_idx != 0
                                                && authority_idx != 3 as u64
                                            {
                                                let mut authority: nghttp2_nv =
                                                    *nva.offset(authority_idx as isize);
                                                i = authority_idx;
                                                while i > 3 as u64 {
                                                    *nva.offset(i as isize) = *nva
                                                        .offset(i.wrapping_sub(1 as u64)
                                                            as isize);
                                                    i = i.wrapping_sub(1);
                                                }
                                                *nva.offset(i as isize) = authority;
                                            }
                                            let mut acc: size_t = 0 as size_t;
                                            i = 0 as size_t;
                                            while i < nheader {
                                                acc = (acc as u64).wrapping_add(
                                                    ((*nva.offset(i as isize)).namelen)
                                                        .wrapping_add(
                                                            (*nva.offset(i as isize)).valuelen,
                                                        ),
                                                )
                                                    as size_t
                                                    as size_t;
                                                i = i.wrapping_add(1);
                                            }
                                            if acc > 60000 as u64 {
                                                Curl_infof(
                                                data,
                                                b"http2_send: Warning: The cumulative length of all headers exceeds %d bytes and that could cause the stream to be rejected.\0"
                                                    as *const u8 as *const i8,
                                                60000  ,
                                            );
                                            }
                                            h2_pri_spec(data, &mut pri_spec);
                                            match (*data).state.httpreq as u32 {
                                                1 | 2 | 3 | 4 => {
                                                    if (*data).state.infilesize
                                                        != -(1) as i64
                                                    {
                                                        (*stream).upload_left =
                                                            (*data).state.infilesize;
                                                    } else {
                                                        (*stream).upload_left = -(1) as curl_off_t;
                                                    }
                                                    data_prd.read_callback = Some(
                                                        data_source_read_callback
                                                            as extern "C" fn(
                                                                *mut nghttp2_session,
                                                                int32_t,
                                                                *mut uint8_t,
                                                                size_t,
                                                                *mut uint32_t,
                                                                *mut nghttp2_data_source,
                                                                *mut libc::c_void,
                                                            )
                                                                -> ssize_t,
                                                    );
                                                    data_prd.source.ptr = 0 as *mut libc::c_void;
                                                    stream_id = nghttp2_submit_request(
                                                        h2,
                                                        &mut pri_spec,
                                                        nva,
                                                        nheader,
                                                        &mut data_prd,
                                                        data as *mut libc::c_void,
                                                    );
                                                }
                                                _ => {
                                                    stream_id = nghttp2_submit_request(
                                                        h2,
                                                        &mut pri_spec,
                                                        nva,
                                                        nheader,
                                                        0 as *const nghttp2_data_provider,
                                                        data as *mut libc::c_void,
                                                    );
                                                }
                                            }
                                            Curl_cfree.expect("non-null function pointer")(
                                                nva as *mut libc::c_void,
                                            );
                                            nva = 0 as *mut nghttp2_nv;
                                            if stream_id < 0 {
                                                *err = CURLE_SEND_ERROR;
                                                return -(1) as ssize_t;
                                            }
                                            Curl_infof(
                                                data,
                                                b"Using Stream ID: %x (easy handle %p)\0"
                                                    as *const u8
                                                    as *const i8,
                                                stream_id,
                                                data as *mut libc::c_void,
                                            );
                                            (*stream).stream_id = stream_id;
                                            rv = h2_session_send(data, h2);
                                            if rv != 0 {
                                                *err = CURLE_SEND_ERROR;
                                                return -(1) as ssize_t;
                                            }
                                            if should_close_session(httpc) != 0 {
                                                *err = CURLE_HTTP2;
                                                return -(1) as ssize_t;
                                            }
                                            nghttp2_session_resume_data(h2, (*stream).stream_id);
                                            return len as ssize_t;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Curl_cfree.expect("non-null function pointer")(nva as *mut libc::c_void);
        *err = CURLE_SEND_ERROR;
        return -(1) as ssize_t;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_setup(data: *mut Curl_easy, mut conn: *mut connectdata) -> CURLcode {
    unsafe {
        let mut result: CURLcode = CURLE_OK;
        let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
        let mut stream: *mut HTTP = (*data).req.p.http;
        (*stream).stream_id = -(1);
        Curl_dyn_init(&mut (*stream).header_recvbuf, (128 * 1024) as size_t);
        Curl_dyn_init(&mut (*stream).trailer_recvbuf, (128 * 1024) as size_t);
        (*stream).upload_left = 0 as curl_off_t;
        let ref mut fresh58 = (*stream).upload_mem;
        *fresh58 = 0 as *const uint8_t;
        (*stream).upload_len = 0 as size_t;
        let ref mut fresh59 = (*stream).mem;
        *fresh59 = (*data).state.buffer;
        (*stream).len = (*data).set.buffer_size as size_t;
        multi_connchanged((*data).multi);
        if (*conn).handler == &Curl_handler_http2_ssl as *const Curl_handler
            || (*conn).handler == &Curl_handler_http2 as *const Curl_handler
        {
            return CURLE_OK;
        }
        if (*(*conn).handler).flags & ((1) << 0) as u32 != 0 {
            let ref mut fresh60 = (*conn).handler;
            *fresh60 = &Curl_handler_http2_ssl;
        } else {
            let ref mut fresh61 = (*conn).handler;
            *fresh61 = &Curl_handler_http2;
        }
        result = http2_init(data, conn);
        if result as u64 != 0 {
            Curl_dyn_free(&mut (*stream).header_recvbuf);
            return result;
        }
        Curl_infof(
            data,
            b"Using HTTP2, server supports multiplexing\0" as *const u8 as *const i8,
        );
        let ref mut fresh62 = (*conn).bits;
        (*fresh62).set_multiplex(1 as bit);
        (*conn).httpversion = 20 as u8;
        (*(*conn).bundle).multiuse = 2;
        (*httpc).inbuflen = 0 as size_t;
        (*httpc).nread_inbuf = 0 as size_t;
        (*httpc).pause_stream_id = 0;
        (*httpc).drain_total = 0 as size_t;
        Curl_infof(
            data,
            b"Connection state changed (HTTP/2 confirmed)\0" as *const u8 as *const i8,
        );
        return CURLE_OK;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_switched(
    data: *mut Curl_easy,
    mem: *const i8,
    nread: size_t,
) -> CURLcode {
    unsafe {
        let mut result: CURLcode = CURLE_OK;
        let conn: *mut connectdata = (*data).conn;
        let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
        let mut rv: i32 = 0;
        let mut stream: *mut HTTP = (*data).req.p.http;
        result = Curl_http2_setup(data, conn);
        if result as u64 != 0 {
            return result;
        }
        let ref mut fresh63 = (*httpc).recv_underlying;
        *fresh63 = (*conn).recv[0 as usize];
        let ref mut fresh64 = (*httpc).send_underlying;
        *fresh64 = (*conn).send[0 as usize];
        let ref mut fresh65 = (*conn).recv[0 as usize];
        *fresh65 = Some(
            http2_recv
                as extern "C" fn(
                    *mut Curl_easy,
                    i32,
                    *mut i8,
                    size_t,
                    *mut CURLcode,
                ) -> ssize_t,
        );
        let ref mut fresh66 = (*conn).send[0 as usize];
        *fresh66 = Some(
            http2_send
                as extern "C" fn(
                    *mut Curl_easy,
                    i32,
                    *const libc::c_void,
                    size_t,
                    *mut CURLcode,
                ) -> ssize_t,
        );
        if (*data).req.upgr101 as u32 == UPGR101_RECEIVED as u32 {
            (*stream).stream_id = 1;
            rv = nghttp2_session_upgrade2(
                (*httpc).h2,
                ((*httpc).binsettings).as_mut_ptr(),
                (*httpc).binlen,
                ((*data).state.httpreq as u32
                    == HTTPREQ_HEAD as i32 as u32) as i32,
                0 as *mut libc::c_void,
            );
            if rv != 0 {
                Curl_failf(
                    data,
                    b"nghttp2_session_upgrade2() failed: %s(%d)\0" as *const u8
                        as *const i8,
                    nghttp2_strerror(rv),
                    rv,
                );
                return CURLE_HTTP2;
            }
            rv = nghttp2_session_set_stream_user_data(
                (*httpc).h2,
                (*stream).stream_id,
                data as *mut libc::c_void,
            );
            if rv != 0 {
                Curl_infof(
                    data,
                    b"http/2: failed to set user_data for stream %d!\0" as *const u8
                        as *const i8,
                    (*stream).stream_id,
                );
            }
        } else {
            populate_settings(data, httpc);
            (*stream).stream_id = -(1);
            rv = nghttp2_submit_settings(
                (*httpc).h2,
                NGHTTP2_FLAG_NONE as uint8_t,
                ((*httpc).local_settings).as_mut_ptr(),
                (*httpc).local_settings_num,
            );
            if rv != 0 {
                Curl_failf(
                    data,
                    b"nghttp2_submit_settings() failed: %s(%d)\0" as *const u8
                        as *const i8,
                    nghttp2_strerror(rv),
                    rv,
                );
                return CURLE_HTTP2;
            }
        }
        rv = nghttp2_session_set_local_window_size(
            (*httpc).h2,
            NGHTTP2_FLAG_NONE as uint8_t,
            0,
            32 * 1024 * 1024,
        );
        if rv != 0 {
            Curl_failf(
                data,
                b"nghttp2_session_set_local_window_size() failed: %s(%d)\0" as *const u8
                    as *const i8,
                nghttp2_strerror(rv),
                rv,
            );
            return CURLE_HTTP2;
        }
        if (32768 as u64) < nread {
            Curl_failf(
            data,
            b"connection buffer size is too small to store data following HTTP Upgrade response header: buflen=%d, datalen=%zu\0"
                as *const u8 as *const i8,
            32768  ,
            nread,
        );
            return CURLE_HTTP2;
        }
        Curl_infof(
            data,
            b"Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=%zu\0"
                as *const u8 as *const i8,
            nread,
        );
        if nread != 0 {
            memcpy(
                (*httpc).inbuf as *mut libc::c_void,
                mem as *const libc::c_void,
                nread,
            );
        }
        (*httpc).inbuflen = nread;
        if -(1) == h2_process_pending_input(data, httpc, &mut result) {
            return CURLE_HTTP2;
        }
        return CURLE_OK;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_stream_pause(data: *mut Curl_easy, pause: bool) -> CURLcode {
    unsafe {
        if (*(*(*data).conn).handler).protocol & ((1) << 0 | (1) << 1) as u32 == 0
            || ((*(*data).conn).proto.httpc.h2).is_null()
        {
            return CURLE_OK;
        } else {
            match () {
                #[cfg(NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE)]
                _ => {
                    let stream: *mut HTTP = (*data).req.p.http;
                    let httpc: *mut http_conn = &mut (*(*data).conn).proto.httpc;
                    let window: uint32_t = (!pause as i32
                        * (32 as i32 * 1024 as i32 * 1024 as i32))
                        as uint32_t;
                    let mut rv: i32 = nghttp2_session_set_local_window_size(
                        (*httpc).h2,
                        NGHTTP2_FLAG_NONE as uint8_t,
                        (*stream).stream_id,
                        window as int32_t,
                    );
                    if rv != 0 {
                        Curl_failf(
                            data,
                            b"nghttp2_session_set_local_window_size() failed: %s(%d)\0" as *const u8
                                as *const i8,
                            nghttp2_strerror(rv),
                            rv,
                        );
                        return CURLE_HTTP2;
                    }
                    rv = h2_session_send(data, (*httpc).h2);
                    if rv != 0 {
                        return CURLE_SEND_ERROR;
                    }
                }
                #[cfg(not(NGHTTP2_HAS_SET_LOCAL_WINDOWS_SIZE))]
                _ => {}
            }
        }
        return CURLE_OK;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_add_child(
    parent: *mut Curl_easy,
    child: *mut Curl_easy,
    exclusive: bool,
) -> CURLcode {
    unsafe {
        if !parent.is_null() {
            let mut tail: *mut *mut Curl_http2_dep = 0 as *mut *mut Curl_http2_dep;
            let mut dep: *mut Curl_http2_dep = Curl_ccalloc.expect("non-null function pointer")(
                1 as size_t,
                ::std::mem::size_of::<Curl_http2_dep>() as u64,
            ) as *mut Curl_http2_dep;
            if dep.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let ref mut fresh67 = (*dep).data;
            *fresh67 = child;
            if !((*parent).set.stream_dependents).is_null() && exclusive as i32 != 0 {
                let mut node: *mut Curl_http2_dep = (*parent).set.stream_dependents;
                while !node.is_null() {
                    let ref mut fresh68 = (*(*node).data).set.stream_depends_on;
                    *fresh68 = child;
                    node = (*node).next;
                }
                tail = &mut (*child).set.stream_dependents;
                while !(*tail).is_null() {
                    tail = &mut (**tail).next;
                }
                *tail = (*parent).set.stream_dependents;
                let ref mut fresh69 = (*parent).set.stream_dependents;
                *fresh69 = 0 as *mut Curl_http2_dep;
            }
            tail = &mut (*parent).set.stream_dependents;
            while !(*tail).is_null() {
                let ref mut fresh70 = (*(**tail).data).set;
                (*fresh70).set_stream_depends_e(0 as bit);
                tail = &mut (**tail).next;
            }
            *tail = dep;
        }
        let ref mut fresh71 = (*child).set.stream_depends_on;
        *fresh71 = parent;
        let ref mut fresh72 = (*child).set;
        (*fresh72).set_stream_depends_e(exclusive as bit);
        return CURLE_OK;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_remove_child(parent: *mut Curl_easy, child: *mut Curl_easy) {
    unsafe {
        let mut last: *mut Curl_http2_dep = 0 as *mut Curl_http2_dep;
        let mut data: *mut Curl_http2_dep = (*parent).set.stream_dependents;
        while !data.is_null() && (*data).data != child {
            last = data;
            data = (*data).next;
        }
        if !data.is_null() {
            if !last.is_null() {
                let ref mut fresh73 = (*last).next;
                *fresh73 = (*data).next;
            } else {
                let ref mut fresh74 = (*parent).set.stream_dependents;
                *fresh74 = (*data).next;
            }
            Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
        }
        let ref mut fresh75 = (*child).set.stream_depends_on;
        *fresh75 = 0 as *mut Curl_easy;
        let ref mut fresh76 = (*child).set;
        (*fresh76).set_stream_depends_e(0 as bit);
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_cleanup_dependencies(data: *mut Curl_easy) {
    unsafe {
        while !((*data).set.stream_dependents).is_null() {
            let mut tmp: *mut Curl_easy = (*(*data).set.stream_dependents).data;
            Curl_http2_remove_child(data, tmp);
            if !((*data).set.stream_depends_on).is_null() {
                Curl_http2_add_child((*data).set.stream_depends_on, tmp, 0 != 0);
            }
        }
        if !((*data).set.stream_depends_on).is_null() {
            Curl_http2_remove_child((*data).set.stream_depends_on, data);
        }
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_h2_http_1_1_error(data: *mut Curl_easy) -> bool {
    unsafe {
        let stream: *mut HTTP = (*data).req.p.http;
        return (*stream).error == NGHTTP2_HTTP_1_1_REQUIRED as u32;
    }
}

#[cfg(not(USE_NGHTTP2))]
#[no_mangle]
pub extern "C" fn Curl_http2_request_upgrade(
    mut req: *mut dynbuf,
    mut data: *mut Curl_easy,
) -> CURLcode {
    return CURLE_UNSUPPORTED_PROTOCOL;
}
#[cfg(not(USE_NGHTTP2))]
#[no_mangle]
pub extern "C" fn Curl_http2_setup(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    return CURLE_UNSUPPORTED_PROTOCOL;
}
#[cfg(not(USE_NGHTTP2))]
#[no_mangle]
pub extern "C" fn Curl_http2_switched(
    mut data: *mut Curl_easy,
    mut mem: *const i8,
    mut nread: size_t,
) -> CURLcode {
    return CURLE_UNSUPPORTED_PROTOCOL;
}
#[cfg(not(USE_NGHTTP2))]
#[no_mangle]
pub extern "C" fn Curl_http2_setup_conn(mut conn: *mut connectdata) {}
#[cfg(not(USE_NGHTTP2))]
#[no_mangle]
pub extern "C" fn Curl_http2_setup_req(mut data: *mut Curl_easy) {}
#[cfg(not(USE_NGHTTP2))]
#[no_mangle]
pub extern "C" fn Curl_http2_done(mut data: *mut Curl_easy, mut premature: bool) {}
#[cfg(not(USE_NGHTTP2))]
#[no_mangle]
pub extern "C" fn curl_pushheader_bynum(
    mut h: *mut curl_pushheaders,
    mut num: size_t,
) -> *mut i8 {
    return 0 as *mut i8;
}
#[cfg(not(USE_NGHTTP2))]
#[no_mangle]
pub extern "C" fn curl_pushheader_byname(
    mut h: *mut curl_pushheaders,
    mut header: *const i8,
) -> *mut i8 {
    return 0 as *mut i8;
}
