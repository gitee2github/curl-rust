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

const NGHTTP2_DEFAULT_WEIGHT: i32 = 16;
const GETSOCK_BLANK: i32 = 0;
const H2_BUFSIZE: size_t = 32768;
const CONNCHECK_ISDEAD: u32 = ((1) << 0) as u32;
const CONNRESULT_DEAD: u32 = ((1) << 0) as u32;
const CONNCHECK_KEEPALIVE: u32 = ((1) << 1) as u32;
const ZERO_NULL: *const uint8_t = 0 as *const uint8_t;
const DEFAULT_MAX_CONCURRENT_STREAMS: uint32_t = 100 as uint32_t;
const KEEP_SEND: i32 = (1) << 1;
const KEEP_SEND_PAUSE: i32 = (1) << 5;
const KEEP_RECV_PAUSE: i32 = (1) << 4;
const FIRSTSOCKET: usize = 0;
const CURL_CSELECT_ERR: i32 = 0x4;
const CURL_CSELECT_IN: i32 = 0x1;
const PORT_HTTP: i32 = 80;
const CURLPROTO_HTTPS: u32 = (1) << 1;
const CURLPROTO_HTTP: u32 = (1) << 0;
const PROTOPT_SSL: u32 = (1) << 0;
const PROTOPT_STREAM: u32 = (1) << 9;
const CONNRESULT_NONE: u32 = 0;
const DYN_H2_HEADERS: size_t = 128 * 1024;
const CURL_PUSH_DENY: i32 = 1;
const DYN_H2_TRAILERS: i32 = 128 * 1024;
const NGHTTP2_DATA: u8 = 0;
const NGHTTP2_HEADERS: u8 = 1;
const NGHTTP2_PUSH_PROMISE: u8 = 5;
const AUTHORITY_DST_IDX: libc::c_ulong = 3;
const HTTPREQ_POST: u32 = 1;
const HTTPREQ_POST_FORM: u32 = 2;
const HTTPREQ_POST_MIME: u32 = 3;
const HTTPREQ_PUT: u32 = 4;
const PROTO_FAMILY_HTTP: u32 = (1) << 0 | (1) << 1;

// TODO http2.c中有一个结构体定义curl_pushheaders和一个enum定义，可能需要放到这里来

const CURLEASY_MAGIC_NUMBER: u32 = 0xc0dedbad;
// fn GOOD_EASY_HANDLE(h: *mut curl_pushheaders) -> bool {
//     unsafe {
//         !((*h).data).is_null() && (*(*h).data).magic == 0xc0dedbad as u32
//     }
// }
fn GOOD_EASY_HANDLE(data: *mut Curl_easy) -> bool {
    unsafe {
        !data.is_null() && (*data).magic == 0xc0dedbad as u32
    }
}

#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_init_state(mut state: *mut UrlState) {
    unsafe {
        (*state).stream_weight = NGHTTP2_DEFAULT_WEIGHT;
    }
}
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_init_userset(mut set: *mut UserDefined) {
    unsafe {
        (*set).stream_weight = NGHTTP2_DEFAULT_WEIGHT;
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
        let mut bitmap: i32 = GETSOCK_BLANK;
        *sock.offset(0) = (*conn).sock[0];
        if (*k).keepon & KEEP_RECV_PAUSE == 0 {
            bitmap |= (1) << 0;
        }
        if (*k).keepon & (KEEP_SEND | KEEP_SEND_PAUSE) == KEEP_SEND
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
            while (*http).push_headers_used > 0 {
                Curl_cfree.expect("non-null function pointer")(
                    *((*http).push_headers)
                        .offset(((*http).push_headers_used).wrapping_sub(1) as isize)
                        as *mut libc::c_void,
                );
                (*http).push_headers_used = (*http).push_headers_used.wrapping_sub(1);
            }
            Curl_cfree.expect("non-null function pointer")(
                (*http).push_headers as *mut libc::c_void,
            );
            (*http).push_headers = 0 as *mut *mut i8;
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
        (*c).inbuf = 0 as *mut i8;
        return CURLE_OK;
    }
}

#[cfg(USE_NGHTTP2)]
extern "C" fn http2_connisdead(data: *mut Curl_easy, conn: *mut connectdata) -> bool {
    unsafe {
        let mut sval: i32 = 0;
        let mut dead: bool = true;
        if ((*conn).bits).close() != 0 {
            return true;
        }
        sval = Curl_socket_check((*conn).sock[FIRSTSOCKET], -(1), -(1), 0 as timediff_t);
        if sval == 0 {
            /* timeout */
            dead = false;
        } else if sval & CURL_CSELECT_ERR != 0 {
            /* socket is in an error state */
            dead = true;
        } else if sval & CURL_CSELECT_IN != 0 {
            /* readable with no error. could still be closed */
            dead = !Curl_connalive(conn);
            if !dead {
                /* This happens before we've sent off a request and the connection is
                not in use by any other transfer, there shouldn't be any data here,
                only "protocol frames" */
                let mut result: CURLcode = CURLE_OK;
                let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
                let mut nread: ssize_t = -1;
                if ((*httpc).recv_underlying).is_some() {
                    /* if called "too early", this pointer isn't setup yet! */
                    nread = ((*httpc).recv_underlying).expect("non-null function pointer")(
                        data,
                        FIRSTSOCKET as i32,
                        (*httpc).inbuf,
                        H2_BUFSIZE,
                        &mut result,
                    );
                }
                if nread != -1 {
                    Curl_infof(
                        data,
                        b"%d bytes stray data read before trying h2 connection\0" as *const u8
                            as *const i8,
                        nread,
                    );
                    (*httpc).nread_inbuf = 0;
                    (*httpc).inbuflen = nread as size_t;
                    if h2_process_pending_input(data, httpc, &mut result) < 0 {
                        /* immediate error, considered dead */

                        dead = true;
                    }
                } else {
                    /* the read failed so let's say this is dead anyway */

                    dead = true;
                }
            }
        }
        return dead;
    }
}

/*
 * Set the transfer that is currently using this HTTP/2 connection.
 */
#[cfg(USE_NGHTTP2)]
extern "C" fn set_transfer(c: *mut http_conn, data: *mut Curl_easy) {
    unsafe {
        (*c).trnsfr = data;
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
        let mut ret_val: u32 = CONNRESULT_NONE;
        let c: *mut http_conn = &mut (*conn).proto.httpc;
        let mut rc: i32 = 0;
        let mut send_frames: bool = false;
        if checks_to_perform & CONNCHECK_ISDEAD != 0 {
            if http2_connisdead(data, conn) {
                ret_val |= CONNRESULT_DEAD;
            }
        }
        if checks_to_perform & CONNCHECK_KEEPALIVE != 0 {
            let now: curltime = Curl_now();
            let elapsed: timediff_t = Curl_timediff(now, (*conn).keepalive);
            if elapsed > (*data).set.upkeep_interval_ms {
                /* Perform an HTTP/2 PING */
                rc = nghttp2_submit_ping((*c).h2, 0 as uint8_t, ZERO_NULL);
                if rc == 0 {
                    /* Successfully added a PING frame to the session. Need to flag this
                    so the frame is sent. */
                    send_frames = true;
                } else {
                    Curl_failf(
                        data,
                        b"nghttp2_submit_ping() failed: %s(%d)\0" as *const u8 as *const i8,
                        nghttp2_strerror(rc),
                        rc,
                    );
                }
                (*conn).keepalive = now;
            }
        }
        if send_frames {
            set_transfer(c, data); /* set the transfer */
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

/* called from http_setup_conn */
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_setup_req(data: *mut Curl_easy) {
    unsafe {
        let mut http: *mut HTTP = (*data).req.p.http;
        (*http).bodystarted = false;
        (*http).status_code = -1;
        (*http).pausedata = 0 as *const uint8_t;
        (*http).pauselen = 0;
        (*http).closed = false;
        (*http).close_handled = false;
        (*http).mem = 0 as *mut i8;
        (*http).len = 0;
        (*http).memlen = 0;
        (*http).error = NGHTTP2_NO_ERROR;
    }
}

/* called from http_setup_conn */
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_setup_conn(mut conn: *mut connectdata) {
    unsafe {
        (*conn).proto.httpc.settings.max_concurrent_streams = DEFAULT_MAX_CONCURRENT_STREAMS;
    }
}

/*
 * HTTP2 handler interface. This isn't added to the general list of protocols
 * but will be used at run-time when the protocol is dynamically switched from
 * HTTP to HTTP2.
 */
#[cfg(USE_NGHTTP2)]
static mut Curl_handler_http2: Curl_handler = Curl_handler {
    /* scheme */
    scheme: b"HTTP\0" as *const u8 as *const i8,
    /* setup_connection */
    setup_connection: None,
    /* do_it */
    do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
    /* done */
    done: Some(Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode),
    /* do_more */
    do_more: None,
    /* connect_it */
    connect_it: None,
    /* connecting */
    connecting: None,
    /* doing */
    doing: None,
    /* proto_getsock */
    proto_getsock: Some(
        http2_getsock
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32,
    ),
    /* doing_getsock */
    doing_getsock: Some(
        http2_getsock
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32,
    ),
    /* domore_getsock */
    domore_getsock: None,
    /* perform_getsock */
    perform_getsock: Some(
        http2_getsock
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32,
    ),
    /* disconnect */
    disconnect: Some(
        http2_disconnect
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
    ),
    /* readwrite */
    readwrite: None,
    /* connection_check */
    connection_check: Some(
        http2_conncheck as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, u32) -> u32,
    ),
    /* attach connection */
    attach: None,
    /* defport */
    defport: PORT_HTTP,
    /* protocol */
    protocol: CURLPROTO_HTTP,
    /* family */
    family: CURLPROTO_HTTP,
    /* flags */
    flags: PROTOPT_STREAM,
};

#[cfg(USE_NGHTTP2)]
static mut Curl_handler_http2_ssl: Curl_handler = Curl_handler {
    /* scheme */
    scheme: b"HTTPS\0" as *const u8 as *const i8,
    /* setup_connection */
    setup_connection: None,
    /* do_it */
    do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
    /* done */
    done: Some(Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode),
    /* do_more */
    do_more: None,
    /* connect_it */
    connect_it: None,
    /* connecting */
    connecting: None,
    /* doing */
    doing: None,
    /* proto_getsock */
    proto_getsock: Some(
        http2_getsock
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32,
    ),
    /* doing_getsock */
    doing_getsock: Some(
        http2_getsock
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32,
    ),
    /* domore_getsock */
    domore_getsock: None,
    /* perform_getsock */
    perform_getsock: Some(
        http2_getsock
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32,
    ),
    /* disconnect */
    disconnect: Some(
        http2_disconnect
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
    ),
    /* readwrite */
    readwrite: None,
    /* connection_check */
    connection_check: Some(
        http2_conncheck as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, u32) -> u32,
    ),
    /* attach connection */
    attach: None,
    /* defport */
    defport: PORT_HTTP,
    /* protocol */
    protocol: CURLPROTO_HTTPS,
    /* family */
    family: CURLPROTO_HTTP,
    /* flags */
    flags: PROTOPT_SSL | PROTOPT_STREAM,
};

/*
 * Store nghttp2 version info in this buffer.
 */
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

/*
 * The implementation of nghttp2_send_callback type. Here we write |data| with
 * size |length| to the network and return the number of bytes actually
 * written. See the documentation of nghttp2_send_callback for the details.
 */
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
            FIRSTSOCKET as i32,
            mem as *const libc::c_void,
            length,
            &mut result,
        );
        if result == CURLE_AGAIN {
            return NGHTTP2_ERR_WOULDBLOCK as ssize_t;
        }
        if written == -1 {
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

/*
 * push header access function. Only to be used from within the push callback
 */
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn curl_pushheader_bynum(h: *mut curl_pushheaders, num: size_t) -> *mut i8 {
    unsafe {
        /* Verify that we got a good easy handle in the push header struct, mostly to
        detect rubbish input fast(er). */
        if h.is_null() || !GOOD_EASY_HANDLE((*h).data) {
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

/*
 * push header access function. Only to be used from within the push callback
 */
#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn curl_pushheader_byname(h: *mut curl_pushheaders, header: *const i8) -> *mut i8 {
    unsafe {
        /* Verify that we got a good easy handle in the push header struct,
        mostly to detect rubbish input fast(er). Also empty header name
        is just a rubbish too. We have to allow ":" at the beginning of
        the header, but header == ":" must be rejected. If we have ':' in
        the middle of header, it could be matched in middle of the value,
        this is because we do prefix match.*/
        if h.is_null()
            || !(!((*h).data).is_null() && GOOD_EASY_HANDLE((*h).data))
            || header.is_null()
            || *header.offset(0) == 0
            || strcmp(header, b":\0" as *const u8 as *const i8) == 0
            || !(strchr(header.offset(1), ':' as i32)).is_null()
        {
            return 0 as *mut i8;
        } else {
            let stream: *mut HTTP = (*(*h).data).req.p.http;
            let len: size_t = strlen(header);
            let mut i: size_t = 0;
            i = 0 as size_t;
            while i < (*stream).push_headers_used {
                if strncmp(header, *((*stream).push_headers).offset(i as isize), len) == 0 {
                    /* sub-match, make sure that it is followed by a colon */
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

/*
 * This specific transfer on this connection has been "drained".
 */
#[cfg(USE_NGHTTP2)]
extern "C" fn drained_transfer(mut data: *mut Curl_easy, httpc: *mut http_conn) {
    unsafe {
        (*httpc).drain_total =
            ((*httpc).drain_total as u64).wrapping_sub((*data).state.drain) as size_t;
        (*data).state.drain = 0;
    }
}

/*
 * Mark this transfer to get "drained".
 */
#[cfg(USE_NGHTTP2)]
extern "C" fn drain_this(data: *mut Curl_easy, httpc: *mut http_conn) {
    unsafe {
        (*data).state.drain = (*data).state.drain.wrapping_add(1);
        (*httpc).drain_total = (*httpc).drain_total.wrapping_add(1);
    }
}

#[cfg(USE_NGHTTP2)]
extern "C" fn duphandle(data: *mut Curl_easy) -> *mut Curl_easy {
    unsafe {
        let mut second: *mut Curl_easy = curl_easy_duphandle(data);
        if !second.is_null() {
            /* setup the request struct */
            let http: *mut HTTP = Curl_ccalloc.expect("non-null function pointer")(
                1,
                ::std::mem::size_of::<HTTP>() as u64,
            ) as *mut HTTP;
            if http.is_null() {
                Curl_close(&mut second);
            } else {
                (*second).req.p.http = http;
                Curl_dyn_init(&mut (*http).header_recvbuf, DYN_H2_HEADERS);
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
        
        'fail: loop {
            if !v.is_null() {
                uc = curl_url_set(u, CURLUPART_SCHEME, v, 0 as libc::c_int as libc::c_uint);
                if uc as u64 != 0 {
                    rc = 1 as libc::c_int;
                    break 'fail;
                }
            }
            v = curl_pushheader_byname(hp, b":authority\0" as *const u8 as *const libc::c_char);
            if !v.is_null() {
                uc = curl_url_set(u, CURLUPART_HOST, v, 0 as libc::c_int as libc::c_uint);
                if uc as u64 != 0 {
                    rc = 2 as libc::c_int;
                    break 'fail;
                }
            }
            v = curl_pushheader_byname(hp, b":path\0" as *const u8 as *const libc::c_char);
            if !v.is_null() {
                uc = curl_url_set(u, CURLUPART_PATH, v, 0 as libc::c_int as libc::c_uint);
                if uc as u64 != 0 {
                    rc = 3 as libc::c_int;
                    break 'fail;
                }
            }
            uc = curl_url_get(u, CURLUPART_URL, &mut url, 0 as libc::c_int as libc::c_uint);
            if uc as u64 != 0 {
                rc = 4 as libc::c_int;
            }
            break 'fail;
        }

        curl_url_cleanup(u);
        if rc != 0 {
            return rc;
        }
        if ((*data).state).url_alloc() != 0 {
            Curl_cfree.expect("non-null function pointer")((*data).state.url as *mut libc::c_void);
        }
        let ref mut fresh10 = (*data).state;
        (*fresh10).set_url_alloc(1 as libc::c_int as bit);
        let ref mut fresh11 = (*data).state.url;
        *fresh11 = url;
        return 0 as libc::c_int;
    }
}

#[cfg(USE_NGHTTP2)]
extern "C" fn push_promise(
    data: *mut Curl_easy,
    conn: *mut connectdata,
    frame: *const nghttp2_push_promise,
) -> i32 {
    unsafe {
        let mut rv: i32 = 0; /* one of the CURL_PUSH_* defines */
        'fail: loop {
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
                /* clone the parent */
                let mut newhandle: *mut Curl_easy = duphandle(data);
                if newhandle.is_null() {
                    Curl_infof(
                        data,
                        b"failed to duplicate handle\0" as *const u8 as *const i8,
                    );
                    rv = CURL_PUSH_DENY; /* FAIL HARD */
                    break 'fail;
                }
                heads.data = data;
                heads.frame = frame;
                stream = (*data).req.p.http;
                if stream.is_null() {
                    Curl_failf(data, b"Internal NULL stream!\0" as *const u8 as *const i8);
                    Curl_close(&mut newhandle);
                    rv = CURL_PUSH_DENY;
                    break 'fail;
                }
                rv = set_transfer_url(newhandle, &mut heads);
                if rv != 0 {
                    Curl_close(&mut newhandle);
                    rv = CURL_PUSH_DENY;
                    break 'fail;
                }
                Curl_set_in_callback(data, 1 as i32 != 0);
                rv = ((*(*data).multi).push_cb).expect("non-null function pointer")(
                    data,
                    newhandle,
                    (*stream).push_headers_used,
                    &mut heads,
                    (*(*data).multi).push_userp,
                );
                Curl_set_in_callback(data, 0 as i32 != 0);
                /* free the headers again */
                i = 0;
                while i < (*stream).push_headers_used {
                    Curl_cfree.expect("non-null function pointer")(
                        *((*stream).push_headers).offset(i as isize) as *mut libc::c_void,
                    );
                    i = i.wrapping_add(1);
                }
                Curl_cfree.expect("non-null function pointer")(
                    (*stream).push_headers as *mut libc::c_void,
                );
                (*stream).push_headers = 0 as *mut *mut i8;
                (*stream).push_headers_used = 0;
                if rv != 0 {
                    /* denied, kill off the new handle again */
                    http2_stream_free((*newhandle).req.p.http);
                    (*newhandle).req.p.http = 0 as *mut HTTP;
                    Curl_close(&mut newhandle);
                    break 'fail;
                }

                newstream = (*newhandle).req.p.http;
                (*newstream).stream_id = (*frame).promised_stream_id;
                (*newhandle).req.maxdownload = -(1 as i32) as curl_off_t;
                (*newhandle).req.size = -(1 as i32) as curl_off_t;

                /* approved, add to the multi handle and immediately switch to PERFORM
                state with the given connection !*/
                rc = Curl_multi_add_perform((*data).multi, newhandle, conn);
                if rc as u64 != 0 {
                    Curl_infof(
                        data,
                        b"failed to add handle to multi\0" as *const u8 as *const i8,
                    );
                    http2_stream_free((*newhandle).req.p.http);
                    (*newhandle).req.p.http = 0 as *mut HTTP;
                    Curl_close(&mut newhandle);
                    rv = CURL_PUSH_DENY;
                    break 'fail;
                }

                httpc = &mut (*conn).proto.httpc;
                rv = nghttp2_session_set_stream_user_data(
                    (*httpc).h2,
                    (*frame).promised_stream_id,
                    newhandle as *mut libc::c_void,
                );

                if rv != 0 {
                    Curl_infof(
                        data,
                        b"failed to set user_data for stream %d\0" as *const u8 as *const i8,
                        (*frame).promised_stream_id,
                    );
                    rv = CURL_PUSH_DENY;
                    break 'fail;
                }
                Curl_dyn_init(&mut (*newstream).header_recvbuf, DYN_H2_HEADERS as size_t);
                Curl_dyn_init(&mut (*newstream).trailer_recvbuf, DYN_H2_TRAILERS as size_t);
            } else {
                rv = CURL_PUSH_DENY;
            }
            break 'fail;
        }
        return rv;
    }
}

/*
 * multi_connchanged() is called to tell that there is a connection in
 * this multi handle that has changed state (multiplexing become possible, the
 * number of allowed streams changed or similar), and a subsequent use of this
 * multi handle should move CONNECT_PEND handles back to CONNECT to have them
 * retry.
 */
#[cfg(USE_NGHTTP2)]
extern "C" fn multi_connchanged(mut multi: *mut Curl_multi) {
    unsafe {
        (*multi).recheckstate = true;
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
            /* stream ID zero is for connection-oriented stuff */
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
            NGHTTP2_DATA => {
                /* If body started on this stream, then receiving DATA is illegal. */
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
            NGHTTP2_HEADERS => {
                if !(*stream).bodystarted {
                    /* Only valid HEADERS after body started is trailer HEADERS.  We
                    buffer them in on_header callback. */
                    if (*stream).status_code == -1 {
                        return NGHTTP2_ERR_CALLBACK_FAILURE;
                    }
                    if (*stream).status_code / 100 != 1 {
                        (*stream).bodystarted = true;
                        (*stream).status_code = -1;
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
                    (*stream).nread_header_recvbuf =
                        ((*stream).nread_header_recvbuf as u64).wrapping_add(ncopy) as size_t;
                    (*stream).len = ((*stream).len as u64).wrapping_sub(ncopy) as size_t;
                    (*stream).memlen = ((*stream).memlen as u64).wrapping_add(ncopy) as size_t;
                    drain_this(data_s, httpc);
                    if get_transfer(httpc) != data_s {
                        Curl_expire(data_s, 0 as timediff_t, EXPIRE_RUN_NOW);
                    }
                }
            }
            NGHTTP2_PUSH_PROMISE => {
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

        /* get the stream from the hash based on Stream ID */
        data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
        if data_s.is_null() {
            /* Receiving a Stream ID not in the hash should not happen, this is an
            internal error more than anything else! */
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
            &mut *((*stream).mem).offset((*stream).memlen as isize) as *mut i8 as *mut libc::c_void,
            mem as *const libc::c_void,
            nread,
        );

        (*stream).len = ((*stream).len as u64).wrapping_sub(nread) as size_t as size_t;
        (*stream).memlen = ((*stream).memlen as u64).wrapping_add(nread) as size_t as size_t;

        drain_this(data_s, &mut (*conn).proto.httpc);

        /* if we receive data for another handle, wake that up */
        if get_transfer(httpc) != data_s {
            Curl_expire(data_s, 0 as timediff_t, EXPIRE_RUN_NOW);
        }

        if nread < len {
            (*stream).pausedata = mem.offset(nread as isize);
            (*stream).pauselen = len.wrapping_sub(nread);
            (*(*data_s).conn).proto.httpc.pause_stream_id = stream_id;

            return NGHTTP2_ERR_PAUSE;
        }

        /* pause execution of nghttp2 if we received data for another handle
        in order to process them first. */
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
            /* get the stream from the hash based on Stream ID, stream ID zero is for
            connection-oriented stuff */
            data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
            if data_s.is_null() {
                /* We could get stream ID not in the hash.  For example, if we
                decided to reject stream (e.g., PUSH_PROMISE). */
                return 0;
            }
            stream = (*data_s).req.p.http;
            if stream.is_null() {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }

            (*stream).closed = true;
            httpc = &mut (*conn).proto.httpc;
            drain_this(data_s, httpc);
            Curl_expire(data_s, 0 as timediff_t, EXPIRE_RUN_NOW);
            (*stream).error = error_code;

            /* remove the entry from the hash as the stream is now gone */
            rv = nghttp2_session_set_stream_user_data(session, stream_id, 0 as *mut libc::c_void);
            if rv != 0 {
                Curl_infof(
                    data_s,
                    b"http/2: failed to clear user_data for stream %d!\0" as *const u8 as *const i8,
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

        if (*frame).hd.type_0 != NGHTTP2_HEADERS {
            return 0;
        }

        stream = (*data_s).req.p.http;
        if stream.is_null() || !(*stream).bodystarted {
            return 0;
        }
        return 0;
    }
}

/* Decode HTTP status code.  Returns -1 if no valid status code was
decoded. */
#[cfg(USE_NGHTTP2)]
extern "C" fn decode_status_code(value: *const uint8_t, len: size_t) -> i32 {
    unsafe {
        let mut i: i32 = 0;
        let mut res: i32 = 0;

        if len != 3 {
            return -1;
        }

        res = 0;

        i = 0;
        while i < 3 {
            let c: i8 = *value.offset(i as isize) as i8;

            if (c as i32) < '0' as i32 || c as i32 > '9' as i32 {
                return -1;
            }

            res *= 10;
            res += c as i32 - '0' as i32;
            i += 1;
        }

        return res;
    }
}

/* frame->hd.type is either NGHTTP2_HEADERS or NGHTTP2_PUSH_PROMISE */
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

        /* get the stream from the hash based on Stream ID */
        data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
        if data_s.is_null() {
            /* Receiving a Stream ID not in the hash should not happen, this is an
            internal error more than anything else! */
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }

        stream = (*data_s).req.p.http;
        if stream.is_null() {
            Curl_failf(data_s, b"Internal NULL stream!\0" as *const u8 as *const i8);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }

        /* Store received PUSH_PROMISE headers to be used when the subsequent
        PUSH_PROMISE callback comes */
        if (*frame).hd.type_0 == NGHTTP2_PUSH_PROMISE {
            let mut h: *mut i8 = 0 as *mut i8;
            if strcmp(b":authority\0" as *const u8 as *const i8, name as *const i8) == 0 {
                /* pseudo headers are lower case */
                let mut rc: i32 = 0;
                let check: *mut i8 = curl_maprintf(
                    b"%s:%d\0" as *const u8 as *const i8,
                    (*conn).host.name,
                    (*conn).remote_port,
                );
                if check.is_null() {
                    /* no memory */
                    return NGHTTP2_ERR_CALLBACK_FAILURE;
                }
                if Curl_strcasecompare(check, value as *const i8) == 0
                    && ((*conn).remote_port != (*(*conn).given).defport
                        || Curl_strcasecompare((*conn).host.name, value as *const i8) == 0)
                {
                    nghttp2_submit_rst_stream(
                        session,
                        NGHTTP2_FLAG_NONE as uint8_t,
                        stream_id,
                        NGHTTP2_PROTOCOL_ERROR as uint32_t,
                    );
                    /* This is push is not for the same authority that was asked for in
                     * the URL. RFC 7540 section 8.2 says: "A client MUST treat a
                     * PUSH_PROMISE for which the server is not authoritative as a stream
                     * error of type PROTOCOL_ERROR."
                     */
                    rc = NGHTTP2_ERR_CALLBACK_FAILURE;
                }
                Curl_cfree.expect("non-null function pointer")(check as *mut libc::c_void);
                if rc != 0 {
                    return rc;
                }
            }

            if ((*stream).push_headers).is_null() {
                (*stream).push_headers_alloc = 10 as size_t;
                (*stream).push_headers = Curl_cmalloc.expect("non-null function pointer")(
                    ((*stream).push_headers_alloc)
                        .wrapping_mul(::std::mem::size_of::<*mut i8>() as u64),
                ) as *mut *mut i8;
                if ((*stream).push_headers).is_null() {
                    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                (*stream).push_headers_used = 0 as size_t;
            } else if (*stream).push_headers_used == (*stream).push_headers_alloc {
                let mut headp: *mut *mut i8 = 0 as *mut *mut i8;
                (*stream).push_headers_alloc = ((*stream).push_headers_alloc as u64)
                    .wrapping_mul(2 as u64) as size_t
                    as size_t;
                headp = Curl_saferealloc(
                    (*stream).push_headers as *mut libc::c_void,
                    ((*stream).push_headers_alloc)
                        .wrapping_mul(::std::mem::size_of::<*mut i8>() as u64),
                ) as *mut *mut i8;
                if headp.is_null() {
                    (*stream).push_headers = 0 as *mut *mut i8;
                    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                (*stream).push_headers = headp;
            }
            h = curl_maprintf(b"%s:%s\0" as *const u8 as *const i8, name, value);
            if !h.is_null() {
                let ref mut fresh25 = (*stream).push_headers_used;
                let fresh26 = *fresh25;
                *fresh25 = (*fresh25).wrapping_add(1);
                *((*stream).push_headers).offset(fresh26 as isize) = h;
            }
            return 0;
        }

        if (*stream).bodystarted {
            /* This is a trailer */
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

        if namelen == (::std::mem::size_of::<[i8; 8]>() as u64).wrapping_sub(1 as u64)
            && memcmp(
                b":status\0" as *const u8 as *const i8 as *const libc::c_void,
                name as *const libc::c_void,
                namelen,
            ) == 0
        {
            /* nghttp2 guarantees :status is received first and only once, and
            value is 3 digits status code, and decode_status_code always
            succeeds. */
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
            /* the space character after the status code is mandatory */
            result = Curl_dyn_add(
                &mut (*stream).header_recvbuf,
                b" \r\n\0" as *const u8 as *const i8,
            );
            if result as u64 != 0 {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            /* if we receive data for another handle, wake that up */
            if get_transfer(httpc) != data_s {
                Curl_expire(data_s, 0 as timediff_t, EXPIRE_RUN_NOW);
            }
            return 0;
        }

        /* nghttp2 guarantees that namelen > 0, and :status was already
        received, and this is not pseudo-header field . */
        /* convert to a HTTP1-style header */
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
        /* if we receive data for another handle, wake that up */
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
            /* get the stream from the hash based on Stream ID, stream ID zero is for
            connection-oriented stuff */
            data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
            if data_s.is_null() {
                /* Receiving a Stream ID not in the hash should not happen, this is an
                internal error more than anything else! */
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
        if nread > 0 {
            memcpy(
                buf as *mut libc::c_void,
                (*stream).upload_mem as *const libc::c_void,
                nread,
            );
            (*stream).upload_mem = (*stream).upload_mem.offset(nread as isize);
            (*stream).upload_len =
                ((*stream).upload_len as u64).wrapping_sub(nread) as size_t as size_t;
            if (*data_s).state.infilesize != -1 {
                (*stream).upload_left =
                    ((*stream).upload_left as u64).wrapping_sub(nread) as curl_off_t as curl_off_t;
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

const HTTP2_HUGE_WINDOW_SIZE: i32 = 32 * 1024 * 1024; /* 32 MB */
#[cfg(USE_NGHTTP2)]
extern "C" fn populate_settings(data: *mut Curl_easy, mut httpc: *mut http_conn) {
    unsafe {
        let iv: *mut nghttp2_settings_entry = ((*httpc).local_settings).as_mut_ptr();

        (*iv.offset(0 as isize)).settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS as i32;
        (*iv.offset(0 as isize)).value = Curl_multi_max_concurrent_streams((*data).multi);

        (*iv.offset(1 as isize)).settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE as i32;
        (*iv.offset(1 as isize)).value = HTTP2_HUGE_WINDOW_SIZE as uint32_t;

        (*iv.offset(2 as isize)).settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH as i32;
        (*iv.offset(2 as isize)).value = ((*(*data).multi).push_cb).is_some() as uint32_t;

        (*httpc).local_settings_num = 3;
    }
}

#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_done(data: *mut Curl_easy, premature: bool) {
    unsafe {
        let mut http: *mut HTTP = (*data).req.p.http;
        let mut httpc: *mut http_conn = &mut (*(*data).conn).proto.httpc;

        /* there might be allocated resources done before this got the 'h2' pointer
        setup */
        Curl_dyn_free(&mut (*http).header_recvbuf);
        Curl_dyn_free(&mut (*http).trailer_recvbuf);
        if !((*http).push_headers).is_null() {
            /* if they weren't used and then freed before */
            while (*http).push_headers_used > 0 as u64 {
                Curl_cfree.expect("non-null function pointer")(
                    *((*http).push_headers)
                        .offset(((*http).push_headers_used).wrapping_sub(1 as u64) as isize)
                        as *mut libc::c_void,
                );
                (*http).push_headers_used = (*http).push_headers_used.wrapping_sub(1);
            }
            Curl_cfree.expect("non-null function pointer")(
                (*http).push_headers as *mut libc::c_void,
            );
            (*http).push_headers = 0 as *mut *mut i8;
        }

        /* not HTTP/2 ? */
        if (*(*(*data).conn).handler).protocol & ((1) << 0 | (1) << 1) as u32 == 0
            || ((*httpc).h2).is_null()
        {
            return;
        }

        if premature {
            /* RST_STREAM */
            set_transfer(httpc, data); /* set the transfer */
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

        /* -1 means unassigned and 0 means cleared */
        if (*http).stream_id > 0 {
            let rv: i32 = nghttp2_session_set_stream_user_data(
                (*httpc).h2,
                (*http).stream_id,
                0 as *mut libc::c_void,
            );

            if rv != 0 {
                Curl_infof(
                    data,
                    b"http/2: failed to clear user_data for stream %d!\0" as *const u8 as *const i8,
                    (*http).stream_id,
                );
            }
            set_transfer(httpc, 0 as *mut Curl_easy);
            (*http).stream_id = 0;
        }
    }
}

/*
 * Initialize nghttp2 for a Curl connection
 */
#[cfg(USE_NGHTTP2)]
extern "C" fn http2_init(data: *mut Curl_easy, conn: *mut connectdata) -> CURLcode {
    unsafe {
        if ((*conn).proto.httpc.h2).is_null() {
            let mut rc: i32 = 0;
            let mut callbacks: *mut nghttp2_session_callbacks = 0 as *mut nghttp2_session_callbacks;

            (*conn).proto.httpc.inbuf =
                Curl_cmalloc.expect("non-null function pointer")(H2_BUFSIZE as size_t) as *mut i8;
            if ((*conn).proto.httpc.inbuf).is_null() {
                return CURLE_OUT_OF_MEMORY; /* most likely at least */
            }

            rc = nghttp2_session_callbacks_new(&mut callbacks);

            /* nghttp2_send_callback */
            if rc != 0 {
                Curl_failf(
                    data,
                    b"Couldn't initialize nghttp2 callbacks!\0" as *const u8 as *const i8,
                );
                return CURLE_OUT_OF_MEMORY;
            }
            /* nghttp2_on_frame_recv_callback */
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
            /* nghttp2_on_data_chunk_recv_callback */
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
            /* nghttp2_on_stream_close_callback */
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
            /* nghttp2_on_begin_headers_callback */
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
            /* nghttp2_on_header_callback */
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

            /* The nghttp2 session is not yet setup, do it */
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
                return CURLE_OUT_OF_MEMORY; /* most likely at least */
            }
        }
        return CURLE_OK;
    }
}

/*
 * Append headers to ask for a HTTP1.1 to HTTP2 upgrade.
 */
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

        /* this returns number of bytes it wrote */
        binlen = nghttp2_pack_settings_payload(
            binsettings,
            80 as size_t,
            ((*httpc).local_settings).as_mut_ptr(),
            (*httpc).local_settings_num,
        );

        if binlen <= 0 {
            Curl_failf(
                data,
                b"nghttp2 unexpectedly failed on pack_settings_payload\0" as *const u8 as *const i8,
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

        if result != 0 {
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

/*
 * Returns nonzero if current HTTP/2 session should be closed.
 */
#[cfg(USE_NGHTTP2)]
extern "C" fn should_close_session(httpc: *mut http_conn) -> i32 {
    unsafe {
        return ((*httpc).drain_total == 0
            && nghttp2_session_want_read((*httpc).h2) == 0
            && nghttp2_session_want_write((*httpc).h2) == 0) as i32;
    }
}

/*
 * h2_process_pending_input() processes pending input left in
 * httpc->inbuf.  Then, call h2_session_send() to send pending data.
 * This function returns 0 if it succeeds, or -1 and error code will
 * be assigned to *err.
 */
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

        set_transfer(httpc, data); /* set the transfer */
        rv = nghttp2_session_mem_recv((*httpc).h2, inbuf as *const uint8_t, nread as size_t);
        if rv < 0 {
            Curl_failf(
                data,
                b"h2_process_pending_input: nghttp2_session_mem_recv() returned %zd:%s\0"
                    as *const u8 as *const i8,
                rv,
                nghttp2_strerror(rv as i32),
            );
            *err = CURLE_RECV_ERROR;
            return -1;
        }

        if nread == rv {
            (*httpc).inbuflen = 0;
            (*httpc).nread_inbuf = 0;
        } else {
            (*httpc).nread_inbuf =
                ((*httpc).nread_inbuf as u64).wrapping_add(rv as u64) as size_t as size_t;
        }

        rv = h2_session_send(data, (*httpc).h2) as ssize_t;
        if rv != 0 {
            *err = CURLE_SEND_ERROR;
            return -1;
        }

        /* No more requests are allowed in the current session, so
        the connection may not be reused. This is set when a
        GOAWAY frame has been received or when the limit of stream
        identifiers has been reached. */
        if nghttp2_session_check_request_allowed((*httpc).h2) == 0 {
            Curl_conncontrol((*data).conn, 1);
        }

        if should_close_session(httpc) != 0 {
            let stream: *mut HTTP = (*data).req.p.http;
            if (*stream).error != 0 {
                *err = CURLE_HTTP2;
            } else {
                /* not an error per se, but should still close the connection */
                Curl_conncontrol((*data).conn, 1);
                *err = CURLE_OK;
            }
            return -1;
        }
        return 0;
    }
}

/*
 * Called from transfer.c:done_sending when we stop uploading.
 */
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
            /* make sure this is only attempted for HTTP/2 transfers */
            let mut stream: *mut HTTP = (*data).req.p.http;
            let httpc: *mut http_conn = &mut (*conn).proto.httpc;
            let h2: *mut nghttp2_session = (*httpc).h2;

            if (*stream).upload_left != 0 {
                /* If the stream still thinks there's data left to upload. */

                (*stream).upload_left = 0 as curl_off_t;

                /* resume sending here to trigger the callback to get called again so
                that it can signal EOF to nghttp2 */
                nghttp2_session_resume_data(h2, (*stream).stream_id);
                h2_process_pending_input(data, httpc, &mut result);
            }

            /* If nghttp2 still has pending frames unsent */
            if nghttp2_session_want_write(h2) != 0 {
                let mut k: *mut SingleRequest = &mut (*data).req;
                let mut rv: i32 = 0;

                /* and attempt to send the pending frames */
                rv = h2_session_send(data, h2);
                if rv != 0 {
                    result = CURLE_SEND_ERROR;
                }

                if nghttp2_session_want_write(h2) != 0 {
                    /* re-set KEEP_SEND to make sure we are called again */
                    (*k).keepon |= KEEP_SEND;
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

        /* Reset to FALSE to prevent infinite loop in readwrite_data function. */
        (*stream).closed = false;
        if (*stream).error == NGHTTP2_REFUSED_STREAM as u32 {
            Curl_conncontrol(conn, 1);
            (*data).state.set_refused_stream(1 as bit);
            *err = CURLE_RECV_ERROR; /* trigger Curl_retry_request() later */
            return -1;
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
                return -1;
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
            return -1;
        }

        if Curl_dyn_len(&mut (*stream).trailer_recvbuf) != 0 {
            let mut trailp: *mut i8 = Curl_dyn_ptr(&mut (*stream).trailer_recvbuf);
            let mut lf: *mut i8 = 0 as *mut i8;

            loop {
                let mut len: size_t = 0 as size_t;
                let mut result: CURLcode = CURLE_OK;
                /* each trailer line ends with a newline */
                lf = strchr(trailp, '\n' as i32);
                if lf.is_null() {
                    break;
                }
                len = lf.offset(1 as isize).offset_from(trailp) as i64 as size_t;

                Curl_debug(data, CURLINFO_HEADER_IN, trailp, len);
                /* pass the trailers one by one to the callback */
                result = Curl_client_write(data, (1) << 1, trailp, len);
                if result != 0 {
                    *err = result;
                    return -1;
                }
                lf = lf.offset(1);
                trailp = lf;
                if lf.is_null() {
                    break;
                }
            }
        }

        (*stream).close_handled = true;

        return 0 as ssize_t;
    }
}

/*
 * h2_pri_spec() fills in the pri_spec struct, used by nghttp2 to send weight
 * and dependency to the peer. It also stores the updated values in the state
 * struct.
 */
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
        (*data)
            .state
            .set_stream_depends_e(((*data).set).stream_depends_e());
        (*data).state.stream_depends_on = (*data).set.stream_depends_on;
    }
}

/*
 * h2_session_send() checks if there's been an update in the priority /
 * dependency settings and if so it submits a PRIORITY frame with the updated
 * info.
 */
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
            /* send new weight and/or dependency */
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
                /* already marked for closure, return OK and we're done */
                *err = CURLE_OK;
                return 0;
            }
            *err = CURLE_HTTP2;
            return -1;
        }

        /* Nullify here because we call nghttp2_session_send() and they
        might refer to the old buffer. */
        (*stream).upload_mem = 0 as *const uint8_t;
        (*stream).upload_len = 0 as size_t;

        /*
         * At this point 'stream' is just in the Curl_easy the connection
         * identifies as its owner at this time.
         */

        if (*stream).bodystarted as i32 != 0
            && (*stream).nread_header_recvbuf < Curl_dyn_len(&mut (*stream).header_recvbuf)
        {
            /* If there is header data pending for this stream to return, do that */
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

            (*stream).nread_header_recvbuf =
                ((*stream).nread_header_recvbuf as u64).wrapping_add(ncopy) as size_t;
            return ncopy as ssize_t;
        }

        if (*data).state.drain != 0 && (*stream).memlen != 0 {
            if mem != (*stream).mem {
                /* if we didn't get the same buffer this time, we must move the data to
                the beginning */
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
                /* We have paused nghttp2, but we have no pause data (see
                on_data_chunk_recv). */
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

            (*stream).pausedata = ((*stream).pausedata).offset(nread as isize);
            (*stream).pauselen = ((*stream).pauselen as u64).wrapping_sub(nread as u64) as size_t;

            if (*stream).pauselen == 0 as u64 {
                (*httpc).pause_stream_id = 0;

                (*stream).pausedata = 0 as *const uint8_t;
                (*stream).pauselen = 0 as size_t;

                /* When NGHTTP2_ERR_PAUSE is returned from
                data_source_read_callback, we might not process DATA frame
                fully.  Calling nghttp2_session_mem_recv() again will
                continue to process DATA frame, but if there is no incoming
                frames, then we have to call it again with 0-length data.
                Without this, on_stream_close callback will not be called,
                and stream could be hanged. */
                if h2_process_pending_input(data, httpc, err) != 0 {
                    return -(1) as ssize_t;
                }
            }
            return nread;
        } else {
            if (*httpc).pause_stream_id != 0 {
                /* If a stream paused nghttp2_session_mem_recv previously, and has
                not processed all data, it still refers to the buffer in
                nghttp2_session.  If we call nghttp2_session_mem_recv(), we may
                overwrite that buffer.  To avoid that situation, just return
                here with CURLE_AGAIN.  This could be busy loop since data in
                socket is not read.  But it seems that usually streams are
                notified with its drain property, and socket is read again
                quickly. */
                if (*stream).closed {
                    /* closed overrides paused */
                    return 0;
                }
                *err = CURLE_AGAIN;
                return -1;
            } else {
                /* remember where to store incoming data for this stream and how big the
                buffer is */
                (*stream).mem = mem;
                (*stream).len = len;
                (*stream).memlen = 0 as size_t;

                if (*httpc).inbuflen == 0 {
                    nread = ((*httpc).recv_underlying).expect("non-null function pointer")(
                        data,
                        FIRSTSOCKET as i32,
                        (*httpc).inbuf,
                        H2_BUFSIZE as size_t,
                        err,
                    );

                    if nread == -1 {
                        if *err != CURLE_AGAIN {
                            Curl_failf(
                                data,
                                b"Failed receiving HTTP2 data\0" as *const u8 as *const i8,
                            );
                        } else if (*stream).closed {
                            /* received when the stream was already closed! */
                            return http2_handle_stream_close(conn, data, stream, err);
                        }
                        return -1;
                    }

                    if nread == 0 {
                        if !(*stream).closed {
                            /* This will happen when the server or proxy server is SIGKILLed
                            during data transfer. We should emit an error since our data
                            received may be incomplete. */
                            Curl_failf(
                            data,
                            b"HTTP/2 stream %d was not closed cleanly before end of the underlying stream\0"
                                as *const u8 as *const i8,
                            (*stream).stream_id,
                        );
                            *err = CURLE_HTTP2_STREAM;
                            return -1;
                        }
                        *err = CURLE_OK;
                        return 0;
                    }

                    (*httpc).inbuflen = nread as size_t;
                } else {
                    nread = ((*httpc).inbuflen).wrapping_sub((*httpc).nread_inbuf) as ssize_t;
                }

                if h2_process_pending_input(data, httpc, err) != 0 {
                    return -1;
                }
            }
        }
        if (*stream).memlen != 0 {
            let retlen: ssize_t = (*stream).memlen as ssize_t;
            (*stream).memlen = 0 as size_t;
            if !((*httpc).pause_stream_id == (*stream).stream_id) {
                /* data for this stream is returned now, but this stream caused a pause
                already so we need it called again asap */
                if !(*stream).closed {
                    drained_transfer(data, httpc);
                } else {
                    /* this stream is closed, trigger a another read ASAP to detect that */
                    Curl_expire(data, 0 as timediff_t, EXPIRE_RUN_NOW);
                }
            }
            return retlen;
        }
        if (*stream).closed {
            return http2_handle_stream_close(conn, data, stream, err);
        }
        *err = CURLE_AGAIN;
        return -1;
    }
}

/*
 * Check header memory for the token "trailers".
 * Parse the tokens as separated by comma and surrounded by whitespace.
 * Returns TRUE if found or FALSE if not.
 */
#[cfg(USE_NGHTTP2)]
extern "C" fn contains_trailers(mut p: *const i8, len: size_t) -> bool {
    unsafe {
        let mut end: *const i8 = p.offset(len as isize);
        loop {
            while p != end && (*p as i32 == ' ' as i32 || *p as i32 == '\t' as i32) {
                p = p.offset(1);
            }
            if p == end
                || (end.offset_from(p) as size_t)
                    < (::std::mem::size_of::<[i8; 9]>() as u64).wrapping_sub(1 as u64)
            {
                return false;
            }
            if Curl_strncasecompare(
                b"trailers\0" as *const u8 as *const i8,
                p,
                (::std::mem::size_of::<[i8; 9]>() as u64).wrapping_sub(1 as u64),
            ) != 0
            {
                p = p.offset(
                    (::std::mem::size_of::<[i8; 9]>() as u64).wrapping_sub(1 as u64) as isize,
                );
                while p != end && (*p as i32 == ' ' as i32 || *p as i32 == '\t' as i32) {
                    p = p.offset(1);
                }
                if p == end || *p as i32 == ',' as i32 {
                    return 1 as i32 != 0;
                }
            }
            /* skip to next token */
            while p != end && *p as i32 != ',' as i32 {
                p = p.offset(1);
            }
            if p == end {
                return false;
            }
            p = p.offset(1);
        }
    }
}

/* Decides how to treat given header field. */
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
                if Curl_strncasecompare(b"te\0" as *const u8 as *const i8, name, namelen) == 0 {
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
unsafe extern "C" fn http2_send(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    /*
     * Currently, we send request in this function, but this function is also
     * used to send request body. It would be nice to add dedicated function for
     * request.
     */
    let mut rv: i32 = 0;
    let mut conn: *mut connectdata = (*data).conn;
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
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
    let mut h2: *mut nghttp2_session = (*httpc).h2;
    let mut pri_spec: nghttp2_priority_spec = nghttp2_priority_spec {
        stream_id: 0,
        weight: 0,
        exclusive: 0,
    };

    if (*stream).stream_id != -1 {
        if (*stream).close_handled {
            Curl_infof(
                data,
                b"stream %d closed\0" as *const u8 as *const i8,
                (*stream).stream_id,
            );
            *err = CURLE_HTTP2_STREAM;
            return -1;
        } else if (*stream).closed {
            return http2_handle_stream_close(conn, data, stream, err);
        }
        /* If stream_id != -1, we have dispatched request HEADERS, and now
        are going to send or sending request body in DATA frame */
        // let ref mut fresh45 = (*stream).upload_mem;
        (*stream).upload_mem = mem as *const uint8_t;
        (*stream).upload_len = len;
        rv = nghttp2_session_resume_data(h2, (*stream).stream_id);
        if nghttp2_is_fatal(rv) != 0 {
            *err = CURLE_SEND_ERROR;
            return -1;
        }
        rv = h2_session_send(data, h2);
        if nghttp2_is_fatal(rv) != 0 {
            *err = CURLE_SEND_ERROR;
            return -1;
        }
        len = (len as libc::c_ulong).wrapping_sub((*stream).upload_len) as size_t as size_t;

        /* Nullify here because we call nghttp2_session_send() and they
        might refer to the old buffer. */
        (*stream).upload_mem = 0 as *const uint8_t;
        (*stream).upload_len = 0 as i32 as size_t;

        if should_close_session(httpc) != 0 {
            *err = CURLE_HTTP2;
            return -1;
        }

        if (*stream).upload_left != 0 {
            /* we are sure that we have more data to send here.  Calling the
            following API will make nghttp2_session_want_write() return
            nonzero if remote window allows it, which then libcurl checks
            socket is writable or not.  See http2_perform_getsock(). */
            nghttp2_session_resume_data(h2, (*stream).stream_id);
        }

        return len as ssize_t;
    }

    /* Calculate number of headers contained in [mem, mem + len) */
    /* Here, we assume the curl http code generate *correct* HTTP header
    field block */
    nheader = 0;
    i = 1;
    while i < len {
        if *hdbuf.offset(i as isize) as i32 == '\n' as i32
            && *hdbuf.offset(i.wrapping_sub(1) as isize) as i32 == '\r' as i32
        {
            nheader = nheader.wrapping_add(1);
            i = i.wrapping_add(1);
        }
        i = i.wrapping_add(1);
    }
    'fail: loop {
        if nheader < 2 as i32 as libc::c_ulong {
            break 'fail;
        }

        /* We counted additional 2 \r\n in the first and last line. We need 3
        new headers: :method, :path and :scheme. Therefore we need one
        more space. */
        nheader = nheader.wrapping_add(1);
        nva = Curl_cmalloc.expect("non-null function pointer")(
            (::std::mem::size_of::<nghttp2_nv>() as libc::c_ulong).wrapping_mul(nheader),
        ) as *mut nghttp2_nv;
        if nva.is_null() {
            *err = CURLE_OUT_OF_MEMORY;
            return -1;
        }

        /* Extract :method, :path from request line
        We do line endings with CRLF so checking for CR is enough */
        line_end = memchr(hdbuf as *const libc::c_void, '\r' as i32, len) as *mut i8;
        if line_end.is_null() {
            break 'fail;
        }

        /* Method does not contain spaces */
        end = memchr(
            hdbuf as *const libc::c_void,
            ' ' as i32,
            line_end.offset_from(hdbuf) as i64 as libc::c_ulong,
        ) as *mut i8;
        if end.is_null() || end == hdbuf {
            break 'fail;
        }
        (*nva.offset(0)).name = b":method\0" as *const u8 as *const i8 as *mut u8;
        (*nva.offset(0)).namelen = strlen((*nva.offset(0)).name as *mut i8);
        (*nva.offset(0)).value = hdbuf as *mut u8;
        (*nva.offset(0)).valuelen = end.offset_from(hdbuf) as i64 as size_t;
        (*nva.offset(0)).flags = NGHTTP2_NV_FLAG_NONE as uint8_t;
        if (*nva.offset(0 as i32 as isize)).namelen > 0xffff as i32 as libc::c_ulong
            || (*nva.offset(0 as i32 as isize)).valuelen
                > (0xffff as i32 as libc::c_ulong)
                    .wrapping_sub((*nva.offset(0 as i32 as isize)).namelen)
        {
            Curl_failf(
                data,
                b"Failed sending HTTP request: Header overflow\0" as *const u8 as *const i8,
            );
            break 'fail;
        }

        hdbuf = end.offset(1);

        /* Path may contain spaces so scan backwards */
        end = 0 as *mut i8;
        i = line_end.offset_from(hdbuf) as size_t;
        while i != 0 {
            if *hdbuf.offset(i.wrapping_sub(1 as i32 as libc::c_ulong) as isize) as i32
                == ' ' as i32
            {
                end = &mut *hdbuf.offset(i.wrapping_sub(1 as i32 as libc::c_ulong) as isize)
                    as *mut i8;
                break;
            } else {
                i = i.wrapping_sub(1);
            }
        }
        if end.is_null() || end == hdbuf {
            break 'fail;
        }
        (*nva.offset(1)).name = b":path\0" as *const u8 as *const i8 as *mut u8;
        (*nva.offset(1)).namelen = strlen((*nva.offset(1)).name as *mut i8);
        (*nva.offset(1)).value = hdbuf as *mut u8;
        (*nva.offset(1)).valuelen = end.offset_from(hdbuf) as i64 as size_t;
        (*nva.offset(1)).flags = NGHTTP2_NV_FLAG_NONE as i32 as uint8_t;
        if (*nva.offset(1)).namelen > 0xffff as i32 as libc::c_ulong
            || (*nva.offset(1)).valuelen
                > (0xffff as i32 as libc::c_ulong)
                    .wrapping_sub((*nva.offset(1 as i32 as isize)).namelen)
        {
            Curl_failf(
                data,
                b"Failed sending HTTP request: Header overflow\0" as *const u8 as *const i8,
            );
            break 'fail;
        }

        (*nva.offset(2)).name = b":scheme\0" as *const u8 as *const i8 as *mut u8;
        (*nva.offset(2)).namelen = strlen((*nva.offset(2)).name as *mut i8);
        if (*(*conn).handler).flags & ((1 as i32) << 0 as i32) as u32 != 0 {
            (*nva.offset(2)).value = b"https\0" as *const u8 as *const i8 as *mut u8;
        } else {
            (*nva.offset(2)).value = b"http\0" as *const u8 as *const i8 as *mut u8;
        }
        (*nva.offset(2)).valuelen = strlen((*nva.offset(2)).value as *mut i8);
        (*nva.offset(2)).flags = NGHTTP2_NV_FLAG_NONE as i32 as uint8_t;
        if (*nva.offset(2)).namelen > 0xffff as i32 as libc::c_ulong
            || (*nva.offset(2)).valuelen
                > (0xffff as i32 as libc::c_ulong).wrapping_sub((*nva.offset(2)).namelen)
        {
            Curl_failf(
                data,
                b"Failed sending HTTP request: Header overflow\0" as *const u8 as *const i8,
            );
            break 'fail;
        }

        authority_idx = 0;
        i = 3;
        while i < nheader {
            let mut hlen: size_t = 0;

            hdbuf = line_end.offset(2);

            /* check for next CR, but only within the piece of data left in the given
            buffer */
            line_end = memchr(
                hdbuf as *const libc::c_void,
                '\r' as i32,
                len.wrapping_sub(hdbuf.offset_from(mem as *mut i8) as i64 as libc::c_ulong),
            ) as *mut i8;

            /* header continuation lines are not supported */
            if line_end.is_null() || line_end == hdbuf {
                break 'fail;
            }
            if *hdbuf as i32 == ' ' as i32 || *hdbuf as i32 == '\t' as i32 {
                // curl_mprintf(b"hanxj\n\0" as *const u8 as *const i8);
                break 'fail;
            }

            end = hdbuf;
            while end < line_end && *end as i32 != ':' as i32 {
                end = end.offset(1);
            }
            if end == hdbuf || end == line_end {
                break 'fail;
            }
            hlen = end.offset_from(hdbuf) as size_t;

            if hlen == 4 && Curl_strncasecompare(b"host\0" as *const u8 as *const i8, hdbuf, 4) != 0
            {
                authority_idx = i;
                (*nva.offset(i as isize)).name =
                    b":authority\0" as *const u8 as *const i8 as *mut u8;
                (*nva.offset(i as isize)).namelen =
                    strlen((*nva.offset(i as isize)).name as *mut i8);
            } else {
                (*nva.offset(i as isize)).namelen = end.offset_from(hdbuf) as size_t;
                /* Lower case the header name for HTTP/2 */
                Curl_strntolower(hdbuf, hdbuf, (*nva.offset(i as isize)).namelen);
                (*nva.offset(i as isize)).name = hdbuf as *mut u8;
            }
            hdbuf = end.offset(1);
            while *hdbuf as i32 == ' ' as i32 || *hdbuf as i32 == '\t' as i32 {
                hdbuf = hdbuf.offset(1);
            }
            end = line_end;

            const HEADERINST_IGNORE: u32 = 1;
            const HEADERINST_TE_TRAILERS: u32 = 2;
            match inspect_header(
                (*nva.offset(i as isize)).name as *const i8,
                (*nva.offset(i as isize)).namelen,
                hdbuf,
                end.offset_from(hdbuf) as size_t,
            ) as u32
            {
                HEADERINST_IGNORE => {
                    nheader = nheader.wrapping_sub(1);
                    continue;
                }
                HEADERINST_TE_TRAILERS => {
                    (*nva.offset(i as isize)).value =
                        b"trailers\0" as *const u8 as *const i8 as *mut uint8_t;
                    (*nva.offset(i as isize)).valuelen =
                        (::std::mem::size_of::<[i8; 9]>() as libc::c_ulong).wrapping_sub(1);
                }
                _ => {
                    (*nva.offset(i as isize)).value = hdbuf as *mut u8;
                    (*nva.offset(i as isize)).valuelen = end.offset_from(hdbuf) as size_t;
                }
            }

            (*nva.offset(i as isize)).flags = NGHTTP2_NV_FLAG_NONE as i32 as uint8_t;
            if (*nva.offset(i as isize)).namelen > 0xffff as i32 as libc::c_ulong
                || (*nva.offset(i as isize)).valuelen
                    > (0xffff as i32 as libc::c_ulong)
                        .wrapping_sub((*nva.offset(i as isize)).namelen)
            {
                Curl_failf(
                    data,
                    b"Failed sending HTTP request: Header overflow\0" as *const u8 as *const i8,
                );
                break 'fail;
            }
            i = i.wrapping_add(1);
        }

        /* :authority must come before non-pseudo header fields */
        if authority_idx != 0 && authority_idx != AUTHORITY_DST_IDX {
            let mut authority: nghttp2_nv = *nva.offset(authority_idx as isize);
            i = authority_idx;
            while i > AUTHORITY_DST_IDX {
                *nva.offset(i as isize) = *nva.offset(i.wrapping_sub(1) as isize);
                i = i.wrapping_sub(1);
            }
            *nva.offset(i as isize) = authority;
        }

        /* Warn stream may be rejected if cumulative length of headers is too large.
        It appears nghttp2 will not send a header frame larger than 64KB. */
        const MAX_ACC: libc::c_ulong = 60000;
        let mut acc: size_t = 0;

        i = 0;
        while i < nheader {
            acc = (acc as libc::c_ulong).wrapping_add(
                ((*nva.offset(i as isize)).namelen)
                    .wrapping_add((*nva.offset(i as isize)).valuelen),
            ) as size_t as size_t;
            i = i.wrapping_add(1);
        }

        if acc > MAX_ACC {
            Curl_infof(
                data,
                b"http2_send: Warning: The cumulative length of all headers exceeds %d bytes and that could cause the stream to be rejected.\0"
                    as *const u8 as *const i8,
                MAX_ACC,
            );
        }

        h2_pri_spec(data, &mut pri_spec);

        match (*data).state.httpreq as u32 {
            HTTPREQ_POST | HTTPREQ_POST_FORM | HTTPREQ_POST_MIME | HTTPREQ_PUT => {
                if (*data).state.infilesize != -1 {
                    (*stream).upload_left = (*data).state.infilesize;
                } else {
                    /* data sending without specifying the data amount up front */
                    (*stream).upload_left = -1; /* unknown, but not zero */
                }
                data_prd.read_callback = Some(
                    data_source_read_callback
                        as unsafe extern "C" fn(
                            *mut nghttp2_session,
                            int32_t,
                            *mut uint8_t,
                            size_t,
                            *mut uint32_t,
                            *mut nghttp2_data_source,
                            *mut libc::c_void,
                        ) -> ssize_t,
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

        Curl_cfree.expect("non-null function pointer")(nva as *mut libc::c_void);
        nva = 0 as *mut nghttp2_nv;

        if stream_id < 0 {
            *err = CURLE_SEND_ERROR;
            return -1;
        }

        Curl_infof(
            data,
            b"Using Stream ID: %x (easy handle %p)\0" as *const u8 as *const i8,
            stream_id,
            data as *mut libc::c_void,
        );
        (*stream).stream_id = stream_id;

        rv = h2_session_send(data, h2);
        if rv != 0 {
            *err = CURLE_SEND_ERROR;
            return -1;
        }

        if should_close_session(httpc) != 0 {
            *err = CURLE_HTTP2;
            return -1;
        }

        /* If whole HEADERS frame was sent off to the underlying socket, the nghttp2
        library calls data_source_read_callback. But only it found that no data
        available, so it deferred the DATA transmission. Which means that
        nghttp2_session_want_write() returns 0 on http2_perform_getsock(), which
        results that no writable socket check is performed. To workaround this,
        we issue nghttp2_session_resume_data() here to bring back DATA
        transmission from deferred state. */
        nghttp2_session_resume_data(h2, (*stream).stream_id);
        return len as ssize_t;
    }

    Curl_cfree.expect("non-null function pointer")(nva as *mut libc::c_void);
    *err = CURLE_SEND_ERROR;
    return -1;
}

#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_setup(data: *mut Curl_easy, mut conn: *mut connectdata) -> CURLcode {
    unsafe {
        let mut result: CURLcode = CURLE_OK;
        let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
        let mut stream: *mut HTTP = (*data).req.p.http;

        (*stream).stream_id = -1;

        Curl_dyn_init(&mut (*stream).header_recvbuf, (128 * 1024) as size_t);
        Curl_dyn_init(&mut (*stream).trailer_recvbuf, (128 * 1024) as size_t);

        (*stream).upload_left = 0 as curl_off_t;
        (*stream).upload_mem = 0 as *const uint8_t;
        (*stream).upload_len = 0 as size_t;
        (*stream).mem = (*data).state.buffer;
        (*stream).len = (*data).set.buffer_size as size_t;

        multi_connchanged((*data).multi);
        /* below this point only connection related inits are done, which only needs
        to be done once per connection */

        if (*conn).handler == &Curl_handler_http2_ssl as *const Curl_handler
            || (*conn).handler == &Curl_handler_http2 as *const Curl_handler
        {
            return CURLE_OK; /* already done */
        }

        if (*(*conn).handler).flags & ((1) << 0) as u32 != 0 {
            (*conn).handler = &Curl_handler_http2_ssl;
        } else {
            (*conn).handler = &Curl_handler_http2;
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
        ((*conn).bits).set_multiplex(1 as bit);
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
        if result != 0 {
            return result;
        }

        (*httpc).recv_underlying = (*conn).recv[FIRSTSOCKET];
        (*httpc).send_underlying = (*conn).send[FIRSTSOCKET];
        (*conn).recv[FIRSTSOCKET] = Some(
            http2_recv
                as extern "C" fn(*mut Curl_easy, i32, *mut i8, size_t, *mut CURLcode) -> ssize_t,
        );
        (*conn).send[FIRSTSOCKET] = Some(
            http2_send
                as unsafe extern "C" fn(
                    *mut Curl_easy,
                    i32,
                    *const libc::c_void,
                    size_t,
                    *mut CURLcode,
                ) -> ssize_t,
        );

        if (*data).req.upgr101 == UPGR101_RECEIVED {
            /* stream 1 is opened implicitly on upgrade */
            (*stream).stream_id = 1;
            /* queue SETTINGS frame (again) */
            rv = nghttp2_session_upgrade2(
                (*httpc).h2,
                ((*httpc).binsettings).as_mut_ptr(),
                (*httpc).binlen,
                ((*data).state.httpreq == HTTPREQ_HEAD) as i32,
                0 as *mut libc::c_void,
            );

            if rv != 0 {
                Curl_failf(
                    data,
                    b"nghttp2_session_upgrade2() failed: %s(%d)\0" as *const u8 as *const i8,
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
                    b"http/2: failed to set user_data for stream %d!\0" as *const u8 as *const i8,
                    (*stream).stream_id,
                );
            }
        } else {
            populate_settings(data, httpc);

            /* stream ID is unknown at this point */
            (*stream).stream_id = -1;
            rv = nghttp2_submit_settings(
                (*httpc).h2,
                NGHTTP2_FLAG_NONE as uint8_t,
                ((*httpc).local_settings).as_mut_ptr(),
                (*httpc).local_settings_num,
            );
            if rv != 0 {
                Curl_failf(
                    data,
                    b"nghttp2_submit_settings() failed: %s(%d)\0" as *const u8 as *const i8,
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

        /* we are going to copy mem to httpc->inbuf.  This is required since
        mem is part of buffer pointed by stream->mem, and callbacks
        called by nghttp2_session_mem_recv() will write stream specific
        data into stream->mem, overwriting data already there. */
        if H2_BUFSIZE < nread {
            Curl_failf(
            data,
            b"connection buffer size is too small to store data following HTTP Upgrade response header: buflen=%d, datalen=%zu\0"
                as *const u8 as *const i8,
                H2_BUFSIZE ,
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

        if -1 == h2_process_pending_input(data, httpc, &mut result) {
            return CURLE_HTTP2;
        }

        return CURLE_OK;
    }
}

#[cfg(USE_NGHTTP2)]
#[no_mangle]
pub extern "C" fn Curl_http2_stream_pause(data: *mut Curl_easy, pause: bool) -> CURLcode {
    unsafe {
        if (*(*(*data).conn).handler).protocol & PROTO_FAMILY_HTTP == 0
            || ((*(*data).conn).proto.httpc.h2).is_null()
        {
            return CURLE_OK;
        } else {
            match () {
                #[cfg(NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE)]
                _ => {
                    let stream: *mut HTTP = (*data).req.p.http;
                    let httpc: *mut http_conn = &mut (*(*data).conn).proto.httpc;
                    let window: uint32_t = (!pause as i32 * HTTP2_HUGE_WINDOW_SIZE) as uint32_t;
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
            (*dep).data = child;

            if !((*parent).set.stream_dependents).is_null() && exclusive as i32 != 0 {
                let mut node: *mut Curl_http2_dep = (*parent).set.stream_dependents;
                while !node.is_null() {
                    (*(*node).data).set.stream_depends_on = child;
                    node = (*node).next;
                }
                tail = &mut (*child).set.stream_dependents;
                while !(*tail).is_null() {
                    tail = &mut (**tail).next;
                }
                *tail = (*parent).set.stream_dependents;
                (*parent).set.stream_dependents = 0 as *mut Curl_http2_dep;
            }

            tail = &mut (*parent).set.stream_dependents;
            while !(*tail).is_null() {
                (*(**tail).data).set.set_stream_depends_e(0 as bit);
                tail = &mut (**tail).next;
            }
            *tail = dep;
        }

        (*child).set.stream_depends_on = parent;
        (*child).set.set_stream_depends_e(exclusive as bit);
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
                (*last).next = (*data).next;
            } else {
                (*parent).set.stream_dependents = (*data).next;
            }
            Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
        }

        (*child).set.stream_depends_on = 0 as *mut Curl_easy;
        (*child).set.set_stream_depends_e(0 as bit);
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
                Curl_http2_add_child((*data).set.stream_depends_on, tmp, false);
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
        return (*stream).error == NGHTTP2_HTTP_1_1_REQUIRED;
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
pub extern "C" fn curl_pushheader_bynum(mut h: *mut curl_pushheaders, mut num: size_t) -> *mut i8 {
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
