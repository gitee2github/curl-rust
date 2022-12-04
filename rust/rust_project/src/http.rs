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
 * Description: http
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

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
#[cfg(USE_SSL)]
#[no_mangle]
pub static mut Curl_handler_https: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTPS\0" as *const u8 as *const libc::c_char,
            setup_connection: Some(
                http_setup_conn
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                Curl_http_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                Curl_http_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: Some(
                https_connecting
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            doing: None,
            proto_getsock: Some(
                https_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
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
            defport: 443 as libc::c_int,
            protocol: ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint,
            family: ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint,
            flags: ((1 as libc::c_int) << 0 as libc::c_int
                | (1 as libc::c_int) << 7 as libc::c_int
                | (1 as libc::c_int) << 8 as libc::c_int
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
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if ((*data).req.p.http).is_null() {} else {
        __assert_fail(
            b"data->req.p.http == ((void*)0)\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            179 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 67],
                &[libc::c_char; 67],
            >(b"CURLcode http_setup_conn(struct Curl_easy *, struct connectdata *)\0"))
                .as_ptr(),
        );
    }
    #[cfg(not(CURLDEBUG))]
    let mut new_http: *mut HTTP = Curl_ccalloc.expect("non-null function pointer")(
        1 as libc::c_int as size_t,
        ::std::mem::size_of::<HTTP>() as libc::c_ulong,
    ) as *mut HTTP;
    #[cfg(CURLDEBUG)]
    let mut new_http: *mut HTTP = curl_dbg_calloc(
        1 as libc::c_int as size_t,
        ::std::mem::size_of::<HTTP>() as libc::c_ulong,
        181 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    ) as *mut HTTP;
    http = new_http;
    if http.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    #[cfg(any(all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)), not(CURL_DISABLE_SMTP), not(CURL_DISABLE_IMAP)))]
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
#[cfg(not(CURL_DISABLE_PROXY))]
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
#[cfg(CURL_DISABLE_PROXY)]
#[no_mangle]
pub unsafe extern "C" fn Curl_checkProxyheaders(
    mut data: *mut Curl_easy,
    mut conn: *const connectdata,
    mut thisheader: *const libc::c_char,
) -> *mut libc::c_char {
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
    len = (end.offset_from(start) as libc::c_long + 1 as libc::c_int as libc::c_long)
        as size_t;
    #[cfg(not(CURLDEBUG))]
    let mut new_value: *mut libc::c_char = Curl_cmalloc.expect("non-null function pointer")(
        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) as *mut libc::c_char;
    #[cfg(CURLDEBUG)]
    let mut new_value: *mut libc::c_char = curl_dbg_malloc(
        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
        282 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    ) as *mut libc::c_char;
    value = new_value;
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
#[cfg(not(CURL_DISABLE_HTTP_AUTH))]
unsafe extern "C" fn http_output_basic(mut data: *mut Curl_easy, mut proxy: bool) -> CURLcode {
    let mut size: size_t = 0 as libc::c_int as size_t;
    let mut authorization: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut userp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut user: *const libc::c_char = 0 as *const libc::c_char;
    let mut pwd: *const libc::c_char = 0 as *const libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    if proxy {
        match () {
            #[cfg(not(CURL_DISABLE_PROXY))]
            _ => {
        userp = &mut (*data).state.aptr.proxyuserpwd;
        user = (*data).state.aptr.proxyuser;
        pwd = (*data).state.aptr.proxypasswd;
            }
            #[cfg(CURL_DISABLE_PROXY)]
            _ => {
                return CURLE_NOT_BUILT_IN;
            }
        }
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
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                *userp as *mut libc::c_void,
                339 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            *userp = curl_maprintf(
                b"%sAuthorization: Basic %s\r\n\0" as *const u8 as *const libc::c_char,
                if proxy as libc::c_int != 0 {
                    b"Proxy-\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                authorization,
            );
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(authorization as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                authorization as *mut libc::c_void,
                343 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            if (*userp).is_null() {
                result = CURLE_OUT_OF_MEMORY;
            }
        }
    }
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        out as *mut libc::c_void,
        350 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    return result;
}
#[cfg(not(CURL_DISABLE_HTTP_AUTH))]
unsafe extern "C" fn http_output_bearer(mut data: *mut Curl_easy) -> CURLcode {
    let mut userp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    userp = &mut (*data).state.aptr.userpwd;
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        *userp as *mut libc::c_void,
        366 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
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
    // todo 解决clippy错误，代码通过测试后就可以删掉注释
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
        match () {
            #[cfg(USE_NTLM)]
            _ => {
        if (*data).state.authproxy.picked
            == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
            || (*data).state.authhost.picked
                == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
            || (*data).state.authproxy.picked
                == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int
            || (*data).state.authhost.picked
                == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int
        {
            if expectsend - bytessent < 2000 as libc::c_int as libc::c_long
                || (*conn).http_ntlm_state as libc::c_uint
                    != NTLMSTATE_NONE as libc::c_int as libc::c_uint
                || (*conn).proxy_ntlm_state as libc::c_uint
                    != NTLMSTATE_NONE as libc::c_int as libc::c_uint
            {
                if ((*conn).bits).authneg() == 0
                    && (*conn).writesockfd != -(1 as libc::c_int)
                {
                    let ref mut fresh2 = (*conn).bits;
                    (*fresh2).set_rewindaftersend(1 as libc::c_int as bit);
                    Curl_infof(
                        data,
                        b"Rewind stream after send\0" as *const u8 as *const libc::c_char,
                    );
                }
                return CURLE_OK;
            }
            if ((*conn).bits).close() != 0 {
                return CURLE_OK;
            }
            Curl_infof(
                data,
                b"NTLM send, close instead of sending %ld bytes\0" as *const u8
                    as *const libc::c_char,
                expectsend - bytessent,
            );
        }
        }
            #[cfg(not(USE_NTLM))]
            _ => { }
        }
        // TODO 待测试
        match () {
            #[cfg(USE_SPNEGO)]
            _ => {
                if (*data).state.authproxy.picked
                    == (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int
                    || (*data).state.authhost.picked
                        == (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int
                {
                    if expectsend - bytessent < 2000 as libc::c_int as libc::c_long
                        || (*conn).http_negotiate_state as libc::c_uint
                            != GSS_AUTHNONE as libc::c_int as libc::c_uint
                        || (*conn).proxy_negotiate_state as libc::c_uint
                            != GSS_AUTHNONE as libc::c_int as libc::c_uint
                    {
                        if ((*conn).bits).authneg() == 0
                            && (*conn).writesockfd != -(1 as libc::c_int)
                        {
                            let ref mut fresh2 = (*conn).bits;
                            (*fresh2).set_rewindaftersend(1 as libc::c_int as bit);
                            Curl_infof(
                                data,
                                b"Rewind stream after send\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        return CURLE_OK;
                    }
                    if ((*conn).bits).close() != 0 {
                        return CURLE_OK;
                    }
                    Curl_infof(
                        data,
                        b"NEGOTIATE send, close instead of sending %ld bytes\0" as *const u8
                            as *const libc::c_char,
                        expectsend - bytessent,
                    );
                }
            }
            #[cfg(not(USE_SPNEGO))]
            _ => { }
        }
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 2 as libc::c_int);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            2 as libc::c_int,
            b"Mid-auth HTTP and much data left to send\0" as *const u8
                as *const libc::c_char,
        );
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
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as libc::c_int);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as libc::c_int,
                b"Force HTTP/1.1 connection\0" as *const u8 as *const libc::c_char,
            );
            (*data)
                .state
                .httpwant = CURL_HTTP_VERSION_1_1 as libc::c_int as libc::c_uchar;
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
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
        match (){
            #[cfg(not(CURLDEBUG))]
            _ => {
                Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
                (*data).req.newurl = 0 as *mut libc::c_char;
                (*data).req.newurl = Curl_cstrdup.expect("non-null function pointer")((*data).state.url);
            }
            #[cfg(CURLDEBUG)]
            _ => {
        curl_dbg_free(
            (*data).req.newurl as *mut libc::c_void,
            626 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
                (*data).req.newurl = 0 as *mut libc::c_char;
                (*data).req.newurl = curl_dbg_strdup(
            (*data).state.url,
            627 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
            }
        }       
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
            #[cfg(not(CURLDEBUG))]
            let new_url: *mut i8 = Curl_cstrdup.expect("non-null function pointer")((*data).state.url);
            #[cfg(CURLDEBUG)]
            let new_url: *mut i8 = curl_dbg_strdup(
                (*data).state.url,
                640 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            (*data).req.newurl = new_url;
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
#[cfg(not(CURL_DISABLE_HTTP_AUTH))]
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
    let flag1: bool = if cfg!(not(CURL_DISABLE_CRYPTO_AUTH)) { (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 7 as libc::c_int } else { false }; 
    let flag2: bool = if cfg!(USE_SPNEGO) { (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int } else { false };
    let flag3: bool = if cfg!(USE_NTLM) { (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int } else { false };
    let flag4: bool = if cfg!(all(USE_NTLM, NTLM_WB_ENABLED)) { (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int } else { false };
    let flag5: bool = if cfg!(not(CURL_DISABLE_CRYPTO_AUTH)) { (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int } else { false };
    if flag1 {
        auth = b"AWS_SIGV4\0" as *const u8 as *const libc::c_char;
        result = Curl_output_aws_sigv4(data, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if flag2 {
        auth = b"Negotiate\0" as *const u8 as *const libc::c_char;
        result = Curl_output_negotiate(data, conn, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if flag3 {
        auth = b"NTLM\0" as *const u8 as *const libc::c_char;
        result = Curl_output_ntlm(data, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if flag4 {
        auth = b"NTLM_WB\0" as *const u8 as *const libc::c_char;
        result = Curl_output_ntlm_wb(data, conn, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if flag5 {
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
        #[cfg(not(CURL_DISABLE_PROXY))]
        let flag6: bool = proxy as libc::c_int != 0
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
                    .is_null();
        #[cfg(CURL_DISABLE_PROXY)]
        let flag6: bool = !proxy
            && ((*conn).bits).user_passwd() as libc::c_int != 0
            && (Curl_checkheaders(data, b"Authorization\0" as *const u8 as *const libc::c_char))
                .is_null();
        if flag6
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
        #[cfg(not(CURL_DISABLE_PROXY))]
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
        #[cfg(CURL_DISABLE_PROXY)]
        Curl_infof(
            data,
            b"Server auth using %s with user '%s'\0" as *const u8 as *const libc::c_char,
            auth,
            if !((*data).state.aptr.user).is_null() {
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
#[cfg(not(CURL_DISABLE_HTTP_AUTH))]
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
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !data.is_null() {} else {
        __assert_fail(
            b"data\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            805 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 122],
                &[libc::c_char; 122],
            >(
                b"CURLcode Curl_http_output_auth(struct Curl_easy *, struct connectdata *, const char *, Curl_HttpReq, const char *, _Bool)\0",
            ))
                .as_ptr(),
        );
    }
    authhost = &mut (*data).state.authhost;
    authproxy = &mut (*data).state.authproxy;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag1: bool = ((*conn).bits).httpproxy() as libc::c_int != 0
        && ((*conn).bits).proxy_user_passwd() as libc::c_int != 0
        || ((*conn).bits).user_passwd() as libc::c_int != 0
        || !((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null();
    #[cfg(CURL_DISABLE_PROXY)]
    let flag1: bool = ((*conn).bits).user_passwd() as libc::c_int != 0
        || !((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null();
    if flag1 {
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
    match () {
        #[cfg(not(CURL_DISABLE_PROXY))]
        _ => {
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
        }
        #[cfg(CURL_DISABLE_PROXY)]
        _ => {
            (*authproxy).set_done(1 as libc::c_int as bit);
        }
    }
    #[cfg(not(CURL_DISABLE_NETRC))]
    let flag2: bool = ((*data).state).this_is_a_follow() == 0
        || ((*conn).bits).netrc() as libc::c_int != 0
        || ((*data).state.first_host).is_null()
        || ((*data).set).allow_auth_to_other_hosts() as libc::c_int != 0
        || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0;
    #[cfg(CURL_DISABLE_NETRC)]
    let flag2: bool = ((*data).state).this_is_a_follow() == 0
        || ((*data).state.first_host).is_null()
        || ((*data).set).allow_auth_to_other_hosts() as libc::c_int != 0
        || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0;
    if flag2 {
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
#[cfg(CURL_DISABLE_HTTP_AUTH)]
#[no_mangle]
pub unsafe extern "C" fn Curl_http_output_auth(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut request: *const libc::c_char,
    mut httpreq: Curl_HttpReq,
    mut path: *const libc::c_char,
    mut proxytunnel: bool,
) -> CURLcode {
    return CURLE_OK;
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
    #[cfg(USE_SPNEGO)]
    let mut negstate: *mut curlnegotiate = if proxy as libc::c_int != 0 {
        &mut (*conn).proxy_negotiate_state
    } else {
        &mut (*conn).http_negotiate_state
    };
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
        #[cfg(USE_SPNEGO)]
        let flag1: bool = curl_strnequal(
            b"Negotiate\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"Negotiate\0" as *const u8 as *const libc::c_char),
        ) != 0 && is_valid_auth_separator(*auth.offset(9 as libc::c_int as isize)) != 0;
        #[cfg(not(USE_SPNEGO))]
        let flag1: bool = false;
        #[cfg(USE_NTLM)]
        let flag2: bool = curl_strnequal(
            b"NTLM\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"NTLM\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(4 as libc::c_int as isize)) != 0;
        #[cfg(not(USE_NTLM))]
        let flag2: bool = false;
        #[cfg(not(CURL_DISABLE_CRYPTO_AUTH))]
        let flag3: bool = curl_strnequal(
            b"Digest\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"Digest\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(6 as libc::c_int as isize)) != 0;
        #[cfg(CURL_DISABLE_CRYPTO_AUTH)]
        let flag3: bool = false;
        if flag1
        {
            match () {
                #[cfg(USE_SPNEGO)]
                _ => {
                    if (*authp).avail & (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int
                        != 0 || Curl_auth_is_spnego_supported() as libc::c_int != 0
                    {
                        *availp |= (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int;
                        (*authp).avail
                            |= (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int;
                        if (*authp).picked
                            == (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int
                        {
                            let mut result: CURLcode = Curl_input_negotiate(
                                data,
                                conn,
                                proxy,
                                auth,
                            );
                            if result as u64 == 0 {
                                let ref mut fresh11 = (*data).req.newurl;
                                *fresh11 = Curl_cstrdup
                                    .expect("non-null function pointer")((*data).state.url);
                                if ((*data).req.newurl).is_null() {
                                    return CURLE_OUT_OF_MEMORY;
                                }
                                let ref mut fresh12 = (*data).state;
                                (*fresh12).set_authproblem(0 as libc::c_int as bit);
                                *negstate = GSS_AUTHRECV;
                            } else {
                                let ref mut fresh13 = (*data).state;
                                (*fresh13).set_authproblem(1 as libc::c_int as bit);
                            }
                        }
                    }
                }
                #[cfg(not(USE_SPNEGO))]
                _ => { }
            }
            // if (*authp).avail & (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int
            //     != 0 || Curl_auth_is_spnego_supported() as libc::c_int != 0
            // {
            //     *availp |= (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int;
            //     (*authp).avail
            //         |= (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int;
            //     if (*authp).picked
            //         == (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int
            //     {
            //         let mut result: CURLcode = Curl_input_negotiate(
            //             data,
            //             conn,
            //             proxy,
            //             auth,
            //         );
            //         if result as u64 == 0 {
            //             let ref mut fresh11 = (*data).req.newurl;
            //             *fresh11 = Curl_cstrdup
            //                 .expect("non-null function pointer")((*data).state.url);
            //             if ((*data).req.newurl).is_null() {
            //                 return CURLE_OUT_OF_MEMORY;
            //             }
            //             let ref mut fresh12 = (*data).state;
            //             (*fresh12).set_authproblem(0 as libc::c_int as bit);
            //             *negstate = GSS_AUTHRECV;
            //         } else {
            //             let ref mut fresh13 = (*data).state;
            //             (*fresh13).set_authproblem(1 as libc::c_int as bit);
            //         }
            //     }
            // }
        } else if flag2
        {
            if (*authp).avail & (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
                != 0
                || (*authp).avail
                    & (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int != 0
                || Curl_auth_is_ntlm_supported() as libc::c_int != 0
            {
                *availp |= (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int;
                (*authp).avail
                    |= (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int;
                if (*authp).picked
                    == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
                    || (*authp).picked
                        == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int
                {
                    let mut result_0: CURLcode = Curl_input_ntlm(data, proxy, auth);
                    if result_0 as u64 == 0 {
                        let ref mut fresh15 = (*data).state;
                        (*fresh15).set_authproblem(0 as libc::c_int as bit);
                        if (*authp).picked
                            == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int
                        {
                            *availp
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 3 as libc::c_int);
                            (*authp).avail
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 3 as libc::c_int);
                            *availp
                                |= (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int;
                            (*authp).avail
                                |= (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int;
                            result_0 = Curl_input_ntlm_wb(data, conn, proxy, auth);
                            if result_0 as u64 != 0 {
                                Curl_infof(
                                    data,
                                    b"Authentication problem. Ignoring this.\0" as *const u8
                                        as *const libc::c_char,
                                );
                                let ref mut fresh16 = (*data).state;
                                (*fresh16).set_authproblem(1 as libc::c_int as bit);
                            }
                        }
                    } else {
                        Curl_infof(
                            data,
                            b"Authentication problem. Ignoring this.\0" as *const u8
                                as *const libc::c_char,
                        );
                        let ref mut fresh17 = (*data).state;
                        (*fresh17).set_authproblem(1 as libc::c_int as bit);
                    }
                }
            }
        } else if flag3
            {
            match () {
                #[cfg(not(CURL_DISABLE_CRYPTO_AUTH))]
                _ => {
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
                }
                #[cfg(CURL_DISABLE_CRYPTO_AUTH)]
                _ => { }
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
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !data.is_null() {} else {
        __assert_fail(
            b"data\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1090 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"_Bool http_should_fail(struct Curl_easy *)\0"))
                .as_ptr(),
        );
    }
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !((*data).conn).is_null() {} else {
        __assert_fail(
            b"data->conn\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1091 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"_Bool http_should_fail(struct Curl_easy *)\0"))
                .as_ptr(),
        );
    }
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
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if httpcode == 401 as libc::c_int || httpcode == 407 as libc::c_int {} else {
        __assert_fail(
            b"(httpcode == 401) || (httpcode == 407)\0" as *const u8
                as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1126 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"_Bool http_should_fail(struct Curl_easy *)\0"))
                .as_ptr(),
        );
    }
    if httpcode == 401 as libc::c_int && ((*(*data).conn).bits).user_passwd() == 0 {
        return 1 as libc::c_int != 0;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    if httpcode == 407 as libc::c_int && ((*(*data).conn).bits).proxy_user_passwd() == 0 {
        return 1 as libc::c_int != 0;
    }
    return ((*data).state).authproblem() != 0;
}
#[cfg(not(USE_HYPER))]
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
#[cfg(not(USE_HYPER))]
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
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if socketindex <= 1 as libc::c_int {} else {
        __assert_fail(
            b"socketindex <= 1\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1240 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 94],
                &[libc::c_char; 94],
            >(
                b"CURLcode Curl_buffer_send(struct dynbuf *, struct Curl_easy *, curl_off_t *, curl_off_t, int)\0",
            ))
                .as_ptr(),
        );
    }
    sockfd = (*conn).sock[socketindex as usize];
    ptr = Curl_dyn_ptr(in_0);
    size = Curl_dyn_len(in_0);
    headersize = size.wrapping_sub(included_body_bytes as size_t);
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if size > included_body_bytes as size_t {} else {
        __assert_fail(
            b"size > (size_t)included_body_bytes\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1253 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 94],
                &[libc::c_char; 94],
            >(
                b"CURLcode Curl_buffer_send(struct dynbuf *, struct Curl_easy *, curl_off_t *, curl_off_t, int)\0",
            ))
                .as_ptr(),
        );
    }
    result = CURLE_OK as libc::c_int as CURLcode;
    if result as u64 != 0 {
        Curl_dyn_free(in_0);
        return result;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag: bool = ((*(*conn).handler).flags & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
        || (*conn).http_proxy.proxytype as libc::c_uint
            == CURLPROXY_HTTPS as libc::c_int as libc::c_uint)
        && (*conn).httpversion as libc::c_int != 20 as libc::c_int;
    #[cfg(CURL_DISABLE_PROXY)]
    let flag: bool = (*(*conn).handler).flags & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
        && (*conn).httpversion as libc::c_int != 20 as libc::c_int;
    if flag
    {
        if (*data).set.max_send_speed != 0
            && included_body_bytes > (*data).set.max_send_speed
        {
            let mut overflow: curl_off_t = included_body_bytes
                - (*data).set.max_send_speed;
            #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
            if (overflow as size_t) < size {} else {
                __assert_fail(
                    b"(size_t)overflow < size\0" as *const u8 as *const libc::c_char,
                    b"http.c\0" as *const u8 as *const libc::c_char,
                    1275 as libc::c_int as libc::c_uint,
                    (*::std::mem::transmute::<
                        &[u8; 94],
                        &[libc::c_char; 94],
                    >(
                        b"CURLcode Curl_buffer_send(struct dynbuf *, struct Curl_easy *, curl_off_t *, curl_off_t, int)\0",
                    ))
                        .as_ptr(),
                );
            }
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
    } else {
        #[cfg(CURLDEBUG)]
        {
            let mut p: *mut libc::c_char = getenv(
                b"CURL_SMALLREQSEND\0" as *const u8 as *const libc::c_char,
            );
            if !p.is_null() {
                let mut altsize: size_t = strtoul(
                    p,
                    0 as *mut *mut libc::c_char,
                    10 as libc::c_int,
                );
                if altsize != 0 {
                    sendsize = if size < altsize { size } else { altsize };
                } else {
                    sendsize = size;
                }
            } else if (*data).set.max_send_speed != 0
                    && included_body_bytes > (*data).set.max_send_speed
                {
                let mut overflow_0: curl_off_t = included_body_bytes
                    - (*data).set.max_send_speed;
                if (overflow_0 as size_t) < size {} else {
                    __assert_fail(
                        b"(size_t)overflow < size\0" as *const u8 as *const libc::c_char,
                        b"http.c\0" as *const u8 as *const libc::c_char,
                        1326 as libc::c_int as libc::c_uint,
                        (*::std::mem::transmute::<
                            &[u8; 94],
                            &[libc::c_char; 94],
                        >(
                            b"CURLcode Curl_buffer_send(struct dynbuf *, struct Curl_easy *, curl_off_t *, curl_off_t, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
                sendsize = size.wrapping_sub(overflow_0 as size_t);
            } else {
                sendsize = size;
            }
        }
        #[cfg(not(CURLDEBUG))]
        {
            if (*data).set.max_send_speed != 0
            && included_body_bytes > (*data).set.max_send_speed
            {
            let mut overflow_0: curl_off_t = included_body_bytes
                - (*data).set.max_send_speed;
            sendsize = size.wrapping_sub(overflow_0 as size_t);
            } else {
                sendsize = size;
            }
        }
    }
    result = Curl_write(data, sockfd, ptr as *const libc::c_void, sendsize, &mut amount);
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
#[cfg(USE_HYPER)]
#[no_mangle]
pub unsafe extern "C" fn Curl_buffer_send(
    mut in_0: *mut dynbuf,
    mut data: *mut Curl_easy,
    mut bytes_written: *mut curl_off_t,
    mut included_body_bytes: curl_off_t,
    mut socketindex: libc::c_int,
) -> CURLcode {
    return CURLE_OK;
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
    #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
    Curl_conncontrol(conn, 0 as libc::c_int);
    #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
    Curl_conncontrol(
        conn,
        0 as libc::c_int,
        b"HTTP default\0" as *const u8 as *const libc::c_char,
    );
    match () {
        #[cfg(not(CURL_DISABLE_PROXY))]
        _ => {
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
        }
        #[cfg(CURL_DISABLE_PROXY)]
        _ => { }
    }
    if (*(*conn).given).protocol & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0 {
        result = https_connecting(data, done);
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
#[cfg(not(CURL_DISABLE_PROXY))]
unsafe extern "C" fn add_haproxy_protocol_header(mut data: *mut Curl_easy) -> CURLcode {
    let mut req: dynbuf = dynbuf {
        bufr: 0 as *mut libc::c_char,
        leng: 0,
        allc: 0,
        toobig: 0,
        #[cfg(DEBUGBUILD)]
        init: 0,
    };
    let mut result: CURLcode = CURLE_OK;
    let mut tcp_version: *const libc::c_char = 0 as *const libc::c_char;
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !((*data).conn).is_null() {} else {
        __assert_fail(
            b"data->conn\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1546 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"CURLcode add_haproxy_protocol_header(struct Curl_easy *)\0"))
                .as_ptr(),
        );
    }
    Curl_dyn_init(&mut req, 2048 as libc::c_int as size_t);
    #[cfg(USE_UNIX_SOCKETS)]
    let flag: bool = !((*(*data).conn).unix_domain_socket).is_null();
    #[cfg(not(USE_UNIX_SOCKETS))]
    let flag: bool = false;
    if flag
    {
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
#[cfg(USE_SSL)]
unsafe extern "C" fn https_connecting(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !data.is_null()
        && (*(*(*data).conn).handler).flags
            & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
    {} else {
        __assert_fail(
            b"(data) && (data->conn->handler->flags & (1<<0))\0" as *const u8
                as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1581 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"CURLcode https_connecting(struct Curl_easy *, _Bool *)\0"))
                .as_ptr(),
        );
    }
    #[cfg(ENABLE_QUIC)]
    if (*conn).transport as libc::c_uint == TRNSPRT_QUIC as libc::c_int as libc::c_uint {
        *done = 1 as libc::c_int != 0;
        return CURLE_OK;
    }
    result = Curl_ssl_connect_nonblocking(
        data,
        conn,
        0 as libc::c_int != 0,
        0 as libc::c_int,
        done,
    );
    if result as u64 != 0 {
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 1 as libc::c_int);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            1 as libc::c_int,
            b"Failed HTTPS connection\0" as *const u8 as *const libc::c_char,
        );
    }
    return result;
}
#[cfg(not(USE_SSL))]
unsafe extern "C" fn https_connecting(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    return CURLE_COULDNT_CONNECT;
}
#[cfg(USE_SSL)]
unsafe extern "C" fn https_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> libc::c_int {
    if (*(*conn).handler).flags
        & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
    {
        return ((*Curl_ssl).getsock).expect("non-null function pointer")(conn, socks);
    }
    return 0 as libc::c_int;
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
    #[cfg(any(all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)), not(CURL_DISABLE_SMTP), not(CURL_DISABLE_IMAP)))]
    Curl_mime_cleanpart(&mut (*http).form);
    Curl_dyn_reset(&mut (*data).state.headerb);
    #[cfg(all(not(CURL_DISABLE_HTTP), USE_HYPER))]
    Curl_hyper_done(data);
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
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 2 as libc::c_int);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            2 as libc::c_int,
            b"Empty reply from server\0" as *const u8 as *const libc::c_char,
        );
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
#[cfg(not(USE_HYPER))]
unsafe extern "C" fn get_http_string(
    mut data: *const Curl_easy,
    mut conn: *const connectdata,
) -> *const libc::c_char {
    #[cfg(ENABLE_QUIC)]
    if (*data).state.httpwant as libc::c_int == CURL_HTTP_VERSION_3 as libc::c_int
        || (*conn).httpversion as libc::c_int == 30 as libc::c_int
    {
        return b"3\0" as *const u8 as *const libc::c_char;
    }
    #[cfg(USE_NGHTTP2)]
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
    // TODO 测试通过后，把注释删掉
    let flag: bool = if cfg!(CURL_DO_LINEEND_CONV) {
        ((*handle).state).prefer_ascii() as libc::c_int != 0
        || ((*handle).set).crlf() as libc::c_int != 0
    } else {
        ((*handle).set).crlf() as libc::c_int != 0
    };
    if flag
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
#[cfg(USE_HYPER)]
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
                            match (){
                                #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                                _ => {
                                    semicolonp = Curl_cstrdup
                                    .expect("non-null function pointer")((*headers).data);
                                }
                                #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                                _ => {
                            semicolonp = curl_dbg_strdup(
                                (*headers).data,
                                1857 as libc::c_int,
                                b"http.c\0" as *const u8 as *const libc::c_char,
                            );
                                }
                            }
                            if semicolonp.is_null() {
                                Curl_dyn_free(req);
                                return CURLE_OUT_OF_MEMORY;
                            }
                            *semicolonp
                                .offset(
                                    ptr.offset_from((*headers).data) as libc::c_long as isize,
                                ) = ':' as i32 as libc::c_char;
                            optr = &mut *semicolonp
                                .offset(
                                    ptr.offset_from((*headers).data) as libc::c_long as isize,
                                ) as *mut libc::c_char;
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
                                strlen(
                                    b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                ),
                            ) != 0)
                        {
                            if !((*data).state.httpreq as libc::c_uint
                                == HTTPREQ_POST_MIME as libc::c_int as libc::c_uint
                                && curl_strnequal(
                                    b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                    compare,
                                    strlen(
                                        b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                    ),
                                ) != 0)
                            {
                                if !(((*conn).bits).authneg() as libc::c_int != 0
                                    && curl_strnequal(
                                        b"Content-Length:\0" as *const u8 as *const libc::c_char,
                                        compare,
                                        strlen(
                                            b"Content-Length:\0" as *const u8 as *const libc::c_char,
                                        ),
                                    ) != 0)
                                {
                                    if !(!((*data).state.aptr.te).is_null()
                                        && curl_strnequal(
                                            b"Connection:\0" as *const u8 as *const libc::c_char,
                                            compare,
                                            strlen(b"Connection:\0" as *const u8 as *const libc::c_char),
                                        ) != 0)
                                    {
                                        if !((*conn).httpversion as libc::c_int >= 20 as libc::c_int
                                            && curl_strnequal(
                                                b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
                                                compare,
                                                strlen(
                                                    b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
                                                ),
                                            ) != 0)
                                        {
                                            if !((curl_strnequal(
                                                b"Authorization:\0" as *const u8 as *const libc::c_char,
                                                compare,
                                                strlen(
                                                    b"Authorization:\0" as *const u8 as *const libc::c_char,
                                                ),
                                            ) != 0
                                                || curl_strnequal(
                                                    b"Cookie:\0" as *const u8 as *const libc::c_char,
                                                    compare,
                                                    strlen(b"Cookie:\0" as *const u8 as *const libc::c_char),
                                                ) != 0)
                                                && (((*data).state).this_is_a_follow() as libc::c_int != 0
                                                    && !((*data).state.first_host).is_null()
                                                    && ((*data).set).allow_auth_to_other_hosts() == 0
                                                    && Curl_strcasecompare(
                                                        (*data).state.first_host,
                                                        (*conn).host.name,
                                                    ) == 0))
                                            {
                                                result = Curl_hyper_header(
                                                    data,
                                                    req as *mut hyper_headers,
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
                        #[cfg(not(CURLDEBUG))]
                        Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(semicolonp as *mut libc::c_void);
                        #[cfg(CURLDEBUG)]
                        curl_dbg_free(
                            semicolonp as *mut libc::c_void,
                            1929 as libc::c_int,
                            b"http.c\0" as *const u8 as *const libc::c_char,
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
#[cfg(not(USE_HYPER))]
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
    match () {
        #[cfg(not(CURL_DISABLE_PROXY))]
        _ => {
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
        }
        #[cfg(CURL_DISABLE_PROXY)]
        _ => {
            h[0 as libc::c_int as usize] = (*data).set.headers;
        }
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
                            match (){
                                #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                                _ => {
                                    semicolonp = Curl_cstrdup
                                    .expect("non-null function pointer")((*headers).data);
                                }
                                #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                                _ => {
                                    semicolonp = curl_dbg_strdup(
                                        (*headers).data,
                                        1857 as libc::c_int,
                                        b"http.c\0" as *const u8 as *const libc::c_char,
                                    );
                                }
                            }
                            if semicolonp.is_null() {
                                #[cfg(not(USE_HYPER))]
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
                                                match () {
                                                    #[cfg(USE_HYPER)]
                                                    _ => {
                                                        result = Curl_hyper_header(data, req, compare);
                                                    }
                                                    #[cfg(not(USE_HYPER))]
                                                    _ => {
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
                        }
                    }
                    if !semicolonp.is_null() {
                        #[cfg(not(CURLDEBUG))]
                        Curl_cfree.expect("non-null function pointer")(
                            semicolonp as *mut libc::c_void,
                        );
                        #[cfg(CURLDEBUG)]
                        curl_dbg_free(
                            semicolonp as *mut libc::c_void,
                            1929 as libc::c_int,
                            b"http.c\0" as *const u8 as *const libc::c_char,
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
#[cfg(all(not(CURL_DISABLE_PARSEDATE), USE_HYPER))]
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
        Curl_failf(data, b"Invalid TIMEVALUE\0" as *const u8 as *const libc::c_char);
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
        b"%s: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8
            as *const libc::c_char,
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
    result = Curl_hyper_header(data, req as *mut hyper_headers, datestr.as_mut_ptr());
    return result;
}
#[cfg(all(not(CURL_DISABLE_PARSEDATE), not(USE_HYPER)))]
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
#[cfg(CURL_DISABLE_PARSEDATE)]
pub unsafe extern "C" fn Curl_add_timecondition(
    mut data: *mut Curl_easy,
    mut req: *mut dynbuf,
) -> CURLcode {
    return CURLE_OK;
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
        #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
        if httpreq as libc::c_uint >= HTTPREQ_GET as libc::c_int as libc::c_uint
            && httpreq as libc::c_uint <= HTTPREQ_HEAD as libc::c_int as libc::c_uint
        {} else {
            __assert_fail(
                b"(httpreq >= HTTPREQ_GET) && (httpreq <= HTTPREQ_HEAD)\0" as *const u8
                    as *const libc::c_char,
                b"http.c\0" as *const u8 as *const libc::c_char,
                2041 as libc::c_int as libc::c_uint,
                (*::std::mem::transmute::<
                    &[u8; 95],
                    &[libc::c_char; 95],
                >(
                    b"void Curl_http_method(struct Curl_easy *, struct connectdata *, const char **, Curl_HttpReq *)\0",
                ))
                    .as_ptr(),
            );
        }
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
    if !(Curl_checkheaders(data, b"User-Agent\0" as *const u8 as *const libc::c_char))
        .is_null()
    {
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.uagent as *mut libc::c_void,
        );
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.aptr.uagent as *mut libc::c_void,
            2072 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        let ref mut fresh38 = (*data).state.aptr.uagent;
        *fresh38 = 0 as *mut libc::c_char;
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
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.first_host as *mut libc::c_void,
        );
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.first_host as *mut libc::c_void,
            2084 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                (*data).state.first_host = Curl_cstrdup.expect("non-null function pointer")((*conn).host.name);
            }
            #[cfg(CURLDEBUG)]
            _ => {
                (*data).state.first_host = curl_dbg_strdup(
            (*conn).host.name,
            2086 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
            }
        }
        if ((*data).state.first_host).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*data).state.first_remote_port = (*conn).remote_port;
    }
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(cookiehost as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*data).state.aptr.host as *mut libc::c_void,
        2092 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    let ref mut fresh40 = (*data).state.aptr.host;
    *fresh40 = 0 as *mut libc::c_char;
    ptr = Curl_checkheaders(data, b"Host\0" as *const u8 as *const libc::c_char);
    if !ptr.is_null()
        && (((*data).state).this_is_a_follow() == 0
            || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0)
    {
        match () {
            #[cfg(not(CURL_DISABLE_COOKIES))]
            _ => {
        let mut cookiehost: *mut libc::c_char = Curl_copy_header_value(ptr);
        if cookiehost.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *cookiehost == 0 {
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(cookiehost as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                cookiehost as *mut libc::c_void,
                2108 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
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
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.cookiehost as *mut libc::c_void,
            );
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*data).state.aptr.cookiehost as *mut libc::c_void,
                2127 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            let ref mut fresh41 = (*data).state.aptr.cookiehost;
            *fresh41 = 0 as *mut libc::c_char;
            let ref mut fresh42 = (*data).state.aptr.cookiehost;
            *fresh42 = cookiehost;
        }
    }
    #[cfg(CURL_DISABLE_COOKIES)]
    _ => { }
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
    match () {
        #[cfg(not(CURL_DISABLE_PROXY))]
        _ => {
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
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(url as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            url as *mut libc::c_void,
            2241 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
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
        }
        #[cfg(CURL_DISABLE_PROXY)]
        _ => {
            result = Curl_dyn_add(r, path);
            if result as u64 != 0 {
                return result;
            }
            if !query.is_null() {
                result = Curl_dyn_addf(r, b"?%s\0" as *const u8 as *const libc::c_char, query);
            }
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
            #[cfg(any(all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)), not(CURL_DISABLE_SMTP), not(CURL_DISABLE_IMAP)))]
            Curl_mime_cleanpart(&mut (*http).form);
            // TODO 待测试
            match () {
                #[cfg(not(CURL_DISABLE_MIME))]
                _ => {
            result = Curl_getformdata(
                data,
                &mut (*http).form,
                (*data).set.httppost,
                (*data).state.fread_func,
            );
                }
                #[cfg(CURL_DISABLE_MIME)]
                _ => {
                    result = CURLE_NOT_BUILT_IN;
                }
            }
            // result = Curl_getformdata(
            //     data,
            //     &mut (*http).form,
            //     (*data).set.httppost,
            //     (*data).state.fread_func,
            // );
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
    #[cfg(not(CURL_DISABLE_MIME))]
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
        // 好像这里其实可以不要条件编译
        match () {
            #[cfg(any(all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)), not(CURL_DISABLE_SMTP), not(CURL_DISABLE_IMAP)))]
            _ => {
        result = Curl_mime_prepare_headers(
            (*http).sendit,
            cthdr,
            0 as *const libc::c_char,
            MIMESTRATEGY_FORM,
        );
            }
            _ => {
                result = CURLE_NOT_BUILT_IN;
            }
        }
        // result = Curl_mime_prepare_headers(
        //     (*http).sendit,
        //     cthdr,
        //     0 as *const libc::c_char,
        //     MIMESTRATEGY_FORM,
        // );
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
    #[cfg(not(USE_HYPER))]
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
                // TODO 测试过了就把注释删咯
                if cfg!(not(CURL_DISABLE_MIME)) {
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
                }
                // #[cfg(not(CURL_DISABLE_MIME))]
                // let mut hdr: *mut curl_slist = 0 as *mut curl_slist;
                // #[cfg(not(CURL_DISABLE_MIME))]
                // hdr = (*(*http).sendit).curlheaders;
                // #[cfg(not(CURL_DISABLE_MIME))]
                // while !hdr.is_null() {
                //     result = Curl_dyn_addf(
                //         r,
                //         b"%s\r\n\0" as *const u8 as *const libc::c_char,
                //         (*hdr).data,
                //     );
                //     if result as u64 != 0 {
                //         return result;
                //     }
                //     hdr = (*hdr).next;
                // }
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
                // TODO 这里也有条件编译
                match () {
                    #[cfg(any(all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)), not(CURL_DISABLE_SMTP), not(CURL_DISABLE_IMAP)))]
                    _ => {
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
                    }
                    _ => {
                        // TODO
                    }
                }
                // *fresh51 = ::std::mem::transmute::<
                //     Option<
                //         unsafe extern "C" fn(
                //             *mut libc::c_char,
                //             size_t,
                //             size_t,
                //             *mut libc::c_void,
                //         ) -> size_t,
                //     >,
                //     curl_read_callback,
                // >(Some(
                //     Curl_mime_read
                //         as unsafe extern "C" fn(
                //             *mut libc::c_char,
                //             size_t,
                //             size_t,
                //             *mut libc::c_void,
                //         ) -> size_t,
                // ));
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
            // TODO 测试通过了就把match删咯
            let flag: bool = if cfg!(not(USE_HYPER)) {
                !((*data).set.postfields).is_null()
            } else {
                false
            };
            if flag
            {
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
            // match () {
            //     #[cfg(not(USE_HYPER))]
            //     _ => {
            //         if !((*data).set.postfields).is_null() {
            //             if (*conn).httpversion as libc::c_int != 20 as libc::c_int
            //                 && ((*data).state).expect100header() == 0
            //                 && (*http).postsize < (64 as libc::c_int * 1024 as libc::c_int) as libc::c_long
            //             {
            //                 result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
            //                 if result as u64 != 0 {
            //                     return result;
            //                 }
            //                 if ((*data).req).upload_chunky() == 0 {
            //                     result =
            //                         Curl_dyn_addn(r, (*data).set.postfields, (*http).postsize as size_t);
            //                     included_body = (*http).postsize;
            //                 } else {
            //                     if (*http).postsize != 0 {
            //                         let mut chunk: [libc::c_char; 16] = [0; 16];
            //                         curl_msnprintf(
            //                             chunk.as_mut_ptr(),
            //                             ::std::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
            //                             b"%x\r\n\0" as *const u8 as *const libc::c_char,
            //                             (*http).postsize as libc::c_int,
            //                         );
            //                         result = Curl_dyn_add(r, chunk.as_mut_ptr());
            //                         if result as u64 == 0 {
            //                             included_body = ((*http).postsize as libc::c_ulong)
            //                                 .wrapping_add(strlen(chunk.as_mut_ptr()))
            //                                 as curl_off_t;
            //                             result = Curl_dyn_addn(
            //                                 r,
            //                                 (*data).set.postfields,
            //                                 (*http).postsize as size_t,
            //                             );
            //                             if result as u64 == 0 {
            //                                 result = Curl_dyn_add(
            //                                     r,
            //                                     b"\r\n\0" as *const u8 as *const libc::c_char,
            //                                 );
            //                             }
            //                             included_body += 2 as libc::c_int as libc::c_long;
            //                         }
            //                     }
            //                     if result as u64 == 0 {
            //                         result =
            //                             Curl_dyn_add(r, b"0\r\n\r\n\0" as *const u8 as *const libc::c_char);
            //                         included_body += 5 as libc::c_int as libc::c_long;
            //                     }
            //                 }
            //                 if result as u64 != 0 {
            //                     return result;
            //                 }
            //                 Curl_pgrsSetUploadSize(data, (*http).postsize);
            //             } else {
            //                 let ref mut fresh55 = (*http).postdata;
            //                 *fresh55 = (*data).set.postfields as *const libc::c_char;
            //                 (*http).sending = HTTPSEND_BODY;
            //                 let ref mut fresh56 = (*data).state.fread_func;
            //                 *fresh56 = ::std::mem::transmute::<
            //                     Option<
            //                         unsafe extern "C" fn(
            //                             *mut libc::c_char,
            //                             size_t,
            //                             size_t,
            //                             *mut libc::c_void,
            //                         ) -> size_t,
            //                     >,
            //                     curl_read_callback,
            //                 >(Some(
            //                     readmoredata
            //                         as unsafe extern "C" fn(
            //                             *mut libc::c_char,
            //                             size_t,
            //                             size_t,
            //                             *mut libc::c_void,
            //                         ) -> size_t,
            //                 ));
            //                 let ref mut fresh57 = (*data).state.in_0;
            //                 *fresh57 = data as *mut libc::c_void;
            //                 Curl_pgrsSetUploadSize(data, (*http).postsize);
            //                 result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
            //                 if result as u64 != 0 {
            //                     return result;
            //                 }
            //             }
            //         } else {
            //             result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
            //             if result as u64 != 0 {
            //                 return result;
            //             }
            //             if ((*data).req).upload_chunky() as libc::c_int != 0
            //                 && ((*conn).bits).authneg() as libc::c_int != 0
            //             {
            //                 result = Curl_dyn_add(
            //                     r,
            //                     b"0\r\n\r\n\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            //                 );
            //                 if result as u64 != 0 {
            //                     return result;
            //                 }
            //             } else if (*data).state.infilesize != 0 {
            //                 Curl_pgrsSetUploadSize(
            //                     data,
            //                     if (*http).postsize != 0 {
            //                         (*http).postsize
            //                     } else {
            //                         -(1 as libc::c_int) as libc::c_long
            //                     },
            //                 );
            //                 if ((*conn).bits).authneg() == 0 {
            //                     let ref mut fresh58 = (*http).postdata;
            //                     *fresh58 =
            //                         &mut (*http).postdata as *mut *const libc::c_char as *mut libc::c_char;
            //                 }
            //             }
            //         }
            //     }
            //     #[cfg(USE_HYPER)]
            //     _ => {
            //         result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
            //         if result as u64 != 0 {
            //             return result;
            //         }
            //         if ((*data).req).upload_chunky() as libc::c_int != 0
            //             && ((*conn).bits).authneg() as libc::c_int != 0
            //         {
            //             result = Curl_dyn_add(
            //                 r,
            //                 b"0\r\n\r\n\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            //             );
            //             if result as u64 != 0 {
            //                 return result;
            //             }
            //         } else if (*data).state.infilesize != 0 {
            //             Curl_pgrsSetUploadSize(
            //                 data,
            //                 if (*http).postsize != 0 {
            //                     (*http).postsize
            //                 } else {
            //                     -(1 as libc::c_int) as libc::c_long
            //                 },
            //             );
            //             if ((*conn).bits).authneg() == 0 {
            //                 let ref mut fresh58 = (*http).postdata;
            //                 *fresh58 =
            //                     &mut (*http).postdata as *mut *const libc::c_char as *mut libc::c_char;
            //             }
            //         }
            //     }
            // }
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
#[cfg(not(CURL_DISABLE_COOKIES))]
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
#[cfg(CURL_DISABLE_COOKIES)]
#[no_mangle]
pub unsafe extern "C" fn Curl_http_cookies(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    return CURLE_OK;
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
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.rangeline as *mut libc::c_void,
            );
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*data).state.aptr.rangeline as *mut libc::c_void,
                2776 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            let ref mut fresh63 = (*data).state.aptr.rangeline;
            *fresh63 = curl_maprintf(
                b"Range: bytes=%s\r\n\0" as *const u8 as *const libc::c_char,
                (*data).state.range,
            );
        } else if (httpreq as libc::c_uint == HTTPREQ_POST as libc::c_int as libc::c_uint
                || httpreq as libc::c_uint == HTTPREQ_PUT as libc::c_int as libc::c_uint)
            && (Curl_checkheaders(data, b"Content-Range\0" as *const u8 as *const libc::c_char))
                    .is_null()
            {
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.rangeline as *mut libc::c_void,
            );
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*data).state.aptr.rangeline as *mut libc::c_void,
                2784 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
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
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if (*(*conn).handler).protocol
        & ((1 as libc::c_int) << 0 as libc::c_int
            | (1 as libc::c_int) << 1 as libc::c_int
            | (1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint != 0
    {} else {
        __assert_fail(
            b"conn->handler->protocol&(((1<<0)|(1<<1))|(1<<18))\0" as *const u8
                as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            2905 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 81],
                &[libc::c_char; 81],
            >(
                b"CURLcode Curl_http_firstwrite(struct Curl_easy *, struct connectdata *, _Bool *)\0",
            ))
                .as_ptr(),
        );
    }
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
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as libc::c_int);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as libc::c_int,
                b"already downloaded\0" as *const u8 as *const libc::c_char,
            );
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
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as libc::c_int);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as libc::c_int,
                b"Simulated 304 handling\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OK;
        }
    }
    return CURLE_OK;
}
#[cfg(HAVE_LIBZ)]
#[no_mangle]
pub unsafe extern "C" fn Curl_transferencode(mut data: *mut Curl_easy) -> CURLcode {
    if (Curl_checkheaders(data, b"TE\0" as *const u8 as *const libc::c_char)).is_null()
        && ((*data).set).http_transfer_encoding() as libc::c_int != 0
    {
        let mut cptr: *mut libc::c_char = Curl_checkheaders(
            data,
            b"Connection\0" as *const u8 as *const libc::c_char,
        );
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*data).state.aptr.te as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.aptr.te as *mut libc::c_void,
            2990 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        let ref mut fresh69 = (*data).state.aptr.te;
        *fresh69 = 0 as *mut libc::c_char;
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
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(cptr as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            cptr as *mut libc::c_void,
            3002 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        if ((*data).state.aptr.te).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[cfg(not(USE_HYPER))]
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
        #[cfg(DEBUGBUILD)]
        init: 0,
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
                    #[cfg(USE_NGHTTP2)]
                    if (*data).state.httpwant as libc::c_int
                        == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE as libc::c_int
                    {
                        #[cfg(not(CURL_DISABLE_PROXY))]
                        let flag1: bool = ((*conn).bits).httpproxy() as libc::c_int != 0
                            && ((*conn).bits).tunnel_proxy() == 0;
                        #[cfg(CURL_DISABLE_PROXY)]
                        let flag1: bool = false;
                        if flag1
                        {
                            Curl_infof(
                                data,
                                b"Ignoring HTTP/2 prior knowledge due to proxy\0" as *const u8
                                    as *const libc::c_char,
                            );
                        } else {
                            Curl_infof(
                                data,
                                b"HTTP/2 over clean TCP\0" as *const u8
                                    as *const libc::c_char,
                            );
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
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !http.is_null() {} else {
        __assert_fail(
            b"http\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            3079 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 48],
                &[libc::c_char; 48],
            >(b"CURLcode Curl_http(struct Curl_easy *, _Bool *)\0"))
                .as_ptr(),
        );
    }
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
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(pq as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        pq as *mut libc::c_void,
        3101 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    if result as u64 != 0 {
        return result;
    }
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")((*data).state.aptr.ref_0 as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*data).state.aptr.ref_0 as *mut libc::c_void,
        3106 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    let ref mut fresh71 = (*data).state.aptr.ref_0;
    *fresh71 = 0 as *mut libc::c_char;
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
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
        );
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
            3115 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        let ref mut fresh73 = (*data).state.aptr.accept_encoding;
        *fresh73 = 0 as *mut libc::c_char;
        let ref mut fresh74 = (*data).state.aptr.accept_encoding;
        *fresh74 = curl_maprintf(
            b"Accept-Encoding: %s\r\n\0" as *const u8 as *const libc::c_char,
            (*data).set.str_0[STRING_ENCODING as libc::c_int as usize],
        );
        if ((*data).state.aptr.accept_encoding).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
        );
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
            3122 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        let ref mut fresh75 = (*data).state.aptr.accept_encoding;
        *fresh75 = 0 as *mut libc::c_char;
    }
    // TODO 测试过了就把注释删咯
    match () {
        #[cfg(HAVE_LIBZ)]
        _ => {
    result = Curl_transferencode(data);
    if result as u64 != 0 {
        return result;
    }
        }
        #[cfg(not(HAVE_LIBZ))]
        _ => { }
    }
    // if cfg!(HAVE_LIBZ) {
    //     result = Curl_transferencode(data);
    //     if result as u64 != 0 {
    //         return result;
    //     }
    // }
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
    #[cfg(not(CURL_DISABLE_ALTSVC))]
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
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag2: bool = ((*conn).bits).httpproxy() as libc::c_int != 0
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
        .is_null();
    #[cfg(CURL_DISABLE_PROXY)]
    let flag2: bool = false;
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
        if flag2
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
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")((*data).state.aptr.userpwd as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*data).state.aptr.userpwd as *mut libc::c_void,
        3224 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    let ref mut fresh76 = (*data).state.aptr.userpwd;
    *fresh76 = 0 as *mut libc::c_char;
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
        3225 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    let ref mut fresh77 = (*data).state.aptr.proxyuserpwd;
    *fresh77 = 0 as *mut libc::c_char;
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(altused as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        altused as *mut libc::c_void,
        3226 as libc::c_int,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
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
#[cfg(not(CURL_DISABLE_RSTP))]
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
    #[cfg(not(CURL_DISABLE_RSTP))]
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
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag1: bool = (*conn).httpversion as libc::c_int == 10 as libc::c_int
        && ((*conn).bits).httpproxy() as libc::c_int != 0
        && Curl_compareheader(
            headp,
            b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
            b"keep-alive\0" as *const u8 as *const libc::c_char,
        ) as libc::c_int
            != 0;
    #[cfg(CURL_DISABLE_PROXY)]
    let flag1: bool = false;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag2: bool = (*conn).httpversion as libc::c_int == 11 as libc::c_int
        && ((*conn).bits).httpproxy() as libc::c_int != 0
        && Curl_compareheader(
            headp,
            b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
            b"close\0" as *const u8 as *const libc::c_char,
        ) as libc::c_int
            != 0;
    #[cfg(CURL_DISABLE_PROXY)]
    let flag2: bool = false;
    #[cfg(not(CURL_DISABLE_COOKIES))]
    let flag3: bool = !((*data).cookies).is_null()
        && ((*data).state).cookie_engine() as libc::c_int != 0
        && curl_strnequal(
            b"Set-Cookie:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Set-Cookie:\0" as *const u8 as *const libc::c_char),
        ) != 0;
    #[cfg(CURL_DISABLE_COOKIES)]
    let flag3: bool = false;
    #[cfg(USE_SPNEGO)]
    let flag4: bool = curl_strnequal(
            b"Persistent-Auth:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Persistent-Auth:\0" as *const u8 as *const libc::c_char),
        ) != 0;
    #[cfg(not(USE_SPNEGO))]
    let flag4: bool = false;
    // let flag4: bool = if cfg!(USE_SPNEGO) {
    //     curl_strnequal(
    //         b"Persistent-Auth:\0" as *const u8 as *const libc::c_char,
    //         headp,
    //         strlen(b"Persistent-Auth:\0" as *const u8 as *const libc::c_char),
    //     ) != 0
    // } else {
    //     false
    // };
    #[cfg(not(CURL_DISABLE_HSTS))]
    let flag5: bool = !((*data).hsts).is_null()
        && curl_strnequal(
            b"Strict-Transport-Security:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(
                b"Strict-Transport-Security:\0" as *const u8 as *const libc::c_char,
            ),
        ) != 0
        && (*(*conn).handler).flags
            & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0;
    #[cfg(CURL_DISABLE_HSTS)]
    let flag5: bool = false;
    let flag6: bool = if cfg!(all(not(CURL_DISABLE_ALTSVC), not(CURLDEBUG))) {
        !((*data).asi).is_null()
        && curl_strnequal(
            b"Alt-Svc:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Alt-Svc:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && ((*(*conn).handler).flags & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
            != 0
            || 0 as libc::c_int != 0)
    } else if cfg!(all(not(CURL_DISABLE_ALTSVC), CURLDEBUG)){
        !((*data).asi).is_null()
        && curl_strnequal(
            b"Alt-Svc:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Alt-Svc:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && ((*(*conn).handler).flags
            & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
            || !(getenv(b"CURL_ALTSVC_HTTP\0" as *const u8 as *const libc::c_char))
                .is_null())
    }else {
        false
    };
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
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 2 as libc::c_int);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                2 as libc::c_int,
                b"overflow content-length\0" as *const u8 as *const libc::c_char,
            );
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
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(contenttype as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                contenttype as *mut libc::c_void,
                3445 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
        } else {
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(
                (*data).info.contenttype as *mut libc::c_void,
            );
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*data).info.contenttype as *mut libc::c_void,
                3447 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            let ref mut fresh82 = (*data).info.contenttype;
            *fresh82 = 0 as *mut libc::c_char;
            let ref mut fresh83 = (*data).info.contenttype;
            *fresh83 = contenttype;
        }
    } else if flag1
        {
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 0 as libc::c_int);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            0 as libc::c_int,
            b"Proxy-Connection keep-alive\0" as *const u8 as *const libc::c_char,
        );
        Curl_infof(
            data,
            b"HTTP/1.0 proxy connection set to keep alive!\0" as *const u8 as *const libc::c_char,
        );
    } else if flag2
        {
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 1 as libc::c_int);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            1 as libc::c_int,
            b"Proxy-Connection: asked to close after done\0" as *const u8
                as *const libc::c_char,
        );
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
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 0 as libc::c_int);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            0 as libc::c_int,
            b"Connection keep-alive\0" as *const u8 as *const libc::c_char,
        );
        Curl_infof(
            data,
            b"HTTP/1.0 connection set to keep alive!\0" as *const u8 as *const libc::c_char,
        );
    } else if Curl_compareheader(
            headp,
            b"Connection:\0" as *const u8 as *const libc::c_char,
            b"close\0" as *const u8 as *const libc::c_char,
        ) {
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 2 as libc::c_int);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            2 as libc::c_int,
            b"Connection: close used\0" as *const u8 as *const libc::c_char,
        );
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
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as libc::c_int);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as libc::c_int,
                b"HTTP/1.1 transfer-encoding without chunks\0" as *const u8
                    as *const libc::c_char,
            );
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
    } else if flag3
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
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            auth as *mut libc::c_void,
            3616 as libc::c_int,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        if result as u64 != 0 {
            return result;
        }
    } else if flag4
    {
        match () {
            #[cfg(USE_SPNEGO)]
            _ => {
                let mut negdata: *mut negotiatedata = &mut (*conn).negotiate;
                let mut authp: *mut auth = &mut (*data).state.authhost;
                if (*authp).picked == (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int {
                    let mut persistentauth: *mut libc::c_char = Curl_copy_header_value(headp);
                    if persistentauth.is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                    (*negdata)
                        .set_noauthpersist(
                            (if curl_strnequal(
                                b"false\0" as *const u8 as *const libc::c_char,
                                persistentauth,
                                strlen(b"false\0" as *const u8 as *const libc::c_char),
                            ) != 0
                            {
                                1 as libc::c_int
                            } else {
                                0 as libc::c_int
                            }) as bit,
                        );
                    (*negdata).set_havenoauthpersist(1 as libc::c_int as bit);
                    Curl_infof(
                        data,
                        b"Negotiate: noauthpersist -> %d, header part: %s\0" as *const u8
                            as *const libc::c_char,
                        (*negdata).noauthpersist() as libc::c_int,
                        persistentauth,
                    );
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(persistentauth as *mut libc::c_void);
                }
            }
            #[cfg(not(USE_SPNEGO))]
            _ => { }
        }
        // let mut negdata: *mut negotiatedata = &mut (*conn).negotiate;
        // let mut authp: *mut auth = &mut (*data).state.authhost;
        // if (*authp).picked == (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int {
        //     let mut persistentauth: *mut libc::c_char = Curl_copy_header_value(headp);
        //     if persistentauth.is_null() {
        //         return CURLE_OUT_OF_MEMORY;
        //     }
        //     (*negdata)
        //         .set_noauthpersist(
        //             (if curl_strnequal(
        //                 b"false\0" as *const u8 as *const libc::c_char,
        //                 persistentauth,
        //                 strlen(b"false\0" as *const u8 as *const libc::c_char),
        //             ) != 0
        //             {
        //                 1 as libc::c_int
        //             } else {
        //                 0 as libc::c_int
        //             }) as bit,
        //         );
        //     (*negdata).set_havenoauthpersist(1 as libc::c_int as bit);
        //     Curl_infof(
        //         data,
        //         b"Negotiate: noauthpersist -> %d, header part: %s\0" as *const u8
        //             as *const libc::c_char,
        //         (*negdata).noauthpersist() as libc::c_int,
        //         persistentauth,
        //     );
        //     Curl_cfree
        //         .expect(
        //             "non-null function pointer",
        //         )(persistentauth as *mut libc::c_void);
        // }
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
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(location as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                location as *mut libc::c_void,
                3647 as libc::c_int,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
        } else {
            let ref mut fresh80 = (*data).req.location;
            *fresh80 = location;
            if ((*data).set).http_follow_location() != 0 {
                #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
                if ((*data).req.newurl).is_null() {} else {
                    __assert_fail(
                        b"!data->req.newurl\0" as *const u8 as *const libc::c_char,
                        b"http.c\0" as *const u8 as *const libc::c_char,
                        3652 as libc::c_int as libc::c_uint,
                        (*::std::mem::transmute::<
                            &[u8; 76],
                            &[libc::c_char; 76],
                        >(
                            b"CURLcode Curl_http_header(struct Curl_easy *, struct connectdata *, char *)\0",
                        ))
                            .as_ptr(),
                    );
                }
                match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {(*data).req.newurl = Curl_cstrdup.expect("non-null function pointer")((*data).req.location);}
                    #[cfg(CURLDEBUG)]
                    _ => {
                        (*data).req.newurl = curl_dbg_strdup(
                    (*data).req.location,
                    3653 as libc::c_int,
                    b"http.c\0" as *const u8 as *const libc::c_char,
                );
                    }
                }                
                if ((*data).req.newurl).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                result = http_perhapsrewind(data, conn);
                if result as u64 != 0 {
                    return result;
                }
            }
        }
    } else if flag5
        {
        match () {
            #[cfg(not(CURL_DISABLE_HSTS))]
            _ => {
        let mut check: CURLcode = Curl_hsts_parse(
            (*data).hsts,
            (*data).state.up.hostname,
            headp
                .offset(
                    strlen(
                        b"Strict-Transport-Security:\0" as *const u8
                            as *const libc::c_char,
                    ) as isize,
                ),
        );
        if check as u64 != 0 {
            Curl_infof(
                data,
                b"Illegal STS header skipped\0" as *const u8 as *const libc::c_char,
            );
                }
                else {
                    #[cfg(DEBUGBUILD)]
            Curl_infof(
                data,
                b"Parsed STS header fine (%zu entries)\0" as *const u8
                    as *const libc::c_char,
                (*(*data).hsts).list.size,
            );
        }
    }
    #[cfg(CURL_DISABLE_HSTS)]
            _ => { }
}
    } else if flag6
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
        #[cfg(not(CURLDEBUG))]
        Curl_conncontrol(conn, 1 as libc::c_int);
        #[cfg(CURLDEBUG)]
        Curl_conncontrol(
            conn,
            1 as libc::c_int,
            b"HTTP/1.0 close after body\0" as *const u8 as *const libc::c_char,
        );
    } else if (*conn).httpversion as libc::c_int == 20 as libc::c_int
        || (*k).upgr101 as libc::c_uint == UPGR101_REQUESTED as libc::c_int as libc::c_uint
                && (*k).httpcode == 101 as libc::c_int
        {
        #[cfg(DEBUGBUILD)]
        Curl_infof(
            data,
            b"HTTP/2 found, allow multiplexing\0" as *const u8 as *const libc::c_char,
        );
        (*(*conn).bundle).multiuse = 2 as libc::c_int;
    } else if (*conn).httpversion as libc::c_int >= 11 as libc::c_int
            && ((*conn).bits).close() == 0
        {
        #[cfg(DEBUGBUILD)]
        Curl_infof(
            data,
            b"HTTP 1.1 or later with persistent connection\0" as *const u8
                as *const libc::c_char,
        );
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
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 2 as libc::c_int);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                2 as libc::c_int,
                b"bad HTTP: No end-of-message indicator\0" as *const u8
                    as *const libc::c_char,
            );
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
                    #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                    Curl_conncontrol(conn, 2 as libc::c_int);
                    #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                    Curl_conncontrol(
                        conn,
                        2 as libc::c_int,
                        b"bad HTTP: No end-of-message indicator\0" as *const u8
                            as *const libc::c_char,
                    );
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
                #[cfg(not(CURL_DOES_CONVERSIONS))]
                if '\r' as i32 == *headp as libc::c_int {
                    headp = headp.offset(1);
                }
                #[cfg(not(CURL_DOES_CONVERSIONS))]
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
                        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                        Curl_conncontrol(conn, 2 as libc::c_int);
                        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                        Curl_conncontrol(
                            conn,
                            2 as libc::c_int,
                            b"HTTP: No end-of-message indicator\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
                #[cfg(USE_NTLM)]
                if ((*conn).bits).close() as libc::c_int != 0
                    && ((*data).req.httpcode == 401 as libc::c_int
                        && (*conn).http_ntlm_state as libc::c_uint
                            == NTLMSTATE_TYPE2 as libc::c_int as libc::c_uint
                        || (*data).req.httpcode == 407 as libc::c_int
                            && (*conn).proxy_ntlm_state as libc::c_uint
                                == NTLMSTATE_TYPE2 as libc::c_int as libc::c_uint)
                {
                    Curl_infof(
                        data,
                        b"Connection closure while negotiating auth (HTTP 1.0?)\0"
                            as *const u8 as *const libc::c_char,
                    );
                    let ref mut fresh89 = (*data).state;
                    (*fresh89).set_authproblem(1 as libc::c_int as bit);
                }
                #[cfg(USE_SPNEGO)]
                if ((*conn).bits).close() as libc::c_int != 0
                    && ((*data).req.httpcode == 401 as libc::c_int
                        && (*conn).http_negotiate_state as libc::c_uint
                            == GSS_AUTHRECV as libc::c_int as libc::c_uint
                        || (*data).req.httpcode == 407 as libc::c_int
                            && (*conn).proxy_negotiate_state as libc::c_uint
                                == GSS_AUTHRECV as libc::c_int as libc::c_uint)
                {
                    Curl_infof(
                        data,
                        b"Connection closure while negotiating auth (HTTP 1.0?)\0"
                            as *const u8 as *const libc::c_char,
                    );
                    let ref mut fresh89 = (*data).state;
                    (*fresh89).set_authproblem(1 as libc::c_int as bit);
                }
                #[cfg(USE_SPNEGO)]
                if (*conn).http_negotiate_state as libc::c_uint
                    == GSS_AUTHDONE as libc::c_int as libc::c_uint
                    && (*data).req.httpcode != 401 as libc::c_int
                {
                    (*conn).http_negotiate_state = GSS_AUTHSUCC;
                }
                #[cfg(USE_SPNEGO)]
                if (*conn).proxy_negotiate_state as libc::c_uint
                    == GSS_AUTHDONE as libc::c_int as libc::c_uint
                    && (*data).req.httpcode != 407 as libc::c_int
                {
                    (*conn).proxy_negotiate_state = GSS_AUTHSUCC;
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
                (*data)
                    .req
                    .deductheadercount = if 100 as libc::c_int <= (*k).httpcode
                    && 199 as libc::c_int >= (*k).httpcode
                {
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
                                        let ref mut fresh92 = (*data).state;
                                        (*fresh92).set_disableexpect(1 as libc::c_int as bit);
                                        #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
                                        if ((*data).req.newurl).is_null() {} else {
                                            __assert_fail(
                                                b"!data->req.newurl\0" as *const u8 as *const libc::c_char,
                                                b"http.c\0" as *const u8 as *const libc::c_char,
                                                4084 as libc::c_int as libc::c_uint,
                                                (*::std::mem::transmute::<
                                                    &[u8; 99],
                                                    &[libc::c_char; 99],
                                                >(
                                                    b"CURLcode Curl_http_readwrite_headers(struct Curl_easy *, struct connectdata *, ssize_t *, _Bool *)\0",
                                                ))
                                                    .as_ptr(),
                                            );
                                        }
                                        match () {
                                            #[cfg(not(CURLDEBUG))]
                                            _ => {
                                                (*data).req.newurl = Curl_cstrdup.expect("non-null function pointer")(
                                                    (*data).state.url,
                                                );
                                            }
                                            #[cfg(CURLDEBUG)]
                                            _ => {
                                                (*data).req.newurl = curl_dbg_strdup(
                                            (*data).state.url,
                                            4085 as libc::c_int,
                                            b"http.c\0" as *const u8 as *const libc::c_char,
                                        );
                                            }
                                        }                                        
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
                                                as *const u8 as *const libc::c_char,
                                        );
                                        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                                        Curl_conncontrol(conn, 2 as libc::c_int);
                                        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                                        Curl_conncontrol(
                                            conn,
                                            2 as libc::c_int,
                                            b"Stop sending data before everything sent\0" as *const u8
                                                as *const libc::c_char,
                                        );
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
                    // TODO 待测试
                    #[cfg(not(CURL_DISABLE_RSTP))]
                    let flag7: bool = ((*data).set).opt_no_body() != 0
                        || (*(*conn).handler).protocol
                            & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
                            != 0
                            && (*data).set.rtspreq as libc::c_uint
                                == RTSPREQ_DESCRIBE as libc::c_int as libc::c_uint
                        && (*k).size <= -(1 as libc::c_int) as libc::c_long;
                    #[cfg(CURL_DISABLE_RSTP)]
                    let flag7: bool = ((*data).set).opt_no_body() != 0;
                    // let flag7: bool = if cfg!(not(CURL_DISABLE_RSTP)) {
                    //     ((*data).set).opt_no_body() != 0
                    //     || (*(*conn).handler).protocol
                    //         & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
                    //         != 0
                    //     && (*data).set.rtspreq as libc::c_uint
                    //         == RTSPREQ_DESCRIBE as libc::c_int as libc::c_uint
                    //     && (*k).size <= -(1 as libc::c_int) as libc::c_long
                    // } else {
                    //     ((*data).set).opt_no_body() != 0
                    // };
                    if flag7
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
                    #[cfg(USE_NGHTTP2)]
                    let flag8: bool = 0 as libc::c_int as libc::c_long == (*k).maxdownload
                        && !((*(*conn).handler).protocol
                            & ((1 as libc::c_int) << 0 as libc::c_int
                                | (1 as libc::c_int) << 1 as libc::c_int)
                                as libc::c_uint
                            != 0
                            && (*conn).httpversion as libc::c_int == 20 as libc::c_int);
                    #[cfg(not(USE_NGHTTP2))]
                    let flag8: bool = 0 as libc::c_int as libc::c_long == (*k).maxdownload;
                    if flag8
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
                                10 | 11 => {
                                    (*conn).httpversion = httpversion as libc::c_uchar;
                                }
                                #[cfg(any(USE_NGHTTP2, USE_HYPER))]
                                20 => {
                                    (*conn).httpversion = httpversion as libc::c_uchar;
                                }
                                #[cfg(ENABLE_QUIC)]
                                30 => {
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
