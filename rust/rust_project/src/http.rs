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

const FIRSTSOCKET: i32 = 0;

const GETSOCK_WRITEBITSTART: i32 = 16;
fn GETSOCK_WRITESOCK(x: i32) -> i32 {
    return 1 << (GETSOCK_WRITEBITSTART + x);
}

const PORT_HTTP: i32 = 80;
const PORT_HTTPS: i32 = 443;

const CURLPROTO_HTTP: u32 = 1 << 0;
const CURLPROTO_HTTPS: u32 = 1 << 1;

const PROTOPT_SSL: u32 = 1 << 0;
const PROTOPT_CREDSPERREQUEST: u32 = 1 << 7;
const PROTOPT_ALPN_NPN: u32 = 1 << 8;
const PROTOPT_USERPWDCTRL: u32 = 1 << 13;

const CURLAUTH_NEGOTIATE: u64 = (1 as u64) << 2;
const CURLAUTH_BEARER: u64 = (1 as u64) << 6;
const CURLAUTH_DIGEST: u64 = (1 as u64) << 1;
const CURLAUTH_NTLM: u64 = (1 as u64) << 3;
const CURLAUTH_NTLM_WB: u64 = (1 as u64) << 5;
const CURLAUTH_BASIC: u64 = (1 as u64) << 0;
const CURLAUTH_AWS_SIGV4: u64 = (1 as u64) << 7;
const CURLAUTH_PICKNONE: u64 = 1 << 30;
const CURLAUTH_NONE: u64 = 0;

const HTTPREQ_GET: u32 = 0;
const HTTPREQ_POST: u32 = 1;
const HTTPREQ_POST_FORM: u32 = 2;
const HTTPREQ_POST_MIME: u32 = 3;
const HTTPREQ_PUT: u32 = 4;
const HTTPREQ_HEAD: u32 = 5;

const MIME_BODY_ONLY: u32 = 1 << 1;

const EXPECT_100_THRESHOLD: i64 = 1024 * 1024;

/*
 * HTTP handler interface.
 */
#[no_mangle]
pub static mut Curl_handler_http: Curl_handler = Curl_handler {
    /* scheme */
    scheme: b"HTTP\0" as *const u8 as *const libc::c_char,
    /* setup_connection */
    setup_connection: Some(
        http_setup_conn as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
    ),
    /* do_it */
    do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
    /* done */
    done: Some(Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode),
    /* do_more */
    do_more: None,
    /* connect_it */
    connect_it: Some(
        Curl_http_connect as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
    ),
    /* connecting */
    connecting: None,
    /* doing */
    doing: None,
    /* proto_getsock */
    proto_getsock: None,
    /* doing_getsock */
    doing_getsock: Some(
        http_getsock_do
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32,
    ),
    /* domore_getsock */
    domore_getsock: None,
    /* perform_getsock */
    perform_getsock: None,
    /* disconnect */
    disconnect: None,
    /* readwrite */
    readwrite: None,
    /* connection_check */
    connection_check: None,
    /* attach connection */
    attach: None,
    /* defport */
    defport: PORT_HTTP,
    /* protocol */
    protocol: CURLPROTO_HTTP,
    /* family */
    family: CURLPROTO_HTTP,
    /* flags */
    flags: PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL,
};

#[cfg(USE_SSL)]
/*
 * HTTPS handler interface.
 */
#[no_mangle]
pub static mut Curl_handler_https: Curl_handler = Curl_handler {
    /* scheme */
    scheme: b"HTTPS\0" as *const u8 as *const libc::c_char,
    /* setup_connection */
    setup_connection: Some(
        http_setup_conn as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
    ),
    /* do_it */
    do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
    /* done */
    done: Some(Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode),
    /* do_more */
    do_more: None,
    /* connect_it */
    connect_it: Some(
        Curl_http_connect as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
    ),
    /* connecting */
    connecting: Some(
        https_connecting as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
    ),
    /* doing */
    doing: None,
    /* proto_getsock */
    proto_getsock: Some(
        https_getsock
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32,
    ),
    /* doing_getsock */
    doing_getsock: Some(
        http_getsock_do
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32,
    ),
    /* domore_getsock */
    domore_getsock: None,
    /* perform_getsock */
    perform_getsock: None,
    /* disconnect */
    disconnect: None,
    /* readwrite */
    readwrite: None,
    /* connection_check */
    connection_check: None,
    /* attach connection */
    attach: None,
    /* defport */
    defport: PORT_HTTPS,
    /* protocol */
    protocol: CURLPROTO_HTTPS,
    /* family */
    family: CURLPROTO_HTTP,
    /* flags */
    flags: PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN_NPN | PROTOPT_USERPWDCTRL,
};

 extern "C" fn http_setup_conn(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    /* allocate the HTTP-specific struct for the Curl_easy, only to survive
    during this request */
    let mut http: *mut HTTP = 0 as *mut HTTP;
    unsafe{
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if ((*data).req.p.http).is_null() {
    } else {
        __assert_fail(
            b"data->req.p.http == ((void*)0)\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            179 as u32,
            (*::std::mem::transmute::<&[u8; 67], &[libc::c_char; 67]>(
                b"CURLcode http_setup_conn(struct Curl_easy *, struct connectdata *)\0",
            ))
            .as_ptr(),
        );
    }}

    #[cfg(not(CURLDEBUG))]
    let mut new_http: *mut HTTP =  unsafe{Curl_ccalloc.expect("non-null function pointer")(
        1 as size_t,
        ::std::mem::size_of::<HTTP>() as u64,
    ) as *mut HTTP};
    #[cfg(CURLDEBUG)]
    let mut new_http: *mut HTTP =  unsafe{curl_dbg_calloc(
        1 as size_t,
        ::std::mem::size_of::<HTTP>() as u64,
        181,
        b"http.c\0" as *const u8 as *const libc::c_char,
    ) as *mut HTTP};

    http = new_http;
    if http.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    unsafe{
    #[cfg(any(
        all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)),
        not(CURL_DISABLE_SMTP),
        not(CURL_DISABLE_IMAP)
    ))]
    Curl_mime_initpart(&mut (*http).form, data);
    (*data).req.p.http = http;
    if (*data).state.httpwant as i32 == CURL_HTTP_VERSION_3 as i32 {
        /* Only go HTTP/3 directly on HTTPS URLs. It needs a UDP socket and does
        the QUIC dance. */
        if (*(*conn).handler).flags & PROTOPT_SSL != 0 {
            (*conn).transport = TRNSPRT_QUIC;
        } else {
            Curl_failf(
                data,
                b"HTTP/3 requested for non-HTTPS URL\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_URL_MALFORMAT;
        }
    } else {
        /* if not already multi-using, setup connection details */
        if (*conn).easyq.size == 0 {
            Curl_http2_setup_conn(conn);
        }
        Curl_http2_setup_req(data);
    }}
    return CURLE_OK;
}

#[cfg(not(CURL_DISABLE_PROXY))]
/*
 * checkProxyHeaders() checks the linked list of custom proxy headers
 * if proxy headers are not available, then it will lookup into http header
 * link list
 *
 * It takes a connectdata struct as input to see if this is a proxy request or
 * not, as it then might check a different header list. Provide the header
 * prefix without colon!
 */
#[no_mangle]
pub  extern "C" fn Curl_checkProxyheaders(
    mut data: *mut Curl_easy,
    mut conn: *const connectdata,
    mut thisheader: *const libc::c_char,
) -> *mut libc::c_char {
    let mut head: *mut curl_slist = 0 as *mut curl_slist;
    let mut thislen: size_t = unsafe{strlen(thisheader)};

    head = unsafe{if ((*conn).bits).proxy() as i32 != 0 && ((*data).set).sep_headers() as i32 != 0 {
        (*data).set.proxyheaders
    } else {
        (*data).set.headers
    }};

    while !head.is_null() {
        if unsafe{Curl_strncasecompare((*head).data, thisheader, thislen) != 0
            && (*((*head).data).offset(thislen as isize) as i32 == ':' as i32
                || *((*head).data).offset(thislen as isize) as i32 == ';' as i32)}
        {
            return unsafe{(*head).data};
        }
        head = unsafe{(*head).next};
    }

    return 0 as *mut libc::c_char;
}

/* disabled */
#[cfg(CURL_DISABLE_PROXY)]
#[no_mangle]
pub extern "C" fn Curl_checkProxyheaders(
    mut data: *mut Curl_easy,
    mut conn: *const connectdata,
    mut thisheader: *const libc::c_char,
) -> *mut libc::c_char {
    return 0 as *mut libc::c_char;
}

/*
 * Strip off leading and trailing whitespace from the value in the
 * given HTTP header line and return a strdupped copy. Returns NULL in
 * case of allocation failure. Returns an empty string if the header value
 * consists entirely of whitespace.
 */
#[no_mangle]
pub  extern "C" fn Curl_copy_header_value(
    mut header: *const libc::c_char,
) -> *mut libc::c_char {
    let mut start: *const libc::c_char = 0 as *const libc::c_char;
    let mut end: *const libc::c_char = 0 as *const libc::c_char;
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;

    /* Find the end of the header name */
    while unsafe{*header as i32 != 0 && *header as i32 != ':' as i32} {
        header = unsafe{header.offset(1)};
    }

    if unsafe{*header != 0 }{
        /* Skip over colon */
        header = unsafe{header.offset(1)};
    }

    /* Find the first non-space letter */
    start = header;
    while unsafe{*start as i32 != 0 && Curl_isspace(*start as u8 as i32) != 0} {
        start = unsafe{start.offset(1)};
    }

    /* data is in the host encoding so
    use '\r' and '\n' instead of 0x0d and 0x0a */
    end = unsafe{strchr(start, '\r' as i32)};
    if end.is_null() {
        end = unsafe{strchr(start, '\n' as i32)};
    }
    if end.is_null() {
        end = unsafe{strchr(start, '\0' as i32)};
    }
    if end.is_null() {
        return 0 as *mut libc::c_char;
    }

    /* skip all trailing space letters */
    while end > start && unsafe{Curl_isspace(*end as u8 as i32) != 0} {
        end = unsafe{end.offset(-1)};
    }

    /* get length of the type */
    len = unsafe{(end.offset_from(start) as i64 + 1 as i64) as size_t};
    #[cfg(not(CURLDEBUG))]
    let mut new_value: *mut libc::c_char =
    unsafe{Curl_cmalloc.expect("non-null function pointer")(len.wrapping_add(1 as u64))
            as *mut libc::c_char};
    #[cfg(CURLDEBUG)]
    let mut new_value: *mut libc::c_char = unsafe{curl_dbg_malloc(
        len.wrapping_add(1 as u64),
        282,
        b"http.c\0" as *const u8 as *const libc::c_char,
    ) as *mut libc::c_char};
    value = new_value;
    if value.is_null() {
        return 0 as *mut libc::c_char;
    }
    unsafe{ memcpy(
        value as *mut libc::c_void,
        start as *const libc::c_void,
        len,
    );
    *value.offset(len as isize) = 0 as libc::c_char;} /* null-terminate */
    return value;
}

#[cfg(not(CURL_DISABLE_HTTP_AUTH))]
/*
 * http_output_basic() sets up an Authorization: header (or the proxy version)
 * for HTTP Basic authentication.
 *
 * Returns CURLcode.
 */
 extern "C" fn http_output_basic(mut data: *mut Curl_easy, mut proxy: bool) -> CURLcode {
    let mut size: size_t = 0 as size_t;
    let mut authorization: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut userp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut user: *const libc::c_char = 0 as *const libc::c_char;
    let mut pwd: *const libc::c_char = 0 as *const libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;

    /* credentials are unique per transfer for HTTP, do not use the ones for the
    connection */
    if proxy {
        match () {
            #[cfg(not(CURL_DISABLE_PROXY))]
            _ => {
                userp = unsafe{&mut (*data).state.aptr.proxyuserpwd};
                user = unsafe{(*data).state.aptr.proxyuser};
                pwd = unsafe{(*data).state.aptr.proxypasswd};
            }
            #[cfg(CURL_DISABLE_PROXY)]
            _ => {
                return CURLE_NOT_BUILT_IN;
            }
        }
    } else {
        userp = unsafe{&mut (*data).state.aptr.userpwd};
        user = unsafe{(*data).state.aptr.user};
        pwd = unsafe{(*data).state.aptr.passwd};
    }

    out =unsafe{ curl_maprintf(
        b"%s:%s\0" as *const u8 as *const libc::c_char,
        user,
        if !pwd.is_null() {
            pwd
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    )};
    if out.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }

    result = unsafe{Curl_base64_encode(data, out, strlen(out), &mut authorization, &mut size)};
    if !(result as u64 != 0) {
        if authorization.is_null() {
            result = CURLE_REMOTE_ACCESS_DENIED;
        } else {unsafe{
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                *userp as *mut libc::c_void,
                339 as i32,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            *userp = curl_maprintf(
                b"%sAuthorization: Basic %s\r\n\0" as *const u8 as *const libc::c_char,
                if proxy as i32 != 0 {
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
                343 as i32,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            if (*userp).is_null() {
                result = CURLE_OUT_OF_MEMORY;
            }}
        }
    }
    unsafe{
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        out as *mut libc::c_void,
        350 as i32,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );}
    return result;
}

/*
 * http_output_bearer() sets up an Authorization: header
 * for HTTP Bearer authentication.
 *
 * Returns CURLcode.
 */
#[cfg(not(CURL_DISABLE_HTTP_AUTH))]
 extern "C" fn http_output_bearer(mut data: *mut Curl_easy) -> CURLcode {
    let mut userp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut result: CURLcode = CURLE_OK;

    userp = unsafe{&mut (*data).state.aptr.userpwd};
    unsafe{
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        *userp as *mut libc::c_void,
        366,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    *userp = curl_maprintf(
        b"Authorization: Bearer %s\r\n\0" as *const u8 as *const libc::c_char,
        (*data).set.str_0[STRING_BEARER as usize],
    );}

    if unsafe{(*userp).is_null()} {
        result = CURLE_OUT_OF_MEMORY;
    }

    return result;
}

/* pickoneauth() selects the most favourable authentication method from the
 * ones available and the ones we want.
 *
 * return TRUE if one was picked
 */
 extern "C" fn pickoneauth(mut pick: *mut auth, mut mask: u64) -> bool {
    let mut picked: bool = false;
    
    /* only deal with authentication we want */
    let mut avail: u64 = unsafe{(*pick).avail & (*pick).want & mask};
    picked = true;

    /* The order of these checks is highly relevant, as this will be the order
    of preference in case of the existence of multiple accepted types. */
    unsafe{
    if avail & CURLAUTH_NEGOTIATE != 0 {
        (*pick).picked = CURLAUTH_NEGOTIATE;
    } else if avail & CURLAUTH_BEARER != 0 {
        (*pick).picked = CURLAUTH_BEARER;
    } else if avail & CURLAUTH_DIGEST != 0 {
        (*pick).picked = CURLAUTH_DIGEST;
    } else if avail & CURLAUTH_NTLM != 0 {
        (*pick).picked = CURLAUTH_NTLM;
    } else if avail & CURLAUTH_NTLM_WB != 0 {
        (*pick).picked = CURLAUTH_NTLM_WB;
    } else if avail & CURLAUTH_BASIC != 0 {
        (*pick).picked = CURLAUTH_BASIC;
    } else if avail & CURLAUTH_AWS_SIGV4 != 0 {
        (*pick).picked = CURLAUTH_AWS_SIGV4;
    } else {
        (*pick).picked = CURLAUTH_PICKNONE; /* we select to use nothing */
        picked = false;
    }
    (*pick).avail = CURLAUTH_NONE; /* clear it here */
    }
    return picked;
}

/*
 * http_perhapsrewind()
 *
 * If we are doing POST or PUT {
 *   If we have more data to send {
 *     If we are doing NTLM {
 *       Keep sending since we must not disconnect
 *     }
 *     else {
 *       If there is more than just a little data left to send, close
 *       the current connection by force.
 *     }
 *   }
 *   If we have sent any data {
 *     If we don't have track of all the data {
 *       call app to tell it to rewind
 *     }
 *     else {
 *       rewind internally so that the operation can restart fine
 *     }
 *   }
 * }
 */
 extern "C" fn http_perhapsrewind(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut http: *mut HTTP = unsafe{(*data).req.p.http};
    let mut bytessent: curl_off_t = 0;
    let mut expectsend: curl_off_t = -1 as curl_off_t; /* default is unknown */

    if http.is_null() {
        /* If this is still NULL, we have not reach very far and we can safely
        skip this rewinding stuff */
        return CURLE_OK;
    }

    match unsafe{(*data).state.httpreq as u32} {
        // 0 | 5 => return CURLE_OK,
        HTTPREQ_GET | HTTPREQ_HEAD => return CURLE_OK,
        _ => {}
    }

    bytessent = unsafe{(*data).req.writebytecount};

    // todo 解决clippy错误，代码通过测试后就可以删掉注释
    if unsafe{((*conn).bits).authneg() != 0 || ((*conn).bits).protoconnstart() == 0} {
        /* This is a state where we are known to be negotiating and we don't send
        any data then. */
        expectsend = 0 as curl_off_t;
    // } else if ((*conn).bits).protoconnstart() == 0 {
    /* HTTP CONNECT in progress: there is no body */
    //     expectsend = 0 as curl_off_t;
    } else {
        match unsafe{(*data).state.httpreq as u32} {
            /* figure out how much data we are expected to send */
            HTTPREQ_POST | HTTPREQ_PUT => {
                if unsafe{(*data).state.infilesize != -1 as i64} {
                    expectsend = unsafe{(*data).state.infilesize};
                }
            }
            HTTPREQ_POST_FORM | HTTPREQ_POST_MIME => {
                expectsend = unsafe{(*http).postsize};
            }
            _ => {}
        }
    }

    unsafe{ (*conn).bits.set_rewindaftersend(0 as bit); }/* default */

    if expectsend == -1 as i64 || expectsend > bytessent {
        match () {
            #[cfg(USE_NTLM)]
            /* There is still data left to send */
            _ => {unsafe{
                if (*data).state.authproxy.picked == CURLAUTH_NTLM
                    || (*data).state.authhost.picked == CURLAUTH_NTLM
                    || (*data).state.authproxy.picked == CURLAUTH_NTLM_WB
                    || (*data).state.authhost.picked == CURLAUTH_NTLM_WB
                {
                    if expectsend - bytessent < 2000 as i64
                        || (*conn).http_ntlm_state as u32 != NTLMSTATE_NONE as u32
                        || (*conn).proxy_ntlm_state as u32 != NTLMSTATE_NONE as u32
                    {
                        /* The NTLM-negotiation has started *OR* there is just a little (<2K)
                        data left to send, keep on sending. */

                        /* rewind data when completely done sending! */
                        if ((*conn).bits).authneg() == 0 && (*conn).writesockfd != -1 {
                            (*conn).bits.set_rewindaftersend(1 as bit);
                            Curl_infof(
                                data,
                                b"Rewind stream after send\0" as *const u8 as *const libc::c_char,
                            );
                        }

                        return CURLE_OK;
                    }

                    if ((*conn).bits).close() != 0 {
                        /* this is already marked to get closed */
                        return CURLE_OK;
                    }
                    Curl_infof(
                        data,
                        b"NTLM send, close instead of sending %ld bytes\0" as *const u8
                            as *const libc::c_char,
                        expectsend - bytessent,
                    );
                }}
            }
            #[cfg(not(USE_NTLM))]
            _ => {}
        }
        // TODO 待测试
        match () {
            #[cfg(USE_SPNEGO)]
            /* There is still data left to send */
            _ => {unsafe{
                if (*data).state.authproxy.picked == CURLAUTH_NEGOTIATE
                    || (*data).state.authhost.picked == CURLAUTH_NEGOTIATE
                {
                    if expectsend - bytessent < 2000 as i64
                        || (*conn).http_negotiate_state as u32 != GSS_AUTHNONE as u32
                        || (*conn).proxy_negotiate_state as u32 != GSS_AUTHNONE as u32
                    {
                        /* The NEGOTIATE-negotiation has started *OR*
                        there is just a little (<2K) data left to send, keep on sending. */

                        /* rewind data when completely done sending! */
                        if ((*conn).bits).authneg() == 0 && (*conn).writesockfd != -1 {
                            (*conn).bits.set_rewindaftersend(1 as bit);
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
                }}
            }
            #[cfg(not(USE_SPNEGO))]
            _ => {}
        }
        unsafe{
        /* This is not NEGOTIATE/NTLM or many bytes left to send: close */
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 2);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            2,
            b"Mid-auth HTTP and much data left to send\0" as *const u8 as *const libc::c_char,
        );
        (*data).req.size = 0 as curl_off_t; /* don't download any more than 0 bytes */
        /* There still is data left to send, but this connection is marked for
        closure so we can safely do the rewind right now */
    }
    }
    if bytessent != 0 {
        /* we rewind now at once since if we already sent something */
        return unsafe{Curl_readrewind(data)};
    }

    return CURLE_OK;
}

/*
 * Curl_http_auth_act() gets called when all HTTP headers have been received
 * and it checks what authentication methods that are available and decides
 * which one (if any) to use. It will set 'newurl' if an auth method was
 * picked.
 */
#[no_mangle]
pub  extern "C" fn Curl_http_auth_act(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = unsafe{(*data).conn};
    let mut pickhost: bool = false;
    let mut pickproxy: bool = false;
    let mut result: CURLcode = CURLE_OK;
    let mut authmask: u64 = !(0 as u64);

    if unsafe{((*data).set.str_0[STRING_BEARER as usize]).is_null()} {
        authmask &= !CURLAUTH_BEARER;
    }

    if unsafe{100 <= (*data).req.httpcode && 199 >= (*data).req.httpcode} {
        /* this is a transient response code, ignore */
        return CURLE_OK;
    }

    if unsafe{((*data).state).authproblem() != 0} {
        return (if unsafe{((*data).set).http_fail_on_error() as i32 != 0} {
            CURLE_HTTP_RETURNED_ERROR as i32
        } else {
            CURLE_OK as i32
        }) as CURLcode;
    }

    if unsafe{(((*conn).bits).user_passwd() as i32 != 0
        || !((*data).set.str_0[STRING_BEARER as usize]).is_null())
        && ((*data).req.httpcode == 401
            || ((*conn).bits).authneg() as i32 != 0 && (*data).req.httpcode < 300)}
    {
        pickhost = unsafe{pickoneauth(&mut (*data).state.authhost, authmask)};
        if !pickhost {
            unsafe{ (*data).state.set_authproblem(1 as bit);}
        }

        if unsafe{(*data).state.authhost.picked == CURLAUTH_NTLM && (*conn).httpversion as i32 > 11 }{
            unsafe{Curl_infof(
                data,
                b"Forcing HTTP/1.1 for NTLM\0" as *const u8 as *const libc::c_char,
            );

            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1,
                b"Force HTTP/1.1 connection\0" as *const u8 as *const libc::c_char,
            );
            (*data).state.httpwant = CURL_HTTP_VERSION_1_1 as u8;}
        }
    }
    unsafe{
    #[cfg(not(CURL_DISABLE_PROXY))]
    if ((*conn).bits).proxy_user_passwd() as i32 != 0
        && ((*data).req.httpcode == 407
            || ((*conn).bits).authneg() as i32 != 0 && (*data).req.httpcode < 300)
    {
        pickproxy = pickoneauth(&mut (*data).state.authproxy, authmask & !((1 as u64) << 6));
        if !pickproxy {
            (*data).state.set_authproblem(1 as bit);
        }
    }}
    if pickhost as i32 != 0 || pickproxy as i32 != 0 {
        if unsafe{(*data).state.httpreq as u32 != HTTPREQ_GET as u32
            && (*data).state.httpreq as u32 != HTTPREQ_HEAD as u32
            && ((*conn).bits).rewindaftersend() == 0}
        {
            result = http_perhapsrewind(data, conn);
            if result as u64 != 0 {
                return result;
            }
        }
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                /* In case this is GSS auth, the newurl field is already allocated so
                we must make sure to free it before allocating a new one. As figured
                out in bug #2284386 */
                unsafe{
                Curl_cfree.expect("non-null function pointer")(
                    (*data).req.newurl as *mut libc::c_void,
                );
                (*data).req.newurl = 0 as *mut libc::c_char;
                /* clone URL */
                (*data).req.newurl =
                    Curl_cstrdup.expect("non-null function pointer")((*data).state.url);}
            }
            #[cfg(CURLDEBUG)]
            _ => {unsafe{
                /* In case this is GSS auth, the newurl field is already allocated so
                we must make sure to free it before allocating a new one. As figured
                out in bug #2284386 */
                curl_dbg_free(
                    (*data).req.newurl as *mut libc::c_void,
                    626,
                    b"http.c\0" as *const u8 as *const libc::c_char,
                );
                (*data).req.newurl = 0 as *mut libc::c_char;
                /* clone URL */
                (*data).req.newurl = curl_dbg_strdup(
                    (*data).state.url,
                    627,
                    b"http.c\0" as *const u8 as *const libc::c_char,
                );}
            }
        }
        if unsafe{((*data).req.newurl).is_null()} {
            return CURLE_OUT_OF_MEMORY;
        }
    } else if unsafe{(*data).req.httpcode < 300
        && ((*data).state.authhost).done() == 0
        && ((*conn).bits).authneg() as i32 != 0}
    {
        /* no (known) authentication available,
        authentication is not "done" yet and
        no authentication seems to be required and
        we didn't try HEAD or GET */
        if unsafe{(*data).state.httpreq as u32 != HTTPREQ_GET as u32
            && (*data).state.httpreq as u32 != HTTPREQ_HEAD as u32}
        {
            #[cfg(not(CURLDEBUG))]
            let new_url: *mut libc::c_char =
            unsafe{ Curl_cstrdup.expect("non-null function pointer")((*data).state.url)};
            #[cfg(CURLDEBUG)]
            let new_url: *mut libc::c_char = unsafe{curl_dbg_strdup(
                (*data).state.url,
                640,
                b"http.c\0" as *const u8 as *const libc::c_char,
            )};
            unsafe{(*data).req.newurl = new_url;} /* clone URL */
            if unsafe{((*data).req.newurl).is_null()} {
                return CURLE_OUT_OF_MEMORY;
            }
            unsafe{ (*data).state.authhost.set_done(1 as bit)};
        }
    }
    if unsafe{http_should_fail(data)} {
        unsafe{Curl_failf(
            data,
            b"The requested URL returned error: %d\0" as *const u8 as *const libc::c_char,
            (*data).req.httpcode,
        );}
        result = CURLE_HTTP_RETURNED_ERROR;
    }
    return result;
}

#[cfg(not(CURL_DISABLE_HTTP_AUTH))]
/*
 * Output the correct authentication header depending on the auth type
 * and whether or not it is to a proxy.
 */
 extern "C" fn output_auth_headers(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut authstatus: *mut auth,
    mut request: *const libc::c_char,
    mut path: *const libc::c_char,
    mut proxy: bool,
) -> CURLcode {
    let mut auth: *const libc::c_char = 0 as *const libc::c_char;
    let mut result: CURLcode = CURLE_OK;

    let flag1: bool = if cfg!(not(CURL_DISABLE_CRYPTO_AUTH)) {
        unsafe{(*authstatus).picked == CURLAUTH_AWS_SIGV4}
    } else {
        false
    };
    let flag2: bool = if cfg!(USE_SPNEGO) {
        unsafe{ (*authstatus).picked == CURLAUTH_NEGOTIATE}
    } else {
        false
    };
    let flag3: bool = if cfg!(USE_NTLM) {
        unsafe{(*authstatus).picked == CURLAUTH_NTLM}
    } else {
        false
    };
    let flag4: bool = if cfg!(all(USE_NTLM, NTLM_WB_ENABLED)) {
        unsafe{(*authstatus).picked == CURLAUTH_NTLM_WB}
    } else {
        false
    };
    let flag5: bool = if cfg!(not(CURL_DISABLE_CRYPTO_AUTH)) {
        unsafe{(*authstatus).picked == CURLAUTH_DIGEST}
    } else {
        false
    };
    if flag1 {
        auth = b"AWS_SIGV4\0" as *const u8 as *const libc::c_char;
        result = unsafe{Curl_output_aws_sigv4(data, proxy)};
        if result as u64 != 0 {
            return result;
        }
    } else if flag2 {
        auth = b"Negotiate\0" as *const u8 as *const libc::c_char;
        result = unsafe{Curl_output_negotiate(data, conn, proxy)};
        if result as u64 != 0 {
            return result;
        }
    } else if flag3 {
        auth = b"NTLM\0" as *const u8 as *const libc::c_char;
        result = unsafe{Curl_output_ntlm(data, proxy)};
        if result as u64 != 0 {
            return result;
        }
    } else if flag4 {
        auth = b"NTLM_WB\0" as *const u8 as *const libc::c_char;
        result = unsafe{Curl_output_ntlm_wb(data, conn, proxy)};
        if result as u64 != 0 {
            return result;
        }
    } else if flag5 {
        auth = b"Digest\0" as *const u8 as *const libc::c_char;
        result = unsafe{Curl_output_digest(data, proxy, request as *const u8, path as *const u8)};
        if result as u64 != 0 {
            return result;
        }
    } else if unsafe{(*authstatus).picked == CURLAUTH_BASIC} {
        #[cfg(not(CURL_DISABLE_PROXY))]
        let flag6: bool = unsafe{proxy as i32 != 0
            && ((*conn).bits).proxy_user_passwd() as i32 != 0
            && (Curl_checkProxyheaders(
                data,
                conn,
                b"Proxy-authorization\0" as *const u8 as *const libc::c_char,
            ))
            .is_null()
            || !proxy
                && ((*conn).bits).user_passwd() as i32 != 0
                && (Curl_checkheaders(
                    data,
                    b"Authorization\0" as *const u8 as *const libc::c_char,
                ))
                .is_null()};
        #[cfg(CURL_DISABLE_PROXY)]
        let flag6: bool = unsafe{!proxy
            && ((*conn).bits).user_passwd() as i32 != 0
            && (Curl_checkheaders(data, b"Authorization\0" as *const u8 as *const libc::c_char))
                .is_null()};
        if flag6 {
            auth = b"Basic\0" as *const u8 as *const libc::c_char;
            result = http_output_basic(data, proxy);
            if result as u64 != 0 {
                return result;
            }
        }

        /* NOTE: this function should set 'done' TRUE, as the other auth
        functions work that way */
        unsafe{ (*authstatus).set_done(1 as bit);}
    }

    if unsafe{(*authstatus).picked == CURLAUTH_BEARER} {
        /* Bearer */
        if unsafe{!proxy
            && !((*data).set.str_0[STRING_BEARER as usize]).is_null()
            && (Curl_checkheaders(data, b"Authorization\0" as *const u8 as *const libc::c_char))
                .is_null()}
        {
            auth = b"Bearer\0" as *const u8 as *const libc::c_char;
            result = http_output_bearer(data);
            if result as u64 != 0 {
                return result;
            }
        }

        /* NOTE: this function should set 'done' TRUE, as the other auth
        functions work that way */
        unsafe{(*authstatus).set_done(1 as bit);}
    }
    if !auth.is_null() {unsafe{
        #[cfg(not(CURL_DISABLE_PROXY))]
        Curl_infof(
            data,
            b"%s auth using %s with user '%s'\0" as *const u8 as *const libc::c_char,
            if proxy as i32 != 0 {
                b"Proxy\0" as *const u8 as *const libc::c_char
            } else {
                b"Server\0" as *const u8 as *const libc::c_char
            },
            auth,
            if proxy as i32 != 0 {
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
        (*authstatus).set_multipass((if (*authstatus).done() == 0 { 1 } else { 0 }) as bit)};
    } else {
        unsafe{ (*authstatus).set_multipass(0 as bit)};
    }
    return CURLE_OK;
}

/**
 * Curl_http_output_auth() setups the authentication headers for the
 * host/proxy and the correct authentication
 * method. data->state.authdone is set to TRUE when authentication is
 * done.
 *
 * @param conn all information about the current connection
 * @param request pointer to the request keyword
 * @param path pointer to the requested path; should include query part
 * @param proxytunnel boolean if this is the request setting up a "proxy
 * tunnel"
 *
 * @returns CURLcode
 */
#[cfg(not(CURL_DISABLE_HTTP_AUTH))]
#[no_mangle]
pub  extern "C" fn Curl_http_output_auth(
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
        unsafe{__assert_fail(
            b"data\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            805 as u32,
            (*::std::mem::transmute::<
                &[u8; 122],
                &[libc::c_char; 122],
            >(
                b"CURLcode Curl_http_output_auth(struct Curl_easy *, struct connectdata *, const char *, Curl_HttpReq, const char *, _Bool)\0",
            ))
                .as_ptr(),
        );}
    }
    authhost = unsafe{&mut (*data).state.authhost};
    authproxy = unsafe{&mut (*data).state.authproxy};
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag1: bool =unsafe{ ((*conn).bits).httpproxy() as i32 != 0
        && ((*conn).bits).proxy_user_passwd() as i32 != 0
        || ((*conn).bits).user_passwd() as i32 != 0
        || !((*data).set.str_0[STRING_BEARER as usize]).is_null()};
    #[cfg(CURL_DISABLE_PROXY)]
    let flag1: bool = unsafe{((*conn).bits).user_passwd() as i32 != 0
        || !((*data).set.str_0[STRING_BEARER as usize]).is_null()};
    if flag1 {
    } else {
        unsafe{ (*authhost).set_done(1 as bit);
        (*authproxy).set_done(1 as bit);}
        return CURLE_OK;
    }
    if unsafe{(*authhost).want != 0 && (*authhost).picked == 0} {
        /* The app has selected one or more methods, but none has been picked
        so far by a server round-trip. Then we set the picked one to the
        want one, and if this is one single bit it'll be used instantly. */
        unsafe{ (*authhost).picked = (*authhost).want;}
    }
    if unsafe{(*authproxy).want != 0 && (*authproxy).picked == 0} {
        /* The app has selected one or more methods, but none has been picked so
        far by a proxy round-trip. Then we set the picked one to the want one,
        and if this is one single bit it'll be used instantly. */
        unsafe{ (*authproxy).picked = (*authproxy).want;}
    }
    match () {
        #[cfg(not(CURL_DISABLE_PROXY))]
        /* Send proxy authentication header if needed */
        _ => {
    if unsafe{((*conn).bits).httpproxy() as i32 != 0
        && ((*conn).bits).tunnel_proxy() == proxytunnel as bit}
    {
                result = output_auth_headers(data, conn, authproxy, request, path, 1 as i32 != 0);
        if result as u64 != 0 {
            return result;
        }
    } else {
        unsafe{(*authproxy).set_done(1 as bit);}
    }
        }
        /* CURL_DISABLE_PROXY */
        #[cfg(CURL_DISABLE_PROXY)]
        /* we have no proxy so let's pretend we're done authenticating
        with it */
        _ => {
            unsafe{ (*authproxy).set_done(1 as i32 as bit);}
        }
    }
    #[cfg(not(CURL_DISABLE_NETRC))]
    let flag2: bool = unsafe{((*data).state).this_is_a_follow() == 0
        || ((*conn).bits).netrc() as i32 != 0
        || ((*data).state.first_host).is_null()
        || ((*data).set).allow_auth_to_other_hosts() as i32 != 0
        || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0};

    /* To prevent the user+password to get sent to other than the original
    host due to a location-follow, we do some weirdo checks here */
    #[cfg(CURL_DISABLE_NETRC)]
    let flag2: bool = unsafe{((*data).state).this_is_a_follow() == 0
        || ((*data).state.first_host).is_null()
        || ((*data).set).allow_auth_to_other_hosts() as i32 != 0
        || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0};
    if flag2 {
        result = output_auth_headers(data, conn, authhost, request, path, 0 as i32 != 0);
    } else {
        unsafe{(*authhost).set_done(1 as bit);}
    }
    if unsafe{ ((*authhost).multipass() as i32 != 0 && (*authhost).done() == 0
        || (*authproxy).multipass() as i32 != 0 && (*authproxy).done() == 0)
        && httpreq as u32 != HTTPREQ_GET as u32
        && httpreq as u32 != HTTPREQ_HEAD as u32}
    {
        let ref mut fresh8 = unsafe{(*conn).bits};
        (*fresh8).set_authneg(1 as bit);
    } else {
        let ref mut fresh9 = unsafe{(*conn).bits};
        (*fresh9).set_authneg(0 as bit);
    }
    return result;
}

/* when disabled */
#[cfg(CURL_DISABLE_HTTP_AUTH)]
#[no_mangle]
pub  extern "C" fn Curl_http_output_auth(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut request: *const libc::c_char,
    mut httpreq: Curl_HttpReq,
    mut path: *const libc::c_char,
    mut proxytunnel: bool,
) -> CURLcode {
    return CURLE_OK;
}

/*
 * Curl_http_input_auth() deals with Proxy-Authenticate: and WWW-Authenticate:
 * headers. They are dealt with both in the transfer.c main loop and in the
 * proxy CONNECT loop.
 */
 extern "C" fn is_valid_auth_separator(mut ch: libc::c_char) -> i32 {
    return (ch as i32 == '\0' as i32
        || ch as i32 == ',' as i32
        || unsafe{Curl_isspace(ch as i32) != 0}) as i32;
}

#[no_mangle]
pub  extern "C" fn Curl_http_input_auth(
    mut data: *mut Curl_easy,
    mut proxy: bool,
    mut auth: *const libc::c_char,
) -> CURLcode {
    /*
     * This resource requires authentication
     */
    let mut conn: *mut connectdata = unsafe{(*data).conn};

    #[cfg(USE_SPNEGO)]
    let mut negstate: *mut curlnegotiate = if proxy as i32 != 0 {
        unsafe{ &mut (*conn).proxy_negotiate_state}
    } else {
        unsafe{ &mut (*conn).http_negotiate_state}
    };
    let mut availp: *mut u64 = 0 as *mut u64;
    let mut authp: *mut auth = 0 as *mut auth;

    if proxy {
        availp = unsafe{&mut (*data).info.proxyauthavail};
        authp = unsafe{&mut (*data).state.authproxy};
    } else {
        availp =unsafe{ &mut (*data).info.httpauthavail};
        authp = unsafe{&mut (*data).state.authhost};
    }

    /*
     * Here we check if we want the specific single authentication (using ==) and
     * if we do, we initiate usage of it.
     *
     * If the provided authentication is wanted as one out of several accepted
     * types (using &), we OR this authentication type to the authavail
     * variable.
     *
     * Note:
     *
     * ->picked is first set to the 'want' value (one or more bits) before the
     * request is sent, and then it is again set _after_ all response 401/407
     * headers have been received but then only to a single preferred method
     * (bit).
     */
    while unsafe{*auth != 0 }{
        #[cfg(USE_SPNEGO)]
        let flag1: bool = unsafe{curl_strnequal(
            b"Negotiate\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"Negotiate\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(9 as i32 as isize)) != 0};
        #[cfg(not(USE_SPNEGO))]
        let flag1: bool = false;
        #[cfg(USE_NTLM)]
        let flag2: bool = unsafe{curl_strnequal(
            b"NTLM\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"NTLM\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(4 as isize)) != 0};
        #[cfg(not(USE_NTLM))]
        let flag2: bool = false;
        #[cfg(not(CURL_DISABLE_CRYPTO_AUTH))]
        let flag3: bool = unsafe{curl_strnequal(
            b"Digest\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"Digest\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(6 as isize)) != 0};
        #[cfg(CURL_DISABLE_CRYPTO_AUTH)]
        let flag3: bool = false;
        if flag1 {
            match () {
                #[cfg(USE_SPNEGO)]
                _ => {unsafe{
                    if (*authp).avail & (1 as u64) << 2 != 0
                        || Curl_auth_is_spnego_supported() as i32 != 0
                    {
                        *availp |= (1 as u64) << 2;
                        (*authp).avail |= (1 as u64) << 2;
                        if (*authp).picked == (1 as u64) << 2 {
                            let mut result: CURLcode =
                                Curl_input_negotiate(data, conn, proxy, auth);
                            if result as u64 == 0 {
                                (*data).req.newurl = Curl_cstrdup
                                    .expect("non-null function pointer")(
                                    (*data).state.url
                                );
                                if ((*data).req.newurl).is_null() {
                                    return CURLE_OUT_OF_MEMORY;
                                }
                                (*data).state.set_authproblem(0 as bit);
                                *negstate = GSS_AUTHRECV;
                            } else {
                                (*data).state.set_authproblem(1 as bit);
                            }
                        }
                    }}
                }
                #[cfg(not(USE_SPNEGO))]
                _ => {}
            }
            // if (*authp).avail & (1 as i32 as u64) << 2 as i32
            //     != 0 || Curl_auth_is_spnego_supported() as i32 != 0
            // {
            //     *availp |= (1 as i32 as u64) << 2 as i32;
            //     (*authp).avail
            //         |= (1 as i32 as u64) << 2 as i32;
            //     if (*authp).picked
            //         == (1 as i32 as u64) << 2 as i32
            //     {
            //         let mut result: CURLcode = Curl_input_negotiate(
            //             data,
            //             conn,
            //             proxy,
            //             auth,
            //         );
            //         if result as u64 == 0 {
            //             (*data).req.newurl = Curl_cstrdup
            //                 .expect("non-null function pointer")((*data).state.url);
            //             if ((*data).req.newurl).is_null() {
            //                 return CURLE_OUT_OF_MEMORY;
            //             }
            //             (*data).state.set_authproblem(0 as i32 as bit);
            //             *negstate = GSS_AUTHRECV;
            //         } else {
            //             (*data).state.set_authproblem(1 as i32 as bit);
            //         }
            //     }
            // }
        } else if flag2 {
            if unsafe{(*authp).avail & CURLAUTH_NTLM != 0
                || (*authp).avail & CURLAUTH_NTLM_WB != 0
                || Curl_auth_is_ntlm_supported() as i32 != 0}
            {
                unsafe{*availp |= CURLAUTH_NTLM;
                (*authp).avail |= CURLAUTH_NTLM;}
                if unsafe{(*authp).picked == CURLAUTH_NTLM || (*authp).picked == CURLAUTH_NTLM_WB} {
                    let mut result_0: CURLcode = unsafe{Curl_input_ntlm(data, proxy, auth)};
                    if result_0 as u64 == 0 {
                        unsafe{(*data).state.set_authproblem(0 as bit)};
                        if unsafe{ (*authp).picked == CURLAUTH_NTLM_WB} {
                            unsafe{ *availp &= !CURLAUTH_NTLM;
                            (*authp).avail &= !CURLAUTH_NTLM;
                            *availp |= CURLAUTH_NTLM_WB;
                            (*authp).avail |= CURLAUTH_NTLM_WB;}
                            result_0 = unsafe{Curl_input_ntlm_wb(data, conn, proxy, auth)};
                            if result_0 as u64 != 0 {
                                unsafe{Curl_infof(
                                    data,
                                    b"Authentication problem. Ignoring this.\0" as *const u8
                                        as *const libc::c_char,
                                );
                                (*data).state.set_authproblem(1 as bit);}
                            }
                        }
                    } else {
                        unsafe{Curl_infof(
                            data,
                            b"Authentication problem. Ignoring this.\0" as *const u8
                                as *const libc::c_char,
                        );
                        (*data).state.set_authproblem(1 as bit);}
                    }
                }
            }
        } else if flag3 {
            match () {
                #[cfg(not(CURL_DISABLE_CRYPTO_AUTH))]
                _ => {
                    if unsafe{(*authp).avail & CURLAUTH_DIGEST != 0 as u64} {
                        unsafe{Curl_infof(
                            data,
                            b"Ignoring duplicate digest auth header.\0" as *const u8
                                as *const libc::c_char,
                        );}
                    } else if unsafe{Curl_auth_is_digest_supported()} {
                        let mut result: CURLcode = CURLE_OK;

                        unsafe{*availp |= CURLAUTH_DIGEST;
                        (*authp).avail |= CURLAUTH_DIGEST;}

                        /* We call this function on input Digest headers even if Digest
                         * authentication isn't activated yet, as we need to store the
                         * incoming data from this header in case we are going to use
                         * Digest */
                        result = unsafe{Curl_input_digest(data, proxy, auth)};
                        if result as u64 != 0 {
                            unsafe{ Curl_infof(
                                data,
                                b"Authentication problem. Ignoring this.\0" as *const u8
                                    as *const libc::c_char,
                            );
                            (*data).state.set_authproblem(1 as bit);}
                        }
                    }
                }
                #[cfg(CURL_DISABLE_CRYPTO_AUTH)]
                _ => {}
            }
        } else if unsafe{curl_strnequal(
            b"Basic\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"Basic\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(5 as isize)) != 0}
        {
            unsafe{ *availp |= CURLAUTH_BASIC;
            (*authp).avail |= CURLAUTH_BASIC;}
            if unsafe{(*authp).picked == CURLAUTH_BASIC }{
                /* We asked for Basic authentication but got a 40X back
                anyway, which basically means our name+password isn't
                valid. */
                unsafe{ (*authp).avail = CURLAUTH_NONE;
                Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8 as *const libc::c_char,
                );
                (*data).state.set_authproblem(1 as bit);}
            }
        } else if unsafe{curl_strnequal(
            b"Bearer\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"Bearer\0" as *const u8 as *const libc::c_char),
        ) != 0
            && is_valid_auth_separator(*auth.offset(6 as isize)) != 0}
        {
            unsafe{*availp |= CURLAUTH_BEARER;
            (*authp).avail |= CURLAUTH_BEARER;}
            if unsafe{ (*authp).picked == CURLAUTH_BEARER} {
                /* We asked for Bearer authentication but got a 40X back
                anyway, which basically means our token isn't valid. */
                unsafe{(*authp).avail = CURLAUTH_NONE;
                Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8 as *const libc::c_char,
                );
                (*data).state.set_authproblem(1 as bit);}
            }
        }

        /* there may be multiple methods on one line, so keep reading */
        while unsafe{ *auth as i32 != 0 && *auth as i32 != ',' as i32} {
            /* read up to the next comma */
            auth = unsafe{auth.offset(1)};
        }
        if unsafe{*auth as i32 == ',' as i32} {
            /* if we're on a comma, skip it */
            auth = unsafe{auth.offset(1)};
        }
        while unsafe{*auth as i32 != 0 && Curl_isspace(*auth as u8 as i32) != 0} {
            auth = unsafe{auth.offset(1)};
        }
    }

    return CURLE_OK;
}

/**
 * http_should_fail() determines whether an HTTP response has gotten us
 * into an error state or not.
 *
 * @param conn all information about the current connection
 *
 * @retval FALSE communications should continue
 *
 * @retval TRUE communications should not continue
 */
 extern "C" fn http_should_fail(mut data: *mut Curl_easy) -> bool {
    let mut httpcode: i32 = 0;

    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !data.is_null() {
    } else {
        unsafe{ __assert_fail(
            b"data\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1090 as u32,
            (*::std::mem::transmute::<&[u8; 43], &[libc::c_char; 43]>(
                b"_Bool http_should_fail(struct Curl_easy *)\0",
            ))
            .as_ptr(),
        );}
    }
    
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if unsafe{!((*data).conn).is_null() }{
    } else {
        unsafe{ __assert_fail(
            b"data->conn\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1091 as u32,
            (*::std::mem::transmute::<&[u8; 43], &[libc::c_char; 43]>(
                b"_Bool http_should_fail(struct Curl_easy *)\0",
            ))
            .as_ptr(),
        );}
    }

    httpcode = unsafe{(*data).req.httpcode};

    /*
     ** If we haven't been asked to fail on error,
     ** don't fail.
     */
    if unsafe{((*data).set).http_fail_on_error() == 0} {
        return false;
    }

    /*
     ** Any code < 400 is never terminal.
     */
    if httpcode < 400 {
        return false;
    }

    /*
     ** A 416 response to a resume request is presumably because the file is
     ** already completely downloaded and thus not actually a fail.
     */
    if unsafe{(*data).state.resume_from != 0
        && (*data).state.httpreq as u32 == HTTPREQ_GET
        && httpcode == 416}
    {
        return false;
    }

    /*
     ** Any code >= 400 that's not 401 or 407 is always
     ** a terminal error
     */
    if httpcode != 401 && httpcode != 407 {
        return true;
    }

    /*
     ** All we have left to deal with is 401 and 407
     */
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if httpcode == 401 || httpcode == 407 {
    } else {
        unsafe{ __assert_fail(
            b"(httpcode == 401) || (httpcode == 407)\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1126 as u32,
            (*::std::mem::transmute::<&[u8; 43], &[libc::c_char; 43]>(
                b"_Bool http_should_fail(struct Curl_easy *)\0",
            ))
            .as_ptr(),
        );}
    }

    /*
     ** Examine the current authentication state to see if this
     ** is an error.  The idea is for this function to get
     ** called after processing all the headers in a response
     ** message.  So, if we've been to asked to authenticate a
     ** particular stage, and we've done it, we're OK.  But, if
     ** we're already completely authenticated, it's not OK to
     ** get another 401 or 407.
     **
     ** It is possible for authentication to go stale such that
     ** the client needs to reauthenticate.  Once that info is
     ** available, use it here.
     */

    /*
     ** Either we're not authenticating, or we're supposed to
     ** be authenticating something else.  This is an error.
     */
    if httpcode == 401 && unsafe{((*(*data).conn).bits).user_passwd() == 0} {
        return true;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    if httpcode == 407 && unsafe{((*(*data).conn).bits).proxy_user_passwd() == 0 }{
        return true;
    }
    return unsafe{((*data).state).authproblem() != 0};
}

/*
 * readmoredata() is a "fread() emulation" to provide POST and/or request
 * data. It is used when a huge POST is to be made and the entire chunk wasn't
 * sent in the first send(). This function will then be called from the
 * transfer.c loop when more data is to be sent to the peer.
 *
 * Returns the amount of bytes it filled the buffer with.
 */
#[cfg(not(USE_HYPER))]
 extern "C" fn readmoredata(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
    mut nitems: size_t,
    mut userp: *mut libc::c_void,
) -> size_t {
    let mut data: *mut Curl_easy = userp as *mut Curl_easy;
    let mut http: *mut HTTP = unsafe{(*data).req.p.http};
    let mut fullsize: size_t = size.wrapping_mul(nitems);

    if unsafe{(*http).postsize == 0 }{
        /* nothing to return */
        return 0 as size_t;
    }

    /* make sure that a HTTP request is never sent away chunked! */
    unsafe{ (*data).req.set_forbidchunk(
        (if (*http).sending as u32 == HTTPSEND_REQUEST {
            1
        } else {
            0
        }) as bit,
    );}

    /* speed limit */
    if unsafe{(*data).set.max_send_speed != 0
        && (*data).set.max_send_speed < fullsize as curl_off_t
        && (*data).set.max_send_speed < (*http).postsize}
    {
        fullsize =unsafe{ (*data).set.max_send_speed as size_t};
    } else if unsafe{(*http).postsize <= fullsize as curl_off_t }{
        unsafe{memcpy(
            buffer as *mut libc::c_void,
            (*http).postdata as *const libc::c_void,
            (*http).postsize as size_t,
        );}
        fullsize = unsafe{(*http).postsize as size_t};

        if unsafe{(*http).backup.postsize != 0} {
            /* move backup data into focus and continue on that */
            unsafe{(*http).postdata = (*http).backup.postdata;
            (*http).postsize = (*http).backup.postsize;
            (*data).state.fread_func = (*http).backup.fread_func;
            (*data).state.in_0 = (*http).backup.fread_in;

            (*http).sending += 1; /* move one step up */

            (*http).backup.postsize = 0 as curl_off_t;}
        } else {
            unsafe{ (*http).postsize = 0 as curl_off_t;}
        }

        return fullsize;
    }

    unsafe{memcpy(
        buffer as *mut libc::c_void,
        (*http).postdata as *const libc::c_void,
        fullsize,
    );

    (*http).postdata = (*http).postdata.offset(fullsize as isize);
    (*http).postsize = ((*http).postsize as u64).wrapping_sub(fullsize) as curl_off_t;}

    return fullsize;
}

/*
 * Curl_buffer_send() sends a header buffer and frees all associated
 * memory.  Body data may be appended to the header data if desired.
 *
 * Returns CURLcode
 */
#[cfg(not(USE_HYPER))]
#[no_mangle]
pub  extern "C" fn Curl_buffer_send(
    mut in_0: *mut dynbuf,
    mut data: *mut Curl_easy,
    /* add the number of sent bytes to this
    counter */
    mut bytes_written: *mut curl_off_t,
    /* how much of the buffer contains body data */
    mut included_body_bytes: curl_off_t,
    mut socketindex: i32,
) -> CURLcode {
    let mut amount: ssize_t = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: size_t = 0;
    let mut conn: *mut connectdata = unsafe{(*data).conn};
    let mut http: *mut HTTP =unsafe{ (*data).req.p.http};
    let mut sendsize: size_t = 0;
    let mut sockfd: curl_socket_t = 0;
    let mut headersize: size_t = 0;

    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if socketindex <= 1 {
    } else {
        unsafe{ __assert_fail(
            b"socketindex <= 1\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1240 as u32,
            (*::std::mem::transmute::<
                &[u8; 94],
                &[libc::c_char; 94],
            >(
                b"CURLcode Curl_buffer_send(struct dynbuf *, struct Curl_easy *, curl_off_t *, curl_off_t, int)\0",
            ))
                .as_ptr(),
        );}
    }

    sockfd = unsafe{(*conn).sock[socketindex as usize]};

    /* The looping below is required since we use non-blocking sockets, but due
    to the circumstances we will just loop and try again and again etc */

    ptr = unsafe{Curl_dyn_ptr(in_0)};
    size = unsafe{Curl_dyn_len(in_0)};

    headersize = size.wrapping_sub(included_body_bytes as size_t); /* the initial part that
                                                                   isn't body is header */

    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if size > included_body_bytes as size_t {
    } else {
        unsafe{ __assert_fail(
            b"size > (size_t)included_body_bytes\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1253 as u32,
            (*::std::mem::transmute::<
                &[u8; 94],
                &[libc::c_char; 94],
            >(
                b"CURLcode Curl_buffer_send(struct dynbuf *, struct Curl_easy *, curl_off_t *, curl_off_t, int)\0",
            ))
                .as_ptr(),
        );}
    }
    result = CURLE_OK;

    /* Curl_convert_to_network calls failf if unsuccessful */
    if result as u64 != 0 {
        /* conversion failed, free memory and return to the caller */
        unsafe{Curl_dyn_free(in_0);}
        return result;
    }

    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag: bool = unsafe{((*(*conn).handler).flags & PROTOPT_SSL != 0
        || (*conn).http_proxy.proxytype as u32 == CURLPROXY_HTTPS as u32)
        && (*conn).httpversion as i32 != 20};
    #[cfg(CURL_DISABLE_PROXY)]
    let flag: bool =unsafe{ (*(*conn).handler).flags & ((1 as i32) << 0 as i32) as u32 != 0
        && (*conn).httpversion as i32 != 20};
    /* Make sure this doesn't send more body bytes than what the max send
       speed says. The request bytes do not count to the max speed.
    */
    if flag {
        if unsafe{(*data).set.max_send_speed != 0 && included_body_bytes > (*data).set.max_send_speed} {
            let mut overflow: curl_off_t = unsafe{included_body_bytes - (*data).set.max_send_speed};
            #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
            if (overflow as size_t) < size {
            } else {
                unsafe{ __assert_fail(
                    b"(size_t)overflow < size\0" as *const u8 as *const libc::c_char,
                    b"http.c\0" as *const u8 as *const libc::c_char,
                    1275 as u32,
                    (*::std::mem::transmute::<
                        &[u8; 94],
                        &[libc::c_char; 94],
                    >(
                        b"CURLcode Curl_buffer_send(struct dynbuf *, struct Curl_easy *, curl_off_t *, curl_off_t, int)\0",
                    ))
                        .as_ptr(),
                );}
            }
            sendsize = size.wrapping_sub(overflow as size_t);
        } else {
            sendsize = size;
        }

        /* OpenSSL is very picky and we must send the SAME buffer pointer to the
           library when we attempt to re-send this buffer. Sending the same data
           is not enough, we must use the exact same address. For this reason, we
           must copy the data to the uploadbuffer first, since that is the buffer
           we will be using if this send is retried later.
        */
        result = unsafe{Curl_get_upload_buffer(data)};
        if result as u64 != 0 {
            /* malloc failed, free memory and return to the caller */
            unsafe{Curl_dyn_free(in_0);}
            return result;
        }
        /* We never send more than upload_buffer_size bytes in one single chunk
           when we speak HTTPS, as if only a fraction of it is sent now, this data
           needs to fit into the normal read-callback buffer later on and that
           buffer is using this size.
        */
        if unsafe{sendsize > (*data).set.upload_buffer_size as size_t} {
            sendsize = unsafe{(*data).set.upload_buffer_size as size_t};
        }

        unsafe{memcpy(
            (*data).state.ulbuf as *mut libc::c_void,
            ptr as *const libc::c_void,
            sendsize,
        );}
        ptr = unsafe{(*data).state.ulbuf};
    } else {
        #[cfg(CURLDEBUG)]
        {
            /* Allow debug builds to override this logic to force short initial
               sends
            */
            let mut p: *mut libc::c_char =
            unsafe{getenv(b"CURL_SMALLREQSEND\0" as *const u8 as *const libc::c_char)};
            if !p.is_null() {
                let mut altsize: size_t = unsafe{strtoul(p, 0 as *mut *mut libc::c_char, 10)};
                if altsize != 0 {
                    sendsize = if size < altsize { size } else { altsize };
                } else {
                    sendsize = size;
                }
            } else if unsafe{(*data).set.max_send_speed != 0
                && included_body_bytes > (*data).set.max_send_speed}
            {
                let mut overflow_0: curl_off_t = unsafe{included_body_bytes - (*data).set.max_send_speed};
                if (overflow_0 as size_t) < size {
                } else {
                    unsafe{  __assert_fail(
                        b"(size_t)overflow < size\0" as *const u8 as *const libc::c_char,
                        b"http.c\0" as *const u8 as *const libc::c_char,
                        1326 as u32,
                        (*::std::mem::transmute::<
                            &[u8; 94],
                            &[libc::c_char; 94],
                        >(
                            b"CURLcode Curl_buffer_send(struct dynbuf *, struct Curl_easy *, curl_off_t *, curl_off_t, int)\0",
                        ))
                            .as_ptr(),
                    );}
                }
                sendsize = size.wrapping_sub(overflow_0 as size_t);
            } else {
                sendsize = size;
            }
        }
        #[cfg(not(CURLDEBUG))]
        {
            /* Make sure this doesn't send more body bytes than what the max send
               speed says. The request bytes do not count to the max speed.
            */
            if unsafe{(*data).set.max_send_speed != 0 && included_body_bytes > (*data).set.max_send_speed} {
                let mut overflow_0: curl_off_t = unsafe{included_body_bytes - (*data).set.max_send_speed};
                sendsize = size.wrapping_sub(overflow_0 as size_t);
            } else {
                sendsize = size;
            }
        }
    }

    result = unsafe{Curl_write(
        data,
        sockfd,
        ptr as *const libc::c_void,
        sendsize,
        &mut amount,
    )};

    if result as u64 == 0 {
        /*
         * Note that we may not send the entire chunk at once, and we have a set
         * number of data bytes at the end of the big buffer (out of which we may
         * only send away a part).
         */
        /* how much of the header that was sent */
        let mut headlen: size_t = if amount as size_t > headersize {
            headersize
        } else {
            amount as size_t
        };

        /* this data _may_ contain binary stuff */
        let mut bodylen: size_t = (amount as u64).wrapping_sub(headlen);
        unsafe{ Curl_debug(data, CURLINFO_HEADER_OUT, ptr, headlen);}
        if bodylen != 0 {
            /* there was body data sent beyond the initial header part, pass that on
            to the debug callback too */
            unsafe{ Curl_debug(
                data,
                CURLINFO_DATA_OUT,
                ptr.offset(headlen as isize),
                bodylen,
            );}
        }

        /* 'amount' can never be a very large value here so typecasting it so a
        signed 31 bit value should not cause problems even if ssize_t is
        64bit */
        unsafe{ *bytes_written += amount;}

        if !http.is_null() {
            /* if we sent a piece of the body here, up the byte counter for it
            accordingly */
            unsafe{ (*data).req.writebytecount = ((*data).req.writebytecount as u64).wrapping_add(bodylen)
                as curl_off_t as curl_off_t;
            Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount);}

            if amount as size_t != size {
                /* The whole request could not be sent in one system call. We must
                queue it up and send it later when we get the chance. We must not
                loop here and wait until it might work again. */

                size = (size as u64).wrapping_sub(amount as u64) as size_t;

                ptr = unsafe{(Curl_dyn_ptr(in_0)).offset(amount as isize)};

                /* backup the currently set pointers */
                unsafe{(*http).backup.fread_func = (*data).state.fread_func;
                (*http).backup.fread_in = (*data).state.in_0;
                (*http).backup.postdata = (*http).postdata;
                (*http).backup.postsize = (*http).postsize;

                /* set the new pointers for the request-sending */
                (*data).state.fread_func = ::std::mem::transmute::<
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
                (*data).state.in_0 = data as *mut libc::c_void;
                (*http).postdata = ptr;
                (*http).postsize = size as curl_off_t;

                /* this much data is remaining header: */
                (*data).req.pendingheader = headersize.wrapping_sub(headlen) as curl_off_t;
                (*http).send_buffer = *in_0; /* copy the whole struct */
                (*http).sending = HTTPSEND_REQUEST;}

                return CURLE_OK;
            }
            unsafe{ (*http).sending = HTTPSEND_BODY;}
        } else if amount as size_t != size {
            /* We have no continue-send mechanism now, fail. This can only happen
               when this function is used from the CONNECT sending function. We
               currently (stupidly) assume that the whole request is always sent
               away in the first single chunk.

               This needs FIXing.
            */
            return CURLE_SEND_ERROR;
        }
    }
    unsafe{ Curl_dyn_free(in_0);

    /* no remaining header data */
    (*data).req.pendingheader = 0 as curl_off_t;}
    return result;
}

#[cfg(USE_HYPER)]
#[no_mangle]
pub extern "C" fn Curl_buffer_send(
    mut in_0: *mut dynbuf,
    mut data: *mut Curl_easy,
    mut bytes_written: *mut curl_off_t,
    mut included_body_bytes: curl_off_t,
    mut socketindex: i32,
) -> CURLcode {
    return CURLE_OK;
}

/*
 * Curl_compareheader()
 *
 * Returns TRUE if 'headerline' contains the 'header' with given 'content'.
 * Pass headers WITH the colon.
 */
#[no_mangle]
pub  extern "C" fn Curl_compareheader(
    mut headerline: *const libc::c_char, /* line to check */
    mut header: *const libc::c_char,     /* header keyword _with_ colon */
    mut content: *const libc::c_char,    /* content string to find */
) -> bool {
    /* RFC2616, section 4.2 says: "Each header field consists of a name followed
     * by a colon (":") and the field value. Field names are case-insensitive.
     * The field value MAY be preceded by any amount of LWS, though a single SP
     * is preferred." */

    let mut hlen: size_t = unsafe{strlen(header)};
    let mut clen: size_t = 0;
    let mut len: size_t = 0;
    let mut start: *const libc::c_char = 0 as *const libc::c_char;
    let mut end: *const libc::c_char = 0 as *const libc::c_char;

    if unsafe{Curl_strncasecompare(headerline, header, hlen) == 0} {
        return false; /* doesn't start with header */
    }

    /* pass the header */
    start = unsafe{&*headerline.offset(hlen as isize) as *const libc::c_char};

    /* pass all whitespace */
    while unsafe{*start as i32 != 0 && Curl_isspace(*start as u8 as i32) != 0} {
        start = unsafe{start.offset(1)};
    }

    /* find the end of the header line */
    end = unsafe{strchr(start, '\r' as i32)}; /* lines end with CRLF */
    if end.is_null() {
        /* in case there's a non-standard compliant line here */
        end = unsafe{strchr(start, '\n' as i32)};

        if end.is_null() {
            /* hm, there's no line ending here, use the zero byte! */
            end = unsafe{strchr(start, '\0' as i32)};
        }
    }

    len = unsafe{end.offset_from(start) as size_t}; /* length of the content part of the input line */
    clen = unsafe{strlen(content)}; /* length of the word to find */

    /* find the content string in the rest of the line */
    while len >= clen {
        if unsafe{Curl_strncasecompare(start, content, clen) != 0} {
            return true; /* match! */
        }
        len = len.wrapping_sub(1);
        start = unsafe{start.offset(1)};
    }
    return false; /* no match */
}

/*
 * Curl_http_connect() performs HTTP stuff to do at connect-time, called from
 * the generic Curl_connect().
 */
#[no_mangle]
pub  extern "C" fn Curl_http_connect(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = unsafe{(*data).conn};

    /* We default to persistent connections. We set this already in this connect
    function to make the re-use checks properly be able to check this bit. */
    unsafe{ #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
    Curl_conncontrol(conn, FIRSTSOCKET);
    #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
    Curl_conncontrol(
        conn,
        FIRSTSOCKET,
        b"HTTP default\0" as *const u8 as *const libc::c_char,
    );}
    match () {
        #[cfg(not(CURL_DISABLE_PROXY))]
        _ => {
            /* the CONNECT procedure might not have been completed */
            result = unsafe{Curl_proxy_connect(data, 0 as i32)};
            if result as u64 != 0 {
                return result;
            }

            if unsafe{ ((*conn).bits).proxy_connect_closed() != 0} {
                /* this is not an error, just part of the connection negotiation */
                return CURLE_OK;
            }

            if unsafe{(*conn).http_proxy.proxytype as u32 == CURLPROXY_HTTPS as u32
                && !(*conn).bits.proxy_ssl_connected[0 as usize]}
            {
                return CURLE_OK; /* wait for HTTPS proxy SSL initialization to complete */
            }
            if unsafe{Curl_connect_ongoing(conn)} {
                /* nothing else to do except wait right now - we're not done here. */
                return CURLE_OK;
            }
            if unsafe{((*data).set).haproxyprotocol() != 0 }{
                /* add HAProxy PROXY protocol header */
                result = add_haproxy_protocol_header(data);
                if result as u64 != 0 {
                    return result;
                }
            }
        }
        #[cfg(CURL_DISABLE_PROXY)]
        _ => {}
    }
    if unsafe{(*(*conn).given).protocol & CURLPROTO_HTTPS != 0} {
        /* perform SSL initialization */
        result = https_connecting(data, done);
        if result as u64 != 0 {
            return result;
        }
    } else {
        unsafe{  *done = true;}
    }
    return CURLE_OK;
}

/* this returns the socket to wait for in the DO and DOING state for the multi
interface and then we're always _sending_ a request and thus we wait for
the single socket to become writable only */
 extern "C" fn http_getsock_do(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    /* write mode */
    unsafe{*socks.offset(0 as isize) = (*conn).sock[FIRSTSOCKET as usize];}
    return GETSOCK_WRITESOCK(0);
}

#[cfg(not(CURL_DISABLE_PROXY))]
 extern "C" fn add_haproxy_protocol_header(mut data: *mut Curl_easy) -> CURLcode {
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
    if unsafe{!((*data).conn).is_null()} {
    } else {
        unsafe{__assert_fail(
            b"data->conn\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1546 as u32,
            (*::std::mem::transmute::<&[u8; 57], &[libc::c_char; 57]>(
                b"CURLcode add_haproxy_protocol_header(struct Curl_easy *)\0",
            ))
            .as_ptr(),
        );}
    }
    unsafe{Curl_dyn_init(&mut req, 2048 as size_t);}
    #[cfg(USE_UNIX_SOCKETS)]
    let flag: bool = unsafe{!((*(*data).conn).unix_domain_socket).is_null()};
    #[cfg(not(USE_UNIX_SOCKETS))]
    let flag: bool = false;
    if flag {
        /* the buffer is large enough to hold this! */
        result = unsafe{Curl_dyn_add(
            &mut req,
            b"PROXY UNKNOWN\r\n\0" as *const u8 as *const libc::c_char,
        )};
    } else {
        /* Emit the correct prefix for IPv6 */
        tcp_version = if unsafe{((*(*data).conn).bits).ipv6() as i32 != 0 }{
            b"TCP6\0" as *const u8 as *const libc::c_char
        } else {
            b"TCP4\0" as *const u8 as *const libc::c_char
        };
        result = unsafe{Curl_dyn_addf(
            &mut req as *mut dynbuf,
            b"PROXY %s %s %s %i %i\r\n\0" as *const u8 as *const libc::c_char,
            tcp_version,
            ((*data).info.conn_local_ip).as_mut_ptr(),
            ((*data).info.conn_primary_ip).as_mut_ptr(),
            (*data).info.conn_local_port,
            (*data).info.conn_primary_port,
        )};
    }

    if result as u64 == 0 {
        result = unsafe{Curl_buffer_send(
            &mut req,
            data,
            &mut (*data).info.request_size,
            0 as curl_off_t,
            FIRSTSOCKET,
        )};
    }
    return result;
}

#[cfg(USE_SSL)]
 extern "C" fn https_connecting(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = unsafe{(*data).conn};

    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if unsafe{!data.is_null() && (*(*(*data).conn).handler).flags & ((1 as i32) << 0 as i32) as u32 != 0} {
    } else {
        unsafe{__assert_fail(
            b"(data) && (data->conn->handler->flags & (1<<0))\0" as *const u8
                as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            1581 as u32,
            (*::std::mem::transmute::<&[u8; 55], &[libc::c_char; 55]>(
                b"CURLcode https_connecting(struct Curl_easy *, _Bool *)\0",
            ))
            .as_ptr(),
        );}
    }
    #[cfg(ENABLE_QUIC)]
    if unsafe{(*conn).transport as u32 == TRNSPRT_QUIC as u32} {
        unsafe{ *done = true;}
        return CURLE_OK;
    }

    /* perform SSL initialization for this socket */
    result = unsafe{Curl_ssl_connect_nonblocking(data, conn, false, 0, done)};
    if result as u64 != 0 {unsafe{
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 1);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            1,
            b"Failed HTTPS connection\0" as *const u8 as *const libc::c_char,
        );}
    }
    return result;
}

#[cfg(not(USE_SSL))]
 extern "C" fn https_connecting(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    return CURLE_COULDNT_CONNECT;
}

#[cfg(USE_SSL)]
 extern "C" fn https_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    if unsafe{(*(*conn).handler).flags & PROTOPT_SSL != 0} {
        return unsafe{((*Curl_ssl).getsock).expect("non-null function pointer")(conn, socks)};
    }
    return 0;
}

#[no_mangle]
pub  extern "C" fn Curl_http_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
    let mut conn: *mut connectdata = unsafe{(*data).conn};
    let mut http: *mut HTTP = unsafe{(*data).req.p.http};

    /* Clear multipass flag. If authentication isn't done yet, then it will get
   * a chance to be set back to true when we output the next auth header */
   unsafe{(*data).state.authhost.set_multipass(0 as bit);
    (*data).state.authproxy.set_multipass(0 as bit);

    Curl_unencode_cleanup(data);

    /* set the proper values (possibly modified on POST) */
    (*conn).seek_func = (*data).set.seek_func; /* restore */
    (*conn).seek_client = (*data).set.seek_client; /* restore */
   }
    if http.is_null() {
        return CURLE_OK;
    }
    unsafe{
    Curl_dyn_free(&mut (*http).send_buffer);
    Curl_http2_done(data, premature);
    #[cfg(any(
        all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)),
        not(CURL_DISABLE_SMTP),
        not(CURL_DISABLE_IMAP)
    ))]
    Curl_mime_cleanpart(&mut (*http).form);
    Curl_dyn_reset(&mut (*data).state.headerb);
    #[cfg(all(not(CURL_DISABLE_HTTP), USE_HYPER))]
    Curl_hyper_done(data);}

    if status as u64 != 0 {
        return status;
    }

    if unsafe{!premature /* this check is pointless when DONE is called before the
    entire operation is complete */
        && ((*conn).bits).retry() == 0
        && ((*data).set).connect_only() == 0
        && (*data).req.bytecount + (*data).req.headerbytecount - (*data).req.deductheadercount
            <= 0 as i64}
    {
        /* If this connection isn't simply closed to be retried, AND nothing was
           read from the HTTP server (that counts), this can't be right so we
           return an error here */
           unsafe{Curl_failf(
            data,
            b"Empty reply from server\0" as *const u8 as *const libc::c_char,
        );
        /* Mark it as closed to avoid the "left intact" message */
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 2);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            2,
            b"Empty reply from server\0" as *const u8 as *const libc::c_char,
        );}
        return CURLE_GOT_NOTHING;
    }
    return CURLE_OK;
}

/*
 * Determine if we should use HTTP 1.1 (OR BETTER) for this request. Reasons
 * to avoid it include:
 *
 * - if the user specifically requested HTTP 1.0
 * - if the server we are connected to only supports 1.0
 * - if any server previously contacted to handle this request only supports
 * 1.0.
 */
#[no_mangle]
pub  extern "C" fn Curl_use_http_1_1plus(
    mut data: *const Curl_easy,
    mut conn: *const connectdata,
) -> bool {
    if unsafe{(*data).state.httpversion as i32 == 10 || (*conn).httpversion as i32 == 10} {
        return false;
    }
    if unsafe{(*data).state.httpwant as i32 == CURL_HTTP_VERSION_1_0 as i32
        && (*conn).httpversion as i32 <= 10}
    {
        return false;
    }
    return unsafe{(*data).state.httpwant as i32 == CURL_HTTP_VERSION_NONE as i32
        || (*data).state.httpwant as i32 >= CURL_HTTP_VERSION_1_1 as i32};
}

#[cfg(not(USE_HYPER))]
 extern "C" fn get_http_string(
    mut data: *const Curl_easy,
    mut conn: *const connectdata,
) -> *const libc::c_char {
    #[cfg(ENABLE_QUIC)]
    if unsafe{(*data).state.httpwant as i32 == CURL_HTTP_VERSION_3 as i32
        || (*conn).httpversion as i32 == 30}
    {
        return b"3\0" as *const u8 as *const libc::c_char;
    }
    #[cfg(USE_NGHTTP2)]
    if !(unsafe{(*conn).proto.httpc.h2}).is_null() {
        return b"2\0" as *const u8 as *const libc::c_char;
    }
    if Curl_use_http_1_1plus(data, conn) {
        return b"1.1\0" as *const u8 as *const libc::c_char;
    }
    return b"1.0\0" as *const u8 as *const libc::c_char;
}

/* check and possibly add an Expect: header */
 extern "C" fn expect100(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    unsafe{(*data).state.set_expect100header(0 as bit);} /* default to false unless it is set
    to TRUE below */
    if unsafe{((*data).state).disableexpect() == 0
        && Curl_use_http_1_1plus(data, conn) as i32 != 0
        && ((*conn).httpversion as i32) < 20}
    {
        /* if not doing HTTP 1.0 or version 2, or disabled explicitly, we add an
       Expect: 100-continue to the headers which actually speeds up post
       operations (as there is one packet coming back from the web server) */
        let mut ptr: *const libc::c_char =
        unsafe{Curl_checkheaders(data, b"Expect\0" as *const u8 as *const libc::c_char)};
        if !ptr.is_null() {
            unsafe{(*data).state.set_expect100header(Curl_compareheader(
                ptr,
                b"Expect:\0" as *const u8 as *const libc::c_char,
                b"100-continue\0" as *const u8 as *const libc::c_char,
            ) as bit);}
        } else {
            result = unsafe{Curl_dyn_add(
                req,
                b"Expect: 100-continue\r\n\0" as *const u8 as *const libc::c_char,
            )};
            if result as u64 == 0 {
                unsafe{(*data).state.set_expect100header(1 as bit);}
            }
        }
    }
    return result;
}

#[no_mangle]
pub  extern "C" fn Curl_http_compile_trailers(
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
        unsafe{ ((*handle).state).prefer_ascii() as i32 != 0 || ((*handle).set).crlf() as i32 != 0}
    } else {
        unsafe{ ((*handle).set).crlf() as i32 != 0}
        /* \n will become \r\n later on */
    };
    if flag {
        endofline_native = b"\n\0" as *const u8 as *const libc::c_char;
        endofline_network = b"\n\0" as *const u8 as *const libc::c_char;
    } else {
        endofline_native = b"\r\n\0" as *const u8 as *const libc::c_char;
        endofline_network = b"\r\n\0" as *const u8 as *const libc::c_char;
    }
    while !trailers.is_null() {
        /* only add correctly formatted trailers */
        ptr = unsafe{strchr((*trailers).data, ':' as i32)};
        if unsafe{!ptr.is_null() && *ptr.offset(1 as isize) as i32 == ' ' as i32} {
            result = unsafe{Curl_dyn_add(b, (*trailers).data)};
            if result as u64 != 0 {
                return result;
            }
            result = unsafe{Curl_dyn_add(b, endofline_native)};
            if result as u64 != 0 {
                return result;
            }
        } else {
            unsafe{Curl_infof(
                handle,
                b"Malformatted trailing header ! Skipping trailer.\0" as *const u8
                    as *const libc::c_char,
            );}
        }
        trailers =unsafe{ (*trailers).next};
    }
    result = unsafe{Curl_dyn_add(b, endofline_network)};
    return result;
}

#[cfg(USE_HYPER)]
#[no_mangle]
pub  extern "C" fn Curl_add_custom_headers(
    mut data: *mut Curl_easy,
    mut is_connect: bool,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut conn: *mut connectdata = unsafe{(*data).conn};
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut h: [*mut curl_slist; 2] = [0 as *mut curl_slist; 2];
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    let mut numlists: i32 = 1;
    let mut i: i32 = 0;
    let mut proxy: proxy_use = HEADER_SERVER;
    if is_connect {
        proxy = HEADER_CONNECT;
    } else {
        proxy = (if unsafe{((*conn).bits).httpproxy() as i32 != 0 && ((*conn).bits).tunnel_proxy() == 0} {
            HEADER_PROXY as i32
        } else {
            HEADER_SERVER as i32
        }) as proxy_use;
    }
    match proxy as u32 {
        0 => {
            h[0 as usize] = unsafe{(*data).set.headers};
        }
        1 => {
            h[0 as usize] = unsafe{(*data).set.headers};
            if unsafe{((*data).set).sep_headers() != 0} {
                h[1 as usize] = unsafe{(*data).set.proxyheaders};
                numlists += 1;
            }
        }
        2 => {
            if unsafe{((*data).set).sep_headers() != 0 }{
                h[0 as usize] = unsafe{(*data).set.proxyheaders};
            } else {
                h[0 as usize] = unsafe{(*data).set.headers};
            }
        }
        _ => {}
    }
    i = 0;
    while i < numlists {
        headers = h[i as usize];
        while !headers.is_null() {
            let mut semicolonp: *mut libc::c_char = 0 as *mut libc::c_char;
            ptr = unsafe{strchr((*headers).data, ':' as i32)};
            if ptr.is_null() {
                let mut optr: *mut libc::c_char = 0 as *mut libc::c_char;
                ptr = unsafe{strchr((*headers).data, ';' as i32)};
                if !ptr.is_null() {
                    optr = ptr;
                    ptr = unsafe{ptr.offset(1)};
                    while unsafe{*ptr as i32 != 0 && Curl_isspace(*ptr as u8 as i32) != 0} {
                        ptr = unsafe{ptr.offset(1)};
                    }
                    if unsafe{*ptr != 0} {
                        optr = 0 as *mut libc::c_char;
                    } else {
                        ptr = unsafe{ptr.offset(-1)};
                        if unsafe{*ptr as i32 == ';' as i32 }{
                            match () {
                                #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                                _ => {
                                    semicolonp =unsafe{ Curl_cstrdup.expect("non-null function pointer")(
                                        (*headers).data,
                                    )};
                                }
                                #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                                _ => {
                                    semicolonp = unsafe{curl_dbg_strdup(
                                        (*headers).data,
                                        1857 as i32,
                                        b"http.c\0" as *const u8 as *const libc::c_char,
                                    )};
                                }
                            }
                            if semicolonp.is_null() {
                                unsafe{Curl_dyn_free(req);}
                                return CURLE_OUT_OF_MEMORY;
                            }
                            unsafe{ *semicolonp.offset(ptr.offset_from((*headers).data) as i64 as isize) =
                                ':' as i32 as libc::c_char;}
                            optr =unsafe{ &mut *semicolonp
                                .offset(ptr.offset_from((*headers).data) as i64 as isize)
                                as *mut libc::c_char};
                        }
                    }
                    ptr = optr;
                }
            }
            if !ptr.is_null() {
                ptr =unsafe{ ptr.offset(1)};
                while unsafe{*ptr as i32 != 0 && Curl_isspace(*ptr as u8 as i32) != 0 }{
                    ptr = unsafe{ptr.offset(1)};
                }
                if unsafe{*ptr as i32 != 0 || !semicolonp.is_null()} {
                    let mut result: CURLcode = CURLE_OK;
                    let mut compare: *mut libc::c_char = if !semicolonp.is_null() {
                        semicolonp
                    } else {
                        unsafe{(*headers).data}
                    };
                    if unsafe{!(!((*data).state.aptr.host).is_null()
                        && curl_strnequal(
                            b"Host:\0" as *const u8 as *const libc::c_char,
                            compare,
                            strlen(b"Host:\0" as *const u8 as *const libc::c_char),
                        ) != 0)}
                    {
                        if unsafe{!((*data).state.httpreq as u32 == HTTPREQ_POST_FORM as i32 as u32
                            && curl_strnequal(
                                b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                compare,
                                strlen(b"Content-Type:\0" as *const u8 as *const libc::c_char),
                            ) != 0)}
                        {
                            if unsafe{!((*data).state.httpreq as u32 == HTTPREQ_POST_MIME as i32 as u32
                                && curl_strnequal(
                                    b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                    compare,
                                    strlen(b"Content-Type:\0" as *const u8 as *const libc::c_char),
                                ) != 0)}
                            {
                                if unsafe{!(((*conn).bits).authneg() as i32 != 0
                                    && curl_strnequal(
                                        b"Content-Length:\0" as *const u8 as *const libc::c_char,
                                        compare,
                                        strlen(
                                            b"Content-Length:\0" as *const u8
                                                as *const libc::c_char,
                                        ),
                                    ) != 0)}
                                {
                                    if unsafe{!(!((*data).state.aptr.te).is_null()
                                        && curl_strnequal(
                                            b"Connection:\0" as *const u8 as *const libc::c_char,
                                            compare,
                                            strlen(
                                                b"Connection:\0" as *const u8
                                                    as *const libc::c_char,
                                            ),
                                        ) != 0)}
                                    {
                                        if unsafe{!((*conn).httpversion as i32 >= 20 as i32
                                            && curl_strnequal(
                                                b"Transfer-Encoding:\0" as *const u8
                                                    as *const libc::c_char,
                                                compare,
                                                strlen(
                                                    b"Transfer-Encoding:\0" as *const u8
                                                        as *const libc::c_char,
                                                ),
                                            ) != 0)}
                                        {
                                            if unsafe{!((curl_strnequal(
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
                                                && (((*data).state).this_is_a_follow() as i32 != 0
                                                    && !((*data).state.first_host).is_null()
                                                    && ((*data).set).allow_auth_to_other_hosts()
                                                        == 0
                                                    && Curl_strcasecompare(
                                                        (*data).state.first_host,
                                                        (*conn).host.name,
                                                    ) == 0))}
                                            {
                                                result = unsafe{Curl_hyper_header(
                                                    data,
                                                    req as *mut hyper_headers,
                                                    compare,
                                                )};
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !semicolonp.is_null() {
                        #[cfg(not(CURLDEBUG))]
                        unsafe{ Curl_cfree.expect("non-null function pointer")(
                            semicolonp as *mut libc::c_void,
                        );}
                        #[cfg(CURLDEBUG)]
                        unsafe{ curl_dbg_free(
                            semicolonp as *mut libc::c_void,
                            1929 as i32,
                            b"http.c\0" as *const u8 as *const libc::c_char,
                        );}
                    }
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            headers = unsafe{(*headers).next};
        }
        i += 1;
    }
    return CURLE_OK;
}

const HEADER_SERVER: u32 = 0; /* direct to server */
const HEADER_PROXY: u32 = 1; /* regular request to proxy */
const HEADER_CONNECT: u32 = 2; /* sending CONNECT to a proxy */

#[cfg(not(USE_HYPER))]
#[no_mangle]
pub  extern "C" fn Curl_add_custom_headers(
    mut data: *mut Curl_easy,
    mut is_connect: bool,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut conn: *mut connectdata = unsafe{(*data).conn};
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut h: [*mut curl_slist; 2] = [0 as *mut curl_slist; 2];
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    let mut numlists: i32 = 1; /* by default */
    let mut i: i32 = 0;

    match () {
        #[cfg(not(CURL_DISABLE_PROXY))]
        _ => {
            let mut proxy: proxy_use = HEADER_SERVER;
            if is_connect {
                proxy = HEADER_CONNECT;
            } else {
                proxy = (if unsafe{((*conn).bits).httpproxy() as i32 != 0
                    && ((*conn).bits).tunnel_proxy() == 0}
                {
                    HEADER_PROXY as i32
                } else {
                    HEADER_SERVER as i32
                }) as proxy_use;
            }
            match proxy as u32 {
                HEADER_SERVER => {
                    h[0 as usize] = unsafe{(*data).set.headers};
                }
                HEADER_PROXY => {
                    h[0 as usize] = unsafe{(*data).set.headers};
                    if unsafe{((*data).set).sep_headers() != 0} {
                        h[1 as usize] =unsafe{ (*data).set.proxyheaders};
                        numlists += 1;
                    }
                }
                HEADER_CONNECT => {
                    if unsafe{((*data).set).sep_headers() != 0} {
                        h[0 as usize] = unsafe{(*data).set.proxyheaders};
                    } else {
                        h[0 as usize] = unsafe{(*data).set.headers};
                    }
                }
                _ => {}
            }
        }
        #[cfg(CURL_DISABLE_PROXY)]
        _ => {
            h[0 as usize] = unsafe{(*data).set.headers};
        }
    }

    /* loop through one or two lists */
    i = 0;
    while i < numlists {
        headers = h[i as usize];

        while !headers.is_null() {
            let mut semicolonp: *mut libc::c_char = 0 as *mut libc::c_char;
            ptr = unsafe{strchr((*headers).data, ':' as i32)};
            if ptr.is_null() {
                let mut optr: *mut libc::c_char = 0 as *mut libc::c_char;
                /* no colon, semicolon? */
                ptr = unsafe{strchr((*headers).data, ';' as i32)};
                if !ptr.is_null() {
                    optr = ptr;
                    ptr = unsafe{ptr.offset(1)}; /* pass the semicolon */
                    while unsafe{*ptr as i32 != 0 && Curl_isspace(*ptr as u8 as i32) != 0} {
                        ptr = unsafe{ptr.offset(1)};
                    }

                    if unsafe{*ptr != 0} {
                        optr = 0 as *mut libc::c_char;
                    } else {
                        ptr = unsafe{ptr.offset(-1)};
                        if unsafe{*ptr as i32 == ';' as i32} {
                            /* this may be used for something else in the future */
                            match () {
                                #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                                _ => {
                                    semicolonp = unsafe{Curl_cstrdup.expect("non-null function pointer")(
                                        (*headers).data,
                                    )};
                                }
                                #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                                _ => {
                                    semicolonp = unsafe{curl_dbg_strdup(
                                        (*headers).data,
                                        1857,
                                        b"http.c\0" as *const u8 as *const libc::c_char,
                                    )};
                                }
                            }
                            if semicolonp.is_null() {
                                /* copy the source */
                                #[cfg(not(USE_HYPER))]
                                unsafe{Curl_dyn_free(req);}
                                return CURLE_OUT_OF_MEMORY;
                            }
                            /* put a colon where the semicolon is */
                            unsafe{ *semicolonp.offset(ptr.offset_from((*headers).data) as i64 as isize) =
                                ':' as i32 as libc::c_char;}
                            /* point at the colon */
                                optr = unsafe{&mut *semicolonp
                                .offset(ptr.offset_from((*headers).data) as i64 as isize)
                                as *mut libc::c_char};
                        }
                    }
                    ptr = optr;
                }
            }
            if !ptr.is_null() {
                /* we require a colon for this to be a true header */
                ptr = unsafe{ptr.offset(1)};
                while unsafe{*ptr as i32 != 0 && Curl_isspace(*ptr as u8 as i32) != 0} {
                    ptr = unsafe{ptr.offset(1)};
                }
                if unsafe{*ptr as i32 != 0 || !semicolonp.is_null()} {
                    /* only send this if the contents was non-blank or done special */
                    let mut result: CURLcode = CURLE_OK;
                    let mut compare: *mut libc::c_char = if !semicolonp.is_null() {
                        semicolonp
                    } else {
                        unsafe{(*headers).data}
                    };
                    if unsafe{!(!((*data).state.aptr.host).is_null() && 
                        /* a Host: header was sent already, don't pass on any custom Host:
                header as that will produce *two* in the same request! */
                        curl_strnequal(
                            b"Host:\0" as *const u8 as *const libc::c_char,
                            compare,
                            strlen(b"Host:\0" as *const u8 as *const libc::c_char),
                        ) != 0)}
                    {
                        if unsafe{!((*data).state.httpreq as u32 == HTTPREQ_POST_FORM
                          /* this header (extended by formdata.c) is sent later */
                        && curl_strnequal(
                                b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                compare,
                                strlen(b"Content-Type:\0" as *const u8 as *const libc::c_char),
                            ) != 0)}
                        {
                            if unsafe{!((*data).state.httpreq as u32 == HTTPREQ_POST_MIME
                            /* this header is sent later */
                                && curl_strnequal(
                                    b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                    compare,
                                    strlen(b"Content-Type:\0" as *const u8 as *const libc::c_char),
                                ) != 0)}
                            {
                                if unsafe{!(((*conn).bits).authneg() as i32 != 0
                                    && 
                                    /* while doing auth neg, don't allow the custom length since
                     we will force length zero then */
                                    curl_strnequal(
                                        b"Content-Length:\0" as *const u8 as *const libc::c_char,
                                        compare,
                                        strlen(
                                            b"Content-Length:\0" as *const u8
                                                as *const libc::c_char,
                                        ),
                                    ) != 0)}
                                {
                                    if unsafe{!(!((*data).state.aptr.te).is_null()
                                        && 
                                        /* when asking for Transfer-Encoding, don't pass on a custom
                     Connection: */
                                        curl_strnequal(
                                            b"Connection:\0" as *const u8 as *const libc::c_char,
                                            compare,
                                            strlen(
                                                b"Connection:\0" as *const u8
                                                    as *const libc::c_char,
                                            ),
                                        ) != 0)}
                                    {
                                        if unsafe{!((*conn).httpversion as i32 >= 20
                                            && 
                                            /* HTTP/2 doesn't support chunked requests */
                                            curl_strnequal(
                                                b"Transfer-Encoding:\0" as *const u8
                                                    as *const libc::c_char,
                                                compare,
                                                strlen(
                                                    b"Transfer-Encoding:\0" as *const u8
                                                        as *const libc::c_char,
                                                ),
                                            ) != 0)}
                                        {
                                            if unsafe{!((curl_strnequal(
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
                                                /* be careful of sending this potentially sensitive header to
                     other hosts */
                                                && (((*data).state).this_is_a_follow() as i32 != 0
                                                    && !((*data).state.first_host).is_null()
                                                    && ((*data).set).allow_auth_to_other_hosts()
                                                        == 0
                                                    && Curl_strcasecompare(
                                                        (*data).state.first_host,
                                                        (*conn).host.name,
                                                    ) == 0))}
                                            {
                                                match () {
                                                    #[cfg(USE_HYPER)]
                                                    _ => {
                                                        result =
                                                        unsafe{Curl_hyper_header(data, req, compare)};
                                                    }
                                                    #[cfg(not(USE_HYPER))]
                                                    _ => {
                                                        result =unsafe{ Curl_dyn_addf(
                                                            req,
                                                            b"%s\r\n\0" as *const u8
                                                                as *const libc::c_char,
                                                            compare,
                                                        )};
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
                        unsafe{ Curl_cfree.expect("non-null function pointer")(
                            semicolonp as *mut libc::c_void,
                        );}
                        #[cfg(CURLDEBUG)]
                        unsafe{ curl_dbg_free(
                            semicolonp as *mut libc::c_void,
                            1929 as i32,
                            b"http.c\0" as *const u8 as *const libc::c_char,
                        );}
                    }
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            headers = unsafe{(*headers).next};
        }
        i += 1;
    }

    return CURLE_OK;
}

const CURL_TIMECOND_IFMODSINCE: u32 = 1;
const CURL_TIMECOND_IFUNMODSINCE: u32 = 2;
const CURL_TIMECOND_LASTMOD: u32 = 3;

#[cfg(all(not(CURL_DISABLE_PARSEDATE), USE_HYPER))]
#[no_mangle]
pub  extern "C" fn Curl_add_timecondition(
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
    if unsafe{(*data).set.timecondition as u32 == CURL_TIMECOND_NONE as u32} {
        /* no condition was asked for */
        return CURLE_OK;
    }
    result = unsafe{Curl_gmtime((*data).set.timevalue, &mut keeptime)};
    if result as u64 != 0 {
        unsafe{Curl_failf(
            data,
            b"Invalid TIMEVALUE\0" as *const u8 as *const libc::c_char,
        );}
        return result;
    }
    tm = &mut keeptime;

    match unsafe{(*data).set.timecondition as u32} {
        CURL_TIMECOND_IFMODSINCE => {
            condp = b"If-Modified-Since\0" as *const u8 as *const libc::c_char;
        }
        CURL_TIMECOND_IFUNMODSINCE => {
            condp = b"If-Unmodified-Since\0" as *const u8 as *const libc::c_char;
        }
        CURL_TIMECOND_LASTMOD => {
            condp = b"Last-Modified\0" as *const u8 as *const libc::c_char;
        }
        _ => return CURLE_BAD_FUNCTION_ARGUMENT,
    }
    if unsafe{!(Curl_checkheaders(data, condp)).is_null()} {
        /* A custom header was specified; it will be sent instead. */
        return CURLE_OK;
    }

    /* The If-Modified-Since header family should have their times set in
     * GMT as RFC2616 defines: "All HTTP date/time stamps MUST be
     * represented in Greenwich Mean Time (GMT), without exception. For the
     * purposes of HTTP, GMT is exactly equal to UTC (Coordinated Universal
     * Time)." (see page 20 of RFC2616).
     */

    /* format: "Tue, 15 Nov 1994 12:45:26 GMT" */
    unsafe{curl_msnprintf(
        datestr.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 80]>() as u64,
        b"%s: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8 as *const libc::c_char,
        condp,
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
    );}

    result = unsafe{Curl_hyper_header(data, req as *mut hyper_headers, datestr.as_mut_ptr())};
    return result;
}

#[cfg(all(not(CURL_DISABLE_PARSEDATE), not(USE_HYPER)))]
#[no_mangle]
pub  extern "C" fn Curl_add_timecondition(
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
    if unsafe{(*data).set.timecondition as u32 == CURL_TIMECOND_NONE as u32 }{
        return CURLE_OK;
    }
    result =unsafe{ Curl_gmtime((*data).set.timevalue, &mut keeptime)};
    if result as u64 != 0 {
        unsafe{ Curl_failf(
            data,
            b"Invalid TIMEVALUE\0" as *const u8 as *const libc::c_char,
        );}
        return result;
    }
    tm = &mut keeptime;
    match unsafe{(*data).set.timecondition as u32} {
        CURL_TIMECOND_IFMODSINCE => {
            condp = b"If-Modified-Since\0" as *const u8 as *const libc::c_char;
        }
        CURL_TIMECOND_IFUNMODSINCE => {
            condp = b"If-Unmodified-Since\0" as *const u8 as *const libc::c_char;
        }
        CURL_TIMECOND_LASTMOD => {
            condp = b"Last-Modified\0" as *const u8 as *const libc::c_char;
        }
        _ => return CURLE_BAD_FUNCTION_ARGUMENT,
    }
    if unsafe{!(Curl_checkheaders(data, condp)).is_null()} {
        return CURLE_OK;
    }
    unsafe{ curl_msnprintf(
        datestr.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 80]>() as u64,
        b"%s: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8 as *const libc::c_char,
        condp,
        Curl_wkday[(if (*tm).tm_wday != 0 {
            (*tm).tm_wday - 1
        } else {
            6
        }) as usize],
        (*tm).tm_mday,
        Curl_month[(*tm).tm_mon as usize],
        (*tm).tm_year + 1900,
        (*tm).tm_hour,
        (*tm).tm_min,
        (*tm).tm_sec,
    );}
    result = unsafe{Curl_dyn_add(req, datestr.as_mut_ptr())};
    return result;
}

/* disabled */
#[cfg(CURL_DISABLE_PARSEDATE)]
pub  extern "C" fn Curl_add_timecondition(
    mut data: *mut Curl_easy,
    mut req: *mut dynbuf,
) -> CURLcode {
    return CURLE_OK;
}

const PROTO_FAMILY_HTTP: u32 = 1 << 0 | 1 << 1;
const CURLPROTO_FTP: u32 = 1 << 2;

#[no_mangle]
pub  extern "C" fn Curl_http_method(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut method: *mut *const libc::c_char,
    mut reqp: *mut Curl_HttpReq,
) {
    let mut httpreq: Curl_HttpReq = unsafe{(*data).state.httpreq};
    let mut request: *const libc::c_char = 0 as *const libc::c_char;
    if unsafe{(*(*conn).handler).protocol
        & (PROTO_FAMILY_HTTP | CURLPROTO_FTP)
        != 0
        && ((*data).set).upload() as i32 != 0}
    {
        httpreq = HTTPREQ_PUT;
    }

    /* Now set the 'request' pointer to the proper request string */
    if unsafe{!((*data).set.str_0[STRING_CUSTOMREQUEST as usize]).is_null()} {
        request = unsafe{(*data).set.str_0[STRING_CUSTOMREQUEST as usize]};
    } else if unsafe{((*data).set).opt_no_body() != 0} {
        request = b"HEAD\0" as *const u8 as *const libc::c_char;
    } else {
        #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
        if httpreq as u32 >= HTTPREQ_GET as u32
            && httpreq as u32 <= HTTPREQ_HEAD as u32
        {
        } else {unsafe{
            __assert_fail(
                b"(httpreq >= HTTPREQ_GET) && (httpreq <= HTTPREQ_HEAD)\0" as *const u8
                    as *const libc::c_char,
                b"http.c\0" as *const u8 as *const libc::c_char,
                2041 as u32,
                (*::std::mem::transmute::<
                    &[u8; 95],
                    &[libc::c_char; 95],
                >(
                    b"void Curl_http_method(struct Curl_easy *, struct connectdata *, const char **, Curl_HttpReq *)\0",
                ))
                    .as_ptr(),
            );}
        }
        match httpreq as u32 {
            HTTPREQ_POST | HTTPREQ_POST_FORM | HTTPREQ_POST_MIME => {
                request = b"POST\0" as *const u8 as *const libc::c_char;
            }
            HTTPREQ_PUT => {
                request = b"PUT\0" as *const u8 as *const libc::c_char;
            }
            HTTPREQ_HEAD => {
                request = b"HEAD\0" as *const u8 as *const libc::c_char;
            }
            HTTPREQ_GET | _ /* this should never happen */ => {
                request = b"GET\0" as *const u8 as *const libc::c_char;
            }
        }
    }
    unsafe{*method = request;
    *reqp = httpreq;}
}

#[no_mangle]
pub  extern "C" fn Curl_http_useragent(mut data: *mut Curl_easy) -> CURLcode {
      /* The User-Agent string might have been allocated in url.c already, because
     it might have been used in the proxy connect, but if we have got a header
     with the user-agent string specified, we erase the previously made string
     here. */
    if unsafe{!(Curl_checkheaders(data, b"User-Agent\0" as *const u8 as *const libc::c_char)).is_null()} {
        unsafe{
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.uagent as *mut libc::c_void,
        );
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.aptr.uagent as *mut libc::c_void,
            2072,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        (*data).state.aptr.uagent = 0 as *mut libc::c_char;}
    }
    return CURLE_OK;
}

#[no_mangle]
pub  extern "C" fn Curl_http_host(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    if unsafe{((*data).state).this_is_a_follow() == 0} {
        /* Free to avoid leaking memory on multiple requests*/
        unsafe{
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.first_host as *mut libc::c_void,
        );
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.first_host as *mut libc::c_void,
            2084,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );}
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                unsafe{(*data).state.first_host =
                    Curl_cstrdup.expect("non-null function pointer")((*conn).host.name);}
            }
            #[cfg(CURLDEBUG)]
            _ => {
                unsafe{ (*data).state.first_host = curl_dbg_strdup(
                    (*conn).host.name,
                    2086 as i32,
                    b"http.c\0" as *const u8 as *const libc::c_char,
                );}
            }
        }
        if unsafe{((*data).state.first_host).is_null()} {
            return CURLE_OUT_OF_MEMORY;
        }
        unsafe{  (*data).state.first_remote_port = (*conn).remote_port;}
    }
    unsafe{
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")((*data).state.aptr.host as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*data).state.aptr.host as *mut libc::c_void,
        2092 as i32,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    (*data).state.aptr.host = 0 as *mut libc::c_char;}
    ptr = unsafe{Curl_checkheaders(data, b"Host\0" as *const u8 as *const libc::c_char)};
    if unsafe{!ptr.is_null()
        && (((*data).state).this_is_a_follow() == 0
            || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0)}
    {
        match () {
            #[cfg(not(CURL_DISABLE_COOKIES))]
            /* If we have a given custom Host: header, we extract the host name in
       order to possibly use it for cookie reasons later on. We only allow the
       custom Host: header if this is NOT a redirect, as setting Host: in the
       redirected request is being out on thin ice. Except if the host name
       is the same as the first one! */
            _ => {
                let mut cookiehost: *mut libc::c_char = Curl_copy_header_value(ptr);
                if cookiehost.is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                if unsafe{*cookiehost == 0 }{unsafe{
                    /* ignore empty data */
                    #[cfg(not(CURLDEBUG))]
                    Curl_cfree.expect("non-null function pointer")(cookiehost as *mut libc::c_void);
                    #[cfg(CURLDEBUG)]
                    curl_dbg_free(
                        cookiehost as *mut libc::c_void,
                        2108,
                        b"http.c\0" as *const u8 as *const libc::c_char,
                    );}
                } else {
                    /* If the host begins with '[', we start searching for the port after
         the bracket has been closed */
                    if unsafe{*cookiehost as i32 == '[' as i32} {
                        let mut closingbracket: *mut libc::c_char = 0 as *mut libc::c_char;
                        /* since the 'cookiehost' is an allocated memory area that will be
           freed later we cannot simply increment the pointer */
           unsafe{ memmove(
                            cookiehost as *mut libc::c_void,
                            cookiehost.offset(1 as isize) as *const libc::c_void,
                            (strlen(cookiehost)).wrapping_sub(1 as u64),
                        );
                        closingbracket = strchr(cookiehost, ']' as i32);
                        if !closingbracket.is_null() {
                            *closingbracket = 0 as libc::c_char;
                        }}
                    } else {
                        let mut startsearch: i32 = 0;
                        let mut colon: *mut libc::c_char =
                        unsafe{strchr(cookiehost.offset(startsearch as isize), ':' as i32)};
                        if !colon.is_null() {
                            unsafe{ *colon = 0 as libc::c_char; }/* The host must not include an embedded port number */
                        }
                    }unsafe{
                    #[cfg(not(CURLDEBUG))]
                    Curl_cfree.expect("non-null function pointer")(
                        (*data).state.aptr.cookiehost as *mut libc::c_void,
                    );
                    #[cfg(CURLDEBUG)]
                    curl_dbg_free(
                        (*data).state.aptr.cookiehost as *mut libc::c_void,
                        2127,
                        b"http.c\0" as *const u8 as *const libc::c_char,
                    );
                    (*data).state.aptr.cookiehost = 0 as *mut libc::c_char;
                    (*data).state.aptr.cookiehost = cookiehost;}
                }
            }
            #[cfg(CURL_DISABLE_COOKIES)]
            _ => {}
        }
        if unsafe{strcmp(b"Host:\0" as *const u8 as *const libc::c_char, ptr) != 0 }{
            unsafe{ (*data).state.aptr.host = curl_maprintf(
                b"Host:%s\r\n\0" as *const u8 as *const libc::c_char,
                &*ptr.offset(5 as isize) as *const libc::c_char,
            );
            if ((*data).state.aptr.host).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }}
        } else {
            /* when clearing the header */
            unsafe{(*data).state.aptr.host = 0 as *mut libc::c_char;}
        }
    } else {
        /* When building Host: headers, we must put the host name within
       [brackets] if the host name is a plain IPv6-address. RFC2732-style. */
        let mut host: *const libc::c_char = unsafe{(*conn).host.name};
        if unsafe{(*(*conn).given).protocol & CURLPROTO_HTTPS != 0
            && (*conn).remote_port == PORT_HTTPS
            || (*(*conn).given).protocol & CURLPROTO_HTTP != 0
                && (*conn).remote_port == PORT_HTTP}
        {
            /* if(HTTPS on port 443) OR (HTTP on port 80) then don't include
         the port number in the host string */
         unsafe{(*data).state.aptr.host = curl_maprintf(
                b"Host: %s%s%s\r\n\0" as *const u8 as *const libc::c_char,
                if ((*conn).bits).ipv6_ip() as i32 != 0 {
                    b"[\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                host,
                if ((*conn).bits).ipv6_ip() as i32 != 0 {
                    b"]\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
            );}
        } else {
            unsafe{(*data).state.aptr.host = curl_maprintf(
                b"Host: %s%s%s:%d\r\n\0" as *const u8 as *const libc::c_char,
                if ((*conn).bits).ipv6_ip() as i32 != 0 {
                    b"[\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                host,
                if ((*conn).bits).ipv6_ip() as i32 != 0 {
                    b"]\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                (*conn).remote_port,
            );}
        }
        /* without Host: we can't make a nice request */
        if unsafe{((*data).state.aptr.host).is_null()} {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}

/*
 * Append the request-target to the HTTP request
 */
#[no_mangle]
pub  extern "C" fn Curl_http_target(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut path: *const libc::c_char = unsafe{(*data).state.up.path};
    let mut query: *const libc::c_char = unsafe{ (*data).state.up.query};
    
    if unsafe{!((*data).set.str_0[STRING_TARGET as usize]).is_null()} {
        path = unsafe{(*data).set.str_0[STRING_TARGET as usize]};
        query = 0 as *const libc::c_char;
    }
    match () {
        #[cfg(not(CURL_DISABLE_PROXY))]
        _ => {
            if unsafe{((*conn).bits).httpproxy() as i32 != 0 && ((*conn).bits).tunnel_proxy() == 0} {
                /* Using a proxy but does not tunnel through it */

    /* The path sent to the proxy is in fact the entire URL. But if the remote
       host is a IDN-name, we must make sure that the request we produce only
       uses the encoded host name! */

    /* and no fragment part */
                let mut uc: CURLUcode = CURLUE_OK;
                let mut url: *mut libc::c_char = 0 as *mut libc::c_char;
                let mut h: *mut CURLU = unsafe{curl_url_dup((*data).state.uh)};
                if h.is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }

                if unsafe{(*conn).host.dispname != (*conn).host.name as *const libc::c_char} {
                    uc = unsafe{curl_url_set(h, CURLUPART_HOST, (*conn).host.name, 0 as u32)};
                    if uc as u64 != 0 {
                        unsafe{ curl_url_cleanup(h);}
                        return CURLE_OUT_OF_MEMORY;
                    }
                }
                uc = unsafe{curl_url_set(
                    h,
                    CURLUPART_FRAGMENT,
                    0 as *const libc::c_char,
                    0 as u32,
                )};
                if uc as u64 != 0 {
                    unsafe{ curl_url_cleanup(h);}
                    return CURLE_OUT_OF_MEMORY;
                }

                if unsafe{Curl_strcasecompare(
                    b"http\0" as *const u8 as *const libc::c_char,
                    (*data).state.up.scheme,
                ) != 0}
                {
                    /* when getting HTTP, we don't want the userinfo the URL */
                    uc = unsafe{curl_url_set(h, CURLUPART_USER, 0 as *const libc::c_char, 0 as u32)};
                    if uc as u64 != 0 {
                        unsafe{curl_url_cleanup(h);}
                        return CURLE_OUT_OF_MEMORY;
                    }
                    uc = unsafe{curl_url_set(
                        h,
                        CURLUPART_PASSWORD,
                        0 as *const libc::c_char,
                        0 as u32,
                    )};
                    if uc as u64 != 0 {
                        unsafe{curl_url_cleanup(h);}
                        return CURLE_OUT_OF_MEMORY;
                    }
                }
                /* Extract the URL to use in the request. Store in STRING_TEMP_URL for
       clean-up reasons if the function returns before the free() further
       down. */
                uc = unsafe{curl_url_get(h, CURLUPART_URL, &mut url, ((1 as i32) << 1 as i32) as u32)};
                if uc as u64 != 0 {
                    unsafe{ curl_url_cleanup(h);}
                    return CURLE_OUT_OF_MEMORY;
                }
                unsafe{  curl_url_cleanup(h);}
                result = unsafe{Curl_dyn_add(
                    r,
                    if !((*data).set.str_0[STRING_TARGET as usize]).is_null() {
                        (*data).set.str_0[STRING_TARGET as usize]
                    } else {
                        url
                    },
                )};
                unsafe{
                #[cfg(not(CURLDEBUG))]
                Curl_cfree.expect("non-null function pointer")(url as *mut libc::c_void);
                #[cfg(CURLDEBUG)]
                curl_dbg_free(
                    url as *mut libc::c_void,
                    2241,
                    b"http.c\0" as *const u8 as *const libc::c_char,
                );
            }
                /* target or url */
                if result as u64 != 0 {
                    return result;
                }
                if unsafe{Curl_strcasecompare(
                    b"ftp\0" as *const u8 as *const libc::c_char,
                    (*data).state.up.scheme,
                ) != 0}
                {
                    if unsafe{((*data).set).proxy_transfer_mode() != 0} {
                        /* when doing ftp, append ;type=<a|i> if not present */
                        let mut type_0: *mut libc::c_char =
                        unsafe{ strstr(path, b";type=\0" as *const u8 as *const libc::c_char)};
                        if unsafe{!type_0.is_null()
                            && *type_0.offset(6 as isize) as i32 != 0
                            && *type_0.offset(7 as isize) as i32 == 0}
                        {
                            match unsafe{Curl_raw_toupper(*type_0.offset(6 as isize)) as i32} {
                                65 | 68 | 73 => {}
                                _ => {
                                    type_0 = 0 as *mut libc::c_char;
                                }
                            }
                        }
                        if type_0.is_null() {
                            result = unsafe{Curl_dyn_addf(
                                r,
                                b";type=%c\0" as *const u8 as *const libc::c_char,
                                if ((*data).state).prefer_ascii() as i32 != 0 {
                                    'a' as i32
                                } else {
                                    'i' as i32
                                },
                            )};
                            if result as u64 != 0 {
                                return result;
                            }
                        }
                    }
                }
            } else {
                result = unsafe{Curl_dyn_add(r, path)};
                if result as u64 != 0 {
                    return result;
                }
                if !query.is_null() {
                    result = unsafe{Curl_dyn_addf(r, b"?%s\0" as *const u8 as *const libc::c_char, query)};
                }
            }
        }
        #[cfg(CURL_DISABLE_PROXY)]
        _ => {
            result = unsafe{Curl_dyn_add(r, path)};
            if result as u64 != 0 {
                return result;
            }
            if !query.is_null() {
                result = unsafe{Curl_dyn_addf(r, b"?%s\0" as *const u8 as *const libc::c_char, query)};
            }
        }
    }
    return result;
}

#[no_mangle]
pub  extern "C" fn Curl_http_body(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut httpreq: Curl_HttpReq,
    mut tep: *mut *const libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    let mut http: *mut HTTP = unsafe{(*data).req.p.http};
    unsafe{(*http).postsize = 0 as curl_off_t;}
    
    match httpreq as u32 {
        HTTPREQ_POST_MIME => {
            unsafe{(*http).sendit = &mut (*data).set.mimepost;}
        }
        HTTPREQ_POST_FORM => {
            unsafe{
            /* Convert the form structure into a mime structure. */
            #[cfg(any(
                all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)),
                not(CURL_DISABLE_SMTP),
                not(CURL_DISABLE_IMAP)
            ))]
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
            (*http).sendit = &mut (*http).form;}
        }
        _ => {
            unsafe{(*http).sendit = 0 as *mut curl_mimepart;}
        }
    }
    #[cfg(not(CURL_DISABLE_MIME))]
    if !(unsafe{(*http).sendit}).is_null(){
        let mut cthdr: *const libc::c_char =
        unsafe{Curl_checkheaders(data, b"Content-Type\0" as *const u8 as *const libc::c_char)};
        
        /* Read and seek body only. */
        unsafe{(*(*http).sendit).flags |= MIME_BODY_ONLY;}

        /* Prepare the mime structure headers & set content type. */
        if !cthdr.is_null() {
            cthdr = unsafe{cthdr.offset(13 as isize)};
            while unsafe{*cthdr as i32 == ' ' as i32} {
                cthdr = unsafe{cthdr.offset(1)};
            }
        } else if unsafe{(*(*http).sendit).kind as u32 == MIMEKIND_MULTIPART as u32} {
            cthdr = b"multipart/form-data\0" as *const u8 as *const libc::c_char;
        }
        unsafe{ curl_mime_headers((*http).sendit, (*data).set.headers, 0 as i32);}
        // 好像这里其实可以不要条件编译
        match () {
            #[cfg(any(
                all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)),
                not(CURL_DISABLE_SMTP),
                not(CURL_DISABLE_IMAP)
            ))]
            _ => {
                result = unsafe{Curl_mime_prepare_headers(
                    (*http).sendit,
                    cthdr,
                    0 as *const libc::c_char,
                    MIMESTRATEGY_FORM,
                )};
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
        unsafe{ curl_mime_headers((*http).sendit, 0 as *mut curl_slist, 0 as i32);}
        if result as u64 == 0 {
            result =unsafe{ Curl_mime_rewind((*http).sendit)};
        }
        if result as u64 != 0 {
            return result;
        }
        unsafe{(*http).postsize = Curl_mime_size((*http).sendit);}
    }
    ptr = unsafe{Curl_checkheaders(
        data,
        b"Transfer-Encoding\0" as *const u8 as *const libc::c_char,
    )};
    if !ptr.is_null() {
        /* Some kind of TE is requested, check if 'chunked' is chosen */
        unsafe{ (*data).req.set_upload_chunky(Curl_compareheader(
            ptr,
            b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
            b"chunked\0" as *const u8 as *const libc::c_char,
        ) as bit);}
    } else {
        if unsafe{(*(*conn).handler).protocol & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
            != 0
            && ((httpreq as u32 == HTTPREQ_POST_MIME as u32
                || httpreq as u32 == HTTPREQ_POST_FORM as u32)
                && (*http).postsize < 0 as i32 as i64
                || (((*data).set).upload() as i32 != 0
                    || httpreq as u32 == HTTPREQ_POST as u32)
                    && (*data).state.infilesize == -(1 as i32) as i64)}
        {unsafe{
            if !(((*conn).bits).authneg() != 0) {
                if Curl_use_http_1_1plus(data, conn) {
                    if ((*conn).httpversion as i32) < 20 {
                        (*data).req.set_upload_chunky(1 as bit);
                    }
                } else {
                    Curl_failf(
                        data,
                        b"Chunky upload is not supported by HTTP 1.0\0" as *const u8
                            as *const libc::c_char,
                    );
                    return CURLE_UPLOAD_FAILED;
                }
            }}
        } else {
            unsafe{ (*data).req.set_upload_chunky(0 as bit);}
        }
        if unsafe{ ((*data).req).upload_chunky() != 0 }{
            unsafe{*tep = b"Transfer-Encoding: chunked\r\n\0" as *const u8 as *const libc::c_char;}
        }
    }
    return result;
}

#[no_mangle]
pub  extern "C" fn Curl_http_bodysend(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    /* Hyper always handles the body separately */
    #[cfg(not(USE_HYPER))]
    let mut included_body: curl_off_t = 0 as curl_off_t;
    let mut result: CURLcode = CURLE_OK;
    let mut http: *mut HTTP = unsafe{(*data).req.p.http};
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    
    /* If 'authdone' is FALSE, we must not set the write socket index to the
     Curl_transfer() call below, as we're not ready to actually upload any
     data yet. */
    
    match httpreq as u32 {
        HTTPREQ_PUT => { /* Let's PUT the data to the server! */
            if unsafe{((*conn).bits).authneg() != 0 }{
                unsafe{ (*http).postsize = 0 as curl_off_t;}
            } else {
                unsafe{  (*http).postsize = (*data).state.infilesize;}
            }
            if unsafe{(*http).postsize != -1 as i64
                && ((*data).req).upload_chunky() == 0
                && (((*conn).bits).authneg() as i32 != 0
                    || (Curl_checkheaders(
                        data,
                        b"Content-Length\0" as *const u8 as *const libc::c_char,
                    ))
                    .is_null())}
            {
                /* only add Content-Length if not uploading chunked */
                result = unsafe{Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*http).postsize,
                )};
                if result as u64 != 0 {
                    return result;
                }
            }
            if unsafe{(*http).postsize != 0 }{
                result = unsafe{expect100(data, conn, r)};
                if result as u64 != 0 {
                    return result;
                }
            }
            result = unsafe{Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char)};
            if result as u64 != 0 {
                return result;
            }
            /* set the upload size to the progress meter */
            unsafe{Curl_pgrsSetUploadSize(data, (*http).postsize);}

            /* this sends the buffer and frees all the buffer resources */
            result = unsafe{Curl_buffer_send(
                r,
                data,
                &mut (*data).info.request_size,
                0 as curl_off_t,
                0,
            )};
            /* this sends the buffer and frees all the buffer resources */
            if result as u64 != 0 {
                unsafe{ Curl_failf(
                    data,
                    b"Failed sending PUT request\0" as *const u8 as *const libc::c_char,
                )};
            } else {
                /* prepare for transfer */
                unsafe{ Curl_setup_transfer(
                    data,
                    0,
                    -1 as curl_off_t,
                    true,
                    if (*http).postsize != 0 {
                        0
                    } else {
                        -1
                    },
                );}
            }
            if result as u64 != 0 {
                return result;
            }
        }
        HTTPREQ_POST_FORM | HTTPREQ_POST_MIME => {
            /* This is form posting using mime data. */
            if unsafe{((*conn).bits).authneg() != 0 }{
                /* nothing to post! */
                result = unsafe{Curl_dyn_add(
                    r,
                    b"Content-Length: 0\r\n\r\n\0" as *const u8 as *const libc::c_char,
                )};

                if result as u64 != 0 {
                    return result;
                }

                result = unsafe{Curl_buffer_send(
                    r,
                    data,
                    &mut (*data).info.request_size,
                    0 as curl_off_t,
                    0,
                )};
                if result as u64 != 0 {
                    unsafe{Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8 as *const libc::c_char,
                    );}
                } else {
                    unsafe{Curl_setup_transfer(
                        data,
                        0,
                        -1 as curl_off_t,
                        true,
                        -1,
                    );}
                }
            } else {
                unsafe{ (*data).state.infilesize = (*http).postsize;}
                
                /* We only set Content-Length and allow a custom Content-Length if
       we don't upload data chunked, as RFC2616 forbids us to set both
       kinds of headers (Transfer-Encoding: chunked and Content-Length) */
                if unsafe{(*http).postsize != -1 as i64
                    && ((*data).req).upload_chunky() == 0
                    && (((*conn).bits).authneg() as i32 != 0
                        || (Curl_checkheaders(
                            data,
                            b"Content-Length\0" as *const u8 as *const libc::c_char,
                        ))
                        .is_null())}
                {
                    /* we allow replacing this header if not during auth negotiation,
         although it isn't very wise to actually set your own */
                    result = unsafe{Curl_dyn_addf(
                        r,
                        b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                        (*http).postsize,
                    )};
                    if result as u64 != 0 {
                        return result;
                    }
                }
                // TODO 测试过了就把注释删咯
                if cfg!(not(CURL_DISABLE_MIME)) {
                    let mut hdr: *mut curl_slist = 0 as *mut curl_slist;
                    hdr =unsafe{ (*(*http).sendit).curlheaders};
                    while !hdr.is_null() {
                        result = unsafe{Curl_dyn_addf(
                            r,
                            b"%s\r\n\0" as *const u8 as *const libc::c_char,
                            (*hdr).data,
                        )};
                        if result as u64 != 0 {
                            return result;
                        }
                        hdr = unsafe{(*hdr).next};
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
                /* For really small posts we don't use Expect: headers at all, and for
       the somewhat bigger ones we allow the app to disable it. Just make
       sure that the expect100header is always set to the preferred value
       here. */

                ptr = unsafe{Curl_checkheaders(data, b"Expect\0" as *const u8 as *const libc::c_char)};
                if !ptr.is_null() {
                    unsafe{ (*data).state.set_expect100header(Curl_compareheader(
                        ptr,
                        b"Expect:\0" as *const u8 as *const libc::c_char,
                        b"100-continue\0" as *const u8 as *const libc::c_char,
                    ) as bit);}

                } else if unsafe{(*http).postsize > EXPECT_100_THRESHOLD
                    || (*http).postsize < 0 as i64}
                {
                    /* make the request end in a true CRLF */
                    result = unsafe{expect100(data, conn, r)};
                    if result as u64 != 0 {
                        return result;
                    }
                } else {
                    unsafe{(*data).state.set_expect100header(0 as bit);}
                }
                result = unsafe{Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char)};
                if result as u64 != 0 {
                    return result;
                }

                /* set the upload size to the progress meter */
                unsafe{  Curl_pgrsSetUploadSize(data, (*http).postsize);}
                let ref mut fresh51 = unsafe{(*data).state.fread_func};
                // TODO 这里也有条件编译
                match () {
                    #[cfg(any(
                        all(not(CURL_DISABLE_HTTP), not(CURL_DISABLE_MIME)),
                        not(CURL_DISABLE_SMTP),
                        not(CURL_DISABLE_IMAP)
                    ))]
                    _ => {
                        *fresh51 = unsafe{::std::mem::transmute::<
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
                        ))};
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

                /* Read from mime structure. */
                unsafe{(*data).state.in_0 = (*http).sendit as *mut libc::c_void;
                (*http).sending = HTTPSEND_BODY;}
                
                /* this sends the buffer and frees all the buffer resources */
                result =unsafe{ Curl_buffer_send(
                    r,
                    data,
                    &mut (*data).info.request_size,
                    0 as curl_off_t,
                    0,
                )};

                if result as u64 != 0 {
                    unsafe{ Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8 as *const libc::c_char,
                    )};
                } else {
                    /* prepare for transfer */
                    unsafe{ Curl_setup_transfer(
                        data,
                        FIRSTSOCKET,
                        -1 as curl_off_t,
                        true,
                        if (*http).postsize != 0 {
                            FIRSTSOCKET
                        } else {
                            -1
                        },
                    );}
                }
                if result as u64 != 0 {
                    return result;
                }
            }
        }
        HTTPREQ_POST => {
            /* this is the simple POST, using x-www-form-urlencoded style */

            if unsafe{((*conn).bits).authneg() != 0} {
                unsafe{(*http).postsize = 0 as curl_off_t;}
            } else {
                /* the size of the post body */
                unsafe{(*http).postsize = (*data).state.infilesize;}
            }

            /* We only set Content-Length and allow a custom Content-Length if
       we don't upload data chunked, as RFC2616 forbids us to set both
       kinds of headers (Transfer-Encoding: chunked and Content-Length) */
            if unsafe{(*http).postsize != -1 as i64
                && ((*data).req).upload_chunky() == 0
                && (((*conn).bits).authneg() as i32 != 0
                    || (Curl_checkheaders(
                        data,
                        b"Content-Length\0" as *const u8 as *const libc::c_char,
                    ))
                    .is_null())}
            {
                /* we allow replacing this header if not during auth negotiation,
         although it isn't very wise to actually set your own */
                result = unsafe{Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*http).postsize,
                )};
                if result as u64 != 0 {
                    return result;
                }
            }
            if unsafe{(Curl_checkheaders(data, b"Content-Type\0" as *const u8 as *const libc::c_char))
                .is_null()}
            {
                result =unsafe{ Curl_dyn_add(
                    r,
                    b"Content-Type: application/x-www-form-urlencoded\r\n\0" as *const u8
                        as *const libc::c_char,
                )};
                if result as u64 != 0 {
                    return result;
                }
            }

            /* For really small posts we don't use Expect: headers at all, and for
       the somewhat bigger ones we allow the app to disable it. Just make
       sure that the expect100header is always set to the preferred value
       here. */
            ptr =unsafe{ Curl_checkheaders(data, b"Expect\0" as *const u8 as *const libc::c_char)};
            if !ptr.is_null() {unsafe{
                (*data).state.set_expect100header(Curl_compareheader(
                    ptr,
                    b"Expect:\0" as *const u8 as *const libc::c_char,
                    b"100-continue\0" as *const u8 as *const libc::c_char,
                ) as bit);}
            } else if unsafe{(*http).postsize > EXPECT_100_THRESHOLD
                || (*http).postsize < 0 as i64}
            {
                result = unsafe{expect100(data, conn, r)};
                if result as u64 != 0 {
                    return result;
                }
            } else {
                unsafe{(*data).state.set_expect100header(0 as bit);}
            }
            // TODO 测试通过了就把match删咯
            let flag: bool = if cfg!(not(USE_HYPER)) {
                unsafe{!((*data).set.postfields).is_null()}
            } else {
                false
            };
            if flag {
                if unsafe{(*conn).httpversion as i32 != 20
                    && ((*data).state).expect100header() == 0
                    && (*http).postsize < (64 * 1024) as i64}
                {
                    /* make the request end in a true CRLF */
                    result = unsafe{Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char)};
                    if result as u64 != 0 {
                        return result;
                    }
                    if unsafe{((*data).req).upload_chunky() == 0 }{
                        result =
                        unsafe{Curl_dyn_addn(r, (*data).set.postfields, (*http).postsize as size_t)};
                        included_body = unsafe{(*http).postsize};
                    } else {
                        if unsafe{(*http).postsize != 0} {
                            let mut chunk: [libc::c_char; 16] = [0; 16];
                            unsafe{curl_msnprintf(
                                chunk.as_mut_ptr(),
                                ::std::mem::size_of::<[libc::c_char; 16]>() as u64,
                                b"%x\r\n\0" as *const u8 as *const libc::c_char,
                                (*http).postsize as i32,
                            );}
                            result = unsafe{Curl_dyn_add(r, chunk.as_mut_ptr())};
                            if result as u64 == 0 {
                                included_body = unsafe{((*http).postsize as u64)
                                    .wrapping_add(strlen(chunk.as_mut_ptr()))
                                    as curl_off_t};
                                result =unsafe{Curl_dyn_addn(
                                    r,
                                    (*data).set.postfields,
                                    (*http).postsize as size_t,
                                )};
                                if result as u64 == 0 {
                                    result = unsafe{Curl_dyn_add(
                                        r,
                                        b"\r\n\0" as *const u8 as *const libc::c_char,
                                    )};
                                }
                                included_body += 2 as i64;
                            }
                        }
                        if result as u64 == 0 {
                            result =
                            unsafe{Curl_dyn_add(r, b"0\r\n\r\n\0" as *const u8 as *const libc::c_char)};
                            included_body += 5 as i64;
                        }
                    }
                    if result as u64 != 0 {
                        return result;
                    }

                    /* set the upload size to the progress meter */
                    unsafe{ Curl_pgrsSetUploadSize(data, (*http).postsize);}
                } else {
                    unsafe{  (*http).postdata = (*data).set.postfields as *const libc::c_char;
                    (*http).sending = HTTPSEND_BODY;
                    (*data).state.fread_func = ::std::mem::transmute::<
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
                    (*data).state.in_0 = data as *mut libc::c_void;
                    Curl_pgrsSetUploadSize(data, (*http).postsize);}
                    result = unsafe{Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char)};
                    if result as u64 != 0 {
                        return result;
                    }
                }
            } else {
                /* make the request end in a true CRLF */
                result =unsafe{ Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char)};
                if result as u64 != 0 {
                    return result;
                }
                if unsafe{((*data).req).upload_chunky() as i32 != 0 && ((*conn).bits).authneg() as i32 != 0}
                {
                    result = unsafe{Curl_dyn_add(
                        r,
                        b"0\r\n\r\n\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    )};
                    if result as u64 != 0 {
                        return result;
                    }
                } else if unsafe{(*data).state.infilesize != 0 }{
                    unsafe{ Curl_pgrsSetUploadSize(
                        data,
                        if (*http).postsize != 0 {
                            (*http).postsize
                        } else {
                           -1 as i64
                        },
                    );}
                    if unsafe{((*conn).bits).authneg() == 0} {
                        unsafe{  (*http).postdata =
                            &mut (*http).postdata as *mut *const libc::c_char as *mut libc::c_char;}
                    }
                }
            }
            // match () {
            //     #[cfg(not(USE_HYPER))]
            //     _ => {
            //         if !((*data).set.postfields).is_null() {
            //             if (*conn).httpversion as i32 != 20 as i32
            //                 && ((*data).state).expect100header() == 0
            //                 && (*http).postsize < (64 as i32 * 1024 as i32) as i64
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
            //                             ::std::mem::size_of::<[libc::c_char; 16]>() as u64,
            //                             b"%x\r\n\0" as *const u8 as *const libc::c_char,
            //                             (*http).postsize as i32,
            //                         );
            //                         result = Curl_dyn_add(r, chunk.as_mut_ptr());
            //                         if result as u64 == 0 {
            //                             included_body = ((*http).postsize as u64)
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
            //                             included_body += 2 as i32 as i64;
            //                         }
            //                     }
            //                     if result as u64 == 0 {
            //                         result =
            //                             Curl_dyn_add(r, b"0\r\n\r\n\0" as *const u8 as *const libc::c_char);
            //                         included_body += 5 as i32 as i64;
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
            //             if ((*data).req).upload_chunky() as i32 != 0
            //                 && ((*conn).bits).authneg() as i32 != 0
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
            //                         -(1 as i32) as i64
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
            //         if ((*data).req).upload_chunky() as i32 != 0
            //             && ((*conn).bits).authneg() as i32 != 0
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
            //                     -(1 as i32) as i64
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

            /* this sends the buffer and frees all the buffer resources */
            result = unsafe{Curl_buffer_send(
                r,
                data,
                &mut (*data).info.request_size,
                included_body,
                0,
            )};
            if result as u64 != 0 {
                unsafe{ Curl_failf(
                    data,
                    b"Failed sending HTTP POST request\0" as *const u8 as *const libc::c_char,
                );}
            } else {
                unsafe{Curl_setup_transfer(
                    data,
                    0,
                    -1 as curl_off_t,
                    true,
                    if !((*http).postdata).is_null() {
                        0 
                    } else {
                        -1
                    },
                );}
            }
        }
        _ => {
            result = unsafe{Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char)};
            if result as u64 != 0 {
                return result;
            }
            result = unsafe{Curl_buffer_send(
                r,
                data,
                &mut (*data).info.request_size,
                0 as curl_off_t,
                0,
            )};
            if result as u64 != 0 {
                unsafe{ Curl_failf(
                    data,
                    b"Failed sending HTTP request\0" as *const u8 as *const libc::c_char,
                );}
            } else {
                unsafe{Curl_setup_transfer(
                    data,
                    0,
                    -1 as curl_off_t,
                    true,
                    -1,
                );}
            }
        }
    }
    return result;
}

#[cfg(not(CURL_DISABLE_COOKIES))]
#[no_mangle]
pub  extern "C" fn Curl_http_cookies(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut addcookies: *mut libc::c_char = 0 as *mut libc::c_char;
    if unsafe{!((*data).set.str_0[STRING_COOKIE as usize]).is_null()
        && (Curl_checkheaders(data, b"Cookie\0" as *const u8 as *const libc::c_char)).is_null()}
    {
        addcookies = unsafe{(*data).set.str_0[STRING_COOKIE as usize]};
    }
    if unsafe{!((*data).cookies).is_null() || !addcookies.is_null()} {
        let mut co: *mut Cookie = 0 as *mut Cookie;
        let mut count: i32 = 0 as i32;
        if unsafe{!((*data).cookies).is_null() && ((*data).state).cookie_engine() as i32 != 0 }{
            let mut host: *const libc::c_char = unsafe{if !((*data).state.aptr.cookiehost).is_null() {
                (*data).state.aptr.cookiehost
            } else {
                (*conn).host.name
            }};
            let secure_context: bool =
                if unsafe{(*(*conn).handler).protocol & ((1 as i32) << 1 as i32) as u32 != 0
                    || Curl_strcasecompare(b"localhost\0" as *const u8 as *const libc::c_char, host)
                        != 0
                    || strcmp(host, b"127.0.0.1\0" as *const u8 as *const libc::c_char) == 0
                    || strcmp(host, b"[::1]\0" as *const u8 as *const libc::c_char) == 0}
                {
                    1
                } else {
                    0
                } != 0;
                unsafe{ Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
            co = Curl_cookie_getlist((*data).cookies, host, (*data).state.up.path, secure_context);
            Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);}
        }
        if !co.is_null() {
            let mut store: *mut Cookie = co;
            /* now loop through all cookies that matched */
            while !co.is_null() {
                if unsafe{!((*co).value).is_null()} {
                    if 0 as i32 == count {
                        result =unsafe{ Curl_dyn_add(r, b"Cookie: \0" as *const u8 as *const libc::c_char)};
                        if result as u64 != 0 {
                            break;
                        }
                    }
                    result = unsafe{Curl_dyn_addf(
                        r,
                        b"%s%s=%s\0" as *const u8 as *const libc::c_char,
                        if count != 0 {
                            b"; \0" as *const u8 as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                        (*co).name,
                        (*co).value,
                    )};

                    if result as u64 != 0 {
                        break;
                    }
                    count += 1;
                }
                co = unsafe{(*co).next};
            }
            unsafe{  Curl_cookie_freelist(store);}
        }
        if !addcookies.is_null() && result as u64 == 0 {
            if count == 0 {
                result = unsafe{Curl_dyn_add(r, b"Cookie: \0" as *const u8 as *const libc::c_char)};
            }
            if result as u64 == 0 {
                result = unsafe{Curl_dyn_addf(
                    r,
                    b"%s%s\0" as *const u8 as *const libc::c_char,
                    if count != 0 {
                        b"; \0" as *const u8 as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                    addcookies,
                )};
                count += 1;
            }
        }
        if count != 0 && result as u64 == 0 {
            result = unsafe{Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char)};
        }
        if result as u64 != 0 {
            return result;
        }
    }
    return result;
}
#[cfg(CURL_DISABLE_COOKIES)]
#[no_mangle]
pub  extern "C" fn Curl_http_cookies(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    return CURLE_OK;
}
#[no_mangle]
pub  extern "C" fn Curl_http_range(
    mut data: *mut Curl_easy,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    if unsafe{((*data).state).use_range() != 0} {
        if (httpreq as u32 == HTTPREQ_GET as u32
            || httpreq as u32 == HTTPREQ_HEAD as u32)
            && unsafe{(Curl_checkheaders(data, b"Range\0" as *const u8 as *const libc::c_char)).is_null()}
        {unsafe{
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.rangeline as *mut libc::c_void,
            );
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*data).state.aptr.rangeline as *mut libc::c_void,
                2776 as i32,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            (*data).state.aptr.rangeline = curl_maprintf(
                b"Range: bytes=%s\r\n\0" as *const u8 as *const libc::c_char,
                (*data).state.range,
            );}
        } else if (httpreq as u32 == HTTPREQ_POST as u32
            || httpreq as u32 == HTTPREQ_PUT as u32)
            && unsafe{(Curl_checkheaders(data, b"Content-Range\0" as *const u8 as *const libc::c_char))
                .is_null()}
        {unsafe{
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.rangeline as *mut libc::c_void,
            );
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*data).state.aptr.rangeline as *mut libc::c_void,
                2784 as i32,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            if (*data).set.set_resume_from < 0 as i64 {
                (*data).state.aptr.rangeline = curl_maprintf(
                    b"Content-Range: bytes 0-%ld/%ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*data).state.infilesize - 1 as i64,
                    (*data).state.infilesize,
                );
            } else if (*data).state.resume_from != 0 {
                let mut total_expected_size: curl_off_t =
                    (*data).state.resume_from + (*data).state.infilesize;
                (*data).state.aptr.rangeline = curl_maprintf(
                    b"Content-Range: bytes %s%ld/%ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*data).state.range,
                    total_expected_size - 1 as i64,
                    total_expected_size,
                );
            } else {
                (*data).state.aptr.rangeline = curl_maprintf(
                    b"Content-Range: bytes %s/%ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*data).state.range,
                    (*data).state.infilesize,
                );
            }
            if ((*data).state.aptr.rangeline).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }}
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub  extern "C" fn Curl_http_resume(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    if (HTTPREQ_POST as u32 == httpreq as u32 || HTTPREQ_PUT as u32 == httpreq as u32)
        && unsafe{(*data).state.resume_from != 0}
    {
        if unsafe{(*data).state.resume_from < 0 as i64 }{
            unsafe{ (*data).state.resume_from = 0 as curl_off_t;}
        }
        if unsafe{(*data).state.resume_from != 0 && ((*data).state).this_is_a_follow() == 0} {
            let mut seekerr: i32 = 2 as i32;
            if unsafe{((*conn).seek_func).is_some() }{
                unsafe{  Curl_set_in_callback(data, 1 as i32 != 0);
                seekerr = ((*conn).seek_func).expect("non-null function pointer")(
                    (*conn).seek_client,
                    (*data).state.resume_from,
                    0 as i32,
                );
                Curl_set_in_callback(data, 0 as i32 != 0);}
            }
            if seekerr != 0 as i32 {
                let mut passed: curl_off_t = 0 as i32 as curl_off_t;
                if seekerr != 2 as i32 {
                    unsafe{Curl_failf(
                        data,
                        b"Could not seek stream\0" as *const u8 as *const libc::c_char,
                    );}
                    return CURLE_READ_ERROR;
                }
                loop {
                    let mut readthisamountnow: size_t =
                        if unsafe{(*data).state.resume_from - passed > (*data).set.buffer_size} {
                            unsafe{ (*data).set.buffer_size as size_t}
                        } else {
                            unsafe{curlx_sotouz((*data).state.resume_from - passed)}
                        };
                    let mut actuallyread: size_t = unsafe{((*data).state.fread_func)
                        .expect("non-null function pointer")(
                        (*data).state.buffer,
                        1 as size_t,
                        readthisamountnow,
                        (*data).state.in_0,
                    )};
                    passed = (passed as u64).wrapping_add(actuallyread) as curl_off_t;
                    if actuallyread == 0 as u64 || actuallyread > readthisamountnow {
                        unsafe{ Curl_failf(
                            data,
                            b"Could only read %ld bytes from the input\0" as *const u8
                                as *const libc::c_char,
                            passed,
                        );}
                        return CURLE_READ_ERROR;
                    }
                    if unsafe{ !(passed < (*data).state.resume_from)} {
                        break;
                    }
                }
            }
            if unsafe{ (*data).state.infilesize > 0 as i64} {
                unsafe{ (*data).state.infilesize -= (*data).state.resume_from;}
                if unsafe{(*data).state.infilesize <= 0 as i64} {
                    unsafe{ Curl_failf(
                        data,
                        b"File already completely uploaded\0" as *const u8 as *const libc::c_char,
                    );}
                    return CURLE_PARTIAL_FILE;
                }
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub  extern "C" fn Curl_http_firstwrite(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut done: *mut bool,
) -> CURLcode {
    let mut k: *mut SingleRequest = unsafe{&mut (*data).req};
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if unsafe{(*(*conn).handler).protocol
        & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32 | (1 as i32) << 18 as i32) as u32
        != 0}
    {
    } else {
        unsafe{  __assert_fail(
            b"conn->handler->protocol&(((1<<0)|(1<<1))|(1<<18))\0" as *const u8
                as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            2905 as u32,
            (*::std::mem::transmute::<
                &[u8; 81],
                &[libc::c_char; 81],
            >(
                b"CURLcode Curl_http_firstwrite(struct Curl_easy *, struct connectdata *, _Bool *)\0",
            ))
                .as_ptr(),
        );}
    }
    if unsafe{((*data).req).ignore_cl() != 0 }{
        let ref mut fresh64 = unsafe{(*k).maxdownload};
        *fresh64 = -(1 as i32) as curl_off_t;
        unsafe{  (*k).size = *fresh64;}
    } else if unsafe{(*k).size != -(1 as i32) as i64 }{
        if unsafe{(*data).set.max_filesize != 0 && (*k).size > (*data).set.max_filesize} {
            unsafe{ Curl_failf(
                data,
                b"Maximum file size exceeded\0" as *const u8 as *const libc::c_char,
            );}
            return CURLE_FILESIZE_EXCEEDED;
        }
        unsafe{ Curl_pgrsSetDownloadSize(data, (*k).size);}
    }
    if unsafe{!((*data).req.newurl).is_null() }{
        if unsafe{((*conn).bits).close() != 0} {
            unsafe{(*k).keepon &= !((1 as i32) << 0 as i32);
            *done = 1 as i32 != 0;}
            return CURLE_OK;
        }
        unsafe{(*k).set_ignorebody(1 as bit);
        Curl_infof(
            data,
            b"Ignoring the response-body\0" as *const u8 as *const libc::c_char,
        );}
    }
    if unsafe{(*data).state.resume_from != 0
        && (*k).content_range() == 0
        && (*data).state.httpreq as u32 == HTTPREQ_GET as u32
        && (*k).ignorebody() == 0}
    {
        if unsafe{(*k).size == (*data).state.resume_from }{
            unsafe{ Curl_infof(
                data,
                b"The entire document is already downloaded\0" as *const u8 as *const libc::c_char,
            );
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as i32);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as i32,
                b"already downloaded\0" as *const u8 as *const libc::c_char,
            );
            (*k).keepon &= !((1 as i32) << 0 as i32);
            *done = 1 as i32 != 0;
            return CURLE_OK;}
        }unsafe{
        Curl_failf(
            data,
            b"HTTP server doesn't seem to support byte ranges. Cannot resume.\0" as *const u8
                as *const libc::c_char,
        );}
        return CURLE_RANGE_ERROR;
    }
    if unsafe{(*data).set.timecondition as u32 != 0 && ((*data).state.range).is_null()} {
        if unsafe{!Curl_meets_timecondition(data, (*k).timeofdoc)} {
            unsafe{*done = 1 as i32 != 0;
            (*data).info.httpcode = 304 as i32;
            Curl_infof(
                data,
                b"Simulate a HTTP 304 response!\0" as *const u8 as *const libc::c_char,
            );
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as i32);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as i32,
                b"Simulated 304 handling\0" as *const u8 as *const libc::c_char,
            );}
            return CURLE_OK;
        }
    }
    return CURLE_OK;
}
#[cfg(HAVE_LIBZ)]
#[no_mangle]
pub  extern "C" fn Curl_transferencode(mut data: *mut Curl_easy) -> CURLcode {
    if unsafe{(Curl_checkheaders(data, b"TE\0" as *const u8 as *const libc::c_char)).is_null()
        && ((*data).set).http_transfer_encoding() as i32 != 0}
    {
        let mut cptr: *mut libc::c_char =
        unsafe{Curl_checkheaders(data, b"Connection\0" as *const u8 as *const libc::c_char)};
        #[cfg(not(CURLDEBUG))]
        unsafe{Curl_cfree.expect("non-null function pointer")((*data).state.aptr.te as *mut libc::c_void);}
        #[cfg(CURLDEBUG)]
        unsafe{curl_dbg_free(
            (*data).state.aptr.te as *mut libc::c_void,
            2990 as i32,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        (*data).state.aptr.te = 0 as *mut libc::c_char;}
        if !cptr.is_null() {
            cptr = Curl_copy_header_value(cptr);
            if cptr.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
        unsafe{ (*data).state.aptr.te = curl_maprintf(
            b"Connection: %s%sTE\r\nTE: gzip\r\n\0" as *const u8 as *const libc::c_char,
            if !cptr.is_null() {
                cptr as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if !cptr.is_null() && *cptr as i32 != 0 {
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
            3002 as i32,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );}
        if unsafe{((*data).state.aptr.te).is_null()} {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[cfg(not(USE_HYPER))]
#[no_mangle]
pub  extern "C" fn Curl_http(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut conn: *mut connectdata = unsafe{(*data).conn};
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
    unsafe{*done = 1 as i32 != 0;}
    if unsafe{(*conn).transport as u32 }!= TRNSPRT_QUIC as u32 {
        if unsafe{((*conn).httpversion as i32) < 20 as i32} {
            unsafe{
            match (*conn).negnpn {
                3 => {
                    (*conn).httpversion = 20 as i32 as u8;
                    result =
                        Curl_http2_switched(data, 0 as *const libc::c_char, 0 as i32 as size_t);
                    if result as u64 != 0 {
                        return result;
                    }
                }
                2 => {}
                _ => {
                    #[cfg(USE_NGHTTP2)]
                    if (*data).state.httpwant as i32 == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE as i32 {
                        #[cfg(not(CURL_DISABLE_PROXY))]
                        let flag1: bool = ((*conn).bits).httpproxy() as i32 != 0
                            && ((*conn).bits).tunnel_proxy() == 0;
                        #[cfg(CURL_DISABLE_PROXY)]
                        let flag1: bool = false;
                        if flag1 {
                            Curl_infof(
                                data,
                                b"Ignoring HTTP/2 prior knowledge due to proxy\0" as *const u8
                                    as *const libc::c_char,
                            );
                        } else {
                            Curl_infof(
                                data,
                                b"HTTP/2 over clean TCP\0" as *const u8 as *const libc::c_char,
                            );
                            (*conn).httpversion = 20 as u8;
                            result = Curl_http2_switched(
                                data,
                                0 as *const libc::c_char,
                                0 as size_t,
                            );
                            if result as u64 != 0 {
                                return result;
                            }
                        }
                    }
                }
            }}
        } else {
            result = unsafe{Curl_http2_setup(data, conn)};
            if result as u64 != 0 {
                return result;
            }
        }
    }
    http =unsafe{ (*data).req.p.http};
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !http.is_null() {
    } else {
        unsafe{__assert_fail(
            b"http\0" as *const u8 as *const libc::c_char,
            b"http.c\0" as *const u8 as *const libc::c_char,
            3079 as u32,
            (*::std::mem::transmute::<&[u8; 48], &[libc::c_char; 48]>(
                b"CURLcode Curl_http(struct Curl_easy *, _Bool *)\0",
            ))
            .as_ptr(),
        );}
    }
    result = unsafe{Curl_http_host(data, conn)};
    if result as u64 != 0 {
        return result;
    }
    result = unsafe{Curl_http_useragent(data)};
    if result as u64 != 0 {
        return result;
    }
    unsafe{Curl_http_method(data, conn, &mut request, &mut httpreq);}
    let mut pq: *mut libc::c_char = 0 as *mut libc::c_char;
    if unsafe{!((*data).state.up.query).is_null() }{
        pq = unsafe{curl_maprintf(
            b"%s?%s\0" as *const u8 as *const libc::c_char,
            (*data).state.up.path,
            (*data).state.up.query,
        )};
        if pq.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    unsafe{
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
        0 as i32 != 0,
    );
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(pq as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        pq as *mut libc::c_void,
        3101 as i32,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );}
    if result as u64 != 0 {
        return result;
    }unsafe{
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")((*data).state.aptr.ref_0 as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*data).state.aptr.ref_0 as *mut libc::c_void,
        3106 as i32,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    (*data).state.aptr.ref_0 = 0 as *mut libc::c_char;}
    if unsafe{!((*data).state.referer).is_null()
        && (Curl_checkheaders(data, b"Referer\0" as *const u8 as *const libc::c_char)).is_null()}
    {
        unsafe{ (*data).state.aptr.ref_0 = curl_maprintf(
            b"Referer: %s\r\n\0" as *const u8 as *const libc::c_char,
            (*data).state.referer,
        );}
        if unsafe{((*data).state.aptr.ref_0).is_null()} {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if unsafe{(Curl_checkheaders(
        data,
        b"Accept-Encoding\0" as *const u8 as *const libc::c_char,
    ))
    .is_null()
        && !((*data).set.str_0[STRING_ENCODING as usize]).is_null()}
    {unsafe{
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
        );
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
            3115 as i32,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        (*data).state.aptr.accept_encoding = 0 as *mut libc::c_char;
        (*data).state.aptr.accept_encoding = curl_maprintf(
            b"Accept-Encoding: %s\r\n\0" as *const u8 as *const libc::c_char,
            (*data).set.str_0[STRING_ENCODING as usize],
        );
        if ((*data).state.aptr.accept_encoding).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }}
    } else {
        unsafe{
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
        );
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
            3122 as i32,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );
        (*data).state.aptr.accept_encoding = 0 as *mut libc::c_char;}
    }
    // TODO 测试过了就把注释删咯
    match () {
        #[cfg(HAVE_LIBZ)]
        _ => {
            result = unsafe{Curl_transferencode(data)};
            if result as u64 != 0 {
                return result;
            }
        }
        #[cfg(not(HAVE_LIBZ))]
        _ => {}
    }
    // if cfg!(HAVE_LIBZ) {
    //     result = Curl_transferencode(data);
    //     if result as u64 != 0 {
    //         return result;
    //     }
    // }
    result = unsafe{Curl_http_body(data, conn, httpreq, &mut te)};
    if result as u64 != 0 {
        return result;
    }
    p_accept =
        if unsafe{!(Curl_checkheaders(data, b"Accept\0" as *const u8 as *const libc::c_char)).is_null()} {
            0 as *const libc::c_char
        } else {
            b"Accept: */*\r\n\0" as *const u8 as *const libc::c_char
        };
    result = unsafe{Curl_http_resume(data, conn, httpreq)};
    if result as u64 != 0 {
        return result;
    }
    result = unsafe{Curl_http_range(data, httpreq)};
    if result as u64 != 0 {
        return result;
    }
    httpstring = unsafe{get_http_string(data, conn)};
    unsafe{Curl_dyn_init(&mut req, (1024 as i32 * 1024 as i32) as size_t);
    Curl_dyn_reset(&mut (*data).state.headerb);}
    result = unsafe{Curl_dyn_addf(
        &mut req as *mut dynbuf,
        b"%s \0" as *const u8 as *const libc::c_char,
        request,
    )};
    if result as u64 == 0 {
        result = unsafe{Curl_http_target(data, conn, &mut req)};
    }
    if result as u64 != 0 {
        unsafe{Curl_dyn_free(&mut req);}
        return result;
    }
    #[cfg(not(CURL_DISABLE_ALTSVC))]
    if unsafe{((*conn).bits).altused() as i32 != 0}
        && unsafe{(Curl_checkheaders(data, b"Alt-Used\0" as *const u8 as *const libc::c_char)).is_null()}
    {
        altused = unsafe{curl_maprintf(
            b"Alt-Used: %s:%d\r\n\0" as *const u8 as *const libc::c_char,
            (*conn).conn_to_host.name,
            (*conn).conn_to_port,
        )};
        if altused.is_null() {
            unsafe{Curl_dyn_free(&mut req);}
            return CURLE_OUT_OF_MEMORY;
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag2: bool = unsafe{((*conn).bits).httpproxy() as i32 != 0
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
        .is_null()};
    #[cfg(CURL_DISABLE_PROXY)]
    let flag2: bool = false;
    result = unsafe{Curl_dyn_addf(
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
        if ((*data).state).use_range() as i32 != 0 && !((*data).state.aptr.rangeline).is_null() {
            (*data).state.aptr.rangeline as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).set.str_0[STRING_USERAGENT as usize]).is_null()
            && *(*data).set.str_0[STRING_USERAGENT as usize] as i32 != 0
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
        if !((*data).set.str_0[STRING_ENCODING as usize]).is_null()
            && *(*data).set.str_0[STRING_ENCODING as usize] as i32 != 0
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
        if flag2 {
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
    )};
    unsafe{
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")((*data).state.aptr.userpwd as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*data).state.aptr.userpwd as *mut libc::c_void,
        3224 as i32,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    (*data).state.aptr.userpwd = 0 as *mut libc::c_char;
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
        3225 as i32,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );
    (*data).state.aptr.proxyuserpwd = 0 as *mut libc::c_char;
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(altused as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        altused as *mut libc::c_void,
        3226 as i32,
        b"http.c\0" as *const u8 as *const libc::c_char,
    );}
    if result as u64 != 0 {
        unsafe{Curl_dyn_free(&mut req);}
        return result;
    }
    if unsafe{(*(*conn).handler).flags & ((1 as i32) << 0 as i32) as u32 == 0
        && (*conn).httpversion as i32 != 20 as i32
        && (*data).state.httpwant as i32 == CURL_HTTP_VERSION_2_0 as i32}
    {
        result = unsafe{Curl_http2_request_upgrade(&mut req, data)};
        if result as u64 != 0 {
            unsafe{Curl_dyn_free(&mut req);}
            return result;
        }
    }
    result = unsafe{Curl_http_cookies(data, conn, &mut req)};
    if result as u64 == 0 {
        result = unsafe{Curl_add_timecondition(data, &mut req)};
    }
    if result as u64 == 0 {
        result = unsafe{Curl_add_custom_headers(data, 0 as i32 != 0, &mut req)};
    }
    if result as u64 == 0 {
        unsafe{(*http).postdata = 0 as *const libc::c_char;}
        if httpreq as u32 == HTTPREQ_GET  as u32
            || httpreq as u32 == HTTPREQ_HEAD as u32
        {
            unsafe{ Curl_pgrsSetUploadSize(data, 0 as curl_off_t);}
        }
        result = unsafe{Curl_http_bodysend(data, conn, &mut req, httpreq)};
    }
    if result as u64 != 0 {
        unsafe{ Curl_dyn_free(&mut req);}
        return result;
    }
    if unsafe{(*http).postsize > -(1 as i32) as i64
        && (*http).postsize <= (*data).req.writebytecount
        && (*http).sending as u32 != HTTPSEND_REQUEST as i32 as u32}
    {
        unsafe{ (*data).req.set_upload_done(1 as i32 as bit);}
    }
    if unsafe{(*data).req.writebytecount != 0 }{
        unsafe{ Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount);}
        if unsafe{Curl_pgrsUpdate(data) != 0} {
            result = CURLE_ABORTED_BY_CALLBACK;
        }
        if unsafe{(*http).postsize == 0} {
            unsafe{ Curl_infof(
                data,
                b"upload completely sent off: %ld out of %ld bytes\0" as *const u8
                    as *const libc::c_char,
                (*data).req.writebytecount,
                (*http).postsize,
            );
            (*data).req.set_upload_done(1 as i32 as bit);
            (*data).req.keepon &= !((1 as i32) << 1 as i32);
            (*data).req.exp100 = EXP100_SEND_DATA;
            Curl_expire_done(data, EXPIRE_100_TIMEOUT);}
        }
    }
    if unsafe{(*conn).httpversion as i32 == 20 as i32 && ((*data).req).upload_chunky() as i32 != 0} {
        unsafe{ (*data).req.set_upload_chunky(0 as bit);}
    }
    return result;
}
 extern "C" fn checkprefixmax(
    mut prefix: *const libc::c_char,
    mut buffer: *const libc::c_char,
    mut len: size_t,
) -> bool {
    let mut ch: size_t = if unsafe{strlen(prefix) < len} {
        unsafe{strlen(prefix)}
    } else {
        len
    };
    return unsafe{curl_strnequal(prefix, buffer, ch) != 0};
}
 extern "C" fn checkhttpprefix(
    mut data: *mut Curl_easy,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> statusline {
    let mut head: *mut curl_slist = unsafe{(*data).set.http200aliases};
    let mut rc: statusline = STATUS_BAD;
    let mut onmatch: statusline = (if len >= 5 as u64 {
        STATUS_DONE as i32
    } else {
        STATUS_UNKNOWN as i32
    }) as statusline;
    while !head.is_null() {
        if unsafe{checkprefixmax((*head).data, s, len)} {
            rc = onmatch;
            break;
        } else {
            head = unsafe{(*head).next};
        }
    }
    if rc as u32 != STATUS_DONE as u32
        && unsafe{checkprefixmax(b"HTTP/\0" as *const u8 as *const libc::c_char, s, len) as i32 != 0}
    {
        rc = onmatch;
    }
    return rc;
}
#[cfg(not(CURL_DISABLE_RSTP))]
 extern "C" fn checkrtspprefix(
    mut data: *mut Curl_easy,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> statusline {
    let mut result: statusline = STATUS_BAD;
    let mut onmatch: statusline = (if len >= 5 as u64 {
        STATUS_DONE as i32
    } else {
        STATUS_UNKNOWN as i32
    }) as statusline;
    if unsafe{checkprefixmax(b"RTSP/\0" as *const u8 as *const libc::c_char, s, len)} {
        result = onmatch;
    }
    return result;
}
 extern "C" fn checkprotoprefix(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> statusline {unsafe{
    #[cfg(not(CURL_DISABLE_RSTP))]
    if (*(*conn).handler).protocol & ((1 as i32) << 18 as i32) as u32 != 0 {
        return checkrtspprefix(data, s, len);
    }
    return checkhttpprefix(data, s, len);}
}
#[no_mangle]
pub extern "C" fn Curl_http_header(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut headp: *mut libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut k: *mut SingleRequest = unsafe{&mut (*data).req};
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag1: bool = unsafe{(*conn).httpversion as i32 == 10 as i32
        && ((*conn).bits).httpproxy() as i32 != 0
        && Curl_compareheader(
            headp,
            b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
            b"keep-alive\0" as *const u8 as *const libc::c_char,
        ) as i32
            != 0};
    #[cfg(CURL_DISABLE_PROXY)]
    let flag1: bool = false;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag2: bool = unsafe{(*conn).httpversion as i32 == 11 as i32
        && ((*conn).bits).httpproxy() as i32 != 0
        && Curl_compareheader(
            headp,
            b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
            b"close\0" as *const u8 as *const libc::c_char,
        ) as i32
            != 0};
    #[cfg(CURL_DISABLE_PROXY)]
    let flag2: bool = false;
    #[cfg(not(CURL_DISABLE_COOKIES))]
    let flag3: bool = unsafe{!((*data).cookies).is_null()
        && ((*data).state).cookie_engine() as i32 != 0
        && curl_strnequal(
            b"Set-Cookie:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Set-Cookie:\0" as *const u8 as *const libc::c_char),
        ) != 0};
    #[cfg(CURL_DISABLE_COOKIES)]
    let flag3: bool = false;
    #[cfg(USE_SPNEGO)]
    let flag4: bool =unsafe{ curl_strnequal(
        b"Persistent-Auth:\0" as *const u8 as *const libc::c_char,
        headp,
        strlen(b"Persistent-Auth:\0" as *const u8 as *const libc::c_char),
    ) != 0};
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
    let flag5: bool = unsafe{!((*data).hsts).is_null()
        && curl_strnequal(
            b"Strict-Transport-Security:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Strict-Transport-Security:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && (*(*conn).handler).flags & ((1 as i32) << 0 as i32) as u32 != 0};
    #[cfg(CURL_DISABLE_HSTS)]
    let flag5: bool = false;
    let flag6: bool =unsafe{ if cfg!(all(not(CURL_DISABLE_ALTSVC), not(CURLDEBUG))) {
        !((*data).asi).is_null()
            && curl_strnequal(
                b"Alt-Svc:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Alt-Svc:\0" as *const u8 as *const libc::c_char),
            ) != 0
            && ((*(*conn).handler).flags & ((1 as i32) << 0 as i32) as u32 != 0 || 0 as i32 != 0)
    } else if cfg!(all(not(CURL_DISABLE_ALTSVC), CURLDEBUG)) {
        !((*data).asi).is_null()
            && curl_strnequal(
                b"Alt-Svc:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Alt-Svc:\0" as *const u8 as *const libc::c_char),
            ) != 0
            && ((*(*conn).handler).flags & ((1 as i32) << 0 as i32) as u32 != 0
                || !(getenv(b"CURL_ALTSVC_HTTP\0" as *const u8 as *const libc::c_char)).is_null())
    } else {
        false
    }};
    if unsafe{(*k).http_bodyless() == 0
        && ((*data).set).ignorecl() == 0
        && curl_strnequal(
            b"Content-Length:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Content-Length:\0" as *const u8 as *const libc::c_char),
        ) != 0}
    {
        let mut contentlength: curl_off_t = 0;
        let mut offt: CURLofft = unsafe{curlx_strtoofft(
            headp.offset(strlen(b"Content-Length:\0" as *const u8 as *const libc::c_char) as isize),
            0 as *mut *mut libc::c_char,
            10 as i32,
            &mut contentlength,
        )};
        if offt as u32 == CURL_OFFT_OK as u32 {
            unsafe{ (*k).size = contentlength;
            (*k).maxdownload = (*k).size;}
        } else if offt as u32 == CURL_OFFT_FLOW as u32 {
            if unsafe{(*data).set.max_filesize != 0} {
                unsafe{ Curl_failf(
                    data,
                    b"Maximum file size exceeded\0" as *const u8 as *const libc::c_char,
                );}
                return CURLE_FILESIZE_EXCEEDED;
            }
            unsafe{ #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 2 as i32);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                2 as i32,
                b"overflow content-length\0" as *const u8 as *const libc::c_char,
            );
            Curl_infof(
                data,
                b"Overflow Content-Length: value!\0" as *const u8 as *const libc::c_char,
            );}
        } else {
            unsafe{Curl_failf(
                data,
                b"Invalid Content-Length: value\0" as *const u8 as *const libc::c_char,
            );}
            return CURLE_WEIRD_SERVER_REPLY;
        }
    } else if unsafe{curl_strnequal(
        b"Content-Type:\0" as *const u8 as *const libc::c_char,
        headp,
        strlen(b"Content-Type:\0" as *const u8 as *const libc::c_char),
    ) != 0}
    {
        let mut contenttype: *mut libc::c_char =unsafe{ Curl_copy_header_value(headp)};
        if contenttype.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if unsafe{*contenttype == 0} {
            unsafe{#[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(contenttype as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                contenttype as *mut libc::c_void,
                3445 as i32,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );}
        } else {
            unsafe{#[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(
                (*data).info.contenttype as *mut libc::c_void,
            );
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*data).info.contenttype as *mut libc::c_void,
                3447 as i32,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );
            (*data).info.contenttype = 0 as *mut libc::c_char;
            (*data).info.contenttype = contenttype;}
        }
    } else if flag1 {
        unsafe{#[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 0 as i32);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            0 as i32,
            b"Proxy-Connection keep-alive\0" as *const u8 as *const libc::c_char,
        );
        Curl_infof(
            data,
            b"HTTP/1.0 proxy connection set to keep alive!\0" as *const u8 as *const libc::c_char,
        );}
    } else if flag2 {
        unsafe{#[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 1 as i32);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            1 as i32,
            b"Proxy-Connection: asked to close after done\0" as *const u8 as *const libc::c_char,
        );
        Curl_infof(
            data,
            b"HTTP/1.1 proxy connection set close!\0" as *const u8 as *const libc::c_char,
        );}
    } else if unsafe{(*conn).httpversion as i32 == 10 as i32
        && Curl_compareheader(
            headp,
            b"Connection:\0" as *const u8 as *const libc::c_char,
            b"keep-alive\0" as *const u8 as *const libc::c_char,
        ) as i32
            != 0}
    {
        unsafe{#[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 0 as i32);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            0 as i32,
            b"Connection keep-alive\0" as *const u8 as *const libc::c_char,
        );
        Curl_infof(
            data,
            b"HTTP/1.0 connection set to keep alive!\0" as *const u8 as *const libc::c_char,
        );}
    } else if unsafe{Curl_compareheader(
        headp,
        b"Connection:\0" as *const u8 as *const libc::c_char,
        b"close\0" as *const u8 as *const libc::c_char,
    ) }{unsafe{
        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
        Curl_conncontrol(conn, 2 as i32);
        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
        Curl_conncontrol(
            conn,
            2 as i32,
            b"Connection: close used\0" as *const u8 as *const libc::c_char,
        );}
    } else if unsafe{(*k).http_bodyless() == 0
        && curl_strnequal(
            b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char),
        ) != 0}
    {
        result =unsafe{ Curl_build_unencoding_stack(
            data,
            headp.offset(
                strlen(b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char) as isize,
            ),
            1 as i32,
        )};
        if result as u64 != 0 {
            return result;
        }
        if unsafe{(*k).chunk() == 0} {
            unsafe{ #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 1 as i32);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                1 as i32,
                b"HTTP/1.1 transfer-encoding without chunks\0" as *const u8 as *const libc::c_char,
            );
            (*k).set_ignore_cl(1 as bit);}
        }
    } else if unsafe{(*k).http_bodyless() == 0
        && curl_strnequal(
            b"Content-Encoding:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Content-Encoding:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && !((*data).set.str_0[STRING_ENCODING as i32 as usize]).is_null()}
    {
        result = unsafe{Curl_build_unencoding_stack(
            data,
            headp.offset(
                strlen(b"Content-Encoding:\0" as *const u8 as *const libc::c_char) as isize,
            ),
            0 as i32,
        )};
        if result as u64 != 0 {
            return result;
        }
    } else if unsafe{curl_strnequal(
        b"Retry-After:\0" as *const u8 as *const libc::c_char,
        headp,
        strlen(b"Retry-After:\0" as *const u8 as *const libc::c_char),
    ) != 0}
    {
        let mut retry_after: curl_off_t = 0 as i32 as curl_off_t;
        let mut date: time_t = unsafe{Curl_getdate_capped(
            headp.offset(strlen(b"Retry-After:\0" as *const u8 as *const libc::c_char) as isize),
        )};
        if -(1 as i32) as i64 == date {
            unsafe{curlx_strtoofft(
                headp
                    .offset(strlen(b"Retry-After:\0" as *const u8 as *const libc::c_char) as isize),
                0 as *mut *mut libc::c_char,
                10 as i32,
                &mut retry_after,
            )};
        } else {
            unsafe{retry_after = date - time(0 as *mut time_t);}
        }
        unsafe{(*data).info.retry_after = retry_after;}
    } else if unsafe{(*k).http_bodyless() == 0
        && curl_strnequal(
            b"Content-Range:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Content-Range:\0" as *const u8 as *const libc::c_char),
        ) != 0}
    {
        let mut ptr: *mut libc::c_char =
        unsafe{headp.offset(strlen(b"Content-Range:\0" as *const u8 as *const libc::c_char) as isize)};
        while unsafe{*ptr as i32 != 0 && Curl_isdigit(*ptr as u8 as i32) == 0 && *ptr as i32 != '*' as i32}
        {
            ptr = unsafe{ptr.offset(1)};
        }
        if unsafe{Curl_isdigit(*ptr as i32) != 0} {
            if unsafe{curlx_strtoofft(
                ptr,
                0 as *mut *mut libc::c_char,
                10 as i32,
                &mut (*k).offset,
            ) as u64
                == 0}
            {
                if unsafe{(*data).state.resume_from == (*k).offset} {
                    unsafe{(*k).set_content_range(1 as bit);}
                }
            }
        } else {
            unsafe{ (*data).state.resume_from = 0 as curl_off_t;}
        }
    } else if flag3 {
        let mut host: *const libc::c_char = unsafe{if !((*data).state.aptr.cookiehost).is_null() {
            (*data).state.aptr.cookiehost
        } else {
            (*conn).host.name
        }};
        let secure_context: bool = if unsafe{(*(*conn).handler).protocol & ((1 as i32) << 1 as i32) as u32
            != 0
            || Curl_strcasecompare(b"localhost\0" as *const u8 as *const libc::c_char, host) != 0
            || strcmp(host, b"127.0.0.1\0" as *const u8 as *const libc::c_char) == 0
            || strcmp(host, b"[::1]\0" as *const u8 as *const libc::c_char) == 0}
        {
            1 as i32
        } else {
            0 as i32
        } != 0;
        unsafe{Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
        Curl_cookie_add(
            data,
            (*data).cookies,
            1 as i32 != 0,
            0 as i32 != 0,
            headp.offset(strlen(b"Set-Cookie:\0" as *const u8 as *const libc::c_char) as isize),
            host,
            (*data).state.up.path,
            secure_context,
        );
        Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);}
    } else if unsafe{(*k).http_bodyless() == 0
        && curl_strnequal(
            b"Last-Modified:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Last-Modified:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && ((*data).set.timecondition as u32 != 0 || ((*data).set).get_filetime() as i32 != 0)}
    {
        unsafe{(*k).timeofdoc = Curl_getdate_capped(
            headp.offset(strlen(b"Last-Modified:\0" as *const u8 as *const libc::c_char) as isize),
        );
        if ((*data).set).get_filetime() != 0 {
            (*data).info.filetime = (*k).timeofdoc;
        }}
    } else if unsafe{curl_strnequal(
        b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char,
        headp,
        strlen(b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char),
    ) != 0
        && 401 as i32 == (*k).httpcode
        || curl_strnequal(
            b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char),
        ) != 0
            && 407 as i32 == (*k).httpcode}
    {
        let mut proxy: bool = if unsafe{(*k).httpcode == 407 as i32} {
            1 as i32
        } else {
            0 as i32
        } != 0;
        let mut auth: *mut libc::c_char = unsafe{Curl_copy_header_value(headp)};
        if auth.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = unsafe{Curl_http_input_auth(data, proxy, auth)};
        unsafe{
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            auth as *mut libc::c_void,
            3616 as i32,
            b"http.c\0" as *const u8 as *const libc::c_char,
        );}
        if result as u64 != 0 {
            return result;
        }
    } else if flag4 {
        match () {
            #[cfg(USE_SPNEGO)]
            _ => {unsafe{
                let mut negdata: *mut negotiatedata = &mut (*conn).negotiate;
                let mut authp: *mut auth = &mut (*data).state.authhost;
                if (*authp).picked == (1 as i32 as u64) << 2 as i32 {
                    let mut persistentauth: *mut libc::c_char = Curl_copy_header_value(headp);
                    if persistentauth.is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                    (*negdata).set_noauthpersist(
                        (if curl_strnequal(
                            b"false\0" as *const u8 as *const libc::c_char,
                            persistentauth,
                            strlen(b"false\0" as *const u8 as *const libc::c_char),
                        ) != 0
                        {
                            1 as i32
                        } else {
                            0 as i32
                        }) as bit,
                    );
                    (*negdata).set_havenoauthpersist(1 as i32 as bit);
                    Curl_infof(
                        data,
                        b"Negotiate: noauthpersist -> %d, header part: %s\0" as *const u8
                            as *const libc::c_char,
                        (*negdata).noauthpersist() as i32,
                        persistentauth,
                    );
                    Curl_cfree.expect("non-null function pointer")(
                        persistentauth as *mut libc::c_void,
                    );
                }}
            }
            #[cfg(not(USE_SPNEGO))]
            _ => {}
        }
        // let mut negdata: *mut negotiatedata = &mut (*conn).negotiate;
        // let mut authp: *mut auth = &mut (*data).state.authhost;
        // if (*authp).picked == (1 as i32 as u64) << 2 as i32 {
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
        //                 1 as i32
        //             } else {
        //                 0 as i32
        //             }) as bit,
        //         );
        //     (*negdata).set_havenoauthpersist(1 as i32 as bit);
        //     Curl_infof(
        //         data,
        //         b"Negotiate: noauthpersist -> %d, header part: %s\0" as *const u8
        //             as *const libc::c_char,
        //         (*negdata).noauthpersist() as i32,
        //         persistentauth,
        //     );
        //     Curl_cfree
        //         .expect(
        //             "non-null function pointer",
        //         )(persistentauth as *mut libc::c_void);
        // }
    } else if unsafe{(*k).httpcode >= 300 as i32
        && (*k).httpcode < 400 as i32
        && curl_strnequal(
            b"Location:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Location:\0" as *const u8 as *const libc::c_char),
        ) != 0
        && ((*data).req.location).is_null()}
    {
        let mut location: *mut libc::c_char = unsafe{Curl_copy_header_value(headp)};
        if location.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if unsafe{*location == 0} {unsafe{
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(location as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                location as *mut libc::c_void,
                3647 as i32,
                b"http.c\0" as *const u8 as *const libc::c_char,
            );}
        } else {
            unsafe{ (*data).req.location = location;}
            if unsafe{((*data).set).http_follow_location() != 0} {
                unsafe{#[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
                if ((*data).req.newurl).is_null() {
                } else {
                    __assert_fail(
                        b"!data->req.newurl\0" as *const u8 as *const libc::c_char,
                        b"http.c\0" as *const u8 as *const libc::c_char,
                        3652 as u32,
                        (*::std::mem::transmute::<
                            &[u8; 76],
                            &[libc::c_char; 76],
                        >(
                            b"CURLcode Curl_http_header(struct Curl_easy *, struct connectdata *, char *)\0",
                        ))
                            .as_ptr(),
                    );
                }}
                match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {unsafe{
                        (*data).req.newurl =
                            Curl_cstrdup.expect("non-null function pointer")((*data).req.location);
                    }}
                    #[cfg(CURLDEBUG)]
                    _ => {unsafe{
                        (*data).req.newurl = curl_dbg_strdup(
                            (*data).req.location,
                            3653 as i32,
                            b"http.c\0" as *const u8 as *const libc::c_char,
                        );}
                    }
                }
                if unsafe{ ((*data).req.newurl).is_null()} {
                    return CURLE_OUT_OF_MEMORY;
                }
                result = unsafe{http_perhapsrewind(data, conn)};
                if result as u64 != 0 {
                    return result;
                }
            }
        }
    } else if flag5 {
        match () {
            #[cfg(not(CURL_DISABLE_HSTS))]
            _ => {
                let mut check: CURLcode = unsafe{Curl_hsts_parse(
                    (*data).hsts,
                    (*data).state.up.hostname,
                    headp.offset(strlen(
                        b"Strict-Transport-Security:\0" as *const u8 as *const libc::c_char,
                    ) as isize),
                )};
                if check as u64 != 0 {
                    unsafe{Curl_infof(
                        data,
                        b"Illegal STS header skipped\0" as *const u8 as *const libc::c_char,
                    )};
                } else {unsafe{
                    #[cfg(DEBUGBUILD)]
                    Curl_infof(
                        data,
                        b"Parsed STS header fine (%zu entries)\0" as *const u8
                            as *const libc::c_char,
                        (*(*data).hsts).list.size,
                    );}
                }
            }
            #[cfg(CURL_DISABLE_HSTS)]
            _ => {}
        }
    } else if flag6 {
        let mut id: alpnid = (if unsafe{(*conn).httpversion as i32 == 20 as i32} {
            ALPN_h2 as i32
        } else {
            ALPN_h1 as i32
        }) as alpnid;
        result = unsafe{Curl_altsvc_parse(
            data,
            (*data).asi,
            headp.offset(strlen(b"Alt-Svc:\0" as *const u8 as *const libc::c_char) as isize),
            id,
            (*conn).host.name,
            curlx_uitous((*conn).remote_port as u32),
        )};
        if result as u64 != 0 {
            return result;
        }
    } else if unsafe{(*(*conn).handler).protocol & ((1 as i32) << 18 as i32) as u32 != 0} {
        result = unsafe{Curl_rtsp_parseheader(data, headp)};
        if result as u64 != 0 {
            return result;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http_statusline(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut k: *mut SingleRequest = unsafe{ &mut (*data).req};
    unsafe{(*data).info.httpcode = (*k).httpcode;
    (*data).info.httpversion = (*conn).httpversion as i32;
    if (*data).state.httpversion == 0
        || (*data).state.httpversion as i32 > (*conn).httpversion as i32
    {
        (*data).state.httpversion = (*conn).httpversion;
    }
    if (*data).state.resume_from != 0
        && (*data).state.httpreq as u32 == HTTPREQ_GET as u32
        && (*k).httpcode == 416 as i32
    {
        (*k).set_ignorebody(1 as bit);
    }
    if (*conn).httpversion as i32 == 10 as i32 {
        Curl_infof(
            data,
            b"HTTP 1.0, assume close after body\0" as *const u8 as *const libc::c_char,
        );
        #[cfg(not(CURLDEBUG))]
        Curl_conncontrol(conn, 1 as i32);
        #[cfg(CURLDEBUG)]
        Curl_conncontrol(
            conn,
            1 as i32,
            b"HTTP/1.0 close after body\0" as *const u8 as *const libc::c_char,
        );
    } else if (*conn).httpversion as i32 == 20 as i32
        || (*k).upgr101 as u32 == UPGR101_REQUESTED as i32 as u32 && (*k).httpcode == 101 as i32
    {
        #[cfg(DEBUGBUILD)]
        Curl_infof(
            data,
            b"HTTP/2 found, allow multiplexing\0" as *const u8 as *const libc::c_char,
        );
        (*(*conn).bundle).multiuse = 2 as i32;
    } else if (*conn).httpversion as i32 >= 11 as i32 && ((*conn).bits).close() == 0 {
        #[cfg(DEBUGBUILD)]
        Curl_infof(
            data,
            b"HTTP 1.1 or later with persistent connection\0" as *const u8 as *const libc::c_char,
        );
    }
    (*k).set_http_bodyless(
        ((*k).httpcode >= 100 as i32 && (*k).httpcode < 200 as i32) as bit,
    );}
    let mut current_block_25: u64;
    match unsafe{(*k).httpcode} {
        304 => {
            if unsafe{(*data).set.timecondition as u64 != 0} {
                unsafe{(*data).info.set_timecond(1 as bit);}
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
            unsafe{ (*k).size = 0 as curl_off_t;
            (*k).maxdownload = 0 as curl_off_t;
            (*k).set_http_bodyless(1 as bit);}
        }
        _ => {}
    }
    return CURLE_OK;
}

/*
 * Read any HTTP header lines from the server and pass them to the client app.
 */
#[no_mangle]
pub extern "C" fn Curl_http_readwrite_headers(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut nread: *mut ssize_t,
    mut stop_reading: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut k: *mut SingleRequest =unsafe{ &mut (*data).req};
    let mut onread: ssize_t = unsafe{*nread};
    let mut ostr: *mut libc::c_char = unsafe{(*k).str_0};
    let mut headp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut str_start: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end_ptr: *mut libc::c_char = 0 as *mut libc::c_char;

    /* header line within buffer loop */
    loop {
        let mut rest_length: size_t = 0;
        let mut full_length: size_t = 0;
        let mut writetype: i32 = 0;

        /* str_start is start of line within buf */
        str_start = unsafe{(*k).str_0};

        /* data is in network encoding so use 0x0a instead of '\n' */
        end_ptr =unsafe{ memchr(str_start as *const libc::c_void, 0xa as i32, *nread as u64)}
            as *mut libc::c_char;
        if end_ptr.is_null() {
            /* Not a complete header line within buffer, append the data to
            the end of the headerbuff. */
            result = unsafe{Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                *nread as size_t,
            )};
            if result as u64 != 0 {
                return result;
            }

            if unsafe{!((*k).headerline == 0) }{
                /* check if this looks like a protocol header */
                break;
            }
            let mut st: statusline = unsafe{checkprotoprefix(
                data,
                conn,
                Curl_dyn_ptr(&mut (*data).state.headerb),
                Curl_dyn_len(&mut (*data).state.headerb),
            )};
            if !(st as u32 == STATUS_BAD as u32) {
                break;
            }
            unsafe{(*k).set_header(0 as bit);
            (*k).badheader = HEADER_ALLBAD;
            #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
            Curl_conncontrol(conn, 2 as i32);
            #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
            Curl_conncontrol(
                conn,
                2 as i32,
                b"bad HTTP: No end-of-message indicator\0" as *const u8 as *const libc::c_char,
            );}
            if unsafe{ ((*data).set).http09_allowed() == 0 }{
                unsafe{Curl_failf(
                    data,
                    b"Received HTTP/0.9 when not allowed\0" as *const u8 as *const libc::c_char,
                );}
                return CURLE_UNSUPPORTED_PROTOCOL;
            }
            break;
        } else {
            rest_length = unsafe{(end_ptr.offset_from((*k).str_0) as i64 + 1 as i32 as i64) as size_t};
            unsafe{*nread -= rest_length as ssize_t;
            (*k).str_0 = end_ptr.offset(1 as isize);
            full_length = ((*k).str_0).offset_from(str_start) as size_t;
            result = Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                full_length,
            );}
            if result as u64 != 0 {
                return result;
            }
            if unsafe{(*k).headerline == 0} {
                let mut st_0: statusline = unsafe{checkprotoprefix(
                    data,
                    conn,
                    Curl_dyn_ptr(&mut (*data).state.headerb),
                    Curl_dyn_len(&mut (*data).state.headerb),
                )};
                if st_0 as u32 == STATUS_BAD as u32 {
                    unsafe{ #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                    Curl_conncontrol(conn, 2 as i32);
                    #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                    Curl_conncontrol(
                        conn,
                        2 as i32,
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
                    (*k).set_header(0 as bit);
                    if *nread != 0 {
                        (*k).badheader = HEADER_PARTHEADER;
                    } else {
                        (*k).badheader = HEADER_ALLBAD;
                        *nread = onread;
                        (*k).str_0 = ostr;
                        return CURLE_OK;
                    }
                    break;
                }}
            }
            headp = unsafe{Curl_dyn_ptr(&mut (*data).state.headerb)};
            if unsafe{0xa as i32 == *headp as i32 || 0xd as i32 == *headp as i32 }{
                let mut headerlen: size_t = 0;
                unsafe{
                #[cfg(not(CURL_DOES_CONVERSIONS))]
                if '\r' as i32 == *headp as i32 {
                    headp = headp.offset(1);
                }
                #[cfg(not(CURL_DOES_CONVERSIONS))]
                if '\n' as i32 == *headp as i32 {
                    headp = headp.offset(1);
                }}
                if unsafe{ 100 as i32 <= (*k).httpcode && 199 as i32 >= (*k).httpcode} {
                    unsafe{match (*k).httpcode {
                        100 => {
                            (*k).set_header(1 as bit);
                            (*k).headerline = 0 as i32;
                            if (*k).exp100 as u32 > EXP100_SEND_DATA as u32 {
                                (*k).exp100 = EXP100_SEND_DATA;
                                (*k).keepon |= (1 as i32) << 1 as i32;
                                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                            }
                        }
                        101 => {
                            if (*k).upgr101 as u32 == UPGR101_REQUESTED as u32 {
                                Curl_infof(
                                    data,
                                    b"Received 101\0" as *const u8 as *const libc::c_char,
                                );
                                (*k).upgr101 = UPGR101_RECEIVED;
                                (*k).set_header(1 as bit);
                                (*k).headerline = 0 as i32;
                                result = Curl_http2_switched(data, (*k).str_0, *nread as size_t);
                                if result as u64 != 0 {
                                    return result;
                                }
                                *nread = 0 as ssize_t;
                            } else {
                                (*k).set_header(0 as bit);
                            }
                        }
                        _ => {
                            (*k).set_header(1 as bit);
                            (*k).headerline = 0 as i32;
                        }
                    }}
                } else {unsafe{
                    (*k).set_header(0 as bit);
                    if (*k).size == -(1 as i32) as i64
                        && (*k).chunk() == 0
                        && ((*conn).bits).close() == 0
                        && (*conn).httpversion as i32 == 11 as i32
                        && (*(*conn).handler).protocol & ((1 as i32) << 18 as i32) as u32 == 0
                        && (*data).state.httpreq as u32 != HTTPREQ_HEAD as u32
                    {
                        Curl_infof(
                            data,
                            b"no chunk, no close, no size. Assume close to signal end\0"
                                as *const u8 as *const libc::c_char,
                        );
                        #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                        Curl_conncontrol(conn, 2 as i32);
                        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                        Curl_conncontrol(
                            conn,
                            2 as i32,
                            b"HTTP: No end-of-message indicator\0" as *const u8
                                as *const libc::c_char,
                        );
                    }}
                }
                unsafe{
                #[cfg(USE_NTLM)]
                if ((*conn).bits).close() as i32 != 0
                    && ((*data).req.httpcode == 401 as i32
                        && (*conn).http_ntlm_state as u32 == NTLMSTATE_TYPE2 as u32
                        || (*data).req.httpcode == 407 as i32
                            && (*conn).proxy_ntlm_state as u32 == NTLMSTATE_TYPE2 as u32)
                {
                    Curl_infof(
                        data,
                        b"Connection closure while negotiating auth (HTTP 1.0?)\0" as *const u8
                            as *const libc::c_char,
                    );
                    (*data).state.set_authproblem(1 as bit);
                }
                #[cfg(USE_SPNEGO)]
                if ((*conn).bits).close() as i32 != 0
                    && ((*data).req.httpcode == 401 as i32
                        && (*conn).http_negotiate_state as u32 == GSS_AUTHRECV as u32
                        || (*data).req.httpcode == 407 as i32
                            && (*conn).proxy_negotiate_state as u32 == GSS_AUTHRECV as u32)
                {
                    Curl_infof(
                        data,
                        b"Connection closure while negotiating auth (HTTP 1.0?)\0" as *const u8
                            as *const libc::c_char,
                    );
                    let ref mut fresh89 = (*data).state;
                    (*fresh89).set_authproblem(1 as bit);
                }
                #[cfg(USE_SPNEGO)]
                if (*conn).http_negotiate_state as u32 == GSS_AUTHDONE as u32
                    && (*data).req.httpcode != 401 as i32
                {
                    (*conn).http_negotiate_state = GSS_AUTHSUCC;
                }
                #[cfg(USE_SPNEGO)]
                if (*conn).proxy_negotiate_state as u32 == GSS_AUTHDONE as u32
                    && (*data).req.httpcode != 407 as i32
                {
                    (*conn).proxy_negotiate_state = GSS_AUTHSUCC;
                }}
                writetype = (1 as i32) << 1 as i32;
                if unsafe{((*data).set).include_header() != 0 }{
                    writetype |= (1 as i32) << 0 as i32;
                }
                headerlen =unsafe{ Curl_dyn_len(&mut (*data).state.headerb)};
                result = unsafe{Curl_client_write(
                    data,
                    writetype,
                    Curl_dyn_ptr(&mut (*data).state.headerb),
                    headerlen,
                )};
                if result as u64 != 0 {
                    return result;
                }
                unsafe{ (*data).info.header_size += headerlen as i64;
                (*data).req.headerbytecount += headerlen as i64;}
                if unsafe{http_should_fail(data)} {
                    unsafe{ Curl_failf(
                        data,
                        b"The requested URL returned error: %d\0" as *const u8
                            as *const libc::c_char,
                        (*k).httpcode,
                    )};
                    return CURLE_HTTP_RETURNED_ERROR;
                }
                unsafe{(*data).req.deductheadercount =
                    if 100 as i32 <= (*k).httpcode && 199 as i32 >= (*k).httpcode {
                        (*data).req.headerbytecount
                    } else {
                        0 as i64
                    };}
                result = unsafe{Curl_http_auth_act(data)};
                if result as u64 != 0 {
                    return result;
                }
                if unsafe{(*k).httpcode >= 300 as i32} {unsafe{
                    if ((*conn).bits).authneg() == 0
                        && ((*conn).bits).close() == 0
                        && ((*conn).bits).rewindaftersend() == 0
                    {
                        match (*data).state.httpreq as u32 {
                            4 | 1 | 2 | 3 => {
                                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                                if (*k).upload_done() == 0 {
                                    if (*k).httpcode == 417 as i32
                                        && ((*data).state).expect100header() as i32 != 0
                                    {
                                        Curl_infof(
                                            data,
                                            b"Got 417 while waiting for a 100\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        (*data).state.set_disableexpect(1 as bit);
                                        #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
                                        if ((*data).req.newurl).is_null() {
                                        } else {
                                            __assert_fail(
                                                b"!data->req.newurl\0" as *const u8 as *const libc::c_char,
                                                b"http.c\0" as *const u8 as *const libc::c_char,
                                                4084 as u32,
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
                                                (*data).req.newurl = Curl_cstrdup
                                                    .expect("non-null function pointer")(
                                                    (*data).state.url,
                                                );
                                            }
                                            #[cfg(CURLDEBUG)]
                                            _ => {
                                                (*data).req.newurl = curl_dbg_strdup(
                                                    (*data).state.url,
                                                    4085 as i32,
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
                                        if (*k).exp100 as u32 > EXP100_SEND_DATA as i32 as u32 {
                                            (*k).exp100 = EXP100_SEND_DATA;
                                            (*k).keepon |= (1 as i32) << 1 as i32;
                                        }
                                    } else {
                                        Curl_infof(
                                            data,
                                            b"HTTP error before end of send, stop sending\0"
                                                as *const u8
                                                as *const libc::c_char,
                                        );
                                        #[cfg(not(all(
                                            DEBUGBUILD,
                                            not(CURL_DISABLE_VERBOSE_STRINGS)
                                        )))]
                                        Curl_conncontrol(conn, 2 as i32);
                                        #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                                        Curl_conncontrol(
                                            conn,
                                            2 as i32,
                                            b"Stop sending data before everything sent\0"
                                                as *const u8
                                                as *const libc::c_char,
                                        );
                                        result = Curl_done_sending(data, k);
                                        if result as u64 != 0 {
                                            return result;
                                        }
                                        (*k).set_upload_done(1 as bit);
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
                        (*k).keepon |= (1 as i32) << 1 as i32;
                    }}
                }
                // 解决clippy错误
                if unsafe{(*k).header() == 0} {
                    // TODO 待测试
                    #[cfg(not(CURL_DISABLE_RSTP))]
                    let flag7: bool = unsafe{((*data).set).opt_no_body() != 0
                        || (*(*conn).handler).protocol & ((1 as i32) << 18 as i32) as u32 != 0
                            && (*data).set.rtspreq as u32 == RTSPREQ_DESCRIBE as u32
                            && (*k).size <= -(1 as i32) as i64};
                    #[cfg(CURL_DISABLE_RSTP)]
                    let flag7: bool = unsafe{((*data).set).opt_no_body() != 0};
                    // let flag7: bool = if cfg!(not(CURL_DISABLE_RSTP)) {
                    //     ((*data).set).opt_no_body() != 0
                    //     || (*(*conn).handler).protocol
                    //         & ((1 as i32) << 18 as i32) as u32
                    //         != 0
                    //     && (*data).set.rtspreq as u32
                    //         == RTSPREQ_DESCRIBE as i32 as u32
                    //     && (*k).size <= -(1 as i32) as i64
                    // } else {
                    //     ((*data).set).opt_no_body() != 0
                    // };
                    if flag7 {
                        unsafe{ *stop_reading = 1 as i32 != 0;}
                    // } else if (*(*conn).handler).protocol
                    //     & ((1 as i32) << 18 as i32) as u32
                    //     != 0
                    //     && (*data).set.rtspreq as u32
                    //         == RTSPREQ_DESCRIBE as i32 as u32
                    //     && (*k).size <= -(1 as i32) as i64
                    // {
                    //     *stop_reading = 1 as i32 != 0;
                    } else if unsafe{(*k).chunk() != 0} {
                        unsafe{ let ref mut fresh89 = (*k).size;
                        *fresh89 = -(1 as i32) as curl_off_t;
                        (*k).maxdownload = *fresh89;}
                    }
                    if -(1 as i32) as i64 != unsafe{(*k).size} {
                        unsafe{ Curl_pgrsSetDownloadSize(data, (*k).size);
                        (*k).maxdownload = (*k).size;}
                    }
                    #[cfg(USE_NGHTTP2)]
                    let flag8: bool = unsafe{0 as i64 == (*k).maxdownload
                        && !((*(*conn).handler).protocol
                            & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
                            != 0
                            && (*conn).httpversion as i32 == 20 as i32)};
                    #[cfg(not(USE_NGHTTP2))]
                    let flag8: bool = 0 as i64 ==unsafe{ (*k).maxdownload};
                    if flag8 {
                        unsafe{ *stop_reading = 1 as i32 != 0;}
                    }
                    if unsafe{*stop_reading} {
                        unsafe{ (*k).keepon &= !((1 as i32) << 0 as i32);}
                    }
                    unsafe{Curl_debug(data, CURLINFO_HEADER_IN, str_start, headerlen);}
                    break;
                } else {
                    unsafe{ Curl_dyn_reset(&mut (*data).state.headerb);}
                }
            } else {
                let ref mut fresh90 = unsafe{(*k).headerline};
                let fresh91 = *fresh90;
                *fresh90 = *fresh90 + 1;
                if fresh91 == 0 {
                    let mut httpversion_major: i32 = 0;
                    let mut rtspversion_major: i32 = 0;
                    let mut nc: i32 = 0 as i32;
                    if unsafe{(*(*conn).handler).protocol}
                        & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
                        != 0
                    {
                        let mut separator: libc::c_char = 0;
                        let mut twoorthree: [libc::c_char; 2] = [0; 2];
                        let mut httpversion: i32 = 0 as i32;
                        let mut digit4: libc::c_char = 0 as libc::c_char;
                        nc = unsafe{sscanf(
                            headp,
                            b" HTTP/%1d.%1d%c%3d%c\0" as *const u8 as *const libc::c_char,
                            &mut httpversion_major as *mut i32,
                            &mut httpversion as *mut i32,
                            &mut separator as *mut libc::c_char,
                            &mut (*k).httpcode as *mut i32,
                            &mut digit4 as *mut libc::c_char,
                        )};
                        if nc == 1 as i32
                            && httpversion_major >= 2 as i32
                            && 2 as i32
                                == unsafe{sscanf(
                                    headp,
                                    b" HTTP/%1[23] %d\0" as *const u8 as *const libc::c_char,
                                    twoorthree.as_mut_ptr(),
                                    &mut (*k).httpcode as *mut i32,
                                )}
                        {
                            unsafe{(*conn).httpversion = 0 as u8;}
                            nc = 4 as i32;
                            separator = ' ' as libc::c_char;
                        } else if unsafe{Curl_isdigit(digit4 as i32) != 0} {
                            unsafe{ Curl_failf(
                                data,
                                b"Unsupported response code in HTTP response\0" as *const u8
                                    as *const libc::c_char,
                            );}
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                        if nc >= 4 as i32 && ' ' as i32 == separator as i32 {
                            httpversion += 10 as i32 * httpversion_major;
                            match httpversion {
                                10 | 11 => {
                                    unsafe{(*conn).httpversion = httpversion as u8;}
                                }
                                #[cfg(any(USE_NGHTTP2, USE_HYPER))]
                                20 => {
                                    unsafe{(*conn).httpversion = httpversion as u8;}
                                }
                                #[cfg(ENABLE_QUIC)]
                                30 => {
                                    unsafe{(*conn).httpversion = httpversion as u8;}
                                }
                                _ => {
                                    unsafe{Curl_failf(
                                        data,
                                        b"Unsupported HTTP version (%u.%d) in response\0"
                                            as *const u8
                                            as *const libc::c_char,
                                        httpversion / 10 as i32,
                                        httpversion % 10 as i32,
                                    );}
                                    return CURLE_UNSUPPORTED_PROTOCOL;
                                }
                            }
                            if unsafe{(*k).upgr101 as u32 == UPGR101_RECEIVED as u32} {
                                if unsafe{(*conn).httpversion as i32 != 20 as i32} {
                                    unsafe{Curl_infof(
                                        data,
                                        b"Lying server, not serving HTTP/2\0" as *const u8
                                            as *const libc::c_char,
                                    );}
                                }
                            }
                            if unsafe{((*conn).httpversion as i32) < 20 as i32} {
                                unsafe{ (*(*conn).bundle).multiuse = -(1 as i32);
                                Curl_infof(
                                    data,
                                    b"Mark bundle as not supporting multiuse\0" as *const u8
                                        as *const libc::c_char,
                                );}
                            }
                        } else if nc == 0 {
                            nc = unsafe{sscanf(
                                headp,
                                b" HTTP %3d\0" as *const u8 as *const libc::c_char,
                                &mut (*k).httpcode as *mut i32,
                            )};
                            unsafe{(*conn).httpversion = 10 as u8;}
                            if nc == 0 {
                                let mut check: statusline = unsafe{checkhttpprefix(
                                    data,
                                    Curl_dyn_ptr(&mut (*data).state.headerb),
                                    Curl_dyn_len(&mut (*data).state.headerb),
                                )};
                                if check as u32 == STATUS_DONE as u32 {
                                    nc = 1 as i32;
                                    unsafe{(*k).httpcode = 200 as i32;
                                    (*conn).httpversion = 10 as u8;}
                                }
                            }
                        } else {
                            unsafe{Curl_failf(
                                data,
                                b"Unsupported HTTP version in response\0" as *const u8
                                    as *const libc::c_char,
                            );}
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                    } else if  unsafe{(*(*conn).handler).protocol & ((1 as i32) << 18 as i32) as u32 != 0} {
                        let mut separator_0: libc::c_char = 0;
                        let mut rtspversion: i32 = 0;
                        nc =  unsafe{sscanf(
                            headp,
                            b" RTSP/%1d.%1d%c%3d\0" as *const u8 as *const libc::c_char,
                            &mut rtspversion_major as *mut i32,
                            &mut rtspversion as *mut i32,
                            &mut separator_0 as *mut libc::c_char,
                            &mut (*k).httpcode as *mut i32,
                        )};
                        if nc == 4 as i32 && ' ' as i32 == separator_0 as i32 {
                            unsafe{ (*conn).httpversion = 11 as u8;}
                        } else {
                            nc = 0 as i32;
                        }
                    }
                    if nc != 0 {
                        result =  unsafe{Curl_http_statusline(data, conn)};
                        if result as u64 != 0 {
                            return result;
                        }
                    } else {
                        unsafe{ (*k).set_header(0 as bit);}
                        break;
                    }
                }
                result = CURLE_OK as CURLcode;
                if result as u64 != 0 {
                    return result;
                }
                result =  unsafe{Curl_http_header(data, conn, headp)};
                if result as u64 != 0 {
                    return result;
                }
                writetype = (1 as i32) << 1 as i32;
                if  unsafe{((*data).set).include_header() != 0} {
                    writetype |= (1 as i32) << 0 as i32;
                }
                unsafe{Curl_debug(
                    data,
                    CURLINFO_HEADER_IN,
                    headp,
                    Curl_dyn_len(&mut (*data).state.headerb),
                );}
                result =  unsafe{Curl_client_write(
                    data,
                    writetype,
                    headp,
                    Curl_dyn_len(&mut (*data).state.headerb),
                )};
                if result as u64 != 0 {
                    return result;
                }
                unsafe{(*data).info.header_size = ((*data).info.header_size as u64)
                    .wrapping_add(Curl_dyn_len(&mut (*data).state.headerb))
                    as curl_off_t;
                (*data).req.headerbytecount = ((*data).req.headerbytecount as u64)
                    .wrapping_add(Curl_dyn_len(&mut (*data).state.headerb))
                    as curl_off_t;
                Curl_dyn_reset(&mut (*data).state.headerb);}
            }
            if  unsafe{!(*(*k).str_0 != 0)} {
                break;
            }
        }
    }
    return CURLE_OK;
}
