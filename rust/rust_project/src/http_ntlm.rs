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
 * Author: wyf<wuyf21@mail.ustc.edu.cn>,
 * Create: 2022-10-31
 * Description: http ntlm
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
#[no_mangle]
pub extern "C" fn Curl_input_ntlm(
    mut data: *mut Curl_easy,
    mut proxy: bool, /* if proxy or not */
    mut header: *const libc::c_char, /* rest of the www-authenticate:
                     header */
) -> CURLcode {
    /* point to the correct struct with this */
    let mut ntlm: *mut ntlmdata = 0 as *mut ntlmdata;
    let mut state: *mut curlntlm = 0 as *mut curlntlm;
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    ntlm = if proxy as i32 != 0 {
        unsafe { &mut (*conn).proxyntlm }
    } else {
        unsafe { &mut (*conn).ntlm }
    };
    state = if proxy as i32 != 0 {
        unsafe { &mut (*conn).proxy_ntlm_state }
    } else {
        unsafe { &mut (*conn).http_ntlm_state }
    };
    if unsafe {
        curl_strnequal(
            b"NTLM\0" as *const u8 as *const libc::c_char,
            header,
            strlen(b"NTLM\0" as *const u8 as *const libc::c_char),
        ) != 0
    } {
        unsafe {
            header = header.offset(strlen(b"NTLM\0" as *const u8 as *const libc::c_char) as isize);
            while *header as i32 != 0 && Curl_isspace(*header as i32) != 0 {
                header = header.offset(1);
            }
            if *header != 0 {
                let mut hdr: *mut u8 = 0 as *mut u8;
                let mut hdrlen: size_t = 0;
                result = Curl_base64_decode(header, &mut hdr, &mut hdrlen);
                if result as u64 == 0 {
                    let mut hdrbuf: bufref = bufref {
                        dtor: None,
                        ptr: 0 as *const u8,
                        len: 0,
                        #[cfg(CURLDEBUG)]
                        signature: 0,
                    };
                    Curl_bufref_init(&mut hdrbuf);
                    Curl_bufref_set(
                        &mut hdrbuf,
                        hdr as *const libc::c_void,
                        hdrlen,
                        Some(curl_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
                    );
                    result = Curl_auth_decode_ntlm_type2_message(data, &mut hdrbuf, ntlm);
                    Curl_bufref_free(&mut hdrbuf);
                }
                if result as u64 != 0 {
                    return result;
                }
                *state = NTLMSTATE_TYPE2;
            } else {
                if *state as u32 == NTLMSTATE_LAST as u32 {
                    Curl_infof(
                        data,
                        b"NTLM auth restarted\0" as *const u8 as *const libc::c_char,
                    );
                    Curl_http_auth_cleanup_ntlm(conn);
                } else if *state as u32 == NTLMSTATE_TYPE3 as u32 {
                    Curl_infof(
                        data,
                        b"NTLM handshake rejected\0" as *const u8 as *const libc::c_char,
                    );
                    Curl_http_auth_cleanup_ntlm(conn);
                    *state = NTLMSTATE_NONE;
                    return CURLE_REMOTE_ACCESS_DENIED;
                } else if *state as u32 >= NTLMSTATE_TYPE1 as u32 {
                    // if *state as u32 >= NTLMSTATE_TYPE1 as i32 as u32 {
                    Curl_infof(
                        data,
                        b"NTLM handshake failure (internal error)\0" as *const u8
                            as *const libc::c_char,
                    );
                    return CURLE_REMOTE_ACCESS_DENIED;
                    // }
                }
                *state = NTLMSTATE_TYPE1;
            }
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_output_ntlm(mut data: *mut Curl_easy, mut proxy: bool) -> CURLcode {
    let mut base64: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0 as size_t;
    let mut result: CURLcode = CURLE_OK;
    let mut ntlmmsg: bufref = bufref {
        dtor: None,
        ptr: 0 as *const u8,
        len: 0,
        #[cfg(CURLDEBUG)]
        signature: 0,
    };
    let mut allocuserpwd: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut userp: *const libc::c_char = 0 as *const libc::c_char;
    let mut passwdp: *const libc::c_char = 0 as *const libc::c_char;
    let mut service: *const libc::c_char = 0 as *const libc::c_char;
    let mut hostname: *const libc::c_char = 0 as *const libc::c_char;
    let mut ntlm: *mut ntlmdata = 0 as *mut ntlmdata;
    let mut state: *mut curlntlm = 0 as *mut curlntlm;
    let mut authp: *mut auth = 0 as *mut auth;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    unsafe {
        #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
        if !conn.is_null() {
        } else {
            __assert_fail(
                b"conn\0" as *const u8 as *const libc::c_char,
                b"http_ntlm.c\0" as *const u8 as *const libc::c_char,
                150,
                (*::std::mem::transmute::<&[u8; 53], &[libc::c_char; 53]>(
                    b"CURLcode Curl_output_ntlm(struct Curl_easy *, _Bool)\0",
                ))
                .as_ptr(),
            );
        }
        #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
        if !data.is_null() {
        } else {
            __assert_fail(
                b"data\0" as *const u8 as *const libc::c_char,
                b"http_ntlm.c\0" as *const u8 as *const libc::c_char,
                151,
                (*::std::mem::transmute::<&[u8; 53], &[libc::c_char; 53]>(
                    b"CURLcode Curl_output_ntlm(struct Curl_easy *, _Bool)\0",
                ))
                .as_ptr(),
            );
        }
    }
    if proxy {
        unsafe {
            match () {
                #[cfg(not(CURL_DISABLE_PROXY))]
                _ => {
                    allocuserpwd = &mut (*data).state.aptr.proxyuserpwd;
                    userp = (*data).state.aptr.proxyuser;
                    passwdp = (*data).state.aptr.proxypasswd;
                    service = if !((*data).set.str_0[STRING_PROXY_SERVICE_NAME as usize]).is_null()
                    {
                        (*data).set.str_0[STRING_PROXY_SERVICE_NAME as usize] as *const libc::c_char
                    } else {
                        b"HTTP\0" as *const u8 as *const libc::c_char
                    };
                    hostname = (*conn).http_proxy.host.name;
                    ntlm = &mut (*conn).proxyntlm;
                    state = &mut (*conn).proxy_ntlm_state;
                    authp = &mut (*data).state.authproxy;
                }
                #[cfg(CURL_DISABLE_PROXY)]
                _ => {
                    return CURLE_NOT_BUILT_IN;
                }
            }
        }
    } else {
        allocuserpwd = unsafe { &mut (*data).state.aptr.userpwd };
        userp = unsafe { (*data).state.aptr.user };
        passwdp = unsafe { (*data).state.aptr.passwd };
        service = unsafe {
            if !((*data).set.str_0[STRING_SERVICE_NAME as usize]).is_null() {
                (*data).set.str_0[STRING_SERVICE_NAME as usize] as *const libc::c_char
            } else {
                b"HTTP\0" as *const u8 as *const libc::c_char
            }
        };
        hostname = unsafe { (*conn).host.name };
        ntlm = unsafe { &mut (*conn).ntlm };
        state = unsafe { &mut (*conn).http_ntlm_state };
        authp = unsafe { &mut (*data).state.authhost };
    }
    unsafe {
        (*authp).set_done(0 as bit);
    }
    if userp.is_null() {
        userp = b"\0" as *const u8 as *const libc::c_char;
    }
    if passwdp.is_null() {
        passwdp = b"\0" as *const u8 as *const libc::c_char;
    }
    unsafe {
        Curl_bufref_init(&mut ntlmmsg);
    }
    let mut current_block_61: u64;
    unsafe {
        match *state as u32 {
            2 => {
                /* We already received the type-2 message, create a type-3 message */
                result =
                    Curl_auth_create_ntlm_type3_message(data, userp, passwdp, ntlm, &mut ntlmmsg);
                if result as u64 == 0 && Curl_bufref_len(&mut ntlmmsg) != 0 {
                    result = Curl_base64_encode(
                        data,
                        Curl_bufref_ptr(&mut ntlmmsg) as *const libc::c_char,
                        Curl_bufref_len(&mut ntlmmsg),
                        &mut base64,
                        &mut len,
                    );
                    if result as u64 == 0 {
                        #[cfg(not(CURLDEBUG))]
                        Curl_cfree.expect("non-null function pointer")(
                            *allocuserpwd as *mut libc::c_void,
                        );
                        #[cfg(CURLDEBUG)]
                        curl_dbg_free(
                            *allocuserpwd as *mut libc::c_void,
                            234,
                            b"http_ntlm.c\0" as *const u8 as *const libc::c_char,
                        );
                        *allocuserpwd = curl_maprintf(
                            b"%sAuthorization: NTLM %s\r\n\0" as *const u8 as *const libc::c_char,
                            if proxy as i32 != 0 {
                                b"Proxy-\0" as *const u8 as *const libc::c_char
                            } else {
                                b"\0" as *const u8 as *const libc::c_char
                            },
                            base64,
                        );
                        #[cfg(not(CURLDEBUG))]
                        Curl_cfree.expect("non-null function pointer")(base64 as *mut libc::c_void);
                        #[cfg(CURLDEBUG)]
                        curl_dbg_free(
                            base64 as *mut libc::c_void,
                            238,
                            b"http_ntlm.c\0" as *const u8 as *const libc::c_char,
                        );
                        if (*allocuserpwd).is_null() {
                            result = CURLE_OUT_OF_MEMORY;
                        } else {
                            *state = NTLMSTATE_TYPE3; /* we send a type-3 */
                            (*authp).set_done(1 as bit);
                        }
                    }
                }
                current_block_61 = 15669289850109000831;
            }
            3 => {
                /* connection is already authenticated,
                 * don't send a header in future requests */
                *state = NTLMSTATE_LAST;
                current_block_61 = 660359442149512078;
            }
            /* FALLTHROUGH */
            4 => {
                current_block_61 = 660359442149512078;
            }
            1 | _ => {
                /* for the weird cases we (re)start here */
                /* Create a type-1 message */
                result = Curl_auth_create_ntlm_type1_message(
                    data,
                    userp,
                    passwdp,
                    service,
                    hostname,
                    ntlm,
                    &mut ntlmmsg,
                );
                if result as u64 == 0 {
                    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
                    if Curl_bufref_len(&mut ntlmmsg) != 0 as u64 {
                    } else {
                        __assert_fail(
                            b"Curl_bufref_len(&ntlmmsg) != 0\0" as *const u8 as *const libc::c_char,
                            b"http_ntlm.c\0" as *const u8 as *const libc::c_char,
                            209,
                            (*::std::mem::transmute::<&[u8; 53], &[libc::c_char; 53]>(
                                b"CURLcode Curl_output_ntlm(struct Curl_easy *, _Bool)\0",
                            ))
                            .as_ptr(),
                        );
                    }
                    result = Curl_base64_encode(
                        data,
                        Curl_bufref_ptr(&mut ntlmmsg) as *const libc::c_char,
                        Curl_bufref_len(&mut ntlmmsg),
                        &mut base64,
                        &mut len,
                    );
                    if result as u64 == 0 {
                        #[cfg(not(CURLDEBUG))]
                        Curl_cfree.expect("non-null function pointer")(
                            *allocuserpwd as *mut libc::c_void,
                        );
                        #[cfg(CURLDEBUG)]
                        curl_dbg_free(
                            *allocuserpwd as *mut libc::c_void,
                            214,
                            b"http_ntlm.c\0" as *const u8 as *const libc::c_char,
                        );
                        *allocuserpwd = curl_maprintf(
                            b"%sAuthorization: NTLM %s\r\n\0" as *const u8 as *const libc::c_char,
                            if proxy as i32 != 0 {
                                b"Proxy-\0" as *const u8 as *const libc::c_char
                            } else {
                                b"\0" as *const u8 as *const libc::c_char
                            },
                            base64,
                        );
                        #[cfg(not(CURLDEBUG))]
                        Curl_cfree.expect("non-null function pointer")(base64 as *mut libc::c_void);
                        #[cfg(CURLDEBUG)]
                        curl_dbg_free(
                            base64 as *mut libc::c_void,
                            218,
                            b"http_ntlm.c\0" as *const u8 as *const libc::c_char,
                        );
                        if (*allocuserpwd).is_null() {
                            result = CURLE_OUT_OF_MEMORY;
                        }
                    }
                }
                current_block_61 = 15669289850109000831;
            }
        }
        match current_block_61 {
            660359442149512078 => {
                #[cfg(not(CURLDEBUG))]
                Curl_cfree.expect("non-null function pointer")(*allocuserpwd as *mut libc::c_void);
                #[cfg(CURLDEBUG)]
                curl_dbg_free(
                    *allocuserpwd as *mut libc::c_void,
                    255,
                    b"http_ntlm.c\0" as *const u8 as *const libc::c_char,
                );
                *allocuserpwd = 0 as *mut libc::c_char;
                (*authp).set_done(1 as bit);
            }
            _ => {}
        }
        Curl_bufref_free(&mut ntlmmsg);
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_http_auth_cleanup_ntlm(mut conn: *mut connectdata) {
    unsafe {
        Curl_auth_cleanup_ntlm(&mut (*conn).ntlm);
        Curl_auth_cleanup_ntlm(&mut (*conn).proxyntlm);
        #[cfg(NTLM_WB_ENABLED)]
        Curl_http_auth_cleanup_ntlm_wb(conn);
    }
}
/* !CURL_DISABLE_HTTP && USE_NTLM */
