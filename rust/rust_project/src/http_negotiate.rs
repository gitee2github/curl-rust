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
 * Description: http negotiate
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

#[no_mangle]
pub unsafe extern "C" fn Curl_input_negotiate(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut proxy: bool,
    mut header: *const libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut len: size_t = 0;
    let mut userp: *const libc::c_char = 0 as *const libc::c_char;
    let mut passwdp: *const libc::c_char = 0 as *const libc::c_char;
    let mut service: *const libc::c_char = 0 as *const libc::c_char;
    let mut host: *const libc::c_char = 0 as *const libc::c_char;
    let mut neg_ctx: *mut negotiatedata = 0 as *mut negotiatedata;
    let mut state: curlnegotiate = GSS_AUTHNONE;
    if proxy {
        match () {
            #[cfg(not(CURL_DISABLE_PROXY))]
            _ => {
                userp = (*conn).http_proxy.user;
                passwdp = (*conn).http_proxy.passwd;
                service = if !((*data)
                    .set
                    .str_0[STRING_PROXY_SERVICE_NAME as libc::c_int as usize])
                    .is_null()
                {
                    (*data).set.str_0[STRING_PROXY_SERVICE_NAME as libc::c_int as usize]
                        as *const libc::c_char
                } else {
                    b"HTTP\0" as *const u8 as *const libc::c_char
                };
                host = (*conn).http_proxy.host.name;
                neg_ctx = &mut (*conn).proxyneg;
                state = (*conn).proxy_negotiate_state;
            }
            #[cfg(CURL_DISABLE_PROXY)]
            _ => {
                return CURLE_NOT_BUILT_IN;
            }
        }
    } else {
        userp = (*conn).user;
        passwdp = (*conn).passwd;
        service = if !((*data).set.str_0[STRING_SERVICE_NAME as libc::c_int as usize])
            .is_null()
        {
            (*data).set.str_0[STRING_SERVICE_NAME as libc::c_int as usize]
                as *const libc::c_char
        } else {
            b"HTTP\0" as *const u8 as *const libc::c_char
        };
        host = (*conn).host.name;
        neg_ctx = &mut (*conn).negotiate;
        state = (*conn).http_negotiate_state;
    }
    if userp.is_null() {
        userp = b"\0" as *const u8 as *const libc::c_char;
    }
    if passwdp.is_null() {
        passwdp = b"\0" as *const u8 as *const libc::c_char;
    }
    header = header
        .offset(strlen(b"Negotiate\0" as *const u8 as *const libc::c_char) as isize);
    while *header as libc::c_int != 0
        && Curl_isspace(*header as libc::c_uchar as libc::c_int) != 0
    {
        header = header.offset(1);
    }
    len = strlen(header);
    (*neg_ctx)
        .set_havenegdata(
            (len != 0 as libc::c_int as libc::c_ulong) as libc::c_int as bit,
        );
    if len == 0 {
        if state as libc::c_uint == GSS_AUTHSUCC as libc::c_int as libc::c_uint {
            Curl_infof(
                data,
                b"Negotiate auth restarted\0" as *const u8 as *const libc::c_char,
            );
            Curl_http_auth_cleanup_negotiate(conn);
        } else if state as libc::c_uint != GSS_AUTHNONE as libc::c_int as libc::c_uint {
            Curl_http_auth_cleanup_negotiate(conn);
            return CURLE_LOGIN_DENIED;
        }
    }
    result = Curl_auth_decode_spnego_message(
        data,
        userp,
        passwdp,
        service,
        host,
        header,
        neg_ctx,
    );
    if result as u64 != 0 {
        Curl_http_auth_cleanup_negotiate(conn);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_output_negotiate(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut proxy: bool,
) -> CURLcode {
    let mut neg_ctx: *mut negotiatedata = if proxy as libc::c_int != 0 {
        &mut (*conn).proxyneg
    } else {
        &mut (*conn).negotiate
    };
    let mut authp: *mut auth = if proxy as libc::c_int != 0 {
        &mut (*data).state.authproxy
    } else {
        &mut (*data).state.authhost
    };
    let mut state: *mut curlnegotiate = if proxy as libc::c_int != 0 {
        &mut (*conn).proxy_negotiate_state
    } else {
        &mut (*conn).http_negotiate_state
    };
    let mut base64: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut userp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    (*authp).set_done(0 as libc::c_int as bit);
    if *state as libc::c_uint == GSS_AUTHRECV as libc::c_int as libc::c_uint {
        if (*neg_ctx).havenegdata() != 0 {
            (*neg_ctx).set_havemultiplerequests(1 as libc::c_int as bit);
        }
    } else if *state as libc::c_uint == GSS_AUTHSUCC as libc::c_int as libc::c_uint {
        if (*neg_ctx).havenoauthpersist() == 0 {
            (*neg_ctx)
                .set_noauthpersist(
                    ((*neg_ctx).havemultiplerequests() == 0) as libc::c_int as bit,
                );
        }
    }
    if (*neg_ctx).noauthpersist() as libc::c_int != 0
        || *state as libc::c_uint != GSS_AUTHDONE as libc::c_int as libc::c_uint
            && *state as libc::c_uint != GSS_AUTHSUCC as libc::c_int as libc::c_uint
    {
        if (*neg_ctx).noauthpersist() as libc::c_int != 0
            && *state as libc::c_uint == GSS_AUTHSUCC as libc::c_int as libc::c_uint
        {
            Curl_infof(
                data,
                b"Curl_output_negotiate, no persistent authentication: cleanup existing context\0"
                    as *const u8 as *const libc::c_char,
            );
            Curl_http_auth_cleanup_negotiate(conn);
        }
        if ((*neg_ctx).context).is_null() {
            result = Curl_input_negotiate(
                data,
                conn,
                proxy,
                b"Negotiate\0" as *const u8 as *const libc::c_char,
            );
            if result as libc::c_uint == CURLE_AUTH_ERROR as libc::c_int as libc::c_uint
            {
                (*authp).set_done(1 as libc::c_int as bit);
                return CURLE_OK;
            } else {
                if result as u64 != 0 {
                    return result;
                }
            }
        }
        result = Curl_auth_create_spnego_message(data, neg_ctx, &mut base64, &mut len);
        if result as u64 != 0 {
            return result;
        }
        userp = curl_maprintf(
            b"%sAuthorization: Negotiate %s\r\n\0" as *const u8 as *const libc::c_char,
            if proxy as libc::c_int != 0 {
                b"Proxy-\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            base64,
        );
        if proxy {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.proxyuserpwd as *mut libc::c_void);
            let ref mut fresh0 = (*data).state.aptr.proxyuserpwd;
            *fresh0 = 0 as *mut libc::c_char;
            let ref mut fresh1 = (*data).state.aptr.proxyuserpwd;
            *fresh1 = userp;
        } else {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.userpwd as *mut libc::c_void);
            let ref mut fresh2 = (*data).state.aptr.userpwd;
            *fresh2 = 0 as *mut libc::c_char;
            let ref mut fresh3 = (*data).state.aptr.userpwd;
            *fresh3 = userp;
        }
        Curl_cfree.expect("non-null function pointer")(base64 as *mut libc::c_void);
        if userp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        *state = GSS_AUTHSENT;
        #[cfg(HAVE_GSSAPI)]
        if (*neg_ctx).status == 0 as libc::c_int as libc::c_uint
            || (*neg_ctx).status
                == ((1 as libc::c_int) << 0 as libc::c_int + 0 as libc::c_int)
                    as libc::c_uint
        {
            *state = GSS_AUTHDONE;
        }
    }
    if *state as libc::c_uint == GSS_AUTHDONE as libc::c_int as libc::c_uint
        || *state as libc::c_uint == GSS_AUTHSUCC as libc::c_int as libc::c_uint
    {
        (*authp).set_done(1 as libc::c_int as bit);
    }
    (*neg_ctx).set_havenegdata(0 as libc::c_int as bit);
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_auth_cleanup_negotiate(mut conn: *mut connectdata) {
    (*conn).http_negotiate_state = GSS_AUTHNONE;
    (*conn).proxy_negotiate_state = GSS_AUTHNONE;
    Curl_auth_cleanup_spnego(&mut (*conn).negotiate);
    Curl_auth_cleanup_spnego(&mut (*conn).proxyneg);
}
