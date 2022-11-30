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
 * Description: http digest
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

#[no_mangle]
pub unsafe extern "C" fn Curl_input_digest(
    mut data: *mut Curl_easy,
    mut proxy: bool,
    mut header: *const libc::c_char,
) -> CURLcode {
    let mut digest: *mut digestdata = 0 as *mut digestdata;
    if proxy {
        digest = &mut (*data).state.proxydigest;
    } else {
        digest = &mut (*data).state.digest;
    }
    if curl_strnequal(
        b"Digest\0" as *const u8 as *const libc::c_char,
        header,
        strlen(b"Digest\0" as *const u8 as *const libc::c_char),
    ) == 0
        || Curl_isspace(*header.offset(6 as libc::c_int as isize) as libc::c_uchar as libc::c_int)
            == 0
    {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    header = header.offset(strlen(b"Digest\0" as *const u8 as *const libc::c_char) as isize);
    while *header as libc::c_int != 0 && Curl_isspace(*header as libc::c_uchar as libc::c_int) != 0
    {
        header = header.offset(1);
    }
    return Curl_auth_decode_digest_http_message(header, digest);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_output_digest(
    mut data: *mut Curl_easy,
    mut proxy: bool,
    mut request: *const libc::c_uchar,
    mut uripath: *const libc::c_uchar,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut path: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut response: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    let mut have_chlg: bool = false;
    let mut allocuserpwd: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut userp: *const libc::c_char = 0 as *const libc::c_char;
    let mut passwdp: *const libc::c_char = 0 as *const libc::c_char;
    let mut digest: *mut digestdata = 0 as *mut digestdata;
    let mut authp: *mut auth = 0 as *mut auth;
    if proxy {
        if cfg!(not(CURL_DISABLE_PROXY)) {
            digest = &mut (*data).state.proxydigest;
            allocuserpwd = &mut (*data).state.aptr.proxyuserpwd;
            userp = (*data).state.aptr.proxyuser;
            passwdp = (*data).state.aptr.proxypasswd;
            authp = &mut (*data).state.authproxy;
        } else {
            return CURLE_NOT_BUILT_IN;
        }
    } else {
        digest = &mut (*data).state.digest;
        allocuserpwd = &mut (*data).state.aptr.userpwd;
        userp = (*data).state.aptr.user;
        passwdp = (*data).state.aptr.passwd;
        authp = &mut (*data).state.authhost;
    }
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(*allocuserpwd as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        *allocuserpwd as *mut libc::c_void,
        112 as libc::c_int,
        b"http_digest.c\0" as *const u8 as *const libc::c_char,
    );
    *allocuserpwd = 0 as *mut libc::c_char;
    if userp.is_null() {
        userp = b"\0" as *const u8 as *const libc::c_char;
    }
    if passwdp.is_null() {
        passwdp = b"\0" as *const u8 as *const libc::c_char;
    }
    have_chlg = if !((*digest).nonce).is_null() {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    } != 0;
    if !have_chlg {
        (*authp).set_done(0 as libc::c_int as bit);
        return CURLE_OK;
    }
    if (*authp).iestyle() != 0 {
        tmp = strchr(uripath as *mut libc::c_char, '?' as i32);
        if !tmp.is_null() {
            let mut urilen: size_t =
                tmp.offset_from(uripath as *mut libc::c_char) as libc::c_long as size_t;
            path = curl_maprintf(
                b"%.*s\0" as *const u8 as *const libc::c_char,
                urilen as libc::c_int,
                uripath,
            ) as *mut libc::c_uchar;
        }
    }
    if tmp.is_null() {
        #[cfg(not(CURLDEBUG))]
        let mut newpath: *mut libc::c_uchar =
            Curl_cstrdup.expect("non-null function pointer")(uripath as *mut libc::c_char)
                as *mut libc::c_uchar;
        #[cfg(CURLDEBUG)]
        let mut newpath: *mut libc::c_uchar = curl_dbg_strdup(
            uripath as *mut libc::c_char,
            154 as libc::c_int,
            b"http_digest.c\0" as *const u8 as *const libc::c_char,
        ) as *mut libc::c_uchar;
        path = newpath;
    }
    if path.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_auth_create_digest_http_message(
        data,
        userp,
        passwdp,
        request,
        path,
        digest,
        &mut response,
        &mut len,
    );
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(path as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        path as *mut libc::c_void,
        161 as libc::c_int,
        b"http_digest.c\0" as *const u8 as *const libc::c_char,
    );
    if result as u64 != 0 {
        return result;
    }
    *allocuserpwd = curl_maprintf(
        b"%sAuthorization: Digest %s\r\n\0" as *const u8 as *const libc::c_char,
        if proxy as libc::c_int != 0 {
            b"Proxy-\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        response,
    );
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(response as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        response as *mut libc::c_void,
        168 as libc::c_int,
        b"http_digest.c\0" as *const u8 as *const libc::c_char,
    );
    if (*allocuserpwd).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (*authp).set_done(1 as libc::c_int as bit);
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_auth_cleanup_digest(mut data: *mut Curl_easy) {
    Curl_auth_digest_cleanup(&mut (*data).state.digest);
    Curl_auth_digest_cleanup(&mut (*data).state.proxydigest);
}
