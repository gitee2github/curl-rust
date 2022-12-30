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

/* Test example headers:

WWW-Authenticate: Digest realm="testrealm", nonce="1053604598"
Proxy-Authenticate: Digest realm="testrealm", nonce="1053604598"

*/

#[no_mangle]
pub extern "C" fn Curl_input_digest(
    mut data: *mut Curl_easy,
    mut proxy: bool,
    mut header: *const libc::c_char,
) -> CURLcode {
        /* rest of the *-authenticate:
        header */
        let mut digest: *mut digestdata =unsafe { 0 as *mut digestdata};
        /* Point to the correct struct with this */
        unsafe {
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
            || Curl_isspace(*header.offset(6 as i32 as isize) as u8 as i32) == 0
        {
            return CURLE_BAD_CONTENT_ENCODING;
        }
        header = header.offset(strlen(b"Digest\0" as *const u8 as *const libc::c_char) as isize);
        while *header as i32 != 0 && Curl_isspace(*header as u8 as i32) != 0 {
            header = header.offset(1);
        }
        return Curl_auth_decode_digest_http_message(header, digest);
    }
}
#[no_mangle]
pub extern "C" fn Curl_output_digest(
    mut data: *mut Curl_easy,
    mut proxy: bool,
    mut request: *const u8,
    mut uripath: *const u8,
) -> CURLcode {
        let mut result: CURLcode = CURLE_OK;
        let mut path: *mut u8 =unsafe { 0 as *mut u8};
        let mut tmp: *mut libc::c_char =unsafe { 0 as *mut libc::c_char};
        let mut response: *mut libc::c_char =unsafe { 0 as *mut libc::c_char};
        let mut len: size_t = 0;
        let mut have_chlg: bool = false;
        /* Point to the address of the pointer that holds the string to send to the
        server, which is for a plain host or for a HTTP proxy */
        let mut allocuserpwd: *mut *mut libc::c_char =unsafe { 0 as *mut *mut libc::c_char};
        /* Point to the name and password for this */
        let mut userp: *const libc::c_char =unsafe { 0 as *const libc::c_char};
        let mut passwdp: *const libc::c_char =unsafe { 0 as *const libc::c_char};
        /* Point to the correct struct with this */
        let mut digest: *mut digestdata = unsafe {0 as *mut digestdata};
        let mut authp: *mut auth =unsafe { 0 as *mut auth};
        unsafe {
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
            112 as i32,
            b"http_digest.c\0" as *const u8 as *const libc::c_char,
        );
        *allocuserpwd = 0 as *mut libc::c_char;
        /* not set means empty */
        if userp.is_null() {
            userp = b"\0" as *const u8 as *const libc::c_char;
        }
        if passwdp.is_null() {
            passwdp = b"\0" as *const u8 as *const libc::c_char;
        }
        have_chlg = if !((*digest).nonce).is_null() {
            1 as i32
        } else {
            0 as i32
        } != 0;
        if !have_chlg {
            (*authp).set_done(0 as bit);
            return CURLE_OK;
        }
        /* So IE browsers < v7 cut off the URI part at the query part when they
           evaluate the MD5 and some (IIS?) servers work with them so we may need to
           do the Digest IE-style. Note that the different ways cause different MD5
           sums to get sent.

           Apache servers can be set to do the Digest IE-style automatically using
           the BrowserMatch feature:
           https://httpd.apache.org/docs/2.2/mod/mod_auth_digest.html#msie

           Further details on Digest implementation differences:
           http://www.fngtps.com/2006/09/http-authentication
        */

        if (*authp).iestyle() != 0 {
            tmp = strchr(uripath as *mut libc::c_char, '?' as i32);
            if !tmp.is_null() {
                let mut urilen: size_t = tmp.offset_from(uripath as *mut libc::c_char) as size_t;
                /* typecast is fine here since the value is always less than 32 bits */
                path = curl_maprintf(
                    b"%.*s\0" as *const u8 as *const libc::c_char,
                    urilen as i32,
                    uripath,
                ) as *mut u8;
            }
        }
        if tmp.is_null() {
            #[cfg(not(CURLDEBUG))]
            let mut newpath: *mut u8 =
                Curl_cstrdup.expect("non-null function pointer")(uripath as *mut libc::c_char)
                    as *mut u8;
            #[cfg(CURLDEBUG)]
            let mut newpath: *mut u8 = curl_dbg_strdup(
                uripath as *mut libc::c_char,
                154 as i32,
                b"http_digest.c\0" as *const u8 as *const libc::c_char,
            ) as *mut u8;
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
            161 as i32,
            b"http_digest.c\0" as *const u8 as *const libc::c_char,
        );
        if result as u64 != 0 {
            return result;
        }
        *allocuserpwd = curl_maprintf(
            b"%sAuthorization: Digest %s\r\n\0" as *const u8 as *const libc::c_char,
            if proxy as i32 != 0 {
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
            168 as i32,
            b"http_digest.c\0" as *const u8 as *const libc::c_char,
        );
        if (*allocuserpwd).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*authp).set_done(1 as bit);
        return CURLE_OK;
    }
}
#[no_mangle]
pub extern "C" fn Curl_http_auth_cleanup_digest(mut data: *mut Curl_easy) {
    unsafe {
        Curl_auth_digest_cleanup(&mut (*data).state.digest);
        Curl_auth_digest_cleanup(&mut (*data).state.proxydigest);
    }
}
