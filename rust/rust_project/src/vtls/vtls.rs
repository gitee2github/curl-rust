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
 * Description: virtual tls
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
/* convenience macro to check if this handle is using a shared SSL session */
fn SSLSESSION_SHARED(data: *mut Curl_easy) -> bool {
    unsafe {
        !((*data).share).is_null()
            && (*(*data).share).specifier & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32) as u32
                != 0
    }
}
extern "C" fn blobdup(mut dest: *mut *mut curl_blob, mut src: *mut curl_blob) -> CURLcode {
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !dest.is_null() {
    } else {
        unsafe {
            __assert_fail(
                b"dest\0" as *const u8 as *const libc::c_char,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                97 as libc::c_uint,
                (*::std::mem::transmute::<&[u8; 58], &[libc::c_char; 58]>(
                    b"CURLcode blobdup(struct curl_blob **, struct curl_blob *)\0",
                ))
                .as_ptr(),
            );
        }
    }
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if unsafe { (*dest).is_null() } {
    } else {
        unsafe {
            __assert_fail(
                b"!*dest\0" as *const u8 as *const libc::c_char,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                98 as libc::c_uint,
                (*::std::mem::transmute::<&[u8; 58], &[libc::c_char; 58]>(
                    b"CURLcode blobdup(struct curl_blob **, struct curl_blob *)\0",
                ))
                .as_ptr(),
            );
        }
    }
    /* only if there's data to dupe! */
    if !src.is_null() {
        let mut d: *mut curl_blob = 0 as *mut curl_blob;
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                d = unsafe {
                    Curl_cmalloc.expect("non-null function pointer")(
                        (::std::mem::size_of::<curl_blob>() as u64).wrapping_add((*src).len),
                    ) as *mut curl_blob
                };
            }
            #[cfg(CURLDEBUG)]
            _ => {
                d = unsafe {
                    curl_dbg_malloc(
                        (::std::mem::size_of::<curl_blob>() as u64).wrapping_add((*src).len),
                        102 as i32,
                        b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                    ) as *mut curl_blob
                };
            }
        }
        if d.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        unsafe {
            (*d).len = (*src).len;
            /* Always duplicate because the connection may survive longer than the
            handle that passed in the blob. */
            (*d).flags = 1 as libc::c_uint;
            (*d).data = (d as *mut libc::c_char).offset(::std::mem::size_of::<curl_blob>() as isize)
                as *mut libc::c_void;
            memcpy((*d).data, (*src).data, (*src).len);
            *dest = d;
        }
    }
    return CURLE_OK;
}
/* returns TRUE if the blobs are identical */
extern "C" fn blobcmp(mut first: *mut curl_blob, mut second: *mut curl_blob) -> bool {
    if first.is_null() && second.is_null() {
        /* both are NULL */
        return 1 as i32 != 0;
    }
    if first.is_null() || second.is_null() {
        /* one is NULL */
        return 0 as i32 != 0;
    }
    if unsafe { (*first).len != (*second).len } {
        /* different sizes */
        return 0 as i32 != 0;
    }
    return unsafe { memcmp((*first).data, (*second).data, (*first).len) } == 0; /* same data */
}
extern "C" fn safecmp(mut a: *mut libc::c_char, mut b: *mut libc::c_char) -> bool {
    if !a.is_null() && !b.is_null() {
        return unsafe { strcmp(a, b) } == 0;
    } else {
        if a.is_null() && b.is_null() {
            return 1 as i32 != 0; /* match */
        }
    }
    return 0 as i32 != 0; /* no match */
}
#[no_mangle]
pub extern "C" fn Curl_ssl_config_matches(
    mut data: *mut ssl_primary_config,
    mut needle: *mut ssl_primary_config,
) -> bool {
    if unsafe {
        (*data).version == (*needle).version
            && (*data).version_max == (*needle).version_max
            && (*data).verifypeer() as i32 == (*needle).verifypeer() as i32
            && (*data).verifyhost() as i32 == (*needle).verifyhost() as i32
            && (*data).verifystatus() as i32 == (*needle).verifystatus() as i32
            && blobcmp((*data).cert_blob, (*needle).cert_blob) as i32 != 0
            && blobcmp((*data).ca_info_blob, (*needle).ca_info_blob) as i32 != 0
            && blobcmp((*data).issuercert_blob, (*needle).issuercert_blob) as i32 != 0
            && safecmp((*data).CApath, (*needle).CApath) as i32 != 0
            && safecmp((*data).CAfile, (*needle).CAfile) as i32 != 0
            && safecmp((*data).issuercert, (*needle).issuercert) as i32 != 0
            && safecmp((*data).clientcert, (*needle).clientcert) as i32 != 0
            && safecmp((*data).random_file, (*needle).random_file) as i32 != 0
            && safecmp((*data).egdsocket, (*needle).egdsocket) as i32 != 0
            && Curl_safe_strcasecompare((*data).cipher_list, (*needle).cipher_list) != 0
            && Curl_safe_strcasecompare((*data).cipher_list13, (*needle).cipher_list13) != 0
            && Curl_safe_strcasecompare((*data).curves, (*needle).curves) != 0
            && Curl_safe_strcasecompare((*data).pinned_key, (*needle).pinned_key) != 0
    } {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_clone_primary_ssl_config(
    mut source: *mut ssl_primary_config,
    mut dest: *mut ssl_primary_config,
) -> bool {
    unsafe {
        (*dest).version = (*source).version;
        (*dest).version_max = (*source).version_max;
        (*dest).set_verifypeer((*source).verifypeer());
        (*dest).set_verifyhost((*source).verifyhost());
        (*dest).set_verifystatus((*source).verifystatus());
        (*dest).set_sessionid((*source).sessionid());
    }
    if unsafe { blobdup(&mut (*dest).cert_blob, (*source).cert_blob) as u64 != 0 } {
        return 0 as i32 != 0;
    }
    if unsafe { blobdup(&mut (*dest).ca_info_blob, (*source).ca_info_blob) as u64 != 0 } {
        return 0 as i32 != 0;
    }
    if unsafe { blobdup(&mut (*dest).issuercert_blob, (*source).issuercert_blob) as u64 != 0 } {
        return 0 as i32 != 0;
    }
    if unsafe { !((*source).CApath).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).CApath = Curl_cstrdup.expect("non-null function pointer")((*source).CApath);
            },
            #[cfg(CURLDEBUG)]
            _ => unsafe {
                (*dest).CApath = curl_dbg_strdup(
                    (*source).CApath,
                    179 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }
        if unsafe { ((*dest).CApath).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).CApath = 0 as *mut libc::c_char;
        }
    }
    if unsafe { !((*source).CAfile).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).CAfile = Curl_cstrdup.expect("non-null function pointer")((*source).CAfile);
            },
            _ => unsafe {
                (*dest).CAfile = curl_dbg_strdup(
                    (*source).CAfile,
                    180 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }
        if unsafe { ((*dest).CAfile).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).CAfile = 0 as *mut libc::c_char;
        }
    }
    if unsafe { !((*source).issuercert).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).issuercert =
                    Curl_cstrdup.expect("non-null function pointer")((*source).issuercert);
            },
            #[cfg(CURLDEBUG)]
            _ => unsafe {
                (*dest).issuercert = curl_dbg_strdup(
                    (*source).issuercert,
                    181 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }

        if unsafe { ((*dest).issuercert).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).issuercert = 0 as *mut libc::c_char;
        }
    }
    if unsafe { !((*source).clientcert).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).clientcert =
                    Curl_cstrdup.expect("non-null function pointer")((*source).clientcert);
            },
            #[cfg(CURLDEBUG)]
            _ => unsafe {
                (*dest).clientcert = curl_dbg_strdup(
                    (*source).clientcert,
                    182 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }

        if unsafe { ((*dest).clientcert).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).clientcert = 0 as *mut libc::c_char;
        }
    }
    if unsafe { !((*source).random_file).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).random_file =
                    Curl_cstrdup.expect("non-null function pointer")((*source).random_file);
            },
            #[cfg(CURLDEBUG)]
            _ => unsafe {
                (*dest).random_file = curl_dbg_strdup(
                    (*source).random_file,
                    183 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }

        if unsafe { ((*dest).random_file).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).random_file = 0 as *mut libc::c_char;
        }
    }
    if unsafe { !((*source).egdsocket).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).egdsocket =
                    Curl_cstrdup.expect("non-null function pointer")((*source).egdsocket);
            },
            #[cfg(CURLDEBUG)]
            _ => unsafe {
                (*dest).egdsocket = curl_dbg_strdup(
                    (*source).egdsocket,
                    184 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }

        if unsafe { ((*dest).egdsocket).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).egdsocket = 0 as *mut libc::c_char;
        }
    }
    if unsafe { !((*source).cipher_list).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).cipher_list =
                    Curl_cstrdup.expect("non-null function pointer")((*source).cipher_list);
            },
            #[cfg(CURLDEBUG)]
            _ => unsafe {
                (*dest).cipher_list = curl_dbg_strdup(
                    (*source).cipher_list,
                    185 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }

        if unsafe { ((*dest).cipher_list).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).cipher_list = 0 as *mut libc::c_char;
        }
    }
    if unsafe { !((*source).cipher_list13).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).cipher_list13 =
                    Curl_cstrdup.expect("non-null function pointer")((*source).cipher_list13);
            },
            #[cfg(CURLDEBUG)]
            _ => unsafe {
                (*dest).cipher_list13 = curl_dbg_strdup(
                    (*source).cipher_list13,
                    186 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }

        if unsafe { ((*dest).cipher_list13).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).cipher_list13 = 0 as *mut libc::c_char;
        }
    }
    if unsafe { !((*source).pinned_key).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).pinned_key =
                    Curl_cstrdup.expect("non-null function pointer")((*source).pinned_key);
            },
            #[cfg(CURLDEBUG)]
            _ => unsafe {
                (*dest).pinned_key = curl_dbg_strdup(
                    (*source).pinned_key,
                    187 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }

        if unsafe { ((*dest).pinned_key).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).pinned_key = 0 as *mut libc::c_char;
        }
    }
    if unsafe { !((*source).curves).is_null() } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => unsafe {
                (*dest).curves = Curl_cstrdup.expect("non-null function pointer")((*source).curves);
            },
            #[cfg(CURLDEBUG)]
            _ => unsafe {
                (*dest).curves = curl_dbg_strdup(
                    (*source).curves,
                    188 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            },
        }

        if unsafe { ((*dest).curves).is_null() } {
            return 0 as i32 != 0;
        }
    } else {
        unsafe {
            (*dest).curves = 0 as *mut libc::c_char;
        }
    }
    return 1 as i32 != 0;
}

#[no_mangle]
pub extern "C" fn Curl_free_primary_ssl_config(mut sslc: *mut ssl_primary_config) {
    unsafe {
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*sslc).CApath as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).CApath as *mut libc::c_void,
            195 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).CApath = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*sslc).CAfile as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).CAfile as *mut libc::c_void,
            196 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).CAfile = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*sslc).issuercert as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).issuercert as *mut libc::c_void,
            197 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).issuercert = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*sslc).clientcert as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).clientcert as *mut libc::c_void,
            198 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).clientcert = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*sslc).random_file as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).random_file as *mut libc::c_void,
            199 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).random_file = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*sslc).egdsocket as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).egdsocket as *mut libc::c_void,
            200 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).egdsocket = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).cipher_list as *mut libc::c_void,
            201 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).cipher_list = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).cipher_list13 as *mut libc::c_void,
            202 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).cipher_list13 = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).pinned_key as *mut libc::c_void,
            203 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).pinned_key = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).cert_blob as *mut libc::c_void,
            204 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).cert_blob = 0 as *mut curl_blob;
        #[cfg(not(CURLDEBUG))]
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).ca_info_blob as *mut libc::c_void,
            205 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).ca_info_blob = 0 as *mut curl_blob;
        #[cfg(not(CURLDEBUG))]
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).issuercert_blob as *mut libc::c_void,
            206 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).issuercert_blob = 0 as *mut curl_blob;
        #[cfg(not(CURLDEBUG))]
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*sslc).curves as *mut libc::c_void,
            207 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*sslc).curves = 0 as *mut libc::c_char;
    }
}
#[no_mangle]
pub extern "C" fn Curl_ssl_backend() -> i32 {
    #[cfg(USE_SSL)]
    multissl_setup(0 as *const Curl_ssl);
    #[cfg(USE_SSL)]
    return unsafe { (*Curl_ssl).info.id as i32 };
    #[cfg(not(USE_SSL))]
    return CURLSSLBACKEND_NONE as i32;
}
#[cfg(USE_SSL)]
static mut init_ssl: bool = 0 as i32 != 0; /* "global" init done? */
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_init() -> i32 {
    unsafe {
        /* make sure this is only done once */
        if init_ssl {
            return 1 as i32; /* never again */
        }
        init_ssl = 1 as i32 != 0;
        return ((*Curl_ssl).init).expect("non-null function pointer")();
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_cleanup() {
    /* Global cleanup */
    unsafe {
        if init_ssl {
            /* only cleanup if we did a previous init */
            ((*Curl_ssl).cleanup).expect("non-null function pointer")();
            if cfg!(CURL_WITH_MULTI_SSL) {
                Curl_ssl = &Curl_ssl_multi;
            }
            init_ssl = 0 as i32 != 0;
        }
    }
}
#[cfg(USE_SSL)]
extern "C" fn ssl_prefs_check(mut data: *mut Curl_easy) -> bool {
    /* check for CURLOPT_SSLVERSION invalid parameter value */

    let sslver: i64 = unsafe { (*data).set.ssl.primary.version };
    if sslver < 0 as i64 || sslver >= CURL_SSLVERSION_LAST as i64 {
        unsafe {
            Curl_failf(
                data,
                b"Unrecognized parameter value passed via CURLOPT_SSLVERSION\0" as *const u8
                    as *const libc::c_char,
            );
        }
        return 0 as i32 != 0;
    }
    match unsafe { (*data).set.ssl.primary.version_max } {
        0 | 65536 => {}
        _ => {
            if unsafe { ((*data).set.ssl.primary.version_max >> 16 as i32) < sslver } {
                unsafe {
                    Curl_failf(
                        data,
                        b"CURL_SSLVERSION_MAX incompatible with CURL_SSLVERSION\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                return 0 as i32 != 0;
            }
        }
    }
    return 1 as i32 != 0;
}

#[cfg(all(USE_SSL, not(CURL_DISABLE_PROXY)))]
extern "C" fn ssl_connect_init_proxy(mut conn: *mut connectdata, mut sockindex: i32) -> CURLcode {
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if unsafe { (*conn).bits.proxy_ssl_connected[sockindex as usize] } {
    } else {
        unsafe {
            __assert_fail(
                b"conn->bits.proxy_ssl_connected[sockindex]\0" as *const u8 as *const libc::c_char,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                290 as libc::c_uint,
                (*::std::mem::transmute::<&[u8; 59], &[libc::c_char; 59]>(
                    b"CURLcode ssl_connect_init_proxy(struct connectdata *, int)\0",
                ))
                .as_ptr(),
            );
        }
    }
    if ssl_connection_complete as libc::c_uint
        == unsafe { (*conn).ssl[sockindex as usize].state as libc::c_uint }
        && unsafe { ((*conn).proxy_ssl[sockindex as usize]).use_0() == 0 }
    {
        let mut pbdata: *mut ssl_backend_data = 0 as *mut ssl_backend_data;
        if unsafe { (*Curl_ssl).supports & ((1 as i32) << 4 as i32) as u32 == 0 } {
            return CURLE_NOT_BUILT_IN;
        }
        /* The pointers to the ssl backend data, which is opaque here, are swapped
        rather than move the contents. */
        unsafe {
            pbdata = (*conn).proxy_ssl[sockindex as usize].backend;
            (*conn).proxy_ssl[sockindex as usize] = (*conn).ssl[sockindex as usize];
            memset(
                &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
                    as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<ssl_connect_data>() as u64,
            );
            memset(
                pbdata as *mut libc::c_void,
                0 as i32,
                (*Curl_ssl).sizeof_ssl_backend_data,
            );
            (*conn).ssl[sockindex as usize].backend = pbdata;
        }
    }
    return CURLE_OK;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    #[cfg(not(CURL_DISABLE_PROXY))]
    if unsafe { (*conn).bits.proxy_ssl_connected[sockindex as usize] } {
        result = ssl_connect_init_proxy(conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if !ssl_prefs_check(data) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    /* mark this is being ssl-enabled from here on. */
    unsafe {
        ((*conn).ssl[sockindex as usize]).set_use_0(1 as bit);
        (*conn).ssl[sockindex as usize].state = ssl_connection_negotiating;
    }
    result = unsafe {
        ((*Curl_ssl).connect_blocking).expect("non-null function pointer")(data, conn, sockindex)
    };
    if result as u64 == 0 {
        unsafe {
            Curl_pgrsTime(data, TIMER_APPCONNECT);
        } /* SSL is connected */
    } else {
        /* mark this is being ssl requested from here on. */
        unsafe {
            ((*conn).ssl[sockindex as usize]).set_use_0(0 as bit);
        }
    }
    return result;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut isproxy: bool,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    #[cfg(not(CURL_DISABLE_PROXY))]
    unsafe {
        if (*conn).bits.proxy_ssl_connected[sockindex as usize] {
            result = ssl_connect_init_proxy(conn, sockindex);
            if result as u64 != 0 {
                return result;
            }
        }
    }
    if !ssl_prefs_check(data) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    unsafe {
        ((*conn).ssl[sockindex as usize]).set_use_0(1 as bit);
        result = ((*Curl_ssl).connect_nonblocking).expect("non-null function pointer")(
            data, conn, sockindex, done,
        );
    }
    if result as u64 != 0 {
        unsafe {
            ((*conn).ssl[sockindex as usize]).set_use_0(0 as bit);
        }
    } else if unsafe { *done as i32 } != 0 && !isproxy {
        unsafe {
            Curl_pgrsTime(data, TIMER_APPCONNECT);
        } /* SSL is connected */
    }
    return result;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_sessionid_lock(mut data: *mut Curl_easy) {
    /*
     * Lock shared SSL session data
     */
    unsafe {
        if (SSLSESSION_SHARED(data)) {
            Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
        }
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_sessionid_unlock(mut data: *mut Curl_easy) {
    /*
     * Unlock shared SSL session data
     */
    unsafe {
        if (SSLSESSION_SHARED(data)) {
            Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);
        }
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_getsessionid(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    isProxy: bool,
    mut ssl_sessionid: *mut *mut libc::c_void,
    mut idsize: *mut size_t, /* set 0 if unknown */
    mut sockindex: i32,
) -> bool {
    /*
     * Check if there's a session ID for the given connection in the cache, and if
     * there's one suitable, it is provided. Returns TRUE when no entry matched.
     */

    let mut check: *mut Curl_ssl_session = 0 as *mut Curl_ssl_session;
    let mut i: size_t = 0;
    let mut general_age: *mut i64 = 0 as *mut i64;
    let mut no_match: bool = 1 as i32 != 0;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let ssl_config: *mut ssl_primary_config = if isProxy as i32 != 0 {
        unsafe { &mut (*conn).proxy_ssl_config }
    } else {
        unsafe { &mut (*conn).ssl_config }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let ssl_config: *mut ssl_primary_config = unsafe { &mut (*conn).ssl_config };
    #[cfg(not(CURL_DISABLE_PROXY))]
    let name: *const libc::c_char = if isProxy as i32 != 0 {
        unsafe { (*conn).http_proxy.host.name }
    } else {
        unsafe { (*conn).host.name }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let name: *const libc::c_char = unsafe { (*conn).host.name };
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut port: i32 = if isProxy as i32 != 0 {
        unsafe { (*conn).port }
    } else {
        unsafe { (*conn).remote_port }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut port: i32 = unsafe { (*conn).remote_port };
    unsafe {
        *ssl_sessionid = 0 as *mut libc::c_void;
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if isProxy as i32 != 0 {
        return 1 as i32 != 0;
    }
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if (if CURLPROXY_HTTPS as libc::c_uint
        == unsafe { (*conn).http_proxy.proxytype as libc::c_uint }
        && ssl_connection_complete as libc::c_uint
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as libc::c_uint
            }
    {
        unsafe { ((*data).set.proxy_ssl.primary).sessionid() as i32 }
    } else {
        unsafe { ((*data).set.ssl.primary).sessionid() as i32 }
    }) != 0
    {
    } else {
        unsafe {
            __assert_fail(
             b"((CURLPROXY_HTTPS == conn->http_proxy.proxytype && ssl_connection_complete != conn->proxy_ssl[conn->sock[1] == -1 ? 0 : 1].state) ? data->set.proxy_ssl.primary.sessionid : data->set.ssl.primary.sessionid)\0"
                 as *const u8 as *const libc::c_char,
             b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
             424 as libc::c_uint,
             (*::std::mem::transmute::<
                 &[u8; 107],
                 &[libc::c_char; 107],
             >(
                 b"_Bool Curl_ssl_getsessionid(struct Curl_easy *, struct connectdata *, const _Bool, void **, size_t *, int)\0",
             ))
                 .as_ptr(),
         );
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag: bool = (if CURLPROXY_HTTPS as libc::c_uint
        == unsafe { (*conn).http_proxy.proxytype as libc::c_uint }
        && ssl_connection_complete as libc::c_uint
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as libc::c_uint
            } {
        unsafe { ((*data).set.proxy_ssl.primary).sessionid() as i32 }
    } else {
        unsafe { ((*data).set.ssl.primary).sessionid() as i32 }
    }) == 0;
    #[cfg(CURL_DISABLE_PROXY)]
    let flag: bool = unsafe { ((*data).set.ssl.primary).sessionid() == 0 };
    if flag || unsafe { ((*data).state.session).is_null() } {
        return 1 as i32 != 0;
    }
    if (SSLSESSION_SHARED(data)) {
        general_age = unsafe { &mut (*(*data).share).sessionage };
    } else {
        general_age = unsafe { &mut (*data).state.sessionage };
    }
    i = 0 as size_t;
    unsafe {
        while i < (*data).set.general_ssl.max_ssl_sessions {
            check = &mut *((*data).state.session).offset(i as isize) as *mut Curl_ssl_session;
            if !((*check).sessionid).is_null() {
                if Curl_strcasecompare(name, (*check).name) != 0
                    && (((*conn).bits).conn_to_host() == 0 && ((*check).conn_to_host).is_null()
                        || ((*conn).bits).conn_to_host() as i32 != 0
                            && !((*check).conn_to_host).is_null()
                            && Curl_strcasecompare(
                                (*conn).conn_to_host.name,
                                (*check).conn_to_host,
                            ) != 0)
                    && (((*conn).bits).conn_to_port() == 0 && (*check).conn_to_port == -(1 as i32)
                        || ((*conn).bits).conn_to_port() as i32 != 0
                            && (*check).conn_to_port != -(1 as i32)
                            && (*conn).conn_to_port == (*check).conn_to_port)
                    && port == (*check).remote_port
                    && Curl_strcasecompare((*(*conn).handler).scheme, (*check).scheme) != 0
                    && Curl_ssl_config_matches(ssl_config, &mut (*check).ssl_config) as i32 != 0
                {
                    /* yes, we have a session ID! */
                    *general_age += 1; /* increase general age */
                    (*check).age = *general_age; /* set this as used in this age */
                    *ssl_sessionid = (*check).sessionid;
                    if !idsize.is_null() {
                        *idsize = (*check).idsize;
                    }
                    no_match = 0 as i32 != 0;
                    break;
                }
            }
            i = i.wrapping_add(1);
        }
    }
    #[cfg(DEBUGBUILD)]
    unsafe {
        Curl_infof(
            data,
            b"%s Session ID in cache for %s %s://%s:%d\0" as *const u8 as *const libc::c_char,
            if no_match as i32 != 0 {
                b"Didn't find\0" as *const u8 as *const libc::c_char
            } else {
                b"Found\0" as *const u8 as *const libc::c_char
            },
            if isProxy as i32 != 0 {
                b"proxy\0" as *const u8 as *const libc::c_char
            } else {
                b"host\0" as *const u8 as *const libc::c_char
            },
            (*(*conn).handler).scheme,
            name,
            port,
        );
    }
    return no_match;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_kill_session(mut session: *mut Curl_ssl_session) {
    /*
     * Kill a single session ID entry in the cache.
     */
    if !unsafe { ((*session).sessionid).is_null() } {
        /* defensive check */
        unsafe {
            /* free the ID the SSL-layer specific way */
            ((*Curl_ssl).session_free).expect("non-null function pointer")((*session).sessionid);
            (*session).sessionid = 0 as *mut libc::c_void;
            (*session).age = 0 as i64; /* fresh */
            Curl_free_primary_ssl_config(&mut (*session).ssl_config);
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")((*session).name as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*session).name as *mut libc::c_void,
                486 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
            (*session).name = 0 as *mut libc::c_char;
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(
                (*session).conn_to_host as *mut libc::c_void,
            );
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*session).conn_to_host as *mut libc::c_void,
                487 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
            (*session).conn_to_host = 0 as *mut libc::c_char;
        }
    }
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_delsessionid(
    mut data: *mut Curl_easy,
    mut ssl_sessionid: *mut libc::c_void,
) {
    /*
     * Delete the given session ID from the cache.
     */

    let mut i: size_t = 0;
    i = 0 as size_t;
    while i < unsafe { (*data).set.general_ssl.max_ssl_sessions } {
        let mut check: *mut Curl_ssl_session =
            unsafe { &mut *((*data).state.session).offset(i as isize) as *mut Curl_ssl_session };
        if unsafe { (*check).sessionid == ssl_sessionid } {
            Curl_ssl_kill_session(check);
            break;
        } else {
            i = i.wrapping_add(1);
        }
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_addsessionid(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    isProxy: bool,
    mut ssl_sessionid: *mut libc::c_void,
    mut idsize: size_t,
    mut sockindex: i32,
) -> CURLcode {
    /*
     * Store session id in the session cache. The ID passed on to this function
     * must already have been extracted and allocated the proper way for the SSL
     * layer. Curl_XXXX_session_free() will be called to free/kill the session ID
     * later on.
     */

    let mut i: size_t = 0;
    let mut store: *mut Curl_ssl_session = 0 as *mut Curl_ssl_session;
    let mut oldest_age: i64 = 0; /* zero if unused */
    let mut clone_host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut clone_conn_to_host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut conn_to_port: i32 = 0;
    let mut general_age: *mut i64 = 0 as *mut i64;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let ssl_config: *mut ssl_primary_config = if isProxy as i32 != 0 {
        unsafe { &mut (*conn).proxy_ssl_config }
    } else {
        unsafe { &mut (*conn).ssl_config }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let ssl_config: *mut ssl_primary_config = unsafe { &mut (*conn).ssl_config };
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut hostname: *const libc::c_char = if isProxy as i32 != 0 {
        unsafe { (*conn).http_proxy.host.name }
    } else {
        unsafe { (*conn).host.name }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut hostname: *const libc::c_char = unsafe { (*conn).host.name };
    if unsafe { ((*data).state.session).is_null() } {
        return CURLE_OK;
    }
    store = unsafe { &mut *((*data).state.session).offset(0 as isize) as *mut Curl_ssl_session };
    oldest_age = unsafe { (*((*data).state.session).offset(0 as isize)).age };
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if (if CURLPROXY_HTTPS as libc::c_uint
        == unsafe { (*conn).http_proxy.proxytype as libc::c_uint }
        && ssl_connection_complete as libc::c_uint
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as libc::c_uint
            }
    {
        unsafe { ((*data).set.proxy_ssl.primary).sessionid() as i32 }
    } else {
        unsafe { ((*data).set.ssl.primary).sessionid() as i32 }
    }) != 0
    {
    } else {
        unsafe {
            __assert_fail(
             b"((CURLPROXY_HTTPS == conn->http_proxy.proxytype && ssl_connection_complete != conn->proxy_ssl[conn->sock[1] == -1 ? 0 : 1].state) ? data->set.proxy_ssl.primary.sessionid : data->set.ssl.primary.sessionid)\0"
                 as *const u8 as *const libc::c_char,
             b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
             544 as i32 as libc::c_uint,
             (*::std::mem::transmute::<
                 &[u8; 107],
                 &[libc::c_char; 107],
             >(
                 b"CURLcode Curl_ssl_addsessionid(struct Curl_easy *, struct connectdata *, const _Bool, void *, size_t, int)\0",
             ))
                 .as_ptr(),
            );
        }
    }
    match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            clone_host = unsafe { Curl_cstrdup.expect("non-null function pointer")(hostname) };
        }
        #[cfg(CURLDEBUG)]
        _ => {
            clone_host = unsafe {
                curl_dbg_strdup(
                    hostname,
                    546 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }

    if clone_host.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if unsafe { ((*conn).bits).conn_to_host() != 0 } {
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                clone_conn_to_host = unsafe {
                    Curl_cstrdup.expect("non-null function pointer")((*conn).conn_to_host.name)
                };
            }
            #[cfg(CURLDEBUG)]
            _ => {
                clone_conn_to_host = unsafe {
                    curl_dbg_strdup(
                        (*conn).conn_to_host.name,
                        551 as i32,
                        b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }

        if clone_conn_to_host.is_null() {
            #[cfg(not(CURLDEBUG))]
            unsafe {
                Curl_cfree.expect("non-null function pointer")(clone_host as *mut libc::c_void);
            }
            #[cfg(CURLDEBUG)]
            unsafe {
                curl_dbg_free(
                    clone_host as *mut libc::c_void,
                    553 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            }
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        clone_conn_to_host = 0 as *mut libc::c_char;
    }
    if unsafe { ((*conn).bits).conn_to_port() != 0 } {
        conn_to_port = unsafe { (*conn).conn_to_port };
    } else {
        conn_to_port = -(1 as i32);
    }
    if (SSLSESSION_SHARED(data)) {
        general_age = unsafe { &mut (*(*data).share).sessionage };
    } else {
        general_age = unsafe { &mut (*data).state.sessionage };
    }
    i = 1 as size_t; /* find an empty slot for us, or find the oldest */
    unsafe {
        while i < (*data).set.general_ssl.max_ssl_sessions
            && !((*((*data).state.session).offset(i as isize)).sessionid).is_null()
        {
            if (*((*data).state.session).offset(i as isize)).age < oldest_age {
                oldest_age = (*((*data).state.session).offset(i as isize)).age;
                store = &mut *((*data).state.session).offset(i as isize) as *mut Curl_ssl_session;
            }
            i = i.wrapping_add(1);
        }
        if i == (*data).set.general_ssl.max_ssl_sessions {
            Curl_ssl_kill_session(store); /* cache is full, we must "kill" the oldest entry! */
        } else {
            store = &mut *((*data).state.session).offset(i as isize) as *mut Curl_ssl_session;
            /* use this slot */
        }
        /* now init the session struct wisely */
        (*store).sessionid = ssl_sessionid;
        (*store).idsize = idsize;
        (*store).age = *general_age; /* set current age */
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*store).name as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*store).name as *mut libc::c_void,
            595 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        ); /* free it if there's one already present */
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*store).conn_to_host as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            (*store).conn_to_host as *mut libc::c_void,
            596 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
        (*store).name = clone_host; /* clone host name */
        (*store).conn_to_host = clone_conn_to_host; /* clone connect to host name */
        (*store).conn_to_port = conn_to_port; /* connect to port number */
        (*store).remote_port = if isProxy as i32 != 0 {
            (*conn).port
        } else {
            (*conn).remote_port
        };
        (*store).scheme = (*(*conn).handler).scheme;
        if !Curl_clone_primary_ssl_config(ssl_config, &mut (*store).ssl_config) {
            Curl_free_primary_ssl_config(&mut (*store).ssl_config);
            (*store).sessionid = 0 as *mut libc::c_void;
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(clone_host as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                clone_host as *mut libc::c_void,
                607 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(clone_conn_to_host as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                clone_conn_to_host as *mut libc::c_void,
                608 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OUT_OF_MEMORY;
        }
        #[cfg(DEBUGBUILD)]
        Curl_infof(
            data,
            b"Added Session ID to cache for %s://%s:%d [%s]\0" as *const u8 as *const libc::c_char,
            (*store).scheme,
            (*store).name,
            (*store).remote_port,
            if isProxy as i32 != 0 {
                b"PROXY\0" as *const u8 as *const libc::c_char
            } else {
                b"server\0" as *const u8 as *const libc::c_char
            },
        );
    }
    return CURLE_OK;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_associate_conn(mut data: *mut Curl_easy, mut conn: *mut connectdata) {
    unsafe {
        if ((*Curl_ssl).associate_connection).is_some() {
            ((*Curl_ssl).associate_connection).expect("non-null function pointer")(
                data, conn, 0 as i32,
            );
            if (*conn).sock[1 as usize] != 0 && ((*conn).bits).sock_accepted() as i32 != 0 {
                ((*Curl_ssl).associate_connection).expect("non-null function pointer")(
                    data, conn, 1 as i32,
                );
            }
        }
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_detach_conn(mut data: *mut Curl_easy, mut conn: *mut connectdata) {
    unsafe {
        if ((*Curl_ssl).disassociate_connection).is_some() {
            ((*Curl_ssl).disassociate_connection).expect("non-null function pointer")(
                data, 0 as i32,
            );
            if (*conn).sock[1 as usize] != 0 && ((*conn).bits).sock_accepted() as i32 != 0 {
                ((*Curl_ssl).disassociate_connection).expect("non-null function pointer")(
                    data, 1 as i32,
                );
            }
        }
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_close_all(mut data: *mut Curl_easy) {
    if unsafe { !((*data).state.session).is_null() && !(SSLSESSION_SHARED(data)) } {
        /* kill the session ID cache if not shared */
        let mut i: size_t = 0;
        i = 0 as size_t;
        while i < unsafe { (*data).set.general_ssl.max_ssl_sessions } {
            /* the single-killer function handles empty table slots */
            unsafe {
                Curl_ssl_kill_session(&mut *((*data).state.session).offset(i as isize));
            }
            i = i.wrapping_add(1); /* free the cache data */
        }
        #[cfg(not(CURLDEBUG))]
        unsafe {
            Curl_cfree.expect("non-null function pointer")(
                (*data).state.session as *mut libc::c_void,
            );
        }
        #[cfg(CURLDEBUG)]
        unsafe {
            curl_dbg_free(
                (*data).state.session as *mut libc::c_void,
                648 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
            (*data).state.session = 0 as *mut Curl_ssl_session;
        }
    }
    unsafe {
        ((*Curl_ssl).close_all).expect("non-null function pointer")(data);
    }
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_getsock(
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    unsafe {
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(0 as isize) as *mut ssl_connect_data; /* write mode */
        if (*connssl).connecting_state as libc::c_uint == ssl_connect_2_writing as libc::c_uint {
            /* read mode */
            *socks.offset(0 as isize) = (*conn).sock[0 as usize];
            return (1 as i32) << 16 as i32 + 0 as i32;
        }
        if (*connssl).connecting_state as libc::c_uint == ssl_connect_2_reading as libc::c_uint {
            *socks.offset(0 as isize) = (*conn).sock[0 as usize];
            return (1 as i32) << 0 as i32;
        }
        return 0 as i32;
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if sockindex <= 1 as i32 && sockindex >= -(1 as i32) {
    } else {
        unsafe {
            __assert_fail(
                b"(sockindex <= 1) && (sockindex >= -1)\0" as *const u8 as *const libc::c_char,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                675 as libc::c_uint,
                (*::std::mem::transmute::<&[u8; 67], &[libc::c_char; 67]>(
                    b"void Curl_ssl_close(struct Curl_easy *, struct connectdata *, int)\0",
                ))
                .as_ptr(),
            );
        }
    }
    unsafe {
        ((*Curl_ssl).close_one).expect("non-null function pointer")(data, conn, sockindex);
        (*conn).ssl[sockindex as usize].state = ssl_connection_none;
    }
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    if unsafe {
        ((*Curl_ssl).shut_down).expect("non-null function pointer")(data, conn, sockindex) != 0
    } {
        return CURLE_SSL_SHUTDOWN_FAILED;
    }
    unsafe {
        ((*conn).ssl[sockindex as usize]).set_use_0(0 as bit);
        (*conn).ssl[sockindex as usize].state = ssl_connection_none;
        (*conn).recv[sockindex as usize] = Some(
            Curl_recv_plain
                as unsafe extern "C" fn(
                    *mut Curl_easy,
                    i32,
                    *mut libc::c_char,
                    size_t,
                    *mut CURLcode,
                ) -> ssize_t,
        );
        (*conn).send[sockindex as usize] = Some(
            Curl_send_plain
                as unsafe extern "C" fn(
                    *mut Curl_easy,
                    i32,
                    *const libc::c_void,
                    size_t,
                    *mut CURLcode,
                ) -> ssize_t,
        );
    }
    return CURLE_OK;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_set_engine(
    mut data: *mut Curl_easy,
    mut engine: *const libc::c_char,
) -> CURLcode {
    unsafe {
        /* Selects an SSL crypto engine
         */
        return ((*Curl_ssl).set_engine).expect("non-null function pointer")(data, engine);
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_set_engine_default(mut data: *mut Curl_easy) -> CURLcode {
    /* Selects the default SSL crypto engine
     */
    unsafe {
        return ((*Curl_ssl).set_engine_default).expect("non-null function pointer")(data);
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_engines_list(mut data: *mut Curl_easy) -> *mut curl_slist {
    /* Return list of OpenSSL crypto engine names. */
    unsafe {
        return ((*Curl_ssl).engines_list).expect("non-null function pointer")(data);
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_initsessions(mut data: *mut Curl_easy, mut amount: size_t) -> CURLcode {
    /*
     * This sets up a session ID cache to the specified size. Make sure this code
     * is agnostic to what underlying SSL technology we use.
     */

    let mut session: *mut Curl_ssl_session = 0 as *mut Curl_ssl_session;
    if unsafe { !((*data).state.session).is_null() } {
        /* this is just a precaution to prevent multiple inits */
        return CURLE_OK;
    }
    match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            session = unsafe {
                Curl_ccalloc.expect("non-null function pointer")(
                    amount,
                    ::std::mem::size_of::<Curl_ssl_session>() as u64,
                ) as *mut Curl_ssl_session
            };
        }
        #[cfg(CURLDEBUG)]
        _ => {
            session = unsafe {
                curl_dbg_calloc(
                    amount,
                    ::std::mem::size_of::<Curl_ssl_session>() as u64,
                    727 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                ) as *mut Curl_ssl_session
            };
        }
    }

    if session.is_null() {
        return CURLE_OUT_OF_MEMORY;
    } /* store the info in the SSL section */
    unsafe {
        (*data).set.general_ssl.max_ssl_sessions = amount;
        (*data).state.session = session;
        (*data).state.sessionage = 1 as i64; /* this is brand new */
    }
    return CURLE_OK;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_version(mut buffer: *mut libc::c_char, mut size: size_t) {
    unsafe {
        #[cfg(CURL_WITH_MULTI_SSL)]
        multissl_version(buffer, size);
        #[cfg(not(CURL_WITH_MULTI_SSL))]
        ((*Curl_ssl).version).expect("non-null function pointer")(buffer, size);
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_check_cxn(mut conn: *mut connectdata) -> i32 {
    unsafe {
        /*
         * This function tries to determine connection status.
         *
         * Return codes:
         *     1 means the connection is still in place
         *     0 means the connection has been closed
         *    -1 means the connection status is unknown
         */
        return ((*Curl_ssl).check_cxn).expect("non-null function pointer")(conn);
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_data_pending(mut conn: *const connectdata, mut connindex: i32) -> bool {
    unsafe {
        return ((*Curl_ssl).data_pending).expect("non-null function pointer")(conn, connindex);
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_free_certinfo(mut data: *mut Curl_easy) {
    let mut ci: *mut curl_certinfo = unsafe { &mut (*data).info.certs };
    if unsafe { (*ci).num_of_certs != 0 } {
        let mut i: i32 = 0;
        i = 0 as i32;
        unsafe {
            while i < (*ci).num_of_certs {
                curl_slist_free_all(*((*ci).certinfo).offset(i as isize));
                *((*ci).certinfo).offset(i as isize) = 0 as *mut curl_slist;
                i += 1;
            }
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")((*ci).certinfo as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                (*ci).certinfo as *mut libc::c_void,
                780 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
            (*ci).certinfo = 0 as *mut *mut curl_slist;
            (*ci).num_of_certs = 0 as i32;
        }
    }
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_init_certinfo(mut data: *mut Curl_easy, mut num: i32) -> CURLcode {
    /* free all individual lists used */

    let mut ci: *mut curl_certinfo = unsafe { &mut (*data).info.certs };
    let mut table: *mut *mut curl_slist = 0 as *mut *mut curl_slist;
    Curl_ssl_free_certinfo(data); /* Free any previous certificate information structures */
    match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            table = unsafe {
                Curl_ccalloc.expect("non-null function pointer")(
                    num as size_t,
                    ::std::mem::size_of::<*mut curl_slist>() as u64,
                ) as *mut *mut curl_slist
            };
        }
        #[cfg(CURLDEBUG)]
        _ => {
            table = unsafe {
                curl_dbg_calloc(
                    num as size_t,
                    ::std::mem::size_of::<*mut curl_slist>() as u64,
                    795 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                ) as *mut *mut curl_slist
            };
        }
    }
    /* Allocate the required certificate information structures */
    if table.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    unsafe {
        (*ci).num_of_certs = num;
        (*ci).certinfo = table;
    }
    return CURLE_OK;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_push_certinfo_len(
    mut data: *mut Curl_easy,
    mut certnum: i32,
    mut label: *const libc::c_char,
    mut value: *const libc::c_char,
    mut valuelen: size_t,
) -> CURLcode {
    /*
     * 'value' is NOT a null-terminated string
     */

    let mut ci: *mut curl_certinfo = unsafe { &mut (*data).info.certs };
    let mut output: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut nl: *mut curl_slist = 0 as *mut curl_slist;
    let mut result: CURLcode = CURLE_OK;
    let mut labellen: size_t = unsafe { strlen(label) };
    let mut outlen: size_t = labellen
        .wrapping_add(1 as u64)
        .wrapping_add(valuelen)
        .wrapping_add(1 as u64); /* label:value\0 */

    match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            output = unsafe {
                Curl_cmalloc.expect("non-null function pointer")(outlen) as *mut libc::c_char
            };
        }
        #[cfg(CURLDEBUG)]
        _ => {
            output = unsafe {
                curl_dbg_malloc(
                    outlen,
                    821 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                ) as *mut libc::c_char
            };
        }
    }

    if output.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    /* sprintf the label and colon */
    unsafe {
        curl_msnprintf(
            output,
            outlen,
            b"%s:\0" as *const u8 as *const libc::c_char,
            label,
        );
        /* memcpy the value (it might not be null-terminated) */
        memcpy(
            &mut *output.offset(labellen.wrapping_add(1 as u64) as isize) as *mut libc::c_char
                as *mut libc::c_void,
            value as *const libc::c_void,
            valuelen,
        );
        /* null-terminate the output */
        *output.offset(labellen.wrapping_add(1 as u64).wrapping_add(valuelen) as isize) =
            0 as libc::c_char;
        nl = Curl_slist_append_nodup(*((*ci).certinfo).offset(certnum as isize), output);
        if nl.is_null() {
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(output as *mut libc::c_void);

            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                output as *mut libc::c_void,
                836 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
            curl_slist_free_all(*((*ci).certinfo).offset(certnum as isize));
            result = CURLE_OUT_OF_MEMORY;
        }

        *((*ci).certinfo).offset(certnum as isize) = nl;
    }
    return result;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_push_certinfo(
    mut data: *mut Curl_easy,
    mut certnum: i32,
    mut label: *const libc::c_char,
    mut value: *const libc::c_char,
) -> CURLcode {
    /*
     * This is a convenience function for push_certinfo_len that takes a zero
     * terminated value.
     */
    unsafe {
        let mut valuelen: size_t = strlen(value);
        return Curl_ssl_push_certinfo_len(data, certnum, label, value, valuelen);
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut u8,
    mut length: size_t,
) -> CURLcode {
    unsafe {
        return ((*Curl_ssl).random).expect("non-null function pointer")(data, entropy, length);
    }
}
#[cfg(USE_SSL)]
extern "C" fn pubkey_pem_to_der(
    mut pem: *const libc::c_char,
    mut der: *mut *mut u8,
    mut der_len: *mut size_t,
) -> CURLcode {
    /*
     * Public key pem to der conversion
     */

    let mut stripped_pem: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut begin_pos: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end_pos: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pem_count: size_t = 0;
    let mut stripped_pem_count: size_t = 0 as size_t;
    let mut pem_len: size_t = 0;
    let mut result: CURLcode = CURLE_OK;
    if pem.is_null() {
        /* if no pem, exit. */
        return CURLE_BAD_CONTENT_ENCODING;
    }
    begin_pos = unsafe {
        strstr(
            pem,
            b"-----BEGIN PUBLIC KEY-----\0" as *const u8 as *const libc::c_char,
        )
    };
    if begin_pos.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_count = unsafe { begin_pos.offset_from(pem) as size_t };
    /* Invalid if not at beginning AND not directly following \n */
    if 0 as u64 != pem_count
        && '\n' as i32 != unsafe { *pem.offset(pem_count.wrapping_sub(1 as u64) as isize) as i32 }
    {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    /* 26 is length of "-----BEGIN PUBLIC KEY-----" */
    pem_count = (pem_count as u64).wrapping_add(26 as u64) as size_t as size_t;
    /* Invalid if not directly following \n */
    end_pos = unsafe {
        strstr(
            pem.offset(pem_count as isize),
            b"\n-----END PUBLIC KEY-----\0" as *const u8 as *const libc::c_char,
        )
    };
    if end_pos.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_len = unsafe { end_pos.offset_from(pem) as size_t };
    match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            stripped_pem = unsafe {
                Curl_cmalloc.expect("non-null function pointer")(
                    pem_len.wrapping_sub(pem_count).wrapping_add(1 as u64),
                ) as *mut libc::c_char
            };
        }
        #[cfg(CURLDEBUG)]
        _ => {
            stripped_pem = unsafe {
                curl_dbg_malloc(
                    pem_len.wrapping_sub(pem_count).wrapping_add(1 as u64),
                    900 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                ) as *mut libc::c_char
            };
        }
    }

    if stripped_pem.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    /*
     * Here we loop through the pem array one character at a time between the
     * correct indices, and place each character that is not '\n' or '\r'
     * into the stripped_pem array, which should represent the raw base64 string
     */
    while pem_count < pem_len {
        if '\n' as i32 != unsafe { *pem.offset(pem_count as isize) as i32 }
            && '\r' as i32 != unsafe { *pem.offset(pem_count as isize) as i32 }
        {
            let fresh56 = stripped_pem_count;
            stripped_pem_count = stripped_pem_count.wrapping_add(1);
            unsafe {
                *stripped_pem.offset(fresh56 as isize) = *pem.offset(pem_count as isize);
            }
        }
        pem_count = pem_count.wrapping_add(1);
    }
    /* Place the null terminator in the correct place */
    unsafe {
        *stripped_pem.offset(stripped_pem_count as isize) = '\0' as libc::c_char;
        result = Curl_base64_decode(stripped_pem, der, der_len);
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(stripped_pem as *mut libc::c_void);

        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            stripped_pem as *mut libc::c_void,
            919 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
    }
    stripped_pem = 0 as *mut libc::c_char;
    return result;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_pin_peer_pubkey(
    mut data: *mut Curl_easy,
    mut pinnedpubkey: *const libc::c_char,
    mut pubkey: *const u8,
    mut pubkeylen: size_t,
) -> CURLcode {
    /*
     * Generic pinned public key check.
     */

    let mut fp: *mut FILE = 0 as *mut FILE;
    let mut buf: *mut u8 = 0 as *mut u8;
    let mut pem_ptr: *mut u8 = 0 as *mut u8;
    let mut result: CURLcode = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    /* if a path wasn't specified, don't pin */
    if pinnedpubkey.is_null() {
        return CURLE_OK;
    }
    if pubkey.is_null() || pubkeylen == 0 {
        return result;
    }
    /* only do this if pinnedpubkey starts with "sha256//", length 8 */
    if unsafe {
        strncmp(
            pinnedpubkey,
            b"sha256//\0" as *const u8 as *const libc::c_char,
            8 as u64,
        ) == 0 as i32
    } {
        let mut encode: CURLcode = CURLE_OK;
        let mut encodedlen: size_t = 0;
        let mut pinkeylen: size_t = 0;
        let mut encoded: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut pinkeycopy: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut begin_pos: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut end_pos: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut sha256sumdigest: *mut u8 = 0 as *mut u8;
        if unsafe { ((*Curl_ssl).sha256sum).is_none() } {
            return result; /* without sha256 support, this cannot match */
        }
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                sha256sumdigest = unsafe {
                    Curl_cmalloc.expect("non-null function pointer")(32 as size_t) as *mut u8
                };
            }
            #[cfg(CURLDEBUG)]
            _ => {
                sha256sumdigest = unsafe {
                    curl_dbg_malloc(
                        32 as size_t,
                        955 as i32,
                        b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                    ) as *mut u8
                };
            }
        }
        /* compute sha256sum of public key */
        if sha256sumdigest.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        encode = unsafe {
            ((*Curl_ssl).sha256sum).expect("non-null function pointer")(
                pubkey,
                pubkeylen,
                sha256sumdigest,
                32 as size_t,
            )
        };
        if encode as u32 != CURLE_OK as u32 {
            return encode;
        }
        encode = unsafe {
            Curl_base64_encode(
                data,
                sha256sumdigest as *mut libc::c_char,
                32 as size_t,
                &mut encoded,
                &mut encodedlen,
            )
        };
        #[cfg(not(CURLDEBUG))]
        unsafe {
            Curl_cfree.expect("non-null function pointer")(sha256sumdigest as *mut libc::c_void);
        }
        #[cfg(CURLDEBUG)]
        unsafe {
            curl_dbg_free(
                sha256sumdigest as *mut libc::c_void,
                967 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
        }
        sha256sumdigest = 0 as *mut u8;
        if encode as u64 != 0 {
            return encode;
        }
        unsafe {
            Curl_infof(
                data,
                b" public key hash: sha256//%s\0" as *const u8 as *const libc::c_char,
                encoded,
            );
        }
        /* it starts with sha256//, copy so we can modify it */
        pinkeylen = unsafe { (strlen(pinnedpubkey)).wrapping_add(1 as u64) };
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                pinkeycopy = unsafe {
                    Curl_cmalloc.expect("non-null function pointer")(pinkeylen) as *mut libc::c_char
                };
            }
            #[cfg(CURLDEBUG)]
            _ => {
                pinkeycopy = unsafe {
                    curl_dbg_malloc(
                        pinkeylen,
                        976 as i32,
                        b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                    ) as *mut libc::c_char
                };
            }
        }

        if pinkeycopy.is_null() {
            #[cfg(not(CURLDEBUG))]
            unsafe {
                Curl_cfree.expect("non-null function pointer")(encoded as *mut libc::c_void);
            }

            #[cfg(CURLDEBUG)]
            unsafe {
                curl_dbg_free(
                    encoded as *mut libc::c_void,
                    978 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            }
            encoded = 0 as *mut libc::c_char;
            return CURLE_OUT_OF_MEMORY;
        }
        unsafe {
            memcpy(
                pinkeycopy as *mut libc::c_void,
                pinnedpubkey as *const libc::c_void,
                pinkeylen,
            );
        }
        /* point begin_pos to the copy, and start extracting keys */
        begin_pos = pinkeycopy;
        loop {
            end_pos = unsafe {
                strstr(
                    begin_pos,
                    b";sha256//\0" as *const u8 as *const libc::c_char,
                )
            };
            /*
             * if there is an end_pos, null terminate,
             * otherwise it'll go to the end of the original string
             */
            if !end_pos.is_null() {
                unsafe {
                    *end_pos.offset(0 as i32 as isize) = '\0' as i32 as libc::c_char;
                }
            }
            /* compare base64 sha256 digests, 8 is the length of "sha256//" */
            if encodedlen == unsafe { strlen(begin_pos.offset(8 as i32 as isize)) }
                && unsafe {
                    memcmp(
                        encoded as *const libc::c_void,
                        begin_pos.offset(8 as isize) as *const libc::c_void,
                        encodedlen,
                    ) == 0
                }
            {
                result = CURLE_OK;
                break;
            } else {
                /*
                 * change back the null-terminator we changed earlier,
                 * and look for next begin
                 */
                if !end_pos.is_null() {
                    unsafe { *end_pos.offset(0 as isize) = ';' as libc::c_char };
                    begin_pos = unsafe {
                        strstr(end_pos, b"sha256//\0" as *const u8 as *const libc::c_char)
                    };
                }
                if !(!end_pos.is_null() && !begin_pos.is_null()) {
                    break;
                }
            }
        }
        #[cfg(not(CURLDEBUG))]
        unsafe {
            Curl_cfree.expect("non-null function pointer")(encoded as *mut libc::c_void);
        }

        #[cfg(CURLDEBUG)]
        unsafe {
            curl_dbg_free(
                encoded as *mut libc::c_void,
                1009 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
        }
        encoded = 0 as *mut libc::c_char;
        #[cfg(not(CURLDEBUG))]
        unsafe {
            Curl_cfree.expect("non-null function pointer")(pinkeycopy as *mut libc::c_void);
        }

        #[cfg(CURLDEBUG)]
        unsafe {
            curl_dbg_free(
                pinkeycopy as *mut libc::c_void,
                1010 as i32,
                b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
            );
        }
        pinkeycopy = 0 as *mut libc::c_char;
        return result;
    }
    match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            fp = unsafe { fopen(pinnedpubkey, b"rb\0" as *const u8 as *const libc::c_char) };
        }
        #[cfg(CURLDEBUG)]
        _ => {
            fp = unsafe {
                curl_dbg_fopen(
                    pinnedpubkey,
                    b"rb\0" as *const u8 as *const libc::c_char,
                    1014 as i32,
                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }

    if fp.is_null() {
        return result;
    }
    let mut filesize: i64 = 0;
    let mut size: size_t = 0;
    let mut pem_len: size_t = 0;
    let mut pem_read: CURLcode = CURLE_OK;
    /* Determine the file's size */
    if unsafe { !(fseek(fp, 0 as i64, 2 as i32) != 0) } {
        filesize = unsafe { ftell(fp) };
        if unsafe { !(fseek(fp, 0 as i64, 0 as i32) != 0) } {
            if !(filesize < 0 as i64 || filesize > 1048576 as i64) {
                /*
                 * if the size of our certificate is bigger than the file
                 * size then it can't match
                 */
                size = unsafe { curlx_sotouz(filesize) };
                if !(pubkeylen > size) {
                    match () {
                        #[cfg(not(CURLDEBUG))]
                        _ => {
                            buf = unsafe {
                                Curl_cmalloc.expect("non-null function pointer")(
                                    size.wrapping_add(1 as u64),
                                ) as *mut u8
                            };
                        }
                        #[cfg(CURLDEBUG)]
                        _ => {
                            buf = unsafe {
                                curl_dbg_malloc(
                                    size.wrapping_add(1 as u64),
                                    1044 as i32,
                                    b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                                ) as *mut u8
                            };
                        }
                    }
                    /*
                     * Allocate buffer for the pinned key
                     * With 1 additional byte for null terminator in case of PEM key
                     */
                    if !buf.is_null() {
                        /* Returns number of elements read, which should be 1 */
                        if unsafe {
                            !(fread(buf as *mut libc::c_void, size, 1 as u64, fp) as i32
                                != 1 as i32)
                        } {
                            /* If the sizes are the same, it can't be base64 encoded, must be der */
                            if pubkeylen == size {
                                if unsafe {
                                    memcmp(
                                        pubkey as *const libc::c_void,
                                        buf as *const libc::c_void,
                                        pubkeylen,
                                    ) == 0
                                } {
                                    result = CURLE_OK;
                                }
                            } else {
                                /*
                                 * Otherwise we will assume it's PEM and try to decode it
                                 * after placing null terminator
                                 */
                                unsafe {
                                    *buf.offset(size as isize) = '\0' as u8;
                                }
                                pem_read = pubkey_pem_to_der(
                                    buf as *const libc::c_char,
                                    &mut pem_ptr,
                                    &mut pem_len,
                                ); /* if it wasn't read successfully, exit */
                                if !(pem_read as u64 != 0) {
                                    if pubkeylen == pem_len
                                        && unsafe {
                                            memcmp(
                                                pubkey as *const libc::c_void,
                                                pem_ptr as *const libc::c_void,
                                                pubkeylen,
                                            ) == 0
                                        }
                                    {
                                        /*
                                         * if the size of our certificate doesn't match the size of
                                         * the decoded file, they can't be the same, otherwise compare
                                         */
                                        result = CURLE_OK;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(CURLDEBUG))]
    unsafe {
        Curl_cfree.expect("non-null function pointer")(buf as *mut libc::c_void);
    }

    #[cfg(CURLDEBUG)]
    unsafe {
        curl_dbg_free(
            buf as *mut libc::c_void,
            1077 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
    }
    buf = 0 as *mut u8;
    #[cfg(not(CURLDEBUG))]
    unsafe {
        Curl_cfree.expect("non-null function pointer")(pem_ptr as *mut libc::c_void);
    }

    #[cfg(CURLDEBUG)]
    unsafe {
        curl_dbg_free(
            pem_ptr as *mut libc::c_void,
            1078 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
    }
    pem_ptr = 0 as *mut u8;
    #[cfg(not(CURLDEBUG))]
    unsafe {
        fclose(fp);
    }
    #[cfg(CURLDEBUG)]
    unsafe {
        curl_dbg_fclose(
            fp,
            1079 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
    }
    return result;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_cert_status_request() -> bool {
    unsafe {
        /*
         * Check whether the SSL backend supports the status_request extension.
         */
        return ((*Curl_ssl).cert_status_request).expect("non-null function pointer")();
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_false_start() -> bool {
    unsafe {
        /*
         * Check whether the SSL backend supports false start.
         */
        return ((*Curl_ssl).false_start).expect("non-null function pointer")();
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_ssl_tls13_ciphersuites() -> bool {
    unsafe {
        /*
         * Check whether the SSL backend supports setting TLS 1.3 cipher suites
         */
        return (*Curl_ssl).supports & ((1 as i32) << 5 as i32) as u32 != 0;
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_init() -> i32 {
    /*
     * Default implementations for unsupported functions.
     */
    return 1 as i32;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_cleanup() {}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> i32 {
    return 0 as i32;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_check_cxn(mut conn: *mut connectdata) -> i32 {
    return -(1 as i32);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut u8,
    mut length: size_t,
) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_close_all(mut data: *mut Curl_easy) {}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_session_free(mut ptr: *mut libc::c_void) {}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_data_pending(mut conn: *const connectdata, mut connindex: i32) -> bool {
    return 0 as i32 != 0;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_cert_status_request() -> bool {
    return 0 as i32 != 0;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_set_engine(
    mut data: *mut Curl_easy,
    mut engine: *const libc::c_char,
) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_set_engine_default(mut data: *mut Curl_easy) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_engines_list(mut data: *mut Curl_easy) -> *mut curl_slist {
    return 0 as *mut libc::c_void as *mut curl_slist;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn Curl_none_false_start() -> bool {
    return 0 as i32 != 0;
}
#[cfg(USE_SSL)]
extern "C" fn multissl_init() -> i32 {
    unsafe {
        if multissl_setup(0 as *const Curl_ssl) != 0 {
            return 1 as i32;
        }
        return ((*Curl_ssl).init).expect("non-null function pointer")();
    }
}
#[cfg(USE_SSL)]
extern "C" fn multissl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    unsafe {
        if multissl_setup(0 as *const Curl_ssl) != 0 {
            return CURLE_FAILED_INIT;
        }
        return ((*Curl_ssl).connect_blocking).expect("non-null function pointer")(
            data, conn, sockindex,
        );
    }
}
#[cfg(USE_SSL)]
extern "C" fn multissl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    unsafe {
        if multissl_setup(0 as *const Curl_ssl) != 0 {
            return CURLE_FAILED_INIT;
        }
        return ((*Curl_ssl).connect_nonblocking).expect("non-null function pointer")(
            data, conn, sockindex, done,
        );
    }
}
#[cfg(USE_SSL)]
extern "C" fn multissl_getsock(mut conn: *mut connectdata, mut socks: *mut curl_socket_t) -> i32 {
    unsafe {
        if multissl_setup(0 as *const Curl_ssl) != 0 {
            return 0 as i32;
        }
        return ((*Curl_ssl).getsock).expect("non-null function pointer")(conn, socks);
    }
}
#[cfg(USE_SSL)]
extern "C" fn multissl_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    unsafe {
        if multissl_setup(0 as *const Curl_ssl) != 0 {
            return 0 as *mut libc::c_void;
        }
        return ((*Curl_ssl).get_internals).expect("non-null function pointer")(connssl, info);
    }
}
#[cfg(USE_SSL)]
extern "C" fn multissl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
    unsafe {
        if multissl_setup(0 as *const Curl_ssl) != 0 {
            return;
        }
        ((*Curl_ssl).close_one).expect("non-null function pointer")(data, conn, sockindex);
    }
}
#[cfg(USE_SSL)]
static mut Curl_ssl_multi: Curl_ssl = {
    {
        /* info */
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_NONE,
                    name: b"multi\0" as *const u8 as *const libc::c_char,
                };
                init
            },
            supports: 0 as libc::c_uint, /* supports nothing */
            sizeof_ssl_backend_data: -(1 as i32) as size_t, /* something insanely large to be on the safe side */
            init: Some(multissl_init as unsafe extern "C" fn() -> i32), /* init */
            cleanup: Some(Curl_none_cleanup as unsafe extern "C" fn() -> ()), /* cleanup */
            version: Some(
                multissl_version as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t,
            ), /* version */
            check_cxn: Some(Curl_none_check_cxn as unsafe extern "C" fn(*mut connectdata) -> i32), /* check_cxn */
            shut_down: Some(
                Curl_none_shutdown
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> i32,
            ), /* shutdown */
            data_pending: Some(
                Curl_none_data_pending as unsafe extern "C" fn(*const connectdata, i32) -> bool,
            ), /* data_pending */
            random: Some(
                Curl_none_random
                    as unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode,
            ), /* random */
            cert_status_request: Some(
                Curl_none_cert_status_request as unsafe extern "C" fn() -> bool,
            ), /* cert_status_request */
            connect_blocking: Some(
                multissl_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> CURLcode,
            ), /* connect */
            connect_nonblocking: Some(
                multissl_connect_nonblocking
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        i32,
                        *mut bool,
                    ) -> CURLcode,
            ), /* connect_nonblocking */
            getsock: Some(
                multissl_getsock
                    as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32,
            ), /* getsock */
            get_internals: Some(
                multissl_get_internals
                    as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
            ), /* get_internals */
            close_one: Some(
                multissl_close as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
            ), /* close_one */
            close_all: Some(Curl_none_close_all as unsafe extern "C" fn(*mut Curl_easy) -> ()), /* close_all */
            session_free: Some(
                Curl_none_session_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ), /* session_free */
            set_engine: Some(
                Curl_none_set_engine
                    as unsafe extern "C" fn(*mut Curl_easy, *const libc::c_char) -> CURLcode,
            ), /* set_engine */
            set_engine_default: Some(
                Curl_none_set_engine_default as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
            ), /* set_engine_default */
            engines_list: Some(
                Curl_none_engines_list as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
            ), /* engines_list */
            false_start: Some(Curl_none_false_start as unsafe extern "C" fn() -> bool), /* false_start */
            sha256sum: None,               /* sha256sum */
            associate_connection: None,    /* associate_connection */
            disassociate_connection: None, /* disassociate_connection */
        };
        init
    }
};
#[cfg(all(USE_SSL, CURL_WITH_MULTI_SSL))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_multi as *const Curl_ssl };
#[cfg(all(USE_SSL, not(CURL_WITH_MULTI_SSL), USE_WOLFSSL))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_wolfssl as *const Curl_ssl };
#[cfg(all(USE_SSL, not(CURL_WITH_MULTI_SSL), not(USE_WOLFSSL), USE_SECTRANSP))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_sectransp as *const Curl_ssl };
#[cfg(all(
    USE_SSL,
    not(CURL_WITH_MULTI_SSL),
    not(USE_WOLFSSL),
    not(USE_SECTRANSP),
    USE_GNUTLS
))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_gnutls as *const Curl_ssl };
#[cfg(all(
    USE_SSL,
    not(CURL_WITH_MULTI_SSL),
    not(USE_WOLFSSL),
    not(USE_SECTRANSP),
    not(USE_GNUTLS),
    USE_GSKIT
))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_gskit as *const Curl_ssl };
#[cfg(all(
    USE_SSL,
    not(CURL_WITH_MULTI_SSL),
    not(USE_WOLFSSL),
    not(USE_SECTRANSP),
    not(USE_GNUTLS),
    not(USE_GSKIT),
    USE_MBEDTLS
))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_mbedtls as *const Curl_ssl };
#[cfg(all(
    USE_SSL,
    not(CURL_WITH_MULTI_SSL),
    not(USE_WOLFSSL),
    not(USE_SECTRANSP),
    not(USE_GNUTLS),
    not(USE_GSKIT),
    not(USE_MBEDTLS),
    USE_NSS
))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_nss as *const Curl_ssl };
#[cfg(all(
    USE_SSL,
    not(CURL_WITH_MULTI_SSL),
    not(USE_WOLFSSL),
    not(USE_SECTRANSP),
    not(USE_GNUTLS),
    not(USE_GSKIT),
    not(USE_MBEDTLS),
    not(USE_NSS),
    USE_RUSTLS
))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_rustls as *const Curl_ssl };
#[cfg(all(
    USE_SSL,
    not(CURL_WITH_MULTI_SSL),
    not(USE_WOLFSSL),
    not(USE_SECTRANSP),
    not(USE_GNUTLS),
    not(USE_GSKIT),
    not(USE_MBEDTLS),
    not(USE_NSS),
    not(USE_RUSTLS),
    USE_OPENSSL
))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_openssl as *const Curl_ssl };
#[cfg(all(
    USE_SSL,
    not(CURL_WITH_MULTI_SSL),
    not(USE_WOLFSSL),
    not(USE_SECTRANSP),
    not(USE_GNUTLS),
    not(USE_GSKIT),
    not(USE_MBEDTLS),
    not(USE_NSS),
    not(USE_RUSTLS),
    not(USE_OPENSSL),
    USE_SCHANNEL
))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_schannel as *const Curl_ssl };
#[cfg(all(
    USE_SSL,
    not(CURL_WITH_MULTI_SSL),
    not(USE_WOLFSSL),
    not(USE_SECTRANSP),
    not(USE_GNUTLS),
    not(USE_GSKIT),
    not(USE_MBEDTLS),
    not(USE_NSS),
    not(USE_RUSTLS),
    not(USE_OPENSSL),
    not(USE_SCHANNEL),
    USE_MESALINK
))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_mesalink as *const Curl_ssl };
#[cfg(all(
    USE_SSL,
    not(CURL_WITH_MULTI_SSL),
    not(USE_WOLFSSL),
    not(USE_SECTRANSP),
    not(USE_GNUTLS),
    not(USE_GSKIT),
    not(USE_MBEDTLS),
    not(USE_NSS),
    not(USE_RUSTLS),
    not(USE_OPENSSL),
    not(USE_SCHANNEL),
    not(USE_MESALINK),
    USE_BEARSSL
))]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_bearssl as *const Curl_ssl };
// TODO 这里的2得改掉，最好是省略数组长度，这里也得先注释了再测试
#[cfg(USE_SSL)]
static mut available_backends: [*const Curl_ssl; 2] = unsafe {
    [
        // #[cfg(USE_WOLFSSL)]
        // &Curl_ssl_wolfssl as *const Curl_ssl,
        // #[cfg(USE_SECTRANSP)]
        // &Curl_ssl_sectransp as *const Curl_ssl,
        // #[cfg(USE_GNUTLS)]
        // &Curl_ssl_gnutls as *const Curl_ssl,
        // #[cfg(USE_GSKIT)]
        // &Curl_ssl_gskit as *const Curl_ssl,
        // #[cfg(USE_MBEDTLS)]
        // &Curl_ssl_mbedtls as *const Curl_ssl,
        // #[cfg(USE_NSS)]
        // &Curl_ssl_nss as *const Curl_ssl,
        #[cfg(USE_OPENSSL)]
        &Curl_ssl_openssl as *const Curl_ssl,
        // #[cfg(USE_SCHANNEL)]
        // &Curl_ssl_schannel as *const Curl_ssl,
        // #[cfg(USE_MESALINK)]
        // &Curl_ssl_mesalink as *const Curl_ssl,
        // #[cfg(USE_BEARSSL)]
        // &Curl_ssl_bearssl as *const Curl_ssl,
        // #[cfg(USE_RUSTLS)]
        // &Curl_ssl_rustls as *const Curl_ssl,
        0 as *const Curl_ssl,
    ]
};
#[cfg(USE_SSL)]
extern "C" fn multissl_version(mut buffer: *mut libc::c_char, mut size: size_t) -> size_t {
    static mut selected: *const Curl_ssl = 0 as *const Curl_ssl;
    static mut backends: [libc::c_char; 200] = [0; 200];
    static mut backends_len: size_t = 0;
    let mut current: *const Curl_ssl = 0 as *const Curl_ssl;
    current = if unsafe { Curl_ssl == &Curl_ssl_multi as *const Curl_ssl } {
        unsafe { available_backends[0 as usize] }
    } else {
        unsafe { Curl_ssl }
    };
    if current != unsafe { selected } {
        let mut p: *mut libc::c_char = unsafe { backends.as_mut_ptr() };
        let mut end: *mut libc::c_char = unsafe {
            backends
                .as_mut_ptr()
                .offset(::std::mem::size_of::<[libc::c_char; 200]>() as isize)
        };
        let mut i: i32 = 0;
        unsafe {
            selected = current;
            backends[0 as usize] = '\0' as libc::c_char;
        }
        i = 0 as i32;
        while unsafe { !(available_backends[i as usize]).is_null() } {
            let mut vb: [libc::c_char; 200] = [0; 200];
            let mut paren: bool = unsafe { selected != available_backends[i as usize] };
            if unsafe {
                ((*available_backends[i as usize]).version).expect("non-null function pointer")(
                    vb.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 200]>() as u64,
                ) != 0
            } {
                p = unsafe {
                    p.offset(curl_msnprintf(
                        p,
                        end.offset_from(p) as size_t,
                        b"%s%s%s%s\0" as *const u8 as *const libc::c_char,
                        if p != backends.as_mut_ptr() {
                            b" \0" as *const u8 as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                        if paren as i32 != 0 {
                            b"(\0" as *const u8 as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                        vb.as_mut_ptr(),
                        if paren as i32 != 0 {
                            b")\0" as *const u8 as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                    ) as isize)
                };
            }
            i += 1;
        }
        unsafe {
            backends_len = p.offset_from(backends.as_mut_ptr()) as size_t;
        }
    }
    if size == 0 {
        return 0 as size_t;
    }
    if size <= unsafe { backends_len } {
        unsafe {
            strncpy(buffer, backends.as_mut_ptr(), size.wrapping_sub(1 as u64));
            *buffer.offset(size.wrapping_sub(1 as u64) as isize) = '\0' as libc::c_char;
        }
        return size.wrapping_sub(1 as u64);
    }
    unsafe {
        strcpy(buffer, backends.as_mut_ptr());

        return backends_len;
    }
}

#[cfg(USE_SSL)]
extern "C" fn multissl_setup(mut backend: *const Curl_ssl) -> i32 {
    let mut env: *const libc::c_char = 0 as *const libc::c_char;
    let mut env_tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    if unsafe { Curl_ssl != &Curl_ssl_multi as *const Curl_ssl } {
        return 1 as i32;
    }
    if !backend.is_null() {
        unsafe {
            Curl_ssl = backend;
        }
        return 0 as i32;
    }
    if unsafe { (available_backends[0 as usize]).is_null() } {
        return 1 as i32;
    }
    env_tmp = unsafe { curl_getenv(b"CURL_SSL_BACKEND\0" as *const u8 as *const libc::c_char) };
    env = env_tmp;
    #[cfg(CURL_DEFAULT_SSL_BACKEND)]
    if env.is_null() {
        env = unsafe { CURL_DEFAULT_SSL_BACKEND };
    }
    if !env.is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        unsafe {
            while !(available_backends[i as usize]).is_null() {
                if Curl_strcasecompare(env, (*available_backends[i as usize]).info.name) != 0 {
                    Curl_ssl = available_backends[i as usize];
                    #[cfg(not(CURLDEBUG))]
                    Curl_cfree.expect("non-null function pointer")(env_tmp as *mut libc::c_void);
                    #[cfg(CURLDEBUG)]
                    curl_dbg_free(
                        env_tmp as *mut libc::c_void,
                        1406 as i32,
                        b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
                    );
                    return 0 as i32;
                }
                i += 1;
            }
        }
    }
    /* Fall back to first available backend */
    unsafe {
        Curl_ssl = available_backends[0 as usize];
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(env_tmp as *mut libc::c_void);

        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            env_tmp as *mut libc::c_void,
            1414 as i32,
            b"vtls/vtls.c\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as i32;
}

#[cfg(USE_SSL)]
#[no_mangle]
pub extern "C" fn curl_global_sslset(
    mut id: curl_sslbackend,
    mut name: *const libc::c_char,
    mut avail: *mut *mut *const curl_ssl_backend,
) -> CURLsslset {
    let mut i: i32 = 0;
    if !avail.is_null() {
        // TODO 这里最后的2也得根据开了多少个ssl进行更改
        unsafe {
            *avail =
                &mut available_backends as *mut [*const Curl_ssl; 2] as *mut *const curl_ssl_backend
        };
    }
    if unsafe { Curl_ssl != &Curl_ssl_multi as *const Curl_ssl } {
        return (if id as u32 == unsafe { (*Curl_ssl).info.id as libc::c_uint }
            || !name.is_null() && unsafe { Curl_strcasecompare(name, (*Curl_ssl).info.name) != 0 }
        {
            CURLSSLSET_OK as i32
        } else {
            if cfg!(CURL_WITH_MULTI_SSL) {
                CURLSSLSET_TOO_LATE as i32
            } else {
                CURLSSLSET_UNKNOWN_BACKEND as i32
            }
        }) as CURLsslset;
    }
    i = 0 as i32;
    while unsafe { !(available_backends[i as usize]).is_null() } {
        if unsafe { (*available_backends[i as usize]).info.id as libc::c_uint }
            == id as libc::c_uint
            || !name.is_null()
                && unsafe { Curl_strcasecompare((*available_backends[i as usize]).info.name, name) }
                    != 0
        {
            unsafe {
                multissl_setup(available_backends[i as usize]);
            }
            return CURLSSLSET_OK;
        }
        i += 1;
    }
    return CURLSSLSET_UNKNOWN_BACKEND;
}

#[cfg(not(USE_SSL))]
#[no_mangle]
pub extern "C" fn Curl_ssl_init() -> i32 {
    return 1 as i32;
}
#[cfg(not(USE_SSL))]
#[no_mangle]
pub extern "C" fn Curl_ssl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    unsafe {
        return CURLE_NOT_BUILT_IN;
    }
}
#[cfg(not(USE_SSL))]
#[no_mangle]
pub extern "C" fn Curl_ssl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
}
#[cfg(not(USE_SSL))]
#[no_mangle]
pub extern "C" fn Curl_ssl_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    unsafe {
        return CURLE_NOT_BUILT_IN;
    }
}
#[cfg(not(USE_SSL))]
#[no_mangle]
pub extern "C" fn Curl_ssl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut isproxy: bool,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    unsafe {
        return CURLE_NOT_BUILT_IN;
    }
}
#[cfg(not(USE_SSL))]
#[no_mangle]
pub extern "C" fn curl_global_sslset(
    mut id: curl_sslbackend,
    mut name: *const libc::c_char,
    mut avail: *mut *mut *const curl_ssl_backend,
) -> CURLsslset {
    unsafe {
        return CURLSSLSET_NO_BACKENDS;
    }
}
