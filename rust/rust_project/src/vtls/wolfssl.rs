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
 * Description: support wolfssl backend
 ******************************************************************************/
use libc;
// use c2rust_bitfields::BitfieldStruct;
use crate::src::vtls::keylog::*;
use crate::src::vtls::vtls::*;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
// ------------------------------
extern "C" fn wolfssl_log_tls12_secret(mut ssl: *mut WOLFSSL) {
    {
        let mut ms: *mut u8 = 0 as *mut u8;
        let mut sr: *mut u8 = 0 as *mut u8;
        let mut cr: *mut u8 = 0 as *mut u8;
        let mut msLen: u32 = 0;
        let mut srLen: u32 = 0;
        let mut crLen: u32 = 0;
        let mut i: u32 = 0;
        let mut x: u32 = 0 as u32;
        // 158 - done
        unsafe {
            if cfg!(LIBWOLFSSL_VERSION_HEX_GT_0X0300D000) {
                /* >= 3.13.0 */
                /* wolfSSL_GetVersion is available since 3.13, we use it instead of
                 * SSL_version since the latter relies on OPENSSL_ALL (--enable-opensslall or
                 * --enable-all). Failing to perform this check could result in an unusable
                 * key log line when TLS 1.3 is actually negotiated. */
                match wolfSSL_GetVersion(ssl) {
                    0 | 1 | 2 | 3 => {}
                    _ => return, /* TLS 1.3 does not use this mechanism, the "master secret" returned below
                                  * is not directly usable. */
                }
            }
            if wolfSSL_get_keys(
                ssl, &mut ms, &mut msLen, &mut sr, &mut srLen, &mut cr, &mut crLen,
            ) != WOLFSSL_SUCCESS as i32
            {
                return;
            }
        }
        i = 0 as u32;
        /* Check for a missing master secret and skip logging. That can happen if
         * curl rejects the server certificate and aborts the handshake.
         */
        while i < msLen {
            unsafe {
                x |= *ms.offset(i as isize) as u32;
            }
            i = i.wrapping_add(1);
        }
        if x == 0 as u32 {
            return;
        }
        Curl_tls_keylog_write(
            b"CLIENT_RANDOM\0" as *const u8 as *const libc::c_char,
            cr as *const u8,
            ms,
            msLen as size_t,
        );
    }
}
extern "C" fn do_file_type(mut type_0: *const libc::c_char) -> i32 {
    unsafe {
        if type_0.is_null() || *type_0.offset(0 as isize) == 0 {
            return WOLFSSL_FILETYPE_PEM as i32;
        }
        if Curl_strcasecompare(type_0, b"PEM\0" as *const u8 as *const libc::c_char) != 0 {
            return WOLFSSL_FILETYPE_PEM as i32;
        }
        if Curl_strcasecompare(type_0, b"DER\0" as *const u8 as *const libc::c_char) != 0 {
            return WOLFSSL_FILETYPE_ASN1 as i32;
        }
        return -(1 as i32);
    }
}
/*
 * This function loads all the client/CA certificates and CRLs. Setup the TLS
 * layer and do all necessary magic.
 */
extern "C" fn wolfssl_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut ciphers: *mut libc::c_char = 0 as *mut libc::c_char;

    let mut connssl: *mut ssl_connect_data = unsafe {
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
    };
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    let mut req_method: *mut SSL_METHOD = 0 as *mut SSL_METHOD;
    let mut sockfd: curl_socket_t = unsafe { (*conn).sock[sockindex as usize] };
    if unsafe { (*connssl).state as u32 } == ssl_connection_complete as u32 {
        return CURLE_OK;
    }

    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_version_max = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*conn).proxy_ssl_config.version_max }
    } else {
        unsafe { (*conn).ssl_config.version_max }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_version_max = unsafe { (*conn).ssl_config.version_max };
    if SSL_CONN_CONFIG_version_max != CURL_SSLVERSION_MAX_NONE as i64 {
        unsafe {
            Curl_failf(
                data,
                b"wolfSSL does not support to set maximum SSL/TLS version\0" as *const u8
                    as *const libc::c_char,
            );
        }
        return CURLE_SSL_CONNECT_ERROR;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_version = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*conn).proxy_ssl_config.version }
    } else {
        unsafe { (*conn).ssl_config.version }
    };
    /* check to see if we've been told to use an explicit SSL/TLS version */
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_version = unsafe { (*conn).ssl_config.version };
    match SSL_CONN_CONFIG_version {
        0 | 1 => {
            // done-237
            /* minimum protocol version is set later after the CTX object is created */
            req_method = unsafe { wolfSSLv23_client_method() };
        }
        4 => {
            #[cfg(any(not(WOLFSSL_ALLOW_TLSV10), NO_OLD_TLS))]
            unsafe {
                Curl_failf(
                    data,
                    b"wolfSSL does not support TLS 1.0\0" as *const u8 as *const libc::c_char,
                );
            }
            #[cfg(any(not(WOLFSSL_ALLOW_TLSV10), NO_OLD_TLS))]
            return CURLE_NOT_BUILT_IN;
        }
        5 =>
        {
            #[cfg(NO_OLD_TLS)]
            if true {
                req_method = unsafe { wolfTLSv1_1_client_method() };
            }
        }
        6 => {
            req_method = unsafe { wolfTLSv1_2_client_method() };
        }
        7 => {
            #[cfg(not(WOLFSSL_TLS13))]
            unsafe {
                Curl_failf(
                    data,
                    b"wolfSSL: TLS 1.3 is not yet supported\0" as *const u8 as *const libc::c_char,
                );
            }
            #[cfg(not(WOLFSSL_TLS13))]
            return CURLE_SSL_CONNECT_ERROR;
        }
        _ => {
            unsafe {
                Curl_failf(
                    data,
                    b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8
                        as *const libc::c_char,
                );
            }
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    if req_method.is_null() {
        unsafe {
            Curl_failf(
                data,
                b"SSL: couldn't create a method!\0" as *const u8 as *const libc::c_char,
            );
        }
        return CURLE_OUT_OF_MEMORY;
    }
    unsafe {
        if !((*backend).ctx).is_null() {
            wolfSSL_CTX_free((*backend).ctx);
        }
        (*backend).ctx = wolfSSL_CTX_new(req_method);
        if ((*backend).ctx).is_null() {
            Curl_failf(
                data,
                b"SSL: couldn't create a context!\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OUT_OF_MEMORY;
        }
    }
    match SSL_CONN_CONFIG_version {
        /* Versions 3.3.0 to 3.4.6 we know the minimum protocol version is
         * whatever minimum version of TLS was built in and at least TLS 1.0. For
         * later library versions that could change (eg TLS 1.0 built in but
         * defaults to TLS 1.1) so we have this short circuit evaluation to find
         * the minimum supported TLS version.
         */
        0 | 1 => {
            #[cfg(WOLFSSL_TLS13)]
            let WOLFSSL_TLS13_flag = unsafe {
                wolfSSL_CTX_SetMinVersion((*backend).ctx, WOLFSSL_TLSV1_3 as i32) != 1 as i32
            };
            #[cfg(not(WOLFSSL_TLS13))]
            let WOLFSSL_TLS13_flag = true;

            if unsafe {
                wolfSSL_CTX_SetMinVersion((*backend).ctx, WOLFSSL_TLSV1 as i32) != 1 as i32
                    && wolfSSL_CTX_SetMinVersion((*backend).ctx, WOLFSSL_TLSV1_1 as i32) != 1 as i32
                    && wolfSSL_CTX_SetMinVersion((*backend).ctx, WOLFSSL_TLSV1_2 as i32) != 1 as i32
                    && WOLFSSL_TLS13_flag
            } {
                unsafe {
                    Curl_failf(
                        data,
                        b"SSL: couldn't set the minimum protocol version\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                return CURLE_SSL_CONNECT_ERROR;
            }
        }
        _ => {}
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_cipher_list = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*conn).proxy_ssl_config.cipher_list }
    } else {
        unsafe { (*conn).ssl_config.cipher_list }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_cipher_list = unsafe { (*conn).ssl_config.cipher_list };
    ciphers = SSL_CONN_CONFIG_cipher_list;
    if !ciphers.is_null() {
        if unsafe { wolfSSL_CTX_set_cipher_list((*backend).ctx, ciphers) == 0 } {
            unsafe {
                Curl_failf(
                    data,
                    b"failed setting cipher list: %s\0" as *const u8 as *const libc::c_char,
                    ciphers,
                );
            }
            return CURLE_SSL_CIPHER;
        }
        unsafe {
            Curl_infof(
                data,
                b"Cipher selection: %s\0" as *const u8 as *const libc::c_char,
                ciphers,
            );
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_CAfile = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*conn).proxy_ssl_config.CAfile }
    } else {
        unsafe { (*conn).ssl_config.CAfile }
    };

    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_CAfile = unsafe { (*conn).ssl_config.CAfile };
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_CApath = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*conn).proxy_ssl_config.CApath }
    } else {
        unsafe { (*conn).ssl_config.CApath }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_CApath = (*conn).ssl_config.CApath;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { ((*conn).proxy_ssl_config).verifypeer() as i32 }
    } else {
        unsafe { ((*conn).ssl_config).verifypeer() as i32 }
    };
    /* load trusted cacert */
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifypeer = ((*conn).ssl_config).verifypeer();
    #[cfg(not(NO_FILESYSTEM))]
    if !(SSL_CONN_CONFIG_CAfile).is_null() {
        if 1 as i32
            != unsafe {
                wolfSSL_CTX_load_verify_locations(
                    (*backend).ctx,
                    (SSL_CONN_CONFIG_CAfile),
                    (SSL_CONN_CONFIG_CApath),
                )
            }
        {
            if SSL_CONN_CONFIG_verifypeer != 0 {
                /* Fail if we insist on successfully verifying the server. */
                unsafe {
                    Curl_failf(
                        data,
                        b"error setting certificate verify locations: CAfile: %s CApath: %s\0"
                            as *const u8 as *const libc::c_char,
                        if !(SSL_CONN_CONFIG_CAfile).is_null() {
                            (SSL_CONN_CONFIG_CAfile) as *const libc::c_char
                        } else {
                            b"none\0" as *const u8 as *const libc::c_char
                        },
                        if !(SSL_CONN_CONFIG_CApath).is_null() {
                            (SSL_CONN_CONFIG_CApath) as *const libc::c_char
                        } else {
                            b"none\0" as *const u8 as *const libc::c_char
                        },
                    );
                }
                return CURLE_SSL_CACERT_BADFILE;
            } else {
                /* Just continue with a warning if no strict certificate
                verification is required. */
                unsafe {
                    Curl_infof(
                        data,
                        b"error setting certificate verify locations, continuing anyway:\0"
                            as *const u8 as *const libc::c_char,
                    );
                }
            }
        } else {
            /* Everything is fine. */
            unsafe {
                Curl_infof(
                    data,
                    b"successfully set certificate verify locations:\0" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        unsafe {
            Curl_infof(
                data,
                b" CAfile: %s\0" as *const u8 as *const libc::c_char,
                if !(SSL_CONN_CONFIG_CAfile).is_null() {
                    (SSL_CONN_CONFIG_CAfile) as *const libc::c_char
                } else {
                    b"none\0" as *const u8 as *const libc::c_char
                },
            );
            Curl_infof(
                data,
                b" CApath: %s\0" as *const u8 as *const libc::c_char,
                if !(SSL_CONN_CONFIG_CApath).is_null() {
                    (SSL_CONN_CONFIG_CApath) as *const libc::c_char
                } else {
                    b"none\0" as *const u8 as *const libc::c_char
                },
            );
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_clientcert = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*data).set.proxy_ssl.primary.clientcert }
    } else {
        unsafe { (*data).set.ssl.primary.clientcert }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_clientcert = unsafe { (*data).set.ssl.primary.clientcert };
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_key = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*data).set.proxy_ssl.key }
    } else {
        unsafe { (*data).set.ssl.key }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_key = (*data).set.ssl.key;
    /* Load the client certificate, and private key */
    #[cfg(not(NO_FILESYSTEM))]
    if !(SSL_SET_OPTION_primary_clientcert).is_null() && !(SSL_SET_OPTION_key).is_null() {
        #[cfg(not(CURL_DISABLE_PROXY))]
        let mut file_type: i32 = do_file_type(
            if CURLPROXY_HTTPS as u32 == unsafe { (*conn).http_proxy.proxytype as u32 }
                && ssl_connection_complete as u32
                    != unsafe {
                        (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                    }
            {
                unsafe { (*data).set.proxy_ssl.cert_type }
            } else {
                unsafe { (*data).set.ssl.cert_type }
            },
        );
        #[cfg(CURL_DISABLE_PROXY)]
        let mut file_type: i32 = do_file_type((*data).set.ssl.cert_type);
        if unsafe {
            wolfSSL_CTX_use_certificate_file(
                (*backend).ctx,
                SSL_SET_OPTION_primary_clientcert,
                file_type,
            ) != 1 as i32
        } {
            unsafe {
                Curl_failf(
                    data,
                    b"unable to use client certificate (no key or wrong pass phrase?)\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            return CURLE_SSL_CONNECT_ERROR;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        if true {
            file_type = do_file_type(
                if CURLPROXY_HTTPS as u32 == unsafe { (*conn).http_proxy.proxytype as u32 }
                    && ssl_connection_complete as u32
                        != unsafe {
                            (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state as u32
                        }
                {
                    unsafe { (*data).set.proxy_ssl.key_type }
                } else {
                    unsafe { (*data).set.ssl.key_type }
                },
            );
        }
        #[cfg(CURL_DISABLE_PROXY)]
        if true {
            file_type = unsafe { do_file_type((*data).set.ssl.key_type) };
        }
        if unsafe { wolfSSL_CTX_use_PrivateKey_file((*backend).ctx, SSL_SET_OPTION_key, file_type) }
            != 1 as i32
        {
            unsafe {
                Curl_failf(
                    data,
                    b"unable to set private key\0" as *const u8 as *const libc::c_char,
                );
            }
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    /* SSL always tries to verify the peer, this only says whether it should
     * fail to connect if the verification fails, or if it should continue
     * anyway. In the latter case the result of the verification is checked with
     * SSL_get_verify_result() below. */
    unsafe {
        wolfSSL_CTX_set_verify(
            (*backend).ctx,
            if SSL_CONN_CONFIG_verifypeer != 0 {
                WOLFSSL_VERIFY_PEER as i32
            } else {
                WOLFSSL_VERIFY_NONE as i32
            },
            None,
        );
    }
    /* give application a chance to interfere with SSL set up. */
    unsafe {
        if ((*data).set.ssl.fsslctx).is_some() {
            let mut result: CURLcode =
                (Some(((*data).set.ssl.fsslctx).expect("non-null function pointer")))
                    .expect("non-null function pointer")(
                    data,
                    (*backend).ctx as *mut libc::c_void,
                    (*data).set.ssl.fsslctxp,
                );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"error signaled by ssl ctx callback\0" as *const u8 as *const libc::c_char,
                );
                return result;
            }
        }
        if !((*backend).wolf_handle).is_null() {
            wolfSSL_free((*backend).wolf_handle);
        }
        /* Let's make an SSL structure */
        (*backend).wolf_handle = wolfSSL_new((*backend).ctx);
        if ((*backend).wolf_handle).is_null() {
            Curl_failf(
                data,
                b"SSL: couldn't create a context (handle)!\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OUT_OF_MEMORY;
        }
    }
    #[cfg(OPENSSL_EXTRA)]
    if Curl_tls_keylog_enabled() {
        /* Ensure the Client Random is preserved. */
        unsafe {
            wolfSSL_KeepArrays((*backend).wolf_handle);
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { ((*data).set.proxy_ssl.primary).sessionid() as i32 }
    } else {
        unsafe { ((*data).set.ssl.primary).sessionid() as i32 }
    };
    /* Check if there's a cached ID we can/should use here! */
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_sessionid = unsafe { ((*data).set.ssl.primary).sessionid() };
    if SSL_SET_OPTION_primary_sessionid != 0 {
        let mut ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
        Curl_ssl_sessionid_lock(data);
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_IS_PROXY_void = if CURLPROXY_HTTPS as u32
            == unsafe { (*conn).http_proxy.proxytype as u32 }
            && ssl_connection_complete as u32
                != unsafe {
                    (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
                } {
            1 as i32
        } else {
            0 as i32
        };
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_IS_PROXY_void = if 0 as i32 != 0 { 1 as i32 } else { 0 as i32 };
        if !Curl_ssl_getsessionid(
            data,
            conn,
            SSL_IS_PROXY_void != 0,
            &mut ssl_sessionid,
            0 as *mut size_t,
            sockindex,
        ) {
            if unsafe {
                wolfSSL_set_session(
                    (*backend).wolf_handle,
                    ssl_sessionid as *mut WOLFSSL_SESSION,
                )
            } == 0
            {
                unsafe {
                    Curl_ssl_delsessionid(data, ssl_sessionid);
                    Curl_infof(
                        data,
                        b"Can't use session ID, going on without\n\0" as *const u8
                            as *const libc::c_char,
                    );
                }
            } else {
                unsafe {
                    Curl_infof(
                        data,
                        b"SSL re-using session ID\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }
        Curl_ssl_sessionid_unlock(data);
    }
    /* pass the raw socket into the SSL layer */
    if unsafe { wolfSSL_set_fd((*backend).wolf_handle, sockfd) } == 0 {
        unsafe {
            Curl_failf(
                data,
                b"SSL: SSL_set_fd failed\0" as *const u8 as *const libc::c_char,
            );
        }
        return CURLE_SSL_CONNECT_ERROR;
    }
    unsafe {
        (*connssl).connecting_state = ssl_connect_2;
    }

    return CURLE_OK;
}
extern "C" fn wolfssl_connect_step2(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut ret: i32 = -(1 as i32);

    let mut connssl: *mut ssl_connect_data = unsafe {
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
    };
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    #[cfg(not(CURL_DISABLE_PROXY))]
    let hostname: *const libc::c_char = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype } as u32
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*conn).http_proxy.host.name }
    } else {
        unsafe { (*conn).host.name }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let hostname: *const libc::c_char = (*conn).host.name;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let dispname: *const libc::c_char = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*conn).http_proxy.host.dispname }
    } else {
        unsafe { (*conn).host.dispname }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let dispname: *const libc::c_char = (*conn).host.dispname;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let pinnedpubkey: *const libc::c_char = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype } as u32
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY_PROXY as usize] }
    } else {
        unsafe { (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as usize] }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let pinnedpubkey: *const libc::c_char =
        unsafe { (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as usize] };
    unsafe {
        wolfSSL_ERR_clear_error();
        (*conn).recv[sockindex as usize] = Some(wolfssl_recv as Curl_recv);
        (*conn).send[sockindex as usize] = Some(wolfssl_send as Curl_send);
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifyhost = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { ((*conn).proxy_ssl_config).verifyhost() as i32 }
    } else {
        unsafe { ((*conn).ssl_config).verifyhost() as i32 }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifyhost = ((*conn).ssl_config).verifyhost();
    if SSL_CONN_CONFIG_verifyhost != 0 {
        ret = unsafe { wolfSSL_check_domain_name((*backend).wolf_handle, hostname) };
        if ret == WOLFSSL_FAILURE as i32 {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    ret = unsafe { wolfSSL_connect((*backend).wolf_handle) };
    #[cfg(OPENSSL_EXTRA)]
    if Curl_tls_keylog_enabled() {
        /* If key logging is enabled, wait for the handshake to complete and then
         * proceed with logging secrets (for TLS 1.2 or older).
         *
         * During the handshake (ret==-1), wolfSSL_want_read() is true as it waits
         * for the server response. At that point the master secret is not yet
         * available, so we must not try to read it.
         * To log the secret on completion with a handshake failure, detect
         * completion via the observation that there is nothing to read or write.
         * Note that OpenSSL SSL_want_read() is always true here. If wolfSSL ever
         * changes, the worst case is that no key is logged on error.
         */
        if ret == WOLFSSL_SUCCESS as i32
            || unsafe {
                wolfSSL_want_read((*backend).wolf_handle) == 0
                    && wolfSSL_want_write((*backend).wolf_handle) == 0
            }
        {
            unsafe {
                wolfssl_log_tls12_secret((*backend).wolf_handle);
                /* Client Random and master secrets are no longer needed, erase these.
                 * Ignored while the handshake is still in progress. */
                wolfSSL_FreeArrays((*backend).wolf_handle);
            }
        }
    }
    if ret != 1 as i32 {
        let mut error_buffer: [libc::c_char; 80] = [0; 80];
        let mut detail: i32 = unsafe { wolfSSL_get_error((*backend).wolf_handle, ret) };
        if WOLFSSL_ERROR_WANT_READ as i32 == detail {
            unsafe { (*connssl).connecting_state = ssl_connect_2_reading };
            return CURLE_OK;
        } else {
            if WOLFSSL_ERROR_WANT_WRITE as i32 == detail {
                unsafe {
                    (*connssl).connecting_state = ssl_connect_2_writing;
                }
                return CURLE_OK;
            } else {
                /* There is no easy way to override only the CN matching.
                 * This will enable the override of both mismatching SubjectAltNames
                 * as also mismatching CN fields */
                if (DOMAIN_NAME_MISMATCH as i32 == detail) {
                    unsafe {
                        Curl_failf(
                            data,
                            b" subject alt name(s) or common name do not match \"%s\"\0"
                                as *const u8 as *const libc::c_char,
                            dispname,
                        );
                    }
                    return CURLE_PEER_FAILED_VERIFICATION;
                } else {
                    /* When the wolfssl_check_domain_name() is used and you desire to
                     * continue on a DOMAIN_NAME_MISMATCH, i.e. 'conn->ssl_config.verifyhost
                     * == 0', CyaSSL version 2.4.0 will fail with an INCOMPLETE_DATA
                     * error. The only way to do this is currently to switch the
                     * Wolfssl_check_domain_name() in and out based on the
                     * 'conn->ssl_config.verifyhost' value. */
                    #[cfg(LIBWOLFSSL_VERSION_HEX_GT_0X02007000)]
                    let LIBWOLFSSL_VERSION_HEX_GT_0X02007000_flag = true;
                    #[cfg(not(LIBWOLFSSL_VERSION_HEX_GT_0X02007000))]
                    let LIBWOLFSSL_VERSION_HEX_GT_0X02007000_flag = false;
                    #[cfg(not(CURL_DISABLE_PROXY))]
                    let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as i32 as u32
                        == unsafe { (*conn).http_proxy.proxytype as u32 }
                        && ssl_connection_complete as u32
                            != unsafe {
                                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                                    0 as i32
                                } else {
                                    1 as i32
                                }) as usize]
                                    .state as u32
                            } {
                        unsafe { ((*conn).proxy_ssl_config).verifypeer() as i32 }
                    } else {
                        unsafe { ((*conn).ssl_config).verifypeer() as i32 }
                    };
                    #[cfg(CURL_DISABLE_PROXY)]
                    let SSL_CONN_CONFIG_verifypeer = unsafe { ((*conn).ssl_config).verifypeer() };
                    if (ASN_NO_SIGNER_E as i32 == detail)
                        && LIBWOLFSSL_VERSION_HEX_GT_0X02007000_flag
                    {
                        if SSL_CONN_CONFIG_verifypeer != 0 {
                            unsafe {
                                Curl_failf(
                                    data,
                                    b" CA signer not available for verification\0" as *const u8
                                        as *const libc::c_char,
                                );
                            }
                            return CURLE_SSL_CACERT_BADFILE;
                        } else {
                            /* Just continue with a warning if no strict certificate
                            verification is required. */
                            unsafe {
                                Curl_infof(
                                    data,
                                    b"CA signer not available for verification, continuing anyway\0"
                                        as *const u8
                                        as *const libc::c_char,
                                );
                            }
                        }
                    } else {
                        unsafe {
                            Curl_failf(
                                data,
                                b"SSL_connect failed with error %d: %s\0" as *const u8
                                    as *const libc::c_char,
                                detail,
                                wolfSSL_ERR_error_string(detail as u64, error_buffer.as_mut_ptr()),
                            );
                        }
                        return CURLE_SSL_CONNECT_ERROR;
                    }
                }
            }
        }
    }
    if !pinnedpubkey.is_null() {
        if cfg!(KEEP_PEER_CERT) {
            let mut x509: *mut X509 = 0 as *mut X509;
            let mut x509_der: *const libc::c_char = 0 as *const libc::c_char;
            let mut x509_der_len: i32 = 0;
            let mut x509_parsed: Curl_X509certificate = Curl_X509certificate {
                certificate: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                version: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                serialNumber: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                signatureAlgorithm: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                signature: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                issuer: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                notBefore: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                notAfter: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                subject: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                subjectPublicKeyInfo: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                subjectPublicKeyAlgorithm: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                subjectPublicKey: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                issuerUniqueID: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                subjectUniqueID: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
                extensions: Curl_asn1Element {
                    header: 0 as *const libc::c_char,
                    beg: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,
                    class: 0,
                    tag: 0,
                    constructed: false,
                },
            };
            let mut pubkey: *mut Curl_asn1Element = 0 as *mut Curl_asn1Element;
            let mut result: CURLcode = CURLE_OK;
            x509 = unsafe { wolfSSL_get_peer_certificate((*backend).wolf_handle) };
            if x509.is_null() {
                unsafe {
                    Curl_failf(
                        data,
                        b"SSL: failed retrieving server certificate\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
            }
            x509_der =
                unsafe { wolfSSL_X509_get_der(x509, &mut x509_der_len) as *const libc::c_char };
            if x509_der.is_null() {
                unsafe {
                    Curl_failf(
                        data,
                        b"SSL: failed retrieving ASN.1 server certificate\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
            }
            unsafe {
                memset(
                    &mut x509_parsed as *mut Curl_X509certificate as *mut libc::c_void,
                    0 as i32,
                    ::std::mem::size_of::<Curl_X509certificate>() as u64,
                );
            }
            if unsafe {
                Curl_parseX509(
                    &mut x509_parsed,
                    x509_der,
                    x509_der.offset(x509_der_len as isize),
                ) != 0
            } {
                return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
            }
            pubkey = &mut x509_parsed.subjectPublicKeyInfo;
            if unsafe { ((*pubkey).header).is_null() || (*pubkey).end <= (*pubkey).header } {
                unsafe {
                    Curl_failf(
                        data,
                        b"SSL: failed retrieving public key from server certificate\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
            }
            result = unsafe {
                Curl_pin_peer_pubkey(
                    data,
                    pinnedpubkey,
                    (*pubkey).header as *const u8,
                    ((*pubkey).end).offset_from((*pubkey).header) as size_t,
                )
            };
            if result as u64 != 0 {
                unsafe {
                    Curl_failf(
                        data,
                        b"SSL: public key does not match pinned public key!\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                return result;
            }
        } else {
            unsafe {
                Curl_failf(
                    data,
                    b"Library lacks pinning support built-in\0" as *const u8 as *const libc::c_char,
                );
            }
            return CURLE_NOT_BUILT_IN;
        }
    }
    unsafe { (*connssl).connecting_state = ssl_connect_3 };

    unsafe {
        Curl_infof(
            data,
            b"SSL connection using %s / %s\0" as *const u8 as *const libc::c_char,
            wolfSSL_get_version((*backend).wolf_handle),
            wolfSSL_get_cipher_name((*backend).wolf_handle),
        );
        Curl_infof(data, b"SSL connected\0" as *const u8 as *const libc::c_char);
    }

    return CURLE_OK;
}
extern "C" fn wolfssl_connect_step3(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;

    let mut connssl: *mut ssl_connect_data = unsafe {
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
    };
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if ssl_connect_3 as libc::c_int as libc::c_uint
        == unsafe { (*connssl).connecting_state as libc::c_uint }
    {
    } else {
        unsafe {
            __assert_fail(
             b"ssl_connect_3 == connssl->connecting_state\0" as *const u8 as *const libc::c_char,
             b"vtls/wolfssl.c\0" as *const u8 as *const libc::c_char,
             730 as libc::c_int as libc::c_uint,
             (*::std::mem::transmute::<&[u8; 78], &[libc::c_char; 78]>(
                 b"CURLcode wolfssl_connect_step3(struct Curl_easy *, struct connectdata *, int)\0",
             ))
             .as_ptr(),
         );
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as u32
        == unsafe { (*conn).http_proxy.proxytype as u32 }
        && ssl_connection_complete as u32
            != unsafe {
                (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
            } {
        unsafe { ((*data).set.proxy_ssl.primary).sessionid() as i32 }
    } else {
        unsafe { ((*data).set.ssl.primary).sessionid() as i32 }
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_sessionid = unsafe { ((*data).set.ssl.primary).sessionid() };
    if SSL_SET_OPTION_primary_sessionid != 0 {
        let mut incache: bool = false;
        let mut old_ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
        let mut our_ssl_sessionid: *mut SSL_SESSION =
            unsafe { wolfSSL_get_session((*backend).wolf_handle) };
        #[cfg(not(CURL_DISABLE_PROXY))]
        let mut isproxy: bool = if CURLPROXY_HTTPS as u32
            == unsafe { (*conn).http_proxy.proxytype as u32 }
            && ssl_connection_complete as u32
                != unsafe {
                    (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
                } {
            1 as i32
        } else {
            0 as i32
        } != 0;
        #[cfg(CURL_DISABLE_PROXY)]
        let mut isproxy: bool = if 0 as i32 != 0 { 1 as i32 } else { 0 as i32 } != 0;
        if !our_ssl_sessionid.is_null() {
            Curl_ssl_sessionid_lock(data);
            incache = !Curl_ssl_getsessionid(
                data,
                conn,
                isproxy,
                &mut old_ssl_sessionid,
                0 as *mut size_t,
                sockindex,
            );
            if incache {
                if old_ssl_sessionid != our_ssl_sessionid as *mut libc::c_void {
                    unsafe {
                        Curl_infof(
                            data,
                            b"old SSL session ID is stale, removing\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    Curl_ssl_delsessionid(data, old_ssl_sessionid);
                    incache = 0 as i32 != 0;
                }
            }
            if !incache {
                result = Curl_ssl_addsessionid(
                    data,
                    conn,
                    isproxy,
                    our_ssl_sessionid as *mut libc::c_void,
                    0 as size_t,
                    sockindex,
                );
                if result as u64 != 0 {
                    Curl_ssl_sessionid_unlock(data);
                    unsafe {
                        Curl_failf(
                            data,
                            b"failed to store ssl session\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    return result;
                }
            }
            Curl_ssl_sessionid_unlock(data);
        }
    }
    unsafe {
        (*connssl).connecting_state = ssl_connect_done;
    }

    return result;
}
extern "C" fn wolfssl_send(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut connssl: *mut ssl_connect_data = unsafe {
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
    };
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    let mut error_buffer: [libc::c_char; 80] = [0; 80];
    let mut memlen: i32 = if len > 2147483647 as size_t {
        2147483647 as i32
    } else {
        len as i32
    };
    let mut rc: i32 = 0;
    unsafe {
        wolfSSL_ERR_clear_error();
        rc = wolfSSL_write((*backend).wolf_handle, mem, memlen);
    }
    if rc <= 0 as i32 {
        let mut err: i32 = unsafe { wolfSSL_get_error((*backend).wolf_handle, rc) };
        match err {
            2 | 3 => {
                /* there's data pending, re-invoke SSL_write() */
                unsafe {
                    *curlcode = CURLE_AGAIN;
                }
                return -(1 as i32) as ssize_t;
            }
            _ => {
                unsafe {
                    Curl_failf(
                        data,
                        b"SSL write: %s, errno %d\0" as *const u8 as *const libc::c_char,
                        wolfSSL_ERR_error_string(err as u64, error_buffer.as_mut_ptr()),
                        *__errno_location(),
                    );
                    *curlcode = CURLE_SEND_ERROR;
                }
                return -(1 as i32) as ssize_t;
            }
        }
    }
    return rc as ssize_t;
}
extern "C" fn wolfssl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
    let mut connssl: *mut ssl_connect_data = unsafe {
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
    };
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    if unsafe { !((*backend).wolf_handle).is_null() } {
        let mut buf: [libc::c_char; 32] = [0; 32];
        /* Maybe the server has already sent a close notify alert.
        Read it to avoid an RST on the TCP connection. */
        unsafe {
            wolfSSL_read(
                (*backend).wolf_handle,
                buf.as_mut_ptr() as *mut libc::c_void,
                ::std::mem::size_of::<[libc::c_char; 32]>() as i32,
            );
            wolfSSL_shutdown((*backend).wolf_handle);
            wolfSSL_free((*backend).wolf_handle);
            (*backend).wolf_handle = 0 as *mut WOLFSSL;
        }
    }
    unsafe {
        if !((*backend).ctx).is_null() {
            wolfSSL_CTX_free((*backend).ctx);
            (*backend).ctx = 0 as *mut SSL_CTX;
        }
    }
}
extern "C" fn wolfssl_recv(
    mut data: *mut Curl_easy,
    mut num: i32,
    mut buf: *mut libc::c_char,
    mut buffersize: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut connssl: *mut ssl_connect_data =
        unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(num as isize) as *mut ssl_connect_data };
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    let mut error_buffer: [libc::c_char; 80] = [0; 80];
    const int_max: size_t = 2147483647 as size_t;
    let mut buffsize: i32 = if buffersize > int_max {
        int_max as i32
    } else {
        buffersize as i32
    };
    let mut nread: i32 = 0;
    unsafe {
        wolfSSL_ERR_clear_error();
        nread = wolfSSL_read((*backend).wolf_handle, buf as *mut libc::c_void, buffsize);
    }
    if nread < 0 as i32 {
        let mut err: i32 = unsafe { wolfSSL_get_error((*backend).wolf_handle, nread) };
        match err {
            6 => {}
            2 | 3 => {
                /* there's data pending, re-invoke SSL_read() */
                unsafe {
                    *curlcode = CURLE_AGAIN;
                }
                return -(1 as i32) as ssize_t;
            }
            _ => {
                unsafe {
                    Curl_failf(
                        data,
                        b"SSL read: %s, errno %d\0" as *const u8 as *const libc::c_char,
                        wolfSSL_ERR_error_string(err as u64, error_buffer.as_mut_ptr()),
                        *__errno_location(),
                    );
                    *curlcode = CURLE_RECV_ERROR;
                }
                return -(1 as i32) as ssize_t;
            }
        }
    }
    return nread as ssize_t;
}
unsafe extern "C" fn wolfssl_session_free(mut ptr: *mut libc::c_void) { /* wolfSSL reuses sessions on own, no free */
}
extern "C" fn wolfssl_version(mut buffer: *mut libc::c_char, mut size: size_t) -> size_t {
    unsafe {
        return curl_msnprintf(
            buffer,
            size,
            b"wolfSSL/%s\0" as *const u8 as *const libc::c_char,
            wolfSSL_lib_version(),
        ) as size_t;
    }
}
extern "C" fn wolfssl_init() -> i32 {
    unsafe {
        #[cfg(OPENSSL_EXTRA)]
        Curl_tls_keylog_open();
        return (wolfSSL_Init() == WOLFSSL_SUCCESS as i32) as i32;
    }
}
extern "C" fn wolfssl_cleanup() {
    unsafe {
        wolfSSL_Cleanup();
        if cfg!(OPENSSL_EXTRA) {
            Curl_tls_keylog_close();
        }
    }
}
extern "C" fn wolfssl_data_pending(mut conn: *const connectdata, mut connindex: i32) -> bool {
    let mut connssl: *const ssl_connect_data =
        unsafe { &*((*conn).ssl).as_ptr().offset(connindex as isize) as *const ssl_connect_data };
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    if unsafe { !((*backend).wolf_handle).is_null() } {
        /* SSL is in use */
        return if 0 as i32 != unsafe { wolfSSL_pending((*backend).wolf_handle) } {
            1 as i32
        } else {
            0 as i32
        } != 0;
    } else {
        return 0 as i32 != 0;
    };
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
extern "C" fn wolfssl_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> i32 {
    let mut retval: i32 = 0 as i32;
    let mut connssl: *mut ssl_connect_data = unsafe {
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
    };
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    unsafe {
        if !((*backend).wolf_handle).is_null() {
            wolfSSL_ERR_clear_error();
            wolfSSL_free((*backend).wolf_handle);
            (*backend).wolf_handle = 0 as *mut WOLFSSL;
        }
    }
    return retval;
}
extern "C" fn wolfssl_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;

    let mut connssl: *mut ssl_connect_data = unsafe {
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
    };
    let mut sockfd: curl_socket_t = unsafe { (*conn).sock[sockindex as usize] };
    let mut what: i32 = 0;
    /* check if the connection has already been established */
    if ssl_connection_complete as u32 == unsafe { (*connssl).state as u32 } {
        unsafe {
            *done = 1 as i32 != 0;
        }
        return CURLE_OK;
    }
    if ssl_connect_1 as u32 == unsafe { (*connssl).connecting_state as u32 } {
        /* Find out how much more time we're allowed */
        let timeout_ms: timediff_t =
            unsafe { Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0) };
        if timeout_ms < 0 as i64 {
            /* no need to continue if time already is up */
            unsafe {
                Curl_failf(
                    data,
                    b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
                );
            }
            return CURLE_OPERATION_TIMEDOUT;
        }
        result = wolfssl_connect_step1(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    while ssl_connect_2 as u32 == unsafe { (*connssl).connecting_state as u32 }
        || ssl_connect_2_reading as u32 == unsafe { (*connssl).connecting_state as u32 }
        || ssl_connect_2_writing as u32 == unsafe { (*connssl).connecting_state as u32 }
    {
        /* check allowed time left */
        let timeout_ms_0: timediff_t =
            unsafe { Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0) };
        if timeout_ms_0 < 0 as i64 {
            /* no need to continue if time already is up */
            unsafe {
                Curl_failf(
                    data,
                    b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
                );
            }
            return CURLE_OPERATION_TIMEDOUT;
        }
        /* if ssl is expecting something, check if it's available. */
        if unsafe {
            (*connssl).connecting_state as u32 == ssl_connect_2_reading as u32
                || (*connssl).connecting_state as u32 == ssl_connect_2_writing as u32
        } {
            let mut writefd: curl_socket_t =
                if ssl_connect_2_writing as u32 == unsafe { (*connssl).connecting_state as u32 } {
                    sockfd
                } else {
                    -(1 as i32)
                };
            let mut readfd: curl_socket_t =
                if ssl_connect_2_reading as u32 == unsafe { (*connssl).connecting_state as u32 } {
                    sockfd
                } else {
                    -(1 as i32)
                };
            what = unsafe {
                Curl_socket_check(
                    readfd,
                    -(1 as i32),
                    writefd,
                    if nonblocking as i32 != 0 {
                        0 as i64
                    } else {
                        timeout_ms_0
                    },
                )
            };
            if what < 0 as i32 {
                /* fatal error */
                unsafe {
                    Curl_failf(
                        data,
                        b"select/poll on SSL socket, errno: %d\0" as *const u8
                            as *const libc::c_char,
                        *__errno_location(),
                    );
                }
                return CURLE_SSL_CONNECT_ERROR;
            } else {
                if 0 as i32 == what {
                    if nonblocking {
                        unsafe {
                            *done = 0 as i32 != 0;
                        }
                        return CURLE_OK;
                    } else {
                        /* timeout */
                        unsafe {
                            Curl_failf(
                                data,
                                b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        return CURLE_OPERATION_TIMEDOUT;
                    }
                }
            }
            /* socket is readable or writable */
        }
        /* Run transaction, and return to the caller if it failed or if
         * this connection is part of a multi handle and this loop would
         * execute again. This permits the owner of a multi handle to
         * abort a connection attempt before step2 has completed while
         * ensuring that a client using select() or epoll() will always
         * have a valid fdset to wait on.
         */
        result = wolfssl_connect_step2(data, conn, sockindex);
        if result as u32 != 0
            || nonblocking as i32 != 0
                && (ssl_connect_2 as u32 == unsafe { (*connssl).connecting_state as u32 }
                    || ssl_connect_2_reading as u32
                        == unsafe { (*connssl).connecting_state as u32 }
                    || ssl_connect_2_writing as u32
                        == unsafe { (*connssl).connecting_state as u32 })
        {
            return result;
        }
    } /* repeat step2 until all transactions are done. */
    if ssl_connect_3 as u32 == unsafe { (*connssl).connecting_state as u32 } {
        result = wolfssl_connect_step3(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if ssl_connect_done as u32 == unsafe { (*connssl).connecting_state as u32 } {
        unsafe {
            (*connssl).state = ssl_connection_complete;
            (*conn).recv[sockindex as usize] = Some(wolfssl_recv as Curl_recv);
            (*conn).send[sockindex as usize] = Some(wolfssl_send as Curl_send);
            *done = 1 as i32 != 0;
        }
    } else {
        unsafe {
            *done = 0 as i32 != 0;
        }
    }
    /* Reset our connect state machine */
    unsafe {
        (*connssl).connecting_state = ssl_connect_1;
    }

    return CURLE_OK;
}
extern "C" fn wolfssl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    return wolfssl_connect_common(data, conn, sockindex, 1 as i32 != 0, done);
}
extern "C" fn wolfssl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut done: bool = 0 as i32 != 0;
    result = wolfssl_connect_common(data, conn, sockindex, 0 as i32 != 0, &mut done);
    if result as u64 != 0 {
        return result;
    }
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if done {
    } else {
        unsafe {
            __assert_fail(
                b"done\0" as *const u8 as *const libc::c_char,
                b"vtls/wolfssl.c\0" as *const u8 as *const libc::c_char,
                1068 as libc::c_int as libc::c_uint,
                (*::std::mem::transmute::<&[u8; 72], &[libc::c_char; 72]>(
                    b"CURLcode wolfssl_connect(struct Curl_easy *, struct connectdata *, int)\0",
                ))
                .as_ptr(),
            );
        }
    }
    return CURLE_OK;
}
extern "C" fn wolfssl_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut u8,
    mut length: size_t,
) -> CURLcode {
    let mut rng: WC_RNG = WC_RNG {
        seed: OS_Seed { fd: 0 },
        heap: 0 as *mut libc::c_void,
        drbg: 0 as *mut DRBG,
        status: 0,
    };
    unsafe {
        if wc_InitRng(&mut rng) != 0 {
            return CURLE_FAILED_INIT;
        }
        const UINT_MAX: u32 = 2147483647 as u32;
        if length > (UINT_MAX).wrapping_mul(2 as u32).wrapping_add(1 as u32) as u64 {
            return CURLE_FAILED_INIT;
        }
        if wc_RNG_GenerateBlock(&mut rng, entropy, length as u32) != 0 {
            return CURLE_FAILED_INIT;
        }
        if wc_FreeRng(&mut rng) != 0 {
            return CURLE_FAILED_INIT;
        }
    }
    return CURLE_OK;
}
extern "C" fn wolfssl_sha256sum(
    mut tmp: *const u8,
    mut tmplen: size_t,
    mut sha256sum: *mut u8,
    mut unused: size_t,
) -> CURLcode {
    let mut SHA256pw: wc_Sha256 = wc_Sha256 {
        digest: [0; 8],
        buffer: [0; 16],
        buffLen: 0,
        loLen: 0,
        hiLen: 0,
        heap: 0 as *mut libc::c_void,
    };
    unsafe {
        wc_InitSha256(&mut SHA256pw);
        wc_Sha256Update(&mut SHA256pw, tmp, tmplen as word32);
        wc_Sha256Final(&mut SHA256pw, sha256sum);
        return CURLE_OK;
    }
}
extern "C" fn wolfssl_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    unsafe {
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        return (*backend).wolf_handle as *mut libc::c_void;
    }
}
#[no_mangle]
pub static mut Curl_ssl_wolfssl: Curl_ssl = Curl_ssl {
    info: {
        curl_ssl_backend {
            id: CURLSSLBACKEND_WOLFSSL,
            name: b"WolfSSL\0" as *const u8 as *const libc::c_char,
        }
    },
    supports: ((1 as i32) << 2 as i32 | (1 as i32) << 3 as i32) as u32,
    sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>() as u64,
    init: Some(wolfssl_init as unsafe extern "C" fn() -> i32),
    cleanup: Some(wolfssl_cleanup as unsafe extern "C" fn() -> ()),
    version: Some(wolfssl_version as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t),
    check_cxn: Some(Curl_none_check_cxn as unsafe extern "C" fn(*mut connectdata) -> i32),
    shut_down: Some(
        wolfssl_shutdown as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> i32,
    ),
    data_pending: Some(
        wolfssl_data_pending as unsafe extern "C" fn(*const connectdata, i32) -> bool,
    ),
    random: Some(
        wolfssl_random as unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode,
    ),
    cert_status_request: Some(Curl_none_cert_status_request as unsafe extern "C" fn() -> bool),
    connect_blocking: Some(
        wolfssl_connect as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> CURLcode,
    ),
    connect_nonblocking: Some(
        wolfssl_connect_nonblocking
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32, *mut bool) -> CURLcode,
    ),
    getsock: Some(
        Curl_ssl_getsock as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32,
    ),
    get_internals: Some(
        wolfssl_get_internals
            as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
    ),
    close_one: Some(
        wolfssl_close as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
    ),
    close_all: Some(Curl_none_close_all as unsafe extern "C" fn(*mut Curl_easy) -> ()),
    session_free: Some(wolfssl_session_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
    set_engine: Some(
        Curl_none_set_engine
            as unsafe extern "C" fn(*mut Curl_easy, *const libc::c_char) -> CURLcode,
    ),
    set_engine_default: Some(
        Curl_none_set_engine_default as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
    ),
    engines_list: Some(
        Curl_none_engines_list as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
    ),
    false_start: Some(Curl_none_false_start as unsafe extern "C" fn() -> bool),
    sha256sum: Some(
        wolfssl_sha256sum as unsafe extern "C" fn(*const u8, size_t, *mut u8, size_t) -> CURLcode,
    ),
    associate_connection: None,
    disassociate_connection: None,
};
