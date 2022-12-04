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
 * Description: support mesalink
 ******************************************************************************/
use crate::src::vtls::vtls::*;
use libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

// 内部没有宏
extern "C" fn do_file_type(mut type_0: *const i8) -> i32 {
    unsafe {
        if type_0.is_null() || *type_0.offset(0 as isize) == 0 {
            return MESALINK_FILETYPE_PEM as i32;
        }
        if Curl_strcasecompare(type_0, b"PEM\0" as *const u8 as *const i8) != 0 {
            return MESALINK_FILETYPE_PEM as i32;
        }
        if Curl_strcasecompare(type_0, b"DER\0" as *const u8 as *const i8) != 0 {
            return MESALINK_FILETYPE_ASN1 as i32;
        }
        return -(1 as i32);
    }
}

/*
 * This function loads all the client/CA certificates and CRLs. Setup the TLS
 * layer and do all necessary magic.
 */
// todo - 有两个选项待翻译：MESALINK_HAVE_CIPHER 和 MESALINK_HAVE_SESSION
extern "C" fn mesalink_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    unsafe {
        let mut ciphers: *mut i8 = 0 as *mut i8;
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut addr4: in_addr = in_addr { s_addr: 0 };
        #[cfg(ENABLE_IPV6)] // done - 98
        let mut addr6: in6_addr = in6_addr {
            __in6_u: C2RustUnnamed_8 {
                __u6_addr8: [0; 16],
            },
        };
        #[cfg(not(CURL_DISABLE_PROXY))]
        let hostname: *const i8 = if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).http_proxy.host.name
        } else {
            (*conn).host.name
        };
        // vtls.h
        #[cfg(CURL_DISABLE_PROXY)]
        let hostname: *const i8 = (*conn).host.name;
        let mut hostname_len: size_t = strlen(hostname);
        let mut req_method: *mut MESALINK_METHOD = 0 as *mut MESALINK_METHOD;
        let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
        if (*connssl).state as u32 == ssl_connection_complete as u32 {
            return CURLE_OK;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let CURL_DISABLE_PROXY_1 = (if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).proxy_ssl_config.version_max
        } else {
            (*conn).ssl_config.version_max
        });
        // vtls.h
        #[cfg(CURL_DISABLE_PROXY)]
        let CURL_DISABLE_PROXY_1 = (*conn).ssl_config.version_max;
        if CURL_DISABLE_PROXY_1 != CURL_SSLVERSION_MAX_NONE as i64 {
            Curl_failf(
                data,
                b"MesaLink does not support to set maximum SSL/TLS version\0" as *const u8
                    as *const i8,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let CURL_DISABLE_PROXY_2 = if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).proxy_ssl_config.version
        } else {
            (*conn).ssl_config.version
        };
        // vtls.h
        #[cfg(CURL_DISABLE_PROXY)]
        let CURL_DISABLE_PROXY_2 = (*conn).ssl_config.version;
        match CURL_DISABLE_PROXY_2 {
            3 | 1 | 4 | 5 => {
                Curl_failf(
                    data,
                    b"MesaLink does not support SSL 3.0, TLS 1.0, or TLS 1.1\0" as *const u8
                        as *const i8,
                );
                return CURLE_NOT_BUILT_IN;
            }
            0 | 6 => {
                req_method = mesalink_TLSv1_2_client_method();
            }
            7 => {
                req_method = mesalink_TLSv1_3_client_method();
            }
            2 => {
                Curl_failf(
                    data,
                    b"MesaLink does not support SSLv2\0" as *const u8 as *const i8,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            _ => {
                Curl_failf(
                    data,
                    b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8
                        as *const i8,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
        }
        if req_method.is_null() {
            Curl_failf(
                data,
                b"SSL: couldn't create a method!\0" as *const u8 as *const i8,
            );
            return CURLE_OUT_OF_MEMORY;
        }
        if !((*(*connssl).backend).mesalink_ctx).is_null() {
            mesalink_SSL_CTX_free((*(*connssl).backend).mesalink_ctx);
        }
        (*(*connssl).backend).mesalink_ctx = mesalink_SSL_CTX_new(req_method);
        if ((*(*connssl).backend).mesalink_ctx).is_null() {
            Curl_failf(
                data,
                b"SSL: couldn't create a context!\0" as *const u8 as *const i8,
            );
            return CURLE_OUT_OF_MEMORY;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let CURL_DISABLE_PROXY_verifypeer = if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            ((*conn).proxy_ssl_config).verifypeer() as i32
        } else {
            ((*conn).ssl_config).verifypeer() as i32
        };
        // vtls.h
        #[cfg(CURL_DISABLE_PROXY)]
        let CURL_DISABLE_PROXY_verifypeer = ((*conn).ssl_config).verifypeer() as i32;
        mesalink_SSL_CTX_set_verify(
            (*(*connssl).backend).mesalink_ctx,
            if CURL_DISABLE_PROXY_verifypeer != 0 {
                MESALINK_SSL_VERIFY_PEER as i32
            } else {
                MESALINK_SSL_VERIFY_NONE as i32
            },
            None,
        );
        #[cfg(not(CURL_DISABLE_PROXY))]
        let CURL_DISABLE_PROXY_CAfile_1 = !(if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).proxy_ssl_config.CAfile
        } else {
            (*conn).ssl_config.CAfile
        })
        .is_null();
        #[cfg(CURL_DISABLE_PROXY)]
        let CURL_DISABLE_PROXY_CAfile_1 = !((*conn).ssl_config.CAfile).is_null();

        #[cfg(not(CURL_DISABLE_PROXY))]
        let CURL_DISABLE_PROXY_CApath_1 = !(if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).proxy_ssl_config.CApath
        } else {
            (*conn).ssl_config.CApath
        })
        .is_null();
        #[cfg(CURL_DISABLE_PROXY)]
        let CURL_DISABLE_PROXY_CApath_1 = !((*conn).ssl_config.CApath).is_null();

        #[cfg(not(CURL_DISABLE_PROXY))]
        let CURL_DISABLE_PROXY_CAfile_2 = if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).proxy_ssl_config.CAfile
        } else {
            (*conn).ssl_config.CAfile
        };
        #[cfg(CURL_DISABLE_PROXY)]
        let CURL_DISABLE_PROXY_CAfile_2 = (*conn).ssl_config.CAfile;

        #[cfg(not(CURL_DISABLE_PROXY))]
        let CURL_DISABLE_PROXY_CApath_2 = if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).proxy_ssl_config.CApath
        } else {
            (*conn).ssl_config.CApath
        };
        #[cfg(CURL_DISABLE_PROXY)]
        let CURL_DISABLE_PROXY_CApath_2 = (*conn).ssl_config.CApath;

        if CURL_DISABLE_PROXY_CAfile_1 || CURL_DISABLE_PROXY_CApath_1 {
            if mesalink_SSL_CTX_load_verify_locations(
                (*(*connssl).backend).mesalink_ctx,
                CURL_DISABLE_PROXY_CAfile_2,
                CURL_DISABLE_PROXY_CApath_2,
            ) == 0
            {
                if CURL_DISABLE_PROXY_verifypeer != 0 {
                    Curl_failf(
                        data,
                        b"error setting certificate verify locations:  CAfile: %s CApath: %s\0"
                            as *const u8 as *const i8,
                        if CURL_DISABLE_PROXY_CAfile_1 {
                            CURL_DISABLE_PROXY_CAfile_2 as *const i8
                        } else {
                            b"none\0" as *const u8 as *const i8
                        },
                        if CURL_DISABLE_PROXY_CApath_1 {
                            CURL_DISABLE_PROXY_CApath_2 as *const i8
                        } else {
                            b"none\0" as *const u8 as *const i8
                        },
                    );
                    return CURLE_SSL_CACERT_BADFILE;
                }
                Curl_infof(
                    data,
                    b"error setting certificate verify locations, continuing anyway:\0" as *const u8
                        as *const i8,
                );
            } else {
                Curl_infof(
                    data,
                    b"successfully set certificate verify locations:\0" as *const u8 as *const i8,
                );
            }
            Curl_infof(
                data,
                b" CAfile: %s\0" as *const u8 as *const i8,
                if CURL_DISABLE_PROXY_CAfile_1 {
                    CURL_DISABLE_PROXY_CAfile_2 as *const i8
                } else {
                    b"none\0" as *const u8 as *const i8
                },
            );
            Curl_infof(
                data,
                b" CApath: %s\0" as *const u8 as *const i8,
                if CURL_DISABLE_PROXY_CApath_1 {
                    CURL_DISABLE_PROXY_CApath_2 as *const i8
                } else {
                    b"none\0" as *const u8 as *const i8
                },
            );
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        if !(if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*data).set.proxy_ssl.primary.clientcert
        } else {
            (*data).set.ssl.primary.clientcert
        })
        .is_null()
            && !(if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*data).set.proxy_ssl.key
            } else {
                (*data).set.ssl.key
            })
            .is_null()
        {
            let mut file_type: i32 = do_file_type(
                if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*data).set.proxy_ssl.cert_type
                } else {
                    (*data).set.ssl.cert_type
                },
            );
            if mesalink_SSL_CTX_use_certificate_chain_file(
                (*(*connssl).backend).mesalink_ctx,
                (if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*data).set.proxy_ssl.primary.clientcert
                } else {
                    (*data).set.ssl.primary.clientcert
                }),
                file_type,
            ) != 1 as i32
            {
                Curl_failf(
                    data,
                    b"unable to use client certificate (no key or wrong pass phrase?)\0"
                        as *const u8 as *const i8,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            file_type = do_file_type(
                if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*data).set.proxy_ssl.key_type
                } else {
                    (*data).set.ssl.key_type
                },
            );
            if mesalink_SSL_CTX_use_PrivateKey_file(
                (*(*connssl).backend).mesalink_ctx,
                (if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*data).set.proxy_ssl.key
                } else {
                    (*data).set.ssl.key
                }),
                file_type,
            ) != 1 as i32
            {
                Curl_failf(
                    data,
                    b"unable to set private key\0" as *const u8 as *const i8,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            Curl_infof(
                data,
                b"client cert: %s\0" as *const u8 as *const i8,
                if !if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*conn).proxy_ssl_config.clientcert
                } else {
                    (*conn).ssl_config.clientcert
                }
                .is_null()
                {
                    (if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                        && ssl_connection_complete as u32
                            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state as u32
                    {
                        (*conn).proxy_ssl_config.clientcert
                    } else {
                        (*conn).ssl_config.clientcert
                    }) as *const i8
                } else {
                    b"none\0" as *const u8 as *const i8
                },
            );
        }
        #[cfg(CURL_DISABLE_PROXY)]
        if !((*data).set.ssl.primary.clientcert).is_null() && !((*data).set.ssl.key).is_null() {
            let mut file_type: i32 = do_file_type((*data).set.ssl.cert_type);
            if mesalink_SSL_CTX_use_certificate_chain_file(
                (*(*connssl).backend).mesalink_ctx,
                (*data).set.ssl.primary.clientcert,
                file_type,
            ) != 1 as i32
            {
                Curl_failf(
                    data,
                    b"unable to use client certificate (no key or wrong pass phrase?)\0"
                        as *const u8 as *const i8,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            file_type = do_file_type((*data).set.ssl.key_type);
            if mesalink_SSL_CTX_use_PrivateKey_file(
                (*(*connssl).backend).mesalink_ctx,
                (*data).set.ssl.key,
                file_type,
            ) != 1 as i32
            {
                Curl_failf(
                    data,
                    b"unable to set private key\0" as *const u8 as *const i8,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            Curl_infof(
                data,
                b"client cert: %s\0" as *const u8 as *const i8,
                if !((*conn).ssl_config.clientcert).is_null() {
                    (*conn).ssl_config.clientcert as *const i8
                } else {
                    b"none\0" as *const u8 as *const i8
                },
            );
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let CURL_DISABLE_PROXY_cipher_list = if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).proxy_ssl_config.cipher_list
        } else {
            (*conn).ssl_config.cipher_list
        };
        #[cfg(CURL_DISABLE_PROXY)]
        let CURL_DISABLE_PROXY_cipher_list = (*conn).ssl_config.cipher_list;

        ciphers = CURL_DISABLE_PROXY_cipher_list;
        if !ciphers.is_null() {
            // TODO - 206
            if cfg!(MESALINK_HAVE_CIPHER) {
                // 选项：MESALINK_HAVE_CIPHER
            }
            Curl_infof(
                data,
                b"Cipher selection: %s\0" as *const u8 as *const i8,
                ciphers,
            );
        }
        if !((*(*connssl).backend).mesalink_handle).is_null() {
            mesalink_SSL_free((*(*connssl).backend).mesalink_handle);
        }
        (*(*connssl).backend).mesalink_handle =
            mesalink_SSL_new((*(*connssl).backend).mesalink_ctx);
        if ((*(*connssl).backend).mesalink_handle).is_null() {
            Curl_failf(
                data,
                b"SSL: couldn't create a context (handle)!\0" as *const u8 as *const i8,
            );
            return CURLE_OUT_OF_MEMORY;
        }
        // done - 225
        #[cfg(ENABLE_IPV6)]
        let ENABLE_IPV6_flag = 0 as i32
            == inet_pton(
                10 as i32,
                hostname,
                &mut addr6 as *mut in6_addr as *mut libc::c_void,
            );
        #[cfg(not(ENABLE_IPV6))] // 如果没有ENABLE_IPV6这个选项，那就不要这个条件，那么一定是true
        let ENABLE_IPV6_flag = true;
        if hostname_len < (32767 as i32 * 2 as i32 + 1 as i32) as u64
            && 0 as i32
                == inet_pton(
                    2 as i32,
                    hostname,
                    &mut addr4 as *mut in_addr as *mut libc::c_void,
                )
            && ENABLE_IPV6_flag
        {
            /* hostname is not a valid IP address */
            if mesalink_SSL_set_tlsext_host_name((*(*connssl).backend).mesalink_handle, hostname)
                != MESALINK_SUCCESS as i32
            {
                Curl_failf(
                    data,
                    b"WARNING: failed to configure server name indication (SNI) TLS extension\n\0"
                        as *const u8 as *const i8,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
        } else {
            /* Check if the hostname is 127.0.0.1 or [::1];
             * otherwise reject because MesaLink always wants a valid DNS Name
             * specified in RFC 5280 Section 7.2 */
            // done - CURLDEBUG不加 238
            Curl_failf(
                data,
                b"ERROR: MesaLink does not accept an IP address as a hostname\n\0" as *const u8
                    as *const i8,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        // todo - 258 选项：MESALINK_HAVE_SESSION
        // #[cfg(MESALINK_HAVE_SESSION)]
        if mesalink_SSL_set_fd((*(*connssl).backend).mesalink_handle, sockfd)
            != MESALINK_SUCCESS as i32
        {
            Curl_failf(data, b"SSL: SSL_set_fd failed\0" as *const u8 as *const i8);
            return CURLE_SSL_CONNECT_ERROR;
        }
        (*connssl).connecting_state = ssl_connect_2;
        return CURLE_OK;
    }
}

// 内部没有宏
extern "C" fn mesalink_connect_step2(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    unsafe {
        let mut ret: i32 = -(1 as i32);
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        (*conn).recv[sockindex as usize] = Some(mesalink_recv as Curl_recv);
        (*conn).send[sockindex as usize] = Some(mesalink_send as Curl_send);
        ret = mesalink_SSL_connect((*(*connssl).backend).mesalink_handle);
        if ret != MESALINK_SUCCESS as i32 {
            let mut detail: i32 =
                mesalink_SSL_get_error((*(*connssl).backend).mesalink_handle, ret);
            if MESALINK_ERROR_WANT_CONNECT as i32 == detail
                || MESALINK_ERROR_WANT_READ as i32 == detail
            {
                (*connssl).connecting_state = ssl_connect_2_reading;
                return CURLE_OK;
            } else {
                let mut error_buffer: [i8; 80] = [0; 80];
                Curl_failf(
                    data,
                    b"SSL_connect failed with error %d: %s\0" as *const u8 as *const i8,
                    detail,
                    mesalink_ERR_error_string_n(
                        detail as u64,
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 80]>() as u64,
                    ),
                );
                mesalink_ERR_print_errors_fp(stderr);
                #[cfg(not(CURL_DISABLE_PROXY))]
                let CURL_DISABLE_PROXY_verifypeer_2 = (if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    ((*conn).proxy_ssl_config).verifypeer() as i32
                } else {
                    ((*conn).ssl_config).verifypeer() as i32
                }) != 0;
                #[cfg(CURL_DISABLE_PROXY)]
                let CURL_DISABLE_PROXY_verifypeer_2 = ((*conn).ssl_config).verifypeer() as i32 != 0;
                if detail != 0 && CURL_DISABLE_PROXY_verifypeer_2 {
                    detail &= !(0xff as i32);
                    if detail == TLS_ERROR_WEBPKI_ERRORS as i32 {
                        Curl_failf(data, b"Cert verify failed\0" as *const u8 as *const i8);
                        return CURLE_PEER_FAILED_VERIFICATION;
                    }
                }
                return CURLE_SSL_CONNECT_ERROR;
            }
        }
        (*connssl).connecting_state = ssl_connect_3;
        Curl_infof(
            data,
            b"SSL connection using %s / %s\0" as *const u8 as *const i8,
            mesalink_SSL_get_version((*(*connssl).backend).mesalink_handle),
            mesalink_SSL_get_cipher_name((*(*connssl).backend).mesalink_handle),
        );
        return CURLE_OK;
    }
}

// todo - 有一个待翻译的宏：MESALINK_HAVE_SESSION
extern "C" fn mesalink_connect_step3(mut conn: *mut connectdata, mut sockindex: i32) -> CURLcode {
    unsafe {
        let mut result: CURLcode = CURLE_OK;
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        // todo - 344
        // #[cfg(MESALINK_HAVE_SESSION)]
        (*connssl).connecting_state = ssl_connect_done;
        return result;
    }
}

// 内部没有宏
extern "C" fn mesalink_send(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    unsafe {
        let mut conn: *mut connectdata = (*data).conn;
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut error_buffer: [i8; 80] = [0; 80];
        const int_max: size_t = 2147483647 as size_t;
        let mut memlen: i32 = if len > int_max {
            int_max as i32
        } else {
            len as i32
        };
        let mut rc: i32 = mesalink_SSL_write((*(*connssl).backend).mesalink_handle, mem, memlen);
        if rc < 0 as i32 {
            let mut err: i32 = mesalink_SSL_get_error((*(*connssl).backend).mesalink_handle, rc);
            match err {
                2 | 3 => {
                    /* there's data pending, re-invoke SSL_write() */
                    *curlcode = CURLE_AGAIN;
                    return -(1 as i32) as ssize_t;
                }
                _ => {
                    Curl_failf(
                        data,
                        b"SSL write: %s, errno %d\0" as *const u8 as *const i8,
                        mesalink_ERR_error_string_n(
                            err as u64,
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 80]>() as u64,
                        ),
                        *__errno_location(),
                    );
                    *curlcode = CURLE_SEND_ERROR;
                    return -(1 as i32) as ssize_t;
                }
            }
        }
        return rc as ssize_t;
    }
}

// 内部没有宏
extern "C" fn mesalink_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
    unsafe {
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        if !((*(*connssl).backend).mesalink_handle).is_null() {
            mesalink_SSL_shutdown((*(*connssl).backend).mesalink_handle);
            mesalink_SSL_free((*(*connssl).backend).mesalink_handle);
            (*(*connssl).backend).mesalink_handle = 0 as *mut MESALINK_SSL;
        }
        if !((*(*connssl).backend).mesalink_ctx).is_null() {
            mesalink_SSL_CTX_free((*(*connssl).backend).mesalink_ctx);
            (*(*connssl).backend).mesalink_ctx = 0 as *mut MESALINK_CTX;
        }
    }
}

// 内部没有宏
extern "C" fn mesalink_recv(
    mut data: *mut Curl_easy,
    mut num: i32,
    mut buf: *mut i8,
    mut buffersize: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    unsafe {
        let mut conn: *mut connectdata = (*data).conn;
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(num as isize) as *mut ssl_connect_data;
        let mut error_buffer: [i8; 80] = [0; 80];
        const int_max: size_t = 2147483647 as size_t;
        let mut buffsize: i32 = if buffersize > int_max {
            int_max as i32
        } else {
            buffersize as i32
        };
        let mut nread: i32 = mesalink_SSL_read(
            (*(*connssl).backend).mesalink_handle,
            buf as *mut libc::c_void,
            buffsize,
        );
        if nread <= 0 as i32 {
            let mut err: i32 = mesalink_SSL_get_error((*(*connssl).backend).mesalink_handle, nread);
            match err {
                1 | 33554437 => {}
                2 | 3 => {
                    /* there's data pending, re-invoke SSL_read() */
                    *curlcode = CURLE_AGAIN;
                    return -(1 as i32) as ssize_t;
                }
                _ => {
                    Curl_failf(
                        data,
                        b"SSL read: %s, errno %d\0" as *const u8 as *const i8,
                        mesalink_ERR_error_string_n(
                            err as u64,
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 80]>() as u64,
                        ),
                        *__errno_location(),
                    );
                    *curlcode = CURLE_RECV_ERROR;
                    return -(1 as i32) as ssize_t;
                }
            }
        }
        return nread as ssize_t;
    }
}

// 内部没有宏
extern "C" fn mesalink_version(mut buffer: *mut i8, mut size: size_t) -> size_t {
    unsafe {
        return curl_msnprintf(
            buffer,
            size,
            b"MesaLink/%s\0" as *const u8 as *const i8,
            b"0.10.1\0" as *const u8 as *const i8,
        ) as size_t;
    }
}

// 内部没有宏
extern "C" fn mesalink_init() -> i32 {
    unsafe {
        return (mesalink_library_init() == MESALINK_SUCCESS as i32) as i32;
    }
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
// 内部没有宏
extern "C" fn mesalink_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> i32 {
    unsafe {
        let mut retval: i32 = 0 as i32;
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        if !((*(*connssl).backend).mesalink_handle).is_null() {
            mesalink_SSL_free((*(*connssl).backend).mesalink_handle);
            (*(*connssl).backend).mesalink_handle = 0 as *mut MESALINK_SSL;
        }
        return retval;
    }
}

// 内部没有宏
extern "C" fn mesalink_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> CURLcode {
    unsafe {
        let mut result: CURLcode = CURLE_OK;
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
        let mut timeout_ms: timediff_t = 0;
        let mut what: i32 = 0;
        /* check if the connection has already been established */
        if ssl_connection_complete as i32 as u32 == (*connssl).state as u32 {
            *done = 1 as i32 != 0;
            return CURLE_OK;
        }
        if ssl_connect_1 as u32 == (*connssl).connecting_state as u32 {
            /* Find out how much more time we're allowed */
            timeout_ms = Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0);
            if timeout_ms < 0 as i64 {
                /* no need to continue if time already is up */
                Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const i8);
                return CURLE_OPERATION_TIMEDOUT;
            }
            result = mesalink_connect_step1(data, conn, sockindex);
            if result as u64 != 0 {
                return result;
            }
        }
        while ssl_connect_2 as u32 == (*connssl).connecting_state as u32
            || ssl_connect_2_reading as u32 == (*connssl).connecting_state as u32
            || ssl_connect_2_writing as u32 == (*connssl).connecting_state as u32
        {
            /* check allowed time left */
            timeout_ms = Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0);
            if timeout_ms < 0 as i64 {
                /* no need to continue if time already is up */
                Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const i8);
                return CURLE_OPERATION_TIMEDOUT;
            }
            /* if ssl is expecting something, check if it's available. */
            if (*connssl).connecting_state as u32 == ssl_connect_2_reading as u32
                || (*connssl).connecting_state as u32 == ssl_connect_2_writing as u32
            {
                let mut writefd: curl_socket_t =
                    if ssl_connect_2_writing as u32 == (*connssl).connecting_state as u32 {
                        sockfd
                    } else {
                        -(1 as i32)
                    };
                let mut readfd: curl_socket_t =
                    if ssl_connect_2_reading as u32 == (*connssl).connecting_state as u32 {
                        sockfd
                    } else {
                        -(1 as i32)
                    };
                what = Curl_socket_check(
                    readfd,
                    -(1 as i32),
                    writefd,
                    if nonblocking as i32 != 0 {
                        0 as i64
                    } else {
                        timeout_ms
                    },
                );
                if what < 0 as i32 {
                    /* fatal error */
                    Curl_failf(
                        data,
                        b"select/poll on SSL socket, errno: %d\0" as *const u8 as *const i8,
                        *__errno_location(),
                    );
                    return CURLE_SSL_CONNECT_ERROR;
                } else {
                    if 0 as i32 == what {
                        if nonblocking {
                            *done = 0 as i32 != 0;
                            return CURLE_OK;
                        } else {
                            /* timeout */
                            Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const i8);
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
            result = mesalink_connect_step2(data, conn, sockindex);
            if result as u32 != 0
                || nonblocking as i32 != 0
                    && (ssl_connect_2 as u32 == (*connssl).connecting_state as u32
                        || ssl_connect_2_reading as u32 == (*connssl).connecting_state as u32
                        || ssl_connect_2_writing as u32 == (*connssl).connecting_state as u32)
            {
                return result;
            }
        } /* repeat step2 until all transactions are done. */
        if ssl_connect_3 as i32 as u32 == (*connssl).connecting_state as u32 {
            result = mesalink_connect_step3(conn, sockindex);
            if result as u64 != 0 {
                return result;
            }
        }
        if ssl_connect_done as u32 == (*connssl).connecting_state as u32 {
            (*connssl).state = ssl_connection_complete;
            (*conn).recv[sockindex as usize] = Some(mesalink_recv as Curl_recv);
            (*conn).send[sockindex as usize] = Some(mesalink_send as Curl_send);
            *done = 1 as i32 != 0;
        } else {
            *done = 0 as i32 != 0;
        }
        /* Reset our connect state machine */
        (*connssl).connecting_state = ssl_connect_1;
        return CURLE_OK;
    }
}

// 内部没有宏
extern "C" fn mesalink_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    unsafe {
        return mesalink_connect_common(data, conn, sockindex, 1 as i32 != 0, done);
    }
}

// 内部没有宏
extern "C" fn mesalink_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    unsafe {
        let mut result: CURLcode = CURLE_OK;
        let mut done: bool = 0 as i32 != 0;
        result = mesalink_connect_common(data, conn, sockindex, 0 as i32 != 0, &mut done);
        if result as u64 != 0 {
            return result;
        }
        return CURLE_OK;
    }
}

// 内部没有宏
extern "C" fn mesalink_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    unsafe {
        return (*(*connssl).backend).mesalink_handle as *mut libc::c_void;
    }
}

// 内部没有宏
#[no_mangle]
pub static mut Curl_ssl_mesalink: Curl_ssl = Curl_ssl {
    info: {
        curl_ssl_backend {
            id: CURLSSLBACKEND_MESALINK,
            name: b"MesaLink\0" as *const u8 as *const i8,
        }
    },
    supports: ((1 as i32) << 3 as i32) as u32,
    sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>() as u64,
    init: Some(mesalink_init as unsafe extern "C" fn() -> i32),
    cleanup: Some(Curl_none_cleanup as unsafe extern "C" fn() -> ()),
    version: Some(mesalink_version as unsafe extern "C" fn(*mut i8, size_t) -> size_t),
    check_cxn: Some(Curl_none_check_cxn as unsafe extern "C" fn(*mut connectdata) -> i32),
    shut_down: Some(
        mesalink_shutdown as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> i32,
    ),
    data_pending: Some(
        Curl_none_data_pending as unsafe extern "C" fn(*const connectdata, i32) -> bool,
    ),
    random: Some(
        Curl_none_random as unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode,
    ),
    cert_status_request: Some(Curl_none_cert_status_request as unsafe extern "C" fn() -> bool),
    connect_blocking: Some(
        mesalink_connect as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> CURLcode,
    ),
    connect_nonblocking: Some(
        mesalink_connect_nonblocking
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32, *mut bool) -> CURLcode,
    ),
    getsock: Some(
        Curl_ssl_getsock as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32,
    ),
    get_internals: Some(
        mesalink_get_internals
            as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
    ),
    close_one: Some(
        mesalink_close as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
    ),
    close_all: Some(Curl_none_close_all as unsafe extern "C" fn(*mut Curl_easy) -> ()),
    session_free: Some(Curl_none_session_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
    set_engine: Some(
        Curl_none_set_engine as unsafe extern "C" fn(*mut Curl_easy, *const i8) -> CURLcode,
    ),
    set_engine_default: Some(
        Curl_none_set_engine_default as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
    ),
    engines_list: Some(
        Curl_none_engines_list as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
    ),
    false_start: Some(Curl_none_false_start as unsafe extern "C" fn() -> bool),
    sha256sum: None,
    associate_connection: None,
    disassociate_connection: None,
};
