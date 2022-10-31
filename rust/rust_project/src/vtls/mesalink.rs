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
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
use crate::src::vtls::vtls::*;

// 内部没有宏
unsafe extern "C" fn do_file_type(mut type_0: *const libc::c_char) -> libc::c_int {
    if type_0.is_null() || *type_0.offset(0 as libc::c_int as isize) == 0 {
        return MESALINK_FILETYPE_PEM as libc::c_int;
    }
    if Curl_strcasecompare(type_0, b"PEM\0" as *const u8 as *const libc::c_char) != 0 {
        return MESALINK_FILETYPE_PEM as libc::c_int;
    }
    if Curl_strcasecompare(type_0, b"DER\0" as *const u8 as *const libc::c_char) != 0 {
        return MESALINK_FILETYPE_ASN1 as libc::c_int;
    }
    return -(1 as libc::c_int);
}

// todo - 有两个选项待翻译：MESALINK_HAVE_CIPHER 和 MESALINK_HAVE_SESSION
unsafe extern "C" fn mesalink_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut ciphers: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut addr4: in_addr = in_addr { s_addr: 0 };
    #[cfg(ENABLE_IPV6)] // done - 98 
    let mut addr6: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_8 {
            __u6_addr8: [0; 16],
        },
    };
    #[cfg(not(CURL_DISABLE_PROXY))]
    let hostname: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
        == (*conn).http_proxy.proxytype as libc::c_uint
        && ssl_connection_complete as libc::c_int as libc::c_uint
            != (*conn)
                .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                    == -(1 as libc::c_int)
                {
                    0 as libc::c_int
                } else {
                    1 as libc::c_int
                }) as usize]
                .state as libc::c_uint
    {
        (*conn).http_proxy.host.name
    } else {
        (*conn).host.name
    };
    // vtls.h
    #[cfg(CURL_DISABLE_PROXY)]
    let hostname: *const libc::c_char = (*conn).host.name;
    let mut hostname_len: size_t = strlen(hostname);
    let mut req_method: *mut MESALINK_METHOD = 0 as *mut MESALINK_METHOD;
    let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
    if (*connssl).state as libc::c_uint
        == ssl_connection_complete as libc::c_int as libc::c_uint
    {
        return CURLE_OK;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let CURL_DISABLE_PROXY_1 = (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                == (*conn).http_proxy.proxytype as libc::c_uint
                                && ssl_connection_complete as libc::c_int as libc::c_uint
                                    != (*conn)
                                        .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                            == -(1 as libc::c_int)
                                        {
                                            0 as libc::c_int
                                        } else {
                                            1 as libc::c_int
                                        }) as usize]
                                        .state as libc::c_uint
                            {
                                (*conn).proxy_ssl_config.version_max
                            } else {
                                (*conn).ssl_config.version_max
                            });
    // vtls.h
    #[cfg(CURL_DISABLE_PROXY)]
    let CURL_DISABLE_PROXY_1 = (*conn).ssl_config.version_max;
    if CURL_DISABLE_PROXY_1 != CURL_SSLVERSION_MAX_NONE as libc::c_int as libc::c_long
    {
        Curl_failf(
            data,
            b"MesaLink does not support to set maximum SSL/TLS version\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let CURL_DISABLE_PROXY_2 = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                            == (*conn).http_proxy.proxytype as libc::c_uint
                            && ssl_connection_complete as libc::c_int as libc::c_uint
                                != (*conn)
                                    .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                        == -(1 as libc::c_int)
                                    {
                                        0 as libc::c_int
                                    } else {
                                        1 as libc::c_int
                                    }) as usize]
                                    .state as libc::c_uint
                        {
                            (*conn).proxy_ssl_config.version
                        } else {
                            (*conn).ssl_config.version
                        } ;
    // vtls.h
    #[cfg(CURL_DISABLE_PROXY)]
    let CURL_DISABLE_PROXY_2 = (*conn).ssl_config.version;
    match  CURL_DISABLE_PROXY_2 {
        3 | 1 | 4 | 5 => {
            Curl_failf(
                data,
                b"MesaLink does not support SSL 3.0, TLS 1.0, or TLS 1.1\0" as *const u8
                    as *const libc::c_char,
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
                b"MesaLink does not support SSLv2\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        _ => {
            Curl_failf(
                data,
                b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8
                    as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    if req_method.is_null() {
        Curl_failf(
            data,
            b"SSL: couldn't create a method!\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*(*connssl).backend).mesalink_ctx).is_null() {
        mesalink_SSL_CTX_free((*(*connssl).backend).mesalink_ctx);
    }
    let ref mut fresh0 = (*(*connssl).backend).mesalink_ctx;
    *fresh0 = mesalink_SSL_CTX_new(req_method);
    if ((*(*connssl).backend).mesalink_ctx).is_null() {
        Curl_failf(
            data,
            b"SSL: couldn't create a context!\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_OUT_OF_MEMORY;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let CURL_DISABLE_PROXY_verifypeer = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                == (*conn).http_proxy.proxytype as libc::c_uint
                                && ssl_connection_complete as libc::c_int as libc::c_uint
                                    != (*conn)
                                        .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                            == -(1 as libc::c_int)
                                        {
                                            0 as libc::c_int
                                        } else {
                                            1 as libc::c_int
                                        }) as usize]
                                        .state as libc::c_uint
                            {
                                ((*conn).proxy_ssl_config).verifypeer() as libc::c_int
                            } else {
                                ((*conn).ssl_config).verifypeer() as libc::c_int
                            };
    // vtls.h
    #[cfg(CURL_DISABLE_PROXY)]
    let CURL_DISABLE_PROXY_verifypeer = ((*conn).ssl_config).verifypeer() as libc::c_int;
    mesalink_SSL_CTX_set_verify(
        (*(*connssl).backend).mesalink_ctx,
        if CURL_DISABLE_PROXY_verifypeer != 0
        {
            MESALINK_SSL_VERIFY_PEER as libc::c_int
        } else {
            MESALINK_SSL_VERIFY_NONE as libc::c_int
        },
        None,
    );
    #[cfg(not(CURL_DISABLE_PROXY))]
    let CURL_DISABLE_PROXY_CAfile_1 = !(if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                    == (*conn).http_proxy.proxytype as libc::c_uint
                                    && ssl_connection_complete as libc::c_int as libc::c_uint
                                        != (*conn)
                                            .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                == -(1 as libc::c_int)
                                            {
                                                0 as libc::c_int
                                            } else {
                                                1 as libc::c_int
                                            }) as usize]
                                            .state as libc::c_uint
                                {
                                    (*conn).proxy_ssl_config.CAfile
                                } else {
                                    (*conn).ssl_config.CAfile
                                })
                                    .is_null() ;
    #[cfg(CURL_DISABLE_PROXY)]
    let CURL_DISABLE_PROXY_CAfile_1 = !((*conn).ssl_config.CAfile).is_null();

    #[cfg(not(CURL_DISABLE_PROXY))]
    let CURL_DISABLE_PROXY_CApath_1 = !(if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                    == (*conn).http_proxy.proxytype as libc::c_uint
                                    && ssl_connection_complete as libc::c_int as libc::c_uint
                                        != (*conn)
                                            .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                == -(1 as libc::c_int)
                                            {
                                                0 as libc::c_int
                                            } else {
                                                1 as libc::c_int
                                            }) as usize]
                                            .state as libc::c_uint
                                {
                                    (*conn).proxy_ssl_config.CApath
                                } else {
                                    (*conn).ssl_config.CApath
                                })
                                    .is_null();
    #[cfg(CURL_DISABLE_PROXY)]
    let CURL_DISABLE_PROXY_CApath_1 = !((*conn).ssl_config.CApath).is_null();
    
    #[cfg(not(CURL_DISABLE_PROXY))]
    let CURL_DISABLE_PROXY_CAfile_2 = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                            == (*conn).http_proxy.proxytype as libc::c_uint
                                            && ssl_connection_complete as libc::c_int as libc::c_uint
                                                != (*conn)
                                                    .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                        == -(1 as libc::c_int)
                                                    {
                                                        0 as libc::c_int
                                                    } else {
                                                        1 as libc::c_int
                                                    }) as usize]
                                                    .state as libc::c_uint
                                        {
                                            (*conn).proxy_ssl_config.CAfile
                                        } else {
                                            (*conn).ssl_config.CAfile
                                        };
    #[cfg(CURL_DISABLE_PROXY)]
    let CURL_DISABLE_PROXY_CAfile_2 = (*conn).ssl_config.CAfile;

    #[cfg(not(CURL_DISABLE_PROXY))]
    let CURL_DISABLE_PROXY_CApath_2 = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                        == (*conn).http_proxy.proxytype as libc::c_uint
                                        && ssl_connection_complete as libc::c_int as libc::c_uint
                                            != (*conn)
                                                .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                    == -(1 as libc::c_int)
                                                {
                                                    0 as libc::c_int
                                                } else {
                                                    1 as libc::c_int
                                                }) as usize]
                                                .state as libc::c_uint
                                    {
                                        (*conn).proxy_ssl_config.CApath
                                    } else {
                                        (*conn).ssl_config.CApath
                                    };
    #[cfg(CURL_DISABLE_PROXY)]
    let CURL_DISABLE_PROXY_CApath_2 = (*conn).ssl_config.CApath;

    if CURL_DISABLE_PROXY_CAfile_1 || CURL_DISABLE_PROXY_CApath_1
    {
        if mesalink_SSL_CTX_load_verify_locations(
            (*(*connssl).backend).mesalink_ctx,
            CURL_DISABLE_PROXY_CAfile_2,
            CURL_DISABLE_PROXY_CApath_2,
        ) == 0
        {
            if CURL_DISABLE_PROXY_verifypeer != 0
            {
                Curl_failf(
                    data,
                    b"error setting certificate verify locations:  CAfile: %s CApath: %s\0"
                        as *const u8 as *const libc::c_char,
                    if CURL_DISABLE_PROXY_CAfile_1
                    {
                        CURL_DISABLE_PROXY_CAfile_2 as *const libc::c_char
                    } else {
                        b"none\0" as *const u8 as *const libc::c_char
                    },
                    if CURL_DISABLE_PROXY_CApath_1
                    {
                        CURL_DISABLE_PROXY_CApath_2 as *const libc::c_char
                    } else {
                        b"none\0" as *const u8 as *const libc::c_char
                    },
                );
                return CURLE_SSL_CACERT_BADFILE;
            }
            Curl_infof(
                data,
                b"error setting certificate verify locations, continuing anyway:\0"
                    as *const u8 as *const libc::c_char,
            );
        } else {
            Curl_infof(
                data,
                b"successfully set certificate verify locations:\0" as *const u8
                    as *const libc::c_char,
            );
        }
        Curl_infof(
            data,
            b" CAfile: %s\0" as *const u8 as *const libc::c_char,
            if CURL_DISABLE_PROXY_CAfile_1
            {
                CURL_DISABLE_PROXY_CAfile_2 as *const libc::c_char
            } else {
                b"none\0" as *const u8 as *const libc::c_char
            },
        );
        Curl_infof(
            data,
            b" CApath: %s\0" as *const u8 as *const libc::c_char,
            if CURL_DISABLE_PROXY_CApath_1
            {
                CURL_DISABLE_PROXY_CApath_2 as *const libc::c_char
            } else {
                b"none\0" as *const u8 as *const libc::c_char
            },
        );
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    if !(if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
        == (*conn).http_proxy.proxytype as libc::c_uint
        && ssl_connection_complete as libc::c_int as libc::c_uint
            != (*conn)
                .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                    == -(1 as libc::c_int)
                {
                    0 as libc::c_int
                } else {
                    1 as libc::c_int
                }) as usize]
                .state as libc::c_uint
    {
        (*data).set.proxy_ssl.primary.clientcert
    } else {
        (*data).set.ssl.primary.clientcert
    })
        .is_null()
        && !(if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
            == (*conn).http_proxy.proxytype as libc::c_uint
            && ssl_connection_complete as libc::c_int as libc::c_uint
                != (*conn)
                    .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                        == -(1 as libc::c_int)
                    {
                        0 as libc::c_int
                    } else {
                        1 as libc::c_int
                    }) as usize]
                    .state as libc::c_uint
        {
            (*data).set.proxy_ssl.key
        } else {
            (*data).set.ssl.key
        })
            .is_null()
    {
        let mut file_type: libc::c_int = do_file_type(
            if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                == (*conn).http_proxy.proxytype as libc::c_uint
                && ssl_connection_complete as libc::c_int as libc::c_uint
                    != (*conn)
                        .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                            == -(1 as libc::c_int)
                        {
                            0 as libc::c_int
                        } else {
                            1 as libc::c_int
                        }) as usize]
                        .state as libc::c_uint
            {
                (*data).set.proxy_ssl.cert_type
            } else {
                (*data).set.ssl.cert_type
            },
        );
        if mesalink_SSL_CTX_use_certificate_chain_file(
            (*(*connssl).backend).mesalink_ctx,
            (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                == (*conn).http_proxy.proxytype as libc::c_uint
                && ssl_connection_complete as libc::c_int as libc::c_uint
                    != (*conn)
                        .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                            == -(1 as libc::c_int)
                        {
                            0 as libc::c_int
                        } else {
                            1 as libc::c_int
                        }) as usize]
                        .state as libc::c_uint
            {
                (*data).set.proxy_ssl.primary.clientcert
            } else {
                (*data).set.ssl.primary.clientcert
            }),
            file_type,
        ) != 1 as libc::c_int
        {
            Curl_failf(
                data,
                b"unable to use client certificate (no key or wrong pass phrase?)\0"
                    as *const u8 as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        file_type = do_file_type(
            if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                == (*conn).http_proxy.proxytype as libc::c_uint
                && ssl_connection_complete as libc::c_int as libc::c_uint
                    != (*conn)
                        .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                            == -(1 as libc::c_int)
                        {
                            0 as libc::c_int
                        } else {
                            1 as libc::c_int
                        }) as usize]
                        .state as libc::c_uint
            {
                (*data).set.proxy_ssl.key_type
            } else {
                (*data).set.ssl.key_type
            },
        );
        if mesalink_SSL_CTX_use_PrivateKey_file(
            (*(*connssl).backend).mesalink_ctx,
            (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                == (*conn).http_proxy.proxytype as libc::c_uint
                && ssl_connection_complete as libc::c_int as libc::c_uint
                    != (*conn)
                        .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                            == -(1 as libc::c_int)
                        {
                            0 as libc::c_int
                        } else {
                            1 as libc::c_int
                        }) as usize]
                        .state as libc::c_uint
            {
                (*data).set.proxy_ssl.key
            } else {
                (*data).set.ssl.key
            }),
            file_type,
        ) != 1 as libc::c_int
        {
            Curl_failf(
                data,
                b"unable to set private key\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        Curl_infof(
            data,
            b"client cert: %s\0" as *const u8 as *const libc::c_char,
            if !if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                == (*conn).http_proxy.proxytype as libc::c_uint
                && ssl_connection_complete as libc::c_int as libc::c_uint
                    != (*conn)
                        .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                            == -(1 as libc::c_int)
                        {
                            0 as libc::c_int
                        } else {
                            1 as libc::c_int
                        }) as usize]
                        .state as libc::c_uint
            {
                (*conn).proxy_ssl_config.clientcert
            } else {
                (*conn).ssl_config.clientcert
            }
                .is_null()
            {
                (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                    == (*conn).http_proxy.proxytype as libc::c_uint
                    && ssl_connection_complete as libc::c_int as libc::c_uint
                        != (*conn)
                            .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                == -(1 as libc::c_int)
                            {
                                0 as libc::c_int
                            } else {
                                1 as libc::c_int
                            }) as usize]
                            .state as libc::c_uint
                {
                    (*conn).proxy_ssl_config.clientcert
                } else {
                    (*conn).ssl_config.clientcert
                }) as *const libc::c_char
            } else {
                b"none\0" as *const u8 as *const libc::c_char
            },
        );
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if !((*data).set.ssl.primary.clientcert).is_null()
        && !((*data).set.ssl.key).is_null()
    {
        let mut file_type: libc::c_int = do_file_type((*data).set.ssl.cert_type);
        if mesalink_SSL_CTX_use_certificate_chain_file(
            (*(*connssl).backend).mesalink_ctx,
            (*data).set.ssl.primary.clientcert,
            file_type,
        ) != 1 as libc::c_int
        {
            Curl_failf(
                data,
                b"unable to use client certificate (no key or wrong pass phrase?)\0"
                    as *const u8 as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        file_type = do_file_type((*data).set.ssl.key_type);
        if mesalink_SSL_CTX_use_PrivateKey_file(
            (*(*connssl).backend).mesalink_ctx,
            (*data).set.ssl.key,
            file_type,
        ) != 1 as libc::c_int
        {
            Curl_failf(
                data,
                b"unable to set private key\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        Curl_infof(
            data,
            b"client cert: %s\0" as *const u8 as *const libc::c_char,
            if !((*conn).ssl_config.clientcert).is_null() {
                (*conn).ssl_config.clientcert as *const libc::c_char
            } else {
                b"none\0" as *const u8 as *const libc::c_char
            },
        );
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let CURL_DISABLE_PROXY_cipher_list = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                    == (*conn).http_proxy.proxytype as libc::c_uint
                                    && ssl_connection_complete as libc::c_int as libc::c_uint
                                        != (*conn)
                                            .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                == -(1 as libc::c_int)
                                            {
                                                0 as libc::c_int
                                            } else {
                                                1 as libc::c_int
                                            }) as usize]
                                            .state as libc::c_uint
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
        if cfg!(MESALINK_HAVE_CIPHER){
            // 选项：MESALINK_HAVE_CIPHER
        }
        Curl_infof(
            data,
            b"Cipher selection: %s\0" as *const u8 as *const libc::c_char,
            ciphers,
        );
    }
    if !((*(*connssl).backend).mesalink_handle).is_null() {
        mesalink_SSL_free((*(*connssl).backend).mesalink_handle);
    }
    let ref mut fresh1 = (*(*connssl).backend).mesalink_handle;
    *fresh1 = mesalink_SSL_new((*(*connssl).backend).mesalink_ctx);
    if ((*(*connssl).backend).mesalink_handle).is_null() {
        Curl_failf(
            data,
            b"SSL: couldn't create a context (handle)!\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_OUT_OF_MEMORY;
    }
    // done - 225
    #[cfg(ENABLE_IPV6)]
    let ENABLE_IPV6_flag = 0 as libc::c_int
                            == inet_pton(
                                10 as libc::c_int,
                                hostname,
                                &mut addr6 as *mut in6_addr as *mut libc::c_void
                            );
    #[cfg(not(ENABLE_IPV6))] // 如果没有ENABLE_IPV6这个选项，那就不要这个条件，那么一定是true
    let ENABLE_IPV6_flag = true;
    if hostname_len
        < (32767 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as libc::c_ulong
        && 0 as libc::c_int
            == inet_pton(
                2 as libc::c_int,
                hostname,
                &mut addr4 as *mut in_addr as *mut libc::c_void,
            )
        && ENABLE_IPV6_flag
    {
        if mesalink_SSL_set_tlsext_host_name((*(*connssl).backend).mesalink_handle, hostname)
            != MESALINK_SUCCESS as libc::c_int
        {
            Curl_failf(
                data,
                b"WARNING: failed to configure server name indication (SNI) TLS extension\n\0"
                    as *const u8 as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    } else {
        // done - CURLDEBUG不加 238
        Curl_failf(
            data,
            b"ERROR: MesaLink does not accept an IP address as a hostname\n\0"
                as *const u8 as *const libc::c_char,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    // todo - 258 选项：MESALINK_HAVE_SESSION
    // #[cfg(MESALINK_HAVE_SESSION)]
    if mesalink_SSL_set_fd((*(*connssl).backend).mesalink_handle, sockfd)
        != MESALINK_SUCCESS as libc::c_int
    {
        Curl_failf(
            data,
            b"SSL: SSL_set_fd failed\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    (*connssl).connecting_state = ssl_connect_2;
    return CURLE_OK;
}

// 内部没有宏
unsafe extern "C" fn mesalink_connect_step2(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let ref mut fresh2 = (*conn).recv[sockindex as usize];
    *fresh2 = Some(mesalink_recv as Curl_recv);
    let ref mut fresh3 = (*conn).send[sockindex as usize];
    *fresh3 = Some(mesalink_send as Curl_send);
    ret = mesalink_SSL_connect((*(*connssl).backend).mesalink_handle);
    if ret != MESALINK_SUCCESS as libc::c_int {
        let mut detail: libc::c_int = mesalink_SSL_get_error(
            (*(*connssl).backend).mesalink_handle,
            ret,
        );
        if MESALINK_ERROR_WANT_CONNECT as libc::c_int == detail
            || MESALINK_ERROR_WANT_READ as libc::c_int == detail
        {
            (*connssl).connecting_state = ssl_connect_2_reading;
            return CURLE_OK;
        } else {
            let mut error_buffer: [libc::c_char; 80] = [0; 80];
            Curl_failf(
                data,
                b"SSL_connect failed with error %d: %s\0" as *const u8
                    as *const libc::c_char,
                detail,
                mesalink_ERR_error_string_n(
                    detail as libc::c_ulong,
                    error_buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong,
                ),
            );
            mesalink_ERR_print_errors_fp(stderr);
            #[cfg(not(CURL_DISABLE_PROXY))]
            let CURL_DISABLE_PROXY_verifypeer_2 = (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                                    == (*conn).http_proxy.proxytype as libc::c_uint
                                                    && ssl_connection_complete as libc::c_int as libc::c_uint
                                                        != (*conn)
                                                            .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                                == -(1 as libc::c_int)
                                                            {
                                                                0 as libc::c_int
                                                            } else {
                                                                1 as libc::c_int
                                                            }) as usize]
                                                            .state as libc::c_uint
                                                {
                                                    ((*conn).proxy_ssl_config).verifypeer() as libc::c_int
                                                } else {
                                                    ((*conn).ssl_config).verifypeer() as libc::c_int
                                                }) != 0 ;
            #[cfg(CURL_DISABLE_PROXY)]
            let CURL_DISABLE_PROXY_verifypeer_2 = ((*conn).ssl_config).verifypeer() as libc::c_int != 0 ; 
            if detail != 0 && CURL_DISABLE_PROXY_verifypeer_2{
                detail &= !(0xff as libc::c_int);
                if detail == TLS_ERROR_WEBPKI_ERRORS as libc::c_int {
                    Curl_failf(
                        data,
                        b"Cert verify failed\0" as *const u8 as *const libc::c_char,
                    );
                    return CURLE_PEER_FAILED_VERIFICATION;
                }
            }
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    (*connssl).connecting_state = ssl_connect_3;
    Curl_infof(
        data,
        b"SSL connection using %s / %s\0" as *const u8 as *const libc::c_char,
        mesalink_SSL_get_version((*(*connssl).backend).mesalink_handle),
        mesalink_SSL_get_cipher_name((*(*connssl).backend).mesalink_handle),
    );
    return CURLE_OK;
}

// todo - 有一个待翻译的宏：MESALINK_HAVE_SESSION
unsafe extern "C" fn mesalink_connect_step3(
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    // todo - 344
    // #[cfg(MESALINK_HAVE_SESSION)]
    (*connssl).connecting_state = ssl_connect_done;
    return result;
}

// 内部没有宏
unsafe extern "C" fn mesalink_send(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut error_buffer: [libc::c_char; 80] = [0; 80];
    let mut memlen: libc::c_int = if len > 2147483647 as libc::c_int as size_t {
        2147483647 as libc::c_int
    } else {
        len as libc::c_int
    };
    let mut rc: libc::c_int = mesalink_SSL_write(
        (*(*connssl).backend).mesalink_handle,
        mem,
        memlen,
    );
    if rc < 0 as libc::c_int {
        let mut err: libc::c_int = mesalink_SSL_get_error(
            (*(*connssl).backend).mesalink_handle,
            rc,
        );
        match err {
            2 | 3 => {
                *curlcode = CURLE_AGAIN;
                return -(1 as libc::c_int) as ssize_t;
            }
            _ => {
                Curl_failf(
                    data,
                    b"SSL write: %s, errno %d\0" as *const u8 as *const libc::c_char,
                    mesalink_ERR_error_string_n(
                        err as libc::c_ulong,
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong,
                    ),
                    *__errno_location(),
                );
                *curlcode = CURLE_SEND_ERROR;
                return -(1 as libc::c_int) as ssize_t;
            }
        }
    }
    return rc as ssize_t;
}

// 内部没有宏
unsafe extern "C" fn mesalink_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    if !((*(*connssl).backend).mesalink_handle).is_null() {
        mesalink_SSL_shutdown((*(*connssl).backend).mesalink_handle);
        mesalink_SSL_free((*(*connssl).backend).mesalink_handle);
        let ref mut fresh4 = (*(*connssl).backend).mesalink_handle;
        *fresh4 = 0 as *mut MESALINK_SSL;
    }
    if !((*(*connssl).backend).mesalink_ctx).is_null() {
        mesalink_SSL_CTX_free((*(*connssl).backend).mesalink_ctx);
        let ref mut fresh5 = (*(*connssl).backend).mesalink_ctx;
        *fresh5 = 0 as *mut MESALINK_CTX;
    }
}

// 内部没有宏
unsafe extern "C" fn mesalink_recv(
    mut data: *mut Curl_easy,
    mut num: libc::c_int,
    mut buf: *mut libc::c_char,
    mut buffersize: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(num as isize) as *mut ssl_connect_data;
    let mut error_buffer: [libc::c_char; 80] = [0; 80];
    let mut buffsize: libc::c_int = if buffersize > 2147483647 as libc::c_int as size_t {
        2147483647 as libc::c_int
    } else {
        buffersize as libc::c_int
    };
    let mut nread: libc::c_int = mesalink_SSL_read(
        (*(*connssl).backend).mesalink_handle,
        buf as *mut libc::c_void,
        buffsize,
    );
    if nread <= 0 as libc::c_int {
        let mut err: libc::c_int = mesalink_SSL_get_error(
            (*(*connssl).backend).mesalink_handle,
            nread,
        );
        match err {
            1 | 33554437 => {}
            2 | 3 => {
                *curlcode = CURLE_AGAIN;
                return -(1 as libc::c_int) as ssize_t;
            }
            _ => {
                Curl_failf(
                    data,
                    b"SSL read: %s, errno %d\0" as *const u8 as *const libc::c_char,
                    mesalink_ERR_error_string_n(
                        err as libc::c_ulong,
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong,
                    ),
                    *__errno_location(),
                );
                *curlcode = CURLE_RECV_ERROR;
                return -(1 as libc::c_int) as ssize_t;
            }
        }
    }
    return nread as ssize_t;
}

// 内部没有宏
unsafe extern "C" fn mesalink_version(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
) -> size_t {
    return curl_msnprintf(
        buffer,
        size,
        b"MesaLink/%s\0" as *const u8 as *const libc::c_char,
        b"0.10.1\0" as *const u8 as *const libc::c_char,
    ) as size_t;
}

// 内部没有宏
unsafe extern "C" fn mesalink_init() -> libc::c_int {
    return (mesalink_library_init() == MESALINK_SUCCESS as libc::c_int) as libc::c_int;
}

// 内部没有宏
unsafe extern "C" fn mesalink_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> libc::c_int {
    let mut retval: libc::c_int = 0 as libc::c_int;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    if !((*(*connssl).backend).mesalink_handle).is_null() {
        mesalink_SSL_free((*(*connssl).backend).mesalink_handle);
        let ref mut fresh6 = (*(*connssl).backend).mesalink_handle;
        *fresh6 = 0 as *mut MESALINK_SSL;
    }
    return retval;
}

// 内部没有宏
unsafe extern "C" fn mesalink_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
    let mut timeout_ms: timediff_t = 0;
    let mut what: libc::c_int = 0;
    if ssl_connection_complete as libc::c_int as libc::c_uint
        == (*connssl).state as libc::c_uint
    {
        *done = 1 as libc::c_int != 0;
        return CURLE_OK;
    }
    if ssl_connect_1 as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        timeout_ms = Curl_timeleft(data, 0 as *mut curltime, 1 as libc::c_int != 0);
        if timeout_ms < 0 as libc::c_int as libc::c_long {
            Curl_failf(
                data,
                b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OPERATION_TIMEDOUT;
        }
        result = mesalink_connect_step1(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    while ssl_connect_2 as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
        || ssl_connect_2_reading as libc::c_int as libc::c_uint
            == (*connssl).connecting_state as libc::c_uint
        || ssl_connect_2_writing as libc::c_int as libc::c_uint
            == (*connssl).connecting_state as libc::c_uint
    {
        timeout_ms = Curl_timeleft(data, 0 as *mut curltime, 1 as libc::c_int != 0);
        if timeout_ms < 0 as libc::c_int as libc::c_long {
            Curl_failf(
                data,
                b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OPERATION_TIMEDOUT;
        }
        if (*connssl).connecting_state as libc::c_uint
            == ssl_connect_2_reading as libc::c_int as libc::c_uint
            || (*connssl).connecting_state as libc::c_uint
                == ssl_connect_2_writing as libc::c_int as libc::c_uint
        {
            let mut writefd: curl_socket_t = if ssl_connect_2_writing as libc::c_int
                as libc::c_uint == (*connssl).connecting_state as libc::c_uint
            {
                sockfd
            } else {
                -(1 as libc::c_int)
            };
            let mut readfd: curl_socket_t = if ssl_connect_2_reading as libc::c_int
                as libc::c_uint == (*connssl).connecting_state as libc::c_uint
            {
                sockfd
            } else {
                -(1 as libc::c_int)
            };
            what = Curl_socket_check(
                readfd,
                -(1 as libc::c_int),
                writefd,
                if nonblocking as libc::c_int != 0 {
                    0 as libc::c_int as libc::c_long
                } else {
                    timeout_ms
                },
            );
            if what < 0 as libc::c_int {
                Curl_failf(
                    data,
                    b"select/poll on SSL socket, errno: %d\0" as *const u8
                        as *const libc::c_char,
                    *__errno_location(),
                );
                return CURLE_SSL_CONNECT_ERROR;
            } else {
                if 0 as libc::c_int == what {
                    if nonblocking {
                        *done = 0 as libc::c_int != 0;
                        return CURLE_OK;
                    } else {
                        Curl_failf(
                            data,
                            b"SSL connection timeout\0" as *const u8
                                as *const libc::c_char,
                        );
                        return CURLE_OPERATION_TIMEDOUT;
                    }
                }
            }
        }
        result = mesalink_connect_step2(data, conn, sockindex);
        if result as libc::c_uint != 0
            || nonblocking as libc::c_int != 0
                && (ssl_connect_2 as libc::c_int as libc::c_uint
                    == (*connssl).connecting_state as libc::c_uint
                    || ssl_connect_2_reading as libc::c_int as libc::c_uint
                        == (*connssl).connecting_state as libc::c_uint
                    || ssl_connect_2_writing as libc::c_int as libc::c_uint
                        == (*connssl).connecting_state as libc::c_uint)
        {
            return result;
        }
    }
    if ssl_connect_3 as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        result = mesalink_connect_step3(conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if ssl_connect_done as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        (*connssl).state = ssl_connection_complete;
        let ref mut fresh7 = (*conn).recv[sockindex as usize];
        *fresh7 = Some(mesalink_recv as Curl_recv);
        let ref mut fresh8 = (*conn).send[sockindex as usize];
        *fresh8 = Some(mesalink_send as Curl_send);
        *done = 1 as libc::c_int != 0;
    } else {
        *done = 0 as libc::c_int != 0;
    }
    (*connssl).connecting_state = ssl_connect_1;
    return CURLE_OK;
}

// 内部没有宏
unsafe extern "C" fn mesalink_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    return mesalink_connect_common(data, conn, sockindex, 1 as libc::c_int != 0, done);
}

// 内部没有宏
unsafe extern "C" fn mesalink_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut done: bool = 0 as libc::c_int != 0;
    result = mesalink_connect_common(
        data,
        conn,
        sockindex,
        0 as libc::c_int != 0,
        &mut done,
    );
    if result as u64 != 0 {
        return result;
    }
    return CURLE_OK;
}

// 内部没有宏
unsafe extern "C" fn mesalink_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    return (*(*connssl).backend).mesalink_handle as *mut libc::c_void;
}

// 内部没有宏
#[no_mangle]
pub static mut Curl_ssl_mesalink: Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_MESALINK,
                    name: b"MesaLink\0" as *const u8 as *const libc::c_char,
                };
                init
            },
            supports: ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint,
            sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>()
                as libc::c_ulong,
            init: Some(mesalink_init as unsafe extern "C" fn() -> libc::c_int),
            cleanup: Some(Curl_none_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(
                mesalink_version
                    as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t,
            ),
            check_cxn: Some(
                Curl_none_check_cxn
                    as unsafe extern "C" fn(*mut connectdata) -> libc::c_int,
            ),
            shut_down: Some(
                mesalink_shutdown
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            data_pending: Some(
                Curl_none_data_pending
                    as unsafe extern "C" fn(*const connectdata, libc::c_int) -> bool,
            ),
            random: Some(
                Curl_none_random
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut libc::c_uchar,
                        size_t,
                    ) -> CURLcode,
            ),
            cert_status_request: Some(
                Curl_none_cert_status_request as unsafe extern "C" fn() -> bool,
            ),
            connect_blocking: Some(
                mesalink_connect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> CURLcode,
            ),
            connect_nonblocking: Some(
                mesalink_connect_nonblocking
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                        *mut bool,
                    ) -> CURLcode,
            ),
            getsock: Some(
                Curl_ssl_getsock
                    as unsafe extern "C" fn(
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            get_internals: Some(
                mesalink_get_internals
                    as unsafe extern "C" fn(
                        *mut ssl_connect_data,
                        CURLINFO,
                    ) -> *mut libc::c_void,
            ),
            close_one: Some(
                mesalink_close
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> (),
            ),
            close_all: Some(
                Curl_none_close_all as unsafe extern "C" fn(*mut Curl_easy) -> (),
            ),
            session_free: Some(
                Curl_none_session_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            set_engine: Some(
                Curl_none_set_engine
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *const libc::c_char,
                    ) -> CURLcode,
            ),
            set_engine_default: Some(
                Curl_none_set_engine_default
                    as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
            ),
            engines_list: Some(
                Curl_none_engines_list
                    as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
            ),
            false_start: Some(Curl_none_false_start as unsafe extern "C" fn() -> bool),
            sha256sum: None,
            associate_connection: None,
            disassociate_connection: None,
        };
        init
    }
};
