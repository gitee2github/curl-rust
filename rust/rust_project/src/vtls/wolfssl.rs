use ::libc;
// use c2rust_bitfields::BitfieldStruct;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
use crate::src::vtls::keylog::*;
use crate::src::vtls::vtls::*;
// ------------------------------
unsafe extern "C" fn wolfssl_log_tls12_secret(mut ssl: *mut WOLFSSL) {
    let mut ms: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut sr: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut cr: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut msLen: libc::c_uint = 0;
    let mut srLen: libc::c_uint = 0;
    let mut crLen: libc::c_uint = 0;
    let mut i: libc::c_uint = 0;
    let mut x: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    // 158 - done
    if cfg!(LIBWOLFSSL_VERSION_HEX_GT_0X0300D000){
        match wolfSSL_GetVersion(ssl) {
            0 | 1 | 2 | 3 => {}
            _ => return,
        }
    }
    if wolfSSL_get_keys(
        ssl,
        &mut ms,
        &mut msLen,
        &mut sr,
        &mut srLen,
        &mut cr,
        &mut crLen,
    ) != WOLFSSL_SUCCESS as libc::c_int
    {
        return;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < msLen {
        x |= *ms.offset(i as isize) as libc::c_uint;
        i = i.wrapping_add(1);
    }
    if x == 0 as libc::c_int as libc::c_uint {
        return;
    }
    Curl_tls_keylog_write(
        b"CLIENT_RANDOM\0" as *const u8 as *const libc::c_char,
        cr as *const libc::c_uchar,
        ms,
        msLen as size_t,
    );
}
unsafe extern "C" fn do_file_type(mut type_0: *const libc::c_char) -> libc::c_int {
    if type_0.is_null() || *type_0.offset(0 as libc::c_int as isize) == 0 {
        return WOLFSSL_FILETYPE_PEM as libc::c_int;
    }
    if Curl_strcasecompare(type_0, b"PEM\0" as *const u8 as *const libc::c_char) != 0 {
        return WOLFSSL_FILETYPE_PEM as libc::c_int;
    }
    if Curl_strcasecompare(type_0, b"DER\0" as *const u8 as *const libc::c_char) != 0 {
        return WOLFSSL_FILETYPE_ASN1 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn wolfssl_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut ciphers: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut req_method: *mut SSL_METHOD = 0 as *mut SSL_METHOD;
    let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
    if (*connssl).state as libc::c_uint
        == ssl_connection_complete as libc::c_int as libc::c_uint
    {
        return CURLE_OK;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_version_max = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_version_max = (*conn).ssl_config.version_max;
    if SSL_CONN_CONFIG_version_max != CURL_SSLVERSION_MAX_NONE as libc::c_int as libc::c_long
    {
        Curl_failf(
            data,
            b"wolfSSL does not support to set maximum SSL/TLS version\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_version = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_version = (*conn).ssl_config.version;
    match SSL_CONN_CONFIG_version {
        0 | 1 => {
            // done-237
            req_method = wolfSSLv23_client_method();            
        }
        4 => {
            #[cfg(any(not(WOLFSSL_ALLOW_TLSV10), NO_OLD_TLS))]
            Curl_failf(
                data,
                b"wolfSSL does not support TLS 1.0\0" as *const u8 as *const libc::c_char,
            );
            #[cfg(any(not(WOLFSSL_ALLOW_TLSV10), NO_OLD_TLS))]
            return CURLE_NOT_BUILT_IN;          
        }
        5 => {
            #[cfg(NO_OLD_TLS)]
            if true {
                req_method = wolfTLSv1_1_client_method();   
            }       
        }
        6 => {
            req_method = wolfTLSv1_2_client_method();
        }
        7 => {
            #[cfg(not(WOLFSSL_TLS13))]
            Curl_failf(
                data,
                b"wolfSSL: TLS 1.3 is not yet supported\0" as *const u8
                    as *const libc::c_char,
            );
            #[cfg(not(WOLFSSL_TLS13))]
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
    if !((*backend).ctx).is_null() {
        wolfSSL_CTX_free((*backend).ctx);
    }
    let ref mut fresh0 = (*backend).ctx;
    *fresh0 = wolfSSL_CTX_new(req_method);
    if ((*backend).ctx).is_null() {
        Curl_failf(
            data,
            b"SSL: couldn't create a context!\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_OUT_OF_MEMORY;
    }
    match SSL_CONN_CONFIG_version {
        0 | 1 => {
            #[cfg(WOLFSSL_TLS13)]
            let WOLFSSL_TLS13_flag = wolfSSL_CTX_SetMinVersion(
                                        (*backend).ctx,
                                        WOLFSSL_TLSV1_3 as libc::c_int,
                                        ) != 1 as libc::c_int;
            #[cfg(not(WOLFSSL_TLS13))]
            let WOLFSSL_TLS13_flag = true;  
            if wolfSSL_CTX_SetMinVersion((*backend).ctx, WOLFSSL_TLSV1 as libc::c_int)
                != 1 as libc::c_int
                && wolfSSL_CTX_SetMinVersion(
                    (*backend).ctx,
                    WOLFSSL_TLSV1_1 as libc::c_int,
                ) != 1 as libc::c_int
                && wolfSSL_CTX_SetMinVersion(
                    (*backend).ctx,
                    WOLFSSL_TLSV1_2 as libc::c_int,
                ) != 1 as libc::c_int
                && WOLFSSL_TLS13_flag
            {
                Curl_failf(
                    data,
                    b"SSL: couldn't set the minimum protocol version\0" as *const u8
                        as *const libc::c_char,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }          
        }
        _ => {}
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_cipher_list = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    let SSL_CONN_CONFIG_cipher_list = (*conn).ssl_config.cipher_list;
    ciphers = SSL_CONN_CONFIG_cipher_list;
    if !ciphers.is_null() {
        if wolfSSL_CTX_set_cipher_list((*backend).ctx, ciphers) == 0 {
            Curl_failf(
                data,
                b"failed setting cipher list: %s\0" as *const u8 as *const libc::c_char,
                ciphers,
            );
            return CURLE_SSL_CIPHER;
        }
        Curl_infof(
            data,
            b"Cipher selection: %s\0" as *const u8 as *const libc::c_char,
            ciphers,
        );
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_CAfile = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    let SSL_CONN_CONFIG_CAfile = (*conn).ssl_config.CAfile;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_CApath = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    let SSL_CONN_CONFIG_CApath = (*conn).ssl_config.CApath;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifypeer = ((*conn).ssl_config).verifypeer();
    #[cfg(not(NO_FILESYSTEM))]
    if !(SSL_CONN_CONFIG_CAfile).is_null()
    {
        if 1 as libc::c_int
            != wolfSSL_CTX_load_verify_locations(
                (*backend).ctx,
                (SSL_CONN_CONFIG_CAfile),
                (SSL_CONN_CONFIG_CApath),
            )
        {
            if SSL_CONN_CONFIG_verifypeer != 0
            {
                Curl_failf(
                    data,
                    b"error setting certificate verify locations: CAfile: %s CApath: %s\0"
                        as *const u8 as *const libc::c_char,
                    if !(SSL_CONN_CONFIG_CAfile).is_null()
                    {
                        (SSL_CONN_CONFIG_CAfile) as *const libc::c_char
                    } else {
                        b"none\0" as *const u8 as *const libc::c_char
                    },
                    if !(SSL_CONN_CONFIG_CApath).is_null()
                    {
                        (SSL_CONN_CONFIG_CApath) as *const libc::c_char
                    } else {
                        b"none\0" as *const u8 as *const libc::c_char
                    },
                );
                return CURLE_SSL_CACERT_BADFILE;
            } else {
                Curl_infof(
                    data,
                    b"error setting certificate verify locations, continuing anyway:\0"
                        as *const u8 as *const libc::c_char,
                );
            }
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
            if !(SSL_CONN_CONFIG_CAfile).is_null()
            {
                (SSL_CONN_CONFIG_CAfile) as *const libc::c_char
            } else {
                b"none\0" as *const u8 as *const libc::c_char
            },
        );
        Curl_infof(
            data,
            b" CApath: %s\0" as *const u8 as *const libc::c_char,
            if !(SSL_CONN_CONFIG_CApath).is_null()
            {
                (SSL_CONN_CONFIG_CApath) as *const libc::c_char
            } else {
                b"none\0" as *const u8 as *const libc::c_char
            },
        );
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_clientcert = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                            (*data).set.ssl.primary.clientcert };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_clientcert = (*data).set.ssl.primary.clientcert;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_key = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                            };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_key = (*data).set.ssl.key;
    #[cfg(not(NO_FILESYSTEM))]
    if !(SSL_SET_OPTION_primary_clientcert).is_null()
        && !(SSL_SET_OPTION_key).is_null()
    {
        #[cfg(not(CURL_DISABLE_PROXY))]
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
        #[cfg(CURL_DISABLE_PROXY)]
        let mut file_type: libc::c_int = do_file_type((*data).set.ssl.cert_type);
        if wolfSSL_CTX_use_certificate_file(
            (*backend).ctx,
            SSL_SET_OPTION_primary_clientcert,
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
        #[cfg(not(CURL_DISABLE_PROXY))]
        if true {
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
        }
        #[cfg(CURL_DISABLE_PROXY)]
        if true {
            file_type = do_file_type((*data).set.ssl.key_type);
        }        
        if wolfSSL_CTX_use_PrivateKey_file(
            (*backend).ctx,
            SSL_SET_OPTION_key,
            file_type,
        ) != 1 as libc::c_int
        {
            Curl_failf(
                data,
                b"unable to set private key\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    wolfSSL_CTX_set_verify(
        (*backend).ctx,
        if SSL_CONN_CONFIG_verifypeer != 0
        {
            WOLFSSL_VERIFY_PEER as libc::c_int
        } else {
            WOLFSSL_VERIFY_NONE as libc::c_int
        },
        None,
    );
    if ((*data).set.ssl.fsslctx).is_some() {
        let mut result: CURLcode = (Some(
            ((*data).set.ssl.fsslctx).expect("non-null function pointer"),
        ))
            .expect(
                "non-null function pointer",
            )(data, (*backend).ctx as *mut libc::c_void, (*data).set.ssl.fsslctxp);
        if result as u64 != 0 {
            Curl_failf(
                data,
                b"error signaled by ssl ctx callback\0" as *const u8
                    as *const libc::c_char,
            );
            return result;
        }
    }
    if !((*backend).wolf_handle).is_null() {
        wolfSSL_free((*backend).wolf_handle);
    }
    let ref mut fresh1 = (*backend).wolf_handle;
    *fresh1 = wolfSSL_new((*backend).ctx);
    if ((*backend).wolf_handle).is_null() {
        Curl_failf(
            data,
            b"SSL: couldn't create a context (handle)!\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_OUT_OF_MEMORY;
    }
    #[cfg(OPENSSL_EXTRA)]
    if Curl_tls_keylog_enabled() {
        wolfSSL_KeepArrays((*backend).wolf_handle);
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                                ((*data).set.proxy_ssl.primary).sessionid() as libc::c_int
                                            } else {
                                                ((*data).set.ssl.primary).sessionid() as libc::c_int
                                            };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_sessionid = ((*data).set.ssl.primary).sessionid();
    if SSL_SET_OPTION_primary_sessionid != 0
    {
        let mut ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
        Curl_ssl_sessionid_lock(data);
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_IS_PROXY_void = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                    1 as libc::c_int
                                } else {
                                    0 as libc::c_int
                                };
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_IS_PROXY_void = if 0 as libc::c_int != 0 { 1 as libc::c_int } else { 0 as libc::c_int };
        if !Curl_ssl_getsessionid(
            data,
            conn,
            SSL_IS_PROXY_void != 0,
            &mut ssl_sessionid,
            0 as *mut size_t,
            sockindex,
        ) {
            if wolfSSL_set_session(
                (*backend).wolf_handle,
                ssl_sessionid as *mut WOLFSSL_SESSION,
            ) == 0
            {
                Curl_ssl_delsessionid(data, ssl_sessionid);
                Curl_infof(
                    data,
                    b"Can't use session ID, going on without\n\0" as *const u8
                        as *const libc::c_char,
                );
            } else {
                Curl_infof(
                    data,
                    b"SSL re-using session ID\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        Curl_ssl_sessionid_unlock(data);
    }  
    if wolfSSL_set_fd((*backend).wolf_handle, sockfd) == 0 {
        Curl_failf(
            data,
            b"SSL: SSL_set_fd failed\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    (*connssl).connecting_state = ssl_connect_2;
    return CURLE_OK;
}
unsafe extern "C" fn wolfssl_connect_step2(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
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
    #[cfg(CURL_DISABLE_PROXY)]
    let hostname: *const libc::c_char = (*conn).host.name;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let dispname: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
        (*conn).http_proxy.host.dispname
    } else {
        (*conn).host.dispname
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let dispname: *const libc::c_char = (*conn).host.dispname;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let pinnedpubkey: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int
        as libc::c_uint == (*conn).http_proxy.proxytype as libc::c_uint
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
        (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY_PROXY as libc::c_int as usize]
    } else {
        (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as libc::c_int as usize]
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let pinnedpubkey: *const libc::c_char = (*data)
    .set
    .str_0[STRING_SSL_PINNEDPUBLICKEY as libc::c_int as usize];
    wolfSSL_ERR_clear_error();
    let ref mut fresh2 = (*conn).recv[sockindex as usize];
    *fresh2 = Some(wolfssl_recv as Curl_recv);
    let ref mut fresh3 = (*conn).send[sockindex as usize];
    *fresh3 = Some(wolfssl_send as Curl_send);
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifyhost = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                        ((*conn).proxy_ssl_config).verifyhost() as libc::c_int
                                    } else {
                                        ((*conn).ssl_config).verifyhost() as libc::c_int
                                    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifyhost = ((*conn).ssl_config).verifyhost();
    if SSL_CONN_CONFIG_verifyhost != 0
    {
        ret = wolfSSL_check_domain_name((*backend).wolf_handle, hostname);
        if ret == WOLFSSL_FAILURE as libc::c_int {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    ret = wolfSSL_connect((*backend).wolf_handle);
    #[cfg(OPENSSL_EXTRA)]
    if Curl_tls_keylog_enabled() {
        if ret == WOLFSSL_SUCCESS as libc::c_int
            || wolfSSL_want_read((*backend).wolf_handle) == 0
                && wolfSSL_want_write((*backend).wolf_handle) == 0
        {
            wolfssl_log_tls12_secret((*backend).wolf_handle);
            wolfSSL_FreeArrays((*backend).wolf_handle);
        }
    }
    if ret != 1 as libc::c_int {
        let mut error_buffer: [libc::c_char; 80] = [0; 80];
        let mut detail: libc::c_int = wolfSSL_get_error((*backend).wolf_handle, ret);
        if WOLFSSL_ERROR_WANT_READ as libc::c_int == detail {
            (*connssl).connecting_state = ssl_connect_2_reading;
            return CURLE_OK;
        } else {
            if WOLFSSL_ERROR_WANT_WRITE as libc::c_int == detail {
                (*connssl).connecting_state = ssl_connect_2_writing;
                return CURLE_OK;
            } else {
                if (DOMAIN_NAME_MISMATCH as libc::c_int == detail) {
                    Curl_failf(
                        data,
                        b" subject alt name(s) or common name do not match \"%s\"\0"
                            as *const u8 as *const libc::c_char,
                        dispname,
                    );
                    return CURLE_PEER_FAILED_VERIFICATION;  
                }   
                else { 
                    #[cfg(LIBWOLFSSL_VERSION_HEX_GT_0X02007000)]
                    let LIBWOLFSSL_VERSION_HEX_GT_0X02007000_flag = true;
                    #[cfg(not(LIBWOLFSSL_VERSION_HEX_GT_0X02007000))]
                    let LIBWOLFSSL_VERSION_HEX_GT_0X02007000_flag = false;
                    #[cfg(not(CURL_DISABLE_PROXY))]
                    let  SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                    #[cfg(CURL_DISABLE_PROXY)]
                    let  SSL_CONN_CONFIG_verifypeer = ((*conn).ssl_config).verifypeer();
                    if (ASN_NO_SIGNER_E as libc::c_int == detail)
                       &&  LIBWOLFSSL_VERSION_HEX_GT_0X02007000_flag{
                        if SSL_CONN_CONFIG_verifypeer != 0
                        {
                            Curl_failf(
                                data,
                                b" CA signer not available for verification\0" as *const u8
                                    as *const libc::c_char,
                            );
                            return CURLE_SSL_CACERT_BADFILE;
                        } else {
                            Curl_infof(
                                data,
                                b"CA signer not available for verification, continuing anyway\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        }
                    } else {
                        Curl_failf(
                            data,
                            b"SSL_connect failed with error %d: %s\0" as *const u8
                                as *const libc::c_char,
                            detail,
                            wolfSSL_ERR_error_string(
                                detail as libc::c_ulong,
                                error_buffer.as_mut_ptr(),
                            ),
                        );
                        return CURLE_SSL_CONNECT_ERROR;
                    }
                }
            }
        }
    }
    if !pinnedpubkey.is_null() {
        if cfg!(KEEP_PEER_CERT){
            let mut x509: *mut X509 = 0 as *mut X509;
            let mut x509_der: *const libc::c_char = 0 as *const libc::c_char;
            let mut x509_der_len: libc::c_int = 0;
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
            x509 = wolfSSL_get_peer_certificate((*backend).wolf_handle);
            if x509.is_null() {
                Curl_failf(
                    data,
                    b"SSL: failed retrieving server certificate\0" as *const u8
                        as *const libc::c_char,
                );
                return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
            }
            x509_der = wolfSSL_X509_get_der(x509, &mut x509_der_len) as *const libc::c_char;
            if x509_der.is_null() {
                Curl_failf(
                    data,
                    b"SSL: failed retrieving ASN.1 server certificate\0" as *const u8
                        as *const libc::c_char,
                );
                return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
            }
            memset(
                &mut x509_parsed as *mut Curl_X509certificate as *mut libc::c_void,
                0 as libc::c_int,
                ::std::mem::size_of::<Curl_X509certificate>() as libc::c_ulong,
            );
            if Curl_parseX509(
                &mut x509_parsed,
                x509_der,
                x509_der.offset(x509_der_len as isize),
            ) != 0
            {
                return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
            }
            pubkey = &mut x509_parsed.subjectPublicKeyInfo;
            if ((*pubkey).header).is_null() || (*pubkey).end <= (*pubkey).header {
                Curl_failf(
                    data,
                    b"SSL: failed retrieving public key from server certificate\0"
                        as *const u8 as *const libc::c_char,
                );
                return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
            }
            result = Curl_pin_peer_pubkey(
                data,
                pinnedpubkey,
                (*pubkey).header as *const libc::c_uchar,
                ((*pubkey).end).offset_from((*pubkey).header) as libc::c_long as size_t,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"SSL: public key does not match pinned public key!\0" as *const u8
                        as *const libc::c_char,
                );
                return result;
            }
        }else{
            Curl_failf(
                data,
                b"Library lacks pinning support built-in\0" as *const u8
                    as *const libc::c_char,
            );
            return CURLE_NOT_BUILT_IN;
        }
    }   
    (*connssl).connecting_state = ssl_connect_3;
    Curl_infof(
        data,
        b"SSL connection using %s / %s\0" as *const u8 as *const libc::c_char,
        wolfSSL_get_version((*backend).wolf_handle),
        wolfSSL_get_cipher_name((*backend).wolf_handle),
    );
    Curl_infof(
        data,
        b"SSL connected\0" as *const u8 as *const libc::c_char,
    );
    return CURLE_OK;
}
unsafe extern "C" fn wolfssl_connect_step3(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                                ((*data).set.proxy_ssl.primary).sessionid() as libc::c_int
                                            } else {
                                                ((*data).set.ssl.primary).sessionid() as libc::c_int
                                            };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_sessionid = ((*data).set.ssl.primary).sessionid();
    if SSL_SET_OPTION_primary_sessionid != 0
    {
        let mut incache: bool = false;
        let mut old_ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
        let mut our_ssl_sessionid: *mut SSL_SESSION = wolfSSL_get_session(
            (*backend).wolf_handle,
        );
        #[cfg(not(CURL_DISABLE_PROXY))]
        let mut isproxy: bool = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
            1 as libc::c_int
        } else {
            0 as libc::c_int
        } != 0;
        #[cfg(CURL_DISABLE_PROXY)]
        let mut isproxy: bool = if 0 as libc::c_int != 0 {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        } != 0;
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
                    Curl_infof(
                        data,
                        b"old SSL session ID is stale, removing\0" as *const u8
                            as *const libc::c_char,
                    );
                    Curl_ssl_delsessionid(data, old_ssl_sessionid);
                    incache = 0 as libc::c_int != 0;
                }
            }
            if !incache {
                result = Curl_ssl_addsessionid(
                    data,
                    conn,
                    isproxy,
                    our_ssl_sessionid as *mut libc::c_void,
                    0 as libc::c_int as size_t,
                    sockindex,
                );
                if result as u64 != 0 {
                    Curl_ssl_sessionid_unlock(data);
                    Curl_failf(
                        data,
                        b"failed to store ssl session\0" as *const u8
                            as *const libc::c_char,
                    );
                    return result;
                }
            }
            Curl_ssl_sessionid_unlock(data);
        }
    }
    (*connssl).connecting_state = ssl_connect_done;
    return result;
}
unsafe extern "C" fn wolfssl_send(
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
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut error_buffer: [libc::c_char; 80] = [0; 80];
    let mut memlen: libc::c_int = if len > 2147483647 as libc::c_int as size_t {
        2147483647 as libc::c_int
    } else {
        len as libc::c_int
    };
    let mut rc: libc::c_int = 0;
    wolfSSL_ERR_clear_error();
    rc = wolfSSL_write((*backend).wolf_handle, mem, memlen);
    if rc <= 0 as libc::c_int {
        let mut err: libc::c_int = wolfSSL_get_error((*backend).wolf_handle, rc);
        match err {
            2 | 3 => {
                *curlcode = CURLE_AGAIN;
                return -(1 as libc::c_int) as ssize_t;
            }
            _ => {
                Curl_failf(
                    data,
                    b"SSL write: %s, errno %d\0" as *const u8 as *const libc::c_char,
                    wolfSSL_ERR_error_string(
                        err as libc::c_ulong,
                        error_buffer.as_mut_ptr(),
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
unsafe extern "C" fn wolfssl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if !((*backend).wolf_handle).is_null() {
        let mut buf: [libc::c_char; 32] = [0; 32];
        wolfSSL_read(
            (*backend).wolf_handle,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as libc::c_int,
        );
        wolfSSL_shutdown((*backend).wolf_handle);
        wolfSSL_free((*backend).wolf_handle);
        let ref mut fresh4 = (*backend).wolf_handle;
        *fresh4 = 0 as *mut WOLFSSL;
    }
    if !((*backend).ctx).is_null() {
        wolfSSL_CTX_free((*backend).ctx);
        let ref mut fresh5 = (*backend).ctx;
        *fresh5 = 0 as *mut SSL_CTX;
    }
}
unsafe extern "C" fn wolfssl_recv(
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
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut error_buffer: [libc::c_char; 80] = [0; 80];
    let mut buffsize: libc::c_int = if buffersize > 2147483647 as libc::c_int as size_t {
        2147483647 as libc::c_int
    } else {
        buffersize as libc::c_int
    };
    let mut nread: libc::c_int = 0;
    wolfSSL_ERR_clear_error();
    nread = wolfSSL_read((*backend).wolf_handle, buf as *mut libc::c_void, buffsize);
    if nread < 0 as libc::c_int {
        let mut err: libc::c_int = wolfSSL_get_error((*backend).wolf_handle, nread);
        match err {
            6 => {}
            2 | 3 => {
                *curlcode = CURLE_AGAIN;
                return -(1 as libc::c_int) as ssize_t;
            }
            _ => {
                Curl_failf(
                    data,
                    b"SSL read: %s, errno %d\0" as *const u8 as *const libc::c_char,
                    wolfSSL_ERR_error_string(
                        err as libc::c_ulong,
                        error_buffer.as_mut_ptr(),
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
unsafe extern "C" fn wolfssl_session_free(mut ptr: *mut libc::c_void) {}
unsafe extern "C" fn wolfssl_version(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
) -> size_t {
    return curl_msnprintf(
        buffer,
        size,
        b"wolfSSL/%s\0" as *const u8 as *const libc::c_char,
        wolfSSL_lib_version(),
    ) as size_t;
}
unsafe extern "C" fn wolfssl_init() -> libc::c_int {
    #[cfg(OPENSSL_EXTRA)]
    Curl_tls_keylog_open();
    return (wolfSSL_Init() == WOLFSSL_SUCCESS as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn wolfssl_cleanup() {
    wolfSSL_Cleanup();
    if cfg!(OPENSSL_EXTRA){
        Curl_tls_keylog_close();
    }
}
unsafe extern "C" fn wolfssl_data_pending(
    mut conn: *const connectdata,
    mut connindex: libc::c_int,
) -> bool {
    let mut connssl: *const ssl_connect_data = &*((*conn).ssl)
        .as_ptr()
        .offset(connindex as isize) as *const ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if !((*backend).wolf_handle).is_null() {
        return if 0 as libc::c_int != wolfSSL_pending((*backend).wolf_handle) {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        } != 0
    } else {
        return 0 as libc::c_int != 0
    };
}
unsafe extern "C" fn wolfssl_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> libc::c_int {
    let mut retval: libc::c_int = 0 as libc::c_int;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if !((*backend).wolf_handle).is_null() {
        wolfSSL_ERR_clear_error();
        wolfSSL_free((*backend).wolf_handle);
        let ref mut fresh6 = (*backend).wolf_handle;
        *fresh6 = 0 as *mut WOLFSSL;
    }
    return retval;
}
unsafe extern "C" fn wolfssl_connect_common(
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
        let timeout_ms: timediff_t = Curl_timeleft(
            data,
            0 as *mut curltime,
            1 as libc::c_int != 0,
        );
        if timeout_ms < 0 as libc::c_int as libc::c_long {
            Curl_failf(
                data,
                b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OPERATION_TIMEDOUT;
        }
        result = wolfssl_connect_step1(data, conn, sockindex);
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
        let timeout_ms_0: timediff_t = Curl_timeleft(
            data,
            0 as *mut curltime,
            1 as libc::c_int != 0,
        );
        if timeout_ms_0 < 0 as libc::c_int as libc::c_long {
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
                    timeout_ms_0
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
        result = wolfssl_connect_step2(data, conn, sockindex);
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
        result = wolfssl_connect_step3(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if ssl_connect_done as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        (*connssl).state = ssl_connection_complete;
        let ref mut fresh7 = (*conn).recv[sockindex as usize];
        *fresh7 = Some(wolfssl_recv as Curl_recv);
        let ref mut fresh8 = (*conn).send[sockindex as usize];
        *fresh8 = Some(wolfssl_send as Curl_send);
        *done = 1 as libc::c_int != 0;
    } else {
        *done = 0 as libc::c_int != 0;
    }
    (*connssl).connecting_state = ssl_connect_1;
    return CURLE_OK;
}
unsafe extern "C" fn wolfssl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    return wolfssl_connect_common(data, conn, sockindex, 1 as libc::c_int != 0, done);
}
unsafe extern "C" fn wolfssl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut done: bool = 0 as libc::c_int != 0;
    result = wolfssl_connect_common(
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
unsafe extern "C" fn wolfssl_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut libc::c_uchar,
    mut length: size_t,
) -> CURLcode {
    let mut rng: WC_RNG = WC_RNG {
        seed: OS_Seed { fd: 0 },
        heap: 0 as *mut libc::c_void,
        drbg: 0 as *mut DRBG,
        status: 0,
    };
    if wc_InitRng(&mut rng) != 0 {
        return CURLE_FAILED_INIT;
    }
    if length
        > (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint) as libc::c_ulong
    {
        return CURLE_FAILED_INIT;
    }
    if wc_RNG_GenerateBlock(&mut rng, entropy, length as libc::c_uint) != 0 {
        return CURLE_FAILED_INIT;
    }
    if wc_FreeRng(&mut rng) != 0 {
        return CURLE_FAILED_INIT;
    }
    return CURLE_OK;
}
unsafe extern "C" fn wolfssl_sha256sum(
    mut tmp: *const libc::c_uchar,
    mut tmplen: size_t,
    mut sha256sum: *mut libc::c_uchar,
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
    wc_InitSha256(&mut SHA256pw);
    wc_Sha256Update(&mut SHA256pw, tmp, tmplen as word32);
    wc_Sha256Final(&mut SHA256pw, sha256sum);
    return CURLE_OK;
}
unsafe extern "C" fn wolfssl_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return (*backend).wolf_handle as *mut libc::c_void;
}
#[no_mangle]
pub static mut Curl_ssl_wolfssl: Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_WOLFSSL,
                    name: b"WolfSSL\0" as *const u8 as *const libc::c_char,
                };
                init
            },           
            supports: ((1 as libc::c_int) << 2 as libc::c_int
                | (1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint,
            sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>()
                as libc::c_ulong,
            init: Some(wolfssl_init as unsafe extern "C" fn() -> libc::c_int),
            cleanup: Some(wolfssl_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(
                wolfssl_version
                    as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t,
            ),
            check_cxn: Some(
                Curl_none_check_cxn
                    as unsafe extern "C" fn(*mut connectdata) -> libc::c_int,
            ),
            shut_down: Some(
                wolfssl_shutdown
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            data_pending: Some(
                wolfssl_data_pending
                    as unsafe extern "C" fn(*const connectdata, libc::c_int) -> bool,
            ),
            random: Some(
                wolfssl_random
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
                wolfssl_connect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> CURLcode,
            ),
            connect_nonblocking: Some(
                wolfssl_connect_nonblocking
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
                wolfssl_get_internals
                    as unsafe extern "C" fn(
                        *mut ssl_connect_data,
                        CURLINFO,
                    ) -> *mut libc::c_void,
            ),
            close_one: Some(
                wolfssl_close
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
                wolfssl_session_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
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
            sha256sum: Some(
                wolfssl_sha256sum
                    as unsafe extern "C" fn(
                        *const libc::c_uchar,
                        size_t,
                        *mut libc::c_uchar,
                        size_t,
                    ) -> CURLcode,
            ),
            associate_connection: None,
            disassociate_connection: None,
        };
        init
    }
};