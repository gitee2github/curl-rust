use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
use crate::src::vtls::vtls::*;

/*
todo
需要不开选项 MBEDTLS_ERROR_C 再翻译一次
#ifndef MBEDTLS_ERROR_C
#define mbedtls_strerror(a,b,c) b[0] = 0
#endif
*/

//有一个漏翻译的
#[cfg(THREADING_SUPPORT)]
static mut ts_entropy: mbedtls_entropy_context = mbedtls_entropy_context {
    accumulator_started: 0,
    accumulator: mbedtls_sha512_context {
        total: [0; 2],
        state: [0; 8],
        buffer: [0; 128],
        is384: 0,
    },
    source_count: 0,
    source: [mbedtls_entropy_source_state {
        f_source: None,
        p_source: 0 as *const libc::c_void as *mut libc::c_void,
        size: 0,
        threshold: 0,
        strong: 0,
    }; 20],
    havege_data: mbedtls_havege_state {
        PT1: 0,
        PT2: 0,
        offset: [0; 2],
        pool: [0; 1024],
        WALK: [0; 8192],
    },
    mutex: mbedtls_threading_mutex_t {
        mutex: pthread_mutex_t {
            __data: __pthread_mutex_s {
                __lock: 0,
                __count: 0,
                __owner: 0,
                __nusers: 0,
                __kind: 0,
                __spins: 0,
                __elision: 0,
                __list: __pthread_list_t {
                    __prev: 0 as *const __pthread_internal_list
                        as *mut __pthread_internal_list,
                    __next: 0 as *const __pthread_internal_list
                        as *mut __pthread_internal_list,
                },
            },
        },
        is_valid: 0,
    },
};
#[cfg(THREADING_SUPPORT)]
static mut entropy_init_initialized: libc::c_int = 0 as libc::c_int;
#[cfg(THREADING_SUPPORT)]
unsafe extern "C" fn entropy_init_mutex(mut ctx: *mut mbedtls_entropy_context) {
    Curl_mbedtlsthreadlock_lock_function(0 as libc::c_int);
    if entropy_init_initialized == 0 as libc::c_int {
        mbedtls_entropy_init(ctx);
        entropy_init_initialized = 1 as libc::c_int;
    }
    Curl_mbedtlsthreadlock_unlock_function(0 as libc::c_int);
}
#[cfg(THREADING_SUPPORT)]
unsafe extern "C" fn entropy_func_mutex(
    mut data: *mut libc::c_void,
    mut output: *mut libc::c_uchar,
    mut len: size_t,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    Curl_mbedtlsthreadlock_lock_function(1 as libc::c_int);
    ret = mbedtls_entropy_func(data, output, len);
    Curl_mbedtlsthreadlock_unlock_function(1 as libc::c_int);
    return ret;
}
// 132 done
// MBEDTLS_DEBUG 暂不添加

/* 
todo
#ifdef USE_NGHTTP2
#  undef HAS_ALPN
#  ifdef MBEDTLS_SSL_ALPN
#    define HAS_ALPN
#  endif
#endif
*/
// 内部没有宏
static mut mbedtls_x509_crt_profile_fr: mbedtls_x509_crt_profile = {
    let mut init = mbedtls_x509_crt_profile {
        allowed_mds: ((1 as libc::c_int)
            << MBEDTLS_MD_SHA1 as libc::c_int - 1 as libc::c_int
            | (1 as libc::c_int)
                << MBEDTLS_MD_RIPEMD160 as libc::c_int - 1 as libc::c_int
            | (1 as libc::c_int) << MBEDTLS_MD_SHA224 as libc::c_int - 1 as libc::c_int
            | (1 as libc::c_int) << MBEDTLS_MD_SHA256 as libc::c_int - 1 as libc::c_int
            | (1 as libc::c_int) << MBEDTLS_MD_SHA384 as libc::c_int - 1 as libc::c_int
            | (1 as libc::c_int) << MBEDTLS_MD_SHA512 as libc::c_int - 1 as libc::c_int)
            as uint32_t,
        allowed_pks: 0xfffffff as libc::c_int as uint32_t,
        allowed_curves: 0xfffffff as libc::c_int as uint32_t,
        rsa_min_bitlen: 1024 as libc::c_int as uint32_t,
    };
    init
};

// done
unsafe extern "C" fn mbedtls_version_from_curl(
    mut mbedver: *mut libc::c_int,
    mut version: libc::c_long,
) -> CURLcode {
    // 189-done
    // #if MBEDTLS_VERSION_NUMBER >= 0x03000000
    if cfg!(MBEDTLS_VERSION_NUMBER_GT_0X03000000){
        // todo
    }   
    else{
        match version {
            4 => {
                *mbedver = 1 as libc::c_int;
                return CURLE_OK;
            }
            5 => {
                *mbedver = 2 as libc::c_int;
                return CURLE_OK;
            }
            6 => {
                *mbedver = 3 as libc::c_int;
                return CURLE_OK;
            }
            7 | _ => {}
        }
    }
    return CURLE_SSL_CONNECT_ERROR;
}

// done
unsafe extern "C" fn set_ssl_version_min_max(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut mbedtls_ver_min: libc::c_int = 1 as libc::c_int;
    let mut mbedtls_ver_max: libc::c_int = 1 as libc::c_int;
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
    let mut ssl_version: libc::c_long = SSL_CONN_CONFIG_version;
    let mut ssl_version_max: libc::c_long = SSL_CONN_CONFIG_version;
    let mut result: CURLcode = CURLE_OK;
    match ssl_version {
        0 | 1 => {
            ssl_version = CURL_SSLVERSION_TLSv1_0 as libc::c_int as libc::c_long;
        }
        _ => {}
    }
    match ssl_version_max {
        0 | 65536 => {
            ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2 as libc::c_int as libc::c_long;
        }
        _ => {}
    }
    result = mbedtls_version_from_curl(&mut mbedtls_ver_min, ssl_version);
    if result as u64 != 0 {
        Curl_failf(
            data,
            b"unsupported min version passed via CURLOPT_SSLVERSION\0" as *const u8
                as *const libc::c_char,
        );
        return result;
    }
    result = mbedtls_version_from_curl(
        &mut mbedtls_ver_max,
        ssl_version_max >> 16 as libc::c_int,
    );
    if result as u64 != 0 {
        Curl_failf(
            data,
            b"unsupported max version passed via CURLOPT_SSLVERSION\0" as *const u8
                as *const libc::c_char,
        );
        return result;
    }
    mbedtls_ssl_conf_min_version(
        &mut (*backend).config,
        3 as libc::c_int,
        mbedtls_ver_min,
    );
    mbedtls_ssl_conf_max_version(
        &mut (*backend).config,
        3 as libc::c_int,
        mbedtls_ver_max,
    );
    return result;
}

// done
unsafe extern "C" fn mbed_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let ssl_cafile: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int
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
        (*conn).proxy_ssl_config.CAfile
    } else {
        (*conn).ssl_config.CAfile
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let ssl_cafile: *const libc::c_char = (*conn).ssl_config.CAfile;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let verifypeer: bool = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    } != 0;
    #[cfg(CURL_DISABLE_PROXY)]
    let verifypeer: bool = ((*conn).ssl_config).verifypeer() != 0;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let ssl_capath: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int
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
        (*conn).proxy_ssl_config.CApath
    } else {
        (*conn).ssl_config.CApath
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let ssl_capath: *const libc::c_char = (*conn).ssl_config.CApath;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let ssl_cert: *mut libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let ssl_cert: *mut libc::c_char = (*data).set.ssl.primary.clientcert;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut ssl_cert_blob: *const curl_blob = if CURLPROXY_HTTPS as libc::c_int
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
        (*data).set.proxy_ssl.primary.cert_blob
    } else {
        (*data).set.ssl.primary.cert_blob
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut ssl_cert_blob: *const curl_blob = (*data).set.ssl.primary.cert_blob;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let ssl_crlfile: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int
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
        (*data).set.proxy_ssl.CRLfile
    } else {
        (*data).set.ssl.CRLfile
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let ssl_crlfile: *const libc::c_char = (*data).set.ssl.CRLfile;
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
    // 280-282
    /*
    #ifndef CURL_DISABLE_VERBOSE_STRINGS
      const long int port = SSL_HOST_PORT();
    #endif
    */
    #[cfg(all(not(CURL_DISABLE_VERBOSE_STRINGS), not(CURL_DISABLE_PROXY)))]
    let port: libc::c_long = (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
        (*conn).port
    } else {
        (*conn).remote_port
    }) as libc::c_long;
    #[cfg(all(not(CURL_DISABLE_VERBOSE_STRINGS), CURL_DISABLE_PROXY))]
    let port: libc::c_long = (*conn).remote_port as libc::c_long;

    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut errorbuf: [libc::c_char; 128] = [0; 128];
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
    if SSL_CONN_CONFIG_version == CURL_SSLVERSION_SSLv2 as libc::c_int as libc::c_long
        || SSL_CONN_CONFIG_version == CURL_SSLVERSION_SSLv3 as libc::c_int as libc::c_long
    {
        Curl_failf(
            data,
            b"Not supported SSL version\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_NOT_BUILT_IN;
    }
    // 292-314
    match () {
        #[cfg(THREADING_SUPPORT)]
        _ => {
            entropy_init_mutex(&mut ts_entropy);
            mbedtls_ctr_drbg_init(&mut (*backend).ctr_drbg);
            ret = mbedtls_ctr_drbg_seed(
                &mut (*backend).ctr_drbg,
                Some(
                    entropy_func_mutex
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *mut libc::c_uchar,
                            size_t,
                        ) -> libc::c_int,
                ),
                &mut ts_entropy as *mut mbedtls_entropy_context as *mut libc::c_void,
                0 as *const libc::c_uchar,
                0 as libc::c_int as size_t,
            );
            if ret != 0 {
                mbedtls_strerror(
                    ret,
                    errorbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                );
                Curl_failf(
                    data,
                    b"Failed - mbedTLS: ctr_drbg_init returned (-0x%04X) %s\0" as *const u8
                        as *const libc::c_char,
                    -ret,
                    errorbuf.as_mut_ptr(),
                );
            }
        }
        #[cfg(not(THREADING_SUPPORT))]
        _ => { }
    }
    // if cfg!(THREADING_SUPPORT){
    //     entropy_init_mutex(&mut ts_entropy);
    //     mbedtls_ctr_drbg_init(&mut (*backend).ctr_drbg);
    //     ret = mbedtls_ctr_drbg_seed(
    //         &mut (*backend).ctr_drbg,
    //         Some(
    //             entropy_func_mutex
    //                 as unsafe extern "C" fn(
    //                     *mut libc::c_void,
    //                     *mut libc::c_uchar,
    //                     size_t,
    //                 ) -> libc::c_int,
    //         ),
    //         &mut ts_entropy as *mut mbedtls_entropy_context as *mut libc::c_void,
    //         0 as *const libc::c_uchar,
    //         0 as libc::c_int as size_t,
    //     );
    //     if ret != 0 {
    //         mbedtls_strerror(
    //             ret,
    //             errorbuf.as_mut_ptr(),
    //             ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
    //         );
    //         Curl_failf(
    //             data,
    //             b"Failed - mbedTLS: ctr_drbg_init returned (-0x%04X) %s\0" as *const u8
    //                 as *const libc::c_char,
    //             -ret,
    //             errorbuf.as_mut_ptr(),
    //         );
    //     }
    // }
    // else{
    //     // todo
    //     // 不开选项 THREADING_SUPPORT 翻译
    // }
    // -375
    mbedtls_x509_crt_init(&mut (*backend).cacert);
    if !ssl_cafile.is_null() {
        ret = mbedtls_x509_crt_parse_file(&mut (*backend).cacert, ssl_cafile);
        if ret < 0 as libc::c_int {
            mbedtls_strerror(
                ret,
                errorbuf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
            Curl_failf(
                data,
                b"Error reading ca cert file %s - mbedTLS: (-0x%04X) %s\0" as *const u8
                    as *const libc::c_char,
                ssl_cafile,
                -ret,
                errorbuf.as_mut_ptr(),
            );
            if verifypeer {
                return CURLE_SSL_CACERT_BADFILE;
            }
        }
    }
    if !ssl_capath.is_null() {
        ret = mbedtls_x509_crt_parse_path(&mut (*backend).cacert, ssl_capath);
        if ret < 0 as libc::c_int {
            mbedtls_strerror(
                ret,
                errorbuf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
            Curl_failf(
                data,
                b"Error reading ca cert path %s - mbedTLS: (-0x%04X) %s\0" as *const u8
                    as *const libc::c_char,
                ssl_capath,
                -ret,
                errorbuf.as_mut_ptr(),
            );
            if verifypeer {
                return CURLE_SSL_CACERT_BADFILE;
            }
        }
    }
    mbedtls_x509_crt_init(&mut (*backend).clicert);
    if !ssl_cert.is_null() {
        ret = mbedtls_x509_crt_parse_file(&mut (*backend).clicert, ssl_cert);
        if ret != 0 {
            mbedtls_strerror(
                ret,
                errorbuf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
            Curl_failf(
                data,
                b"Error reading client cert file %s - mbedTLS: (-0x%04X) %s\0"
                    as *const u8 as *const libc::c_char,
                ssl_cert,
                -ret,
                errorbuf.as_mut_ptr(),
            );
            return CURLE_SSL_CERTPROBLEM;
        }
    }
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

    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_key_blob = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                (*data).set.proxy_ssl.key_blob
                            } else {
                                (*data).set.ssl.key_blob
                            };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_key_blob = (*data).set.ssl.key_blob;
    
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_key_passwd = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                        (*data).set.proxy_ssl.key_passwd
                                    } else {
                                        (*data).set.ssl.key_passwd
                                    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_key_passwd = (*data).set.ssl.key_passwd;

    if !ssl_cert_blob.is_null() {
        let mut blob_data: *const libc::c_uchar = (*ssl_cert_blob).data
            as *const libc::c_uchar;
        ret = mbedtls_x509_crt_parse(
            &mut (*backend).clicert,
            blob_data,
            (*ssl_cert_blob).len,
        );
        if ret != 0 {
            mbedtls_strerror(
                ret,
                errorbuf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
            Curl_failf(
                data,
                b"Error reading private key %s - mbedTLS: (-0x%04X) %s\0" as *const u8
                    as *const libc::c_char,
                SSL_SET_OPTION_key,
                -ret,
                errorbuf.as_mut_ptr(),
            );
            return CURLE_SSL_CERTPROBLEM;
        }
    }
    mbedtls_pk_init(&mut (*backend).pk);
    // 377 - if(SSL_SET_OPTION(key) || SSL_SET_OPTION(key_blob)) {
    if !(SSL_SET_OPTION_key).is_null() || !(SSL_SET_OPTION_key_blob).is_null(){ // 377 - if(SSL_SET_OPTION(key) || SSL_SET_OPTION(key_blob)) {
        // 378 - if(SSL_SET_OPTION(key)) {
        if !(SSL_SET_OPTION_key).is_null()
        { // 378 - if(SSL_SET_OPTION(key)) {
            ret = mbedtls_pk_parse_keyfile(
                &mut (*backend).pk,
                SSL_SET_OPTION_key,
                SSL_SET_OPTION_key_passwd,
            );
            if ret != 0 {
                mbedtls_strerror(
                    ret,
                    errorbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                );
                Curl_failf(
                    data,
                    b"Error reading private key %s - mbedTLS: (-0x%04X) %s\0"
                        as *const u8 as *const libc::c_char,
                    SSL_SET_OPTION_key,
                    -ret,
                    errorbuf.as_mut_ptr(),
                );
                return CURLE_SSL_CERTPROBLEM;
            }
        } else {
            let mut ssl_key_blob: *const curl_blob = SSL_SET_OPTION_key_blob;
            let mut key_data: *const libc::c_uchar = (*ssl_key_blob).data
                as *const libc::c_uchar;
            let mut passwd: *const libc::c_char = SSL_SET_OPTION_key_passwd;
// 401-done
// #if MBEDTLS_VERSION_NUMBER >= 0x03000000
            if cfg!(MBEDTLS_VERSION_NUMBER_GT_0X03000000){
                // todo-402
                /* 
                todo
                ret = mbedtls_pk_parse_key(&backend->pk, key_data, ssl_key_blob->len,
                                        (const unsigned char *)passwd,
                                        passwd ? strlen(passwd) : 0,
                                        mbedtls_ctr_drbg_random,
                                        &backend->ctr_drbg);
                */
            }    
            else{
                ret = mbedtls_pk_parse_key(
                    &mut (*backend).pk,
                    key_data,
                    (*ssl_key_blob).len,
                    passwd as *const libc::c_uchar,
                    if !passwd.is_null() {
                        strlen(passwd)
                    } else {
                        0 as libc::c_int as libc::c_ulong
                    },
                );
            }    
            
            if ret != 0 {
                    mbedtls_strerror(
                        ret,
                        errorbuf.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                    );
                    Curl_failf(
                        data,
                        b"Error parsing private key - mbedTLS: (-0x%04X) %s\0" as *const u8
                            as *const libc::c_char,
                        -ret,
                        errorbuf.as_mut_ptr(),
                    );
                    return CURLE_SSL_CERTPROBLEM;
                }           
        }        
        if ret == 0 as libc::c_int
            && !(mbedtls_pk_can_do(&mut (*backend).pk, MBEDTLS_PK_RSA) != 0
                || mbedtls_pk_can_do(&mut (*backend).pk, MBEDTLS_PK_ECKEY) != 0)
        {
            ret = -(0x3f00 as libc::c_int);
        }
    }        

    mbedtls_x509_crl_init(&mut (*backend).crl);
    if !ssl_crlfile.is_null() {
        ret = mbedtls_x509_crl_parse_file(&mut (*backend).crl, ssl_crlfile);
        if ret != 0 {
            mbedtls_strerror(
                ret,
                errorbuf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
            Curl_failf(
                data,
                b"Error reading CRL file %s - mbedTLS: (-0x%04X) %s\0" as *const u8
                    as *const libc::c_char,
                ssl_crlfile,
                -ret,
                errorbuf.as_mut_ptr(),
            );
            return CURLE_SSL_CRL_BADFILE;
        }
    }
    Curl_infof(
        data,
        b"mbedTLS: Connecting to %s:%ld\0" as *const u8 as *const libc::c_char,
        hostname,
        port,
    );
    mbedtls_ssl_config_init(&mut (*backend).config);
    mbedtls_ssl_init(&mut (*backend).ssl);
    if mbedtls_ssl_setup(&mut (*backend).ssl, &mut (*backend).config) != 0 {
        Curl_failf(
            data,
            b"mbedTLS: ssl_init failed\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    ret = mbedtls_ssl_config_defaults(
        &mut (*backend).config,
        0 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
    );
    if ret != 0 {
        Curl_failf(
            data,
            b"mbedTLS: ssl_config failed\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    mbedtls_ssl_conf_cert_profile(&mut (*backend).config, &mbedtls_x509_crt_profile_fr);
    match SSL_CONN_CONFIG_version {
    // 467-done
    // #if MBEDTLS_VERSION_NUMBER < 0x03000000
    0 | 1 => {
        #[cfg(MBEDTLS_VERSION_NUMBER_LT_0X03000000)]
        mbedtls_ssl_conf_min_version(
            &mut (*backend).config,
            3 as libc::c_int,
            1 as libc::c_int,
        );
        #[cfg(MBEDTLS_VERSION_NUMBER_LT_0X03000000)]
        Curl_infof(
            data,
            b"mbedTLS: Set min SSL version to TLS 1.0\0" as *const u8
                as *const libc::c_char,
        );
    } 
// 471        
        4 | 5 | 6 | 7 => {
            let mut result: CURLcode = set_ssl_version_min_max(data, conn, sockindex);
            if result as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
                return result;
            }
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
    mbedtls_ssl_conf_authmode(&mut (*backend).config, 1 as libc::c_int);
    mbedtls_ssl_conf_rng(
        &mut (*backend).config,
        Some(
            mbedtls_ctr_drbg_random
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_uchar,
                    size_t,
                ) -> libc::c_int,
        ),
        &mut (*backend).ctr_drbg as *mut mbedtls_ctr_drbg_context as *mut libc::c_void,
    );
    mbedtls_ssl_set_bio(
        &mut (*backend).ssl,
        &mut *((*conn).sock).as_mut_ptr().offset(sockindex as isize)
            as *mut curl_socket_t as *mut libc::c_void,
        Some(
            mbedtls_net_send
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_uchar,
                    size_t,
                ) -> libc::c_int,
        ),
        Some(
            mbedtls_net_recv
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_uchar,
                    size_t,
                ) -> libc::c_int,
        ),
        None,
    );
    mbedtls_ssl_conf_ciphersuites(
        &mut (*backend).config,
        mbedtls_ssl_list_ciphersuites(),
    );
    // 499
    #[cfg(MBEDTLS_SSL_RENEGOTIATION)]
        mbedtls_ssl_conf_renegotiation(&mut (*backend).config, 1 as libc::c_int);
    // 504
    #[cfg(MBEDTLS_SSL_SESSION_TICKETS)]
        mbedtls_ssl_conf_session_tickets(&mut (*backend).config, 0 as libc::c_int);
    
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

    if SSL_SET_OPTION_primary_sessionid != 0{
        let mut old_session: *mut libc::c_void = 0 as *mut libc::c_void;
        Curl_ssl_sessionid_lock(data);
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_IS_PROXY_null = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                } != 0 ;
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_IS_PROXY_null = if 0 as libc::c_int != 0 { 1 as libc::c_int } else { 0 as libc::c_int } != 0 ;
        if !Curl_ssl_getsessionid(
            data,
            conn,
            SSL_IS_PROXY_null,
            &mut old_session,
            0 as *mut size_t,
            sockindex,
        ) {
            ret = mbedtls_ssl_set_session(
                &mut (*backend).ssl,
                old_session as *const mbedtls_ssl_session,
            );
            if ret != 0 {
                Curl_ssl_sessionid_unlock(data);
                Curl_failf(
                    data,
                    b"mbedtls_ssl_set_session returned -0x%x\0" as *const u8
                        as *const libc::c_char,
                    -ret,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            Curl_infof(
                data,
                b"mbedTLS re-using session\0" as *const u8 as *const libc::c_char,
            );
        }
        Curl_ssl_sessionid_unlock(data);
    }
    mbedtls_ssl_conf_ca_chain(
        &mut (*backend).config,
        &mut (*backend).cacert,
        &mut (*backend).crl,
    );
    if !(SSL_SET_OPTION_key).is_null() || !(SSL_SET_OPTION_key_blob).is_null(){
        mbedtls_ssl_conf_own_cert(
            &mut (*backend).config,
            &mut (*backend).clicert,
            &mut (*backend).pk,
        );
    }
    if mbedtls_ssl_set_hostname(&mut (*backend).ssl, hostname) != 0 {
        Curl_failf(
            data,
            b"couldn't set hostname in mbedTLS\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    // 544-done
    if cfg!(HAS_ALPN){
        if ((*conn).bits).tls_enable_alpn() != 0 {
            let mut p: *mut *const libc::c_char = &mut *((*backend).protocols)
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize) as *mut *const libc::c_char;
            #[cfg(USE_NGHTTP2)]
            if (*data).state.httpwant as libc::c_int >= CURL_HTTP_VERSION_2_0 as libc::c_int
            {
                let fresh0 = p;
                p = p.offset(1);
                *fresh0 = b"h2\0" as *const u8 as *const libc::c_char;
            }
            let fresh1 = p;
            p = p.offset(1);
            *fresh1 = b"http/1.1\0" as *const u8 as *const libc::c_char;
            *p = 0 as *const libc::c_char;
            if mbedtls_ssl_conf_alpn_protocols(
                &mut (*backend).config,
                &mut *((*backend).protocols).as_mut_ptr().offset(0 as libc::c_int as isize),
            ) != 0
            {
                Curl_failf(
                    data,
                    b"Failed setting ALPN protocols\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            p = &mut *((*backend).protocols).as_mut_ptr().offset(0 as libc::c_int as isize)
                as *mut *const libc::c_char;
            while !(*p).is_null() {
                Curl_infof(
                    data,
                    b"ALPN, offering %s\0" as *const u8 as *const libc::c_char,
                    *p,
                );
                p = p.offset(1);
            }
        }
    }
    if ((*data).set.ssl.fsslctx).is_some() {
        ret = (Some(((*data).set.ssl.fsslctx).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            data,
            &mut (*backend).config as *mut mbedtls_ssl_config as *mut libc::c_void,
            (*data).set.ssl.fsslctxp,
        ) as libc::c_int;
        if ret != 0 {
            Curl_failf(
                data,
                b"error signaled by ssl ctx callback\0" as *const u8
                    as *const libc::c_char,
            );
            return ret as CURLcode;
        }
    }
    (*connssl).connecting_state = ssl_connect_2;
    return CURLE_OK;
}

// done
unsafe extern "C" fn mbed_connect_step2(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut ret: libc::c_int = 0;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut peercert: *const mbedtls_x509_crt = 0 as *const mbedtls_x509_crt;
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
    let ref mut fresh2 = (*conn).recv[sockindex as usize];
    *fresh2 = Some(mbed_recv as Curl_recv);
    let ref mut fresh3 = (*conn).send[sockindex as usize];
    *fresh3 = Some(mbed_send as Curl_send);
    ret = mbedtls_ssl_handshake(&mut (*backend).ssl);
    if ret == -(0x6900 as libc::c_int) {
        (*connssl).connecting_state = ssl_connect_2_reading;
        return CURLE_OK;
    } else {
        if ret == -(0x6880 as libc::c_int) {
            (*connssl).connecting_state = ssl_connect_2_writing;
            return CURLE_OK;
        } else {
            if ret != 0 {
                let mut errorbuf: [libc::c_char; 128] = [0; 128];
                mbedtls_strerror(
                    ret,
                    errorbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                );
                Curl_failf(
                    data,
                    b"ssl_handshake returned - mbedTLS: (-0x%04X) %s\0" as *const u8
                        as *const libc::c_char,
                    -ret,
                    errorbuf.as_mut_ptr(),
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
        }
    }
    Curl_infof(
        data,
        b"mbedTLS: Handshake complete, cipher is %s\0" as *const u8
            as *const libc::c_char,
        mbedtls_ssl_get_ciphersuite(&mut (*backend).ssl),
    );
    ret = mbedtls_ssl_get_verify_result(&mut (*backend).ssl) as libc::c_int;
    #[cfg(not(CURL_DISABLE_PROXY))]
    if if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    } == 0
    {
        ret &= !(0x4 as libc::c_int);
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if ((*conn).ssl_config).verifyhost() == 0 {
        ret &= !(0x4 as libc::c_int);
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifyhost_1 = (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                    }) != 0;
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifyhost_1 = ((*conn).ssl_config).verifypeer() as libc::c_int != 0;
    if ret != 0 && SSL_CONN_CONFIG_verifyhost_1{
        if ret & 0x1 as libc::c_int != 0 {
            Curl_failf(
                data,
                b"Cert verify failed: BADCERT_EXPIRED\0" as *const u8
                    as *const libc::c_char,
            );
        } else if ret & 0x2 as libc::c_int != 0 {
            Curl_failf(
                data,
                b"Cert verify failed: BADCERT_REVOKED\0" as *const u8
                    as *const libc::c_char,
            );
        } else if ret & 0x4 as libc::c_int != 0 {
            Curl_failf(
                data,
                b"Cert verify failed: BADCERT_CN_MISMATCH\0" as *const u8
                    as *const libc::c_char,
            );
        } else if ret & 0x8 as libc::c_int != 0 {
            Curl_failf(
                data,
                b"Cert verify failed: BADCERT_NOT_TRUSTED\0" as *const u8
                    as *const libc::c_char,
            );
        } else if ret & 0x200 as libc::c_int != 0 {
            Curl_failf(
                data,
                b"Cert verify failed: BADCERT_FUTURE\0" as *const u8
                    as *const libc::c_char,
            );
        }
        return CURLE_PEER_FAILED_VERIFICATION;
    }
    peercert = mbedtls_ssl_get_peer_cert(&mut (*backend).ssl);
    if !peercert.is_null() && ((*data).set).verbose() as libc::c_int != 0 {
        let bufsize: size_t = 16384 as libc::c_int as size_t;
        let mut buffer: *mut libc::c_char = Curl_cmalloc
            .expect("non-null function pointer")(bufsize) as *mut libc::c_char;
        if buffer.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if mbedtls_x509_crt_info(
            buffer,
            bufsize,
            b"* \0" as *const u8 as *const libc::c_char,
            peercert,
        ) > 0 as libc::c_int
        {
            Curl_infof(
                data,
                b"Dumping cert info: %s\0" as *const u8 as *const libc::c_char,
                buffer,
            );
        } else {
            Curl_infof(
                data,
                b"Unable to dump certificate information\0" as *const u8
                    as *const libc::c_char,
            );
        }
        Curl_cfree.expect("non-null function pointer")(buffer as *mut libc::c_void);
    }
    if !pinnedpubkey.is_null() {
        let mut size: libc::c_int = 0;
        let mut result: CURLcode = CURLE_OK;
        let mut p: *mut mbedtls_x509_crt = 0 as *mut mbedtls_x509_crt;
        let mut pubkey: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
        // ******************************************************************
        // 674 - done
        // #if MBEDTLS_VERSION_NUMBER >= 0x03000000
        if cfg!(MBEDTLS_VERSION_NUMBER_GT_0X03000000){
            // todo
            // 暂不支持 MBEDTLS_VERSION_NUMBER >= 0x03000000
        }
        else{
            if peercert.is_null() || ((*peercert).raw.p).is_null()
                || (*peercert).raw.len == 0
            {
                Curl_failf(
                    data,
                    b"Failed due to missing peer certificate\0" as *const u8
                        as *const libc::c_char,
                );
                return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
            }       
        }
        // ******************************************************************     
        p = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(
            1 as libc::c_int as size_t,
            ::std::mem::size_of::<mbedtls_x509_crt>() as libc::c_ulong,
        ) as *mut mbedtls_x509_crt;
        if p.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        pubkey = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(
            (if 38 as libc::c_int + 2 as libc::c_int * 1024 as libc::c_int
                > 30 as libc::c_int
                    + 2 as libc::c_int
                        * ((521 as libc::c_int + 7 as libc::c_int) / 8 as libc::c_int)
            {
                38 as libc::c_int + 2 as libc::c_int * 1024 as libc::c_int
            } else {
                30 as libc::c_int
                    + 2 as libc::c_int
                        * ((521 as libc::c_int + 7 as libc::c_int) / 8 as libc::c_int)
            }) as size_t,
        ) as *mut libc::c_uchar;
        if pubkey.is_null() {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            mbedtls_x509_crt_init(p);
// *************************************************************************
// 701 - TODO
// #if MBEDTLS_VERSION_NUMBER >= 0x03000000
            if cfg!(MBEDTLS_VERSION_NUMBER_GT_0X03000000){
                // TODO
                // 尚不支持 MBEDTLS_VERSION_NUMBER >= 0x03000000
            }
            else{
                if mbedtls_x509_crt_parse_der(p, (*peercert).raw.p, (*peercert).raw.len) != 0
                {
                    Curl_failf(
                        data,
                        b"Failed copying peer certificate\0" as *const u8
                            as *const libc::c_char,
                    );
                    result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
                } else {
                    size = mbedtls_pk_write_pubkey_der(
                        &mut (*p).pk,
                        pubkey,
                        (if 38 as libc::c_int + 2 as libc::c_int * 1024 as libc::c_int
                            > 30 as libc::c_int
                                + 2 as libc::c_int
                                    * ((521 as libc::c_int + 7 as libc::c_int)
                                        / 8 as libc::c_int)
                        {
                            38 as libc::c_int + 2 as libc::c_int * 1024 as libc::c_int
                        } else {
                            30 as libc::c_int
                                + 2 as libc::c_int
                                    * ((521 as libc::c_int + 7 as libc::c_int)
                                        / 8 as libc::c_int)
                        }) as size_t,
                    ); 
                }
                if size <= 0 as libc::c_int {
                        Curl_failf(
                            data,
                            b"Failed copying public key from peer certificate\0" as *const u8
                                as *const libc::c_char,
                        );
                        result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
                } else {
                    result = Curl_pin_peer_pubkey(
                        data,
                        pinnedpubkey,
                        &mut *pubkey
                            .offset(
                                ((if 38 as libc::c_int
                                    + 2 as libc::c_int * 1024 as libc::c_int
                                    > 30 as libc::c_int
                                        + 2 as libc::c_int
                                            * ((521 as libc::c_int + 7 as libc::c_int)
                                                / 8 as libc::c_int)
                                {
                                    38 as libc::c_int + 2 as libc::c_int * 1024 as libc::c_int
                                } else {
                                    30 as libc::c_int
                                        + 2 as libc::c_int
                                            * ((521 as libc::c_int + 7 as libc::c_int)
                                                / 8 as libc::c_int)
                                }) - size) as isize,
                            ),
                        size as size_t,
                    );
                }
// *************************************************************************                      
            }
        }
        mbedtls_x509_crt_free(p);
        Curl_cfree.expect("non-null function pointer")(p as *mut libc::c_void);
        Curl_cfree.expect("non-null function pointer")(pubkey as *mut libc::c_void);
        if result as u64 != 0 {
            return result;
        }
    }
    // 738-763 todo
    if cfg!(HAS_ALPN){
        if ((*conn).bits).tls_enable_alpn() != 0 {
            let mut next_protocol: *const libc::c_char = mbedtls_ssl_get_alpn_protocol(
                &mut (*backend).ssl,
            );
            if !next_protocol.is_null() {
                Curl_infof(
                    data,
                    b"ALPN, server accepted to use %s\0" as *const u8 as *const libc::c_char,
                    next_protocol,
                );
                #[cfg(USE_NGHTTP2)]
                let USE_NGHTTP2_flag = true;
                #[cfg(not(USE_NGHTTP2))]
                let USE_NGHTTP2_flag = false;
                if strncmp(
                    next_protocol,
                    b"h2\0" as *const u8 as *const libc::c_char,
                    2 as libc::c_int as libc::c_ulong,
                ) == 0 && *next_protocol.offset(2 as libc::c_int as isize) == 0 && USE_NGHTTP2_flag
                {
                    (*conn).negnpn = CURL_HTTP_VERSION_2_0 as libc::c_int;
                } else if strncmp(
                        next_protocol,
                        b"http/1.1\0" as *const u8 as *const libc::c_char,
                        8 as libc::c_int as libc::c_ulong,
                    ) == 0 && *next_protocol.offset(8 as libc::c_int as isize) == 0
                    {
                    (*conn).negnpn = CURL_HTTP_VERSION_1_1 as libc::c_int;
                }
            } else {
                Curl_infof(
                    data,
                    b"ALPN, server did not agree to a protocol\0" as *const u8
                        as *const libc::c_char,
                );
            }
            Curl_multiuse_state(
                data,
                if (*conn).negnpn == CURL_HTTP_VERSION_2_0 as libc::c_int {
                    2 as libc::c_int
                } else {
                    -(1 as libc::c_int)
                },
            );
        }
    }    
    (*connssl).connecting_state = ssl_connect_3;
    Curl_infof(data, b"SSL connected\0" as *const u8 as *const libc::c_char);
    return CURLE_OK;
}

// 内部没有宏
unsafe extern "C" fn mbed_connect_step3(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut retcode: CURLcode = CURLE_OK;
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

    if SSL_SET_OPTION_primary_sessionid != 0{
        let mut ret: libc::c_int = 0;
        let mut our_ssl_sessionid: *mut mbedtls_ssl_session = 0
            as *mut mbedtls_ssl_session;
        let mut old_ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_IS_PROXY_null_1 = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                } != 0 ;
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_IS_PROXY_null_1 = if 0 as libc::c_int != 0 { 1 as libc::c_int } else { 0 as libc::c_int } != 0 ;
        let mut isproxy: bool = SSL_IS_PROXY_null_1;
        our_ssl_sessionid = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<mbedtls_ssl_session>() as libc::c_ulong)
            as *mut mbedtls_ssl_session;
        if our_ssl_sessionid.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        mbedtls_ssl_session_init(our_ssl_sessionid);
        ret = mbedtls_ssl_get_session(&mut (*backend).ssl, our_ssl_sessionid);
        if ret != 0 {
            if ret != -(0x7f00 as libc::c_int) {
                mbedtls_ssl_session_free(our_ssl_sessionid);
            }
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )(our_ssl_sessionid as *mut libc::c_void);
            Curl_failf(
                data,
                b"mbedtls_ssl_get_session returned -0x%x\0" as *const u8
                    as *const libc::c_char,
                -ret,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        Curl_ssl_sessionid_lock(data);
        if !Curl_ssl_getsessionid(
            data,
            conn,
            isproxy,
            &mut old_ssl_sessionid,
            0 as *mut size_t,
            sockindex,
        ) {
            Curl_ssl_delsessionid(data, old_ssl_sessionid);
        }
        retcode = Curl_ssl_addsessionid(
            data,
            conn,
            isproxy,
            our_ssl_sessionid as *mut libc::c_void,
            0 as libc::c_int as size_t,
            sockindex,
        );
        Curl_ssl_sessionid_unlock(data);
        if retcode as u64 != 0 {
            mbedtls_ssl_session_free(our_ssl_sessionid);
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )(our_ssl_sessionid as *mut libc::c_void);
            Curl_failf(
                data,
                b"failed to store ssl session\0" as *const u8 as *const libc::c_char,
            );
            return retcode;
        }
    }
    (*connssl).connecting_state = ssl_connect_done;
    return CURLE_OK;
}

// 内部没有宏
unsafe extern "C" fn mbed_send(
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
    let mut ret: libc::c_int = -(1 as libc::c_int);
    ret = mbedtls_ssl_write(&mut (*backend).ssl, mem as *mut libc::c_uchar, len);
    if ret < 0 as libc::c_int {
        *curlcode = (if ret == -(0x6880 as libc::c_int) {
            CURLE_AGAIN as libc::c_int
        } else {
            CURLE_SEND_ERROR as libc::c_int
        }) as CURLcode;
        ret = -(1 as libc::c_int);
    }
    return ret as ssize_t;
}

// 内部没有宏
unsafe extern "C" fn mbedtls_close_all(mut data: *mut Curl_easy) {}

// done
unsafe extern "C" fn mbedtls_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut buf: [libc::c_char; 32] = [0; 32];
    mbedtls_ssl_read(
        &mut (*backend).ssl,
        buf.as_mut_ptr() as *mut libc::c_uchar,
        ::std::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
    );
    mbedtls_pk_free(&mut (*backend).pk);
    mbedtls_x509_crt_free(&mut (*backend).clicert);
    mbedtls_x509_crt_free(&mut (*backend).cacert);
    mbedtls_x509_crl_free(&mut (*backend).crl);
    mbedtls_ssl_config_free(&mut (*backend).config);
    mbedtls_ssl_free(&mut (*backend).ssl);
    mbedtls_ctr_drbg_free(&mut (*backend).ctr_drbg);
    // done - 869
    #[cfg(THREADING_SUPPORT)]
    mbedtls_entropy_free(&mut (*backend).entropy);
}

// 内部没有宏
unsafe extern "C" fn mbed_recv(
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
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut len: ssize_t = -(1 as libc::c_int) as ssize_t;
    ret = mbedtls_ssl_read(&mut (*backend).ssl, buf as *mut libc::c_uchar, buffersize);
    if ret <= 0 as libc::c_int {
        if ret == -(0x7880 as libc::c_int) {
            return 0 as libc::c_int as ssize_t;
        }
        *curlcode = (if ret == -(0x6900 as libc::c_int) {
            CURLE_AGAIN as libc::c_int
        } else {
            CURLE_RECV_ERROR as libc::c_int
        }) as CURLcode;
        return -(1 as libc::c_int) as ssize_t;
    }
    len = ret as ssize_t;
    return len;
}

// 内部没有宏
unsafe extern "C" fn mbedtls_session_free(mut ptr: *mut libc::c_void) {
    mbedtls_ssl_session_free(ptr as *mut mbedtls_ssl_session);
    Curl_cfree.expect("non-null function pointer")(ptr);
}

// done
unsafe extern "C" fn mbedtls_version(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
) -> size_t {
    // 909 - done
    if cfg!(MBEDTLS_VERSION_C){
        let mut version: libc::c_uint = mbedtls_version_get_number();
        return curl_msnprintf(
            buffer,
            size,
            b"mbedTLS/%u.%u.%u\0" as *const u8 as *const libc::c_char,
            version >> 24 as libc::c_int,
            version >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint,
            version >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint,
        ) as size_t;
    } 
    else{
        return curl_msnprintf(
            buffer,
            size,
            b"mbedTLS/%s\0" as *const u8 as *const libc::c_char,
            b"2.16.3\0" as *const u8 as *const libc::c_char,
        ) as size_t;
    } 
        
}

// done
unsafe extern "C" fn mbedtls_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut libc::c_uchar,
    mut length: size_t,
) -> CURLcode {
    if cfg!(MBEDTLS_CTR_DRBG_C){
        let mut ret: libc::c_int = -(1 as libc::c_int);
        let mut errorbuf: [libc::c_char; 128] = [0; 128];
        let mut ctr_entropy: mbedtls_entropy_context = mbedtls_entropy_context {
            accumulator_started: 0,
            accumulator: mbedtls_sha512_context {
                total: [0; 2],
                state: [0; 8],
                buffer: [0; 128],
                is384: 0,
            },
            source_count: 0,
            source: [mbedtls_entropy_source_state {
                f_source: None,
                p_source: 0 as *const libc::c_void as *mut libc::c_void,
                size: 0,
                threshold: 0,
                strong: 0,
            }; 20],
            havege_data: mbedtls_havege_state {
                PT1: 0,
                PT2: 0,
                offset: [0; 2],
                pool: [0; 1024],
                WALK: [0; 8192],
            },
            mutex: mbedtls_threading_mutex_t {
                mutex: pthread_mutex_t {
                    __data: __pthread_mutex_s {
                        __lock: 0,
                        __count: 0,
                        __owner: 0,
                        __nusers: 0,
                        __kind: 0,
                        __spins: 0,
                        __elision: 0,
                        __list: __pthread_list_t {
                            __prev: 0 as *const __pthread_internal_list
                                as *mut __pthread_internal_list,
                            __next: 0 as *const __pthread_internal_list
                                as *mut __pthread_internal_list,
                        },
                    },
                },
                is_valid: 0,
            },
        };
        let mut ctr_drbg: mbedtls_ctr_drbg_context = mbedtls_ctr_drbg_context {
            counter: [0; 16],
            reseed_counter: 0,
            prediction_resistance: 0,
            entropy_len: 0,
            reseed_interval: 0,
            aes_ctx: mbedtls_aes_context {
                nr: 0,
                rk: 0 as *mut uint32_t,
                buf: [0; 68],
            },
            f_entropy: None,
            p_entropy: 0 as *mut libc::c_void,
            mutex: mbedtls_threading_mutex_t {
                mutex: pthread_mutex_t {
                    __data: __pthread_mutex_s {
                        __lock: 0,
                        __count: 0,
                        __owner: 0,
                        __nusers: 0,
                        __kind: 0,
                        __spins: 0,
                        __elision: 0,
                        __list: __pthread_list_t {
                            __prev: 0 as *const __pthread_internal_list
                                as *mut __pthread_internal_list,
                            __next: 0 as *const __pthread_internal_list
                                as *mut __pthread_internal_list,
                        },
                    },
                },
                is_valid: 0,
            },
        };
        mbedtls_entropy_init(&mut ctr_entropy);
        mbedtls_ctr_drbg_init(&mut ctr_drbg);
        ret = mbedtls_ctr_drbg_seed(
            &mut ctr_drbg,
            Some(
                mbedtls_entropy_func
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_uchar,
                        size_t,
                    ) -> libc::c_int,
            ),
            &mut ctr_entropy as *mut mbedtls_entropy_context as *mut libc::c_void,
            0 as *const libc::c_uchar,
            0 as libc::c_int as size_t,
        );
        if ret != 0 {
            mbedtls_strerror(
                ret,
                errorbuf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
            Curl_failf(
                data,
                b"Failed - mbedTLS: ctr_drbg_seed returned (-0x%04X) %s\0" as *const u8
                    as *const libc::c_char,
                -ret,
                errorbuf.as_mut_ptr(),
            );
        } else {
            ret = mbedtls_ctr_drbg_random(
                &mut ctr_drbg as *mut mbedtls_ctr_drbg_context as *mut libc::c_void,
                entropy,
                length,
            );
            if ret != 0 {
                mbedtls_strerror(
                    ret,
                    errorbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                );
                Curl_failf(
                    data,
                    b"mbedTLS: ctr_drbg_init returned (-0x%04X) %s\0" as *const u8
                        as *const libc::c_char,
                    -ret,
                    errorbuf.as_mut_ptr(),
                );
            }
        }
        mbedtls_ctr_drbg_free(&mut ctr_drbg);
        mbedtls_entropy_free(&mut ctr_entropy);
        return (if ret == 0 as libc::c_int {
            CURLE_OK as libc::c_int
        } else {
            CURLE_FAILED_INIT as libc::c_int
        }) as CURLcode;
    }else if cfg!(MBEDTLS_HAVEGE_C){
        // todo
        return CURLE_OK as libc::c_int as CURLcode;
    }else{
        return CURLE_NOT_BUILT_IN as libc::c_int as CURLcode;
    }    
}

// 内部没有宏
unsafe extern "C" fn mbed_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> CURLcode {
    let mut retcode: CURLcode = CURLE_OK;
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
        retcode = mbed_connect_step1(data, conn, sockindex);
        if retcode as u64 != 0 {
            return retcode;
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
        retcode = mbed_connect_step2(data, conn, sockindex);
        if retcode as libc::c_uint != 0
            || nonblocking as libc::c_int != 0
                && (ssl_connect_2 as libc::c_int as libc::c_uint
                    == (*connssl).connecting_state as libc::c_uint
                    || ssl_connect_2_reading as libc::c_int as libc::c_uint
                        == (*connssl).connecting_state as libc::c_uint
                    || ssl_connect_2_writing as libc::c_int as libc::c_uint
                        == (*connssl).connecting_state as libc::c_uint)
        {
            return retcode;
        }
    }
    if ssl_connect_3 as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        retcode = mbed_connect_step3(data, conn, sockindex);
        if retcode as u64 != 0 {
            return retcode;
        }
    }
    if ssl_connect_done as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        (*connssl).state = ssl_connection_complete;
        let ref mut fresh4 = (*conn).recv[sockindex as usize];
        *fresh4 = Some(mbed_recv as Curl_recv);
        let ref mut fresh5 = (*conn).send[sockindex as usize];
        *fresh5 = Some(mbed_send as Curl_send);
        *done = 1 as libc::c_int != 0;
    } else {
        *done = 0 as libc::c_int != 0;
    }
    (*connssl).connecting_state = ssl_connect_1;
    return CURLE_OK;
}

// 内部没有宏
unsafe extern "C" fn mbedtls_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    return mbed_connect_common(data, conn, sockindex, 1 as libc::c_int != 0, done);
}

// 内部没有宏
unsafe extern "C" fn mbedtls_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut retcode: CURLcode = CURLE_OK;
    let mut done: bool = 0 as libc::c_int != 0;
    retcode = mbed_connect_common(
        data,
        conn,
        sockindex,
        0 as libc::c_int != 0,
        &mut done,
    );
    if retcode as u64 != 0 {
        return retcode;
    }
    return CURLE_OK;
}

// 内部没有宏
unsafe extern "C" fn mbedtls_init() -> libc::c_int {
    return Curl_mbedtlsthreadlock_thread_setup();
}

// 内部没有宏
unsafe extern "C" fn mbedtls_cleanup() {
    Curl_mbedtlsthreadlock_thread_cleanup();
}

// 内部没有宏
unsafe extern "C" fn mbedtls_data_pending(
    mut conn: *const connectdata,
    mut sockindex: libc::c_int,
) -> bool {
    let mut connssl: *const ssl_connect_data = &*((*conn).ssl)
        .as_ptr()
        .offset(sockindex as isize) as *const ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return mbedtls_ssl_get_bytes_avail(&mut (*backend).ssl)
        != 0 as libc::c_int as libc::c_ulong;
}

// done
unsafe extern "C" fn mbedtls_sha256sum(
    mut input: *const libc::c_uchar,
    mut inputlen: size_t,
    mut sha256sum: *mut libc::c_uchar,
    mut sha256len: size_t,
) -> CURLcode {
// 1128 - done
    if cfg!(MBEDTLS_VERSION_NUMBER_LT_0X02070000){
        // C语句 - 未翻译
        // mbedtls_sha256(input, inputlen, sha256sum, 0);
    }
    else{
        /* returns 0 on success, otherwise failure */
        if cfg!(MBEDTLS_VERSION_NUMBER_GT_0X03000000){
            // C语句 - 未翻译
            // if(mbedtls_sha256(input, inputlen, sha256sum, 0) != 0)
        }    
        else{
            // 这边翻译出来对应的是
            // C语句
            // if(mbedtls_sha256_ret(input, inputlen, sha256sum, 0) != 0)
            // 所以对应的版本是     0X03000000 > MBEDTLS_VERSION_NUMBER >= 0X02070000
            if mbedtls_sha256_ret(input, inputlen, sha256sum, 0 as libc::c_int)!= 0 as libc::c_int {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
        }
    }
    return CURLE_OK;
}

// 内部没有宏
unsafe extern "C" fn mbedtls_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return &mut (*backend).ssl as *mut mbedtls_ssl_context as *mut libc::c_void;
}


#[no_mangle]
pub static mut Curl_ssl_mbedtls: Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_MBEDTLS,
                    name: b"mbedtls\0" as *const u8 as *const libc::c_char,
                };
                init
            },
            supports: ((1 as libc::c_int) << 0 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int
                | (1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint,
            sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>()
                as libc::c_ulong,
            init: Some(mbedtls_init as unsafe extern "C" fn() -> libc::c_int),
            cleanup: Some(mbedtls_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(
                mbedtls_version
                    as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t,
            ),
            check_cxn: Some(
                Curl_none_check_cxn
                    as unsafe extern "C" fn(*mut connectdata) -> libc::c_int,
            ),
            shut_down: Some(
                Curl_none_shutdown
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            data_pending: Some(
                mbedtls_data_pending
                    as unsafe extern "C" fn(*const connectdata, libc::c_int) -> bool,
            ),
            random: Some(
                mbedtls_random
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
                mbedtls_connect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> CURLcode,
            ),
            connect_nonblocking: Some(
                mbedtls_connect_nonblocking
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
                mbedtls_get_internals
                    as unsafe extern "C" fn(
                        *mut ssl_connect_data,
                        CURLINFO,
                    ) -> *mut libc::c_void,
            ),
            close_one: Some(
                mbedtls_close
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> (),
            ),
            close_all: Some(
                mbedtls_close_all as unsafe extern "C" fn(*mut Curl_easy) -> (),
            ),
            session_free: Some(
                mbedtls_session_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
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
                mbedtls_sha256sum
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
