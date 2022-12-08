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
 * Description: support gnutls backend
 ******************************************************************************/
use crate::src::vtls::vtls::*;
use libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

static mut gtls_inited: bool = 0 as i32 != 0;
unsafe extern "C" fn gtls_push(
    mut s: *mut libc::c_void,
    mut buf: *const libc::c_void,
    mut len: size_t,
) -> ssize_t {
    let mut sock: curl_socket_t = *(s as *mut curl_socket_t);
    #[cfg(not(CURLDEBUG))]
    let mut ret: ssize_t = send(sock, buf, len, MSG_NOSIGNAL as i32);

    #[cfg(CURLDEBUG)]
    let mut ret: ssize_t = curl_dbg_send(
        sock,
        buf,
        len,
        MSG_NOSIGNAL as i32,
        86 as i32,
        b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
    );
    return ret;
}
unsafe extern "C" fn gtls_pull(
    mut s: *mut libc::c_void,
    mut buf: *mut libc::c_void,
    mut len: size_t,
) -> ssize_t {
    let mut sock: curl_socket_t = *(s as *mut curl_socket_t);
    #[cfg(not(CURLDEBUG))]
    let mut ret: ssize_t = recv(sock, buf, len, 0 as i32);

    #[cfg(CURLDEBUG)]
    let mut ret: ssize_t = curl_dbg_recv(
        sock,
        buf,
        len,
        0 as i32,
        93 as i32,
        b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
    );
    return ret;
}
unsafe extern "C" fn gtls_push_ssl(
    mut s: *mut libc::c_void,
    mut buf: *const libc::c_void,
    mut len: size_t,
) -> ssize_t {
    return gnutls_record_send(s as gnutls_session_t, buf, len);
}
unsafe extern "C" fn gtls_pull_ssl(
    mut s: *mut libc::c_void,
    mut buf: *mut libc::c_void,
    mut len: size_t,
) -> ssize_t {
    return gnutls_record_recv(s as gnutls_session_t, buf, len);
}

unsafe extern "C" fn gtls_init() -> i32 {
    let mut ret: i32 = 1 as i32;
    if !gtls_inited {
        ret = if gnutls_global_init() != 0 {
            0 as i32
        } else {
            1 as i32
        };

        // #[cfg(GTLSDEBUG)]
        gtls_inited = 1 as i32 != 0;
    }
    return ret;
}

unsafe extern "C" fn gtls_cleanup() {
    if gtls_inited {
        gnutls_global_deinit();
        gtls_inited = 0 as i32 != 0;
    }
}
#[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
unsafe extern "C" fn showtime(
    mut data: *mut Curl_easy,
    mut text: *const libc::c_char,
    mut stamp: time_t,
) {
    let mut buffer: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: 0 as *const libc::c_char,
    };
    let mut tm: *const tm = &mut buffer;
    let mut str: [libc::c_char; 96] = [0; 96];
    let mut result: CURLcode = Curl_gmtime(stamp, &mut buffer);
    if result as u64 != 0 {
        return;
    }
    curl_msnprintf(
        str.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 96]>() as u64,
        b"  %s: %s, %02d %s %4d %02d:%02d:%02d GMT\0" as *const u8 as *const libc::c_char,
        text,
        Curl_wkday[(if (*tm).tm_wday != 0 {
            (*tm).tm_wday - 1 as i32
        } else {
            6 as i32
        }) as usize],
        (*tm).tm_mday,
        Curl_month[(*tm).tm_mon as usize],
        (*tm).tm_year + 1900 as i32,
        (*tm).tm_hour,
        (*tm).tm_min,
        (*tm).tm_sec,
    );
    Curl_infof(
        data,
        b"%s\0" as *const u8 as *const libc::c_char,
        str.as_mut_ptr(),
    );
}
unsafe extern "C" fn load_file(mut file: *const libc::c_char) -> gnutls_datum_t {
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut loaded_file: gnutls_datum_t = {
        let mut init = gnutls_datum_t {
            data: 0 as *mut u8,
            size: 0 as u32,
        };
        init
    };
    let mut filelen: i64 = 0;
    let mut ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    match () {
        #[cfg(not(CURLDEBUG))]
        _ => {
            f = fopen(file, b"rb\0" as *const u8 as *const libc::c_char);
        }
        #[cfg(CURLDEBUG)]
        _ => {
            f = curl_dbg_fopen(
                file,
                b"rb\0" as *const u8 as *const libc::c_char,
                170 as i32,
                b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
            );
        }
    }

    if f.is_null() {
        return loaded_file;
    }
    'out: loop {
        if !(fseek(f, 0 as i64, 2 as i32) != 0 as i32
            || {
                filelen = ftell(f);
                filelen < 0 as i64
            }
            || fseek(f, 0 as i64, 0 as i32) != 0 as i32
            || {
                match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {
                        ptr = Curl_cmalloc.expect("non-null function pointer")(filelen as size_t);
                    }
                    #[cfg(CURLDEBUG)]
                    _ => {
                        ptr = curl_dbg_malloc(
                            filelen as size_t,
                            176 as i32,
                            b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }

                ptr.is_null()
            })
        {
            break 'out;
        }

        if fread(ptr, 1 as u64, filelen as size_t, f) < filelen as size_t {
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(ptr);

            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                ptr,
                179 as i32,
                b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
            );

            break 'out;
        } else {
            loaded_file.data = ptr as *mut u8;
            loaded_file.size = filelen as u32;
        }

        break 'out;
    }
    #[cfg(not(CURLDEBUG))]
    fclose(f);

    #[cfg(CURLDEBUG)]
    curl_dbg_fclose(
        f,
        186 as i32,
        b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
    );
    return loaded_file;
}
unsafe extern "C" fn unload_file(mut data: gnutls_datum_t) {
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(data.data as *mut libc::c_void);

    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        data.data as *mut libc::c_void,
        192 as i32,
        b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn handshake(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut duringconnect: bool,
    mut nonblocking: bool,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut session: gnutls_session_t = (*backend).session;
    let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
    loop {
        let mut timeout_ms: timediff_t = 0;
        let mut rc: i32 = 0;
        timeout_ms = Curl_timeleft(data, 0 as *mut curltime, duringconnect);
        if timeout_ms < 0 as i64 {
            Curl_failf(
                data,
                b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OPERATION_TIMEDOUT;
        }
        if (*connssl).connecting_state as u32
            == ssl_connect_2_reading as u32
            || (*connssl).connecting_state as u32
                == ssl_connect_2_writing as u32
        {
            let mut what: i32 = 0;
            let mut writefd: curl_socket_t = if ssl_connect_2_writing as u32
                == (*connssl).connecting_state as u32
            {
                sockfd
            } else {
                -(1 as i32)
            };
            let mut readfd: curl_socket_t = if ssl_connect_2_reading as u32
                == (*connssl).connecting_state as u32
            {
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
                } else if timeout_ms != 0 {
                    timeout_ms
                } else {
                    1000 as i64
                },
            );
            if what < 0 as i32 {
                Curl_failf(
                    data,
                    b"select/poll on SSL socket, errno: %d\0" as *const u8 as *const libc::c_char,
                    *__errno_location(),
                );
                return CURLE_SSL_CONNECT_ERROR;
            } else {
                if 0 as i32 == what {
                    if nonblocking {
                        return CURLE_OK;
                    } else {
                        if timeout_ms != 0 {
                            Curl_failf(
                                data,
                                b"SSL connection timeout at %ld\0" as *const u8
                                    as *const libc::c_char,
                                timeout_ms,
                            );
                            return CURLE_OPERATION_TIMEDOUT;
                        }
                    }
                }
            }
        }
        rc = gnutls_handshake(session);
        if rc == -(28 as i32) || rc == -(52 as i32) {
            (*connssl).connecting_state = (if gnutls_record_get_direction(session) != 0 {
                ssl_connect_2_writing as i32
            } else {
                ssl_connect_2_reading as i32
            }) as ssl_connect_state;
        } else if rc < 0 as i32 && gnutls_error_is_fatal(rc) == 0 {
            let mut strerr: *const libc::c_char = 0 as *const libc::c_char;
            if rc == -(16 as i32) {
                let mut alert: i32 = gnutls_alert_get(session) as i32;
                strerr = gnutls_alert_get_name(alert as gnutls_alert_description_t);
            }
            if strerr.is_null() {
                strerr = gnutls_strerror(rc);
            }
            Curl_infof(
                data,
                b"gnutls_handshake() warning: %s\0" as *const u8 as *const libc::c_char,
                strerr,
            );
        } else {
            if rc < 0 as i32 {
                let mut strerr_0: *const libc::c_char = 0 as *const libc::c_char;
                if rc == -(12 as i32) {
                    let mut alert_0: i32 = gnutls_alert_get(session) as i32;
                    strerr_0 = gnutls_alert_get_name(alert_0 as gnutls_alert_description_t);
                }
                if strerr_0.is_null() {
                    strerr_0 = gnutls_strerror(rc);
                }
                Curl_failf(
                    data,
                    b"gnutls_handshake() failed: %s\0" as *const u8 as *const libc::c_char,
                    strerr_0,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            (*connssl).connecting_state = ssl_connect_1;
            return CURLE_OK;
        }
    }
}
unsafe extern "C" fn do_file_type(mut type_0: *const libc::c_char) -> gnutls_x509_crt_fmt_t {
    if type_0.is_null() || *type_0.offset(0 as isize) == 0 {
        return GNUTLS_X509_FMT_PEM;
    }
    if Curl_strcasecompare(type_0, b"PEM\0" as *const u8 as *const libc::c_char) != 0 {
        return GNUTLS_X509_FMT_PEM;
    }
    if Curl_strcasecompare(type_0, b"DER\0" as *const u8 as *const libc::c_char) != 0 {
        return GNUTLS_X509_FMT_DER;
    }
    return GNUTLS_X509_FMT_PEM;
}
unsafe extern "C" fn set_ssl_version_min_max(
    mut data: *mut Curl_easy,
    mut prioritylist: *mut *const libc::c_char,
    mut tls13support: *const libc::c_char,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut ssl_version: i64 = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
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
    #[cfg(CURL_DISABLE_PROXY)]
    let mut ssl_version: i64 = (*conn).ssl_config.version;

    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut ssl_version_max: i64 = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*conn).proxy_ssl_config.version_max
    } else {
        (*conn).ssl_config.version_max
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut ssl_version_max: i64 = (*conn).ssl_config.version_max;

    if ssl_version == CURL_SSLVERSION_DEFAULT as i64
        || ssl_version == CURL_SSLVERSION_TLSv1 as i64
    {
        ssl_version = CURL_SSLVERSION_TLSv1_0 as i64;
    }
    if ssl_version_max == CURL_SSLVERSION_MAX_NONE as i64 {
        ssl_version_max = CURL_SSLVERSION_MAX_DEFAULT as i64;
    }
    if tls13support.is_null() {
        if ssl_version_max == CURL_SSLVERSION_MAX_TLSv1_3 as i64
            || ssl_version_max == CURL_SSLVERSION_MAX_DEFAULT as i64
        {
            ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2 as i64;
        }
    } else if ssl_version_max == CURL_SSLVERSION_MAX_DEFAULT as i64 {
        ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_3 as i64;
    }
    match ssl_version | ssl_version_max {
        262148 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.0\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        327684 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.1:+VERS-TLS1.0\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        393220 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.1:+VERS-TLS1.0\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        327685 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.1\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        393221 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.1\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        393222 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.2\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        458759 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        458756 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        458757 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2:+VERS-TLS1.1\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        458758 => {
            *prioritylist = b"NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509:-VERS-SSL3.0:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2\0"
                as *const u8 as *const libc::c_char;
            return CURLE_OK;
        }
        _ => {}
    }
    Curl_failf(
        data,
        b"GnuTLS: cannot set ssl protocol\0" as *const u8 as *const libc::c_char,
    );
    return CURLE_SSL_CONNECT_ERROR;
}

unsafe extern "C" fn gtls_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut init_flags: u32 = 0;
    let mut session: gnutls_session_t = 0 as *mut gnutls_session_int;
    let mut rc: i32 = 0;
    let mut sni: bool = 1 as i32 != 0;
    let mut transport_ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut gnutls_transport_push: gnutls_push_func = None;
    let mut gnutls_transport_pull: gnutls_pull_func = None;
    #[cfg(ENABLE_IPV6)]
    let mut addr: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_8 {
            __u6_addr8: [0; 16],
        },
    };
    // 选项 - 不开启 ENABLE_IPV6
    #[cfg(not(ENABLE_IPV6))]
    let mut addr: in_addr = in_addr { s_addr: 0 };
    let mut prioritylist: *const libc::c_char = 0 as *const libc::c_char;
    let mut err: *const libc::c_char = 0 as *const libc::c_char;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let hostname: *const libc::c_char = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
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
    #[cfg(CURL_DISABLE_PROXY)]
    let hostname: *const libc::c_char = (*conn).host.name;

    #[cfg(not(CURL_DISABLE_PROXY))]
    let certverifyresult: *mut i64 = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        &mut (*data).set.proxy_ssl.certverifyresult
    } else {
        &mut (*data).set.ssl.certverifyresult
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let certverifyresult: *mut i64 = &mut (*data).set.ssl.certverifyresult;

    let mut tls13support: *const libc::c_char = 0 as *const libc::c_char;
    if (*connssl).state as u32 == ssl_connection_complete as u32 {
        return CURLE_OK;
    }
    if !gtls_inited {
        gtls_init();
    }
    *certverifyresult = 0 as i64;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_version = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
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
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_version = (*conn).ssl_config.version;
    if SSL_CONN_CONFIG_version == CURL_SSLVERSION_SSLv2 as i64 {
        Curl_failf(
            data,
            b"GnuTLS does not support SSLv2\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_SSL_CONNECT_ERROR;
    } else {
        if SSL_CONN_CONFIG_version == CURL_SSLVERSION_SSLv3 as i64 {
            sni = 0 as i32 != 0;
        }
    }
    rc = gnutls_certificate_allocate_credentials(&mut (*backend).cred);
    if rc != 0 as i32 {
        Curl_failf(
            data,
            b"gnutls_cert_all_cred() failed: %s\0" as *const u8 as *const libc::c_char,
            gnutls_strerror(rc),
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_authtype = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*data).set.proxy_ssl.authtype as u32
    } else {
        (*data).set.ssl.authtype as u32
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_authtype = (*data).set.ssl.authtype as u32;
    #[cfg(HAVE_GNUTLS_SRP)]
    if SSL_SET_OPTION_authtype == CURL_TLSAUTH_SRP as u32 {
        #[cfg(not(CURL_DISABLE_PROXY))]
        Curl_infof(
            data,
            b"Using TLS-SRP username: %s\0" as *const u8 as *const libc::c_char,
            if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*data).set.proxy_ssl.username
            } else {
                (*data).set.ssl.username
            },
        );
        #[cfg(CURL_DISABLE_PROXY)]
        Curl_infof(
            data,
            b"Using TLS-SRP username: %s\0" as *const u8 as *const libc::c_char,
            (*data).set.ssl.username,
        );
        rc = gnutls_srp_allocate_client_credentials(&mut (*backend).srp_client_cred);
        if rc != 0 as i32 {
            Curl_failf(
                data,
                b"gnutls_srp_allocate_client_cred() failed: %s\0" as *const u8
                    as *const libc::c_char,
                gnutls_strerror(rc),
            );
            return CURLE_OUT_OF_MEMORY;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        if true {
            rc = gnutls_srp_set_client_credentials(
                (*backend).srp_client_cred,
                if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*data).set.proxy_ssl.username
                } else {
                    (*data).set.ssl.username
                },
                if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*data).set.proxy_ssl.password
                } else {
                    (*data).set.ssl.password
                },
            );
        }
        #[cfg(CURL_DISABLE_PROXY)]
        if true {
            rc = gnutls_srp_set_client_credentials(
                (*backend).srp_client_cred,
                (*data).set.ssl.username,
                (*data).set.ssl.password,
            );
        }
        if rc != 0 as i32 {
            Curl_failf(
                data,
                b"gnutls_srp_set_client_cred() failed: %s\0" as *const u8 as *const libc::c_char,
                gnutls_strerror(rc),
            );
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    if !if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*conn).proxy_ssl_config.CAfile
    } else {
        (*conn).ssl_config.CAfile
    }
    .is_null()
    {
        gnutls_certificate_set_verify_flags((*backend).cred, 0 as u32);
        rc = gnutls_certificate_set_x509_trust_file(
            (*backend).cred,
            if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*conn).proxy_ssl_config.CAfile
            } else {
                (*conn).ssl_config.CAfile
            },
            GNUTLS_X509_FMT_PEM,
        );
        if rc < 0 as i32 {
            Curl_infof(
                data,
                b"error reading ca cert file %s (%s)\0" as *const u8 as *const libc::c_char,
                if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*conn).proxy_ssl_config.CAfile
                } else {
                    (*conn).ssl_config.CAfile
                },
                gnutls_strerror(rc),
            );
            if if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                ((*conn).proxy_ssl_config).verifypeer() as i32
            } else {
                ((*conn).ssl_config).verifypeer() as i32
            } != 0
            {
                *certverifyresult = rc as i64;
                return CURLE_SSL_CACERT_BADFILE;
            }
        } else {
            Curl_infof(
                data,
                b"found %d certificates in %s\0" as *const u8 as *const libc::c_char,
                rc,
                if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*conn).proxy_ssl_config.CAfile
                } else {
                    (*conn).ssl_config.CAfile
                },
            );
        }
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if !((*conn).ssl_config.CAfile).is_null() {
        gnutls_certificate_set_verify_flags((*backend).cred, 0 as u32);
        rc = gnutls_certificate_set_x509_trust_file(
            (*backend).cred,
            (*conn).ssl_config.CAfile,
            GNUTLS_X509_FMT_PEM,
        );
        if rc < 0 as i32 {
            Curl_infof(
                data,
                b"error reading ca cert file %s (%s)\0" as *const u8 as *const libc::c_char,
                (*conn).ssl_config.CAfile,
                gnutls_strerror(rc),
            );
            if ((*conn).ssl_config).verifypeer() != 0 {
                *certverifyresult = rc as i64;
                return CURLE_SSL_CACERT_BADFILE;
            }
        } else {
            Curl_infof(
                data,
                b"found %d certificates in %s\0" as *const u8 as *const libc::c_char,
                rc,
                (*conn).ssl_config.CAfile,
            );
        }
    }

    #[cfg(not(CURL_DISABLE_PROXY))]
    if !if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*conn).proxy_ssl_config.CApath
    } else {
        (*conn).ssl_config.CApath
    }
    .is_null()
    {
        rc = gnutls_certificate_set_x509_trust_dir(
            (*backend).cred,
            if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*conn).proxy_ssl_config.CApath
            } else {
                (*conn).ssl_config.CApath
            },
            GNUTLS_X509_FMT_PEM,
        );
        if rc < 0 as i32 {
            Curl_infof(
                data,
                b"error reading ca cert file %s (%s)\0" as *const u8 as *const libc::c_char,
                if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*conn).proxy_ssl_config.CApath
                } else {
                    (*conn).ssl_config.CApath
                },
                gnutls_strerror(rc),
            );
            if if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                ((*conn).proxy_ssl_config).verifypeer() as i32
            } else {
                ((*conn).ssl_config).verifypeer() as i32
            } != 0
            {
                *certverifyresult = rc as i64;
                return CURLE_SSL_CACERT_BADFILE;
            }
        } else {
            Curl_infof(
                data,
                b"found %d certificates in %s\0" as *const u8 as *const libc::c_char,
                rc,
                if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*conn).proxy_ssl_config.CApath
                } else {
                    (*conn).ssl_config.CApath
                },
            );
        }
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if !((*conn).ssl_config.CApath).is_null() {
        rc = gnutls_certificate_set_x509_trust_dir(
            (*backend).cred,
            (*conn).ssl_config.CApath,
            GNUTLS_X509_FMT_PEM,
        );
        if rc < 0 as i32 {
            Curl_infof(
                data,
                b"error reading ca cert file %s (%s)\0" as *const u8 as *const libc::c_char,
                (*conn).ssl_config.CApath,
                gnutls_strerror(rc),
            );
            if ((*conn).ssl_config).verifypeer() != 0 {
                *certverifyresult = rc as i64;
                return CURLE_SSL_CACERT_BADFILE;
            }
        } else {
            Curl_infof(
                data,
                b"found %d certificates in %s\0" as *const u8 as *const libc::c_char,
                rc,
                (*conn).ssl_config.CApath,
            );
        }
    }

    // todo - 497
    // #[cfg(CURL_CA_FALLBACK)]
    #[cfg(not(CURL_DISABLE_PROXY))]
    if !if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*data).set.proxy_ssl.CRLfile
    } else {
        (*data).set.ssl.CRLfile
    }
    .is_null()
    {
        rc = gnutls_certificate_set_x509_crl_file(
            (*backend).cred,
            if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*data).set.proxy_ssl.CRLfile
            } else {
                (*data).set.ssl.CRLfile
            },
            GNUTLS_X509_FMT_PEM,
        );
        if rc < 0 as i32 {
            Curl_failf(
                data,
                b"error reading crl file %s (%s)\0" as *const u8 as *const libc::c_char,
                if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*data).set.proxy_ssl.CRLfile
                } else {
                    (*data).set.ssl.CRLfile
                },
                gnutls_strerror(rc),
            );
            return CURLE_SSL_CRL_BADFILE;
        } else {
            Curl_infof(
                data,
                b"found %d CRL in %s\0" as *const u8 as *const libc::c_char,
                rc,
                if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*data).set.proxy_ssl.CRLfile
                } else {
                    (*data).set.ssl.CRLfile
                },
            );
        }
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if !((*data).set.ssl.CRLfile).is_null() {
        rc = gnutls_certificate_set_x509_crl_file(
            (*backend).cred,
            (*data).set.ssl.CRLfile,
            GNUTLS_X509_FMT_PEM,
        );
        if rc < 0 as i32 {
            Curl_failf(
                data,
                b"error reading crl file %s (%s)\0" as *const u8 as *const libc::c_char,
                (*data).set.ssl.CRLfile,
                gnutls_strerror(rc),
            );
            return CURLE_SSL_CRL_BADFILE;
        } else {
            Curl_infof(
                data,
                b"found %d CRL in %s\0" as *const u8 as *const libc::c_char,
                rc,
                (*data).set.ssl.CRLfile,
            );
        }
    }

    init_flags = ((1 as i32) << 1 as i32) as u32;
    #[cfg(GNUTLS_FORCE_CLIENT_CERT)]
    if true {
        init_flags |= ((1 as i32) << 9 as i32) as u32;
    }
    #[cfg(GNUTLS_NO_TICKETS)]
    if true {
        init_flags |= ((1 as i32) << 10 as i32) as u32;
    }
    rc = gnutls_init(&mut (*backend).session, init_flags);
    if rc != 0 as i32 {
        Curl_failf(
            data,
            b"gnutls_init() failed: %d\0" as *const u8 as *const libc::c_char,
            rc,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    session = (*backend).session;
    // done - 条件编译 - 542
    #[cfg(ENABLE_IPV6)]
    if 0 as i32
        == inet_pton(
            2 as i32,
            hostname,
            &mut addr as *mut in6_addr as *mut libc::c_void,
        )
        && 0 as i32
            == inet_pton(
                10 as i32,
                hostname,
                &mut addr as *mut in6_addr as *mut libc::c_void,
            )
        && sni as i32 != 0
        && gnutls_server_name_set(
            session,
            GNUTLS_NAME_DNS,
            hostname as *const libc::c_void,
            strlen(hostname),
        ) < 0 as i32
    {
        Curl_infof(
            data,
            b"WARNING: failed to configure server name indication (SNI) TLS extension\0"
                as *const u8 as *const libc::c_char,
        );
    }
    #[cfg(not(ENABLE_IPV6))]
    if 0 as i32
        == inet_pton(
            2 as i32,
            hostname,
            &mut addr as *mut in_addr as *mut libc::c_void,
        )
        && sni as i32 != 0
        && gnutls_server_name_set(
            session,
            GNUTLS_NAME_DNS,
            hostname as *const libc::c_void,
            strlen(hostname),
        ) < 0 as i32
    {
        Curl_infof(
            data,
            b"WARNING: failed to configure server name indication (SNI) TLS extension\0"
                as *const u8 as *const libc::c_char,
        );
    }
    rc = gnutls_set_default_priority(session);
    if rc != 0 as i32 {
        return CURLE_SSL_CONNECT_ERROR;
    }
    tls13support = gnutls_check_version(b"3.6.5\0" as *const u8 as *const libc::c_char);
    match SSL_CONN_CONFIG_version {
        7 => {
            if tls13support.is_null() {
                Curl_failf(
                    data,
                    b"This GnuTLS installation does not support TLS 1.3\0" as *const u8
                        as *const libc::c_char,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
        }
        0 | 1 | 4 | 5 | 6 => {}
        2 | 3 | _ => {
            Curl_failf(
                data,
                b"GnuTLS does not support SSLv2 or SSLv3\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    let mut result: CURLcode = set_ssl_version_min_max(data, &mut prioritylist, tls13support);
    if result as u64 != 0 {
        return result;
    }
    #[cfg(HAVE_GNUTLS_SRP)]
    if SSL_SET_OPTION_authtype as u32 == CURL_TLSAUTH_SRP as i32 as u32 {
        let mut len: size_t = strlen(prioritylist);
        #[cfg(not(CURLDEBUG))]
        let mut prioritysrp: *mut libc::c_char = Curl_cmalloc.expect("non-null function pointer")(
            len.wrapping_add(::std::mem::size_of::<[libc::c_char; 5]>() as u64)
                .wrapping_add(1 as u64),
        ) as *mut libc::c_char;
        #[cfg(CURLDEBUG)]
        let mut prioritysrp: *mut libc::c_char = curl_dbg_malloc(
            len.wrapping_add(::std::mem::size_of::<[libc::c_char; 5]>() as u64)
                .wrapping_add(1 as u64),
            591 as i32,
            b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
        ) as *mut libc::c_char;
        if prioritysrp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        strcpy(prioritysrp, prioritylist);
        strcpy(
            prioritysrp.offset(len as isize),
            b":+SRP\0" as *const u8 as *const libc::c_char,
        );
        rc = gnutls_priority_set_direct(session, prioritysrp, &mut err);
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")(prioritysrp as *mut libc::c_void);

        #[cfg(CURLDEBUG)]
        curl_dbg_free(
            prioritysrp as *mut libc::c_void,
            597 as i32,
            b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
        );
        if rc == -(50 as i32) && !err.is_null() {
            Curl_infof(
                data,
                b"This GnuTLS does not support SRP\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        Curl_infof(
            data,
            b"GnuTLS ciphers: %s\0" as *const u8 as *const libc::c_char,
            prioritylist,
        );
        rc = gnutls_priority_set_direct(session, prioritylist, &mut err);
    }
    #[cfg(not(HAVE_GNUTLS_SRP))]
    if true {
        Curl_infof(
            data,
            b"GnuTLS ciphers: %s\0" as *const u8 as *const libc::c_char,
            prioritylist,
        );
        rc = gnutls_priority_set_direct(session, prioritylist, &mut err);
    }
    if rc != 0 as i32 {
        Curl_failf(
            data,
            b"Error %d setting GnuTLS cipher list starting with %s\0" as *const u8
                as *const libc::c_char,
            rc,
            err,
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    if ((*conn).bits).tls_enable_alpn() != 0 {
        let mut cur: i32 = 0 as i32;
        let mut protocols: [gnutls_datum_t; 2] = [gnutls_datum_t {
            data: 0 as *mut u8,
            size: 0,
        }; 2];
        // done - 623
        #[cfg(not(CURL_DISABLE_PROXY))]
        let CURL_DISABLE_PROXY_flag = (!(CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                    == -(1 as i32)
                {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32)
            || ((*conn).bits).tunnel_proxy() == 0);
        #[cfg(CURL_DISABLE_PROXY)]
        let CURL_DISABLE_PROXY_flag = true;
        #[cfg(USE_HTTP2)]
        if (*data).state.httpwant as i32 >= CURL_HTTP_VERSION_2_0 as i32
            && CURL_DISABLE_PROXY_flag
        {
            protocols[cur as usize].data =
                b"h2\0" as *const u8 as *const libc::c_char as *mut u8;
            protocols[cur as usize].size = 2 as u32;
            cur += 1;
            Curl_infof(
                data,
                b"ALPN, offering %.*s\0" as *const u8 as *const libc::c_char,
                2 as i32,
                b"h2\0" as *const u8 as *const libc::c_char,
            );
        }
        protocols[cur as usize].data =
            b"http/1.1\0" as *const u8 as *const libc::c_char as *mut u8;
        protocols[cur as usize].size = 8 as u32;
        cur += 1;
        Curl_infof(
            data,
            b"ALPN, offering %s\0" as *const u8 as *const libc::c_char,
            b"http/1.1\0" as *const u8 as *const libc::c_char,
        );
        gnutls_alpn_set_protocols(
            session,
            protocols.as_mut_ptr(),
            cur as u32,
            0 as u32,
        );
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_clientcert = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*data).set.proxy_ssl.primary.clientcert
    } else {
        (*data).set.ssl.primary.clientcert
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_clientcert = (*data).set.ssl.primary.clientcert;

    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_key_passwd = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*data).set.proxy_ssl.key_passwd
    } else {
        (*data).set.ssl.key_passwd
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_key_passwd = (*data).set.ssl.key_passwd;

    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_key = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*data).set.proxy_ssl.key
    } else {
        (*data).set.ssl.key
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_key = (*data).set.ssl.key;

    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_cert_type = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*data).set.proxy_ssl.cert_type
    } else {
        (*data).set.ssl.cert_type
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_cert_type = (*data).set.ssl.cert_type;

    if !SSL_SET_OPTION_primary_clientcert.is_null() {
        if !SSL_SET_OPTION_key_passwd.is_null() {
            let supported_key_encryption_algorithms: u32 =
                (GNUTLS_PKCS_PKCS12_3DES as i32
                    | GNUTLS_PKCS_PKCS12_ARCFOUR as i32
                    | GNUTLS_PKCS_PKCS12_RC2_40 as i32
                    | GNUTLS_PKCS_PBES2_3DES as i32
                    | GNUTLS_PKCS_PBES2_AES_128 as i32
                    | GNUTLS_PKCS_PBES2_AES_192 as i32
                    | GNUTLS_PKCS_PBES2_AES_256 as i32) as u32;
            rc = gnutls_certificate_set_x509_key_file2(
                (*backend).cred,
                SSL_SET_OPTION_primary_clientcert,
                if !SSL_SET_OPTION_key.is_null() {
                    SSL_SET_OPTION_key
                } else {
                    SSL_SET_OPTION_primary_clientcert
                },
                do_file_type(SSL_SET_OPTION_cert_type),
                SSL_SET_OPTION_key_passwd,
                supported_key_encryption_algorithms,
            );
            if rc != 0 as i32 {
                Curl_failf(
                    data,
                    b"error reading X.509 potentially-encrypted key file: %s\0" as *const u8
                        as *const libc::c_char,
                    gnutls_strerror(rc),
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
        } else if gnutls_certificate_set_x509_key_file(
            (*backend).cred,
            SSL_SET_OPTION_primary_clientcert,
            if !(SSL_SET_OPTION_key).is_null() {
                SSL_SET_OPTION_key
            } else {
                SSL_SET_OPTION_primary_clientcert
            },
            do_file_type(SSL_SET_OPTION_cert_type),
        ) != 0 as i32
        {
            Curl_failf(
                data,
                b"error reading X.509 key or certificate file\0" as *const u8
                    as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    #[cfg(HAVE_GNUTLS_SRP)]
    if SSL_SET_OPTION_authtype == CURL_TLSAUTH_SRP as u32 {
        rc = gnutls_credentials_set(
            session,
            GNUTLS_CRD_SRP,
            (*backend).srp_client_cred as *mut libc::c_void,
        );
        if rc != 0 as i32 {
            Curl_failf(
                data,
                b"gnutls_credentials_set() failed: %s\0" as *const u8 as *const libc::c_char,
                gnutls_strerror(rc),
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    } else {
        rc = gnutls_credentials_set(
            session,
            GNUTLS_CRD_CERTIFICATE,
            (*backend).cred as *mut libc::c_void,
        );
        if rc != 0 as i32 {
            Curl_failf(
                data,
                b"gnutls_credentials_set() failed: %s\0" as *const u8 as *const libc::c_char,
                gnutls_strerror(rc),
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    #[cfg(not(HAVE_GNUTLS_SRP))]
    if true {
        rc = gnutls_credentials_set(
            session,
            GNUTLS_CRD_CERTIFICATE,
            (*backend).cred as *mut libc::c_void,
        );
        if rc != 0 as i32 {
            Curl_failf(
                data,
                b"gnutls_credentials_set() failed: %s\0" as *const u8 as *const libc::c_char,
                gnutls_strerror(rc),
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }

    #[cfg(not(CURL_DISABLE_PROXY))]
    if ((*conn).proxy_ssl[sockindex as usize]).use_0() != 0 {
        transport_ptr =
            (*(*conn).proxy_ssl[sockindex as usize].backend).session as *mut libc::c_void;
        gnutls_transport_push = Some(
            gtls_push_ssl
                as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> ssize_t,
        );
        gnutls_transport_pull = Some(
            gtls_pull_ssl
                as unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void, size_t) -> ssize_t,
        );
    } else {
        transport_ptr = &mut *((*conn).sock).as_mut_ptr().offset(sockindex as isize)
            as *mut curl_socket_t as *mut libc::c_void;
        gnutls_transport_push = Some(
            gtls_push
                as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> ssize_t,
        );
        gnutls_transport_pull = Some(
            gtls_pull
                as unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void, size_t) -> ssize_t,
        );
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if true {
        transport_ptr = &mut *((*conn).sock).as_mut_ptr().offset(sockindex as isize)
            as *mut curl_socket_t as *mut libc::c_void;
        gnutls_transport_push = Some(
            gtls_push
                as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> ssize_t,
        );
        gnutls_transport_pull = Some(
            gtls_pull
                as unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void, size_t) -> ssize_t,
        );
    }
    gnutls_transport_set_ptr(session, transport_ptr);
    gnutls_transport_set_push_function(session, gnutls_transport_push);
    gnutls_transport_set_pull_function(session, gnutls_transport_pull);
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifystatus = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        ((*conn).proxy_ssl_config).verifystatus() as i32
    } else {
        ((*conn).ssl_config).verifystatus() as i32
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifystatus = ((*conn).ssl_config).verifystatus();
    if SSL_CONN_CONFIG_verifystatus != 0 {
        rc = gnutls_ocsp_status_request_enable_client(
            session,
            0 as *mut gnutls_datum_t,
            0 as size_t,
            0 as *mut gnutls_datum_t,
        );
        if rc != 0 as i32 {
            Curl_failf(
                data,
                b"gnutls_ocsp_status_request_enable_client() failed: %d\0" as *const u8
                    as *const libc::c_char,
                rc,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        ((*data).set.proxy_ssl.primary).sessionid() as i32
    } else {
        ((*data).set.ssl.primary).sessionid() as i32
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_sessionid = ((*data).set.ssl.primary).sessionid();
    if SSL_SET_OPTION_primary_sessionid != 0 {
        let mut ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
        let mut ssl_idsize: size_t = 0;
        Curl_ssl_sessionid_lock(data);
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_IS_PROXY_void_1 = if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                    == -(1 as i32)
                {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            1 as i32
        } else {
            0 as i32
        } != 0;
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_IS_PROXY_void_1 = if 0 as i32 != 0 {
            1 as i32
        } else {
            0 as i32
        } != 0;
        if !Curl_ssl_getsessionid(
            data,
            conn,
            SSL_IS_PROXY_void_1,
            &mut ssl_sessionid,
            &mut ssl_idsize,
            sockindex,
        ) {
            gnutls_session_set_data(session, ssl_sessionid, ssl_idsize);
            Curl_infof(
                data,
                b"SSL re-using session ID\0" as *const u8 as *const libc::c_char,
            );
        }
        Curl_ssl_sessionid_unlock(data);
    }
    return CURLE_OK;
}
unsafe extern "C" fn pkp_pin_peer_pubkey(
    mut data: *mut Curl_easy,
    mut cert: gnutls_x509_crt_t,
    mut pinnedpubkey: *const libc::c_char,
) -> CURLcode {
    let mut len1: size_t = 0 as size_t;
    let mut len2: size_t = 0 as size_t;
    let mut buff1: *mut u8 = 0 as *mut u8;
    let mut key: gnutls_pubkey_t = 0 as gnutls_pubkey_t;
    let mut result: CURLcode = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    if pinnedpubkey.is_null() {
        return CURLE_OK;
    }
    if cert.is_null() {
        return result;
    }
    let mut ret: i32 = 0;
    gnutls_pubkey_init(&mut key);
    ret = gnutls_pubkey_import_x509(key, cert, 0 as u32);
    if !(ret < 0 as i32) {
        ret = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, 0 as *mut libc::c_void, &mut len1);
        if !(ret != -(51 as i32) || len1 == 0 as u64) {
            match () {
                #[cfg(not(CURLDEBUG))]
                _ => {
                    buff1 = Curl_cmalloc.expect("non-null function pointer")(len1)
                        as *mut u8;
                }
                #[cfg(CURLDEBUG)]
                _ => {
                    buff1 = curl_dbg_malloc(
                        len1,
                        785 as i32,
                        b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
                    ) as *mut u8;
                }
            }

            if !buff1.is_null() {
                len2 = len1;
                ret = gnutls_pubkey_export(
                    key,
                    GNUTLS_X509_FMT_DER,
                    buff1 as *mut libc::c_void,
                    &mut len2,
                );
                if !(ret < 0 as i32 || len1 != len2) {
                    result = Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1);
                }
            }
        }
    }
    if !key.is_null() {
        gnutls_pubkey_deinit(key);
    }
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(buff1 as *mut libc::c_void);

    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        buff1 as *mut libc::c_void,
        804 as i32,
        b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
    );
    buff1 = 0 as *mut u8;
    return result;
}

unsafe extern "C" fn gtls_connect_step3(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut cert_list_size: u32 = 0;
    let mut chainp: *const gnutls_datum_t = 0 as *const gnutls_datum_t;
    let mut verify_status: u32 = 0 as u32;
    let mut x509_cert: gnutls_x509_crt_t = 0 as *mut gnutls_x509_crt_int;
    let mut x509_issuer: gnutls_x509_crt_t = 0 as *mut gnutls_x509_crt_int;
    let mut issuerp: gnutls_datum_t = gnutls_datum_t {
        data: 0 as *mut u8,
        size: 0,
    };
    let mut certfields: gnutls_datum_t = gnutls_datum_t {
        data: 0 as *mut u8,
        size: 0,
    };
    let mut certname: [libc::c_char; 65] = *::std::mem::transmute::<
        &[u8; 65],
        &mut [libc::c_char; 65],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut size: size_t = 0;
    let mut certclock: time_t = 0;
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut session: gnutls_session_t = (*backend).session;
    let mut rc: i32 = 0;
    let mut proto: gnutls_datum_t = gnutls_datum_t {
        data: 0 as *mut u8,
        size: 0,
    };
    let mut result: CURLcode = CURLE_OK;
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    let mut algo: u32 = 0;
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    let mut bits: u32 = 0;
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    let mut version: gnutls_protocol_t = gnutls_protocol_get_version(session);
    #[cfg(not(CURL_DISABLE_PROXY))]
    let hostname: *const libc::c_char = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
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
    #[cfg(CURL_DISABLE_PROXY)]
    let hostname: *const libc::c_char = (*conn).host.name;

    #[cfg(not(CURL_DISABLE_PROXY))]
    let certverifyresult: *mut i64 = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        &mut (*data).set.proxy_ssl.certverifyresult
    } else {
        &mut (*data).set.ssl.certverifyresult
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let certverifyresult: *mut i64 = &mut (*data).set.ssl.certverifyresult;

    ptr = gnutls_cipher_suite_get_name(
        gnutls_kx_get(session),
        gnutls_cipher_get(session),
        gnutls_mac_get(session),
    );
    Curl_infof(
        data,
        b"SSL connection using %s / %s\0" as *const u8 as *const libc::c_char,
        gnutls_protocol_get_name(version),
        ptr,
    );
    chainp = gnutls_certificate_get_peers(session, &mut cert_list_size);
    #[cfg(not(CURL_DISABLE_PROXY))]
    if chainp.is_null() {
        if (if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                    == -(1 as i32)
                {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            ((*conn).proxy_ssl_config).verifypeer() as i32
        } else {
            ((*conn).ssl_config).verifypeer() as i32
        }) != 0
            || (if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                ((*conn).proxy_ssl_config).verifyhost() as i32
            } else {
                ((*conn).ssl_config).verifyhost() as i32
            }) != 0
            || !(if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*conn).proxy_ssl_config.issuercert
            } else {
                (*conn).ssl_config.issuercert
            })
            .is_null()
        {
            #[cfg(HAVE_GNUTLS_SRP)]
            if (if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*data).set.proxy_ssl.authtype as u32
            } else {
                (*data).set.ssl.authtype as u32
            }) == CURL_TLSAUTH_SRP as u32
                && !(if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*data).set.proxy_ssl.username
                } else {
                    (*data).set.ssl.username
                })
                .is_null()
                && (if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    ((*conn).proxy_ssl_config).verifypeer() as i32
                } else {
                    ((*conn).ssl_config).verifypeer() as i32
                }) == 0
                && gnutls_cipher_get(session) as u32 != 0
            {
            } else {
                Curl_failf(
                    data,
                    b"failed to get server cert\0" as *const u8 as *const libc::c_char,
                );
                *certverifyresult = -(49 as i32) as i64;
                return CURLE_PEER_FAILED_VERIFICATION;
            }
            #[cfg(not(HAVE_GNUTLS_SRP))]
            if true {
                Curl_failf(
                    data,
                    b"failed to get server cert\0" as *const u8 as *const libc::c_char,
                );
                *certverifyresult = -(49 as i32) as i64;
                return CURLE_PEER_FAILED_VERIFICATION;
            }
        }
        Curl_infof(
            data,
            b" common name: WARNING couldn't obtain\0" as *const u8 as *const libc::c_char,
        );
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if chainp.is_null() {
        if ((*conn).ssl_config).verifypeer() as i32 != 0
            || ((*conn).ssl_config).verifyhost() as i32 != 0
            || !((*conn).ssl_config.issuercert).is_null()
        {
            #[cfg(HAVE_GNUTLS_SRP)]
            if (*data).set.ssl.authtype as u32
                == CURL_TLSAUTH_SRP as u32
                && !((*data).set.ssl.username).is_null()
                && ((*conn).ssl_config).verifypeer() == 0
                && gnutls_cipher_get(session) as u32 != 0
            {
            } else {
                Curl_failf(
                    data,
                    b"failed to get server cert\0" as *const u8 as *const libc::c_char,
                );
                *certverifyresult = -(49 as i32) as i64;
                return CURLE_PEER_FAILED_VERIFICATION;
            }
            #[cfg(not(HAVE_GNUTLS_SRP))]
            if true {
                Curl_failf(
                    data,
                    b"failed to get server cert\0" as *const u8 as *const libc::c_char,
                );
                *certverifyresult = -(49 as i32) as i64;
                return CURLE_PEER_FAILED_VERIFICATION;
            }
        }
        Curl_infof(
            data,
            b" common name: WARNING couldn't obtain\0" as *const u8 as *const libc::c_char,
        );
    }
    if ((*data).set.ssl).certinfo() as i32 != 0 && !chainp.is_null() {
        let mut i: u32 = 0;
        result = Curl_ssl_init_certinfo(data, cert_list_size as i32);
        if result as u64 != 0 {
            return result;
        }
        i = 0 as i32 as u32;
        while i < cert_list_size {
            let mut beg: *const libc::c_char =
                (*chainp.offset(i as isize)).data as *const libc::c_char;
            let mut end: *const libc::c_char =
                beg.offset((*chainp.offset(i as isize)).size as isize);
            result = Curl_extract_certinfo(data, i as i32, beg, end);
            if result as u64 != 0 {
                return result;
            }
            i = i.wrapping_add(1);
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
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
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifypeer = ((*conn).ssl_config).verifypeer();

    if SSL_CONN_CONFIG_verifypeer != 0 {
        rc = gnutls_certificate_verify_peers2(session, &mut verify_status);
        if rc < 0 as i32 {
            Curl_failf(
                data,
                b"server cert verify failed: %d\0" as *const u8 as *const libc::c_char,
                rc,
            );
            *certverifyresult = rc as i64;
            return CURLE_SSL_CONNECT_ERROR;
        }
        *certverifyresult = verify_status as i64;
        if verify_status & GNUTLS_CERT_INVALID as u32 != 0 {
            if SSL_CONN_CONFIG_verifypeer != 0 {
                #[cfg(not(CURL_DISABLE_PROXY))]
                Curl_failf(
                    data,
                    b"server certificate verification failed. CAfile: %s CRLfile: %s\0" as *const u8
                        as *const libc::c_char,
                    if !if CURLPROXY_HTTPS as u32
                        == (*conn).http_proxy.proxytype as u32
                        && ssl_connection_complete as u32
                            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                == -(1 as i32)
                            {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state as u32
                    {
                        (*conn).proxy_ssl_config.CAfile
                    } else {
                        (*conn).ssl_config.CAfile
                    }
                    .is_null()
                    {
                        (if CURLPROXY_HTTPS as u32
                            == (*conn).http_proxy.proxytype as u32
                            && ssl_connection_complete as u32
                                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                    == -(1 as i32)
                                {
                                    0 as i32
                                } else {
                                    1 as i32
                                }) as usize]
                                    .state as u32
                        {
                            (*conn).proxy_ssl_config.CAfile
                        } else {
                            (*conn).ssl_config.CAfile
                        }) as *const libc::c_char
                    } else {
                        b"none\0" as *const u8 as *const libc::c_char
                    },
                    if !if CURLPROXY_HTTPS as u32
                        == (*conn).http_proxy.proxytype as u32
                        && ssl_connection_complete as u32
                            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                == -(1 as i32)
                            {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state as u32
                    {
                        (*data).set.proxy_ssl.CRLfile
                    } else {
                        (*data).set.ssl.CRLfile
                    }
                    .is_null()
                    {
                        (if CURLPROXY_HTTPS as u32
                            == (*conn).http_proxy.proxytype as u32
                            && ssl_connection_complete as u32
                                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                    == -(1 as i32)
                                {
                                    0 as i32
                                } else {
                                    1 as i32
                                }) as usize]
                                    .state as u32
                        {
                            (*data).set.proxy_ssl.CRLfile
                        } else {
                            (*data).set.ssl.CRLfile
                        }) as *const libc::c_char
                    } else {
                        b"none\0" as *const u8 as *const libc::c_char
                    },
                );
                #[cfg(CURL_DISABLE_PROXY)]
                Curl_failf(
                    data,
                    b"server certificate verification failed. CAfile: %s CRLfile: %s\0" as *const u8
                        as *const libc::c_char,
                    if !((*conn).ssl_config.CAfile).is_null() {
                        (*conn).ssl_config.CAfile as *const libc::c_char
                    } else {
                        b"none\0" as *const u8 as *const libc::c_char
                    },
                    if !((*data).set.ssl.CRLfile).is_null() {
                        (*data).set.ssl.CRLfile as *const libc::c_char
                    } else {
                        b"none\0" as *const u8 as *const libc::c_char
                    },
                );
                return CURLE_PEER_FAILED_VERIFICATION;
            } else {
                Curl_infof(
                    data,
                    b"  server certificate verification FAILED\0" as *const u8
                        as *const libc::c_char,
                );
            }
        } else {
            Curl_infof(
                data,
                b"  server certificate verification OK\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        Curl_infof(
            data,
            b"  server certificate verification SKIPPED\0" as *const u8 as *const libc::c_char,
        );
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifystatus_1 = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        ((*conn).proxy_ssl_config).verifystatus() as i32
    } else {
        ((*conn).ssl_config).verifystatus() as i32
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifystatus_1 = ((*conn).ssl_config).verifystatus();
    if SSL_CONN_CONFIG_verifystatus_1 != 0 {
        if gnutls_ocsp_status_request_is_checked(session, 0 as u32)
            == 0 as u32
        {
            let mut status_request: gnutls_datum_t = gnutls_datum_t {
                data: 0 as *mut u8,
                size: 0,
            };
            let mut ocsp_resp: gnutls_ocsp_resp_t = 0 as *mut gnutls_ocsp_resp_int;
            let mut status: gnutls_ocsp_cert_status_t = GNUTLS_OCSP_CERT_GOOD;
            let mut reason: gnutls_x509_crl_reason_t = GNUTLS_X509_CRLREASON_UNSPECIFIED;
            rc = gnutls_ocsp_status_request_get(session, &mut status_request);
            Curl_infof(
                data,
                b" server certificate status verification FAILED\0" as *const u8
                    as *const libc::c_char,
            );
            if rc == -(56 as i32) {
                Curl_failf(
                    data,
                    b"No OCSP response received\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_SSL_INVALIDCERTSTATUS;
            }
            if rc < 0 as i32 {
                Curl_failf(
                    data,
                    b"Invalid OCSP response received\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_SSL_INVALIDCERTSTATUS;
            }
            gnutls_ocsp_resp_init(&mut ocsp_resp);
            rc = gnutls_ocsp_resp_import(ocsp_resp, &mut status_request);
            if rc < 0 as i32 {
                Curl_failf(
                    data,
                    b"Invalid OCSP response received\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_SSL_INVALIDCERTSTATUS;
            }
            gnutls_ocsp_resp_get_single(
                ocsp_resp as gnutls_ocsp_resp_const_t,
                0 as u32,
                0 as *mut gnutls_digest_algorithm_t,
                0 as *mut gnutls_datum_t,
                0 as *mut gnutls_datum_t,
                0 as *mut gnutls_datum_t,
                &mut status as *mut gnutls_ocsp_cert_status_t as *mut u32,
                0 as *mut time_t,
                0 as *mut time_t,
                0 as *mut time_t,
                &mut reason as *mut gnutls_x509_crl_reason_t as *mut u32,
            );
            match status as u32 {
                0 => {}
                1 => {
                    let mut crl_reason: *const libc::c_char = 0 as *const libc::c_char;
                    match reason as u32 {
                        1 => {
                            crl_reason =
                                b"private key compromised\0" as *const u8 as *const libc::c_char;
                        }
                        2 => {
                            crl_reason = b"CA compromised\0" as *const u8 as *const libc::c_char;
                        }
                        3 => {
                            crl_reason =
                                b"affiliation has changed\0" as *const u8 as *const libc::c_char;
                        }
                        4 => {
                            crl_reason =
                                b"certificate superseded\0" as *const u8 as *const libc::c_char;
                        }
                        5 => {
                            crl_reason =
                                b"operation has ceased\0" as *const u8 as *const libc::c_char;
                        }
                        6 => {
                            crl_reason =
                                b"certificate is on hold\0" as *const u8 as *const libc::c_char;
                        }
                        8 => {
                            crl_reason = b"will be removed from delta CRL\0" as *const u8
                                as *const libc::c_char;
                        }
                        9 => {
                            crl_reason =
                                b"privilege withdrawn\0" as *const u8 as *const libc::c_char;
                        }
                        10 => {
                            crl_reason = b"AA compromised\0" as *const u8 as *const libc::c_char;
                        }
                        0 | _ => {
                            crl_reason =
                                b"unspecified reason\0" as *const u8 as *const libc::c_char;
                        }
                    }
                    Curl_failf(
                        data,
                        b"Server certificate was revoked: %s\0" as *const u8 as *const libc::c_char,
                        crl_reason,
                    );
                }
                2 | _ => {
                    Curl_failf(
                        data,
                        b"Server certificate status is unknown\0" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            gnutls_ocsp_resp_deinit(ocsp_resp);
            return CURLE_SSL_INVALIDCERTSTATUS;
        } else {
            Curl_infof(
                data,
                b"  server certificate status verification OK\0" as *const u8
                    as *const libc::c_char,
            );
        }
    } else {
        Curl_infof(
            data,
            b"  server certificate status verification SKIPPED\0" as *const u8
                as *const libc::c_char,
        );
    }
    gnutls_x509_crt_init(&mut x509_cert);
    if !chainp.is_null() {
        gnutls_x509_crt_import(x509_cert, chainp, GNUTLS_X509_FMT_DER);
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    if !if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*conn).proxy_ssl_config.issuercert
    } else {
        (*conn).ssl_config.issuercert
    }
    .is_null()
    {
        gnutls_x509_crt_init(&mut x509_issuer);
        issuerp = load_file(
            if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*conn).proxy_ssl_config.issuercert
            } else {
                (*conn).ssl_config.issuercert
            },
        );
        gnutls_x509_crt_import(x509_issuer, &mut issuerp, GNUTLS_X509_FMT_PEM);
        rc = gnutls_x509_crt_check_issuer(x509_cert, x509_issuer) as i32;
        gnutls_x509_crt_deinit(x509_issuer);
        unload_file(issuerp);
        if rc <= 0 as i32 {
            Curl_failf(
                data,
                b"server certificate issuer check failed (IssuerCert: %s)\0" as *const u8
                    as *const libc::c_char,
                if !if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*conn).proxy_ssl_config.issuercert
                } else {
                    (*conn).ssl_config.issuercert
                }
                .is_null()
                {
                    (if CURLPROXY_HTTPS as u32
                        == (*conn).http_proxy.proxytype as u32
                        && ssl_connection_complete as u32
                            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                == -(1 as i32)
                            {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state as u32
                    {
                        (*conn).proxy_ssl_config.issuercert
                    } else {
                        (*conn).ssl_config.issuercert
                    }) as *const libc::c_char
                } else {
                    b"none\0" as *const u8 as *const libc::c_char
                },
            );
            gnutls_x509_crt_deinit(x509_cert);
            return CURLE_SSL_ISSUER_ERROR;
        }
        Curl_infof(
            data,
            b"  server certificate issuer check OK (Issuer Cert: %s)\0" as *const u8
                as *const libc::c_char,
            if !if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*conn).proxy_ssl_config.issuercert
            } else {
                (*conn).ssl_config.issuercert
            }
            .is_null()
            {
                (if CURLPROXY_HTTPS as u32
                    == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                            == -(1 as i32)
                        {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*conn).proxy_ssl_config.issuercert
                } else {
                    (*conn).ssl_config.issuercert
                }) as *const libc::c_char
            } else {
                b"none\0" as *const u8 as *const libc::c_char
            },
        );
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if !((*conn).ssl_config.issuercert).is_null() {
        gnutls_x509_crt_init(&mut x509_issuer);
        issuerp = load_file((*conn).ssl_config.issuercert);
        gnutls_x509_crt_import(x509_issuer, &mut issuerp, GNUTLS_X509_FMT_PEM);
        rc = gnutls_x509_crt_check_issuer(x509_cert, x509_issuer) as i32;
        gnutls_x509_crt_deinit(x509_issuer);
        unload_file(issuerp);
        if rc <= 0 as i32 {
            Curl_failf(
                data,
                b"server certificate issuer check failed (IssuerCert: %s)\0" as *const u8
                    as *const libc::c_char,
                if !((*conn).ssl_config.issuercert).is_null() {
                    (*conn).ssl_config.issuercert as *const libc::c_char
                } else {
                    b"none\0" as *const u8 as *const libc::c_char
                },
            );
            gnutls_x509_crt_deinit(x509_cert);
            return CURLE_SSL_ISSUER_ERROR;
        }
        Curl_infof(
            data,
            b"  server certificate issuer check OK (Issuer Cert: %s)\0" as *const u8
                as *const libc::c_char,
            if !((*conn).ssl_config.issuercert).is_null() {
                (*conn).ssl_config.issuercert as *const libc::c_char
            } else {
                b"none\0" as *const u8 as *const libc::c_char
            },
        );
    }
    size = ::std::mem::size_of::<[libc::c_char; 65]>() as u64;
    rc = gnutls_x509_crt_get_dn_by_oid(
        x509_cert,
        b"2.5.4.3\0" as *const u8 as *const libc::c_char,
        0 as u32,
        0 as u32,
        certname.as_mut_ptr() as *mut libc::c_void,
        &mut size,
    );
    if rc != 0 {
        Curl_infof(
            data,
            b"error fetching CN from cert:%s\0" as *const u8 as *const libc::c_char,
            gnutls_strerror(rc),
        );
    }
    rc = gnutls_x509_crt_check_hostname(x509_cert, hostname) as i32;
    // todo -  GNUTLS_VERSION_NUMBER < 0x030306
    // 1079
    if rc == 0 {
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_HOST_DISPNAME_void = if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                    == -(1 as i32)
                {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).http_proxy.host.dispname
        } else {
            (*conn).host.dispname
        };
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_HOST_DISPNAME_void = (*conn).host.dispname;
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_CONN_CONFIG_verifyhost = if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                    == -(1 as i32)
                {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            ((*conn).proxy_ssl_config).verifyhost() as i32
        } else {
            ((*conn).ssl_config).verifyhost() as i32
        };
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_CONN_CONFIG_verifyhost = ((*conn).ssl_config).verifyhost();
        if SSL_CONN_CONFIG_verifyhost != 0 {
            Curl_failf(
                data,
                b"SSL: certificate subject name (%s) does not match target host name '%s'\0"
                    as *const u8 as *const libc::c_char,
                certname.as_mut_ptr(),
                SSL_HOST_DISPNAME_void,
            );
            gnutls_x509_crt_deinit(x509_cert);
            return CURLE_PEER_FAILED_VERIFICATION;
        } else {
            Curl_infof(
                data,
                b"  common name: %s (does not match '%s')\0" as *const u8 as *const libc::c_char,
                certname.as_mut_ptr(),
                SSL_HOST_DISPNAME_void,
            );
        }
    } else {
        Curl_infof(
            data,
            b"  common name: %s (matched)\0" as *const u8 as *const libc::c_char,
            certname.as_mut_ptr(),
        );
    }
    certclock = gnutls_x509_crt_get_expiration_time(x509_cert);
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifypeer_1 = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32)
            {
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
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifypeer_1 = ((*conn).ssl_config).verifypeer();
    if certclock == -(1 as i32) as time_t {
        if SSL_CONN_CONFIG_verifypeer_1 != 0 {
            Curl_failf(
                data,
                b"server cert expiration date verify failed\0" as *const u8 as *const libc::c_char,
            );
            *certverifyresult = GNUTLS_CERT_EXPIRED as i64;
            gnutls_x509_crt_deinit(x509_cert);
            return CURLE_SSL_CONNECT_ERROR;
        } else {
            Curl_infof(
                data,
                b"  server certificate expiration date verify FAILED\0" as *const u8
                    as *const libc::c_char,
            );
        }
    } else if certclock < time(0 as *mut time_t) {
        if SSL_CONN_CONFIG_verifypeer_1 != 0 {
            Curl_failf(
                data,
                b"server certificate expiration date has passed.\0" as *const u8
                    as *const libc::c_char,
            );
            *certverifyresult = GNUTLS_CERT_EXPIRED as i32 as i64;
            gnutls_x509_crt_deinit(x509_cert);
            return CURLE_PEER_FAILED_VERIFICATION;
        } else {
            Curl_infof(
                data,
                b"  server certificate expiration date FAILED\0" as *const u8
                    as *const libc::c_char,
            );
        }
    } else {
        Curl_infof(
            data,
            b"  server certificate expiration date OK\0" as *const u8 as *const libc::c_char,
        );
    }
    certclock = gnutls_x509_crt_get_activation_time(x509_cert);
    if certclock == -(1 as i32) as time_t {
        if SSL_CONN_CONFIG_verifypeer_1 != 0 {
            Curl_failf(
                data,
                b"server cert activation date verify failed\0" as *const u8 as *const libc::c_char,
            );
            *certverifyresult = GNUTLS_CERT_NOT_ACTIVATED as i64;
            gnutls_x509_crt_deinit(x509_cert);
            return CURLE_SSL_CONNECT_ERROR;
        } else {
            Curl_infof(
                data,
                b"  server certificate activation date verify FAILED\0" as *const u8
                    as *const libc::c_char,
            );
        }
    } else if certclock > time(0 as *mut time_t) {
        if SSL_CONN_CONFIG_verifypeer_1 != 0 {
            Curl_failf(
                data,
                b"server certificate not activated yet.\0" as *const u8 as *const libc::c_char,
            );
            *certverifyresult = GNUTLS_CERT_NOT_ACTIVATED as i64;
            gnutls_x509_crt_deinit(x509_cert);
            return CURLE_PEER_FAILED_VERIFICATION;
        } else {
            Curl_infof(
                data,
                b"  server certificate activation date FAILED\0" as *const u8
                    as *const libc::c_char,
            );
        }
    } else {
        Curl_infof(
            data,
            b"  server certificate activation date OK\0" as *const u8 as *const libc::c_char,
        );
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_PINNED_PUB_KEY_void = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY_PROXY as usize]
    } else {
        (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as usize]
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_PINNED_PUB_KEY_void =
        (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as usize];
    ptr = SSL_PINNED_PUB_KEY_void;
    if !ptr.is_null() {
        result = pkp_pin_peer_pubkey(data, x509_cert, ptr);
        if result as u32 != CURLE_OK as u32 {
            Curl_failf(
                data,
                b"SSL: public key does not match pinned public key!\0" as *const u8
                    as *const libc::c_char,
            );
            gnutls_x509_crt_deinit(x509_cert);
            return result;
        }
    }
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    algo = gnutls_x509_crt_get_pk_algorithm(x509_cert, &mut bits) as u32;
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    Curl_infof(
        data,
        b"  certificate public key: %s\0" as *const u8 as *const libc::c_char,
        gnutls_pk_algorithm_get_name(algo as gnutls_pk_algorithm_t),
    );
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    Curl_infof(
        data,
        b"  certificate version: #%d\0" as *const u8 as *const libc::c_char,
        gnutls_x509_crt_get_version(x509_cert),
    );
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    rc = gnutls_x509_crt_get_dn2(x509_cert, &mut certfields);
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    if rc != 0 {
        Curl_infof(
            data,
            b"Failed to get certificate name\0" as *const u8 as *const libc::c_char,
        );
    } else {
        Curl_infof(
            data,
            b"  subject: %s\0" as *const u8 as *const libc::c_char,
            certfields.data,
        );
        certclock = gnutls_x509_crt_get_activation_time(x509_cert);
        showtime(
            data,
            b"start date\0" as *const u8 as *const libc::c_char,
            certclock,
        );
        certclock = gnutls_x509_crt_get_expiration_time(x509_cert);
        showtime(
            data,
            b"expire date\0" as *const u8 as *const libc::c_char,
            certclock,
        );
        gnutls_free.expect("non-null function pointer")(certfields.data as *mut libc::c_void);
    }
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    rc = gnutls_x509_crt_get_issuer_dn2(x509_cert, &mut certfields);
    #[cfg(not(CURL_DISABLE_VERBOSE_STRINGS))]
    if rc != 0 {
        Curl_infof(
            data,
            b"Failed to get certificate issuer\0" as *const u8 as *const libc::c_char,
        );
    } else {
        Curl_infof(
            data,
            b"  issuer: %s\0" as *const u8 as *const libc::c_char,
            certfields.data,
        );
        gnutls_free.expect("non-null function pointer")(certfields.data as *mut libc::c_void);
    }
    gnutls_x509_crt_deinit(x509_cert);
    if ((*conn).bits).tls_enable_alpn() != 0 {
        rc = gnutls_alpn_get_selected_protocol(session, &mut proto);
        if rc == 0 as i32 {
            Curl_infof(
                data,
                b"ALPN, server accepted to use %.*s\0" as *const u8 as *const libc::c_char,
                proto.size,
                proto.data,
            );
            // done - 1254
            #[cfg(USE_HTTP2)]
            let USE_HTTP2_flag = proto.size == 2 as u32
                && memcmp(
                    b"h2\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    proto.data as *const libc::c_void,
                    2 as u64,
                ) == 0;
            #[cfg(not(USE_HTTP2))]
            let USE_HTTP2_flag = false;
            if USE_HTTP2_flag {
                (*conn).negnpn = CURL_HTTP_VERSION_2_0 as i32;
            } else if proto.size == 8 as u32
                && memcmp(
                    b"http/1.1\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    proto.data as *const libc::c_void,
                    8 as u64,
                ) == 0
            {
                (*conn).negnpn = CURL_HTTP_VERSION_1_1 as i32;
            }
        } else {
            Curl_infof(
                data,
                b"ALPN, server did not agree to a protocol\0" as *const u8 as *const libc::c_char,
            );
        }
        Curl_multiuse_state(
            data,
            if (*conn).negnpn == CURL_HTTP_VERSION_2_0 as i32 {
                2 as i32
            } else {
                -(1 as i32)
            },
        );
    }
    (*conn).ssl[sockindex as usize].state = ssl_connection_complete;
    (*conn).recv[sockindex as usize] = Some(gtls_recv as Curl_recv);
    (*conn).send[sockindex as usize] = Some(gtls_send as Curl_send);
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        ((*data).set.proxy_ssl.primary).sessionid() as i32
    } else {
        ((*data).set.ssl.primary).sessionid() as i32
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_sessionid = ((*data).set.ssl.primary).sessionid();
    if SSL_SET_OPTION_primary_sessionid != 0 {
        let mut connect_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
        let mut connect_idsize: size_t = 0 as size_t;
        gnutls_session_get_data(session, 0 as *mut libc::c_void, &mut connect_idsize);
        match () {
            #[cfg(not(CURLDEBUG))]
            _ => {
                connect_sessionid =
                    Curl_cmalloc.expect("non-null function pointer")(connect_idsize);
            }
            #[cfg(CURLDEBUG)]
            _ => {
                connect_sessionid = curl_dbg_malloc(
                    connect_idsize,
                    1286 as i32,
                    b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
                );
            }
        }

        if !connect_sessionid.is_null() {
            let mut incache: bool = false;
            let mut ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
            gnutls_session_get_data(session, connect_sessionid, &mut connect_idsize);
            Curl_ssl_sessionid_lock(data);
            #[cfg(not(CURL_DISABLE_PROXY))]
            let SSL_IS_PROXY_void_1 = if CURLPROXY_HTTPS as u32
                == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                        == -(1 as i32)
                    {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                1 as i32
            } else {
                0 as i32
            } != 0;
            #[cfg(CURL_DISABLE_PROXY)]
            let SSL_IS_PROXY_void_1 = if 0 as i32 != 0 {
                1 as i32
            } else {
                0 as i32
            } != 0;
            incache = !Curl_ssl_getsessionid(
                data,
                conn,
                SSL_IS_PROXY_void_1,
                &mut ssl_sessionid,
                0 as *mut size_t,
                sockindex,
            );
            if incache {
                Curl_ssl_delsessionid(data, ssl_sessionid);
            }
            result = Curl_ssl_addsessionid(
                data,
                conn,
                SSL_IS_PROXY_void_1,
                connect_sessionid,
                connect_idsize,
                sockindex,
            );
            Curl_ssl_sessionid_unlock(data);
            if result as u64 != 0 {
                #[cfg(not(CURLDEBUG))]
                Curl_cfree.expect("non-null function pointer")(connect_sessionid);

                #[cfg(CURLDEBUG)]
                curl_dbg_free(
                    connect_sessionid,
                    1312 as i32,
                    b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
                );
                result = CURLE_OUT_OF_MEMORY;
            }
        } else {
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    return result;
}
unsafe extern "C" fn gtls_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> CURLcode {
    let mut rc: i32 = 0;
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
    if ssl_connect_1 as u32 == (*connssl).connecting_state as u32 {
        rc = gtls_connect_step1(data, conn, sockindex) as i32;
        if rc != 0 {
            return rc as CURLcode;
        }
    }
    rc = handshake(data, conn, sockindex, 1 as i32 != 0, nonblocking) as i32;
    if rc != 0 {
        return rc as CURLcode;
    }
    if ssl_connect_1 as u32 == (*connssl).connecting_state as u32 {
        rc = gtls_connect_step3(data, conn, sockindex) as i32;
        if rc != 0 {
            return rc as CURLcode;
        }
    }
    *done =
        ssl_connect_1 as u32 == (*connssl).connecting_state as u32;
    return CURLE_OK;
}
unsafe extern "C" fn gtls_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    return gtls_connect_common(data, conn, sockindex, 1 as i32 != 0, done);
}
unsafe extern "C" fn gtls_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut done: bool = 0 as i32 != 0;
    result = gtls_connect_common(data, conn, sockindex, 0 as i32 != 0, &mut done);
    if result as u64 != 0 {
        return result;
    }
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if done {
    } else {
        __assert_fail(
            b"done\0" as *const u8 as *const libc::c_char,
            b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
            1384 as u32,
            (*::std::mem::transmute::<&[u8; 69], &[libc::c_char; 69]>(
                b"CURLcode gtls_connect(struct Curl_easy *, struct connectdata *, int)\0",
            ))
            .as_ptr(),
        );
    }
    return CURLE_OK;
}
unsafe extern "C" fn gtls_data_pending(
    mut conn: *const connectdata,
    mut connindex: i32,
) -> bool {
    let mut connssl: *const ssl_connect_data =
        &*((*conn).ssl).as_ptr().offset(connindex as isize) as *const ssl_connect_data;
    let mut res: bool = 0 as i32 != 0;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if !((*backend).session).is_null()
        && 0 as u64 != gnutls_record_check_pending((*backend).session)
    {
        res = 1 as i32 != 0;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    if true {
        connssl =
            &*((*conn).proxy_ssl).as_ptr().offset(connindex as isize) as *const ssl_connect_data;
        backend = (*connssl).backend;
        if !((*backend).session).is_null()
            && 0 as u64 != gnutls_record_check_pending((*backend).session)
        {
            res = 1 as i32 != 0;
        }
    }

    return res;
}
unsafe extern "C" fn gtls_send(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut rc: ssize_t = gnutls_record_send((*backend).session, mem, len);
    if rc < 0 as i64 {
        *curlcode = (if rc == -(28 as i32) as i64 {
            CURLE_AGAIN as i32
        } else {
            CURLE_SEND_ERROR as i32
        }) as CURLcode;
        rc = -(1 as i32) as ssize_t;
    }
    return rc;
}
unsafe extern "C" fn close_one(mut connssl: *mut ssl_connect_data) {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if !((*backend).session).is_null() {
        let mut buf: [libc::c_char; 32] = [0; 32];
        gnutls_record_recv(
            (*backend).session,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[libc::c_char; 32]>() as u64,
        );
        gnutls_bye((*backend).session, GNUTLS_SHUT_WR);
        gnutls_deinit((*backend).session);
        (*backend).session = 0 as gnutls_session_t;
    }
    if !((*backend).cred).is_null() {
        gnutls_certificate_free_credentials((*backend).cred);
        (*backend).cred = 0 as gnutls_certificate_credentials_t;
    }
    #[cfg(HAVE_GNUTLS_SRP)]
    if !((*backend).srp_client_cred).is_null() {
        gnutls_srp_free_client_credentials((*backend).srp_client_cred);
        (*backend).srp_client_cred = 0 as gnutls_srp_client_credentials_t;
    }
}
unsafe extern "C" fn gtls_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
    close_one(&mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize));
    #[cfg(not(CURL_DISABLE_PROXY))]
    close_one(&mut *((*conn).proxy_ssl).as_mut_ptr().offset(sockindex as isize));
}

unsafe extern "C" fn gtls_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> i32 {
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut retval: i32 = 0 as i32;
    #[cfg(not(CURL_DISABLE_FTP))]
    if (*data).set.ftp_ccc as u32 == CURLFTPSSL_CCC_ACTIVE as u32 {
        gnutls_bye((*backend).session, GNUTLS_SHUT_WR);
    }
    if !((*backend).session).is_null() {
        let mut result: ssize_t = 0;
        let mut done: bool = 0 as i32 != 0;
        let mut buf: [libc::c_char; 120] = [0; 120];
        while !done {
            let mut what: i32 = Curl_socket_check(
                (*conn).sock[sockindex as usize],
                -(1 as i32),
                -(1 as i32),
                10000 as timediff_t,
            );
            if what > 0 as i32 {
                result = gnutls_record_recv(
                    (*backend).session,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    ::std::mem::size_of::<[libc::c_char; 120]>() as u64,
                );
                match result {
                    0 => {
                        done = 1 as i32 != 0;
                    }
                    -28 | -52 => {
                        Curl_infof(
                            data,
                            b"GNUTLS_E_AGAIN || GNUTLS_E_INTERRUPTED\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    _ => {
                        retval = -(1 as i32);
                        done = 1 as i32 != 0;
                    }
                }
            } else if 0 as i32 == what {
                Curl_failf(
                    data,
                    b"SSL shutdown timeout\0" as *const u8 as *const libc::c_char,
                );
                done = 1 as i32 != 0;
            } else {
                Curl_failf(
                    data,
                    b"select/poll on SSL socket, errno: %d\0" as *const u8 as *const libc::c_char,
                    *__errno_location(),
                );
                retval = -(1 as i32);
                done = 1 as i32 != 0;
            }
        }
        gnutls_deinit((*backend).session);
    }
    gnutls_certificate_free_credentials((*backend).cred);
    #[cfg(all(HAVE_GNUTLS_SRP, not(CURL_DISABLE_PROXY)))]
    if (if CURLPROXY_HTTPS as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as u32
            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
            {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state as u32
    {
        (*data).set.proxy_ssl.authtype as u32
    } else {
        (*data).set.ssl.authtype as u32
    }) == CURL_TLSAUTH_SRP as u32
        && !(if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete aas u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                    == -(1 as i32)
                {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*data).set.proxy_ssl.username
        } else {
            (*data).set.ssl.username
        })
        .is_null()
    {
        gnutls_srp_free_client_credentials((*backend).srp_client_cred);
    }
    #[cfg(all(HAVE_GNUTLS_SRP, CURL_DISABLE_PROXY))]
    if (*data).set.ssl.authtype as u32 == CURL_TLSAUTH_SRP as u32
        && !((*data).set.ssl.username).is_null()
    {
        gnutls_srp_free_client_credentials((*backend).srp_client_cred);
    }
    (*backend).cred = 0 as gnutls_certificate_credentials_t;
    (*backend).session = 0 as gnutls_session_t;
    return retval;
}

unsafe extern "C" fn gtls_recv(
    mut data: *mut Curl_easy,
    mut num: i32,
    mut buf: *mut libc::c_char,
    mut buffersize: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(num as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut ret: ssize_t = 0;
    ret = gnutls_record_recv((*backend).session, buf as *mut libc::c_void, buffersize);
    if ret == -(28 as i32) as i64 || ret == -(52 as i32) as i64 {
        *curlcode = CURLE_AGAIN;
        return -(1 as i32) as ssize_t;
    }
    if ret == -(37 as i32) as i64 {
        let mut result: CURLcode = handshake(
            data,
            conn,
            num,
            0 as i32 != 0,
            0 as i32 != 0,
        );
        if result as u64 != 0 {
            *curlcode = result;
        } else {
            *curlcode = CURLE_AGAIN;
        }
        return -(1 as i32) as ssize_t;
    }
    if ret < 0 as i32 as i64 {
        Curl_failf(
            data,
            b"GnuTLS recv error (%d): %s\0" as *const u8 as *const libc::c_char,
            ret as i32,
            gnutls_strerror(ret as i32),
        );
        *curlcode = CURLE_RECV_ERROR;
        return -(1 as i32) as ssize_t;
    }
    return ret;
}
unsafe extern "C" fn gtls_session_free(mut ptr: *mut libc::c_void) {
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(ptr);

    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        ptr,
        1586 as i32,
        b"vtls/gtls.c\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn gtls_version(mut buffer: *mut libc::c_char, mut size: size_t) -> size_t {
    return curl_msnprintf(
        buffer,
        size,
        b"GnuTLS/%s\0" as *const u8 as *const libc::c_char,
        gnutls_check_version(0 as *const libc::c_char),
    ) as size_t;
}
unsafe extern "C" fn gtls_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut u8,
    mut length: size_t,
) -> CURLcode {
    let mut rc: i32 = 0;
    rc = gnutls_rnd(GNUTLS_RND_RANDOM, entropy as *mut libc::c_void, length);
    return (if rc != 0 {
        CURLE_FAILED_INIT as i32
    } else {
        CURLE_OK as i32
    }) as CURLcode;
}
unsafe extern "C" fn gtls_sha256sum(
    mut tmp: *const u8,
    mut tmplen: size_t,
    mut sha256sum: *mut u8,
    mut sha256len: size_t,
) -> CURLcode {
    let mut SHA256pw: sha256_ctx = sha256_ctx {
        state: [0; 8],
        count: 0,
        block: [0; 64],
        index: 0,
    };
    nettle_sha256_init(&mut SHA256pw);
    nettle_sha256_update(&mut SHA256pw, tmplen as size_t, tmp);
    nettle_sha256_digest(
        &mut SHA256pw,
        sha256len as size_t,
        sha256sum,
    );
    return CURLE_OK;
}
unsafe extern "C" fn gtls_cert_status_request() -> bool {
    return 1 as i32 != 0;
}
unsafe extern "C" fn gtls_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return (*backend).session as *mut libc::c_void;
}
#[no_mangle]
pub static mut Curl_ssl_gnutls: Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_GNUTLS,
                    name: b"gnutls\0" as *const u8 as *const libc::c_char,
                };
                init
            },
            supports: ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32
                | (1 as i32) << 2 as i32
                | (1 as i32) << 4 as i32) as u32,
            sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>() as u64,
            init: Some(gtls_init as unsafe extern "C" fn() -> i32),
            cleanup: Some(gtls_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(
                gtls_version as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t,
            ),
            check_cxn: Some(
                Curl_none_check_cxn as unsafe extern "C" fn(*mut connectdata) -> i32,
            ),
            shut_down: Some(
                gtls_shutdown
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        i32,
                    ) -> i32,
            ),
            data_pending: Some(
                gtls_data_pending as unsafe extern "C" fn(*const connectdata, i32) -> bool,
            ),
            random: Some(
                gtls_random
                    as unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode,
            ),
            cert_status_request: Some(gtls_cert_status_request as unsafe extern "C" fn() -> bool),
            connect_blocking: Some(
                gtls_connect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        i32,
                    ) -> CURLcode,
            ),
            connect_nonblocking: Some(
                gtls_connect_nonblocking
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        i32,
                        *mut bool,
                    ) -> CURLcode,
            ),
            getsock: Some(
                Curl_ssl_getsock
                    as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32,
            ),
            get_internals: Some(
                gtls_get_internals
                    as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
            ),
            close_one: Some(
                gtls_close
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
            ),
            close_all: Some(Curl_none_close_all as unsafe extern "C" fn(*mut Curl_easy) -> ()),
            session_free: Some(gtls_session_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
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
                gtls_sha256sum
                    as unsafe extern "C" fn(
                        *const u8,
                        size_t,
                        *mut u8,
                        size_t,
                    ) -> CURLcode,
            ),
            associate_connection: None,
            disassociate_connection: None,
        };
        init
    }
};
