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
 * Description: support rustls backend
 ******************************************************************************/
use ::libc;
// use c2rust_bitfields::BitfieldStruct;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
use crate::src::vtls::vtls::*;
// #[derive(Copy, Clone)]
// #[repr(C)]
// pub struct ssl_backend_data {
//     pub config: *const rustls_client_config,
//     pub conn: *mut rustls_connection,
//     pub data_pending: bool,
// }

unsafe extern "C" fn map_error(mut r: rustls_result) -> CURLcode {
    if rustls_result_is_cert_error(r) {
        return CURLE_PEER_FAILED_VERIFICATION;
    }
    match r as libc::c_uint {
        7000 => return CURLE_OK,
        7002 => return CURLE_BAD_FUNCTION_ARGUMENT,
        _ => return CURLE_READ_ERROR,
    };
}
unsafe extern "C" fn cr_data_pending(
    mut conn: *const connectdata,
    mut sockindex: libc::c_int,
) -> bool {
    let mut connssl: *const ssl_connect_data = &*((*conn).ssl)
        .as_ptr()
        .offset(sockindex as isize) as *const ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return (*backend).data_pending;
}
unsafe extern "C" fn cr_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    Curl_infof(
        data,
        b"rustls_connect: unimplemented\0" as *const u8 as *const libc::c_char,
    );
    return CURLE_SSL_CONNECT_ERROR;
}
unsafe extern "C" fn read_cb(
    mut userdata: *mut libc::c_void,
    mut buf: *mut uint8_t,
    mut len: uintptr_t,
    mut out_n: *mut uintptr_t,
) -> libc::c_int {
    let mut n: ssize_t = recv(
        *(userdata as *mut libc::c_int),
        buf as *mut libc::c_void,
        len,
        0 as libc::c_int,
    );
    if n < 0 as libc::c_int as libc::c_long {
        return *__errno_location();
    }
    *out_n = n as uintptr_t;
    return 0 as libc::c_int;
}
unsafe extern "C" fn write_cb(
    mut userdata: *mut libc::c_void,
    mut buf: *const uint8_t,
    mut len: uintptr_t,
    mut out_n: *mut uintptr_t,
) -> libc::c_int {
    let mut n: ssize_t = send(
        *(userdata as *mut libc::c_int),
        buf as *const libc::c_void,
        len,
        MSG_NOSIGNAL as libc::c_int,
    );
    if n < 0 as libc::c_int as libc::c_long {
        return *__errno_location();
    }
    *out_n = n as uintptr_t;
    return 0 as libc::c_int;
}
unsafe extern "C" fn cr_recv(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut plainbuf: *mut libc::c_char,
    mut plainlen: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let backend: *mut ssl_backend_data = (*connssl).backend;
    let rconn: *mut rustls_connection = (*backend).conn;
    let mut n: size_t = 0 as libc::c_int as size_t;
    let mut tls_bytes_read: size_t = 0 as libc::c_int as size_t;
    let mut plain_bytes_copied: size_t = 0 as libc::c_int as size_t;
    let mut rresult: rustls_result = 0 as rustls_result;
    let mut errorbuf: [libc::c_char; 255] = [0; 255];
    let mut io_error: rustls_io_result = 0;
    io_error = rustls_connection_read_tls(
        rconn,
        Some(
            read_cb
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut uint8_t,
                    uintptr_t,
                    *mut uintptr_t,
                ) -> libc::c_int,
        ),
        &mut *((*conn).sock).as_mut_ptr().offset(sockindex as isize)
            as *mut curl_socket_t as *mut libc::c_void,
        &mut tls_bytes_read,
    );
    if io_error == 11 as libc::c_int || io_error == 11 as libc::c_int {
        Curl_infof(
            data,
            b"sread: EAGAIN or EWOULDBLOCK\0" as *const u8 as *const libc::c_char,
        );
    } else if io_error != 0 {
        let mut buffer: [libc::c_char; 256] = [0; 256];
        Curl_failf(
            data,
            b"reading from socket: %s\0" as *const u8 as *const libc::c_char,
            Curl_strerror(
                io_error,
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            ),
        );
        *err = CURLE_READ_ERROR;
        return -(1 as libc::c_int) as ssize_t;
    } else {
        if tls_bytes_read == 0 as libc::c_int as libc::c_ulong {
            Curl_failf(
                data,
                b"connection closed without TLS close_notify alert\0" as *const u8
                    as *const libc::c_char,
            );
            *err = CURLE_READ_ERROR;
            return -(1 as libc::c_int) as ssize_t;
        }
    }
    Curl_infof(
        data,
        b"cr_recv read %ld bytes from the network\0" as *const u8 as *const libc::c_char,
        tls_bytes_read,
    );
    rresult = rustls_connection_process_new_packets(rconn);
    if rresult as libc::c_uint != RUSTLS_RESULT_OK as libc::c_int as libc::c_uint {
        rustls_error(
            rresult,
            errorbuf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 255]>() as libc::c_ulong,
            &mut n,
        );
        Curl_failf(
            data,
            b"%.*s\0" as *const u8 as *const libc::c_char,
            n,
            errorbuf.as_mut_ptr(),
        );
        *err = map_error(rresult);
        return -(1 as libc::c_int) as ssize_t;
    }
    (*backend).data_pending = 1 as libc::c_int != 0;
    while plain_bytes_copied < plainlen {
        rresult = rustls_connection_read(
            rconn,
            (plainbuf as *mut uint8_t).offset(plain_bytes_copied as isize),
            plainlen.wrapping_sub(plain_bytes_copied),
            &mut n,
        );
        if rresult as libc::c_uint
            == RUSTLS_RESULT_ALERT_CLOSE_NOTIFY as libc::c_int as libc::c_uint
        {
            *err = CURLE_OK;
            return 0 as libc::c_int as ssize_t;
        } else if rresult as libc::c_uint
                != RUSTLS_RESULT_OK as libc::c_int as libc::c_uint
            {
            Curl_failf(
                data,
                b"error in rustls_connection_read\0" as *const u8 as *const libc::c_char,
            );
            *err = CURLE_READ_ERROR;
            return -(1 as libc::c_int) as ssize_t;
        } else if n == 0 as libc::c_int as libc::c_ulong {
            Curl_infof(
                data,
                b"cr_recv got 0 bytes of plaintext\0" as *const u8 as *const libc::c_char,
            );
            (*backend).data_pending = 0 as libc::c_int != 0;
            break;
        } else {
            Curl_infof(
                data,
                b"cr_recv copied out %ld bytes of plaintext\0" as *const u8
                    as *const libc::c_char,
                n,
            );
            plain_bytes_copied = (plain_bytes_copied as libc::c_ulong).wrapping_add(n)
                as size_t as size_t;
        }
    }
    if plain_bytes_copied == 0 as libc::c_int as libc::c_ulong {
        *err = CURLE_AGAIN;
        return -(1 as libc::c_int) as ssize_t;
    }
    return plain_bytes_copied as ssize_t;
}
unsafe extern "C" fn cr_send(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut plainbuf: *const libc::c_void,
    mut plainlen: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let backend: *mut ssl_backend_data = (*connssl).backend;
    let rconn: *mut rustls_connection = (*backend).conn;
    let mut plainwritten: size_t = 0 as libc::c_int as size_t;
    let mut tlswritten: size_t = 0 as libc::c_int as size_t;
    let mut tlswritten_total: size_t = 0 as libc::c_int as size_t;
    let mut rresult: rustls_result = 0 as rustls_result;
    let mut io_error: rustls_io_result = 0;
    Curl_infof(
        data,
        b"cr_send %ld bytes of plaintext\0" as *const u8 as *const libc::c_char,
        plainlen,
    );
    if plainlen > 0 as libc::c_int as libc::c_ulong {
        rresult = rustls_connection_write(
            rconn,
            plainbuf as *const uint8_t,
            plainlen,
            &mut plainwritten,
        );
        if rresult as libc::c_uint != RUSTLS_RESULT_OK as libc::c_int as libc::c_uint {
            Curl_failf(
                data,
                b"error in rustls_connection_write\0" as *const u8 as *const libc::c_char,
            );
            *err = CURLE_WRITE_ERROR;
            return -(1 as libc::c_int) as ssize_t;
        } else {
            if plainwritten == 0 as libc::c_int as libc::c_ulong {
                Curl_failf(
                    data,
                    b"EOF in rustls_connection_write\0" as *const u8
                        as *const libc::c_char,
                );
                *err = CURLE_WRITE_ERROR;
                return -(1 as libc::c_int) as ssize_t;
            }
        }
    }
    while rustls_connection_wants_write(rconn) {
        io_error = rustls_connection_write_tls(
            rconn,
            Some(
                write_cb
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                        uintptr_t,
                        *mut uintptr_t,
                    ) -> libc::c_int,
            ),
            &mut *((*conn).sock).as_mut_ptr().offset(sockindex as isize)
                as *mut curl_socket_t as *mut libc::c_void,
            &mut tlswritten,
        );
        if io_error == 11 as libc::c_int || io_error == 11 as libc::c_int {
            Curl_infof(
                data,
                b"swrite: EAGAIN after %ld bytes\0" as *const u8 as *const libc::c_char,
                tlswritten_total,
            );
            *err = CURLE_AGAIN;
            return -(1 as libc::c_int) as ssize_t;
        } else {
            if io_error != 0 {
                let mut buffer: [libc::c_char; 256] = [0; 256];
                Curl_failf(
                    data,
                    b"writing to socket: %s\0" as *const u8 as *const libc::c_char,
                    Curl_strerror(
                        io_error,
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                    ),
                );
                *err = CURLE_WRITE_ERROR;
                return -(1 as libc::c_int) as ssize_t;
            }
        }
        if tlswritten == 0 as libc::c_int as libc::c_ulong {
            Curl_failf(data, b"EOF in swrite\0" as *const u8 as *const libc::c_char);
            *err = CURLE_WRITE_ERROR;
            return -(1 as libc::c_int) as ssize_t;
        }
        Curl_infof(
            data,
            b"cr_send wrote %ld bytes to network\0" as *const u8 as *const libc::c_char,
            tlswritten,
        );
        tlswritten_total = (tlswritten_total as libc::c_ulong).wrapping_add(tlswritten)
            as size_t as size_t;
    }
    return plainwritten as ssize_t;
}
unsafe extern "C" fn cr_verify_none(
    mut userdata: *mut libc::c_void,
    mut params: *const rustls_verify_server_cert_params,
) -> rustls_result {
    return RUSTLS_RESULT_OK;
}
unsafe extern "C" fn cr_hostname_is_ip(mut hostname: *const libc::c_char) -> bool {
    let mut in_0: in_addr = in_addr { s_addr: 0 };
    let mut in6: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_8 {
            __u6_addr8: [0; 16],
        },
    };
    if inet_pton(
        10 as libc::c_int,
        hostname,
        &mut in6 as *mut in6_addr as *mut libc::c_void,
    ) > 0 as libc::c_int
    {
        return 1 as libc::c_int != 0;
    }
    if inet_pton(
        2 as libc::c_int,
        hostname,
        &mut in_0 as *mut in_addr as *mut libc::c_void,
    ) > 0 as libc::c_int
    {
        return 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
unsafe extern "C" fn cr_init_backend(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    backend: *mut ssl_backend_data,
) -> CURLcode {
    let mut rconn: *mut rustls_connection = (*backend).conn;
    let mut config_builder: *mut rustls_client_config_builder = 0
        as *mut rustls_client_config_builder;
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
    let mut hostname: *const libc::c_char = (*conn).host.name;
    let mut errorbuf: [libc::c_char; 256] = [0; 256];
    let mut errorlen: size_t = 0;
    let mut result: libc::c_int = 0;
    let mut alpn: [rustls_slice_bytes; 2] = [
        {
            let mut init = rustls_slice_bytes {
                data: b"http/1.1\0" as *const u8 as *const libc::c_char
                    as *const uint8_t,
                len: 8 as libc::c_int as size_t,
            };
            init
        },
        {
            let mut init = rustls_slice_bytes {
                data: b"h2\0" as *const u8 as *const libc::c_char as *const uint8_t,
                len: 2 as libc::c_int as size_t,
            };
            init
        },
    ];
    config_builder = rustls_client_config_builder_new();
    Curl_infof(
        data,
        b"offering ALPN for HTTP/1.1 and HTTP/2\0" as *const u8 as *const libc::c_char,
    );
    rustls_client_config_builder_set_protocols(
        config_builder,
        alpn.as_mut_ptr(),
        2 as libc::c_int as size_t,
    );
    if !verifypeer {
        rustls_client_config_builder_dangerous_set_certificate_verifier(
            config_builder,
            Some(
                cr_verify_none
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const rustls_verify_server_cert_params,
                    ) -> rustls_result,
            ),
        );
        if cr_hostname_is_ip(hostname) {
            rustls_client_config_builder_set_enable_sni(
                config_builder,
                0 as libc::c_int != 0,
            );
            hostname = b"example.invalid\0" as *const u8 as *const libc::c_char;
        }
    } else if !ssl_cafile.is_null() {
        result = rustls_client_config_builder_load_roots_from_file(
            config_builder,
            ssl_cafile,
        ) as libc::c_int;
        if result != RUSTLS_RESULT_OK as libc::c_int {
            Curl_failf(
                data,
                b"failed to load trusted certificates\0" as *const u8
                    as *const libc::c_char,
            );
            rustls_client_config_free(
                rustls_client_config_builder_build(config_builder),
            );
            return CURLE_SSL_CACERT_BADFILE;
        }
    }
    let ref mut fresh0 = (*backend).config;
    *fresh0 = rustls_client_config_builder_build(config_builder);
    result = rustls_client_connection_new((*backend).config, hostname, &mut rconn)
        as libc::c_int;
    if result != RUSTLS_RESULT_OK as libc::c_int {
        rustls_error(
            result as rustls_result,
            errorbuf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            &mut errorlen,
        );
        Curl_failf(
            data,
            b"rustls_client_connection_new: %.*s\0" as *const u8 as *const libc::c_char,
            errorlen,
            errorbuf.as_mut_ptr(),
        );
        return CURLE_COULDNT_CONNECT;
    }
    rustls_connection_set_userdata(rconn, backend as *mut libc::c_void);
    let ref mut fresh1 = (*backend).conn;
    *fresh1 = rconn;
    return CURLE_OK;
}
unsafe extern "C" fn cr_set_negotiated_alpn(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut rconn: *const rustls_connection,
) {
    let mut protocol: *const uint8_t = 0 as *const uint8_t;
    let mut len: size_t = 0 as libc::c_int as size_t;
    rustls_connection_get_alpn_protocol(rconn, &mut protocol, &mut len);
    if protocol.is_null() {
        Curl_infof(
            data,
            b"ALPN, server did not agree to a protocol\0" as *const u8
                as *const libc::c_char,
        );
        return;
    }
    if len == 2 as libc::c_int as libc::c_ulong
        && 0 as libc::c_int
            == memcmp(
                b"h2\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                protocol as *const libc::c_void,
                len,
            )
    {
        Curl_infof(data, b"ALPN, negotiated h2\0" as *const u8 as *const libc::c_char);
        (*conn).negnpn = CURL_HTTP_VERSION_2_0 as libc::c_int;
    } else if len == 8 as libc::c_int as libc::c_ulong
            && 0 as libc::c_int
                == memcmp(
                    b"http/1.1\0" as *const u8 as *const libc::c_char
                        as *const libc::c_void,
                    protocol as *const libc::c_void,
                    len,
                )
        {
        Curl_infof(
            data,
            b"ALPN, negotiated http/1.1\0" as *const u8 as *const libc::c_char,
        );
        (*conn).negnpn = CURL_HTTP_VERSION_1_1 as libc::c_int;
    } else {
        Curl_infof(
            data,
            b"ALPN, negotiated an unrecognized protocol\0" as *const u8
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
unsafe extern "C" fn cr_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    let connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
    let backend: *mut ssl_backend_data = (*connssl).backend;
    let mut rconn: *mut rustls_connection = 0 as *mut rustls_connection;
    let mut tmperr: CURLcode = CURLE_OK;
    let mut result: libc::c_int = 0;
    let mut what: libc::c_int = 0;
    let mut wants_read: bool = false;
    let mut wants_write: bool = false;
    let mut writefd: curl_socket_t = 0;
    let mut readfd: curl_socket_t = 0;
    if ssl_connection_none as libc::c_int as libc::c_uint
        == (*connssl).state as libc::c_uint
    {
        result = cr_init_backend(data, conn, (*connssl).backend) as libc::c_int;
        if result != CURLE_OK as libc::c_int {
            return result as CURLcode;
        }
        (*connssl).state = ssl_connection_negotiating;
    }
    rconn = (*backend).conn;
    loop {
        if !rustls_connection_is_handshaking(rconn) {
            Curl_infof(data, b"Done handshaking\0" as *const u8 as *const libc::c_char);
            (*connssl).state = ssl_connection_complete;
            cr_set_negotiated_alpn(data, conn, rconn);
            let ref mut fresh2 = (*conn).recv[sockindex as usize];
            *fresh2 = Some(
                cr_recv
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        libc::c_int,
                        *mut libc::c_char,
                        size_t,
                        *mut CURLcode,
                    ) -> ssize_t,
            );
            let ref mut fresh3 = (*conn).send[sockindex as usize];
            *fresh3 = Some(
                cr_send
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        libc::c_int,
                        *const libc::c_void,
                        size_t,
                        *mut CURLcode,
                    ) -> ssize_t,
            );
            *done = 1 as libc::c_int != 0;
            return CURLE_OK;
        }
        wants_read = rustls_connection_wants_read(rconn);
        wants_write = rustls_connection_wants_write(rconn);
        writefd = if wants_write as libc::c_int != 0 {
            sockfd
        } else {
            -(1 as libc::c_int)
        };
        readfd = if wants_read as libc::c_int != 0 {
            sockfd
        } else {
            -(1 as libc::c_int)
        };
        what = Curl_socket_check(
            readfd,
            -(1 as libc::c_int),
            writefd,
            0 as libc::c_int as timediff_t,
        );
        if what < 0 as libc::c_int {
            Curl_failf(
                data,
                b"select/poll on SSL socket, errno: %d\0" as *const u8
                    as *const libc::c_char,
                *__errno_location(),
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        if 0 as libc::c_int == what {
            Curl_infof(
                data,
                b"Curl_socket_check: %s would block\0" as *const u8
                    as *const libc::c_char,
                if wants_read as libc::c_int != 0 && wants_write as libc::c_int != 0 {
                    b"writing and reading\0" as *const u8 as *const libc::c_char
                } else if wants_write as libc::c_int != 0 {
                    b"writing\0" as *const u8 as *const libc::c_char
                } else {
                    b"reading\0" as *const u8 as *const libc::c_char
                },
            );
            *done = 0 as libc::c_int != 0;
            return CURLE_OK;
        }
        if wants_write {
            Curl_infof(
                data,
                b"rustls_connection wants us to write_tls.\0" as *const u8
                    as *const libc::c_char,
            );
            cr_send(
                data,
                sockindex,
                0 as *const libc::c_void,
                0 as libc::c_int as size_t,
                &mut tmperr,
            );
            if tmperr as libc::c_uint == CURLE_AGAIN as libc::c_int as libc::c_uint {
                Curl_infof(
                    data,
                    b"writing would block\0" as *const u8 as *const libc::c_char,
                );
            } else if tmperr as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
                return tmperr
            }
        }
        if wants_read {
            Curl_infof(
                data,
                b"rustls_connection wants us to read_tls.\0" as *const u8
                    as *const libc::c_char,
            );
            cr_recv(
                data,
                sockindex,
                0 as *mut libc::c_char,
                0 as libc::c_int as size_t,
                &mut tmperr,
            );
            if tmperr as libc::c_uint == CURLE_AGAIN as libc::c_int as libc::c_uint {
                Curl_infof(
                    data,
                    b"reading would block\0" as *const u8 as *const libc::c_char,
                );
            } else if tmperr as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
                if tmperr as libc::c_uint
                    == CURLE_READ_ERROR as libc::c_int as libc::c_uint
                {
                    return CURLE_SSL_CONNECT_ERROR
                } else {
                    return tmperr
                }
            }
        }
    };
}
unsafe extern "C" fn cr_getsock(
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> libc::c_int {
    let connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut ssl_connect_data;
    let mut sockfd: curl_socket_t = (*conn).sock[0 as libc::c_int as usize];
    let backend: *mut ssl_backend_data = (*connssl).backend;
    let mut rconn: *mut rustls_connection = (*backend).conn;
    if rustls_connection_wants_write(rconn) {
        *socks.offset(0 as libc::c_int as isize) = sockfd;
        return (1 as libc::c_int) << 16 as libc::c_int + 0 as libc::c_int;
    }
    if rustls_connection_wants_read(rconn) {
        *socks.offset(0 as libc::c_int as isize) = sockfd;
        return (1 as libc::c_int) << 0 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn cr_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return &mut (*backend).conn as *mut *mut rustls_connection as *mut libc::c_void;
}
unsafe extern "C" fn cr_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut tmperr: CURLcode = CURLE_OK;
    let mut n: ssize_t = 0 as libc::c_int as ssize_t;
    if !((*backend).conn).is_null() {
        rustls_connection_send_close_notify((*backend).conn);
        n = cr_send(
            data,
            sockindex,
            0 as *const libc::c_void,
            0 as libc::c_int as size_t,
            &mut tmperr,
        );
        if n < 0 as libc::c_int as libc::c_long {
            Curl_failf(
                data,
                b"error sending close notify: %d\0" as *const u8 as *const libc::c_char,
                tmperr as libc::c_uint,
            );
        }
        rustls_connection_free((*backend).conn);
        let ref mut fresh4 = (*backend).conn;
        *fresh4 = 0 as *mut rustls_connection;
    }
    if !((*backend).config).is_null() {
        rustls_client_config_free((*backend).config);
        let ref mut fresh5 = (*backend).config;
        *fresh5 = 0 as *const rustls_client_config;
    }
}
#[no_mangle]
pub static mut Curl_ssl_rustls: Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_RUSTLS,
                    name: b"rustls\0" as *const u8 as *const libc::c_char,
                };
                init
            },
            supports: ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uint,
            sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>()
                as libc::c_ulong,
            init: Some(Curl_none_init as unsafe extern "C" fn() -> libc::c_int),
            cleanup: Some(Curl_none_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(
                rustls_version
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
                cr_data_pending
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
                cr_connect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> CURLcode,
            ),
            connect_nonblocking: Some(
                cr_connect_nonblocking
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                        *mut bool,
                    ) -> CURLcode,
            ),
            getsock: Some(
                cr_getsock
                    as unsafe extern "C" fn(
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            get_internals: Some(
                cr_get_internals
                    as unsafe extern "C" fn(
                        *mut ssl_connect_data,
                        CURLINFO,
                    ) -> *mut libc::c_void,
            ),
            close_one: Some(
                cr_close
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
