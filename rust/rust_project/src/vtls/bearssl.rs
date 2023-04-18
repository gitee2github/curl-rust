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
 * Description: support bearssl backend
 ******************************************************************************/
use crate::src::vtls::vtls::*;
use libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

#[inline]
extern "C" fn br_pem_decoder_name(mut ctx: *mut br_pem_decoder_context) -> *const i8 {
    unsafe {
        return ((*ctx).name).as_mut_ptr();
    }
}
#[inline]
extern "C" fn br_pem_decoder_setdest(
    mut ctx: *mut br_pem_decoder_context,
    mut dest: Option<unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> ()>,
    mut dest_ctx: *mut libc::c_void,
) {
    unsafe {
        (*ctx).dest = dest;
        (*ctx).dest_ctx = dest_ctx;
    }
}
#[inline]
extern "C" fn br_ssl_engine_last_error(mut cc: *const br_ssl_engine_context) -> i32 {
    unsafe {
        return (*cc).err;
    }
}
#[inline]
extern "C" fn br_ssl_engine_set_session_parameters(
    mut cc: *mut br_ssl_engine_context,
    mut pp: *const br_ssl_session_parameters,
) {
    unsafe {
        memcpy(
            &mut (*cc).session as *mut br_ssl_session_parameters as *mut libc::c_void,
            pp as *const libc::c_void,
            ::std::mem::size_of::<br_ssl_session_parameters>() as u64,
        );
    }
}
#[inline]
extern "C" fn br_ssl_engine_get_session_parameters(
    mut cc: *const br_ssl_engine_context,
    mut pp: *mut br_ssl_session_parameters,
) {
    unsafe {
        memcpy(
            pp as *mut libc::c_void,
            &(*cc).session as *const br_ssl_session_parameters as *const libc::c_void,
            ::std::mem::size_of::<br_ssl_session_parameters>() as u64,
        );
    }
}
#[inline]
extern "C" fn br_x509_decoder_get_pkey(mut ctx: *mut br_x509_decoder_context) -> *mut br_x509_pkey {
    unsafe {
        if (*ctx).decoded as i32 != 0 && (*ctx).err == 0 as i32 {
            return &mut (*ctx).pkey;
        } else {
            return 0 as *mut br_x509_pkey;
        };
    }
}
#[inline]
extern "C" fn br_x509_decoder_last_error(mut ctx: *mut br_x509_decoder_context) -> i32 {
    unsafe {
        if (*ctx).err != 0 as i32 {
            return (*ctx).err;
        }
        if (*ctx).decoded == 0 {
            return 34 as i32;
        }
        return 0 as i32;
    }
}
#[inline]
extern "C" fn br_x509_decoder_isCA(mut ctx: *mut br_x509_decoder_context) -> i32 {
    unsafe {
        return (*ctx).isCA as i32;
    }
}
#[inline]
extern "C" fn br_ssl_engine_set_versions(
    mut cc: *mut br_ssl_engine_context,
    mut version_min: u32,
    mut version_max: u32,
) {
    unsafe {
        (*cc).version_min = version_min as uint16_t;
        (*cc).version_max = version_max as uint16_t;
    }
}
#[inline]
extern "C" fn br_ssl_engine_set_x509(
    mut cc: *mut br_ssl_engine_context,
    mut x509ctx: *mut *const br_x509_class,
) {
    unsafe {
        (*cc).x509ctx = x509ctx;
    }
}
#[inline]
extern "C" fn br_ssl_engine_set_protocol_names(
    mut ctx: *mut br_ssl_engine_context,
    mut names: *mut *const i8,
    mut num: size_t,
) {
    unsafe {
        (*ctx).protocol_names = names;
        (*ctx).protocol_names_num = num as uint16_t;
    }
}
#[inline]
extern "C" fn br_ssl_engine_get_selected_protocol(
    mut ctx: *mut br_ssl_engine_context,
) -> *const i8 {
    let mut k: u32 = 0;
    unsafe {
        k = (*ctx).selected_protocol as u32;
        return if k == 0 as u32 || k == 0xffff as u32 {
            0 as *const libc::c_char
        } else {
            *((*ctx).protocol_names).offset(k.wrapping_sub(1 as u32) as isize)
        };
    }
}
extern "C" fn append_dn(mut ctx: *mut libc::c_void, mut buf: *const libc::c_void, mut len: size_t) {
    unsafe {
        let mut ca: *mut cafile_parser = ctx as *mut cafile_parser;
        if (*ca).err as u32 != CURLE_OK as u32 || !(*ca).in_cert {
            return;
        }
        if (::std::mem::size_of::<[u8; 1024]>() as u64).wrapping_sub((*ca).dn_len) < len {
            (*ca).err = CURLE_FAILED_INIT;
            return;
        }
        memcpy(
            ((*ca).dn).as_mut_ptr().offset((*ca).dn_len as isize) as *mut libc::c_void,
            buf,
            len,
        );
        (*ca).dn_len = ((*ca).dn_len as u64).wrapping_add(len) as size_t as size_t;
    }
}
extern "C" fn x509_push(mut ctx: *mut libc::c_void, mut buf: *const libc::c_void, mut len: size_t) {
    let mut ca: *mut cafile_parser = ctx as *mut cafile_parser;
    unsafe {
        if (*ca).in_cert {
            br_x509_decoder_push(&mut (*ca).xc, buf, len);
        }
    }
}
extern "C" fn load_cafile(
    mut source: *mut cafile_source,
    mut anchors: *mut *mut br_x509_trust_anchor,
    mut anchors_len: *mut size_t,
) -> CURLcode {
    let mut ca: cafile_parser = cafile_parser {
        err: CURLE_OK,
        in_cert: false,
        xc: br_x509_decoder_context {
            pkey: br_x509_pkey {
                key_type: 0,
                key: bear_C2RustUnnamed_6 {
                    rsa: br_rsa_public_key {
                        n: 0 as *mut u8,
                        nlen: 0,
                        e: 0 as *mut u8,
                        elen: 0,
                    },
                },
            },
            cpu: C2RustUnnamed_30 {
                dp: 0 as *mut uint32_t,
                rp: 0 as *mut uint32_t,
                ip: 0 as *const u8,
            },
            dp_stack: [0; 32],
            rp_stack: [0; 32],
            err: 0,
            pad: [0; 256],
            decoded: 0,
            notbefore_days: 0,
            notbefore_seconds: 0,
            notafter_days: 0,
            notafter_seconds: 0,
            isCA: 0,
            copy_dn: 0,
            append_dn_ctx: 0 as *mut libc::c_void,
            append_dn: None,
            hbuf: 0 as *const u8,
            hlen: 0,
            pkey_data: [0; 520],
            signer_key_type: 0,
            signer_hash_id: 0,
        },
        anchors: 0 as *mut br_x509_trust_anchor,
        anchors_len: 0,
        dn: [0; 1024],
        dn_len: 0,
    };
    let mut pc: br_pem_decoder_context = br_pem_decoder_context {
        cpu: C2RustUnnamed_31 {
            dp: 0 as *mut uint32_t,
            rp: 0 as *mut uint32_t,
            ip: 0 as *const u8,
        },
        dp_stack: [0; 32],
        rp_stack: [0; 32],
        err: 0,
        hbuf: 0 as *const u8,
        hlen: 0,
        dest: None,
        dest_ctx: 0 as *mut libc::c_void,
        event: 0,
        name: [0; 128],
        buf: [0; 255],
        ptr: 0,
    };
    let mut ta: *mut br_x509_trust_anchor = 0 as *mut br_x509_trust_anchor;
    let mut ta_size: size_t = 0;
    let mut new_anchors: *mut br_x509_trust_anchor = 0 as *mut br_x509_trust_anchor;
    let mut new_anchors_len: size_t = 0;
    let mut pkey: *mut br_x509_pkey = 0 as *mut br_x509_pkey;
    let mut fp: *mut FILE = 0 as *mut FILE;
    let mut buf: [u8; 8192] = [0; 8192];
    let mut p: *const u8 = 0 as *const u8;
    let mut name: *const i8 = 0 as *const libc::c_char;
    let mut n: size_t = 0;
    let mut i: size_t = 0;
    let mut pushed: size_t = 0;
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if (*source).type_0 == 1 as libc::c_int || (*source).type_0 == 2 as libc::c_int {
    } else {
        __assert_fail(
            b"source->type == 1 || source->type == 2\0" as *const u8
                as *const libc::c_char,
            b"vtls/bearssl.c\0" as *const u8 as *const libc::c_char,
            119 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 80],
                &[libc::c_char; 80],
            >(
                b"CURLcode load_cafile(struct cafile_source *, br_x509_trust_anchor **, size_t *)\0",
            ))
                .as_ptr(),
        );
    }
    unsafe {
        if (*source).type_0 == 1 as i32 {
            fp = fopen((*source).data, b"rb\0" as *const u8 as *const libc::c_char);
            if fp.is_null() {
                return CURLE_SSL_CACERT_BADFILE;
            }
        }
    }
    let int_max = 2147483647 as size_t;
    unsafe {
        if (*source).type_0 == 2 as i32 && (*source).len > int_max {
            return CURLE_SSL_CACERT_BADFILE;
        }
    }
    ca.err = CURLE_OK;
    ca.in_cert = 0 as i32 != 0;
    ca.anchors = 0 as *mut br_x509_trust_anchor;
    ca.anchors_len = 0 as size_t;
    unsafe {
        br_pem_decoder_init(&mut pc);
    }
    br_pem_decoder_setdest(
        &mut pc,
        Some(
            x509_push as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> (),
        ),
        &mut ca as *mut cafile_parser as *mut libc::c_void,
    );
    #[allow(clippy::never_loop)]
    'fail: loop {
        loop {
            unsafe {
                if (*source).type_0 == 1 as i32 {
                    n = fread(
                        buf.as_mut_ptr() as *mut libc::c_void,
                        1 as u64,
                        ::std::mem::size_of::<[u8; 8192]>() as u64,
                        fp,
                    );
                    if n == 0 as u64 {
                        break;
                    }
                    p = buf.as_mut_ptr();
                } else if (*source).type_0 == 2 as i32 {
                    n = (*source).len;
                    p = (*source).data as *mut u8;
                }
            }
            while n != 0 {
                unsafe {
                    pushed = br_pem_decoder_push(&mut pc, p as *const libc::c_void, n);
                }
                if ca.err as u64 != 0 {
                    break 'fail;
                }
                unsafe {
                    p = p.offset(pushed as isize);
                }
                n = (n as u64).wrapping_sub(pushed) as size_t;
                match unsafe { br_pem_decoder_event(&mut pc) } {
                    0 => {}
                    1 => {
                        name = br_pem_decoder_name(&mut pc);
                        unsafe {
                            if !(strcmp(name, b"CERTIFICATE\0" as *const u8 as *const libc::c_char) != 0
                                && strcmp(name, b"X509 CERTIFICATE\0" as *const u8 as *const libc::c_char)
                                    != 0)
                            {
                                br_x509_decoder_init(
                                    &mut ca.xc,
                                    Some(
                                        append_dn
                                            as unsafe extern "C" fn(
                                                *mut libc::c_void,
                                                *const libc::c_void,
                                                size_t,
                                            )
                                                -> (),
                                    ),
                                    &mut ca as *mut cafile_parser as *mut libc::c_void,
                                );
                            }
                        }
                        let size_max = 18446744073709551615 as u64;
                        if ca.anchors_len
                            == (size_max)
                                .wrapping_div(::std::mem::size_of::<br_x509_trust_anchor>() as u64)
                        {
                            ca.err = CURLE_OUT_OF_MEMORY;
                            break 'fail;
                        }
                        new_anchors_len = (ca.anchors_len).wrapping_add(1 as u64);
                        match () {
                            #[cfg(not(CURLDEBUG))]
                            _ => unsafe {
                                new_anchors = Curl_crealloc.expect("non-null function pointer")(
                                    ca.anchors as *mut libc::c_void,
                                    new_anchors_len.wrapping_mul(::std::mem::size_of::<
                                        br_x509_trust_anchor,
                                    >(
                                    )
                                        as u64),
                                )
                                    as *mut br_x509_trust_anchor;
                            },
                            #[cfg(CURLDEBUG)]
                            _ => {
                                new_anchors = realloc(
                                    ca.anchors as *mut libc::c_void,
                                    new_anchors_len.wrapping_mul(::std::mem::size_of::<
                                        br_x509_trust_anchor,
                                    >(
                                    )
                                        as libc::c_ulong),
                                )
                                    as *mut br_x509_trust_anchor;
                            }
                        }
                        if new_anchors.is_null() {
                            ca.err = CURLE_OUT_OF_MEMORY;
                            break 'fail;
                        }
                        ca.anchors = new_anchors;
                        ca.anchors_len = new_anchors_len;
                        ca.in_cert = 1 as i32 != 0;
                        ca.dn_len = 0 as size_t;
                        unsafe {
                            ta = &mut *(ca.anchors)
                                .offset((ca.anchors_len).wrapping_sub(1 as u64) as isize)
                                as *mut br_x509_trust_anchor;
                            (*ta).dn.data = 0 as *mut u8;
                        }
                    }
                    2 => {
                        if ca.in_cert {
                            ca.in_cert = 0 as i32 != 0;
                            if br_x509_decoder_last_error(&mut ca.xc) != 0 {
                                ca.err = CURLE_SSL_CACERT_BADFILE;
                                break 'fail;
                            }
                            unsafe {
                                (*ta).flags = 0 as u32;
                                if br_x509_decoder_isCA(&mut ca.xc) != 0 {
                                    (*ta).flags |= 0x1 as u32;
                                }
                            }
                            pkey = br_x509_decoder_get_pkey(&mut ca.xc);
                            if pkey.is_null() {
                                ca.err = CURLE_SSL_CACERT_BADFILE;
                                break 'fail;
                            }
                            unsafe {
                                (*ta).pkey = *pkey;
                            }
                            /* calculate space needed for trust anchor data */
                            ta_size = ca.dn_len;
                            unsafe {
                                match (*pkey).key_type as i32 {
                                    1 => {
                                        ta_size = (ta_size as u64).wrapping_add(
                                            ((*pkey).key.rsa.nlen)
                                                .wrapping_add((*pkey).key.rsa.elen),
                                        )
                                            as size_t
                                            as size_t;
                                    }
                                    2 => {
                                        ta_size = (ta_size as u64).wrapping_add((*pkey).key.ec.qlen)
                                            as size_t
                                            as size_t;
                                    }
                                    _ => {
                                        ca.err = CURLE_FAILED_INIT;
                                        break 'fail;
                                    }
                                }
                                match () {
                                    #[cfg(not(CURLDEBUG))]
                                    _ => {
                                        (*ta).dn.data = Curl_cmalloc
                                            .expect("non-null function pointer")(
                                            ta_size
                                        )
                                            as *mut u8;
                                    }
                                    #[cfg(CURLDEBUG)]
                                    _ => {
                                        (*ta).dn.data = malloc(ta_size) as *mut libc::c_uchar;
                                    }
                                }
                                if ((*ta).dn.data).is_null() {
                                    ca.err = CURLE_OUT_OF_MEMORY;
                                    break 'fail;
                                }
                                memcpy(
                                    (*ta).dn.data as *mut libc::c_void,
                                    (ca.dn).as_mut_ptr() as *const libc::c_void,
                                    ca.dn_len,
                                );
                                (*ta).dn.len = ca.dn_len;
                                match (*pkey).key_type as i32 {
                                    1 => {
                                        (*ta).pkey.key.rsa.n =
                                            ((*ta).dn.data).offset((*ta).dn.len as isize);
                                        memcpy(
                                            (*ta).pkey.key.rsa.n as *mut libc::c_void,
                                            (*pkey).key.rsa.n as *const libc::c_void,
                                            (*pkey).key.rsa.nlen,
                                        );
                                        (*ta).pkey.key.rsa.e = ((*ta).pkey.key.rsa.n)
                                            .offset((*ta).pkey.key.rsa.nlen as isize);
                                        memcpy(
                                            (*ta).pkey.key.rsa.e as *mut libc::c_void,
                                            (*pkey).key.rsa.e as *const libc::c_void,
                                            (*pkey).key.rsa.elen,
                                        );
                                    }
                                    2 => {
                                        (*ta).pkey.key.ec.q =
                                            ((*ta).dn.data).offset((*ta).dn.len as isize);
                                        memcpy(
                                            (*ta).pkey.key.ec.q as *mut libc::c_void,
                                            (*pkey).key.ec.q as *const libc::c_void,
                                            (*pkey).key.ec.qlen,
                                        );
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {
                        ca.err = CURLE_SSL_CACERT_BADFILE;
                        break 'fail;
                    }
                }
            }
            if unsafe { !((*source).type_0 != 2 as i32) } {
                break;
            }
        }
        if !fp.is_null() && unsafe { ferror(fp) != 0 } {
            ca.err = CURLE_READ_ERROR;
        }
        break 'fail;
    }

    if !fp.is_null() {
        unsafe {
            fclose(fp);
        }
    }
    if ca.err as u32 == CURLE_OK as u32 {
        unsafe {
            *anchors = ca.anchors;
            *anchors_len = ca.anchors_len;
        }
    } else {
        i = 0 as size_t;
        while i < ca.anchors_len {
            #[cfg(not(CURLDEBUG))]
            unsafe {
                Curl_cfree.expect("non-null function pointer")(
                    (*(ca.anchors).offset(i as isize)).dn.data as *mut libc::c_void,
                );
            }

            #[cfg(CURLDEBUG)]
            free((*(ca.anchors).offset(i as isize)).dn.data as *mut libc::c_void);

            i = i.wrapping_add(1);
        }
        #[cfg(not(CURLDEBUG))]
        unsafe {
            Curl_cfree.expect("non-null function pointer")(ca.anchors as *mut libc::c_void);
        }
        #[cfg(CURLDEBUG)]
        free(ca.anchors as *mut libc::c_void);
    }
    return ca.err;
}

extern "C" fn x509_start_chain(mut ctx: *mut *const br_x509_class, mut server_name: *const i8) {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    unsafe {
        if !(*x509).verifyhost {
            server_name = 0 as *const libc::c_char;
        }
        ((*(*x509).minimal.vtable).start_chain).expect("non-null function pointer")(
            &mut (*x509).minimal.vtable,
            server_name,
        );
    }
}
extern "C" fn x509_start_cert(mut ctx: *mut *const br_x509_class, mut length: uint32_t) {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    unsafe {
        ((*(*x509).minimal.vtable).start_cert).expect("non-null function pointer")(
            &mut (*x509).minimal.vtable,
            length,
        );
    }
}
extern "C" fn x509_append(mut ctx: *mut *const br_x509_class, mut buf: *const u8, mut len: size_t) {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    unsafe {
        ((*(*x509).minimal.vtable).append).expect("non-null function pointer")(
            &mut (*x509).minimal.vtable,
            buf,
            len,
        );
    }
}
extern "C" fn x509_end_cert(mut ctx: *mut *const br_x509_class) {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    unsafe {
        ((*(*x509).minimal.vtable).end_cert).expect("non-null function pointer")(
            &mut (*x509).minimal.vtable,
        );
    }
}
extern "C" fn x509_end_chain(mut ctx: *mut *const br_x509_class) -> u32 {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    let mut err: u32 = 0;
    unsafe {
        err = ((*(*x509).minimal.vtable).end_chain).expect("non-null function pointer")(
            &mut (*x509).minimal.vtable,
        );
        if err != 0 && !(*x509).verifypeer {
            /* ignore any X.509 errors */
            err = 0 as u32;
        }
        return err;
    }
}
extern "C" fn x509_get_pkey(
    mut ctx: *const *const br_x509_class,
    mut usages: *mut u32,
) -> *const br_x509_pkey {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    unsafe {
        return ((*(*x509).minimal.vtable).get_pkey).expect("non-null function pointer")(
            &mut (*x509).minimal.vtable,
            usages,
        );
    }
}

static mut x509_vtable: br_x509_class = br_x509_class_ {
    context_size: ::std::mem::size_of::<x509_context>() as u64,
    start_chain: Some(
        x509_start_chain as unsafe extern "C" fn(*mut *const br_x509_class, *const i8) -> (),
    ),
    start_cert: Some(
        x509_start_cert as unsafe extern "C" fn(*mut *const br_x509_class, uint32_t) -> (),
    ),
    append: Some(
        x509_append as unsafe extern "C" fn(*mut *const br_x509_class, *const u8, size_t) -> (),
    ),
    end_cert: Some(x509_end_cert as unsafe extern "C" fn(*mut *const br_x509_class) -> ()),
    end_chain: Some(x509_end_chain as unsafe extern "C" fn(*mut *const br_x509_class) -> u32),
    get_pkey: Some(
        x509_get_pkey
            as unsafe extern "C" fn(*const *const br_x509_class, *mut u32) -> *const br_x509_pkey,
    ),
};

extern "C" fn bearssl_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    unsafe {
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        #[cfg(not(CURL_DISABLE_PROXY))]
        let mut ca_info_blob: *const curl_blob = if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            (*conn).proxy_ssl_config.ca_info_blob
        } else {
            (*conn).ssl_config.ca_info_blob
        };
        #[cfg(CURL_DISABLE_PROXY)]
        let mut ca_info_blob: *const curl_blob = (*conn).ssl_config.ca_info_blob;
        #[cfg(not(CURL_DISABLE_PROXY))]
        /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
        let ssl_cafile: *const i8 = if !ca_info_blob.is_null() {
            0 as *mut i8
        } else if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
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
        let ssl_cafile: *const i8 = (*conn).ssl_config.CAfile;
        #[cfg(not(CURL_DISABLE_PROXY))]
        let mut hostname: *const i8 = if CURLPROXY_HTTPS as u32
            == (*conn).http_proxy.proxytype as u32
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
        #[cfg(CURL_DISABLE_PROXY)]
        let mut hostname: *const i8 = (*conn).host.name;
        #[cfg(not(CURL_DISABLE_PROXY))]
        let verifypeer: bool = if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
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
        } != 0;
        #[cfg(CURL_DISABLE_PROXY)]
        let verifypeer: bool = ((*conn).ssl_config).verifypeer() as i32 != 0;
        #[cfg(not(CURL_DISABLE_PROXY))]
        let verifyhost: bool = if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            ((*conn).proxy_ssl_config).verifyhost() as i32
        } else {
            ((*conn).ssl_config).verifyhost() as i32
        } != 0;
        #[cfg(CURL_DISABLE_PROXY)]
        let verifyhost: bool = ((*conn).ssl_config).verifyhost() as i32 != 0;
        let mut ret: CURLcode = CURLE_OK;
        let mut version_min: u32 = 0;
        let mut version_max: u32 = 0;
        #[cfg(ENABLE_IPV6)]
        let mut addr: in6_addr = in6_addr {
            __in6_u: C2RustUnnamed_8 {
                __u6_addr8: [0; 16],
            },
        };
        #[cfg(not(ENABLE_IPV6))]
        let mut addr: in_addr = in_addr { s_addr: 0 };

        #[cfg(not(CURL_DISABLE_PROXY))]
        let flag6: i64 = if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
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
        #[cfg(CURL_DISABLE_PROXY)]
        let flag6: i64 = (*conn).ssl_config.version;
        match flag6 {
            2 => {
                Curl_failf(
                    data,
                    b"BearSSL does not support SSLv2\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            3 => {
                Curl_failf(
                    data,
                    b"BearSSL does not support SSLv3\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            4 => {
                version_min = 0x301 as u32;
                version_max = 0x301 as u32;
            }
            5 => {
                version_min = 0x302 as u32;
                version_max = 0x302 as u32;
            }
            6 => {
                version_min = 0x303 as u32;
                version_max = 0x303 as u32;
            }
            0 | 1 => {
                version_min = 0x301 as u32;
                version_max = 0x303 as u32;
            }
            _ => {
                Curl_failf(
                    data,
                    b"BearSSL: unknown CURLOPT_SSLVERSION\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
        }
        if !ca_info_blob.is_null() {
            let mut source: cafile_source = {
                cafile_source {
                    type_0: 2 as i32,
                    data: (*ca_info_blob).data as *const libc::c_char,
                    len: (*ca_info_blob).len,
                }
            };
            ret = load_cafile(
                &mut source,
                &mut (*backend).anchors,
                &mut (*backend).anchors_len,
            );
            if ret as u32 != CURLE_OK as u32 {
                if verifypeer {
                    Curl_failf(
                        data,
                        b"error importing CA certificate blob\0" as *const u8 as *const libc::c_char,
                    );
                    return ret;
                }
                Curl_infof(
                    data,
                    b"error importing CA certificate blob, continuing anyway\0" as *const u8
                    as *const libc::c_char,
                );
            }
        }
        if !ssl_cafile.is_null() {
            let mut source_0: cafile_source = {
                cafile_source {
                    type_0: 1 as i32,
                    data: ssl_cafile,
                    len: 0 as size_t,
                }
            };
            ret = load_cafile(
                &mut source_0,
                &mut (*backend).anchors,
                &mut (*backend).anchors_len,
            );
            if ret as u32 != CURLE_OK as u32 {
                if verifypeer {
                    Curl_failf(
                        data,
                        b"error setting certificate verify locations. CAfile: %s\0" as *const u8
                            as *const libc::c_char,
                        ssl_cafile,
                    );
                    return ret;
                }
                /* Only warn if no certificate verification is required. */
                Curl_infof(
                    data,
                    b"error setting certificate verify locations, continuing anyway:\0" as *const u8
                    as *const libc::c_char,
                );
            }
        }
        /* initialize SSL context */
        br_ssl_client_init_full(
            &mut (*backend).bear_ctx,
            &mut (*backend).x509.minimal,
            (*backend).anchors,
            (*backend).anchors_len,
        );
        br_ssl_engine_set_versions(&mut (*backend).bear_ctx.eng, version_min, version_max);
        br_ssl_engine_set_buffer(
            &mut (*backend).bear_ctx.eng,
            ((*backend).buf).as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[u8; 33178]>() as u64,
            1 as i32,
        );
        (*backend).x509.vtable = &x509_vtable;
        (*backend).x509.verifypeer = verifypeer;
        (*backend).x509.verifyhost = verifyhost;
        br_ssl_engine_set_x509(&mut (*backend).bear_ctx.eng, &mut (*backend).x509.vtable);
        #[cfg(not(CURL_DISABLE_PROXY))]
        let flag7: bool = if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            ((*data).set.proxy_ssl.primary).sessionid() as i32
        } else {
            ((*data).set.ssl.primary).sessionid() as i32
        } != 0;
        #[cfg(CURL_DISABLE_PROXY)]
        let flag7: bool = ((*data).set.ssl.primary).sessionid() as i32 != 0;
        if flag7 {
            let mut session: *mut libc::c_void = 0 as *mut libc::c_void;
            Curl_ssl_sessionid_lock(data);
            #[cfg(not(CURL_DISABLE_PROXY))]
            let flag8: bool = CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32;
            #[cfg(CURL_DISABLE_PROXY)]
            let flag8: bool = false;
            if !Curl_ssl_getsessionid(
                data,
                conn,
                if flag8 { 1 as i32 } else { 0 as i32 } != 0,
                &mut session,
                0 as *mut size_t,
                sockindex,
            ) {
                br_ssl_engine_set_session_parameters(
                    &mut (*backend).bear_ctx.eng,
                    session as *const br_ssl_session_parameters,
                );
                Curl_infof(
                    data,
                    b"BearSSL: re-using session ID\0" as *const u8 as *const libc::c_char,
                );
            }
            Curl_ssl_sessionid_unlock(data);
        }
        if ((*conn).bits).tls_enable_alpn() != 0 {
            let mut cur: i32 = 0 as i32;
            match () {
                #[cfg(USE_HTTP2)]
                _ => {
                    #[cfg(not(CURL_DISABLE_PROXY))]
                    let CURL_DISABLE_PROXY_flag = (!(CURLPROXY_HTTPS as u32
                        == (*conn).http_proxy.proxytype as u32
                        && ssl_connection_complete as u32
                            != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state as u32)
                        || ((*conn).bits).tunnel_proxy() == 0);
                    /* NOTE: when adding more protocols here, increase the size of the
                     * protocols array in `struct ssl_backend_data`.
                     */
                    #[cfg(CURL_DISABLE_PROXY)]
                    let CURL_DISABLE_PROXY_flag = true;
                    if (*data).state.httpwant as i32 >= CURL_HTTP_VERSION_2_0 as i32
                        && CURL_DISABLE_PROXY_flag
                    {
                        let fresh11 = cur;
                        cur = cur + 1;
                        (*backend).protocols[fresh11 as usize] = b"h2\0" as *const u8 as *const libc::c_char;
                        Curl_infof(
                            data,
                            b"ALPN, offering %s\0" as *const u8 as *const libc::c_char,
                            b"h2\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
                #[cfg(not(USE_HTTP2))]
                _ => {}
            }
            let fresh13 = cur;
            cur = cur + 1;
            (*backend).protocols[fresh13 as usize] = b"http/1.1\0" as *const u8 as *const libc::c_char;
            Curl_infof(
                data,
                b"ALPN, offering %s\0" as *const u8 as *const libc::c_char,
                b"http/1.1\0" as *const u8 as *const libc::c_char,
            );
            br_ssl_engine_set_protocol_names(
                &mut (*backend).bear_ctx.eng,
                ((*backend).protocols).as_mut_ptr(),
                cur as size_t,
            );
        }
        #[cfg(ENABLE_IPV6)]
        let ENABLE_IPV6_flag = 1 as i32
            == inet_pton(
                2 as i32,
                hostname,
                &mut addr as *mut in6_addr as *mut libc::c_void,
            )
            || 1 as i32
                == inet_pton(
                    10 as i32,
                    hostname,
                    &mut addr as *mut in6_addr as *mut libc::c_void,
                );
        #[cfg(not(ENABLE_IPV6))]
        let ENABLE_IPV6_flag = 1 as i32
            == inet_pton(
                2 as i32,
                hostname,
                &mut addr as *mut in_addr as *mut libc::c_void,
            );
        if ENABLE_IPV6_flag {
            if verifyhost {
                Curl_failf(
                    data,
                    b"BearSSL: host verification of IP address is not supported\0" as *const u8
                        as *const libc::c_char,
                );
                return CURLE_PEER_FAILED_VERIFICATION;
            }
            hostname = 0 as *const libc::c_char;
        }
        if br_ssl_client_reset(&mut (*backend).bear_ctx, hostname, 0 as i32) == 0 {
            return CURLE_FAILED_INIT;
        }
        (*backend).active = 1 as i32 != 0;
        (*connssl).connecting_state = ssl_connect_2;
        return CURLE_OK;
    }
}

extern "C" fn bearssl_run_until(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut target: u32,
) -> CURLcode {
    unsafe {
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
        let mut state: u32 = 0;
        let mut buf: *mut u8 = 0 as *mut u8;
        let mut len: size_t = 0;
        let mut ret: ssize_t = 0;
        let mut err: i32 = 0;
        loop {
            state = br_ssl_engine_current_state(&mut (*backend).bear_ctx.eng);
            if state & 0x1 as u32 != 0 {
                err = br_ssl_engine_last_error(&mut (*backend).bear_ctx.eng);
                match err {
                    0 => {
                        /* TLS close notify */
                        if (*connssl).state as u32 != ssl_connection_complete as u32 {
                            Curl_failf(
                                data,
                                b"SSL: connection closed during handshake\0" as *const u8
                                    as *const libc::c_char,
                            );
                            return CURLE_SSL_CONNECT_ERROR;
                        }
                        return CURLE_OK;
                    }
                    54 => {
                        Curl_failf(
                            data,
                            b"SSL: X.509 verification: certificate is expired or not yet valid\0"
                                as *const u8 as *const libc::c_char,
                        );
                        return CURLE_PEER_FAILED_VERIFICATION;
                    }
                    56 => {
                        Curl_failf(
                         data,
                         b"SSL: X.509 verification: expected server name was not found in the chain\0"
                             as *const u8 as *const libc::c_char,
                     );
                        return CURLE_PEER_FAILED_VERIFICATION;
                    }
                    62 => {
                        Curl_failf(
                        data,
                        b"SSL: X.509 verification: chain could not be linked to a trust anchor\0"
                            as *const u8 as *const libc::c_char,
                    );
                        return CURLE_PEER_FAILED_VERIFICATION;
                    }
                    _ => {}
                }
                /* X.509 errors are documented to have the range 32..63 */
                if err >= 32 as i32 && err < 64 as i32 {
                    return CURLE_PEER_FAILED_VERIFICATION;
                }
                return CURLE_SSL_CONNECT_ERROR;
            }
            if state & target != 0 {
                return CURLE_OK;
            }
            if state & 0x2 as u32 != 0 {
                buf = br_ssl_engine_sendrec_buf(&mut (*backend).bear_ctx.eng, &mut len);
                ret = send(sockfd, buf as *const libc::c_void, len, MSG_NOSIGNAL as i32);
                if ret == -(1 as i32) as i64 {
                    if *__errno_location() == 11 as i32 || *__errno_location() == 11 as i32 {
                        if (*connssl).state as u32 != ssl_connection_complete as u32 {
                            (*connssl).connecting_state = ssl_connect_2_writing;
                        }
                        return CURLE_AGAIN;
                    }
                    return CURLE_WRITE_ERROR;
                }
                br_ssl_engine_sendrec_ack(&mut (*backend).bear_ctx.eng, ret as size_t);
            } else if state & 0x4 as u32 != 0 {
                buf = br_ssl_engine_recvrec_buf(&mut (*backend).bear_ctx.eng, &mut len);
                ret = recv(sockfd, buf as *mut libc::c_void, len, 0 as i32);
                if ret == 0 as i64 {
                    Curl_failf(
                        data,
                        b"SSL: EOF without close notify\0" as *const u8 as *const libc::c_char,
                    );
                    return CURLE_READ_ERROR;
                }
                if ret == -(1 as i32) as i64 {
                    if *__errno_location() == 11 as i32 || *__errno_location() == 11 as i32 {
                        if (*connssl).state as u32 != ssl_connection_complete as u32 {
                            (*connssl).connecting_state = ssl_connect_2_reading;
                        }
                        return CURLE_AGAIN;
                    }
                    return CURLE_READ_ERROR;
                }
                br_ssl_engine_recvrec_ack(&mut (*backend).bear_ctx.eng, ret as size_t);
            }
        }
    }
}

extern "C" fn bearssl_connect_step2(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    unsafe {
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        let mut ret: CURLcode = CURLE_OK;
        ret = bearssl_run_until(data, conn, sockindex, (0x8 as i32 | 0x10 as i32) as u32);
        if ret as u32 == CURLE_AGAIN as u32 {
            return CURLE_OK;
        }
        if ret as u32 == CURLE_OK as u32 {
            if br_ssl_engine_current_state(&mut (*backend).bear_ctx.eng) == 0x1 as u32 {
                Curl_failf(
                    data,
                    b"SSL: connection closed during handshake\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_SSL_CONNECT_ERROR;
            }
            (*connssl).connecting_state = ssl_connect_3;
        }
        return ret;
    }
}

extern "C" fn bearssl_connect_step3(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    unsafe {
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        let mut ret: CURLcode = CURLE_OK;
        #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
        if ssl_connect_3 as libc::c_int as libc::c_uint
            == (*connssl).connecting_state as libc::c_uint
        {
        } else {
            __assert_fail(
            b"ssl_connect_3 == connssl->connecting_state\0" as *const u8
                as *const libc::c_char,
            b"vtls/bearssl.c\0" as *const u8 as *const libc::c_char,
            584 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 78],
                &[libc::c_char; 78],
            >(
                b"CURLcode bearssl_connect_step3(struct Curl_easy *, struct connectdata *, int)\0",
            ))
                .as_ptr(),
        );
        }
        if ((*conn).bits).tls_enable_alpn() != 0 {
            let mut protocol: *const i8 = 0 as *const libc::c_char;
            protocol = br_ssl_engine_get_selected_protocol(&mut (*backend).bear_ctx.eng);
            if !protocol.is_null() {
                Curl_infof(
                    data,
                    b"ALPN, server accepted to use %s\0" as *const u8 as *const libc::c_char,
                    protocol,
                );
                #[cfg(USE_HTTP2)]
                let USE_HTTP2_flag = strcmp(protocol, b"h2\0" as *const u8 as *const libc::c_char) == 0;
                #[cfg(not(USE_HTTP2))]
                let USE_HTTP2_flag = false;
                if USE_HTTP2_flag {
                    match () {
                        #[cfg(USE_HTTP2)]
                        _ => {
                            (*conn).negnpn = CURL_HTTP_VERSION_2_0 as i32;
                        }
                        #[cfg(not(USE_HTTP2))]
                        _ => {}
                    }
                } else if strcmp(protocol, b"http/1.1\0" as *const u8 as *const libc::c_char) == 0 {
                    (*conn).negnpn = CURL_HTTP_VERSION_1_1 as i32;
                } else {
                    Curl_infof(
                        data,
                        b"ALPN, unrecognized protocol %s\0" as *const u8 as *const libc::c_char,
                        protocol,
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
            } else {
                Curl_infof(
                    data,
                    b"ALPN, server did not agree to a protocol\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let flag1: bool = if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            ((*data).set.proxy_ssl.primary).sessionid() as i32
        } else {
            ((*data).set.ssl.primary).sessionid() as i32
        } != 0;
        #[cfg(CURL_DISABLE_PROXY)]
        let flag1: bool = ((*data).set.ssl.primary).sessionid() as i32 != 0;
        if flag1 {
            let mut incache: bool = false;
            let mut oldsession: *mut libc::c_void = 0 as *mut libc::c_void;
            let mut session: *mut br_ssl_session_parameters = 0 as *mut br_ssl_session_parameters;
            match () {
                #[cfg(not(CURLDEBUG))]
                _ => {
                    session =
                        Curl_cmalloc.expect("non-null function pointer")(::std::mem::size_of::<
                            br_ssl_session_parameters,
                        >()
                            as u64) as *mut br_ssl_session_parameters;
                }
                #[cfg(CURLDEBUG)]
                _ => {
                    session =
                        malloc(::std::mem::size_of::<br_ssl_session_parameters>() as libc::c_ulong)
                            as *mut br_ssl_session_parameters;
                }
            }

            if session.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            br_ssl_engine_get_session_parameters(&mut (*backend).bear_ctx.eng, session);
            Curl_ssl_sessionid_lock(data);
            #[cfg(not(CURL_DISABLE_PROXY))]
            let flag1: bool = CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32;
            #[cfg(CURL_DISABLE_PROXY)]
            let flag1: bool = false;
            incache = !Curl_ssl_getsessionid(
                data,
                conn,
                if flag1 { 1 as i32 } else { 0 as i32 } != 0,
                &mut oldsession,
                0 as *mut size_t,
                sockindex,
            );
            if incache {
                Curl_ssl_delsessionid(data, oldsession);
            }
            #[cfg(not(CURL_DISABLE_PROXY))]
            let flag2: bool = CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32;
            #[cfg(CURL_DISABLE_PROXY)]
            let flag2: bool = false;
            ret = Curl_ssl_addsessionid(
                data,
                conn,
                if flag2 { 1 as i32 } else { 0 as i32 } != 0,
                session as *mut libc::c_void,
                0 as size_t,
                sockindex,
            );
            Curl_ssl_sessionid_unlock(data);
            if ret as u64 != 0 {
                #[cfg(not(CURLDEBUG))]
                Curl_cfree.expect("non-null function pointer")(session as *mut libc::c_void);
                #[cfg(CURLDEBUG)]
                free(session as *mut libc::c_void);

                return CURLE_OUT_OF_MEMORY;
            }
        }
        (*connssl).connecting_state = ssl_connect_done;
        return CURLE_OK;
    }
}

extern "C" fn bearssl_send(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut buf: *const libc::c_void,
    mut len: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    unsafe {
        let mut conn: *mut connectdata = (*data).conn;
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        let mut app: *mut u8 = 0 as *mut u8;
        let mut applen: size_t = 0;
        loop {
            *err = bearssl_run_until(data, conn, sockindex, 0x8 as u32);
            if *err as u32 != CURLE_OK as u32 {
                return -(1 as i32) as ssize_t;
            }
            app = br_ssl_engine_sendapp_buf(&mut (*backend).bear_ctx.eng, &mut applen);
            if app.is_null() {
                Curl_failf(
                    data,
                    b"SSL: connection closed during write\0" as *const u8 as *const libc::c_char,
                );
                *err = CURLE_SEND_ERROR;
                return -(1 as i32) as ssize_t;
            }
            if (*backend).pending_write != 0 {
                applen = (*backend).pending_write;
                (*backend).pending_write = 0 as size_t;
                return applen as ssize_t;
            }
            if applen > len {
                applen = len;
            }
            memcpy(app as *mut libc::c_void, buf, applen);
            br_ssl_engine_sendapp_ack(&mut (*backend).bear_ctx.eng, applen);
            br_ssl_engine_flush(&mut (*backend).bear_ctx.eng, 0 as i32);
            (*backend).pending_write = applen;
        }
    }
}

extern "C" fn bearssl_recv(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut buf: *mut i8,
    mut len: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    unsafe {
        let mut conn: *mut connectdata = (*data).conn;
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        let mut app: *mut u8 = 0 as *mut u8;
        let mut applen: size_t = 0;
        *err = bearssl_run_until(data, conn, sockindex, 0x10 as u32);
        if *err as u32 != CURLE_OK as u32 {
            return -(1 as i32) as ssize_t;
        }
        app = br_ssl_engine_recvapp_buf(&mut (*backend).bear_ctx.eng, &mut applen);
        if app.is_null() {
            return 0 as ssize_t;
        }
        if applen > len {
            applen = len;
        }
        memcpy(buf as *mut libc::c_void, app as *const libc::c_void, applen);
        br_ssl_engine_recvapp_ack(&mut (*backend).bear_ctx.eng, applen);
        return applen as ssize_t;
    }
}

extern "C" fn bearssl_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    unsafe {
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
        let mut timeout_ms: timediff_t = 0;
        let mut what: i32 = 0;
        /* check if the connection has already been established */
        if ssl_connection_complete as u32 == (*connssl).state as u32 {
            *done = 1 as i32 != 0;
            return CURLE_OK;
        }
        if ssl_connect_1 as u32 == (*connssl).connecting_state as u32 {
            ret = bearssl_connect_step1(data, conn, sockindex);
            if ret as u64 != 0 {
                return ret;
            }
        }
        #[allow(clippy::while_immutable_condition)]
        while ssl_connect_2 as u32 == (*connssl).connecting_state as u32
            || ssl_connect_2_reading as u32 == (*connssl).connecting_state as u32
            || ssl_connect_2_writing as u32 == (*connssl).connecting_state as u32
        {
            /* check allowed time left */
            timeout_ms = Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0);
            if timeout_ms < 0 as i64 {
                /* no need to continue if time already is up */
                Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const libc::c_char);
                return CURLE_OPERATION_TIMEDOUT;
            }
            /* if ssl is expecting something, check if it's available. */
            if ssl_connect_2_reading as u32 == (*connssl).connecting_state as u32
                || ssl_connect_2_writing as u32 == (*connssl).connecting_state as u32
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
                        b"select/poll on SSL socket, errno: %d\0" as *const u8 as *const libc::c_char,
                        *__errno_location(),
                    );
                    return CURLE_SSL_CONNECT_ERROR;
                } else {
                    /* timeout */
                    if 0 as i32 == what {
                        if nonblocking {
                            *done = 0 as i32 != 0;
                            return CURLE_OK;
                        } else {
                            Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const libc::c_char);
                            return CURLE_OPERATION_TIMEDOUT;
                        }
                    }
                }
                /* socket is readable or writable */
            }
            /* Run transaction, and return to the caller if it failed or if this
             * connection is done nonblocking and this loop would execute again. This
             * permits the owner of a multi handle to abort a connection attempt
             * before step2 has completed while ensuring that a client using select()
             * or epoll() will always have a valid fdset to wait on.
             */
            ret = bearssl_connect_step2(data, conn, sockindex);
            if ret as u32 != 0
                || nonblocking as i32 != 0
                    && (ssl_connect_2 as u32 == (*connssl).connecting_state as u32
                        || ssl_connect_2_reading as u32 == (*connssl).connecting_state as u32
                        || ssl_connect_2_writing as u32 == (*connssl).connecting_state as u32)
            {
                return ret;
            }
        }
        if ssl_connect_3 as u32 == (*connssl).connecting_state as u32 {
            ret = bearssl_connect_step3(data, conn, sockindex);
            if ret as u64 != 0 {
                return ret;
            }
        }
        if ssl_connect_done as u32 == (*connssl).connecting_state as u32 {
            (*connssl).state = ssl_connection_complete;
            (*conn).recv[sockindex as usize] = Some(
                bearssl_recv
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        i32,
                        *mut i8,
                        size_t,
                        *mut CURLcode,
                    ) -> ssize_t,
            );
            (*conn).send[sockindex as usize] = Some(
                bearssl_send
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        i32,
                        *const libc::c_void,
                        size_t,
                        *mut CURLcode,
                    ) -> ssize_t,
            );
            *done = 1 as i32 != 0;
        } else {
            *done = 0 as i32 != 0;
        }
        /* Reset our connect state machine */
        (*connssl).connecting_state = ssl_connect_1;
        return CURLE_OK;
    }
}

extern "C" fn bearssl_version(mut buffer: *mut i8, mut size: size_t) -> size_t {
    unsafe {
        return curl_msnprintf(buffer, size, b"BearSSL\0" as *const u8 as *const libc::c_char) as size_t;
    }
}
extern "C" fn bearssl_data_pending(mut conn: *const connectdata, mut connindex: i32) -> bool {
    unsafe {
        let mut connssl: *const ssl_connect_data =
            &*((*conn).ssl).as_ptr().offset(connindex as isize) as *const ssl_connect_data;
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        return br_ssl_engine_current_state(&mut (*backend).bear_ctx.eng) & 0x10 as u32 != 0;
    }
}

extern "C" fn bearssl_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut u8,
    mut length: size_t,
) -> CURLcode {
    static mut ctx: br_hmac_drbg_context = br_hmac_drbg_context {
        vtable: 0 as *const br_prng_class,
        K: [0; 64],
        V: [0; 64],
        digest_class: 0 as *const br_hash_class,
    };
    static mut seeded: bool = 0 as i32 != 0;
    unsafe {
        if !seeded {
            let mut seeder: br_prng_seeder = None;
            br_hmac_drbg_init(
                &mut ctx,
                &br_sha256_vtable,
                0 as *const libc::c_void,
                0 as size_t,
            );
            seeder = br_prng_seeder_system(0 as *mut *const i8);
            if seeder.is_none() || seeder.expect("non-null function pointer")(&mut ctx.vtable) == 0
            {
                return CURLE_FAILED_INIT;
            }
            seeded = 1 as i32 != 0;
        }
        br_hmac_drbg_generate(&mut ctx, entropy as *mut libc::c_void, length);
    }
    return CURLE_OK;
}

extern "C" fn bearssl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut done: bool = 0 as i32 != 0;
    ret = bearssl_connect_common(data, conn, sockindex, 0 as i32 != 0, &mut done);
    if ret as u64 != 0 {
        return ret;
    }
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if done {
    } else {
        __assert_fail(
            b"done\0" as *const u8 as *const libc::c_char,
            b"vtls/bearssl.c\0" as *const u8 as *const libc::c_char,
            839 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<&[u8; 72], &[libc::c_char; 72]>(
                b"CURLcode bearssl_connect(struct Curl_easy *, struct connectdata *, int)\0",
            ))
            .as_ptr(),
        );
    }
    return CURLE_OK;
}

extern "C" fn bearssl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    return bearssl_connect_common(data, conn, sockindex, 1 as i32 != 0, done);
}

extern "C" fn bearssl_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    unsafe {
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        return &mut (*backend).bear_ctx as *mut br_ssl_client_context as *mut libc::c_void;
    }
}

extern "C" fn bearssl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
    unsafe {
        let mut connssl: *mut ssl_connect_data =
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
        let mut backend: *mut ssl_backend_data = (*connssl).backend;
        let mut i: size_t = 0;
        if (*backend).active {
            br_ssl_engine_close(&mut (*backend).bear_ctx.eng);
            bearssl_run_until(data, conn, sockindex, 0x1 as u32);
        }
        i = 0 as size_t;
        while i < (*backend).anchors_len {
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(
                (*((*backend).anchors).offset(i as isize)).dn.data as *mut libc::c_void,
            );
            #[cfg(CURLDEBUG)]
            free((*((*backend).anchors).offset(i as isize)).dn.data as *mut libc::c_void);

            i = i.wrapping_add(1);
        }
        #[cfg(not(CURLDEBUG))]
        Curl_cfree.expect("non-null function pointer")((*backend).anchors as *mut libc::c_void);
        #[cfg(CURLDEBUG)]
        free((*backend).anchors as *mut libc::c_void);
    }
}

extern "C" fn bearssl_session_free(mut ptr: *mut libc::c_void) {
    #[cfg(not(CURLDEBUG))]
    unsafe {
        Curl_cfree.expect("non-null function pointer")(ptr);
    }
    #[cfg(CURLDEBUG)]
    free(ptr);
}

extern "C" fn bearssl_sha256sum(
    mut input: *const u8,
    mut inputlen: size_t,
    mut sha256sum: *mut u8,
    mut sha256len: size_t,
) -> CURLcode {
    let mut ctx: br_sha256_context = br_sha256_context {
        vtable: 0 as *const br_hash_class,
        buf: [0; 64],
        count: 0,
        val: [0; 8],
    };
    unsafe {
        br_sha256_init(&mut ctx);
        br_sha224_update(&mut ctx, input as *const libc::c_void, inputlen);
        br_sha256_out(&mut ctx, sha256sum as *mut libc::c_void);
    }
    return CURLE_OK;
}

#[no_mangle]

pub static mut Curl_ssl_bearssl: Curl_ssl = Curl_ssl {
    info: {
        curl_ssl_backend {
            id: CURLSSLBACKEND_BEARSSL,
            name: b"bearssl\0" as *const u8 as *const libc::c_char,
        }
    },
    supports: ((1 as i32) << 6 as i32) as u32,
    sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>() as u64,
    init: Some(Curl_none_init as unsafe extern "C" fn() -> i32),
    cleanup: Some(Curl_none_cleanup as unsafe extern "C" fn() -> ()),
    version: Some(bearssl_version as unsafe extern "C" fn(*mut i8, size_t) -> size_t),
    check_cxn: Some(Curl_none_check_cxn as unsafe extern "C" fn(*mut connectdata) -> i32),
    shut_down: Some(
        Curl_none_shutdown as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> i32,
    ),
    data_pending: Some(
        bearssl_data_pending as unsafe extern "C" fn(*const connectdata, i32) -> bool,
    ),
    random: Some(
        bearssl_random as unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode,
    ),
    cert_status_request: Some(Curl_none_cert_status_request as unsafe extern "C" fn() -> bool),
    connect_blocking: Some(
        bearssl_connect as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> CURLcode,
    ),
    connect_nonblocking: Some(
        bearssl_connect_nonblocking
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32, *mut bool) -> CURLcode,
    ),
    getsock: Some(
        Curl_ssl_getsock as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32,
    ),
    get_internals: Some(
        bearssl_get_internals
            as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
    ),
    close_one: Some(
        bearssl_close as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
    ),
    close_all: Some(Curl_none_close_all as unsafe extern "C" fn(*mut Curl_easy) -> ()),
    session_free: Some(bearssl_session_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
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
    sha256sum: Some(
        bearssl_sha256sum as unsafe extern "C" fn(*const u8, size_t, *mut u8, size_t) -> CURLcode,
    ),
    associate_connection: None,
    disassociate_connection: None,
};
