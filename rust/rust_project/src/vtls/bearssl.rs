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
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
use crate::src::vtls::vtls::*;

#[inline]
unsafe extern "C" fn br_pem_decoder_name(
    mut ctx: *mut br_pem_decoder_context,
) -> *const libc::c_char {
    return ((*ctx).name).as_mut_ptr();
}
#[inline]
unsafe extern "C" fn br_pem_decoder_setdest(
    mut ctx: *mut br_pem_decoder_context,
    mut dest: Option::<
        unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> (),
    >,
    mut dest_ctx: *mut libc::c_void,
) {
    let ref mut fresh0 = (*ctx).dest;
    *fresh0 = dest;
    let ref mut fresh1 = (*ctx).dest_ctx;
    *fresh1 = dest_ctx;
}
#[inline]
unsafe extern "C" fn br_ssl_engine_last_error(
    mut cc: *const br_ssl_engine_context,
) -> libc::c_int {
    return (*cc).err;
}
#[inline]
unsafe extern "C" fn br_ssl_engine_set_session_parameters(
    mut cc: *mut br_ssl_engine_context,
    mut pp: *const br_ssl_session_parameters,
) {
    memcpy(
        &mut (*cc).session as *mut br_ssl_session_parameters as *mut libc::c_void,
        pp as *const libc::c_void,
        ::std::mem::size_of::<br_ssl_session_parameters>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn br_ssl_engine_get_session_parameters(
    mut cc: *const br_ssl_engine_context,
    mut pp: *mut br_ssl_session_parameters,
) {
    memcpy(
        pp as *mut libc::c_void,
        &(*cc).session as *const br_ssl_session_parameters as *const libc::c_void,
        ::std::mem::size_of::<br_ssl_session_parameters>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn br_x509_decoder_get_pkey(
    mut ctx: *mut br_x509_decoder_context,
) -> *mut br_x509_pkey {
    if (*ctx).decoded as libc::c_int != 0 && (*ctx).err == 0 as libc::c_int {
        return &mut (*ctx).pkey
    } else {
        return 0 as *mut br_x509_pkey
    };
}
#[inline]
unsafe extern "C" fn br_x509_decoder_last_error(
    mut ctx: *mut br_x509_decoder_context,
) -> libc::c_int {
    if (*ctx).err != 0 as libc::c_int {
        return (*ctx).err;
    }
    if (*ctx).decoded == 0 {
        return 34 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[inline]
unsafe extern "C" fn br_x509_decoder_isCA(
    mut ctx: *mut br_x509_decoder_context,
) -> libc::c_int {
    return (*ctx).isCA as libc::c_int;
}
#[inline]
unsafe extern "C" fn br_ssl_engine_set_versions(
    mut cc: *mut br_ssl_engine_context,
    mut version_min: libc::c_uint,
    mut version_max: libc::c_uint,
) {
    (*cc).version_min = version_min as uint16_t;
    (*cc).version_max = version_max as uint16_t;
}
#[inline]
unsafe extern "C" fn br_ssl_engine_set_x509(
    mut cc: *mut br_ssl_engine_context,
    mut x509ctx: *mut *const br_x509_class,
) {
    let ref mut fresh2 = (*cc).x509ctx;
    *fresh2 = x509ctx;
}
#[inline]
unsafe extern "C" fn br_ssl_engine_set_protocol_names(
    mut ctx: *mut br_ssl_engine_context,
    mut names: *mut *const libc::c_char,
    mut num: size_t,
) {
    let ref mut fresh3 = (*ctx).protocol_names;
    *fresh3 = names;
    (*ctx).protocol_names_num = num as uint16_t;
}
#[inline]
unsafe extern "C" fn br_ssl_engine_get_selected_protocol(
    mut ctx: *mut br_ssl_engine_context,
) -> *const libc::c_char {
    let mut k: libc::c_uint = 0;
    k = (*ctx).selected_protocol as libc::c_uint;
    return if k == 0 as libc::c_int as libc::c_uint
        || k == 0xffff as libc::c_int as libc::c_uint
    {
        0 as *const libc::c_char
    } else {
        *((*ctx).protocol_names)
            .offset(k.wrapping_sub(1 as libc::c_int as libc::c_uint) as isize)
    };
}
unsafe extern "C" fn append_dn(
    mut ctx: *mut libc::c_void,
    mut buf: *const libc::c_void,
    mut len: size_t,
) {
    let mut ca: *mut cafile_parser = ctx as *mut cafile_parser;
    if (*ca).err as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint
        || !(*ca).in_cert
    {
        return;
    }
    if (::std::mem::size_of::<[libc::c_uchar; 1024]>() as libc::c_ulong)
        .wrapping_sub((*ca).dn_len) < len
    {
        (*ca).err = CURLE_FAILED_INIT;
        return;
    }
    memcpy(
        ((*ca).dn).as_mut_ptr().offset((*ca).dn_len as isize) as *mut libc::c_void,
        buf,
        len,
    );
    let ref mut fresh4 = (*ca).dn_len;
    *fresh4 = (*fresh4 as libc::c_ulong).wrapping_add(len) as size_t as size_t;
}
unsafe extern "C" fn x509_push(
    mut ctx: *mut libc::c_void,
    mut buf: *const libc::c_void,
    mut len: size_t,
) {
    let mut ca: *mut cafile_parser = ctx as *mut cafile_parser;
    if (*ca).in_cert {
        br_x509_decoder_push(&mut (*ca).xc, buf, len);
    }
}
unsafe extern "C" fn load_cafile(
    mut source: *mut cafile_source,
    mut anchors: *mut *mut br_x509_trust_anchor,
    mut anchors_len: *mut size_t,
) -> CURLcode {
    let mut current_block: u64;
    let mut ca: cafile_parser = cafile_parser {
        err: CURLE_OK,
        in_cert: false,
        xc: br_x509_decoder_context {
            pkey: br_x509_pkey {
                key_type: 0,
                key: bear_C2RustUnnamed_6 {
                    rsa: br_rsa_public_key {
                        n: 0 as *mut libc::c_uchar,
                        nlen: 0,
                        e: 0 as *mut libc::c_uchar,
                        elen: 0,
                    },
                },
            },
            cpu: C2RustUnnamed_30 {
                dp: 0 as *mut uint32_t,
                rp: 0 as *mut uint32_t,
                ip: 0 as *const libc::c_uchar,
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
            hbuf: 0 as *const libc::c_uchar,
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
            ip: 0 as *const libc::c_uchar,
        },
        dp_stack: [0; 32],
        rp_stack: [0; 32],
        err: 0,
        hbuf: 0 as *const libc::c_uchar,
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
    let mut buf: [libc::c_uchar; 8192] = [0; 8192];
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut name: *const libc::c_char = 0 as *const libc::c_char;
    let mut n: size_t = 0;
    let mut i: size_t = 0;
    let mut pushed: size_t = 0;
    if (*source).type_0 == 1 as libc::c_int {
        fp = fopen((*source).data, b"rb\0" as *const u8 as *const libc::c_char);
        if fp.is_null() {
            return CURLE_SSL_CACERT_BADFILE;
        }
    }
    if (*source).type_0 == 2 as libc::c_int
        && (*source).len > 2147483647 as libc::c_int as size_t
    {
        return CURLE_SSL_CACERT_BADFILE;
    }
    ca.err = CURLE_OK;
    ca.in_cert = 0 as libc::c_int != 0;
    ca.anchors = 0 as *mut br_x509_trust_anchor;
    ca.anchors_len = 0 as libc::c_int as size_t;
    br_pem_decoder_init(&mut pc);
    br_pem_decoder_setdest(
        &mut pc,
        Some(
            x509_push
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_void,
                    size_t,
                ) -> (),
        ),
        &mut ca as *mut cafile_parser as *mut libc::c_void,
    );
    's_106: loop {
        if (*source).type_0 == 1 as libc::c_int {
            n = fread(
                buf.as_mut_ptr() as *mut libc::c_void,
                1 as libc::c_int as libc::c_ulong,
                ::std::mem::size_of::<[libc::c_uchar; 8192]>() as libc::c_ulong,
                fp,
            );
            if n == 0 as libc::c_int as libc::c_ulong {
                current_block = 8062065914618164218;
                break;
            }
            p = buf.as_mut_ptr();
        } else if (*source).type_0 == 2 as libc::c_int {
            n = (*source).len;
            p = (*source).data as *mut libc::c_uchar;
        }
        while n != 0 {
            pushed = br_pem_decoder_push(&mut pc, p as *const libc::c_void, n);
            if ca.err as u64 != 0 {
                current_block = 16641473711560579579;
                break 's_106;
            }
            p = p.offset(pushed as isize);
            n = (n as libc::c_ulong).wrapping_sub(pushed) as size_t as size_t;
            match br_pem_decoder_event(&mut pc) {
                0 => {}
                1 => {
                    name = br_pem_decoder_name(&mut pc);
                    if strcmp(name, b"CERTIFICATE\0" as *const u8 as *const libc::c_char)
                        != 0
                        && strcmp(
                            name,
                            b"X509 CERTIFICATE\0" as *const u8 as *const libc::c_char,
                        ) != 0
                    {
                        continue;
                    }
                    br_x509_decoder_init(
                        &mut ca.xc,
                        Some(
                            append_dn
                                as unsafe extern "C" fn(
                                    *mut libc::c_void,
                                    *const libc::c_void,
                                    size_t,
                                ) -> (),
                        ),
                        &mut ca as *mut cafile_parser as *mut libc::c_void,
                    );
                    if ca.anchors_len
                        == (18446744073709551615 as libc::c_ulong)
                            .wrapping_div(
                                ::std::mem::size_of::<br_x509_trust_anchor>()
                                    as libc::c_ulong,
                            )
                    {
                        ca.err = CURLE_OUT_OF_MEMORY;
                        current_block = 16641473711560579579;
                        break 's_106;
                    } else {
                        new_anchors_len = (ca.anchors_len)
                            .wrapping_add(1 as libc::c_int as libc::c_ulong);
                        new_anchors = Curl_crealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            ca.anchors as *mut libc::c_void,
                            new_anchors_len
                                .wrapping_mul(
                                    ::std::mem::size_of::<br_x509_trust_anchor>()
                                        as libc::c_ulong,
                                ),
                        ) as *mut br_x509_trust_anchor;
                        if new_anchors.is_null() {
                            ca.err = CURLE_OUT_OF_MEMORY;
                            current_block = 16641473711560579579;
                            break 's_106;
                        } else {
                            ca.anchors = new_anchors;
                            ca.anchors_len = new_anchors_len;
                            ca.in_cert = 1 as libc::c_int != 0;
                            ca.dn_len = 0 as libc::c_int as size_t;
                            ta = &mut *(ca.anchors)
                                .offset(
                                    (ca.anchors_len)
                                        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                ) as *mut br_x509_trust_anchor;
                            let ref mut fresh5 = (*ta).dn.data;
                            *fresh5 = 0 as *mut libc::c_uchar;
                        }
                    }
                }
                2 => {
                    if !ca.in_cert {
                        continue;
                    }
                    ca.in_cert = 0 as libc::c_int != 0;
                    if br_x509_decoder_last_error(&mut ca.xc) != 0 {
                        ca.err = CURLE_SSL_CACERT_BADFILE;
                        current_block = 16641473711560579579;
                        break 's_106;
                    } else {
                        (*ta).flags = 0 as libc::c_int as libc::c_uint;
                        if br_x509_decoder_isCA(&mut ca.xc) != 0 {
                            (*ta).flags |= 0x1 as libc::c_int as libc::c_uint;
                        }
                        pkey = br_x509_decoder_get_pkey(&mut ca.xc);
                        if pkey.is_null() {
                            ca.err = CURLE_SSL_CACERT_BADFILE;
                            current_block = 16641473711560579579;
                            break 's_106;
                        } else {
                            (*ta).pkey = *pkey;
                            ta_size = ca.dn_len;
                            match (*pkey).key_type as libc::c_int {
                                1 => {
                                    ta_size = (ta_size as libc::c_ulong)
                                        .wrapping_add(
                                            ((*pkey).key.rsa.nlen).wrapping_add((*pkey).key.rsa.elen),
                                        ) as size_t as size_t;
                                }
                                2 => {
                                    ta_size = (ta_size as libc::c_ulong)
                                        .wrapping_add((*pkey).key.ec.qlen) as size_t as size_t;
                                }
                                _ => {
                                    ca.err = CURLE_FAILED_INIT;
                                    current_block = 16641473711560579579;
                                    break 's_106;
                                }
                            }
                            let ref mut fresh6 = (*ta).dn.data;
                            *fresh6 = Curl_cmalloc
                                .expect("non-null function pointer")(ta_size)
                                as *mut libc::c_uchar;
                            if ((*ta).dn.data).is_null() {
                                ca.err = CURLE_OUT_OF_MEMORY;
                                current_block = 16641473711560579579;
                                break 's_106;
                            } else {
                                memcpy(
                                    (*ta).dn.data as *mut libc::c_void,
                                    (ca.dn).as_mut_ptr() as *const libc::c_void,
                                    ca.dn_len,
                                );
                                (*ta).dn.len = ca.dn_len;
                                match (*pkey).key_type as libc::c_int {
                                    1 => {
                                        let ref mut fresh7 = (*ta).pkey.key.rsa.n;
                                        *fresh7 = ((*ta).dn.data).offset((*ta).dn.len as isize);
                                        memcpy(
                                            (*ta).pkey.key.rsa.n as *mut libc::c_void,
                                            (*pkey).key.rsa.n as *const libc::c_void,
                                            (*pkey).key.rsa.nlen,
                                        );
                                        let ref mut fresh8 = (*ta).pkey.key.rsa.e;
                                        *fresh8 = ((*ta).pkey.key.rsa.n)
                                            .offset((*ta).pkey.key.rsa.nlen as isize);
                                        memcpy(
                                            (*ta).pkey.key.rsa.e as *mut libc::c_void,
                                            (*pkey).key.rsa.e as *const libc::c_void,
                                            (*pkey).key.rsa.elen,
                                        );
                                    }
                                    2 => {
                                        let ref mut fresh9 = (*ta).pkey.key.ec.q;
                                        *fresh9 = ((*ta).dn.data).offset((*ta).dn.len as isize);
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
                }
                _ => {
                    ca.err = CURLE_SSL_CACERT_BADFILE;
                    current_block = 16641473711560579579;
                    break 's_106;
                }
            }
        }
        if !((*source).type_0 != 2 as libc::c_int) {
            current_block = 8062065914618164218;
            break;
        }
    }
    match current_block {
        8062065914618164218 => {
            if !fp.is_null() && ferror(fp) != 0 {
                ca.err = CURLE_READ_ERROR;
            }
        }
        _ => {}
    }
    if !fp.is_null() {
        fclose(fp);
    }
    if ca.err as libc::c_uint == CURLE_OK as libc::c_int as libc::c_uint {
        *anchors = ca.anchors;
        *anchors_len = ca.anchors_len;
    } else {
        i = 0 as libc::c_int as size_t;
        while i < ca.anchors_len {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*(ca.anchors).offset(i as isize)).dn.data as *mut libc::c_void);
            i = i.wrapping_add(1);
        }
        Curl_cfree.expect("non-null function pointer")(ca.anchors as *mut libc::c_void);
    }
    return ca.err;
}
unsafe extern "C" fn x509_start_chain(
    mut ctx: *mut *const br_x509_class,
    mut server_name: *const libc::c_char,
) {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    if !(*x509).verifyhost {
        server_name = 0 as *const libc::c_char;
    }
    ((*(*x509).minimal.vtable).start_chain)
        .expect("non-null function pointer")(&mut (*x509).minimal.vtable, server_name);
}
unsafe extern "C" fn x509_start_cert(
    mut ctx: *mut *const br_x509_class,
    mut length: uint32_t,
) {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    ((*(*x509).minimal.vtable).start_cert)
        .expect("non-null function pointer")(&mut (*x509).minimal.vtable, length);
}
unsafe extern "C" fn x509_append(
    mut ctx: *mut *const br_x509_class,
    mut buf: *const libc::c_uchar,
    mut len: size_t,
) {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    ((*(*x509).minimal.vtable).append)
        .expect("non-null function pointer")(&mut (*x509).minimal.vtable, buf, len);
}
unsafe extern "C" fn x509_end_cert(mut ctx: *mut *const br_x509_class) {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    ((*(*x509).minimal.vtable).end_cert)
        .expect("non-null function pointer")(&mut (*x509).minimal.vtable);
}
unsafe extern "C" fn x509_end_chain(mut ctx: *mut *const br_x509_class) -> libc::c_uint {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    let mut err: libc::c_uint = 0;
    err = ((*(*x509).minimal.vtable).end_chain)
        .expect("non-null function pointer")(&mut (*x509).minimal.vtable);
    if err != 0 && !(*x509).verifypeer {
        err = 0 as libc::c_int as libc::c_uint;
    }
    return err;
}
unsafe extern "C" fn x509_get_pkey(
    mut ctx: *const *const br_x509_class,
    mut usages: *mut libc::c_uint,
) -> *const br_x509_pkey {
    let mut x509: *mut x509_context = ctx as *mut x509_context;
    return ((*(*x509).minimal.vtable).get_pkey)
        .expect("non-null function pointer")(&mut (*x509).minimal.vtable, usages);
}

static mut x509_vtable: br_x509_class = unsafe {
    {
        let mut init = br_x509_class_ {
            context_size: ::std::mem::size_of::<x509_context>() as libc::c_ulong,
            start_chain: Some(
                x509_start_chain
                    as unsafe extern "C" fn(
                        *mut *const br_x509_class,
                        *const libc::c_char,
                    ) -> (),
            ),
            start_cert: Some(
                x509_start_cert
                    as unsafe extern "C" fn(*mut *const br_x509_class, uint32_t) -> (),
            ),
            append: Some(
                x509_append
                    as unsafe extern "C" fn(
                        *mut *const br_x509_class,
                        *const libc::c_uchar,
                        size_t,
                    ) -> (),
            ),
            end_cert: Some(
                x509_end_cert as unsafe extern "C" fn(*mut *const br_x509_class) -> (),
            ),
            end_chain: Some(
                x509_end_chain
                    as unsafe extern "C" fn(*mut *const br_x509_class) -> libc::c_uint,
            ),
            get_pkey: Some(
                x509_get_pkey
                    as unsafe extern "C" fn(
                        *const *const br_x509_class,
                        *mut libc::c_uint,
                    ) -> *const br_x509_pkey,
            ),
        };
        init
    }
};
unsafe extern "C" fn bearssl_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut ca_info_blob: *const curl_blob = if CURLPROXY_HTTPS as libc::c_int
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
        (*conn).proxy_ssl_config.ca_info_blob
    } else {
        (*conn).ssl_config.ca_info_blob
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut ca_info_blob: *const curl_blob = (*conn).ssl_config.ca_info_blob;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let ssl_cafile: *const libc::c_char = if !ca_info_blob.is_null() {
        0 as *mut libc::c_char
    } else if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    let ssl_cafile: *const libc::c_char = (*conn).ssl_config.CAfile;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut hostname: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int
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
        (*conn).http_proxy.host.name
    } else {
        (*conn).host.name
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut hostname: *const libc::c_char = (*conn).host.name;
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
    let verifypeer: bool = ((*conn).ssl_config).verifypeer() as libc::c_int != 0;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let verifyhost: bool = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    } != 0;
    #[cfg(CURL_DISABLE_PROXY)]
    let verifyhost: bool = ((*conn).ssl_config).verifyhost() as libc::c_int != 0;
    let mut ret: CURLcode = CURLE_OK;
    let mut version_min: libc::c_uint = 0;
    let mut version_max: libc::c_uint = 0;
    #[cfg(ENABLE_IPV6)]
    let mut addr: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_8 {
            __u6_addr8: [0; 16],
        },
    };
    #[cfg(not(ENABLE_IPV6))]
    let mut addr: in_addr = in_addr { s_addr: 0 };
    
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag6: libc::c_long = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    let flag6: libc::c_long = (*conn).ssl_config.version;
    match flag6
    {
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
            version_min = 0x301 as libc::c_int as libc::c_uint;
            version_max = 0x301 as libc::c_int as libc::c_uint;
        }
        5 => {
            version_min = 0x302 as libc::c_int as libc::c_uint;
            version_max = 0x302 as libc::c_int as libc::c_uint;
        }
        6 => {
            version_min = 0x303 as libc::c_int as libc::c_uint;
            version_max = 0x303 as libc::c_int as libc::c_uint;
        }
        0 | 1 => {
            version_min = 0x301 as libc::c_int as libc::c_uint;
            version_max = 0x303 as libc::c_int as libc::c_uint;
        }
        _ => {
            Curl_failf(
                data,
                b"BearSSL: unknown CURLOPT_SSLVERSION\0" as *const u8
                    as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    if !ca_info_blob.is_null() {
        let mut source: cafile_source = {
            let mut init = cafile_source {
                type_0: 2 as libc::c_int,
                data: (*ca_info_blob).data as *const libc::c_char,
                len: (*ca_info_blob).len,
            };
            init
        };
        ret = load_cafile(
            &mut source,
            &mut (*backend).anchors,
            &mut (*backend).anchors_len,
        );
        if ret as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
            if verifypeer {
                Curl_failf(
                    data,
                    b"error importing CA certificate blob\0" as *const u8
                        as *const libc::c_char,
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
            let mut init = cafile_source {
                type_0: 1 as libc::c_int,
                data: ssl_cafile,
                len: 0 as libc::c_int as size_t,
            };
            init
        };
        ret = load_cafile(
            &mut source_0,
            &mut (*backend).anchors,
            &mut (*backend).anchors_len,
        );
        if ret as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
            if verifypeer {
                Curl_failf(
                    data,
                    b"error setting certificate verify locations. CAfile: %s\0"
                        as *const u8 as *const libc::c_char,
                    ssl_cafile,
                );
                return ret;
            }
            Curl_infof(
                data,
                b"error setting certificate verify locations, continuing anyway:\0"
                    as *const u8 as *const libc::c_char,
            );
        }
    }
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
        ::std::mem::size_of::<[libc::c_uchar; 33178]>() as libc::c_ulong,
        1 as libc::c_int,
    );
    let ref mut fresh10 = (*backend).x509.vtable;
    *fresh10 = &x509_vtable;
    (*backend).x509.verifypeer = verifypeer;
    (*backend).x509.verifyhost = verifyhost;
    br_ssl_engine_set_x509(&mut (*backend).bear_ctx.eng, &mut (*backend).x509.vtable);
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag7: bool = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                } != 0;
    #[cfg(CURL_DISABLE_PROXY)]
    let flag7: bool = ((*data).set.ssl.primary).sessionid() as libc::c_int != 0;
    if flag7
    {
        let mut session: *mut libc::c_void = 0 as *mut libc::c_void;
        Curl_ssl_sessionid_lock(data);
        #[cfg(not(CURL_DISABLE_PROXY))]
        let flag8: bool = CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                    .state as libc::c_uint;
        #[cfg(CURL_DISABLE_PROXY)]
        let flag8: bool = false;
        if !Curl_ssl_getsessionid(
            data,
            conn,
            if flag8
            {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            } != 0,
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
        let mut cur: libc::c_int = 0 as libc::c_int;
        match () {
            #[cfg(USE_HTTP2)]
            _ => {
                #[cfg(not(CURL_DISABLE_PROXY))]
                let CURL_DISABLE_PROXY_flag = (!(CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                                            .state as libc::c_uint) || ((*conn).bits).tunnel_proxy() == 0);
                #[cfg(CURL_DISABLE_PROXY)]
                let CURL_DISABLE_PROXY_flag = true;
                if (*data).state.httpwant as libc::c_int >= CURL_HTTP_VERSION_2_0 as libc::c_int
                    && CURL_DISABLE_PROXY_flag
                {
                    let fresh11 = cur;
                    cur = cur + 1;
                    let ref mut fresh12 = (*backend).protocols[fresh11 as usize];
                    *fresh12 = b"h2\0" as *const u8 as *const libc::c_char;
                    Curl_infof(
                        data,
                        b"ALPN, offering %s\0" as *const u8 as *const libc::c_char,
                        b"h2\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            #[cfg(not(USE_HTTP2))]
            _ => { }
        }
        let fresh13 = cur;
        cur = cur + 1;
        let ref mut fresh14 = (*backend).protocols[fresh13 as usize];
        *fresh14 = b"http/1.1\0" as *const u8 as *const libc::c_char;
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
    let ENABLE_IPV6_flag = 1 as libc::c_int
        == inet_pton(
            2 as libc::c_int,
            hostname,
            &mut addr as *mut in6_addr as *mut libc::c_void,
        )
        || 1 as libc::c_int
            == inet_pton(
                10 as libc::c_int,
                hostname,
                &mut addr as *mut in6_addr as *mut libc::c_void,
            );
    #[cfg(not(ENABLE_IPV6))]
    let ENABLE_IPV6_flag = 1 as libc::c_int
        == inet_pton(
            2 as libc::c_int,
            hostname,
            &mut addr as *mut in_addr as *mut libc::c_void,
        );
    if ENABLE_IPV6_flag
    {
        if verifyhost {
            Curl_failf(
                data,
                b"BearSSL: host verification of IP address is not supported\0"
                    as *const u8 as *const libc::c_char,
            );
            return CURLE_PEER_FAILED_VERIFICATION;
        }
        hostname = 0 as *const libc::c_char;
    }
    if br_ssl_client_reset(&mut (*backend).bear_ctx, hostname, 0 as libc::c_int) == 0 {
        return CURLE_FAILED_INIT;
    }
    (*backend).active = 1 as libc::c_int != 0;
    (*connssl).connecting_state = ssl_connect_2;
    return CURLE_OK;
}

unsafe extern "C" fn bearssl_run_until(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut target: libc::c_uint,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
    let mut state: libc::c_uint = 0;
    let mut buf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut len: size_t = 0;
    let mut ret: ssize_t = 0;
    let mut err: libc::c_int = 0;
    loop {
        state = br_ssl_engine_current_state(&mut (*backend).bear_ctx.eng);
        if state & 0x1 as libc::c_int as libc::c_uint != 0 {
            err = br_ssl_engine_last_error(&mut (*backend).bear_ctx.eng);
            match err {
                0 => {
                    if (*connssl).state as libc::c_uint
                        != ssl_connection_complete as libc::c_int as libc::c_uint
                    {
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
            if err >= 32 as libc::c_int && err < 64 as libc::c_int {
                return CURLE_PEER_FAILED_VERIFICATION;
            }
            return CURLE_SSL_CONNECT_ERROR;
        }
        if state & target != 0 {
            return CURLE_OK;
        }
        if state & 0x2 as libc::c_int as libc::c_uint != 0 {
            buf = br_ssl_engine_sendrec_buf(&mut (*backend).bear_ctx.eng, &mut len);
            ret = send(
                sockfd,
                buf as *const libc::c_void,
                len,
                MSG_NOSIGNAL as libc::c_int,
            );
            if ret == -(1 as libc::c_int) as libc::c_long {
                if *__errno_location() == 11 as libc::c_int
                    || *__errno_location() == 11 as libc::c_int
                {
                    if (*connssl).state as libc::c_uint
                        != ssl_connection_complete as libc::c_int as libc::c_uint
                    {
                        (*connssl).connecting_state = ssl_connect_2_writing;
                    }
                    return CURLE_AGAIN;
                }
                return CURLE_WRITE_ERROR;
            }
            br_ssl_engine_sendrec_ack(&mut (*backend).bear_ctx.eng, ret as size_t);
        } else if state & 0x4 as libc::c_int as libc::c_uint != 0 {
            buf = br_ssl_engine_recvrec_buf(&mut (*backend).bear_ctx.eng, &mut len);
            ret = recv(sockfd, buf as *mut libc::c_void, len, 0 as libc::c_int);
            if ret == 0 as libc::c_int as libc::c_long {
                Curl_failf(
                    data,
                    b"SSL: EOF without close notify\0" as *const u8
                        as *const libc::c_char,
                );
                return CURLE_READ_ERROR;
            }
            if ret == -(1 as libc::c_int) as libc::c_long {
                if *__errno_location() == 11 as libc::c_int
                    || *__errno_location() == 11 as libc::c_int
                {
                    if (*connssl).state as libc::c_uint
                        != ssl_connection_complete as libc::c_int as libc::c_uint
                    {
                        (*connssl).connecting_state = ssl_connect_2_reading;
                    }
                    return CURLE_AGAIN;
                }
                return CURLE_READ_ERROR;
            }
            br_ssl_engine_recvrec_ack(&mut (*backend).bear_ctx.eng, ret as size_t);
        }
    };
}

unsafe extern "C" fn bearssl_connect_step2(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut ret: CURLcode = CURLE_OK;
    ret = bearssl_run_until(
        data,
        conn,
        sockindex,
        (0x8 as libc::c_int | 0x10 as libc::c_int) as libc::c_uint,
    );
    if ret as libc::c_uint == CURLE_AGAIN as libc::c_int as libc::c_uint {
        return CURLE_OK;
    }
    if ret as libc::c_uint == CURLE_OK as libc::c_int as libc::c_uint {
        if br_ssl_engine_current_state(&mut (*backend).bear_ctx.eng)
            == 0x1 as libc::c_int as libc::c_uint
        {
            Curl_failf(
                data,
                b"SSL: connection closed during handshake\0" as *const u8
                    as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        (*connssl).connecting_state = ssl_connect_3;
    }
    return ret;
}

unsafe extern "C" fn bearssl_connect_step3(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut ret: CURLcode = CURLE_OK;
    if ((*conn).bits).tls_enable_alpn() != 0 {
        let mut protocol: *const libc::c_char = 0 as *const libc::c_char;
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
                        (*conn).negnpn = CURL_HTTP_VERSION_2_0 as libc::c_int;
                    }
                    #[cfg(not(USE_HTTP2))]
                    _ => { }
                }
            } else if strcmp(protocol, b"http/1.1\0" as *const u8 as *const libc::c_char)
                    == 0
                {
                (*conn).negnpn = CURL_HTTP_VERSION_1_1 as libc::c_int;
            } else {
                Curl_infof(
                    data,
                    b"ALPN, unrecognized protocol %s\0" as *const u8
                        as *const libc::c_char,
                    protocol,
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
        } else {
            Curl_infof(
                data,
                b"ALPN, server did not agree to a protocol\0" as *const u8
                    as *const libc::c_char,
            );
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag1: bool = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                } != 0;
    #[cfg(CURL_DISABLE_PROXY)]
    let flag1: bool = ((*data).set.ssl.primary).sessionid() as libc::c_int != 0;
    if flag1
    {
        let mut incache: bool = false;
        let mut oldsession: *mut libc::c_void = 0 as *mut libc::c_void;
        let mut session: *mut br_ssl_session_parameters = 0
            as *mut br_ssl_session_parameters;
        session = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<br_ssl_session_parameters>() as libc::c_ulong)
            as *mut br_ssl_session_parameters;
        if session.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        br_ssl_engine_get_session_parameters(&mut (*backend).bear_ctx.eng, session);
        Curl_ssl_sessionid_lock(data);
        #[cfg(not(CURL_DISABLE_PROXY))]
        let flag1: bool = CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                    .state as libc::c_uint;
        #[cfg(CURL_DISABLE_PROXY)]
        let flag1: bool = false;
        incache = !Curl_ssl_getsessionid(
            data,
            conn,
            if flag1
            {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            } != 0,
            &mut oldsession,
            0 as *mut size_t,
            sockindex,
        );
        if incache {
            Curl_ssl_delsessionid(data, oldsession);
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let flag2: bool = CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                    .state as libc::c_uint;
        #[cfg(CURL_DISABLE_PROXY)]
        let flag2: bool = false;
        ret = Curl_ssl_addsessionid(
            data,
            conn,
            if flag2
            {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            } != 0,
            session as *mut libc::c_void,
            0 as libc::c_int as size_t,
            sockindex,
        );
        Curl_ssl_sessionid_unlock(data);
        if ret as u64 != 0 {
            Curl_cfree.expect("non-null function pointer")(session as *mut libc::c_void);
            return CURLE_OUT_OF_MEMORY;
        }
    }
    (*connssl).connecting_state = ssl_connect_done;
    return CURLE_OK;
}

unsafe extern "C" fn bearssl_send(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut buf: *const libc::c_void,
    mut len: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut app: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut applen: size_t = 0;
    loop {
        *err = bearssl_run_until(
            data,
            conn,
            sockindex,
            0x8 as libc::c_int as libc::c_uint,
        );
        if *err as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
            return -(1 as libc::c_int) as ssize_t;
        }
        app = br_ssl_engine_sendapp_buf(&mut (*backend).bear_ctx.eng, &mut applen);
        if app.is_null() {
            Curl_failf(
                data,
                b"SSL: connection closed during write\0" as *const u8
                    as *const libc::c_char,
            );
            *err = CURLE_SEND_ERROR;
            return -(1 as libc::c_int) as ssize_t;
        }
        if (*backend).pending_write != 0 {
            applen = (*backend).pending_write;
            (*backend).pending_write = 0 as libc::c_int as size_t;
            return applen as ssize_t;
        }
        if applen > len {
            applen = len;
        }
        memcpy(app as *mut libc::c_void, buf, applen);
        br_ssl_engine_sendapp_ack(&mut (*backend).bear_ctx.eng, applen);
        br_ssl_engine_flush(&mut (*backend).bear_ctx.eng, 0 as libc::c_int);
        (*backend).pending_write = applen;
    };
}

unsafe extern "C" fn bearssl_recv(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut buf: *mut libc::c_char,
    mut len: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut app: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut applen: size_t = 0;
    *err = bearssl_run_until(data, conn, sockindex, 0x10 as libc::c_int as libc::c_uint);
    if *err as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
        return -(1 as libc::c_int) as ssize_t;
    }
    app = br_ssl_engine_recvapp_buf(&mut (*backend).bear_ctx.eng, &mut applen);
    if app.is_null() {
        return 0 as libc::c_int as ssize_t;
    }
    if applen > len {
        applen = len;
    }
    memcpy(buf as *mut libc::c_void, app as *const libc::c_void, applen);
    br_ssl_engine_recvapp_ack(&mut (*backend).bear_ctx.eng, applen);
    return applen as ssize_t;
}

unsafe extern "C" fn bearssl_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
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
        ret = bearssl_connect_step1(data, conn, sockindex);
        if ret as u64 != 0 {
            return ret;
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
        if ssl_connect_2_reading as libc::c_int as libc::c_uint
            == (*connssl).connecting_state as libc::c_uint
            || ssl_connect_2_writing as libc::c_int as libc::c_uint
                == (*connssl).connecting_state as libc::c_uint
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
        ret = bearssl_connect_step2(data, conn, sockindex);
        if ret as libc::c_uint != 0
            || nonblocking as libc::c_int != 0
                && (ssl_connect_2 as libc::c_int as libc::c_uint
                    == (*connssl).connecting_state as libc::c_uint
                    || ssl_connect_2_reading as libc::c_int as libc::c_uint
                        == (*connssl).connecting_state as libc::c_uint
                    || ssl_connect_2_writing as libc::c_int as libc::c_uint
                        == (*connssl).connecting_state as libc::c_uint)
        {
            return ret;
        }
    }
    if ssl_connect_3 as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        ret = bearssl_connect_step3(data, conn, sockindex);
        if ret as u64 != 0 {
            return ret;
        }
    }
    if ssl_connect_done as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        (*connssl).state = ssl_connection_complete;
        let ref mut fresh15 = (*conn).recv[sockindex as usize];
        *fresh15 = Some(
            bearssl_recv
                as unsafe extern "C" fn(
                    *mut Curl_easy,
                    libc::c_int,
                    *mut libc::c_char,
                    size_t,
                    *mut CURLcode,
                ) -> ssize_t,
        );
        let ref mut fresh16 = (*conn).send[sockindex as usize];
        *fresh16 = Some(
            bearssl_send
                as unsafe extern "C" fn(
                    *mut Curl_easy,
                    libc::c_int,
                    *const libc::c_void,
                    size_t,
                    *mut CURLcode,
                ) -> ssize_t,
        );
        *done = 1 as libc::c_int != 0;
    } else {
        *done = 0 as libc::c_int != 0;
    }
    (*connssl).connecting_state = ssl_connect_1;
    return CURLE_OK;
}

unsafe extern "C" fn bearssl_version(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
) -> size_t {
    return curl_msnprintf(buffer, size, b"BearSSL\0" as *const u8 as *const libc::c_char)
        as size_t;
}

unsafe extern "C" fn bearssl_data_pending(
    mut conn: *const connectdata,
    mut connindex: libc::c_int,
) -> bool {
    let mut connssl: *const ssl_connect_data = &*((*conn).ssl)
        .as_ptr()
        .offset(connindex as isize) as *const ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return br_ssl_engine_current_state(&mut (*backend).bear_ctx.eng)
        & 0x10 as libc::c_int as libc::c_uint != 0;
}

unsafe extern "C" fn bearssl_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut libc::c_uchar,
    mut length: size_t,
) -> CURLcode {
    static mut ctx: br_hmac_drbg_context = br_hmac_drbg_context {
        vtable: 0 as *const br_prng_class,
        K: [0; 64],
        V: [0; 64],
        digest_class: 0 as *const br_hash_class,
    };
    static mut seeded: bool = 0 as libc::c_int != 0;
    if !seeded {
        let mut seeder: br_prng_seeder = None;
        br_hmac_drbg_init(
            &mut ctx,
            &br_sha256_vtable,
            0 as *const libc::c_void,
            0 as libc::c_int as size_t,
        );
        seeder = br_prng_seeder_system(0 as *mut *const libc::c_char);
        if seeder.is_none()
            || seeder.expect("non-null function pointer")(&mut ctx.vtable) == 0
        {
            return CURLE_FAILED_INIT;
        }
        seeded = 1 as libc::c_int != 0;
    }
    br_hmac_drbg_generate(&mut ctx, entropy as *mut libc::c_void, length);
    return CURLE_OK;
}

unsafe extern "C" fn bearssl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut done: bool = 0 as libc::c_int != 0;
    ret = bearssl_connect_common(
        data,
        conn,
        sockindex,
        0 as libc::c_int != 0,
        &mut done,
    );
    if ret as u64 != 0 {
        return ret;
    }
    return CURLE_OK;
}

unsafe extern "C" fn bearssl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    return bearssl_connect_common(data, conn, sockindex, 1 as libc::c_int != 0, done);
}

unsafe extern "C" fn bearssl_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return &mut (*backend).bear_ctx as *mut br_ssl_client_context as *mut libc::c_void;
}

unsafe extern "C" fn bearssl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut i: size_t = 0;
    if (*backend).active {
        br_ssl_engine_close(&mut (*backend).bear_ctx.eng);
        bearssl_run_until(data, conn, sockindex, 0x1 as libc::c_int as libc::c_uint);
    }
    i = 0 as libc::c_int as size_t;
    while i < (*backend).anchors_len {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*((*backend).anchors).offset(i as isize)).dn.data as *mut libc::c_void);
        i = i.wrapping_add(1);
    }
    Curl_cfree
        .expect("non-null function pointer")((*backend).anchors as *mut libc::c_void);
}

unsafe extern "C" fn bearssl_session_free(mut ptr: *mut libc::c_void) {
    Curl_cfree.expect("non-null function pointer")(ptr);
}

unsafe extern "C" fn bearssl_sha256sum(
    mut input: *const libc::c_uchar,
    mut inputlen: size_t,
    mut sha256sum: *mut libc::c_uchar,
    mut sha256len: size_t,
) -> CURLcode {
    let mut ctx: br_sha256_context = br_sha256_context {
        vtable: 0 as *const br_hash_class,
        buf: [0; 64],
        count: 0,
        val: [0; 8],
    };
    br_sha256_init(&mut ctx);
    br_sha224_update(&mut ctx, input as *const libc::c_void, inputlen);
    br_sha256_out(&mut ctx, sha256sum as *mut libc::c_void);
    return CURLE_OK;
}
#[no_mangle]

pub static mut Curl_ssl_bearssl: Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_BEARSSL,
                    name: b"bearssl\0" as *const u8 as *const libc::c_char,
                };
                init
            },
            supports: ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint,
            sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>()
                as libc::c_ulong,
            init: Some(Curl_none_init as unsafe extern "C" fn() -> libc::c_int),
            cleanup: Some(Curl_none_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(
                bearssl_version
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
                bearssl_data_pending
                    as unsafe extern "C" fn(*const connectdata, libc::c_int) -> bool,
            ),
            random: Some(
                bearssl_random
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
                bearssl_connect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> CURLcode,
            ),
            connect_nonblocking: Some(
                bearssl_connect_nonblocking
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
                bearssl_get_internals
                    as unsafe extern "C" fn(
                        *mut ssl_connect_data,
                        CURLINFO,
                    ) -> *mut libc::c_void,
            ),
            close_one: Some(
                bearssl_close
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
                bearssl_session_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
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
                bearssl_sha256sum
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
