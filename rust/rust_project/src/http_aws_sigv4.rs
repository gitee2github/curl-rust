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
 * Author: wyf<wuyf21@mail.ustc.edu.cn>, 
 * Create: 2022-10-31
 * Description: http aws sigv4
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

unsafe extern "C" fn sha256_to_hex(
    mut dst: *mut libc::c_char,
    mut sha: *mut libc::c_uchar,
    mut dst_l: size_t,
) {
    let mut i: libc::c_int = 0;
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if dst_l >= 65 as libc::c_int as libc::c_ulong {
    } else {
        __assert_fail(
            b"dst_l >= 65\0" as *const u8 as *const libc::c_char,
            b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
            63 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<&[u8; 52], &[libc::c_char; 52]>(
                b"void sha256_to_hex(char *, unsigned char *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    i = 0 as libc::c_int;
    while i < 32 as libc::c_int {
        curl_msnprintf(
            dst.offset((i * 2 as libc::c_int) as isize),
            dst_l.wrapping_sub((i * 2 as libc::c_int) as libc::c_ulong),
            b"%02x\0" as *const u8 as *const libc::c_char,
            *sha.offset(i as isize) as libc::c_int,
        );
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_output_aws_sigv4(
    mut data: *mut Curl_easy,
    mut proxy: bool,
) -> CURLcode {
    let mut current_block: u64;
    let mut ret: CURLcode = CURLE_OUT_OF_MEMORY;
    let mut conn: *mut connectdata = (*data).conn;
    let mut len: size_t = 0;
    let mut tmp0: *const libc::c_char = 0 as *const libc::c_char;
    let mut tmp1: *const libc::c_char = 0 as *const libc::c_char;
    let mut provider0_low: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut provider0_up: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut provider1_low: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut provider1_mid: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut region: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut service: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hostname: *const libc::c_char = (*conn).host.name;
    let mut force_timestamp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut clock: time_t = 0;
    let mut tm: tm = tm {
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
    let mut timestamp: [libc::c_char; 17] = [0; 17];
    let mut date: [libc::c_char; 9] = [0; 9];
    let mut content_type: *const libc::c_char =
        Curl_checkheaders(data, b"Content-Type\0" as *const u8 as *const libc::c_char);
    let mut canonical_headers: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut signed_headers: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut httpreq: Curl_HttpReq = HTTPREQ_GET;
    let mut method: *const libc::c_char = 0 as *const libc::c_char;
    let mut post_data: *const libc::c_char = (if !((*data).set.postfields).is_null() {
        (*data).set.postfields
    } else {
        b"\0" as *const u8 as *const libc::c_char as *const libc::c_void
    }) as *const libc::c_char;
    let mut sha_hash: [libc::c_uchar; 32] = [0; 32];
    let mut sha_hex: [libc::c_char; 65] = [0; 65];
    let mut canonical_request: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut request_type: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut credential_scope: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut str_to_sign: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut user: *const libc::c_char = if !((*data).state.aptr.user).is_null() {
        (*data).state.aptr.user as *const libc::c_char
    } else {
        b"\0" as *const u8 as *const libc::c_char
    };
    let mut passwd: *const libc::c_char = if !((*data).state.aptr.passwd).is_null() {
        (*data).state.aptr.passwd as *const libc::c_char
    } else {
        b"\0" as *const u8 as *const libc::c_char
    };
    let mut secret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp_sign0: [libc::c_uchar; 32] = [
        0 as libc::c_int as libc::c_uchar,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut tmp_sign1: [libc::c_uchar; 32] = [
        0 as libc::c_int as libc::c_uchar,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut auth_headers: *mut libc::c_char = 0 as *mut libc::c_char;
    #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
    if !proxy {
    } else {
        __assert_fail(
            b"!proxy\0" as *const u8 as *const libc::c_char,
            b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
            109 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<&[u8; 58], &[libc::c_char; 58]>(
                b"CURLcode Curl_output_aws_sigv4(struct Curl_easy *, _Bool)\0",
            ))
            .as_ptr(),
        );
    }
    if !(Curl_checkheaders(data, b"Authorization\0" as *const u8 as *const libc::c_char)).is_null()
    {
        return CURLE_OK;
    }
    tmp0 = if !((*data).set.str_0[STRING_AWS_SIGV4 as libc::c_int as usize]).is_null() {
        (*data).set.str_0[STRING_AWS_SIGV4 as libc::c_int as usize] as *const libc::c_char
    } else {
        b"aws:amz\0" as *const u8 as *const libc::c_char
    };
    tmp1 = strchr(tmp0, ':' as i32);
    len = if !tmp1.is_null() {
        tmp1.offset_from(tmp0) as libc::c_long as size_t
    } else {
        strlen(tmp0)
    };
    if len < 1 as libc::c_int as libc::c_ulong {
        Curl_infof(
            data,
            b"first provider can't be empty\0" as *const u8 as *const libc::c_char,
        );
        ret = CURLE_BAD_FUNCTION_ARGUMENT;
    } else {
        #[cfg(not(CURLDEBUG))]
        let mut new_provider0_low: *mut libc::c_char = Curl_cmalloc.expect("non-null function pointer")(
            len.wrapping_add(1 as libc::c_int as libc::c_ulong),
        ) as *mut libc::c_char;
        #[cfg(CURLDEBUG)]
        let mut new_provider0_low: *mut libc::c_char = curl_dbg_malloc(
            len.wrapping_add(1 as libc::c_int as libc::c_ulong),
            133 as libc::c_int,
            b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
        ) as *mut libc::c_char;
        provider0_low = new_provider0_low;
        #[cfg(not(CURLDEBUG))]
        let mut new_provider0_up: *mut libc::c_char = Curl_cmalloc.expect("non-null function pointer")(
            len.wrapping_add(1 as libc::c_int as libc::c_ulong),
        ) as *mut libc::c_char;
        #[cfg(CURLDEBUG)]
        let mut new_provider0_up: *mut libc::c_char = curl_dbg_malloc(
            len.wrapping_add(1 as libc::c_int as libc::c_ulong),
            134 as libc::c_int,
            b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
        ) as *mut libc::c_char;
        provider0_up = new_provider0_up;
        if !(provider0_low.is_null() || provider0_up.is_null()) {
            Curl_strntolower(provider0_low, tmp0, len);
            *provider0_low.offset(len as isize) = '\0' as i32 as libc::c_char;
            Curl_strntoupper(provider0_up, tmp0, len);
            *provider0_up.offset(len as isize) = '\0' as i32 as libc::c_char;
            if !tmp1.is_null() {
                tmp0 = tmp1.offset(1 as libc::c_int as isize);
                tmp1 = strchr(tmp0, ':' as i32);
                len = if !tmp1.is_null() {
                    tmp1.offset_from(tmp0) as libc::c_long as size_t
                } else {
                    strlen(tmp0)
                };
                if len < 1 as libc::c_int as libc::c_ulong {
                    Curl_infof(
                        data,
                        b"second provider can't be empty\0" as *const u8 as *const libc::c_char,
                    );
                    ret = CURLE_BAD_FUNCTION_ARGUMENT;
                    current_block = 16896850163988546332;
                } else {
                    #[cfg(not(CURLDEBUG))]
                    let mut new_provider1_low: *mut libc::c_char = Curl_cmalloc.expect("non-null function pointer")(
                        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                    ) as *mut libc::c_char;
                    #[cfg(CURLDEBUG)]
                    let mut new_provider1_low: *mut libc::c_char = curl_dbg_malloc(
                        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                        152 as libc::c_int,
                        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
                    ) as *mut libc::c_char;
                    provider1_low = new_provider1_low;
                    #[cfg(not(CURLDEBUG))]
                    let mut new_provider1_mid: *mut libc::c_char = Curl_cmalloc.expect("non-null function pointer")(
                        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                    ) as *mut libc::c_char;
                    #[cfg(CURLDEBUG)]
                    let mut new_provider1_mid: *mut libc::c_char = curl_dbg_malloc(
                        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                        153 as libc::c_int,
                        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
                    ) as *mut libc::c_char;
                    provider1_mid = new_provider1_mid;
                    if provider1_low.is_null() || provider1_mid.is_null() {
                        current_block = 16896850163988546332;
                    } else {
                        Curl_strntolower(provider1_low, tmp0, len);
                        *provider1_low.offset(len as isize) = '\0' as i32 as libc::c_char;
                        Curl_strntolower(provider1_mid, tmp0, len);
                        *provider1_mid.offset(0 as libc::c_int as isize) =
                            Curl_raw_toupper(*provider1_mid.offset(0 as libc::c_int as isize));
                        *provider1_mid.offset(len as isize) = '\0' as i32 as libc::c_char;
                        if !tmp1.is_null() {
                            tmp0 = tmp1.offset(1 as libc::c_int as isize);
                            tmp1 = strchr(tmp0, ':' as i32);
                            len = if !tmp1.is_null() {
                                tmp1.offset_from(tmp0) as libc::c_long as size_t
                            } else {
                                strlen(tmp0)
                            };
                            if len < 1 as libc::c_int as libc::c_ulong {
                                Curl_infof(
                                    data,
                                    b"region can't be empty\0" as *const u8 as *const libc::c_char,
                                );
                                ret = CURLE_BAD_FUNCTION_ARGUMENT;
                                current_block = 16896850163988546332;
                            } else {
                                region = Curl_memdup(
                                    tmp0 as *const libc::c_void,
                                    len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                                ) as *mut libc::c_char;
                                if region.is_null() {
                                    current_block = 16896850163988546332;
                                } else {
                                    *region.offset(len as isize) = '\0' as i32 as libc::c_char;
                                    if !tmp1.is_null() {
                                        tmp0 = tmp1.offset(1 as libc::c_int as isize);
                                        #[cfg(not(CURLDEBUG))]
                                        let mut new_service: *mut libc::c_char =
                                        Curl_cstrdup.expect("non-null function pointer")(tmp0);
                                        #[cfg(CURLDEBUG)]
                                        let mut new_service: *mut libc::c_char = curl_dbg_strdup(
                                            tmp0,
                                            180 as libc::c_int,
                                            b"http_aws_sigv4.c\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        service = new_service;
                                        if service.is_null() {
                                            current_block = 16896850163988546332;
                                        } else if strlen(service)
                                            < 1 as libc::c_int as libc::c_ulong
                                        {
                                            Curl_infof(
                                                data,
                                                b"service can't be empty\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                            ret = CURLE_BAD_FUNCTION_ARGUMENT;
                                            current_block = 16896850163988546332;
                                        } else {
                                            current_block = 11052029508375673978;
                                        }
                                    } else {
                                        current_block = 11052029508375673978;
                                    }
                                }
                            }
                        } else {
                            current_block = 11052029508375673978;
                        }
                    }
                }
            } else {
                provider1_low = Curl_memdup(
                    provider0_low as *const libc::c_void,
                    len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                ) as *mut libc::c_char;
                provider1_mid = Curl_memdup(
                    provider0_low as *const libc::c_void,
                    len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                ) as *mut libc::c_char;
                if provider1_low.is_null() || provider1_mid.is_null() {
                    current_block = 16896850163988546332;
                } else {
                    *provider1_mid.offset(0 as libc::c_int as isize) =
                        Curl_raw_toupper(*provider1_mid.offset(0 as libc::c_int as isize));
                    current_block = 11052029508375673978;
                }
            }
            match current_block {
                16896850163988546332 => {}
                _ => {
                    if service.is_null() {
                        tmp0 = hostname;
                        tmp1 = strchr(tmp0, '.' as i32);
                        len = tmp1.offset_from(tmp0) as libc::c_long as size_t;
                        if tmp1.is_null() || len < 1 as libc::c_int as libc::c_ulong {
                            Curl_infof(
                                data,
                                b"service missing in parameters or hostname\0" as *const u8
                                    as *const libc::c_char,
                            );
                            ret = CURLE_URL_MALFORMAT;
                            current_block = 16896850163988546332;
                        } else {
                            service = Curl_memdup(
                                tmp0 as *const libc::c_void,
                                len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                            ) as *mut libc::c_char;
                            if service.is_null() {
                                current_block = 16896850163988546332;
                            } else {
                                *service.offset(len as isize) = '\0' as i32 as libc::c_char;
                                if region.is_null() {
                                    tmp0 = tmp1.offset(1 as libc::c_int as isize);
                                    tmp1 = strchr(tmp0, '.' as i32);
                                    len = tmp1.offset_from(tmp0) as libc::c_long as size_t;
                                    if tmp1.is_null() || len < 1 as libc::c_int as libc::c_ulong {
                                        Curl_infof(
                                            data,
                                            b"region missing in parameters or hostname\0"
                                                as *const u8
                                                as *const libc::c_char,
                                        );
                                        ret = CURLE_URL_MALFORMAT;
                                        current_block = 16896850163988546332;
                                    } else {
                                        region = Curl_memdup(
                                            tmp0 as *const libc::c_void,
                                            len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                                        )
                                            as *mut libc::c_char;
                                        if region.is_null() {
                                            current_block = 16896850163988546332;
                                        } else {
                                            *region.offset(len as isize) =
                                                '\0' as i32 as libc::c_char;
                                            current_block = 6040267449472925966;
                                        }
                                    }
                                } else {
                                    current_block = 6040267449472925966;
                                }
                            }
                        }
                    } else {
                        current_block = 6040267449472925966;
                    }
                    match current_block {
                        16896850163988546332 => {}
                        _ => {
                            #[cfg(CURLDEBUG)]
                            force_timestamp =
                                getenv(b"CURL_FORCETIME\0" as *const u8 as *const libc::c_char);
                            #[cfg(CURLDEBUG)]
                            if !force_timestamp.is_null() {
                                clock = 0 as libc::c_int as time_t;
                            } else {
                                time(&mut clock);
                            }
                            #[cfg(not(CURLDEBUG))]
                            time(&mut clock);
                            ret = Curl_gmtime(clock, &mut tm);
                            if !(ret as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint) {
                                if !(strftime(
                                    timestamp.as_mut_ptr(),
                                    ::std::mem::size_of::<[libc::c_char; 17]>() as libc::c_ulong,
                                    b"%Y%m%dT%H%M%SZ\0" as *const u8 as *const libc::c_char,
                                    &mut tm,
                                ) == 0)
                                {
                                    memcpy(
                                        date.as_mut_ptr() as *mut libc::c_void,
                                        timestamp.as_mut_ptr() as *const libc::c_void,
                                        ::std::mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong,
                                    );
                                    date[(::std::mem::size_of::<[libc::c_char; 9]>()
                                        as libc::c_ulong)
                                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                        as usize] = 0 as libc::c_int as libc::c_char;
                                    if !content_type.is_null() {
                                        content_type = strchr(content_type, ':' as i32);
                                        if content_type.is_null() {
                                            ret = CURLE_FAILED_INIT;
                                            current_block = 16896850163988546332;
                                        } else {
                                            content_type = content_type.offset(1);
                                            while *content_type as libc::c_int == ' ' as i32
                                                || *content_type as libc::c_int == '\t' as i32
                                            {
                                                content_type = content_type.offset(1);
                                            }
                                            canonical_headers = curl_maprintf(
                                                b"content-type:%s\nhost:%s\nx-%s-date:%s\n\0"
                                                    as *const u8
                                                    as *const libc::c_char,
                                                content_type,
                                                hostname,
                                                provider1_low,
                                                timestamp.as_mut_ptr(),
                                            );
                                            signed_headers = curl_maprintf(
                                                b"content-type;host;x-%s-date\0" as *const u8
                                                    as *const libc::c_char,
                                                provider1_low,
                                            );
                                            current_block = 5248622017361056354;
                                        }
                                    } else {
                                        canonical_headers = curl_maprintf(
                                            b"host:%s\nx-%s-date:%s\n\0" as *const u8
                                                as *const libc::c_char,
                                            hostname,
                                            provider1_low,
                                            timestamp.as_mut_ptr(),
                                        );
                                        signed_headers = curl_maprintf(
                                            b"host;x-%s-date\0" as *const u8 as *const libc::c_char,
                                            provider1_low,
                                        );
                                        current_block = 5248622017361056354;
                                    }
                                    match current_block {
                                        16896850163988546332 => {}
                                        _ => {
                                            if !(canonical_headers.is_null()
                                                || signed_headers.is_null())
                                            {
                                                Curl_sha256it(
                                                    sha_hash.as_mut_ptr(),
                                                    post_data as *const libc::c_uchar,
                                                    strlen(post_data),
                                                );
                                                sha256_to_hex(
                                                    sha_hex.as_mut_ptr(),
                                                    sha_hash.as_mut_ptr(),
                                                    ::std::mem::size_of::<[libc::c_char; 65]>()
                                                        as libc::c_ulong,
                                                );
                                                Curl_http_method(
                                                    data,
                                                    conn,
                                                    &mut method,
                                                    &mut httpreq,
                                                );
                                                canonical_request = curl_maprintf(
                                                    b"%s\n%s\n%s\n%s\n%s\n%s\0" as *const u8
                                                        as *const libc::c_char,
                                                    method,
                                                    (*data).state.up.path,
                                                    if !((*data).state.up.query).is_null() {
                                                        (*data).state.up.query
                                                            as *const libc::c_char
                                                    } else {
                                                        b"\0" as *const u8 as *const libc::c_char
                                                    },
                                                    canonical_headers,
                                                    signed_headers,
                                                    sha_hex.as_mut_ptr(),
                                                );
                                                if !canonical_request.is_null() {
                                                    request_type = curl_maprintf(
                                                        b"%s4_request\0" as *const u8
                                                            as *const libc::c_char,
                                                        provider0_low,
                                                    );
                                                    if !request_type.is_null() {
                                                        credential_scope = curl_maprintf(
                                                            b"%s/%s/%s/%s\0" as *const u8
                                                                as *const libc::c_char,
                                                            date.as_mut_ptr(),
                                                            region,
                                                            service,
                                                            request_type,
                                                        );
                                                        if !credential_scope.is_null() {
                                                            Curl_sha256it(
                                                                sha_hash.as_mut_ptr(),
                                                                canonical_request
                                                                    as *mut libc::c_uchar,
                                                                strlen(canonical_request),
                                                            );
                                                            sha256_to_hex(
                                                                sha_hex.as_mut_ptr(),
                                                                sha_hash.as_mut_ptr(),
                                                                ::std::mem::size_of::<
                                                                    [libc::c_char; 65],
                                                                >(
                                                                )
                                                                    as libc::c_ulong,
                                                            );
                                                            str_to_sign = curl_maprintf(
                                                                b"%s4-HMAC-SHA256\n%s\n%s\n%s\0"
                                                                    as *const u8
                                                                    as *const libc::c_char,
                                                                provider0_up,
                                                                timestamp.as_mut_ptr(),
                                                                credential_scope,
                                                                sha_hex.as_mut_ptr(),
                                                            );
                                                            if !str_to_sign.is_null() {
                                                                secret = curl_maprintf(
                                                                    b"%s4%s\0" as *const u8
                                                                        as *const libc::c_char,
                                                                    provider0_up,
                                                                    passwd,
                                                                );
                                                                if !secret.is_null() {
                                                                    ret = Curl_hmacit(
                                                                        Curl_HMAC_SHA256.as_ptr(),
                                                                        secret
                                                                            as *mut libc::c_uchar,
                                                                        strlen(secret)
                                                                            as libc::c_uint
                                                                            as size_t,
                                                                        date.as_mut_ptr()
                                                                            as *mut libc::c_uchar,
                                                                        strlen(date.as_mut_ptr())
                                                                            as libc::c_uint
                                                                            as size_t,
                                                                        tmp_sign0.as_mut_ptr(),
                                                                    );
                                                                    if !(ret as libc::c_uint
                                                                        != CURLE_OK as libc::c_int
                                                                            as libc::c_uint)
                                                                    {
                                                                        ret = Curl_hmacit(
                                                                            Curl_HMAC_SHA256.as_ptr(),
                                                                            tmp_sign0.as_mut_ptr(),
                                                                            ::std::mem::size_of::<[libc::c_uchar; 32]>()
                                                                                as libc::c_ulong as libc::c_uint as size_t,
                                                                            region as *mut libc::c_uchar,
                                                                            strlen(region) as libc::c_uint as size_t,
                                                                            tmp_sign1.as_mut_ptr(),
                                                                        );
                                                                        if !(ret as libc::c_uint
                                                                            != CURLE_OK
                                                                                as libc::c_int
                                                                                as libc::c_uint)
                                                                        {
                                                                            ret = Curl_hmacit(
                                                                                Curl_HMAC_SHA256.as_ptr(),
                                                                                tmp_sign1.as_mut_ptr(),
                                                                                ::std::mem::size_of::<[libc::c_uchar; 32]>()
                                                                                    as libc::c_ulong as libc::c_uint as size_t,
                                                                                service as *mut libc::c_uchar,
                                                                                strlen(service) as libc::c_uint as size_t,
                                                                                tmp_sign0.as_mut_ptr(),
                                                                            );
                                                                            if !(ret
                                                                                as libc::c_uint
                                                                                != CURLE_OK
                                                                                    as libc::c_int
                                                                                    as libc::c_uint)
                                                                            {
                                                                                ret = Curl_hmacit(
                                                                                    Curl_HMAC_SHA256.as_ptr(),
                                                                                    tmp_sign0.as_mut_ptr(),
                                                                                    ::std::mem::size_of::<[libc::c_uchar; 32]>()
                                                                                        as libc::c_ulong as libc::c_uint as size_t,
                                                                                    request_type as *mut libc::c_uchar,
                                                                                    strlen(request_type) as libc::c_uint as size_t,
                                                                                    tmp_sign1.as_mut_ptr(),
                                                                                );
                                                                                if !(ret as libc::c_uint
                                                                                    != CURLE_OK as libc::c_int as libc::c_uint)
                                                                                {
                                                                                    ret = Curl_hmacit(
                                                                                        Curl_HMAC_SHA256.as_ptr(),
                                                                                        tmp_sign1.as_mut_ptr(),
                                                                                        ::std::mem::size_of::<[libc::c_uchar; 32]>()
                                                                                            as libc::c_ulong as libc::c_uint as size_t,
                                                                                        str_to_sign as *mut libc::c_uchar,
                                                                                        strlen(str_to_sign) as libc::c_uint as size_t,
                                                                                        tmp_sign0.as_mut_ptr(),
                                                                                    );
                                                                                    if !(ret as libc::c_uint
                                                                                        != CURLE_OK as libc::c_int as libc::c_uint)
                                                                                    {
                                                                                        sha256_to_hex(
                                                                                            sha_hex.as_mut_ptr(),
                                                                                            tmp_sign0.as_mut_ptr(),
                                                                                            ::std::mem::size_of::<[libc::c_char; 65]>() as libc::c_ulong,
                                                                                        );
                                                                                        auth_headers = curl_maprintf(
                                                                                            b"Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s\r\nX-%s-Date: %s\r\n\0"
                                                                                                as *const u8 as *const libc::c_char,
                                                                                            provider0_up,
                                                                                            user,
                                                                                            credential_scope,
                                                                                            signed_headers,
                                                                                            sha_hex.as_mut_ptr(),
                                                                                            provider1_mid,
                                                                                            timestamp.as_mut_ptr(),
                                                                                        );
                                                                                        if !auth_headers.is_null() {
                                                                                            #[cfg(not(CURLDEBUG))]
                                                                                            Curl_cfree
                                                                                            .expect(
                                                                                                "non-null function pointer",
                                                                                            )((*data).state.aptr.userpwd as *mut libc::c_void);
                                                                                            #[cfg(CURLDEBUG)]
                                                                                            curl_dbg_free(
                                                                                                (*data).state.aptr.userpwd as *mut libc::c_void,
                                                                                                372 as libc::c_int,
                                                                                                b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
                                                                                            );
                                                                                            let ref mut fresh0 = (*data).state.aptr.userpwd;
                                                                                            *fresh0 = 0 as *mut libc::c_char;
                                                                                            let ref mut fresh1 = (*data).state.aptr.userpwd;
                                                                                            *fresh1 = auth_headers;
                                                                                            let ref mut fresh2 = (*data).state.authhost;
                                                                                            (*fresh2).set_done(1 as libc::c_int as bit);
                                                                                            ret = CURLE_OK;
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
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
    Curl_cfree.expect("non-null function pointer")(provider0_low as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(provider0_up as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(provider1_low as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(provider1_mid as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(region as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(service as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(canonical_headers as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(signed_headers as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(canonical_request as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(request_type as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(credential_scope as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(str_to_sign as *mut libc::c_void);
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(secret as *mut libc::c_void);
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        provider0_low as *mut libc::c_void,
        378 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        provider0_up as *mut libc::c_void,
        379 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        provider1_low as *mut libc::c_void,
        380 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        provider1_mid as *mut libc::c_void,
        381 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        region as *mut libc::c_void,
        382 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        service as *mut libc::c_void,
        383 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        canonical_headers as *mut libc::c_void,
        384 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        signed_headers as *mut libc::c_void,
        385 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        canonical_request as *mut libc::c_void,
        386 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        request_type as *mut libc::c_void,
        387 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        credential_scope as *mut libc::c_void,
        388 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        str_to_sign as *mut libc::c_void,
        389 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        secret as *mut libc::c_void,
        390 as libc::c_int,
        b"http_aws_sigv4.c\0" as *const u8 as *const libc::c_char,
    );
    return ret;
}
