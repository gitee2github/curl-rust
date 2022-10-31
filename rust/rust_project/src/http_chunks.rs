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
 * Description: http chunks
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

#[no_mangle]
pub unsafe extern "C" fn Curl_httpchunk_init(mut data: *mut Curl_easy) {
    let mut conn: *mut connectdata = (*data).conn;
    let mut chunk: *mut Curl_chunker = &mut (*conn).chunk;
    (*chunk).hexindex = 0 as libc::c_int as libc::c_uchar;
    (*chunk).state = CHUNK_HEX;
    Curl_dyn_init(&mut (*conn).trailer, 4096 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_httpchunk_read(
    mut data: *mut Curl_easy,
    mut datap: *mut libc::c_char,
    mut datalen: ssize_t,
    mut wrotep: *mut ssize_t,
    mut extrap: *mut CURLcode,
) -> CHUNKcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ch: *mut Curl_chunker = &mut (*conn).chunk;
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut piece: size_t = 0;
    let mut length: curl_off_t = datalen;
    let mut wrote: *mut size_t = wrotep as *mut size_t;
    *wrote = 0 as libc::c_int as size_t;
    if ((*data).set).http_te_skip() as libc::c_int != 0 && (*k).ignorebody() == 0 {
        result = Curl_client_write(
            data,
            (1 as libc::c_int) << 0 as libc::c_int,
            datap,
            datalen as size_t,
        );
        if result as u64 != 0 {
            *extrap = result;
            return CHUNKE_PASSTHRU_ERROR;
        }
    }
    while length != 0 {
        let mut current_block_101: u64;
        match (*ch).state as libc::c_uint {
            0 => {
                if Curl_isxdigit(*datap as libc::c_int) != 0 {
                    if ((*ch).hexindex as libc::c_int) < 8 as libc::c_int * 2 as libc::c_int {
                        (*ch).hexbuffer[(*ch).hexindex as usize] = *datap;
                        datap = datap.offset(1);
                        length -= 1;
                        let ref mut fresh0 = (*ch).hexindex;
                        *fresh0 = (*fresh0).wrapping_add(1);
                    } else {
                        return CHUNKE_TOO_LONG_HEX;
                    }
                } else {
                    let mut endptr: *mut libc::c_char = 0 as *mut libc::c_char;
                    if 0 as libc::c_int == (*ch).hexindex as libc::c_int {
                        return CHUNKE_ILLEGAL_HEX;
                    }
                    (*ch).hexbuffer[(*ch).hexindex as usize] = 0 as libc::c_int as libc::c_char;
                    result = CURLE_OK as libc::c_int as CURLcode;
                    if result as u64 != 0 {
                        return CHUNKE_ILLEGAL_HEX;
                    }
                    if curlx_strtoofft(
                        ((*ch).hexbuffer).as_mut_ptr(),
                        &mut endptr,
                        16 as libc::c_int,
                        &mut (*ch).datasize,
                    ) as u64
                        != 0
                    {
                        return CHUNKE_ILLEGAL_HEX;
                    }
                    (*ch).state = CHUNK_LF;
                }
            }
            1 => {
                if *datap as libc::c_int == 0xa as libc::c_int {
                    if 0 as libc::c_int as libc::c_long == (*ch).datasize {
                        (*ch).state = CHUNK_TRAILER;
                    } else {
                        (*ch).state = CHUNK_DATA;
                    }
                }
                datap = datap.offset(1);
                length -= 1;
            }
            2 => {
                piece = curlx_sotouz(if (*ch).datasize >= length {
                    length
                } else {
                    (*ch).datasize
                });
                if ((*data).set).http_te_skip() == 0 && (*k).ignorebody() == 0 {
                    if ((*data).set).http_ce_skip() == 0 && !((*k).writer_stack).is_null() {
                        result = Curl_unencode_write(data, (*k).writer_stack, datap, piece);
                    } else {
                        result = Curl_client_write(
                            data,
                            (1 as libc::c_int) << 0 as libc::c_int,
                            datap,
                            piece,
                        );
                    }
                    if result as u64 != 0 {
                        *extrap = result;
                        return CHUNKE_PASSTHRU_ERROR;
                    }
                }
                *wrote = (*wrote as libc::c_ulong).wrapping_add(piece) as size_t as size_t;
                let ref mut fresh1 = (*ch).datasize;
                *fresh1 =
                    (*fresh1 as libc::c_ulong).wrapping_sub(piece) as curl_off_t as curl_off_t;
                datap = datap.offset(piece as isize);
                length = (length as libc::c_ulong).wrapping_sub(piece) as curl_off_t as curl_off_t;
                if 0 as libc::c_int as libc::c_long == (*ch).datasize {
                    (*ch).state = CHUNK_POSTLF;
                }
            }
            3 => {
                if *datap as libc::c_int == 0xa as libc::c_int {
                    Curl_httpchunk_init(data);
                } else if *datap as libc::c_int != 0xd as libc::c_int {
                    return CHUNKE_BAD_CHUNK;
                }
                datap = datap.offset(1);
                length -= 1;
            }
            5 => {
                if *datap as libc::c_int == 0xd as libc::c_int
                    || *datap as libc::c_int == 0xa as libc::c_int
                {
                    let mut tr: *mut libc::c_char = Curl_dyn_ptr(&mut (*conn).trailer);
                    if !tr.is_null() {
                        let mut trlen: size_t = 0;
                        result = Curl_dyn_add(
                            &mut (*conn).trailer,
                            b"\r\n\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                        );
                        if result as u64 != 0 {
                            return CHUNKE_OUT_OF_MEMORY;
                        }
                        tr = Curl_dyn_ptr(&mut (*conn).trailer);
                        trlen = Curl_dyn_len(&mut (*conn).trailer);
                        result = CURLE_OK as libc::c_int as CURLcode;
                        if result as u64 != 0 {
                            return CHUNKE_BAD_CHUNK;
                        }
                        if ((*data).set).http_te_skip() == 0 {
                            result = Curl_client_write(
                                data,
                                (1 as libc::c_int) << 1 as libc::c_int,
                                tr,
                                trlen,
                            );
                            if result as u64 != 0 {
                                *extrap = result;
                                return CHUNKE_PASSTHRU_ERROR;
                            }
                        }
                        Curl_dyn_reset(&mut (*conn).trailer);
                        (*ch).state = CHUNK_TRAILER_CR;
                        if *datap as libc::c_int == 0xa as libc::c_int {
                            current_block_101 = 15586796709793571329;
                        } else {
                            current_block_101 = 14329534724295951598;
                        }
                    } else {
                        (*ch).state = CHUNK_TRAILER_POSTCR;
                        current_block_101 = 15586796709793571329;
                    }
                } else {
                    result = Curl_dyn_addn(
                        &mut (*conn).trailer,
                        datap as *const libc::c_void,
                        1 as libc::c_int as size_t,
                    );
                    if result as u64 != 0 {
                        return CHUNKE_OUT_OF_MEMORY;
                    }
                    current_block_101 = 14329534724295951598;
                }
                match current_block_101 {
                    15586796709793571329 => {}
                    _ => {
                        datap = datap.offset(1);
                        length -= 1;
                    }
                }
            }
            6 => {
                if *datap as libc::c_int == 0xa as libc::c_int {
                    (*ch).state = CHUNK_TRAILER_POSTCR;
                    datap = datap.offset(1);
                    length -= 1;
                } else {
                    return CHUNKE_BAD_CHUNK;
                }
            }
            7 => {
                if *datap as libc::c_int != 0xd as libc::c_int
                    && *datap as libc::c_int != 0xa as libc::c_int
                {
                    (*ch).state = CHUNK_TRAILER;
                } else {
                    if *datap as libc::c_int == 0xd as libc::c_int {
                        datap = datap.offset(1);
                        length -= 1;
                    }
                    (*ch).state = CHUNK_STOP;
                }
            }
            4 => {
                if *datap as libc::c_int == 0xa as libc::c_int {
                    length -= 1;
                    (*ch).datasize = curlx_sotouz(length) as curl_off_t;
                    return CHUNKE_STOP;
                } else {
                    return CHUNKE_BAD_CHUNK;
                }
            }
            _ => {}
        }
    }
    return CHUNKE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_chunked_strerror(mut code: CHUNKcode) -> *const libc::c_char {
    match code as libc::c_int {
        1 => return b"Too long hexadecimal number\0" as *const u8 as *const libc::c_char,
        2 => {
            return b"Illegal or missing hexadecimal sequence\0" as *const u8
                as *const libc::c_char;
        }
        3 => return b"Malformed encoding found\0" as *const u8 as *const libc::c_char,
        6 => return b"\0" as *const u8 as *const libc::c_char,
        4 => return b"Bad content-encoding found\0" as *const u8 as *const libc::c_char,
        5 => return b"Out of memory\0" as *const u8 as *const libc::c_char,
        _ => return b"OK\0" as *const u8 as *const libc::c_char,
    };
}
