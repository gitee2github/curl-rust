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
 * Description: about keylog
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

static mut keylog_file_fp: *mut FILE = 0 as *const FILE as *mut FILE;
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_open() {
    let mut keylog_file_name: *mut libc::c_char = 0 as *mut libc::c_char;
    if keylog_file_fp.is_null() {
        keylog_file_name = curl_getenv(b"SSLKEYLOGFILE\0" as *const u8 as *const libc::c_char);
        if !keylog_file_name.is_null() {
            match () {
                #[cfg(not(CURLDEBUG))]
                _ => {
                    keylog_file_fp =
                        fopen(keylog_file_name, b"a\0" as *const u8 as *const libc::c_char);
                }
                #[cfg(CURLDEBUG)]
                _ => {
                    keylog_file_fp = curl_dbg_fopen(
                        keylog_file_name,
                        b"a\0" as *const u8 as *const libc::c_char,
                        53 as libc::c_int,
                        b"vtls/keylog.c\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if !keylog_file_fp.is_null() {
                #[cfg(WIN32)]
                let flag: bool = setvbuf(
                    keylog_file_fp,
                    0 as *mut libc::c_char,
                    1 as libc::c_int,
                    0 as libc::c_int as size_t,
                ) != 0;
                #[cfg(not(WIN32))]
                let flag: bool = setvbuf(
                    keylog_file_fp,
                    0 as *mut libc::c_char,
                    1 as libc::c_int,
                    4096 as libc::c_int as size_t,
                ) != 0;
                if flag {
                    #[cfg(not(CURLDEBUG))]
                    fclose(keylog_file_fp);
                    #[cfg(CURLDEBUG)]
                    curl_dbg_fclose(
                        keylog_file_fp,
                        61 as libc::c_int,
                        b"vtls/keylog.c\0" as *const u8 as *const libc::c_char,
                    );
                    keylog_file_fp = 0 as *mut FILE;
                }
            }
            #[cfg(not(CURLDEBUG))]
            Curl_cfree.expect("non-null function pointer")(keylog_file_name as *mut libc::c_void);
            #[cfg(CURLDEBUG)]
            curl_dbg_free(
                keylog_file_name as *mut libc::c_void,
                65 as libc::c_int,
                b"vtls/keylog.c\0" as *const u8 as *const libc::c_char,
            );
            keylog_file_name = 0 as *mut libc::c_char;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_close() {
    if !keylog_file_fp.is_null() {
        #[cfg(not(CURLDEBUG))]
        fclose(keylog_file_fp);
        #[cfg(CURLDEBUG)]
        curl_dbg_fclose(
            keylog_file_fp,
            74 as libc::c_int,
            b"vtls/keylog.c\0" as *const u8 as *const libc::c_char,
        );
        keylog_file_fp = 0 as *mut FILE;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_enabled() -> bool {
    return !keylog_file_fp.is_null();
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_write_line(mut line: *const libc::c_char) -> bool {
    let mut linelen: size_t = 0;
    let mut buf: [libc::c_char; 256] = [0; 256];
    if keylog_file_fp.is_null() || line.is_null() {
        return 0 as libc::c_int != 0;
    }
    linelen = strlen(line);
    if linelen == 0 as libc::c_int as libc::c_ulong
        || linelen
            > (::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                .wrapping_sub(2 as libc::c_int as libc::c_ulong)
    {
        return 0 as libc::c_int != 0;
    }
    memcpy(
        buf.as_mut_ptr() as *mut libc::c_void,
        line as *const libc::c_void,
        linelen,
    );
    if *line.offset(linelen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize) as libc::c_int
        != '\n' as i32
    {
        let fresh0 = linelen;
        linelen = linelen.wrapping_add(1);
        buf[fresh0 as usize] = '\n' as i32 as libc::c_char;
    }
    buf[linelen as usize] = '\0' as i32 as libc::c_char;
    fputs(buf.as_mut_ptr(), keylog_file_fp);
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_write(
    mut label: *const libc::c_char,
    mut client_random: *const libc::c_uchar,
    mut secret: *const libc::c_uchar,
    mut secretlen: size_t,
) -> bool {
    let mut hex: *const libc::c_char = b"0123456789ABCDEF\0" as *const u8 as *const libc::c_char;
    let mut pos: size_t = 0;
    let mut i: size_t = 0;
    let mut line: [libc::c_char; 195] = [0; 195];
    if keylog_file_fp.is_null() {
        return 0 as libc::c_int != 0;
    }
    pos = strlen(label);
    if pos
        > (::std::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        || secretlen == 0
        || secretlen > 48 as libc::c_int as libc::c_ulong
    {
        return 0 as libc::c_int != 0;
    }
    memcpy(
        line.as_mut_ptr() as *mut libc::c_void,
        label as *const libc::c_void,
        pos,
    );
    let fresh1 = pos;
    pos = pos.wrapping_add(1);
    line[fresh1 as usize] = ' ' as i32 as libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i < 32 as libc::c_int as libc::c_ulong {
        let fresh2 = pos;
        pos = pos.wrapping_add(1);
        line[fresh2 as usize] = *hex.offset(
            (*client_random.offset(i as isize) as libc::c_int >> 4 as libc::c_int) as isize,
        );
        let fresh3 = pos;
        pos = pos.wrapping_add(1);
        line[fresh3 as usize] = *hex.offset(
            (*client_random.offset(i as isize) as libc::c_int & 0xf as libc::c_int) as isize,
        );
        i = i.wrapping_add(1);
    }
    let fresh4 = pos;
    pos = pos.wrapping_add(1);
    line[fresh4 as usize] = ' ' as i32 as libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i < secretlen {
        let fresh5 = pos;
        pos = pos.wrapping_add(1);
        line[fresh5 as usize] =
            *hex.offset((*secret.offset(i as isize) as libc::c_int >> 4 as libc::c_int) as isize);
        let fresh6 = pos;
        pos = pos.wrapping_add(1);
        line[fresh6 as usize] =
            *hex.offset((*secret.offset(i as isize) as libc::c_int & 0xf as libc::c_int) as isize);
        i = i.wrapping_add(1);
    }
    let fresh7 = pos;
    pos = pos.wrapping_add(1);
    line[fresh7 as usize] = '\n' as i32 as libc::c_char;
    line[pos as usize] = '\0' as i32 as libc::c_char;
    fputs(line.as_mut_ptr(), keylog_file_fp);
    return 1 as libc::c_int != 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keylog() {
        unsafe {
            Curl_tls_keylog_open();
            Curl_tls_keylog_write_line(b"0123456789ABCDEF\0" as *const u8 as *const libc::c_char);
            assert_eq!(Curl_tls_keylog_enabled(), true);
            Curl_tls_keylog_close();
        }
    }
}
