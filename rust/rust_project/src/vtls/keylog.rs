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

const FOPEN_APPENDTEXT: *const libc::c_char = b"a\0" as *const u8 as *const libc::c_char;
const _IOLBF: i32 = 1;
const _IONBF: i32 = 2;

const KEYLOG_LABEL_MAXLEN: u64 =
    (::std::mem::size_of::<[libc::c_char; 32]>() as u64).wrapping_sub(1 as u64);

const CLIENT_RANDOM_SIZE: u64 = 32;

/*
 * The master secret in TLS 1.2 and before is always 48 bytes. In TLS 1.3, the
 * secret size depends on the cipher suite's hash function which is 32 bytes
 * for SHA-256 and 48 bytes for SHA-384.
 */
const SECRET_MAXLEN: u64 = 48;

/* The fp for the open SSLKEYLOGFILE, or NULL if not open */
static mut keylog_file_fp: *mut FILE = 0 as *const FILE as *mut FILE;

#[no_mangle]
pub extern "C" fn Curl_tls_keylog_open() {
    let mut keylog_file_name: *mut libc::c_char = 0 as *mut libc::c_char;

    if unsafe { keylog_file_fp.is_null() } {
        keylog_file_name =
            unsafe { curl_getenv(b"SSLKEYLOGFILE\0" as *const u8 as *const libc::c_char) };
        if !keylog_file_name.is_null() {
            match () {
                #[cfg(not(CURLDEBUG))]
                _ => unsafe {
                    keylog_file_fp = fopen(keylog_file_name, FOPEN_APPENDTEXT);
                },
                #[cfg(CURLDEBUG)]
                _ => unsafe {
                    keylog_file_fp = curl_dbg_fopen(
                        keylog_file_name,
                        b"a\0" as *const u8 as *const libc::c_char,
                        53 as i32,
                        b"vtls/keylog.c\0" as *const u8 as *const libc::c_char,
                    );
                },
            }
            if unsafe { !keylog_file_fp.is_null() } {
                #[cfg(WIN32)]
                let flag: bool = unsafe {
                    setvbuf(keylog_file_fp, 0 as *mut libc::c_char, _IONBF, 0 as size_t) != 0
                };
                #[cfg(not(WIN32))]
                let flag: bool = unsafe {
                    setvbuf(
                        keylog_file_fp,
                        0 as *mut libc::c_char,
                        _IOLBF,
                        4096 as size_t,
                    ) != 0
                };
                if flag {
                    #[cfg(not(CURLDEBUG))]
                    unsafe {
                        fclose(keylog_file_fp);
                    }
                    #[cfg(CURLDEBUG)]
                    unsafe {
                        curl_dbg_fclose(
                            keylog_file_fp,
                            61,
                            b"vtls/keylog.c\0" as *const u8 as *const libc::c_char,
                        );
                        keylog_file_fp = 0 as *mut FILE;
                    }
                }
            }
            unsafe {
                #[cfg(not(CURLDEBUG))]
                Curl_cfree.expect("non-null function pointer")(
                    keylog_file_name as *mut libc::c_void,
                );
                #[cfg(CURLDEBUG)]
                curl_dbg_free(
                    keylog_file_name as *mut libc::c_void,
                    65,
                    b"vtls/keylog.c\0" as *const u8 as *const libc::c_char,
                );
            }
            keylog_file_name = 0 as *mut libc::c_char;
        }
    }
}

#[no_mangle]
pub extern "C" fn Curl_tls_keylog_close() {
    if unsafe { !keylog_file_fp.is_null() } {
        unsafe {
            #[cfg(not(CURLDEBUG))]
            fclose(keylog_file_fp);
            #[cfg(CURLDEBUG)]
            curl_dbg_fclose(
                keylog_file_fp,
                74,
                b"vtls/keylog.c\0" as *const u8 as *const libc::c_char,
            );

            keylog_file_fp = 0 as *mut FILE;
        }
    }
    if unsafe { !keylog_file_fp.is_null() } {
        unsafe {
            #[cfg(not(CURLDEBUG))]
            fclose(keylog_file_fp);
            #[cfg(CURLDEBUG)]
            curl_dbg_fclose(
                keylog_file_fp,
                74,
                b"vtls/keylog.c\0" as *const u8 as *const libc::c_char,
            );
            keylog_file_fp = 0 as *mut FILE;
        }
    }
}

#[no_mangle]
pub extern "C" fn Curl_tls_keylog_enabled() -> bool {
    unsafe {
        return !keylog_file_fp.is_null();
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] 
pub extern "C" fn Curl_tls_keylog_write_line(mut line: *const libc::c_char) -> bool {
    /* The current maximum valid keylog line length LF and NUL is 195. */
    let mut linelen: size_t = 0;
    let mut buf: [libc::c_char; 256] = [0; 256];

    if unsafe { keylog_file_fp.is_null() || line.is_null() } {
        return false;
    }

    linelen = unsafe { strlen(line) };
    if linelen == 0
        || linelen > (::std::mem::size_of::<[libc::c_char; 256]>() as u64).wrapping_sub(2)
    {
        /* Empty line or too big to fit in a LF and NUL. */
        return false;
    }

    unsafe {
        memcpy(
            buf.as_mut_ptr() as *mut libc::c_void,
            line as *const libc::c_void,
            linelen,
        );
    }
    if unsafe { *line.offset(linelen.wrapping_sub(1) as isize) as i32 != '\n' as i32 } {
        buf[linelen as usize] = '\n' as i32 as libc::c_char;
        linelen = linelen.wrapping_add(1);
    }
    buf[linelen as usize] = '\0' as i32 as libc::c_char;

    /* Using fputs here instead of fprintf since libcurl's fprintf replacement
    may not be thread-safe. */
    unsafe { fputs(buf.as_mut_ptr(), keylog_file_fp) };
    return true;
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] 
pub extern "C" fn Curl_tls_keylog_write(
    mut label: *const libc::c_char,
    mut client_random: *const u8,
    mut secret: *const u8,
    mut secretlen: size_t,
) -> bool {
    let mut hex: *const libc::c_char = b"0123456789ABCDEF\0" as *const u8 as *const libc::c_char;
    let mut pos: size_t = 0;
    let mut i: size_t = 0;
    let mut line: [libc::c_char;
        (KEYLOG_LABEL_MAXLEN + 1 + 2 * CLIENT_RANDOM_SIZE + 1 + 2 * SECRET_MAXLEN + 1 + 1)
            as usize] =
        [0; (KEYLOG_LABEL_MAXLEN + 1 + 2 * CLIENT_RANDOM_SIZE + 1 + 2 * SECRET_MAXLEN + 1 + 1)
            as usize];

    if unsafe { keylog_file_fp.is_null() } {
        return false;
    }

    pos = unsafe { strlen(label) };
    if pos > KEYLOG_LABEL_MAXLEN || secretlen == 0 || secretlen > 48 {
        /* Should never happen - sanity check anyway. */
        return false;
    }

    unsafe {
        memcpy(
            line.as_mut_ptr() as *mut libc::c_void,
            label as *const libc::c_void,
            pos,
        );
    }
    line[pos as usize] = ' ' as i32 as libc::c_char;
    pos = pos.wrapping_add(1);

    /* Client Random */
    i = 0 as size_t;
    while i < CLIENT_RANDOM_SIZE {
        line[pos as usize] =
            unsafe { *hex.offset((*client_random.offset(i as isize) >> 4) as isize) };
        pos = pos.wrapping_add(1);

        line[pos as usize] = unsafe {
            *hex.offset((*client_random.offset(i as isize) as i32 & 0xf as i32) as isize)
        };
        pos = pos.wrapping_add(1);

        i = i.wrapping_add(1);
    }
    line[pos as usize] = ' ' as i32 as libc::c_char;
    pos = pos.wrapping_add(1);

    /* Secret */
    i = 0 as size_t;
    while i < secretlen {
        line[pos as usize] =
            unsafe { *hex.offset((*secret.offset(i as isize) as i32 >> 4 as i32) as isize) };
        pos = pos.wrapping_add(1);
        line[pos as usize] =
            unsafe { *hex.offset((*secret.offset(i as isize) as i32 & 0xf as i32) as isize) };
        pos = pos.wrapping_add(1);
        i = i.wrapping_add(1);
    }
    line[pos as usize] = '\n' as i32 as libc::c_char;
    pos = pos.wrapping_add(1);
    line[pos as usize] = '\0' as i32 as libc::c_char;

    /* Using fputs here instead of fprintf since libcurl's fprintf replacement
    may not be thread-safe. */
    unsafe {
        fputs(line.as_mut_ptr(), keylog_file_fp);
    }
    return true;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keylog() {
        Curl_tls_keylog_open();
        Curl_tls_keylog_write_line(b"0123456789ABCDEF\0" as *const u8 as *const libc::c_char);
        assert_eq!(Curl_tls_keylog_enabled(), true);
        Curl_tls_keylog_close();
    }
}
