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
 * Author: pnext<pnext@mail.ustc.edu.cn>, 
 * Create: 2022-10-31
 * Description: ftplistparser
 ******************************************************************************/
 use ::libc;
 use rust_ffi::src::ffi_alias::type_alias::*;
 use rust_ffi::src::ffi_fun::fun_call::*;
 use rust_ffi::src::ffi_struct::struct_define::*;
 // use crate::src::ftp::*;
 
 // TODO
 // 有2个enum，2个union，1个struct在ftplistparser.c中定义的，要保留在这个文件中
 
 #[no_mangle]
 pub unsafe extern "C" fn Curl_ftp_parselist_data_alloc() -> *mut ftp_parselist_data {
     #[cfg(not(CURLDEBUG))]
     return Curl_ccalloc.expect("non-null function pointer")(
         1 as libc::c_int as size_t,
         ::std::mem::size_of::<ftp_parselist_data>() as libc::c_ulong,
     ) as *mut ftp_parselist_data;
     #[cfg(CURLDEBUG)]
     return curl_dbg_calloc(
         1 as libc::c_int as size_t,
         ::std::mem::size_of::<ftp_parselist_data>() as libc::c_ulong,
         184 as libc::c_int,
         b"ftplistparser.c\0" as *const u8 as *const libc::c_char,
     ) as *mut ftp_parselist_data;
 }
 #[no_mangle]
 pub unsafe extern "C" fn Curl_ftp_parselist_data_free(mut parserp: *mut *mut ftp_parselist_data) {
     let mut parser: *mut ftp_parselist_data = *parserp;
     if !parser.is_null() {
         Curl_fileinfo_cleanup((*parser).file_data);
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(parser as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         parser as *mut libc::c_void,
         193 as libc::c_int,
         b"ftplistparser.c\0" as *const u8 as *const libc::c_char,
     );
     *parserp = 0 as *mut ftp_parselist_data;
 }
 #[no_mangle]
 pub unsafe extern "C" fn Curl_ftp_parselist_geterror(
     mut pl_data: *mut ftp_parselist_data,
 ) -> CURLcode {
     return (*pl_data).error;
 }
 unsafe extern "C" fn ftp_pl_get_permission(mut str: *const libc::c_char) -> libc::c_int {
     let mut permissions: libc::c_int = 0 as libc::c_int;
     if *str.offset(0 as libc::c_int as isize) as libc::c_int == 'r' as i32 {
         permissions |= (1 as libc::c_int) << 8 as libc::c_int;
     } else if *str.offset(0 as libc::c_int as isize) as libc::c_int != '-' as i32 {
         permissions |= 0x1000000 as libc::c_int;
     }
     if *str.offset(1 as libc::c_int as isize) as libc::c_int == 'w' as i32 {
         permissions |= (1 as libc::c_int) << 7 as libc::c_int;
     } else if *str.offset(1 as libc::c_int as isize) as libc::c_int != '-' as i32 {
         permissions |= 0x1000000 as libc::c_int;
     }
     if *str.offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32 {
         permissions |= (1 as libc::c_int) << 6 as libc::c_int;
     } else if *str.offset(2 as libc::c_int as isize) as libc::c_int == 's' as i32 {
         permissions |= (1 as libc::c_int) << 6 as libc::c_int;
         permissions |= (1 as libc::c_int) << 11 as libc::c_int;
     } else if *str.offset(2 as libc::c_int as isize) as libc::c_int == 'S' as i32 {
         permissions |= (1 as libc::c_int) << 11 as libc::c_int;
     } else if *str.offset(2 as libc::c_int as isize) as libc::c_int != '-' as i32 {
         permissions |= 0x1000000 as libc::c_int;
     }
     if *str.offset(3 as libc::c_int as isize) as libc::c_int == 'r' as i32 {
         permissions |= (1 as libc::c_int) << 5 as libc::c_int;
     } else if *str.offset(3 as libc::c_int as isize) as libc::c_int != '-' as i32 {
         permissions |= 0x1000000 as libc::c_int;
     }
     if *str.offset(4 as libc::c_int as isize) as libc::c_int == 'w' as i32 {
         permissions |= (1 as libc::c_int) << 4 as libc::c_int;
     } else if *str.offset(4 as libc::c_int as isize) as libc::c_int != '-' as i32 {
         permissions |= 0x1000000 as libc::c_int;
     }
     if *str.offset(5 as libc::c_int as isize) as libc::c_int == 'x' as i32 {
         permissions |= (1 as libc::c_int) << 3 as libc::c_int;
     } else if *str.offset(5 as libc::c_int as isize) as libc::c_int == 's' as i32 {
         permissions |= (1 as libc::c_int) << 3 as libc::c_int;
         permissions |= (1 as libc::c_int) << 10 as libc::c_int;
     } else if *str.offset(5 as libc::c_int as isize) as libc::c_int == 'S' as i32 {
         permissions |= (1 as libc::c_int) << 10 as libc::c_int;
     } else if *str.offset(5 as libc::c_int as isize) as libc::c_int != '-' as i32 {
         permissions |= 0x1000000 as libc::c_int;
     }
     if *str.offset(6 as libc::c_int as isize) as libc::c_int == 'r' as i32 {
         permissions |= (1 as libc::c_int) << 2 as libc::c_int;
     } else if *str.offset(6 as libc::c_int as isize) as libc::c_int != '-' as i32 {
         permissions |= 0x1000000 as libc::c_int;
     }
     if *str.offset(7 as libc::c_int as isize) as libc::c_int == 'w' as i32 {
         permissions |= (1 as libc::c_int) << 1 as libc::c_int;
     } else if *str.offset(7 as libc::c_int as isize) as libc::c_int != '-' as i32 {
         permissions |= 0x1000000 as libc::c_int;
     }
     if *str.offset(8 as libc::c_int as isize) as libc::c_int == 'x' as i32 {
         permissions |= 1 as libc::c_int;
     } else if *str.offset(8 as libc::c_int as isize) as libc::c_int == 't' as i32 {
         permissions |= 1 as libc::c_int;
         permissions |= (1 as libc::c_int) << 9 as libc::c_int;
     } else if *str.offset(8 as libc::c_int as isize) as libc::c_int == 'T' as i32 {
         permissions |= (1 as libc::c_int) << 9 as libc::c_int;
     } else if *str.offset(8 as libc::c_int as isize) as libc::c_int != '-' as i32 {
         permissions |= 0x1000000 as libc::c_int;
     }
     return permissions;
 }
 unsafe extern "C" fn ftp_pl_insert_finfo(
     mut data: *mut Curl_easy,
     mut infop: *mut fileinfo,
 ) -> CURLcode {
     let mut compare: curl_fnmatch_callback = None;
     let mut wc: *mut WildcardData = &mut (*data).wildcard;
     let mut ftpwc: *mut ftp_wc = (*wc).protdata as *mut ftp_wc;
     let mut llist: *mut Curl_llist = &mut (*wc).filelist;
     let mut parser: *mut ftp_parselist_data = (*ftpwc).parser;
     let mut add: bool = 1 as libc::c_int != 0;
     let mut finfo: *mut curl_fileinfo = &mut (*infop).info;
     let mut str: *mut libc::c_char = (*finfo).b_data;
     let ref mut fresh0 = (*finfo).filename;
     *fresh0 = str.offset((*parser).offsets.filename as isize);
     let ref mut fresh1 = (*finfo).strings.group;
     *fresh1 = if (*parser).offsets.group != 0 {
         str.offset((*parser).offsets.group as isize)
     } else {
         0 as *mut libc::c_char
     };
     let ref mut fresh2 = (*finfo).strings.perm;
     *fresh2 = if (*parser).offsets.perm != 0 {
         str.offset((*parser).offsets.perm as isize)
     } else {
         0 as *mut libc::c_char
     };
     let ref mut fresh3 = (*finfo).strings.target;
     *fresh3 = if (*parser).offsets.symlink_target != 0 {
         str.offset((*parser).offsets.symlink_target as isize)
     } else {
         0 as *mut libc::c_char
     };
     let ref mut fresh4 = (*finfo).strings.time;
     *fresh4 = str.offset((*parser).offsets.time as isize);
     let ref mut fresh5 = (*finfo).strings.user;
     *fresh5 = if (*parser).offsets.user != 0 {
         str.offset((*parser).offsets.user as isize)
     } else {
         0 as *mut libc::c_char
     };
     compare = (*data).set.fnmatch;
     if compare.is_none() {
         compare = Some(
             Curl_fnmatch
                 as unsafe extern "C" fn(
                     *mut libc::c_void,
                     *const libc::c_char,
                     *const libc::c_char,
                 ) -> libc::c_int,
         );
     }
     Curl_set_in_callback(data, 1 as libc::c_int != 0);
     if compare.expect("non-null function pointer")(
         (*data).set.fnmatch_data,
         (*wc).pattern,
         (*finfo).filename,
     ) == 0 as libc::c_int
     {
         if (*finfo).filetype as libc::c_uint == CURLFILETYPE_SYMLINK as libc::c_int as libc::c_uint
             && !((*finfo).strings.target).is_null()
             && !(strstr(
                 (*finfo).strings.target,
                 b" -> \0" as *const u8 as *const libc::c_char,
             ))
                 .is_null()
         {
             add = 0 as libc::c_int != 0;
         }
     } else {
         add = 0 as libc::c_int != 0;
     }
     Curl_set_in_callback(data, 0 as libc::c_int != 0);
     if add {
         Curl_llist_insert_next(
             llist,
             (*llist).tail,
             finfo as *const libc::c_void,
             &mut (*infop).list,
         );
     } else {
         Curl_fileinfo_cleanup(infop);
     }
     let ref mut fresh6 = (*(*ftpwc).parser).file_data;
     *fresh6 = 0 as *mut fileinfo;
     return CURLE_OK;
 }
#[no_mangle]
pub unsafe extern "C" fn Curl_ftp_parselist(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
    mut nmemb: size_t,
    mut connptr: *mut libc::c_void,
) -> size_t {
    let mut bufflen: size_t = size.wrapping_mul(nmemb);
    let mut data: *mut Curl_easy = connptr as *mut Curl_easy;
    let mut ftpwc: *mut ftp_wc = (*data).wildcard.protdata as *mut ftp_wc;
    let mut parser: *mut ftp_parselist_data = (*ftpwc).parser;
    let mut infop: *mut fileinfo = 0 as *mut fileinfo;
    let mut finfo: *mut curl_fileinfo = 0 as *mut curl_fileinfo;
    let mut i: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    let mut result: CURLcode = CURLE_OK;
    let mut retsize: size_t = bufflen;

    'fail: loop {
        if (*parser).error as u64 != 0 {
            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
            break 'fail;
        }
        if (*parser).os_type as libc::c_uint
            == OS_TYPE_UNKNOWN as libc::c_int as libc::c_uint
            && bufflen > 0 as libc::c_int as libc::c_ulong
        {
            (*parser)
                .os_type = (if *buffer.offset(0 as libc::c_int as isize) as libc::c_int
                >= '0' as i32
                && *buffer.offset(0 as libc::c_int as isize) as libc::c_int <= '9' as i32
            {
                OS_TYPE_WIN_NT as libc::c_int
            } else {
                OS_TYPE_UNIX as libc::c_int
            }) as C2RustUnnamed_22;
        }
        while i < bufflen {
            let mut c: libc::c_char = *buffer.offset(i as isize);
            if ((*parser).file_data).is_null() {
                let ref mut fresh7 = (*parser).file_data;
                *fresh7 = Curl_fileinfo_alloc();
                if ((*parser).file_data).is_null() {
                    (*parser).error = CURLE_OUT_OF_MEMORY;
                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                    break 'fail;
                }
                match () {
                    #[cfg(not(CURLDEBUG))]
                    _ => {
                        (*(*parser).file_data).info.b_data = Curl_cmalloc
                        .expect("non-null function pointer")(160 as libc::c_int as size_t)
                        as *mut libc::c_char;
                    }
                    #[cfg(CURLDEBUG)]
                    _ => {
                        (*(*parser).file_data).info.b_data = curl_dbg_malloc(
                            160 as libc::c_int as size_t,
                            364 as libc::c_int,
                            b"ftplistparser.c\0" as *const u8 as *const libc::c_char,
                        ) as *mut libc::c_char;
                    }
                }
   
                if ((*(*parser).file_data).info.b_data).is_null() {
                    (*parser).error = CURLE_OUT_OF_MEMORY;
                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                    break 'fail;
                }
                (*(*parser).file_data).info.b_size = 160 as libc::c_int as size_t;
                (*parser).item_offset = 0 as libc::c_int as size_t;
                (*parser).item_length = 0 as libc::c_int as libc::c_uint;
            }
            infop = (*parser).file_data;
            finfo = &mut (*infop).info;
            let ref mut fresh9 = (*finfo).b_used;
            let fresh10 = *fresh9;
            *fresh9 = (*fresh9).wrapping_add(1);
            *((*finfo).b_data).offset(fresh10 as isize) = c;
            if (*finfo).b_used
                >= ((*finfo).b_size).wrapping_sub(1 as libc::c_int as libc::c_ulong)
            {
                #[cfg(not(CURLDEBUG))]
                let mut tmp: *mut libc::c_char = Curl_crealloc
                    .expect(
                        "non-null function pointer",
                    )(
                    (*finfo).b_data as *mut libc::c_void,
                    ((*finfo).b_size).wrapping_add(160 as libc::c_int as libc::c_ulong),
                ) as *mut libc::c_char;
                #[cfg(CURLDEBUG)]
                let mut tmp: *mut libc::c_char = curl_dbg_realloc(
                    (*finfo).b_data as *mut libc::c_void,
                    ((*finfo).b_size).wrapping_add(160 as libc::c_int as libc::c_ulong),
                    381 as libc::c_int,
                    b"ftplistparser.c\0" as *const u8 as *const libc::c_char,
                ) as *mut libc::c_char;
                if !tmp.is_null() {
                    let ref mut fresh11 = (*finfo).b_size;
                    *fresh11 = (*fresh11 as libc::c_ulong)
                        .wrapping_add(160 as libc::c_int as libc::c_ulong) as size_t
                        as size_t;
                    let ref mut fresh12 = (*finfo).b_data;
                    *fresh12 = tmp;
                } else {
                    Curl_fileinfo_cleanup((*parser).file_data);
                    let ref mut fresh13 = (*parser).file_data;
                    *fresh13 = 0 as *mut fileinfo;
                    (*parser).error = CURLE_OUT_OF_MEMORY;
                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                    break 'fail;
                }
            }
            match (*parser).os_type as libc::c_uint {
                1 => {
                    match (*parser).state.UNIX.main as libc::c_uint {
                        0 => {
                            match (*parser).state.UNIX.sub.total_dirsize as libc::c_uint {
                                0 => {
                                    if c as libc::c_int == 't' as i32 {
                                        (*parser)
                                            .state
                                            .UNIX
                                            .sub
                                            .total_dirsize = PL_UNIX_TOTALSIZE_READING;
                                        let ref mut fresh14 = (*parser).item_length;
                                        *fresh14 = (*fresh14).wrapping_add(1);
                                    } else {
                                        (*parser).state.UNIX.main = PL_UNIX_FILETYPE;
                                        (*finfo).b_used = 0 as libc::c_int as size_t;
                                        continue;
                                    }
                                }
                                1 => {
                                    let ref mut fresh15 = (*parser).item_length;
                                    *fresh15 = (*fresh15).wrapping_add(1);
                                    if c as libc::c_int == '\r' as i32 {
                                        let ref mut fresh16 = (*parser).item_length;
                                        *fresh16 = (*fresh16).wrapping_sub(1);
                                        let ref mut fresh17 = (*finfo).b_used;
                                        *fresh17 = (*fresh17).wrapping_sub(1);
                                    } else if c as libc::c_int == '\n' as i32 {
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_length)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        if strncmp(
                                            b"total \0" as *const u8 as *const libc::c_char,
                                            (*finfo).b_data,
                                            6 as libc::c_int as libc::c_ulong,
                                        ) == 0 as libc::c_int
                                        {
                                            let mut endptr: *mut libc::c_char = ((*finfo).b_data)
                                                .offset(6 as libc::c_int as isize);
                                            while Curl_isspace(*endptr as libc::c_uchar as libc::c_int)
                                                != 0
                                            {
                                                endptr = endptr.offset(1);
                                            }
                                            while Curl_isdigit(*endptr as libc::c_uchar as libc::c_int)
                                                != 0
                                            {
                                                endptr = endptr.offset(1);
                                            }
                                            if *endptr != 0 {
                                                (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                                // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                                break 'fail;
                                            }
                                            (*parser).state.UNIX.main = PL_UNIX_FILETYPE;
                                            (*finfo).b_used = 0 as libc::c_int as size_t;
                                        } else {
                                            (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        1 => {
                            match c as libc::c_int {
                                45 => {
                                    (*finfo).filetype = CURLFILETYPE_FILE;
                                }
                                100 => {
                                    (*finfo).filetype = CURLFILETYPE_DIRECTORY;
                                }
                                108 => {
                                    (*finfo).filetype = CURLFILETYPE_SYMLINK;
                                }
                                112 => {
                                    (*finfo).filetype = CURLFILETYPE_NAMEDPIPE;
                                }
                                115 => {
                                    (*finfo).filetype = CURLFILETYPE_SOCKET;
                                }
                                99 => {
                                    (*finfo).filetype = CURLFILETYPE_DEVICE_CHAR;
                                }
                                98 => {
                                    (*finfo).filetype = CURLFILETYPE_DEVICE_BLOCK;
                                }
                                68 => {
                                    (*finfo).filetype = CURLFILETYPE_DOOR;
                                }
                                _ => {
                                    (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                    break 'fail;
                                }
                            }
                            (*parser).state.UNIX.main = PL_UNIX_PERMISSION;
                            (*parser).item_length = 0 as libc::c_int as libc::c_uint;
                            (*parser).item_offset = 1 as libc::c_int as size_t;
                        }
                        2 => {
                            let ref mut fresh18 = (*parser).item_length;
                            *fresh18 = (*fresh18).wrapping_add(1);
                            if (*parser).item_length <= 9 as libc::c_int as libc::c_uint {
                                if (strchr(
                                    b"rwx-tTsS\0" as *const u8 as *const libc::c_char,
                                    c as libc::c_int,
                                ))
                                    .is_null()
                                {
                                    (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                    break 'fail;
                                }
                            } else if (*parser).item_length
                                    == 10 as libc::c_int as libc::c_uint
                                {
                                let mut perm: libc::c_uint = 0;
                                if c as libc::c_int != ' ' as i32 {
                                    (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                    break 'fail;
                                }
                                *((*finfo).b_data)
                                    .offset(
                                        10 as libc::c_int as isize,
                                    ) = 0 as libc::c_int as libc::c_char;
                                perm = ftp_pl_get_permission(
                                    ((*finfo).b_data).offset((*parser).item_offset as isize),
                                ) as libc::c_uint;
                                if perm & 0x1000000 as libc::c_int as libc::c_uint != 0 {
                                    (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                    break 'fail;
                                }
                                (*(*parser).file_data).info.flags
                                    |= ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint;
                                (*(*parser).file_data).info.perm = perm;
                                (*parser).offsets.perm = (*parser).item_offset;
                                (*parser).item_length = 0 as libc::c_int as libc::c_uint;
                                (*parser).state.UNIX.main = PL_UNIX_HLINKS;
                                (*parser).state.UNIX.sub.hlinks = PL_UNIX_HLINKS_PRESPACE;
                            }
                        }
                        3 => {
                            match (*parser).state.UNIX.sub.hlinks as libc::c_uint {
                                0 => {
                                    if c as libc::c_int != ' ' as i32 {
                                        if c as libc::c_int >= '0' as i32
                                            && c as libc::c_int <= '9' as i32
                                        {
                                            (*parser)
                                                .item_offset = ((*finfo).b_used)
                                                .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                            (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                            (*parser).state.UNIX.sub.hlinks = PL_UNIX_HLINKS_NUMBER;
                                        } else {
                                            (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                    }
                                }
                                1 => {
                                    let ref mut fresh19 = (*parser).item_length;
                                    *fresh19 = (*fresh19).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
                                        let mut hlinks: libc::c_long = 0;
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        hlinks = strtol(
                                            ((*finfo).b_data).offset((*parser).item_offset as isize),
                                            &mut p,
                                            10 as libc::c_int,
                                        );
                                        if *p.offset(0 as libc::c_int as isize) as libc::c_int
                                            == '\u{0}' as i32
                                            && hlinks != 9223372036854775807 as libc::c_long
                                            && hlinks
                                                != -(9223372036854775807 as libc::c_long)
                                                    - 1 as libc::c_long
                                        {
                                            (*(*parser).file_data).info.flags
                                                |= ((1 as libc::c_int) << 7 as libc::c_int) as libc::c_uint;
                                            (*(*parser).file_data).info.hardlinks = hlinks;
                                        }
                                        (*parser).item_length = 0 as libc::c_int as libc::c_uint;
                                        (*parser).item_offset = 0 as libc::c_int as size_t;
                                        (*parser).state.UNIX.main = PL_UNIX_USER;
                                        (*parser).state.UNIX.sub.user = PL_UNIX_USER_PRESPACE;
                                    } else if (c as libc::c_int) < '0' as i32
                                            || c as libc::c_int > '9' as i32
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                _ => {}
                            }
                        }
                        4 => {
                            match (*parser).state.UNIX.sub.user as libc::c_uint {
                                0 => {
                                    if c as libc::c_int != ' ' as i32 {
                                        (*parser)
                                            .item_offset = ((*finfo).b_used)
                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                        (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                        (*parser).state.UNIX.sub.user = PL_UNIX_USER_PARSING;
                                    }
                                }
                                1 => {
                                    let ref mut fresh20 = (*parser).item_length;
                                    *fresh20 = (*fresh20).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        (*parser).offsets.user = (*parser).item_offset;
                                        (*parser).state.UNIX.main = PL_UNIX_GROUP;
                                        (*parser).state.UNIX.sub.group = PL_UNIX_GROUP_PRESPACE;
                                        (*parser).item_offset = 0 as libc::c_int as size_t;
                                        (*parser).item_length = 0 as libc::c_int as libc::c_uint;
                                    }
                                }
                                _ => {}
                            }
                        }
                        5 => {
                            match (*parser).state.UNIX.sub.group as libc::c_uint {
                                0 => {
                                    if c as libc::c_int != ' ' as i32 {
                                        (*parser)
                                            .item_offset = ((*finfo).b_used)
                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                        (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                        (*parser).state.UNIX.sub.group = PL_UNIX_GROUP_NAME;
                                    }
                                }
                                1 => {
                                    let ref mut fresh21 = (*parser).item_length;
                                    *fresh21 = (*fresh21).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        (*parser).offsets.group = (*parser).item_offset;
                                        (*parser).state.UNIX.main = PL_UNIX_SIZE;
                                        (*parser).state.UNIX.sub.size = PL_UNIX_SIZE_PRESPACE;
                                        (*parser).item_offset = 0 as libc::c_int as size_t;
                                        (*parser).item_length = 0 as libc::c_int as libc::c_uint;
                                    }
                                }
                                _ => {}
                            }
                        }
                        6 => {
                            match (*parser).state.UNIX.sub.size as libc::c_uint {
                                0 => {
                                    if c as libc::c_int != ' ' as i32 {
                                        if c as libc::c_int >= '0' as i32
                                            && c as libc::c_int <= '9' as i32
                                        {
                                            (*parser)
                                                .item_offset = ((*finfo).b_used)
                                                .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                            (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                            (*parser).state.UNIX.sub.size = PL_UNIX_SIZE_NUMBER;
                                        } else {
                                            (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                    }
                                }
                                1 => {
                                    let ref mut fresh22 = (*parser).item_length;
                                    *fresh22 = (*fresh22).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        let mut p_0: *mut libc::c_char = 0 as *mut libc::c_char;
                                        let mut fsize: curl_off_t = 0;
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        if curlx_strtoofft(
                                            ((*finfo).b_data).offset((*parser).item_offset as isize),
                                            &mut p_0,
                                            10 as libc::c_int,
                                            &mut fsize,
                                        ) as u64 == 0
                                        {
                                            if *p_0.offset(0 as libc::c_int as isize) as libc::c_int
                                                == '\u{0}' as i32
                                                && fsize != 0x7fffffffffffffff as libc::c_long
                                                && fsize
                                                    != -(0x7fffffffffffffff as libc::c_long) - 1 as libc::c_long
                                            {
                                                (*(*parser).file_data).info.flags
                                                    |= ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                                                (*(*parser).file_data).info.size = fsize;
                                            }
                                            (*parser).item_length = 0 as libc::c_int as libc::c_uint;
                                            (*parser).item_offset = 0 as libc::c_int as size_t;
                                            (*parser).state.UNIX.main = PL_UNIX_TIME;
                                            (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PREPART1;
                                        }
                                    } else if Curl_isdigit(c as libc::c_uchar as libc::c_int)
                                            == 0
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                _ => {}
                            }
                        }
                        7 => {
                            match (*parser).state.UNIX.sub.time as libc::c_uint {
                                0 => {
                                    if c as libc::c_int != ' ' as i32 {
                                        if Curl_isalnum(c as libc::c_uchar as libc::c_int) != 0 {
                                            (*parser)
                                                .item_offset = ((*finfo).b_used)
                                                .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                            (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                            (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PART1;
                                        } else {
                                            (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                    }
                                }
                                1 => {
                                    let ref mut fresh23 = (*parser).item_length;
                                    *fresh23 = (*fresh23).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PREPART2;
                                    } else if Curl_isalnum(c as libc::c_uchar as libc::c_int)
                                            == 0 && c as libc::c_int != '.' as i32
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                2 => {
                                    let ref mut fresh24 = (*parser).item_length;
                                    *fresh24 = (*fresh24).wrapping_add(1);
                                    if c as libc::c_int != ' ' as i32 {
                                        if Curl_isalnum(c as libc::c_uchar as libc::c_int) != 0 {
                                            (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PART2;
                                        } else {
                                            (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                    }
                                }
                                3 => {
                                    let ref mut fresh25 = (*parser).item_length;
                                    *fresh25 = (*fresh25).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PREPART3;
                                    } else if Curl_isalnum(c as libc::c_uchar as libc::c_int)
                                            == 0 && c as libc::c_int != '.' as i32
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                4 => {
                                    let ref mut fresh26 = (*parser).item_length;
                                    *fresh26 = (*fresh26).wrapping_add(1);
                                    if c as libc::c_int != ' ' as i32 {
                                        if Curl_isalnum(c as libc::c_uchar as libc::c_int) != 0 {
                                            (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PART3;
                                        } else {
                                            (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                    }
                                }
                                5 => {
                                    let ref mut fresh27 = (*parser).item_length;
                                    *fresh27 = (*fresh27).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        (*parser).offsets.time = (*parser).item_offset;
                                        if (*finfo).filetype as libc::c_uint
                                            == CURLFILETYPE_SYMLINK as libc::c_int as libc::c_uint
                                        {
                                            (*parser).state.UNIX.main = PL_UNIX_SYMLINK;
                                            (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_PRESPACE;
                                        } else {
                                            (*parser).state.UNIX.main = PL_UNIX_FILENAME;
                                            (*parser)
                                                .state
                                                .UNIX
                                                .sub
                                                .filename = PL_UNIX_FILENAME_PRESPACE;
                                        }
                                    } else if Curl_isalnum(c as libc::c_uchar as libc::c_int)
                                            == 0 && c as libc::c_int != '.' as i32
                                            && c as libc::c_int != ':' as i32
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                _ => {}
                            }
                        }
                        8 => {
                            match (*parser).state.UNIX.sub.filename as libc::c_uint {
                                0 => {
                                    if c as libc::c_int != ' ' as i32 {
                                        (*parser)
                                            .item_offset = ((*finfo).b_used)
                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                        (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                        (*parser).state.UNIX.sub.filename = PL_UNIX_FILENAME_NAME;
                                    }
                                }
                                1 => {
                                    let ref mut fresh28 = (*parser).item_length;
                                    *fresh28 = (*fresh28).wrapping_add(1);
                                    if c as libc::c_int == '\r' as i32 {
                                        (*parser)
                                            .state
                                            .UNIX
                                            .sub
                                            .filename = PL_UNIX_FILENAME_WINDOWSEOL;
                                    } else if c as libc::c_int == '\n' as i32 {
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        (*parser).offsets.filename = (*parser).item_offset;
                                        (*parser).state.UNIX.main = PL_UNIX_FILETYPE;
                                        result = ftp_pl_insert_finfo(data, infop);
                                        if result as u64 != 0 {
                                            (*parser).error = result;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                    }
                                }
                                2 => {
                                    if c as libc::c_int == '\n' as i32 {
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        (*parser).offsets.filename = (*parser).item_offset;
                                        (*parser).state.UNIX.main = PL_UNIX_FILETYPE;
                                        result = ftp_pl_insert_finfo(data, infop);
                                        if result as u64 != 0 {
                                            (*parser).error = result;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                    } else {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                _ => {}
                            }
                        }
                        9 => {
                            match (*parser).state.UNIX.sub.symlink as libc::c_uint {
                                0 => {
                                    if c as libc::c_int != ' ' as i32 {
                                        (*parser)
                                            .item_offset = ((*finfo).b_used)
                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                        (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                        (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_NAME;
                                    }
                                }
                                1 => {
                                    let ref mut fresh29 = (*parser).item_length;
                                    *fresh29 = (*fresh29).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        (*parser)
                                            .state
                                            .UNIX
                                            .sub
                                            .symlink = PL_UNIX_SYMLINK_PRETARGET1;
                                    } else if c as libc::c_int == '\r' as i32
                                            || c as libc::c_int == '\n' as i32
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                2 => {
                                    let ref mut fresh30 = (*parser).item_length;
                                    *fresh30 = (*fresh30).wrapping_add(1);
                                    if c as libc::c_int == '-' as i32 {
                                        (*parser)
                                            .state
                                            .UNIX
                                            .sub
                                            .symlink = PL_UNIX_SYMLINK_PRETARGET2;
                                    } else if c as libc::c_int == '\r' as i32
                                            || c as libc::c_int == '\n' as i32
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    } else {
                                        (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_NAME;
                                    }
                                }
                                3 => {
                                    let ref mut fresh31 = (*parser).item_length;
                                    *fresh31 = (*fresh31).wrapping_add(1);
                                    if c as libc::c_int == '>' as i32 {
                                        (*parser)
                                            .state
                                            .UNIX
                                            .sub
                                            .symlink = PL_UNIX_SYMLINK_PRETARGET3;
                                    } else if c as libc::c_int == '\r' as i32
                                            || c as libc::c_int == '\n' as i32
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    } else {
                                        (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_NAME;
                                    }
                                }
                                4 => {
                                    let ref mut fresh32 = (*parser).item_length;
                                    *fresh32 = (*fresh32).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        (*parser)
                                            .state
                                            .UNIX
                                            .sub
                                            .symlink = PL_UNIX_SYMLINK_PRETARGET4;
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(4 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        (*parser).offsets.filename = (*parser).item_offset;
                                        (*parser).item_length = 0 as libc::c_int as libc::c_uint;
                                        (*parser).item_offset = 0 as libc::c_int as size_t;
                                    } else if c as libc::c_int == '\r' as i32
                                            || c as libc::c_int == '\n' as i32
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    } else {
                                        (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_NAME;
                                    }
                                }
                                5 => {
                                    if c as libc::c_int != '\r' as i32
                                        && c as libc::c_int != '\n' as i32
                                    {
                                        (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_TARGET;
                                        (*parser)
                                            .item_offset = ((*finfo).b_used)
                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                        (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                    } else {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                6 => {
                                    let ref mut fresh33 = (*parser).item_length;
                                    *fresh33 = (*fresh33).wrapping_add(1);
                                    if c as libc::c_int == '\r' as i32 {
                                        (*parser)
                                            .state
                                            .UNIX
                                            .sub
                                            .symlink = PL_UNIX_SYMLINK_WINDOWSEOL;
                                    } else if c as libc::c_int == '\n' as i32 {
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        (*parser).offsets.symlink_target = (*parser).item_offset;
                                        result = ftp_pl_insert_finfo(data, infop);
                                        if result as u64 != 0 {
                                            (*parser).error = result;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                        (*parser).state.UNIX.main = PL_UNIX_FILETYPE;
                                    }
                                }
                                7 => {
                                    if c as libc::c_int == '\n' as i32 {
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        (*parser).offsets.symlink_target = (*parser).item_offset;
                                        result = ftp_pl_insert_finfo(data, infop);
                                        if result as u64 != 0 {
                                            (*parser).error = result;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                        (*parser).state.UNIX.main = PL_UNIX_FILETYPE;
                                    } else {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                2 => {
                    match (*parser).state.NT.main as libc::c_uint {
                        0 => {
                            let ref mut fresh34 = (*parser).item_length;
                            *fresh34 = (*fresh34).wrapping_add(1);
                            if (*parser).item_length < 9 as libc::c_int as libc::c_uint {
                                if (strchr(
                                    b"0123456789-\0" as *const u8 as *const libc::c_char,
                                    c as libc::c_int,
                                ))
                                    .is_null()
                                {
                                    (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                    break 'fail;
                                }
                            } else if (*parser).item_length
                                    == 9 as libc::c_int as libc::c_uint
                                {
                                if c as libc::c_int == ' ' as i32 {
                                    (*parser).state.NT.main = PL_WINNT_TIME;
                                    (*parser).state.NT.sub.time = PL_WINNT_TIME_PRESPACE;
                                } else {
                                    (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                    break 'fail;
                                }
                            } else {
                                (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                break 'fail;
                            }
                        }
                        1 => {
                            let ref mut fresh35 = (*parser).item_length;
                            *fresh35 = (*fresh35).wrapping_add(1);
                            match (*parser).state.NT.sub.time as libc::c_uint {
                                0 => {
                                    if Curl_isspace(c as libc::c_uchar as libc::c_int) == 0 {
                                        (*parser).state.NT.sub.time = PL_WINNT_TIME_TIME;
                                    }
                                }
                                1 => {
                                    if c as libc::c_int == ' ' as i32 {
                                        (*parser).offsets.time = (*parser).item_offset;
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        (*parser).state.NT.main = PL_WINNT_DIRORSIZE;
                                        (*parser)
                                            .state
                                            .NT
                                            .sub
                                            .dirorsize = PL_WINNT_DIRORSIZE_PRESPACE;
                                        (*parser).item_length = 0 as libc::c_int as libc::c_uint;
                                    } else if (strchr(
                                            b"APM0123456789:\0" as *const u8 as *const libc::c_char,
                                            c as libc::c_int,
                                        ))
                                            .is_null()
                                        {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                _ => {}
                            }
                        }
                        2 => {
                            match (*parser).state.NT.sub.dirorsize as libc::c_uint {
                                0 => {
                                    if c as libc::c_int != ' ' as i32 {
                                        (*parser)
                                            .item_offset = ((*finfo).b_used)
                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                        (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                        (*parser)
                                            .state
                                            .NT
                                            .sub
                                            .dirorsize = PL_WINNT_DIRORSIZE_CONTENT;
                                    }
                                }
                                1 => {
                                    let ref mut fresh36 = (*parser).item_length;
                                    *fresh36 = (*fresh36).wrapping_add(1);
                                    if c as libc::c_int == ' ' as i32 {
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*parser).item_offset)
                                                    .wrapping_add((*parser).item_length as libc::c_ulong)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        if strcmp(
                                            b"<DIR>\0" as *const u8 as *const libc::c_char,
                                            ((*finfo).b_data).offset((*parser).item_offset as isize),
                                        ) == 0 as libc::c_int
                                        {
                                            (*finfo).filetype = CURLFILETYPE_DIRECTORY;
                                            (*finfo).size = 0 as libc::c_int as curl_off_t;
                                        } else {
                                            let mut endptr_0: *mut libc::c_char = 0
                                                as *mut libc::c_char;
                                            if curlx_strtoofft(
                                                ((*finfo).b_data).offset((*parser).item_offset as isize),
                                                &mut endptr_0,
                                                10 as libc::c_int,
                                                &mut (*finfo).size,
                                            ) as u64 != 0
                                            {
                                                (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                                // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                                break 'fail;
                                            }
                                            (*(*parser).file_data).info.filetype = CURLFILETYPE_FILE;
                                        }
                                        (*(*parser).file_data).info.flags
                                            |= ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                                        (*parser).item_length = 0 as libc::c_int as libc::c_uint;
                                        (*parser).state.NT.main = PL_WINNT_FILENAME;
                                        (*parser)
                                            .state
                                            .NT
                                            .sub
                                            .filename = PL_WINNT_FILENAME_PRESPACE;
                                    }
                                }
                                _ => {}
                            }
                        }
                        3 => {
                            match (*parser).state.NT.sub.filename as libc::c_uint {
                                0 => {
                                    if c as libc::c_int != ' ' as i32 {
                                        (*parser)
                                            .item_offset = ((*finfo).b_used)
                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                                        (*parser).item_length = 1 as libc::c_int as libc::c_uint;
                                        (*parser).state.NT.sub.filename = PL_WINNT_FILENAME_CONTENT;
                                    }
                                }
                                1 => {
                                    let ref mut fresh37 = (*parser).item_length;
                                    *fresh37 = (*fresh37).wrapping_add(1);
                                    if c as libc::c_int == '\r' as i32 {
                                        (*parser).state.NT.sub.filename = PL_WINNT_FILENAME_WINEOL;
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*finfo).b_used)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                    } else if c as libc::c_int == '\n' as i32 {
                                        (*parser).offsets.filename = (*parser).item_offset;
                                        *((*finfo).b_data)
                                            .offset(
                                                ((*finfo).b_used)
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                            ) = 0 as libc::c_int as libc::c_char;
                                        result = ftp_pl_insert_finfo(data, infop);
                                        if result as u64 != 0 {
                                            (*parser).error = result;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                        (*parser).state.NT.main = PL_WINNT_DATE;
                                        (*parser)
                                            .state
                                            .NT
                                            .sub
                                            .filename = PL_WINNT_FILENAME_PRESPACE;
                                    }
                                }
                                2 => {
                                    if c as libc::c_int == '\n' as i32 {
                                        (*parser).offsets.filename = (*parser).item_offset;
                                        result = ftp_pl_insert_finfo(data, infop);
                                        if result as u64 != 0 {
                                            (*parser).error = result;
                                            // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                            break 'fail;
                                        }
                                        (*parser).state.NT.main = PL_WINNT_DATE;
                                        (*parser)
                                            .state
                                            .NT
                                            .sub
                                            .filename = PL_WINNT_FILENAME_PRESPACE;
                                    } else {
                                        (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                        // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                        break 'fail;
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                _ => {
                    retsize = bufflen.wrapping_add(1 as libc::c_int as libc::c_ulong);
                    // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                    break 'fail;
                }
            }
            i = i.wrapping_add(1);
        }
        // original normal exit
        return retsize;
        break 'fail;
    }


    // original label fail
    if !((*parser).file_data).is_null() {
        Curl_fileinfo_cleanup((*parser).file_data);
        let ref mut fresh38 = (*parser).file_data;
        *fresh38 = 0 as *mut fileinfo;
    }
    return retsize;
}
