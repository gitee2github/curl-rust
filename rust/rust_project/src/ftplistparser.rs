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

/**
 * Now implemented:
 *
 * 1) Unix version 1
 * drwxr-xr-x 1 user01 ftp  512 Jan 29 23:32 prog
 * 2) Unix version 2
 * drwxr-xr-x 1 user01 ftp  512 Jan 29 1997  prog
 * 3) Unix version 3
 * drwxr-xr-x 1      1   1  512 Jan 29 23:32 prog
 * 4) Unix symlink
 * lrwxr-xr-x 1 user01 ftp  512 Jan 29 23:32 prog -> prog2000
 * 5) DOS style
 * 01-29-97 11:32PM <DIR> prog
 */
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
// use crate::src::ftp::*;

// TODO
// 有2个enum，2个union，1个struct在ftplistparser.c中定义的，要保留在这个文件中
#[no_mangle]
pub extern "C" fn Curl_ftp_parselist_data_alloc() -> *mut ftp_parselist_data {
   unsafe{
    #[cfg(not(CURLDEBUG))]
    return Curl_ccalloc.expect("non-null function pointer")(
        1 as size_t,
        ::std::mem::size_of::<ftp_parselist_data>() as u64,
    ) as *mut ftp_parselist_data;
    #[cfg(CURLDEBUG)]
    return curl_dbg_calloc(
        1 as size_t,
        ::std::mem::size_of::<ftp_parselist_data>() as u64,
        184 as i32,
        b"ftplistparser.c\0" as *const u8 as *const libc::c_char,
    ) as *mut ftp_parselist_data;
   }
}
#[no_mangle]
pub extern "C" fn Curl_ftp_parselist_data_free(mut parserp: *mut *mut ftp_parselist_data) {
   unsafe{
    let mut parser: *mut ftp_parselist_data = *parserp;
    if !parser.is_null() {
        Curl_fileinfo_cleanup((*parser).file_data);
    }
    #[cfg(not(CURLDEBUG))]
    Curl_cfree.expect("non-null function pointer")(parser as *mut libc::c_void);

    #[cfg(CURLDEBUG)]
    curl_dbg_free(
        parser as *mut libc::c_void,
        193 as i32,
        b"ftplistparser.c\0" as *const u8 as *const libc::c_char,
    );
    *parserp = 0 as *mut ftp_parselist_data;
   }
}
#[no_mangle]
pub extern "C" fn Curl_ftp_parselist_geterror(
    mut pl_data: *mut ftp_parselist_data,
) -> CURLcode {
   unsafe{
    return (*pl_data).error;
   }
}
extern "C" fn ftp_pl_get_permission(mut str: *const libc::c_char) -> i32 {
   unsafe{
    let mut permissions: i32 = 0 as i32;
    /* USER */
    if *str.offset(0 as isize) as i32 == 'r' as i32 {
        permissions |= (1 as i32) << 8 as i32;
    } else if *str.offset(0 as isize) as i32 != '-' as i32 {
        permissions |= 0x1000000 as i32;
    }
    if *str.offset(1 as isize) as i32 == 'w' as i32 {
        permissions |= (1 as i32) << 7 as i32;
    } else if *str.offset(1 as isize) as i32 != '-' as i32 {
        permissions |= 0x1000000 as i32;
    }
    if *str.offset(2 as isize) as i32 == 'x' as i32 {
        permissions |= (1 as i32) << 6 as i32;
    } else if *str.offset(2 as i32 as isize) as i32 == 's' as i32 {
        permissions |= (1 as i32) << 6 as i32;
        permissions |= (1 as i32) << 11 as i32;
    } else if *str.offset(2 as isize) as i32 == 'S' as i32 {
        permissions |= (1 as i32) << 11 as i32;
    } else if *str.offset(2 as isize) as i32 != '-' as i32 {
        permissions |= 0x1000000 as i32;
    }
    /* GROUP */
    if *str.offset(3 as isize) as i32 == 'r' as i32 {
        permissions |= (1 as i32) << 5 as i32;
    } else if *str.offset(3 as isize) as i32 != '-' as i32 {
        permissions |= 0x1000000 as i32;
    }
    if *str.offset(4 as isize) as i32 == 'w' as i32 {
        permissions |= (1 as i32) << 4 as i32;
    } else if *str.offset(4 as isize) as i32 != '-' as i32 {
        permissions |= 0x1000000 as i32;
    }
    if *str.offset(5 as isize) as i32 == 'x' as i32 {
        permissions |= (1 as i32) << 3 as i32;
    } else if *str.offset(5 as isize) as i32 == 's' as i32 {
        permissions |= (1 as i32) << 3 as i32;
        permissions |= (1 as i32) << 10 as i32;
    } else if *str.offset(5 as isize) as i32 == 'S' as i32 {
        permissions |= (1 as i32) << 10 as i32;
    } else if *str.offset(5 as isize) as i32 != '-' as i32 {
        permissions |= 0x1000000 as i32;
    }
    /* others */
    if *str.offset(6 as isize) as i32 == 'r' as i32 {
        permissions |= (1 as i32) << 2 as i32;
    } else if *str.offset(6 as isize) as i32 != '-' as i32 {
        permissions |= 0x1000000 as i32;
    }
    if *str.offset(7 as isize) as i32 == 'w' as i32 {
        permissions |= (1 as i32) << 1 as i32;
    } else if *str.offset(7 as isize) as i32 != '-' as i32 {
        permissions |= 0x1000000 as i32;
    }
    if *str.offset(8 as isize) as i32 == 'x' as i32 {
        permissions |= 1 as i32;
    } else if *str.offset(8 as isize) as i32 == 't' as i32 {
        permissions |= 1 as i32;
        permissions |= (1 as i32) << 9 as i32;
    } else if *str.offset(8 as isize) as i32 == 'T' as i32 {
        permissions |= (1 as i32) << 9 as i32;
    } else if *str.offset(8 as isize) as i32 != '-' as i32 {
        permissions |= 0x1000000 as i32;
    }
    return permissions;
   }
}
extern "C" fn ftp_pl_insert_finfo(
    mut data: *mut Curl_easy,
    mut infop: *mut fileinfo,
) -> CURLcode {
   unsafe{
    let mut compare: curl_fnmatch_callback = None;
    let mut wc: *mut WildcardData = &mut (*data).wildcard;
    let mut ftpwc: *mut ftp_wc = (*wc).protdata as *mut ftp_wc;
    let mut llist: *mut Curl_llist = &mut (*wc).filelist;
    let mut parser: *mut ftp_parselist_data = (*ftpwc).parser;
    let mut add: bool = 1 as i32 != 0;
    let mut finfo: *mut curl_fileinfo = &mut (*infop).info;
    /* move finfo pointers to b_data */
    let mut str: *mut libc::c_char = (*finfo).b_data;
    // let ref mut fresh0 = (*finfo).filename;
    (*finfo).filename = str.offset((*parser).offsets.filename as isize);
    // let ref mut fresh1 = (*finfo).strings.group;
    (*finfo).strings.group = if (*parser).offsets.group != 0 {
        str.offset((*parser).offsets.group as isize)
    } else {
        0 as *mut libc::c_char
    };
    // let ref mut fresh2 = (*finfo).strings.perm;
    (*finfo).strings.perm = if (*parser).offsets.perm != 0 {
        str.offset((*parser).offsets.perm as isize)
    } else {
        0 as *mut libc::c_char
    };
    // let ref mut fresh3 = (*finfo).strings.target;
    (*finfo).strings.target = if (*parser).offsets.symlink_target != 0 {
        str.offset((*parser).offsets.symlink_target as isize)
    } else {
        0 as *mut libc::c_char
    };
    // let ref mut fresh4 = (*finfo).strings.time;
    (*finfo).strings.time = str.offset((*parser).offsets.time as isize);
    // let ref mut fresh5 = (*finfo).strings.user;
    (*finfo).strings.user = if (*parser).offsets.user != 0 {
        str.offset((*parser).offsets.user as isize)
    } else {
        0 as *mut libc::c_char
    };
     /* get correct fnmatch callback */
    compare = (*data).set.fnmatch;
    if compare.is_none() {
        compare = Some(
            Curl_fnmatch
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    *const libc::c_char,
                ) -> i32,
        );
    }
    /* filter pattern-corresponding filenames */
    Curl_set_in_callback(data, 1 as i32 != 0);
    if compare.expect("non-null function pointer")(
        (*data).set.fnmatch_data,
        (*wc).pattern,
        (*finfo).filename,
    ) == 0 as i32
    {/* discard symlink which is containing multiple " -> " */
        if (*finfo).filetype as u32 == CURLFILETYPE_SYMLINK as u32
            && !((*finfo).strings.target).is_null()
            && !(strstr(
                (*finfo).strings.target,
                b" -> \0" as *const u8 as *const libc::c_char,
            ))
                .is_null()
        {
            add = 0 as i32 != 0;
        }
    } else {
        add = 0 as i32 != 0;
    }
    Curl_set_in_callback(data, 0 as i32 != 0);
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
    // let ref mut fresh6 = (*(*ftpwc).parser).file_data;
    (*(*ftpwc).parser).file_data = 0 as *mut fileinfo;
    return CURLE_OK;
   }
}
#[no_mangle]
pub extern "C" fn Curl_ftp_parselist(
   mut buffer: *mut libc::c_char,
   mut size: size_t,
   mut nmemb: size_t,
   mut connptr: *mut libc::c_void,
) -> size_t {
   unsafe{
   let mut bufflen: size_t = size.wrapping_mul(nmemb);
   let mut data: *mut Curl_easy = connptr as *mut Curl_easy;
   let mut ftpwc: *mut ftp_wc = (*data).wildcard.protdata as *mut ftp_wc;
   let mut parser: *mut ftp_parselist_data = (*ftpwc).parser;
   let mut infop: *mut fileinfo = 0 as *mut fileinfo;
   let mut finfo: *mut curl_fileinfo = 0 as *mut curl_fileinfo;
   let mut i: u64 = 0 as i32 as u64;
   let mut result: CURLcode = CURLE_OK;
   let mut retsize: size_t = bufflen;

   'fail: loop {
       if (*parser).error as u64 != 0 {
           /* error in previous call */
   /* scenario:
    * 1. call => OK..
    * 2. call => OUT_OF_MEMORY (or other error)
    * 3. (last) call => is skipped RIGHT HERE and the error is hadled later
    *    in wc_statemach()
    */
           // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
           break 'fail;
       }
       if (*parser).os_type as u32
           == OS_TYPE_UNKNOWN as u32
           && bufflen > 0 as u64
       {/* considering info about FILE response format */
           (*parser)
               .os_type = (if *buffer.offset(0 as isize) as i32
               >= '0' as i32
               && *buffer.offset(0 as isize) as i32 <= '9' as i32
           {
               OS_TYPE_WIN_NT as i32
           } else {
               OS_TYPE_UNIX as i32
           }) as C2RustUnnamed_22;
       }
       while i < bufflen {/* FSM */
           let mut c: libc::c_char = *buffer.offset(i as isize);
           if ((*parser).file_data).is_null() {/* tmp file data is not allocated yet */
            //    let ref mut fresh7 = (*parser).file_data;
               (*parser).file_data = Curl_fileinfo_alloc();
               if ((*parser).file_data).is_null() {
                   (*parser).error = CURLE_OUT_OF_MEMORY;
                   // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                   break 'fail;
               }
               match () {
                   #[cfg(not(CURLDEBUG))]
                   _ => {
                       (*(*parser).file_data).info.b_data = Curl_cmalloc
                       .expect("non-null function pointer")(160 as size_t)
                       as *mut libc::c_char;
                   }
                   #[cfg(CURLDEBUG)]
                   _ => {
                       (*(*parser).file_data).info.b_data = curl_dbg_malloc(
                           160 as size_t,
                           364 as i32,
                           b"ftplistparser.c\0" as *const u8 as *const libc::c_char,
                       ) as *mut libc::c_char;
                   }
               }
  
               if ((*(*parser).file_data).info.b_data).is_null() {
                   (*parser).error = CURLE_OUT_OF_MEMORY;
                   // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                   break 'fail;
               }
               (*(*parser).file_data).info.b_size = 160 as size_t;
               (*parser).item_offset = 0 as size_t;
               (*parser).item_length = 0 as u32;
           }
           infop = (*parser).file_data;
           finfo = &mut (*infop).info;
        //    let ref mut fresh9 = (*finfo).b_used;
           let fresh10 =  (*finfo).b_used;
           (*finfo).b_used = ( (*finfo).b_used).wrapping_add(1);
           *((*finfo).b_data).offset(fresh10 as isize) = c;
           if (*finfo).b_used
               >= ((*finfo).b_size).wrapping_sub(1 as u64)
           { /* if it is important, extend buffer space for file data */
               #[cfg(not(CURLDEBUG))]
               let mut tmp: *mut libc::c_char = Curl_crealloc
                   .expect(
                       "non-null function pointer",
                   )(
                   (*finfo).b_data as *mut libc::c_void,
                   ((*finfo).b_size).wrapping_add(160 as u64),
               ) as *mut libc::c_char;
               #[cfg(CURLDEBUG)]
               let mut tmp: *mut libc::c_char = curl_dbg_realloc(
                   (*finfo).b_data as *mut libc::c_void,
                   ((*finfo).b_size).wrapping_add(160 as u64),
                   381 as i32,
                   b"ftplistparser.c\0" as *const u8 as *const libc::c_char,
               ) as *mut libc::c_char;
               if !tmp.is_null() {
                //    let ref mut fresh11 = (*finfo).b_size;
                   (*finfo).b_size = ((*finfo).b_size as u64)
                       .wrapping_add(160 as u64) as size_t
                       as size_t;
                //    let ref mut fresh12 = (*finfo).b_data;
                   (*finfo).b_data = tmp;
               } else {
                   Curl_fileinfo_cleanup((*parser).file_data);
                //    let ref mut fresh13 = (*parser).file_data;
                   (*parser).file_data = 0 as *mut fileinfo;
                   (*parser).error = CURLE_OUT_OF_MEMORY;
                   // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                   break 'fail;
               }
           }
           match (*parser).os_type as u32 {
               1 => {
                   match (*parser).state.UNIX.main as u32 {
                       0 => {
                           match (*parser).state.UNIX.sub.total_dirsize as u32 {
                               0 => {
                                   if c as i32 == 't' as i32 {
                                       (*parser)
                                           .state
                                           .UNIX
                                           .sub
                                           .total_dirsize = PL_UNIX_TOTALSIZE_READING;
                                    //    let ref mut fresh14 = (*parser).item_length;
                                       (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   } else {
                                       (*parser).state.UNIX.main = PL_UNIX_FILETYPE;
                                       /* start FSM again not considering size of directory */
                                       (*finfo).b_used = 0 as size_t;
                                       continue;
                                   }
                               }
                               1 => {
                                //    let ref mut fresh15 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == '\r' as i32 {
                                    //    let ref mut fresh16 = (*parser).item_length;
                                       (*parser).item_length = ((*parser).item_length).wrapping_sub(1);
                                    //    let ref mut fresh17 = (*finfo).b_used;
                                       (*finfo).b_used = ((*finfo).b_used).wrapping_sub(1);
                                   } else if c as i32 == '\n' as i32 {
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_length)
                                                   .wrapping_sub(1 as u32) as isize,
                                           ) = 0 as libc::c_char;
                                       if strncmp(
                                           b"total \0" as *const u8 as *const libc::c_char,
                                           (*finfo).b_data,
                                           6 as u64,
                                       ) == 0 as i32
                                       {
                                           let mut endptr: *mut libc::c_char = ((*finfo).b_data)
                                               .offset(6 as isize);
                                               /* here we can deal with directory size, pass the leading
                whitespace and then the digits */
                                           while Curl_isspace(*endptr as u8 as i32)
                                               != 0
                                           {
                                               endptr = endptr.offset(1);
                                           }
                                           while Curl_isdigit(*endptr as u8 as i32)
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
                                           (*finfo).b_used = 0 as size_t;/* terminate permissions */
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
                           match c as i32 {
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
                           (*parser).item_length = 0 as u32;
                           (*parser).item_offset = 1 as size_t;
                       }
                       2 => {
                        //    let ref mut fresh18 = (*parser).item_length;
                           (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                           if (*parser).item_length <= 9 as u32 {
                               if (strchr(
                                   b"rwx-tTsS\0" as *const u8 as *const libc::c_char,
                                   c as i32,
                               ))
                                   .is_null()
                               {
                                   (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                   // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                   break 'fail;
                               }
                           } else if (*parser).item_length
                                   == 10 as u32
                               {
                               let mut perm: u32 = 0;
                               if c as i32 != ' ' as i32 {
                                   (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                   // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                   break 'fail;
                               }
                               *((*finfo).b_data)
                                   .offset(
                                       10 as isize,
                                   ) = 0 as libc::c_char;
                               perm = ftp_pl_get_permission(
                                   ((*finfo).b_data).offset((*parser).item_offset as isize),
                               ) as u32;
                               if perm & 0x1000000 as u32 != 0 {
                                   (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                   // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                   break 'fail;
                               }
                               (*(*parser).file_data).info.flags
                                   |= ((1 as i32) << 3 as i32) as u32;
                               (*(*parser).file_data).info.perm = perm;
                               (*parser).offsets.perm = (*parser).item_offset;
                               (*parser).item_length = 0 as u32;
                               (*parser).state.UNIX.main = PL_UNIX_HLINKS;
                               (*parser).state.UNIX.sub.hlinks = PL_UNIX_HLINKS_PRESPACE;
                           }
                       }
                       3 => {
                           match (*parser).state.UNIX.sub.hlinks as u32 {
                               0 => {
                                   if c as i32 != ' ' as i32 {
                                       if c as i32 >= '0' as i32
                                           && c as i32 <= '9' as i32
                                       {
                                           (*parser)
                                               .item_offset = ((*finfo).b_used)
                                               .wrapping_sub(1 as u64);
                                           (*parser).item_length = 1 as u32;
                                           (*parser).state.UNIX.sub.hlinks = PL_UNIX_HLINKS_NUMBER;
                                       } else {
                                           (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                           // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                           break 'fail;
                                       }
                                   }
                               }
                               1 => {
                                //    let ref mut fresh19 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
                                       let mut hlinks: i64 = 0;
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
                                       hlinks = strtol(
                                           ((*finfo).b_data).offset((*parser).item_offset as isize),
                                           &mut p,
                                           10 as i32,
                                       );
                                       if *p.offset(0 as isize) as i32
                                           == '\u{0}' as i32
                                           && hlinks != 9223372036854775807 as i64
                                           && hlinks
                                               != -(9223372036854775807 as i64)
                                                   - 1 as i64
                                       {
                                           (*(*parser).file_data).info.flags
                                               |= ((1 as i32) << 7 as i32) as u32;
                                           (*(*parser).file_data).info.hardlinks = hlinks;
                                       }
                                       (*parser).item_length = 0 as u32;
                                       (*parser).item_offset = 0 as size_t;
                                       (*parser).state.UNIX.main = PL_UNIX_USER;
                                       (*parser).state.UNIX.sub.user = PL_UNIX_USER_PRESPACE;
                                   } else if (c as i32) < '0' as i32
                                           || c as i32 > '9' as i32
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
                           match (*parser).state.UNIX.sub.user as u32 {
                               0 => {
                                   if c as i32 != ' ' as i32 {
                                       (*parser)
                                           .item_offset = ((*finfo).b_used)
                                           .wrapping_sub(1 as u64);
                                       (*parser).item_length = 1 as u32;
                                       (*parser).state.UNIX.sub.user = PL_UNIX_USER_PARSING;
                                   }
                               }
                               1 => {
                                //    let ref mut fresh20 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
                                       (*parser).offsets.user = (*parser).item_offset;
                                       (*parser).state.UNIX.main = PL_UNIX_GROUP;
                                       (*parser).state.UNIX.sub.group = PL_UNIX_GROUP_PRESPACE;
                                       (*parser).item_offset = 0 as size_t;
                                       (*parser).item_length = 0 as u32;
                                   }
                               }
                               _ => {}
                           }
                       }
                       5 => {
                           match (*parser).state.UNIX.sub.group as u32 {
                               0 => {
                                   if c as i32 != ' ' as i32 {
                                       (*parser)
                                           .item_offset = ((*finfo).b_used)
                                           .wrapping_sub(1 as u64);
                                       (*parser).item_length = 1 as u32;
                                       (*parser).state.UNIX.sub.group = PL_UNIX_GROUP_NAME;
                                   }
                               }
                               1 => {
                                //    let ref mut fresh21 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
                                       (*parser).offsets.group = (*parser).item_offset;
                                       (*parser).state.UNIX.main = PL_UNIX_SIZE;
                                       (*parser).state.UNIX.sub.size = PL_UNIX_SIZE_PRESPACE;
                                       (*parser).item_offset = 0 as size_t;
                                       (*parser).item_length = 0 as u32;
                                   }
                               }
                               _ => {}
                           }
                       }
                       6 => {
                           match (*parser).state.UNIX.sub.size as u32 {
                               0 => {
                                   if c as i32 != ' ' as i32 {
                                       if c as i32 >= '0' as i32
                                           && c as i32 <= '9' as i32
                                       {
                                           (*parser)
                                               .item_offset = ((*finfo).b_used)
                                               .wrapping_sub(1 as u64);
                                           (*parser).item_length = 1 as u32;
                                           (*parser).state.UNIX.sub.size = PL_UNIX_SIZE_NUMBER;
                                       } else {
                                           (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                           // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                           break 'fail;
                                       }
                                   }
                               }
                               1 => {
                                //    let ref mut fresh22 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       let mut p_0: *mut libc::c_char = 0 as *mut libc::c_char;
                                       let mut fsize: curl_off_t = 0;
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
                                       if curlx_strtoofft(
                                           ((*finfo).b_data).offset((*parser).item_offset as isize),
                                           &mut p_0,
                                           10 as i32,
                                           &mut fsize,
                                       ) as u64 == 0
                                       {
                                           if *p_0.offset(0 as isize) as i32
                                               == '\u{0}' as i32
                                               && fsize != 0x7fffffffffffffff as i64
                                               && fsize
                                                   != -(0x7fffffffffffffff as i64) - 1 as i64
                                           {
                                               (*(*parser).file_data).info.flags
                                                   |= ((1 as i32) << 6 as i32) as u32;
                                               (*(*parser).file_data).info.size = fsize;
                                           }
                                           (*parser).item_length = 0 as u32;
                                           (*parser).item_offset = 0 as size_t;
                                           (*parser).state.UNIX.main = PL_UNIX_TIME;
                                           (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PREPART1;
                                       }
                                   } else if Curl_isdigit(c as i32)
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
                           match (*parser).state.UNIX.sub.time as u32 {
                               0 => {
                                   if c as i32 != ' ' as i32 {
                                       if Curl_isalnum(c as i32) != 0 {
                                           (*parser)
                                               .item_offset = ((*finfo).b_used)
                                               .wrapping_sub(1 as u64);
                                           (*parser).item_length = 1 as u32;
                                           (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PART1;
                                       } else {
                                           (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                           // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                           break 'fail;
                                       }
                                   }
                               }
                               1 => {
                                //    let ref mut fresh23 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PREPART2;
                                   } else if Curl_isalnum(c as i32)
                                           == 0 && c as i32 != '.' as i32
                                       {
                                       (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                       // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                       break 'fail;
                                   }
                               }
                               2 => {
                                //    let ref mut fresh24 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 != ' ' as i32 {
                                       if Curl_isalnum(c as i32) != 0 {
                                           (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PART2;
                                       } else {
                                           (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                           // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                           break 'fail;
                                       }
                                   }
                               }
                               3 => {
                                //    let ref mut fresh25 = (*parser).item_length;
                                   (*parser).item_length = ( (*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PREPART3;
                                   } else if Curl_isalnum(c as i32)
                                           == 0 && c as i32 != '.' as i32
                                       {
                                       (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                       // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                       break 'fail;
                                   }
                               }
                               4 => {
                                //    let ref mut fresh26 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 != ' ' as i32 {
                                       if Curl_isalnum(c as i32) != 0 {
                                           (*parser).state.UNIX.sub.time = PL_UNIX_TIME_PART3;
                                       } else {
                                           (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                           // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                           break 'fail;
                                       }
                                   }
                               }
                               5 => {
                                //    let ref mut fresh27 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
                                       (*parser).offsets.time = (*parser).item_offset;
                                       /*
             if(ftp_pl_gettime(parser, finfo->b_data + parser->item_offset)) {
               parser->file_data->flags |= CURLFINFOFLAG_KNOWN_TIME;
             }
           */
                                       if (*finfo).filetype as u32
                                           == CURLFILETYPE_SYMLINK as u32
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
                                   } else if Curl_isalnum(c as i32)
                                           == 0 && c as i32 != '.' as i32
                                           && c as i32 != ':' as i32
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
                           match (*parser).state.UNIX.sub.filename as u32 {
                               0 => {
                                   if c as i32 != ' ' as i32 {
                                       (*parser)
                                           .item_offset = ((*finfo).b_used)
                                           .wrapping_sub(1 as u64);
                                       (*parser).item_length = 1 as u32;
                                       (*parser).state.UNIX.sub.filename = PL_UNIX_FILENAME_NAME;
                                   }
                               }
                               1 => {
                                //    let ref mut fresh28 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == '\r' as i32 {
                                       (*parser)
                                           .state
                                           .UNIX
                                           .sub
                                           .filename = PL_UNIX_FILENAME_WINDOWSEOL;
                                   } else if c as i32 == '\n' as i32 {
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
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
                                   if c as i32 == '\n' as i32 {
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
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
                           match (*parser).state.UNIX.sub.symlink as u32 {
                               0 => {
                                   if c as i32 != ' ' as i32 {
                                       (*parser)
                                           .item_offset = ((*finfo).b_used)
                                           .wrapping_sub(1 as u64);
                                       (*parser).item_length = 1 as u32;
                                       (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_NAME;
                                       /* now place where is symlink following */
                                   }
                               }
                               1 => {
                                //    let ref mut fresh29 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       (*parser)
                                           .state
                                           .UNIX
                                           .sub
                                           .symlink = PL_UNIX_SYMLINK_PRETARGET1;
                                   } else if c as i32 == '\r' as i32
                                           || c as i32 == '\n' as i32
                                       {
                                       (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                       // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                       break 'fail;
                                   }
                               }
                               2 => {
                                //    let ref mut fresh30 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == '-' as i32 {
                                       (*parser)
                                           .state
                                           .UNIX
                                           .sub
                                           .symlink = PL_UNIX_SYMLINK_PRETARGET2;
                                   } else if c as i32 == '\r' as i32
                                           || c as i32 == '\n' as i32
                                       {
                                       (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                       // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                       break 'fail;
                                   } else {
                                       (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_NAME;
                                   }
                               }
                               3 => {
                                //    let ref mut fresh31 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == '>' as i32 {
                                       (*parser)
                                           .state
                                           .UNIX
                                           .sub
                                           .symlink = PL_UNIX_SYMLINK_PRETARGET3;
                                   } else if c as i32 == '\r' as i32
                                           || c as i32 == '\n' as i32
                                       {
                                       (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                       // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                       break 'fail;
                                   } else {
                                       (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_NAME;
                                   }
                               }
                               4 => {
                                //    let ref mut fresh32 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       (*parser)
                                           .state
                                           .UNIX
                                           .sub
                                           .symlink = PL_UNIX_SYMLINK_PRETARGET4;
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(4 as u64) as isize,
                                           ) = 0 as libc::c_char;
                                       (*parser).offsets.filename = (*parser).item_offset;
                                       (*parser).item_length = 0 as u32;
                                       (*parser).item_offset = 0 as size_t;
                                   } else if c as i32 == '\r' as i32
                                           || c as i32 == '\n' as i32
                                       {
                                       (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                       // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                       break 'fail;
                                   } else {
                                       (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_NAME;
                                   }
                               }
                               5 => {
                                   if c as i32 != '\r' as i32
                                       && c as i32 != '\n' as i32
                                   {
                                       (*parser).state.UNIX.sub.symlink = PL_UNIX_SYMLINK_TARGET;
                                       (*parser)
                                           .item_offset = ((*finfo).b_used)
                                           .wrapping_sub(1 as u64);
                                       (*parser).item_length = 1 as u32;
                                   } else {
                                       (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                       // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                       break 'fail;
                                   }
                               }
                               6 => {
                                //    let ref mut fresh33 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == '\r' as i32 {
                                       (*parser)
                                           .state
                                           .UNIX
                                           .sub
                                           .symlink = PL_UNIX_SYMLINK_WINDOWSEOL;
                                   } else if c as i32 == '\n' as i32 {
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
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
                                   if c as i32 == '\n' as i32 {
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
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
                   match (*parser).state.NT.main as u32 {
                       0 => {
                        //    let ref mut fresh34 = (*parser).item_length;
                           (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                           if (*parser).item_length < 9 as u32 {
                               if (strchr(
                                   b"0123456789-\0" as *const u8 as *const libc::c_char,
                                   c as i32,
                               ))
                                   .is_null()
                               {/* only simple control */
                                   (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                   // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                   break 'fail;
                               }
                           } else if (*parser).item_length
                                   == 9 as u32
                               {
                               if c as i32 == ' ' as i32 {
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
                        //    let ref mut fresh35 = (*parser).item_length;
                           (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                           match (*parser).state.NT.sub.time as u32 {
                               0 => {
                                   if Curl_isspace(c as i32) == 0 {
                                       (*parser).state.NT.sub.time = PL_WINNT_TIME_TIME;
                                   }
                               }
                               1 => {
                                   if c as i32 == ' ' as i32 {
                                       (*parser).offsets.time = (*parser).item_offset;
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
                                       (*parser).state.NT.main = PL_WINNT_DIRORSIZE;
                                       (*parser)
                                           .state
                                           .NT
                                           .sub
                                           .dirorsize = PL_WINNT_DIRORSIZE_PRESPACE;
                                       (*parser).item_length = 0 as u32;
                                   } else if (strchr(
                                           b"APM0123456789:\0" as *const u8 as *const libc::c_char,
                                           c as i32,
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
                           match (*parser).state.NT.sub.dirorsize as u32 {
                               0 => {
                                   if c as i32 != ' ' as i32 {
                                       (*parser)
                                           .item_offset = ((*finfo).b_used)
                                           .wrapping_sub(1 as u64);
                                       (*parser).item_length = 1 as u32;
                                       (*parser)
                                           .state
                                           .NT
                                           .sub
                                           .dirorsize = PL_WINNT_DIRORSIZE_CONTENT;
                                   }
                               }
                               1 => {
                                //    let ref mut fresh36 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == ' ' as i32 {
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*parser).item_offset)
                                                   .wrapping_add((*parser).item_length as u64)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
                                       if strcmp(
                                           b"<DIR>\0" as *const u8 as *const libc::c_char,
                                           ((*finfo).b_data).offset((*parser).item_offset as isize),
                                       ) == 0 as i32
                                       {
                                           (*finfo).filetype = CURLFILETYPE_DIRECTORY;
                                           (*finfo).size = 0 as curl_off_t;
                                       } else {
                                           let mut endptr_0: *mut libc::c_char = 0
                                               as *mut libc::c_char;
                                           if curlx_strtoofft(
                                               ((*finfo).b_data).offset((*parser).item_offset as isize),
                                               &mut endptr_0,
                                               10 as i32,
                                               &mut (*finfo).size,
                                           ) as u64 != 0
                                           {
                                               (*parser).error = CURLE_FTP_BAD_FILE_LIST;
                                               // printf(b"hanxj\n\0" as *const u8 as *const libc::c_char);
                                               break 'fail;
                                           }
                                            /* correct file type */
                                           (*(*parser).file_data).info.filetype = CURLFILETYPE_FILE;
                                       }
                                       (*(*parser).file_data).info.flags
                                           |= ((1 as i32) << 6 as i32) as u32;
                                       (*parser).item_length = 0 as u32;
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
                           match (*parser).state.NT.sub.filename as u32 {
                               0 => {
                                   if c as i32 != ' ' as i32 {
                                       (*parser)
                                           .item_offset = ((*finfo).b_used)
                                           .wrapping_sub(1 as u64);
                                       (*parser).item_length = 1 as u32;
                                       (*parser).state.NT.sub.filename = PL_WINNT_FILENAME_CONTENT;
                                   }
                               }
                               1 => {
                                //    let ref mut fresh37 = (*parser).item_length;
                                   (*parser).item_length = ((*parser).item_length).wrapping_add(1);
                                   if c as i32 == '\r' as i32 {
                                       (*parser).state.NT.sub.filename = PL_WINNT_FILENAME_WINEOL;
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*finfo).b_used)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
                                   } else if c as i32 == '\n' as i32 {
                                       (*parser).offsets.filename = (*parser).item_offset;
                                       *((*finfo).b_data)
                                           .offset(
                                               ((*finfo).b_used)
                                                   .wrapping_sub(1 as u64) as isize,
                                           ) = 0 as libc::c_char;
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
                                   if c as i32 == '\n' as i32 {
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
                   retsize = bufflen.wrapping_add(1 as u64);
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
    /* Clean up any allocated memory. */
   if !((*parser).file_data).is_null() {
       Curl_fileinfo_cleanup((*parser).file_data);
    //    let ref mut fresh38 = (*parser).file_data;
       (*parser).file_data = 0 as *mut fileinfo;
   }
   return retsize;
}
}
