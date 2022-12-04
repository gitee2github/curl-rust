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
 /*
  * Chunk format (simplified):
  *
  * <HEX SIZE>[ chunk extension ] CRLF
  * <DATA> CRLF
  *
  * Highlights from RFC2616 section 3.6 say:
 
    The chunked encoding modifies the body of a message in order to
    transfer it as a series of chunks, each with its own size indicator,
    followed by an OPTIONAL trailer containing entity-header fields. This
    allows dynamically produced content to be transferred along with the
    information necessary for the recipient to verify that it has
    received the full message.
 
        Chunked-Body   = *chunk
                         last-chunk
                         trailer
                         CRLF
 
        chunk          = chunk-size [ chunk-extension ] CRLF
                         chunk-data CRLF
        chunk-size     = 1*HEX
        last-chunk     = 1*("0") [ chunk-extension ] CRLF
 
        chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
        chunk-ext-name = token
        chunk-ext-val  = token | quoted-string
        chunk-data     = chunk-size(OCTET)
        trailer        = *(entity-header CRLF)
 
    The chunk-size field is a string of hex digits indicating the size of
    the chunk. The chunked encoding is ended by any chunk whose size is
    zero, followed by the trailer, which is terminated by an empty line.
 
  */
 #[no_mangle]
 pub extern "C" fn Curl_httpchunk_init(mut data: *mut Curl_easy) {
     unsafe{
         let mut conn: *mut connectdata = (*data).conn;
     let mut chunk: *mut Curl_chunker = &mut (*conn).chunk;
     (*chunk).hexindex = 0 as u8; /* start at 0 */
     (*chunk).state = CHUNK_HEX;/* we get hex first! */
     Curl_dyn_init(&mut (*conn).trailer, 4096 as size_t);
     }
 }
 #[no_mangle]
 
 /*
  * chunk_read() returns a OK for normal operations, or a positive return code
  * for errors. STOP means this sequence of chunks is complete.  The 'wrote'
  * argument is set to tell the caller how many bytes we actually passed to the
  * client (for byte-counting and whatever).
  *
  * The states and the state-machine is further explained in the header file.
  *
  * This function always uses ASCII hex values to accommodate non-ASCII hosts.
  * For example, 0x0d and 0x0a are used instead of '\r' and '\n'.
  */
 pub extern "C" fn Curl_httpchunk_read(
     mut data: *mut Curl_easy,
     mut datap: *mut libc::c_char,
     mut datalen: ssize_t,
     mut wrotep: *mut ssize_t,
     mut extrap: *mut CURLcode,
 ) -> CHUNKcode {
     unsafe{
         let mut result: CURLcode = CURLE_OK;
     let mut conn: *mut connectdata = (*data).conn;
     let mut ch: *mut Curl_chunker = &mut (*conn).chunk;
     let mut k: *mut SingleRequest = &mut (*data).req;
     let mut piece: size_t = 0;
     let mut length: curl_off_t = datalen;
     let mut wrote: *mut size_t = wrotep as *mut size_t;
     *wrote = 0 as size_t;  /* nothing's written yet */
 
   /* the original data is written to the client, but we go on with the
      chunk read process, to properly calculate the content length*/
     if ((*data).set).http_te_skip() as i32 != 0 && (*k).ignorebody() == 0 {
         result = Curl_client_write(
             data,
             (1 as i32) << 0 as i32,
             datap,
             datalen as size_t,
         );
         if result as u64 != 0 {
             *extrap = result;
             return CHUNKE_PASSTHRU_ERROR; /* longer hex than we support */
         }
     }
     while length != 0 {
         let mut current_block_101: u64;
         match (*ch).state as u32 {
             0 => {
                 if Curl_isxdigit(*datap as i32) != 0 {
                     /* This is illegal data, we received junk where we expected
              a hexadecimal digit. */
                     if ((*ch).hexindex as i32) < 8  as i32 {
                         (*ch).hexbuffer[(*ch).hexindex as usize] = *datap;
                         datap = datap.offset(1);
                         length -= 1;
                         (*ch).hexindex = ((*ch).hexindex).wrapping_add(1);
                     } else {
                         return CHUNKE_TOO_LONG_HEX;
                     }
                 } else {
                     /* length and datap are unmodified */
                     let mut endptr: *mut libc::c_char = 0 as *mut libc::c_char;
                     if 0 as i32 == (*ch).hexindex as i32 {
                         return CHUNKE_ILLEGAL_HEX;
                     }
                     (*ch).hexbuffer[(*ch).hexindex as usize] = 0 as libc::c_char;
                     /* convert to host encoding before calling strtoul */
                     result = CURLE_OK as CURLcode;
                     if result as u64 != 0 {
                         /* Curl_convert_from_network calls failf if unsuccessful */
           /* Treat it as a bad hex character */
                         return CHUNKE_ILLEGAL_HEX;
                     }
                     if curlx_strtoofft(
                         ((*ch).hexbuffer).as_mut_ptr(),
                         &mut endptr,
                         16 as i32,
                         &mut (*ch).datasize,
                     ) as u64
                         != 0
                     {
                         /* now wait for the CRLF */
                         return CHUNKE_ILLEGAL_HEX;
                     }
                     (*ch).state = CHUNK_LF;
                 }
             }
             1 => {
                 if *datap as i32 == 0xa as i32 {
                     if 0 as i64 == (*ch).datasize {
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
                             (1 as i32) << 0 as i32,
                             datap,
                             piece,
                         );
                     }
                     if result as u64 != 0 {
                         *extrap = result;
                         return CHUNKE_PASSTHRU_ERROR;
                     }
                 }
                 /* decrease amount left to expect */
                 *wrote = (*wrote as u64).wrapping_add(piece) as size_t;
                 (*ch).datasize =
                     ((*ch).datasize as u64).wrapping_sub(piece) as curl_off_t;
                 datap = datap.offset(piece as isize);
                 /* move read pointer forward */
                 length = (length as u64).wrapping_sub(piece) as curl_off_t;
                 /* decrease space left in this round */
                 if 0 as i64 == (*ch).datasize {
                     /* end of data this round, we now expect a trailing CRLF */
                     (*ch).state = CHUNK_POSTLF;
                 }
             }
             3 => {
                 if *datap as i32 == 0xa as i32 {
                     /* The last one before we go back to hex state and start all over. */
                     Curl_httpchunk_init(data);/* sets state back to CHUNK_HEX */
                 } else if *datap as i32 != 0xd as i32 {
                     return CHUNKE_BAD_CHUNK;
                 }
                 datap = datap.offset(1);
                 length -= 1;
             }
             5 => {
                 if *datap as i32 == 0xd as i32
                     || *datap as i32 == 0xa as i32
                 {
                     let mut tr: *mut libc::c_char = Curl_dyn_ptr(&mut (*conn).trailer);
                     /* this is the end of a trailer, but if the trailer was zero bytes
            there was no trailer and we move on */
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
                         /* Convert to host encoding before calling Curl_client_write */
                         result = CURLE_OK as CURLcode;
                         if result as u64 != 0 {
                             /* Curl_convert_from_network calls failf if unsuccessful */
             /* Treat it as a bad chunk */
                             return CHUNKE_BAD_CHUNK;
                         }
                         if ((*data).set).http_te_skip() == 0 {
                             /* already on the LF */
                             result = Curl_client_write(
                                 data,
                                 (1 as i32) << 1 as i32,
                                 tr,
                                 trlen,
                             );
                             if result as u64 != 0 {
                                 *extrap = result;
                                 return CHUNKE_PASSTHRU_ERROR;
                             }
                         }
                         Curl_dyn_reset(&mut (*conn).trailer);
                         /* no trailer, we're on the final CRLF pair */
                         (*ch).state = CHUNK_TRAILER_CR;
                         if *datap as i32 == 0xa as i32 {
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
                         1 as size_t,
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
                 if *datap as i32 == 0xa as i32 {
                     /* no trailer, we're on the final CRLF pair */
                     (*ch).state = CHUNK_TRAILER_POSTCR;
                     datap = datap.offset(1);
                     length -= 1;
                     /* don't advance the pointer */
                 } else {
                     return CHUNKE_BAD_CHUNK;
                 }
             }
             7 => {
                 /* We enter this state when a CR should arrive so we expect to
          have to first pass a CR before we wait for LF */
                 if *datap as i32 != 0xd as i32
                     && *datap as i32 != 0xa as i32
                     /* not a CR then it must be another header in the trailer */
                 {
                     (*ch).state = CHUNK_TRAILER;
                 } else {
                     if *datap as i32 == 0xd as i32 {
                         /* skip if CR */
                         datap = datap.offset(1);
                         length -= 1;
                     }
                     /* now wait for the final LF */
                     (*ch).state = CHUNK_STOP; /* return stop */
                 }
             }
             4 => {
                 if *datap as i32 == 0xa as i32 {
                     length -= 1;
                     /* Record the length of any data left in the end of the buffer
            even if there's no more chunks to read */
                     (*ch).datasize = curlx_sotouz(length) as curl_off_t;
                     return CHUNKE_STOP;/* return stop */
                 } else {
                     return CHUNKE_BAD_CHUNK;
                 }
             }
             _ => {}
         }
     }
     return CHUNKE_OK;
     }
 }
 #[no_mangle]
 pub extern "C" fn Curl_chunked_strerror(mut code: CHUNKcode) -> *const libc::c_char {
     unsafe{
         match code as i32 {
             1 => return b"Too long hexadecimal number\0" as *const u8 as *const libc::c_char,
             2 => {
                 return b"Illegal or missing hexadecimal sequence\0" as *const u8
                     as *const libc::c_char;
             }
             3 => return b"Malformed encoding found\0" as *const u8 as *const libc::c_char,
             6 => return b"\0" as *const u8 as *const libc::c_char, /* never used */
             4 => return b"Bad content-encoding found\0" as *const u8 as *const libc::c_char,
             5 => return b"Out of memory\0" as *const u8 as *const libc::c_char,
             _ => return b"OK\0" as *const u8 as *const libc::c_char,
         };
     }
 }
 /* CURL_DISABLE_HTTP */