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
 * Description: support openssl backend
 ******************************************************************************/
 use crate::src::vtls::keylog::*;
 use crate::src::vtls::vtls::*;
 use libc;
 use rust_ffi::src::ffi_alias::type_alias::*;
 use rust_ffi::src::ffi_fun::fun_call::*;
 use rust_ffi::src::ffi_struct::struct_define::*;
 
 #[inline]
 extern "C" fn sk_X509_pop(mut sk: *mut stack_st_X509) -> *mut X509 {
     unsafe {
         return OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) as *mut X509;
     }
 }
 #[inline]
 extern "C" fn sk_X509_pop_free(mut sk: *mut stack_st_X509, mut freefunc: sk_X509_freefunc) {
     unsafe {
         OPENSSL_sk_pop_free(
             sk as *mut OPENSSL_STACK,
             ::std::mem::transmute::<sk_X509_freefunc, OPENSSL_sk_freefunc>(freefunc),
         );
     }
 }
 #[inline]
 extern "C" fn sk_X509_INFO_num(mut sk: *const stack_st_X509_INFO) -> i32 {
     unsafe {
         return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
     }
 }
 #[inline]
 extern "C" fn sk_X509_INFO_value(
     mut sk: *const stack_st_X509_INFO,
     mut idx: i32,
 ) -> *mut X509_INFO {
     unsafe {
         return OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) as *mut X509_INFO;
     }
 }
 #[inline]
 extern "C" fn sk_X509_INFO_pop_free(
     mut sk: *mut stack_st_X509_INFO,
     mut freefunc: sk_X509_INFO_freefunc,
 ) {
     unsafe {
         OPENSSL_sk_pop_free(
             sk as *mut OPENSSL_STACK,
             ::std::mem::transmute::<sk_X509_INFO_freefunc, OPENSSL_sk_freefunc>(freefunc),
         );
     }
 }
 #[inline]
 extern "C" fn sk_X509_EXTENSION_num(mut sk: *const stack_st_X509_EXTENSION) -> i32 {
     unsafe {
         return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
     }
 }
 #[inline]
 extern "C" fn sk_X509_EXTENSION_value(
     mut sk: *const stack_st_X509_EXTENSION,
     mut idx: i32,
 ) -> *mut X509_EXTENSION {
     unsafe {
         return OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) as *mut X509_EXTENSION;
     }
 }
 #[inline]
 extern "C" fn sk_X509_num(mut sk: *const stack_st_X509) -> i32 {
     unsafe {
         return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
     }
 }
 #[inline]
 extern "C" fn sk_X509_value(mut sk: *const stack_st_X509, mut idx: i32) -> *mut X509 {
     unsafe {
         return OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) as *mut X509;
     }
 }
 #[inline]
 extern "C" fn sk_GENERAL_NAME_num(mut sk: *const stack_st_GENERAL_NAME) -> i32 {
     unsafe {
         return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
     }
 }
 #[inline]
 extern "C" fn sk_GENERAL_NAME_value(
     mut sk: *const stack_st_GENERAL_NAME,
     mut idx: i32,
 ) -> *mut GENERAL_NAME {
     unsafe {
         return OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) as *mut GENERAL_NAME;
     }
 }
 #[cfg(HAVE_KEYLOG_CALLBACK)]
 extern "C" fn ossl_keylog_callback(mut ssl: *const SSL, mut line: *const libc::c_char) {
     unsafe {
         Curl_tls_keylog_write_line(line);
     }
 }
 // TODO - 255 - 关闭 HAVE_KEYLOG_CALLBACK选项，在翻译一次
 // #[cfg(not(HAVE_KEYLOG_CALLBACK))]
 
 extern "C" fn SSL_ERROR_to_str(mut err: i32) -> *const libc::c_char {
     match err {
         0 => return b"SSL_ERROR_NONE\0" as *const u8 as *const libc::c_char,
         1 => return b"SSL_ERROR_SSL\0" as *const u8 as *const libc::c_char,
         2 => return b"SSL_ERROR_WANT_READ\0" as *const u8 as *const libc::c_char,
         3 => return b"SSL_ERROR_WANT_WRITE\0" as *const u8 as *const libc::c_char,
         4 => return b"SSL_ERROR_WANT_X509_LOOKUP\0" as *const u8 as *const libc::c_char,
         5 => return b"SSL_ERROR_SYSCALL\0" as *const u8 as *const libc::c_char,
         6 => return b"SSL_ERROR_ZERO_RETURN\0" as *const u8 as *const libc::c_char,
         7 => return b"SSL_ERROR_WANT_CONNECT\0" as *const u8 as *const libc::c_char,
         8 => return b"SSL_ERROR_WANT_ACCEPT\0" as *const u8 as *const libc::c_char,
         #[cfg(SSL_ERROR_WANT_ASYNC)]
         9 => return b"SSL_ERROR_WANT_ASYNC\0" as *const u8 as *const libc::c_char,
         #[cfg(SSL_ERROR_WANT_ASYNC_JOB)]
         10 => return b"SSL_ERROR_WANT_ASYNC_JOB\0" as *const u8 as *const libc::c_char,
         #[cfg(SSL_ERROR_WANT_EARLY)]
         11 => return b"SSL_ERROR_WANT_EARLY\0" as *const u8 as *const libc::c_char,
         _ => return b"SSL_ERROR unknown\0" as *const u8 as *const libc::c_char,
     };
 }
 /* Return error string for last OpenSSL error
  */
 extern "C" fn ossl_strerror(
     mut error: u64,
     mut buf: *mut libc::c_char,
     mut size: size_t,
 ) -> *mut libc::c_char {
     unsafe {
         if size != 0 {
             *buf = '\0' as libc::c_char;
         }
         // TODO - 351
         // #[cfg(OPENSSL_IS_BORINGSSL)]
         #[cfg(not(OPENSSL_IS_BORINGSSL))]
         ERR_error_string_n(error, buf, size);
         if size > 1 as u64 && *buf == 0 {
             strncpy(
                 buf,
                 if error != 0 {
                     b"Unknown error\0" as *const u8 as *const libc::c_char
                 } else {
                     b"No error\0" as *const u8 as *const libc::c_char
                 },
                 size,
             );
             *buf.offset(size.wrapping_sub(1 as u64) as isize) = '\0' as libc::c_char;
         }
     }
     return buf;
 }
 /* Return an extra data index for the transfer data.
  * This index can be used with SSL_get_ex_data() and SSL_set_ex_data().
  */
 extern "C" fn ossl_get_ssl_data_index() -> i32 {
     static mut ssl_ex_data_data_index: i32 = -(1 as i32);
     unsafe {
         if ssl_ex_data_data_index < 0 as i32 {
             ssl_ex_data_data_index = CRYPTO_get_ex_new_index(
                 0 as i32,
                 0 as i64,
                 0 as *mut libc::c_void,
                 None,
                 None,
                 None,
             );
         }
         return ssl_ex_data_data_index;
     }
 }
 /* Return an extra data index for the connection data.
  * This index can be used with SSL_get_ex_data() and SSL_set_ex_data().
  */
 extern "C" fn ossl_get_ssl_conn_index() -> i32 {
     static mut ssl_ex_data_conn_index: i32 = -(1 as i32);
     unsafe {
         if ssl_ex_data_conn_index < 0 as i32 {
             ssl_ex_data_conn_index = CRYPTO_get_ex_new_index(
                 0 as i32,
                 0 as i64,
                 0 as *mut libc::c_void,
                 None,
                 None,
                 None,
             );
         }
         return ssl_ex_data_conn_index;
     }
 }
 /* Return an extra data index for the sockindex.
  * This index can be used with SSL_get_ex_data() and SSL_set_ex_data().
  */
 extern "C" fn ossl_get_ssl_sockindex_index() -> i32 {
     static mut sockindex_index: i32 = -(1 as i32);
     unsafe {
         if sockindex_index < 0 as i32 {
             sockindex_index = CRYPTO_get_ex_new_index(
                 0 as i32,
                 0 as i64,
                 0 as *mut libc::c_void,
                 None,
                 None,
                 None,
             );
         }
         return sockindex_index;
     }
 }
 /* Return an extra data index for proxy boolean.
  * This index can be used with SSL_get_ex_data() and SSL_set_ex_data().
  */
 extern "C" fn ossl_get_proxy_index() -> i32 {
     static mut proxy_index: i32 = -(1 as i32);
     unsafe {
         if proxy_index < 0 as i32 {
             proxy_index = CRYPTO_get_ex_new_index(
                 0 as i32,
                 0 as i64,
                 0 as *mut libc::c_void,
                 None,
                 None,
                 None,
             );
         }
         return proxy_index;
     }
 }
 
 extern "C" fn passwd_callback(
     mut buf: *mut libc::c_char,
     mut num: i32,
     mut encrypting: i32,
     mut global_passwd: *mut libc::c_void,
 ) -> i32 {
     #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
     if 0 as i32 == encrypting {
     } else {
         unsafe {
             __assert_fail(
                 b"0 == encrypting\0" as *const u8 as *const libc::c_char,
                 b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                 416 as u32,
                 (*::std::mem::transmute::<&[u8; 46], &[libc::c_char; 46]>(
                     b"int passwd_callback(char *, int, int, void *)\0",
                 ))
                 .as_ptr(),
             );
         }
     }
     if encrypting == 0 {
         let mut klen: i32 = unsafe { curlx_uztosi(strlen(global_passwd as *mut libc::c_char)) };
         if num > klen {
             unsafe {
                 memcpy(
                     buf as *mut libc::c_void,
                     global_passwd,
                     (klen + 1 as i32) as u64,
                 );
             }
             return klen;
         }
     }
     return 0 as i32;
 }
 extern "C" fn rand_enough() -> bool {
     return if 0 as i32 != unsafe { RAND_status() } {
         1 as i32
     } else {
         0 as i32
     } != 0;
 }
 extern "C" fn ossl_seed(mut data: *mut Curl_easy) -> CURLcode {
     let mut fname: [libc::c_char; 256] = [0; 256];
     /* This might get called before it has been added to a multi handle */
     if unsafe { !((*data).multi).is_null() && (*(*data).multi).ssl_seeded as i32 != 0 } {
         return CURLE_OK;
     }
     if rand_enough() {
         if unsafe { !((*data).multi).is_null() } {
             unsafe {
                 (*(*data).multi).ssl_seeded = 1 as i32 != 0;
             }
         }
         return CURLE_OK;
     }
     // TODO - 451 - 选项 RANDOM_FILE
     unsafe {
         RAND_load_file(
             if !((*data).set.str_0[STRING_SSL_RANDOM_FILE as usize]).is_null() {
                 (*data).set.str_0[STRING_SSL_RANDOM_FILE as usize] as *const libc::c_char
             } else {
                 b"/dev/urandom\0" as *const u8 as *const libc::c_char
             },
             1024 as i64,
         );
     }
     if rand_enough() {
         return CURLE_OK;
     }
 
     /* fallback to a custom seeding of the PRNG using a hash based on a current
     time */
     // TODO - 467 有一段if的条件编译
     // #[cfg(HAVE_RAND_EGD)]
     loop {
         let mut randb: [u8; 64] = [0; 64];
         let mut len: size_t = ::std::mem::size_of::<[u8; 64]>() as u64;
         let mut i: size_t = 0;
         let mut i_max: size_t = 0;
         i = 0 as size_t;
         i_max = len.wrapping_div(::std::mem::size_of::<curltime>() as u64);
         while i < i_max {
             let mut tv: curltime = unsafe { Curl_now() };
             unsafe {
                 Curl_wait_ms(1 as timediff_t);
             }
             tv.tv_sec = (tv.tv_sec as u64).wrapping_mul(i.wrapping_add(1 as u64)) as time_t;
             tv.tv_usec = (tv.tv_usec as u32).wrapping_mul((i as u32).wrapping_add(2 as u32)) as i32;
             unsafe {
                 tv.tv_sec = (tv.tv_sec as u64
                     ^ (((Curl_now()).tv_sec + (Curl_now()).tv_usec as i64) as u64)
                         .wrapping_mul(i.wrapping_add(3 as u64))
                         << 8 as i32) as time_t;
                 tv.tv_usec = (tv.tv_usec as u32
                     ^ ((((Curl_now()).tv_sec + (Curl_now()).tv_usec as i64) as u64)
                         .wrapping_mul(i.wrapping_add(4 as u64)) as u32)
                         << 16 as i32) as i32;
                 memcpy(
                     &mut *randb
                         .as_mut_ptr()
                         .offset(i.wrapping_mul(::std::mem::size_of::<curltime>() as u64) as isize)
                         as *mut u8 as *mut libc::c_void,
                     &mut tv as *mut curltime as *const libc::c_void,
                     ::std::mem::size_of::<curltime>() as u64,
                 );
             }
             i = i.wrapping_add(1);
         }
         unsafe {
             RAND_add(
                 randb.as_mut_ptr() as *const libc::c_void,
                 len as i32,
                 len as libc::c_double / 2 as libc::c_double,
             );
         }
         if rand_enough() {
             break;
         }
     }
     /* generates a default path for the random seed file */
     fname[0 as usize] = 0 as libc::c_char; /* blank it first */
     unsafe {
         RAND_file_name(
             fname.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
         );
     }
     if fname[0 as usize] != 0 {
         /* we got a file name to try */
         unsafe {
             RAND_load_file(fname.as_mut_ptr(), 1024 as i64);
         }
         if rand_enough() {
             return CURLE_OK;
         }
     }
     unsafe {
         Curl_infof(
             data,
             b"libcurl is now using a weak random seed!\0" as *const u8 as *const libc::c_char,
         );
     }
     return (if rand_enough() as i32 != 0 {
         CURLE_OK as i32
     } else {
         CURLE_SSL_CONNECT_ERROR as i32
     }) as CURLcode;
 }
 
 extern "C" fn do_file_type(mut type_0: *const libc::c_char) -> i32 {
     unsafe {
         if type_0.is_null() || *type_0.offset(0 as isize) == 0 {
             return 1 as i32;
         }
         if Curl_strcasecompare(type_0, b"PEM\0" as *const u8 as *const libc::c_char) != 0 {
             return 1 as i32;
         }
         if Curl_strcasecompare(type_0, b"DER\0" as *const u8 as *const libc::c_char) != 0 {
             return 2 as i32;
         }
         if Curl_strcasecompare(type_0, b"ENG\0" as *const u8 as *const libc::c_char) != 0 {
             return 42 as i32;
         }
         if Curl_strcasecompare(type_0, b"P12\0" as *const u8 as *const libc::c_char) != 0 {
             return 43 as i32;
         }
         return -(1 as i32);
     }
 }
 
 /*
  * Supply default password to the engine user interface conversation.
  * The password is passed by OpenSSL engine from ENGINE_load_private_key()
  * last argument to the ui and can be obtained by UI_get0_user_data(ui) here.
  */
 #[cfg(USE_OPENSSL_ENGINE)]
 extern "C" fn ssl_ui_reader(mut ui: *mut UI, mut uis: *mut UI_STRING) -> i32 {
     let mut password: *const libc::c_char = 0 as *const libc::c_char;
     match unsafe { UI_get_string_type(uis) as u32 } {
         1 | 2 => {
             password = unsafe { UI_get0_user_data(ui) as *const libc::c_char };
             if !password.is_null() && unsafe { UI_get_input_flags(uis) & 0x2 as i32 != 0 } {
                 unsafe {
                     UI_set_result(ui, uis, password);
                 }
                 return 1 as i32;
             }
         }
         _ => {}
     }
     return unsafe {
         (UI_method_get_reader(UI_OpenSSL())).expect("non-null function pointer")(ui, uis)
     };
 }
 
 /*
  * Suppress interactive request for a default password if available.
  */
 #[cfg(USE_OPENSSL_ENGINE)]
 extern "C" fn ssl_ui_writer(mut ui: *mut UI, mut uis: *mut UI_STRING) -> i32 {
     unsafe {
         match UI_get_string_type(uis) as u32 {
             1 | 2 => {
                 if !(UI_get0_user_data(ui)).is_null() && UI_get_input_flags(uis) & 0x2 as i32 != 0 {
                     return 1 as i32;
                 }
             }
             _ => {}
         }
         return (UI_method_get_writer(UI_OpenSSL())).expect("non-null function pointer")(ui, uis);
     }
 }
 
 /*
  * Check if a given string is a PKCS#11 URI
  */
 #[cfg(USE_OPENSSL_ENGINE)]
 extern "C" fn is_pkcs11_uri(mut string: *const libc::c_char) -> bool {
     unsafe {
         return !string.is_null()
             && Curl_strncasecompare(
                 string,
                 b"pkcs11:\0" as *const u8 as *const libc::c_char,
                 7 as size_t,
             ) != 0;
     }
 }
 extern "C" fn SSL_CTX_use_certificate_blob(
     mut ctx: *mut SSL_CTX,
     mut blob: *const curl_blob,
     mut type_0: i32,
     mut key_passwd: *const libc::c_char,
 ) -> i32 {
     let mut current_block: u64;
     let mut ret: i32 = 0 as i32;
     let mut x: *mut X509 = 0 as *mut X509;
     /* the typecast of blob->len is fine since it is guaranteed to never be
     larger than CURL_MAX_INPUT_LENGTH */
     let mut in_0: *mut BIO = unsafe { BIO_new_mem_buf((*blob).data, (*blob).len as i32) };
     if in_0.is_null() {
         return CURLE_OUT_OF_MEMORY as i32;
     }
     'end: loop {
         if type_0 == 2 as i32 {
             /* j = ERR_R_ASN1_LIB; */
             x = unsafe { d2i_X509_bio(in_0, 0 as *mut *mut X509) };
         } else if type_0 == 1 as i32 {
             /* ERR_R_PEM_LIB; */
             x = unsafe {
                 PEM_read_bio_X509(
                     in_0,
                     0 as *mut *mut X509,
                     Some(
                         passwd_callback
                             as unsafe extern "C" fn(
                                 *mut libc::c_char,
                                 i32,
                                 i32,
                                 *mut libc::c_void,
                             ) -> i32,
                     ),
                     key_passwd as *mut libc::c_void,
                 )
             };
         } else {
             ret = 0 as i32;
             break 'end;
         }
         if x.is_null() {
             ret = 0 as i32;
             break 'end;
         }
         ret = unsafe { SSL_CTX_use_certificate(ctx, x) };
         break 'end;
     }
     unsafe {
         X509_free(x);
         BIO_free(in_0);
     }
     return ret;
 }
 
 extern "C" fn SSL_CTX_use_PrivateKey_blob(
     mut ctx: *mut SSL_CTX,
     mut blob: *const curl_blob,
     mut type_0: i32,
     mut key_passwd: *const libc::c_char,
 ) -> i32 {
     /* SSL_CTX_add1_chain_cert introduced in OpenSSL 1.0.2 */
     let mut current_block: u64;
     let mut ret: i32 = 0 as i32;
     let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
     let mut in_0: *mut BIO = unsafe { BIO_new_mem_buf((*blob).data, (*blob).len as i32) };
     if in_0.is_null() {
         return CURLE_OUT_OF_MEMORY as i32;
     }
     'end: loop {
         if type_0 == 1 as i32 {
             pkey = unsafe {
                 PEM_read_bio_PrivateKey(
                     in_0,
                     0 as *mut *mut EVP_PKEY,
                     Some(
                         passwd_callback
                             as unsafe extern "C" fn(
                                 *mut libc::c_char,
                                 i32,
                                 i32,
                                 *mut libc::c_void,
                             ) -> i32,
                     ),
                     key_passwd as *mut libc::c_void,
                 )
             };
         } else if type_0 == 2 as i32 {
             pkey = unsafe { d2i_PrivateKey_bio(in_0, 0 as *mut *mut EVP_PKEY) };
         } else {
             ret = 0 as i32;
             break 'end;
         }
         if pkey.is_null() {
             ret = 0 as i32;
             break 'end;
         }
         unsafe {
             ret = SSL_CTX_use_PrivateKey(ctx, pkey);
             EVP_PKEY_free(pkey);
         }
         break 'end;
     }
     unsafe {
         BIO_free(in_0);
     }
     return ret;
 }
 extern "C" fn SSL_CTX_use_certificate_chain_blob(
     mut ctx: *mut SSL_CTX,
     mut blob: *const curl_blob,
     mut key_passwd: *const libc::c_char,
 ) -> i32 {
     /* SSL_CTX_add1_chain_cert introduced in OpenSSL 1.0.2 */
     // TODO - 672 与OPENSSL_VERSION_NUMBER有关的条件编译
     let mut current_block: u64;
     let mut ret: i32 = 0 as i32;
     let mut x: *mut X509 = 0 as *mut X509;
     let mut passwd_callback_userdata: *mut libc::c_void = key_passwd as *mut libc::c_void;
     let mut in_0: *mut BIO = unsafe { BIO_new_mem_buf((*blob).data, (*blob).len as i32) };
     if in_0.is_null() {
         return CURLE_OUT_OF_MEMORY as i32;
     }
     unsafe {
         ERR_clear_error();
         x = PEM_read_bio_X509_AUX(
             in_0,
             0 as *mut *mut X509,
             Some(
                 passwd_callback
                     as unsafe extern "C" fn(*mut libc::c_char, i32, i32, *mut libc::c_void) -> i32,
             ),
             key_passwd as *mut libc::c_void,
         );
     }
     'end: loop {
         if x.is_null() {
             ret = 0 as i32;
             break 'end;
         }
         ret = unsafe { SSL_CTX_use_certificate(ctx, x) };
         if unsafe { ERR_peek_error() } != 0 as u64 {
             ret = 0 as i32;
         }
         if ret != 0 {
             let mut ca: *mut X509 = 0 as *mut X509;
             let mut err: u64 = 0;
             if unsafe {
                 SSL_CTX_ctrl(
                     ctx,
                     88 as i32,
                     0 as i64,
                     0 as *mut libc::c_void as *mut libc::c_char as *mut libc::c_void,
                 )
             } == 0
             {
                 ret = 0 as i32;
                 break 'end;
             }
             loop {
                 ca = unsafe {
                     PEM_read_bio_X509(
                         in_0,
                         0 as *mut *mut X509,
                         Some(
                             passwd_callback
                                 as unsafe extern "C" fn(
                                     *mut libc::c_char,
                                     i32,
                                     i32,
                                     *mut libc::c_void,
                                 ) -> i32,
                         ),
                         passwd_callback_userdata,
                     )
                 };
                 if ca.is_null() {
                     break;
                 }
                 if unsafe {
                     SSL_CTX_ctrl(
                         ctx,
                         89 as i32,
                         0 as i64,
                         ca as *mut libc::c_char as *mut libc::c_void,
                     )
                 } == 0
                 {
                     unsafe {
                         X509_free(ca);
                     }
                     ret = 0 as i32;
                     break 'end;
                 }
             }
             err = unsafe { ERR_peek_last_error() };
             if (err >> 24 as i64 & 0xff as u64) as i32 == 9 as i32
                 && (err & 0xfff as u64) as i32 == 108 as i32
             {
                 unsafe { ERR_clear_error() };
             } else {
                 ret = 0 as i32;
             }
         }
         break 'end;
     }
     unsafe {
         X509_free(x);
         BIO_free(in_0);
     }
     return ret;
 }
 
 extern "C" fn cert_stuff(
     mut data: *mut Curl_easy,
     mut ctx: *mut SSL_CTX,
     mut cert_file: *mut libc::c_char,
     mut cert_blob: *const curl_blob,
     mut cert_type: *const libc::c_char,
     mut key_file: *mut libc::c_char,
     mut key_blob: *const curl_blob,
     mut key_type: *const libc::c_char,
     mut key_passwd: *mut libc::c_char,
 ) -> i32 {
     let mut current_block: u64;
     let mut error_buffer: [libc::c_char; 256] = [0; 256];
     let mut check_privkey: bool = 1 as i32 != 0;
     let mut file_type: i32 = do_file_type(cert_type);
     if !cert_file.is_null() || !cert_blob.is_null() || file_type == 42 as i32 {
         let mut ssl: *mut SSL = 0 as *mut SSL;
         let mut x509: *mut X509 = 0 as *mut X509;
         let mut cert_done: i32 = 0 as i32;
         let mut cert_use_result: i32 = 0;
         if !key_passwd.is_null() {
             /* set the password in the callback userdata */
             unsafe {
                 SSL_CTX_set_default_passwd_cb_userdata(ctx, key_passwd as *mut libc::c_void);
                 /* Set passwd callback: */
                 SSL_CTX_set_default_passwd_cb(
                     ctx,
                     Some(
                         passwd_callback
                             as unsafe extern "C" fn(
                                 *mut libc::c_char,
                                 i32,
                                 i32,
                                 *mut libc::c_void,
                             ) -> i32,
                     ),
                 );
             }
         }
 
         match file_type {
             1 => {
                 /* SSL_CTX_use_certificate_chain_file() only works on PEM files */
                 cert_use_result = if !cert_blob.is_null() {
                     SSL_CTX_use_certificate_chain_blob(ctx, cert_blob, key_passwd)
                 } else {
                     unsafe { SSL_CTX_use_certificate_chain_file(ctx, cert_file) }
                 };
                 if cert_use_result != 1 as i32 {
                     unsafe {
                         Curl_failf(
                              data,
                              b"could not load PEM client certificate, OpenSSL error %s, (no key found, wrong pass phrase, or wrong file format?)\0"
                                  as *const u8 as *const libc::c_char,
                              ossl_strerror(
                                  ERR_get_error(),
                                  error_buffer.as_mut_ptr(),
                                  ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                              ),
                          );
                     }
                     return 0 as i32;
                 }
             }
             2 => {
                 /* SSL_CTX_use_certificate_file() works with either PEM or ASN1, but
                 we use the case above for PEM so this can only be performed with
                 ASN1 files. */
                 cert_use_result = if !cert_blob.is_null() {
                     SSL_CTX_use_certificate_blob(ctx, cert_blob, file_type, key_passwd)
                 } else {
                     unsafe { SSL_CTX_use_certificate_file(ctx, cert_file, file_type) }
                 };
                 if cert_use_result != 1 as i32 {
                     unsafe {
                         Curl_failf(
                              data,
                              b"could not load ASN1 client certificate, OpenSSL error %s, (no key found, wrong pass phrase, or wrong file format?)\0"
                                  as *const u8 as *const libc::c_char,
                              ossl_strerror(
                                  ERR_get_error(),
                                  error_buffer.as_mut_ptr(),
                                  ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                              ),
                          );
                     }
                     return 0 as i32;
                 }
             }
             // DONE - 804
             42 => {
                 unsafe {
                     /* Implicitly use pkcs11 engine if none was provided and the
                      * cert_file is a PKCS#11 URI */
                     #[cfg(all(USE_OPENSSL_ENGINE, ENGINE_CTRL_GET_CMD_FROM_NAME))]
                     if ((*data).state.engine).is_null() {
                         if is_pkcs11_uri(cert_file) {
                             if ossl_set_engine(
                                 data,
                                 b"pkcs11\0" as *const u8 as *const libc::c_char,
                             ) as u32
                                 != CURLE_OK as u32
                             {
                                 return 0 as i32;
                             }
                         }
                     }
                     #[cfg(all(USE_OPENSSL_ENGINE, ENGINE_CTRL_GET_CMD_FROM_NAME))]
                     if !((*data).state.engine).is_null() {
                         let mut cmd_name: *const libc::c_char =
                             b"LOAD_CERT_CTRL\0" as *const u8 as *const libc::c_char;
                         let mut params: C2RustUnnamed_13 = C2RustUnnamed_13 {
                             cert_id: 0 as *const libc::c_char,
                             cert: 0 as *mut X509,
                         };
                         params.cert_id = cert_file;
                         params.cert = 0 as *mut X509;
                         /* Does the engine supports LOAD_CERT_CTRL ? */
                         if ENGINE_ctrl(
                             (*data).state.engine as *mut ENGINE,
                             13 as i32,
                             0 as i64,
                             cmd_name as *mut libc::c_void,
                             None,
                         ) == 0
                         {
                             Curl_failf(
                                 data,
                                 b"ssl engine does not support loading certificates\0" as *const u8
                                     as *const libc::c_char,
                             );
                             return 0 as i32;
                         }
                         /* Load the certificate from the engine */
                         if ENGINE_ctrl_cmd(
                             (*data).state.engine as *mut ENGINE,
                             cmd_name,
                             0 as i64,
                             &mut params as *mut C2RustUnnamed_13 as *mut libc::c_void,
                             None,
                             1 as i32,
                         ) == 0
                         {
                             Curl_failf(
                                 data,
                                 b"ssl engine cannot load client cert with id '%s' [%s]\0"
                                     as *const u8
                                     as *const libc::c_char,
                                 cert_file,
                                 ossl_strerror(
                                     ERR_get_error(),
                                     error_buffer.as_mut_ptr(),
                                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                                 ),
                             );
                             return 0 as i32;
                         }
                         if (params.cert).is_null() {
                             Curl_failf(
                                 data,
                                 b"ssl engine didn't initialized the certificate properly.\0"
                                     as *const u8
                                     as *const libc::c_char,
                             );
                             return 0 as i32;
                         }
                         if SSL_CTX_use_certificate(ctx, params.cert) != 1 as i32 {
                             Curl_failf(
                                 data,
                                 b"unable to set client certificate\0" as *const u8
                                     as *const libc::c_char,
                             );
                             X509_free(params.cert);
                             return 0 as i32;
                         }
                         X509_free(params.cert); /* we don't need the handle any more... */
                     } else {
                         Curl_failf(
                             data,
                             b"crypto engine not set, can't load certificate\0" as *const u8
                                 as *const libc::c_char,
                         );
                         return 0 as i32;
                     }
                     #[cfg(any(not(USE_OPENSSL_ENGINE), not(ENGINE_CTRL_GET_CMD_FROM_NAME)))]
                     Curl_failf(
                         data,
                         b"file type ENG for certificate not implemented" as *const u8
                             as *const libc::c_char,
                     );
                 }
                 #[cfg(any(not(USE_OPENSSL_ENGINE), not(ENGINE_CTRL_GET_CMD_FROM_NAME)))]
                 return 0 as i32;
             }
             43 => {
                 let mut cert_bio: *mut BIO = 0 as *mut BIO;
                 let mut p12: *mut PKCS12 = 0 as *mut PKCS12;
                 let mut pri: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
                 let mut ca: *mut stack_st_X509 = 0 as *mut stack_st_X509;
                 if !cert_blob.is_null() {
                     unsafe {
                         cert_bio = BIO_new_mem_buf((*cert_blob).data, (*cert_blob).len as i32);
                         if cert_bio.is_null() {
                             Curl_failf(
                                 data,
                                 b"BIO_new_mem_buf NULL, OpenSSL error %s\0" as *const u8
                                     as *const libc::c_char,
                                 ossl_strerror(
                                     ERR_get_error(),
                                     error_buffer.as_mut_ptr(),
                                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                                 ),
                             );
                         }
                         return 0 as i32;
                     }
                 } else {
                     unsafe {
                         cert_bio = BIO_new(BIO_s_file());
                         if cert_bio.is_null() {
                             Curl_failf(
                                 data,
                                 b"BIO_new return NULL, OpenSSL error %s\0" as *const u8
                                     as *const libc::c_char,
                                 ossl_strerror(
                                     ERR_get_error(),
                                     error_buffer.as_mut_ptr(),
                                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                                 ),
                             );
                             return 0 as i32;
                         }
                         if BIO_ctrl(
                             cert_bio,
                             108 as i32,
                             (0x1 as i32 | 0x2 as i32) as i64,
                             cert_file as *mut libc::c_void,
                         ) as i32
                             <= 0 as i32
                         {
                             Curl_failf(
                                 data,
                                 b"could not open PKCS12 file '%s'\0" as *const u8
                                     as *const libc::c_char,
                                 cert_file,
                             );
                             BIO_free(cert_bio);
                             return 0 as i32;
                         }
                     }
                 }
                 unsafe {
                     p12 = d2i_PKCS12_bio(cert_bio, 0 as *mut *mut PKCS12);
                     BIO_free(cert_bio);
                     if p12.is_null() {
                         Curl_failf(
                             data,
                             b"error reading PKCS12 file '%s'\0" as *const u8 as *const libc::c_char,
                             if !cert_blob.is_null() {
                                 b"(memory blob)\0" as *const u8 as *const libc::c_char
                             } else {
                                 cert_file as *const libc::c_char
                             },
                         );
                         return 0 as i32;
                     }
                     PKCS12_PBE_add();
                     if PKCS12_parse(p12, key_passwd, &mut pri, &mut x509, &mut ca) == 0 {
                         Curl_failf(
                             data,
                             b"could not parse PKCS12 file, check password, OpenSSL error %s\0"
                                 as *const u8 as *const libc::c_char,
                             ossl_strerror(
                                 ERR_get_error(),
                                 error_buffer.as_mut_ptr(),
                                 ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                             ),
                         );
                         PKCS12_free(p12);
                         return 0 as i32;
                     }
 
                     PKCS12_free(p12);
                 }
                 'fail: loop {
                     if unsafe { SSL_CTX_use_certificate(ctx, x509) } != 1 as i32 {
                         unsafe {
                             Curl_failf(
                                 data,
                                 b"could not load PKCS12 client certificate, OpenSSL error %s\0"
                                     as *const u8
                                     as *const libc::c_char,
                                 ossl_strerror(
                                     ERR_get_error(),
                                     error_buffer.as_mut_ptr(),
                                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                                 ),
                             );
                         }
                         break 'fail;
                     }
                     if unsafe { SSL_CTX_use_PrivateKey(ctx, pri) } != 1 as i32 {
                         unsafe {
                             Curl_failf(
                                 data,
                                 b"unable to use private key from PKCS12 file '%s'\0" as *const u8
                                     as *const libc::c_char,
                                 cert_file,
                             );
                         }
                         break 'fail;
                     }
                     if unsafe { SSL_CTX_check_private_key(ctx) } == 0 {
                         unsafe {
                             Curl_failf(
                             data,
                             b"private key from PKCS12 file '%s' does not match certificate in same file\0"
                                 as *const u8 as *const libc::c_char,
                             cert_file,
                         );
                         }
                         break 'fail;
                     }
                     /* Set Certificate Verification chain */
                     if !ca.is_null() {
                         while sk_X509_num(ca) != 0 {
                             /*
                              * Note that sk_X509_pop() is used below to make sure the cert is
                              * removed from the stack properly before getting passed to
                              * SSL_CTX_add_extra_chain_cert(), which takes ownership. Previously
                              * we used sk_X509_value() instead, but then we'd clean it in the
                              * subsequent sk_X509_pop_free() call.
                              */
                             let mut x: *mut X509 = sk_X509_pop(ca);
                             if unsafe { SSL_CTX_add_client_CA(ctx, x) } == 0 {
                                 unsafe {
                                     X509_free(x);
                                     Curl_failf(
                                         data,
                                         b"cannot add certificate to client CA list\0" as *const u8
                                             as *const libc::c_char,
                                     );
                                 }
                                 break 'fail;
                             }
                             if unsafe {
                                 SSL_CTX_ctrl(
                                     ctx,
                                     14 as i32,
                                     0 as i64,
                                     x as *mut libc::c_char as *mut libc::c_void,
                                 )
                             } == 0
                             {
                                 unsafe {
                                     X509_free(x);
                                     Curl_failf(
                                         data,
                                         b"cannot add certificate to certificate chain\0"
                                             as *const u8
                                             as *const libc::c_char,
                                     );
                                 }
                                 break 'fail;
                             }
                         }
                         break 'fail;
                     }
                     cert_done = 1 as i32;
                 }
                 unsafe {
                     EVP_PKEY_free(pri);
                     X509_free(x509);
 
                     #[cfg(USE_AMISSL)]
                     sk_X509_pop_free(
                         ca,
                         Some(Curl_amiga_X509_free as unsafe extern "C" fn(*mut X509) -> ()),
                     );
                     #[cfg(not(USE_AMISSL))]
                     sk_X509_pop_free(ca, Some(X509_free as unsafe extern "C" fn(*mut X509) -> ()));
                     if cert_done == 0 {
                         return 0 as i32;
                     }
                 }
             }
             _ => {
                 unsafe {
                     Curl_failf(
                         data,
                         b"not supported file type '%s' for certificate\0" as *const u8
                             as *const libc::c_char,
                         cert_type,
                     );
                 }
                 return 0 as i32;
             }
         }
         if key_file.is_null() && key_blob.is_null() {
             key_file = cert_file;
             key_blob = cert_blob;
         } else {
             file_type = do_file_type(key_type);
         }
         let mut current_block_141: u64;
         match file_type {
             1 => {
                 if cert_done != 0 {
                     current_block_141 = 14358540534591340610;
                 } else {
                     current_block_141 = 2766187242236248435;
                 }
             }
             2 => {
                 current_block_141 = 2766187242236248435;
             }
             // DONE - 1011
             42 => match () {
                 #[cfg(USE_OPENSSL_ENGINE)]
                 _ => {
                     /* XXXX still needs some work */
                     let mut priv_key: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
                     unsafe {
                         /* Implicitly use pkcs11 engine if none was provided and the
                          * key_file is a PKCS#11 URI */
                         if ((*data).state.engine).is_null() {
                             if is_pkcs11_uri(key_file) {
                                 if ossl_set_engine(
                                     data,
                                     b"pkcs11\0" as *const u8 as *const libc::c_char,
                                 ) as u32
                                     != CURLE_OK as u32
                                 {
                                     return 0 as i32;
                                 }
                             }
                         }
                         if !((*data).state.engine).is_null() {
                             let mut ui_method: *mut UI_METHOD = UI_create_method(
                                 b"curl user interface\0" as *const u8 as *const libc::c_char
                                     as *mut libc::c_char,
                             );
                             if ui_method.is_null() {
                                 Curl_failf(
                                     data,
                                     b"unable do create OpenSSL user-interface method\0" as *const u8
                                         as *const libc::c_char,
                                 );
                                 return 0 as i32;
                             }
                             UI_method_set_opener(ui_method, UI_method_get_opener(UI_OpenSSL()));
                             UI_method_set_closer(ui_method, UI_method_get_closer(UI_OpenSSL()));
                             UI_method_set_reader(
                                 ui_method,
                                 Some(
                                     ssl_ui_reader
                                         as unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> i32,
                                 ),
                             );
                             UI_method_set_writer(
                                 ui_method,
                                 Some(
                                     ssl_ui_writer
                                         as unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> i32,
                                 ),
                             );
                             /* the typecast below was added to please mingw32 */
                             priv_key = ENGINE_load_private_key(
                                 (*data).state.engine as *mut ENGINE,
                                 key_file,
                                 ui_method,
                                 key_passwd as *mut libc::c_void,
                             );
                             UI_destroy_method(ui_method);
                             if priv_key.is_null() {
                                 Curl_failf(
                                     data,
                                     b"failed to load private key from crypto engine\0" as *const u8
                                         as *const libc::c_char,
                                 );
                                 return 0 as i32;
                             }
                             if SSL_CTX_use_PrivateKey(ctx, priv_key) != 1 as i32 {
                                 Curl_failf(
                                     data,
                                     b"unable to set private key\0" as *const u8
                                         as *const libc::c_char,
                                 );
                                 EVP_PKEY_free(priv_key); /* we don't need the handle any more... */
                                 return 0 as i32;
                             }
                             EVP_PKEY_free(priv_key);
                         } else {
                             Curl_failf(
                                 data,
                                 b"crypto engine not set, can't load private key\0" as *const u8
                                     as *const libc::c_char,
                             );
 
                             return 0 as i32;
                         }
                         current_block_141 = 14358540534591340610;
                     }
                 }
                 #[cfg(not(USE_OPENSSL_ENGINE))]
                 _ => unsafe {
                     Curl_failf(
                         data,
                         b"file type ENG for private key not supported" as *const u8
                             as *const libc::c_char,
                     );
                     return 0 as i32;
                 },
             },
             43 => {
                 if cert_done == 0 {
                     unsafe {
                         Curl_failf(
                             data,
                             b"file type P12 for private key not supported\0" as *const u8
                                 as *const libc::c_char,
                         );
                     }
                     return 0 as i32;
                 }
                 current_block_141 = 14358540534591340610;
             }
             _ => {
                 unsafe {
                     Curl_failf(
                         data,
                         b"not supported file type for private key\0" as *const u8
                             as *const libc::c_char,
                     );
                 }
                 return 0 as i32;
             }
         }
         match current_block_141 {
             2766187242236248435 => {
                 cert_use_result = if !key_blob.is_null() {
                     SSL_CTX_use_PrivateKey_blob(ctx, key_blob, file_type, key_passwd)
                 } else {
                     unsafe { SSL_CTX_use_PrivateKey_file(ctx, key_file, file_type) }
                 };
                 if cert_use_result != 1 as i32 {
                     unsafe {
                         Curl_failf(
                             data,
                             b"unable to set private key file: '%s' type %s\0" as *const u8
                                 as *const libc::c_char,
                             if !key_file.is_null() {
                                 key_file as *const libc::c_char
                             } else {
                                 b"(memory blob)\0" as *const u8 as *const libc::c_char
                             },
                             if !key_type.is_null() {
                                 key_type
                             } else {
                                 b"PEM\0" as *const u8 as *const libc::c_char
                             },
                         );
                     }
                     return 0 as i32;
                 }
             }
             _ => {}
         }
         unsafe {
             ssl = SSL_new(ctx);
             if ssl.is_null() {
                 Curl_failf(
                     data,
                     b"unable to create an SSL structure\0" as *const u8 as *const libc::c_char,
                 );
                 return 0 as i32;
             }
             x509 = SSL_get_certificate(ssl);
         }
         /* This version was provided by Evan Jordan and is supposed to not
         leak memory as the previous version: */
         if !x509.is_null() {
             unsafe {
                 let mut pktmp: *mut EVP_PKEY = X509_get_pubkey(x509);
                 EVP_PKEY_copy_parameters(pktmp, SSL_get_privatekey(ssl));
                 EVP_PKEY_free(pktmp);
             }
         }
         #[cfg(all(not(OPENSSL_NO_RSA), not(OPENSSL_IS_BORINGSSL)))]
         let mut priv_key_0: *mut EVP_PKEY = unsafe { SSL_get_privatekey(ssl) };
 
         #[cfg(all(
             not(OPENSSL_NO_RSA),
             not(OPENSSL_IS_BORINGSSL),
             not(HAVE_OPAQUE_EVP_PKEY)
         ))]
         // TODO 未开的情况下不是 = 0，是另一种情况
         let mut pktype: i32 = 0;
         #[cfg(all(not(OPENSSL_NO_RSA), not(OPENSSL_IS_BORINGSSL), HAVE_OPAQUE_EVP_PKEY))]
         let mut pktype: i32 = EVP_PKEY_id(priv_key_0);
         // TODO - 不开HAVE_OPAQUE_EVP_PKEY选项
         // #[cfg(all(not(OPENSSL_NO_RSA), not(OPENSSL_IS_BORINGSSL), not(HAVE_OPAQUE_EVP_PKEY)))]
         #[cfg(all(not(OPENSSL_NO_RSA), not(OPENSSL_IS_BORINGSSL)))]
         if pktype == 6 as i32 {
             let mut rsa: *mut RSA = unsafe { EVP_PKEY_get1_RSA(priv_key_0) };
             unsafe {
                 if RSA_flags(rsa) & 0x1 as i32 != 0 {
                     check_privkey = 0 as i32 != 0;
                 }
                 RSA_free(rsa); /* Decrement reference count */
             }
         }
         unsafe {
             SSL_free(ssl);
         }
         /* If we are using DSA, we can copy the parameters from
          * the private key */
         if check_privkey as i32 == 1 as i32 {
             /* Now we know that a key and cert have been set against
              * the SSL context */
             if unsafe { SSL_CTX_check_private_key(ctx) == 0 } {
                 unsafe {
                     Curl_failf(
                         data,
                         b"Private key does not match the certificate public key\0" as *const u8
                             as *const libc::c_char,
                     );
                 }
                 return 0 as i32;
             }
         }
     }
     return 1 as i32;
 }
 
 /* returns non-zero on failure */
 extern "C" fn x509_name_oneline(
     mut a: *mut X509_NAME,
     mut buf: *mut libc::c_char,
     mut size: size_t,
 ) -> i32 {
     let mut bio_out: *mut BIO = unsafe { BIO_new(BIO_s_mem()) };
     let mut biomem: *mut BUF_MEM = 0 as *mut BUF_MEM;
     let mut rc: i32 = 0;
     if bio_out.is_null() {
         return 1 as i32; /* alloc failed! */
     }
     rc = unsafe { X509_NAME_print_ex(bio_out, a, 0 as i32, ((3 as i32) << 16 as i32) as u64) };
     unsafe {
         BIO_ctrl(
             bio_out,
             115 as i32,
             0 as i64,
             &mut biomem as *mut *mut BUF_MEM as *mut libc::c_char as *mut libc::c_void,
         );
         if (*biomem).length < size {
             size = (*biomem).length;
         } else {
             size = size.wrapping_sub(1); /* don't overwrite the buffer end */
         }
         memcpy(
             buf as *mut libc::c_void,
             (*biomem).data as *const libc::c_void,
             size,
         );
         *buf.offset(size as isize) = 0 as libc::c_char;
         BIO_free(bio_out);
     }
     return (rc == 0) as i32;
 }
 
 /**
  * Global SSL init
  *
  * @retval 0 error initializing SSL
  * @retval 1 SSL initialized successfully
  */
 extern "C" fn ossl_init() -> i32 {
     #[cfg(OPENSSL_INIT_ENGINE_ALL_BUILTIN)]
     let flag_1 = 0x200 as i64 | 0x400 as i64 | 0x1000 as i64 | 0x2000 as i64 | 0x4000 as i64;
     #[cfg(not(OPENSSL_INIT_ENGINE_ALL_BUILTIN))]
     let flag_1 = 0x0000 as i64;
     #[cfg(CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG)]
     let flag_2 = 0x80 as i64;
     #[cfg(not(CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG))]
     let flag_2 = 0x40 as i64;
     let flags: uint64_t = (flag_1 | flag_2 | 0 as i64) as uint64_t;
 
     unsafe {
         OPENSSL_init_ssl(flags, 0 as *const OPENSSL_INIT_SETTINGS);
     }
     Curl_tls_keylog_open();
     /* Initialize the extra data indexes */
     if ossl_get_ssl_data_index() < 0 as i32
         || ossl_get_ssl_conn_index() < 0 as i32
         || ossl_get_ssl_sockindex_index() < 0 as i32
         || ossl_get_proxy_index() < 0 as i32
     {
         return 0 as i32;
     }
     return 1 as i32;
 }
 
 /* Global cleanup */
 extern "C" fn ossl_cleanup() {
     Curl_tls_keylog_close();
 }
 
 /*
  * This function is used to determine connection status.
  *
  * Return codes:
  *     1 means the connection is still in place
  *     0 means the connection has been closed
  *    -1 means the connection status is unknown
  */
 extern "C" fn ossl_check_cxn(mut conn: *mut connectdata) -> i32 {
     /* SSL_peek takes data out of the raw recv buffer without peeking so we use
     recv MSG_PEEK instead. Bug #795 */
     #[cfg(MSG_PEEK)]
     let mut buf: libc::c_char = 0;
     #[cfg(MSG_PEEK)]
     let mut nread: ssize_t = recv(
         (*conn).sock[0 as usize],
         &mut buf as *mut libc::c_char as *mut libc::c_void,
         1 as size_t,
         MSG_PEEK as i32,
     );
     #[cfg(MSG_PEEK)]
     if nread == 0 as i64 {
         return 0 as i32; /* connection has been closed */
     }
     #[cfg(MSG_PEEK)]
     if nread == 1 as i64 {
         return 1 as i32; /* connection still in place */
     } else {
         if nread == -(1 as i32) as i64 {
             let mut err: i32 = *__errno_location();
             // 写法不对，rust中如何判断宏值的相等
             // TODO - 1276
             if err == 115 as i32 || err == 11 as i32 {
                 return 1 as i32; /* connection still in place */
             }
             // DONE - 1282
             #[cfg(ECONNABORTED)]
             let ECONNABORTED_flag = err == 103;
             #[cfg(not(ECONNABORTED))]
             let ECONNABORTED_flag = false;
             #[cfg(ENETDOWN)]
             let ENETDOWN_flag = err == 100;
             #[cfg(not(ENETDOWN))]
             let ENETDOWN_flag = false;
             #[cfg(ENETRESET)]
             let ENETRESET_flag = err == 102;
             #[cfg(not(ENETRESET))]
             let ENETRESET_flag = false;
             #[cfg(ESHUTDOWN)]
             let ESHUTDOWN_flag = err == 108;
             #[cfg(not(ESHUTDOWN))]
             let ESHUTDOWN_flag = false;
             #[cfg(ETIMEDOUT)]
             let ETIMEDOUT_flag = err == 110;
             #[cfg(not(ETIMEDOUT))]
             let ETIMEDOUT_flag = false;
             if err == 104 as i32
                 || ECONNABORTED_flag
                 || ENETDOWN_flag
                 || ENETRESET_flag
                 || ENETDOWN_flag
                 || ETIMEDOUT_flag
                 || err == 107 as i32
             {
                 return 0 as i32; /* connection has been closed */
             }
         }
     }
     return -(1 as i32); /* connection status unknown */
 }
 
 /* Selects an OpenSSL crypto engine
  */
 extern "C" fn ossl_set_engine(
     mut data: *mut Curl_easy,
     mut engine: *const libc::c_char,
 ) -> CURLcode {
     if cfg!(USE_OPENSSL_ENGINE) {
         let mut e: *mut ENGINE = 0 as *mut ENGINE;
         e = unsafe { ENGINE_by_id(engine) };
         if e.is_null() {
             unsafe {
                 Curl_failf(
                     data,
                     b"SSL Engine '%s' not found\0" as *const u8 as *const libc::c_char,
                     engine,
                 );
             }
             return CURLE_SSL_ENGINE_NOTFOUND;
         }
         unsafe {
             if !((*data).state.engine).is_null() {
                 ENGINE_finish((*data).state.engine as *mut ENGINE);
                 ENGINE_free((*data).state.engine as *mut ENGINE);
                 (*data).state.engine = 0 as *mut libc::c_void;
             }
             if ENGINE_init(e) == 0 {
                 let mut buf: [libc::c_char; 256] = [0; 256];
                 ENGINE_free(e);
                 Curl_failf(
                     data,
                     b"Failed to initialise SSL Engine '%s': %s\0" as *const u8
                         as *const libc::c_char,
                     engine,
                     ossl_strerror(
                         ERR_get_error(),
                         buf.as_mut_ptr(),
                         ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                     ),
                 );
                 return CURLE_SSL_ENGINE_INITFAILED;
             }
             (*data).state.engine = e as *mut libc::c_void;
         }
         return CURLE_OK;
     } else {
         unsafe {
             Curl_infof(
                 data,
                 b"SSL Engine not supported\0" as *const u8 as *const libc::c_char,
             );
         }
         return CURLE_SSL_ENGINE_NOTFOUND;
     }
 }
 
 /* Sets engine as default for all SSL operations
  */
 extern "C" fn ossl_set_engine_default(mut data: *mut Curl_easy) -> CURLcode {
     if cfg!(USE_OPENSSL_ENGINE) {
         unsafe {
             if !((*data).state.engine).is_null() {
                 if ENGINE_set_default((*data).state.engine as *mut ENGINE, 0xffff as i32 as u32)
                     > 0 as i32
                 {
                     Curl_infof(
                         data,
                         b"set default crypto engine '%s'\0" as *const u8 as *const libc::c_char,
                         ENGINE_get_id((*data).state.engine as *const ENGINE),
                     );
                 } else {
                     Curl_failf(
                         data,
                         b"set default crypto engine '%s' failed\0" as *const u8
                             as *const libc::c_char,
                         ENGINE_get_id((*data).state.engine as *const ENGINE),
                     );
                     return CURLE_SSL_ENGINE_SETFAILED;
                 }
             }
         }
     }
     return CURLE_OK;
 }
 
 /* Return list of OpenSSL crypto engine names.
  */
 extern "C" fn ossl_engines_list(mut data: *mut Curl_easy) -> *mut curl_slist {
     let mut list: *mut curl_slist = 0 as *mut curl_slist;
     if cfg!(USE_OPENSSL_ENGINE) {
         let mut beg: *mut curl_slist = 0 as *mut curl_slist;
         let mut e: *mut ENGINE = 0 as *mut ENGINE;
         e = unsafe { ENGINE_get_first() };
         while !e.is_null() {
             unsafe {
                 beg = curl_slist_append(list, ENGINE_get_id(e));
                 if beg.is_null() {
                     curl_slist_free_all(list);
                     return 0 as *mut curl_slist;
                 }
             }
             list = beg;
             e = unsafe { ENGINE_get_next(e) };
         }
     }
     return list;
 }
 extern "C" fn ossl_closeone(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut connssl: *mut ssl_connect_data,
 ) {
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     unsafe {
         if !((*backend).handle).is_null() {
             let mut buf: [libc::c_char; 32] = [0; 32];
             (*(*conn).ssl[0 as usize].backend).logger = data;
             /* Maybe the server has already sent a close notify alert.
             Read it to avoid an RST on the TCP connection. */
             SSL_read(
                 (*backend).handle,
                 buf.as_mut_ptr() as *mut libc::c_void,
                 ::std::mem::size_of::<[libc::c_char; 32]>() as i32,
             );
             SSL_shutdown((*backend).handle);
             SSL_set_connect_state((*backend).handle);
             SSL_free((*backend).handle);
             (*backend).handle = 0 as *mut SSL;
         }
         if !((*backend).ctx).is_null() {
             SSL_CTX_free((*backend).ctx);
             (*backend).ctx = 0 as *mut SSL_CTX;
         }
     }
 }
 
 /*
  * This function is called when an SSL connection is closed.
  */
 extern "C" fn ossl_close(mut data: *mut Curl_easy, mut conn: *mut connectdata, mut sockindex: i32) {
     unsafe {
         ossl_closeone(
             data,
             conn,
             &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize),
         );
         #[cfg(not(CURL_DISABLE_PROXY))]
         ossl_closeone(
             data,
             conn,
             &mut *((*conn).proxy_ssl).as_mut_ptr().offset(sockindex as isize),
         );
     }
 }
 
 /*
  * This function is called to shut down the SSL layer but keep the
  * socket open (CCC - Clear Command Channel)
  */
 extern "C" fn ossl_shutdown(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) -> i32 {
     let mut retval: i32 = 0 as i32;
     let mut connssl: *mut ssl_connect_data = unsafe {
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
     };
     let mut buf: [libc::c_char; 256] = [0; 256]; /* We will use this for the OpenSSL error buffer, so it has
                                                  to be at least 256 bytes long. */
     let mut sslerror: u64 = 0;
     let mut nread: ssize_t = 0;
     let mut buffsize: i32 = 0;
     let mut err: i32 = 0;
     let mut done: bool = 0 as i32 != 0;
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     let mut loop_0: i32 = 10 as i32;
     /* This has only been tested on the proftpd server, and the mod_tls code
     sends a close notify alert without waiting for a close notify alert in
     response. Thus we wait for a close notify alert from the server, but
     we do not send one. Let's hope other servers do the same... */
     #[cfg(not(CURL_DISABLE_FTP))]
     unsafe {
         if (*data).set.ftp_ccc as u32 == CURLFTPSSL_CCC_ACTIVE as u32 {
             SSL_shutdown((*backend).handle);
         }
     }
     if unsafe { !((*backend).handle).is_null() } {
         buffsize = ::std::mem::size_of::<[libc::c_char; 256]>() as i32;
         while !done && {
             let fresh5 = loop_0;
             loop_0 = loop_0 - 1;
             fresh5 != 0
         } {
             let mut what: i32 = unsafe {
                 Curl_socket_check(
                     (*conn).sock[sockindex as usize],
                     -(1 as i32),
                     -(1 as i32),
                     10000 as timediff_t,
                 )
             };
             if what > 0 as i32 {
                 /* Something to read, let's do it and hope that it is the close
                 notify alert from the server */
                 unsafe {
                     ERR_clear_error();
                     nread = SSL_read(
                         (*backend).handle,
                         buf.as_mut_ptr() as *mut libc::c_void,
                         buffsize,
                     ) as ssize_t;
                     err = SSL_get_error((*backend).handle, nread as i32);
                 }
                 match err {
                     0 | 6 => {
                         /* This is the expected response. There was no data but only
                         the close notify alert */
                         done = 1 as i32 != 0;
                     }
                     2 => unsafe {
                         Curl_infof(
                             data,
                             b"SSL_ERROR_WANT_READ\0" as *const u8 as *const libc::c_char,
                         );
                     },
                     3 => {
                         /* SSL wants a write. Really odd. Let's bail out. */
                         unsafe {
                             Curl_infof(
                                 data,
                                 b"SSL_ERROR_WANT_WRITE\0" as *const u8 as *const libc::c_char,
                             );
                         }
                         done = 1 as i32 != 0;
                     }
                     _ => {
                         /* openssl/ssl.h says "look at error stack/return value/errno" */
                         unsafe {
                             sslerror = ERR_get_error();
                             Curl_failf(
                                 data,
                                 b"OpenSSL SSL_read on shutdown: %s, errno %d\0" as *const u8
                                     as *const libc::c_char,
                                 if sslerror != 0 {
                                     ossl_strerror(
                                         sslerror,
                                         buf.as_mut_ptr(),
                                         ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                                     ) as *const libc::c_char
                                 } else {
                                     SSL_ERROR_to_str(err)
                                 },
                                 *__errno_location(),
                             );
                         }
                         done = 1 as i32 != 0;
                     }
                 }
             } else if 0 as i32 == what {
                 /* timeout */
                 unsafe {
                     Curl_failf(
                         data,
                         b"SSL shutdown timeout\0" as *const u8 as *const libc::c_char,
                     );
                 }
                 done = 1 as i32 != 0;
             } else {
                 /* anything that gets here is fatally bad */
                 unsafe {
                     Curl_failf(
                         data,
                         b"select/poll on SSL socket, errno: %d\0" as *const u8
                             as *const libc::c_char,
                         *__errno_location(),
                     );
                 }
                 retval = -(1 as i32);
                 done = 1 as i32 != 0;
             }
         } /* while()-loop for the select() */
         if unsafe { ((*data).set).verbose() != 0 } {
             if cfg!(HAVE_SSL_GET_SHUTDOWN) {
                 unsafe {
                     match SSL_get_shutdown((*backend).handle) {
                         1 => {
                             Curl_infof(
                                 data,
                                 b"SSL_get_shutdown() returned SSL_SENT_SHUTDOWN\0" as *const u8
                                     as *const libc::c_char,
                             );
                         }
                         2 => {
                             Curl_infof(
                                 data,
                                 b"SSL_get_shutdown() returned SSL_RECEIVED_SHUTDOWN\0" as *const u8
                                     as *const libc::c_char,
                             );
                         }
                         3 => {
                             Curl_infof(
                                  data,
                                  b"SSL_get_shutdown() returned SSL_SENT_SHUTDOWN|SSL_RECEIVED__SHUTDOWN\0"
                                      as *const u8 as *const libc::c_char,
                              );
                         }
                         _ => {}
                     }
                 }
             }
         }
         unsafe {
             SSL_free((*backend).handle);
             (*backend).handle = 0 as *mut SSL;
         }
     }
     return retval;
 }
 
 extern "C" fn ossl_session_free(mut ptr: *mut libc::c_void) {
     unsafe {
         SSL_SESSION_free(ptr as *mut SSL_SESSION); /* free the ID */
     }
 }
 
 /*
  * This function is called when the 'data' struct is going away. Close
  * down everything and free all resources!
  */
 extern "C" fn ossl_close_all(mut data: *mut Curl_easy) {
     unsafe {
         #[cfg(USE_OPENSSL_ENGINE)]
         if !((*data).state.engine).is_null() {
             ENGINE_finish((*data).state.engine as *mut ENGINE);
             ENGINE_free((*data).state.engine as *mut ENGINE);
             (*data).state.engine = 0 as *mut libc::c_void;
         }
         // TODO - 1560
         // #[cfg(all(not(HAVE_ERR_REMOVE_THREAD_STATE_DEPRECATED), HAVE_ERR_REMOVE_THREAD_STATE))]
     }
 }
 
 /*
  * Match subjectAltName against the host name. This requires a conversion
  * in CURL_DOES_CONVERSIONS builds.
  */
 // TODO - 1579 开启 CURL_DOES_CONVERSIONS 选项
 // #[cfg(CURL_DOES_CONVERSIONS)]
 #[cfg(not(CURL_DOES_CONVERSIONS))]
 extern "C" fn subj_alt_hostcheck(
     mut data: *mut Curl_easy,
     mut match_pattern: *const libc::c_char,
     mut hostname: *const libc::c_char,
     mut dispname: *const libc::c_char,
 ) -> bool {
     unsafe {
         if Curl_cert_hostcheck(match_pattern, hostname) != 0 {
             Curl_infof(
                 data,
                 b" subjectAltName: host \"%s\" matched cert's \"%s\"\0" as *const u8
                     as *const libc::c_char,
                 dispname,
                 match_pattern,
             );
             return 1 as i32 != 0;
         }
         return 0 as i32 != 0;
     }
 }
 
 /* Quote from RFC2818 section 3.1 "Server Identity"
 
    If a subjectAltName extension of type dNSName is present, that MUST
    be used as the identity. Otherwise, the (most specific) Common Name
    field in the Subject field of the certificate MUST be used. Although
    the use of the Common Name is existing practice, it is deprecated and
    Certification Authorities are encouraged to use the dNSName instead.
 
    Matching is performed using the matching rules specified by
    [RFC2459].  If more than one identity of a given type is present in
    the certificate (e.g., more than one dNSName name, a match in any one
    of the set is considered acceptable.) Names may contain the wildcard
    character * which is considered to match any single domain name
    component or component fragment. E.g., *.a.com matches foo.a.com but
    not bar.foo.a.com. f*.com matches foo.com but not bar.com.
 
    In some cases, the URI is specified as an IP address rather than a
    hostname. In this case, the iPAddress subjectAltName must be present
    in the certificate and must exactly match the IP in the URI.
 
 */
 extern "C" fn verifyhost(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut server_cert: *mut X509,
 ) -> CURLcode {
     let mut matched: bool = 0 as i32 != 0;
     let mut target: i32 = 2 as i32; /* target type, GEN_DNS or GEN_IPADD */
     let mut addrlen: size_t = 0 as size_t;
     let mut altnames: *mut stack_st_GENERAL_NAME = 0 as *mut stack_st_GENERAL_NAME;
     #[cfg(ENABLE_IPV6)]
     let mut addr: in6_addr = in6_addr {
         __in6_u: C2RustUnnamed_8 {
             __u6_addr8: [0; 16],
         },
     };
     #[cfg(not(ENABLE_IPV6))]
     let mut addr: in_addr = in_addr { s_addr: 0 };
     // TODO - 1650
     // #[cfg(not(ENABLE_IPV6))]
     let mut result: CURLcode = CURLE_OK;
     let mut dNSName: bool = 0 as i32 != 0; /* if a dNSName field exists in the cert */
     let mut iPAddress: bool = 0 as i32 != 0; /* if a iPAddress field exists in the cert */
     #[cfg(not(CURL_DISABLE_PROXY))]
     let hostname: *const libc::c_char = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype as u32 }
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         unsafe { (*conn).http_proxy.host.name }
     } else {
         unsafe { (*conn).host.name }
     };
     #[cfg(CURL_DISABLE_PROXY)]
     let hostname: *const libc::c_char = unsafe { (*conn).host.name };
     #[cfg(not(CURL_DISABLE_PROXY))]
     let dispname: *const libc::c_char = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype as u32 }
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         unsafe { (*conn).http_proxy.host.dispname }
     } else {
         unsafe { (*conn).host.dispname }
     };
     #[cfg(CURL_DISABLE_PROXY)]
     let dispname: *const libc::c_char = unsafe { (*conn).host.dispname };
     // DONE - 1661
     #[cfg(ENABLE_IPV6)]
     if unsafe {
         ((*conn).bits).ipv6_ip() as i32 != 0
             && inet_pton(
                 10 as i32,
                 hostname,
                 &mut addr as *mut in6_addr as *mut libc::c_void,
             ) != 0
     } {
         target = 7 as i32;
         addrlen = ::std::mem::size_of::<in6_addr>() as u64;
     } else if unsafe {
         inet_pton(
             2 as i32,
             hostname,
             &mut addr as *mut in6_addr as *mut libc::c_void,
         )
     } != 0
     {
         target = 7 as i32;
         addrlen = ::std::mem::size_of::<in_addr>() as u64;
     }
     #[cfg(not(ENABLE_IPV6))]
     if unsafe {
         inet_pton(
             2 as i32,
             hostname,
             &mut addr as *mut in_addr as *mut libc::c_void,
         )
     } != 0
     {
         target = 7 as i32;
         addrlen = ::std::mem::size_of::<in_addr>() as u64;
     }
     /* get a "list" of alternative names */
     altnames = unsafe { X509_get_ext_d2i(server_cert, 85 as i32, 0 as *mut i32, 0 as *mut i32) }
         as *mut stack_st_GENERAL_NAME;
     if !altnames.is_null() {
         unsafe {
             // TODO 待确认
             #[cfg(OPENSSL_IS_BORINGSSL)]
             let mut numalts: ibc::c_int = 0;
             #[cfg(OPENSSL_IS_BORINGSSL)]
             let mut i: ibc::c_int = 0;
             #[cfg(not(OPENSSL_IS_BORINGSSL))]
             let mut numalts: i32 = 0;
             #[cfg(not(OPENSSL_IS_BORINGSSL))]
             let mut i: i32 = 0;
             let mut dnsmatched: bool = 0 as i32 != 0;
             let mut ipmatched: bool = 0 as i32 != 0;
             /* get amount of alternatives, RFC2459 claims there MUST be at least
             one, but we don't depend on it... */
             numalts = sk_GENERAL_NAME_num(altnames);
             /* loop through all alternatives - until a dnsmatch */
             i = 0 as i32;
             while i < numalts && !dnsmatched {
                 /* get a handle to alternative name number i */
                 let mut check: *const GENERAL_NAME = sk_GENERAL_NAME_value(altnames, i);
                 if (*check).type_0 == 2 as i32 {
                     dNSName = 1 as i32 != 0;
                 } else if (*check).type_0 == 7 as i32 {
                     iPAddress = 1 as i32 != 0;
                 }
                 /* only check alternatives of the same type the target is */
                 if (*check).type_0 == target {
                     /* get data and length */
                     let mut altptr: *const libc::c_char =
                         ASN1_STRING_get0_data((*check).d.ia5) as *mut libc::c_char;
                     let mut altlen: size_t = ASN1_STRING_length((*check).d.ia5) as size_t;
                     match target {
                         2 => {
                             /* name/pattern comparison */
                             /* The OpenSSL man page explicitly says: "In general it cannot be
                                assumed that the data returned by ASN1_STRING_data() is null
                                terminated or does not contain embedded nulls." But also that
                                "The actual format of the data will depend on the actual string
                                type itself: for example for an IA5String the data will be ASCII"
 
                                It has been however verified that in 0.9.6 and 0.9.7, IA5String
                                is always null-terminated.
                             */
                             if altlen == strlen(altptr)
                                 && subj_alt_hostcheck(data, altptr, hostname, dispname) as i32 != 0
                             {
                                 /* if this isn't true, there was an embedded zero in the name
                                 string and we cannot match it. */
                                 dnsmatched = 1 as i32 != 0;
                             }
                         }
                         7 => {
                             /* IP address comparison */
                             #[cfg(ENABLE_IPV6)]
                             let ENABLE_IPV6_a = memcmp(
                                 altptr as *const libc::c_void,
                                 &mut addr as *mut in6_addr as *const libc::c_void,
                                 altlen,
                             ) == 0;
                             #[cfg(not(ENABLE_IPV6))]
                             let ENABLE_IPV6_a = memcmp(
                                 altptr as *const libc::c_void,
                                 &mut addr as *mut in_addr as *const libc::c_void,
                                 altlen,
                             ) == 0;
                             /* compare alternative IP address if the data chunk is the same size
                             our server IP address is */
                             if altlen == addrlen && ENABLE_IPV6_a {
                                 ipmatched = 1 as i32 != 0;
                                 Curl_infof(
                                     data,
                                     b" subjectAltName: host \"%s\" matched cert's IP address!\0"
                                         as *const u8
                                         as *const libc::c_char,
                                     dispname,
                                 );
                             }
                         }
                         _ => {}
                     }
                 }
                 i += 1;
             }
             GENERAL_NAMES_free(altnames);
             if dnsmatched as i32 != 0 || ipmatched as i32 != 0 {
                 matched = 1 as i32 != 0;
             }
         }
     }
     /* an alternative name matched */
     if !matched {
         if dNSName as i32 != 0 || iPAddress as i32 != 0 {
             unsafe {
                 Curl_infof(
                     data,
                     b" subjectAltName does not match %s\0" as *const u8 as *const libc::c_char,
                     dispname,
                 );
                 Curl_failf(
                     data,
                     b"SSL: no alternative certificate subject name matches target host name '%s'\0"
                         as *const u8 as *const libc::c_char,
                     dispname,
                 );
             }
             result = CURLE_PEER_FAILED_VERIFICATION;
         } else {
             /* we have to look to the last occurrence of a commonName in the
             distinguished one to get the most significant one. */
             let mut j: i32 = 0;
             let mut i_0: i32 = -(1 as i32);
             /* The following is done because of a bug in 0.9.6b */
             let mut nulstr: *mut u8 = b"\0" as *const u8 as *const libc::c_char as *mut u8;
             let mut peer_CN: *mut u8 = nulstr;
             let mut name: *mut X509_NAME = unsafe { X509_get_subject_name(server_cert) };
             if !name.is_null() {
                 loop {
                     j = unsafe { X509_NAME_get_index_by_NID(name, 13 as i32, i_0) };
                     if !(j >= 0 as i32) {
                         break;
                     }
                     i_0 = j;
                 }
             }
             /* we have the name entry and we will now convert this to a string
             that we can use for comparison. Doing this we support BMPstring,
             UTF8, etc. */
 
             if i_0 >= 0 as i32 {
                 let mut tmp: *mut ASN1_STRING =
                     unsafe { X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i_0)) };
                 if !tmp.is_null() {
                     unsafe {
                         /* In OpenSSL 0.9.7d and earlier, ASN1_STRING_to_UTF8 fails if the input
                         is already UTF-8 encoded. We check for this case and copy the raw
                         string manually to avoid the problem. This code can be made
                         conditional in the future when OpenSSL has been fixed. */
                         if ASN1_STRING_type(tmp) == 12 as i32 {
                             j = ASN1_STRING_length(tmp);
                             if j >= 0 as i32 {
                                 peer_CN = CRYPTO_malloc(
                                     (j + 1 as i32) as size_t,
                                     b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                                     1786 as i32,
                                 ) as *mut u8;
                                 if !peer_CN.is_null() {
                                     memcpy(
                                         peer_CN as *mut libc::c_void,
                                         ASN1_STRING_get0_data(tmp) as *const libc::c_void,
                                         j as u64,
                                     );
                                     *peer_CN.offset(j as isize) = '\0' as i32 as u8;
                                 }
                             }
                         } else {
                             /* not a UTF8 name */
                             j = ASN1_STRING_to_UTF8(&mut peer_CN, tmp);
                         }
                         if !peer_CN.is_null()
                             && curlx_uztosi(strlen(peer_CN as *mut libc::c_char)) != j
                         {
                             /* there was a terminating zero before the end of string, this
                             cannot match and we return failure! */
                             Curl_failf(
                                 data,
                                 b"SSL: illegal cert name field\0" as *const u8
                                     as *const libc::c_char,
                             );
                             result = CURLE_PEER_FAILED_VERIFICATION;
                         }
                     }
                 }
             }
             if peer_CN == nulstr {
                 peer_CN = 0 as *mut u8;
             } else {
                 /* convert peer_CN from UTF8 */
                 let mut rc: CURLcode = CURLE_OK as CURLcode;
                 /* Curl_convert_from_utf8 calls failf if unsuccessful */
                 if rc as u64 != 0 {
                     unsafe {
                         CRYPTO_free(
                             peer_CN as *mut libc::c_void,
                             b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                             1813 as i32,
                         );
                     }
                     return rc;
                 }
             }
             if !(result as u64 != 0) {
                 /* error already detected, pass through */
                 if peer_CN.is_null() {
                     unsafe {
                         Curl_failf(
                             data,
                             b"SSL: unable to obtain common name from peer certificate\0"
                                 as *const u8 as *const libc::c_char,
                         );
                     }
                     result = CURLE_PEER_FAILED_VERIFICATION;
                 } else if unsafe { Curl_cert_hostcheck(peer_CN as *const libc::c_char, hostname) }
                     == 0
                 {
                     unsafe {
                         Curl_failf(
                         data,
                         b"SSL: certificate subject name '%s' does not match target host name '%s'\0"
                             as *const u8 as *const libc::c_char,
                         peer_CN,
                         dispname,
                     );
                     }
                     result = CURLE_PEER_FAILED_VERIFICATION;
                 } else {
                     unsafe {
                         Curl_infof(
                             data,
                             b" common name: %s (matched)\0" as *const u8 as *const libc::c_char,
                             peer_CN,
                         );
                     }
                 }
             }
             if !peer_CN.is_null() {
                 unsafe {
                     CRYPTO_free(
                         peer_CN as *mut libc::c_void,
                         b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                         1835 as i32,
                     );
                 }
             }
         }
     }
     return result;
 }
 
 #[cfg(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP)))]
 extern "C" fn verifystatus(
     mut data: *mut Curl_easy,
     mut connssl: *mut ssl_connect_data,
 ) -> CURLcode {
     let mut current_block: u64;
     let mut i: i32 = 0;
     let mut ocsp_status: i32 = 0;
     let mut status: *mut u8 = 0 as *mut u8;
     let mut p: *const u8 = 0 as *const u8;
     let mut result: CURLcode = CURLE_OK;
     let mut rsp: *mut OCSP_RESPONSE = 0 as *mut OCSP_RESPONSE;
     let mut br: *mut OCSP_BASICRESP = 0 as *mut OCSP_BASICRESP;
     let mut st: *mut X509_STORE = 0 as *mut X509_STORE;
     let mut ch: *mut stack_st_X509 = 0 as *mut stack_st_X509;
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     let mut cert: *mut X509 = 0 as *mut X509;
     let mut id: *mut OCSP_CERTID = 0 as *mut OCSP_CERTID;
     let mut cert_status: i32 = 0;
     let mut crl_reason: i32 = 0;
     let mut rev: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
     let mut thisupd: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
     let mut nextupd: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
     let mut ret: i32 = 0;
     let mut len: i64 = unsafe {
         SSL_ctrl(
             (*backend).handle,
             70 as i32,
             0 as i64,
             &mut status as *mut *mut u8 as *mut libc::c_void,
         )
     };
     'end: loop {
         if status.is_null() {
             unsafe {
                 Curl_failf(
                     data,
                     b"No OCSP response received\0" as *const u8 as *const libc::c_char,
                 );
             }
             result = CURLE_SSL_INVALIDCERTSTATUS;
             break 'end;
         }
         p = status;
         rsp = unsafe { d2i_OCSP_RESPONSE(0 as *mut *mut OCSP_RESPONSE, &mut p, len) };
         if rsp.is_null() {
             unsafe {
                 Curl_failf(
                     data,
                     b"Invalid OCSP response\0" as *const u8 as *const libc::c_char,
                 );
             }
             result = CURLE_SSL_INVALIDCERTSTATUS;
             break 'end;
         }
         ocsp_status = unsafe { OCSP_response_status(rsp) };
         if ocsp_status != 0 as i32 {
             unsafe {
                 Curl_failf(
                     data,
                     b"Invalid OCSP response status: %s (%d)\0" as *const u8 as *const libc::c_char,
                     OCSP_response_status_str(ocsp_status as i64),
                     ocsp_status,
                 );
             }
             result = CURLE_SSL_INVALIDCERTSTATUS;
             break 'end;
         }
         br = unsafe { OCSP_response_get1_basic(rsp) };
         if br.is_null() {
             unsafe {
                 Curl_failf(
                     data,
                     b"Invalid OCSP response\0" as *const u8 as *const libc::c_char,
                 );
             }
             result = CURLE_SSL_INVALIDCERTSTATUS;
             break 'end;
         }
         unsafe {
             ch = SSL_get_peer_cert_chain((*backend).handle);
             st = SSL_CTX_get_cert_store((*backend).ctx);
         }
         /* The authorized responder cert in the OCSP response MUST be signed by the
         peer cert's issuer (see RFC6960 section 4.2.2.2). If that's a root cert,
         no problem, but if it's an intermediate cert OpenSSL has a bug where it
         expects this issuer to be present in the chain embedded in the OCSP
         response. So we add it if necessary. */
 
         /* First make sure the peer cert chain includes both a peer and an issuer,
         and the OCSP response contains a responder cert. */
         // TODO - 1894 这里有一段跟OPENSSL_VERSION_NUMBER相关的条件编译
         if cfg!(any(
             OPENSSL_VERSION_NUMBER_LT_0X1000201FL,
             all(
                 LIBRESSL_VERSION_NUMBER,
                 LIBRESSL_VERSION_NUMBER_LT_0X2040200FL
             )
         )) {
             // TODO
         }
         if unsafe { OCSP_basic_verify(br, ch, st, 0 as u64) <= 0 as i32 } {
             unsafe {
                 Curl_failf(
                     data,
                     b"OCSP response verification failed\0" as *const u8 as *const libc::c_char,
                 );
             }
             result = CURLE_SSL_INVALIDCERTSTATUS;
             break 'end;
         }
         cert = unsafe { SSL_get_peer_certificate((*backend).handle) };
         if cert.is_null() {
             unsafe {
                 Curl_failf(
                     data,
                     b"Error getting peer certificate\0" as *const u8 as *const libc::c_char,
                 );
             }
             result = CURLE_SSL_INVALIDCERTSTATUS;
             break 'end;
         }
         /* Find issuer of responder cert and add it to the OCSP response chain */
         i = 0 as i32;
         while i < sk_X509_num(ch) {
             let mut issuer: *mut X509 = sk_X509_value(ch, i);
             if unsafe { X509_check_issued(issuer, cert) } == 0 as i32 {
                 id = unsafe { OCSP_cert_to_id(EVP_sha1(), cert, issuer) };
                 break;
             } else {
                 i += 1;
             }
         }
         unsafe {
             X509_free(cert);
         }
         if id.is_null() {
             unsafe {
                 Curl_failf(
                     data,
                     b"Error computing OCSP ID\0" as *const u8 as *const libc::c_char,
                 );
             }
             result = CURLE_SSL_INVALIDCERTSTATUS;
             break 'end;
         }
         /* Find the single OCSP response corresponding to the certificate ID */
         unsafe {
             ret = OCSP_resp_find_status(
                 br,
                 id,
                 &mut cert_status,
                 &mut crl_reason,
                 &mut rev,
                 &mut thisupd,
                 &mut nextupd,
             );
             OCSP_CERTID_free(id);
         }
         if ret != 1 as i32 {
             unsafe {
                 Curl_failf(
                     data,
                     b"Could not find certificate ID in OCSP response\0" as *const u8
                         as *const libc::c_char,
                 );
             }
             result = CURLE_SSL_INVALIDCERTSTATUS;
             break 'end;
         }
         /* Validate the corresponding single OCSP response */
         unsafe {
             if OCSP_check_validity(thisupd, nextupd, 300 as i64, -(1 as i64)) == 0 {
                 Curl_failf(
                     data,
                     b"OCSP response has expired\0" as *const u8 as *const libc::c_char,
                 );
                 result = CURLE_SSL_INVALIDCERTSTATUS;
                 break 'end;
             }
             Curl_infof(
                 data,
                 b"SSL certificate status: %s (%d)\0" as *const u8 as *const libc::c_char,
                 OCSP_cert_status_str(cert_status as i64),
                 cert_status,
             );
         }
         let mut current_block_63: u64;
         match cert_status {
             0 => {
                 current_block_63 = 13484060386966298149;
             }
             1 => {
                 result = CURLE_SSL_INVALIDCERTSTATUS;
                 unsafe {
                     Curl_failf(
                         data,
                         b"SSL certificate revocation reason: %s (%d)\0" as *const u8
                             as *const libc::c_char,
                         OCSP_crl_reason_str(crl_reason as i64),
                         crl_reason,
                     );
                 }
                 current_block_63 = 11531555616992456840;
                 break 'end;
             }
             2 | _ => {
                 current_block_63 = 11531555616992456840;
             }
         }
         match current_block_63 {
             11531555616992456840 => {
                 result = CURLE_SSL_INVALIDCERTSTATUS;
                 break 'end;
             }
             _ => {}
         }
         break 'end;
     }
     if !br.is_null() {
         unsafe {
             OCSP_BASICRESP_free(br);
         }
     }
     unsafe {
         OCSP_RESPONSE_free(rsp);
     }
     return result;
 }
 
 #[cfg(SSL_CTRL_SET_MSG_CALLBACK)]
 extern "C" fn ssl_msg_type(mut ssl_ver: i32, mut msg: i32) -> *const libc::c_char {
     if ssl_ver == 0x3 as i32 {
         match msg {
             0 => return b"Hello request\0" as *const u8 as *const libc::c_char,
             1 => return b"Client hello\0" as *const u8 as *const libc::c_char,
             2 => return b"Server hello\0" as *const u8 as *const libc::c_char,
             #[cfg(SSL3_MT_NEWSESSION_TICKET)]
             4 => return b"Newsession Ticket\0" as *const u8 as *const libc::c_char,
             11 => return b"Certificate\0" as *const u8 as *const libc::c_char,
             12 => return b"Server key exchange\0" as *const u8 as *const libc::c_char,
             16 => return b"Client key exchange\0" as *const u8 as *const libc::c_char,
             13 => return b"Request CERT\0" as *const u8 as *const libc::c_char,
             14 => return b"Server finished\0" as *const u8 as *const libc::c_char,
             15 => return b"CERT verify\0" as *const u8 as *const libc::c_char,
             20 => return b"Finished\0" as *const u8 as *const libc::c_char,
             #[cfg(SSL3_MT_CERTIFICATE_STATUS)]
             22 => return b"Certificate Status\0" as *const u8 as *const libc::c_char,
             #[cfg(SSL3_MT_ENCRYPTED_EXTENSIONS)]
             8 => return b"Encrypted Extensions\0" as *const u8 as *const libc::c_char,
             #[cfg(SSL3_MT_SUPPLEMENTAL_DATA)]
             23 => return b"Supplemental data\0" as *const u8 as *const libc::c_char,
             #[cfg(SSL3_MT_END_OF_EARLY_DATA)]
             5 => return b"End of early data\0" as *const u8 as *const libc::c_char,
             #[cfg(SSL3_MT_KEY_UPDATE)]
             24 => return b"Key update\0" as *const u8 as *const libc::c_char,
             #[cfg(SSL3_MT_NEXT_PROTO)]
             67 => return b"Next protocol\0" as *const u8 as *const libc::c_char,
             #[cfg(SSL3_MT_MESSAGE_HASH)]
             254 => return b"Message hash\0" as *const u8 as *const libc::c_char,
             _ => {}
         }
     }
     return b"Unknown\0" as *const u8 as *const libc::c_char;
 }
 
 #[cfg(SSL_CTRL_SET_MSG_CALLBACK)]
 extern "C" fn tls_rt_type(mut type_0: i32) -> *const libc::c_char {
     match type_0 {
         #[cfg(SSL3_RT_HEADER)]
         256 => return b"TLS header\0" as *const u8 as *const libc::c_char,
         20 => return b"TLS change cipher\0" as *const u8 as *const libc::c_char,
         21 => return b"TLS alert\0" as *const u8 as *const libc::c_char,
         22 => return b"TLS handshake\0" as *const u8 as *const libc::c_char,
         23 => return b"TLS app data\0" as *const u8 as *const libc::c_char,
         _ => return b"TLS Unknown\0" as *const u8 as *const libc::c_char,
     };
 }
 
 /*
  * Our callback from the SSL/TLS layers.
  */
 #[cfg(SSL_CTRL_SET_MSG_CALLBACK)]
 extern "C" fn ossl_trace(
     mut direction: i32,
     mut ssl_ver: i32,
     mut content_type: i32,
     mut buf: *const libc::c_void,
     mut len: size_t,
     mut ssl: *mut SSL,
     mut userp: *mut libc::c_void,
 ) {
     let mut unknown: [libc::c_char; 32] = [0; 32];
     let mut verstr: *const libc::c_char = 0 as *const libc::c_char;
     let mut conn: *mut connectdata = userp as *mut connectdata;
     let mut connssl: *mut ssl_connect_data =
         unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(0 as isize) as *mut ssl_connect_data };
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     let mut data: *mut Curl_easy = unsafe { (*backend).logger };
     if conn.is_null()
         || data.is_null()
         || unsafe { ((*data).set.fdebug).is_none() }
         || direction != 0 as i32 && direction != 1 as i32
     {
         return;
     }
     match ssl_ver {
         #[cfg(SSL2_VERSION)]
         2 => {
             verstr = b"SSLv2\0" as *const u8 as *const libc::c_char;
         }
         #[cfg(SSL3_VERSION)]
         768 => {
             verstr = b"SSLv3\0" as *const u8 as *const libc::c_char;
         }
         769 => {
             verstr = b"TLSv1.0\0" as *const u8 as *const libc::c_char;
         }
         #[cfg(TLS1_1_VERSION)]
         770 => {
             verstr = b"TLSv1.1\0" as *const u8 as *const libc::c_char;
         }
         #[cfg(TLS1_2_VERSION)]
         771 => {
             verstr = b"TLSv1.2\0" as *const u8 as *const libc::c_char;
         }
         #[cfg(TLS1_3_VERSION)]
         772 => {
             verstr = b"TLSv1.3\0" as *const u8 as *const libc::c_char;
         }
         0 => {}
         _ => {
             unsafe {
                 curl_msnprintf(
                     unknown.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 32]>() as u64,
                     b"(%x)\0" as *const u8 as *const libc::c_char,
                     ssl_ver,
                 );
             }
             verstr = unknown.as_mut_ptr();
         }
     }
     /* Log progress for interesting records only (like Handshake or Alert), skip
      * all raw record headers (content_type == SSL3_RT_HEADER or ssl_ver == 0).
      * For TLS 1.3, skip notification of the decrypted inner Content-Type.
      */
     // DONE - 2168
     #[cfg(SSL3_RT_INNER_CONTENT_TYPE)]
     let SSL3_RT_INNER_CONTENT_TYPE_flag = content_type != 0x101;
     #[cfg(not(SSL3_RT_INNER_CONTENT_TYPE))]
     let SSL3_RT_INNER_CONTENT_TYPE_flag = true;
     if ssl_ver != 0 && SSL3_RT_INNER_CONTENT_TYPE_flag {
         let mut msg_name: *const libc::c_char = 0 as *const libc::c_char;
         let mut tls_rt_name: *const libc::c_char = 0 as *const libc::c_char;
         let mut ssl_buf: [libc::c_char; 1024] = [0; 1024];
         let mut msg_type: i32 = 0;
         let mut txt_len: i32 = 0;
         /* the info given when the version is zero is not that useful for us */
 
         ssl_ver >>= 8 as i32; /* check the upper 8 bits only below */
         /* SSLv2 doesn't seem to have TLS record-type headers, so OpenSSL
          * always pass-up content-type as 0. But the interesting message-type
          * is at 'buf[0]'.
          */
         if ssl_ver == 0x3 as i32 && content_type != 0 {
             tls_rt_name = tls_rt_type(content_type);
         } else {
             tls_rt_name = b"\0" as *const u8 as *const libc::c_char;
         }
         if content_type == 20 as i32 {
             msg_type = unsafe { *(buf as *mut libc::c_char) } as i32;
             msg_name = b"Change cipher spec\0" as *const u8 as *const libc::c_char;
         } else if content_type == 21 as i32 {
             msg_type = unsafe {
                 ((*(buf as *mut libc::c_char).offset(0 as isize) as i32) << 8 as i32)
                     + *(buf as *mut libc::c_char).offset(1 as isize) as i32
             };
             msg_name = unsafe { SSL_alert_desc_string_long(msg_type) };
         } else {
             msg_type = unsafe { *(buf as *mut libc::c_char) } as i32;
             msg_name = ssl_msg_type(ssl_ver, msg_type);
         }
         txt_len = unsafe {
             curl_msnprintf(
                 ssl_buf.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 1024]>() as u64,
                 b"%s (%s), %s, %s (%d):\n\0" as *const u8 as *const libc::c_char,
                 verstr,
                 if direction != 0 {
                     b"OUT\0" as *const u8 as *const libc::c_char
                 } else {
                     b"IN\0" as *const u8 as *const libc::c_char
                 },
                 tls_rt_name,
                 msg_name,
                 msg_type,
             )
         };
         if 0 as i32 <= txt_len
             && (txt_len as u64) < ::std::mem::size_of::<[libc::c_char; 1024]>() as u64
         {
             unsafe {
                 Curl_debug(data, CURLINFO_TEXT, ssl_buf.as_mut_ptr(), txt_len as size_t);
             }
         }
     }
     unsafe {
         Curl_debug(
             data,
             (if direction == 1 as i32 {
                 CURLINFO_SSL_DATA_OUT as i32
             } else {
                 CURLINFO_SSL_DATA_IN as i32
             }) as curl_infotype,
             buf as *mut libc::c_char,
             len,
         );
     }
 }
 
 #[cfg(all(USE_OPENSSL, HAS_NPN))]
 extern "C" fn select_next_protocol(
     mut out: *mut *mut u8,
     mut outlen: *mut u8,
     mut in_0: *const u8,
     mut inlen: u32,
     mut key: *const libc::c_char,
     mut keylen: u32,
 ) -> i32 {
     let mut i: u32 = 0;
     i = 0 as u32;
     while i.wrapping_add(keylen) <= inlen {
         if unsafe {
             memcmp(
                 &*in_0.offset(i.wrapping_add(1 as u32) as isize) as *const u8
                     as *const libc::c_void,
                 key as *const libc::c_void,
                 keylen as u64,
             )
         } == 0 as i32
         {
             unsafe {
                 *out = &*in_0.offset(i.wrapping_add(1 as u32) as isize) as *const u8 as *mut u8;
                 *outlen = *in_0.offset(i as isize);
             }
             return 0 as i32;
         }
         i = unsafe { i.wrapping_add((*in_0.offset(i as isize) as i32 + 1 as i32) as u32) };
     }
     return -(1 as i32);
 }
 
 #[cfg(all(USE_OPENSSL, HAS_NPN))]
 extern "C" fn select_next_proto_cb(
     mut ssl: *mut SSL,
     mut out: *mut *mut u8,
     mut outlen: *mut u8,
     mut in_0: *const u8,
     mut inlen: u32,
     mut arg: *mut libc::c_void,
 ) -> i32 {
     unsafe {
         let mut data: *mut Curl_easy = arg as *mut Curl_easy;
         let mut conn: *mut connectdata = (*data).conn;
         #[cfg(USE_HTTP2)]
         if (*data).state.httpwant as i32 >= CURL_HTTP_VERSION_2_0 as i32
             && select_next_protocol(
                 out,
                 outlen,
                 in_0,
                 inlen,
                 b"h2\0" as *const u8 as *const libc::c_char,
                 2 as u32,
             ) == 0
         {
             Curl_infof(
                 data,
                 b"NPN, negotiated HTTP2 (%s)\0" as *const u8 as *const libc::c_char,
                 b"h2\0" as *const u8 as *const libc::c_char,
             );
             (*conn).negnpn = CURL_HTTP_VERSION_2_0 as i32;
             return 0 as i32;
         }
         if select_next_protocol(
             out,
             outlen,
             in_0,
             inlen,
             b"http/1.1\0" as *const u8 as *const libc::c_char,
             8 as u32,
         ) == 0
         {
             Curl_infof(
                 data,
                 b"NPN, negotiated HTTP1.1\0" as *const u8 as *const libc::c_char,
             );
             (*conn).negnpn = CURL_HTTP_VERSION_1_1 as i32;
             return 0 as i32;
         }
         Curl_infof(
             data,
             b"NPN, no overlap, use HTTP1.1\0" as *const u8 as *const libc::c_char,
         );
         *out = b"http/1.1\0" as *const u8 as *const libc::c_char as *mut u8;
         *outlen = 8 as u8;
         (*conn).negnpn = CURL_HTTP_VERSION_1_1 as i32;
         return 0 as i32;
     }
 }
 // TODO
 // USE_OPENSSL以及与OPENSSL_VERSION_NUMBER相关的条件编译
 #[cfg(USE_OPENSSL)]
 extern "C" fn set_ssl_version_min_max(
     mut ctx: *mut SSL_CTX,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     #[cfg(not(CURL_DISABLE_PROXY))]
     let mut curl_ssl_version_min: i64 = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype as u32 }
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         unsafe { (*conn).proxy_ssl_config.version }
     } else {
         unsafe { (*conn).ssl_config.version }
     };
     #[cfg(CURL_DISABLE_PROXY)]
     let mut curl_ssl_version_min: i64 = unsafe { (*conn).ssl_config.version };
 
     let mut curl_ssl_version_max: i64 = 0;
     // TODO - 2307
     // #[cfg(any(OPENSSL_IS_BORINGSSL, LIBRESSL_VERSION_NUMBER))]
     // TODO - 2307
     // #[cfg(any(OPENSSL_IS_BORINGSSL, LIBRESSL_VERSION_NUMBER))]
     #[cfg(all(not(OPENSSL_IS_BORINGSSL), not(LIBRESSL_VERSION_NUMBER)))]
     let mut ossl_ssl_version_min: i64 = 0 as i64;
     #[cfg(all(not(OPENSSL_IS_BORINGSSL), not(LIBRESSL_VERSION_NUMBER)))]
     let mut ossl_ssl_version_max: i64 = 0 as i64;
     match curl_ssl_version_min {
         1 | 4 => {
             ossl_ssl_version_min = 0x301 as i64;
         }
         5 => {
             ossl_ssl_version_min = 0x302 as i64;
         }
         6 => {
             ossl_ssl_version_min = 0x303 as i64;
         }
         #[cfg(TLS1_3_VERSION)]
         7 => {
             ossl_ssl_version_min = 0x304 as i64;
         }
         _ => {}
     }
     /* CURL_SSLVERSION_DEFAULT means that no option was selected.
        We don't want to pass 0 to SSL_CTX_set_min_proto_version as
        it would enable all versions down to the lowest supported by
        the library.
        So we skip this, and stay with the library default
     */
     if curl_ssl_version_min != CURL_SSLVERSION_DEFAULT as i64 {
         if unsafe {
             SSL_CTX_ctrl(
                 ctx,
                 123 as i32,
                 ossl_ssl_version_min,
                 0 as *mut libc::c_void,
             )
         } == 0
         {
             return CURLE_SSL_CONNECT_ERROR;
         }
     }
 
     #[cfg(not(CURL_DISABLE_PROXY))]
     let SSL_CONN_CONFIG_version_max = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype } as u32
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         unsafe { (*conn).proxy_ssl_config.version_max }
     } else {
         unsafe { (*conn).ssl_config.version_max }
     };
     /* ... then, TLS max version */
     #[cfg(CURL_DISABLE_PROXY)]
     let SSL_CONN_CONFIG_version_max = unsafe { (*conn).ssl_config.version_max };
 
     curl_ssl_version_max = SSL_CONN_CONFIG_version_max;
     let mut current_block_15: u64;
     /* convert curl max SSL version option to OpenSSL constant */
     match curl_ssl_version_max {
         262144 => {
             ossl_ssl_version_max = 0x301 as i64;
             current_block_15 = 18386322304582297246;
         }
         327680 => {
             ossl_ssl_version_max = 0x302 as i64;
             current_block_15 = 18386322304582297246;
         }
         393216 => {
             ossl_ssl_version_max = 0x303 as i64;
             current_block_15 = 18386322304582297246;
         }
         #[cfg(TLS1_3_VERSION)]
         458752 => {
             ossl_ssl_version_max = 0x304 as i64;
             current_block_15 = 18386322304582297246;
         }
         // TODO 这里翻译的很奇怪，感觉没有必要这样
         0 => {
             current_block_15 = 9181747712041856033;
         }
         65536 | _ => {
             current_block_15 = 9181747712041856033;
         }
     }
     match current_block_15 {
         9181747712041856033 => {
             /* SSL_CTX_set_max_proto_version states that:
             setting the maximum to 0 will enable
             protocol versions up to the highest version
             supported by the library */
             ossl_ssl_version_max = 0 as i64;
         }
         _ => {}
     }
     if unsafe {
         SSL_CTX_ctrl(
             ctx,
             124 as i32,
             ossl_ssl_version_max,
             0 as *mut libc::c_void,
         )
     } == 0
     {
         return CURLE_SSL_CONNECT_ERROR;
     }
     return CURLE_OK;
 }
 
 /* The "new session" callback must return zero if the session can be removed
  * or non-zero if the session has been put into the session cache.
  */
 // TODO 这里有个与OPENSSL_VERSION_NUMBER相关的条件编译
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_new_session_cb(mut ssl: *mut SSL, mut ssl_sessionid: *mut SSL_SESSION) -> i32 {
     let mut res: i32 = 0 as i32;
     let mut conn: *mut connectdata = 0 as *mut connectdata;
     let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
     let mut sockindex: i32 = 0;
     let mut sockindex_ptr: *mut curl_socket_t = 0 as *mut curl_socket_t;
     let mut data_idx: i32 = ossl_get_ssl_data_index();
     let mut connectdata_idx: i32 = ossl_get_ssl_conn_index();
     let mut sockindex_idx: i32 = ossl_get_ssl_sockindex_index();
     let mut proxy_idx: i32 = ossl_get_proxy_index();
     let mut isproxy: bool = false;
     if data_idx < 0 as i32
         || connectdata_idx < 0 as i32
         || sockindex_idx < 0 as i32
         || proxy_idx < 0 as i32
     {
         return 0 as i32;
     }
     conn = unsafe { SSL_get_ex_data(ssl, connectdata_idx) as *mut connectdata };
     if conn.is_null() {
         return 0 as i32;
     }
     data = unsafe { SSL_get_ex_data(ssl, data_idx) as *mut Curl_easy };
     /* The sockindex has been stored as a pointer to an array element */
     sockindex_ptr = unsafe { SSL_get_ex_data(ssl, sockindex_idx) as *mut curl_socket_t };
     sockindex = unsafe { sockindex_ptr.offset_from(((*conn).sock).as_mut_ptr()) as i32 };
     isproxy = if unsafe { !(SSL_get_ex_data(ssl, proxy_idx)).is_null() } {
         1 as i32
     } else {
         0 as i32
     } != 0;
     #[cfg(not(CURL_DISABLE_PROXY))]
     let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype as u32 }
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         unsafe { ((*data).set.proxy_ssl.primary).sessionid() as i32 }
     } else {
         unsafe { ((*data).set.ssl.primary).sessionid() as i32 }
     };
     #[cfg(CURL_DISABLE_PROXY)]
     let SSL_SET_OPTION_primary_sessionid = unsafe { ((*data).set.ssl.primary).sessionid() };
     if SSL_SET_OPTION_primary_sessionid != 0 {
         let mut incache: bool = false;
         let mut old_ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
         Curl_ssl_sessionid_lock(data);
         if isproxy {
             incache = 0 as i32 != 0;
         } else {
             incache = !Curl_ssl_getsessionid(
                 data,
                 conn,
                 isproxy,
                 &mut old_ssl_sessionid,
                 0 as *mut size_t,
                 sockindex,
             );
         }
         if incache {
             if old_ssl_sessionid != ssl_sessionid as *mut libc::c_void {
                 unsafe {
                     Curl_infof(
                         data,
                         b"old SSL session ID is stale, removing\0" as *const u8
                             as *const libc::c_char,
                     );
                 }
                 Curl_ssl_delsessionid(data, old_ssl_sessionid);
                 incache = 0 as i32 != 0;
             }
         }
         if !incache {
             if Curl_ssl_addsessionid(
                 data,
                 conn,
                 isproxy,
                 ssl_sessionid as *mut libc::c_void,
                 0 as size_t,
                 sockindex,
             ) as u64
                 == 0
             {
                 /* the session has been put into the session cache */
                 res = 1 as i32;
             } else {
                 unsafe {
                     Curl_failf(
                         data,
                         b"failed to store ssl session\0" as *const u8 as *const libc::c_char,
                     );
                 }
             }
         }
         Curl_ssl_sessionid_unlock(data);
     }
     return res;
 }
// hanxj
 #[cfg(USE_OPENSSL)]
 extern "C" fn load_cacert_from_memory(
     mut ctx: *mut SSL_CTX,
     mut ca_info_blob: *const curl_blob,
 ) -> CURLcode {
     /* these need to be freed at the end */
     let mut cbio: *mut BIO = 0 as *mut BIO;
     let mut inf: *mut stack_st_X509_INFO = 0 as *mut stack_st_X509_INFO;
     /* everything else is just a reference */
     let mut i: i32 = 0;
     let mut count: i32 = 0 as i32;
     let mut cts: *mut X509_STORE = 0 as *mut X509_STORE;
     let mut itmp: *mut X509_INFO = 0 as *mut X509_INFO;
     if unsafe { (*ca_info_blob).len } > 2147483647 as size_t {
         return CURLE_SSL_CACERT_BADFILE;
     }
     cts = unsafe { SSL_CTX_get_cert_store(ctx) };
     if cts.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     cbio = unsafe { BIO_new_mem_buf((*ca_info_blob).data, (*ca_info_blob).len as i32) };
     if cbio.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     inf = unsafe {
         PEM_X509_INFO_read_bio(
             cbio,
             0 as *mut stack_st_X509_INFO,
             None,
             0 as *mut libc::c_void,
         )
     };
     if inf.is_null() {
         unsafe {
             BIO_free(cbio);
         }
         return CURLE_SSL_CACERT_BADFILE;
     }
     /* add each entry from PEM file to x509_store */
     i = 0 as i32;
     while i < sk_X509_INFO_num(inf) {
         itmp = sk_X509_INFO_value(inf, i);
         if unsafe { !((*itmp).x509).is_null() } {
             if unsafe { X509_STORE_add_cert(cts, (*itmp).x509) } != 0 {
                 count += 1;
             } else {
                 /* set count to 0 to return an error */
                 count = 0 as i32;
                 break;
             }
         }
         if unsafe { !((*itmp).crl).is_null() } {
             if unsafe { X509_STORE_add_crl(cts, (*itmp).crl) } != 0 {
                 count += 1;
             } else {
                 /* set count to 0 to return an error */
                 count = 0 as i32;
                 break;
             }
         }
         i += 1;
     }
     sk_X509_INFO_pop_free(
         inf,
         Some(X509_INFO_free as unsafe extern "C" fn(*mut X509_INFO) -> ()),
     );
     unsafe {
         BIO_free(cbio);
     }
     /* if we didn't end up importing anything, treat that as an error */
     return (if count > 0 as i32 {
         CURLE_OK as i32
     } else {
         CURLE_SSL_CACERT_BADFILE as i32
     }) as CURLcode;
 }
 
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_connect_step1(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut ciphers: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut req_method: *const SSL_METHOD = 0 as *const SSL_METHOD;
     let mut lookup: *mut X509_LOOKUP = 0 as *mut X509_LOOKUP;
     let mut sockfd: curl_socket_t = unsafe { (*conn).sock[sockindex as usize] };
     let mut connssl: *mut ssl_connect_data =
         unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }
             as *mut ssl_connect_data;
     let mut ctx_options: ctx_option_t = 0 as ctx_option_t;
     let mut ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
     let mut sni: bool = false;
     let hostname: *const libc::c_char = unsafe { (*conn).host.name };
     let mut addr: in_addr = in_addr { s_addr: 0 };
     let ssl_version: i64 = unsafe { (*conn).ssl_config.version };
     let ssl_authtype: CURL_TLSAUTH = unsafe { (*data).set.ssl.authtype };
     let ssl_cert: *mut libc::c_char = unsafe { (*data).set.ssl.primary.clientcert };
     let mut ssl_cert_blob: *const curl_blob = unsafe { (*data).set.ssl.primary.cert_blob };
     let mut ca_info_blob: *const curl_blob = unsafe { (*conn).ssl_config.ca_info_blob };
     let ssl_cert_type: *const libc::c_char = unsafe { (*data).set.ssl.cert_type };
     let ssl_cafile: *const libc::c_char = if !ca_info_blob.is_null() {
         0 as *mut libc::c_char
     } else {
         unsafe { (*conn).ssl_config.CAfile }
     };
     let ssl_capath: *const libc::c_char = unsafe { (*conn).ssl_config.CApath };
     let verifypeer: bool = unsafe { ((*conn).ssl_config).verifypeer() } != 0;
     let ssl_crlfile: *const libc::c_char = unsafe { (*data).set.ssl.CRLfile }; /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
     let mut error_buffer: [libc::c_char; 256] = [0; 256];
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     let mut imported_native_ca: bool = 0 as i32 != 0;
     /* Make funny stuff to get random input */
     #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
     if ssl_connect_1 as u32 == unsafe { (*connssl).connecting_state as u32 } {
     } else {
         unsafe {
             __assert_fail(
                 b"ssl_connect_1 == connssl->connecting_state\0" as *const u8 as *const libc::c_char,
                 b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                 2628 as u32,
                 (*::std::mem::transmute::<&[u8; 75], &[libc::c_char; 75]>(
                     b"CURLcode ossl_connect_step1(struct Curl_easy *, struct connectdata *, int)\0",
                 ))
                 .as_ptr(),
             );
         }
     }
     result = ossl_seed(data);
     if result as u64 != 0 {
         return result;
     }
     unsafe {
         (*data).set.ssl.certverifyresult = (0 as i32 == 0) as i64;
     }
     /* check to see if we've been told to use an explicit SSL/TLS version */
     match ssl_version {
         0 | 1 | 4 | 5 | 6 | 7 => {
             req_method = unsafe { TLS_client_method() }; /* it will be handled later with the context options */
             sni = 1 as i32 != 0;
         }
         2 => {
             unsafe {
                 Curl_failf(
                     data,
                     b"No SSLv2 support\0" as *const u8 as *const libc::c_char,
                 );
             }
             return CURLE_NOT_BUILT_IN;
         }
         3 => {
             unsafe {
                 Curl_failf(
                     data,
                     b"No SSLv3 support\0" as *const u8 as *const libc::c_char,
                 );
             }
             return CURLE_NOT_BUILT_IN;
         }
         _ => {
             unsafe {
                 Curl_failf(
                     data,
                     b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8
                         as *const libc::c_char,
                 );
             }
             return CURLE_SSL_CONNECT_ERROR;
         }
     }
     #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
     if unsafe { ((*backend).ctx).is_null() } {
     } else {
         unsafe {
             __assert_fail(
                 b"!backend->ctx\0" as *const u8 as *const libc::c_char,
                 b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                 2665 as u32,
                 (*::std::mem::transmute::<&[u8; 75], &[libc::c_char; 75]>(
                     b"CURLcode ossl_connect_step1(struct Curl_easy *, struct connectdata *, int)\0",
                 ))
                 .as_ptr(),
             );
         }
     }
     unsafe {
         (*backend).ctx = SSL_CTX_new(req_method);
         if ((*backend).ctx).is_null() {
             Curl_failf(
                 data,
                 b"SSL: couldn't create a context: %s\0" as *const u8 as *const libc::c_char,
                 ossl_strerror(
                     ERR_peek_error(),
                     error_buffer.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                 ),
             );
             return CURLE_OUT_OF_MEMORY;
         }
         SSL_CTX_ctrl(
             (*backend).ctx,
             33 as i32,
             0x10 as i64,
             0 as *mut libc::c_void,
         );
         if ((*data).set.fdebug).is_some() && ((*data).set).verbose() as i32 != 0 {
             /* the SSL trace callback is only used for verbose logging */
             SSL_CTX_set_msg_callback(
                 (*backend).ctx,
                 Some(
                     ossl_trace
                         as unsafe extern "C" fn(
                             i32,
                             i32,
                             i32,
                             *const libc::c_void,
                             size_t,
                             *mut SSL,
                             *mut libc::c_void,
                         ) -> (),
                 ),
             );
             SSL_CTX_ctrl(
                 (*backend).ctx,
                 16 as i32,
                 0 as i64,
                 conn as *mut libc::c_void,
             );
             (*(*conn).ssl[0 as usize].backend).logger = data;
         }
     }
     /* OpenSSL contains code to work around lots of bugs and flaws in various
        SSL-implementations. SSL_CTX_set_options() is used to enabled those
        work-arounds. The man page for this option states that SSL_OP_ALL enables
        all the work-arounds and that "It is usually safe to use SSL_OP_ALL to
        enable the bug workaround options if compatibility with somewhat broken
        implementations is desired."
 
        The "-no_ticket" option was introduced in OpenSSL 0.9.8j. It's a flag to
        disable "rfc4507bis session ticket support".  rfc4507bis was later turned
        into the proper RFC5077 it seems: https://tools.ietf.org/html/rfc5077
 
        The enabled extension concerns the session management. I wonder how often
        libcurl stops a connection and then resumes a TLS session. Also, sending
        the session data is some overhead. I suggest that you just use your
        proposed patch (which explicitly disables TICKET).
 
        If someone writes an application with libcurl and OpenSSL who wants to
        enable the feature, one can do this in the SSL callback.
 
        SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG option enabling allowed proper
        interoperability with web server Netscape Enterprise Server 2.0.1 which
        was released back in 1996.
 
        Due to CVE-2010-4180, option SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG has
        become ineffective as of OpenSSL 0.9.8q and 1.0.0c. In order to mitigate
        CVE-2010-4180 when using previous OpenSSL versions we no longer enable
        this option regardless of OpenSSL version and SSL_OP_ALL definition.
 
        OpenSSL added a work-around for a SSL 3.0/TLS 1.0 CBC vulnerability
        (https://www.openssl.org/~bodo/tls-cbc.txt). In 0.9.6e they added a bit to
        SSL_OP_ALL that _disables_ that work-around despite the fact that
        SSL_OP_ALL is documented to do "rather harmless" workarounds. In order to
        keep the secure work-around, the SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS bit
        must not be set.
     */
     ctx_options =
         (0x80000000 as u32 | 0x800 as u32 | 0x4 as u32 | 0x10 as u32 | 0x40 as u32) as ctx_option_t;
     ctx_options |= 0x4000 as i64;
     ctx_options |= 0x20000 as i64;
     ctx_options &= !(0 as i32) as i64;
     if unsafe { ((*data).set.ssl).enable_beast() == 0 } {
         ctx_options &= !(0x800 as u32) as i64;
     }
     let mut current_block_41: u64;
     match ssl_version {
         2 | 3 => return CURLE_NOT_BUILT_IN,
         0 | 1 => {
             current_block_41 = 14687600604451543688;
         }
         4 => {
             current_block_41 = 14687600604451543688;
         }
         5 => {
             current_block_41 = 9382186424990608957;
         }
         6 | 7 => {
             current_block_41 = 4869852262838046136;
         }
         _ => {
             unsafe {
                 Curl_failf(
                     data,
                     b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8
                         as *const libc::c_char,
                 );
             }
             return CURLE_SSL_CONNECT_ERROR;
         }
     }
     match current_block_41 {
         14687600604451543688 => {
             current_block_41 = 9382186424990608957;
         }
         _ => {}
     }
     match current_block_41 {
         9382186424990608957 => {}
         _ => {}
     }
     /* asking for any TLS version as the minimum, means no SSL versions
     allowed */
     ctx_options |= 0 as i64;
     ctx_options |= 0x2000000 as i64;
     result = unsafe { set_ssl_version_min_max((*backend).ctx, conn) };
     if result as u32 != CURLE_OK as u32 {
         return result;
     }
     unsafe {
         SSL_CTX_set_options((*backend).ctx, ctx_options as u64);
 
         // ************************************************************************
         #[cfg(HAS_NPN)]
         if ((*conn).bits).tls_enable_npn() != 0 {
             SSL_CTX_set_next_proto_select_cb(
                 (*backend).ctx,
                 Some(
                     select_next_proto_cb
                         as unsafe extern "C" fn(
                             *mut SSL,
                             *mut *mut u8,
                             *mut u8,
                             *const u8,
                             u32,
                             *mut libc::c_void,
                         ) -> i32,
                 ),
                 data as *mut libc::c_void,
             );
         }
     }
     #[cfg(HAS_APLN)]
     if unsafe { ((*conn).bits).tls_enable_alpn() != 0 } {
         let mut cur: i32 = 0 as i32;
         let mut protocols: [u8; 128] = [0; 128];
         if cfg!(USE_HTTP2) {
             unsafe {
                 #[cfg(not(CURL_DISABLE_PROXY))]
                 let CURL_DISABLE_PROXY_flag_1 = (!(CURLPROXY_HTTPS as u32
                     == (*conn).http_proxy.proxytype as u32
                     && ssl_connection_complete as u32
                         != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                             0 as i32
                         } else {
                             1 as i32
                         }) as usize]
                             .state as u32)
                     || ((*conn).bits).tunnel_proxy() == 0);
                 #[cfg(CURL_DISABLE_PROXY)]
                 let CURL_DISABLE_PROXY_flag_1 = true;
                 if (*data).state.httpwant as i32 >= CURL_HTTP_VERSION_2_0 as i32
                     && CURL_DISABLE_PROXY_flag_1
                 {
                     let fresh10 = cur;
                     cur = cur + 1;
                     protocols[fresh10 as usize] = 2 as u8;
                     memcpy(
                         &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut u8
                             as *mut libc::c_void,
                         b"h2\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                         2 as u64,
                     );
                     cur += 2 as i32;
                     Curl_infof(
                         data,
                         b"ALPN, offering %s\0" as *const u8 as *const libc::c_char,
                         b"h2\0" as *const u8 as *const libc::c_char,
                     );
                 }
             }
         }
         let fresh11 = cur;
         cur = cur + 1;
         protocols[fresh11 as usize] = 8 as u8;
         unsafe {
             memcpy(
                 &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut u8 as *mut libc::c_void,
                 b"http/1.1\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                 8 as u64,
             );
         }
         cur += 8 as i32;
         unsafe {
             Curl_infof(
                 data,
                 b"ALPN, offering %s\0" as *const u8 as *const libc::c_char,
                 b"http/1.1\0" as *const u8 as *const libc::c_char,
             );
         }
         /* expects length prefixed preference ordered list of protocols in wire
          * format
          */
         if unsafe { SSL_CTX_set_alpn_protos((*backend).ctx, protocols.as_mut_ptr(), cur as u32) }
             != 0
         {
             unsafe {
                 Curl_failf(
                     data,
                     b"Error setting ALPN\0" as *const u8 as *const libc::c_char,
                 );
             }
             return CURLE_SSL_CONNECT_ERROR;
         }
     }
 
     if !ssl_cert.is_null() || !ssl_cert_blob.is_null() || !ssl_cert_type.is_null() {
         unsafe {
             #[cfg(not(CURL_DISABLE_PROXY))]
             let cert_stuff_flag = cert_stuff(
                 data,
                 (*backend).ctx,
                 ssl_cert,
                 ssl_cert_blob,
                 ssl_cert_type,
                 (if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                     && ssl_connection_complete as u32
                         != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                             0 as i32
                         } else {
                             1 as i32
                         }) as usize]
                             .state as u32
                 {
                     (*data).set.proxy_ssl.key
                 } else {
                     (*data).set.ssl.key
                 }),
                 (if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                     && ssl_connection_complete as u32
                         != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                             0 as i32
                         } else {
                             1 as i32
                         }) as usize]
                             .state as u32
                 {
                     (*data).set.proxy_ssl.key_blob
                 } else {
                     (*data).set.ssl.key_blob
                 }),
                 (if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                     && ssl_connection_complete as u32
                         != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                             0 as i32
                         } else {
                             1 as i32
                         }) as usize]
                             .state as u32
                 {
                     (*data).set.proxy_ssl.key_type
                 } else {
                     (*data).set.ssl.key_type
                 }),
                 (if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                     && ssl_connection_complete as u32
                         != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                             0 as i32
                         } else {
                             1 as i32
                         }) as usize]
                             .state as u32
                 {
                     (*data).set.proxy_ssl.key_passwd
                 } else {
                     (*data).set.ssl.key_passwd
                 }),
             );
             #[cfg(CURL_DISABLE_PROXY)]
             let cert_stuff_flag = cert_stuff(
                 data,
                 (*backend).ctx,
                 ssl_cert,
                 ssl_cert_blob,
                 ssl_cert_type,
                 (*data).set.ssl.key,
                 (*data).set.ssl.key_blob,
                 (*data).set.ssl.key_type,
                 (*data).set.ssl.key_passwd,
             );
             if result as u64 == 0 && cert_stuff_flag == 0 {
                 result = CURLE_SSL_CERTPROBLEM;
             }
             if result as u64 != 0 {
                 /* failf() is already done in cert_stuff() */
                 return result;
             }
         }
     }
     unsafe {
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_CONN_CONFIG_cipher_list = if CURLPROXY_HTTPS as u32
             == (*conn).http_proxy.proxytype as u32
             && ssl_connection_complete as u32
                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
         {
             (*conn).proxy_ssl_config.cipher_list
         } else {
             (*conn).ssl_config.cipher_list
         };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_CONN_CONFIG_cipher_list = (*conn).ssl_config.cipher_list;
         ciphers = SSL_CONN_CONFIG_cipher_list;
         if ciphers.is_null() {
             ciphers = 0 as *mut libc::c_char;
         }
         if !ciphers.is_null() {
             if SSL_CTX_set_cipher_list((*backend).ctx, ciphers) == 0 {
                 Curl_failf(
                     data,
                     b"failed setting cipher list: %s\0" as *const u8 as *const libc::c_char,
                     ciphers,
                 );
                 return CURLE_SSL_CIPHER;
             }
             Curl_infof(
                 data,
                 b"Cipher selection: %s\0" as *const u8 as *const libc::c_char,
                 ciphers,
             );
         }
 
         // ***************************************************************
         #[cfg(all(HAVE_SSL_CTX_SET_CIPHERSUITES, not(CURL_DISABLE_PROXY)))]
         let mut ciphers13: *mut libc::c_char = if CURLPROXY_HTTPS as u32
             == (*conn).http_proxy.proxytype as u32
             && ssl_connection_complete as u32
                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
         {
             (*conn).proxy_ssl_config.cipher_list13
         } else {
             (*conn).ssl_config.cipher_list13
         };
 
         #[cfg(all(HAVE_SSL_CTX_SET_CIPHERSUITES, CURL_DISABLE_PROXY))]
         let mut ciphers13: *mut libc::c_char = (*conn).ssl_config.cipher_list13;
         #[cfg(HAVE_SSL_CTX_SET_CIPHERSUITES)]
         if !ciphers13.is_null() {
             if SSL_CTX_set_ciphersuites((*backend).ctx, ciphers13) == 0 {
                 Curl_failf(
                     data,
                     b"failed setting TLS 1.3 cipher suite: %s\0" as *const u8
                         as *const libc::c_char,
                     ciphers13,
                 );
                 return CURLE_SSL_CIPHER;
             }
             Curl_infof(
                 data,
                 b"TLS 1.3 cipher selection: %s\0" as *const u8 as *const libc::c_char,
                 ciphers13,
             );
         }
         /* OpenSSL 1.1.1 requires clients to opt-in for PHA */
         #[cfg(HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH)]
         SSL_CTX_set_post_handshake_auth((*backend).ctx, 1 as i32);
         #[cfg(all(HAVE_SSL_CTX_SET_EC_CURVES, not(CURL_DISABLE_PROXY)))]
         let mut curves: *mut libc::c_char = if CURLPROXY_HTTPS as u32
             == (*conn).http_proxy.proxytype as u32
             && ssl_connection_complete as u32
                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
         {
             (*conn).proxy_ssl_config.curves
         } else {
             (*conn).ssl_config.curves
         };
         #[cfg(all(HAVE_SSL_CTX_SET_EC_CURVES, CURL_DISABLE_PROXY))]
         let mut curves: *mut libc::c_char = (*conn).ssl_config.curves;
         #[cfg(HAVE_SSL_CTX_SET_EC_CURVES)]
         if !curves.is_null() {
             if SSL_CTX_ctrl(
                 (*backend).ctx,
                 92 as i32,
                 0 as i64,
                 curves as *mut libc::c_void,
             ) == 0
             {
                 Curl_failf(
                     data,
                     b"failed setting curves list: '%s'\0" as *const u8 as *const libc::c_char,
                     curves,
                 );
                 return CURLE_SSL_CIPHER;
             }
         }
         // #[cfg(USE_OPENSSL_SRP)]
         if ssl_authtype as u32 == CURL_TLSAUTH_SRP as u32 {
             #[cfg(not(CURL_DISABLE_PROXY))]
             let ssl_username: *mut libc::c_char = if CURLPROXY_HTTPS as u32
                 == (*conn).http_proxy.proxytype as u32
                 && ssl_connection_complete as u32
                     != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                         0 as i32
                     } else {
                         1 as i32
                     }) as usize]
                         .state as u32
             {
                 (*data).set.proxy_ssl.username
             } else {
                 (*data).set.ssl.username
             };
             #[cfg(CURL_DISABLE_PROXY)]
             let ssl_username: *mut libc::c_char = (*data).set.ssl.username;
             Curl_infof(
                 data,
                 b"Using TLS-SRP username: %s\0" as *const u8 as *const libc::c_char,
                 ssl_username,
             );
             if SSL_CTX_set_srp_username((*backend).ctx, ssl_username) == 0 {
                 Curl_failf(
                     data,
                     b"Unable to set SRP user name\0" as *const u8 as *const libc::c_char,
                 );
                 return CURLE_BAD_FUNCTION_ARGUMENT;
             }
             #[cfg(not(CURL_DISABLE_PROXY))]
             if SSL_CTX_set_srp_password(
                 (*backend).ctx,
                 (if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                     && ssl_connection_complete as u32
                         != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                             0 as i32
                         } else {
                             1 as i32
                         }) as usize]
                             .state as u32
                 {
                     (*data).set.proxy_ssl.password
                 } else {
                     (*data).set.ssl.password
                 }),
             ) == 0
             {
                 Curl_failf(
                     data,
                     b"failed setting SRP password\0" as *const u8 as *const libc::c_char,
                 );
                 return CURLE_BAD_FUNCTION_ARGUMENT;
             }
             #[cfg(CURL_DISABLE_PROXY)]
             if SSL_CTX_set_srp_password((*backend).ctx, (*data).set.ssl.password) == 0 {
                 Curl_failf(
                     data,
                     b"failed setting SRP password\0" as *const u8 as *const libc::c_char,
                 );
                 return CURLE_BAD_FUNCTION_ARGUMENT;
             }
 
             #[cfg(not(CURL_DISABLE_PROXY))]
             if if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                 && ssl_connection_complete as u32
                     != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                         0 as i32
                     } else {
                         1 as i32
                     }) as usize]
                         .state as u32
             {
                 (*conn).proxy_ssl_config.cipher_list
             } else {
                 (*conn).ssl_config.cipher_list
             }
             .is_null()
             {
                 Curl_infof(
                     data,
                     b"Setting cipher list SRP\0" as *const u8 as *const libc::c_char,
                 );
                 if SSL_CTX_set_cipher_list(
                     (*backend).ctx,
                     b"SRP\0" as *const u8 as *const libc::c_char,
                 ) == 0
                 {
                     Curl_failf(
                         data,
                         b"failed setting SRP cipher list\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_SSL_CIPHER;
                 }
             }
             #[cfg(CURL_DISABLE_PROXY)]
             if ((*conn).ssl_config.cipher_list).is_null() {
                 Curl_infof(
                     data,
                     b"Setting cipher list SRP\0" as *const u8 as *const libc::c_char,
                 );
                 if SSL_CTX_set_cipher_list(
                     (*backend).ctx,
                     b"SRP\0" as *const u8 as *const libc::c_char,
                 ) == 0
                 {
                     Curl_failf(
                         data,
                         b"failed setting SRP cipher list\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_SSL_CIPHER;
                 }
             }
         }
     }
     if !ca_info_blob.is_null() {
         result = unsafe { load_cacert_from_memory((*backend).ctx, ca_info_blob) };
         if result as u64 != 0 {
             if result as u32 == CURLE_OUT_OF_MEMORY as u32
                 || verifypeer as i32 != 0 && !imported_native_ca
             {
                 /* Fail if we insist on successfully verifying the server. */
                 unsafe {
                     Curl_failf(
                         data,
                         b"error importing CA certificate blob\0" as *const u8
                             as *const libc::c_char,
                     );
                 }
                 return result;
             }
             /* Continue with warning if certificate verification isn't required. */
             unsafe {
                 Curl_infof(
                     data,
                     b"error importing CA certificate blob, continuing anyway\0" as *const u8
                         as *const libc::c_char,
                 );
             }
         }
     }
     if !ssl_cafile.is_null() || !ssl_capath.is_null() {
         /* tell SSL where to find CA certificates that are used to verify
         the server's certificate. */
         if unsafe { SSL_CTX_load_verify_locations((*backend).ctx, ssl_cafile, ssl_capath) } == 0 {
             if verifypeer as i32 != 0 && !imported_native_ca {
                 /* Fail if we insist on successfully verifying the server. */
                 unsafe {
                     Curl_failf(
                         data,
                         b"error setting certificate verify locations:  CAfile: %s CApath: %s\0"
                             as *const u8 as *const libc::c_char,
                         if !ssl_cafile.is_null() {
                             ssl_cafile
                         } else {
                             b"none\0" as *const u8 as *const libc::c_char
                         },
                         if !ssl_capath.is_null() {
                             ssl_capath
                         } else {
                             b"none\0" as *const u8 as *const libc::c_char
                         },
                     );
                 }
                 return CURLE_SSL_CACERT_BADFILE;
             }
             /* Just continue with a warning if no strict certificate verification
             is required. */
             unsafe {
                 Curl_infof(
                     data,
                     b"error setting certificate verify locations, continuing anyway:\0" as *const u8
                         as *const libc::c_char,
                 );
             }
         } else {
             /* Everything is fine. */
             unsafe {
                 Curl_infof(
                     data,
                     b"successfully set certificate verify locations:\0" as *const u8
                         as *const libc::c_char,
                 );
             }
         }
         unsafe {
             Curl_infof(
                 data,
                 b" CAfile: %s\0" as *const u8 as *const libc::c_char,
                 if !ssl_cafile.is_null() {
                     ssl_cafile
                 } else {
                     b"none\0" as *const u8 as *const libc::c_char
                 },
             );
             Curl_infof(
                 data,
                 b" CApath: %s\0" as *const u8 as *const libc::c_char,
                 if !ssl_capath.is_null() {
                     ssl_capath
                 } else {
                     b"none\0" as *const u8 as *const libc::c_char
                 },
             );
         }
     }
 
     if !ssl_crlfile.is_null() {
         /* tell OpenSSL where to find CRL file that is used to check certificate
          * revocation */
         lookup = unsafe {
             X509_STORE_add_lookup(SSL_CTX_get_cert_store((*backend).ctx), X509_LOOKUP_file())
         };
         if lookup.is_null() || unsafe { X509_load_crl_file(lookup, ssl_crlfile, 1 as i32) } == 0 {
             unsafe {
                 Curl_failf(
                     data,
                     b"error loading CRL file: %s\0" as *const u8 as *const libc::c_char,
                     ssl_crlfile,
                 );
             }
             return CURLE_SSL_CRL_BADFILE;
         }
         /* Everything is fine. */
         unsafe {
             Curl_infof(
                 data,
                 b"successfully loaded CRL file:\0" as *const u8 as *const libc::c_char,
             );
             X509_STORE_set_flags(
                 SSL_CTX_get_cert_store((*backend).ctx),
                 (0x4 as i32 | 0x8 as i32) as u64,
             );
             Curl_infof(
                 data,
                 b"  CRLfile: %s\0" as *const u8 as *const libc::c_char,
                 ssl_crlfile,
             );
         }
     }
     if verifypeer {
         /* Try building a chain using issuers in the trusted store first to avoid
            problems with server-sent legacy intermediates.  Newer versions of
            OpenSSL do alternate chain checking by default but we do not know how to
            determine that in a reliable manner.
            https://rt.openssl.org/Ticket/Display.html?id=3621&user=guest&pass=guest
         */
         unsafe {
             X509_STORE_set_flags(SSL_CTX_get_cert_store((*backend).ctx), 0x8000 as u64);
             if ((*data).set.ssl).no_partialchain() == 0 && ssl_crlfile.is_null() {
                 /* Have intermediate certificates in the trust store be treated as
                    trust-anchors, in the same way as self-signed root CA certificates
                    are. This allows users to verify servers using the intermediate cert
                    only, instead of needing the whole chain.
 
                    Due to OpenSSL bug https://github.com/openssl/openssl/issues/5081 we
                    cannot do partial chains with a CRL check.
                 */
                 X509_STORE_set_flags(SSL_CTX_get_cert_store((*backend).ctx), 0x80000 as u64);
             }
         }
     }
     /* OpenSSL always tries to verify the peer, this only says whether it should
      * fail to connect if the verification fails, or if it should continue
      * anyway. In the latter case the result of the verification is checked with
      * SSL_get_verify_result() below. */
     unsafe {
         SSL_CTX_set_verify(
             (*backend).ctx,
             if verifypeer as i32 != 0 {
                 0x1 as i32
             } else {
                 0 as i32
             },
             None,
         );
         /* Enable logging of secrets to the file specified in env SSLKEYLOGFILE. */
         #[cfg(HAVE_KEYLOG_CALLBACK)]
         if Curl_tls_keylog_enabled() {
             SSL_CTX_set_keylog_callback(
                 (*backend).ctx,
                 Some(
                     ossl_keylog_callback
                         as unsafe extern "C" fn(*const SSL, *const libc::c_char) -> (),
                 ),
             );
         }
         SSL_CTX_ctrl(
             (*backend).ctx,
             44 as i32,
             (0x1 as i32 | (0x100 as i32 | 0x200 as i32)) as i64,
             0 as *mut libc::c_void,
         );
         /* Enable the session cache because it's a prerequisite for the "new session"
          * callback. Use the "external storage" mode to prevent OpenSSL from creating
          * an internal session cache.
          */
         SSL_CTX_sess_set_new_cb(
             (*backend).ctx,
             Some(ossl_new_session_cb as unsafe extern "C" fn(*mut SSL, *mut SSL_SESSION) -> i32),
         );
         /* give application a chance to interfere with SSL set up. */
         if ((*data).set.ssl.fsslctx).is_some() {
             Curl_set_in_callback(data, 1 as i32 != 0);
             result = (Some(((*data).set.ssl.fsslctx).expect("non-null function pointer")))
                 .expect("non-null function pointer")(
                 data,
                 (*backend).ctx as *mut libc::c_void,
                 (*data).set.ssl.fsslctxp,
             );
             Curl_set_in_callback(data, 0 as i32 != 0);
             if result as u64 != 0 {
                 Curl_failf(
                     data,
                     b"error signaled by ssl ctx callback\0" as *const u8 as *const libc::c_char,
                 );
                 return result;
             }
         }
         /* Let's make an SSL structure */
         if !((*backend).handle).is_null() {
             SSL_free((*backend).handle);
         }
         (*backend).handle = SSL_new((*backend).ctx);
         if ((*backend).handle).is_null() {
             Curl_failf(
                 data,
                 b"SSL: couldn't create a context (handle)!\0" as *const u8 as *const libc::c_char,
             );
             return CURLE_OUT_OF_MEMORY;
         }
         if ((*conn).ssl_config).verifystatus() != 0 {
             SSL_ctrl(
                 (*backend).handle,
                 65 as i32,
                 1 as i64,
                 0 as *mut libc::c_void,
             );
         }
         SSL_set_connect_state((*backend).handle);
         (*backend).server_cert = 0 as *mut X509;
         if 0 as i32
             == inet_pton(
                 2 as i32,
                 hostname,
                 &mut addr as *mut in_addr as *mut libc::c_void,
             )
             && sni as i32 != 0
         {
             let mut nlen: size_t = strlen(hostname);
             if nlen as i64 >= (*data).set.buffer_size {
                 /* this is seriously messed up */
                 return CURLE_SSL_CONNECT_ERROR;
             }
             /* RFC 6066 section 3 says the SNI field is case insensitive, but browsers
             send the data lowercase and subsequently there are now numerous servers
             out there that don't work unless the name is lowercased */
             Curl_strntolower((*data).state.buffer, hostname, nlen);
             *((*data).state.buffer).offset(nlen as isize) = 0 as libc::c_char;
             if SSL_ctrl(
                 (*backend).handle,
                 55 as i32,
                 0 as i64,
                 (*data).state.buffer as *mut libc::c_void,
             ) == 0
             {
                 /* Informational message */
                 Curl_infof(
                     data,
                     b"WARNING: failed to configure server name indication (SNI) TLS extension\0"
                         as *const u8 as *const libc::c_char,
                 );
             }
         }
     }
 
     ossl_associate_connection(data, conn, sockindex);
     Curl_ssl_sessionid_lock(data);
     if !Curl_ssl_getsessionid(
         data,
         conn,
         if 0 as i32 != 0 { 1 as i32 } else { 0 as i32 } != 0,
         &mut ssl_sessionid,
         0 as *mut size_t,
         sockindex,
     ) {
         unsafe {
             /* we got a session id, use it! */
             if SSL_set_session((*backend).handle, ssl_sessionid as *mut SSL_SESSION) == 0 {
                 Curl_ssl_sessionid_unlock(data);
                 /* pass the raw socket into the SSL layers */
                 Curl_failf(
                     data,
                     b"SSL: SSL_set_session failed: %s\0" as *const u8 as *const libc::c_char,
                     ossl_strerror(
                         ERR_get_error(),
                         error_buffer.as_mut_ptr(),
                         ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                     ),
                 );
                 return CURLE_SSL_CONNECT_ERROR;
             }
             /* Informational message */
             Curl_infof(
                 data,
                 b"SSL re-using session ID\0" as *const u8 as *const libc::c_char,
             );
         }
     }
     Curl_ssl_sessionid_unlock(data);
     #[cfg(not(CURL_DISABLE_PROXY))]
     if unsafe { ((*conn).proxy_ssl[sockindex as usize]).use_0() } != 0 {
         let bio: *mut BIO = unsafe { BIO_new(BIO_f_ssl()) };
         let mut handle: *mut SSL =
             unsafe { (*(*conn).proxy_ssl[sockindex as usize].backend).handle };
         unsafe {
             #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
             if ssl_connection_complete as u32 == (*conn).proxy_ssl[sockindex as usize].state as u32
             {
             } else {
                 __assert_fail(
                 b"ssl_connection_complete == conn->proxy_ssl[sockindex].state\0" as *const u8
                     as *const libc::c_char,
                 b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                 3264 as u32,
                 (*::std::mem::transmute::<&[u8; 75], &[libc::c_char; 75]>(
                     b"CURLcode ossl_connect_step1(struct Curl_easy *, struct connectdata *, int)\0",
                 ))
                 .as_ptr(),
             );
             }
             #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
             if !handle.is_null() {
             } else {
                 __assert_fail(
                 b"handle != ((void*)0)\0" as *const u8 as *const libc::c_char,
                 b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                 3265 as u32,
                 (*::std::mem::transmute::<&[u8; 75], &[libc::c_char; 75]>(
                     b"CURLcode ossl_connect_step1(struct Curl_easy *, struct connectdata *, int)\0",
                 ))
                 .as_ptr(),
             );
             }
             #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
             if !bio.is_null() {
             } else {
                 __assert_fail(
                 b"bio != ((void*)0)\0" as *const u8 as *const libc::c_char,
                 b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                 3266 as u32,
                 (*::std::mem::transmute::<&[u8; 75], &[libc::c_char; 75]>(
                     b"CURLcode ossl_connect_step1(struct Curl_easy *, struct connectdata *, int)\0",
                 ))
                 .as_ptr(),
             );
             }
             BIO_ctrl(bio, 109 as i32, 0 as i64, handle as *mut libc::c_void);
             SSL_set_bio((*backend).handle, bio, bio);
         }
     } else if unsafe { SSL_set_fd((*backend).handle, sockfd) == 0 } {
         unsafe {
             Curl_failf(
                 data,
                 b"SSL: SSL_set_fd failed: %s\0" as *const u8 as *const libc::c_char,
                 ossl_strerror(
                     ERR_get_error(),
                     error_buffer.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                 ),
             );
         }
         return CURLE_SSL_CONNECT_ERROR;
     }

     unsafe {
        #[cfg(CURL_DISABLE_PROXY)]
        if SSL_set_fd((*backend).handle, sockfd) == 0 {
            /* pass the raw socket into the SSL layers */
            Curl_failf(
                data,
                b"SSL: SSL_set_fd failed: %s\0" as *const u8 as *const libc::c_char,
                ossl_strerror(
                    ERR_get_error(),
                    error_buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                ),
            );
        return CURLE_SSL_CONNECT_ERROR;
    }
         (*connssl).connecting_state = ssl_connect_2;
     }
     return CURLE_OK;
 }
 
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_connect_step2(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) -> CURLcode {
     let mut err: i32 = 0;
     let mut connssl: *mut ssl_connect_data =
         unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }
             as *mut ssl_connect_data;
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     unsafe {
         #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
         if ssl_connect_2 as u32 == (*connssl).connecting_state as u32
             || ssl_connect_2_reading as u32 == (*connssl).connecting_state as u32
             || ssl_connect_2_writing as u32 == (*connssl).connecting_state as u32
         {
         } else {
             __assert_fail(
              b"ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state\0"
                  as *const u8 as *const libc::c_char,
              b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
              3292 as u32,
              (*::std::mem::transmute::<
                  &[u8; 75],
                  &[libc::c_char; 75],
              >(
                  b"CURLcode ossl_connect_step2(struct Curl_easy *, struct connectdata *, int)\0",
              ))
                  .as_ptr(),
          );
         }
         ERR_clear_error();
 
         err = SSL_connect((*backend).handle);
     }
     /* 1  is fine
     0  is "not successful but was shut down controlled"
     <0 is "handshake was not successful, because a fatal error occurred" */
     // TODO
     // #[cfg(HAVE_KEYLOG_CALLBACK)]
     if 1 as i32 != err {
         let mut detail: i32 = unsafe { SSL_get_error((*backend).handle, err) };
         if 2 as i32 == detail {
             unsafe {
                 (*connssl).connecting_state = ssl_connect_2_reading;
             }
             return CURLE_OK;
         }
         if 3 as i32 == detail {
             unsafe {
                 (*connssl).connecting_state = ssl_connect_2_writing;
             }
             return CURLE_OK;
         }
         // TODO if的条件编译
         #[cfg(SSL_ERROR_WANT_ASYNC)]
         let SSL_ERROR_WANT_ASYNC_flag_3 = true;
         #[cfg(not(SSL_ERROR_WANT_ASYNC))]
         let SSL_ERROR_WANT_ASYNC_flag_3 = false;
         if 9 as i32 == detail && SSL_ERROR_WANT_ASYNC_flag_3 {
             unsafe {
                 (*connssl).connecting_state = ssl_connect_2;
             }
             return CURLE_OK;
         } else {
             /* untreated error */
             let mut errdetail: u64 = 0;
             let mut error_buffer: [libc::c_char; 256] = unsafe {
                 *::std::mem::transmute::<
                      &[u8; 256],
                      &mut [libc::c_char; 256],
                  >(
                      b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                  )
             };
             let mut result: CURLcode = CURLE_OK;
             let mut lerr: i64 = 0;
             let mut lib: i32 = 0;
             let mut reason: i32 = 0;
             /* the connection failed, we're not waiting for anything else. */
             unsafe {
                 (*connssl).connecting_state = ssl_connect_2;
             }
             /* Get the earliest error code from the thread's error queue and remove
             the entry. */
             errdetail = unsafe { ERR_get_error() };
             /* Extract which lib and reason */
             lib = (errdetail >> 24 as i64 & 0xff as i64 as u64) as i32;
             reason = (errdetail & 0xfff as u64) as i32;
             if lib == 20 as i32 && (reason == 134 as i32 || reason == 1045 as i32) {
                 result = CURLE_PEER_FAILED_VERIFICATION;
                 lerr = unsafe { SSL_get_verify_result((*backend).handle) };
                 if lerr != 0 as i64 {
                     #[cfg(not(CURL_DISABLE_PROXY))]
                     if true {
                         *if CURLPROXY_HTTPS as u32 == unsafe { (*conn).http_proxy.proxytype as u32 }
                             && ssl_connection_complete as u32
                                 != unsafe {
                                     (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                                         0 as i32
                                     } else {
                                         1 as i32
                                     })
                                         as usize]
                                         .state as u32
                                 }
                         {
                             unsafe { &mut (*data).set.proxy_ssl.certverifyresult }
                         } else {
                             unsafe { &mut (*data).set.ssl.certverifyresult }
                         } = lerr;
                     }
                     #[cfg(CURL_DISABLE_PROXY)]
                     if true {
                         unsafe {
                             (*data).set.ssl.certverifyresult = lerr;
                         }
                     }
                     unsafe {
                         curl_msnprintf(
                             error_buffer.as_mut_ptr(),
                             ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                             b"SSL certificate problem: %s\0" as *const u8 as *const libc::c_char,
                             X509_verify_cert_error_string(lerr),
                         );
                     }
                 } else {
                     /* strcpy() is fine here as long as the string fits within
                     error_buffer */
                     unsafe {
                         strcpy(
                             error_buffer.as_mut_ptr(),
                             b"SSL certificate verification failed\0" as *const u8
                                 as *const libc::c_char,
                         );
                     }
                 }
                 // else if的条件编译
                 /* SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED is only available on
                 OpenSSL version above v1.1.1, not LibreSSL nor BoringSSL */
             } else if lib == 20 as i32 && reason == 1116 as i32 {
                 /* If client certificate is required, communicate the
                 error to client */
                 result = CURLE_SSL_CLIENTCERT;
                 ossl_strerror(
                     errdetail,
                     error_buffer.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                 );
             } else {
                 result = CURLE_SSL_CONNECT_ERROR;
                 ossl_strerror(
                     errdetail,
                     error_buffer.as_mut_ptr(),
                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                 );
             }
             /* detail is already set to the SSL error above */
 
             /* If we e.g. use SSLv2 request-method and the server doesn't like us
              * (RST connection, etc.), OpenSSL gives no explanation whatsoever and
              * the SO_ERROR is also lost.
              */
             if CURLE_SSL_CONNECT_ERROR as u32 == result as u32 && errdetail == 0 as u64 {
                 unsafe {
                     #[cfg(not(CURL_DISABLE_PROXY))]
                     let hostname: *const libc::c_char = if CURLPROXY_HTTPS as u32
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
                     let hostname: *const libc::c_char = (*conn).host.name;
                     #[cfg(not(CURL_DISABLE_PROXY))]
                     let port: i64 = (if CURLPROXY_HTTPS as u32
                         == (*conn).http_proxy.proxytype as u32
                         && ssl_connection_complete as u32
                             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                                 0 as i32
                             } else {
                                 1 as i32
                             }) as usize]
                                 .state as u32
                     {
                         (*conn).port
                     } else {
                         (*conn).remote_port
                     }) as i64;
                     #[cfg(CURL_DISABLE_PROXY)]
                     let port: i64 = (*conn).remote_port as i64;
                     let mut extramsg: [libc::c_char; 80] = *::std::mem::transmute::<
                          &[u8; 80],
                          &mut [libc::c_char; 80],
                      >(
                          b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                      );
                     let mut sockerr: i32 = *__errno_location();
                     if sockerr != 0 && detail == 5 as i32 {
                         Curl_strerror(
                             sockerr,
                             extramsg.as_mut_ptr(),
                             ::std::mem::size_of::<[libc::c_char; 80]>() as u64,
                         );
                     }
                     Curl_failf(
                         data,
                         b"OpenSSL SSL_connect: %s in connection to %s:%ld \0" as *const u8
                             as *const libc::c_char,
                         if extramsg[0 as usize] as i32 != 0 {
                             extramsg.as_mut_ptr() as *const libc::c_char
                         } else {
                             SSL_ERROR_to_str(detail)
                         },
                         hostname,
                         port,
                     );
                 }
                 return result;
             }
             /* Could be a CERT problem */
             unsafe {
                 Curl_failf(
                     data,
                     b"%s\0" as *const u8 as *const libc::c_char,
                     error_buffer.as_mut_ptr(),
                 );
             }
             return result;
         }
     } else {
         unsafe {
             /* we connected fine, we're not waiting for anything else. */
             (*connssl).connecting_state = ssl_connect_3;
             /* Informational message */
             Curl_infof(
                 data,
                 b"SSL connection using %s / %s\0" as *const u8 as *const libc::c_char,
                 SSL_get_version((*backend).handle),
                 SSL_CIPHER_get_name(SSL_get_current_cipher((*backend).handle)),
             );
             /* Sets data and len to negotiated protocol, len is 0 if no protocol was
              * negotiated
              */
             #[cfg(HAS_APLN)]
             if ((*conn).bits).tls_enable_alpn() != 0 {
                 let mut neg_protocol: *const u8 = 0 as *const u8;
                 let mut len: u32 = 0;
                 SSL_get0_alpn_selected((*backend).handle, &mut neg_protocol, &mut len);
                 if len != 0 {
                     Curl_infof(
                         data,
                         b"ALPN, server accepted to use %.*s\0" as *const u8 as *const libc::c_char,
                         len,
                         neg_protocol,
                     );
                     // TODO if的条件编译
                     #[cfg(USE_HTTP2)]
                     let USE_HTTP2_flag = true;
                     #[cfg(not(USE_HTTP2))]
                     let USE_HTTP2_flag = false;
                     if len == 2 as u32
                         && USE_HTTP2_flag
                         && memcmp(
                             b"h2\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                             neg_protocol as *const libc::c_void,
                             len as u64,
                         ) == 0
                     {
                         (*conn).negnpn = CURL_HTTP_VERSION_2_0 as i32;
                     } else if len == 8 as u32
                         && memcmp(
                             b"http/1.1\0" as *const u8 as *const libc::c_char
                                 as *const libc::c_void,
                             neg_protocol as *const libc::c_void,
                             8 as u64,
                         ) == 0
                     {
                         (*conn).negnpn = CURL_HTTP_VERSION_1_1 as i32;
                     }
                 } else {
                     Curl_infof(
                         data,
                         b"ALPN, server did not agree to a protocol\0" as *const u8
                             as *const libc::c_char,
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
             }
         }
         return CURLE_OK;
     };
 }
 
 #[cfg(USE_OPENSSL)]
 extern "C" fn asn1_object_dump(
     mut a: *mut ASN1_OBJECT,
     mut buf: *mut libc::c_char,
     mut len: size_t,
 ) -> i32 {
     let mut i: i32 = 0;
     let mut ilen: i32 = 0;
     ilen = len as i32;
     if ilen < 0 as i32 {
         return 1 as i32; /* buffer too big */
     }
     i = unsafe { i2t_ASN1_OBJECT(buf, ilen, a) };
     if i >= ilen {
         return 1 as i32; /* buffer too small */
     }
     return 0 as i32;
 }
 // TODO-3474-参数列表有条件编译
 #[cfg(all(USE_OPENSSL, HAVE_OPAQUE_RSA_DSA_DH))]
 extern "C" fn pubkey_show(
     mut data: *mut Curl_easy,
     mut mem: *mut BIO,
     mut num: i32,
     mut type_0: *const libc::c_char,
     mut name: *const libc::c_char,
     mut bn: *const BIGNUM,
 ) {
     let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut namebuf: [libc::c_char; 32] = [0; 32];
     unsafe {
         curl_msnprintf(
             namebuf.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 32]>() as u64,
             b"%s(%s)\0" as *const u8 as *const libc::c_char,
             type_0,
             name,
         );
     }
     if !bn.is_null() {
         unsafe {
             BN_print(mem, bn);
         }
     }
     let mut info_len: i64 = unsafe {
         BIO_ctrl(
             mem,
             3 as i32,
             0 as i64,
             &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
         )
     };
     Curl_ssl_push_certinfo_len(data, num, namebuf.as_mut_ptr(), ptr, info_len as size_t);
     1 as i32 != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
 }
 
 #[cfg(USE_OPENSSL)]
 extern "C" fn X509V3_ext(
     mut data: *mut Curl_easy,
     mut certnum: i32,
     mut exts: *const stack_st_X509_EXTENSION,
 ) {
     let mut i: i32 = 0;
     if sk_X509_EXTENSION_num(exts) <= 0 as i32 {
         /* no extensions, bail out */
         return;
     }
     i = 0 as i32;
     while i < sk_X509_EXTENSION_num(exts) {
         let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
         let mut ext: *mut X509_EXTENSION = sk_X509_EXTENSION_value(exts, i);
         let mut biomem: *mut BUF_MEM = 0 as *mut BUF_MEM;
         let mut namebuf: [libc::c_char; 128] = [0; 128];
         let mut bio_out: *mut BIO = unsafe { BIO_new(BIO_s_mem()) };
         if bio_out.is_null() {
             return;
         }
         obj = unsafe { X509_EXTENSION_get_object(ext) };
         asn1_object_dump(
             obj,
             namebuf.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 128]>() as u64,
         );
         if unsafe { X509V3_EXT_print(bio_out, ext, 0 as u64, 0 as i32) } == 0 {
             unsafe { ASN1_STRING_print(bio_out, X509_EXTENSION_get_data(ext) as *mut ASN1_STRING) };
         }
         unsafe {
             BIO_ctrl(
                 bio_out,
                 115 as i32,
                 0 as i64,
                 &mut biomem as *mut *mut BUF_MEM as *mut libc::c_char as *mut libc::c_void,
             );
             Curl_ssl_push_certinfo_len(
                 data,
                 certnum,
                 namebuf.as_mut_ptr(),
                 (*biomem).data,
                 (*biomem).length,
             );
             BIO_free(bio_out);
         }
         i += 1;
     }
 }
 
 #[cfg(USE_OPENSSL)]
 extern "C" fn get_cert_chain(
     mut data: *mut Curl_easy,
     mut connssl: *mut ssl_connect_data,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut sk: *mut stack_st_X509 = 0 as *mut stack_st_X509;
     let mut i: i32 = 0;
     let mut numcerts: numcert_t = 0;
     let mut mem: *mut BIO = 0 as *mut BIO;
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     sk = unsafe { SSL_get_peer_cert_chain((*backend).handle) };
     if sk.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     numcerts = sk_X509_num(sk);
     result = Curl_ssl_init_certinfo(data, numcerts);
     if result as u64 != 0 {
         return result;
     }
     mem = unsafe { BIO_new(BIO_s_mem()) };
     i = 0 as i32;
     while i < numcerts {
         let mut num: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
         let mut x: *mut X509 = sk_X509_value(sk, i);
         let mut pubkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
         let mut j: i32 = 0;
         let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
         let mut psig: *const ASN1_BIT_STRING = 0 as *const ASN1_BIT_STRING;
         unsafe {
             X509_NAME_print_ex(
                 mem,
                 X509_get_subject_name(x),
                 0 as i32,
                 (1 as i32
                     | 2 as i32
                     | 4 as i32
                     | 0x10 as i32
                     | 0x100 as i32
                     | 0x200 as i32
                     | 8 as i32
                     | (2 as i32) << 16 as i32
                     | (1 as i32) << 23 as i32
                     | 0 as i32) as u64,
             );
             let mut info_len: i64 = BIO_ctrl(
                 mem,
                 3 as i32,
                 0 as i64,
                 &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
             );
 
             Curl_ssl_push_certinfo_len(
                 data,
                 i,
                 b"Subject\0" as *const u8 as *const libc::c_char,
                 ptr,
                 info_len as size_t,
             );
         }
         1 as i32 != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
         unsafe {
             X509_NAME_print_ex(
                 mem,
                 X509_get_issuer_name(x),
                 0 as i32,
                 (1 as i32
                     | 2 as i32
                     | 4 as i32
                     | 0x10 as i32
                     | 0x100 as i32
                     | 0x200 as i32
                     | 8 as i32
                     | (2 as i32) << 16 as i32
                     | (1 as i32) << 23 as i32
                     | 0 as i32) as u64,
             );
         }
         let mut info_len_0: i64 = unsafe {
             BIO_ctrl(
                 mem,
                 3 as i32,
                 0 as i64,
                 &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
             )
         };
         Curl_ssl_push_certinfo_len(
             data,
             i,
             b"Issuer\0" as *const u8 as *const libc::c_char,
             ptr,
             info_len_0 as size_t,
         );
         1 as i32 != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
         unsafe {
             BIO_printf(
                 mem,
                 b"%lx\0" as *const u8 as *const libc::c_char,
                 X509_get_version(x),
             );
         }
         let mut info_len_1: i64 = unsafe {
             BIO_ctrl(
                 mem,
                 3 as i32,
                 0 as i64,
                 &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
             )
         };
         Curl_ssl_push_certinfo_len(
             data,
             i,
             b"Version\0" as *const u8 as *const libc::c_char,
             ptr,
             info_len_1 as size_t,
         );
         1 as i32 != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
         num = unsafe { X509_get_serialNumber(x) };
         if unsafe { (*num).type_0 } == 2 as i32 | 0x100 as i32 {
             unsafe {
                 BIO_puts(mem, b"-\0" as *const u8 as *const libc::c_char);
             }
         }
         j = 0 as i32;
         while j < unsafe { (*num).length } {
             unsafe {
                 BIO_printf(
                     mem,
                     b"%02x\0" as *const u8 as *const libc::c_char,
                     *((*num).data).offset(j as isize) as i32,
                 );
             }
             j += 1;
         }
         let mut info_len_2: i64 = unsafe {
             BIO_ctrl(
                 mem,
                 3 as i32,
                 0 as i64,
                 &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
             )
         };
         Curl_ssl_push_certinfo_len(
             data,
             i,
             b"Serial Number\0" as *const u8 as *const libc::c_char,
             ptr,
             info_len_2 as size_t,
         );
         1 as i32 != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
 
         if cfg!(all(HAVE_X509_GET0_SIGNATURE, HAVE_X509_GET0_EXTENSIONS)) {
             let mut sigalg: *const X509_ALGOR = 0 as *const X509_ALGOR;
             let mut xpubkey: *mut X509_PUBKEY = 0 as *mut X509_PUBKEY;
             let mut pubkeyoid: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
             unsafe {
                 X509_get0_signature(&mut psig, &mut sigalg, x);
             }
             if !sigalg.is_null() {
                 unsafe {
                     i2a_ASN1_OBJECT(mem, (*sigalg).algorithm);
                 }
                 let mut info_len_3: i64 = unsafe {
                     BIO_ctrl(
                         mem,
                         3 as i32,
                         0 as i64,
                         &mut ptr as *mut *mut libc::c_char as *mut libc::c_char
                             as *mut libc::c_void,
                     )
                 };
                 Curl_ssl_push_certinfo_len(
                     data,
                     i,
                     b"Signature Algorithm\0" as *const u8 as *const libc::c_char,
                     ptr,
                     info_len_3 as size_t,
                 );
                 1 as i32
                     != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
             }
             xpubkey = unsafe { X509_get_X509_PUBKEY(x) };
             if !xpubkey.is_null() {
                 unsafe {
                     X509_PUBKEY_get0_param(
                         &mut pubkeyoid,
                         0 as *mut *const u8,
                         0 as *mut i32,
                         0 as *mut *mut X509_ALGOR,
                         xpubkey,
                     );
                     if !pubkeyoid.is_null() {
                         i2a_ASN1_OBJECT(mem, pubkeyoid);
                         let mut info_len_4: i64 = BIO_ctrl(
                             mem,
                             3 as i32,
                             0 as i64,
                             &mut ptr as *mut *mut libc::c_char as *mut libc::c_char
                                 as *mut libc::c_void,
                         );
                         Curl_ssl_push_certinfo_len(
                             data,
                             i,
                             b"Public Key Algorithm\0" as *const u8 as *const libc::c_char,
                             ptr,
                             info_len_4 as size_t,
                         );
                         1 as i32
                             != BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32;
                     }
                 }
             }
             unsafe {
                 X509V3_ext(data, i, X509_get0_extensions(x));
             }
         } else {
             // before OpenSSL 1.0.2
         }
         unsafe {
             ASN1_TIME_print(mem, X509_get0_notBefore(x));
         }
         let mut info_len_5: i64 = unsafe {
             BIO_ctrl(
                 mem,
                 3 as i32,
                 0 as i64,
                 &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
             )
         };
         Curl_ssl_push_certinfo_len(
             data,
             i,
             b"Start date\0" as *const u8 as *const libc::c_char,
             ptr,
             info_len_5 as size_t,
         );
         1 as i32 != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
         unsafe {
             ASN1_TIME_print(mem, X509_get0_notAfter(x));
         }
         let mut info_len_6: i64 = unsafe {
             BIO_ctrl(
                 mem,
                 3 as i32,
                 0 as i64,
                 &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
             )
         };
         Curl_ssl_push_certinfo_len(
             data,
             i,
             b"Expire date\0" as *const u8 as *const libc::c_char,
             ptr,
             info_len_6 as size_t,
         );
         1 as i32 != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
 
         pubkey = unsafe { X509_get_pubkey(x) };
         if pubkey.is_null() {
             unsafe {
                 Curl_infof(
                     data,
                     b"   Unable to load public key\0" as *const u8 as *const libc::c_char,
                 );
             }
         } else {
             let mut pktype: i32 = 0;
             match () {
                 #[cfg(HAVE_OPAQUE_EVP_PKEY)]
                 _ => {
                     pktype = unsafe { EVP_PKEY_id(pubkey) };
                 }
                 #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                 _ => {}
             }
             // #[cfg(HAVE_OPAQUE_EVP_PKEY)]
             // pktype = EVP_PKEY_id(pubkey);
             // TODO - 3652
             // #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
             match pktype {
                 6 => {
                     #[cfg(HAVE_OPAQUE_EVP_PKEY)]
                     let mut rsa: *mut RSA = unsafe { EVP_PKEY_get0_RSA(pubkey) };
                     // TODO - 3652
                     // #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                     #[cfg(HAVE_OPAQUE_RSA_DSA_DH)]
                     if true {
                         let mut n: *const BIGNUM = 0 as *const BIGNUM;
                         let mut e: *const BIGNUM = 0 as *const BIGNUM;
                         unsafe {
                             RSA_get0_key(rsa, &mut n, &mut e, 0 as *mut *const BIGNUM);
                         }
 
                         BIO_printf(
                             mem,
                             b"%d\0" as *const u8 as *const libc::c_char,
                             BN_num_bits(n),
                         );
 
                         let mut info_len_7: i64 = unsafe {
                             BIO_ctrl(
                                 mem,
                                 3 as i32,
                                 0 as i64,
                                 &mut ptr as *mut *mut libc::c_char as *mut libc::c_char
                                     as *mut libc::c_void,
                             )
                         };
                         unsafe {
                             Curl_ssl_push_certinfo_len(
                                 data,
                                 i,
                                 b"RSA Public Key\0" as *const u8 as *const libc::c_char,
                                 ptr,
                                 info_len_7 as size_t,
                             );
                         }
                         1 as i32
                             != unsafe {
                                 BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32
                             };
                         unsafe {
                             pubkey_show(
                                 data,
                                 mem,
                                 i,
                                 b"rsa\0" as *const u8 as *const libc::c_char,
                                 b"n\0" as *const u8 as *const libc::c_char,
                                 n,
                             );
                             pubkey_show(
                                 data,
                                 mem,
                                 i,
                                 b"rsa\0" as *const u8 as *const libc::c_char,
                                 b"e\0" as *const u8 as *const libc::c_char,
                                 e,
                             );
                         }
                     }
                     #[cfg(not(HAVE_OPAQUE_RSA_DSA_DH))]
                     if true {
                         // TODO - 3678
                     }
                 }
                 116 => {
                     if cfg!(not(OPENSSL_NO_DSA)) {
                         #[cfg(HAVE_OPAQUE_EVP_PKEY)]
                         let mut dsa: *mut DSA = unsafe { EVP_PKEY_get0_DSA(pubkey) };
                         // TODO - 3691
                         // #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                         #[cfg(HAVE_OPAQUE_RSA_DSA_DH)]
                         if true {
                             let mut p: *const BIGNUM = 0 as *const BIGNUM;
                             let mut q: *const BIGNUM = 0 as *const BIGNUM;
                             let mut g: *const BIGNUM = 0 as *const BIGNUM;
                             let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
                             unsafe {
                                 DSA_get0_pqg(dsa, &mut p, &mut q, &mut g);
                                 DSA_get0_key(dsa, &mut pub_key, 0 as *mut *const BIGNUM);
                                 pubkey_show(
                                     data,
                                     mem,
                                     i,
                                     b"dsa\0" as *const u8 as *const libc::c_char,
                                     b"p\0" as *const u8 as *const libc::c_char,
                                     p,
                                 );
                                 pubkey_show(
                                     data,
                                     mem,
                                     i,
                                     b"dsa\0" as *const u8 as *const libc::c_char,
                                     b"q\0" as *const u8 as *const libc::c_char,
                                     q,
                                 );
                                 pubkey_show(
                                     data,
                                     mem,
                                     i,
                                     b"dsa\0" as *const u8 as *const libc::c_char,
                                     b"g\0" as *const u8 as *const libc::c_char,
                                     g,
                                 );
                                 pubkey_show(
                                     data,
                                     mem,
                                     i,
                                     b"dsa\0" as *const u8 as *const libc::c_char,
                                     b"pub_key\0" as *const u8 as *const libc::c_char,
                                     pub_key,
                                 );
                             }
                         }
                         #[cfg(not(HAVE_OPAQUE_RSA_DSA_DH))]
                         if true {
                             // cfg!(not(HAVE_OPAQUE_RSA_DSA_DH))
                         }
                     }
                 }
                 28 => {
                     #[cfg(HAVE_OPAQUE_EVP_PKEY)]
                     let mut dh: *mut DH = unsafe { EVP_PKEY_get0_DH(pubkey) };
                     // TODO
                     // #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                     #[cfg(HAVE_OPAQUE_RSA_DSA_DH)]
                     if true {
                         let mut p_0: *const BIGNUM = 0 as *const BIGNUM;
                         let mut q_0: *const BIGNUM = 0 as *const BIGNUM;
                         let mut g_0: *const BIGNUM = 0 as *const BIGNUM;
                         let mut pub_key_0: *const BIGNUM = 0 as *const BIGNUM;
                         unsafe {
                             DH_get0_pqg(dh, &mut p_0, &mut q_0, &mut g_0);
                             DH_get0_key(dh, &mut pub_key_0, 0 as *mut *const BIGNUM);
                             pubkey_show(
                                 data,
                                 mem,
                                 i,
                                 b"dh\0" as *const u8 as *const libc::c_char,
                                 b"p\0" as *const u8 as *const libc::c_char,
                                 p_0,
                             );
                             pubkey_show(
                                 data,
                                 mem,
                                 i,
                                 b"dh\0" as *const u8 as *const libc::c_char,
                                 b"q\0" as *const u8 as *const libc::c_char,
                                 q_0,
                             );
                             pubkey_show(
                                 data,
                                 mem,
                                 i,
                                 b"dh\0" as *const u8 as *const libc::c_char,
                                 b"g\0" as *const u8 as *const libc::c_char,
                                 g_0,
                             );
                             pubkey_show(
                                 data,
                                 mem,
                                 i,
                                 b"dh\0" as *const u8 as *const libc::c_char,
                                 b"pub_key\0" as *const u8 as *const libc::c_char,
                                 pub_key_0,
                             );
                         }
                     }
                     // TODO
                     #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                     if true {
                         // TODO - 3471
                     }
                 }
                 _ => {}
             }
             unsafe {
                 EVP_PKEY_free(pubkey);
             }
         }
         if !psig.is_null() {
             j = 0 as i32;
             while j < unsafe { (*psig).length } {
                 unsafe {
                     BIO_printf(
                         mem,
                         b"%02x:\0" as *const u8 as *const libc::c_char,
                         *((*psig).data).offset(j as isize) as i32,
                     );
                 }
                 j += 1;
             }
             let mut info_len_8: i64 = unsafe {
                 BIO_ctrl(
                     mem,
                     3 as i32,
                     0 as i64,
                     &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
                 )
             };
             Curl_ssl_push_certinfo_len(
                 data,
                 i,
                 b"Signature\0" as *const u8 as *const libc::c_char,
                 ptr,
                 info_len_8 as size_t,
             );
             1 as i32 != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
         }
         unsafe {
             PEM_write_bio_X509(mem, x);
         }
         let mut info_len_9: i64 = unsafe {
             BIO_ctrl(
                 mem,
                 3 as i32,
                 0 as i64,
                 &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
             )
         };
         Curl_ssl_push_certinfo_len(
             data,
             i,
             b"Cert\0" as *const u8 as *const libc::c_char,
             ptr,
             info_len_9 as size_t,
         );
         1 as i32 != unsafe { BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void) as i32 };
         i += 1;
     }
     unsafe {
         BIO_free(mem);
     }
     return CURLE_OK;
 }
 
 /*
  * Heavily modified from:
  * https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#OpenSSL
  */
 #[cfg(USE_OPENSSL)]
 extern "C" fn pkp_pin_peer_pubkey(
     mut data: *mut Curl_easy,
     mut cert: *mut X509,
     mut pinnedpubkey: *const libc::c_char,
 ) -> CURLcode {
     /* Scratch */
     let mut len1: i32 = 0 as i32;
     let mut len2: i32 = 0 as i32;
     let mut buff1: *mut u8 = 0 as *mut u8;
     let mut temp: *mut u8 = 0 as *mut u8;
     /* Result is returned to caller */
     let mut result: CURLcode = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
     /* if a path wasn't specified, don't pin */
     if pinnedpubkey.is_null() {
         return CURLE_OK;
     }
     if cert.is_null() {
         return result;
     }
     /* Begin Gyrations to get the subjectPublicKeyInfo     */
     /* Thanks to Viktor Dukhovni on the OpenSSL mailing list */
     len1 = unsafe { i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), 0 as *mut *mut u8) };
     if !(len1 < 1 as i32) {
         match () {
             #[cfg(not(CURLDEBUG))]
             _ => {
                 temp = unsafe {
                     Curl_cmalloc.expect("non-null function pointer")(len1 as size_t) as *mut u8
                 };
             }
             #[cfg(CURLDEBUG)]
             _ => {
                 temp = unsafe {
                     curl_dbg_malloc(
                         len1 as size_t,
                         3798 as i32,
                         b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                     )
                 } as *mut u8;
             }
         }
         buff1 = temp;
         if !buff1.is_null() {
             len2 = unsafe { i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &mut temp) };
             /*
              * These checks are verifying we got back the same values as when we
              * sized the buffer. It's pretty weak since they should always be the
              * same. But it gives us something to test.
              */
             if !(len1 != len2
                 || temp.is_null()
                 || unsafe { temp.offset_from(buff1) } as i64 != len1 as i64)
             {
                 /* End Gyrations */
 
                 /* The one good exit point */
                 result = Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1 as size_t);
             }
         }
     }
     if !buff1.is_null() {
         #[cfg(not(CURLDEBUG))]
         unsafe {
             Curl_cfree.expect("non-null function pointer")(buff1 as *mut libc::c_void);
         }
 
         #[cfg(CURLDEBUG)]
         unsafe {
             curl_dbg_free(
                 buff1 as *mut libc::c_void,
                 3820 as i32,
                 b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
             );
         }
     }
     return result;
 }
 
 /*
  * Get the server cert, verify it and show it, etc., only call failf() if the
  * 'strict' argument is TRUE as otherwise all this is for informational
  * purposes only!
  *
  * We check certificates to authenticate the server; otherwise we risk
  * man-in-the-middle attack.
  */
 #[cfg(USE_OPENSSL)]
 extern "C" fn servercert(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut connssl: *mut ssl_connect_data,
     mut strict: bool,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut rc: i32 = 0;
     let mut lerr: i64 = 0;
     let mut issuer: *mut X509 = 0 as *mut X509;
     let mut fp: *mut BIO = 0 as *mut BIO;
     let mut error_buffer: [libc::c_char; 256] = unsafe {
         *::std::mem::transmute::<
              &[u8; 256],
              &mut [libc::c_char; 256],
          >(
              b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
          )
     };
     let mut buffer: [libc::c_char; 2048] = [0; 2048];
     let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
     let mut mem: *mut BIO = unsafe { BIO_new(BIO_s_mem()) };
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     if unsafe { ((*data).set.ssl).certinfo() } != 0 {
         /* we've been asked to gather certificate info! */
         get_cert_chain(data, connssl);
     }
     unsafe {
         (*backend).server_cert = SSL_get_peer_certificate((*backend).handle);
     }
     if unsafe { ((*backend).server_cert).is_null() } {
         unsafe {
             BIO_free(mem);
         }
         if !strict {
             return CURLE_OK;
         }
         unsafe {
             Curl_failf(
                 data,
                 b"SSL: couldn't get peer certificate!\0" as *const u8 as *const libc::c_char,
             );
         }
         return CURLE_PEER_FAILED_VERIFICATION;
     }
     #[cfg(not(CURL_DISABLE_PROXY))]
     let SSL_IS_PROXY_void = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype } as u32
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         b"Proxy\0" as *const u8 as *const libc::c_char
     } else {
         b"Server\0" as *const u8 as *const libc::c_char
     };
     #[cfg(CURL_DISABLE_PROXY)]
     let SSL_IS_PROXY_void = if 0 as i32 != 0 {
         b"Proxy\0" as *const u8 as *const libc::c_char
     } else {
         b"Server\0" as *const u8 as *const libc::c_char
     };
     unsafe {
         Curl_infof(
             data,
             b"%s certificate:\0" as *const u8 as *const libc::c_char,
             SSL_IS_PROXY_void,
         );
     }
     rc = unsafe {
         x509_name_oneline(
             X509_get_subject_name((*backend).server_cert),
             buffer.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 2048]>() as u64,
         )
     };
     unsafe {
         Curl_infof(
             data,
             b" subject: %s\0" as *const u8 as *const libc::c_char,
             if rc != 0 {
                 b"[NONE]\0" as *const u8 as *const libc::c_char
             } else {
                 buffer.as_mut_ptr() as *const libc::c_char
             },
         );
     }
     // DONE - 3869
     if cfg!(not(CURL_DISABLE_VERBOSE_STRINGS)) {
         let mut len: i64 = 0;
         unsafe {
             ASN1_TIME_print(mem, X509_get0_notBefore((*backend).server_cert));
         }
         len = unsafe {
             BIO_ctrl(
                 mem,
                 3 as i32,
                 0 as i64,
                 &mut ptr as *mut *const libc::c_char as *mut *mut libc::c_char as *mut libc::c_char
                     as *mut libc::c_void,
             )
         };
         unsafe {
             Curl_infof(
                 data,
                 b" start date: %.*s\0" as *const u8 as *const libc::c_char,
                 len as i32,
                 ptr,
             );
             BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void);
             ASN1_TIME_print(mem, X509_get0_notAfter((*backend).server_cert));
         }
         len = unsafe {
             BIO_ctrl(
                 mem,
                 3 as i32,
                 0 as i64,
                 &mut ptr as *mut *const libc::c_char as *mut *mut libc::c_char as *mut libc::c_char
                     as *mut libc::c_void,
             )
         };
         unsafe {
             Curl_infof(
                 data,
                 b" expire date: %.*s\0" as *const u8 as *const libc::c_char,
                 len as i32,
                 ptr,
             );
             BIO_ctrl(mem, 1 as i32, 0 as i64, 0 as *mut libc::c_void);
             BIO_free(mem);
         }
     }
     #[cfg(not(CURL_DISABLE_PROXY))]
     let SSL_CONN_CONFIG_verifyhost = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype } as u32
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         unsafe { ((*conn).proxy_ssl_config).verifyhost() as i32 }
     } else {
         unsafe { ((*conn).ssl_config).verifyhost() as i32 }
     } != 0;
     #[cfg(CURL_DISABLE_PROXY)]
     let SSL_CONN_CONFIG_verifyhost = unsafe { ((*conn).ssl_config).verifyhost() != 0 };
 
     if SSL_CONN_CONFIG_verifyhost {
         result = unsafe { verifyhost(data, conn, (*backend).server_cert) };
         if result as u64 != 0 {
             unsafe {
                 X509_free((*backend).server_cert);
                 (*backend).server_cert = 0 as *mut X509;
             }
             return result;
         }
     }
     rc = unsafe {
         x509_name_oneline(
             X509_get_issuer_name((*backend).server_cert),
             buffer.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 2048]>() as u64,
         )
     };
     if rc != 0 {
         if strict {
             unsafe {
                 Curl_failf(
                     data,
                     b"SSL: couldn't get X509-issuer name!\0" as *const u8 as *const libc::c_char,
                 );
             }
         }
         result = CURLE_PEER_FAILED_VERIFICATION;
     } else {
         unsafe {
             Curl_infof(
                 data,
                 b" issuer: %s\0" as *const u8 as *const libc::c_char,
                 buffer.as_mut_ptr(),
             );
         }
         /* We could do all sorts of certificate verification stuff here before
         deallocating the certificate. */
 
         /* e.g. match issuer name with provided issuer certificate */
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_CONN_CONFIG_issuercert = if CURLPROXY_HTTPS as u32
             == unsafe { (*conn).http_proxy.proxytype as u32 }
             && ssl_connection_complete as u32
                 != unsafe {
                     (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                         0 as i32
                     } else {
                         1 as i32
                     }) as usize]
                         .state as u32
                 } {
             unsafe { (*conn).proxy_ssl_config.issuercert }
         } else {
             unsafe { (*conn).ssl_config.issuercert }
         };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_CONN_CONFIG_issuercert = unsafe { (*conn).ssl_config.issuercert };
 
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_CONN_CONFIG_issuercert_blob = if CURLPROXY_HTTPS as u32
             == unsafe { (*conn).http_proxy.proxytype as u32 }
             && ssl_connection_complete as u32
                 != unsafe {
                     (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                         0 as i32
                     } else {
                         1 as i32
                     }) as usize]
                         .state as u32
                 } {
             unsafe { (*conn).proxy_ssl_config.issuercert_blob }
         } else {
             unsafe { (*conn).ssl_config.issuercert_blob }
         };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_CONN_CONFIG_issuercert_blob = unsafe { (*conn).ssl_config.issuercert_blob };
         if !(SSL_CONN_CONFIG_issuercert).is_null() || !(SSL_CONN_CONFIG_issuercert_blob).is_null() {
             if !(SSL_CONN_CONFIG_issuercert_blob).is_null() {
                 fp = unsafe {
                     BIO_new_mem_buf(
                         (*SSL_CONN_CONFIG_issuercert_blob).data,
                         (*SSL_CONN_CONFIG_issuercert_blob).len as i32,
                     )
                 };
             } else {
                 fp = unsafe { BIO_new(BIO_s_file()) };
                 if fp.is_null() {
                     unsafe {
                         Curl_failf(
                             data,
                             b"BIO_new return NULL, OpenSSL error %s\0" as *const u8
                                 as *const libc::c_char,
                             ossl_strerror(
                                 ERR_get_error(),
                                 error_buffer.as_mut_ptr(),
                                 ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                             ),
                         );
                         X509_free((*backend).server_cert);
                         (*backend).server_cert = 0 as *mut X509;
                     }
                     return CURLE_OUT_OF_MEMORY;
                 }
                 if unsafe {
                     BIO_ctrl(
                         fp,
                         108 as i32,
                         (0x1 as i32 | 0x2 as i32) as i64,
                         SSL_CONN_CONFIG_issuercert as *mut libc::c_void,
                     )
                 } as i32
                     <= 0 as i32
                 {
                     if strict {
                         unsafe {
                             Curl_failf(
                                 data,
                                 b"SSL: Unable to open issuer cert (%s)\0" as *const u8
                                     as *const libc::c_char,
                                 SSL_CONN_CONFIG_issuercert,
                             );
                         }
                     }
                     unsafe {
                         BIO_free(fp);
                         X509_free((*backend).server_cert);
                         (*backend).server_cert = 0 as *mut X509;
                     }
                     return CURLE_SSL_ISSUER_ERROR;
                 }
             }
             issuer =
                 unsafe { PEM_read_bio_X509(fp, 0 as *mut *mut X509, None, 0 as *mut libc::c_void) };
             if issuer.is_null() {
                 if strict {
                     unsafe {
                         Curl_failf(
                             data,
                             b"SSL: Unable to read issuer cert (%s)\0" as *const u8
                                 as *const libc::c_char,
                             SSL_CONN_CONFIG_issuercert,
                         );
                     }
                 }
                 unsafe {
                     BIO_free(fp);
                     X509_free(issuer);
                     X509_free((*backend).server_cert);
                     (*backend).server_cert = 0 as *mut X509;
                 }
                 return CURLE_SSL_ISSUER_ERROR;
             }
             if unsafe { X509_check_issued(issuer, (*backend).server_cert) } != 0 as i32 {
                 if strict {
                     unsafe {
                         Curl_failf(
                             data,
                             b"SSL: Certificate issuer check failed (%s)\0" as *const u8
                                 as *const libc::c_char,
                             SSL_CONN_CONFIG_issuercert,
                         );
                     }
                 }
                 unsafe {
                     BIO_free(fp);
                     X509_free(issuer);
                     X509_free((*backend).server_cert);
                     (*backend).server_cert = 0 as *mut X509;
                 }
                 return CURLE_SSL_ISSUER_ERROR;
             }
             unsafe {
                 Curl_infof(
                     data,
                     b" SSL certificate issuer check ok (%s)\0" as *const u8 as *const libc::c_char,
                     SSL_CONN_CONFIG_issuercert,
                 );
                 BIO_free(fp);
                 X509_free(issuer);
             }
         }
         lerr = unsafe { SSL_get_verify_result((*backend).handle) };
         #[cfg(not(CURL_DISABLE_PROXY))]
         if true {
             *if CURLPROXY_HTTPS as u32 == unsafe { (*conn).http_proxy.proxytype as u32 }
                 && ssl_connection_complete as u32
                     != unsafe {
                         (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                             0 as i32
                         } else {
                             1 as i32
                         }) as usize]
                             .state as u32
                     }
             {
                 unsafe { &mut (*data).set.proxy_ssl.certverifyresult }
             } else {
                 unsafe { &mut (*data).set.ssl.certverifyresult }
             } = lerr;
         }
         #[cfg(CURL_DISABLE_PROXY)]
         unsafe {
        (*data).set.ssl.certverifyresult = lerr;
         }
         if lerr != 0 as i64 {
             #[cfg(not(CURL_DISABLE_PROXY))]
             let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as u32
                 == unsafe { (*conn).http_proxy.proxytype as u32 }
                 && ssl_connection_complete as u32
                     != unsafe {
                         (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                             0 as i32
                         } else {
                             1 as i32
                         }) as usize]
                             .state as u32
                     } {
                 unsafe { ((*conn).proxy_ssl_config).verifypeer() as i32 }
             } else {
                 unsafe { ((*conn).ssl_config).verifypeer() as i32 }
             } != 0;
             #[cfg(CURL_DISABLE_PROXY)]
             let SSL_CONN_CONFIG_verifypeer = unsafe { ((*conn).ssl_config).verifystatus() } != 0;
             if SSL_CONN_CONFIG_verifypeer {
                 /* We probably never reach this, because SSL_connect() will fail
                 and we return earlier if verifypeer is set? */
                 if strict {
                     unsafe {
                         Curl_failf(
                             data,
                             b"SSL certificate verify result: %s (%ld)\0" as *const u8
                                 as *const libc::c_char,
                             X509_verify_cert_error_string(lerr),
                             lerr,
                         );
                     }
                 }
                 result = CURLE_PEER_FAILED_VERIFICATION;
             } else {
                 unsafe {
                     Curl_infof(
                         data,
                         b" SSL certificate verify result: %s (%ld), continuing anyway.\0"
                             as *const u8 as *const libc::c_char,
                         X509_verify_cert_error_string(lerr),
                         lerr,
                     );
                 }
             }
         } else {
             unsafe {
                 Curl_infof(
                     data,
                     b" SSL certificate verify ok.\0" as *const u8 as *const libc::c_char,
                 );
             }
         }
     }
     // DONE - 3986
     #[cfg(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP), not(CURL_DISABLE_PROXY)))]
     let SSL_CONN_CONFIG_verifystatus = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype as u32 }
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         unsafe { ((*conn).proxy_ssl_config).verifystatus() as i32 }
     } else {
         unsafe { ((*conn).ssl_config).verifystatus() as i32 }
     } != 0;
     #[cfg(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP), CURL_DISABLE_PROXY))]
     let SSL_CONN_CONFIG_verifystatus = unsafe { ((*conn).ssl_config).verifystatus() } != 0;
     #[cfg(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP)))]
     if SSL_CONN_CONFIG_verifystatus {
         result = verifystatus(data, connssl);
         if result as u64 != 0 {
             unsafe {
                 X509_free((*backend).server_cert);
                 (*backend).server_cert = 0 as *mut X509;
             }
             return result;
         }
     }
     if !strict {
         /* when not strict, we don't bother about the verify cert problems */
         result = CURLE_OK;
     }
     #[cfg(not(CURL_DISABLE_PROXY))]
     let SSL_PINNED_PUB_KEY_void = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype as u32 }
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         unsafe { (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY_PROXY as usize] }
     } else {
         unsafe { (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as usize] }
     };
     #[cfg(CURL_DISABLE_PROXY)]
     let SSL_PINNED_PUB_KEY_void = unsafe { (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as usize] };
     ptr = SSL_PINNED_PUB_KEY_void;
     if result as u64 == 0 && !ptr.is_null() {
         result = unsafe { pkp_pin_peer_pubkey(data, (*backend).server_cert, ptr) };
         if result as u64 != 0 {
             unsafe {
                 Curl_failf(
                     data,
                     b"SSL: public key does not match pinned public key!\0" as *const u8
                         as *const libc::c_char,
                 );
             }
         }
     }
     unsafe {
         X509_free((*backend).server_cert);
         (*backend).server_cert = 0 as *mut X509;
         (*connssl).connecting_state = ssl_connect_done;
     }
     return result;
 }
 
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_connect_step3(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut connssl: *mut ssl_connect_data = unsafe {
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
     };
     #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
     if ssl_connect_3 as u32 == unsafe { (*connssl).connecting_state as u32 } {
     } else {
         unsafe {
             __assert_fail(
                 b"ssl_connect_3 == connssl->connecting_state\0" as *const u8 as *const libc::c_char,
                 b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                 4022 as u32,
                 (*::std::mem::transmute::<&[u8; 75], &[libc::c_char; 75]>(
                     b"CURLcode ossl_connect_step3(struct Curl_easy *, struct connectdata *, int)\0",
                 ))
                 .as_ptr(),
             );
         }
     }
 
     #[cfg(not(CURL_DISABLE_PROXY))]
     let servercert_value_result = servercert(
         data,
         conn,
         connssl,
         (if CURLPROXY_HTTPS as u32 == unsafe { (*conn).http_proxy.proxytype as u32 }
             && ssl_connection_complete as u32
                 != unsafe {
                     (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                         0 as i32
                     } else {
                         1 as i32
                     }) as usize]
                         .state as u32
                 }
         {
             unsafe { ((*conn).proxy_ssl_config).verifypeer() as i32 }
         } else {
             unsafe { ((*conn).ssl_config).verifypeer() as i32 }
         }) != 0
             || (if CURLPROXY_HTTPS as u32 == unsafe { (*conn).http_proxy.proxytype as u32 }
                 && ssl_connection_complete as u32
                     != unsafe {
                         (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                             0 as i32
                         } else {
                             1 as i32
                         }) as usize]
                             .state as u32
                     }
             {
                 unsafe { ((*conn).proxy_ssl_config).verifyhost() as i32 }
             } else {
                 unsafe { ((*conn).ssl_config).verifyhost() as i32 }
             }) != 0,
     );
     #[cfg(CURL_DISABLE_PROXY)]
     let servercert_value_result = servercert(
         data,
         conn,
         connssl,
         unsafe { ((*conn).ssl_config).verifypeer() } as i32 != 0
             || unsafe { ((*conn).ssl_config).verifyhost() } as i32 != 0,
     );
     /*
      * We check certificates to authenticate the server; otherwise we risk
      * man-in-the-middle attack; NEVERTHELESS, if we're told explicitly not to
      * verify the peer, ignore faults and failures from the server cert
      * operations.
      */
     result = servercert_value_result;
     if result as u64 == 0 {
         unsafe {
             (*connssl).connecting_state = ssl_connect_done;
         }
     }
     return result;
 }
 
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_connect_common(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
     mut nonblocking: bool,
     mut done: *mut bool,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut connssl: *mut ssl_connect_data =
         unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }
             as *mut ssl_connect_data;
     let mut sockfd: curl_socket_t = unsafe { (*conn).sock[sockindex as usize] };
     let mut what: i32 = 0;
     /* check if the connection has already been established */
     if ssl_connection_complete as u32 == unsafe { (*connssl).state as u32 } {
         unsafe {
             *done = 1 as i32 != 0;
         }
         return CURLE_OK;
     }
     if ssl_connect_1 as u32 == unsafe { (*connssl).connecting_state as u32 } {
         /* Find out how much more time we're allowed */
         let timeout_ms: timediff_t =
             unsafe { Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0) };
         if timeout_ms < 0 as i64 {
             /* no need to continue if time is already up */
             unsafe {
                 Curl_failf(
                     data,
                     b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
                 );
             }
             return CURLE_OPERATION_TIMEDOUT;
         }
         result = ossl_connect_step1(data, conn, sockindex);
         if result as u64 != 0 {
             return result;
         }
     }
     unsafe {
         while ssl_connect_2 as u32 == (*connssl).connecting_state as u32
             || ssl_connect_2_reading as u32 == (*connssl).connecting_state as u32
             || ssl_connect_2_writing as u32 == (*connssl).connecting_state as u32
         {
             /* check allowed time left */
             let timeout_ms_0: timediff_t = Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0);
             if timeout_ms_0 < 0 as i64 {
                 /* no need to continue if time already is up */
                 Curl_failf(
                     data,
                     b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
                 );
                 return CURLE_OPERATION_TIMEDOUT;
             }
             /* if ssl is expecting something, check if it's available. */
             if (*connssl).connecting_state as u32 == ssl_connect_2_reading as u32
                 || (*connssl).connecting_state as u32 == ssl_connect_2_writing as u32
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
                         timeout_ms_0
                     },
                 );
                 if what < 0 as i32 {
                     /* fatal error */
                     Curl_failf(
                         data,
                         b"select/poll on SSL socket, errno: %d\0" as *const u8
                             as *const libc::c_char,
                         *__errno_location(),
                     );
                     return CURLE_SSL_CONNECT_ERROR;
                 }
                 if 0 as i32 == what {
                     if nonblocking {
                         *done = 0 as i32 != 0;
                         return CURLE_OK;
                     }
                     /* timeout */
                     Curl_failf(
                         data,
                         b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
                     );
                     return CURLE_OPERATION_TIMEDOUT;
                 }
                 /* socket is readable or writable */
             }
             /* Run transaction, and return to the caller if it failed or if this
              * connection is done nonblocking and this loop would execute again. This
              * permits the owner of a multi handle to abort a connection attempt
              * before step2 has completed while ensuring that a client using select()
              * or epoll() will always have a valid fdset to wait on.
              */
             result = ossl_connect_step2(data, conn, sockindex);
             if result as u32 != 0
                 || nonblocking as i32 != 0
                     && (ssl_connect_2 as u32 == (*connssl).connecting_state as u32
                         || ssl_connect_2_reading as u32 == (*connssl).connecting_state as u32
                         || ssl_connect_2_writing as u32 == (*connssl).connecting_state as u32)
             {
                 return result;
             }
         }
     } /* repeat step2 until all transactions are done. */
 
     if ssl_connect_3 as u32 == unsafe { (*connssl).connecting_state as u32 } {
         result = ossl_connect_step3(data, conn, sockindex);
         if result as u64 != 0 {
             return result;
         }
     }
     if ssl_connect_done as u32 == unsafe { (*connssl).connecting_state as u32 } {
         unsafe {
             (*connssl).state = ssl_connection_complete;
             (*conn).recv[sockindex as usize] = Some(ossl_recv as Curl_recv);
             (*conn).send[sockindex as usize] = Some(ossl_send as Curl_send);
             *done = 1 as i32 != 0;
         }
     } else {
         unsafe {
             *done = 0 as i32 != 0;
         }
     }
     /* Reset our connect state machine */
     unsafe {
         (*connssl).connecting_state = ssl_connect_1;
     }
     return CURLE_OK;
 }
 
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_connect_nonblocking(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
     mut done: *mut bool,
 ) -> CURLcode {
     return ossl_connect_common(data, conn, sockindex, 1 as i32 != 0, done);
 }
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_connect(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) -> CURLcode {
     let mut result: CURLcode = CURLE_OK;
     let mut done: bool = 0 as i32 != 0;
     result = ossl_connect_common(data, conn, sockindex, 0 as i32 != 0, &mut done);
     if result as u64 != 0 {
         return result;
     }
     #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
     if done {
     } else {
         unsafe {
             __assert_fail(
                 b"done\0" as *const u8 as *const libc::c_char,
                 b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                 4170 as u32,
                 (*::std::mem::transmute::<&[u8; 69], &[libc::c_char; 69]>(
                     b"CURLcode ossl_connect(struct Curl_easy *, struct connectdata *, int)\0",
                 ))
                 .as_ptr(),
             );
         }
     }
     return CURLE_OK;
 }
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_data_pending(mut conn: *const connectdata, mut connindex: i32) -> bool {
     unsafe {
         let mut connssl: *const ssl_connect_data =
             &*((*conn).ssl).as_ptr().offset(connindex as isize) as *const ssl_connect_data;
         if !((*(*connssl).backend).handle).is_null()
             && SSL_pending((*(*connssl).backend).handle) != 0
         {
             return 1 as i32 != 0;
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         let mut proxyssl: *const ssl_connect_data =
             &*((*conn).proxy_ssl).as_ptr().offset(connindex as isize) as *const ssl_connect_data;
         #[cfg(not(CURL_DISABLE_PROXY))]
         if !((*(*proxyssl).backend).handle).is_null()
             && SSL_pending((*(*proxyssl).backend).handle) != 0
         {
             return 1 as i32 != 0;
         }
         return 0 as i32 != 0;
     }
 }
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_send(
     mut data: *mut Curl_easy,
     mut sockindex: i32,
     mut mem: *const libc::c_void,
     mut len: size_t,
     mut curlcode: *mut CURLcode,
 ) -> ssize_t {
     /* SSL_write() is said to return 'int' while write() and send() returns
     'size_t' */
     let mut err: i32 = 0;
     let mut error_buffer: [libc::c_char; 256] = [0; 256];
     let mut sslerror: u64 = 0;
     let mut memlen: i32 = 0;
     let mut rc: i32 = 0;
     let mut conn: *mut connectdata = unsafe { (*data).conn };
     let mut connssl: *mut ssl_connect_data = unsafe {
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
     };
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     unsafe {
         ERR_clear_error();
     }
     const INT_MAX: size_t = 2147483647 as size_t;
     memlen = if len > INT_MAX {
         INT_MAX as i32
     } else {
         len as i32
     };
     unsafe {
         (*(*conn).ssl[0 as usize].backend).logger = data;
     }
     rc = unsafe { SSL_write((*backend).handle, mem, memlen) };
     if rc <= 0 as i32 {
         err = unsafe { SSL_get_error((*backend).handle, rc) };
         match err {
             2 | 3 => {
                 /* The operation did not complete; the same TLS/SSL I/O function
                 should be called again later. This is basically an EWOULDBLOCK
                 equivalent. */
                 unsafe {
                     *curlcode = CURLE_AGAIN;
                 }
                 return -(1 as i32) as ssize_t;
             }
             5 => {
                 let mut sockerr: i32 = unsafe { *__errno_location() };
                 sslerror = unsafe { ERR_get_error() };
                 if sslerror != 0 {
                     ossl_strerror(
                         sslerror,
                         error_buffer.as_mut_ptr(),
                         ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                     );
                 } else if sockerr != 0 {
                     unsafe {
                         Curl_strerror(
                             sockerr,
                             error_buffer.as_mut_ptr(),
                             ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                         );
                     }
                 } else {
                     unsafe {
                         strncpy(
                             error_buffer.as_mut_ptr(),
                             SSL_ERROR_to_str(err),
                             ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                         );
                     }
                     error_buffer[(::std::mem::size_of::<[libc::c_char; 256]>() as u64)
                         .wrapping_sub(1 as u64) as usize] = '\0' as i32 as libc::c_char;
                 }
                 unsafe {
                     Curl_failf(
                         data,
                         b"OpenSSL SSL_write: %s, errno %d\0" as *const u8 as *const libc::c_char,
                         error_buffer.as_mut_ptr(),
                         sockerr,
                     );
                     *curlcode = CURLE_SEND_ERROR;
                 }
                 return -(1 as i32) as ssize_t;
             }
             1 => {
                 /*  A failure in the SSL library occurred, usually a protocol error.
                 The OpenSSL error queue contains more information on the error. */
                 sslerror = unsafe { ERR_get_error() };
                 unsafe {
                     #[cfg(not(CURL_DISABLE_PROXY))]
                     let CURL_DISABLE_PROXY_flag_4 = (*conn).proxy_ssl[sockindex as usize].state
                         as u32
                         == ssl_connection_complete as u32;
                     #[cfg(CURL_DISABLE_PROXY)]
                     let CURL_DISABLE_PROXY_flag_4 = true;
                     if (sslerror >> 24 as i64 & 0xff as u64) as i32 == 20 as i32
                         && (sslerror & 0xfff as u64) as i32 == 128 as i32
                         && (*conn).ssl[sockindex as usize].state as u32
                             == ssl_connection_complete as u32
                         && CURL_DISABLE_PROXY_flag_4
                     {
                         let mut ver: [libc::c_char; 120] = [0; 120];
                         ossl_version(
                             ver.as_mut_ptr(),
                             ::std::mem::size_of::<[libc::c_char; 120]>() as u64,
                         );
                         Curl_failf(
                             data,
                             b"Error: %s does not support double SSL tunneling.\0" as *const u8
                                 as *const libc::c_char,
                             ver.as_mut_ptr(),
                         );
                     } else {
                         Curl_failf(
                             data,
                             b"SSL_write() error: %s\0" as *const u8 as *const libc::c_char,
                             ossl_strerror(
                                 sslerror,
                                 error_buffer.as_mut_ptr(),
                                 ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                             ),
                         );
                     }
 
                     *curlcode = CURLE_SEND_ERROR;
                 }
                 return -(1 as i32) as ssize_t;
             }
             _ => {}
         }
         /* a true error */
         unsafe {
             Curl_failf(
                 data,
                 b"OpenSSL SSL_write: %s, errno %d\0" as *const u8 as *const libc::c_char,
                 SSL_ERROR_to_str(err),
                 *__errno_location(),
             );
             *curlcode = CURLE_SEND_ERROR;
         }
         return -(1 as i32) as ssize_t;
     }
     unsafe {
         *curlcode = CURLE_OK;
     }
     return rc as ssize_t;
 }
 
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_recv(
     mut data: *mut Curl_easy,
     mut num: i32,
     mut buf: *mut libc::c_char,
     mut buffersize: size_t,
     mut curlcode: *mut CURLcode,
 ) -> ssize_t {
     let mut error_buffer: [libc::c_char; 256] = [0; 256];
     let mut sslerror: u64 = 0;
     let mut nread: ssize_t = 0;
     let mut buffsize: i32 = 0;
     let mut conn: *mut connectdata = unsafe { (*data).conn };
     let mut connssl: *mut ssl_connect_data =
         unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(num as isize) } as *mut ssl_connect_data;
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     unsafe {
         ERR_clear_error();
     }
     const INT_MAX: size_t = 2147483647 as size_t;
     buffsize = if buffersize > INT_MAX {
         INT_MAX as i32
     } else {
         buffersize as i32
     };
     unsafe {
         (*(*conn).ssl[0 as usize].backend).logger = data;
         nread = SSL_read((*backend).handle, buf as *mut libc::c_void, buffsize) as ssize_t;
     }
     if nread <= 0 as i64 {
         let mut err: i32 = unsafe { SSL_get_error((*backend).handle, nread as i32) };
         match err {
             0 => {}
             6 => {
                 if num == 0 as i32 {
                     #[cfg(not(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS))))]
                     unsafe {
                         Curl_conncontrol(conn, 1 as i32);
                     }
 
                     #[cfg(all(DEBUGBUILD, not(CURL_DISABLE_VERBOSE_STRINGS)))]
                     unsafe {
                         Curl_conncontrol(
                             conn,
                             1 as i32,
                             b"TLS close_notify\0" as *const u8 as *const libc::c_char,
                         );
                     }
                 }
             }
             2 | 3 => {
                 unsafe {
                     *curlcode = CURLE_AGAIN;
                 }
                 return -(1 as i32) as ssize_t;
             }
             _ => {
                 sslerror = unsafe { ERR_get_error() };
                 if nread < 0 as i64 || sslerror != 0 {
                     let mut sockerr: i32 = unsafe { *__errno_location() };
                     if sslerror != 0 {
                         ossl_strerror(
                             sslerror,
                             error_buffer.as_mut_ptr(),
                             ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                         );
                     } else if sockerr != 0 && err == 5 as i32 {
                         unsafe {
                             Curl_strerror(
                                 sockerr,
                                 error_buffer.as_mut_ptr(),
                                 ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                             );
                         }
                     } else {
                         unsafe {
                             strncpy(
                                 error_buffer.as_mut_ptr(),
                                 SSL_ERROR_to_str(err),
                                 ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                             );
                         }
                         error_buffer[(::std::mem::size_of::<[libc::c_char; 256]>() as u64)
                             .wrapping_sub(1 as u64)
                             as usize] = '\0' as i32 as libc::c_char;
                     }
                     unsafe {
                         Curl_failf(
                             data,
                             b"OpenSSL SSL_read: %s, errno %d\0" as *const u8 as *const libc::c_char,
                             error_buffer.as_mut_ptr(),
                             sockerr,
                         );
                         *curlcode = CURLE_RECV_ERROR;
                     }
                     return -(1 as i32) as ssize_t;
                     /* For debug builds be a little stricter and error on any
                     SSL_ERROR_SYSCALL. For example a server may have closed the connection
                     abruptly without a close_notify alert. For compatibility with older
                     peers we don't do this by default. #4624
 
                     We can use this to gauge how many users may be affected, and
                     if it goes ok eventually transition to allow in dev and release with
                     the newest OpenSSL: #if (OPENSSL_VERSION_NUMBER >= 0x10101000L) */
                     #[cfg(DEBUGBUILD)]
                     unsafe {
                         if err == 5 as i32 {
                             let mut sockerr_0: i32 = *__errno_location();
                             if sockerr_0 != 0 {
                                 Curl_strerror(
                                     sockerr_0,
                                     error_buffer.as_mut_ptr(),
                                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                                 );
                             } else {
                                 curl_msnprintf(
                                     error_buffer.as_mut_ptr(),
                                     ::std::mem::size_of::<[libc::c_char; 256]>() as u64,
                                     b"Connection closed abruptly\0" as *const u8
                                         as *const libc::c_char,
                                 );
                             }
                             Curl_failf(
                              data,
                              b"OpenSSL SSL_read: %s, errno %d (Fatal because this is a curl debug build)\0"
                                  as *const u8 as *const libc::c_char,
                              error_buffer.as_mut_ptr(),
                              sockerr_0,
                          );
                             *curlcode = CURLE_RECV_ERROR;
                             return -(1 as i32) as ssize_t;
                         }
                     }
                 }
             }
         }
     }
     return nread;
 }
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_version(mut buffer: *mut libc::c_char, mut size: size_t) -> size_t {
     // TODO 这里有一个很长的条件编译
     // if cfg!(LIBRESSL_VERSION_NUMBER){
     //     if cfg!(LIBRESSL_VERSION_NUMBER_LT_0X2070100FL){
     //         /*
     //         return msnprintf(buffer, size, "%s/%lx.%lx.%lx",
     //                OSSL_PACKAGE,
     //                (LIBRESSL_VERSION_NUMBER>>28)&0xf,
     //                (LIBRESSL_VERSION_NUMBER>>20)&0xff,
     //                (LIBRESSL_VERSION_NUMBER>>12)&0xff);
     //         */
     //     }
     //     else{
     //         /*
     //         char *p;
     //         int count;
     //         const char *ver = OpenSSL_version(OPENSSL_VERSION);
     //         const char expected[] = OSSL_PACKAGE " "; /* ie "LibreSSL " */
     //         if(Curl_strncasecompare(ver, expected, sizeof(expected) - 1)) {
     //             ver += sizeof(expected) - 1;
     //         }
     //         count = msnprintf(buffer, size, "%s/%s", OSSL_PACKAGE, ver);
     //         for(p = buffer; *p; ++p) {
     //             if(ISSPACE(*p))
     //             *p = '_';
     //         }
     //         return count;
     //         */
     //     }
     // }
     // else if cfg!(OPENSSL_IS_BORINGSSL){
     //     // return msnprintf(buffer, size, OSSL_PACKAGE);
 
     // }
     // else if cfg!(all(HAVE_OPENSSL_VERSION, OPENSSL_VERSION_STRING)){
     //     /*
     //     return msnprintf(buffer, size, "%s/%s",
     //                OSSL_PACKAGE, OpenSSL_version(OPENSSL_VERSION_STRING));
     //     */
     // }
     //else{
     /* not LibreSSL, BoringSSL and not using OpenSSL_version */
     let mut sub: [libc::c_char; 3] = [0; 3];
     let mut ssleay_value: u64 = 0;
     sub[2 as i32 as usize] = '\0' as libc::c_char;
     sub[1 as i32 as usize] = '\0' as libc::c_char;
     ssleay_value = unsafe { OpenSSL_version_num() };
     if ssleay_value < 0x906000 as u64 {
         ssleay_value = 0x1010106f as u64;
         sub[0 as usize] = '\0' as libc::c_char;
     } else if ssleay_value & 0xff0 as i32 as u64 != 0 {
         let mut minor_ver: i32 = (ssleay_value >> 4 as i32 & 0xff as u64) as i32;
         if minor_ver > 26 as i32 {
             /* handle extended version introduced for 0.9.8za */
             sub[1 as usize] =
                 ((minor_ver - 1 as i32) % 26 as i32 + 'a' as i32 + 1 as i32) as libc::c_char;
             sub[0 as usize] = 'z' as libc::c_char;
         } else {
             sub[0 as usize] = (minor_ver + 'a' as i32 - 1 as i32) as libc::c_char;
         }
     } else {
         sub[0 as usize] = '\0' as libc::c_char;
     }
     #[cfg(not(OPENSSL_FIPS))]
     return unsafe {
         curl_msnprintf(
             buffer,
             size,
             b"%s/%lx.%lx.%lx%s\0" as *const u8 as *const libc::c_char,
             b"OpenSSL\0" as *const u8 as *const libc::c_char,
             ssleay_value >> 28 as i32 & 0xf as u64,
             ssleay_value >> 20 as i32 & 0xff as u64,
             ssleay_value >> 12 as i32 & 0xff as u64,
             sub.as_mut_ptr(),
         ) as size_t
     };
     #[cfg(OPENSSL_FIPS)]
     return unsafe {
         curl_msnprintf(
             buffer,
             size,
             b"%s/%lx.%lx.%lx%s\0" as *const u8 as *const libc::c_char,
             b"-fips\0" as *const u8 as *const libc::c_char,
             b"OpenSSL\0" as *const u8 as *const libc::c_char,
             ssleay_value >> 28 as i32 & 0xf as u64,
             ssleay_value >> 20 as i32 & 0xff as u64,
             ssleay_value >> 12 as i32 & 0xff as u64,
             sub.as_mut_ptr(),
         ) as size_t
     };
     //}
 }
 /* can be called with data == NULL */
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_random(
     mut data: *mut Curl_easy,
     mut entropy: *mut u8,
     mut length: size_t,
 ) -> CURLcode {
     let mut rc: i32 = 0;
     if !data.is_null() {
         if ossl_seed(data) as u64 != 0 {
             /* Initiate the seed if not already done */
             return CURLE_FAILED_INIT; /* couldn't seed for some reason */
         }
     } else if !rand_enough() {
         return CURLE_FAILED_INIT;
     }
     /* RAND_bytes() returns 1 on success, 0 otherwise.  */
     rc = unsafe { RAND_bytes(entropy, curlx_uztosi(length)) };
     return (if rc == 1 as i32 {
         CURLE_OK as i32
     } else {
         CURLE_FAILED_INIT as i32
     }) as CURLcode;
 }
 
 #[cfg(not(OPENSSL_NO_SHA256))]
 extern "C" fn ossl_sha256sum(
     mut tmp: *const u8,
     mut tmplen: size_t,
     mut sha256sum: *mut u8,
     mut unused: size_t,
 ) -> CURLcode {
     let mut mdctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
     let mut len: u32 = 0 as u32;
     mdctx = unsafe { EVP_MD_CTX_new() };
     if mdctx.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     unsafe {
         EVP_DigestInit(mdctx, EVP_sha256());
         EVP_DigestUpdate(mdctx, tmp as *const libc::c_void, tmplen);
         EVP_DigestFinal_ex(mdctx, sha256sum, &mut len);
         EVP_MD_CTX_free(mdctx);
     }
     return CURLE_OK;
 }
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_cert_status_request() -> bool {
     // TODO - 4475
     if cfg!(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP))) {
         return 1 as i32 != 0;
     } else {
         return 0 as i32 != 0;
     }
 }
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_get_internals(
     mut connssl: *mut ssl_connect_data,
     mut info: CURLINFO,
 ) -> *mut libc::c_void {
     unsafe {
         let mut backend: *mut ssl_backend_data = (*connssl).backend;
         return if info as u32 == CURLINFO_TLS_SESSION as u32 {
             (*backend).ctx as *mut libc::c_void
         } else {
             (*backend).handle as *mut libc::c_void
         };
     }
 }
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_associate_connection(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) {
     let mut connssl: *mut ssl_connect_data = unsafe {
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
     };
     /* Legacy: CURLINFO_TLS_SESSION must return an SSL_CTX pointer. */
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     if unsafe { ((*backend).handle).is_null() } {
         /* If we don't have SSL context, do nothing. */
         return;
     }
     unsafe {
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as u32
             == (*conn).http_proxy.proxytype as u32
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
         let SSL_SET_OPTION_primary_sessionid = ((*data).set.ssl.primary).sessionid() != 0;
 
         if SSL_SET_OPTION_primary_sessionid {
             let mut data_idx: i32 = ossl_get_ssl_data_index();
             let mut connectdata_idx: i32 = ossl_get_ssl_conn_index();
             let mut sockindex_idx: i32 = ossl_get_ssl_sockindex_index();
             let mut proxy_idx: i32 = ossl_get_proxy_index();
             if data_idx >= 0 as i32
                 && connectdata_idx >= 0 as i32
                 && sockindex_idx >= 0 as i32
                 && proxy_idx >= 0 as i32
             {
                 /* Store the data needed for the "new session" callback.
                  * The sockindex is stored as a pointer to an array element. */
 
                 SSL_set_ex_data((*backend).handle, data_idx, data as *mut libc::c_void);
                 SSL_set_ex_data(
                     (*backend).handle,
                     connectdata_idx,
                     conn as *mut libc::c_void,
                 );
                 SSL_set_ex_data(
                     (*backend).handle,
                     sockindex_idx,
                     ((*conn).sock).as_mut_ptr().offset(sockindex as isize) as *mut libc::c_void,
                 );
                 #[cfg(not(CURL_DISABLE_PROXY))]
                 SSL_set_ex_data(
                     (*backend).handle,
                     proxy_idx,
                     if CURLPROXY_HTTPS as u32 == (*conn).http_proxy.proxytype as u32
                         && ssl_connection_complete as u32
                             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                                 0 as i32
                             } else {
                                 1 as i32
                             }) as usize]
                                 .state as u32
                     {
                         1 as *mut libc::c_void
                     } else {
                         0 as *mut libc::c_void
                     },
                 );
                 // TODO - 4516
                 #[cfg(CURL_DISABLE_PROXY)]
                 SSL_set_ex_data((*backend).handle, proxy_idx, 0 as *mut libc::c_void);
             }
         }
     }
 }
 
 /*
  * Starting with TLS 1.3, the ossl_new_session_cb callback gets called after
  * the handshake. If the transfer that sets up the callback gets killed before
  * this callback arrives, we must make sure to properly clear the data to
  * avoid UAF problems. A future optimization could be to instead store another
  * transfer that might still be using the same connection.
  */
 #[cfg(USE_OPENSSL)]
 extern "C" fn ossl_disassociate_connection(mut data: *mut Curl_easy, mut sockindex: i32) {
     let mut conn: *mut connectdata = unsafe { (*data).conn };
     let mut connssl: *mut ssl_connect_data = unsafe {
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
     };
     let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
     /* If we don't have SSL context, do nothing. */
     if unsafe { ((*backend).handle).is_null() } {
         return;
     }
     #[cfg(not(CURL_DISABLE_PROXY))]
     let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as u32
         == unsafe { (*conn).http_proxy.proxytype as u32 }
         && ssl_connection_complete as u32
             != unsafe {
                 (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32) {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
             } {
         unsafe { ((*data).set.proxy_ssl.primary).sessionid() as i32 }
     } else {
         unsafe { ((*data).set.ssl.primary).sessionid() as i32 }
     } != 0;
     #[cfg(CURL_DISABLE_PROXY)]
     let SSL_SET_OPTION_primary_sessionid = unsafe { ((*data).set.ssl.primary).sessionid() } != 0;
     if SSL_SET_OPTION_primary_sessionid {
         let mut data_idx: i32 = ossl_get_ssl_data_index();
         let mut connectdata_idx: i32 = ossl_get_ssl_conn_index();
         let mut sockindex_idx: i32 = ossl_get_ssl_sockindex_index();
         let mut proxy_idx: i32 = ossl_get_proxy_index();
         if data_idx >= 0 as i32
             && connectdata_idx >= 0 as i32
             && sockindex_idx >= 0 as i32
             && proxy_idx >= 0 as i32
         {
             /* Disable references to data in "new session" callback to avoid
              * accessing a stale pointer. */
             unsafe {
                 SSL_set_ex_data((*backend).handle, data_idx, 0 as *mut libc::c_void);
                 SSL_set_ex_data((*backend).handle, connectdata_idx, 0 as *mut libc::c_void);
                 SSL_set_ex_data((*backend).handle, sockindex_idx, 0 as *mut libc::c_void);
                 SSL_set_ex_data((*backend).handle, proxy_idx, 0 as *mut libc::c_void);
             }
         }
     }
 }
 
 #[no_mangle]
 pub static mut Curl_ssl_openssl: Curl_ssl = Curl_ssl {
     info: {
         curl_ssl_backend {
             id: CURLSSLBACKEND_OPENSSL,
             name: b"openssl\0" as *const u8 as *const libc::c_char,
         }
     },
     supports: ((1 as i32) << 0 as i32
         | (1 as i32) << 6 as i32
         | (1 as i32) << 1 as i32
         | (1 as i32) << 2 as i32
         | (1 as i32) << 3 as i32
         | (1 as i32) << 5 as i32
         | (1 as i32) << 4 as i32) as u32,
     sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>() as u64,
     init: Some(ossl_init as unsafe extern "C" fn() -> i32),
     cleanup: Some(ossl_cleanup as unsafe extern "C" fn() -> ()),
     version: Some(ossl_version as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t),
     check_cxn: Some(ossl_check_cxn as unsafe extern "C" fn(*mut connectdata) -> i32),
     shut_down: Some(
         ossl_shutdown as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> i32,
     ),
     data_pending: Some(ossl_data_pending as unsafe extern "C" fn(*const connectdata, i32) -> bool),
     random: Some(ossl_random as unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode),
     cert_status_request: Some(ossl_cert_status_request as unsafe extern "C" fn() -> bool),
     connect_blocking: Some(
         ossl_connect as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> CURLcode,
     ),
     connect_nonblocking: Some(
         ossl_connect_nonblocking
             as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32, *mut bool) -> CURLcode,
     ),
     getsock: Some(
         Curl_ssl_getsock as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32,
     ),
     get_internals: Some(
         ossl_get_internals
             as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
     ),
     close_one: Some(
         ossl_close as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
     ),
     close_all: Some(ossl_close_all as unsafe extern "C" fn(*mut Curl_easy) -> ()),
     session_free: Some(ossl_session_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
     set_engine: Some(
         ossl_set_engine as unsafe extern "C" fn(*mut Curl_easy, *const libc::c_char) -> CURLcode,
     ),
     set_engine_default: Some(
         ossl_set_engine_default as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
     ),
     engines_list: Some(
         ossl_engines_list as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
     ),
     false_start: Some(Curl_none_false_start as unsafe extern "C" fn() -> bool),
     sha256sum: Some(
         ossl_sha256sum as unsafe extern "C" fn(*const u8, size_t, *mut u8, size_t) -> CURLcode,
     ),
     associate_connection: Some(
         ossl_associate_connection
             as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
     ),
     disassociate_connection: Some(
         ossl_disassociate_connection as unsafe extern "C" fn(*mut Curl_easy, i32) -> (),
     ),
 };
 