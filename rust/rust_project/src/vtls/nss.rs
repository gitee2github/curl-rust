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
 * Description: support nss
 ******************************************************************************/
 use ::libc;
 use rust_ffi::src::ffi_alias::type_alias::*;
 use rust_ffi::src::ffi_fun::fun_call::*;
 use rust_ffi::src::ffi_struct::struct_define::*;
 use crate::src::vtls::vtls::*;
 
 #[inline]
 extern "C" fn stat(
     mut __path: *const libc::c_char,
     mut __statbuf: *mut stat,
 ) -> i32 {
     unsafe{
         return __xstat(1 as i32, __path, __statbuf);
     }
 }
 static mut nss_initlock: *mut PRLock = 0 as *const PRLock as *mut PRLock;
 static mut nss_crllock: *mut PRLock = 0 as *const PRLock as *mut PRLock;
 static mut nss_findslot_lock: *mut PRLock = 0 as *const PRLock as *mut PRLock;
 static mut nss_trustload_lock: *mut PRLock = 0 as *const PRLock as *mut PRLock;
 static mut nss_crl_list: Curl_llist = Curl_llist {
     head: 0 as *const Curl_llist_element as *mut Curl_llist_element,
     tail: 0 as *const Curl_llist_element as *mut Curl_llist_element,
     dtor: None,
     size: 0,
 };
 static mut nss_context: *mut NSSInitContext = 0 as *const NSSInitContext as *mut NSSInitContext;
 static mut initialized: i32 = 0 as i32;
 static mut cipherlist: [cipher_s; 94] = [
     {
         let mut init = cipher_s {
             name: b"rc4\0" as *const u8 as *const libc::c_char,
             num: 0xff01 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rc4-md5\0" as *const u8 as *const libc::c_char,
             num: 0xff01 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rc4export\0" as *const u8 as *const libc::c_char,
             num: 0xff02 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rc2\0" as *const u8 as *const libc::c_char,
             num: 0xff03 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rc2export\0" as *const u8 as *const libc::c_char,
             num: 0xff04 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"des\0" as *const u8 as *const libc::c_char,
             num: 0xff06 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"desede3\0" as *const u8 as *const libc::c_char,
             num: 0xff07 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_rc4_128_md5\0" as *const u8 as *const libc::c_char,
             num: 0x4 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_rc4_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0x5 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_3des_sha\0" as *const u8 as *const libc::c_char,
             num: 0xa as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_des_sha\0" as *const u8 as *const libc::c_char,
             num: 0x9 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_rc4_40_md5\0" as *const u8 as *const libc::c_char,
             num: 0x3 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_rc2_40_md5\0" as *const u8 as *const libc::c_char,
             num: 0x6 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_null_md5\0" as *const u8 as *const libc::c_char,
             num: 0x1 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_null_sha\0" as *const u8 as *const libc::c_char,
             num: 0x2 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"fips_3des_sha\0" as *const u8 as *const libc::c_char,
             num: 0xfeff as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"fips_des_sha\0" as *const u8 as *const libc::c_char,
             num: 0xfefe as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"fortezza\0" as *const u8 as *const libc::c_char,
             num: 0x1d as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"fortezza_rc4_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0x1e as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"fortezza_null\0" as *const u8 as *const libc::c_char,
             num: 0x1c as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_3des_sha\0" as *const u8 as *const libc::c_char,
             num: 0x16 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_3des_sha\0" as *const u8 as *const libc::c_char,
             num: 0x13 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_des_sha\0" as *const u8 as *const libc::c_char,
             num: 0x15 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_des_sha\0" as *const u8 as *const libc::c_char,
             num: 0x12 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_des_56_sha\0" as *const u8 as *const libc::c_char,
             num: 0x62 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_rc4_56_sha\0" as *const u8 as *const libc::c_char,
             num: 0x64 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_rc4_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0x66 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_aes_128_cbc_sha\0" as *const u8 as *const libc::c_char,
             num: 0x32 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_aes_256_cbc_sha\0" as *const u8 as *const libc::c_char,
             num: 0x38 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_aes_128_cbc_sha\0" as *const u8 as *const libc::c_char,
             num: 0x33 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_aes_256_cbc_sha\0" as *const u8 as *const libc::c_char,
             num: 0x39 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0x2f as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
             num: 0x35 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_ecdsa_null_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc001 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_ecdsa_rc4_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc002 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_ecdsa_3des_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc003 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_ecdsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc004 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_ecdsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc005 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_null_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc006 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_rc4_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc007 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_3des_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc008 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc009 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc00a as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_rsa_null_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc00b as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_rsa_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc00c as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_rsa_3des_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc00d as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_rsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc00e as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_rsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc00f as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_null\0" as *const u8 as *const libc::c_char,
             num: 0xc010 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_rc4_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc011 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_3des_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc012 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc013 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc014 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_anon_null_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc015 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_anon_rc4_128sha\0" as *const u8 as *const libc::c_char,
             num: 0xc016 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_anon_3des_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc017 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_anon_aes_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc018 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_anon_aes_256_sha\0" as *const u8 as *const libc::c_char,
             num: 0xc019 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_null_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x3b as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_aes_128_cbc_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x3c as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_aes_256_cbc_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x3d as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_aes_128_cbc_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x67 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_aes_256_cbc_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x6b as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_aes_128_cbc_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xc023 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_aes_128_cbc_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xc027 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x9c as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x9e as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xa2 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xc02b as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_ecdsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xc02d as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xc02f as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdh_rsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xc031 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
             num: 0x9d as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
             num: 0x9f as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
             num: 0xa3 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_aes_256_sha_384\0" as *const u8 as *const libc::c_char,
             num: 0xc024 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_aes_256_sha_384\0" as *const u8 as *const libc::c_char,
             num: 0xc028 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
             num: 0xc02c as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
             num: 0xc030 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_rsa_chacha20_poly1305_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xcca8 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"ecdhe_ecdsa_chacha20_poly1305_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xcca9 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_chacha20_poly1305_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0xccaa as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x1301 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
             num: 0x1302 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"chacha20_poly1305_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x1303 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_aes_128_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x40 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_aes_256_sha_256\0" as *const u8 as *const libc::c_char,
             num: 0x6a as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_camellia_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0x45 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_camellia_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0x44 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_rsa_camellia_256_sha\0" as *const u8 as *const libc::c_char,
             num: 0x88 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"dhe_dss_camellia_256_sha\0" as *const u8 as *const libc::c_char,
             num: 0x87 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_camellia_128_sha\0" as *const u8 as *const libc::c_char,
             num: 0x41 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_camellia_256_sha\0" as *const u8 as *const libc::c_char,
             num: 0x84 as i32,
         };
         init
     },
     {
         let mut init = cipher_s {
             name: b"rsa_seed_sha\0" as *const u8 as *const libc::c_char,
             num: 0x96 as i32,
         };
         init
     },
 ];
 static mut pem_library: *const libc::c_char = b"libnsspem.so\0" as *const u8 as *const libc::c_char;
 static mut trust_library: *const libc::c_char =
     b"libnssckbi.so\0" as *const u8 as *const libc::c_char;
 static mut pem_module: *mut SECMODModule = 0 as *const SECMODModule as *mut SECMODModule;
 static mut trust_module: *mut SECMODModule = 0 as *const SECMODModule as *mut SECMODModule;
 /* NSPR I/O layer we use to detect blocking direction during SSL handshake */
 static mut nspr_io_identity: PRDescIdentity = -(1 as i32);
 static mut nspr_io_methods: PRIOMethods = PRIOMethods {
     file_type: 0 as PRDescType,
     close: None,
     read: None,
     write: None,
     available: None,
     available64: None,
     fsync: None,
     seek: None,
     seek64: None,
     fileInfo: None,
     fileInfo64: None,
     writev: None,
     connect: None,
     accept: None,
     bind: None,
     listen: None,
     shutdown: None,
     recv: None,
     send: None,
     recvfrom: None,
     sendto: None,
     poll: None,
     acceptread: None,
     transmitfile: None,
     getsockname: None,
     getpeername: None,
     reserved_fn_6: None,
     reserved_fn_5: None,
     getsocketoption: None,
     setsocketoption: None,
     sendfile: None,
     connectcontinue: None,
     reserved_fn_3: None,
     reserved_fn_2: None,
     reserved_fn_1: None,
     reserved_fn_0: None,
 };
 extern "C" fn nss_error_to_name(mut code: PRErrorCode) -> *const libc::c_char {
     unsafe{
         let mut name: *const libc::c_char = PR_ErrorToName(code);
     if !name.is_null() {
         return name;
     }
     return b"unknown error\0" as *const u8 as *const libc::c_char;
     }
 }
 extern "C" fn nss_print_error_message(mut data: *mut Curl_easy, mut err: PRUint32) {
     unsafe{
         Curl_failf(
             data,
             b"%s\0" as *const u8 as *const libc::c_char,
             PR_ErrorToString(err as PRErrorCode, 0 as i32 as PRLanguageCode),
         );
     }
 }
 extern "C" fn nss_sslver_to_name(mut nssver: PRUint16) -> *mut libc::c_char {
     unsafe{
         match nssver as i32 {
         2 => {
             #[cfg(not(CURLDEBUG))]
             return Curl_cstrdup.expect("non-null function pointer")(
                 b"SSLv2\0" as *const u8 as *const libc::c_char,
             );
             #[cfg(CURLDEBUG)]
             return curl_dbg_strdup(
                 b"SSLv2\0" as *const u8 as *const libc::c_char,
                 285 as libc::c_int,
                 b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
             );
         }
         768 => {
             #[cfg(not(CURLDEBUG))]
             return Curl_cstrdup.expect("non-null function pointer")(
                 b"SSLv3\0" as *const u8 as *const libc::c_char,
             );
             #[cfg(CURLDEBUG)]
             return curl_dbg_strdup(
                 b"SSLv3\0" as *const u8 as *const libc::c_char,
                 287 as libc::c_int,
                 b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
             );
         }
         769 => {
             #[cfg(not(CURLDEBUG))]
             return Curl_cstrdup.expect("non-null function pointer")(
                 b"TLSv1.0\0" as *const u8 as *const libc::c_char,
             );
             #[cfg(CURLDEBUG)]
             return curl_dbg_strdup(
                 b"TLSv1.0\0" as *const u8 as *const libc::c_char,
                 289 as libc::c_int,
                 b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
             );
         }
             #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
         770 => {
             #[cfg(not(CURLDEBUG))]
             return Curl_cstrdup.expect("non-null function pointer")(
                 b"TLSv1.1\0" as *const u8 as *const libc::c_char,
             );
             #[cfg(CURLDEBUG)]
             return curl_dbg_strdup(
                 b"TLSv1.1\0" as *const u8 as *const libc::c_char,
                 292 as libc::c_int,
                 b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
             );
         }
             #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
         771 => {
             #[cfg(not(CURLDEBUG))]
             return Curl_cstrdup.expect("non-null function pointer")(
                 b"TLSv1.2\0" as *const u8 as *const libc::c_char,
             );
             #[cfg(CURLDEBUG)]
             return curl_dbg_strdup(
                 b"TLSv1.2\0" as *const u8 as *const libc::c_char,
                 296 as libc::c_int,
                 b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
             );
         }
             #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
         772 => {
             #[cfg(not(CURLDEBUG))]
             return Curl_cstrdup.expect("non-null function pointer")(
                 b"TLSv1.3\0" as *const u8 as *const libc::c_char,
             );
             #[cfg(CURLDEBUG)]
             return curl_dbg_strdup(
                 b"TLSv1.3\0" as *const u8 as *const libc::c_char,
                 300 as libc::c_int,
                 b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
             );
         }
         _ => {
             return curl_maprintf(
                 b"0x%04x\0" as *const u8 as *const libc::c_char,
                     nssver as i32,
             );
         }
     };
 
 }
 }
 extern "C" fn set_ciphers(
     mut data: *mut Curl_easy,
     mut model: *mut PRFileDesc,
     mut cipher_list: *mut libc::c_char,
 ) -> SECStatus {
     unsafe{
         let mut i: u32 = 0;
     let mut cipher_state: [PRBool; 94] = [0; 94];
     let mut found: PRBool = 0;
     let mut cipher: *mut libc::c_char = 0 as *mut libc::c_char;
     /* use accessors to avoid dynamic linking issues after an update of NSS */
     let num_implemented_ciphers: PRUint16 = SSL_GetNumImplementedCiphers();
     let mut implemented_ciphers: *const PRUint16 = SSL_GetImplementedCiphers();
     if implemented_ciphers.is_null() {
         return SECFailure;
     }
     i = 0 as u32;
     /* First disable all ciphers. This uses a different max value in case
    * NSS adds more ciphers later we don't want them available by
    * accident
    */
     while i < num_implemented_ciphers as u32 {
         SSL_CipherPrefSet(
             model,
             *implemented_ciphers.offset(i as isize) as PRInt32,
             0 as i32,
         );
         i = i.wrapping_add(1);
     }
     i = 0 as u32;
     /* Set every entry in our list to false */
     while (i as u64)
         < (::std::mem::size_of::<[cipher_s; 94]>() as u64)
             .wrapping_div(::std::mem::size_of::<cipher_s>() as u64)
     {
         cipher_state[i as usize] = 0 as i32;
         i = i.wrapping_add(1);
     }
     cipher = cipher_list;
     while !cipher_list.is_null()
         && *cipher_list.offset(0 as isize) as i32 != 0
     {
         while *cipher as i32 != 0
             && Curl_isspace(*cipher as i32) != 0
         {
             cipher = cipher.offset(1);
         }
         cipher_list = strpbrk(cipher, b":, \0" as *const u8 as *const libc::c_char);
         if !cipher_list.is_null() {
             let fresh0 = cipher_list;
             cipher_list = cipher_list.offset(1);
             *fresh0 = '\u{0}' as libc::c_char;
         }
         found = 0 as i32;
         i = 0 as u32;
         while (i as u64)
             < (::std::mem::size_of::<[cipher_s; 94]>() as u64)
                 .wrapping_div(::std::mem::size_of::<cipher_s>() as u64)
         {
             if Curl_strcasecompare(cipher, cipherlist[i as usize].name) != 0 {
                 cipher_state[i as usize] = 1 as i32;
                 found = 1 as i32;
                 break;
             } else {
                 i = i.wrapping_add(1);
             }
         }
         if found == 0 as i32 {
             Curl_failf(
                 data,
                 b"Unknown cipher in list: %s\0" as *const u8 as *const libc::c_char,
                 cipher,
             );
             return SECFailure;
         }
         if !cipher_list.is_null() {
             cipher = cipher_list;
         }
     }
     i = 0 as u32;
     while (i as u64)
         < (::std::mem::size_of::<[cipher_s; 94]>() as u64)
             .wrapping_div(::std::mem::size_of::<cipher_s>() as u64)
     {
         if !(cipher_state[i as usize] == 0) {
             if SSL_CipherPrefSet(model, cipherlist[i as usize].num, 1 as i32) as i32
                 != SECSuccess as i32
             {
                 Curl_failf(
                     data,
                     b"cipher-suite not supported by NSS: %s\0" as *const u8 as *const libc::c_char,
                     cipherlist[i as usize].name,
                 );
                 return SECFailure;
             }
         }
         i = i.wrapping_add(1);
     }
     return SECSuccess;
 
     }
 }
 
 
 /*
  * Return true if at least one cipher-suite is enabled. Used to determine
  * if we need to call NSS_SetDomesticPolicy() to enable the default ciphers.
  */
 extern "C" fn any_cipher_enabled() -> bool {
     unsafe{
         let mut i: u32 = 0;
     i = 0 as u32;
     while (i as u64)
         < (::std::mem::size_of::<[cipher_s; 94]>() as u64)
             .wrapping_div(::std::mem::size_of::<cipher_s>() as u64)
     {
         let mut policy: PRInt32 = 0 as i32;
         SSL_CipherPolicyGet(cipherlist[i as usize].num, &mut policy);
         if policy != 0 {
             return 1 as i32 != 0;
         }
         i = i.wrapping_add(1);
     }
     return 0 as i32 != 0;
     }
 }
 
 /*
  * Determine whether the nickname passed in is a filename that needs to
  * be loaded as a PEM or a regular NSS nickname.
  *
  * returns 1 for a file
  * returns 0 for not a file (NSS nickname)
  */
 extern "C" fn is_file(mut filename: *const libc::c_char) -> i32 {
     unsafe{
         let mut st: stat = stat {
             st_dev: 0,
             st_ino: 0,
             st_nlink: 0,
             st_mode: 0,
             st_uid: 0,
             st_gid: 0,
             __pad0: 0,
             st_rdev: 0,
             st_size: 0,
             st_blksize: 0,
             st_blocks: 0,
             st_atim: timespec {
                 tv_sec: 0,
                 tv_nsec: 0,
             },
             st_mtim: timespec {
                 tv_sec: 0,
                 tv_nsec: 0,
             },
             st_ctim: timespec {
                 tv_sec: 0,
                 tv_nsec: 0,
             },
             __glibc_reserved: [0; 3],
         };
         if filename.is_null() {
             return 0 as i32;
         }
         if stat(filename, &mut st) == 0 as i32 {
             if st.st_mode & 0o170000 as u32
                 == 0o100000 as u32
                 || st.st_mode & 0o170000 as u32
                     == 0o10000 as u32
                 || st.st_mode & 0o170000 as u32
                     == 0o20000 as u32
             {
                 return 1 as i32;
             }
         }
         return 0 as i32;
     }
 }
 
 /* Check if the given string is filename or nickname of a certificate.  If the
  * given string is recognized as filename, return NULL.  If the given string is
  * recognized as nickname, return a duplicated string.  The returned string
  * should be later deallocated using free().  If the OOM failure occurs, we
  * return NULL, too.
  */
 extern "C" fn dup_nickname(
     mut data: *mut Curl_easy,
     mut str: *const libc::c_char,
 ) -> *mut libc::c_char {
     unsafe{
         let mut n: *const libc::c_char = 0 as *const libc::c_char;
     if is_file(str) == 0 {
         /* no such file exists, use the string as nickname */
         #[cfg(not(CURLDEBUG))]
         return Curl_cstrdup.expect("non-null function pointer")(str);
 
         #[cfg(CURLDEBUG)]
         return curl_dbg_strdup(
             str,
             430 as libc::c_int,
             b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
         );
     }
     /* search the first slash; we require at least one slash in a file name */
     n = strchr(str, '/' as i32);
     if n.is_null() {
         Curl_infof(
             data,
             b"warning: certificate file name \"%s\" handled as nickname; please use \"./%s\" to force file name\0"
                 as *const u8 as *const libc::c_char,
             str,
             str,
         );
         #[cfg(not(CURLDEBUG))]
         return Curl_cstrdup.expect("non-null function pointer")(str);
         #[cfg(CURLDEBUG)]
         return curl_dbg_strdup(
             str,
             437 as libc::c_int,
             b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
         );
     }
     return 0 as *mut libc::c_char;
     }
     /* we'll use the PEM reader to read the certificate from file */
 }
 
 
 /* Lock/unlock wrapper for PK11_FindSlotByName() to work around race condition
  * in nssSlot_IsTokenPresent() causing spurious SEC_ERROR_NO_TOKEN.  For more
  * details, go to <https://bugzilla.mozilla.org/1297397>.
  */
 extern "C" fn nss_find_slot_by_name(
     mut slot_name: *const libc::c_char,
 ) -> *mut PK11SlotInfo {
     unsafe{
         let mut slot: *mut PK11SlotInfo = 0 as *mut PK11SlotInfo;
     PR_Lock(nss_findslot_lock);
     slot = PK11_FindSlotByName(slot_name);
     PR_Unlock(nss_findslot_lock);
     return slot;
     }
 }
 /* wrap 'ptr' as list node and tail-insert into 'list' */
 extern "C" fn insert_wrapped_ptr(
     mut list: *mut Curl_llist,
     mut ptr: *mut libc::c_void,
 ) -> CURLcode {
     unsafe{
         
         #[cfg(not(CURLDEBUG))]
         let mut wrap: *mut ptr_list_wrap = Curl_cmalloc.expect("non-null function pointer")(
             ::std::mem::size_of::<ptr_list_wrap>() as u64,
         ) as *mut ptr_list_wrap;
         #[cfg(CURLDEBUG)]
         let mut wrap: *mut ptr_list_wrap = curl_dbg_malloc(
             ::std::mem::size_of::<ptr_list_wrap>() as libc::c_ulong,
             460 as libc::c_int,
             b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
         ) as *mut ptr_list_wrap;
         if wrap.is_null() {
             return CURLE_OUT_OF_MEMORY;
         }
         (*wrap).ptr = ptr;
         Curl_llist_insert_next(
             list,
             (*list).tail,
             wrap as *const libc::c_void,
             &mut (*wrap).node,
         );
         return CURLE_OK;
     }
 }
 /* Call PK11_CreateGenericObject() with the given obj_class and filename.  If
  * the call succeeds, append the object handle to the list of objects so that
  * the object can be destroyed in nss_close(). */
 extern "C" fn nss_create_object(
     mut connssl: *mut ssl_connect_data,
     mut obj_class: CK_OBJECT_CLASS,
     mut filename: *const libc::c_char,
     mut cacert: bool,
 ) -> CURLcode {
     unsafe{
         let mut slot: *mut PK11SlotInfo = 0 as *mut PK11SlotInfo;
     let mut obj: *mut PK11GenericObject = 0 as *mut PK11GenericObject;
     let mut cktrue: CK_BBOOL = 1 as i32 as CK_BBOOL;
     let mut ckfalse: CK_BBOOL = 0 as i32 as CK_BBOOL;
     let mut attrs: [CK_ATTRIBUTE; 4] = [CK_ATTRIBUTE {
         type_0: 0,
         pValue: 0 as *mut libc::c_void,
         ulValueLen: 0,
     }; 4];
     let mut attr_cnt: i32 = 0 as i32;
     let mut result: CURLcode = (if cacert as i32 != 0 {
         CURLE_SSL_CACERT_BADFILE as i32
     } else {
         CURLE_SSL_CERTPROBLEM as i32
     }) as CURLcode;
     let slot_id: i32 = if cacert as i32 != 0 {
         0 as i32
     } else {
         1 as i32
     };
     let mut slot_name: *mut libc::c_char = curl_maprintf(
         b"PEM Token #%d\0" as *const u8 as *const libc::c_char,
         slot_id,
     );
     let mut backend: *mut ssl_backend_data = (*connssl).backend;
     if slot_name.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     slot = nss_find_slot_by_name(slot_name);
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(slot_name as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         slot_name as *mut libc::c_void,
         493 as libc::c_int,
         b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
     );
     if slot.is_null() {
         return result;
     }
     attr_cnt = attr_cnt + 1;
     let mut ptr: *mut CK_ATTRIBUTE = attrs.as_mut_ptr().offset(attr_cnt as isize);
     (*ptr).type_0 = 0 as CK_ATTRIBUTE_TYPE;
     (*ptr).pValue = &mut obj_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR;
     (*ptr).ulValueLen = ::std::mem::size_of::<CK_OBJECT_CLASS>() as u64;
     attr_cnt = attr_cnt + 1;
     let mut ptr_0: *mut CK_ATTRIBUTE = attrs.as_mut_ptr().offset(attr_cnt as isize);
     (*ptr_0).type_0 = 0x1 as CK_ATTRIBUTE_TYPE;
     (*ptr_0).pValue = &mut cktrue as *mut CK_BBOOL as CK_VOID_PTR;
     (*ptr_0).ulValueLen = ::std::mem::size_of::<CK_BBOOL>() as u64;
     attr_cnt = attr_cnt + 1;
     let mut ptr_1: *mut CK_ATTRIBUTE = attrs.as_mut_ptr().offset(attr_cnt as isize);
     (*ptr_1).type_0 = 0x3 as CK_ATTRIBUTE_TYPE;
     (*ptr_1).pValue = filename as *mut u8 as CK_VOID_PTR;
     (*ptr_1).ulValueLen = (strlen(filename)).wrapping_add(1 as u64);
     if 0x1 as u64 == obj_class {
         let mut pval: *mut CK_BBOOL = if cacert as i32 != 0 {
             &mut cktrue
         } else {
             &mut ckfalse
         };
         attr_cnt = attr_cnt + 1;
         let mut ptr_2: *mut CK_ATTRIBUTE = attrs.as_mut_ptr().offset(attr_cnt as isize);
         (*ptr_2).type_0 = (0x80000000 as u32 | 0x4e534350 as u32)
             .wrapping_add(0x2000 as u32)
             as CK_ATTRIBUTE_TYPE;
         (*ptr_2).pValue = pval as CK_VOID_PTR;
         (*ptr_2).ulValueLen = ::std::mem::size_of::<CK_BBOOL>() as u64;
     }
     // done - 511
     if cfg!(HAVE_PK11_CREATEMANAGEDGENERICOBJECT){
         obj = PK11_CreateManagedGenericObject(slot, attrs.as_mut_ptr(), attr_cnt, 0 as i32);
     }
     PK11_FreeSlot(slot);
     if obj.is_null() {
         return result;
     }
     if insert_wrapped_ptr(&mut (*backend).obj_list, obj as *mut libc::c_void) as u32
         != CURLE_OK as u32
     {
         PK11_DestroyGenericObject(obj);
         return CURLE_OUT_OF_MEMORY;
     }
     if !cacert && 0x1 as u64 == obj_class {
         /* store reference to a client certificate */
         (*backend).obj_clicert = obj;
     }
      /* PK11_CreateManagedGenericObject() was introduced in NSS 3.34 because
    * PK11_DestroyGenericObject() does not release resources allocated by
    * PK11_CreateGenericObject() early enough.  */
     return CURLE_OK;
     }
 }
 
 /* Destroy the NSS object whose handle is given by ptr.  This function is
  * a callback of Curl_llist_alloc() used by Curl_llist_destroy() to destroy
  * NSS objects in nss_close() */
 extern "C" fn nss_destroy_object(mut user: *mut libc::c_void, mut ptr: *mut libc::c_void) {
     unsafe{
         let mut wrap: *mut ptr_list_wrap = ptr as *mut ptr_list_wrap;
     let mut obj: *mut PK11GenericObject = (*wrap).ptr as *mut PK11GenericObject;
     PK11_DestroyGenericObject(obj);
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(wrap as *mut libc::c_void);
 
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         wrap as *mut libc::c_void,
         543 as libc::c_int,
         b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
     );
     }
 }
 
 /* same as nss_destroy_object() but for CRL items */
 extern "C" fn nss_destroy_crl_item(mut user: *mut libc::c_void, mut ptr: *mut libc::c_void) {
     unsafe{
         let mut wrap: *mut ptr_list_wrap = ptr as *mut ptr_list_wrap;
     let mut crl_der: *mut SECItem = (*wrap).ptr as *mut SECItem;
     SECITEM_FreeItem(crl_der, 1 as i32);
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(wrap as *mut libc::c_void);
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         wrap as *mut libc::c_void,
         553 as libc::c_int,
         b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
     );
     }
 }
 extern "C" fn nss_load_cert(
     mut ssl: *mut ssl_connect_data,
     mut filename: *const libc::c_char,
     mut cacert: PRBool,
 ) -> CURLcode {
     unsafe{
         /* libnsspem.so leaks memory if the requested file does not exist.  For more
    * details, go to <https://bugzilla.redhat.com/734760>. */
         let mut result: CURLcode = (if cacert != 0 {
             CURLE_SSL_CACERT_BADFILE as i32
         } else {
             CURLE_SSL_CERTPROBLEM as i32
         }) as CURLcode;
         if is_file(filename) != 0 {
              /* we have successfully loaded a client certificate */
             result = nss_create_object(
                 ssl,
                 0x1 as CK_OBJECT_CLASS,
                 filename,
                 cacert != 0,
             );
         }
         if result as u64 == 0 && cacert == 0 {
             let mut nickname: *mut libc::c_char = 0 as *mut libc::c_char;
             let mut n: *mut libc::c_char = strrchr(filename, '/' as i32);
             if !n.is_null() {
                 n = n.offset(1);
             }
             /* The following undocumented magic helps to avoid a SIGSEGV on call
      * of PK11_ReadRawAttribute() from SelectClientCert() when using an
      * immature version of libnsspem.so.  For more details, go to
      * <https://bugzilla.redhat.com/733685>. */
             nickname = curl_maprintf(b"PEM Token #1:%s\0" as *const u8 as *const libc::c_char, n);
             if !nickname.is_null() {
                 let mut cert: *mut CERTCertificate =
                     PK11_FindCertFromNickname(nickname, 0 as *mut libc::c_void);
                 if !cert.is_null() {
                     CERT_DestroyCertificate(cert);
                 }
                 #[cfg(not(CURLDEBUG))]
                 Curl_cfree.expect("non-null function pointer")(nickname as *mut libc::c_void);
                 #[cfg(CURLDEBUG)]
                 curl_dbg_free(
                     nickname as *mut libc::c_void,
                     585 as libc::c_int,
                     b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
                 );
             }
         }
         return result;
 
     }
 }
 
 /* add given CRL to cache if it is not already there */
 extern "C" fn nss_cache_crl(mut crl_der: *mut SECItem) -> CURLcode {
     unsafe{
         let mut db: *mut CERTCertDBHandle = CERT_GetDefaultCertDB();
     let mut crl: *mut CERTSignedCrl = SEC_FindCrlByDERCert(db, crl_der, 0 as i32);
     if !crl.is_null() {
         /* CRL already cached */
         SEC_DestroyCrl(crl);
         SECITEM_FreeItem(crl_der, 1 as i32);
         return CURLE_OK;
     }
 
 
   /* acquire lock before call of CERT_CacheCRL() and accessing nss_crl_list */
     PR_Lock(nss_crllock);
     if SECSuccess as i32 != CERT_CacheCRL(db, crl_der) as i32 {
         /* unable to cache CRL */
         SECITEM_FreeItem(crl_der, 1 as i32);
         PR_Unlock(nss_crllock);
         return CURLE_SSL_CRL_BADFILE;
     }
      /* store the CRL item so that we can free it in nss_cleanup() */
     if insert_wrapped_ptr(&mut nss_crl_list, crl_der as *mut libc::c_void) as u32
         != CURLE_OK as u32
     {
         if SECSuccess as i32 == CERT_UncacheCRL(db, crl_der) as i32 {
             SECITEM_FreeItem(crl_der, 1 as i32);
         }
         PR_Unlock(nss_crllock);
         return CURLE_OUT_OF_MEMORY;
     }
      /* we need to clear session cache, so that the CRL could take effect */
     SSL_ClearSessionCache();
     PR_Unlock(nss_crllock);
     return CURLE_OK;
     }
 }
 // unsafe extern "C" fn nss_load_crl(mut crlfilename: *const libc::c_char) -> CURLcode {
 //     let mut current_block: u64;
 //     let mut infile: *mut PRFileDesc = 0 as *mut PRFileDesc;
 //     let mut info: PRFileInfo = PRFileInfo {
 //         type_0: 0 as PRFileType,
 //         size: 0,
 //         creationTime: 0,
 //         modifyTime: 0,
 //     };
 //     let mut filedata: SECItem = {
 //         let mut init = SECItemStr {
 //             type_0: siBuffer,
 //             data: 0 as *mut u8,
 //             len: 0 as i32 as u32,
 //         };
 //         init
 //     };
 //     let mut crl_der: *mut SECItem = 0 as *mut SECItem;
 //     let mut body: *mut libc::c_char = 0 as *mut libc::c_char;
 //     infile = PR_Open(crlfilename, 0x1 as i32, 0 as i32);
 //     if infile.is_null() {
 //         return CURLE_SSL_CRL_BADFILE;
 //     }
 //     if !(PR_SUCCESS as i32
 //         != PR_GetOpenFileInfo(infile, &mut info) as i32)
 //     {
 //         if !(SECITEM_AllocItem(
 //             0 as *mut PLArenaPool,
 //             &mut filedata,
 //             (info.size + 1 as i32) as u32,
 //         ))
 //             .is_null()
 //         {
 //             if !(info.size
 //                 != PR_Read(infile, filedata.data as *mut libc::c_void, info.size))
 //             {
 //                 crl_der = SECITEM_AllocItem(
 //                     0 as *mut PLArenaPool,
 //                     0 as *mut SECItem,
 //                     0 as u32,
 //                 );
 //                 if !crl_der.is_null() {
 //                     body = filedata.data as *mut libc::c_char;
 //                     filedata.len = (filedata.len).wrapping_sub(1);
 //                     *body.offset(filedata.len as isize) = '\u{0}' as i32 as libc::c_char;
 //                     body = strstr(
 //                         body,
 //                         b"-----BEGIN\0" as *const u8 as *const libc::c_char,
 //                     );
 //                     if !body.is_null() {
 //                         let mut trailer: *mut libc::c_char = 0 as *mut libc::c_char;
 //                         let mut begin: *mut libc::c_char = strchr(body, '\n' as i32);
 //                         if begin.is_null() {
 //                             begin = strchr(body, '\r' as i32);
 //                         }
 //                         if begin.is_null() {
 //                             current_block = 8725644592553896754;
 //                         } else {
 //                             begin = begin.offset(1);
 //                             trailer = strstr(
 //                                 begin,
 //                                 b"-----END\0" as *const u8 as *const libc::c_char,
 //                             );
 //                             if trailer.is_null() {
 //                                 current_block = 8725644592553896754;
 //                             } else {
 //                                 *trailer = '\u{0}' as i32 as libc::c_char;
 //                                 if ATOB_ConvertAsciiToItem(crl_der, begin) as u64 != 0 {
 //                                     current_block = 8725644592553896754;
 //                                 } else {
 //                                     SECITEM_FreeItem(&mut filedata, 0 as i32);
 //                                     current_block = 17478428563724192186;
 //                                 }
 //                             }
 //                         }
 //                     } else {
 //                         *crl_der = filedata;
 //                         current_block = 17478428563724192186;
 //                     }
 //                     match current_block {
 //                         8725644592553896754 => {}
 //                         _ => {
 //                             PR_Close(infile);
 //                             return nss_cache_crl(crl_der);
 //                         }
 //                     }
 //                 }
 //             }
 //         }
 //     }
 //     PR_Close(infile);
 //     SECITEM_FreeItem(crl_der, 1 as i32);
 //     SECITEM_FreeItem(&mut filedata, 0 as i32);
 //     return CURLE_SSL_CRL_BADFILE;
 // }
 extern "C" fn nss_load_crl(mut crlfilename: *const libc::c_char) -> CURLcode {
     unsafe{
         let mut infile: *mut PRFileDesc = 0 as *mut PRFileDesc;
     let mut info: PRFileInfo = PRFileInfo {
         type_0: 0 as PRFileType,
         size: 0,
         creationTime: 0,
         modifyTime: 0,
     };
     let mut filedata: SECItem = {
         let mut init = SECItemStr {
             type_0: siBuffer,
             data: 0 as *mut u8,
             len: 0 as i32 as u32,
         };
         init
     };
     let mut crl_der: *mut SECItem = 0 as *mut SECItem;
     let mut body: *mut libc::c_char = 0 as *mut libc::c_char;
     infile = PR_Open(crlfilename, 0x1 as i32, 0 as i32);
     if infile.is_null() {
         return CURLE_SSL_CRL_BADFILE;
     }
     // 创建一个循环
     'fail: loop {
         if PR_SUCCESS as i32 != PR_GetOpenFileInfo(infile, &mut info) as i32
         {
             break 'fail;
         }
         if (SECITEM_AllocItem(
             0 as *mut PLArenaPool,
             &mut filedata,
             (info.size + 1 as i32) as u32,
         ))
             .is_null()
         {
             break 'fail;
         }
         if info.size != PR_Read(infile, filedata.data as *mut libc::c_void, info.size) {
             break 'fail;
         }
         crl_der = SECITEM_AllocItem(
             0 as *mut PLArenaPool,
             0 as *mut SECItem,
             0 as u32,
         );
         if crl_der.is_null() {
             break 'fail;
         }
         /* place a trailing zero right after the visible data */
         body = filedata.data as *mut libc::c_char;
         filedata.len = (filedata.len).wrapping_sub(1);
         *body.offset(filedata.len as isize) = '\u{0}' as i32 as libc::c_char;
         body = strstr(body, b"-----BEGIN\0" as *const u8 as *const libc::c_char);
         if !body.is_null() {
             /* assume ASCII */
             let mut trailer: *mut libc::c_char = 0 as *mut libc::c_char;
             let mut begin: *mut libc::c_char = strchr(body, '\n' as i32);
             if begin.is_null() {
                 begin = strchr(body, '\r' as i32);
             }
             if begin.is_null() {
                 break 'fail;
             }
             begin = begin.offset(1);
             trailer = strstr(begin, b"-----END\0" as *const u8 as *const libc::c_char);
             if trailer.is_null() {
                 break 'fail;
             }
             /* retrieve DER from ASCII */
             *trailer = '\u{0}' as libc::c_char;
             if ATOB_ConvertAsciiToItem(crl_der, begin) as u64 != 0 {
                 break 'fail;
             }
             SECITEM_FreeItem(&mut filedata, 0 as i32);
         } else {
             /* assume DER */
             *crl_der = filedata;
         }
         PR_Close(infile);
         // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
         return nss_cache_crl(crl_der);
         break 'fail;
     }
     PR_Close(infile);
     SECITEM_FreeItem(crl_der, 1 as i32);
     SECITEM_FreeItem(&mut filedata, 0 as i32);
     return CURLE_SSL_CRL_BADFILE;
     }
 }
 extern "C" fn nss_load_key(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
     mut key_file: *mut libc::c_char,
 ) -> CURLcode {
     unsafe{
         let mut slot: *mut PK11SlotInfo = 0 as *mut PK11SlotInfo;
     let mut tmp: *mut PK11SlotInfo = 0 as *mut PK11SlotInfo;
     let mut status: SECStatus = SECSuccess;
     let mut result: CURLcode = CURLE_OK;
     let mut ssl: *mut ssl_connect_data = ((*conn).ssl).as_mut_ptr();
     result = nss_create_object(
         ssl,
         0x3 as CK_OBJECT_CLASS,
         key_file,
         0 as i32 != 0,
     );
     if result as u64 != 0 {
         PR_SetError(SEC_ERROR_BAD_KEY as i32, 0 as i32);
         return result;
     }
     slot = nss_find_slot_by_name(b"PEM Token #1\0" as *const u8 as *const libc::c_char);
     if slot.is_null() {
         return CURLE_SSL_CERTPROBLEM;
     }
     /* This will force the token to be seen as re-inserted */
     tmp = SECMOD_WaitForAnyTokenEvent(
         pem_module,
         0 as u64,
         0 as PRIntervalTime,
     );
     if !tmp.is_null() {
         PK11_FreeSlot(tmp);
     }
     if PK11_IsPresent(slot) == 0 {
         PK11_FreeSlot(slot);
         return CURLE_SSL_CERTPROBLEM;
     }
     #[cfg(not(CURL_DISABLE_PROXY))]
     let SSL_SET_OPTION_key_passwd = PK11_Authenticate(
                                         slot,
                                         1 as i32,
                                         (if CURLPROXY_HTTPS as u32
                                             == (*conn).http_proxy.proxytype as u32
                                             && ssl_connection_complete as u32
                                                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                     == -(1 as i32)
                                                 {
                                                     0 as i32
                                                 } else {
                                                     1 as i32
                                                 }) as usize]
                                                     .state as u32
                                         {
                                             (*data).set.proxy_ssl.key_passwd
                                         } else {
                                             (*data).set.ssl.key_passwd
                                         }) as *mut libc::c_void,
                                     );
     #[cfg(CURL_DISABLE_PROXY)]
     let SSL_SET_OPTION_key_passwd = PK11_Authenticate(
                                         slot,
                                         1 as i32,
                                         (*data).set.ssl.key_passwd as *mut libc::c_void,
                                     );
 
     status = SSL_SET_OPTION_key_passwd;
     PK11_FreeSlot(slot);
     return (if SECSuccess as i32 == status as i32 {
         CURLE_OK as i32
     } else {
         CURLE_SSL_CERTPROBLEM as i32
     }) as CURLcode;
     }
 }
 extern "C" fn display_error(
     mut data: *mut Curl_easy,
     mut err: PRInt32,
     mut filename: *const libc::c_char,
 ) -> i32 {
     unsafe{
         match err {
             -8177 => {
                 Curl_failf(
                     data,
                     b"Unable to load client key: Incorrect password\0" as *const u8
                         as *const libc::c_char,
                 );
                 return 1 as i32;
             }
             -8077 => {
                 Curl_failf(
                     data,
                     b"Unable to load certificate %s\0" as *const u8 as *const libc::c_char,
                     filename,
                 );
                 return 1 as i32;
             }
             _ => {}
         }
         return 0 as i32;/* The caller will print a generic error */
     }
 }
 extern "C" fn cert_stuff(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
     mut cert_file: *mut libc::c_char,
     mut key_file: *mut libc::c_char,
 ) -> CURLcode {
     unsafe{
         let mut result: CURLcode = CURLE_OK;
     if !cert_file.is_null() {
         result = nss_load_cert(
             &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize),
             cert_file,
             0 as i32,
         );
         if result as u64 != 0 {
             let err: PRErrorCode = PR_GetError();
             if display_error(data, err, cert_file) == 0 {
                 let mut err_name: *const libc::c_char = nss_error_to_name(err);
                 Curl_failf(
                     data,
                     b"unable to load client cert: %d (%s)\0" as *const u8 as *const libc::c_char,
                     err,
                     err_name,
                 );
             }
             return result;
         }
     }
     if !key_file.is_null() || is_file(cert_file) != 0 {
         if !key_file.is_null() {
             result = nss_load_key(data, conn, sockindex, key_file);
         } else {
             /* In case the cert file also has the key */
             result = nss_load_key(data, conn, sockindex, cert_file);
         }
         if result as u64 != 0 {
             let err_0: PRErrorCode = PR_GetError();
             if display_error(data, err_0, key_file) == 0 {
                 let mut err_name_0: *const libc::c_char = nss_error_to_name(err_0);
                 Curl_failf(
                     data,
                     b"unable to load client key: %d (%s)\0" as *const u8 as *const libc::c_char,
                     err_0,
                     err_name_0,
                 );
             }
             return result;
         }
     }
     return CURLE_OK;
     }
 }
 extern "C" fn nss_get_password(
     mut slot: *mut PK11SlotInfo, /* unused */
     mut retry: PRBool,
     mut arg: *mut libc::c_void,
 ) -> *mut libc::c_char {
     unsafe{
         if retry != 0 || arg.is_null() {
             return 0 as *mut libc::c_char;
         } else {
             return PORT_Strdup(arg as *mut libc::c_char);
         };
     }
 }
 
 
 /* bypass the default SSL_AuthCertificate() hook in case we do not want to
  * verify peer */
 extern "C" fn nss_auth_cert_hook(
     mut arg: *mut libc::c_void,
     mut fd: *mut PRFileDesc,
     mut checksig: PRBool,
     mut isServer: PRBool,
 ) -> SECStatus {
     unsafe{
         let mut data: *mut Curl_easy = arg as *mut Curl_easy;
     let mut conn: *mut connectdata = (*data).conn;
     #[cfg(not(CURL_DISABLE_PROXY))]
     let SSL_CONN_CONFIG_verifystatus = if CURLPROXY_HTTPS as i32 as u32
                                             == (*conn).http_proxy.proxytype as u32
                                             && ssl_connection_complete as i32 as u32
                                                 != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32)
                                                 {
                                                     0 as i32
                                                 } else {
                                                     1 as i32
                                                 }) as usize]
                                                     .state as u32
                                         {
                                             ((*conn).proxy_ssl_config).verifystatus() as i32
                                         } else {
                                             ((*conn).ssl_config).verifystatus() as i32
                                         };
     #[cfg(CURL_DISABLE_PROXY)]
     let SSL_CONN_CONFIG_verifystatus = ((*conn).ssl_config).verifystatus();
     #[cfg(not(CURL_DISABLE_PROXY))]
     let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as u32
                                         == (*conn).http_proxy.proxytype as u32
                                         && ssl_connection_complete as u32
                                             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
                                             {
                                                 0 as i32
                                             } else {
                                                 1 as i32
                                             }) as usize]
                                                 .state as u32
                                     {
                                         ((*conn).proxy_ssl_config).verifypeer() as i32
                                     } else {
                                         ((*conn).ssl_config).verifypeer() as i32
                                     };
     #[cfg(CURL_DISABLE_PROXY)]
     let SSL_CONN_CONFIG_verifypeer = ((*conn).ssl_config).verifypeer();
     #[cfg(SSL_ENABLE_OCSP_STAPLING)]
     if SSL_CONN_CONFIG_verifystatus != 0
     {
         let mut cacheResult: SECStatus = SECSuccess;
         let mut csa: *const SECItemArray = SSL_PeerStapledOCSPResponses(fd);
         if csa.is_null() {
             Curl_failf(
                 data,
                 b"Invalid OCSP response\0" as *const u8 as *const libc::c_char,
             );
             return SECFailure;
         }
         if (*csa).len == 0 as u32 {
             Curl_failf(
                 data,
                 b"No OCSP response received\0" as *const u8 as *const libc::c_char,
             );
             return SECFailure;
         }
         cacheResult = CERT_CacheOCSPResponseFromSideChannel(
             CERT_GetDefaultCertDB(),
             SSL_PeerCertificate(fd),
             PR_Now(),
             &mut *((*csa).items).offset(0 as isize),
             arg,
         );
         if cacheResult as i32 != SECSuccess as i32 {
             Curl_failf(
                 data,
                 b"Invalid OCSP response\0" as *const u8 as *const libc::c_char,
             );
             return cacheResult;
         }
     }
     if SSL_CONN_CONFIG_verifypeer == 0
     {
         Curl_infof(
             data,
             b"skipping SSL peer certificate verification\0" as *const u8 as *const libc::c_char,
         );
         return SECSuccess;
     }
     return SSL_AuthCertificate(
         CERT_GetDefaultCertDB() as *mut libc::c_void,
         fd,
         checksig,
         isServer,
     );
     }
 }
 
 
 /**
  * Inform the application that the handshake is complete.
  */
 extern "C" fn HandshakeCallback(mut sock: *mut PRFileDesc, mut arg: *mut libc::c_void) {
     unsafe{
         let mut data: *mut Curl_easy = arg as *mut Curl_easy;
     let mut conn: *mut connectdata = (*data).conn;
     let mut buflenmax: u32 = 50 as u32;
     let mut buf: [u8; 50] = [0; 50];
     let mut buflen: u32 = 0;
     let mut state: SSLNextProtoState = SSL_NEXT_PROTO_NO_SUPPORT;
     if ((*conn).bits).tls_enable_npn() == 0 && ((*conn).bits).tls_enable_alpn() == 0 {
         return;
     }
     if SSL_GetNextProto(sock, &mut state, buf.as_mut_ptr(), &mut buflen, buflenmax) as i32
         == SECSuccess as i32
     {
         let mut current_block_6: u64;
         match state as u32 {
             4 | 0 | 2 => {
                 Curl_infof(
                     data,
                     b"ALPN/NPN, server did not agree to a protocol\0" as *const u8
                         as *const libc::c_char,
                 );
                 return;
             }
             #[cfg(SSL_ENABLE_ALPN)]
             3 => {
                 Curl_infof(
                     data,
                     b"ALPN, server accepted to use %.*s\0" as *const u8 as *const libc::c_char,
                     buflen,
                     buf.as_mut_ptr(),
                 );
             }
             1 => {
                 Curl_infof(
                     data,
                     b"NPN, server accepted to use %.*s\0" as *const u8 as *const libc::c_char,
                     buflen,
                     buf.as_mut_ptr(),
                 );
             }
             _ => {
                 current_block_6 = 10599921512955367680;
             }
         }
         if buflen == 2 as u32
             && memcmp(
                 b"h2\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                 buf.as_mut_ptr() as *const libc::c_void,
                 2 as u64,
             ) == 0
         {
             (*conn).negnpn = CURL_HTTP_VERSION_2_0 as i32;
         } else if buflen == 8 as u32
             && memcmp(
                 b"http/1.1\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                 buf.as_mut_ptr() as *const libc::c_void,
                 8 as u64,
             ) == 0
         {
             (*conn).negnpn = CURL_HTTP_VERSION_1_1 as i32;
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
 }
 // unsafe extern "C" fn CanFalseStartCallback(
 //     mut sock: *mut PRFileDesc,
 //     mut client_data: *mut libc::c_void,
 //     mut canFalseStart: *mut PRBool,
 // ) -> SECStatus {
 //     let mut data: *mut Curl_easy = client_data as *mut Curl_easy;
 //     let mut channelInfo: SSLChannelInfo = SSLChannelInfo {
 //         length: 0,
 //         protocolVersion: 0,
 //         cipherSuite: 0,
 //         authKeyBits: 0,
 //         keaKeyBits: 0,
 //         creationTime: 0,
 //         lastAccessTime: 0,
 //         expirationTime: 0,
 //         sessionIDLength: 0,
 //         sessionID: [0; 32],
 //         compressionMethodName: 0 as *const libc::c_char,
 //         compressionMethod: ssl_compression_null,
 //         extendedMasterSecretUsed: 0,
 //         earlyDataAccepted: 0,
 //         keaType: ssl_kea_null,
 //         keaGroup: 0 as SSLNamedGroup,
 //         symCipher: ssl_calg_null,
 //         macAlgorithm: ssl_mac_null,
 //         authType: ssl_auth_null,
 //         signatureScheme: ssl_sig_none,
 //         originalKeaGroup: 0 as SSLNamedGroup,
 //         resumed: 0,
 //         peerDelegCred: 0,
 //     };
 //     let mut cipherInfo: SSLCipherSuiteInfo = SSLCipherSuiteInfo {
 //         length: 0,
 //         cipherSuite: 0,
 //         cipherSuiteName: 0 as *const libc::c_char,
 //         authAlgorithmName: 0 as *const libc::c_char,
 //         authAlgorithm: ssl_auth_null,
 //         keaTypeName: 0 as *const libc::c_char,
 //         keaType: ssl_kea_null,
 //         symCipherName: 0 as *const libc::c_char,
 //         symCipher: ssl_calg_null,
 //         symKeyBits: 0,
 //         symKeySpace: 0,
 //         effectiveKeyBits: 0,
 //         macAlgorithmName: 0 as *const libc::c_char,
 //         macAlgorithm: ssl_mac_null,
 //         macBits: 0,
 //         c2rust_padding: [0; 1],
 //         isFIPS_isExportable_nonStandard_reservedBits: [0; 5],
 //         authType: ssl_auth_null,
 //         kdfHash: ssl_hash_none,
 //     };
 //     let mut rv: SECStatus = SECSuccess;
 //     let mut negotiatedExtension: PRBool = 0;
 //     *canFalseStart = 0 as i32;
 //     if SSL_GetChannelInfo(
 //         sock,
 //         &mut channelInfo,
 //         ::std::mem::size_of::<SSLChannelInfo>() as u64 as PRUintn,
 //     ) as i32
 //         != SECSuccess as i32
 //     {
 //         return SECFailure;
 //     }
 //     if SSL_GetCipherSuiteInfo(
 //         channelInfo.cipherSuite,
 //         &mut cipherInfo,
 //         ::std::mem::size_of::<SSLCipherSuiteInfo>() as u64 as PRUintn,
 //     ) as i32
 //         != SECSuccess as i32
 //     {
 //         return SECFailure;
 //     }
 //     if !(channelInfo.protocolVersion as i32 != 0x303 as i32) {
 //         if !(cipherInfo.keaType as u32 != ssl_kea_ecdh as i32 as u32) {
 //             if !(cipherInfo.symCipher as u32
 //                 != ssl_calg_aes_gcm as i32 as u32)
 //             {
 //                 rv = SSL_HandshakeNegotiatedExtension(
 //                     sock,
 //                     ssl_app_layer_protocol_xtn,
 //                     &mut negotiatedExtension,
 //                 );
 //                 if rv as i32 != SECSuccess as i32 || negotiatedExtension == 0 {
 //                     rv = SSL_HandshakeNegotiatedExtension(
 //                         sock,
 //                         ssl_next_proto_nego_xtn,
 //                         &mut negotiatedExtension,
 //                     );
 //                 }
 //                 if !(rv as i32 != SECSuccess as i32 || negotiatedExtension == 0) {
 //                     *canFalseStart = 1 as i32;
 //                     Curl_infof(
 //                         data,
 //                         b"Trying TLS False Start\0" as *const u8 as *const libc::c_char,
 //                     );
 //                 }
 //             }
 //         }
 //     }
 //     return SECSuccess;
 // }
 extern "C" fn CanFalseStartCallback(
     mut sock: *mut PRFileDesc,
     mut client_data: *mut libc::c_void,
     mut canFalseStart: *mut PRBool,
 ) -> SECStatus {
     unsafe{
         let mut data: *mut Curl_easy = client_data as *mut Curl_easy;
     let mut channelInfo: SSLChannelInfo = SSLChannelInfo {
         length: 0,
         protocolVersion: 0,
         cipherSuite: 0,
         authKeyBits: 0,
         keaKeyBits: 0,
         creationTime: 0,
         lastAccessTime: 0,
         expirationTime: 0,
         sessionIDLength: 0,
         sessionID: [0; 32],
         compressionMethodName: 0 as *const libc::c_char,
         compressionMethod: ssl_compression_null,
         extendedMasterSecretUsed: 0,
         earlyDataAccepted: 0,
         keaType: ssl_kea_null,
         keaGroup: 0 as SSLNamedGroup,
         symCipher: ssl_calg_null,
         macAlgorithm: ssl_mac_null,
         authType: ssl_auth_null,
         signatureScheme: ssl_sig_none,
         originalKeaGroup: 0 as SSLNamedGroup,
         resumed: 0,
         peerDelegCred: 0,
     };
     let mut cipherInfo: SSLCipherSuiteInfo = SSLCipherSuiteInfo {
         length: 0,
         cipherSuite: 0,
         cipherSuiteName: 0 as *const libc::c_char,
         authAlgorithmName: 0 as *const libc::c_char,
         authAlgorithm: ssl_auth_null,
         keaTypeName: 0 as *const libc::c_char,
         keaType: ssl_kea_null,
         symCipherName: 0 as *const libc::c_char,
         symCipher: ssl_calg_null,
         symKeyBits: 0,
         symKeySpace: 0,
         effectiveKeyBits: 0,
         macAlgorithmName: 0 as *const libc::c_char,
         macAlgorithm: ssl_mac_null,
         macBits: 0,
         c2rust_padding: [0; 1],
         isFIPS_isExportable_nonStandard_reservedBits: [0; 5],
         authType: ssl_auth_null,
         kdfHash: ssl_hash_none,
     };
     let mut rv: SECStatus = SECSuccess;
     let mut negotiatedExtension: PRBool = 0;
     *canFalseStart = 0 as i32;
     if SSL_GetChannelInfo(
         sock,
         &mut channelInfo,
         ::std::mem::size_of::<SSLChannelInfo>() as PRUintn,
     ) as i32
         != SECSuccess as i32
     {
         return SECFailure;
     }
     if SSL_GetCipherSuiteInfo(
         channelInfo.cipherSuite,
         &mut cipherInfo,
         ::std::mem::size_of::<SSLCipherSuiteInfo>() as PRUintn,
     ) as i32
         != SECSuccess as i32
     {
         return SECFailure;
     }
     // 创建一个循环
     // 循环开始
     'end: loop {
         /* Prevent version downgrade attacks from TLS 1.2, and avoid False Start for
    * TLS 1.3 and later. See https://bugzilla.mozilla.org/show_bug.cgi?id=861310
    */
         if channelInfo.protocolVersion as i32 != 0x303 as i32 {
             break 'end;
         }
         /* Only allow ECDHE key exchange algorithm.
    * See https://bugzilla.mozilla.org/show_bug.cgi?id=952863 */
         if cipherInfo.keaType as u32 != ssl_kea_ecdh as u32
         {
             break 'end;
         }
         /* Prevent downgrade attacks on the symmetric cipher. We do not allow CBC
    * mode due to BEAST, POODLE, and other attacks on the MAC-then-Encrypt
    * design. See https://bugzilla.mozilla.org/show_bug.cgi?id=1109766 */
         if cipherInfo.symCipher as u32
             != ssl_calg_aes_gcm as u32
         {
             break 'end;
         }
         /* Enforce ALPN or NPN to do False Start, as an indicator of server
    * compatibility. */
         rv = SSL_HandshakeNegotiatedExtension(
             sock,
             ssl_app_layer_protocol_xtn,
             &mut negotiatedExtension,
         );
         if rv as i32 != SECSuccess as i32 || negotiatedExtension == 0 {
             rv = SSL_HandshakeNegotiatedExtension(
                 sock,
                 ssl_next_proto_nego_xtn,
                 &mut negotiatedExtension,
             );
         }
         if rv as i32 != SECSuccess as i32 || negotiatedExtension == 0 {
             break 'end;
         }
         *canFalseStart = 1 as i32;
         Curl_infof(data, b"Trying TLS False Start\0" as *const u8 as *const libc::c_char);
         break 'end;
     }
     // 循环结束
     // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
     return SECSuccess;
     }
 }
 extern "C" fn display_cert_info(mut data: *mut Curl_easy, mut cert: *mut CERTCertificate) {
     unsafe{
         let mut subject: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut issuer: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut common_name: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut printableTime: PRExplodedTime = PRExplodedTime {
         tm_usec: 0,
         tm_sec: 0,
         tm_min: 0,
         tm_hour: 0,
         tm_mday: 0,
         tm_month: 0,
         tm_year: 0,
         tm_wday: 0,
         tm_yday: 0,
         tm_params: PRTimeParameters {
             tp_gmt_offset: 0,
             tp_dst_offset: 0,
         },
     };
     let mut timeString: [libc::c_char; 256] = [0; 256];
     let mut notBefore: PRTime = 0;
     let mut notAfter: PRTime = 0;
     subject = CERT_NameToAscii(&mut (*cert).subject);
     issuer = CERT_NameToAscii(&mut (*cert).issuer);
     common_name = CERT_GetCommonName(&mut (*cert).subject);
     Curl_infof(
         data,
         b"subject: %s\n\0" as *const u8 as *const libc::c_char,
         subject,
     );
     CERT_GetCertTimes(cert, &mut notBefore, &mut notAfter);
     PR_ExplodeTime(
         notBefore,
         Some(PR_GMTParameters as unsafe extern "C" fn(*const PRExplodedTime) -> PRTimeParameters),
         &mut printableTime,
     );
     PR_FormatTime(
         timeString.as_mut_ptr(),
         256 as i32,
         b"%b %d %H:%M:%S %Y GMT\0" as *const u8 as *const libc::c_char,
         &mut printableTime,
     );
     Curl_infof(
         data,
         b" start date: %s\0" as *const u8 as *const libc::c_char,
         timeString.as_mut_ptr(),
     );
     PR_ExplodeTime(
         notAfter,
         Some(PR_GMTParameters as unsafe extern "C" fn(*const PRExplodedTime) -> PRTimeParameters),
         &mut printableTime,
     );
     PR_FormatTime(
         timeString.as_mut_ptr(),
         256 as i32,
         b"%b %d %H:%M:%S %Y GMT\0" as *const u8 as *const libc::c_char,
         &mut printableTime,
     );
     Curl_infof(
         data,
         b" expire date: %s\0" as *const u8 as *const libc::c_char,
         timeString.as_mut_ptr(),
     );
     Curl_infof(
         data,
         b" common name: %s\0" as *const u8 as *const libc::c_char,
         common_name,
     );
     Curl_infof(
         data,
         b" issuer: %s\0" as *const u8 as *const libc::c_char,
         issuer,
     );
     PR_Free(subject as *mut libc::c_void);
     PR_Free(issuer as *mut libc::c_void);
     PR_Free(common_name as *mut libc::c_void);
     }
 }
 extern "C" fn display_conn_info(
     mut data: *mut Curl_easy,
     mut sock: *mut PRFileDesc,
 ) -> CURLcode {
     unsafe{
         let mut result: CURLcode = CURLE_OK;
     let mut channel: SSLChannelInfo = SSLChannelInfo {
         length: 0,
         protocolVersion: 0,
         cipherSuite: 0,
         authKeyBits: 0,
         keaKeyBits: 0,
         creationTime: 0,
         lastAccessTime: 0,
         expirationTime: 0,
         sessionIDLength: 0,
         sessionID: [0; 32],
         compressionMethodName: 0 as *const libc::c_char,
         compressionMethod: ssl_compression_null,
         extendedMasterSecretUsed: 0,
         earlyDataAccepted: 0,
         keaType: ssl_kea_null,
         keaGroup: 0 as SSLNamedGroup,
         symCipher: ssl_calg_null,
         macAlgorithm: ssl_mac_null,
         authType: ssl_auth_null,
         signatureScheme: ssl_sig_none,
         originalKeaGroup: 0 as SSLNamedGroup,
         resumed: 0,
         peerDelegCred: 0,
     };
     let mut suite: SSLCipherSuiteInfo = SSLCipherSuiteInfo {
         length: 0,
         cipherSuite: 0,
         cipherSuiteName: 0 as *const libc::c_char,
         authAlgorithmName: 0 as *const libc::c_char,
         authAlgorithm: ssl_auth_null,
         keaTypeName: 0 as *const libc::c_char,
         keaType: ssl_kea_null,
         symCipherName: 0 as *const libc::c_char,
         symCipher: ssl_calg_null,
         symKeyBits: 0,
         symKeySpace: 0,
         effectiveKeyBits: 0,
         macAlgorithmName: 0 as *const libc::c_char,
         macAlgorithm: ssl_mac_null,
         macBits: 0,
         c2rust_padding: [0; 1],
         isFIPS_isExportable_nonStandard_reservedBits: [0; 5],
         authType: ssl_auth_null,
         kdfHash: ssl_hash_none,
     };
     let mut cert: *mut CERTCertificate = 0 as *mut CERTCertificate;
     let mut cert2: *mut CERTCertificate = 0 as *mut CERTCertificate;
     let mut cert3: *mut CERTCertificate = 0 as *mut CERTCertificate;
     let mut now: PRTime = 0;
     if SSL_GetChannelInfo(
         sock,
         &mut channel,
         ::std::mem::size_of::<SSLChannelInfo>() as PRUintn,
     ) as i32
         == SECSuccess as i32
         && channel.length as u64
             == ::std::mem::size_of::<SSLChannelInfo>() as u64
         && channel.cipherSuite as i32 != 0
     {
         if SSL_GetCipherSuiteInfo(
             channel.cipherSuite,
             &mut suite,
             ::std::mem::size_of::<SSLCipherSuiteInfo>() as PRUintn,
         ) as i32
             == SECSuccess as i32
         {
             Curl_infof(
                 data,
                 b"SSL connection using %s\0" as *const u8 as *const libc::c_char,
                 suite.cipherSuiteName,
             );
         }
     }
     cert = SSL_PeerCertificate(sock);
     if !cert.is_null() {
         Curl_infof(
             data,
             b"Server certificate:\0" as *const u8 as *const libc::c_char,
         );
         if ((*data).set.ssl).certinfo() == 0 {
             display_cert_info(data, cert);
             CERT_DestroyCertificate(cert);
         } else {
              /* Count certificates in chain. */
             let mut i: i32 = 1 as i32;
             now = PR_Now();
             if (*cert).isRoot == 0 {
                 cert2 = CERT_FindCertIssuer(cert, now, certUsageSSLCA);
                 while !cert2.is_null() {
                     i += 1;
                     if (*cert2).isRoot != 0 {
                         CERT_DestroyCertificate(cert2);
                         break;
                     } else {
                         cert3 = CERT_FindCertIssuer(cert2, now, certUsageSSLCA);
                         CERT_DestroyCertificate(cert2);
                         cert2 = cert3;
                     }
                 }
             }
             result = Curl_ssl_init_certinfo(data, i);
             if result as u64 == 0 {
                 i = 0 as i32;
                 while !cert.is_null() {
                     i = i + 1;
                     result = Curl_extract_certinfo(
                         data,
                         i,
                         (*cert).derCert.data as *mut libc::c_char,
                         ((*cert).derCert.data as *mut libc::c_char)
                             .offset((*cert).derCert.len as isize),
                     );
                     if result as u64 != 0 {
                         break;
                     }
                     if (*cert).isRoot != 0 {
                         CERT_DestroyCertificate(cert);
                         break;
                     } else {
                         cert2 = CERT_FindCertIssuer(cert, now, certUsageSSLCA);
                         CERT_DestroyCertificate(cert);
                         cert = cert2;
                     }
                 }
             }
         }
     }
     return result;
     }
 }
 #[cfg(not(CURL_DISABLE_PROXY))]
 extern "C" fn BadCertHandler(
     mut arg: *mut libc::c_void,
     mut sock: *mut PRFileDesc,
 ) -> SECStatus {
     unsafe{
         let mut data: *mut Curl_easy = arg as *mut Curl_easy;
     let mut conn: *mut connectdata = (*data).conn;
     let mut err: PRErrorCode = PR_GetError();
     let mut cert: *mut CERTCertificate = 0 as *mut CERTCertificate;
     
     #[cfg(not(CURL_DISABLE_PROXY))]
     if true {
         *if CURLPROXY_HTTPS as u32
             == (*conn).http_proxy.proxytype as u32
             && ssl_connection_complete as u32
                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
                 {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
         {
             &mut (*data).set.proxy_ssl.certverifyresult
         } else {
             &mut (*data).set.ssl.certverifyresult
         } = err as i64;
     }
     #[cfg(CURL_DISABLE_PROXY)]
     if true {
         (*data).set.ssl.certverifyresult = err as i64;
     }
         
     if err == SSL_ERROR_BAD_CERT_DOMAIN as i32
         && (if CURLPROXY_HTTPS as u32
             == (*conn).http_proxy.proxytype as u32
             && ssl_connection_complete as u32
                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                     == -(1 as i32)
                 {
                     0 as i32
                 } else {
                     1 as i32
                 }) as usize]
                     .state as u32
         {
             ((*conn).proxy_ssl_config).verifyhost() as i32
         } else {
             ((*conn).ssl_config).verifyhost() as i32
         }) == 0
     {
         return SECSuccess;
     }
     cert = SSL_PeerCertificate(sock);
     if !cert.is_null() {
         Curl_infof(
             data,
             b"Server certificate:\0" as *const u8 as *const libc::c_char,
         );
         display_cert_info(data, cert);
         CERT_DestroyCertificate(cert);
     }
     return SECFailure;
     }
 }
 #[cfg(CURL_DISABLE_PROXY)]
 extern "C" fn BadCertHandler(
     mut arg: *mut libc::c_void,
     mut sock: *mut PRFileDesc,
 ) -> SECStatus {
     unsafe{
         let mut data: *mut Curl_easy = arg as *mut Curl_easy;
     let mut conn: *mut connectdata = (*data).conn;
     let mut err: PRErrorCode = PR_GetError();
     let mut cert: *mut CERTCertificate = 0 as *mut CERTCertificate;
     /* remember the cert verification result */
     (*data).set.ssl.certverifyresult = err as i64;
     if err == SSL_ERROR_BAD_CERT_DOMAIN as i32
         && ((*conn).ssl_config).verifyhost() == 0
     {
         /* we are asked not to verify the host name */
         return SECSuccess;
     }
     /* print only info about the cert, the error is printed off the callback */
     cert = SSL_PeerCertificate(sock);
     if !cert.is_null() {
         Curl_infof(data, b"Server certificate:\0" as *const u8 as *const libc::c_char);
         display_cert_info(data, cert);
         CERT_DestroyCertificate(cert);
     }
     return SECFailure;
     }
 }
 /**
  *
  * Check that the Peer certificate's issuer certificate matches the one found
  * by issuer_nickname.  This is not exactly the way OpenSSL and GNU TLS do the
  * issuer check, so we provide comments that mimic the OpenSSL
  * X509_check_issued function (in x509v3/v3_purp.c)
  */
 extern "C" fn check_issuer_cert(
     mut sock: *mut PRFileDesc,
     mut issuer_nickname: *mut libc::c_char,
 ) -> SECStatus {
     unsafe{
         let mut cert: *mut CERTCertificate = 0 as *mut CERTCertificate;
     let mut cert_issuer: *mut CERTCertificate = 0 as *mut CERTCertificate;
     let mut issuer: *mut CERTCertificate = 0 as *mut CERTCertificate;
     let mut res: SECStatus = SECSuccess;
     let mut proto_win: *mut libc::c_void = 0 as *mut libc::c_void;
     cert = SSL_PeerCertificate(sock);
     cert_issuer = CERT_FindCertIssuer(cert, PR_Now(), certUsageObjectSigner);
     proto_win = SSL_RevealPinArg(sock);
     issuer = PK11_FindCertFromNickname(issuer_nickname, proto_win);
     if cert_issuer.is_null() || issuer.is_null() {
         res = SECFailure;
     } else if SECITEM_CompareItem(&mut (*cert_issuer).derCert, &mut (*issuer).derCert)
         as i32
         != SECEqual as i32
     {
         res = SECFailure;
     }
     CERT_DestroyCertificate(cert);
     CERT_DestroyCertificate(issuer);
     CERT_DestroyCertificate(cert_issuer);
     return res;
     }
 }
 extern "C" fn cmp_peer_pubkey(
     mut connssl: *mut ssl_connect_data,
     mut pinnedpubkey: *const libc::c_char,
 ) -> CURLcode {
     unsafe{
         let mut result: CURLcode = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
     let mut backend: *mut ssl_backend_data = (*connssl).backend;
     let mut data: *mut Curl_easy = (*backend).data;
     let mut cert: *mut CERTCertificate = 0 as *mut CERTCertificate;
     if pinnedpubkey.is_null() {
         return CURLE_OK;
     }
     cert = SSL_PeerCertificate((*backend).nss_handle);
     if !cert.is_null() {
         /* no pinned public key specified */
         let mut pubkey: *mut SECKEYPublicKey = CERT_ExtractPublicKey(cert);
         if !pubkey.is_null() {
             let mut cert_der: *mut SECItem = PK11_DEREncodePublicKey(pubkey);
             if !cert_der.is_null() {
                 result = Curl_pin_peer_pubkey(
                     data,
                     pinnedpubkey,
                     (*cert_der).data,
                     (*cert_der).len as size_t,
                 );
                 SECITEM_FreeItem(cert_der, 1 as i32);
             }
             SECKEY_DestroyPublicKey(pubkey);
         }
         CERT_DestroyCertificate(cert);
     }
     match result as u32 {
         0 => {
             Curl_infof(
                 data,
                 b"pinned public key verified successfully!\0" as *const u8 as *const libc::c_char,
             );
         }
         90 => {
             Curl_failf(
                 data,
                 b"failed to verify pinned public key\0" as *const u8 as *const libc::c_char,
             );
         }
         _ => {}
     }
     return result;
     }
 }
 
 
 /**
  *
  * Callback to pick the SSL client certificate.
  */
 extern "C" fn SelectClientCert(
     mut arg: *mut libc::c_void,
     mut sock: *mut PRFileDesc,
     mut caNames: *mut CERTDistNamesStr,
     mut pRetCert: *mut *mut CERTCertificateStr,
     mut pRetKey: *mut *mut SECKEYPrivateKeyStr,
 ) -> SECStatus {
     unsafe{
         let mut connssl: *mut ssl_connect_data = arg as *mut ssl_connect_data;
     let mut backend: *mut ssl_backend_data = (*connssl).backend;
     let mut data: *mut Curl_easy = (*backend).data;
     let mut nickname: *const libc::c_char = (*backend).client_nickname;
     static mut pem_slotname: [libc::c_char; 13] =
         unsafe { *::std::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"PEM Token #1\0") };
     if !((*backend).obj_clicert).is_null() {
         /* use the cert/key provided by PEM reader */
         let mut cert_der: SECItem = {
             let mut init = SECItemStr {
                 type_0: siBuffer,
                 data: 0 as *mut u8,
                 len: 0 as u32,
             };
             init
         };
         let mut proto_win: *mut libc::c_void = SSL_RevealPinArg(sock);
         let mut cert: *mut CERTCertificateStr = 0 as *mut CERTCertificateStr;
         let mut key: *mut SECKEYPrivateKeyStr = 0 as *mut SECKEYPrivateKeyStr;
         let mut slot: *mut PK11SlotInfo = nss_find_slot_by_name(pem_slotname.as_ptr());
         if slot.is_null() {
             Curl_failf(
                 data,
                 b"NSS: PK11 slot not found: %s\0" as *const u8 as *const libc::c_char,
                 pem_slotname.as_ptr(),
             );
             return SECFailure;
         }
         if PK11_ReadRawAttribute(
             PK11_TypeGeneric,
             (*backend).obj_clicert as *mut libc::c_void,
             0x11 as CK_ATTRIBUTE_TYPE,
             &mut cert_der,
         ) as i32
             != SECSuccess as i32
         {
             Curl_failf(
                 data,
                 b"NSS: CKA_VALUE not found in PK11 generic object\0" as *const u8
                     as *const libc::c_char,
             );
             PK11_FreeSlot(slot);
             return SECFailure;
         }
         cert = PK11_FindCertFromDERCertItem(slot, &mut cert_der, proto_win);
         SECITEM_FreeItem(&mut cert_der, 0 as i32);
         if cert.is_null() {
             /* extract public key from peer certificate */
             Curl_failf(
                 data,
                 b"NSS: client certificate from file not found\0" as *const u8
                     as *const libc::c_char,
             );
             PK11_FreeSlot(slot);
             return SECFailure;
         }
         key = PK11_FindPrivateKeyFromCert(slot, cert, 0 as *mut libc::c_void);
         PK11_FreeSlot(slot);
         if key.is_null() {
             Curl_failf(
                 data,
                 b"NSS: private key from file not found\0" as *const u8 as *const libc::c_char,
             );
             CERT_DestroyCertificate(cert);
             return SECFailure;
         }
         Curl_infof(
             data,
             b"NSS: client certificate from file\0" as *const u8 as *const libc::c_char,
         );
         display_cert_info(data, cert);
         *pRetCert = cert;
         *pRetKey = key;
         return SECSuccess;
     }
 
       /* use the default NSS hook */
     if SECSuccess as i32
         != NSS_GetClientAuthData(
             nickname as *mut libc::c_void,
             sock,
             caNames,
             pRetCert,
             pRetKey,
         ) as i32
         || (*pRetCert).is_null()
     {
         if nickname.is_null() {
             Curl_failf(
                 data,
                 b"NSS: client certificate not found (nickname not specified)\0" as *const u8
                     as *const libc::c_char,
             );
         } else {
             Curl_failf(
                 data,
                 b"NSS: client certificate not found: %s\0" as *const u8 as *const libc::c_char,
                 nickname,
             );
         }
         return SECFailure;
     }
 
     /* get certificate nickname if any */
     nickname = (**pRetCert).nickname;
     if nickname.is_null() {
         nickname = b"[unknown]\0" as *const u8 as *const libc::c_char;
     }
     if strncmp(
         nickname,
         pem_slotname.as_ptr(),
         (::std::mem::size_of::<[libc::c_char; 13]>() as u64)
             .wrapping_sub(1 as u64),
     ) == 0
     {
         Curl_failf(
             data,
             b"NSS: refusing previously loaded certificate from file: %s\0" as *const u8
                 as *const libc::c_char,
             nickname,
         );
         return SECFailure;
     }
     if (*pRetKey).is_null() {
         Curl_failf(
             data,
             b"NSS: private key not found for certificate: %s\0" as *const u8 as *const libc::c_char,
             nickname,
         );
         return SECFailure;
     }
     Curl_infof(
         data,
         b"NSS: using client certificate: %s\0" as *const u8 as *const libc::c_char,
         nickname,
     );
     display_cert_info(data, *pRetCert);
     return SECSuccess;
     }
 }
 
 /* update blocking direction in case of PR_WOULD_BLOCK_ERROR */
 extern "C" fn nss_update_connecting_state(
     mut state: ssl_connect_state,
     mut secret: *mut libc::c_void,
 ) {
     unsafe{
         let mut connssl: *mut ssl_connect_data = secret as *mut ssl_connect_data;
     if PR_GetError() as i64 != -(5998 as i64) {
          /* an unrelated error is passing by */
         return;
     }
     match (*connssl).connecting_state as u32 {
         1 | 2 | 3 => {}
         _ => return,
     }
     /* we are not called from an SSL handshake */
     (*connssl).connecting_state = state;
     }
 }
 
 /* recv() wrapper we use to detect blocking direction during SSL handshake */
 extern "C" fn nspr_io_recv(
     mut fd: *mut PRFileDesc,
     mut buf: *mut libc::c_void,
     mut amount: PRInt32,
     mut flags: PRIntn,
     mut timeout: PRIntervalTime,
 ) -> PRInt32 {
     unsafe{
         let recv_fn: PRRecvFN = (*(*(*fd).lower).methods).recv;
     let rv: PRInt32 =
         recv_fn.expect("non-null function pointer")((*fd).lower, buf, amount, flags, timeout);
     if rv < 0 as i32 {
         /* check for PR_WOULD_BLOCK_ERROR and update blocking direction */
         nss_update_connecting_state(ssl_connect_2_reading, (*fd).secret as *mut libc::c_void);
     }
     return rv;
     }
 }
 
 /* send() wrapper we use to detect blocking direction during SSL handshake */
 extern "C" fn nspr_io_send(
     mut fd: *mut PRFileDesc,
     mut buf: *const libc::c_void,
     mut amount: PRInt32,
     mut flags: PRIntn,
     mut timeout: PRIntervalTime,
 ) -> PRInt32 {
     unsafe{
         let send_fn: PRSendFN = (*(*(*fd).lower).methods).send;
     let rv: PRInt32 =
         send_fn.expect("non-null function pointer")((*fd).lower, buf, amount, flags, timeout);
     if rv < 0 as i32 {
         /* check for PR_WOULD_BLOCK_ERROR and update blocking direction */
         nss_update_connecting_state(ssl_connect_2_writing, (*fd).secret as *mut libc::c_void);
     }
     return rv;
     }
 }
 /* close() wrapper to avoid assertion failure due to fd->secret != NULL */
 extern "C" fn nspr_io_close(mut fd: *mut PRFileDesc) -> PRStatus {
     unsafe{
         let close_fn: PRCloseFN = (*PR_GetDefaultIOMethods()).close;
     (*fd).secret = 0 as *mut PRFilePrivate;
     return close_fn.expect("non-null function pointer")(fd);
     }
 }
 
 /* load a PKCS #11 module */
 extern "C" fn nss_load_module(
     mut pmod: *mut *mut SECMODModule,
     mut library: *const libc::c_char,
     mut name: *const libc::c_char,
 ) -> CURLcode {
     unsafe{
         let mut config_string: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut module: *mut SECMODModule = *pmod;
     if !module.is_null() {
         /* already loaded */
         return CURLE_OK;
     }
     config_string = curl_maprintf(
         b"library=%s name=%s\0" as *const u8 as *const libc::c_char,
         library,
         name,
     );
     if config_string.is_null() {
         return CURLE_OUT_OF_MEMORY;
     }
     module = SECMOD_LoadUserModule(config_string, 0 as *mut SECMODModule, 0 as i32);
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")(config_string as *mut libc::c_void);
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         config_string as *mut libc::c_void,
         1311 as libc::c_int,
         b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
     );
     if !module.is_null() && (*module).loaded != 0 {
         /* loaded successfully */
         *pmod = module;
         return CURLE_OK;
     }
     if !module.is_null() {
         SECMOD_DestroyModule(module);
     }
     return CURLE_FAILED_INIT;
     }
 }
 
 
 /* unload a PKCS #11 module */
 extern "C" fn nss_unload_module(mut pmod: *mut *mut SECMODModule) {
     unsafe{
         let mut module: *mut SECMODModule = *pmod;
     if module.is_null() {
         /* not loaded */
         return;
     }
     if SECMOD_UnloadUserModule(module) as i32 != SECSuccess as i32 {
         /* unload failed */
         return;
     }
     SECMOD_DestroyModule(module);
     *pmod = 0 as *mut SECMODModule;
     }
 }
 
 /* data might be NULL */
 extern "C" fn nss_init_core(
     mut data: *mut Curl_easy,
     mut cert_dir: *const libc::c_char,
 ) -> CURLcode {
     unsafe{
         let mut initparams: NSSInitParameters = NSSInitParameters {
             length: 0,
             passwordRequired: 0,
             minPWLen: 0,
             manufactureID: 0 as *mut libc::c_char,
             libraryDescription: 0 as *mut libc::c_char,
             cryptoTokenDescription: 0 as *mut libc::c_char,
             dbTokenDescription: 0 as *mut libc::c_char,
             FIPSTokenDescription: 0 as *mut libc::c_char,
             cryptoSlotDescription: 0 as *mut libc::c_char,
             dbSlotDescription: 0 as *mut libc::c_char,
             FIPSSlotDescription: 0 as *mut libc::c_char,
         };
         let mut err: PRErrorCode = 0;
         let mut err_name: *const libc::c_char = 0 as *const libc::c_char;
         if !nss_context.is_null() {
             return CURLE_OK;
         }
         memset(
             &mut initparams as *mut NSSInitParameters as *mut libc::c_void,
             '\u{0}' as i32,
             ::std::mem::size_of::<NSSInitParameters>() as u64,
         );
         initparams.length = ::std::mem::size_of::<NSSInitParameters>() as u32;
         if !cert_dir.is_null() {
             let mut certpath: *mut libc::c_char =
                 curl_maprintf(b"sql:%s\0" as *const u8 as *const libc::c_char, cert_dir);
             if certpath.is_null() {
                 return CURLE_OUT_OF_MEMORY;
             }
             Curl_infof(
                 data,
                 b"Initializing NSS with certpath: %s\0" as *const u8 as *const libc::c_char,
                 certpath,
             );
             nss_context = NSS_InitContext(
                 certpath,
                 b"\0" as *const u8 as *const libc::c_char,
                 b"\0" as *const u8 as *const libc::c_char,
                 b"\0" as *const u8 as *const libc::c_char,
                 &mut initparams,
                 (0x1 as i32 | 0x80 as i32) as PRUint32,
             );
             #[cfg(not(CURLDEBUG))]
             Curl_cfree.expect("non-null function pointer")(certpath as *mut libc::c_void);
             #[cfg(CURLDEBUG)]
             curl_dbg_free(
                 certpath as *mut libc::c_void,
                 1361 as libc::c_int,
                 b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
             );
             if !nss_context.is_null() {
                 return CURLE_OK;
             }
             err = PR_GetError();
             err_name = nss_error_to_name(err);
             Curl_infof(
                 data,
                 b"Unable to initialize NSS database: %d (%s)\0" as *const u8 as *const libc::c_char,
                 err,
                 err_name,
             );
         }
         Curl_infof(
             data,
             b"Initializing NSS with certpath: none\0" as *const u8 as *const libc::c_char,
         );
         nss_context = NSS_InitContext(
             b"\0" as *const u8 as *const libc::c_char,
             b"\0" as *const u8 as *const libc::c_char,
             b"\0" as *const u8 as *const libc::c_char,
             b"\0" as *const u8 as *const libc::c_char,
             &mut initparams,
             (0x1 as i32
                 | 0x2 as i32
                 | 0x4 as i32
                 | 0x8 as i32
                 | 0x10 as i32
                 | 0x20 as i32
                 | 0x80 as i32) as PRUint32,
         );
         if !nss_context.is_null() {
             return CURLE_OK;
         }
         err = PR_GetError();
         err_name = nss_error_to_name(err);
         Curl_failf(
             data,
             b"Unable to initialize NSS: %d (%s)\0" as *const u8 as *const libc::c_char,
             err,
             err_name,
         );
         return CURLE_SSL_CACERT_BADFILE;
     }
 }
 
 
 /* data might be NULL */
 extern "C" fn nss_setup(mut data: *mut Curl_easy) -> CURLcode {
     unsafe{
         let mut cert_dir: *mut libc::c_char = 0 as *mut libc::c_char;
     let mut st: stat = stat {
         st_dev: 0,
         st_ino: 0,
         st_nlink: 0,
         st_mode: 0,
         st_uid: 0,
         st_gid: 0,
         __pad0: 0,
         st_rdev: 0,
         st_size: 0,
         st_blksize: 0,
         st_blocks: 0,
         st_atim: timespec {
             tv_sec: 0,
             tv_nsec: 0,
         },
         st_mtim: timespec {
             tv_sec: 0,
             tv_nsec: 0,
         },
         st_ctim: timespec {
             tv_sec: 0,
             tv_nsec: 0,
         },
         __glibc_reserved: [0; 3],
     };
     let mut result: CURLcode = CURLE_OK;
     if initialized != 0 {
         return CURLE_OK;
     }
     /* list of all CRL items we need to destroy in nss_cleanup() */
     Curl_llist_init(
         &mut nss_crl_list,
         Some(
             nss_destroy_crl_item
                 as unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> (),
         ),
     );
     /* First we check if $SSL_DIR points to a valid dir */
     cert_dir = getenv(b"SSL_DIR\0" as *const u8 as *const libc::c_char);
     if !cert_dir.is_null() {
         if stat(cert_dir, &mut st) != 0 as i32
             || !(st.st_mode & 0o170000 as u32
                 == 0o40000 as u32)
         {
             cert_dir = 0 as *mut libc::c_char;
         }
     }
 
     /* Now we check if the default location is a valid dir */
     if cert_dir.is_null() {
         /* allocate an identity for our own NSPR I/O layer */
         if stat(
             b"/etc/pki/nssdb\0" as *const u8 as *const libc::c_char,
             &mut st,
         ) == 0 as i32
             && st.st_mode & 0o170000 as u32
                 == 0o40000 as u32
         {
             cert_dir = b"/etc/pki/nssdb\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
         }
     }
     if nspr_io_identity == -(1 as i32) {
         nspr_io_identity = PR_GetUniqueIdentity(b"libcurl\0" as *const u8 as *const libc::c_char);
         if nspr_io_identity == -(1 as i32) {
             return CURLE_OUT_OF_MEMORY;
         }
         /* the default methods just call down to the lower I/O layer */
         memcpy(
             &mut nspr_io_methods as *mut PRIOMethods as *mut libc::c_void,
             PR_GetDefaultIOMethods() as *const libc::c_void,
             ::std::mem::size_of::<PRIOMethods>() as u64,
         );
         /* override certain methods in the table by our wrappers */
         nspr_io_methods.recv = Some(
             nspr_io_recv
                 as unsafe extern "C" fn(
                     *mut PRFileDesc,
                     *mut libc::c_void,
                     PRInt32,
                     PRIntn,
                     PRIntervalTime,
                 ) -> PRInt32,
         );
         nspr_io_methods.send = Some(
             nspr_io_send
                 as unsafe extern "C" fn(
                     *mut PRFileDesc,
                     *const libc::c_void,
                     PRInt32,
                     PRIntn,
                     PRIntervalTime,
                 ) -> PRInt32,
         );
         nspr_io_methods.close =
             Some(nspr_io_close as unsafe extern "C" fn(*mut PRFileDesc) -> PRStatus);
     }
     result = nss_init_core(data, cert_dir);
     if result as u64 != 0 {
         return result;
     }
     if !any_cipher_enabled() {
         NSS_SetDomesticPolicy();
     }
     ::std::ptr::write_volatile(&mut initialized as *mut i32, 1 as i32);
     return CURLE_OK;
     }
 }
 /**
  * Global SSL init
  *
  * @retval 0 error initializing SSL
  * @retval 1 SSL initialized successfully
  */
 
 extern "C" fn nss_init() -> i32 {
     unsafe{
         /* curl_global_init() is not thread-safe so this test is ok */
         if nss_initlock.is_null() {
             PR_Init(
                 PR_USER_THREAD,
                 PR_PRIORITY_NORMAL,
                 0 as PRUintn,
             );
             nss_initlock = PR_NewLock();
             nss_crllock = PR_NewLock();
             nss_findslot_lock = PR_NewLock();
             nss_trustload_lock = PR_NewLock();
         }
         /* We will actually initialize NSS later */
         return 1 as i32;
     }
 }
 #[no_mangle]
 /* data might be NULL */
 pub extern "C" fn Curl_nss_force_init(mut data: *mut Curl_easy) -> CURLcode {
     unsafe{
         let mut result: CURLcode = CURLE_OK;
     if nss_initlock.is_null() {
         if !data.is_null() {
             Curl_failf(
                 data,
                 b"unable to initialize NSS, curl_global_init() should have been called with CURL_GLOBAL_SSL or CURL_GLOBAL_ALL\0"
                     as *const u8 as *const libc::c_char,
             );
         }
         return CURLE_FAILED_INIT;
     }
     PR_Lock(nss_initlock);
     result = nss_setup(data);
     PR_Unlock(nss_initlock);
     return result;
     }
 }
 
 /* Global cleanup */
 extern "C" fn nss_cleanup() {
     unsafe{
         /* This function isn't required to be threadsafe and this is only done
    * as a safety feature.
    */
         PR_Lock(nss_initlock);
     if initialized != 0 {
         /* Free references to client certificates held in the SSL session cache.
      * Omitting this hampers destruction of the security module owning
      * the certificates. */
         SSL_ClearSessionCache();
         nss_unload_module(&mut pem_module);
         nss_unload_module(&mut trust_module);
         NSS_ShutdownContext(nss_context);
         nss_context = 0 as *mut NSSInitContext;
     }
      /* destroy all CRL items */
     Curl_llist_destroy(&mut nss_crl_list, 0 as *mut libc::c_void);
     PR_Unlock(nss_initlock);
     PR_DestroyLock(nss_initlock);
     PR_DestroyLock(nss_crllock);
     PR_DestroyLock(nss_findslot_lock);
     PR_DestroyLock(nss_trustload_lock);
     nss_initlock = 0 as *mut PRLock;
     ::std::ptr::write_volatile(&mut initialized as *mut i32, 0 as i32);
     }
 }
 
 
 
 /*
  * This function uses SSL_peek to determine connection status.
  *
  * Return codes:
  *     1 means the connection is still in place
  *     0 means the connection has been closed
  *    -1 means the connection status is unknown
  */
 extern "C" fn nss_check_cxn(mut conn: *mut connectdata) -> i32 {
     unsafe{
         let mut connssl: *mut ssl_connect_data =
         &mut *((*conn).ssl).as_mut_ptr().offset(0 as isize) as *mut ssl_connect_data;
     let mut backend: *mut ssl_backend_data = (*connssl).backend;
     let mut rc: i32 = 0;
     let mut buf: libc::c_char = 0;
     rc = PR_Recv(
         (*backend).nss_handle,
         &mut buf as *mut libc::c_char as *mut libc::c_void,
         1 as i32,
         0x2 as i32,
         PR_SecondsToInterval(1 as PRUint32),
     );
     if rc > 0 as i32 {
         return 1 as i32; /* connection still in place */
     }
     if rc == 0 as i32 {
         return 0 as i32;/* connection has been closed */
     }
     return -(1 as i32);/* connection status unknown */
     }
 }
 extern "C" fn close_one(mut connssl: *mut ssl_connect_data) {
     unsafe{
         /* before the cleanup, check whether we are using a client certificate */
         let mut backend: *mut ssl_backend_data = (*connssl).backend;
     let client_cert: bool =
         !((*backend).client_nickname).is_null() || !((*backend).obj_clicert).is_null();
     if !((*backend).nss_handle).is_null() {
         let mut buf: [libc::c_char; 32] = [0; 32];
          /* Maybe the server has already sent a close notify alert.
        Read it to avoid an RST on the TCP connection. */
         PR_Recv(
             (*backend).nss_handle,
             buf.as_mut_ptr() as *mut libc::c_void,
             ::std::mem::size_of::<[libc::c_char; 32]>() as i32,
             0 as i32,
             0 as PRIntervalTime,
         );
     }
     #[cfg(not(CURLDEBUG))]
     Curl_cfree.expect("non-null function pointer")((*backend).client_nickname as *mut libc::c_void);
     #[cfg(CURLDEBUG)]
     curl_dbg_free(
         (*backend).client_nickname as *mut libc::c_void,
         1557 as libc::c_int,
         b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
     );
     (*backend).client_nickname = 0 as *mut libc::c_char;
     /* destroy all NSS objects in order to avoid failure of NSS shutdown */
     Curl_llist_destroy(&mut (*backend).obj_list, 0 as *mut libc::c_void);
     (*backend).obj_clicert = 0 as *mut PK11GenericObject;
     if !((*backend).nss_handle).is_null() {
         if client_cert {
             /* A server might require different authentication based on the
        * particular path being requested by the client.  To support this
        * scenario, we must ensure that a connection will never reuse the
        * authentication data from a previous connection. */
             SSL_InvalidateSession((*backend).nss_handle);
         }
         PR_Close((*backend).nss_handle);
         (*backend).nss_handle = 0 as *mut PRFileDesc;
     }
     }
 }
 
 
 /*
  * This function is called when an SSL connection is closed.
  */
 extern "C" fn nss_close(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) {
     unsafe{
         let mut connssl: *mut ssl_connect_data =
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
     #[cfg(not(CURL_DISABLE_PROXY))]
     let mut connssl_proxy: *mut ssl_connect_data =
         &mut *((*conn).proxy_ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
 
     let mut backend: *mut ssl_backend_data = (*connssl).backend;
     #[cfg(not(CURL_DISABLE_PROXY))]
     let CURL_DISABLE_PROXY_3 = !((*(*connssl_proxy).backend).nss_handle).is_null();
     #[cfg(CURL_DISABLE_PROXY)]
     let CURL_DISABLE_PROXY_3 = false;
     if !((*backend).nss_handle).is_null() || CURL_DISABLE_PROXY_3{
         #[cfg(CURLDEBUG)]
         curl_dbg_mark_sclose(
             (*conn).sock[sockindex as usize],
             1597,
             b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
         );
         (*conn).sock[sockindex as usize] = -(1 as i32);
     }
     #[cfg(not(CURL_DISABLE_PROXY))]
     if !((*backend).nss_handle).is_null() {
         (*(*connssl_proxy).backend).nss_handle = 0 as *mut PRFileDesc;
     }
     #[cfg(not(CURL_DISABLE_PROXY))]
     close_one(connssl_proxy);
     close_one(connssl);
     }
 }
 
 /* return true if NSS can provide error code (and possibly msg) for the
    error */
 extern "C" fn is_nss_error(mut err: CURLcode) -> bool {
     unsafe{
         match err as u32 {
             60 | 58 | 35 | 83 => return 1 as i32 != 0,
             _ => return 0 as i32 != 0,
         };
     }
 }
 
 /* return true if the given error code is related to a client certificate */
 extern "C" fn is_cc_error(mut err: PRInt32) -> bool {
     unsafe{
         match err {
             -12271 | -12269 | -12270 => return 1 as i32 != 0,
             _ => return 0 as i32 != 0,
         };
     }
 }
 extern "C" fn nss_load_ca_certificates(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) -> CURLcode {
     unsafe{
         #[cfg(not(CURL_DISABLE_PROXY))]
     let mut cafile: *const libc::c_char = if CURLPROXY_HTTPS as u32
         == (*conn).http_proxy.proxytype as u32
         && ssl_connection_complete as u32
             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
             {
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
     let mut cafile: *const libc::c_char = (*conn).ssl_config.CAfile;
     #[cfg(not(CURL_DISABLE_PROXY))]
     let mut capath: *const libc::c_char = if CURLPROXY_HTTPS as u32
         == (*conn).http_proxy.proxytype as u32
         && ssl_connection_complete as u32
             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
             {
                 0 as i32
             } else {
                 1 as i32
             }) as usize]
                 .state as u32
     {
         (*conn).proxy_ssl_config.CApath
     } else {
         (*conn).ssl_config.CApath
     };
     #[cfg(CURL_DISABLE_PROXY)]
     let mut capath: *const libc::c_char = (*conn).ssl_config.CApath;
     let mut use_trust_module: bool = false;
     let mut result: CURLcode = CURLE_OK;
 
     /* treat empty string as unset */
     if !cafile.is_null() && *cafile.offset(0 as isize) == 0 {
         cafile = 0 as *const libc::c_char;
     }
     if !capath.is_null() && *capath.offset(0 as isize) == 0 {
         capath = 0 as *const libc::c_char;
     }
     Curl_infof(
         data,
         b" CAfile: %s\0" as *const u8 as *const libc::c_char,
         if !cafile.is_null() {
             cafile
         } else {
             b"none\0" as *const u8 as *const libc::c_char
         },
     );
     Curl_infof(
         data,
         b" CApath: %s\0" as *const u8 as *const libc::c_char,
         if !capath.is_null() {
             capath
         } else {
             b"none\0" as *const u8 as *const libc::c_char
         },
     );
 
     /* load libnssckbi.so if no other trust roots were specified */
     use_trust_module = cafile.is_null() && capath.is_null();
     PR_Lock(nss_trustload_lock);
     if use_trust_module as i32 != 0 && trust_module.is_null() {
         /* libnssckbi.so needed but not yet loaded --> load it! */
         result = nss_load_module(
             &mut trust_module,
             trust_library,
             b"trust\0" as *const u8 as *const libc::c_char,
         );
         Curl_infof(
             data,
             b"%s %s\0" as *const u8 as *const libc::c_char,
             if result as u32 != 0 {
                 b"failed to load\0" as *const u8 as *const libc::c_char
             } else {
                 b"loaded\0" as *const u8 as *const libc::c_char
             },
             trust_library,
         );
         if result as u32 == CURLE_FAILED_INIT as i32 as u32 {
             /* If libnssckbi.so is not available (or fails to load), one can still
          use CA certificates stored in NSS database.  Ignore the failure. */
             result = CURLE_OK;
         }
     } else if !use_trust_module && !trust_module.is_null() {
         /* libnssckbi.so not needed but already loaded --> unload it! */
         Curl_infof(
             data,
             b"unloading %s\0" as *const u8 as *const libc::c_char,
             trust_library,
         );
         nss_unload_module(&mut trust_module);
     }
     PR_Unlock(nss_trustload_lock);
     if !cafile.is_null() {
         result = nss_load_cert(
             &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize),
             cafile,
             1 as i32,
         );
     }
     if result as u64 != 0 {
         return result;
     }
     if !capath.is_null() {
         let mut st: stat = stat {
             st_dev: 0,
             st_ino: 0,
             st_nlink: 0,
             st_mode: 0,
             st_uid: 0,
             st_gid: 0,
             __pad0: 0,
             st_rdev: 0,
             st_size: 0,
             st_blksize: 0,
             st_blocks: 0,
             st_atim: timespec {
                 tv_sec: 0,
                 tv_nsec: 0,
             },
             st_mtim: timespec {
                 tv_sec: 0,
                 tv_nsec: 0,
             },
             st_ctim: timespec {
                 tv_sec: 0,
                 tv_nsec: 0,
             },
             __glibc_reserved: [0; 3],
         };
         if stat(capath, &mut st) == -(1 as i32) {
             return CURLE_SSL_CACERT_BADFILE;
         }
         if st.st_mode & 0o170000 as u32
             == 0o40000 as u32
         {
             let mut entry: *mut PRDirEntry = 0 as *mut PRDirEntry;
             let mut dir: *mut PRDir = PR_OpenDir(capath);
             if dir.is_null() {
                 return CURLE_SSL_CACERT_BADFILE;
             }
             loop {
                 entry = PR_ReadDir(
                     dir,
                     (PR_SKIP_BOTH as i32 | PR_SKIP_HIDDEN as i32) as PRDirFlags,
                 );
                 if entry.is_null() {
                     break;
                 }
                 let mut fullpath: *mut libc::c_char = curl_maprintf(
                     b"%s/%s\0" as *const u8 as *const libc::c_char,
                     capath,
                     (*entry).name,
                 );
                 if fullpath.is_null() {
                     PR_CloseDir(dir);
                     return CURLE_OUT_OF_MEMORY;
                 }
                 if CURLSHE_OK as u32
                     != nss_load_cert(
                         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize),
                         fullpath,
                         1 as i32,
                     ) as u32
                 {
                     /* This is purposefully tolerant of errors so non-PEM files can
            * be in the same directory */
                     Curl_infof(
                         data,
                         b"failed to load '%s' from CURLOPT_CAPATH\0" as *const u8
                             as *const libc::c_char,
                         fullpath,
                     );
                 }
                 #[cfg(not(CURLDEBUG))]
                 Curl_cfree.expect("non-null function pointer")(fullpath as *mut libc::c_void);
                 #[cfg(CURLDEBUG)]
                 curl_dbg_free(
                     fullpath as *mut libc::c_void,
                     1715 as libc::c_int,
                     b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
                 );
             }
             PR_CloseDir(dir);
         } else {
             Curl_infof(
                 data,
                 b"warning: CURLOPT_CAPATH not a directory (%s)\0" as *const u8
                     as *const libc::c_char,
                 capath,
             );
         }
     }
     return CURLE_OK;
     }
 }
 extern "C" fn nss_sslver_from_curl(
     mut nssver: *mut PRUint16,
     mut version: i64,
 ) -> CURLcode {
     unsafe{
         match version {
             2 => {
                 *nssver = 0x2 as PRUint16;
                 return CURLE_OK;
             }
             3 => return CURLE_NOT_BUILT_IN,
             4 => {
                 *nssver = 0x301 as PRUint16;
                 return CURLE_OK;
             }
             5 => {
                 match () {
                     #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
                     _ => {
                         *nssver = 0x302 as PRUint16;
                         return CURLE_OK;
                     }
                     #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_1))]
                     _ => {
                         return CURLE_SSL_CONNECT_ERROR;
                     }
                 }
                 // #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
                 // *nssver = 0x302 as i32 as PRUint16;
                 // #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
                 // return CURLE_OK;
                 // #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_1))]
                 // return CURLE_SSL_CONNECT_ERROR;
             }
             6 => {
                 match () {
                     #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
                     _ => {
                         *nssver = 0x303 as PRUint16;
                         return CURLE_OK;
                     }
                     #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_2))]
                     _ => {
                         return CURLE_SSL_CONNECT_ERROR;
                     }
                 }
                 // #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
                 // *nssver = 0x303 as i32 as PRUint16;
                 // #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
                 // return CURLE_OK;
                 // #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_2))]
                 // return CURLE_SSL_CONNECT_ERROR;
             }
             7 => {
                 match () {
                     #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
                     _ => {
                         *nssver = 0x304 as PRUint16;
                         return CURLE_OK;
                     }
                     #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_3))]
                     _ => {
                         return CURLE_SSL_CONNECT_ERROR;
                     }
                 }
                 // #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
                 // *nssver = 0x304 as i32 as PRUint16;
                 // #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
                 // return CURLE_OK;
                 // #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_3))]
                 // return CURLE_SSL_CONNECT_ERROR;
             }
             _ => return CURLE_SSL_CONNECT_ERROR,
         };
     }
 }
 extern "C" fn nss_init_sslver(
     mut sslver: *mut SSLVersionRange,
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
 ) -> CURLcode {
     unsafe{
         let mut result: CURLcode = CURLE_OK;
     #[cfg(not(CURL_DISABLE_PROXY))]
     let min: i64 = if CURLPROXY_HTTPS as u32
         == (*conn).http_proxy.proxytype as u32
         && ssl_connection_complete as u32
             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
             {
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
     let min: i64 = (*conn).ssl_config.version;
     #[cfg(not(CURL_DISABLE_PROXY))]
     let max: i64 = if CURLPROXY_HTTPS as u32
         == (*conn).http_proxy.proxytype as u32
         && ssl_connection_complete as u32
             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize] == -(1 as i32)
             {
                 0 as i32
             } else {
                 1 as i32
             }) as usize]
                 .state as u32
     {
         (*conn).proxy_ssl_config.version_max
     } else {
         (*conn).ssl_config.version_max
     };
     #[cfg(CURL_DISABLE_PROXY)]
     let max: i64 = (*conn).ssl_config.version_max;
     let mut vrange: SSLVersionRange = SSLVersionRange { min: 0, max: 0 };
     match min {
         1 | 0 => {
             /* Bump our minimum TLS version if NSS has stricter requirements. */
             if SSL_VersionRangeGetDefault(ssl_variant_stream, &mut vrange) as i32
                 != SECSuccess as i32
             {
                 return CURLE_SSL_CONNECT_ERROR;
             }
             if ((*sslver).min as i32) < vrange.min as i32 {
                 (*sslver).min = vrange.min;
             }
         }
         _ => {
             result = nss_sslver_from_curl(&mut (*sslver).min, min);
             if result as u64 != 0 {
                 Curl_failf(
                     data,
                     b"unsupported min version passed via CURLOPT_SSLVERSION\0" as *const u8
                         as *const libc::c_char,
                 );
                 return result;
             }
         }
     }
     match max {
         0 | 65536 => {}
         _ => {
             result = nss_sslver_from_curl(&mut (*sslver).max, max >> 16 as i32);
             if result as u64 != 0 {
                 Curl_failf(
                     data,
                     b"unsupported max version passed via CURLOPT_SSLVERSION\0" as *const u8
                         as *const libc::c_char,
                 );
                 return result;
             }
         }
     }
     return CURLE_OK;
     }
 }
 extern "C" fn nss_fail_connect(
     mut connssl: *mut ssl_connect_data,
     mut data: *mut Curl_easy,
     mut curlerr: CURLcode,
 ) -> CURLcode {
     unsafe{
         let mut backend: *mut ssl_backend_data = (*connssl).backend;
     if is_nss_error(curlerr) {
         /* read NSPR error code */
         let mut err: PRErrorCode = PR_GetError();
         if is_cc_error(err) {
             curlerr = CURLE_SSL_CERTPROBLEM;
         }
         /* print the error number and error string */
         Curl_infof(
             data,
             b"NSS error %d (%s)\0" as *const u8 as *const libc::c_char,
             err,
             nss_error_to_name(err),
         );
          /* print a human-readable message describing the error if available */
         nss_print_error_message(data, err as PRUint32);
     }
     /* cleanup on connection failure */
     Curl_llist_destroy(&mut (*backend).obj_list, 0 as *mut libc::c_void);
     return curlerr;
     }
 }
 
 /* Switch the SSL socket into blocking or non-blocking mode. */
 extern "C" fn nss_set_blocking(
     mut connssl: *mut ssl_connect_data,
     mut data: *mut Curl_easy,
     mut blocking: bool,
 ) -> CURLcode {
     unsafe{
         let mut sock_opt: PRSocketOptionData = PRSocketOptionData {
             option: PR_SockOpt_Nonblocking,
             value: nss_C2RustUnnamed_5 { ip_ttl: 0 },
         };
         let mut backend: *mut ssl_backend_data = (*connssl).backend;
         sock_opt.option = PR_SockOpt_Nonblocking;
         sock_opt.value.non_blocking = !blocking as i32;
         if PR_SetSocketOption((*backend).nss_handle, &mut sock_opt) as i32
             != PR_SUCCESS as i32
         {
             return nss_fail_connect(connssl, data, CURLE_SSL_CONNECT_ERROR);
         }
         return CURLE_OK;
     }
 }
 // unsafe extern "C" fn nss_setup_connect(
 //     mut data: *mut Curl_easy,
 //     mut conn: *mut connectdata,
 //     mut sockindex: i32,
 // ) -> CURLcode {
 //     let mut current_block: u64;
 //     let mut model: *mut PRFileDesc = 0 as *mut PRFileDesc;
 //     let mut nspr_io: *mut PRFileDesc = 0 as *mut PRFileDesc;
 //     let mut nspr_io_stub: *mut PRFileDesc = 0 as *mut PRFileDesc;
 //     let mut ssl_no_cache: PRBool = 0;
 //     let mut ssl_cbc_random_iv: PRBool = 0;
 //     let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
 //     let mut connssl: *mut ssl_connect_data =
 //         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
 //     let mut backend: *mut ssl_backend_data = (*connssl).backend;
 //     let mut result: CURLcode = CURLE_OK;
 //     let mut second_layer: bool = 0 as i32 != 0;
 //     let mut sslver_supported: SSLVersionRange = SSLVersionRange { min: 0, max: 0 };
 //     let mut sslver: SSLVersionRange = {
 //         let mut init = SSLVersionRangeStr {
 //             min: 0x301 as i32 as PRUint16,
 //             max: 0x304 as i32 as PRUint16,
 //         };
 //         init
 //     };
 //     let ref mut fresh17 = (*backend).data;
 //     *fresh17 = data;
 //     Curl_llist_init(
 //         &mut (*backend).obj_list,
 //         Some(
 //             nss_destroy_object as unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> (),
 //         ),
 //     );
 //     PR_Lock(nss_initlock);
 //     result = nss_setup(data);
 //     if result as u64 != 0 {
 //         PR_Unlock(nss_initlock);
 //     } else {
 //         PK11_SetPasswordFunc(Some(
 //             nss_get_password
 //                 as unsafe extern "C" fn(
 //                     *mut PK11SlotInfo,
 //                     PRBool,
 //                     *mut libc::c_void,
 //                 ) -> *mut libc::c_char,
 //         ));
 //         result = nss_load_module(
 //             &mut pem_module,
 //             pem_library,
 //             b"PEM\0" as *const u8 as *const libc::c_char,
 //         );
 //         PR_Unlock(nss_initlock);
 //         if result as u32 == CURLE_FAILED_INIT as i32 as u32 {
 //             Curl_infof(
 //                 data,
 //                 b"WARNING: failed to load NSS PEM library %s. Using OpenSSL PEM certificates will not work.\0"
 //                     as *const u8 as *const libc::c_char,
 //                 pem_library,
 //             );
 //             current_block = 6009453772311597924;
 //         } else if result as u64 != 0 {
 //             current_block = 8192695711153237833;
 //         } else {
 //             current_block = 6009453772311597924;
 //         }
 //         match current_block {
 //             8192695711153237833 => {}
 //             _ => {
 //                 result = CURLE_SSL_CONNECT_ERROR;
 //                 model = PR_NewTCPSocket();
 //                 if !model.is_null() {
 //                     model = SSL_ImportFD(0 as *mut PRFileDesc, model);
 //                     if !(SSL_OptionSet(model, 1 as i32, 1 as i32) as i32
 //                         != SECSuccess as i32)
 //                     {
 //                         if !(SSL_OptionSet(model, 6 as i32, 0 as i32)
 //                             as i32
 //                             != SECSuccess as i32)
 //                         {
 //                             if !(SSL_OptionSet(model, 5 as i32, 1 as i32)
 //                                 as i32
 //                                 != SECSuccess as i32)
 //                             {
 //                                 ssl_no_cache = if (if CURLPROXY_HTTPS as i32 as u32
 //                                     == (*conn).http_proxy.proxytype as u32
 //                                     && ssl_connection_complete as i32 as u32
 //                                         != (*conn).proxy_ssl[(if (*conn).sock
 //                                             [1 as i32 as usize]
 //                                             == -(1 as i32)
 //                                         {
 //                                             0 as i32
 //                                         } else {
 //                                             1 as i32
 //                                         })
 //                                             as usize]
 //                                             .state
 //                                             as u32
 //                                 {
 //                                     ((*data).set.proxy_ssl.primary).sessionid() as i32
 //                                 } else {
 //                                     ((*data).set.ssl.primary).sessionid() as i32
 //                                 }) != 0
 //                                     && (if CURLPROXY_HTTPS as i32 as u32
 //                                         == (*conn).http_proxy.proxytype as u32
 //                                         && ssl_connection_complete as i32 as u32
 //                                             != (*conn).proxy_ssl[(if (*conn).sock
 //                                                 [1 as i32 as usize]
 //                                                 == -(1 as i32)
 //                                             {
 //                                                 0 as i32
 //                                             } else {
 //                                                 1 as i32
 //                                             })
 //                                                 as usize]
 //                                                 .state
 //                                                 as u32
 //                                     {
 //                                         ((*conn).proxy_ssl_config).verifypeer() as i32
 //                                     } else {
 //                                         ((*conn).ssl_config).verifypeer() as i32
 //                                     }) != 0
 //                                 {
 //                                     0 as i32
 //                                 } else {
 //                                     1 as i32
 //                                 };
 //                                 if !(SSL_OptionSet(model, 9 as i32, ssl_no_cache)
 //                                     as i32
 //                                     != SECSuccess as i32)
 //                                 {
 //                                     if !(nss_init_sslver(&mut sslver, data, conn) as u32
 //                                         != CURLE_OK as i32 as u32)
 //                                     {
 //                                         if !(SSL_VersionRangeGetSupported(
 //                                             ssl_variant_stream,
 //                                             &mut sslver_supported,
 //                                         )
 //                                             as i32
 //                                             != SECSuccess as i32)
 //                                         {
 //                                             if (sslver_supported.max as i32)
 //                                                 < sslver.max as i32
 //                                                 && sslver_supported.max as i32
 //                                                     >= sslver.min as i32
 //                                             {
 //                                                 let mut sslver_req_str: *mut libc::c_char =
 //                                                     0 as *mut libc::c_char;
 //                                                 let mut sslver_supp_str: *mut libc::c_char =
 //                                                     0 as *mut libc::c_char;
 //                                                 sslver_req_str = nss_sslver_to_name(sslver.max);
 //                                                 sslver_supp_str =
 //                                                     nss_sslver_to_name(sslver_supported.max);
 //                                                 if !sslver_req_str.is_null()
 //                                                     && !sslver_supp_str.is_null()
 //                                                 {
 //                                                     Curl_infof(
 //                                                         data,
 //                                                         b"Falling back from %s to max supported SSL version (%s)\0"
 //                                                             as *const u8 as *const libc::c_char,
 //                                                         sslver_req_str,
 //                                                         sslver_supp_str,
 //                                                     );
 //                                                 }
 //                                                 Curl_cfree.expect("non-null function pointer")(
 //                                                     sslver_req_str as *mut libc::c_void,
 //                                                 );
 //                                                 Curl_cfree.expect("non-null function pointer")(
 //                                                     sslver_supp_str as *mut libc::c_void,
 //                                                 );
 //                                                 sslver.max = sslver_supported.max;
 //                                             }
 //                                             if !(SSL_VersionRangeSet(model, &mut sslver)
 //                                                 as i32
 //                                                 != SECSuccess as i32)
 //                                             {
 //                                                 ssl_cbc_random_iv = (if CURLPROXY_HTTPS
 //                                                     as i32
 //                                                     as u32
 //                                                     == (*conn).http_proxy.proxytype as u32
 //                                                     && ssl_connection_complete as i32
 //                                                         as u32
 //                                                         != (*conn).proxy_ssl[(if (*conn).sock
 //                                                             [1 as i32 as usize]
 //                                                             == -(1 as i32)
 //                                                         {
 //                                                             0 as i32
 //                                                         } else {
 //                                                             1 as i32
 //                                                         })
 //                                                             as usize]
 //                                                             .state
 //                                                             as u32
 //                                                 {
 //                                                     ((*data).set.proxy_ssl).enable_beast()
 //                                                         as i32
 //                                                 } else {
 //                                                     ((*data).set.ssl).enable_beast() as i32
 //                                                 } == 0)
 //                                                     as i32;
 //                                                 if SSL_OptionSet(
 //                                                     model,
 //                                                     23 as i32,
 //                                                     ssl_cbc_random_iv,
 //                                                 )
 //                                                     as i32
 //                                                     != SECSuccess as i32
 //                                                 {
 //                                                     Curl_infof(
 //                                                         data,
 //                                                         b"warning: failed to set SSL_CBC_RANDOM_IV = %d\0"
 //                                                             as *const u8 as *const libc::c_char,
 //                                                         ssl_cbc_random_iv,
 //                                                     );
 //                                                 }
 //                                                 if !if CURLPROXY_HTTPS as i32
 //                                                     as u32
 //                                                     == (*conn).http_proxy.proxytype as u32
 //                                                     && ssl_connection_complete as i32
 //                                                         as u32
 //                                                         != (*conn).proxy_ssl[(if (*conn).sock
 //                                                             [1 as i32 as usize]
 //                                                             == -(1 as i32)
 //                                                         {
 //                                                             0 as i32
 //                                                         } else {
 //                                                             1 as i32
 //                                                         })
 //                                                             as usize]
 //                                                             .state
 //                                                             as u32
 //                                                 {
 //                                                     (*conn).proxy_ssl_config.cipher_list
 //                                                 } else {
 //                                                     (*conn).ssl_config.cipher_list
 //                                                 }
 //                                                 .is_null()
 //                                                 {
 //                                                     if set_ciphers(
 //                                                         data,
 //                                                         model,
 //                                                         (if CURLPROXY_HTTPS as i32
 //                                                             as u32
 //                                                             == (*conn).http_proxy.proxytype
 //                                                                 as u32
 //                                                             && ssl_connection_complete
 //                                                                 as i32
 //                                                                 as u32
 //                                                                 != (*conn).proxy_ssl[(if (*conn)
 //                                                                     .sock
 //                                                                     [1 as i32 as usize]
 //                                                                     == -(1 as i32)
 //                                                                 {
 //                                                                     0 as i32
 //                                                                 } else {
 //                                                                     1 as i32
 //                                                                 })
 //                                                                     as usize]
 //                                                                     .state
 //                                                                     as u32
 //                                                         {
 //                                                             (*conn).proxy_ssl_config.cipher_list
 //                                                         } else {
 //                                                             (*conn).ssl_config.cipher_list
 //                                                         }),
 //                                                     )
 //                                                         as i32
 //                                                         != SECSuccess as i32
 //                                                     {
 //                                                         result = CURLE_SSL_CIPHER;
 //                                                         current_block = 8192695711153237833;
 //                                                     } else {
 //                                                         current_block = 12381812505308290051;
 //                                                     }
 //                                                 } else {
 //                                                     current_block = 12381812505308290051;
 //                                                 }
 //                                                 match current_block {
 //                                                     8192695711153237833 => {}
 //                                                     _ => {
 //                                                         if (if CURLPROXY_HTTPS as i32
 //                                                             as u32
 //                                                             == (*conn).http_proxy.proxytype
 //                                                                 as u32
 //                                                             && ssl_connection_complete
 //                                                                 as i32
 //                                                                 as u32
 //                                                                 != (*conn).proxy_ssl[(if (*conn)
 //                                                                     .sock
 //                                                                     [1 as i32 as usize]
 //                                                                     == -(1 as i32)
 //                                                                 {
 //                                                                     0 as i32
 //                                                                 } else {
 //                                                                     1 as i32
 //                                                                 })
 //                                                                     as usize]
 //                                                                     .state
 //                                                                     as u32
 //                                                         {
 //                                                             ((*conn).proxy_ssl_config).verifypeer()
 //                                                                 as i32
 //                                                         } else {
 //                                                             ((*conn).ssl_config).verifypeer()
 //                                                                 as i32
 //                                                         }) == 0
 //                                                             && (if CURLPROXY_HTTPS as i32
 //                                                                 as u32
 //                                                                 == (*conn).http_proxy.proxytype
 //                                                                     as u32
 //                                                                 && ssl_connection_complete
 //                                                                     as i32
 //                                                                     as u32
 //                                                                     != (*conn).proxy_ssl[(if (*conn)
 //                                                                         .sock
 //                                                                         [1 as i32 as usize]
 //                                                                         == -(1 as i32)
 //                                                                     {
 //                                                                         0 as i32
 //                                                                     } else {
 //                                                                         1 as i32
 //                                                                     })
 //                                                                         as usize]
 //                                                                         .state
 //                                                                         as u32
 //                                                             {
 //                                                                 ((*conn).proxy_ssl_config)
 //                                                                     .verifyhost()
 //                                                                     as i32
 //                                                             } else {
 //                                                                 ((*conn).ssl_config).verifyhost()
 //                                                                     as i32
 //                                                             }) != 0
 //                                                         {
 //                                                             Curl_infof(
 //                                                                 data,
 //                                                                 b"warning: ignoring value of ssl.verifyhost\0" as *const u8
 //                                                                     as *const libc::c_char,
 //                                                             );
 //                                                         }
 //                                                         if !(SSL_AuthCertificateHook(
 //                                                             model,
 //                                                             Some(
 //                                                                 nss_auth_cert_hook
 //                                                                     as unsafe extern "C" fn(
 //                                                                         *mut libc::c_void,
 //                                                                         *mut PRFileDesc,
 //                                                                         PRBool,
 //                                                                         PRBool,
 //                                                                     ) -> SECStatus,
 //                                                             ),
 //                                                             data as *mut libc::c_void,
 //                                                         ) as i32 != SECSuccess as i32)
 //                                                         {
 //                                                             *if CURLPROXY_HTTPS as i32 as u32
 //                                                                 == (*conn).http_proxy.proxytype as u32
 //                                                                 && ssl_connection_complete as i32 as u32
 //                                                                     != (*conn)
 //                                                                         .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                             == -(1 as i32)
 //                                                                         {
 //                                                                             0 as i32
 //                                                                         } else {
 //                                                                             1 as i32
 //                                                                         }) as usize]
 //                                                                         .state as u32
 //                                                             {
 //                                                                 &mut (*data).set.proxy_ssl.certverifyresult
 //                                                             } else {
 //                                                                 &mut (*data).set.ssl.certverifyresult
 //                                                             } = 0 as i32 as i64;
 //                                                             if !(SSL_BadCertHook(
 //                                                                 model,
 //                                                                 Some(
 //                                                                     BadCertHandler
 //                                                                         as unsafe extern "C" fn(
 //                                                                             *mut libc::c_void,
 //                                                                             *mut PRFileDesc,
 //                                                                         ) -> SECStatus,
 //                                                                 ),
 //                                                                 data as *mut libc::c_void,
 //                                                             ) as i32 != SECSuccess as i32)
 //                                                             {
 //                                                                 if !(SSL_HandshakeCallback(
 //                                                                     model,
 //                                                                     Some(
 //                                                                         HandshakeCallback
 //                                                                             as unsafe extern "C" fn(
 //                                                                                 *mut PRFileDesc,
 //                                                                                 *mut libc::c_void,
 //                                                                             ) -> (),
 //                                                                     ),
 //                                                                     data as *mut libc::c_void,
 //                                                                 ) as i32 != SECSuccess as i32)
 //                                                                 {
 //                                                                     let rv: CURLcode = nss_load_ca_certificates(
 //                                                                         data,
 //                                                                         conn,
 //                                                                         sockindex,
 //                                                                     );
 //                                                                     if rv as u32
 //                                                                         == CURLE_SSL_CACERT_BADFILE as i32 as u32
 //                                                                         && (if CURLPROXY_HTTPS as i32 as u32
 //                                                                             == (*conn).http_proxy.proxytype as u32
 //                                                                             && ssl_connection_complete as i32 as u32
 //                                                                                 != (*conn)
 //                                                                                     .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                         == -(1 as i32)
 //                                                                                     {
 //                                                                                         0 as i32
 //                                                                                     } else {
 //                                                                                         1 as i32
 //                                                                                     }) as usize]
 //                                                                                     .state as u32
 //                                                                         {
 //                                                                             ((*conn).proxy_ssl_config).verifypeer() as i32
 //                                                                         } else {
 //                                                                             ((*conn).ssl_config).verifypeer() as i32
 //                                                                         }) == 0
 //                                                                     {
 //                                                                         Curl_infof(
 //                                                                             data,
 //                                                                             b"warning: CA certificates failed to load\0" as *const u8
 //                                                                                 as *const libc::c_char,
 //                                                                         );
 //                                                                         current_block = 6528285054092551010;
 //                                                                     } else if rv as u64 != 0 {
 //                                                                         result = rv;
 //                                                                         current_block = 8192695711153237833;
 //                                                                     } else {
 //                                                                         current_block = 6528285054092551010;
 //                                                                     }
 //                                                                     match current_block {
 //                                                                         8192695711153237833 => {}
 //                                                                         _ => {
 //                                                                             if !if CURLPROXY_HTTPS as i32 as u32
 //                                                                                 == (*conn).http_proxy.proxytype as u32
 //                                                                                 && ssl_connection_complete as i32 as u32
 //                                                                                     != (*conn)
 //                                                                                         .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                             == -(1 as i32)
 //                                                                                         {
 //                                                                                             0 as i32
 //                                                                                         } else {
 //                                                                                             1 as i32
 //                                                                                         }) as usize]
 //                                                                                         .state as u32
 //                                                                             {
 //                                                                                 (*data).set.proxy_ssl.CRLfile
 //                                                                             } else {
 //                                                                                 (*data).set.ssl.CRLfile
 //                                                                             }
 //                                                                                 .is_null()
 //                                                                             {
 //                                                                                 let rv_0: CURLcode = nss_load_crl(
 //                                                                                     if CURLPROXY_HTTPS as i32 as u32
 //                                                                                         == (*conn).http_proxy.proxytype as u32
 //                                                                                         && ssl_connection_complete as i32 as u32
 //                                                                                             != (*conn)
 //                                                                                                 .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                     == -(1 as i32)
 //                                                                                                 {
 //                                                                                                     0 as i32
 //                                                                                                 } else {
 //                                                                                                     1 as i32
 //                                                                                                 }) as usize]
 //                                                                                                 .state as u32
 //                                                                                     {
 //                                                                                         (*data).set.proxy_ssl.CRLfile
 //                                                                                     } else {
 //                                                                                         (*data).set.ssl.CRLfile
 //                                                                                     },
 //                                                                                 );
 //                                                                                 if rv_0 as u64 != 0 {
 //                                                                                     result = rv_0;
 //                                                                                     current_block = 8192695711153237833;
 //                                                                                 } else {
 //                                                                                     Curl_infof(
 //                                                                                         data,
 //                                                                                         b"  CRLfile: %s\0" as *const u8 as *const libc::c_char,
 //                                                                                         if CURLPROXY_HTTPS as i32 as u32
 //                                                                                             == (*conn).http_proxy.proxytype as u32
 //                                                                                             && ssl_connection_complete as i32 as u32
 //                                                                                                 != (*conn)
 //                                                                                                     .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                         == -(1 as i32)
 //                                                                                                     {
 //                                                                                                         0 as i32
 //                                                                                                     } else {
 //                                                                                                         1 as i32
 //                                                                                                     }) as usize]
 //                                                                                                     .state as u32
 //                                                                                         {
 //                                                                                             (*data).set.proxy_ssl.CRLfile
 //                                                                                         } else {
 //                                                                                             (*data).set.ssl.CRLfile
 //                                                                                         },
 //                                                                                     );
 //                                                                                     current_block = 14001958660280927786;
 //                                                                                 }
 //                                                                             } else {
 //                                                                                 current_block = 14001958660280927786;
 //                                                                             }
 //                                                                             match current_block {
 //                                                                                 8192695711153237833 => {}
 //                                                                                 _ => {
 //                                                                                     if !if CURLPROXY_HTTPS as i32 as u32
 //                                                                                         == (*conn).http_proxy.proxytype as u32
 //                                                                                         && ssl_connection_complete as i32 as u32
 //                                                                                             != (*conn)
 //                                                                                                 .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                     == -(1 as i32)
 //                                                                                                 {
 //                                                                                                     0 as i32
 //                                                                                                 } else {
 //                                                                                                     1 as i32
 //                                                                                                 }) as usize]
 //                                                                                                 .state as u32
 //                                                                                     {
 //                                                                                         (*data).set.proxy_ssl.primary.clientcert
 //                                                                                     } else {
 //                                                                                         (*data).set.ssl.primary.clientcert
 //                                                                                     }
 //                                                                                         .is_null()
 //                                                                                     {
 //                                                                                         let mut nickname: *mut libc::c_char = dup_nickname(
 //                                                                                             data,
 //                                                                                             if CURLPROXY_HTTPS as i32 as u32
 //                                                                                                 == (*conn).http_proxy.proxytype as u32
 //                                                                                                 && ssl_connection_complete as i32 as u32
 //                                                                                                     != (*conn)
 //                                                                                                         .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                             == -(1 as i32)
 //                                                                                                         {
 //                                                                                                             0 as i32
 //                                                                                                         } else {
 //                                                                                                             1 as i32
 //                                                                                                         }) as usize]
 //                                                                                                         .state as u32
 //                                                                                             {
 //                                                                                                 (*data).set.proxy_ssl.primary.clientcert
 //                                                                                             } else {
 //                                                                                                 (*data).set.ssl.primary.clientcert
 //                                                                                             },
 //                                                                                         );
 //                                                                                         if !nickname.is_null() {
 //                                                                                             let ref mut fresh18 = (*backend).obj_clicert;
 //                                                                                             *fresh18 = 0 as *mut PK11GenericObject;
 //                                                                                             current_block = 7178192492338286402;
 //                                                                                         } else {
 //                                                                                             let mut rv_1: CURLcode = cert_stuff(
 //                                                                                                 data,
 //                                                                                                 conn,
 //                                                                                                 sockindex,
 //                                                                                                 if CURLPROXY_HTTPS as i32 as u32
 //                                                                                                     == (*conn).http_proxy.proxytype as u32
 //                                                                                                     && ssl_connection_complete as i32 as u32
 //                                                                                                         != (*conn)
 //                                                                                                             .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                                 == -(1 as i32)
 //                                                                                                             {
 //                                                                                                                 0 as i32
 //                                                                                                             } else {
 //                                                                                                                 1 as i32
 //                                                                                                             }) as usize]
 //                                                                                                             .state as u32
 //                                                                                                 {
 //                                                                                                     (*data).set.proxy_ssl.primary.clientcert
 //                                                                                                 } else {
 //                                                                                                     (*data).set.ssl.primary.clientcert
 //                                                                                                 },
 //                                                                                                 if CURLPROXY_HTTPS as i32 as u32
 //                                                                                                     == (*conn).http_proxy.proxytype as u32
 //                                                                                                     && ssl_connection_complete as i32 as u32
 //                                                                                                         != (*conn)
 //                                                                                                             .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                                 == -(1 as i32)
 //                                                                                                             {
 //                                                                                                                 0 as i32
 //                                                                                                             } else {
 //                                                                                                                 1 as i32
 //                                                                                                             }) as usize]
 //                                                                                                             .state as u32
 //                                                                                                 {
 //                                                                                                     (*data).set.proxy_ssl.key
 //                                                                                                 } else {
 //                                                                                                     (*data).set.ssl.key
 //                                                                                                 },
 //                                                                                             );
 //                                                                                             if rv_1 as u64 != 0 {
 //                                                                                                 result = rv_1;
 //                                                                                                 current_block = 8192695711153237833;
 //                                                                                             } else {
 //                                                                                                 current_block = 7178192492338286402;
 //                                                                                             }
 //                                                                                         }
 //                                                                                         match current_block {
 //                                                                                             8192695711153237833 => {}
 //                                                                                             _ => {
 //                                                                                                 let ref mut fresh19 = (*backend).client_nickname;
 //                                                                                                 *fresh19 = nickname;
 //                                                                                                 current_block = 9437375157805982253;
 //                                                                                             }
 //                                                                                         }
 //                                                                                     } else {
 //                                                                                         let ref mut fresh20 = (*backend).client_nickname;
 //                                                                                         *fresh20 = 0 as *mut libc::c_char;
 //                                                                                         current_block = 9437375157805982253;
 //                                                                                     }
 //                                                                                     match current_block {
 //                                                                                         8192695711153237833 => {}
 //                                                                                         _ => {
 //                                                                                             if SSL_GetClientAuthDataHook(
 //                                                                                                 model,
 //                                                                                                 Some(
 //                                                                                                     SelectClientCert
 //                                                                                                         as unsafe extern "C" fn(
 //                                                                                                             *mut libc::c_void,
 //                                                                                                             *mut PRFileDesc,
 //                                                                                                             *mut CERTDistNamesStr,
 //                                                                                                             *mut *mut CERTCertificateStr,
 //                                                                                                             *mut *mut SECKEYPrivateKeyStr,
 //                                                                                                         ) -> SECStatus,
 //                                                                                                 ),
 //                                                                                                 connssl as *mut libc::c_void,
 //                                                                                             ) as i32 != SECSuccess as i32
 //                                                                                             {
 //                                                                                                 result = CURLE_SSL_CERTPROBLEM;
 //                                                                                             } else {
 //                                                                                                 if ((*conn).proxy_ssl[sockindex as usize]).use_0() != 0 {
 //                                                                                                     nspr_io = (*(*conn).proxy_ssl[sockindex as usize].backend)
 //                                                                                                          handle;
 //                                                                                                     second_layer = 1 as i32 != 0;
 //                                                                                                     current_block = 10393716428851982524;
 //                                                                                                 } else {
 //                                                                                                     nspr_io = PR_ImportTCPSocket(sockfd);
 //                                                                                                     if nspr_io.is_null() {
 //                                                                                                         current_block = 8192695711153237833;
 //                                                                                                     } else {
 //                                                                                                         current_block = 10393716428851982524;
 //                                                                                                     }
 //                                                                                                 }
 //                                                                                                 match current_block {
 //                                                                                                     8192695711153237833 => {}
 //                                                                                                     _ => {
 //                                                                                                         nspr_io_stub = PR_CreateIOLayerStub(
 //                                                                                                             nspr_io_identity,
 //                                                                                                             &mut nspr_io_methods,
 //                                                                                                         );
 //                                                                                                         if nspr_io_stub.is_null() {
 //                                                                                                             if !second_layer {
 //                                                                                                                 PR_Close(nspr_io);
 //                                                                                                             }
 //                                                                                                         } else {
 //                                                                                                             let ref mut fresh21 = (*nspr_io_stub).secret;
 //                                                                                                             *fresh21 = connssl as *mut libc::c_void
 //                                                                                                                 as *mut PRFilePrivate;
 //                                                                                                             if PR_PushIOLayer(
 //                                                                                                                 nspr_io,
 //                                                                                                                 -(2 as i32),
 //                                                                                                                 nspr_io_stub,
 //                                                                                                             ) as i32 != PR_SUCCESS as i32
 //                                                                                                             {
 //                                                                                                                 if !second_layer {
 //                                                                                                                     PR_Close(nspr_io);
 //                                                                                                                 }
 //                                                                                                                 PR_Close(nspr_io_stub);
 //                                                                                                             } else {
 //                                                                                                                 let ref mut fresh22 = (*backend).handle;
 //                                                                                                                 *fresh22 = SSL_ImportFD(model, nspr_io);
 //                                                                                                                 if ((*backend).handle).is_null() {
 //                                                                                                                     if !second_layer {
 //                                                                                                                         PR_Close(nspr_io);
 //                                                                                                                     }
 //                                                                                                                 } else {
 //                                                                                                                     PR_Close(model);
 //                                                                                                                     model = 0 as *mut PRFileDesc;
 //                                                                                                                     if !if CURLPROXY_HTTPS as i32 as u32
 //                                                                                                                         == (*conn).http_proxy.proxytype as u32
 //                                                                                                                         && ssl_connection_complete as i32 as u32
 //                                                                                                                             != (*conn)
 //                                                                                                                                 .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                                                     == -(1 as i32)
 //                                                                                                                                 {
 //                                                                                                                                     0 as i32
 //                                                                                                                                 } else {
 //                                                                                                                                     1 as i32
 //                                                                                                                                 }) as usize]
 //                                                                                                                                 .state as u32
 //                                                                                                                     {
 //                                                                                                                         (*data).set.proxy_ssl.key_passwd
 //                                                                                                                     } else {
 //                                                                                                                         (*data).set.ssl.key_passwd
 //                                                                                                                     }
 //                                                                                                                         .is_null()
 //                                                                                                                     {
 //                                                                                                                         SSL_SetPKCS11PinArg(
 //                                                                                                                             (*backend).handle,
 //                                                                                                                             (if CURLPROXY_HTTPS as i32 as u32
 //                                                                                                                                 == (*conn).http_proxy.proxytype as u32
 //                                                                                                                                 && ssl_connection_complete as i32 as u32
 //                                                                                                                                     != (*conn)
 //                                                                                                                                         .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                                                             == -(1 as i32)
 //                                                                                                                                         {
 //                                                                                                                                             0 as i32
 //                                                                                                                                         } else {
 //                                                                                                                                             1 as i32
 //                                                                                                                                         }) as usize]
 //                                                                                                                                         .state as u32
 //                                                                                                                             {
 //                                                                                                                                 (*data).set.proxy_ssl.key_passwd
 //                                                                                                                             } else {
 //                                                                                                                                 (*data).set.ssl.key_passwd
 //                                                                                                                             }) as *mut libc::c_void,
 //                                                                                                                         );
 //                                                                                                                     }
 //                                                                                                                     if if CURLPROXY_HTTPS as i32 as u32
 //                                                                                                                         == (*conn).http_proxy.proxytype as u32
 //                                                                                                                         && ssl_connection_complete as i32 as u32
 //                                                                                                                             != (*conn)
 //                                                                                                                                 .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                                                     == -(1 as i32)
 //                                                                                                                                 {
 //                                                                                                                                     0 as i32
 //                                                                                                                                 } else {
 //                                                                                                                                     1 as i32
 //                                                                                                                                 }) as usize]
 //                                                                                                                                 .state as u32
 //                                                                                                                     {
 //                                                                                                                         ((*conn).proxy_ssl_config).verifystatus() as i32
 //                                                                                                                     } else {
 //                                                                                                                         ((*conn).ssl_config).verifystatus() as i32
 //                                                                                                                     } != 0
 //                                                                                                                     {
 //                                                                                                                         if SSL_OptionSet(
 //                                                                                                                             (*backend).handle,
 //                                                                                                                             24 as i32,
 //                                                                                                                             1 as i32,
 //                                                                                                                         ) as i32 != SECSuccess as i32
 //                                                                                                                         {
 //                                                                                                                             current_block = 8192695711153237833;
 //                                                                                                                         } else {
 //                                                                                                                             current_block = 4983594971376015098;
 //                                                                                                                         }
 //                                                                                                                     } else {
 //                                                                                                                         current_block = 4983594971376015098;
 //                                                                                                                     }
 //                                                                                                                     match current_block {
 //                                                                                                                         8192695711153237833 => {}
 //                                                                                                                         _ => {
 //                                                                                                                             if !(SSL_OptionSet(
 //                                                                                                                                 (*backend).handle,
 //                                                                                                                                 25 as i32,
 //                                                                                                                                 (if ((*conn).bits).tls_enable_npn() as i32 != 0 {
 //                                                                                                                                     1 as i32
 //                                                                                                                                 } else {
 //                                                                                                                                     0 as i32
 //                                                                                                                                 }),
 //                                                                                                                             ) as i32 != SECSuccess as i32)
 //                                                                                                                             {
 //                                                                                                                                 if !(SSL_OptionSet(
 //                                                                                                                                     (*backend).handle,
 //                                                                                                                                     26 as i32,
 //                                                                                                                                     (if ((*conn).bits).tls_enable_alpn() as i32 != 0 {
 //                                                                                                                                         1 as i32
 //                                                                                                                                     } else {
 //                                                                                                                                         0 as i32
 //                                                                                                                                     }),
 //                                                                                                                                 ) as i32 != SECSuccess as i32)
 //                                                                                                                                 {
 //                                                                                                                                     if ((*data).set.ssl).falsestart() != 0 {
 //                                                                                                                                         if SSL_OptionSet(
 //                                                                                                                                             (*backend).handle,
 //                                                                                                                                             22 as i32,
 //                                                                                                                                             1 as i32,
 //                                                                                                                                         ) as i32 != SECSuccess as i32
 //                                                                                                                                         {
 //                                                                                                                                             current_block = 8192695711153237833;
 //                                                                                                                                         } else if SSL_SetCanFalseStartCallback(
 //                                                                                                                                                 (*backend).handle,
 //                                                                                                                                                 Some(
 //                                                                                                                                                     CanFalseStartCallback
 //                                                                                                                                                         as unsafe extern "C" fn(
 //                                                                                                                                                             *mut PRFileDesc,
 //                                                                                                                                                             *mut libc::c_void,
 //                                                                                                                                                             *mut PRBool,
 //                                                                                                                                                         ) -> SECStatus,
 //                                                                                                                                                 ),
 //                                                                                                                                                 data as *mut libc::c_void,
 //                                                                                                                                             ) as i32 != SECSuccess as i32
 //                                                                                                                                             {
 //                                                                                                                                             current_block = 8192695711153237833;
 //                                                                                                                                         } else {
 //                                                                                                                                             current_block = 16375338222180917333;
 //                                                                                                                                         }
 //                                                                                                                                     } else {
 //                                                                                                                                         current_block = 16375338222180917333;
 //                                                                                                                                     }
 //                                                                                                                                     match current_block {
 //                                                                                                                                         8192695711153237833 => {}
 //                                                                                                                                         _ => {
 //                                                                                                                                             if ((*conn).bits).tls_enable_npn() as i32 != 0
 //                                                                                                                                                 || ((*conn).bits).tls_enable_alpn() as i32 != 0
 //                                                                                                                                             {
 //                                                                                                                                                 let mut cur: i32 = 0 as i32;
 //                                                                                                                                                 let mut protocols: [u8; 128] = [0; 128];
 //                                                                                                                                                 if (*data).state.httpwant as i32
 //                                                                                                                                                     >= CURL_HTTP_VERSION_2_0 as i32
 //                                                                                                                                                     && (!(CURLPROXY_HTTPS as i32 as u32
 //                                                                                                                                                         == (*conn).http_proxy.proxytype as u32
 //                                                                                                                                                         && ssl_connection_complete as i32 as u32
 //                                                                                                                                                             != (*conn)
 //                                                                                                                                                                 .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                                                                                     == -(1 as i32)
 //                                                                                                                                                                 {
 //                                                                                                                                                                     0 as i32
 //                                                                                                                                                                 } else {
 //                                                                                                                                                                     1 as i32
 //                                                                                                                                                                 }) as usize]
 //                                                                                                                                                                 .state as u32)
 //                                                                                                                                                         || ((*conn).bits).tunnel_proxy() == 0)
 //                                                                                                                                                 {
 //                                                                                                                                                     let fresh23 = cur;
 //                                                                                                                                                     cur = cur + 1;
 //                                                                                                                                                     protocols[fresh23
 //                                                                                                                                                         as usize] = 2 as i32 as u8;
 //                                                                                                                                                     memcpy(
 //                                                                                                                                                         &mut *protocols.as_mut_ptr().offset(cur as isize)
 //                                                                                                                                                             as *mut u8 as *mut libc::c_void,
 //                                                                                                                                                         b"h2\0" as *const u8 as *const libc::c_char
 //                                                                                                                                                             as *const libc::c_void,
 //                                                                                                                                                         2 as i32 as u64,
 //                                                                                                                                                     );
 //                                                                                                                                                     cur += 2 as i32;
 //                                                                                                                                                 }
 //                                                                                                                                                 let fresh24 = cur;
 //                                                                                                                                                 cur = cur + 1;
 //                                                                                                                                                 protocols[fresh24
 //                                                                                                                                                     as usize] = 8 as i32 as u8;
 //                                                                                                                                                 memcpy(
 //                                                                                                                                                     &mut *protocols.as_mut_ptr().offset(cur as isize)
 //                                                                                                                                                         as *mut u8 as *mut libc::c_void,
 //                                                                                                                                                     b"http/1.1\0" as *const u8 as *const libc::c_char
 //                                                                                                                                                         as *const libc::c_void,
 //                                                                                                                                                     8 as i32 as u64,
 //                                                                                                                                                 );
 //                                                                                                                                                 cur += 8 as i32;
 //                                                                                                                                                 if SSL_SetNextProtoNego(
 //                                                                                                                                                     (*backend).handle,
 //                                                                                                                                                     protocols.as_mut_ptr(),
 //                                                                                                                                                     cur as u32,
 //                                                                                                                                                 ) as i32 != SECSuccess as i32
 //                                                                                                                                                 {
 //                                                                                                                                                     current_block = 8192695711153237833;
 //                                                                                                                                                 } else {
 //                                                                                                                                                     current_block = 16910810822589621899;
 //                                                                                                                                                 }
 //                                                                                                                                             } else {
 //                                                                                                                                                 current_block = 16910810822589621899;
 //                                                                                                                                             }
 //                                                                                                                                             match current_block {
 //                                                                                                                                                 8192695711153237833 => {}
 //                                                                                                                                                 _ => {
 //                                                                                                                                                     if !(SSL_ResetHandshake((*backend).handle, 0 as i32)
 //                                                                                                                                                         as i32 != SECSuccess as i32)
 //                                                                                                                                                     {
 //                                                                                                                                                         if !(SSL_SetURL(
 //                                                                                                                                                             (*backend).handle,
 //                                                                                                                                                             (if CURLPROXY_HTTPS as i32 as u32
 //                                                                                                                                                                 == (*conn).http_proxy.proxytype as u32
 //                                                                                                                                                                 && ssl_connection_complete as i32 as u32
 //                                                                                                                                                                     != (*conn)
 //                                                                                                                                                                         .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                                                                                             == -(1 as i32)
 //                                                                                                                                                                         {
 //                                                                                                                                                                             0 as i32
 //                                                                                                                                                                         } else {
 //                                                                                                                                                                             1 as i32
 //                                                                                                                                                                         }) as usize]
 //                                                                                                                                                                         .state as u32
 //                                                                                                                                                             {
 //                                                                                                                                                                 (*conn).http_proxy.host.name
 //                                                                                                                                                             } else {
 //                                                                                                                                                                 (*conn).host.name
 //                                                                                                                                                             }),
 //                                                                                                                                                         ) as i32 != SECSuccess as i32)
 //                                                                                                                                                         {
 //                                                                                                                                                             if !(SSL_SetSockPeerID(
 //                                                                                                                                                                 (*backend).handle,
 //                                                                                                                                                                 (if CURLPROXY_HTTPS as i32 as u32
 //                                                                                                                                                                     == (*conn).http_proxy.proxytype as u32
 //                                                                                                                                                                     && ssl_connection_complete as i32 as u32
 //                                                                                                                                                                         != (*conn)
 //                                                                                                                                                                             .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                                                                                                                                                                 == -(1 as i32)
 //                                                                                                                                                                             {
 //                                                                                                                                                                                 0 as i32
 //                                                                                                                                                                             } else {
 //                                                                                                                                                                                 1 as i32
 //                                                                                                                                                                             }) as usize]
 //                                                                                                                                                                             .state as u32
 //                                                                                                                                                                 {
 //                                                                                                                                                                     (*conn).http_proxy.host.name
 //                                                                                                                                                                 } else {
 //                                                                                                                                                                     (*conn).host.name
 //                                                                                                                                                                 }),
 //                                                                                                                                                             ) as i32 != SECSuccess as i32)
 //                                                                                                                                                             {
 //                                                                                                                                                                 return CURLE_OK;
 //                                                                                                                                                             }
 //                                                                                                                                                         }
 //                                                                                                                                                     }
 //                                                                                                                                                 }
 //                                                                                                                                             }
 //                                                                                                                                         }
 //                                                                                                                                     }
 //                                                                                                                                 }
 //                                                                                                                             }
 //                                                                                                                         }
 //                                                                                                                     }
 //                                                                                                                 }
 //                                                                                                             }
 //                                                                                                         }
 //                                                                                                     }
 //                                                                                                 }
 //                                                                                             }
 //                                                                                         }
 //                                                                                     }
 //                                                                                 }
 //                                                                             }
 //                                                                         }
 //                                                                     }
 //                                                                 }
 //                                                             }
 //                                                         }
 //                                                     }
 //                                                 }
 //                                             }
 //                                         }
 //                                     }
 //                                 }
 //                             }
 //                         }
 //                     }
 //                 }
 //             }
 //         }
 //     }
 //     if !model.is_null() {
 //         PR_Close(model);
 //     }
 //     return nss_fail_connect(connssl, data, result);
 // }
 extern "C" fn nss_setup_connect(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) -> CURLcode {
     unsafe{
         let mut model: *mut PRFileDesc = 0 as *mut PRFileDesc;
     let mut nspr_io: *mut PRFileDesc = 0 as *mut PRFileDesc;
     let mut nspr_io_stub: *mut PRFileDesc = 0 as *mut PRFileDesc;
     let mut ssl_no_cache: PRBool = 0;
     let mut ssl_cbc_random_iv: PRBool = 0;
     let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
     let mut connssl: *mut ssl_connect_data =
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
     let mut backend: *mut ssl_backend_data = (*connssl).backend;
     let mut result: CURLcode = CURLE_OK;
     let mut second_layer: bool = 0 as i32 != 0;
     let mut sslver_supported: SSLVersionRange = SSLVersionRange { min: 0, max: 0 };
     let mut sslver: SSLVersionRange = {
         #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
         let mut init = SSLVersionRangeStr {
             min: 0x301 as PRUint16,
             max: 0x304 as PRUint16,
         };
         #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
         let mut init = SSLVersionRangeStr {
             min: 0x301 as PRUint16,
             max: 0x303 as PRUint16,
         };
         #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
         let mut init = SSLVersionRangeStr {
             min: 0x301 as PRUint16,
             max: 0x302 as PRUint16,
         };
         #[cfg(all(not(SSL_LIBRARY_VERSION_TLS_1_3), not(SSL_LIBRARY_VERSION_TLS_1_2), not(SSL_LIBRARY_VERSION_TLS_1_1)))]
         let mut init = SSLVersionRangeStr {
             min: 0x301 as PRUint16,
             max: 0x301 as PRUint16,
         };
         init
     };
     (*backend).data = data;
     /* list of all NSS objects we need to destroy in nss_do_close() */
     Curl_llist_init(
         &mut (*backend).obj_list,
         Some(
             nss_destroy_object as unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> (),
         ),
     );
     PR_Lock(nss_initlock);
     result = nss_setup(data);
     // 创建一个循环
     // 循环开始
     'error: loop {
         if result as u64 != 0 {
             PR_Unlock(nss_initlock);
             break 'error;
         }
         PK11_SetPasswordFunc(
             Some(
                 nss_get_password
                     as unsafe extern "C" fn(
                         *mut PK11SlotInfo,
                         PRBool,
                         *mut libc::c_void,
                     ) -> *mut libc::c_char,
             ),
         );
         result = nss_load_module(
             &mut pem_module,
             pem_library,
             b"PEM\0" as *const u8 as *const libc::c_char,
         );
         PR_Unlock(nss_initlock);
         if result as u32 == CURLE_FAILED_INIT as i32 as u32 {
             Curl_infof(
                 data,
                 b"WARNING: failed to load NSS PEM library %s. Using OpenSSL PEM certificates will not work.\0"
                     as *const u8 as *const libc::c_char,
                 pem_library,
             );
         } else if result as u64 != 0 {
             break 'error;
         }
         result = CURLE_SSL_CONNECT_ERROR;
         model = PR_NewTCPSocket();
         if model.is_null() {
             break 'error;
         }
         model = SSL_ImportFD(0 as *mut PRFileDesc, model);
         if SSL_OptionSet(model, 1 as i32, 1 as i32) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         if SSL_OptionSet(model, 6 as i32, 0 as i32) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         if SSL_OptionSet(model, 5 as i32, 1 as i32) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         let ssl_no_cache_value = if (if CURLPROXY_HTTPS as i32 as u32
                                     == (*conn).http_proxy.proxytype as u32
                                     && ssl_connection_complete as i32 as u32
                                         != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize]
                                             == -(1 as i32)
                                         {
                                             0 as i32
                                         } else {
                                             1 as i32
                                         }) as usize]
                                             .state as u32
                                 {
                                     ((*data).set.proxy_ssl.primary).sessionid() as i32
                                 } else {
                                     ((*data).set.ssl.primary).sessionid() as i32
                                 }) != 0
                                     && (if CURLPROXY_HTTPS as u32
                                         == (*conn).http_proxy.proxytype as u32
                                         && ssl_connection_complete as u32
                                             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                 == -(1 as i32)
                                             {
                                                 0 as i32
                                             } else {
                                                 1 as i32
                                             }) as usize]
                                                 .state as u32
                                     {
                                         ((*conn).proxy_ssl_config).verifypeer() as i32
                                     } else {
                                         ((*conn).ssl_config).verifypeer() as i32
                                     }) != 0
                                 {
                                     0 as i32
                                 } else {
                                     1 as i32
                                 };
         #[cfg(CURL_DISABLE_PROXY)]
         let ssl_no_cache_value = if ((*data).set.ssl.primary).sessionid()
                                     as i32 != 0
                                     && ((*conn).ssl_config).verifypeer() as i32 != 0
                                 {
                                     0 as i32
                                 } else {
                                     1 as i32
                                 };
 
         /* do not use SSL cache if disabled or we are not going to verify peer */
         ssl_no_cache = ssl_no_cache_value;
         if SSL_OptionSet(model, 9 as i32, ssl_no_cache) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         /* enable/disable the requested SSL version(s) */
         if nss_init_sslver(&mut sslver, data, conn) as u32
             != CURLE_OK as u32
         {
             break 'error;
         }
         if SSL_VersionRangeGetSupported(ssl_variant_stream, &mut sslver_supported) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         if (sslver_supported.max as i32) < sslver.max as i32
             && sslver_supported.max as i32 >= sslver.min as i32
         {
             let mut sslver_req_str: *mut libc::c_char = 0 as *mut libc::c_char;
             let mut sslver_supp_str: *mut libc::c_char = 0 as *mut libc::c_char;
             sslver_req_str = nss_sslver_to_name(sslver.max);
             sslver_supp_str = nss_sslver_to_name(sslver_supported.max);
             if !sslver_req_str.is_null() && !sslver_supp_str.is_null() {
                 Curl_infof(
                     data,
                     b"Falling back from %s to max supported SSL version (%s)\0" as *const u8
                         as *const libc::c_char,
                     sslver_req_str,
                     sslver_supp_str,
                 );
             }
             #[cfg(not(CURLDEBUG))]
             Curl_cfree.expect("non-null function pointer")(sslver_req_str as *mut libc::c_void);
             #[cfg(not(CURLDEBUG))]
             Curl_cfree.expect("non-null function pointer")(sslver_supp_str as *mut libc::c_void);
            
             #[cfg(CURLDEBUG)]
             curl_dbg_free(
                 sslver_req_str as *mut libc::c_void,
                 1935 as libc::c_int,
                 b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
             );
             #[cfg(CURLDEBUG)]
             curl_dbg_free(
                 sslver_supp_str as *mut libc::c_void,
                 1936 as libc::c_int,
                 b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
             );
          
             sslver.max = sslver_supported.max;
         }
         if SSL_VersionRangeSet(model, &mut sslver) as i32 != SECSuccess as i32 {
             break 'error;
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         let ssl_cbc_random_iv_value = (if CURLPROXY_HTTPS as u32
                                         == (*conn).http_proxy.proxytype as u32
                                         && ssl_connection_complete as u32
                                             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                 == -(1 as i32)
                                             {
                                                 0 as i32
                                             } else {
                                                 1 as i32
                                             }) as usize]
                                                 .state as u32
                                     {
                                         ((*data).set.proxy_ssl).enable_beast() as i32
                                     } else {
                                         ((*data).set.ssl).enable_beast() as i32
                                     } == 0) as i32;
         #[cfg(CURL_DISABLE_PROXY)]
         let ssl_cbc_random_iv_value = (((*data).set.ssl).enable_beast() == 0)
                                             as i32;
         ssl_cbc_random_iv = ssl_cbc_random_iv_value;
         #[cfg(SSL_CBC_RANDOM_IV)]
         /* unless the user explicitly asks to allow the protocol vulnerability, we
      use the work-around */
         if SSL_OptionSet(model, 23 as i32, ssl_cbc_random_iv) as i32
             != SECSuccess as i32
         {
             Curl_infof(
                 data,
                 b"warning: failed to set SSL_CBC_RANDOM_IV = %d\0" as *const u8
                     as *const libc::c_char,
                 ssl_cbc_random_iv,
             );
         }
 
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_CONN_CONFIG_cipher_list = if CURLPROXY_HTTPS as u32
                                             == (*conn).http_proxy.proxytype as u32
                                             && ssl_connection_complete as i32 as u32
                                                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                     == -(1 as i32)
                                                 {
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
         if !SSL_CONN_CONFIG_cipher_list.is_null()
         {
             if set_ciphers(
                 data,
                 model,
                 SSL_CONN_CONFIG_cipher_list,
             ) as i32
                 != SECSuccess as i32
             {
                 result = CURLE_SSL_CIPHER;
                 // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
                 break 'error;
             }
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as u32
                                             == (*conn).http_proxy.proxytype as u32
                                             && ssl_connection_complete as u32
                                                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                     == -(1 as i32)
                                                 {
                                                     0 as i32
                                                 } else {
                                                     1 as i32
                                                 }) as usize]
                                                     .state as u32
                                         {
                                             ((*conn).proxy_ssl_config).verifypeer() as i32
                                         } else {
                                             ((*conn).ssl_config).verifypeer() as i32
                                         };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_CONN_CONFIG_verifypeer = ((*conn).ssl_config).verifypeer();
         
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_CONN_CONFIG_verifyhost = if CURLPROXY_HTTPS as u32
                                             == (*conn).http_proxy.proxytype as u32
                                             && ssl_connection_complete as u32
                                                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                     == -(1 as i32)
                                                 {
                                                     0 as i32
                                                 } else {
                                                     1 as i32
                                                 }) as usize]
                                                     .state as u32
                                         {
                                             ((*conn).proxy_ssl_config).verifyhost() as i32
                                         } else {
                                             ((*conn).ssl_config).verifyhost() as i32
                                         };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_CONN_CONFIG_verifyhost = ((*conn).ssl_config).verifyhost();
 
 
         if (SSL_CONN_CONFIG_verifypeer) == 0
             && (SSL_CONN_CONFIG_verifyhost) != 0
         {
             Curl_infof(
                 data,
                 b"warning: ignoring value of ssl.verifyhost\0" as *const u8 as *const libc::c_char,
             );
         }
 /* bypass the default SSL_AuthCertificate() hook in case we do not want to
    * verify peer */
         if SSL_AuthCertificateHook(
             model,
             Some(
                 nss_auth_cert_hook
                     as unsafe extern "C" fn(
                         *mut libc::c_void,
                         *mut PRFileDesc,
                         PRBool,
                         PRBool,
                     ) -> SECStatus,
             ),
             data as *mut libc::c_void,
         ) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         if true {
             *if CURLPROXY_HTTPS as u32
                 == (*conn).http_proxy.proxytype as u32
                 && ssl_connection_complete as u32
                     != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                         == -(1 as i32)
                     {
                         0 as i32
                     } else {
                         1 as i32
                     }) as usize]
                         .state as u32
             {
                 &mut (*data).set.proxy_ssl.certverifyresult
             } else {
                 &mut (*data).set.ssl.certverifyresult
             } = 0 as i64;
         }
         #[cfg(CURL_DISABLE_PROXY)]
         if true {
              (*data)
                 .set
                 .ssl
                 .certverifyresult = 0 as i64;
         }
         if SSL_BadCertHook(
             model,
             Some(
                 BadCertHandler
                     as unsafe extern "C" fn(*mut libc::c_void, *mut PRFileDesc) -> SECStatus,
             ),
             data as *mut libc::c_void,
         ) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         if SSL_HandshakeCallback(
             model,
             Some(
                 HandshakeCallback as unsafe extern "C" fn(*mut PRFileDesc, *mut libc::c_void) -> (),
             ),
             data as *mut libc::c_void,
         ) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         let rv: CURLcode = nss_load_ca_certificates(data, conn, sockindex);
         if rv as u32 == CURLE_SSL_CACERT_BADFILE as u32
             && (SSL_CONN_CONFIG_verifypeer) == 0
         {
             Curl_infof(
                 data,
                 b"warning: CA certificates failed to load\0" as *const u8 as *const libc::c_char,
             );
         } else if rv as u64 != 0 {
             result = rv;
             break 'error;
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_SET_OPTION_CRLfile = if CURLPROXY_HTTPS as u32
                                         == (*conn).http_proxy.proxytype as u32
                                         && ssl_connection_complete as u32
                                             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                 == -(1 as i32)
                                             {
                                                 0 as i32
                                             } else {
                                                 1 as i32
                                             }) as usize]
                                                 .state as u32
                                     {
                                         (*data).set.proxy_ssl.CRLfile
                                     } else {
                                         (*data).set.ssl.CRLfile
                                     };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_SET_OPTION_CRLfile = (*data).set.ssl.CRLfile;
         if !SSL_SET_OPTION_CRLfile.is_null()
         {
             let rv_0: CURLcode = nss_load_crl(SSL_SET_OPTION_CRLfile);
             if rv_0 as u64 != 0 {
                 result = rv_0;
                 break 'error;
             }
             Curl_infof(
                 data,
                 b"  CRLfile: %s\0" as *const u8 as *const libc::c_char,
                 SSL_SET_OPTION_CRLfile,
             );
         }
 
         #[cfg(not(CURL_DISABLE_PROXY))]
         let  SSL_SET_OPTION_primary_clientcert = if CURLPROXY_HTTPS as u32
                                                     == (*conn).http_proxy.proxytype as u32
                                                     && ssl_connection_complete as u32
                                                         != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                             == -(1 as i32)
                                                         {
                                                             0 as i32
                                                         } else {
                                                             1 as i32
                                                         }) as usize]
                                                             .state as u32
                                                 {
                                                     (*data).set.proxy_ssl.primary.clientcert
                                                 } else {
                                                     (*data).set.ssl.primary.clientcert
                                                 };
         #[cfg(CURL_DISABLE_PROXY)]
         let  SSL_SET_OPTION_primary_clientcert = (*data).set.ssl.primary.clientcert;
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_SET_OPTION_key = if CURLPROXY_HTTPS as u32
                                         == (*conn).http_proxy.proxytype as u32
                                         && ssl_connection_complete as u32
                                             != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                 == -(1 as i32)
                                             {
                                                 0 as i32
                                             } else {
                                                 1 as i32
                                             }) as usize]
                                                 .state as u32
                                     {
                                         (*data).set.proxy_ssl.key
                                     } else {
                                         (*data).set.ssl.key
                                     };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_SET_OPTION_key = (*data).set.ssl.key;
         if ! SSL_SET_OPTION_primary_clientcert.is_null()
         {
             let mut nickname: *mut libc::c_char = dup_nickname(
                 data,
                 SSL_SET_OPTION_primary_clientcert,
             );
             if !nickname.is_null() {
                 (*backend).obj_clicert = 0 as *mut PK11GenericObject;
             } else {
                 let mut rv_1: CURLcode = cert_stuff(
                     data,
                     conn,
                     sockindex,
                     SSL_SET_OPTION_primary_clientcert,
                     SSL_SET_OPTION_key,
                 );
                 if rv_1 as u64 != 0 {
                     result = rv_1;
                     break 'error;
                 }
             }
             (*backend).client_nickname = nickname;
         } else {
             (*backend).client_nickname = 0 as *mut libc::c_char;
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         if SSL_GetClientAuthDataHook(
             model,
             Some(
                 SelectClientCert
                     as unsafe extern "C" fn(
                         *mut libc::c_void,
                         *mut PRFileDesc,
                         *mut CERTDistNamesStr,
                         *mut *mut CERTCertificateStr,
                         *mut *mut SECKEYPrivateKeyStr,
                     ) -> SECStatus,
             ),
             connssl as *mut libc::c_void,
         ) as i32
             != SECSuccess as i32
         {
             result = CURLE_SSL_CERTPROBLEM;
             break 'error;
         }
 
         #[cfg(not(CURL_DISABLE_PROXY))]
         if ((*conn).proxy_ssl[sockindex as usize]).use_0() != 0 {
             #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
             if ssl_connection_complete as libc::c_int as libc::c_uint
                 == (*conn).proxy_ssl[sockindex as usize].state
                     as libc::c_uint
             {} else {
                 __assert_fail(
                     b"ssl_connection_complete == conn->proxy_ssl[sockindex].state\0"
                         as *const u8 as *const libc::c_char,
                     b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
                     2029 as libc::c_int as libc::c_uint,
                     (*::std::mem::transmute::<
                         &[u8; 74],
                         &[libc::c_char; 74],
                     >(
                         b"CURLcode nss_setup_connect(struct Curl_easy *, struct connectdata *, int)\0",
                     ))
                         .as_ptr(),
                 );
             }
             #[cfg(all(DEBUGBUILD, HAVE_ASSERT_H))]
             if !((*(*conn).proxy_ssl[sockindex as usize].backend)
                 .handle)
                 .is_null()
             {} else {
                 __assert_fail(
                     b"conn->proxy_ssl[sockindex].backend->handle != ((void*)0)\0"
                         as *const u8 as *const libc::c_char,
                     b"vtls/nss.c\0" as *const u8 as *const libc::c_char,
                     2030 as libc::c_int as libc::c_uint,
                     (*::std::mem::transmute::<
                         &[u8; 74],
                         &[libc::c_char; 74],
                     >(
                         b"CURLcode nss_setup_connect(struct Curl_easy *, struct connectdata *, int)\0",
                     ))
                         .as_ptr(),
                 );
             }
             nspr_io = (*(*conn).proxy_ssl[sockindex as usize].backend).nss_handle;
             second_layer = 1 as i32 != 0;
         } else {
             nspr_io = PR_ImportTCPSocket(sockfd);
             if nspr_io.is_null() {
                 break 'error;
             }
         }
 
         #[cfg(CURL_DISABLE_PROXY)]
         if SSL_GetClientAuthDataHook(
             model,
             Some(
                 SelectClientCert
                     as unsafe extern "C" fn(
                         *mut libc::c_void,
                         *mut PRFileDesc,
                         *mut CERTDistNamesStr,
                         *mut *mut CERTCertificateStr,
                         *mut *mut SECKEYPrivateKeyStr,
                     ) -> SECStatus,
             ),
             connssl as *mut libc::c_void,
         ) as i32
             != SECSuccess as i32
         {
             result = CURLE_SSL_CERTPROBLEM;
             break 'error;
         }else {
             nspr_io = PR_ImportTCPSocket(sockfd);
             if nspr_io.is_null() {
                 break 'error;
             }
         }
 
 
         nspr_io_stub = PR_CreateIOLayerStub(nspr_io_identity, &mut nspr_io_methods);
         if nspr_io_stub.is_null() {
             if !second_layer {
                 PR_Close(nspr_io);
             }
             break 'error;
         }
         (*nspr_io_stub).secret = connssl as *mut libc::c_void as *mut PRFilePrivate;
         if PR_PushIOLayer(nspr_io, -(2 as i32), nspr_io_stub) as i32
             != PR_SUCCESS as i32
         {
             if !second_layer {
                 PR_Close(nspr_io);
             }
             PR_Close(nspr_io_stub);
             break 'error;
         }
         (*backend).nss_handle = SSL_ImportFD(model, nspr_io);
         if ((*backend).nss_handle).is_null() {
             if !second_layer {
                 PR_Close(nspr_io);
             }
             break 'error;
         }
         PR_Close(model);
         model = 0 as *mut PRFileDesc;
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_SET_OPTION_key_passwd = if CURLPROXY_HTTPS as u32
                                             == (*conn).http_proxy.proxytype as u32
                                             && ssl_connection_complete as u32
                                                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                     == -(1 as i32)
                                                 {
                                                     0 as i32
                                                 } else {
                                                     1 as i32
                                                 }) as usize]
                                                     .state as u32
                                         {
                                             (*data).set.proxy_ssl.key_passwd
                                         } else {
                                             (*data).set.ssl.key_passwd
                                         };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_SET_OPTION_key_passwd = (*data).set.ssl.key_passwd;
         if !SSL_SET_OPTION_key_passwd.is_null()
         {
             SSL_SetPKCS11PinArg(
                 (*backend).nss_handle,
                 SSL_SET_OPTION_key_passwd as *mut libc::c_void,
             );
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_CONN_CONFIG_verifystatus = if CURLPROXY_HTTPS as u32
                                                 == (*conn).http_proxy.proxytype as u32
                                                 && ssl_connection_complete as u32
                                                     != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                         == -(1 as i32)
                                                     {
                                                         0 as i32
                                                     } else {
                                                         1 as i32
                                                     }) as usize]
                                                         .state as u32
                                             {
                                                 ((*conn).proxy_ssl_config).verifystatus() as i32
                                             } else {
                                                 ((*conn).ssl_config).verifystatus() as i32
                                             };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_CONN_CONFIG_verifystatus = ((*conn).ssl_config).verifystatus();
         #[cfg(SSL_ENABLE_OCSP_STAPLING)]
         if SSL_CONN_CONFIG_verifystatus != 0
         {
             if SSL_OptionSet((*backend).nss_handle, 24 as i32, 1 as i32) as i32
                 != SECSuccess as i32
             {
                 break 'error;
             }
         }
         #[cfg(SSL_ENABLE_NPN)]
         if SSL_OptionSet(
             (*backend).nss_handle,
             25 as i32,
             (if ((*conn).bits).tls_enable_npn() as i32 != 0 {
                 1 as i32
             } else {
                 0 as i32
             }),
         ) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         #[cfg(SSL_ENABLE_ALPN)]
         if SSL_OptionSet(
             (*backend).nss_handle,
             26 as i32,
             (if ((*conn).bits).tls_enable_alpn() as i32 != 0 {
                 1 as i32
             } else {
                 0 as i32
             }),
         ) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         if ((*data).set.ssl).falsestart() != 0 {
             if SSL_OptionSet((*backend).nss_handle, 22 as i32, 1 as i32) as i32
                 != SECSuccess as i32
             {
                 break 'error;
             }
             if SSL_SetCanFalseStartCallback(
                 (*backend).nss_handle,
                 Some(
                     CanFalseStartCallback
                         as unsafe extern "C" fn(
                             *mut PRFileDesc,
                             *mut libc::c_void,
                             *mut PRBool,
                         ) -> SECStatus,
                 ),
                 data as *mut libc::c_void,
             ) as i32
                 != SECSuccess as i32
             {
                 break 'error;
             }
         }
         #[cfg(any(SSL_ENABLE_NPN, SSL_ENABLE_ALPN))]
         if ((*conn).bits).tls_enable_npn() as i32 != 0
             || ((*conn).bits).tls_enable_alpn() as i32 != 0
         {
             let mut cur: i32 = 0 as i32;
             let mut protocols: [u8; 128] = [0; 128];
             #[cfg(USE_HTTP2)]
             if true{
                 #[cfg(not(CURL_DISABLE_PROXY))]
                 let CURL_DISABLE_PROXY_1 = (!(CURLPROXY_HTTPS as u32
                                             == (*conn).http_proxy.proxytype as u32
                                             && ssl_connection_complete as u32
                                                 != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                                     == -(1 as i32)
                                                 {
                                                     0 as i32
                                                 } else {
                                                     1 as i32
                                                 }) as usize]
                                                     .state as u32)
                                             || ((*conn).bits).tunnel_proxy() == 0);
                 #[cfg(CURL_DISABLE_PROXY)]
                 let CURL_DISABLE_PROXY_1 = true;                 
                 if (*data).state.httpwant as i32 >= CURL_HTTP_VERSION_2_0 as i32
                     && CURL_DISABLE_PROXY_1
                 {
                     cur = cur + 1;
                     protocols[cur as usize] = 2 as u8;
                     memcpy(
                         &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut u8
                             as *mut libc::c_void,
                         b"h2\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                         2 as u64,
                     );
                     cur += 2 as i32;
                 }
             }
             cur = cur + 1;
             protocols[cur as usize] = 8 as u8;
             memcpy(
                 &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut u8
                     as *mut libc::c_void,
                 b"http/1.1\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                 8 as u64,
             );
             cur += 8 as i32;
             if SSL_SetNextProtoNego(
                 (*backend).nss_handle,
                 protocols.as_mut_ptr(),
                 cur as u32,
             ) as i32
                 != SECSuccess as i32
             {
                 break 'error;
             }
         }
         if SSL_ResetHandshake((*backend).nss_handle, 0 as i32) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_HOST_NAME_void = if CURLPROXY_HTTPS as u32
                                     == (*conn).http_proxy.proxytype as u32
                                     && ssl_connection_complete as u32
                                         != (*conn).proxy_ssl[(if (*conn).sock[1 as usize]
                                             == -(1 as i32)
                                         {
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
         let SSL_HOST_NAME_void = (*conn).host.name;
         if SSL_SetURL(
             (*backend).nss_handle,
             SSL_HOST_NAME_void,
         ) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         if SSL_SetSockPeerID(
             (*backend).nss_handle,
             SSL_HOST_NAME_void,
         ) as i32
             != SECSuccess as i32
         {
             break 'error;
         }
         return CURLE_OK;
     }
     // 循环结束
     if !model.is_null() {
         PR_Close(model);
     }
     return nss_fail_connect(connssl, data, result);
     }
 }
 
 // unsafe extern "C" fn nss_do_connect(
 //     mut data: *mut Curl_easy,
 //     mut conn: *mut connectdata,
 //     mut sockindex: i32,
 // ) -> CURLcode {
 //     let mut current_block: u64;
 //     let mut connssl: *mut ssl_connect_data =
 //         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
 //     let mut backend: *mut ssl_backend_data = (*connssl).backend;
 //     let mut result: CURLcode = CURLE_SSL_CONNECT_ERROR;
 //     let mut timeout: PRUint32 = 0;
 //     let time_left: timediff_t = Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0);
 //     if time_left < 0 as i32 as i64 {
 //         Curl_failf(
 //             data,
 //             b"timed out before SSL handshake\0" as *const u8 as *const libc::c_char,
 //         );
 //         result = CURLE_OPERATION_TIMEDOUT;
 //     } else {
 //         timeout = PR_MillisecondsToInterval(time_left as PRUint32);
 //         if SSL_ForceHandshakeWithTimeout((*backend).handle, timeout) as i32
 //             != SECSuccess as i32
 //         {
 //             if PR_GetError() as i64 == -(5998 as i64) {
 //                 return CURLE_AGAIN;
 //             } else {
 //                 if (if CURLPROXY_HTTPS as i32 as u32
 //                     == (*conn).http_proxy.proxytype as u32
 //                     && ssl_connection_complete as i32 as u32
 //                         != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                             == -(1 as i32)
 //                         {
 //                             0 as i32
 //                         } else {
 //                             1 as i32
 //                         }) as usize]
 //                             .state as u32
 //                 {
 //                     (*data).set.proxy_ssl.certverifyresult
 //                 } else {
 //                     (*data).set.ssl.certverifyresult
 //                 }) == SSL_ERROR_BAD_CERT_DOMAIN as i32 as i64
 //                 {
 //                     result = CURLE_PEER_FAILED_VERIFICATION;
 //                 } else if (if CURLPROXY_HTTPS as i32 as u32
 //                     == (*conn).http_proxy.proxytype as u32
 //                     && ssl_connection_complete as i32 as u32
 //                         != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                             == -(1 as i32)
 //                         {
 //                             0 as i32
 //                         } else {
 //                             1 as i32
 //                         }) as usize]
 //                             .state as u32
 //                 {
 //                     (*data).set.proxy_ssl.certverifyresult
 //                 } else {
 //                     (*data).set.ssl.certverifyresult
 //                 }) != 0 as i32 as i64
 //                 {
 //                     result = CURLE_PEER_FAILED_VERIFICATION;
 //                 }
 //             }
 //         } else {
 //             result = display_conn_info(data, (*backend).handle);
 //             if !(result as u64 != 0) {
 //                 if !if CURLPROXY_HTTPS as i32 as u32
 //                     == (*conn).http_proxy.proxytype as u32
 //                     && ssl_connection_complete as i32 as u32
 //                         != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                             == -(1 as i32)
 //                         {
 //                             0 as i32
 //                         } else {
 //                             1 as i32
 //                         }) as usize]
 //                             .state as u32
 //                 {
 //                     (*conn).proxy_ssl_config.issuercert
 //                 } else {
 //                     (*conn).ssl_config.issuercert
 //                 }
 //                 .is_null()
 //                 {
 //                     let mut ret: SECStatus = SECFailure;
 //                     let mut nickname: *mut libc::c_char = dup_nickname(
 //                         data,
 //                         if CURLPROXY_HTTPS as i32 as u32
 //                             == (*conn).http_proxy.proxytype as u32
 //                             && ssl_connection_complete as i32 as u32
 //                                 != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                     == -(1 as i32)
 //                                 {
 //                                     0 as i32
 //                                 } else {
 //                                     1 as i32
 //                                 }) as usize]
 //                                     .state as u32
 //                         {
 //                             (*conn).proxy_ssl_config.issuercert
 //                         } else {
 //                             (*conn).ssl_config.issuercert
 //                         },
 //                     );
 //                     if !nickname.is_null() {
 //                         ret = check_issuer_cert((*backend).handle, nickname);
 //                         Curl_cfree.expect("non-null function pointer")(
 //                             nickname as *mut libc::c_void,
 //                         );
 //                     }
 //                     if SECFailure as i32 == ret as i32 {
 //                         Curl_infof(
 //                             data,
 //                             b"SSL certificate issuer check failed\0" as *const u8
 //                                 as *const libc::c_char,
 //                         );
 //                         result = CURLE_SSL_ISSUER_ERROR;
 //                         current_block = 8268984542875525005;
 //                     } else {
 //                         Curl_infof(
 //                             data,
 //                             b"SSL certificate issuer check ok\0" as *const u8
 //                                 as *const libc::c_char,
 //                         );
 //                         current_block = 15925075030174552612;
 //                     }
 //                 } else {
 //                     current_block = 15925075030174552612;
 //                 }
 //                 match current_block {
 //                     8268984542875525005 => {}
 //                     _ => {
 //                         result = cmp_peer_pubkey(
 //                             connssl,
 //                             if CURLPROXY_HTTPS as i32 as u32
 //                                 == (*conn).http_proxy.proxytype as u32
 //                                 && ssl_connection_complete as i32 as u32
 //                                     != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize]
 //                                         == -(1 as i32)
 //                                     {
 //                                         0 as i32
 //                                     } else {
 //                                         1 as i32
 //                                     })
 //                                         as usize]
 //                                         .state
 //                                         as u32
 //                             {
 //                                 (*data).set.str_0
 //                                     [STRING_SSL_PINNEDPUBLICKEY_PROXY as i32 as usize]
 //                             } else {
 //                                 (*data).set.str_0
 //                                     [STRING_SSL_PINNEDPUBLICKEY as i32 as usize]
 //                             },
 //                         );
 //                         if !(result as u64 != 0) {
 //                             return CURLE_OK;
 //                         }
 //                     }
 //                 }
 //             }
 //         }
 //     }
 //     return nss_fail_connect(connssl, data, result);
 // }
 extern "C" fn nss_do_connect(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) -> CURLcode {
     unsafe{
         let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
         .as_mut_ptr()
         .offset(sockindex as isize) as *mut ssl_connect_data;
     let mut backend: *mut ssl_backend_data = (*connssl).backend;
     let mut result: CURLcode = CURLE_SSL_CONNECT_ERROR;
     let mut timeout: PRUint32 = 0;
     let time_left: timediff_t = Curl_timeleft(
         data,
         0 as *mut curltime,
         1 as i32 != 0,
     );
     'error: loop {
         if time_left < 0 as i64 {
             Curl_failf(
                 data,
                 b"timed out before SSL handshake\0" as *const u8 as *const libc::c_char,
             );
             result = CURLE_OPERATION_TIMEDOUT;
             break 'error;
         }
         timeout = PR_MillisecondsToInterval(time_left as PRUint32);
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_SET_OPTION_certverifyresult = if CURLPROXY_HTTPS as u32
                                                 == (*conn).http_proxy.proxytype as u32
                                                 && ssl_connection_complete as u32
                                                     != (*conn)
                                                         .proxy_ssl[(if (*conn).sock[1 as usize]
                                                             == -(1 as i32)
                                                         {
                                                             0 as i32
                                                         } else {
                                                             1 as i32
                                                         }) as usize]
                                                         .state as u32
                                             {
                                                 (*data).set.proxy_ssl.certverifyresult
                                             } else {
                                                 (*data).set.ssl.certverifyresult
                                             };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_SET_OPTION_certverifyresult = (*data).set.ssl.certverifyresult;
         if SSL_ForceHandshakeWithTimeout((*backend).nss_handle, timeout) as i32
             != SECSuccess as i32
         {
             if PR_GetError() as i64 == -(5998 as i64) {
                 return CURLE_AGAIN
             } else {
                 if SSL_SET_OPTION_certverifyresult == SSL_ERROR_BAD_CERT_DOMAIN as i64
                 {
                     result = CURLE_PEER_FAILED_VERIFICATION;
                 } else if SSL_SET_OPTION_certverifyresult != 0 as i64
                     {
                     result = CURLE_PEER_FAILED_VERIFICATION;
                 }
             }
             break 'error;
         }
         result = display_conn_info(data, (*backend).nss_handle);
         if result as u64 != 0 {
             break 'error;
         }
 
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_CONN_CONFIG_issuercert = if CURLPROXY_HTTPS as u32
                                             == (*conn).http_proxy.proxytype as u32
                                             && ssl_connection_complete as u32
                                                 != (*conn)
                                                     .proxy_ssl[(if (*conn).sock[1 as usize]
                                                         == -(1 as i32)
                                                     {
                                                         0 as i32
                                                     } else {
                                                         1 as i32
                                                     }) as usize]
                                                     .state as u32
                                         {
                                             (*conn).proxy_ssl_config.issuercert
                                         } else {
                                             (*conn).ssl_config.issuercert
                                         };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_CONN_CONFIG_issuercert = (*conn).ssl_config.issuercert;
         if !SSL_CONN_CONFIG_issuercert.is_null()
         {
             let mut ret: SECStatus = SECFailure;
             let mut nickname: *mut libc::c_char = dup_nickname(
                 data,
                 SSL_CONN_CONFIG_issuercert,
             );
             if !nickname.is_null() {
                 ret = check_issuer_cert((*backend).nss_handle, nickname);
                 Curl_cfree
                     .expect("non-null function pointer")(nickname as *mut libc::c_void);
             }
             if SECFailure as i32 == ret as i32 {
                 Curl_infof(
                     data,
                     b"SSL certificate issuer check failed\0" as *const u8
                         as *const libc::c_char,
                 );
                 result = CURLE_SSL_ISSUER_ERROR;
                 break 'error;
             } else {
                 Curl_infof(
                     data,
                     b"SSL certificate issuer check ok\0" as *const u8 as *const libc::c_char,
                 );
             }
         }
         #[cfg(not(CURL_DISABLE_PROXY))]
         let SSL_PINNED_PUB_KEY_void = if CURLPROXY_HTTPS as u32
                                         == (*conn).http_proxy.proxytype as u32
                                         && ssl_connection_complete as u32
                                             != (*conn)
                                                 .proxy_ssl[(if (*conn).sock[1 as usize]
                                                     == -(1 as i32)
                                                 {
                                                     0 as i32
                                                 } else {
                                                     1 as i32
                                                 }) as usize]
                                                 .state as u32
                                     {
                                         (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY_PROXY as usize]
                                     } else {
                                         (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as usize]
                                     };
         #[cfg(CURL_DISABLE_PROXY)]
         let SSL_PINNED_PUB_KEY_void = (*data)
                                         .set
                                         .str_0[STRING_SSL_PINNEDPUBLICKEY as usize];
         result = cmp_peer_pubkey(
             connssl,
             SSL_PINNED_PUB_KEY_void,
         );
         if result as u64 != 0 {
             break 'error;
         }
         return CURLE_OK;
     }
     return nss_fail_connect(connssl, data, result);
     }
 }
 extern "C" fn nss_connect_common(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
     mut done: *mut bool,
 ) -> CURLcode {
     unsafe{
         let mut connssl: *mut ssl_connect_data =
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
     let blocking: bool = done.is_null();
     let mut result: CURLcode = CURLE_OK;
     if (*connssl).state as u32 == ssl_connection_complete as u32 {
         if !blocking {
             *done = 1 as i32 != 0;
         }
         return CURLE_OK;
     }
     /* ssl_connect_done is never used outside, go back to the initial state */
     if (*connssl).connecting_state as u32 == ssl_connect_1 as u32 {
         result = nss_setup_connect(data, conn, sockindex);
         if result as u64 != 0 {
             return result;
         }
         (*connssl).connecting_state = ssl_connect_2;
     }
     result = nss_set_blocking(connssl, data, blocking);
     if result as u64 != 0 {
         return result;
     }
     result = nss_do_connect(data, conn, sockindex);
     's_96: {
         match result as u32 {
             0 => {
                 break 's_96;
             }
             81 => {
                 if !blocking {
                     return CURLE_OK;
                 }
             }
             _ => {}
         }
         return result;
     }
     if blocking {
         result = nss_set_blocking(connssl, data, 0 as i32 != 0);
         if result as u64 != 0 {
             return result;
         }
     } else {
         *done = 1 as i32 != 0;
     }
     (*connssl).state = ssl_connection_complete;
     (*conn).recv[sockindex as usize] = Some(nss_recv as Curl_recv);
     (*conn).send[sockindex as usize] = Some(nss_send as Curl_send);
     (*connssl).connecting_state = ssl_connect_1;
     return CURLE_OK;
     }
 }
 extern "C" fn nss_connect(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
 ) -> CURLcode {
     unsafe{
         return nss_connect_common(data, conn, sockindex, 0 as *mut bool);
     }
 }
 extern "C" fn nss_connect_nonblocking(
     mut data: *mut Curl_easy,
     mut conn: *mut connectdata,
     mut sockindex: i32,
     mut done: *mut bool,
 ) -> CURLcode {
     unsafe{
         return nss_connect_common(data, conn, sockindex, done);
     }
 }
 
 extern "C" fn nss_send(
     mut data: *mut Curl_easy,
     mut sockindex: i32,
     mut mem: *const libc::c_void,
     mut len: size_t,
     mut curlcode: *mut CURLcode,
 ) -> ssize_t {
     unsafe{
         let mut conn: *mut connectdata = (*data).conn;
     let mut connssl: *mut ssl_connect_data =
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
     let mut backend: *mut ssl_backend_data = (*connssl).backend;
     let mut rc: ssize_t = 0;
     (*backend).data = data;
     rc = PR_Send(
         (*backend).nss_handle,
         mem,
         len as i32,
         0 as i32,
         0 as PRIntervalTime,
     ) as ssize_t;/* The SelectClientCert() hook uses this for infof() and failf() but the
     handle stored in nss_setup_connect() could have already been freed. */
     if rc < 0 as i64 {
         let mut err: PRInt32 = PR_GetError();
         if err as i64 == -(5998 as i64) {
             *curlcode = CURLE_AGAIN;
         } else {
             /* print the error number and error string */
             let mut err_name: *const libc::c_char = nss_error_to_name(err);
             Curl_infof(
                 data,
                 b"SSL write: error %d (%s)\0" as *const u8 as *const libc::c_char,
                 err,
                 err_name,
             );/* print a human-readable message describing the error if available */
             nss_print_error_message(data, err as PRUint32);
             *curlcode = (if is_cc_error(err) as i32 != 0 {
                 CURLE_SSL_CERTPROBLEM as i32
             } else {
                 CURLE_SEND_ERROR as i32
             }) as CURLcode;
         }
         return -(1 as i32) as ssize_t;
     }
     return rc;/* number of bytes */
     }
 }
 extern "C" fn nss_recv(
     mut data: *mut Curl_easy, /* transfer */
     mut sockindex: i32,/* socketindex */
     mut buf: *mut libc::c_char, /* store read data here */
     mut buffersize: size_t, /* max amount to read */
     mut curlcode: *mut CURLcode,
 ) -> ssize_t {
     unsafe{
         let mut conn: *mut connectdata = (*data).conn;
     let mut connssl: *mut ssl_connect_data =
         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
     let mut backend: *mut ssl_backend_data = (*connssl).backend;
     let mut nread: ssize_t = 0;
     (*backend).data = data;
     /* The SelectClientCert() hook uses this for infof() and failf() but the
      handle stored in nss_setup_connect() could have already been freed. */
     nread = PR_Recv(
         (*backend).nss_handle,
         buf as *mut libc::c_void,
         buffersize as i32,
         0 as i32,
         0 as PRIntervalTime,
     ) as ssize_t;
     if nread < 0 as i64 {
         /* failed SSL read */
         let mut err: PRInt32 = PR_GetError();
         if err as i64 == -(5998 as i64) {
             *curlcode = CURLE_AGAIN;
         } else {
             /* print the error number and error string */
             let mut err_name: *const libc::c_char = nss_error_to_name(err);
             Curl_infof(
                 data,
                 b"SSL read: errno %d (%s)\0" as *const u8 as *const libc::c_char,
                 err,
                 err_name,
             );
             /* print a human-readable message describing the error if available */
             nss_print_error_message(data, err as PRUint32);
             *curlcode = (if is_cc_error(err) as i32 != 0 {
                 CURLE_SSL_CERTPROBLEM as i32
             } else {
                 CURLE_RECV_ERROR as i32
             }) as CURLcode;
         }
         return -(1 as i32) as ssize_t;
     }
     return nread;
     }
 }
 extern "C" fn nss_version(mut buffer: *mut libc::c_char, mut size: size_t) -> size_t {
     unsafe{
         return curl_msnprintf(
             buffer,
             size,
             b"NSS/%s\0" as *const u8 as *const libc::c_char,
             NSS_GetVersion(),
         ) as size_t;
     }
 }
 
 /* data might be NULL */
 extern "C" fn Curl_nss_seed(mut data: *mut Curl_easy) -> i32 {
     unsafe{
         /* make sure that NSS is initialized */
         return (Curl_nss_force_init(data) as u64 != 0) as i32;
     }
 }
 
 /* data might be NULL */
 extern "C" fn nss_random(
     mut data: *mut Curl_easy,
     mut entropy: *mut u8,
     mut length: size_t,
 ) -> CURLcode {
     unsafe{
         Curl_nss_seed(data);/* Initiate the seed if not already done */
 
         if SECSuccess as i32
             != PK11_GenerateRandom(entropy, curlx_uztosi(length)) as i32
         {
             /* signal a failure */
             return CURLE_FAILED_INIT;
         }
         return CURLE_OK;
     }
 }
 extern "C" fn nss_sha256sum(
     mut tmp: *const u8,  /* input */
     mut tmplen: size_t,
     mut sha256sum: *mut u8,/* output */
     mut sha256len: size_t,
 ) -> CURLcode {
     unsafe{
         let mut SHA256pw: *mut PK11Context = PK11_CreateDigestContext(SEC_OID_SHA256);
     let mut SHA256out: u32 = 0;
     if SHA256pw.is_null() {
         return CURLE_NOT_BUILT_IN;
     }
     PK11_DigestOp(SHA256pw, tmp, curlx_uztoui(tmplen));
     PK11_DigestFinal(SHA256pw, sha256sum, &mut SHA256out, curlx_uztoui(sha256len));
     PK11_DestroyContext(SHA256pw, 1 as i32);
     return CURLE_OK;
     }
 }
 extern "C" fn nss_cert_status_request() -> bool {
     unsafe{
         #[cfg(SSL_ENABLE_OCSP_STAPLING)]
     return 1 as i32 != 0;
     #[cfg(not(SSL_ENABLE_OCSP_STAPLING))]
     return 0 as i32 != 0;
     }
 }
 extern "C" fn nss_false_start() -> bool {
     unsafe{
          // #[cfg(NSSVERNUM >= 0x030f04)]
     return 1 as i32 != 0;/* 3.15.4 */
     }
 }
 extern "C" fn nss_get_internals(
     mut connssl: *mut ssl_connect_data,
     mut info: CURLINFO,
 ) -> *mut libc::c_void {
     unsafe{
         let mut backend: *mut ssl_backend_data = (*connssl).backend;
     return (*backend).nss_handle as *mut libc::c_void;
     }
 }
 #[no_mangle]
 pub static mut Curl_ssl_nss: Curl_ssl =  {
     {
         let mut init = Curl_ssl {
             info: {
                 let mut init = curl_ssl_backend {
                     id: CURLSSLBACKEND_NSS,
                     name: b"nss\0" as *const u8 as *const libc::c_char,
                 };
                 init
             },
             supports: ((1 as i32) << 0 as i32
                 | (1 as i32) << 1 as i32
                 | (1 as i32) << 2 as i32
                 | (1 as i32) << 4 as i32) as u32,
             sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>() as u64,
             init: Some(nss_init as unsafe extern "C" fn() -> i32),
             cleanup: Some(nss_cleanup as unsafe extern "C" fn() -> ()),
             version: Some(nss_version as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t),
             check_cxn: Some(nss_check_cxn as unsafe extern "C" fn(*mut connectdata) -> i32),
             shut_down: Some(
                 Curl_none_shutdown
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         i32,
                     ) -> i32,
             ),
             data_pending: Some(
                 Curl_none_data_pending
                     as unsafe extern "C" fn(*const connectdata, i32) -> bool,
             ),
             random: Some(
                 nss_random
                     as unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode,
             ),
             cert_status_request: Some(nss_cert_status_request as unsafe extern "C" fn() -> bool),
             connect_blocking: Some(
                 nss_connect
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         i32,
                     ) -> CURLcode,
             ),
             connect_nonblocking: Some(
                 nss_connect_nonblocking
                     as unsafe extern "C" fn(
                         *mut Curl_easy,
                         *mut connectdata,
                         i32,
                         *mut bool,
                     ) -> CURLcode,
             ),
             getsock: Some(
                 Curl_ssl_getsock
                     as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32,
             ),
             get_internals: Some(
                 nss_get_internals
                     as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
             ),
             close_one: Some(
                 nss_close
                     as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
             ),
             close_all: Some(Curl_none_close_all as unsafe extern "C" fn(*mut Curl_easy) -> ()),
             session_free: Some(
                 Curl_none_session_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
             ),
             set_engine: Some(
                 Curl_none_set_engine
                     as unsafe extern "C" fn(*mut Curl_easy, *const libc::c_char) -> CURLcode,
             ),
             set_engine_default: Some(
                 Curl_none_set_engine_default as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
             ),
             engines_list: Some(
                 Curl_none_engines_list as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
             ),
             false_start: Some(nss_false_start as unsafe extern "C" fn() -> bool),
             sha256sum: Some(
                 nss_sha256sum
                     as unsafe extern "C" fn(
                         *const u8,
                         size_t,
                         *mut u8,
                         size_t,
                     ) -> CURLcode,
             ),
             associate_connection: None,
             disassociate_connection: None,
         };
         init
     }
 };
 