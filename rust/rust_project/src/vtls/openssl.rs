use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
use crate::src::vtls::vtls::*;
use crate::src::vtls::keylog::*;

#[inline]
unsafe extern "C" fn sk_X509_pop(mut sk: *mut stack_st_X509) -> *mut X509 {
    return OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_pop_free(
    mut sk: *mut stack_st_X509,
    mut freefunc: sk_X509_freefunc,
) {
    OPENSSL_sk_pop_free(
        sk as *mut OPENSSL_STACK,
        ::std::mem::transmute::<sk_X509_freefunc, OPENSSL_sk_freefunc>(freefunc),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_num(mut sk: *const stack_st_X509_INFO) -> libc::c_int {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_value(
    mut sk: *const stack_st_X509_INFO,
    mut idx: libc::c_int,
) -> *mut X509_INFO {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) as *mut X509_INFO;
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_pop_free(
    mut sk: *mut stack_st_X509_INFO,
    mut freefunc: sk_X509_INFO_freefunc,
) {
    OPENSSL_sk_pop_free(
        sk as *mut OPENSSL_STACK,
        ::std::mem::transmute::<sk_X509_INFO_freefunc, OPENSSL_sk_freefunc>(freefunc),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_num(
    mut sk: *const stack_st_X509_EXTENSION,
) -> libc::c_int {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_value(
    mut sk: *const stack_st_X509_EXTENSION,
    mut idx: libc::c_int,
) -> *mut X509_EXTENSION {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) as *mut X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_num(mut sk: *const stack_st_X509) -> libc::c_int {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_value(
    mut sk: *const stack_st_X509,
    mut idx: libc::c_int,
) -> *mut X509 {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_num(
    mut sk: *const stack_st_GENERAL_NAME,
) -> libc::c_int {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_value(
    mut sk: *const stack_st_GENERAL_NAME,
    mut idx: libc::c_int,
) -> *mut GENERAL_NAME {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) as *mut GENERAL_NAME;
}
#[cfg(HAVE_KEYLOG_CALLBACK)]
unsafe extern "C" fn ossl_keylog_callback(
    mut ssl: *const SSL,
    mut line: *const libc::c_char,
) {
    Curl_tls_keylog_write_line(line);
}
// TODO - 255 - 关闭 HAVE_KEYLOG_CALLBACK选项，在翻译一次
// #[cfg(not(HAVE_KEYLOG_CALLBACK))]

unsafe extern "C" fn SSL_ERROR_to_str(mut err: libc::c_int) -> *const libc::c_char {
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

unsafe extern "C" fn ossl_strerror(
    mut error: libc::c_ulong,
    mut buf: *mut libc::c_char,
    mut size: size_t,
) -> *mut libc::c_char {
    if size != 0 {
        *buf = '\0' as i32 as libc::c_char;
    }
    // TODO - 351
    // #[cfg(OPENSSL_IS_BORINGSSL)]
    #[cfg(not(OPENSSL_IS_BORINGSSL))]
    ERR_error_string_n(error, buf, size);
    if size > 1 as libc::c_int as libc::c_ulong && *buf == 0 {
        strncpy(
            buf,
            if error != 0 {
                b"Unknown error\0" as *const u8 as *const libc::c_char
            } else {
                b"No error\0" as *const u8 as *const libc::c_char
            },
            size,
        );
        *buf
            .offset(
                size.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            ) = '\0' as i32 as libc::c_char;
    }
    return buf;
}
unsafe extern "C" fn ossl_get_ssl_data_index() -> libc::c_int {
    static mut ssl_ex_data_data_index: libc::c_int = -(1 as libc::c_int);
    if ssl_ex_data_data_index < 0 as libc::c_int {
        ssl_ex_data_data_index = CRYPTO_get_ex_new_index(
            0 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            0 as *mut libc::c_void,
            None,
            None,
            None,
        );
    }
    return ssl_ex_data_data_index;
}
unsafe extern "C" fn ossl_get_ssl_conn_index() -> libc::c_int {
    static mut ssl_ex_data_conn_index: libc::c_int = -(1 as libc::c_int);
    if ssl_ex_data_conn_index < 0 as libc::c_int {
        ssl_ex_data_conn_index = CRYPTO_get_ex_new_index(
            0 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            0 as *mut libc::c_void,
            None,
            None,
            None,
        );
    }
    return ssl_ex_data_conn_index;
}
unsafe extern "C" fn ossl_get_ssl_sockindex_index() -> libc::c_int {
    static mut sockindex_index: libc::c_int = -(1 as libc::c_int);
    if sockindex_index < 0 as libc::c_int {
        sockindex_index = CRYPTO_get_ex_new_index(
            0 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            0 as *mut libc::c_void,
            None,
            None,
            None,
        );
    }
    return sockindex_index;
}
unsafe extern "C" fn ossl_get_proxy_index() -> libc::c_int {
    static mut proxy_index: libc::c_int = -(1 as libc::c_int);
    if proxy_index < 0 as libc::c_int {
        proxy_index = CRYPTO_get_ex_new_index(
            0 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            0 as *mut libc::c_void,
            None,
            None,
            None,
        );
    }
    return proxy_index;
}
unsafe extern "C" fn passwd_callback(
    mut buf: *mut libc::c_char,
    mut num: libc::c_int,
    mut encrypting: libc::c_int,
    mut global_passwd: *mut libc::c_void,
) -> libc::c_int {
    if encrypting == 0 {
        let mut klen: libc::c_int = curlx_uztosi(
            strlen(global_passwd as *mut libc::c_char),
        );
        if num > klen {
            memcpy(
                buf as *mut libc::c_void,
                global_passwd,
                (klen + 1 as libc::c_int) as libc::c_ulong,
            );
            return klen;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn rand_enough() -> bool {
    return if 0 as libc::c_int != RAND_status() {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    } != 0;
}
unsafe extern "C" fn ossl_seed(mut data: *mut Curl_easy) -> CURLcode {
    let mut fname: [libc::c_char; 256] = [0; 256];
    if !((*data).multi).is_null() && (*(*data).multi).ssl_seeded as libc::c_int != 0 {
        return CURLE_OK;
    }
    if rand_enough() {
        if !((*data).multi).is_null() {
            (*(*data).multi).ssl_seeded = 1 as libc::c_int != 0;
        }
        return CURLE_OK;
    }
    // TODO - 451 - 选项 RANDOM_FILE
    RAND_load_file(
        if !((*data).set.str_0[STRING_SSL_RANDOM_FILE as libc::c_int as usize]).is_null()
        {
            (*data).set.str_0[STRING_SSL_RANDOM_FILE as libc::c_int as usize]
                as *const libc::c_char
        } else {
            b"/dev/urandom\0" as *const u8 as *const libc::c_char
        },
        1024 as libc::c_int as libc::c_long,
    );
    if rand_enough() {
        return CURLE_OK;
    }
    // TODO - 467 有一段if的条件编译
    // #[cfg(HAVE_RAND_EGD)]
    loop {
        let mut randb: [libc::c_uchar; 64] = [0; 64];
        let mut len: size_t = ::std::mem::size_of::<[libc::c_uchar; 64]>()
            as libc::c_ulong;
        let mut i: size_t = 0;
        let mut i_max: size_t = 0;
        i = 0 as libc::c_int as size_t;
        i_max = len.wrapping_div(::std::mem::size_of::<curltime>() as libc::c_ulong);
        while i < i_max {
            let mut tv: curltime = Curl_now();
            Curl_wait_ms(1 as libc::c_int as timediff_t);
            tv
                .tv_sec = (tv.tv_sec as libc::c_ulong)
                .wrapping_mul(i.wrapping_add(1 as libc::c_int as libc::c_ulong))
                as time_t as time_t;
            tv
                .tv_usec = (tv.tv_usec as libc::c_uint)
                .wrapping_mul(
                    (i as libc::c_uint).wrapping_add(2 as libc::c_int as libc::c_uint),
                ) as libc::c_int as libc::c_int;
            tv
                .tv_sec = (tv.tv_sec as libc::c_ulong
                ^ (((Curl_now()).tv_sec + (Curl_now()).tv_usec as libc::c_long)
                    as libc::c_ulong)
                    .wrapping_mul(i.wrapping_add(3 as libc::c_int as libc::c_ulong))
                    << 8 as libc::c_int) as time_t;
            tv
                .tv_usec = (tv.tv_usec as libc::c_uint
                ^ ((((Curl_now()).tv_sec + (Curl_now()).tv_usec as libc::c_long)
                    as libc::c_ulong)
                    .wrapping_mul(i.wrapping_add(4 as libc::c_int as libc::c_ulong))
                    as libc::c_uint) << 16 as libc::c_int) as libc::c_int;
            memcpy(
                &mut *randb
                    .as_mut_ptr()
                    .offset(
                        i
                            .wrapping_mul(
                                ::std::mem::size_of::<curltime>() as libc::c_ulong,
                            ) as isize,
                    ) as *mut libc::c_uchar as *mut libc::c_void,
                &mut tv as *mut curltime as *const libc::c_void,
                ::std::mem::size_of::<curltime>() as libc::c_ulong,
            );
            i = i.wrapping_add(1);
        }
        RAND_add(
            randb.as_mut_ptr() as *const libc::c_void,
            len as libc::c_int,
            len as libc::c_double / 2 as libc::c_int as libc::c_double,
        );
        if rand_enough() {
            break;
        }
    }
    fname[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
    RAND_file_name(
        fname.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
    );
    if fname[0 as libc::c_int as usize] != 0 {
        RAND_load_file(fname.as_mut_ptr(), 1024 as libc::c_int as libc::c_long);
        if rand_enough() {
            return CURLE_OK;
        }
    }
    Curl_infof(
        data,
        b"libcurl is now using a weak random seed!\0" as *const u8 as *const libc::c_char,
    );
    return (if rand_enough() as libc::c_int != 0 {
        CURLE_OK as libc::c_int
    } else {
        CURLE_SSL_CONNECT_ERROR as libc::c_int
    }) as CURLcode;
}
unsafe extern "C" fn do_file_type(mut type_0: *const libc::c_char) -> libc::c_int {
    if type_0.is_null() || *type_0.offset(0 as libc::c_int as isize) == 0 {
        return 1 as libc::c_int;
    }
    if Curl_strcasecompare(type_0, b"PEM\0" as *const u8 as *const libc::c_char) != 0 {
        return 1 as libc::c_int;
    }
    if Curl_strcasecompare(type_0, b"DER\0" as *const u8 as *const libc::c_char) != 0 {
        return 2 as libc::c_int;
    }
    if Curl_strcasecompare(type_0, b"ENG\0" as *const u8 as *const libc::c_char) != 0 {
        return 42 as libc::c_int;
    }
    if Curl_strcasecompare(type_0, b"P12\0" as *const u8 as *const libc::c_char) != 0 {
        return 43 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
#[cfg(USE_OPENSSL_ENGINE)] 
unsafe extern "C" fn ssl_ui_reader(
    mut ui: *mut UI,
    mut uis: *mut UI_STRING,
) -> libc::c_int {
    let mut password: *const libc::c_char = 0 as *const libc::c_char;
    match UI_get_string_type(uis) as libc::c_uint {
        1 | 2 => {
            password = UI_get0_user_data(ui) as *const libc::c_char;
            if !password.is_null() && UI_get_input_flags(uis) & 0x2 as libc::c_int != 0 {
                UI_set_result(ui, uis, password);
                return 1 as libc::c_int;
            }
        }
        _ => {}
    }
    return (UI_method_get_reader(UI_OpenSSL()))
        .expect("non-null function pointer")(ui, uis);
}
#[cfg(USE_OPENSSL_ENGINE)]
unsafe extern "C" fn ssl_ui_writer(
    mut ui: *mut UI,
    mut uis: *mut UI_STRING,
) -> libc::c_int {
    match UI_get_string_type(uis) as libc::c_uint {
        1 | 2 => {
            if !(UI_get0_user_data(ui)).is_null()
                && UI_get_input_flags(uis) & 0x2 as libc::c_int != 0
            {
                return 1 as libc::c_int;
            }
        }
        _ => {}
    }
    return (UI_method_get_writer(UI_OpenSSL()))
        .expect("non-null function pointer")(ui, uis);
}
#[cfg(USE_OPENSSL_ENGINE)]
unsafe extern "C" fn is_pkcs11_uri(mut string: *const libc::c_char) -> bool {
    return !string.is_null()
        && Curl_strncasecompare(
            string,
            b"pkcs11:\0" as *const u8 as *const libc::c_char,
            7 as libc::c_int as size_t,
        ) != 0;
}
unsafe extern "C" fn SSL_CTX_use_certificate_blob(
    mut ctx: *mut SSL_CTX,
    mut blob: *const curl_blob,
    mut type_0: libc::c_int,
    mut key_passwd: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut x: *mut X509 = 0 as *mut X509;
    let mut in_0: *mut BIO = BIO_new_mem_buf((*blob).data, (*blob).len as libc::c_int);
    if in_0.is_null() {
        return CURLE_OUT_OF_MEMORY as libc::c_int;
    }
    if type_0 == 2 as libc::c_int {
        x = d2i_X509_bio(in_0, 0 as *mut *mut X509);
        current_block = 1917311967535052937;
    } else if type_0 == 1 as libc::c_int {
        x = PEM_read_bio_X509(
            in_0,
            0 as *mut *mut X509,
            Some(
                passwd_callback
                    as unsafe extern "C" fn(
                        *mut libc::c_char,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            key_passwd as *mut libc::c_void,
        );
        current_block = 1917311967535052937;
    } else {
        ret = 0 as libc::c_int;
        current_block = 7485986817425170615;
    }
    match current_block {
        1917311967535052937 => {
            if x.is_null() {
                ret = 0 as libc::c_int;
            } else {
                ret = SSL_CTX_use_certificate(ctx, x);
            }
        }
        _ => {}
    }
    X509_free(x);
    BIO_free(in_0);
    return ret;
}
unsafe extern "C" fn SSL_CTX_use_PrivateKey_blob(
    mut ctx: *mut SSL_CTX,
    mut blob: *const curl_blob,
    mut type_0: libc::c_int,
    mut key_passwd: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut in_0: *mut BIO = BIO_new_mem_buf((*blob).data, (*blob).len as libc::c_int);
    if in_0.is_null() {
        return CURLE_OUT_OF_MEMORY as libc::c_int;
    }
    if type_0 == 1 as libc::c_int {
        pkey = PEM_read_bio_PrivateKey(
            in_0,
            0 as *mut *mut EVP_PKEY,
            Some(
                passwd_callback
                    as unsafe extern "C" fn(
                        *mut libc::c_char,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            key_passwd as *mut libc::c_void,
        );
        current_block = 14523784380283086299;
    } else if type_0 == 2 as libc::c_int {
        pkey = d2i_PrivateKey_bio(in_0, 0 as *mut *mut EVP_PKEY);
        current_block = 14523784380283086299;
    } else {
        ret = 0 as libc::c_int;
        current_block = 12770555312395776852;
    }
    match current_block {
        14523784380283086299 => {
            if pkey.is_null() {
                ret = 0 as libc::c_int;
            } else {
                ret = SSL_CTX_use_PrivateKey(ctx, pkey);
                EVP_PKEY_free(pkey);
            }
        }
        _ => {}
    }
    BIO_free(in_0);
    return ret;
}
unsafe extern "C" fn SSL_CTX_use_certificate_chain_blob(
    mut ctx: *mut SSL_CTX,
    mut blob: *const curl_blob,
    mut key_passwd: *const libc::c_char,
) -> libc::c_int {
    // TODO - 672 与OPENSSL_VERSION_NUMBER有关的条件编译
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut x: *mut X509 = 0 as *mut X509;
    let mut passwd_callback_userdata: *mut libc::c_void = key_passwd
        as *mut libc::c_void;
    let mut in_0: *mut BIO = BIO_new_mem_buf((*blob).data, (*blob).len as libc::c_int);
    if in_0.is_null() {
        return CURLE_OUT_OF_MEMORY as libc::c_int;
    }
    ERR_clear_error();
    x = PEM_read_bio_X509_AUX(
        in_0,
        0 as *mut *mut X509,
        Some(
            passwd_callback
                as unsafe extern "C" fn(
                    *mut libc::c_char,
                    libc::c_int,
                    libc::c_int,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        key_passwd as *mut libc::c_void,
    );
    if x.is_null() {
        ret = 0 as libc::c_int;
    } else {
        ret = SSL_CTX_use_certificate(ctx, x);
        if ERR_peek_error() != 0 as libc::c_int as libc::c_ulong {
            ret = 0 as libc::c_int;
        }
        if ret != 0 {
            let mut ca: *mut X509 = 0 as *mut X509;
            let mut err: libc::c_ulong = 0;
            if SSL_CTX_ctrl(
                ctx,
                88 as libc::c_int,
                0 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void as *mut libc::c_char as *mut libc::c_void,
            ) == 0
            {
                ret = 0 as libc::c_int;
            } else {
                loop {
                    ca = PEM_read_bio_X509(
                        in_0,
                        0 as *mut *mut X509,
                        Some(
                            passwd_callback
                                as unsafe extern "C" fn(
                                    *mut libc::c_char,
                                    libc::c_int,
                                    libc::c_int,
                                    *mut libc::c_void,
                                ) -> libc::c_int,
                        ),
                        passwd_callback_userdata,
                    );
                    if ca.is_null() {
                        current_block = 26972500619410423;
                        break;
                    }
                    if !(SSL_CTX_ctrl(
                        ctx,
                        89 as libc::c_int,
                        0 as libc::c_int as libc::c_long,
                        ca as *mut libc::c_char as *mut libc::c_void,
                    ) == 0)
                    {
                        continue;
                    }
                    X509_free(ca);
                    ret = 0 as libc::c_int;
                    current_block = 11304770531872933971;
                    break;
                }
                match current_block {
                    11304770531872933971 => {}
                    _ => {
                        err = ERR_peek_last_error();
                        if (err >> 24 as libc::c_long
                            & 0xff as libc::c_long as libc::c_ulong) as libc::c_int
                            == 9 as libc::c_int
                            && (err & 0xfff as libc::c_long as libc::c_ulong)
                                as libc::c_int == 108 as libc::c_int
                        {
                            ERR_clear_error();
                        } else {
                            ret = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    X509_free(x);
    BIO_free(in_0);
    return ret;
}
unsafe extern "C" fn cert_stuff(
    mut data: *mut Curl_easy,
    mut ctx: *mut SSL_CTX,
    mut cert_file: *mut libc::c_char,
    mut cert_blob: *const curl_blob,
    mut cert_type: *const libc::c_char,
    mut key_file: *mut libc::c_char,
    mut key_blob: *const curl_blob,
    mut key_type: *const libc::c_char,
    mut key_passwd: *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut error_buffer: [libc::c_char; 256] = [0; 256];
    let mut check_privkey: bool = 1 as libc::c_int != 0;
    let mut file_type: libc::c_int = do_file_type(cert_type);
    if !cert_file.is_null() || !cert_blob.is_null() || file_type == 42 as libc::c_int {
        let mut ssl: *mut SSL = 0 as *mut SSL;
        let mut x509: *mut X509 = 0 as *mut X509;
        let mut cert_done: libc::c_int = 0 as libc::c_int;
        let mut cert_use_result: libc::c_int = 0;
        if !key_passwd.is_null() {
            SSL_CTX_set_default_passwd_cb_userdata(ctx, key_passwd as *mut libc::c_void);
            SSL_CTX_set_default_passwd_cb(
                ctx,
                Some(
                    passwd_callback
                        as unsafe extern "C" fn(
                            *mut libc::c_char,
                            libc::c_int,
                            libc::c_int,
                            *mut libc::c_void,
                        ) -> libc::c_int,
                ),
            );
        }
        match file_type {
            1 => {
                cert_use_result = if !cert_blob.is_null() {
                    SSL_CTX_use_certificate_chain_blob(ctx, cert_blob, key_passwd)
                } else {
                    SSL_CTX_use_certificate_chain_file(ctx, cert_file)
                };
                if cert_use_result != 1 as libc::c_int {
                    Curl_failf(
                        data,
                        b"could not load PEM client certificate, OpenSSL error %s, (no key found, wrong pass phrase, or wrong file format?)\0"
                            as *const u8 as *const libc::c_char,
                        ossl_strerror(
                            ERR_get_error(),
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        ),
                    );
                    return 0 as libc::c_int;
                }
            }
            2 => {
                cert_use_result = if !cert_blob.is_null() {
                    SSL_CTX_use_certificate_blob(ctx, cert_blob, file_type, key_passwd)
                } else {
                    SSL_CTX_use_certificate_file(ctx, cert_file, file_type)
                };
                if cert_use_result != 1 as libc::c_int {
                    Curl_failf(
                        data,
                        b"could not load ASN1 client certificate, OpenSSL error %s, (no key found, wrong pass phrase, or wrong file format?)\0"
                            as *const u8 as *const libc::c_char,
                        ossl_strerror(
                            ERR_get_error(),
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        ),
                    );
                    return 0 as libc::c_int;
                }
            }
            // DONE - 804
            42 => {
                    #[cfg(all(USE_OPENSSL_ENGINE, ENGINE_CTRL_GET_CMD_FROM_NAME))]
                    if ((*data).state.engine).is_null() {
                        if is_pkcs11_uri(cert_file) {
                            if ossl_set_engine(
                                data,
                                b"pkcs11\0" as *const u8 as *const libc::c_char,
                            ) as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint
                            {
                                return 0 as libc::c_int;
                            }
                        }
                    }
                    #[cfg(all(USE_OPENSSL_ENGINE, ENGINE_CTRL_GET_CMD_FROM_NAME))]    
                    if !((*data).state.engine).is_null() {
                        let mut cmd_name: *const libc::c_char = b"LOAD_CERT_CTRL\0"
                            as *const u8 as *const libc::c_char;
                        let mut params: C2RustUnnamed_13 = C2RustUnnamed_13 {
                            cert_id: 0 as *const libc::c_char,
                            cert: 0 as *mut X509,
                        };
                        params.cert_id = cert_file;
                        params.cert = 0 as *mut X509;
                        if ENGINE_ctrl(
                            (*data).state.engine as *mut ENGINE,
                            13 as libc::c_int,
                            0 as libc::c_int as libc::c_long,
                            cmd_name as *mut libc::c_void,
                            None,
                        ) == 0
                        {
                            Curl_failf(
                                data,
                                b"ssl engine does not support loading certificates\0"
                                    as *const u8 as *const libc::c_char,
                            );
                            return 0 as libc::c_int;
                        }
                        if ENGINE_ctrl_cmd(
                            (*data).state.engine as *mut ENGINE,
                            cmd_name,
                            0 as libc::c_int as libc::c_long,
                            &mut params as *mut C2RustUnnamed_13 as *mut libc::c_void,
                            None,
                            1 as libc::c_int,
                        ) == 0
                        {
                            Curl_failf(
                                data,
                                b"ssl engine cannot load client cert with id '%s' [%s]\0"
                                    as *const u8 as *const libc::c_char,
                                cert_file,
                                ossl_strerror(
                                    ERR_get_error(),
                                    error_buffer.as_mut_ptr(),
                                    ::std::mem::size_of::<[libc::c_char; 256]>()
                                        as libc::c_ulong,
                                ),
                            );
                            return 0 as libc::c_int;
                        }
                        if (params.cert).is_null() {
                            Curl_failf(
                                data,
                                b"ssl engine didn't initialized the certificate properly.\0"
                                    as *const u8 as *const libc::c_char,
                            );
                            return 0 as libc::c_int;
                        }
                        if SSL_CTX_use_certificate(ctx, params.cert) != 1 as libc::c_int {
                            Curl_failf(
                                data,
                                b"unable to set client certificate\0" as *const u8
                                    as *const libc::c_char,
                            );
                            X509_free(params.cert);
                            return 0 as libc::c_int;
                        }
                        X509_free(params.cert);
                    } else {
                        Curl_failf(
                            data,
                            b"crypto engine not set, can't load certificate\0" as *const u8
                                as *const libc::c_char,
                        );
                        return 0 as libc::c_int;
                    }
                    #[cfg(any(not(USE_OPENSSL_ENGINE), not(ENGINE_CTRL_GET_CMD_FROM_NAME)))]
                    Curl_failf(
                        data,
                        b"file type ENG for certificate not implemented"
                            as *const u8 as *const libc::c_char,
                    );
                    #[cfg(any(not(USE_OPENSSL_ENGINE), not(ENGINE_CTRL_GET_CMD_FROM_NAME)))]
                    return 0 as libc::c_int;
                }        
            43 => {
                let mut cert_bio: *mut BIO = 0 as *mut BIO;
                let mut p12: *mut PKCS12 = 0 as *mut PKCS12;
                let mut pri: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
                let mut ca: *mut stack_st_X509 = 0 as *mut stack_st_X509;
                if !cert_blob.is_null() {
                    cert_bio = BIO_new_mem_buf(
                        (*cert_blob).data,
                        (*cert_blob).len as libc::c_int,
                    );
                    if cert_bio.is_null() {
                        Curl_failf(
                            data,
                            b"BIO_new_mem_buf NULL, OpenSSL error %s\0" as *const u8
                                as *const libc::c_char,
                            ossl_strerror(
                                ERR_get_error(),
                                error_buffer.as_mut_ptr(),
                                ::std::mem::size_of::<[libc::c_char; 256]>()
                                    as libc::c_ulong,
                            ),
                        );
                        return 0 as libc::c_int;
                    }
                } else {
                    cert_bio = BIO_new(BIO_s_file());
                    if cert_bio.is_null() {
                        Curl_failf(
                            data,
                            b"BIO_new return NULL, OpenSSL error %s\0" as *const u8
                                as *const libc::c_char,
                            ossl_strerror(
                                ERR_get_error(),
                                error_buffer.as_mut_ptr(),
                                ::std::mem::size_of::<[libc::c_char; 256]>()
                                    as libc::c_ulong,
                            ),
                        );
                        return 0 as libc::c_int;
                    }
                    if BIO_ctrl(
                        cert_bio,
                        108 as libc::c_int,
                        (0x1 as libc::c_int | 0x2 as libc::c_int) as libc::c_long,
                        cert_file as *mut libc::c_void,
                    ) as libc::c_int <= 0 as libc::c_int
                    {
                        Curl_failf(
                            data,
                            b"could not open PKCS12 file '%s'\0" as *const u8
                                as *const libc::c_char,
                            cert_file,
                        );
                        BIO_free(cert_bio);
                        return 0 as libc::c_int;
                    }
                }
                p12 = d2i_PKCS12_bio(cert_bio, 0 as *mut *mut PKCS12);
                BIO_free(cert_bio);
                if p12.is_null() {
                    Curl_failf(
                        data,
                        b"error reading PKCS12 file '%s'\0" as *const u8
                            as *const libc::c_char,
                        if !cert_blob.is_null() {
                            b"(memory blob)\0" as *const u8 as *const libc::c_char
                        } else {
                            cert_file as *const libc::c_char
                        },
                    );
                    return 0 as libc::c_int;
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
                            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        ),
                    );
                    PKCS12_free(p12);
                    return 0 as libc::c_int;
                }
                PKCS12_free(p12);
                if SSL_CTX_use_certificate(ctx, x509) != 1 as libc::c_int {
                    Curl_failf(
                        data,
                        b"could not load PKCS12 client certificate, OpenSSL error %s\0"
                            as *const u8 as *const libc::c_char,
                        ossl_strerror(
                            ERR_get_error(),
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        ),
                    );
                } else if SSL_CTX_use_PrivateKey(ctx, pri) != 1 as libc::c_int {
                    Curl_failf(
                        data,
                        b"unable to use private key from PKCS12 file '%s'\0" as *const u8
                            as *const libc::c_char,
                        cert_file,
                    );
                } else if SSL_CTX_check_private_key(ctx) == 0 {
                    Curl_failf(
                        data,
                        b"private key from PKCS12 file '%s' does not match certificate in same file\0"
                            as *const u8 as *const libc::c_char,
                        cert_file,
                    );
                } else {
                    if !ca.is_null() {
                        loop {
                            if !(sk_X509_num(ca) != 0) {
                                current_block = 17395932908762866334;
                                break;
                            }
                            let mut x: *mut X509 = sk_X509_pop(ca);
                            if SSL_CTX_add_client_CA(ctx, x) == 0 {
                                X509_free(x);
                                Curl_failf(
                                    data,
                                    b"cannot add certificate to client CA list\0" as *const u8
                                        as *const libc::c_char,
                                );
                                current_block = 12402052390070716948;
                                break;
                            } else {
                                if !(SSL_CTX_ctrl(
                                    ctx,
                                    14 as libc::c_int,
                                    0 as libc::c_int as libc::c_long,
                                    x as *mut libc::c_char as *mut libc::c_void,
                                ) == 0)
                                {
                                    continue;
                                }
                                X509_free(x);
                                Curl_failf(
                                    data,
                                    b"cannot add certificate to certificate chain\0"
                                        as *const u8 as *const libc::c_char,
                                );
                                current_block = 12402052390070716948;
                                break;
                            }
                        }
                    } else {
                        current_block = 17395932908762866334;
                    }
                    match current_block {
                        12402052390070716948 => {}
                        _ => {
                            cert_done = 1 as libc::c_int;
                        }
                    }
                }
                EVP_PKEY_free(pri);
                X509_free(x509);
                
                #[cfg(USE_AMISSL)]
                sk_X509_pop_free(
                    ca,
                    Some(Curl_amiga_X509_free as unsafe extern "C" fn(*mut X509) -> ()),
                );
                #[cfg(not(USE_AMISSL))]
                sk_X509_pop_free(
                    ca,
                    Some(X509_free as unsafe extern "C" fn(*mut X509) -> ()),
                );
                if cert_done == 0 {
                    return 0 as libc::c_int;
                }
            }
            _ => {
                Curl_failf(
                    data,
                    b"not supported file type '%s' for certificate\0" as *const u8
                        as *const libc::c_char,
                    cert_type,
                );
                return 0 as libc::c_int;
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
            42 => {
                match () {
                    #[cfg(USE_OPENSSL_ENGINE)]
                    _ => {
                        let mut priv_key: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
                        if ((*data).state.engine).is_null() {
                            if is_pkcs11_uri(key_file) {
                                if ossl_set_engine(
                                    data,
                                    b"pkcs11\0" as *const u8 as *const libc::c_char,
                                ) as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint
                                {
                                    return 0 as libc::c_int;
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
                                    b"unable do create OpenSSL user-interface method\0"
                                        as *const u8 as *const libc::c_char,
                                );
                                return 0 as libc::c_int;
                            }
                            UI_method_set_opener(ui_method, UI_method_get_opener(UI_OpenSSL()));
                            UI_method_set_closer(ui_method, UI_method_get_closer(UI_OpenSSL()));
                            UI_method_set_reader(
                                ui_method,
                                Some(
                                    ssl_ui_reader
                                        as unsafe extern "C" fn(
                                            *mut UI,
                                            *mut UI_STRING,
                                        ) -> libc::c_int,
                                ),
                            );
                            UI_method_set_writer(
                                ui_method,
                                Some(
                                    ssl_ui_writer
                                        as unsafe extern "C" fn(
                                            *mut UI,
                                            *mut UI_STRING,
                                        ) -> libc::c_int,
                                ),
                            );
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
                                    b"failed to load private key from crypto engine\0"
                                        as *const u8 as *const libc::c_char,
                                );
                                return 0 as libc::c_int;
                            }
                            if SSL_CTX_use_PrivateKey(ctx, priv_key) != 1 as libc::c_int {
                                Curl_failf(
                                    data,
                                    b"unable to set private key\0" as *const u8
                                        as *const libc::c_char,
                                );
                                EVP_PKEY_free(priv_key);
                                return 0 as libc::c_int;
                            }
                            EVP_PKEY_free(priv_key);
                        } else {
                            Curl_failf(
                                data,
                                b"crypto engine not set, can't load private key\0" as *const u8
                                    as *const libc::c_char,
                            );
                            return 0 as libc::c_int;
                        }
                        current_block_141 = 14358540534591340610;
                    }
                    #[cfg(not(USE_OPENSSL_ENGINE))]
                    _ => {
                        Curl_failf(
                            data,
                            b"file type ENG for private key not supported" as *const u8
                                as *const libc::c_char,
                        );
                        return 0 as libc::c_int;
                    }
                }
                // #[cfg(USE_OPENSSL_ENGINE)]
                // if true {
                //     let mut priv_key: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
                //     if ((*data).state.engine).is_null() {
                //         if is_pkcs11_uri(key_file) {
                //             if ossl_set_engine(
                //                 data,
                //                 b"pkcs11\0" as *const u8 as *const libc::c_char,
                //             ) as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint
                //             {
                //                 return 0 as libc::c_int;
                //             }
                //         }
                //     }
                //     if !((*data).state.engine).is_null() {
                //         let mut ui_method: *mut UI_METHOD = UI_create_method(
                //             b"curl user interface\0" as *const u8 as *const libc::c_char
                //                 as *mut libc::c_char,
                //         );
                //         if ui_method.is_null() {
                //             Curl_failf(
                //                 data,
                //                 b"unable do create OpenSSL user-interface method\0"
                //                     as *const u8 as *const libc::c_char,
                //             );
                //             return 0 as libc::c_int;
                //         }
                //         UI_method_set_opener(ui_method, UI_method_get_opener(UI_OpenSSL()));
                //         UI_method_set_closer(ui_method, UI_method_get_closer(UI_OpenSSL()));
                //         UI_method_set_reader(
                //             ui_method,
                //             Some(
                //                 ssl_ui_reader
                //                     as unsafe extern "C" fn(
                //                         *mut UI,
                //                         *mut UI_STRING,
                //                     ) -> libc::c_int,
                //             ),
                //         );
                //         UI_method_set_writer(
                //             ui_method,
                //             Some(
                //                 ssl_ui_writer
                //                     as unsafe extern "C" fn(
                //                         *mut UI,
                //                         *mut UI_STRING,
                //                     ) -> libc::c_int,
                //             ),
                //         );
                //         priv_key = ENGINE_load_private_key(
                //             (*data).state.engine as *mut ENGINE,
                //             key_file,
                //             ui_method,
                //             key_passwd as *mut libc::c_void,
                //         );
                //         UI_destroy_method(ui_method);
                //         if priv_key.is_null() {
                //             Curl_failf(
                //                 data,
                //                 b"failed to load private key from crypto engine\0"
                //                     as *const u8 as *const libc::c_char,
                //             );
                //             return 0 as libc::c_int;
                //         }
                //         if SSL_CTX_use_PrivateKey(ctx, priv_key) != 1 as libc::c_int {
                //             Curl_failf(
                //                 data,
                //                 b"unable to set private key\0" as *const u8
                //                     as *const libc::c_char,
                //             );
                //             EVP_PKEY_free(priv_key);
                //             return 0 as libc::c_int;
                //         }
                //         EVP_PKEY_free(priv_key);
                //     } else {
                //         Curl_failf(
                //             data,
                //             b"crypto engine not set, can't load private key\0" as *const u8
                //                 as *const libc::c_char,
                //         );
                //         return 0 as libc::c_int;
                //     }
                //     current_block_141 = 14358540534591340610;
                // }
                // #[cfg(not(USE_OPENSSL_ENGINE))]
                // if true {
                //     Curl_failf(
                //         data,
                //         b"file type ENG for private key not supported" as *const u8
                //             as *const libc::c_char,
                //     );
                //     return 0 as libc::c_int;
                // }
            }
            43 => {
                if cert_done == 0 {
                    Curl_failf(
                        data,
                        b"file type P12 for private key not supported\0" as *const u8
                            as *const libc::c_char,
                    );
                    return 0 as libc::c_int;
                }
                current_block_141 = 14358540534591340610;
            }
            _ => {
                Curl_failf(
                    data,
                    b"not supported file type for private key\0" as *const u8
                        as *const libc::c_char,
                );
                return 0 as libc::c_int;
            }
        }
        match current_block_141 {
            2766187242236248435 => {
                cert_use_result = if !key_blob.is_null() {
                    SSL_CTX_use_PrivateKey_blob(ctx, key_blob, file_type, key_passwd)
                } else {
                    SSL_CTX_use_PrivateKey_file(ctx, key_file, file_type)
                };
                if cert_use_result != 1 as libc::c_int {
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
                    return 0 as libc::c_int;
                }
            }
            _ => {}
        }
        ssl = SSL_new(ctx);
        if ssl.is_null() {
            Curl_failf(
                data,
                b"unable to create an SSL structure\0" as *const u8
                    as *const libc::c_char,
            );
            return 0 as libc::c_int;
        }
        x509 = SSL_get_certificate(ssl);
        if !x509.is_null() {
            let mut pktmp: *mut EVP_PKEY = X509_get_pubkey(x509);
            EVP_PKEY_copy_parameters(pktmp, SSL_get_privatekey(ssl));
            EVP_PKEY_free(pktmp);
        }
        #[cfg(all(not(OPENSSL_NO_RSA), not(OPENSSL_IS_BORINGSSL)))]
        let mut priv_key_0: *mut EVP_PKEY = SSL_get_privatekey(ssl);
        #[cfg(all(not(OPENSSL_NO_RSA), not(OPENSSL_IS_BORINGSSL), not(HAVE_OPAQUE_EVP_PKEY)))]
        // TODO 未开的情况下不是 = 0，是另一种情况
        let mut pktype: libc::c_int = 0;
        #[cfg(all(not(OPENSSL_NO_RSA), not(OPENSSL_IS_BORINGSSL), HAVE_OPAQUE_EVP_PKEY))]
        let mut pktype: libc::c_int = EVP_PKEY_id(priv_key_0);
        // TODO - 不开HAVE_OPAQUE_EVP_PKEY选项
        // #[cfg(all(not(OPENSSL_NO_RSA), not(OPENSSL_IS_BORINGSSL), not(HAVE_OPAQUE_EVP_PKEY)))]
        #[cfg(all(not(OPENSSL_NO_RSA), not(OPENSSL_IS_BORINGSSL)))]
        if pktype == 6 as libc::c_int {
            let mut rsa: *mut RSA = EVP_PKEY_get1_RSA(priv_key_0);
            if RSA_flags(rsa) & 0x1 as libc::c_int != 0 {
                check_privkey = 0 as libc::c_int != 0;
            }
            RSA_free(rsa);
        }
        SSL_free(ssl);
        if check_privkey as libc::c_int == 1 as libc::c_int {
            if SSL_CTX_check_private_key(ctx) == 0 {
                Curl_failf(
                    data,
                    b"Private key does not match the certificate public key\0"
                        as *const u8 as *const libc::c_char,
                );
                return 0 as libc::c_int;
            }
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn x509_name_oneline(
    mut a: *mut X509_NAME,
    mut buf: *mut libc::c_char,
    mut size: size_t,
) -> libc::c_int {
    let mut bio_out: *mut BIO = BIO_new(BIO_s_mem());
    let mut biomem: *mut BUF_MEM = 0 as *mut BUF_MEM;
    let mut rc: libc::c_int = 0;
    if bio_out.is_null() {
        return 1 as libc::c_int;
    }
    rc = X509_NAME_print_ex(
        bio_out,
        a,
        0 as libc::c_int,
        ((3 as libc::c_int) << 16 as libc::c_int) as libc::c_ulong,
    );
    BIO_ctrl(
        bio_out,
        115 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        &mut biomem as *mut *mut BUF_MEM as *mut libc::c_char as *mut libc::c_void,
    );
    if (*biomem).length < size {
        size = (*biomem).length;
    } else {
        size = size.wrapping_sub(1);
    }
    memcpy(buf as *mut libc::c_void, (*biomem).data as *const libc::c_void, size);
    *buf.offset(size as isize) = 0 as libc::c_int as libc::c_char;
    BIO_free(bio_out);
    return (rc == 0) as libc::c_int;
}
unsafe extern "C" fn ossl_init() -> libc::c_int {
    #[cfg(OPENSSL_INIT_ENGINE_ALL_BUILTIN)]
    let flag_1 = 0x200 as libc::c_long | 0x400 as libc::c_long
               | 0x1000 as libc::c_long | 0x2000 as libc::c_long | 0x4000 as libc::c_long;
    #[cfg(not(OPENSSL_INIT_ENGINE_ALL_BUILTIN))]
    let flag_1 = 0x0000 as libc::c_long;
    #[cfg(CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG)]
    let flag_2 = 0x80 as libc::c_long;
    #[cfg(not(CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG))]
    let flag_2 = 0x40 as libc::c_long;
    let flags: uint64_t = (flag_1
        | flag_2 | 0 as libc::c_int as libc::c_long) as uint64_t;
    
    OPENSSL_init_ssl(flags, 0 as *const OPENSSL_INIT_SETTINGS);
    Curl_tls_keylog_open();
    if ossl_get_ssl_data_index() < 0 as libc::c_int
        || ossl_get_ssl_conn_index() < 0 as libc::c_int
        || ossl_get_ssl_sockindex_index() < 0 as libc::c_int
        || ossl_get_proxy_index() < 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ossl_cleanup() {
    Curl_tls_keylog_close();
}
unsafe extern "C" fn ossl_check_cxn(mut conn: *mut connectdata) -> libc::c_int {
    #[cfg(MSG_PEEK)]
    let mut buf: libc::c_char = 0;
    #[cfg(MSG_PEEK)]
    let mut nread: ssize_t = recv(
                        (*conn).sock[0 as libc::c_int as usize],
                        &mut buf as *mut libc::c_char as *mut libc::c_void,
                        1 as libc::c_int as size_t,
                        MSG_PEEK as libc::c_int,
                    );
    #[cfg(MSG_PEEK)]
    if nread == 0 as libc::c_int as libc::c_long {
        return 0 as libc::c_int;
    }
    #[cfg(MSG_PEEK)]
    if nread == 1 as libc::c_int as libc::c_long {
        return 1 as libc::c_int
    } else {
        if nread == -(1 as libc::c_int) as libc::c_long {
            let mut err: libc::c_int = *__errno_location();
            // 写法不对，rust中如何判断宏值的相等
            // TODO - 1276
            if err == 115 as libc::c_int || err == 11 as libc::c_int {
                return 1 as libc::c_int;
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
            if err == 104 as libc::c_int || ECONNABORTED_flag
                || ENETDOWN_flag || ENETRESET_flag
                || ENETDOWN_flag || ETIMEDOUT_flag
                || err == 107 as libc::c_int
            {
                return 0 as libc::c_int;
            }
        }
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn ossl_set_engine(
    mut data: *mut Curl_easy,
    mut engine: *const libc::c_char,
) -> CURLcode {
    if cfg!(USE_OPENSSL_ENGINE){
        let mut e: *mut ENGINE = 0 as *mut ENGINE;
        e = ENGINE_by_id(engine);
        if e.is_null() {
            Curl_failf(
                data,
                b"SSL Engine '%s' not found\0" as *const u8 as *const libc::c_char,
                engine,
            );
            return CURLE_SSL_ENGINE_NOTFOUND;
        }
        if !((*data).state.engine).is_null() {
            ENGINE_finish((*data).state.engine as *mut ENGINE);
            ENGINE_free((*data).state.engine as *mut ENGINE);
            let ref mut fresh0 = (*data).state.engine;
            *fresh0 = 0 as *mut libc::c_void;
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
                    ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                ),
            );
            return CURLE_SSL_ENGINE_INITFAILED;
        }
        let ref mut fresh1 = (*data).state.engine;
        *fresh1 = e as *mut libc::c_void;
        return CURLE_OK;
    }else{
        Curl_infof(
            data,
            b"SSL Engine not supported\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_SSL_ENGINE_NOTFOUND;
    }     
}
unsafe extern "C" fn ossl_set_engine_default(mut data: *mut Curl_easy) -> CURLcode {
    if cfg!(USE_OPENSSL_ENGINE){
        if !((*data).state.engine).is_null() {
            if ENGINE_set_default(
                (*data).state.engine as *mut ENGINE,
                0xffff as libc::c_int as libc::c_uint,
            ) > 0 as libc::c_int
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
    return CURLE_OK;
}
unsafe extern "C" fn ossl_engines_list(mut data: *mut Curl_easy) -> *mut curl_slist {
    let mut list: *mut curl_slist = 0 as *mut curl_slist;
    if cfg!(USE_OPENSSL_ENGINE){
        let mut beg: *mut curl_slist = 0 as *mut curl_slist;
        let mut e: *mut ENGINE = 0 as *mut ENGINE;
        e = ENGINE_get_first();
        while !e.is_null() {
            beg = curl_slist_append(list, ENGINE_get_id(e));
            if beg.is_null() {
                curl_slist_free_all(list);
                return 0 as *mut curl_slist;
            }
            list = beg;
            e = ENGINE_get_next(e);
        }
    }
    return list;
}
unsafe extern "C" fn ossl_closeone(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut connssl: *mut ssl_connect_data,
) {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if !((*backend).handle).is_null() {
        let mut buf: [libc::c_char; 32] = [0; 32];
        let ref mut fresh2 = (*(*conn).ssl[0 as libc::c_int as usize].backend).logger;
        *fresh2 = data;
        SSL_read(
            (*backend).handle,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as libc::c_int,
        );
        SSL_shutdown((*backend).handle);
        SSL_set_connect_state((*backend).handle);
        SSL_free((*backend).handle);
        let ref mut fresh3 = (*backend).handle;
        *fresh3 = 0 as *mut SSL;
    }
    if !((*backend).ctx).is_null() {
        SSL_CTX_free((*backend).ctx);
        let ref mut fresh4 = (*backend).ctx;
        *fresh4 = 0 as *mut SSL_CTX;
    }
}
unsafe extern "C" fn ossl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
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
unsafe extern "C" fn ossl_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> libc::c_int {
    let mut retval: libc::c_int = 0 as libc::c_int;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut buf: [libc::c_char; 256] = [0; 256];
    let mut sslerror: libc::c_ulong = 0;
    let mut nread: ssize_t = 0;
    let mut buffsize: libc::c_int = 0;
    let mut err: libc::c_int = 0;
    let mut done: bool = 0 as libc::c_int != 0;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut loop_0: libc::c_int = 10 as libc::c_int;
    #[cfg(not(CURL_DISABLE_FTP))]
    if (*data).set.ftp_ccc as libc::c_uint
        == CURLFTPSSL_CCC_ACTIVE as libc::c_int as libc::c_uint
    {
        SSL_shutdown((*backend).handle);
    }
    if !((*backend).handle).is_null() {
        buffsize = ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
            as libc::c_int;
        while !done
            && {
                let fresh5 = loop_0;
                loop_0 = loop_0 - 1;
                fresh5 != 0
            }
        {
            let mut what: libc::c_int = Curl_socket_check(
                (*conn).sock[sockindex as usize],
                -(1 as libc::c_int),
                -(1 as libc::c_int),
                10000 as libc::c_int as timediff_t,
            );
            if what > 0 as libc::c_int {
                ERR_clear_error();
                nread = SSL_read(
                    (*backend).handle,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buffsize,
                ) as ssize_t;
                err = SSL_get_error((*backend).handle, nread as libc::c_int);
                match err {
                    0 | 6 => {
                        done = 1 as libc::c_int != 0;
                    }
                    2 => {
                        Curl_infof(
                            data,
                            b"SSL_ERROR_WANT_READ\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    3 => {
                        Curl_infof(
                            data,
                            b"SSL_ERROR_WANT_WRITE\0" as *const u8 as *const libc::c_char,
                        );
                        done = 1 as libc::c_int != 0;
                    }
                    _ => {
                        sslerror = ERR_get_error();
                        Curl_failf(
                            data,
                            b"OpenSSL SSL_read on shutdown: %s, errno %d\0" as *const u8
                                as *const libc::c_char,
                            if sslerror != 0 {
                                ossl_strerror(
                                    sslerror,
                                    buf.as_mut_ptr(),
                                    ::std::mem::size_of::<[libc::c_char; 256]>()
                                        as libc::c_ulong,
                                ) as *const libc::c_char
                            } else {
                                SSL_ERROR_to_str(err)
                            },
                            *__errno_location(),
                        );
                        done = 1 as libc::c_int != 0;
                    }
                }
            } else if 0 as libc::c_int == what {
                Curl_failf(
                    data,
                    b"SSL shutdown timeout\0" as *const u8 as *const libc::c_char,
                );
                done = 1 as libc::c_int != 0;
            } else {
                Curl_failf(
                    data,
                    b"select/poll on SSL socket, errno: %d\0" as *const u8
                        as *const libc::c_char,
                    *__errno_location(),
                );
                retval = -(1 as libc::c_int);
                done = 1 as libc::c_int != 0;
            }
        }
        if ((*data).set).verbose() != 0 {
            if cfg!(HAVE_SSL_GET_SHUTDOWN){
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
                            b"SSL_get_shutdown() returned SSL_RECEIVED_SHUTDOWN\0"
                                as *const u8 as *const libc::c_char,
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
        SSL_free((*backend).handle);
        let ref mut fresh6 = (*backend).handle;
        *fresh6 = 0 as *mut SSL;
    }
    return retval;
}
unsafe extern "C" fn ossl_session_free(mut ptr: *mut libc::c_void) {
    SSL_SESSION_free(ptr as *mut SSL_SESSION);
}
unsafe extern "C" fn ossl_close_all(mut data: *mut Curl_easy) {
    #[cfg(USE_OPENSSL_ENGINE)] 
    if !((*data).state.engine).is_null() {
        ENGINE_finish((*data).state.engine as *mut ENGINE);
        ENGINE_free((*data).state.engine as *mut ENGINE);
        let ref mut fresh7 = (*data).state.engine;
        *fresh7 = 0 as *mut libc::c_void;
    }
    // TODO - 1560
    // #[cfg(all(not(HAVE_ERR_REMOVE_THREAD_STATE_DEPRECATED), HAVE_ERR_REMOVE_THREAD_STATE))]
}
// TODO - 1579 开启 CURL_DOES_CONVERSIONS 选项
// #[cfg(CURL_DOES_CONVERSIONS)]
#[cfg(not(CURL_DOES_CONVERSIONS))]
unsafe extern "C" fn subj_alt_hostcheck(
    mut data: *mut Curl_easy,
    mut match_pattern: *const libc::c_char,
    mut hostname: *const libc::c_char,
    mut dispname: *const libc::c_char,
) -> bool {
    if Curl_cert_hostcheck(match_pattern, hostname) != 0 {
        Curl_infof(
            data,
            b" subjectAltName: host \"%s\" matched cert's \"%s\"\0" as *const u8
                as *const libc::c_char,
            dispname,
            match_pattern,
        );
        return 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
unsafe extern "C" fn verifyhost(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut server_cert: *mut X509,
) -> CURLcode {
    let mut matched: bool = 0 as libc::c_int != 0;
    let mut target: libc::c_int = 2 as libc::c_int;
    let mut addrlen: size_t = 0 as libc::c_int as size_t;
    let mut altnames: *mut stack_st_GENERAL_NAME = 0 as *mut stack_st_GENERAL_NAME;
    #[cfg(ENABLE_IPV6)]
    let mut addr: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_10 {
            __u6_addr8: [0; 16],
        },
    };
    #[cfg(not(ENABLE_IPV6))]
    let mut addr: in_addr = in_addr { s_addr: 0 };
    // TODO - 1650
    // #[cfg(not(ENABLE_IPV6))]
    let mut result: CURLcode = CURLE_OK;
    let mut dNSName: bool = 0 as libc::c_int != 0;
    let mut iPAddress: bool = 0 as libc::c_int != 0;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let hostname: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
        (*conn).http_proxy.host.name
    } else {
        (*conn).host.name
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let hostname: *const libc::c_char = (*conn).host.name;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let dispname: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
        (*conn).http_proxy.host.dispname
    } else {
        (*conn).host.dispname
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let dispname: *const libc::c_char = (*conn).host.dispname;
    // DONE - 1661
    #[cfg(ENABLE_IPV6)]
    if ((*conn).bits).ipv6_ip() as libc::c_int != 0
        && inet_pton(
            10 as libc::c_int,
            hostname,
            &mut addr as *mut in6_addr as *mut libc::c_void,
        ) != 0
    {
        target = 7 as libc::c_int;
        addrlen = ::std::mem::size_of::<in6_addr>() as libc::c_ulong;
    } else if inet_pton(
            2 as libc::c_int,
            hostname,
            &mut addr as *mut in6_addr as *mut libc::c_void,
        ) != 0
        {
        target = 7 as libc::c_int;
        addrlen = ::std::mem::size_of::<in_addr>() as libc::c_ulong;
    }
    #[cfg(not(ENABLE_IPV6))]
    if inet_pton(
        2 as libc::c_int,
        hostname,
        &mut addr as *mut in_addr as *mut libc::c_void,
    ) != 0
    {
        target = 7 as libc::c_int;
        addrlen = ::std::mem::size_of::<in_addr>() as libc::c_ulong;
    }
    altnames = X509_get_ext_d2i(
        server_cert,
        85 as libc::c_int,
        0 as *mut libc::c_int,
        0 as *mut libc::c_int,
    ) as *mut stack_st_GENERAL_NAME;
    if !altnames.is_null() {
        // TODO 待确认
        #[cfg(OPENSSL_IS_BORINGSSL)]
        let mut numalts: ibc::c_int = 0;
        #[cfg(OPENSSL_IS_BORINGSSL)]
        let mut i: ibc::c_int = 0;
        #[cfg(not(OPENSSL_IS_BORINGSSL))]
        let mut numalts: libc::c_int = 0;
        #[cfg(not(OPENSSL_IS_BORINGSSL))]
        let mut i: libc::c_int = 0;
        let mut dnsmatched: bool = 0 as libc::c_int != 0;
        let mut ipmatched: bool = 0 as libc::c_int != 0;
        numalts = sk_GENERAL_NAME_num(altnames);
        i = 0 as libc::c_int;
        while i < numalts && !dnsmatched {
            let mut check: *const GENERAL_NAME = sk_GENERAL_NAME_value(altnames, i);
            if (*check).type_0 == 2 as libc::c_int {
                dNSName = 1 as libc::c_int != 0;
            } else if (*check).type_0 == 7 as libc::c_int {
                iPAddress = 1 as libc::c_int != 0;
            }
            if (*check).type_0 == target {
                let mut altptr: *const libc::c_char = ASN1_STRING_get0_data(
                    (*check).d.ia5,
                ) as *mut libc::c_char;
                let mut altlen: size_t = ASN1_STRING_length((*check).d.ia5) as size_t;
                match target {
                    2 => {
                        if altlen == strlen(altptr)
                            && subj_alt_hostcheck(data, altptr, hostname, dispname)
                                as libc::c_int != 0
                        {
                            dnsmatched = 1 as libc::c_int != 0;
                        }
                    }
                    7 => {
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
                        if altlen == addrlen
                           && ENABLE_IPV6_a{
                            ipmatched = 1 as libc::c_int != 0;
                            Curl_infof(
                                data,
                                b" subjectAltName: host \"%s\" matched cert's IP address!\0"
                                    as *const u8 as *const libc::c_char,
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
        if dnsmatched as libc::c_int != 0 || ipmatched as libc::c_int != 0 {
            matched = 1 as libc::c_int != 0;
        }
    }
    if !matched {
        if dNSName as libc::c_int != 0 || iPAddress as libc::c_int != 0 {
            Curl_infof(
                data,
                b" subjectAltName does not match %s\0" as *const u8
                    as *const libc::c_char,
                dispname,
            );
            Curl_failf(
                data,
                b"SSL: no alternative certificate subject name matches target host name '%s'\0"
                    as *const u8 as *const libc::c_char,
                dispname,
            );
            result = CURLE_PEER_FAILED_VERIFICATION;
        } else {
            let mut j: libc::c_int = 0;
            let mut i_0: libc::c_int = -(1 as libc::c_int);
            let mut nulstr: *mut libc::c_uchar = b"\0" as *const u8
                as *const libc::c_char as *mut libc::c_uchar;
            let mut peer_CN: *mut libc::c_uchar = nulstr;
            let mut name: *mut X509_NAME = X509_get_subject_name(server_cert);
            if !name.is_null() {
                loop {
                    j = X509_NAME_get_index_by_NID(name, 13 as libc::c_int, i_0);
                    if !(j >= 0 as libc::c_int) {
                        break;
                    }
                    i_0 = j;
                }
            }
            if i_0 >= 0 as libc::c_int {
                let mut tmp: *mut ASN1_STRING = X509_NAME_ENTRY_get_data(
                    X509_NAME_get_entry(name, i_0),
                );
                if !tmp.is_null() {
                    if ASN1_STRING_type(tmp) == 12 as libc::c_int {
                        j = ASN1_STRING_length(tmp);
                        if j >= 0 as libc::c_int {
                            peer_CN = CRYPTO_malloc(
                                (j + 1 as libc::c_int) as size_t,
                                b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                                1786 as libc::c_int,
                            ) as *mut libc::c_uchar;
                            if !peer_CN.is_null() {
                                memcpy(
                                    peer_CN as *mut libc::c_void,
                                    ASN1_STRING_get0_data(tmp) as *const libc::c_void,
                                    j as libc::c_ulong,
                                );
                                *peer_CN.offset(j as isize) = '\0' as i32 as libc::c_uchar;
                            }
                        }
                    } else {
                        j = ASN1_STRING_to_UTF8(&mut peer_CN, tmp);
                    }
                    if !peer_CN.is_null()
                        && curlx_uztosi(strlen(peer_CN as *mut libc::c_char)) != j
                    {
                        Curl_failf(
                            data,
                            b"SSL: illegal cert name field\0" as *const u8
                                as *const libc::c_char,
                        );
                        result = CURLE_PEER_FAILED_VERIFICATION;
                    }
                }
            }
            if peer_CN == nulstr {
                peer_CN = 0 as *mut libc::c_uchar;
            } else {
                let mut rc: CURLcode = CURLE_OK as libc::c_int as CURLcode;
                if rc as u64 != 0 {
                    CRYPTO_free(
                        peer_CN as *mut libc::c_void,
                        b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                        1813 as libc::c_int,
                    );
                    return rc;
                }
            }
            if !(result as u64 != 0) {
                if peer_CN.is_null() {
                    Curl_failf(
                        data,
                        b"SSL: unable to obtain common name from peer certificate\0"
                            as *const u8 as *const libc::c_char,
                    );
                    result = CURLE_PEER_FAILED_VERIFICATION;
                } else if Curl_cert_hostcheck(peer_CN as *const libc::c_char, hostname)
                        == 0
                    {
                    Curl_failf(
                        data,
                        b"SSL: certificate subject name '%s' does not match target host name '%s'\0"
                            as *const u8 as *const libc::c_char,
                        peer_CN,
                        dispname,
                    );
                    result = CURLE_PEER_FAILED_VERIFICATION;
                } else {
                    Curl_infof(
                        data,
                        b" common name: %s (matched)\0" as *const u8
                            as *const libc::c_char,
                        peer_CN,
                    );
                }
            }
            if !peer_CN.is_null() {
                CRYPTO_free(
                    peer_CN as *mut libc::c_void,
                    b"vtls/openssl.c\0" as *const u8 as *const libc::c_char,
                    1835 as libc::c_int,
                );
            }
        }
    }
    return result;
}
#[cfg(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP)))]
unsafe extern "C" fn verifystatus(
    mut data: *mut Curl_easy,
    mut connssl: *mut ssl_connect_data,
) -> CURLcode {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut ocsp_status: libc::c_int = 0;
    let mut status: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut result: CURLcode = CURLE_OK;
    let mut rsp: *mut OCSP_RESPONSE = 0 as *mut OCSP_RESPONSE;
    let mut br: *mut OCSP_BASICRESP = 0 as *mut OCSP_BASICRESP;
    let mut st: *mut X509_STORE = 0 as *mut X509_STORE;
    let mut ch: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut cert: *mut X509 = 0 as *mut X509;
    let mut id: *mut OCSP_CERTID = 0 as *mut OCSP_CERTID;
    let mut cert_status: libc::c_int = 0;
    let mut crl_reason: libc::c_int = 0;
    let mut rev: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
    let mut thisupd: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
    let mut nextupd: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
    let mut ret: libc::c_int = 0;
    let mut len: libc::c_long = SSL_ctrl(
        (*backend).handle,
        70 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        &mut status as *mut *mut libc::c_uchar as *mut libc::c_void,
    );
    if status.is_null() {
        Curl_failf(
            data,
            b"No OCSP response received\0" as *const u8 as *const libc::c_char,
        );
        result = CURLE_SSL_INVALIDCERTSTATUS;
    } else {
        p = status;
        rsp = d2i_OCSP_RESPONSE(0 as *mut *mut OCSP_RESPONSE, &mut p, len);
        if rsp.is_null() {
            Curl_failf(
                data,
                b"Invalid OCSP response\0" as *const u8 as *const libc::c_char,
            );
            result = CURLE_SSL_INVALIDCERTSTATUS;
        } else {
            ocsp_status = OCSP_response_status(rsp);
            if ocsp_status != 0 as libc::c_int {
                Curl_failf(
                    data,
                    b"Invalid OCSP response status: %s (%d)\0" as *const u8
                        as *const libc::c_char,
                    OCSP_response_status_str(ocsp_status as libc::c_long),
                    ocsp_status,
                );
                result = CURLE_SSL_INVALIDCERTSTATUS;
            } else {
                br = OCSP_response_get1_basic(rsp);
                if br.is_null() {
                    Curl_failf(
                        data,
                        b"Invalid OCSP response\0" as *const u8 as *const libc::c_char,
                    );
                    result = CURLE_SSL_INVALIDCERTSTATUS;
                } else {
                    ch = SSL_get_peer_cert_chain((*backend).handle);
                    st = SSL_CTX_get_cert_store((*backend).ctx);
                    // TODO - 1894 这里有一段跟OPENSSL_VERSION_NUMBER相关的条件编译
                    if cfg!(any(OPENSSL_VERSION_NUMBER_LT_0X1000201FL, all(LIBRESSL_VERSION_NUMBER, LIBRESSL_VERSION_NUMBER_LT_0X2040200FL))){
                        // TODO
                    }
                    if OCSP_basic_verify(br, ch, st, 0 as libc::c_int as libc::c_ulong)
                        <= 0 as libc::c_int
                    {
                        Curl_failf(
                            data,
                            b"OCSP response verification failed\0" as *const u8
                                as *const libc::c_char,
                        );
                        result = CURLE_SSL_INVALIDCERTSTATUS;
                    } else {
                        cert = SSL_get_peer_certificate((*backend).handle);
                        if cert.is_null() {
                            Curl_failf(
                                data,
                                b"Error getting peer certificate\0" as *const u8
                                    as *const libc::c_char,
                            );
                            result = CURLE_SSL_INVALIDCERTSTATUS;
                        } else {
                            i = 0 as libc::c_int;
                            while i < sk_X509_num(ch) {
                                let mut issuer: *mut X509 = sk_X509_value(ch, i);
                                if X509_check_issued(issuer, cert) == 0 as libc::c_int {
                                    id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                            X509_free(cert);
                            if id.is_null() {
                                Curl_failf(
                                    data,
                                    b"Error computing OCSP ID\0" as *const u8
                                        as *const libc::c_char,
                                );
                                result = CURLE_SSL_INVALIDCERTSTATUS;
                            } else {
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
                                if ret != 1 as libc::c_int {
                                    Curl_failf(
                                        data,
                                        b"Could not find certificate ID in OCSP response\0"
                                            as *const u8 as *const libc::c_char,
                                    );
                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                } else if OCSP_check_validity(
                                        thisupd,
                                        nextupd,
                                        300 as libc::c_long,
                                        -(1 as libc::c_long),
                                    ) == 0
                                    {
                                    Curl_failf(
                                        data,
                                        b"OCSP response has expired\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                } else {
                                    Curl_infof(
                                        data,
                                        b"SSL certificate status: %s (%d)\0" as *const u8
                                            as *const libc::c_char,
                                        OCSP_cert_status_str(cert_status as libc::c_long),
                                        cert_status,
                                    );
                                    match cert_status {
                                        0 => {}
                                        1 => {
                                            current_block = 12089705661391070189;
                                            match current_block {
                                                14279247759268772714 => {
                                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                                }
                                                _ => {
                                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                                    Curl_failf(
                                                        data,
                                                        b"SSL certificate revocation reason: %s (%d)\0" as *const u8
                                                            as *const libc::c_char,
                                                        OCSP_crl_reason_str(crl_reason as libc::c_long),
                                                        crl_reason,
                                                    );
                                                }
                                            }
                                        }
                                        2 | _ => {
                                            current_block = 14279247759268772714;
                                            match current_block {
                                                14279247759268772714 => {
                                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                                }
                                                _ => {
                                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                                    Curl_failf(
                                                        data,
                                                        b"SSL certificate revocation reason: %s (%d)\0" as *const u8
                                                            as *const libc::c_char,
                                                        OCSP_crl_reason_str(crl_reason as libc::c_long),
                                                        crl_reason,
                                                    );
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
    if !br.is_null() {
        OCSP_BASICRESP_free(br);
    }
    OCSP_RESPONSE_free(rsp);
    return result;
}

#[cfg(SSL_CTRL_SET_MSG_CALLBACK)]
unsafe extern "C" fn ssl_msg_type(
    mut ssl_ver: libc::c_int,
    mut msg: libc::c_int,
) -> *const libc::c_char {
    if ssl_ver == 0x3 as libc::c_int {
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
unsafe extern "C" fn tls_rt_type(mut type_0: libc::c_int) -> *const libc::c_char {
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
#[cfg(SSL_CTRL_SET_MSG_CALLBACK)]
unsafe extern "C" fn ossl_trace(
    mut direction: libc::c_int,
    mut ssl_ver: libc::c_int,
    mut content_type: libc::c_int,
    mut buf: *const libc::c_void,
    mut len: size_t,
    mut ssl: *mut SSL,
    mut userp: *mut libc::c_void,
) {
    let mut unknown: [libc::c_char; 32] = [0; 32];
    let mut verstr: *const libc::c_char = 0 as *const libc::c_char;
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut data: *mut Curl_easy = (*backend).logger;
    if conn.is_null() || data.is_null() || ((*data).set.fdebug).is_none()
        || direction != 0 as libc::c_int && direction != 1 as libc::c_int
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
            curl_msnprintf(
                unknown.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
                b"(%x)\0" as *const u8 as *const libc::c_char,
                ssl_ver,
            );
            verstr = unknown.as_mut_ptr();
        }
    }
    // DONE - 2168
    #[cfg(SSL3_RT_INNER_CONTENT_TYPE)]
    let SSL3_RT_INNER_CONTENT_TYPE_flag = content_type != 0x101;
    #[cfg(not(SSL3_RT_INNER_CONTENT_TYPE))]
    let SSL3_RT_INNER_CONTENT_TYPE_flag = true;
    if ssl_ver != 0 && SSL3_RT_INNER_CONTENT_TYPE_flag {
        let mut msg_name: *const libc::c_char = 0 as *const libc::c_char;
        let mut tls_rt_name: *const libc::c_char = 0 as *const libc::c_char;
        let mut ssl_buf: [libc::c_char; 1024] = [0; 1024];
        let mut msg_type: libc::c_int = 0;
        let mut txt_len: libc::c_int = 0;
        ssl_ver >>= 8 as libc::c_int;
        if ssl_ver == 0x3 as libc::c_int && content_type != 0 {
            tls_rt_name = tls_rt_type(content_type);
        } else {
            tls_rt_name = b"\0" as *const u8 as *const libc::c_char;
        }
        if content_type == 20 as libc::c_int {
            msg_type = *(buf as *mut libc::c_char) as libc::c_int;
            msg_name = b"Change cipher spec\0" as *const u8 as *const libc::c_char;
        } else if content_type == 21 as libc::c_int {
            msg_type = ((*(buf as *mut libc::c_char).offset(0 as libc::c_int as isize)
                as libc::c_int) << 8 as libc::c_int)
                + *(buf as *mut libc::c_char).offset(1 as libc::c_int as isize)
                    as libc::c_int;
            msg_name = SSL_alert_desc_string_long(msg_type);
        } else {
            msg_type = *(buf as *mut libc::c_char) as libc::c_int;
            msg_name = ssl_msg_type(ssl_ver, msg_type);
        }
        txt_len = curl_msnprintf(
            ssl_buf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
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
        );
        if 0 as libc::c_int <= txt_len
            && (txt_len as libc::c_uint as libc::c_ulong)
                < ::std::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong
        {
            Curl_debug(data, CURLINFO_TEXT, ssl_buf.as_mut_ptr(), txt_len as size_t);
        }
    }
    Curl_debug(
        data,
        (if direction == 1 as libc::c_int {
            CURLINFO_SSL_DATA_OUT as libc::c_int
        } else {
            CURLINFO_SSL_DATA_IN as libc::c_int
        }) as curl_infotype,
        buf as *mut libc::c_char,
        len,
    );
}

#[cfg(all(USE_OPENSSL, HAS_NPN))]
unsafe extern "C" fn select_next_protocol(
    mut out: *mut *mut libc::c_uchar,
    mut outlen: *mut libc::c_uchar,
    mut in_0: *const libc::c_uchar,
    mut inlen: libc::c_uint,
    mut key: *const libc::c_char,
    mut keylen: libc::c_uint,
) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i.wrapping_add(keylen) <= inlen {
        if memcmp(
            &*in_0.offset(i.wrapping_add(1 as libc::c_int as libc::c_uint) as isize)
                as *const libc::c_uchar as *const libc::c_void,
            key as *const libc::c_void,
            keylen as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            *out = &*in_0
                .offset(i.wrapping_add(1 as libc::c_int as libc::c_uint) as isize)
                as *const libc::c_uchar as *mut libc::c_uchar;
            *outlen = *in_0.offset(i as isize);
            return 0 as libc::c_int;
        }
        i = i
            .wrapping_add(
                (*in_0.offset(i as isize) as libc::c_int + 1 as libc::c_int)
                    as libc::c_uint,
            );
    }
    return -(1 as libc::c_int);
}
#[cfg(all(USE_OPENSSL, HAS_NPN))]
unsafe extern "C" fn select_next_proto_cb(
    mut ssl: *mut SSL,
    mut out: *mut *mut libc::c_uchar,
    mut outlen: *mut libc::c_uchar,
    mut in_0: *const libc::c_uchar,
    mut inlen: libc::c_uint,
    mut arg: *mut libc::c_void,
) -> libc::c_int {
    let mut data: *mut Curl_easy = arg as *mut Curl_easy;
    let mut conn: *mut connectdata = (*data).conn;
    #[cfg(USE_HTTP2)]
    if (*data).state.httpwant as libc::c_int >= CURL_HTTP_VERSION_2_0 as libc::c_int
        && select_next_protocol(
            out,
            outlen,
            in_0,
            inlen,
            b"h2\0" as *const u8 as *const libc::c_char,
            2 as libc::c_int as libc::c_uint,
        ) == 0
    {
        Curl_infof(
            data,
            b"NPN, negotiated HTTP2 (%s)\0" as *const u8 as *const libc::c_char,
            b"h2\0" as *const u8 as *const libc::c_char,
        );
        (*conn).negnpn = CURL_HTTP_VERSION_2_0 as libc::c_int;
        return 0 as libc::c_int;
    }
    if select_next_protocol(
        out,
        outlen,
        in_0,
        inlen,
        b"http/1.1\0" as *const u8 as *const libc::c_char,
        8 as libc::c_int as libc::c_uint,
    ) == 0
    {
        Curl_infof(
            data,
            b"NPN, negotiated HTTP1.1\0" as *const u8 as *const libc::c_char,
        );
        (*conn).negnpn = CURL_HTTP_VERSION_1_1 as libc::c_int;
        return 0 as libc::c_int;
    }
    Curl_infof(
        data,
        b"NPN, no overlap, use HTTP1.1\0" as *const u8 as *const libc::c_char,
    );
    *out = b"http/1.1\0" as *const u8 as *const libc::c_char as *mut libc::c_uchar;
    *outlen = 8 as libc::c_int as libc::c_uchar;
    (*conn).negnpn = CURL_HTTP_VERSION_1_1 as libc::c_int;
    return 0 as libc::c_int;
}
// TODO
// USE_OPENSSL以及与OPENSSL_VERSION_NUMBER相关的条件编译
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn set_ssl_version_min_max(
    mut ctx: *mut SSL_CTX,
    mut conn: *mut connectdata,
) -> CURLcode {
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut curl_ssl_version_min: libc::c_long = if CURLPROXY_HTTPS as libc::c_int
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
        (*conn).proxy_ssl_config.version
    } else {
        (*conn).ssl_config.version
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut curl_ssl_version_min: libc::c_long = (*conn).ssl_config.version;


    let mut curl_ssl_version_max: libc::c_long = 0;
    // TODO - 2307
    // #[cfg(any(OPENSSL_IS_BORINGSSL, LIBRESSL_VERSION_NUMBER))]
    // TODO - 2307
    // #[cfg(any(OPENSSL_IS_BORINGSSL, LIBRESSL_VERSION_NUMBER))]
    #[cfg(all(not(OPENSSL_IS_BORINGSSL), not(LIBRESSL_VERSION_NUMBER)))]
    let mut ossl_ssl_version_min: libc::c_long = 0 as libc::c_int as libc::c_long;
    #[cfg(all(not(OPENSSL_IS_BORINGSSL), not(LIBRESSL_VERSION_NUMBER)))]
    let mut ossl_ssl_version_max: libc::c_long = 0 as libc::c_int as libc::c_long;
    match curl_ssl_version_min {
        1 | 4 => {
            ossl_ssl_version_min = 0x301 as libc::c_int as libc::c_long;
        }
        5 => {
            ossl_ssl_version_min = 0x302 as libc::c_int as libc::c_long;
        }
        6 => {
            ossl_ssl_version_min = 0x303 as libc::c_int as libc::c_long;
        }
        #[cfg(TLS1_3_VERSION)]
        7 => {
            ossl_ssl_version_min = 0x304 as libc::c_int as libc::c_long;
        }
        _ => {}
    }
    if curl_ssl_version_min != CURL_SSLVERSION_DEFAULT as libc::c_int as libc::c_long {
        if SSL_CTX_ctrl(
            ctx,
            123 as libc::c_int,
            ossl_ssl_version_min,
            0 as *mut libc::c_void,
        ) == 0
        {
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_version_max = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                        (*conn).proxy_ssl_config.version_max
                                    } else {
                                        (*conn).ssl_config.version_max
                                    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_version_max = (*conn).ssl_config.version_max;

    curl_ssl_version_max = SSL_CONN_CONFIG_version_max;
    let mut current_block_15: u64;
    match curl_ssl_version_max {
        262144 => {
            ossl_ssl_version_max = 0x301 as libc::c_int as libc::c_long;
            current_block_15 = 18386322304582297246;
        }
        327680 => {
            ossl_ssl_version_max = 0x302 as libc::c_int as libc::c_long;
            current_block_15 = 18386322304582297246;
        }
        393216 => {
            ossl_ssl_version_max = 0x303 as libc::c_int as libc::c_long;
            current_block_15 = 18386322304582297246;
        }
        #[cfg(TLS1_3_VERSION)]
        458752 => {
            ossl_ssl_version_max = 0x304 as libc::c_int as libc::c_long;
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
            ossl_ssl_version_max = 0 as libc::c_int as libc::c_long;
        }
        _ => {}
    }
    if SSL_CTX_ctrl(
        ctx,
        124 as libc::c_int,
        ossl_ssl_version_max,
        0 as *mut libc::c_void,
    ) == 0
    {
        return CURLE_SSL_CONNECT_ERROR;
    }
    return CURLE_OK;
}

// TODO 这里有个与OPENSSL_VERSION_NUMBER相关的条件编译
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_new_session_cb(
    mut ssl: *mut SSL,
    mut ssl_sessionid: *mut SSL_SESSION,
) -> libc::c_int {
    let mut res: libc::c_int = 0 as libc::c_int;
    let mut conn: *mut connectdata = 0 as *mut connectdata;
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut sockindex: libc::c_int = 0;
    let mut sockindex_ptr: *mut curl_socket_t = 0 as *mut curl_socket_t;
    let mut data_idx: libc::c_int = ossl_get_ssl_data_index();
    let mut connectdata_idx: libc::c_int = ossl_get_ssl_conn_index();
    let mut sockindex_idx: libc::c_int = ossl_get_ssl_sockindex_index();
    let mut proxy_idx: libc::c_int = ossl_get_proxy_index();
    let mut isproxy: bool = false;
    if data_idx < 0 as libc::c_int || connectdata_idx < 0 as libc::c_int
        || sockindex_idx < 0 as libc::c_int || proxy_idx < 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    conn = SSL_get_ex_data(ssl, connectdata_idx) as *mut connectdata;
    if conn.is_null() {
        return 0 as libc::c_int;
    }
    data = SSL_get_ex_data(ssl, data_idx) as *mut Curl_easy;
    sockindex_ptr = SSL_get_ex_data(ssl, sockindex_idx) as *mut curl_socket_t;
    sockindex = sockindex_ptr.offset_from(((*conn).sock).as_mut_ptr()) as libc::c_long
        as libc::c_int;
    isproxy = if !(SSL_get_ex_data(ssl, proxy_idx)).is_null() {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    } != 0;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                        };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_sessionid = ((*data).set.ssl.primary).sessionid();
    if SSL_SET_OPTION_primary_sessionid != 0
    {
        let mut incache: bool = false;
        let mut old_ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
        Curl_ssl_sessionid_lock(data);
        if isproxy {
            incache = 0 as libc::c_int != 0;
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
                Curl_infof(
                    data,
                    b"old SSL session ID is stale, removing\0" as *const u8
                        as *const libc::c_char,
                );
                Curl_ssl_delsessionid(data, old_ssl_sessionid);
                incache = 0 as libc::c_int != 0;
            }
        }
        if !incache {
            if Curl_ssl_addsessionid(
                data,
                conn,
                isproxy,
                ssl_sessionid as *mut libc::c_void,
                0 as libc::c_int as size_t,
                sockindex,
            ) as u64 == 0
            {
                res = 1 as libc::c_int;
            } else {
                Curl_failf(
                    data,
                    b"failed to store ssl session\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        Curl_ssl_sessionid_unlock(data);
    }
    return res;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn load_cacert_from_memory(
    mut ctx: *mut SSL_CTX,
    mut ca_info_blob: *const curl_blob,
) -> CURLcode {
    let mut cbio: *mut BIO = 0 as *mut BIO;
    let mut inf: *mut stack_st_X509_INFO = 0 as *mut stack_st_X509_INFO;
    let mut i: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    let mut cts: *mut X509_STORE = 0 as *mut X509_STORE;
    let mut itmp: *mut X509_INFO = 0 as *mut X509_INFO;
    if (*ca_info_blob).len > 2147483647 as libc::c_int as size_t {
        return CURLE_SSL_CACERT_BADFILE;
    }
    cts = SSL_CTX_get_cert_store(ctx);
    if cts.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    cbio = BIO_new_mem_buf((*ca_info_blob).data, (*ca_info_blob).len as libc::c_int);
    if cbio.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    inf = PEM_X509_INFO_read_bio(
        cbio,
        0 as *mut stack_st_X509_INFO,
        None,
        0 as *mut libc::c_void,
    );
    if inf.is_null() {
        BIO_free(cbio);
        return CURLE_SSL_CACERT_BADFILE;
    }
    i = 0 as libc::c_int;
    while i < sk_X509_INFO_num(inf) {
        itmp = sk_X509_INFO_value(inf, i);
        if !((*itmp).x509).is_null() {
            if X509_STORE_add_cert(cts, (*itmp).x509) != 0 {
                count += 1;
            } else {
                count = 0 as libc::c_int;
                break;
            }
        }
        if !((*itmp).crl).is_null() {
            if X509_STORE_add_crl(cts, (*itmp).crl) != 0 {
                count += 1;
            } else {
                count = 0 as libc::c_int;
                break;
            }
        }
        i += 1;
    }
    sk_X509_INFO_pop_free(
        inf,
        Some(X509_INFO_free as unsafe extern "C" fn(*mut X509_INFO) -> ()),
    );
    BIO_free(cbio);
    return (if count > 0 as libc::c_int {
        CURLE_OK as libc::c_int
    } else {
        CURLE_SSL_CACERT_BADFILE as libc::c_int
    }) as CURLcode;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    // let mut result: CURLcode = CURLE_OK;
    // let mut ciphers: *mut libc::c_char = 0 as *mut libc::c_char;
    // let mut req_method: *const SSL_METHOD = 0 as *const SSL_METHOD;
    // let mut lookup: *mut X509_LOOKUP = 0 as *mut X509_LOOKUP;
    // let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
    // let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
    //     .as_mut_ptr()
    //     .offset(sockindex as isize) as *mut ssl_connect_data;
    // let mut ctx_options: ctx_option_t = 0 as libc::c_int as ctx_option_t;
    // let mut ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
    // #[cfg(SSL_CTRL_SET_TLSEXT_HOSTNAME)]
    // let mut sni: bool = false;
    // #[cfg(all(SSL_CTRL_SET_TLSEXT_HOSTNAME, not(CURL_DISABLE_PROXY)))]
    // let hostname: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //     == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     (*conn).http_proxy.host.name
    // } else {
    //     (*conn).host.name
    // };
    // #[cfg(all(SSL_CTRL_SET_TLSEXT_HOSTNAME, CURL_DISABLE_PROXY))]
    // let hostname: *const libc::c_char = (*conn).host.name;
    // #[cfg(all(SSL_CTRL_SET_TLSEXT_HOSTNAME, ENABLE_IPV6))]
    // let mut addr: in6_addr = in6_addr {
    //     __in6_u: C2RustUnnamed_10 {
    //         __u6_addr8: [0; 16],
    //     },
    // };
    // #[cfg(all(SSL_CTRL_SET_TLSEXT_HOSTNAME, not(ENABLE_IPV6)))]
    // let mut addr: in_addr = in_addr { s_addr: 0 };
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let ssl_version: libc::c_long = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //     == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     (*conn).proxy_ssl_config.version
    // } else {
    //     (*conn).ssl_config.version
    // };
    // #[cfg(CURL_DISABLE_PROXY)]
    // let ssl_version: libc::c_long = (*conn).ssl_config.version;
    // #[cfg(all(USE_OPENSSL_SRP, not(CURL_DISABLE_PROXY)))]
    // let ssl_authtype: CURL_TLSAUTH = (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //     == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     (*data).set.proxy_ssl.authtype as libc::c_uint
    // } else {
    //     (*data).set.ssl.authtype as libc::c_uint
    // }) as CURL_TLSAUTH;
    // #[cfg(all(USE_OPENSSL_SRP, CURL_DISABLE_PROXY))]
    // let ssl_authtype: CURL_TLSAUTH = (*data).set.ssl.authtype;
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let ssl_cert: *mut libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //     == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     (*data).set.proxy_ssl.primary.clientcert
    // } else {
    //     (*data).set.ssl.primary.clientcert
    // };
    // #[cfg(CURL_DISABLE_PROXY)]
    // let ssl_cert: *mut libc::c_char = (*data).set.ssl.primary.clientcert;
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let mut ssl_cert_blob: *const curl_blob = if CURLPROXY_HTTPS as libc::c_int
    //     as libc::c_uint == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     (*data).set.proxy_ssl.primary.cert_blob
    // } else {
    //     (*data).set.ssl.primary.cert_blob
    // };
    // #[cfg(CURL_DISABLE_PROXY)]
    // let mut ssl_cert_blob: *const curl_blob = (*data).set.ssl.primary.cert_blob;
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let mut ca_info_blob: *const curl_blob = if CURLPROXY_HTTPS as libc::c_int
    //     as libc::c_uint == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     (*conn).proxy_ssl_config.ca_info_blob
    // } else {
    //     (*conn).ssl_config.ca_info_blob
    // };
    // #[cfg(CURL_DISABLE_PROXY)]
    // let mut ca_info_blob: *const curl_blob = (*conn).ssl_config.ca_info_blob;
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let ssl_cert_type: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int
    //     as libc::c_uint == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     (*data).set.proxy_ssl.cert_type
    // } else {
    //     (*data).set.ssl.cert_type
    // };
    // #[cfg(CURL_DISABLE_PROXY)]
    // let ssl_cert_type: *const libc::c_char = (*data).set.ssl.cert_type;
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let ssl_cafile: *const libc::c_char = if !ca_info_blob.is_null() {
    //     0 as *mut libc::c_char
    // } else if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //         == (*conn).http_proxy.proxytype as libc::c_uint
    //         && ssl_connection_complete as libc::c_int as libc::c_uint
    //             != (*conn)
    //                 .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                     == -(1 as libc::c_int)
    //                 {
    //                     0 as libc::c_int
    //                 } else {
    //                     1 as libc::c_int
    //                 }) as usize]
    //                 .state as libc::c_uint
    //     {
    //     (*conn).proxy_ssl_config.CAfile
    // } else {
    //     (*conn).ssl_config.CAfile
    // };
    // #[cfg(CURL_DISABLE_PROXY)]
    // let ssl_cafile: *const libc::c_char = if !ca_info_blob.is_null() {
    //     0 as *mut libc::c_char
    // } else {
    //     (*conn).ssl_config.CAfile
    // };
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let ssl_capath: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int
    //     as libc::c_uint == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     (*conn).proxy_ssl_config.CApath
    // } else {
    //     (*conn).ssl_config.CApath
    // };
    // #[cfg(CURL_DISABLE_PROXY)]
    // let ssl_capath: *const libc::c_char = (*conn).ssl_config.CApath;
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let verifypeer: bool = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //     == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     ((*conn).proxy_ssl_config).verifypeer() as libc::c_int
    // } else {
    //     ((*conn).ssl_config).verifypeer() as libc::c_int
    // } != 0;
    // #[cfg(CURL_DISABLE_PROXY)]
    // let verifypeer: bool = ((*conn).ssl_config).verifypeer() != 0;
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let ssl_crlfile: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int
    //     as libc::c_uint == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     (*data).set.proxy_ssl.CRLfile
    // } else {
    //     (*data).set.ssl.CRLfile
    // };
    // #[cfg(CURL_DISABLE_PROXY)]
    // let ssl_crlfile: *const libc::c_char = (*data).set.ssl.CRLfile;
    // let mut error_buffer: [libc::c_char; 256] = [0; 256];
    // let mut backend: *mut ssl_backend_data = (*connssl).backend;
    // let mut imported_native_ca: bool = 0 as libc::c_int != 0;
    // result = ossl_seed(data);
    // if result as u64 != 0 {
    //     return result;
    // }
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // if true {
    //     *if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //         == (*conn).http_proxy.proxytype as libc::c_uint
    //         && ssl_connection_complete as libc::c_int as libc::c_uint
    //             != (*conn)
    //                 .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                     == -(1 as libc::c_int)
    //                 {
    //                     0 as libc::c_int
    //                 } else {
    //                     1 as libc::c_int
    //                 }) as usize]
    //                 .state as libc::c_uint
    //     {
    //         &mut (*data).set.proxy_ssl.certverifyresult
    //     } else {
    //         &mut (*data).set.ssl.certverifyresult
    //     } = (0 as libc::c_int == 0) as libc::c_int as libc::c_long;
    // }
    // #[cfg(CURL_DISABLE_PROXY)]
    // if true {
    //     (*data)
    //         .set
    //         .ssl
    //         .certverifyresult = (0 as libc::c_int == 0) as libc::c_int as libc::c_long;
    // }
    // match ssl_version {
    //     0 | 1 | 4 | 5 | 6 | 7 => {
    //         req_method = TLS_client_method();          
    //         sni = 1 as libc::c_int != 0;
    //     }
    //     2 => {
    //         Curl_failf(data, b"No SSLv2 support\0" as *const u8 as *const libc::c_char);
    //         return CURLE_NOT_BUILT_IN;
    //     }
    //     3 => {
    //         Curl_failf(data, b"No SSLv3 support\0" as *const u8 as *const libc::c_char);
    //         return CURLE_NOT_BUILT_IN;
    //     }
    //     _ => {
    //         Curl_failf(
    //             data,
    //             b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8
    //                 as *const libc::c_char,
    //         );
    //         return CURLE_SSL_CONNECT_ERROR;
    //     }
    // }
    // let ref mut fresh8 = (*backend).ctx;
    // *fresh8 = SSL_CTX_new(req_method);
    // if ((*backend).ctx).is_null() {
    //     Curl_failf(
    //         data,
    //         b"SSL: couldn't create a context: %s\0" as *const u8 as *const libc::c_char,
    //         ossl_strerror(
    //             ERR_peek_error(),
    //             error_buffer.as_mut_ptr(),
    //             ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
    //         ),
    //     );
    //     return CURLE_OUT_OF_MEMORY;
    // }
    // #[cfg(SSL_MODE_RELEASE_BUFFERS)]
    // SSL_CTX_ctrl(
    //     (*backend).ctx,
    //     33 as libc::c_int,
    //     0x10 as libc::c_uint as libc::c_long,
    //     0 as *mut libc::c_void,
    // );
    // #[cfg(SSL_CTRL_SET_MSG_CALLBACK)]
    // if ((*data).set.fdebug).is_some() && ((*data).set).verbose() as libc::c_int != 0 {
    //     SSL_CTX_set_msg_callback(
    //         (*backend).ctx,
    //         Some(
    //             ossl_trace
    //                 as unsafe extern "C" fn(
    //                     libc::c_int,
    //                     libc::c_int,
    //                     libc::c_int,
    //                     *const libc::c_void,
    //                     size_t,
    //                     *mut SSL,
    //                     *mut libc::c_void,
    //                 ) -> (),
    //         ),
    //     );
    //     SSL_CTX_ctrl(
    //         (*backend).ctx,
    //         16 as libc::c_int,
    //         0 as libc::c_int as libc::c_long,
    //         conn as *mut libc::c_void,
    //     );
    //     let ref mut fresh9 = (*(*conn).ssl[0 as libc::c_int as usize].backend).logger;
    //     *fresh9 = data;
    // }
    // ctx_options = (0x80000000 as libc::c_uint | 0x800 as libc::c_uint
    //     | 0x4 as libc::c_uint | 0x10 as libc::c_uint | 0x40 as libc::c_uint)
    //     as ctx_option_t;
    // #[cfg(SSL_OP_NO_TICKET)]
    // if true {
    //     ctx_options |= 0x4000 as libc::c_uint as libc::c_long;
    // }
    // #[cfg(SSL_OP_NO_COMPRESSION)]
    // if true {
    //     ctx_options |= 0x20000 as libc::c_uint as libc::c_long;
    // } 
    // #[cfg(SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG)]
    // if true {
    //     ctx_options &= !(0 as libc::c_int) as libc::c_long;
    // }
    // #[cfg(all(SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS, not(CURL_DISABLE_PROXY)))]
    // if if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //                                     == (*conn).http_proxy.proxytype as libc::c_uint
    //                                     && ssl_connection_complete as libc::c_int as libc::c_uint
    //                                         != (*conn)
    //                                             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                                                 == -(1 as libc::c_int)
    //                                             {
    //                                                 0 as libc::c_int
    //                                             } else {
    //                                                 1 as libc::c_int
    //                                             }) as usize]
    //                                             .state as libc::c_uint
    //                                 {
    //                                     ((*data).set.proxy_ssl).enable_beast() as libc::c_int
    //                                 } else {
    //                                     ((*data).set.ssl).enable_beast() as libc::c_int
    //                                 } == 0{
    //     ctx_options &= !(0x800 as libc::c_uint) as libc::c_long;
    // }
    // #[cfg(all(SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS, CURL_DISABLE_PROXY))]
    // if ((*data).set.ssl).enable_beast() == 0 {
    //     ctx_options &= !(0x800 as libc::c_uint) as libc::c_long;
    // }
    // let mut current_block_41: u64;
    // match ssl_version {
    //     2 | 3 => return CURLE_NOT_BUILT_IN,
    //     0 | 1 => {
    //         current_block_41 = 17115951058795741266;
    //     }
    //     4 => {
    //         current_block_41 = 17115951058795741266;
    //     }
    //     5 => {
    //         current_block_41 = 9560911598671572930;
    //     }
    //     6 | 7 => {
    //         current_block_41 = 876631155094734048;
    //     }
    //     _ => {
    //         Curl_failf(
    //             data,
    //             b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8
    //                 as *const libc::c_char,
    //         );
    //         return CURLE_SSL_CONNECT_ERROR;
    //     }
    // }
    // match current_block_41 {
    //     17115951058795741266 => {
    //         current_block_41 = 9560911598671572930;
    //     }
    //     _ => {}
    // }
    // match current_block_41 {
    //     9560911598671572930 => {}
    //     _ => {}
    // }
    // ctx_options |= 0 as libc::c_int as libc::c_long;
    // ctx_options |= 0x2000000 as libc::c_uint as libc::c_long;
    // result = set_ssl_version_min_max((*backend).ctx, conn);
    // if result as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
    //     return result;
    // }
    // SSL_CTX_set_options((*backend).ctx, ctx_options as libc::c_ulong);
    let mut result: CURLcode = CURLE_OK;
    let mut ciphers: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut req_method: *const SSL_METHOD = 0 as *const SSL_METHOD;
    let mut lookup: *mut X509_LOOKUP = 0 as *mut X509_LOOKUP;
    let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut ctx_options: ctx_option_t = 0 as libc::c_int as ctx_option_t;
    let mut ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut sni: bool = false;
    let hostname: *const libc::c_char = (*conn).host.name;
    let mut addr: in_addr = in_addr { s_addr: 0 };
    let ssl_version: libc::c_long = (*conn).ssl_config.version;
    let ssl_authtype: CURL_TLSAUTH = (*data).set.ssl.authtype;
    let ssl_cert: *mut libc::c_char = (*data).set.ssl.primary.clientcert;
    let mut ssl_cert_blob: *const curl_blob = (*data).set.ssl.primary.cert_blob;
    let mut ca_info_blob: *const curl_blob = (*conn).ssl_config.ca_info_blob;
    let ssl_cert_type: *const libc::c_char = (*data).set.ssl.cert_type;
    let ssl_cafile: *const libc::c_char = if !ca_info_blob.is_null() {
        0 as *mut libc::c_char
    } else {
        (*conn).ssl_config.CAfile
    };
    let ssl_capath: *const libc::c_char = (*conn).ssl_config.CApath;
    let verifypeer: bool = ((*conn).ssl_config).verifypeer() != 0;
    let ssl_crlfile: *const libc::c_char = (*data).set.ssl.CRLfile;
    let mut error_buffer: [libc::c_char; 256] = [0; 256];
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut imported_native_ca: bool = 0 as libc::c_int != 0;
    result = ossl_seed(data);
    if result as u64 != 0 {
        return result;
    }
    (*data)
        .set
        .ssl
        .certverifyresult = (0 as libc::c_int == 0) as libc::c_int as libc::c_long;
    match ssl_version {
        0 | 1 | 4 | 5 | 6 | 7 => {
            req_method = TLS_client_method();
            sni = 1 as libc::c_int != 0;
        }
        2 => {
            Curl_failf(data, b"No SSLv2 support\0" as *const u8 as *const libc::c_char);
            return CURLE_NOT_BUILT_IN;
        }
        3 => {
            Curl_failf(data, b"No SSLv3 support\0" as *const u8 as *const libc::c_char);
            return CURLE_NOT_BUILT_IN;
        }
        _ => {
            Curl_failf(
                data,
                b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8
                    as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    let ref mut fresh8 = (*backend).ctx;
    *fresh8 = SSL_CTX_new(req_method);
    if ((*backend).ctx).is_null() {
        Curl_failf(
            data,
            b"SSL: couldn't create a context: %s\0" as *const u8 as *const libc::c_char,
            ossl_strerror(
                ERR_peek_error(),
                error_buffer.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            ),
        );
        return CURLE_OUT_OF_MEMORY;
    }
    SSL_CTX_ctrl(
        (*backend).ctx,
        33 as libc::c_int,
        0x10 as libc::c_uint as libc::c_long,
        0 as *mut libc::c_void,
    );
    if ((*data).set.fdebug).is_some() && ((*data).set).verbose() as libc::c_int != 0 {
        SSL_CTX_set_msg_callback(
            (*backend).ctx,
            Some(
                ossl_trace
                    as unsafe extern "C" fn(
                        libc::c_int,
                        libc::c_int,
                        libc::c_int,
                        *const libc::c_void,
                        size_t,
                        *mut SSL,
                        *mut libc::c_void,
                    ) -> (),
            ),
        );
        SSL_CTX_ctrl(
            (*backend).ctx,
            16 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            conn as *mut libc::c_void,
        );
        let ref mut fresh9 = (*(*conn).ssl[0 as libc::c_int as usize].backend).logger;
        *fresh9 = data;
    }
    ctx_options = (0x80000000 as libc::c_uint | 0x800 as libc::c_uint
        | 0x4 as libc::c_uint | 0x10 as libc::c_uint | 0x40 as libc::c_uint)
        as ctx_option_t;
    ctx_options |= 0x4000 as libc::c_uint as libc::c_long;
    ctx_options |= 0x20000 as libc::c_uint as libc::c_long;
    ctx_options &= !(0 as libc::c_int) as libc::c_long;
    if ((*data).set.ssl).enable_beast() == 0 {
        ctx_options &= !(0x800 as libc::c_uint) as libc::c_long;
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
            Curl_failf(
                data,
                b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8
                    as *const libc::c_char,
            );
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
    ctx_options |= 0 as libc::c_int as libc::c_long;
    ctx_options |= 0x2000000 as libc::c_uint as libc::c_long;
    result = set_ssl_version_min_max((*backend).ctx, conn);
    if result as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
        return result;
    }
    SSL_CTX_set_options((*backend).ctx, ctx_options as libc::c_ulong);



    
// ************************************************************************
    #[cfg(HAS_NPN)]
    if ((*conn).bits).tls_enable_npn() != 0 {
        SSL_CTX_set_next_proto_select_cb(
            (*backend).ctx,
            Some(
                select_next_proto_cb
                    as unsafe extern "C" fn(
                        *mut SSL,
                        *mut *mut libc::c_uchar,
                        *mut libc::c_uchar,
                        *const libc::c_uchar,
                        libc::c_uint,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            data as *mut libc::c_void,
        );
    }
    #[cfg(HAS_APLN)]
    if ((*conn).bits).tls_enable_alpn() != 0 {
        let mut cur: libc::c_int = 0 as libc::c_int;
        let mut protocols: [libc::c_uchar; 128] = [0; 128];
        if cfg!(USE_HTTP2){
            #[cfg(not(CURL_DISABLE_PROXY))]
            let CURL_DISABLE_PROXY_flag_1 =  (!(CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
            let CURL_DISABLE_PROXY_flag_1 = true;                         
            if (*data).state.httpwant as libc::c_int >= CURL_HTTP_VERSION_2_0 as libc::c_int
            && CURL_DISABLE_PROXY_flag_1
            {
                let fresh10 = cur;
                cur = cur + 1;
                protocols[fresh10 as usize] = 2 as libc::c_int as libc::c_uchar;
                memcpy(
                    &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut libc::c_uchar
                        as *mut libc::c_void,
                    b"h2\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    2 as libc::c_int as libc::c_ulong,
                );
                cur += 2 as libc::c_int;
                Curl_infof(
                    data,
                    b"ALPN, offering %s\0" as *const u8 as *const libc::c_char,
                    b"h2\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        let fresh11 = cur;
        cur = cur + 1;
        protocols[fresh11 as usize] = 8 as libc::c_int as libc::c_uchar;
        memcpy(
            &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut libc::c_uchar
                as *mut libc::c_void,
            b"http/1.1\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            8 as libc::c_int as libc::c_ulong,
        );
        cur += 8 as libc::c_int;
        Curl_infof(
            data,
            b"ALPN, offering %s\0" as *const u8 as *const libc::c_char,
            b"http/1.1\0" as *const u8 as *const libc::c_char,
        );
        if SSL_CTX_set_alpn_protos(
            (*backend).ctx,
            protocols.as_mut_ptr(),
            cur as libc::c_uint,
        ) != 0
        {
            Curl_failf(
                data,
                b"Error setting ALPN\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
   
    if !ssl_cert.is_null() || !ssl_cert_blob.is_null() || !ssl_cert_type.is_null() {
        #[cfg(not(CURL_DISABLE_PROXY))]
        let cert_stuff_flag = cert_stuff(
                                data,
                                (*backend).ctx,
                                ssl_cert,
                                ssl_cert_blob,
                                ssl_cert_type,
                                (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                    (*data).set.proxy_ssl.key
                                } else {
                                    (*data).set.ssl.key
                                }),
                                (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                    (*data).set.proxy_ssl.key_blob
                                } else {
                                    (*data).set.ssl.key_blob
                                }),
                                (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                    (*data).set.proxy_ssl.key_type
                                } else {
                                    (*data).set.ssl.key_type
                                }),
                                (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
        if result as u64 == 0
           && cert_stuff_flag == 0
        {
            result = CURLE_SSL_CERTPROBLEM;
        }
        if result as u64 != 0 {
            return result;
        }
    }
   
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_cipher_list = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                        (*conn).proxy_ssl_config.cipher_list
                                    } else {
                                        (*conn).ssl_config.cipher_list
                                    };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_cipher_list = (*conn).ssl_config.cipher_list;
    ciphers = SSL_CONN_CONFIG_cipher_list;
    if ciphers.is_null() {
        ciphers = 0 as *mut libc::c_void as *mut libc::c_char;
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
    let mut ciphers13: *mut libc::c_char = if CURLPROXY_HTTPS as libc::c_int
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
    #[cfg(HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH)]
    SSL_CTX_set_post_handshake_auth((*backend).ctx, 1 as libc::c_int);
    #[cfg(all(HAVE_SSL_CTX_SET_EC_CURVES, not(CURL_DISABLE_PROXY)))]
    let mut curves: *mut libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
            92 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            curves as *mut libc::c_void,
        ) == 0
        {
            Curl_failf(
                data,
                b"failed setting curves list: '%s'\0" as *const u8
                    as *const libc::c_char,
                curves,
            );
            return CURLE_SSL_CIPHER;
        }
    }
    // #[cfg(USE_OPENSSL_SRP)]
    if ssl_authtype as libc::c_uint == CURL_TLSAUTH_SRP as libc::c_int as libc::c_uint 
    {
        #[cfg(not(CURL_DISABLE_PROXY))]
        let ssl_username: *mut libc::c_char = if CURLPROXY_HTTPS as libc::c_int
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
            (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
        if if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
            (*conn).proxy_ssl_config.cipher_list
        } else {
            (*conn).ssl_config.cipher_list
        }.is_null() {
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
                    b"failed setting SRP cipher list\0" as *const u8
                        as *const libc::c_char,
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
                    b"failed setting SRP cipher list\0" as *const u8
                        as *const libc::c_char,
                );
                return CURLE_SSL_CIPHER;
            }
        }
    }
    if !ca_info_blob.is_null() {
        result = load_cacert_from_memory((*backend).ctx, ca_info_blob);
        if result as u64 != 0 {
            if result as libc::c_uint
                == CURLE_OUT_OF_MEMORY as libc::c_int as libc::c_uint
                || verifypeer as libc::c_int != 0 && !imported_native_ca
            {
                Curl_failf(
                    data,
                    b"error importing CA certificate blob\0" as *const u8
                        as *const libc::c_char,
                );
                return result;
            }
            Curl_infof(
                data,
                b"error importing CA certificate blob, continuing anyway\0" as *const u8
                    as *const libc::c_char,
            );
        }
    }
    if !ssl_cafile.is_null() || !ssl_capath.is_null() {
        if SSL_CTX_load_verify_locations((*backend).ctx, ssl_cafile, ssl_capath) == 0 {
            if verifypeer as libc::c_int != 0 && !imported_native_ca {
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
                return CURLE_SSL_CACERT_BADFILE;
            }
            Curl_infof(
                data,
                b"error setting certificate verify locations, continuing anyway:\0"
                    as *const u8 as *const libc::c_char,
            );
        } else {
            Curl_infof(
                data,
                b"successfully set certificate verify locations:\0" as *const u8
                    as *const libc::c_char,
            );
        }
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

// ******************************************************************
    // if !ssl_crlfile.is_null() {
    //     lookup = X509_STORE_add_lookup(
    //         SSL_CTX_get_cert_store((*backend).ctx),
    //         X509_LOOKUP_file(),
    //     );
    //     if lookup.is_null()
    //         || X509_load_crl_file(lookup, ssl_crlfile, 1 as libc::c_int) == 0
    //     {
    //         Curl_failf(
    //             data,
    //             b"error loading CRL file: %s\0" as *const u8 as *const libc::c_char,
    //             ssl_crlfile,
    //         );
    //         return CURLE_SSL_CRL_BADFILE;
    //     }
    //     Curl_infof(
    //         data,
    //         b"successfully loaded CRL file:\0" as *const u8 as *const libc::c_char,
    //     );
    //     X509_STORE_set_flags(
    //         SSL_CTX_get_cert_store((*backend).ctx),
    //         (0x4 as libc::c_int | 0x8 as libc::c_int) as libc::c_ulong,
    //     );
    //     Curl_infof(
    //         data,
    //         b"  CRLfile: %s\0" as *const u8 as *const libc::c_char,
    //         ssl_crlfile,
    //     );
    // }
    // if verifypeer {
    //     #[cfg(X509_V_FLAG_TRUSTED_FIRST)]
    //     X509_STORE_set_flags(
    //         SSL_CTX_get_cert_store((*backend).ctx),
    //         0x8000 as libc::c_int as libc::c_ulong,
    //     );
    //     #[cfg(all(X509_V_FLAG_PARTIAL_CHAIN, not(CURL_DISABLE_PROXY)))]
    //     let SSL_SET_OPTION_no_partialchain = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //                                         == (*conn).http_proxy.proxytype as libc::c_uint
    //                                         && ssl_connection_complete as libc::c_int as libc::c_uint
    //                                             != (*conn)
    //                                                 .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                                                     == -(1 as libc::c_int)
    //                                                 {
    //                                                     0 as libc::c_int
    //                                                 } else {
    //                                                     1 as libc::c_int
    //                                                 }) as usize]
    //                                                 .state as libc::c_uint
    //                                     {
    //                                         ((*data).set.proxy_ssl).no_partialchain() as libc::c_int
    //                                     } else {
    //                                         ((*data).set.ssl).no_partialchain() as libc::c_int
    //                                     };
    //     #[cfg(all(X509_V_FLAG_PARTIAL_CHAIN, CURL_DISABLE_PROXY))]
    //     let SSL_SET_OPTION_no_partialchain = ((*data).set.ssl).no_partialchain();
    //     #[cfg(X509_V_FLAG_PARTIAL_CHAIN)]
    //     if SSL_SET_OPTION_no_partialchain == 0 && ssl_crlfile.is_null()
    //     {
    //         X509_STORE_set_flags(
    //             SSL_CTX_get_cert_store((*backend).ctx),
    //             0x80000 as libc::c_int as libc::c_ulong,
    //         );
    //     }
    // }
    // SSL_CTX_set_verify(
    //     (*backend).ctx,
    //     if verifypeer as libc::c_int != 0 {
    //         0x1 as libc::c_int
    //     } else {
    //         0 as libc::c_int
    //     },
    //     None,
    // );
    // #[cfg(HAVE_KEYLOG_CALLBACK)]
    // if Curl_tls_keylog_enabled() {
    //     SSL_CTX_set_keylog_callback(
    //         (*backend).ctx,
    //         Some(
    //             ossl_keylog_callback
    //                 as unsafe extern "C" fn(*const SSL, *const libc::c_char) -> (),
    //         ),
    //     );
    // }
    // SSL_CTX_ctrl(
    //     (*backend).ctx,
    //     44 as libc::c_int,
    //     (0x1 as libc::c_int | (0x100 as libc::c_int | 0x200 as libc::c_int))
    //         as libc::c_long,
    //     0 as *mut libc::c_void,
    // );
    // SSL_CTX_sess_set_new_cb(
    //     (*backend).ctx,
    //     Some(
    //         ossl_new_session_cb
    //             as unsafe extern "C" fn(*mut SSL, *mut SSL_SESSION) -> libc::c_int,
    //     ),
    // );
    // if ((*data).set.ssl.fsslctx).is_some() {
    //     Curl_set_in_callback(data, 1 as libc::c_int != 0);
    //     result = (Some(((*data).set.ssl.fsslctx).expect("non-null function pointer")))
    //         .expect(
    //             "non-null function pointer",
    //         )(data, (*backend).ctx as *mut libc::c_void, (*data).set.ssl.fsslctxp);
    //     Curl_set_in_callback(data, 0 as libc::c_int != 0);
    //     if result as u64 != 0 {
    //         Curl_failf(
    //             data,
    //             b"error signaled by ssl ctx callback\0" as *const u8
    //                 as *const libc::c_char,
    //         );
    //         return result;
    //     }
    // }
    // if !((*backend).handle).is_null() {
    //     SSL_free((*backend).handle);
    // }
    // let ref mut fresh12 = (*backend).handle;
    // *fresh12 = SSL_new((*backend).ctx);
    // if ((*backend).handle).is_null() {
    //     Curl_failf(
    //         data,
    //         b"SSL: couldn't create a context (handle)!\0" as *const u8
    //             as *const libc::c_char,
    //     );
    //     return CURLE_OUT_OF_MEMORY;
    // }
    // #[cfg(all(not(OPENSSL_NO_OCSP), not(OPENSSL_NO_TLSEXT), not(CURL_DISABLE_PROXY)))]
    // if if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //     == (*conn).http_proxy.proxytype as libc::c_uint
    //     && ssl_connection_complete as libc::c_int as libc::c_uint
    //         != (*conn)
    //             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                 == -(1 as libc::c_int)
    //             {
    //                 0 as libc::c_int
    //             } else {
    //                 1 as libc::c_int
    //             }) as usize]
    //             .state as libc::c_uint
    // {
    //     ((*conn).proxy_ssl_config).verifystatus() as libc::c_int
    // } else {
    //     ((*conn).ssl_config).verifystatus() as libc::c_int
    // } != 0
    // {
    //     SSL_ctrl(
    //         (*backend).handle,
    //         65 as libc::c_int,
    //         1 as libc::c_int as libc::c_long,
    //         0 as *mut libc::c_void,
    //     );
    // }
    // #[cfg(all(not(OPENSSL_NO_OCSP), not(OPENSSL_NO_TLSEXT), CURL_DISABLE_PROXY))]
    // if ((*conn).ssl_config).verifystatus() != 0 {
    //     SSL_ctrl(
    //         (*backend).handle,
    //         65 as libc::c_int,
    //         1 as libc::c_int as libc::c_long,
    //         0 as *mut libc::c_void,
    //     );
    // }
    // // TODO - 3213
    // // #[cfg(all(OPENSSL_IS_BORINGSSL, ALLOW_RENEG))]
    // SSL_set_connect_state((*backend).handle);
    // let ref mut fresh13 = (*backend).server_cert;
    // *fresh13 = 0 as *mut X509;
    // #[cfg(all(SSL_CTRL_SET_TLSEXT_HOSTNAME, ENABLE_IPV6))]
    // let ENABLE_IPV6_b = 0 as libc::c_int
    //                     == inet_pton(
    //                         2 as libc::c_int,
    //                         hostname,
    //                         &mut addr as *mut in6_addr as *mut libc::c_void,
    //                     )
    //                     && 0 as libc::c_int == inet_pton(
    //                             10 as libc::c_int,
    //                             hostname,
    //                             &mut addr as *mut in6_addr as *mut libc::c_void,
    //                     ) 
    //                     && sni as libc::c_int != 0 ;
    // #[cfg(all(SSL_CTRL_SET_TLSEXT_HOSTNAME, not(ENABLE_IPV6)))]
    // let ENABLE_IPV6_b = 0 as libc::c_int
    //                     == inet_pton(
    //                         2 as libc::c_int,
    //                         hostname,
    //                         &mut addr as *mut in_addr as *mut libc::c_void,
    //                     ) && sni as libc::c_int != 0 ;
    // #[cfg(SSL_CTRL_SET_TLSEXT_HOSTNAME)]
    // if ENABLE_IPV6_b {
    //     let mut nlen: size_t = strlen(hostname);
    //     if nlen as libc::c_long >= (*data).set.buffer_size {
    //         return CURLE_SSL_CONNECT_ERROR;
    //     }
    //     Curl_strntolower((*data).state.buffer, hostname, nlen);
    //     *((*data).state.buffer).offset(nlen as isize) = 0 as libc::c_int as libc::c_char;
    //     if SSL_ctrl(
    //         (*backend).handle,
    //         55 as libc::c_int,
    //         0 as libc::c_int as libc::c_long,
    //         (*data).state.buffer as *mut libc::c_void,
    //     ) == 0
    //     {
    //         Curl_infof(
    //             data,
    //             b"WARNING: failed to configure server name indication (SNI) TLS extension\0"
    //                 as *const u8 as *const libc::c_char,
    //         );
    //     }
    // }
    if !ssl_crlfile.is_null() {
        lookup = X509_STORE_add_lookup(
            SSL_CTX_get_cert_store((*backend).ctx),
            X509_LOOKUP_file(),
        );
        if lookup.is_null()
            || X509_load_crl_file(lookup, ssl_crlfile, 1 as libc::c_int) == 0
        {
            Curl_failf(
                data,
                b"error loading CRL file: %s\0" as *const u8 as *const libc::c_char,
                ssl_crlfile,
            );
            return CURLE_SSL_CRL_BADFILE;
        }
        Curl_infof(
            data,
            b"successfully loaded CRL file:\0" as *const u8 as *const libc::c_char,
        );
        X509_STORE_set_flags(
            SSL_CTX_get_cert_store((*backend).ctx),
            (0x4 as libc::c_int | 0x8 as libc::c_int) as libc::c_ulong,
        );
        Curl_infof(
            data,
            b"  CRLfile: %s\0" as *const u8 as *const libc::c_char,
            ssl_crlfile,
        );
    }
    if verifypeer {
        X509_STORE_set_flags(
            SSL_CTX_get_cert_store((*backend).ctx),
            0x8000 as libc::c_int as libc::c_ulong,
        );
        if ((*data).set.ssl).no_partialchain() == 0 && ssl_crlfile.is_null() {
            X509_STORE_set_flags(
                SSL_CTX_get_cert_store((*backend).ctx),
                0x80000 as libc::c_int as libc::c_ulong,
            );
        }
    }
    SSL_CTX_set_verify(
        (*backend).ctx,
        if verifypeer as libc::c_int != 0 {
            0x1 as libc::c_int
        } else {
            0 as libc::c_int
        },
        None,
    );
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
        44 as libc::c_int,
        (0x1 as libc::c_int | (0x100 as libc::c_int | 0x200 as libc::c_int))
            as libc::c_long,
        0 as *mut libc::c_void,
    );
    SSL_CTX_sess_set_new_cb(
        (*backend).ctx,
        Some(
            ossl_new_session_cb
                as unsafe extern "C" fn(*mut SSL, *mut SSL_SESSION) -> libc::c_int,
        ),
    );
    if ((*data).set.ssl.fsslctx).is_some() {
        Curl_set_in_callback(data, 1 as libc::c_int != 0);
        result = (Some(((*data).set.ssl.fsslctx).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(data, (*backend).ctx as *mut libc::c_void, (*data).set.ssl.fsslctxp);
        Curl_set_in_callback(data, 0 as libc::c_int != 0);
        if result as u64 != 0 {
            Curl_failf(
                data,
                b"error signaled by ssl ctx callback\0" as *const u8
                    as *const libc::c_char,
            );
            return result;
        }
    }
    if !((*backend).handle).is_null() {
        SSL_free((*backend).handle);
    }
    let ref mut fresh12 = (*backend).handle;
    *fresh12 = SSL_new((*backend).ctx);
    if ((*backend).handle).is_null() {
        Curl_failf(
            data,
            b"SSL: couldn't create a context (handle)!\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_OUT_OF_MEMORY;
    }
    if ((*conn).ssl_config).verifystatus() != 0 {
        SSL_ctrl(
            (*backend).handle,
            65 as libc::c_int,
            1 as libc::c_int as libc::c_long,
            0 as *mut libc::c_void,
        );
    }
    SSL_set_connect_state((*backend).handle);
    let ref mut fresh13 = (*backend).server_cert;
    *fresh13 = 0 as *mut X509;
    if 0 as libc::c_int
        == inet_pton(
            2 as libc::c_int,
            hostname,
            &mut addr as *mut in_addr as *mut libc::c_void,
        ) && sni as libc::c_int != 0
    {
        let mut nlen: size_t = strlen(hostname);
        if nlen as libc::c_long >= (*data).set.buffer_size {
            return CURLE_SSL_CONNECT_ERROR;
        }
        Curl_strntolower((*data).state.buffer, hostname, nlen);
        *((*data).state.buffer).offset(nlen as isize) = 0 as libc::c_int as libc::c_char;
        if SSL_ctrl(
            (*backend).handle,
            55 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            (*data).state.buffer as *mut libc::c_void,
        ) == 0
        {
            Curl_infof(
                data,
                b"WARNING: failed to configure server name indication (SNI) TLS extension\0"
                    as *const u8 as *const libc::c_char,
            );
        }
    }
    
    // **********************************************************************
    // ossl_associate_connection(data, conn, sockindex);
    // Curl_ssl_sessionid_lock(data);
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // let SSL_IS_PROXY_void_1 = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
    //                             == (*conn).http_proxy.proxytype as libc::c_uint
    //                             && ssl_connection_complete as libc::c_int as libc::c_uint
    //                                 != (*conn)
    //                                     .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
    //                                         == -(1 as libc::c_int)
    //                                     {
    //                                         0 as libc::c_int
    //                                     } else {
    //                                         1 as libc::c_int
    //                                     }) as usize]
    //                                     .state as libc::c_uint
    //                         {
    //                             1 as libc::c_int
    //                         } else {
    //                             0 as libc::c_int
    //                         } != 0 ;
    // #[cfg(CURL_DISABLE_PROXY)]
    // let SSL_IS_PROXY_void_1 = if 0 as libc::c_int != 0 { 1 as libc::c_int } else { 0 as libc::c_int } != 0;
    // if !Curl_ssl_getsessionid(
    //     data,
    //     conn,
    //     SSL_IS_PROXY_void_1,
    //     &mut ssl_sessionid,
    //     0 as *mut size_t,
    //     sockindex,
    // ) {
    //     if SSL_set_session((*backend).handle, ssl_sessionid as *mut SSL_SESSION) == 0 {
    //         Curl_ssl_sessionid_unlock(data);
    //         Curl_failf(
    //             data,
    //             b"SSL: SSL_set_session failed: %s\0" as *const u8 as *const libc::c_char,
    //             ossl_strerror(
    //                 ERR_get_error(),
    //                 error_buffer.as_mut_ptr(),
    //                 ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
    //             ),
    //         );
    //         return CURLE_SSL_CONNECT_ERROR;
    //     }
    //     Curl_infof(
    //         data,
    //         b"SSL re-using session ID\0" as *const u8 as *const libc::c_char,
    //     );
    // }
    // Curl_ssl_sessionid_unlock(data);
    // // DONE - 3260
    // #[cfg(not(CURL_DISABLE_PROXY))]
    // if ((*conn).proxy_ssl[sockindex as usize]).use_0() != 0 {
    //     let bio: *mut BIO = BIO_new(BIO_f_ssl());
    //     let mut handle: *mut SSL = (*(*conn).proxy_ssl[sockindex as usize].backend)
    //         .handle;
    //     BIO_ctrl(
    //         bio,
    //         109 as libc::c_int,
    //         0 as libc::c_int as libc::c_long,
    //         handle as *mut libc::c_char as *mut libc::c_void,
    //     );
    //     SSL_set_bio((*backend).handle, bio, bio);
    // } else if SSL_set_fd((*backend).handle, sockfd) == 0 {
    //     Curl_failf(
    //         data,
    //         b"SSL: SSL_set_fd failed: %s\0" as *const u8 as *const libc::c_char,
    //         ossl_strerror(
    //             ERR_get_error(),
    //             error_buffer.as_mut_ptr(),
    //             ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
    //         ),
    //     );
    //     return CURLE_SSL_CONNECT_ERROR;
    // }
    
    // #[cfg(CURL_DISABLE_PROXY)]
    // if SSL_set_fd((*backend).handle, sockfd) == 0 {
    //     Curl_failf(
    //         data,
    //         b"SSL: SSL_set_fd failed: %s\0" as *const u8 as *const libc::c_char,
    //         ossl_strerror(
    //             ERR_get_error(),
    //             error_buffer.as_mut_ptr(),
    //             ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
    //         ),
    //     );
    //     return CURLE_SSL_CONNECT_ERROR;
    // }
    // (*connssl).connecting_state = ssl_connect_2;
    // return CURLE_OK;
    ossl_associate_connection(data, conn, sockindex);
    Curl_ssl_sessionid_lock(data);
    if !Curl_ssl_getsessionid(
        data,
        conn,
        if 0 as libc::c_int != 0 { 1 as libc::c_int } else { 0 as libc::c_int } != 0,
        &mut ssl_sessionid,
        0 as *mut size_t,
        sockindex,
    ) {
        if SSL_set_session((*backend).handle, ssl_sessionid as *mut SSL_SESSION) == 0 {
            Curl_ssl_sessionid_unlock(data);
            Curl_failf(
                data,
                b"SSL: SSL_set_session failed: %s\0" as *const u8 as *const libc::c_char,
                ossl_strerror(
                    ERR_get_error(),
                    error_buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                ),
            );
            return CURLE_SSL_CONNECT_ERROR;
        }
        Curl_infof(
            data,
            b"SSL re-using session ID\0" as *const u8 as *const libc::c_char,
        );
    }
    Curl_ssl_sessionid_unlock(data);
    if SSL_set_fd((*backend).handle, sockfd) == 0 {
        Curl_failf(
            data,
            b"SSL: SSL_set_fd failed: %s\0" as *const u8 as *const libc::c_char,
            ossl_strerror(
                ERR_get_error(),
                error_buffer.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            ),
        );
        return CURLE_SSL_CONNECT_ERROR;
    }
    (*connssl).connecting_state = ssl_connect_2;
    return CURLE_OK;

}


#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_connect_step2(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut err: libc::c_int = 0;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    ERR_clear_error();
    err = SSL_connect((*backend).handle);
    // TODO
    // #[cfg(HAVE_KEYLOG_CALLBACK)]
    if 1 as libc::c_int != err {
        let mut detail: libc::c_int = SSL_get_error((*backend).handle, err);
        if 2 as libc::c_int == detail {
            (*connssl).connecting_state = ssl_connect_2_reading;
            return CURLE_OK;
        }
        if 3 as libc::c_int == detail {
            (*connssl).connecting_state = ssl_connect_2_writing;
            return CURLE_OK;
        }
        // TODO if的条件编译
        #[cfg(SSL_ERROR_WANT_ASYNC)]
        let SSL_ERROR_WANT_ASYNC_flag_3 = true;
        #[cfg(not(SSL_ERROR_WANT_ASYNC))]
        let SSL_ERROR_WANT_ASYNC_flag_3 = false;
        if 9 as libc::c_int == detail 
           && SSL_ERROR_WANT_ASYNC_flag_3{
            (*connssl).connecting_state = ssl_connect_2;
            return CURLE_OK;
        } else {
            let mut errdetail: libc::c_ulong = 0;
            let mut error_buffer: [libc::c_char; 256] = *::std::mem::transmute::<
                &[u8; 256],
                &mut [libc::c_char; 256],
            >(
                b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            );
            let mut result: CURLcode = CURLE_OK;
            let mut lerr: libc::c_long = 0;
            let mut lib: libc::c_int = 0;
            let mut reason: libc::c_int = 0;
            (*connssl).connecting_state = ssl_connect_2;
            errdetail = ERR_get_error();
            lib = (errdetail >> 24 as libc::c_long
                & 0xff as libc::c_long as libc::c_ulong) as libc::c_int;
            reason = (errdetail & 0xfff as libc::c_long as libc::c_ulong) as libc::c_int;
            if lib == 20 as libc::c_int
                && (reason == 134 as libc::c_int || reason == 1045 as libc::c_int)
            {
                result = CURLE_PEER_FAILED_VERIFICATION;
                lerr = SSL_get_verify_result((*backend).handle);
                if lerr != 0 as libc::c_int as libc::c_long {
                    #[cfg(not(CURL_DISABLE_PROXY))]
                    if true {
                        *if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                            &mut (*data).set.proxy_ssl.certverifyresult
                        } else {
                            &mut (*data).set.ssl.certverifyresult
                        } = lerr;
                    }
                    #[cfg(CURL_DISABLE_PROXY)]
                    if true {
                        (*data).set.ssl.certverifyresult = lerr;  
                    }         
                    curl_msnprintf(
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        b"SSL certificate problem: %s\0" as *const u8
                            as *const libc::c_char,
                        X509_verify_cert_error_string(lerr),
                    );
                } else {
                    strcpy(
                        error_buffer.as_mut_ptr(),
                        b"SSL certificate verification failed\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                // else if的条件编译
            } else if lib == 20 as libc::c_int && reason == 1116 as libc::c_int {
                result = CURLE_SSL_CLIENTCERT;
                ossl_strerror(
                    errdetail,
                    error_buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                );
            } else {
                result = CURLE_SSL_CONNECT_ERROR;
                ossl_strerror(
                    errdetail,
                    error_buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                );
            }
            if CURLE_SSL_CONNECT_ERROR as libc::c_int as libc::c_uint
                == result as libc::c_uint
                && errdetail == 0 as libc::c_int as libc::c_ulong
            {
                #[cfg(not(CURL_DISABLE_PROXY))]
                let hostname: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int
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
                let hostname: *const libc::c_char = (*conn).host.name;
                #[cfg(not(CURL_DISABLE_PROXY))]
                let port: libc::c_long = (if CURLPROXY_HTTPS as libc::c_int
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
                    (*conn).port
                } else {
                    (*conn).remote_port
                }) as libc::c_long;
                #[cfg(CURL_DISABLE_PROXY)]
                let port: libc::c_long = (*conn).remote_port as libc::c_long;
                let mut extramsg: [libc::c_char; 80] = *::std::mem::transmute::<
                    &[u8; 80],
                    &mut [libc::c_char; 80],
                >(
                    b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                );
                let mut sockerr: libc::c_int = *__errno_location();
                if sockerr != 0 && detail == 5 as libc::c_int {
                    Curl_strerror(
                        sockerr,
                        extramsg.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong,
                    );
                }
                Curl_failf(
                    data,
                    b"OpenSSL SSL_connect: %s in connection to %s:%ld \0" as *const u8
                        as *const libc::c_char,
                    if extramsg[0 as libc::c_int as usize] as libc::c_int != 0 {
                        extramsg.as_mut_ptr() as *const libc::c_char
                    } else {
                        SSL_ERROR_to_str(detail)
                    },
                    hostname,
                    port,
                );
                return result;
            }
            Curl_failf(
                data,
                b"%s\0" as *const u8 as *const libc::c_char,
                error_buffer.as_mut_ptr(),
            );
            return result;
        }
    } else {
        (*connssl).connecting_state = ssl_connect_3;
        Curl_infof(
            data,
            b"SSL connection using %s / %s\0" as *const u8 as *const libc::c_char,
            SSL_get_version((*backend).handle),
            SSL_CIPHER_get_name(SSL_get_current_cipher((*backend).handle)),
        );
        #[cfg(HAS_APLN)]
        if ((*conn).bits).tls_enable_alpn() != 0 {
            let mut neg_protocol: *const libc::c_uchar = 0 as *const libc::c_uchar;
            let mut len: libc::c_uint = 0;
            SSL_get0_alpn_selected((*backend).handle, &mut neg_protocol, &mut len);
            if len != 0 {
                Curl_infof(
                    data,
                    b"ALPN, server accepted to use %.*s\0" as *const u8
                        as *const libc::c_char,
                    len,
                    neg_protocol,
                );
                // TODO if的条件编译
                #[cfg(USE_HTTP2)]
                let USE_HTTP2_flag = true;
                #[cfg(not(USE_HTTP2))]
                let USE_HTTP2_flag = false;
                if len == 2 as libc::c_int as libc::c_uint
                    && USE_HTTP2_flag
                    && memcmp(
                        b"h2\0" as *const u8 as *const libc::c_char
                            as *const libc::c_void,
                        neg_protocol as *const libc::c_void,
                        len as libc::c_ulong,
                    ) == 0
                {
                    (*conn).negnpn = CURL_HTTP_VERSION_2_0 as libc::c_int;
                } else if len == 8 as libc::c_int as libc::c_uint
                        && memcmp(
                            b"http/1.1\0" as *const u8 as *const libc::c_char
                                as *const libc::c_void,
                            neg_protocol as *const libc::c_void,
                            8 as libc::c_int as libc::c_ulong,
                        ) == 0
                    {
                    (*conn).negnpn = CURL_HTTP_VERSION_1_1 as libc::c_int;
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
                if (*conn).negnpn == CURL_HTTP_VERSION_2_0 as libc::c_int {
                    2 as libc::c_int
                } else {
                    -(1 as libc::c_int)
                },
            );
        }
        return CURLE_OK;
    };
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn asn1_object_dump(
    mut a: *mut ASN1_OBJECT,
    mut buf: *mut libc::c_char,
    mut len: size_t,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ilen: libc::c_int = 0;
    ilen = len as libc::c_int;
    if ilen < 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    i = i2t_ASN1_OBJECT(buf, ilen, a);
    if i >= ilen {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
// TODO-3474-参数列表有条件编译
#[cfg(all(USE_OPENSSL, HAVE_OPAQUE_RSA_DSA_DH))]
unsafe extern "C" fn pubkey_show(
    mut data: *mut Curl_easy,
    mut mem: *mut BIO,
    mut num: libc::c_int,
    mut type_0: *const libc::c_char,
    mut name: *const libc::c_char,
    mut bn: *const BIGNUM,
) {
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut namebuf: [libc::c_char; 32] = [0; 32];
    curl_msnprintf(
        namebuf.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
        b"%s(%s)\0" as *const u8 as *const libc::c_char,
        type_0,
        name,
    );
    if !bn.is_null() {
        BN_print(mem, bn);
    }
    let mut info_len: libc::c_long = BIO_ctrl(
        mem,
        3 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
    );
    Curl_ssl_push_certinfo_len(data, num, namebuf.as_mut_ptr(), ptr, info_len as size_t);
    1 as libc::c_int
        != BIO_ctrl(
            mem,
            1 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            0 as *mut libc::c_void,
        ) as libc::c_int;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn X509V3_ext(
    mut data: *mut Curl_easy,
    mut certnum: libc::c_int,
    mut exts: *const stack_st_X509_EXTENSION,
) {
    let mut i: libc::c_int = 0;
    if sk_X509_EXTENSION_num(exts) <= 0 as libc::c_int {
        return;
    }
    i = 0 as libc::c_int;
    while i < sk_X509_EXTENSION_num(exts) {
        let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
        let mut ext: *mut X509_EXTENSION = sk_X509_EXTENSION_value(exts, i);
        let mut biomem: *mut BUF_MEM = 0 as *mut BUF_MEM;
        let mut namebuf: [libc::c_char; 128] = [0; 128];
        let mut bio_out: *mut BIO = BIO_new(BIO_s_mem());
        if bio_out.is_null() {
            return;
        }
        obj = X509_EXTENSION_get_object(ext);
        asn1_object_dump(
            obj,
            namebuf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
        );
        if X509V3_EXT_print(
            bio_out,
            ext,
            0 as libc::c_int as libc::c_ulong,
            0 as libc::c_int,
        ) == 0
        {
            ASN1_STRING_print(bio_out, X509_EXTENSION_get_data(ext) as *mut ASN1_STRING);
        }
        BIO_ctrl(
            bio_out,
            115 as libc::c_int,
            0 as libc::c_int as libc::c_long,
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
        i += 1;
    }
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn get_cert_chain(
    mut data: *mut Curl_easy,
    mut connssl: *mut ssl_connect_data,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut sk: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut i: libc::c_int = 0;
    let mut numcerts: numcert_t = 0;
    let mut mem: *mut BIO = 0 as *mut BIO;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    sk = SSL_get_peer_cert_chain((*backend).handle);
    if sk.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    numcerts = sk_X509_num(sk);
    result = Curl_ssl_init_certinfo(data, numcerts);
    if result as u64 != 0 {
        return result;
    }
    mem = BIO_new(BIO_s_mem());
    i = 0 as libc::c_int;
    while i < numcerts {
        let mut num: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
        let mut x: *mut X509 = sk_X509_value(sk, i);
        let mut pubkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
        let mut j: libc::c_int = 0;
        let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut psig: *const ASN1_BIT_STRING = 0 as *const ASN1_BIT_STRING;
        X509_NAME_print_ex(
            mem,
            X509_get_subject_name(x),
            0 as libc::c_int,
            (1 as libc::c_int | 2 as libc::c_int | 4 as libc::c_int | 0x10 as libc::c_int
                | 0x100 as libc::c_int | 0x200 as libc::c_int | 8 as libc::c_int
                | (2 as libc::c_int) << 16 as libc::c_int
                | (1 as libc::c_int) << 23 as libc::c_int | 0 as libc::c_int)
                as libc::c_ulong,
        );
        let mut info_len: libc::c_long = BIO_ctrl(
            mem,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
        );
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Subject\0" as *const u8 as *const libc::c_char,
            ptr,
            info_len as size_t,
        );
        1 as libc::c_int
            != BIO_ctrl(
                mem,
                1 as libc::c_int,
                0 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            ) as libc::c_int;
        X509_NAME_print_ex(
            mem,
            X509_get_issuer_name(x),
            0 as libc::c_int,
            (1 as libc::c_int | 2 as libc::c_int | 4 as libc::c_int | 0x10 as libc::c_int
                | 0x100 as libc::c_int | 0x200 as libc::c_int | 8 as libc::c_int
                | (2 as libc::c_int) << 16 as libc::c_int
                | (1 as libc::c_int) << 23 as libc::c_int | 0 as libc::c_int)
                as libc::c_ulong,
        );
        let mut info_len_0: libc::c_long = BIO_ctrl(
            mem,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
        );
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Issuer\0" as *const u8 as *const libc::c_char,
            ptr,
            info_len_0 as size_t,
        );
        1 as libc::c_int
            != BIO_ctrl(
                mem,
                1 as libc::c_int,
                0 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            ) as libc::c_int;
        BIO_printf(
            mem,
            b"%lx\0" as *const u8 as *const libc::c_char,
            X509_get_version(x),
        );
        let mut info_len_1: libc::c_long = BIO_ctrl(
            mem,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
        );
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Version\0" as *const u8 as *const libc::c_char,
            ptr,
            info_len_1 as size_t,
        );
        1 as libc::c_int
            != BIO_ctrl(
                mem,
                1 as libc::c_int,
                0 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            ) as libc::c_int;
        num = X509_get_serialNumber(x);
        if (*num).type_0 == 2 as libc::c_int | 0x100 as libc::c_int {
            BIO_puts(mem, b"-\0" as *const u8 as *const libc::c_char);
        }
        j = 0 as libc::c_int;
        while j < (*num).length {
            BIO_printf(
                mem,
                b"%02x\0" as *const u8 as *const libc::c_char,
                *((*num).data).offset(j as isize) as libc::c_int,
            );
            j += 1;
        }
        let mut info_len_2: libc::c_long = BIO_ctrl(
            mem,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
        );
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Serial Number\0" as *const u8 as *const libc::c_char,
            ptr,
            info_len_2 as size_t,
        );
        1 as libc::c_int
            != BIO_ctrl(
                mem,
                1 as libc::c_int,
                0 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            ) as libc::c_int;
        
        if cfg!(all(HAVE_X509_GET0_SIGNATURE, HAVE_X509_GET0_EXTENSIONS)){
            let mut sigalg: *const X509_ALGOR = 0 as *const X509_ALGOR;
            let mut xpubkey: *mut X509_PUBKEY = 0 as *mut X509_PUBKEY;
            let mut pubkeyoid: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
            X509_get0_signature(&mut psig, &mut sigalg, x);
            if !sigalg.is_null() {
                i2a_ASN1_OBJECT(mem, (*sigalg).algorithm);
                let mut info_len_3: libc::c_long = BIO_ctrl(
                    mem,
                    3 as libc::c_int,
                    0 as libc::c_int as libc::c_long,
                    &mut ptr as *mut *mut libc::c_char as *mut libc::c_char
                        as *mut libc::c_void,
                );
                Curl_ssl_push_certinfo_len(
                    data,
                    i,
                    b"Signature Algorithm\0" as *const u8 as *const libc::c_char,
                    ptr,
                    info_len_3 as size_t,
                );
                1 as libc::c_int
                    != BIO_ctrl(
                        mem,
                        1 as libc::c_int,
                        0 as libc::c_int as libc::c_long,
                        0 as *mut libc::c_void,
                    ) as libc::c_int;
            }
            xpubkey = X509_get_X509_PUBKEY(x);
            if !xpubkey.is_null() {
                X509_PUBKEY_get0_param(
                    &mut pubkeyoid,
                    0 as *mut *const libc::c_uchar,
                    0 as *mut libc::c_int,
                    0 as *mut *mut X509_ALGOR,
                    xpubkey,
                );
                if !pubkeyoid.is_null() {
                    i2a_ASN1_OBJECT(mem, pubkeyoid);
                    let mut info_len_4: libc::c_long = BIO_ctrl(
                        mem,
                        3 as libc::c_int,
                        0 as libc::c_int as libc::c_long,
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
                    1 as libc::c_int
                        != BIO_ctrl(
                            mem,
                            1 as libc::c_int,
                            0 as libc::c_int as libc::c_long,
                            0 as *mut libc::c_void,
                        ) as libc::c_int;
                }
            }
            X509V3_ext(data, i, X509_get0_extensions(x));
        }else{
            // before OpenSSL 1.0.2
        }
        ASN1_TIME_print(mem, X509_get0_notBefore(x));
        let mut info_len_5: libc::c_long = BIO_ctrl(
            mem,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
        );
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Start date\0" as *const u8 as *const libc::c_char,
            ptr,
            info_len_5 as size_t,
        );
        1 as libc::c_int
            != BIO_ctrl(
                mem,
                1 as libc::c_int,
                0 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            ) as libc::c_int;
        ASN1_TIME_print(mem, X509_get0_notAfter(x));
        let mut info_len_6: libc::c_long = BIO_ctrl(
            mem,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
        );
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Expire date\0" as *const u8 as *const libc::c_char,
            ptr,
            info_len_6 as size_t,
        );
        1 as libc::c_int
            != BIO_ctrl(
                mem,
                1 as libc::c_int,
                0 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            ) as libc::c_int;
        
        pubkey = X509_get_pubkey(x);
        if pubkey.is_null() {
            Curl_infof(
                data,
                b"   Unable to load public key\0" as *const u8 as *const libc::c_char,
            );
        } else {
            let mut pktype: libc::c_int = 0;
            match () {
                #[cfg(HAVE_OPAQUE_EVP_PKEY)]
                _ => {
                    pktype = EVP_PKEY_id(pubkey);
                }
                #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                _ => {

                }
            }
            // #[cfg(HAVE_OPAQUE_EVP_PKEY)]
            // pktype = EVP_PKEY_id(pubkey);
            // TODO - 3652
            // #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
            match pktype {
                6 => {
                    #[cfg(HAVE_OPAQUE_EVP_PKEY)]
                    let mut rsa: *mut RSA = EVP_PKEY_get0_RSA(pubkey);
                    // TODO - 3652
                    // #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                    #[cfg(HAVE_OPAQUE_RSA_DSA_DH)]
                    if true {
                        let mut n: *const BIGNUM = 0 as *const BIGNUM;
                        let mut e: *const BIGNUM = 0 as *const BIGNUM;
                        RSA_get0_key(rsa, &mut n, &mut e, 0 as *mut *const BIGNUM);
                        BIO_printf(
                            mem,
                            b"%d\0" as *const u8 as *const libc::c_char,
                            BN_num_bits(n),
                        );
                        let mut info_len_7: libc::c_long = BIO_ctrl(
                            mem,
                            3 as libc::c_int,
                            0 as libc::c_int as libc::c_long,
                            &mut ptr as *mut *mut libc::c_char as *mut libc::c_char
                                as *mut libc::c_void,
                        );
                        Curl_ssl_push_certinfo_len(
                            data,
                            i,
                            b"RSA Public Key\0" as *const u8 as *const libc::c_char,
                            ptr,
                            info_len_7 as size_t,
                        );
                        1 as libc::c_int
                            != BIO_ctrl(
                                mem,
                                1 as libc::c_int,
                                0 as libc::c_int as libc::c_long,
                                0 as *mut libc::c_void,
                            ) as libc::c_int;
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
                    #[cfg(not(HAVE_OPAQUE_RSA_DSA_DH))]
                    if true {
                        // TODO - 3678
                    }
                }
                116 => {
                    if cfg!(not(OPENSSL_NO_DSA)){
                            #[cfg(HAVE_OPAQUE_EVP_PKEY)]
                            let mut dsa: *mut DSA = EVP_PKEY_get0_DSA(pubkey);
                            // TODO - 3691
                            // #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                            #[cfg(HAVE_OPAQUE_RSA_DSA_DH)]
                            if true {
                                let mut p: *const BIGNUM = 0 as *const BIGNUM;
                                let mut q: *const BIGNUM = 0 as *const BIGNUM;
                                let mut g: *const BIGNUM = 0 as *const BIGNUM;
                                let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
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
                            #[cfg(not(HAVE_OPAQUE_RSA_DSA_DH))]
                            if true {
                                // cfg!(not(HAVE_OPAQUE_RSA_DSA_DH))
                            }   
                        }     
                    }
                28 => {
                    #[cfg(HAVE_OPAQUE_EVP_PKEY)]
                    let mut dh: *mut DH = EVP_PKEY_get0_DH(pubkey);
                    // TODO
                    // #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                    #[cfg(HAVE_OPAQUE_RSA_DSA_DH)]
                    if true {
                        let mut p_0: *const BIGNUM = 0 as *const BIGNUM;
                        let mut q_0: *const BIGNUM = 0 as *const BIGNUM;
                        let mut g_0: *const BIGNUM = 0 as *const BIGNUM;
                        let mut pub_key_0: *const BIGNUM = 0 as *const BIGNUM;
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
                    // TODO
                    #[cfg(not(HAVE_OPAQUE_EVP_PKEY))]
                    if true{
                        // TODO - 3471
                    }   
                }
                _ => {}
            }
            EVP_PKEY_free(pubkey);
        }
        if !psig.is_null() {
            j = 0 as libc::c_int;
            while j < (*psig).length {
                BIO_printf(
                    mem,
                    b"%02x:\0" as *const u8 as *const libc::c_char,
                    *((*psig).data).offset(j as isize) as libc::c_int,
                );
                j += 1;
            }
            let mut info_len_8: libc::c_long = BIO_ctrl(
                mem,
                3 as libc::c_int,
                0 as libc::c_int as libc::c_long,
                &mut ptr as *mut *mut libc::c_char as *mut libc::c_char
                    as *mut libc::c_void,
            );
            Curl_ssl_push_certinfo_len(
                data,
                i,
                b"Signature\0" as *const u8 as *const libc::c_char,
                ptr,
                info_len_8 as size_t,
            );
            1 as libc::c_int
                != BIO_ctrl(
                    mem,
                    1 as libc::c_int,
                    0 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                ) as libc::c_int;
        }
        PEM_write_bio_X509(mem, x);
        let mut info_len_9: libc::c_long = BIO_ctrl(
            mem,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            &mut ptr as *mut *mut libc::c_char as *mut libc::c_char as *mut libc::c_void,
        );
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Cert\0" as *const u8 as *const libc::c_char,
            ptr,
            info_len_9 as size_t,
        );
        1 as libc::c_int
            != BIO_ctrl(
                mem,
                1 as libc::c_int,
                0 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            ) as libc::c_int;
        i += 1;
    }
    BIO_free(mem);
    return CURLE_OK;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn pkp_pin_peer_pubkey(
    mut data: *mut Curl_easy,
    mut cert: *mut X509,
    mut pinnedpubkey: *const libc::c_char,
) -> CURLcode {
    let mut len1: libc::c_int = 0 as libc::c_int;
    let mut len2: libc::c_int = 0 as libc::c_int;
    let mut buff1: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut temp: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut result: CURLcode = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    if pinnedpubkey.is_null() {
        return CURLE_OK;
    }
    if cert.is_null() {
        return result;
    }
    len1 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), 0 as *mut *mut libc::c_uchar);
    if !(len1 < 1 as libc::c_int) {
        temp = Curl_cmalloc.expect("non-null function pointer")(len1 as size_t)
            as *mut libc::c_uchar;
        buff1 = temp;
        if !buff1.is_null() {
            len2 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &mut temp);
            if !(len1 != len2 || temp.is_null()
                || temp.offset_from(buff1) as libc::c_long != len1 as libc::c_long)
            {
                result = Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1 as size_t);
            }
        }
    }
    if !buff1.is_null() {
        Curl_cfree.expect("non-null function pointer")(buff1 as *mut libc::c_void);
    }
    return result;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn servercert(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut connssl: *mut ssl_connect_data,
    mut strict: bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut rc: libc::c_int = 0;
    let mut lerr: libc::c_long = 0;
    let mut issuer: *mut X509 = 0 as *mut X509;
    let mut fp: *mut BIO = 0 as *mut BIO;
    let mut error_buffer: [libc::c_char; 256] = *::std::mem::transmute::<
        &[u8; 256],
        &mut [libc::c_char; 256],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut buffer: [libc::c_char; 2048] = [0; 2048];
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    let mut mem: *mut BIO = BIO_new(BIO_s_mem());
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if ((*data).set.ssl).certinfo() != 0 {
        get_cert_chain(data, connssl);
    }
    let ref mut fresh14 = (*backend).server_cert;
    *fresh14 = SSL_get_peer_certificate((*backend).handle);
    if ((*backend).server_cert).is_null() {
        BIO_free(mem);
        if !strict {
            return CURLE_OK;
        }
        Curl_failf(
            data,
            b"SSL: couldn't get peer certificate!\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_PEER_FAILED_VERIFICATION;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_IS_PROXY_void = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                b"Proxy\0" as *const u8 as *const libc::c_char
                            } else {
                                b"Server\0" as *const u8 as *const libc::c_char
                            };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_IS_PROXY_void = if 0 as libc::c_int != 0 {
                                b"Proxy\0" as *const u8 as *const libc::c_char
                            } else {
                                b"Server\0" as *const u8 as *const libc::c_char
                            };
    Curl_infof(
        data,
        b"%s certificate:\0" as *const u8 as *const libc::c_char,
        SSL_IS_PROXY_void,
    );
    rc = x509_name_oneline(
        X509_get_subject_name((*backend).server_cert),
        buffer.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
    );
    Curl_infof(
        data,
        b" subject: %s\0" as *const u8 as *const libc::c_char,
        if rc != 0 {
            b"[NONE]\0" as *const u8 as *const libc::c_char
        } else {
            buffer.as_mut_ptr() as *const libc::c_char
        },
    );
    // DONE - 3869
    if cfg!(not(CURL_DISABLE_VERBOSE_STRINGS)){
        let mut len: libc::c_long = 0;
        ASN1_TIME_print(mem, X509_get0_notBefore((*backend).server_cert));
        len = BIO_ctrl(
            mem,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            &mut ptr as *mut *const libc::c_char as *mut *mut libc::c_char
                as *mut libc::c_char as *mut libc::c_void,
        );
        Curl_infof(
            data,
            b" start date: %.*s\0" as *const u8 as *const libc::c_char,
            len as libc::c_int,
            ptr,
        );
        BIO_ctrl(
            mem,
            1 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            0 as *mut libc::c_void,
        );
        ASN1_TIME_print(mem, X509_get0_notAfter((*backend).server_cert));
        len = BIO_ctrl(
            mem,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            &mut ptr as *mut *const libc::c_char as *mut *mut libc::c_char
                as *mut libc::c_char as *mut libc::c_void,
        );
        Curl_infof(
            data,
            b" expire date: %.*s\0" as *const u8 as *const libc::c_char,
            len as libc::c_int,
            ptr,
        );
        BIO_ctrl(
            mem,
            1 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            0 as *mut libc::c_void,
        );
        BIO_free(mem);
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifyhost = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    let SSL_CONN_CONFIG_verifyhost = ((*conn).ssl_config).verifyhost() != 0;

    if SSL_CONN_CONFIG_verifyhost {
        result = verifyhost(data, conn, (*backend).server_cert);
        if result as u64 != 0 {
            X509_free((*backend).server_cert);
            let ref mut fresh15 = (*backend).server_cert;
            *fresh15 = 0 as *mut X509;
            return result;
        }
    }
    rc = x509_name_oneline(
        X509_get_issuer_name((*backend).server_cert),
        buffer.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
    );
    if rc != 0 {
        if strict {
            Curl_failf(
                data,
                b"SSL: couldn't get X509-issuer name!\0" as *const u8
                    as *const libc::c_char,
            );
        }
        result = CURLE_PEER_FAILED_VERIFICATION;
    } else {
        Curl_infof(
            data,
            b" issuer: %s\0" as *const u8 as *const libc::c_char,
            buffer.as_mut_ptr(),
        );
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_CONN_CONFIG_issuercert = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                            (*conn).proxy_ssl_config.issuercert
                                        } else {
                                            (*conn).ssl_config.issuercert
                                        };
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_CONN_CONFIG_issuercert = (*conn).ssl_config.issuercert;

        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_CONN_CONFIG_issuercert_blob = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                                (*conn).proxy_ssl_config.issuercert_blob
                                            } else {
                                                (*conn).ssl_config.issuercert_blob
                                            };
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_CONN_CONFIG_issuercert_blob = (*conn).ssl_config.issuercert_blob;

        if !(SSL_CONN_CONFIG_issuercert).is_null() || !(SSL_CONN_CONFIG_issuercert_blob).is_null()
        {
            if !(SSL_CONN_CONFIG_issuercert_blob).is_null()
            {
                fp = BIO_new_mem_buf(
                    (*SSL_CONN_CONFIG_issuercert_blob).data,
                    (*SSL_CONN_CONFIG_issuercert_blob).len as libc::c_int,
                );
            } else {
                fp = BIO_new(BIO_s_file());
                if fp.is_null() {
                    Curl_failf(
                        data,
                        b"BIO_new return NULL, OpenSSL error %s\0" as *const u8
                            as *const libc::c_char,
                        ossl_strerror(
                            ERR_get_error(),
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        ),
                    );
                    X509_free((*backend).server_cert);
                    let ref mut fresh16 = (*backend).server_cert;
                    *fresh16 = 0 as *mut X509;
                    return CURLE_OUT_OF_MEMORY;
                }
                if BIO_ctrl(
                    fp,
                    108 as libc::c_int,
                    (0x1 as libc::c_int | 0x2 as libc::c_int) as libc::c_long,
                    SSL_CONN_CONFIG_issuercert as *mut libc::c_void,
                ) as libc::c_int <= 0 as libc::c_int
                {
                    if strict {
                        Curl_failf(
                            data,
                            b"SSL: Unable to open issuer cert (%s)\0" as *const u8
                                as *const libc::c_char,
                            SSL_CONN_CONFIG_issuercert,
                        );
                    }
                    BIO_free(fp);
                    X509_free((*backend).server_cert);
                    let ref mut fresh17 = (*backend).server_cert;
                    *fresh17 = 0 as *mut X509;
                    return CURLE_SSL_ISSUER_ERROR;
                }
            }
            issuer = PEM_read_bio_X509(
                fp,
                0 as *mut *mut X509,
                None,
                0 as *mut libc::c_void,
            );
            if issuer.is_null() {
                if strict {
                    Curl_failf(
                        data,
                        b"SSL: Unable to read issuer cert (%s)\0" as *const u8
                            as *const libc::c_char,
                        SSL_CONN_CONFIG_issuercert,
                    );
                }
                BIO_free(fp);
                X509_free(issuer);
                X509_free((*backend).server_cert);
                let ref mut fresh18 = (*backend).server_cert;
                *fresh18 = 0 as *mut X509;
                return CURLE_SSL_ISSUER_ERROR;
            }
            if X509_check_issued(issuer, (*backend).server_cert) != 0 as libc::c_int {
                if strict {
                    Curl_failf(
                        data,
                        b"SSL: Certificate issuer check failed (%s)\0" as *const u8
                            as *const libc::c_char,
                        SSL_CONN_CONFIG_issuercert,
                    );
                }
                BIO_free(fp);
                X509_free(issuer);
                X509_free((*backend).server_cert);
                let ref mut fresh19 = (*backend).server_cert;
                *fresh19 = 0 as *mut X509;
                return CURLE_SSL_ISSUER_ERROR;
            }
            Curl_infof(
                data,
                b" SSL certificate issuer check ok (%s)\0" as *const u8
                    as *const libc::c_char,
                SSL_CONN_CONFIG_issuercert,
            );
            BIO_free(fp);
            X509_free(issuer);
        }
        lerr = SSL_get_verify_result((*backend).handle);
        #[cfg(not(CURL_DISABLE_PROXY))]
        if true{
            *if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                &mut (*data).set.proxy_ssl.certverifyresult
            } else {
                &mut (*data).set.ssl.certverifyresult
            } = lerr;
        }
        #[cfg(CURL_DISABLE_PROXY)]
        if true {
            (*data).set.ssl.certverifyresult = lerr;
        }
        if lerr != 0 as libc::c_int as libc::c_long {
            #[cfg(not(CURL_DISABLE_PROXY))]
            let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                            } != 0 ;
            #[cfg(CURL_DISABLE_PROXY)]
            let SSL_CONN_CONFIG_verifypeer = ((*conn).ssl_config).verifystatus() != 0;
            if SSL_CONN_CONFIG_verifypeer {
                if strict {
                    Curl_failf(
                        data,
                        b"SSL certificate verify result: %s (%ld)\0" as *const u8
                            as *const libc::c_char,
                        X509_verify_cert_error_string(lerr),
                        lerr,
                    );
                }
                result = CURLE_PEER_FAILED_VERIFICATION;
            } else {
                Curl_infof(
                    data,
                    b" SSL certificate verify result: %s (%ld), continuing anyway.\0"
                        as *const u8 as *const libc::c_char,
                    X509_verify_cert_error_string(lerr),
                    lerr,
                );
            }
        } else {
            Curl_infof(
                data,
                b" SSL certificate verify ok.\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    // DONE - 3986
    #[cfg(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP), not(CURL_DISABLE_PROXY)))]
    let SSL_CONN_CONFIG_verifystatus = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                            ((*conn).proxy_ssl_config).verifystatus() as libc::c_int
                                        } else {
                                            ((*conn).ssl_config).verifystatus() as libc::c_int
                                        } != 0;
    #[cfg(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP), CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifystatus = ((*conn).ssl_config).verifystatus() != 0;
    #[cfg(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP)))]
    if SSL_CONN_CONFIG_verifystatus {
        result = verifystatus(data, connssl);
        if result as u64 != 0 {
            X509_free((*backend).server_cert);
            let ref mut fresh20 = (*backend).server_cert;
            *fresh20 = 0 as *mut X509;
            return result;
        }
    }
    if !strict {
        result = CURLE_OK;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_PINNED_PUB_KEY_void = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY_PROXY as libc::c_int as usize]
                            } else {
                                (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as libc::c_int as usize]
                            };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_PINNED_PUB_KEY_void = (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as libc::c_int as usize];
    ptr = SSL_PINNED_PUB_KEY_void;
    if result as u64 == 0 && !ptr.is_null() {
        result = pkp_pin_peer_pubkey(data, (*backend).server_cert, ptr);
        if result as u64 != 0 {
            Curl_failf(
                data,
                b"SSL: public key does not match pinned public key!\0" as *const u8
                    as *const libc::c_char,
            );
        }
    }
    X509_free((*backend).server_cert);
    let ref mut fresh21 = (*backend).server_cert;
    *fresh21 = 0 as *mut X509;
    (*connssl).connecting_state = ssl_connect_done;
    return result;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_connect_step3(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    
    #[cfg(not(CURL_DISABLE_PROXY))]
    let servercert_value_result =  servercert(
                                        data,
                                        conn,
                                        connssl,
                                        (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                        }) != 0
                                            || (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                            }) != 0,
                                    );
    #[cfg(CURL_DISABLE_PROXY)]
    let servercert_value_result =  servercert(
                                        data,
                                        conn,
                                        connssl,
                                        ((*conn).ssl_config).verifypeer() as libc::c_int != 0
                                            || ((*conn).ssl_config).verifyhost() as libc::c_int != 0,
                                    );
    result = servercert_value_result;
    if result as u64 == 0 {
        (*connssl).connecting_state = ssl_connect_done;
    }
    return result;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut sockfd: curl_socket_t = (*conn).sock[sockindex as usize];
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
        let timeout_ms: timediff_t = Curl_timeleft(
            data,
            0 as *mut curltime,
            1 as libc::c_int != 0,
        );
        if timeout_ms < 0 as libc::c_int as libc::c_long {
            Curl_failf(
                data,
                b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OPERATION_TIMEDOUT;
        }
        result = ossl_connect_step1(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    while ssl_connect_2 as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
        || ssl_connect_2_reading as libc::c_int as libc::c_uint
            == (*connssl).connecting_state as libc::c_uint
        || ssl_connect_2_writing as libc::c_int as libc::c_uint
            == (*connssl).connecting_state as libc::c_uint
    {
        let timeout_ms_0: timediff_t = Curl_timeleft(
            data,
            0 as *mut curltime,
            1 as libc::c_int != 0,
        );
        if timeout_ms_0 < 0 as libc::c_int as libc::c_long {
            Curl_failf(
                data,
                b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OPERATION_TIMEDOUT;
        }
        if (*connssl).connecting_state as libc::c_uint
            == ssl_connect_2_reading as libc::c_int as libc::c_uint
            || (*connssl).connecting_state as libc::c_uint
                == ssl_connect_2_writing as libc::c_int as libc::c_uint
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
                    timeout_ms_0
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
            }
            if 0 as libc::c_int == what {
                if nonblocking {
                    *done = 0 as libc::c_int != 0;
                    return CURLE_OK;
                }
                Curl_failf(
                    data,
                    b"SSL connection timeout\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_OPERATION_TIMEDOUT;
            }
        }
        result = ossl_connect_step2(data, conn, sockindex);
        if result as libc::c_uint != 0
            || nonblocking as libc::c_int != 0
                && (ssl_connect_2 as libc::c_int as libc::c_uint
                    == (*connssl).connecting_state as libc::c_uint
                    || ssl_connect_2_reading as libc::c_int as libc::c_uint
                        == (*connssl).connecting_state as libc::c_uint
                    || ssl_connect_2_writing as libc::c_int as libc::c_uint
                        == (*connssl).connecting_state as libc::c_uint)
        {
            return result;
        }
    }
    if ssl_connect_3 as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        result = ossl_connect_step3(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if ssl_connect_done as libc::c_int as libc::c_uint
        == (*connssl).connecting_state as libc::c_uint
    {
        (*connssl).state = ssl_connection_complete;
        let ref mut fresh22 = (*conn).recv[sockindex as usize];
        *fresh22 = Some(ossl_recv as Curl_recv);
        let ref mut fresh23 = (*conn).send[sockindex as usize];
        *fresh23 = Some(ossl_send as Curl_send);
        *done = 1 as libc::c_int != 0;
    } else {
        *done = 0 as libc::c_int != 0;
    }
    (*connssl).connecting_state = ssl_connect_1;
    return CURLE_OK;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    return ossl_connect_common(data, conn, sockindex, 1 as libc::c_int != 0, done);
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut done: bool = 0 as libc::c_int != 0;
    result = ossl_connect_common(
        data,
        conn,
        sockindex,
        0 as libc::c_int != 0,
        &mut done,
    );
    if result as u64 != 0 {
        return result;
    }
    return CURLE_OK;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_data_pending(
    mut conn: *const connectdata,
    mut connindex: libc::c_int,
) -> bool {
    let mut connssl: *const ssl_connect_data = &*((*conn).ssl)
        .as_ptr()
        .offset(connindex as isize) as *const ssl_connect_data;
    if !((*(*connssl).backend).handle).is_null()
        && SSL_pending((*(*connssl).backend).handle) != 0
    {
        return 1 as libc::c_int != 0;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut proxyssl: *const ssl_connect_data = &*((*conn).proxy_ssl)
        .as_ptr()
        .offset(connindex as isize) as *const ssl_connect_data;
    #[cfg(not(CURL_DISABLE_PROXY))]
    if !((*(*proxyssl).backend).handle).is_null()
        && SSL_pending((*(*proxyssl).backend).handle) != 0
    {
        return 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_send(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut err: libc::c_int = 0;
    let mut error_buffer: [libc::c_char; 256] = [0; 256];
    let mut sslerror: libc::c_ulong = 0;
    let mut memlen: libc::c_int = 0;
    let mut rc: libc::c_int = 0;
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    ERR_clear_error();
    memlen = if len > 2147483647 as libc::c_int as size_t {
        2147483647 as libc::c_int
    } else {
        len as libc::c_int
    };
    let ref mut fresh24 = (*(*conn).ssl[0 as libc::c_int as usize].backend).logger;
    *fresh24 = data;
    rc = SSL_write((*backend).handle, mem, memlen);
    if rc <= 0 as libc::c_int {
        err = SSL_get_error((*backend).handle, rc);
        match err {
            2 | 3 => {
                *curlcode = CURLE_AGAIN;
                return -(1 as libc::c_int) as ssize_t;
            }
            5 => {
                let mut sockerr: libc::c_int = *__errno_location();
                sslerror = ERR_get_error();
                if sslerror != 0 {
                    ossl_strerror(
                        sslerror,
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                    );
                } else if sockerr != 0 {
                    Curl_strerror(
                        sockerr,
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                    );
                } else {
                    strncpy(
                        error_buffer.as_mut_ptr(),
                        SSL_ERROR_to_str(err),
                        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                    );
                    error_buffer[(::std::mem::size_of::<[libc::c_char; 256]>()
                        as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        as usize] = '\0' as i32 as libc::c_char;
                }
                Curl_failf(
                    data,
                    b"OpenSSL SSL_write: %s, errno %d\0" as *const u8
                        as *const libc::c_char,
                    error_buffer.as_mut_ptr(),
                    sockerr,
                );
                *curlcode = CURLE_SEND_ERROR;
                return -(1 as libc::c_int) as ssize_t;
            }
            1 => {
                sslerror = ERR_get_error();
                #[cfg(not(CURL_DISABLE_PROXY))]
                let CURL_DISABLE_PROXY_flag_4 = (*conn).proxy_ssl[sockindex as usize].state as libc::c_uint
                                              == ssl_connection_complete as libc::c_int as libc::c_uint ;
                #[cfg(CURL_DISABLE_PROXY)]
                let CURL_DISABLE_PROXY_flag_4 = true;                   
                if (sslerror >> 24 as libc::c_long
                    & 0xff as libc::c_long as libc::c_ulong) as libc::c_int
                    == 20 as libc::c_int
                    && (sslerror & 0xfff as libc::c_long as libc::c_ulong) as libc::c_int
                        == 128 as libc::c_int
                    && (*conn).ssl[sockindex as usize].state as libc::c_uint
                        == ssl_connection_complete as libc::c_int as libc::c_uint
                    && CURL_DISABLE_PROXY_flag_4
                {
                    let mut ver: [libc::c_char; 120] = [0; 120];
                    ossl_version(
                        ver.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 120]>() as libc::c_ulong,
                    );
                    Curl_failf(
                        data,
                        b"Error: %s does not support double SSL tunneling.\0"
                            as *const u8 as *const libc::c_char,
                        ver.as_mut_ptr(),
                    );
                } else {
                    Curl_failf(
                        data,
                        b"SSL_write() error: %s\0" as *const u8 as *const libc::c_char,
                        ossl_strerror(
                            sslerror,
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        ),
                    );
                }
                *curlcode = CURLE_SEND_ERROR;
                return -(1 as libc::c_int) as ssize_t;
            }
            _ => {}
        }
        Curl_failf(
            data,
            b"OpenSSL SSL_write: %s, errno %d\0" as *const u8 as *const libc::c_char,
            SSL_ERROR_to_str(err),
            *__errno_location(),
        );
        *curlcode = CURLE_SEND_ERROR;
        return -(1 as libc::c_int) as ssize_t;
    }
    *curlcode = CURLE_OK;
    return rc as ssize_t;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_recv(
    mut data: *mut Curl_easy,
    mut num: libc::c_int,
    mut buf: *mut libc::c_char,
    mut buffersize: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut error_buffer: [libc::c_char; 256] = [0; 256];
    let mut sslerror: libc::c_ulong = 0;
    let mut nread: ssize_t = 0;
    let mut buffsize: libc::c_int = 0;
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(num as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    ERR_clear_error();
    buffsize = if buffersize > 2147483647 as libc::c_int as size_t {
        2147483647 as libc::c_int
    } else {
        buffersize as libc::c_int
    };
    let ref mut fresh25 = (*(*conn).ssl[0 as libc::c_int as usize].backend).logger;
    *fresh25 = data;
    nread = SSL_read((*backend).handle, buf as *mut libc::c_void, buffsize) as ssize_t;
    if nread <= 0 as libc::c_int as libc::c_long {
        let mut err: libc::c_int = SSL_get_error(
            (*backend).handle,
            nread as libc::c_int,
        );
        match err {
            0 => {}
            6 => {
                if num == 0 as libc::c_int {
                    Curl_conncontrol(conn, 1 as libc::c_int);
                }
            }
            2 | 3 => {
                *curlcode = CURLE_AGAIN;
                return -(1 as libc::c_int) as ssize_t;
            }
            _ => {
                sslerror = ERR_get_error();
                if nread < 0 as libc::c_int as libc::c_long || sslerror != 0 {
                    let mut sockerr: libc::c_int = *__errno_location();
                    if sslerror != 0 {
                        ossl_strerror(
                            sslerror,
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        );
                    } else if sockerr != 0 && err == 5 as libc::c_int {
                        Curl_strerror(
                            sockerr,
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        );
                    } else {
                        strncpy(
                            error_buffer.as_mut_ptr(),
                            SSL_ERROR_to_str(err),
                            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                        );
                        error_buffer[(::std::mem::size_of::<[libc::c_char; 256]>()
                            as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                            as usize] = '\0' as i32 as libc::c_char;
                    }
                    Curl_failf(
                        data,
                        b"OpenSSL SSL_read: %s, errno %d\0" as *const u8
                            as *const libc::c_char,
                        error_buffer.as_mut_ptr(),
                        sockerr,
                    );
                    *curlcode = CURLE_RECV_ERROR;
                    return -(1 as libc::c_int) as ssize_t;
                    // TODO debug相关的条件编译，应该不加
                }
            }
        }
    }
    return nread;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_version(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
) -> size_t {
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
        let mut sub: [libc::c_char; 3] = [0; 3];
        let mut ssleay_value: libc::c_ulong = 0;
        sub[2 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
        sub[1 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
        ssleay_value = OpenSSL_version_num();
        if ssleay_value < 0x906000 as libc::c_int as libc::c_ulong {
            ssleay_value = 0x1010106f as libc::c_long as libc::c_ulong;
            sub[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
        } else if ssleay_value & 0xff0 as libc::c_int as libc::c_ulong != 0 {
            let mut minor_ver: libc::c_int = (ssleay_value >> 4 as libc::c_int
                & 0xff as libc::c_int as libc::c_ulong) as libc::c_int;
            if minor_ver > 26 as libc::c_int {
                sub[1 as libc::c_int
                    as usize] = ((minor_ver - 1 as libc::c_int) % 26 as libc::c_int
                    + 'a' as i32 + 1 as libc::c_int) as libc::c_char;
                sub[0 as libc::c_int as usize] = 'z' as i32 as libc::c_char;
            } else {
                sub[0 as libc::c_int
                    as usize] = (minor_ver + 'a' as i32 - 1 as libc::c_int) as libc::c_char;
            }
        } else {
            sub[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
        }
        #[cfg(not(OPENSSL_FIPS))]
        return curl_msnprintf(
            buffer,
            size,
            b"%s/%lx.%lx.%lx%s\0" as *const u8 as *const libc::c_char,
            b"OpenSSL\0" as *const u8 as *const libc::c_char,
            ssleay_value >> 28 as libc::c_int & 0xf as libc::c_int as libc::c_ulong,
            ssleay_value >> 20 as libc::c_int & 0xff as libc::c_int as libc::c_ulong,
            ssleay_value >> 12 as libc::c_int & 0xff as libc::c_int as libc::c_ulong,
            sub.as_mut_ptr(),
        ) as size_t;  
        #[cfg(OPENSSL_FIPS)]
        return curl_msnprintf(
            buffer,
            size,
            b"%s/%lx.%lx.%lx%s\0" as *const u8 as *const libc::c_char,
            b"-fips\0" as *const u8 as *const libc::c_char,
            b"OpenSSL\0" as *const u8 as *const libc::c_char,
            ssleay_value >> 28 as libc::c_int & 0xf as libc::c_int as libc::c_ulong,
            ssleay_value >> 20 as libc::c_int & 0xff as libc::c_int as libc::c_ulong,
            ssleay_value >> 12 as libc::c_int & 0xff as libc::c_int as libc::c_ulong,
            sub.as_mut_ptr(),
        ) as size_t;
    //}       
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut libc::c_uchar,
    mut length: size_t,
) -> CURLcode {
    let mut rc: libc::c_int = 0;
    if !data.is_null() {
        if ossl_seed(data) as u64 != 0 {
            return CURLE_FAILED_INIT;
        }
    } else if !rand_enough() {
        return CURLE_FAILED_INIT
    }
    rc = RAND_bytes(entropy, curlx_uztosi(length));
    return (if rc == 1 as libc::c_int {
        CURLE_OK as libc::c_int
    } else {
        CURLE_FAILED_INIT as libc::c_int
    }) as CURLcode;
}
#[cfg(not(OPENSSL_NO_SHA256))]
unsafe extern "C" fn ossl_sha256sum(
    mut tmp: *const libc::c_uchar,
    mut tmplen: size_t,
    mut sha256sum: *mut libc::c_uchar,
    mut unused: size_t,
) -> CURLcode {
    let mut mdctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    mdctx = EVP_MD_CTX_new();
    if mdctx.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    EVP_DigestInit(mdctx, EVP_sha256());
    EVP_DigestUpdate(mdctx, tmp as *const libc::c_void, tmplen);
    EVP_DigestFinal_ex(mdctx, sha256sum, &mut len);
    EVP_MD_CTX_free(mdctx);
    return CURLE_OK;
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_cert_status_request() -> bool {
    // TODO - 4475
    if cfg!(all(not(OPENSSL_NO_TLSEXT), not(OPENSSL_NO_OCSP))){
        return 1 as libc::c_int != 0;
    }else{
        return 0 as libc::c_int != 0;
    }
        
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return if info as libc::c_uint == CURLINFO_TLS_SESSION as libc::c_int as libc::c_uint
    {
        (*backend).ctx as *mut libc::c_void
    } else {
        (*backend).handle as *mut libc::c_void
    };
}
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_associate_connection(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if ((*backend).handle).is_null() {
        return;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                        } != 0 ;
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_primary_sessionid = ((*data).set.ssl.primary).sessionid() != 0;

    if SSL_SET_OPTION_primary_sessionid{
        let mut data_idx: libc::c_int = ossl_get_ssl_data_index();
        let mut connectdata_idx: libc::c_int = ossl_get_ssl_conn_index();
        let mut sockindex_idx: libc::c_int = ossl_get_ssl_sockindex_index();
        let mut proxy_idx: libc::c_int = ossl_get_proxy_index();
        if data_idx >= 0 as libc::c_int && connectdata_idx >= 0 as libc::c_int
            && sockindex_idx >= 0 as libc::c_int && proxy_idx >= 0 as libc::c_int
        {
            SSL_set_ex_data((*backend).handle, data_idx, data as *mut libc::c_void);
            SSL_set_ex_data(
                (*backend).handle,
                connectdata_idx,
                conn as *mut libc::c_void,
            );
            SSL_set_ex_data(
                (*backend).handle,
                sockindex_idx,
                ((*conn).sock).as_mut_ptr().offset(sockindex as isize)
                    as *mut libc::c_void,
            );
            #[cfg(not(CURL_DISABLE_PROXY))]
            SSL_set_ex_data(
                (*backend).handle,
                proxy_idx,
                if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                    1 as libc::c_int as *mut libc::c_void
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
#[cfg(USE_OPENSSL)]
unsafe extern "C" fn ossl_disassociate_connection(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
) {
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if ((*backend).handle).is_null() {
        return;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_SET_OPTION_primary_sessionid = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    let SSL_SET_OPTION_primary_sessionid = ((*data).set.ssl.primary).sessionid() != 0;
    if SSL_SET_OPTION_primary_sessionid {
        let mut data_idx: libc::c_int = ossl_get_ssl_data_index();
        let mut connectdata_idx: libc::c_int = ossl_get_ssl_conn_index();
        let mut sockindex_idx: libc::c_int = ossl_get_ssl_sockindex_index();
        let mut proxy_idx: libc::c_int = ossl_get_proxy_index();
        if data_idx >= 0 as libc::c_int && connectdata_idx >= 0 as libc::c_int
            && sockindex_idx >= 0 as libc::c_int && proxy_idx >= 0 as libc::c_int
        {
            SSL_set_ex_data((*backend).handle, data_idx, 0 as *mut libc::c_void);
            SSL_set_ex_data((*backend).handle, connectdata_idx, 0 as *mut libc::c_void);
            SSL_set_ex_data((*backend).handle, sockindex_idx, 0 as *mut libc::c_void);
            SSL_set_ex_data((*backend).handle, proxy_idx, 0 as *mut libc::c_void);
        }
    }
}
#[no_mangle]
pub static mut Curl_ssl_openssl: Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_OPENSSL,
                    name: b"openssl\0" as *const u8 as *const libc::c_char,
                };
                init
            },
            supports: ((1 as libc::c_int) << 0 as libc::c_int
                | (1 as libc::c_int) << 6 as libc::c_int
                | (1 as libc::c_int) << 1 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int
                | (1 as libc::c_int) << 3 as libc::c_int
                | (1 as libc::c_int) << 5 as libc::c_int
                | (1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint,
            sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>()
                as libc::c_ulong,
            init: Some(ossl_init as unsafe extern "C" fn() -> libc::c_int),
            cleanup: Some(ossl_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(
                ossl_version as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t,
            ),
            check_cxn: Some(
                ossl_check_cxn as unsafe extern "C" fn(*mut connectdata) -> libc::c_int,
            ),
            shut_down: Some(
                ossl_shutdown
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            data_pending: Some(
                ossl_data_pending
                    as unsafe extern "C" fn(*const connectdata, libc::c_int) -> bool,
            ),
            random: Some(
                ossl_random
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut libc::c_uchar,
                        size_t,
                    ) -> CURLcode,
            ),
            cert_status_request: Some(
                ossl_cert_status_request as unsafe extern "C" fn() -> bool,
            ),
            connect_blocking: Some(
                ossl_connect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> CURLcode,
            ),
            connect_nonblocking: Some(
                ossl_connect_nonblocking
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
                ossl_get_internals
                    as unsafe extern "C" fn(
                        *mut ssl_connect_data,
                        CURLINFO,
                    ) -> *mut libc::c_void,
            ),
            close_one: Some(
                ossl_close
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> (),
            ),
            close_all: Some(
                ossl_close_all as unsafe extern "C" fn(*mut Curl_easy) -> (),
            ),
            session_free: Some(
                ossl_session_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            set_engine: Some(
                ossl_set_engine
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *const libc::c_char,
                    ) -> CURLcode,
            ),
            set_engine_default: Some(
                ossl_set_engine_default
                    as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
            ),
            engines_list: Some(
                ossl_engines_list
                    as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
            ),
            false_start: Some(Curl_none_false_start as unsafe extern "C" fn() -> bool),
            sha256sum: Some(
                ossl_sha256sum
                    as unsafe extern "C" fn(
                        *const libc::c_uchar,
                        size_t,
                        *mut libc::c_uchar,
                        size_t,
                    ) -> CURLcode,
            ),
            associate_connection: Some(
                ossl_associate_connection
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> (),
            ),
            disassociate_connection: Some(
                ossl_disassociate_connection
                    as unsafe extern "C" fn(*mut Curl_easy, libc::c_int) -> (),
            ),
        };
        init
    }
};