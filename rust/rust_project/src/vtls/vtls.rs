use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

unsafe extern "C" fn blobdup(mut dest: *mut *mut curl_blob, mut src: *mut curl_blob) -> CURLcode {
    if !src.is_null() {
        let mut d: *mut curl_blob = 0 as *mut curl_blob;
        d = Curl_cmalloc.expect("non-null function pointer")(
            (::std::mem::size_of::<curl_blob>() as libc::c_ulong).wrapping_add((*src).len),
        ) as *mut curl_blob;
        if d.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*d).len = (*src).len;
        (*d).flags = 1 as libc::c_int as libc::c_uint;
        let ref mut fresh0 = (*d).data;
        *fresh0 = (d as *mut libc::c_char)
            .offset(::std::mem::size_of::<curl_blob>() as libc::c_ulong as isize)
            as *mut libc::c_void;
        memcpy((*d).data, (*src).data, (*src).len);
        *dest = d;
    }
    return CURLE_OK;
}
unsafe extern "C" fn blobcmp(mut first: *mut curl_blob, mut second: *mut curl_blob) -> bool {
    if first.is_null() && second.is_null() {
        return 1 as libc::c_int != 0;
    }
    if first.is_null() || second.is_null() {
        return 0 as libc::c_int != 0;
    }
    if (*first).len != (*second).len {
        return 0 as libc::c_int != 0;
    }
    return memcmp((*first).data, (*second).data, (*first).len) == 0;
}
unsafe extern "C" fn safecmp(mut a: *mut libc::c_char, mut b: *mut libc::c_char) -> bool {
    if !a.is_null() && !b.is_null() {
        return strcmp(a, b) == 0;
    } else {
        if a.is_null() && b.is_null() {
            return 1 as libc::c_int != 0;
        }
    }
    return 0 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_config_matches(
    mut data: *mut ssl_primary_config,
    mut needle: *mut ssl_primary_config,
) -> bool {
    if (*data).version == (*needle).version
        && (*data).version_max == (*needle).version_max
        && (*data).verifypeer() as libc::c_int == (*needle).verifypeer() as libc::c_int
        && (*data).verifyhost() as libc::c_int == (*needle).verifyhost() as libc::c_int
        && (*data).verifystatus() as libc::c_int == (*needle).verifystatus() as libc::c_int
        && blobcmp((*data).cert_blob, (*needle).cert_blob) as libc::c_int != 0
        && blobcmp((*data).ca_info_blob, (*needle).ca_info_blob) as libc::c_int != 0
        && blobcmp((*data).issuercert_blob, (*needle).issuercert_blob) as libc::c_int != 0
        && safecmp((*data).CApath, (*needle).CApath) as libc::c_int != 0
        && safecmp((*data).CAfile, (*needle).CAfile) as libc::c_int != 0
        && safecmp((*data).issuercert, (*needle).issuercert) as libc::c_int != 0
        && safecmp((*data).clientcert, (*needle).clientcert) as libc::c_int != 0
        && safecmp((*data).random_file, (*needle).random_file) as libc::c_int != 0
        && safecmp((*data).egdsocket, (*needle).egdsocket) as libc::c_int != 0
        && Curl_safe_strcasecompare((*data).cipher_list, (*needle).cipher_list) != 0
        && Curl_safe_strcasecompare((*data).cipher_list13, (*needle).cipher_list13) != 0
        && Curl_safe_strcasecompare((*data).curves, (*needle).curves) != 0
        && Curl_safe_strcasecompare((*data).pinned_key, (*needle).pinned_key) != 0
    {
        return 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_clone_primary_ssl_config(
    mut source: *mut ssl_primary_config,
    mut dest: *mut ssl_primary_config,
) -> bool {
    (*dest).version = (*source).version;
    (*dest).version_max = (*source).version_max;
    (*dest).set_verifypeer((*source).verifypeer());
    (*dest).set_verifyhost((*source).verifyhost());
    (*dest).set_verifystatus((*source).verifystatus());
    (*dest).set_sessionid((*source).sessionid());
    if blobdup(&mut (*dest).cert_blob, (*source).cert_blob) as u64 != 0 {
        return 0 as libc::c_int != 0;
    }
    if blobdup(&mut (*dest).ca_info_blob, (*source).ca_info_blob) as u64 != 0 {
        return 0 as libc::c_int != 0;
    }
    if blobdup(&mut (*dest).issuercert_blob, (*source).issuercert_blob) as u64 != 0 {
        return 0 as libc::c_int != 0;
    }
    if !((*source).CApath).is_null() {
        let ref mut fresh1 = (*dest).CApath;
        *fresh1 = Curl_cstrdup.expect("non-null function pointer")((*source).CApath);
        if ((*dest).CApath).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh2 = (*dest).CApath;
        *fresh2 = 0 as *mut libc::c_char;
    }
    if !((*source).CAfile).is_null() {
        let ref mut fresh3 = (*dest).CAfile;
        *fresh3 = Curl_cstrdup.expect("non-null function pointer")((*source).CAfile);
        if ((*dest).CAfile).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh4 = (*dest).CAfile;
        *fresh4 = 0 as *mut libc::c_char;
    }
    if !((*source).issuercert).is_null() {
        let ref mut fresh5 = (*dest).issuercert;
        *fresh5 = Curl_cstrdup.expect("non-null function pointer")((*source).issuercert);
        if ((*dest).issuercert).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh6 = (*dest).issuercert;
        *fresh6 = 0 as *mut libc::c_char;
    }
    if !((*source).clientcert).is_null() {
        let ref mut fresh7 = (*dest).clientcert;
        *fresh7 = Curl_cstrdup.expect("non-null function pointer")((*source).clientcert);
        if ((*dest).clientcert).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh8 = (*dest).clientcert;
        *fresh8 = 0 as *mut libc::c_char;
    }
    if !((*source).random_file).is_null() {
        let ref mut fresh9 = (*dest).random_file;
        *fresh9 = Curl_cstrdup.expect("non-null function pointer")((*source).random_file);
        if ((*dest).random_file).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh10 = (*dest).random_file;
        *fresh10 = 0 as *mut libc::c_char;
    }
    if !((*source).egdsocket).is_null() {
        let ref mut fresh11 = (*dest).egdsocket;
        *fresh11 = Curl_cstrdup.expect("non-null function pointer")((*source).egdsocket);
        if ((*dest).egdsocket).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh12 = (*dest).egdsocket;
        *fresh12 = 0 as *mut libc::c_char;
    }
    if !((*source).cipher_list).is_null() {
        let ref mut fresh13 = (*dest).cipher_list;
        *fresh13 = Curl_cstrdup.expect("non-null function pointer")((*source).cipher_list);
        if ((*dest).cipher_list).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh14 = (*dest).cipher_list;
        *fresh14 = 0 as *mut libc::c_char;
    }
    if !((*source).cipher_list13).is_null() {
        let ref mut fresh15 = (*dest).cipher_list13;
        *fresh15 = Curl_cstrdup.expect("non-null function pointer")((*source).cipher_list13);
        if ((*dest).cipher_list13).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh16 = (*dest).cipher_list13;
        *fresh16 = 0 as *mut libc::c_char;
    }
    if !((*source).pinned_key).is_null() {
        let ref mut fresh17 = (*dest).pinned_key;
        *fresh17 = Curl_cstrdup.expect("non-null function pointer")((*source).pinned_key);
        if ((*dest).pinned_key).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh18 = (*dest).pinned_key;
        *fresh18 = 0 as *mut libc::c_char;
    }
    if !((*source).curves).is_null() {
        let ref mut fresh19 = (*dest).curves;
        *fresh19 = Curl_cstrdup.expect("non-null function pointer")((*source).curves);
        if ((*dest).curves).is_null() {
            return 0 as libc::c_int != 0;
        }
    } else {
        let ref mut fresh20 = (*dest).curves;
        *fresh20 = 0 as *mut libc::c_char;
    }
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_free_primary_ssl_config(mut sslc: *mut ssl_primary_config) {
    Curl_cfree.expect("non-null function pointer")((*sslc).CApath as *mut libc::c_void);
    let ref mut fresh21 = (*sslc).CApath;
    *fresh21 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).CAfile as *mut libc::c_void);
    let ref mut fresh22 = (*sslc).CAfile;
    *fresh22 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).issuercert as *mut libc::c_void);
    let ref mut fresh23 = (*sslc).issuercert;
    *fresh23 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).clientcert as *mut libc::c_void);
    let ref mut fresh24 = (*sslc).clientcert;
    *fresh24 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).random_file as *mut libc::c_void);
    let ref mut fresh25 = (*sslc).random_file;
    *fresh25 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).egdsocket as *mut libc::c_void);
    let ref mut fresh26 = (*sslc).egdsocket;
    *fresh26 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).cipher_list as *mut libc::c_void);
    let ref mut fresh27 = (*sslc).cipher_list;
    *fresh27 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).cipher_list13 as *mut libc::c_void);
    let ref mut fresh28 = (*sslc).cipher_list13;
    *fresh28 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).pinned_key as *mut libc::c_void);
    let ref mut fresh29 = (*sslc).pinned_key;
    *fresh29 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*sslc).cert_blob as *mut libc::c_void);
    let ref mut fresh30 = (*sslc).cert_blob;
    *fresh30 = 0 as *mut curl_blob;
    Curl_cfree.expect("non-null function pointer")((*sslc).ca_info_blob as *mut libc::c_void);
    let ref mut fresh31 = (*sslc).ca_info_blob;
    *fresh31 = 0 as *mut curl_blob;
    Curl_cfree.expect("non-null function pointer")((*sslc).issuercert_blob as *mut libc::c_void);
    let ref mut fresh32 = (*sslc).issuercert_blob;
    *fresh32 = 0 as *mut curl_blob;
    Curl_cfree.expect("non-null function pointer")((*sslc).curves as *mut libc::c_void);
    let ref mut fresh33 = (*sslc).curves;
    *fresh33 = 0 as *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_backend() -> libc::c_int {
    #[cfg(USE_SSL)]
    multissl_setup(0 as *const Curl_ssl);
    #[cfg(USE_SSL)]
    return (*Curl_ssl).info.id as libc::c_int;
    #[cfg(not(USE_SSL))]
    return CURLSSLBACKEND_NONE as libc::c_int;
}
#[cfg(USE_SSL)]
static mut init_ssl: bool = 0 as libc::c_int != 0;
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_init() -> libc::c_int {
    if init_ssl {
        return 1 as libc::c_int;
    }
    init_ssl = 1 as libc::c_int != 0;
    return ((*Curl_ssl).init).expect("non-null function pointer")();
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_cleanup() {
    if init_ssl {
        ((*Curl_ssl).cleanup).expect("non-null function pointer")();
        if cfg!(CURL_WITH_MULTI_SSL) {
            Curl_ssl = &Curl_ssl_multi;
        }
        init_ssl = 0 as libc::c_int != 0;
    }
}
#[cfg(USE_SSL)]
unsafe extern "C" fn ssl_prefs_check(mut data: *mut Curl_easy) -> bool {
    let sslver: libc::c_long = (*data).set.ssl.primary.version;
    if sslver < 0 as libc::c_int as libc::c_long
        || sslver >= CURL_SSLVERSION_LAST as libc::c_int as libc::c_long
    {
        Curl_failf(
            data,
            b"Unrecognized parameter value passed via CURLOPT_SSLVERSION\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as libc::c_int != 0;
    }
    match (*data).set.ssl.primary.version_max {
        0 | 65536 => {}
        _ => {
            if ((*data).set.ssl.primary.version_max >> 16 as libc::c_int) < sslver {
                Curl_failf(
                    data,
                    b"CURL_SSLVERSION_MAX incompatible with CURL_SSLVERSION\0"
                        as *const u8 as *const libc::c_char,
                );
                return 0 as libc::c_int != 0;
            }
        }
    }
    return 1 as libc::c_int != 0;
}
#[cfg(all(USE_SSL, not(CURL_DISABLE_PROXY)))]
unsafe extern "C" fn ssl_connect_init_proxy(
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    if ssl_connection_complete as libc::c_int as libc::c_uint
        == (*conn).ssl[sockindex as usize].state as libc::c_uint
        && ((*conn).proxy_ssl[sockindex as usize]).use_0() == 0
    {
        let mut pbdata: *mut ssl_backend_data = 0 as *mut ssl_backend_data;
        if (*Curl_ssl).supports
            & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint == 0
        {
            return CURLE_NOT_BUILT_IN;
        }
        pbdata = (*conn).proxy_ssl[sockindex as usize].backend;
        (*conn).proxy_ssl[sockindex as usize] = (*conn).ssl[sockindex as usize];
        memset(
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize)
                as *mut ssl_connect_data as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<ssl_connect_data>() as libc::c_ulong,
        );
        memset(
            pbdata as *mut libc::c_void,
            0 as libc::c_int,
            (*Curl_ssl).sizeof_ssl_backend_data,
        );
        let ref mut fresh34 = (*conn).ssl[sockindex as usize].backend;
        *fresh34 = pbdata;
    }
    return CURLE_OK;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    #[cfg(not(CURL_DISABLE_PROXY))]
    if (*conn).bits.proxy_ssl_connected[sockindex as usize] {
        result = ssl_connect_init_proxy(conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if !ssl_prefs_check(data) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    let ref mut fresh35 = (*conn).ssl[sockindex as usize];
    (*fresh35).set_use_0(1 as libc::c_int as bit);
    (*conn).ssl[sockindex as usize].state = ssl_connection_negotiating;
    result = ((*Curl_ssl).connect_blocking)
        .expect("non-null function pointer")(data, conn, sockindex);
    if result as u64 == 0 {
        Curl_pgrsTime(data, TIMER_APPCONNECT);
    } else {
        let ref mut fresh36 = (*conn).ssl[sockindex as usize];
        (*fresh36).set_use_0(0 as libc::c_int as bit);
    }
    return result;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut isproxy: bool,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    #[cfg(not(CURL_DISABLE_PROXY))]
    if (*conn).bits.proxy_ssl_connected[sockindex as usize] {
        result = ssl_connect_init_proxy(conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if !ssl_prefs_check(data) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    let ref mut fresh37 = (*conn).ssl[sockindex as usize];
    (*fresh37).set_use_0(1 as libc::c_int as bit);
    result = ((*Curl_ssl).connect_nonblocking)
        .expect("non-null function pointer")(data, conn, sockindex, done);
    if result as u64 != 0 {
        let ref mut fresh38 = (*conn).ssl[sockindex as usize];
        (*fresh38).set_use_0(0 as libc::c_int as bit);
    } else if *done as libc::c_int != 0 && !isproxy {
        Curl_pgrsTime(data, TIMER_APPCONNECT);
    }
    return result;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_sessionid_lock(mut data: *mut Curl_easy) {
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as libc::c_int) << CURL_LOCK_DATA_SSL_SESSION as libc::c_int)
                as libc::c_uint != 0
    {
        Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_sessionid_unlock(mut data: *mut Curl_easy) {
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as libc::c_int) << CURL_LOCK_DATA_SSL_SESSION as libc::c_int)
                as libc::c_uint != 0
    {
        Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_getsessionid(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    isProxy: bool,
    mut ssl_sessionid: *mut *mut libc::c_void,
    mut idsize: *mut size_t,
    mut sockindex: libc::c_int,
) -> bool {
    let mut check: *mut Curl_ssl_session = 0 as *mut Curl_ssl_session;
    let mut i: size_t = 0;
    let mut general_age: *mut libc::c_long = 0 as *mut libc::c_long;
    let mut no_match: bool = 1 as libc::c_int != 0;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let ssl_config: *mut ssl_primary_config = if isProxy as libc::c_int != 0 {
        &mut (*conn).proxy_ssl_config
    } else {
        &mut (*conn).ssl_config
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let ssl_config: *mut ssl_primary_config = &mut (*conn).ssl_config;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let name: *const libc::c_char = if isProxy as libc::c_int != 0 {
        (*conn).http_proxy.host.name
    } else {
        (*conn).host.name
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let name: *const libc::c_char = (*conn).host.name;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut port: libc::c_int = if isProxy as libc::c_int != 0 {
        (*conn).port
    } else {
        (*conn).remote_port
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut port: libc::c_int = (*conn).remote_port;
    *ssl_sessionid = 0 as *mut libc::c_void;
    #[cfg(CURL_DISABLE_PROXY)]
    if isProxy as libc::c_int != 0 {
        return 1 as libc::c_int != 0;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    let flag: bool = (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
    }) == 0;
    #[cfg(CURL_DISABLE_PROXY)]
    let flag: bool = ((*data).set.ssl.primary).sessionid() == 0;
    if flag || ((*data).state.session).is_null()
    {
        return 1 as libc::c_int != 0;
    }
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as libc::c_int) << CURL_LOCK_DATA_SSL_SESSION as libc::c_int)
                as libc::c_uint != 0
    {
        general_age = &mut (*(*data).share).sessionage;
    } else {
        general_age = &mut (*data).state.sessionage;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*data).set.general_ssl.max_ssl_sessions {
        check = &mut *((*data).state.session).offset(i as isize)
            as *mut Curl_ssl_session;
        if !((*check).sessionid).is_null() {
            if Curl_strcasecompare(name, (*check).name) != 0
                && (((*conn).bits).conn_to_host() == 0
                    && ((*check).conn_to_host).is_null()
                    || ((*conn).bits).conn_to_host() as libc::c_int != 0
                        && !((*check).conn_to_host).is_null()
                        && Curl_strcasecompare(
                            (*conn).conn_to_host.name,
                            (*check).conn_to_host,
                        ) != 0)
                && (((*conn).bits).conn_to_port() == 0
                    && (*check).conn_to_port == -(1 as libc::c_int)
                    || ((*conn).bits).conn_to_port() as libc::c_int != 0
                        && (*check).conn_to_port != -(1 as libc::c_int)
                        && (*conn).conn_to_port == (*check).conn_to_port)
                && port == (*check).remote_port
                && Curl_strcasecompare((*(*conn).handler).scheme, (*check).scheme) != 0
                && Curl_ssl_config_matches(ssl_config, &mut (*check).ssl_config)
                    as libc::c_int != 0
            {
                *general_age += 1;
                (*check).age = *general_age;
                *ssl_sessionid = (*check).sessionid;
                if !idsize.is_null() {
                    *idsize = (*check).idsize;
                }
                no_match = 0 as libc::c_int != 0;
                break;
            }
        }
        i = i.wrapping_add(1);
    }
    return no_match;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_kill_session(mut session: *mut Curl_ssl_session) {
    if !((*session).sessionid).is_null() {
        ((*Curl_ssl).session_free)
            .expect("non-null function pointer")((*session).sessionid);
        let ref mut fresh39 = (*session).sessionid;
        *fresh39 = 0 as *mut libc::c_void;
        (*session).age = 0 as libc::c_int as libc::c_long;
        Curl_free_primary_ssl_config(&mut (*session).ssl_config);
        Curl_cfree
            .expect("non-null function pointer")((*session).name as *mut libc::c_void);
        let ref mut fresh40 = (*session).name;
        *fresh40 = 0 as *mut libc::c_char;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*session).conn_to_host as *mut libc::c_void);
        let ref mut fresh41 = (*session).conn_to_host;
        *fresh41 = 0 as *mut libc::c_char;
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_delsessionid(
    mut data: *mut Curl_easy,
    mut ssl_sessionid: *mut libc::c_void,
) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*data).set.general_ssl.max_ssl_sessions {
        let mut check: *mut Curl_ssl_session = &mut *((*data).state.session)
            .offset(i as isize) as *mut Curl_ssl_session;
        if (*check).sessionid == ssl_sessionid {
            Curl_ssl_kill_session(check);
            break;
        } else {
            i = i.wrapping_add(1);
        }
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_addsessionid(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    isProxy: bool,
    mut ssl_sessionid: *mut libc::c_void,
    mut idsize: size_t,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut i: size_t = 0;
    let mut store: *mut Curl_ssl_session = 0 as *mut Curl_ssl_session;
    let mut oldest_age: libc::c_long = 0;
    let mut clone_host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut clone_conn_to_host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut conn_to_port: libc::c_int = 0;
    let mut general_age: *mut libc::c_long = 0 as *mut libc::c_long;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let ssl_config: *mut ssl_primary_config = if isProxy as libc::c_int != 0 {
        &mut (*conn).proxy_ssl_config
    } else {
        &mut (*conn).ssl_config
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let ssl_config: *mut ssl_primary_config = &mut (*conn).ssl_config;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut hostname: *const libc::c_char = if isProxy as libc::c_int != 0 {
        (*conn).http_proxy.host.name
    } else {
        (*conn).host.name
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut hostname: *const libc::c_char = (*conn).host.name;
    if ((*data).state.session).is_null() {
        return CURLE_OK;
    }
    store = &mut *((*data).state.session).offset(0 as libc::c_int as isize)
        as *mut Curl_ssl_session;
    oldest_age = (*((*data).state.session).offset(0 as libc::c_int as isize)).age;
    clone_host = Curl_cstrdup.expect("non-null function pointer")(hostname);
    if clone_host.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if ((*conn).bits).conn_to_host() != 0 {
        clone_conn_to_host = Curl_cstrdup
            .expect("non-null function pointer")((*conn).conn_to_host.name);
        if clone_conn_to_host.is_null() {
            Curl_cfree
                .expect("non-null function pointer")(clone_host as *mut libc::c_void);
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        clone_conn_to_host = 0 as *mut libc::c_char;
    }
    if ((*conn).bits).conn_to_port() != 0 {
        conn_to_port = (*conn).conn_to_port;
    } else {
        conn_to_port = -(1 as libc::c_int);
    }
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as libc::c_int) << CURL_LOCK_DATA_SSL_SESSION as libc::c_int)
                as libc::c_uint != 0
    {
        general_age = &mut (*(*data).share).sessionage;
    } else {
        general_age = &mut (*data).state.sessionage;
    }
    i = 1 as libc::c_int as size_t;
    while i < (*data).set.general_ssl.max_ssl_sessions
        && !((*((*data).state.session).offset(i as isize)).sessionid).is_null()
    {
        if (*((*data).state.session).offset(i as isize)).age < oldest_age {
            oldest_age = (*((*data).state.session).offset(i as isize)).age;
            store = &mut *((*data).state.session).offset(i as isize)
                as *mut Curl_ssl_session;
        }
        i = i.wrapping_add(1);
    }
    if i == (*data).set.general_ssl.max_ssl_sessions {
        Curl_ssl_kill_session(store);
    } else {
        store = &mut *((*data).state.session).offset(i as isize)
            as *mut Curl_ssl_session;
    }
    let ref mut fresh42 = (*store).sessionid;
    *fresh42 = ssl_sessionid;
    (*store).idsize = idsize;
    (*store).age = *general_age;
    Curl_cfree.expect("non-null function pointer")((*store).name as *mut libc::c_void);
    Curl_cfree
        .expect("non-null function pointer")((*store).conn_to_host as *mut libc::c_void);
    let ref mut fresh43 = (*store).name;
    *fresh43 = clone_host;
    let ref mut fresh44 = (*store).conn_to_host;
    *fresh44 = clone_conn_to_host;
    (*store).conn_to_port = conn_to_port;
    (*store)
        .remote_port = if isProxy as libc::c_int != 0 {
        (*conn).port
    } else {
        (*conn).remote_port
    };
    let ref mut fresh45 = (*store).scheme;
    *fresh45 = (*(*conn).handler).scheme;
    if !Curl_clone_primary_ssl_config(ssl_config, &mut (*store).ssl_config) {
        Curl_free_primary_ssl_config(&mut (*store).ssl_config);
        let ref mut fresh46 = (*store).sessionid;
        *fresh46 = 0 as *mut libc::c_void;
        Curl_cfree.expect("non-null function pointer")(clone_host as *mut libc::c_void);
        Curl_cfree
            .expect(
                "non-null function pointer",
            )(clone_conn_to_host as *mut libc::c_void);
        return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_associate_conn(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    if ((*Curl_ssl).associate_connection).is_some() {
        ((*Curl_ssl).associate_connection)
            .expect("non-null function pointer")(data, conn, 0 as libc::c_int);
        if (*conn).sock[1 as libc::c_int as usize] != 0
            && ((*conn).bits).sock_accepted() as libc::c_int != 0
        {
            ((*Curl_ssl).associate_connection)
                .expect("non-null function pointer")(data, conn, 1 as libc::c_int);
        }
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_detach_conn(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    if ((*Curl_ssl).disassociate_connection).is_some() {
        ((*Curl_ssl).disassociate_connection)
            .expect("non-null function pointer")(data, 0 as libc::c_int);
        if (*conn).sock[1 as libc::c_int as usize] != 0
            && ((*conn).bits).sock_accepted() as libc::c_int != 0
        {
            ((*Curl_ssl).disassociate_connection)
                .expect("non-null function pointer")(data, 1 as libc::c_int);
        }
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_close_all(mut data: *mut Curl_easy) {
    if !((*data).state.session).is_null()
        && !(!((*data).share).is_null()
            && (*(*data).share).specifier
                & ((1 as libc::c_int) << CURL_LOCK_DATA_SSL_SESSION as libc::c_int)
                    as libc::c_uint != 0)
    {
        let mut i: size_t = 0;
        i = 0 as libc::c_int as size_t;
        while i < (*data).set.general_ssl.max_ssl_sessions {
            Curl_ssl_kill_session(&mut *((*data).state.session).offset(i as isize));
            i = i.wrapping_add(1);
        }
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.session as *mut libc::c_void);
        let ref mut fresh47 = (*data).state.session;
        *fresh47 = 0 as *mut Curl_ssl_session;
    }
    ((*Curl_ssl).close_all).expect("non-null function pointer")(data);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_getsock(
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> libc::c_int {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut ssl_connect_data;
    if (*connssl).connecting_state as libc::c_uint
        == ssl_connect_2_writing as libc::c_int as libc::c_uint
    {
        *socks
            .offset(0 as libc::c_int as isize) = (*conn).sock[0 as libc::c_int as usize];
        return (1 as libc::c_int) << 16 as libc::c_int + 0 as libc::c_int;
    }
    if (*connssl).connecting_state as libc::c_uint
        == ssl_connect_2_reading as libc::c_int as libc::c_uint
    {
        *socks
            .offset(0 as libc::c_int as isize) = (*conn).sock[0 as libc::c_int as usize];
        return (1 as libc::c_int) << 0 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
    ((*Curl_ssl).close_one).expect("non-null function pointer")(data, conn, sockindex);
    (*conn).ssl[sockindex as usize].state = ssl_connection_none;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    if ((*Curl_ssl).shut_down).expect("non-null function pointer")(data, conn, sockindex)
        != 0
    {
        return CURLE_SSL_SHUTDOWN_FAILED;
    }
    let ref mut fresh48 = (*conn).ssl[sockindex as usize];
    (*fresh48).set_use_0(0 as libc::c_int as bit);
    (*conn).ssl[sockindex as usize].state = ssl_connection_none;
    let ref mut fresh49 = (*conn).recv[sockindex as usize];
    *fresh49 = Some(
        Curl_recv_plain
            as unsafe extern "C" fn(
                *mut Curl_easy,
                libc::c_int,
                *mut libc::c_char,
                size_t,
                *mut CURLcode,
            ) -> ssize_t,
    );
    let ref mut fresh50 = (*conn).send[sockindex as usize];
    *fresh50 = Some(
        Curl_send_plain
            as unsafe extern "C" fn(
                *mut Curl_easy,
                libc::c_int,
                *const libc::c_void,
                size_t,
                *mut CURLcode,
            ) -> ssize_t,
    );
    return CURLE_OK;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_set_engine(
    mut data: *mut Curl_easy,
    mut engine: *const libc::c_char,
) -> CURLcode {
    return ((*Curl_ssl).set_engine).expect("non-null function pointer")(data, engine);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_set_engine_default(
    mut data: *mut Curl_easy,
) -> CURLcode {
    return ((*Curl_ssl).set_engine_default).expect("non-null function pointer")(data);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_engines_list(
    mut data: *mut Curl_easy,
) -> *mut curl_slist {
    return ((*Curl_ssl).engines_list).expect("non-null function pointer")(data);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_initsessions(
    mut data: *mut Curl_easy,
    mut amount: size_t,
) -> CURLcode {
    let mut session: *mut Curl_ssl_session = 0 as *mut Curl_ssl_session;
    if !((*data).state.session).is_null() {
        return CURLE_OK;
    }
    session = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(amount, ::std::mem::size_of::<Curl_ssl_session>() as libc::c_ulong)
        as *mut Curl_ssl_session;
    if session.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (*data).set.general_ssl.max_ssl_sessions = amount;
    let ref mut fresh51 = (*data).state.session;
    *fresh51 = session;
    (*data).state.sessionage = 1 as libc::c_int as libc::c_long;
    return CURLE_OK;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_version(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
) {
    #[cfg(CURL_WITH_MULTI_SSL)]
    multissl_version(buffer, size);
    #[cfg(not(CURL_WITH_MULTI_SSL))]
    ((*Curl_ssl).version).expect("non-null function pointer")(buffer, size);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_check_cxn(mut conn: *mut connectdata) -> libc::c_int {
    return ((*Curl_ssl).check_cxn).expect("non-null function pointer")(conn);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_data_pending(
    mut conn: *const connectdata,
    mut connindex: libc::c_int,
) -> bool {
    return ((*Curl_ssl).data_pending)
        .expect("non-null function pointer")(conn, connindex);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_free_certinfo(mut data: *mut Curl_easy) {
    let mut ci: *mut curl_certinfo = &mut (*data).info.certs;
    if (*ci).num_of_certs != 0 {
        let mut i: libc::c_int = 0;
        i = 0 as libc::c_int;
        while i < (*ci).num_of_certs {
            curl_slist_free_all(*((*ci).certinfo).offset(i as isize));
            let ref mut fresh52 = *((*ci).certinfo).offset(i as isize);
            *fresh52 = 0 as *mut curl_slist;
            i += 1;
        }
        Curl_cfree
            .expect("non-null function pointer")((*ci).certinfo as *mut libc::c_void);
        let ref mut fresh53 = (*ci).certinfo;
        *fresh53 = 0 as *mut *mut curl_slist;
        (*ci).num_of_certs = 0 as libc::c_int;
    }
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_init_certinfo(
    mut data: *mut Curl_easy,
    mut num: libc::c_int,
) -> CURLcode {
    let mut ci: *mut curl_certinfo = &mut (*data).info.certs;
    let mut table: *mut *mut curl_slist = 0 as *mut *mut curl_slist;
    Curl_ssl_free_certinfo(data);
    table = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(num as size_t, ::std::mem::size_of::<*mut curl_slist>() as libc::c_ulong)
        as *mut *mut curl_slist;
    if table.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (*ci).num_of_certs = num;
    let ref mut fresh54 = (*ci).certinfo;
    *fresh54 = table;
    return CURLE_OK;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_push_certinfo_len(
    mut data: *mut Curl_easy,
    mut certnum: libc::c_int,
    mut label: *const libc::c_char,
    mut value: *const libc::c_char,
    mut valuelen: size_t,
) -> CURLcode {
    let mut ci: *mut curl_certinfo = &mut (*data).info.certs;
    let mut output: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut nl: *mut curl_slist = 0 as *mut curl_slist;
    let mut result: CURLcode = CURLE_OK;
    let mut labellen: size_t = strlen(label);
    let mut outlen: size_t = labellen
        .wrapping_add(1 as libc::c_int as libc::c_ulong)
        .wrapping_add(valuelen)
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    output = Curl_cmalloc.expect("non-null function pointer")(outlen)
        as *mut libc::c_char;
    if output.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    curl_msnprintf(output, outlen, b"%s:\0" as *const u8 as *const libc::c_char, label);
    memcpy(
        &mut *output
            .offset(labellen.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize)
            as *mut libc::c_char as *mut libc::c_void,
        value as *const libc::c_void,
        valuelen,
    );
    *output
        .offset(
            labellen
                .wrapping_add(1 as libc::c_int as libc::c_ulong)
                .wrapping_add(valuelen) as isize,
        ) = 0 as libc::c_int as libc::c_char;
    nl = Curl_slist_append_nodup(*((*ci).certinfo).offset(certnum as isize), output);
    if nl.is_null() {
        Curl_cfree.expect("non-null function pointer")(output as *mut libc::c_void);
        curl_slist_free_all(*((*ci).certinfo).offset(certnum as isize));
        result = CURLE_OUT_OF_MEMORY;
    }
    let ref mut fresh55 = *((*ci).certinfo).offset(certnum as isize);
    *fresh55 = nl;
    return result;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_push_certinfo(
    mut data: *mut Curl_easy,
    mut certnum: libc::c_int,
    mut label: *const libc::c_char,
    mut value: *const libc::c_char,
) -> CURLcode {
    let mut valuelen: size_t = strlen(value);
    return Curl_ssl_push_certinfo_len(data, certnum, label, value, valuelen);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut libc::c_uchar,
    mut length: size_t,
) -> CURLcode {
    return ((*Curl_ssl).random)
        .expect("non-null function pointer")(data, entropy, length);
}
#[cfg(USE_SSL)]
unsafe extern "C" fn pubkey_pem_to_der(
    mut pem: *const libc::c_char,
    mut der: *mut *mut libc::c_uchar,
    mut der_len: *mut size_t,
) -> CURLcode {
    let mut stripped_pem: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut begin_pos: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end_pos: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pem_count: size_t = 0;
    let mut stripped_pem_count: size_t = 0 as libc::c_int as size_t;
    let mut pem_len: size_t = 0;
    let mut result: CURLcode = CURLE_OK;
    if pem.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    begin_pos = strstr(
        pem,
        b"-----BEGIN PUBLIC KEY-----\0" as *const u8 as *const libc::c_char,
    );
    if begin_pos.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_count = begin_pos.offset_from(pem) as libc::c_long as size_t;
    if 0 as libc::c_int as libc::c_ulong != pem_count
        && '\n' as i32
            != *pem
                .offset(
                    pem_count.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                ) as libc::c_int
    {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_count = (pem_count as libc::c_ulong)
        .wrapping_add(26 as libc::c_int as libc::c_ulong) as size_t as size_t;
    end_pos = strstr(
        pem.offset(pem_count as isize),
        b"\n-----END PUBLIC KEY-----\0" as *const u8 as *const libc::c_char,
    );
    if end_pos.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_len = end_pos.offset_from(pem) as libc::c_long as size_t;
    stripped_pem = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(
        pem_len.wrapping_sub(pem_count).wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) as *mut libc::c_char;
    if stripped_pem.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    while pem_count < pem_len {
        if '\n' as i32 != *pem.offset(pem_count as isize) as libc::c_int
            && '\r' as i32 != *pem.offset(pem_count as isize) as libc::c_int
        {
            let fresh56 = stripped_pem_count;
            stripped_pem_count = stripped_pem_count.wrapping_add(1);
            *stripped_pem.offset(fresh56 as isize) = *pem.offset(pem_count as isize);
        }
        pem_count = pem_count.wrapping_add(1);
    }
    *stripped_pem.offset(stripped_pem_count as isize) = '\0' as i32 as libc::c_char;
    result = Curl_base64_decode(stripped_pem, der, der_len);
    Curl_cfree.expect("non-null function pointer")(stripped_pem as *mut libc::c_void);
    stripped_pem = 0 as *mut libc::c_char;
    return result;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_pin_peer_pubkey(
    mut data: *mut Curl_easy,
    mut pinnedpubkey: *const libc::c_char,
    mut pubkey: *const libc::c_uchar,
    mut pubkeylen: size_t,
) -> CURLcode {
    let mut fp: *mut FILE = 0 as *mut FILE;
    let mut buf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut pem_ptr: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut result: CURLcode = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    if pinnedpubkey.is_null() {
        return CURLE_OK;
    }
    if pubkey.is_null() || pubkeylen == 0 {
        return result;
    }
    if strncmp(
        pinnedpubkey,
        b"sha256//\0" as *const u8 as *const libc::c_char,
        8 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        let mut encode: CURLcode = CURLE_OK;
        let mut encodedlen: size_t = 0;
        let mut pinkeylen: size_t = 0;
        let mut encoded: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut pinkeycopy: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut begin_pos: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut end_pos: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut sha256sumdigest: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
        if ((*Curl_ssl).sha256sum).is_none() {
            return result;
        }
        sha256sumdigest = Curl_cmalloc
            .expect("non-null function pointer")(32 as libc::c_int as size_t)
            as *mut libc::c_uchar;
        if sha256sumdigest.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        encode = ((*Curl_ssl).sha256sum)
            .expect(
                "non-null function pointer",
            )(pubkey, pubkeylen, sha256sumdigest, 32 as libc::c_int as size_t);
        if encode as libc::c_uint != CURLE_OK as libc::c_int as libc::c_uint {
            return encode;
        }
        encode = Curl_base64_encode(
            data,
            sha256sumdigest as *mut libc::c_char,
            32 as libc::c_int as size_t,
            &mut encoded,
            &mut encodedlen,
        );
        Curl_cfree
            .expect("non-null function pointer")(sha256sumdigest as *mut libc::c_void);
        sha256sumdigest = 0 as *mut libc::c_uchar;
        if encode as u64 != 0 {
            return encode;
        }
        Curl_infof(
            data,
            b" public key hash: sha256//%s\0" as *const u8 as *const libc::c_char,
            encoded,
        );
        pinkeylen = (strlen(pinnedpubkey))
            .wrapping_add(1 as libc::c_int as libc::c_ulong);
        pinkeycopy = Curl_cmalloc.expect("non-null function pointer")(pinkeylen)
            as *mut libc::c_char;
        if pinkeycopy.is_null() {
            Curl_cfree.expect("non-null function pointer")(encoded as *mut libc::c_void);
            encoded = 0 as *mut libc::c_char;
            return CURLE_OUT_OF_MEMORY;
        }
        memcpy(
            pinkeycopy as *mut libc::c_void,
            pinnedpubkey as *const libc::c_void,
            pinkeylen,
        );
        begin_pos = pinkeycopy;
        loop {
            end_pos = strstr(
                begin_pos,
                b";sha256//\0" as *const u8 as *const libc::c_char,
            );
            if !end_pos.is_null() {
                *end_pos.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
            }
            if encodedlen == strlen(begin_pos.offset(8 as libc::c_int as isize))
                && memcmp(
                    encoded as *const libc::c_void,
                    begin_pos.offset(8 as libc::c_int as isize) as *const libc::c_void,
                    encodedlen,
                ) == 0
            {
                result = CURLE_OK;
                break;
            } else {
                if !end_pos.is_null() {
                    *end_pos
                        .offset(0 as libc::c_int as isize) = ';' as i32 as libc::c_char;
                    begin_pos = strstr(
                        end_pos,
                        b"sha256//\0" as *const u8 as *const libc::c_char,
                    );
                }
                if !(!end_pos.is_null() && !begin_pos.is_null()) {
                    break;
                }
            }
        }
        Curl_cfree.expect("non-null function pointer")(encoded as *mut libc::c_void);
        encoded = 0 as *mut libc::c_char;
        Curl_cfree.expect("non-null function pointer")(pinkeycopy as *mut libc::c_void);
        pinkeycopy = 0 as *mut libc::c_char;
        return result;
    }
    fp = fopen(pinnedpubkey, b"rb\0" as *const u8 as *const libc::c_char);
    if fp.is_null() {
        return result;
    }
    let mut filesize: libc::c_long = 0;
    let mut size: size_t = 0;
    let mut pem_len: size_t = 0;
    let mut pem_read: CURLcode = CURLE_OK;
    if !(fseek(fp, 0 as libc::c_int as libc::c_long, 2 as libc::c_int) != 0) {
        filesize = ftell(fp);
        if !(fseek(fp, 0 as libc::c_int as libc::c_long, 0 as libc::c_int) != 0) {
            if !(filesize < 0 as libc::c_int as libc::c_long
                || filesize > 1048576 as libc::c_int as libc::c_long)
            {
                size = curlx_sotouz(filesize);
                if !(pubkeylen > size) {
                    buf = Curl_cmalloc
                        .expect(
                            "non-null function pointer",
                        )(size.wrapping_add(1 as libc::c_int as libc::c_ulong))
                        as *mut libc::c_uchar;
                    if !buf.is_null() {
                        if !(fread(
                            buf as *mut libc::c_void,
                            size,
                            1 as libc::c_int as libc::c_ulong,
                            fp,
                        ) as libc::c_int != 1 as libc::c_int)
                        {
                            if pubkeylen == size {
                                if memcmp(
                                    pubkey as *const libc::c_void,
                                    buf as *const libc::c_void,
                                    pubkeylen,
                                ) == 0
                                {
                                    result = CURLE_OK;
                                }
                            } else {
                                *buf.offset(size as isize) = '\0' as i32 as libc::c_uchar;
                                pem_read = pubkey_pem_to_der(
                                    buf as *const libc::c_char,
                                    &mut pem_ptr,
                                    &mut pem_len,
                                );
                                if !(pem_read as u64 != 0) {
                                    if pubkeylen == pem_len
                                        && memcmp(
                                            pubkey as *const libc::c_void,
                                            pem_ptr as *const libc::c_void,
                                            pubkeylen,
                                        ) == 0
                                    {
                                        result = CURLE_OK;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(buf as *mut libc::c_void);
    buf = 0 as *mut libc::c_uchar;
    Curl_cfree.expect("non-null function pointer")(pem_ptr as *mut libc::c_void);
    pem_ptr = 0 as *mut libc::c_uchar;
    fclose(fp);
    return result;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_cert_status_request() -> bool {
    return ((*Curl_ssl).cert_status_request).expect("non-null function pointer")();
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_false_start() -> bool {
    return ((*Curl_ssl).false_start).expect("non-null function pointer")();
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_tls13_ciphersuites() -> bool {
    return (*Curl_ssl).supports
        & ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uint != 0;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_init() -> libc::c_int {
    return 1 as libc::c_int;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_cleanup() {}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> libc::c_int {
    return 0 as libc::c_int;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_check_cxn(mut conn: *mut connectdata) -> libc::c_int {
    return -(1 as libc::c_int);
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut libc::c_uchar,
    mut length: size_t,
) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_close_all(mut data: *mut Curl_easy) {}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_session_free(mut ptr: *mut libc::c_void) {}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_data_pending(
    mut conn: *const connectdata,
    mut connindex: libc::c_int,
) -> bool {
    return 0 as libc::c_int != 0;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_cert_status_request() -> bool {
    return 0 as libc::c_int != 0;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_set_engine(
    mut data: *mut Curl_easy,
    mut engine: *const libc::c_char,
) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_set_engine_default(
    mut data: *mut Curl_easy,
) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_engines_list(
    mut data: *mut Curl_easy,
) -> *mut curl_slist {
    return 0 as *mut libc::c_void as *mut curl_slist;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn Curl_none_false_start() -> bool {
    return 0 as libc::c_int != 0;
}
#[cfg(USE_SSL)]
unsafe extern "C" fn multissl_init() -> libc::c_int {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return 1 as libc::c_int;
    }
    return ((*Curl_ssl).init).expect("non-null function pointer")();
}
#[cfg(USE_SSL)]
unsafe extern "C" fn multissl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return CURLE_FAILED_INIT;
    }
    return ((*Curl_ssl).connect_blocking)
        .expect("non-null function pointer")(data, conn, sockindex);
}
#[cfg(USE_SSL)]
unsafe extern "C" fn multissl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return CURLE_FAILED_INIT;
    }
    return ((*Curl_ssl).connect_nonblocking)
        .expect("non-null function pointer")(data, conn, sockindex, done);
}
#[cfg(USE_SSL)]
unsafe extern "C" fn multissl_getsock(
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> libc::c_int {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return 0 as libc::c_int;
    }
    return ((*Curl_ssl).getsock).expect("non-null function pointer")(conn, socks);
}
#[cfg(USE_SSL)]
unsafe extern "C" fn multissl_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return 0 as *mut libc::c_void;
    }
    return ((*Curl_ssl).get_internals)
        .expect("non-null function pointer")(connssl, info);
}
#[cfg(USE_SSL)]
unsafe extern "C" fn multissl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return;
    }
    ((*Curl_ssl).close_one).expect("non-null function pointer")(data, conn, sockindex);
}
#[cfg(USE_SSL)]
static mut Curl_ssl_multi: Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_NONE,
                    name: b"multi\0" as *const u8 as *const libc::c_char,
                };
                init
            },
            supports: 0 as libc::c_int as libc::c_uint,
            sizeof_ssl_backend_data: -(1 as libc::c_int) as size_t,
            init: Some(multissl_init as unsafe extern "C" fn() -> libc::c_int),
            cleanup: Some(Curl_none_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(
                multissl_version
                    as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t,
            ),
            check_cxn: Some(
                Curl_none_check_cxn
                    as unsafe extern "C" fn(*mut connectdata) -> libc::c_int,
            ),
            shut_down: Some(
                Curl_none_shutdown
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            data_pending: Some(
                Curl_none_data_pending
                    as unsafe extern "C" fn(*const connectdata, libc::c_int) -> bool,
            ),
            random: Some(
                Curl_none_random
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut libc::c_uchar,
                        size_t,
                    ) -> CURLcode,
            ),
            cert_status_request: Some(
                Curl_none_cert_status_request as unsafe extern "C" fn() -> bool,
            ),
            connect_blocking: Some(
                multissl_connect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> CURLcode,
            ),
            connect_nonblocking: Some(
                multissl_connect_nonblocking
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                        *mut bool,
                    ) -> CURLcode,
            ),
            getsock: Some(
                multissl_getsock
                    as unsafe extern "C" fn(
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            get_internals: Some(
                multissl_get_internals
                    as unsafe extern "C" fn(
                        *mut ssl_connect_data,
                        CURLINFO,
                    ) -> *mut libc::c_void,
            ),
            close_one: Some(
                multissl_close
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> (),
            ),
            close_all: Some(
                Curl_none_close_all as unsafe extern "C" fn(*mut Curl_easy) -> (),
            ),
            session_free: Some(
                Curl_none_session_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            set_engine: Some(
                Curl_none_set_engine
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *const libc::c_char,
                    ) -> CURLcode,
            ),
            set_engine_default: Some(
                Curl_none_set_engine_default
                    as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
            ),
            engines_list: Some(
                Curl_none_engines_list
                    as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
            ),
            false_start: Some(Curl_none_false_start as unsafe extern "C" fn() -> bool),
            sha256sum: None,
            associate_connection: None,
            disassociate_connection: None,
        };
        init
    }
};
// TODO 待测试，这里只能先把别的注释掉然后测试
#[cfg(USE_SSL)]
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe {
    // if cfg!(CURL_WITH_MULTI_SSL) {
        // &Curl_ssl_multi as *const Curl_ssl
    // } else if cfg!(USE_WOLFSSL) {
    //     &Curl_ssl_wolfssl as *const Curl_ssl
    // } else if cfg!(USE_SECTRANSP) {
    //     &Curl_ssl_sectransp as *const Curl_ssl
    // } else if cfg!(USE_GNUTLS) {
    //     &Curl_ssl_gnutls as *const Curl_ssl
    // } else if cfg!(USE_GSKIT) {
    //     &Curl_ssl_gskit as *const Curl_ssl
    // } else if cfg!(USE_MBEDTLS) {
    //     &Curl_ssl_mbedtls as *const Curl_ssl
    // } else if cfg!(USE_NSS) {
    //     &Curl_ssl_nss as *const Curl_ssl
    // } else if cfg!(USE_RUSTLS) {
    //     &Curl_ssl_rustls as *const Curl_ssl
    // } else if cfg!(USE_OPENSSL) {
        &Curl_ssl_openssl as *const Curl_ssl
    // } else if cfg!(USE_SCHANNEL) {
    //     &Curl_ssl_schannel as *const Curl_ssl
    // } else if cfg!(USE_MESALINK) {
    //     &Curl_ssl_mesalink as *const Curl_ssl
    // } else if cfg!(USE_BEARSSL) {
    //     &Curl_ssl_bearssl as *const Curl_ssl
    // }
};
// TODO 这里的2得改掉，最好是省略数组长度，这里也得先注释了再测试
#[cfg(USE_SSL)]
static mut available_backends: [*const Curl_ssl; 2] = unsafe {
    [
        // #[cfg(USE_WOLFSSL)]
        // &Curl_ssl_wolfssl as *const Curl_ssl,
        // #[cfg(USE_SECTRANSP)]
        // &Curl_ssl_sectransp as *const Curl_ssl,
        // #[cfg(USE_GNUTLS)]
        // &Curl_ssl_gnutls as *const Curl_ssl,
        // #[cfg(USE_GSKIT)]
        // &Curl_ssl_gskit as *const Curl_ssl,
        // #[cfg(USE_MBEDTLS)]
        // &Curl_ssl_mbedtls as *const Curl_ssl,
        // #[cfg(USE_NSS)]
        // &Curl_ssl_nss as *const Curl_ssl,
        #[cfg(USE_OPENSSL)]
        &Curl_ssl_openssl as *const Curl_ssl,
        // #[cfg(USE_SCHANNEL)]
        // &Curl_ssl_schannel as *const Curl_ssl,
        // #[cfg(USE_MESALINK)]
        // &Curl_ssl_mesalink as *const Curl_ssl,
        // #[cfg(USE_BEARSSL)]
        // &Curl_ssl_bearssl as *const Curl_ssl,
        // #[cfg(USE_RUSTLS)]
        // &Curl_ssl_rustls as *const Curl_ssl,
        0 as *const Curl_ssl,
    ]
};
#[cfg(USE_SSL)]
unsafe extern "C" fn multissl_version(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
) -> size_t {
    static mut selected: *const Curl_ssl = 0 as *const Curl_ssl;
    static mut backends: [libc::c_char; 200] = [0; 200];
    static mut backends_len: size_t = 0;
    let mut current: *const Curl_ssl = 0 as *const Curl_ssl;
    current = if Curl_ssl == &Curl_ssl_multi as *const Curl_ssl {
        available_backends[0 as libc::c_int as usize]
    } else {
        Curl_ssl
    };
    if current != selected {
        let mut p: *mut libc::c_char = backends.as_mut_ptr();
        let mut end: *mut libc::c_char = backends
            .as_mut_ptr()
            .offset(
                ::std::mem::size_of::<[libc::c_char; 200]>() as libc::c_ulong as isize,
            );
        let mut i: libc::c_int = 0;
        selected = current;
        backends[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
        i = 0 as libc::c_int;
        while !(available_backends[i as usize]).is_null() {
            let mut vb: [libc::c_char; 200] = [0; 200];
            let mut paren: bool = selected != available_backends[i as usize];
            if ((*available_backends[i as usize]).version)
                .expect(
                    "non-null function pointer",
                )(
                vb.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 200]>() as libc::c_ulong,
            ) != 0
            {
                p = p
                    .offset(
                        curl_msnprintf(
                            p,
                            end.offset_from(p) as libc::c_long as size_t,
                            b"%s%s%s%s\0" as *const u8 as *const libc::c_char,
                            if p != backends.as_mut_ptr() {
                                b" \0" as *const u8 as *const libc::c_char
                            } else {
                                b"\0" as *const u8 as *const libc::c_char
                            },
                            if paren as libc::c_int != 0 {
                                b"(\0" as *const u8 as *const libc::c_char
                            } else {
                                b"\0" as *const u8 as *const libc::c_char
                            },
                            vb.as_mut_ptr(),
                            if paren as libc::c_int != 0 {
                                b")\0" as *const u8 as *const libc::c_char
                            } else {
                                b"\0" as *const u8 as *const libc::c_char
                            },
                        ) as isize,
                    );
            }
            i += 1;
        }
        backends_len = p.offset_from(backends.as_mut_ptr()) as libc::c_long as size_t;
    }
    if size == 0 {
        return 0 as libc::c_int as size_t;
    }
    if size <= backends_len {
        strncpy(
            buffer,
            backends.as_mut_ptr(),
            size.wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
        *buffer
            .offset(
                size.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            ) = '\0' as i32 as libc::c_char;
        return size.wrapping_sub(1 as libc::c_int as libc::c_ulong);
    }
    strcpy(buffer, backends.as_mut_ptr());
    return backends_len;
}
#[cfg(USE_SSL)]
unsafe extern "C" fn multissl_setup(mut backend: *const Curl_ssl) -> libc::c_int {
    let mut env: *const libc::c_char = 0 as *const libc::c_char;
    let mut env_tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    if Curl_ssl != &Curl_ssl_multi as *const Curl_ssl {
        return 1 as libc::c_int;
    }
    if !backend.is_null() {
        Curl_ssl = backend;
        return 0 as libc::c_int;
    }
    if (available_backends[0 as libc::c_int as usize]).is_null() {
        return 1 as libc::c_int;
    }
    env_tmp = curl_getenv(b"CURL_SSL_BACKEND\0" as *const u8 as *const libc::c_char);
    env = env_tmp;
    #[cfg(CURL_DEFAULT_SSL_BACKEND)]
    if env.is_null() {
        env = CURL_DEFAULT_SSL_BACKEND;
    }
    if !env.is_null() {
        let mut i: libc::c_int = 0;
        i = 0 as libc::c_int;
        while !(available_backends[i as usize]).is_null() {
            if Curl_strcasecompare(env, (*available_backends[i as usize]).info.name) != 0
            {
                Curl_ssl = available_backends[i as usize];
                Curl_cfree
                    .expect("non-null function pointer")(env_tmp as *mut libc::c_void);
                return 0 as libc::c_int;
            }
            i += 1;
        }
    }
    Curl_ssl = available_backends[0 as libc::c_int as usize];
    Curl_cfree.expect("non-null function pointer")(env_tmp as *mut libc::c_void);
    return 0 as libc::c_int;
}
#[cfg(USE_SSL)]
#[no_mangle]
pub unsafe extern "C" fn curl_global_sslset(
    mut id: curl_sslbackend,
    mut name: *const libc::c_char,
    mut avail: *mut *mut *const curl_ssl_backend,
) -> CURLsslset {
    let mut i: libc::c_int = 0;
    if !avail.is_null() {
        // TODO 这里最后的2也得根据开了多少个ssl进行更改
        *avail = &mut available_backends as *mut [*const Curl_ssl; 2]
            as *mut *const curl_ssl_backend;
    }
    if Curl_ssl != &Curl_ssl_multi as *const Curl_ssl {
        return (if id as libc::c_uint == (*Curl_ssl).info.id as libc::c_uint
            || !name.is_null() && Curl_strcasecompare(name, (*Curl_ssl).info.name) != 0
        {
            CURLSSLSET_OK as libc::c_int
        } else {
            if cfg!(CURL_WITH_MULTI_SSL) {
                CURLSSLSET_TOO_LATE as libc::c_int
            } else {
                CURLSSLSET_UNKNOWN_BACKEND as libc::c_int
            }
        }) as CURLsslset;
    }
    i = 0 as libc::c_int;
    while !(available_backends[i as usize]).is_null() {
        if (*available_backends[i as usize]).info.id as libc::c_uint
            == id as libc::c_uint
            || !name.is_null()
                && Curl_strcasecompare((*available_backends[i as usize]).info.name, name)
                    != 0
        {
            multissl_setup(available_backends[i as usize]);
            return CURLSSLSET_OK;
        }
        i += 1;
    }
    return CURLSSLSET_UNKNOWN_BACKEND;
}
#[cfg(not(USE_SSL))]
#[no_mangle]
pub unsafe extern "C" fn curl_global_sslset(
    mut id: curl_sslbackend,
    mut name: *const libc::c_char,
    mut avail: *mut *mut *const curl_ssl_backend,
) -> CURLsslset {
    return CURLSSLSET_NO_BACKENDS;
}
