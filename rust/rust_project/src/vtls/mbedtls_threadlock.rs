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
 * Description: support mbedtls backend
 ******************************************************************************/
use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;

#[cfg(all(USE_THREADS_POSIX, HAVE_PTHREAD_H))]
static mut mutex_buf: *mut pthread_mutex_t = 0 as *const pthread_mutex_t
    as *mut pthread_mutex_t;
#[cfg(all(USE_THREADS_POSIX, HAVE_PTHREAD_H))]
#[no_mangle]
pub unsafe extern "C" fn Curl_mbedtlsthreadlock_thread_setup() -> libc::c_int {
    let mut i: libc::c_int = 0;
    mutex_buf = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        (2 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<pthread_mutex_t>() as libc::c_ulong),
        1 as libc::c_int as size_t,
    ) as *mut pthread_mutex_t;
    if mutex_buf.is_null() {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while i < 2 as libc::c_int {
        if pthread_mutex_init(
            &mut *mutex_buf.offset(i as isize),
            0 as *const pthread_mutexattr_t,
        ) != 0
        {
            return 0 as libc::c_int;
        }
        i += 1;
    }
    return 1 as libc::c_int;
}
#[cfg(any(not(USE_THREADS_POSIX), not(HAVE_PTHREAD_H)))]
#[no_mangle]
pub unsafe extern "C" fn Curl_mbedtlsthreadlock_thread_setup() -> libc::c_int {
    return 1 as libc::c_int;
}
#[cfg(all(USE_THREADS_POSIX, HAVE_PTHREAD_H))]
#[no_mangle]
pub unsafe extern "C" fn Curl_mbedtlsthreadlock_thread_cleanup() -> libc::c_int {
    let mut i: libc::c_int = 0;
    if mutex_buf.is_null() {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while i < 2 as libc::c_int {
        if pthread_mutex_destroy(&mut *mutex_buf.offset(i as isize)) != 0 {
            return 0 as libc::c_int;
        }
        i += 1;
    }
    Curl_cfree.expect("non-null function pointer")(mutex_buf as *mut libc::c_void);
    mutex_buf = 0 as *mut pthread_mutex_t;
    return 1 as libc::c_int;
}
#[cfg(any(not(USE_THREADS_POSIX), not(HAVE_PTHREAD_H)))]
#[no_mangle]
pub unsafe extern "C" fn Curl_mbedtlsthreadlock_thread_cleanup() -> libc::c_int {
    return 1 as libc::c_int;
}
#[cfg(all(USE_THREADS_POSIX, HAVE_PTHREAD_H))]
#[no_mangle]
pub unsafe extern "C" fn Curl_mbedtlsthreadlock_lock_function(
    mut n: libc::c_int,
) -> libc::c_int {
    if n < 2 as libc::c_int {
        if pthread_mutex_lock(&mut *mutex_buf.offset(n as isize)) != 0 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[cfg(any(not(USE_THREADS_POSIX), not(HAVE_PTHREAD_H)))]
#[no_mangle]
pub unsafe extern "C" fn Curl_mbedtlsthreadlock_lock_function(
    mut n: libc::c_int,
) -> libc::c_int {
    return 1 as libc::c_int;
}
#[cfg(all(USE_THREADS_POSIX, HAVE_PTHREAD_H))]
#[no_mangle]
pub unsafe extern "C" fn Curl_mbedtlsthreadlock_unlock_function(
    mut n: libc::c_int,
) -> libc::c_int {
    if n < 2 as libc::c_int {
        if pthread_mutex_unlock(&mut *mutex_buf.offset(n as isize)) != 0 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[cfg(any(not(USE_THREADS_POSIX), not(HAVE_PTHREAD_H)))]
#[no_mangle]
pub unsafe extern "C" fn Curl_mbedtlsthreadlock_unlock_function(
    mut n: libc::c_int,
) -> libc::c_int {
    return 1 as libc::c_int;
}
