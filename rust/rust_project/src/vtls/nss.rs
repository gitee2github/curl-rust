use ::libc;
use rust_ffi::src::ffi_alias::type_alias::*;
use rust_ffi::src::ffi_fun::fun_call::*;
use rust_ffi::src::ffi_struct::struct_define::*;
use crate::src::vtls::vtls::*;

#[inline]
unsafe extern "C" fn stat(
    mut __path: *const libc::c_char,
    mut __statbuf: *mut stat,
) -> libc::c_int {
    return __xstat(1 as libc::c_int, __path, __statbuf);
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
static mut initialized: libc::c_int = 0 as libc::c_int;
static mut cipherlist: [cipher_s; 94] = [
    {
        let mut init = cipher_s {
            name: b"rc4\0" as *const u8 as *const libc::c_char,
            num: 0xff01 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rc4-md5\0" as *const u8 as *const libc::c_char,
            num: 0xff01 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rc4export\0" as *const u8 as *const libc::c_char,
            num: 0xff02 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rc2\0" as *const u8 as *const libc::c_char,
            num: 0xff03 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rc2export\0" as *const u8 as *const libc::c_char,
            num: 0xff04 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"des\0" as *const u8 as *const libc::c_char,
            num: 0xff06 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"desede3\0" as *const u8 as *const libc::c_char,
            num: 0xff07 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_rc4_128_md5\0" as *const u8 as *const libc::c_char,
            num: 0x4 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_rc4_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0x5 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_3des_sha\0" as *const u8 as *const libc::c_char,
            num: 0xa as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_des_sha\0" as *const u8 as *const libc::c_char,
            num: 0x9 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_rc4_40_md5\0" as *const u8 as *const libc::c_char,
            num: 0x3 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_rc2_40_md5\0" as *const u8 as *const libc::c_char,
            num: 0x6 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_null_md5\0" as *const u8 as *const libc::c_char,
            num: 0x1 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_null_sha\0" as *const u8 as *const libc::c_char,
            num: 0x2 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"fips_3des_sha\0" as *const u8 as *const libc::c_char,
            num: 0xfeff as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"fips_des_sha\0" as *const u8 as *const libc::c_char,
            num: 0xfefe as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"fortezza\0" as *const u8 as *const libc::c_char,
            num: 0x1d as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"fortezza_rc4_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0x1e as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"fortezza_null\0" as *const u8 as *const libc::c_char,
            num: 0x1c as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_3des_sha\0" as *const u8 as *const libc::c_char,
            num: 0x16 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_3des_sha\0" as *const u8 as *const libc::c_char,
            num: 0x13 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_des_sha\0" as *const u8 as *const libc::c_char,
            num: 0x15 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_des_sha\0" as *const u8 as *const libc::c_char,
            num: 0x12 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_des_56_sha\0" as *const u8 as *const libc::c_char,
            num: 0x62 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_rc4_56_sha\0" as *const u8 as *const libc::c_char,
            num: 0x64 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_rc4_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0x66 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_aes_128_cbc_sha\0" as *const u8 as *const libc::c_char,
            num: 0x32 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_aes_256_cbc_sha\0" as *const u8 as *const libc::c_char,
            num: 0x38 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_aes_128_cbc_sha\0" as *const u8 as *const libc::c_char,
            num: 0x33 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_aes_256_cbc_sha\0" as *const u8 as *const libc::c_char,
            num: 0x39 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0x2f as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
            num: 0x35 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_ecdsa_null_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc001 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_ecdsa_rc4_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc002 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_ecdsa_3des_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc003 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_ecdsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc004 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_ecdsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc005 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_null_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc006 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_rc4_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc007 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_3des_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc008 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc009 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc00a as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_rsa_null_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc00b as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_rsa_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc00c as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_rsa_3des_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc00d as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_rsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc00e as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_rsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc00f as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_null\0" as *const u8 as *const libc::c_char,
            num: 0xc010 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_rc4_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc011 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_3des_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc012 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_aes_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc013 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_aes_256_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc014 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_anon_null_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc015 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_anon_rc4_128sha\0" as *const u8 as *const libc::c_char,
            num: 0xc016 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_anon_3des_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc017 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_anon_aes_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc018 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_anon_aes_256_sha\0" as *const u8 as *const libc::c_char,
            num: 0xc019 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_null_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x3b as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_aes_128_cbc_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x3c as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_aes_256_cbc_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x3d as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_aes_128_cbc_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x67 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_aes_256_cbc_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x6b as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_aes_128_cbc_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xc023 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_aes_128_cbc_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xc027 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x9c as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x9e as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xa2 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xc02b as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_ecdsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xc02d as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xc02f as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdh_rsa_aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xc031 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
            num: 0x9d as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
            num: 0x9f as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
            num: 0xa3 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_aes_256_sha_384\0" as *const u8 as *const libc::c_char,
            num: 0xc024 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_aes_256_sha_384\0" as *const u8 as *const libc::c_char,
            num: 0xc028 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
            num: 0xc02c as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
            num: 0xc030 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_rsa_chacha20_poly1305_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xcca8 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"ecdhe_ecdsa_chacha20_poly1305_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xcca9 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_chacha20_poly1305_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0xccaa as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"aes_128_gcm_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x1301 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"aes_256_gcm_sha_384\0" as *const u8 as *const libc::c_char,
            num: 0x1302 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"chacha20_poly1305_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x1303 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_aes_128_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x40 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_aes_256_sha_256\0" as *const u8 as *const libc::c_char,
            num: 0x6a as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_camellia_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0x45 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_camellia_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0x44 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_rsa_camellia_256_sha\0" as *const u8 as *const libc::c_char,
            num: 0x88 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"dhe_dss_camellia_256_sha\0" as *const u8 as *const libc::c_char,
            num: 0x87 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_camellia_128_sha\0" as *const u8 as *const libc::c_char,
            num: 0x41 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_camellia_256_sha\0" as *const u8 as *const libc::c_char,
            num: 0x84 as libc::c_int,
        };
        init
    },
    {
        let mut init = cipher_s {
            name: b"rsa_seed_sha\0" as *const u8 as *const libc::c_char,
            num: 0x96 as libc::c_int,
        };
        init
    },
];
static mut pem_library: *const libc::c_char = b"libnsspem.so\0" as *const u8 as *const libc::c_char;
static mut trust_library: *const libc::c_char =
    b"libnssckbi.so\0" as *const u8 as *const libc::c_char;
static mut pem_module: *mut SECMODModule = 0 as *const SECMODModule as *mut SECMODModule;
static mut trust_module: *mut SECMODModule = 0 as *const SECMODModule as *mut SECMODModule;
static mut nspr_io_identity: PRDescIdentity = -(1 as libc::c_int);
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
unsafe extern "C" fn nss_error_to_name(mut code: PRErrorCode) -> *const libc::c_char {
    let mut name: *const libc::c_char = PR_ErrorToName(code);
    if !name.is_null() {
        return name;
    }
    return b"unknown error\0" as *const u8 as *const libc::c_char;
}
unsafe extern "C" fn nss_print_error_message(mut data: *mut Curl_easy, mut err: PRUint32) {
    Curl_failf(
        data,
        b"%s\0" as *const u8 as *const libc::c_char,
        PR_ErrorToString(err as PRErrorCode, 0 as libc::c_int as PRLanguageCode),
    );
}
unsafe extern "C" fn nss_sslver_to_name(mut nssver: PRUint16) -> *mut libc::c_char {
    match nssver as libc::c_int {
        2 => {
            return Curl_cstrdup.expect("non-null function pointer")(
                b"SSLv2\0" as *const u8 as *const libc::c_char,
            );
        }
        768 => {
            return Curl_cstrdup.expect("non-null function pointer")(
                b"SSLv3\0" as *const u8 as *const libc::c_char,
            );
        }
        769 => {
            return Curl_cstrdup.expect("non-null function pointer")(
                b"TLSv1.0\0" as *const u8 as *const libc::c_char,
            );
        }
        #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
        770 => {
            return Curl_cstrdup.expect("non-null function pointer")(
                b"TLSv1.1\0" as *const u8 as *const libc::c_char,
            );
        }
        #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
        771 => {
            return Curl_cstrdup.expect("non-null function pointer")(
                b"TLSv1.2\0" as *const u8 as *const libc::c_char,
            );
        }
        #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
        772 => {
            return Curl_cstrdup.expect("non-null function pointer")(
                b"TLSv1.3\0" as *const u8 as *const libc::c_char,
            );
        }
        _ => {
            return curl_maprintf(
                b"0x%04x\0" as *const u8 as *const libc::c_char,
                nssver as libc::c_int,
            );
        }
    };
}
unsafe extern "C" fn set_ciphers(
    mut data: *mut Curl_easy,
    mut model: *mut PRFileDesc,
    mut cipher_list: *mut libc::c_char,
) -> SECStatus {
    let mut i: libc::c_uint = 0;
    let mut cipher_state: [PRBool; 94] = [0; 94];
    let mut found: PRBool = 0;
    let mut cipher: *mut libc::c_char = 0 as *mut libc::c_char;
    let num_implemented_ciphers: PRUint16 = SSL_GetNumImplementedCiphers();
    let mut implemented_ciphers: *const PRUint16 = SSL_GetImplementedCiphers();
    if implemented_ciphers.is_null() {
        return SECFailure;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < num_implemented_ciphers as libc::c_uint {
        SSL_CipherPrefSet(
            model,
            *implemented_ciphers.offset(i as isize) as PRInt32,
            0 as libc::c_int,
        );
        i = i.wrapping_add(1);
    }
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::std::mem::size_of::<[cipher_s; 94]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<cipher_s>() as libc::c_ulong)
    {
        cipher_state[i as usize] = 0 as libc::c_int;
        i = i.wrapping_add(1);
    }
    cipher = cipher_list;
    while !cipher_list.is_null()
        && *cipher_list.offset(0 as libc::c_int as isize) as libc::c_int != 0
    {
        while *cipher as libc::c_int != 0
            && Curl_isspace(*cipher as libc::c_uchar as libc::c_int) != 0
        {
            cipher = cipher.offset(1);
        }
        cipher_list = strpbrk(cipher, b":, \0" as *const u8 as *const libc::c_char);
        if !cipher_list.is_null() {
            let fresh0 = cipher_list;
            cipher_list = cipher_list.offset(1);
            *fresh0 = '\u{0}' as i32 as libc::c_char;
        }
        found = 0 as libc::c_int;
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong)
            < (::std::mem::size_of::<[cipher_s; 94]>() as libc::c_ulong)
                .wrapping_div(::std::mem::size_of::<cipher_s>() as libc::c_ulong)
        {
            if Curl_strcasecompare(cipher, cipherlist[i as usize].name) != 0 {
                cipher_state[i as usize] = 1 as libc::c_int;
                found = 1 as libc::c_int;
                break;
            } else {
                i = i.wrapping_add(1);
            }
        }
        if found == 0 as libc::c_int {
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
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::std::mem::size_of::<[cipher_s; 94]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<cipher_s>() as libc::c_ulong)
    {
        if !(cipher_state[i as usize] == 0) {
            if SSL_CipherPrefSet(model, cipherlist[i as usize].num, 1 as libc::c_int) as libc::c_int
                != SECSuccess as libc::c_int
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
unsafe extern "C" fn any_cipher_enabled() -> bool {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::std::mem::size_of::<[cipher_s; 94]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<cipher_s>() as libc::c_ulong)
    {
        let mut policy: PRInt32 = 0 as libc::c_int;
        SSL_CipherPolicyGet(cipherlist[i as usize].num, &mut policy);
        if policy != 0 {
            return 1 as libc::c_int != 0;
        }
        i = i.wrapping_add(1);
    }
    return 0 as libc::c_int != 0;
}
unsafe extern "C" fn is_file(mut filename: *const libc::c_char) -> libc::c_int {
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
        return 0 as libc::c_int;
    }
    if stat(filename, &mut st) == 0 as libc::c_int {
        if st.st_mode & 0o170000 as libc::c_int as libc::c_uint
            == 0o100000 as libc::c_int as libc::c_uint
            || st.st_mode & 0o170000 as libc::c_int as libc::c_uint
                == 0o10000 as libc::c_int as libc::c_uint
            || st.st_mode & 0o170000 as libc::c_int as libc::c_uint
                == 0o20000 as libc::c_int as libc::c_uint
        {
            return 1 as libc::c_int;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn dup_nickname(
    mut data: *mut Curl_easy,
    mut str: *const libc::c_char,
) -> *mut libc::c_char {
    let mut n: *const libc::c_char = 0 as *const libc::c_char;
    if is_file(str) == 0 {
        return Curl_cstrdup.expect("non-null function pointer")(str);
    }
    n = strchr(str, '/' as i32);
    if n.is_null() {
        Curl_infof(
            data,
            b"warning: certificate file name \"%s\" handled as nickname; please use \"./%s\" to force file name\0"
                as *const u8 as *const libc::c_char,
            str,
            str,
        );
        return Curl_cstrdup.expect("non-null function pointer")(str);
    }
    return 0 as *mut libc::c_char;
}
unsafe extern "C" fn nss_find_slot_by_name(
    mut slot_name: *const libc::c_char,
) -> *mut PK11SlotInfo {
    let mut slot: *mut PK11SlotInfo = 0 as *mut PK11SlotInfo;
    PR_Lock(nss_findslot_lock);
    slot = PK11_FindSlotByName(slot_name);
    PR_Unlock(nss_findslot_lock);
    return slot;
}
unsafe extern "C" fn insert_wrapped_ptr(
    mut list: *mut Curl_llist,
    mut ptr: *mut libc::c_void,
) -> CURLcode {
    let mut wrap: *mut ptr_list_wrap = Curl_cmalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<ptr_list_wrap>() as libc::c_ulong,
    ) as *mut ptr_list_wrap;
    if wrap.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    let ref mut fresh1 = (*wrap).ptr;
    *fresh1 = ptr;
    Curl_llist_insert_next(
        list,
        (*list).tail,
        wrap as *const libc::c_void,
        &mut (*wrap).node,
    );
    return CURLE_OK;
}
unsafe extern "C" fn nss_create_object(
    mut connssl: *mut ssl_connect_data,
    mut obj_class: CK_OBJECT_CLASS,
    mut filename: *const libc::c_char,
    mut cacert: bool,
) -> CURLcode {
    let mut slot: *mut PK11SlotInfo = 0 as *mut PK11SlotInfo;
    let mut obj: *mut PK11GenericObject = 0 as *mut PK11GenericObject;
    let mut cktrue: CK_BBOOL = 1 as libc::c_int as CK_BBOOL;
    let mut ckfalse: CK_BBOOL = 0 as libc::c_int as CK_BBOOL;
    let mut attrs: [CK_ATTRIBUTE; 4] = [CK_ATTRIBUTE {
        type_0: 0,
        pValue: 0 as *mut libc::c_void,
        ulValueLen: 0,
    }; 4];
    let mut attr_cnt: libc::c_int = 0 as libc::c_int;
    let mut result: CURLcode = (if cacert as libc::c_int != 0 {
        CURLE_SSL_CACERT_BADFILE as libc::c_int
    } else {
        CURLE_SSL_CERTPROBLEM as libc::c_int
    }) as CURLcode;
    let slot_id: libc::c_int = if cacert as libc::c_int != 0 {
        0 as libc::c_int
    } else {
        1 as libc::c_int
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
    Curl_cfree.expect("non-null function pointer")(slot_name as *mut libc::c_void);
    if slot.is_null() {
        return result;
    }
    let fresh2 = attr_cnt;
    attr_cnt = attr_cnt + 1;
    let mut ptr: *mut CK_ATTRIBUTE = attrs.as_mut_ptr().offset(fresh2 as isize);
    (*ptr).type_0 = 0 as libc::c_int as CK_ATTRIBUTE_TYPE;
    let ref mut fresh3 = (*ptr).pValue;
    *fresh3 = &mut obj_class as *mut CK_OBJECT_CLASS as CK_VOID_PTR;
    (*ptr).ulValueLen = ::std::mem::size_of::<CK_OBJECT_CLASS>() as libc::c_ulong;
    let fresh4 = attr_cnt;
    attr_cnt = attr_cnt + 1;
    let mut ptr_0: *mut CK_ATTRIBUTE = attrs.as_mut_ptr().offset(fresh4 as isize);
    (*ptr_0).type_0 = 0x1 as libc::c_int as CK_ATTRIBUTE_TYPE;
    let ref mut fresh5 = (*ptr_0).pValue;
    *fresh5 = &mut cktrue as *mut CK_BBOOL as CK_VOID_PTR;
    (*ptr_0).ulValueLen = ::std::mem::size_of::<CK_BBOOL>() as libc::c_ulong;
    let fresh6 = attr_cnt;
    attr_cnt = attr_cnt + 1;
    let mut ptr_1: *mut CK_ATTRIBUTE = attrs.as_mut_ptr().offset(fresh6 as isize);
    (*ptr_1).type_0 = 0x3 as libc::c_int as CK_ATTRIBUTE_TYPE;
    let ref mut fresh7 = (*ptr_1).pValue;
    *fresh7 = filename as *mut libc::c_uchar as CK_VOID_PTR;
    (*ptr_1).ulValueLen = (strlen(filename)).wrapping_add(1 as libc::c_int as libc::c_ulong);
    if 0x1 as libc::c_int as libc::c_ulong == obj_class {
        let mut pval: *mut CK_BBOOL = if cacert as libc::c_int != 0 {
            &mut cktrue
        } else {
            &mut ckfalse
        };
        let fresh8 = attr_cnt;
        attr_cnt = attr_cnt + 1;
        let mut ptr_2: *mut CK_ATTRIBUTE = attrs.as_mut_ptr().offset(fresh8 as isize);
        (*ptr_2).type_0 = (0x80000000 as libc::c_uint | 0x4e534350 as libc::c_int as libc::c_uint)
            .wrapping_add(0x2000 as libc::c_int as libc::c_uint)
            as CK_ATTRIBUTE_TYPE;
        let ref mut fresh9 = (*ptr_2).pValue;
        *fresh9 = pval as CK_VOID_PTR;
        (*ptr_2).ulValueLen = ::std::mem::size_of::<CK_BBOOL>() as libc::c_ulong;
    }
    // done - 511
    if cfg!(HAVE_PK11_CREATEMANAGEDGENERICOBJECT){
        obj = PK11_CreateManagedGenericObject(slot, attrs.as_mut_ptr(), attr_cnt, 0 as libc::c_int);
    }
    PK11_FreeSlot(slot);
    if obj.is_null() {
        return result;
    }
    if insert_wrapped_ptr(&mut (*backend).obj_list, obj as *mut libc::c_void) as libc::c_uint
        != CURLE_OK as libc::c_int as libc::c_uint
    {
        PK11_DestroyGenericObject(obj);
        return CURLE_OUT_OF_MEMORY;
    }
    if !cacert && 0x1 as libc::c_int as libc::c_ulong == obj_class {
        let ref mut fresh10 = (*backend).obj_clicert;
        *fresh10 = obj;
    }
    return CURLE_OK;
}
unsafe extern "C" fn nss_destroy_object(mut user: *mut libc::c_void, mut ptr: *mut libc::c_void) {
    let mut wrap: *mut ptr_list_wrap = ptr as *mut ptr_list_wrap;
    let mut obj: *mut PK11GenericObject = (*wrap).ptr as *mut PK11GenericObject;
    PK11_DestroyGenericObject(obj);
    Curl_cfree.expect("non-null function pointer")(wrap as *mut libc::c_void);
}
unsafe extern "C" fn nss_destroy_crl_item(mut user: *mut libc::c_void, mut ptr: *mut libc::c_void) {
    let mut wrap: *mut ptr_list_wrap = ptr as *mut ptr_list_wrap;
    let mut crl_der: *mut SECItem = (*wrap).ptr as *mut SECItem;
    SECITEM_FreeItem(crl_der, 1 as libc::c_int);
    Curl_cfree.expect("non-null function pointer")(wrap as *mut libc::c_void);
}
unsafe extern "C" fn nss_load_cert(
    mut ssl: *mut ssl_connect_data,
    mut filename: *const libc::c_char,
    mut cacert: PRBool,
) -> CURLcode {
    let mut result: CURLcode = (if cacert != 0 {
        CURLE_SSL_CACERT_BADFILE as libc::c_int
    } else {
        CURLE_SSL_CERTPROBLEM as libc::c_int
    }) as CURLcode;
    if is_file(filename) != 0 {
        result = nss_create_object(
            ssl,
            0x1 as libc::c_int as CK_OBJECT_CLASS,
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
        nickname = curl_maprintf(b"PEM Token #1:%s\0" as *const u8 as *const libc::c_char, n);
        if !nickname.is_null() {
            let mut cert: *mut CERTCertificate =
                PK11_FindCertFromNickname(nickname, 0 as *mut libc::c_void);
            if !cert.is_null() {
                CERT_DestroyCertificate(cert);
            }
            Curl_cfree.expect("non-null function pointer")(nickname as *mut libc::c_void);
        }
    }
    return result;
}
unsafe extern "C" fn nss_cache_crl(mut crl_der: *mut SECItem) -> CURLcode {
    let mut db: *mut CERTCertDBHandle = CERT_GetDefaultCertDB();
    let mut crl: *mut CERTSignedCrl = SEC_FindCrlByDERCert(db, crl_der, 0 as libc::c_int);
    if !crl.is_null() {
        SEC_DestroyCrl(crl);
        SECITEM_FreeItem(crl_der, 1 as libc::c_int);
        return CURLE_OK;
    }
    PR_Lock(nss_crllock);
    if SECSuccess as libc::c_int != CERT_CacheCRL(db, crl_der) as libc::c_int {
        SECITEM_FreeItem(crl_der, 1 as libc::c_int);
        PR_Unlock(nss_crllock);
        return CURLE_SSL_CRL_BADFILE;
    }
    if insert_wrapped_ptr(&mut nss_crl_list, crl_der as *mut libc::c_void) as libc::c_uint
        != CURLE_OK as libc::c_int as libc::c_uint
    {
        if SECSuccess as libc::c_int == CERT_UncacheCRL(db, crl_der) as libc::c_int {
            SECITEM_FreeItem(crl_der, 1 as libc::c_int);
        }
        PR_Unlock(nss_crllock);
        return CURLE_OUT_OF_MEMORY;
    }
    SSL_ClearSessionCache();
    PR_Unlock(nss_crllock);
    return CURLE_OK;
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
//             data: 0 as *mut libc::c_uchar,
//             len: 0 as libc::c_int as libc::c_uint,
//         };
//         init
//     };
//     let mut crl_der: *mut SECItem = 0 as *mut SECItem;
//     let mut body: *mut libc::c_char = 0 as *mut libc::c_char;
//     infile = PR_Open(crlfilename, 0x1 as libc::c_int, 0 as libc::c_int);
//     if infile.is_null() {
//         return CURLE_SSL_CRL_BADFILE;
//     }
//     if !(PR_SUCCESS as libc::c_int
//         != PR_GetOpenFileInfo(infile, &mut info) as libc::c_int)
//     {
//         if !(SECITEM_AllocItem(
//             0 as *mut PLArenaPool,
//             &mut filedata,
//             (info.size + 1 as libc::c_int) as libc::c_uint,
//         ))
//             .is_null()
//         {
//             if !(info.size
//                 != PR_Read(infile, filedata.data as *mut libc::c_void, info.size))
//             {
//                 crl_der = SECITEM_AllocItem(
//                     0 as *mut PLArenaPool,
//                     0 as *mut SECItem,
//                     0 as libc::c_uint,
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
//                                     SECITEM_FreeItem(&mut filedata, 0 as libc::c_int);
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
//     SECITEM_FreeItem(crl_der, 1 as libc::c_int);
//     SECITEM_FreeItem(&mut filedata, 0 as libc::c_int);
//     return CURLE_SSL_CRL_BADFILE;
// }
unsafe extern "C" fn nss_load_crl(mut crlfilename: *const libc::c_char) -> CURLcode {
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
            data: 0 as *mut libc::c_uchar,
            len: 0 as libc::c_int as libc::c_uint,
        };
        init
    };
    let mut crl_der: *mut SECItem = 0 as *mut SECItem;
    let mut body: *mut libc::c_char = 0 as *mut libc::c_char;
    infile = PR_Open(crlfilename, 0x1 as libc::c_int, 0 as libc::c_int);
    if infile.is_null() {
        return CURLE_SSL_CRL_BADFILE;
    }
    // 创建一个循环
    'error: loop {
        if PR_SUCCESS as libc::c_int != PR_GetOpenFileInfo(infile, &mut info) as libc::c_int {
            // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if (SECITEM_AllocItem(
            0 as *mut PLArenaPool,
            &mut filedata,
            (info.size + 1 as libc::c_int) as libc::c_uint,
        ))
        .is_null()
        {
            // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if info.size != PR_Read(infile, filedata.data as *mut libc::c_void, info.size) {
            // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        crl_der = SECITEM_AllocItem(0 as *mut PLArenaPool, 0 as *mut SECItem, 0 as libc::c_uint);
        if crl_der.is_null() {
            // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        body = filedata.data as *mut libc::c_char;
        filedata.len = (filedata.len).wrapping_sub(1);
        *body.offset(filedata.len as isize) = '\u{0}' as i32 as libc::c_char;
        body = strstr(body, b"-----BEGIN\0" as *const u8 as *const libc::c_char);
        if !body.is_null() {
            let mut trailer: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut begin: *mut libc::c_char = strchr(body, '\n' as i32);
            if begin.is_null() {
                begin = strchr(body, '\r' as i32);
            }
            if begin.is_null() {
                // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
                break 'error;
            }
            begin = begin.offset(1);
            trailer = strstr(begin, b"-----END\0" as *const u8 as *const libc::c_char);
            if trailer.is_null() {
                // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
                break 'error;
            }
            *trailer = '\u{0}' as i32 as libc::c_char;
            if ATOB_ConvertAsciiToItem(crl_der, begin) as u64 != 0 {
                // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
                break 'error;
            }
            SECITEM_FreeItem(&mut filedata, 0 as libc::c_int);
        } else {
            *crl_der = filedata;
        }
        PR_Close(infile);
        // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
        return nss_cache_crl(crl_der);
        break;
    }
    PR_Close(infile);
    SECITEM_FreeItem(crl_der, 1 as libc::c_int);
    SECITEM_FreeItem(&mut filedata, 0 as libc::c_int);
    return CURLE_SSL_CRL_BADFILE;
}
unsafe extern "C" fn nss_load_key(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut key_file: *mut libc::c_char,
) -> CURLcode {
    let mut slot: *mut PK11SlotInfo = 0 as *mut PK11SlotInfo;
    let mut tmp: *mut PK11SlotInfo = 0 as *mut PK11SlotInfo;
    let mut status: SECStatus = SECSuccess;
    let mut result: CURLcode = CURLE_OK;
    let mut ssl: *mut ssl_connect_data = ((*conn).ssl).as_mut_ptr();
    result = nss_create_object(
        ssl,
        0x3 as libc::c_int as CK_OBJECT_CLASS,
        key_file,
        0 as libc::c_int != 0,
    );
    if result as u64 != 0 {
        PR_SetError(SEC_ERROR_BAD_KEY as libc::c_int, 0 as libc::c_int);
        return result;
    }
    slot = nss_find_slot_by_name(b"PEM Token #1\0" as *const u8 as *const libc::c_char);
    if slot.is_null() {
        return CURLE_SSL_CERTPROBLEM;
    }
    tmp = SECMOD_WaitForAnyTokenEvent(
        pem_module,
        0 as libc::c_int as libc::c_ulong,
        0 as libc::c_int as PRIntervalTime,
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
                                        1 as libc::c_int,
                                        (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                            == (*conn).http_proxy.proxytype as libc::c_uint
                                            && ssl_connection_complete as libc::c_int as libc::c_uint
                                                != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
                                        }) as *mut libc::c_void,
                                    );
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_SET_OPTION_key_passwd = PK11_Authenticate(
                                        slot,
                                        1 as libc::c_int,
                                        (*data).set.ssl.key_passwd as *mut libc::c_void,
                                    );

    status = SSL_SET_OPTION_key_passwd;
    PK11_FreeSlot(slot);
    return (if SECSuccess as libc::c_int == status as libc::c_int {
        CURLE_OK as libc::c_int
    } else {
        CURLE_SSL_CERTPROBLEM as libc::c_int
    }) as CURLcode;
}
unsafe extern "C" fn display_error(
    mut data: *mut Curl_easy,
    mut err: PRInt32,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    match err {
        -8177 => {
            Curl_failf(
                data,
                b"Unable to load client key: Incorrect password\0" as *const u8
                    as *const libc::c_char,
            );
            return 1 as libc::c_int;
        }
        -8077 => {
            Curl_failf(
                data,
                b"Unable to load certificate %s\0" as *const u8 as *const libc::c_char,
                filename,
            );
            return 1 as libc::c_int;
        }
        _ => {}
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn cert_stuff(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut cert_file: *mut libc::c_char,
    mut key_file: *mut libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if !cert_file.is_null() {
        result = nss_load_cert(
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize),
            cert_file,
            0 as libc::c_int,
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
unsafe extern "C" fn nss_get_password(
    mut slot: *mut PK11SlotInfo,
    mut retry: PRBool,
    mut arg: *mut libc::c_void,
) -> *mut libc::c_char {
    if retry != 0 || arg.is_null() {
        return 0 as *mut libc::c_char;
    } else {
        return PORT_Strdup(arg as *mut libc::c_char);
    };
}



unsafe extern "C" fn nss_auth_cert_hook(
    mut arg: *mut libc::c_void,
    mut fd: *mut PRFileDesc,
    mut checksig: PRBool,
    mut isServer: PRBool,
) -> SECStatus {
    let mut data: *mut Curl_easy = arg as *mut Curl_easy;
    let mut conn: *mut connectdata = (*data).conn;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifystatus = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                            == (*conn).http_proxy.proxytype as libc::c_uint
                                            && ssl_connection_complete as libc::c_int as libc::c_uint
                                                != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize] == -(1 as libc::c_int)
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
                                        };
    #[cfg(CURL_DISABLE_PROXY)]
    let SSL_CONN_CONFIG_verifystatus = ((*conn).ssl_config).verifystatus();
    #[cfg(not(CURL_DISABLE_PROXY))]
    let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                        == (*conn).http_proxy.proxytype as libc::c_uint
                                        && ssl_connection_complete as libc::c_int as libc::c_uint
                                            != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize] == -(1 as libc::c_int)
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
        if (*csa).len == 0 as libc::c_int as libc::c_uint {
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
            &mut *((*csa).items).offset(0 as libc::c_int as isize),
            arg,
        );
        if cacheResult as libc::c_int != SECSuccess as libc::c_int {
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



unsafe extern "C" fn HandshakeCallback(mut sock: *mut PRFileDesc, mut arg: *mut libc::c_void) {
    let mut data: *mut Curl_easy = arg as *mut Curl_easy;
    let mut conn: *mut connectdata = (*data).conn;
    let mut buflenmax: libc::c_uint = 50 as libc::c_int as libc::c_uint;
    let mut buf: [libc::c_uchar; 50] = [0; 50];
    let mut buflen: libc::c_uint = 0;
    let mut state: SSLNextProtoState = SSL_NEXT_PROTO_NO_SUPPORT;
    if ((*conn).bits).tls_enable_npn() == 0 && ((*conn).bits).tls_enable_alpn() == 0 {
        return;
    }
    if SSL_GetNextProto(sock, &mut state, buf.as_mut_ptr(), &mut buflen, buflenmax) as libc::c_int
        == SECSuccess as libc::c_int
    {
        let mut current_block_6: u64;
        match state as libc::c_uint {
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
        if buflen == 2 as libc::c_int as libc::c_uint
            && memcmp(
                b"h2\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                2 as libc::c_int as libc::c_ulong,
            ) == 0
        {
            (*conn).negnpn = CURL_HTTP_VERSION_2_0 as libc::c_int;
        } else if buflen == 8 as libc::c_int as libc::c_uint
            && memcmp(
                b"http/1.1\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                8 as libc::c_int as libc::c_ulong,
            ) == 0
        {
            (*conn).negnpn = CURL_HTTP_VERSION_1_1 as libc::c_int;
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
//     *canFalseStart = 0 as libc::c_int;
//     if SSL_GetChannelInfo(
//         sock,
//         &mut channelInfo,
//         ::std::mem::size_of::<SSLChannelInfo>() as libc::c_ulong as PRUintn,
//     ) as libc::c_int
//         != SECSuccess as libc::c_int
//     {
//         return SECFailure;
//     }
//     if SSL_GetCipherSuiteInfo(
//         channelInfo.cipherSuite,
//         &mut cipherInfo,
//         ::std::mem::size_of::<SSLCipherSuiteInfo>() as libc::c_ulong as PRUintn,
//     ) as libc::c_int
//         != SECSuccess as libc::c_int
//     {
//         return SECFailure;
//     }
//     if !(channelInfo.protocolVersion as libc::c_int != 0x303 as libc::c_int) {
//         if !(cipherInfo.keaType as libc::c_uint != ssl_kea_ecdh as libc::c_int as libc::c_uint) {
//             if !(cipherInfo.symCipher as libc::c_uint
//                 != ssl_calg_aes_gcm as libc::c_int as libc::c_uint)
//             {
//                 rv = SSL_HandshakeNegotiatedExtension(
//                     sock,
//                     ssl_app_layer_protocol_xtn,
//                     &mut negotiatedExtension,
//                 );
//                 if rv as libc::c_int != SECSuccess as libc::c_int || negotiatedExtension == 0 {
//                     rv = SSL_HandshakeNegotiatedExtension(
//                         sock,
//                         ssl_next_proto_nego_xtn,
//                         &mut negotiatedExtension,
//                     );
//                 }
//                 if !(rv as libc::c_int != SECSuccess as libc::c_int || negotiatedExtension == 0) {
//                     *canFalseStart = 1 as libc::c_int;
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
unsafe extern "C" fn CanFalseStartCallback(
    mut sock: *mut PRFileDesc,
    mut client_data: *mut libc::c_void,
    mut canFalseStart: *mut PRBool,
) -> SECStatus {
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
    *canFalseStart = 0 as libc::c_int;
    if SSL_GetChannelInfo(
        sock,
        &mut channelInfo,
        ::std::mem::size_of::<SSLChannelInfo>() as libc::c_ulong as PRUintn,
    ) as libc::c_int
        != SECSuccess as libc::c_int
    {
        return SECFailure;
    }
    if SSL_GetCipherSuiteInfo(
        channelInfo.cipherSuite,
        &mut cipherInfo,
        ::std::mem::size_of::<SSLCipherSuiteInfo>() as libc::c_ulong as PRUintn,
    ) as libc::c_int
        != SECSuccess as libc::c_int
    {
        return SECFailure;
    }
    // 创建一个循环
    // 循环开始
    'end: loop {
        if channelInfo.protocolVersion as libc::c_int != 0x303 as libc::c_int {
            // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
            break 'end;
        }
        if cipherInfo.keaType as libc::c_uint != ssl_kea_ecdh as libc::c_int as libc::c_uint {
            // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
            break 'end;
        }
        if cipherInfo.symCipher as libc::c_uint != ssl_calg_aes_gcm as libc::c_int as libc::c_uint {
            // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
            break 'end;
        }
        rv = SSL_HandshakeNegotiatedExtension(
            sock,
            ssl_app_layer_protocol_xtn,
            &mut negotiatedExtension,
        );
        if rv as libc::c_int != SECSuccess as libc::c_int || negotiatedExtension == 0 {
            rv = SSL_HandshakeNegotiatedExtension(
                sock,
                ssl_next_proto_nego_xtn,
                &mut negotiatedExtension,
            );
        }
        if rv as libc::c_int != SECSuccess as libc::c_int || negotiatedExtension == 0 {
            // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
            break 'end;
        }
        *canFalseStart = 1 as libc::c_int;
        Curl_infof(
            data,
            b"Trying TLS False Start\0" as *const u8 as *const libc::c_char,
        );
    }
    // 循环结束
    // curl_mprintf(b"hanxj\0" as *const u8 as *const libc::c_char);
    return SECSuccess;
}
unsafe extern "C" fn display_cert_info(mut data: *mut Curl_easy, mut cert: *mut CERTCertificate) {
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
        256 as libc::c_int,
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
        256 as libc::c_int,
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
unsafe extern "C" fn display_conn_info(
    mut data: *mut Curl_easy,
    mut sock: *mut PRFileDesc,
) -> CURLcode {
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
        ::std::mem::size_of::<SSLChannelInfo>() as libc::c_ulong as PRUintn,
    ) as libc::c_int
        == SECSuccess as libc::c_int
        && channel.length as libc::c_ulong
            == ::std::mem::size_of::<SSLChannelInfo>() as libc::c_ulong
        && channel.cipherSuite as libc::c_int != 0
    {
        if SSL_GetCipherSuiteInfo(
            channel.cipherSuite,
            &mut suite,
            ::std::mem::size_of::<SSLCipherSuiteInfo>() as libc::c_ulong as PRUintn,
        ) as libc::c_int
            == SECSuccess as libc::c_int
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
            let mut i: libc::c_int = 1 as libc::c_int;
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
                i = 0 as libc::c_int;
                while !cert.is_null() {
                    let fresh11 = i;
                    i = i + 1;
                    result = Curl_extract_certinfo(
                        data,
                        fresh11,
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
#[cfg(not(CURL_DISABLE_PROXY))]
unsafe extern "C" fn BadCertHandler(
    mut arg: *mut libc::c_void,
    mut sock: *mut PRFileDesc,
) -> SECStatus {
    let mut data: *mut Curl_easy = arg as *mut Curl_easy;
    let mut conn: *mut connectdata = (*data).conn;
    let mut err: PRErrorCode = PR_GetError();
    let mut cert: *mut CERTCertificate = 0 as *mut CERTCertificate;
    
    #[cfg(not(CURL_DISABLE_PROXY))]
    if true {
        *if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
            == (*conn).http_proxy.proxytype as libc::c_uint
            && ssl_connection_complete as libc::c_int as libc::c_uint
                != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize] == -(1 as libc::c_int)
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
        } = err as libc::c_long;
    }
    #[cfg(CURL_DISABLE_PROXY)]
    if true {
        (*data).set.ssl.certverifyresult = err as libc::c_long;
    }
        
    if err == SSL_ERROR_BAD_CERT_DOMAIN as libc::c_int
        && (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
            == (*conn).http_proxy.proxytype as libc::c_uint
            && ssl_connection_complete as libc::c_int as libc::c_uint
                != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
#[cfg(CURL_DISABLE_PROXY)]
unsafe extern "C" fn BadCertHandler(
    mut arg: *mut libc::c_void,
    mut sock: *mut PRFileDesc,
) -> SECStatus {
    let mut data: *mut Curl_easy = arg as *mut Curl_easy;
    let mut conn: *mut connectdata = (*data).conn;
    let mut err: PRErrorCode = PR_GetError();
    let mut cert: *mut CERTCertificate = 0 as *mut CERTCertificate;
    (*data).set.ssl.certverifyresult = err as libc::c_long;
    if err == SSL_ERROR_BAD_CERT_DOMAIN as libc::c_int
        && ((*conn).ssl_config).verifyhost() == 0
    {
        return SECSuccess;
    }
    cert = SSL_PeerCertificate(sock);
    if !cert.is_null() {
        Curl_infof(data, b"Server certificate:\0" as *const u8 as *const libc::c_char);
        display_cert_info(data, cert);
        CERT_DestroyCertificate(cert);
    }
    return SECFailure;
}
unsafe extern "C" fn check_issuer_cert(
    mut sock: *mut PRFileDesc,
    mut issuer_nickname: *mut libc::c_char,
) -> SECStatus {
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
        as libc::c_int
        != SECEqual as libc::c_int
    {
        res = SECFailure;
    }
    CERT_DestroyCertificate(cert);
    CERT_DestroyCertificate(issuer);
    CERT_DestroyCertificate(cert_issuer);
    return res;
}
unsafe extern "C" fn cmp_peer_pubkey(
    mut connssl: *mut ssl_connect_data,
    mut pinnedpubkey: *const libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut data: *mut Curl_easy = (*backend).data;
    let mut cert: *mut CERTCertificate = 0 as *mut CERTCertificate;
    if pinnedpubkey.is_null() {
        return CURLE_OK;
    }
    cert = SSL_PeerCertificate((*backend).nss_handle);
    if !cert.is_null() {
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
                SECITEM_FreeItem(cert_der, 1 as libc::c_int);
            }
            SECKEY_DestroyPublicKey(pubkey);
        }
        CERT_DestroyCertificate(cert);
    }
    match result as libc::c_uint {
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
unsafe extern "C" fn SelectClientCert(
    mut arg: *mut libc::c_void,
    mut sock: *mut PRFileDesc,
    mut caNames: *mut CERTDistNamesStr,
    mut pRetCert: *mut *mut CERTCertificateStr,
    mut pRetKey: *mut *mut SECKEYPrivateKeyStr,
) -> SECStatus {
    let mut connssl: *mut ssl_connect_data = arg as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut data: *mut Curl_easy = (*backend).data;
    let mut nickname: *const libc::c_char = (*backend).client_nickname;
    static mut pem_slotname: [libc::c_char; 13] =
        unsafe { *::std::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"PEM Token #1\0") };
    if !((*backend).obj_clicert).is_null() {
        let mut cert_der: SECItem = {
            let mut init = SECItemStr {
                type_0: siBuffer,
                data: 0 as *mut libc::c_uchar,
                len: 0 as libc::c_int as libc::c_uint,
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
            0x11 as libc::c_int as CK_ATTRIBUTE_TYPE,
            &mut cert_der,
        ) as libc::c_int
            != SECSuccess as libc::c_int
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
        SECITEM_FreeItem(&mut cert_der, 0 as libc::c_int);
        if cert.is_null() {
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
    if SECSuccess as libc::c_int
        != NSS_GetClientAuthData(
            nickname as *mut libc::c_void,
            sock,
            caNames,
            pRetCert,
            pRetKey,
        ) as libc::c_int
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
    nickname = (**pRetCert).nickname;
    if nickname.is_null() {
        nickname = b"[unknown]\0" as *const u8 as *const libc::c_char;
    }
    if strncmp(
        nickname,
        pem_slotname.as_ptr(),
        (::std::mem::size_of::<[libc::c_char; 13]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_uint as libc::c_ulong),
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
unsafe extern "C" fn nss_update_connecting_state(
    mut state: ssl_connect_state,
    mut secret: *mut libc::c_void,
) {
    let mut connssl: *mut ssl_connect_data = secret as *mut ssl_connect_data;
    if PR_GetError() as libc::c_long != -(5998 as libc::c_long) {
        return;
    }
    match (*connssl).connecting_state as libc::c_uint {
        1 | 2 | 3 => {}
        _ => return,
    }
    (*connssl).connecting_state = state;
}
unsafe extern "C" fn nspr_io_recv(
    mut fd: *mut PRFileDesc,
    mut buf: *mut libc::c_void,
    mut amount: PRInt32,
    mut flags: PRIntn,
    mut timeout: PRIntervalTime,
) -> PRInt32 {
    let recv_fn: PRRecvFN = (*(*(*fd).lower).methods).recv;
    let rv: PRInt32 =
        recv_fn.expect("non-null function pointer")((*fd).lower, buf, amount, flags, timeout);
    if rv < 0 as libc::c_int {
        nss_update_connecting_state(ssl_connect_2_reading, (*fd).secret as *mut libc::c_void);
    }
    return rv;
}
unsafe extern "C" fn nspr_io_send(
    mut fd: *mut PRFileDesc,
    mut buf: *const libc::c_void,
    mut amount: PRInt32,
    mut flags: PRIntn,
    mut timeout: PRIntervalTime,
) -> PRInt32 {
    let send_fn: PRSendFN = (*(*(*fd).lower).methods).send;
    let rv: PRInt32 =
        send_fn.expect("non-null function pointer")((*fd).lower, buf, amount, flags, timeout);
    if rv < 0 as libc::c_int {
        nss_update_connecting_state(ssl_connect_2_writing, (*fd).secret as *mut libc::c_void);
    }
    return rv;
}
unsafe extern "C" fn nspr_io_close(mut fd: *mut PRFileDesc) -> PRStatus {
    let close_fn: PRCloseFN = (*PR_GetDefaultIOMethods()).close;
    let ref mut fresh12 = (*fd).secret;
    *fresh12 = 0 as *mut PRFilePrivate;
    return close_fn.expect("non-null function pointer")(fd);
}
unsafe extern "C" fn nss_load_module(
    mut pmod: *mut *mut SECMODModule,
    mut library: *const libc::c_char,
    mut name: *const libc::c_char,
) -> CURLcode {
    let mut config_string: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut module: *mut SECMODModule = *pmod;
    if !module.is_null() {
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
    module = SECMOD_LoadUserModule(config_string, 0 as *mut SECMODModule, 0 as libc::c_int);
    Curl_cfree.expect("non-null function pointer")(config_string as *mut libc::c_void);
    if !module.is_null() && (*module).loaded != 0 {
        *pmod = module;
        return CURLE_OK;
    }
    if !module.is_null() {
        SECMOD_DestroyModule(module);
    }
    return CURLE_FAILED_INIT;
}
unsafe extern "C" fn nss_unload_module(mut pmod: *mut *mut SECMODModule) {
    let mut module: *mut SECMODModule = *pmod;
    if module.is_null() {
        return;
    }
    if SECMOD_UnloadUserModule(module) as libc::c_int != SECSuccess as libc::c_int {
        return;
    }
    SECMOD_DestroyModule(module);
    *pmod = 0 as *mut SECMODModule;
}
unsafe extern "C" fn nss_init_core(
    mut data: *mut Curl_easy,
    mut cert_dir: *const libc::c_char,
) -> CURLcode {
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
        ::std::mem::size_of::<NSSInitParameters>() as libc::c_ulong,
    );
    initparams.length = ::std::mem::size_of::<NSSInitParameters>() as libc::c_ulong as libc::c_uint;
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
            (0x1 as libc::c_int | 0x80 as libc::c_int) as PRUint32,
        );
        Curl_cfree.expect("non-null function pointer")(certpath as *mut libc::c_void);
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
        (0x1 as libc::c_int
            | 0x2 as libc::c_int
            | 0x4 as libc::c_int
            | 0x8 as libc::c_int
            | 0x10 as libc::c_int
            | 0x20 as libc::c_int
            | 0x80 as libc::c_int) as PRUint32,
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
unsafe extern "C" fn nss_setup(mut data: *mut Curl_easy) -> CURLcode {
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
    Curl_llist_init(
        &mut nss_crl_list,
        Some(
            nss_destroy_crl_item
                as unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> (),
        ),
    );
    cert_dir = getenv(b"SSL_DIR\0" as *const u8 as *const libc::c_char);
    if !cert_dir.is_null() {
        if stat(cert_dir, &mut st) != 0 as libc::c_int
            || !(st.st_mode & 0o170000 as libc::c_int as libc::c_uint
                == 0o40000 as libc::c_int as libc::c_uint)
        {
            cert_dir = 0 as *mut libc::c_char;
        }
    }
    if cert_dir.is_null() {
        if stat(
            b"/etc/pki/nssdb\0" as *const u8 as *const libc::c_char,
            &mut st,
        ) == 0 as libc::c_int
            && st.st_mode & 0o170000 as libc::c_int as libc::c_uint
                == 0o40000 as libc::c_int as libc::c_uint
        {
            cert_dir = b"/etc/pki/nssdb\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
    }
    if nspr_io_identity == -(1 as libc::c_int) {
        nspr_io_identity = PR_GetUniqueIdentity(b"libcurl\0" as *const u8 as *const libc::c_char);
        if nspr_io_identity == -(1 as libc::c_int) {
            return CURLE_OUT_OF_MEMORY;
        }
        memcpy(
            &mut nspr_io_methods as *mut PRIOMethods as *mut libc::c_void,
            PR_GetDefaultIOMethods() as *const libc::c_void,
            ::std::mem::size_of::<PRIOMethods>() as libc::c_ulong,
        );
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
    ::std::ptr::write_volatile(&mut initialized as *mut libc::c_int, 1 as libc::c_int);
    return CURLE_OK;
}
unsafe extern "C" fn nss_init() -> libc::c_int {
    if nss_initlock.is_null() {
        PR_Init(
            PR_USER_THREAD,
            PR_PRIORITY_NORMAL,
            0 as libc::c_int as PRUintn,
        );
        nss_initlock = PR_NewLock();
        nss_crllock = PR_NewLock();
        nss_findslot_lock = PR_NewLock();
        nss_trustload_lock = PR_NewLock();
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_nss_force_init(mut data: *mut Curl_easy) -> CURLcode {
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
unsafe extern "C" fn nss_cleanup() {
    PR_Lock(nss_initlock);
    if initialized != 0 {
        SSL_ClearSessionCache();
        nss_unload_module(&mut pem_module);
        nss_unload_module(&mut trust_module);
        NSS_ShutdownContext(nss_context);
        nss_context = 0 as *mut NSSInitContext;
    }
    Curl_llist_destroy(&mut nss_crl_list, 0 as *mut libc::c_void);
    PR_Unlock(nss_initlock);
    PR_DestroyLock(nss_initlock);
    PR_DestroyLock(nss_crllock);
    PR_DestroyLock(nss_findslot_lock);
    PR_DestroyLock(nss_trustload_lock);
    nss_initlock = 0 as *mut PRLock;
    ::std::ptr::write_volatile(&mut initialized as *mut libc::c_int, 0 as libc::c_int);
}
unsafe extern "C" fn nss_check_cxn(mut conn: *mut connectdata) -> libc::c_int {
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(0 as libc::c_int as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut rc: libc::c_int = 0;
    let mut buf: libc::c_char = 0;
    rc = PR_Recv(
        (*backend).nss_handle,
        &mut buf as *mut libc::c_char as *mut libc::c_void,
        1 as libc::c_int,
        0x2 as libc::c_int,
        PR_SecondsToInterval(1 as libc::c_int as PRUint32),
    );
    if rc > 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if rc == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn close_one(mut connssl: *mut ssl_connect_data) {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let client_cert: bool =
        !((*backend).client_nickname).is_null() || !((*backend).obj_clicert).is_null();
    if !((*backend).nss_handle).is_null() {
        let mut buf: [libc::c_char; 32] = [0; 32];
        PR_Recv(
            (*backend).nss_handle,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as libc::c_int,
            0 as libc::c_int,
            0 as libc::c_ulong as PRIntervalTime,
        );
    }
    Curl_cfree.expect("non-null function pointer")((*backend).client_nickname as *mut libc::c_void);
    let ref mut fresh13 = (*backend).client_nickname;
    *fresh13 = 0 as *mut libc::c_char;
    Curl_llist_destroy(&mut (*backend).obj_list, 0 as *mut libc::c_void);
    let ref mut fresh14 = (*backend).obj_clicert;
    *fresh14 = 0 as *mut PK11GenericObject;
    if !((*backend).nss_handle).is_null() {
        if client_cert {
            SSL_InvalidateSession((*backend).nss_handle);
        }
        PR_Close((*backend).nss_handle);
        let ref mut fresh15 = (*backend).nss_handle;
        *fresh15 = 0 as *mut PRFileDesc;
    }
}
unsafe extern "C" fn nss_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) {
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
        (*conn).sock[sockindex as usize] = -(1 as libc::c_int);
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    if !((*backend).nss_handle).is_null() {
        let ref mut fresh16 = (*(*connssl_proxy).backend).nss_handle;
        *fresh16 = 0 as *mut PRFileDesc;
    }
    #[cfg(not(CURL_DISABLE_PROXY))]
    close_one(connssl_proxy);
    close_one(connssl);
}
unsafe extern "C" fn is_nss_error(mut err: CURLcode) -> bool {
    match err as libc::c_uint {
        60 | 58 | 35 | 83 => return 1 as libc::c_int != 0,
        _ => return 0 as libc::c_int != 0,
    };
}
unsafe extern "C" fn is_cc_error(mut err: PRInt32) -> bool {
    match err {
        -12271 | -12269 | -12270 => return 1 as libc::c_int != 0,
        _ => return 0 as libc::c_int != 0,
    };
}
unsafe extern "C" fn nss_load_ca_certificates(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut cafile: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
        == (*conn).http_proxy.proxytype as libc::c_uint
        && ssl_connection_complete as libc::c_int as libc::c_uint
            != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize] == -(1 as libc::c_int)
            {
                0 as libc::c_int
            } else {
                1 as libc::c_int
            }) as usize]
                .state as libc::c_uint
    {
        (*conn).proxy_ssl_config.CAfile
    } else {
        (*conn).ssl_config.CAfile
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut cafile: *const libc::c_char = (*conn).ssl_config.CAfile;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let mut capath: *const libc::c_char = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
        == (*conn).http_proxy.proxytype as libc::c_uint
        && ssl_connection_complete as libc::c_int as libc::c_uint
            != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize] == -(1 as libc::c_int)
            {
                0 as libc::c_int
            } else {
                1 as libc::c_int
            }) as usize]
                .state as libc::c_uint
    {
        (*conn).proxy_ssl_config.CApath
    } else {
        (*conn).ssl_config.CApath
    };
    #[cfg(CURL_DISABLE_PROXY)]
    let mut capath: *const libc::c_char = (*conn).ssl_config.CApath;
    let mut use_trust_module: bool = false;
    let mut result: CURLcode = CURLE_OK;
    if !cafile.is_null() && *cafile.offset(0 as libc::c_int as isize) == 0 {
        cafile = 0 as *const libc::c_char;
    }
    if !capath.is_null() && *capath.offset(0 as libc::c_int as isize) == 0 {
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
    use_trust_module = cafile.is_null() && capath.is_null();
    PR_Lock(nss_trustload_lock);
    if use_trust_module as libc::c_int != 0 && trust_module.is_null() {
        result = nss_load_module(
            &mut trust_module,
            trust_library,
            b"trust\0" as *const u8 as *const libc::c_char,
        );
        Curl_infof(
            data,
            b"%s %s\0" as *const u8 as *const libc::c_char,
            if result as libc::c_uint != 0 {
                b"failed to load\0" as *const u8 as *const libc::c_char
            } else {
                b"loaded\0" as *const u8 as *const libc::c_char
            },
            trust_library,
        );
        if result as libc::c_uint == CURLE_FAILED_INIT as libc::c_int as libc::c_uint {
            result = CURLE_OK;
        }
    } else if !use_trust_module && !trust_module.is_null() {
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
            1 as libc::c_int,
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
        if stat(capath, &mut st) == -(1 as libc::c_int) {
            return CURLE_SSL_CACERT_BADFILE;
        }
        if st.st_mode & 0o170000 as libc::c_int as libc::c_uint
            == 0o40000 as libc::c_int as libc::c_uint
        {
            let mut entry: *mut PRDirEntry = 0 as *mut PRDirEntry;
            let mut dir: *mut PRDir = PR_OpenDir(capath);
            if dir.is_null() {
                return CURLE_SSL_CACERT_BADFILE;
            }
            loop {
                entry = PR_ReadDir(
                    dir,
                    (PR_SKIP_BOTH as libc::c_int | PR_SKIP_HIDDEN as libc::c_int) as PRDirFlags,
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
                if CURLE_OK as libc::c_int as libc::c_uint
                    != nss_load_cert(
                        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize),
                        fullpath,
                        1 as libc::c_int,
                    ) as libc::c_uint
                {
                    Curl_infof(
                        data,
                        b"failed to load '%s' from CURLOPT_CAPATH\0" as *const u8
                            as *const libc::c_char,
                        fullpath,
                    );
                }
                Curl_cfree.expect("non-null function pointer")(fullpath as *mut libc::c_void);
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
unsafe extern "C" fn nss_sslver_from_curl(
    mut nssver: *mut PRUint16,
    mut version: libc::c_long,
) -> CURLcode {
    match version {
        2 => {
            *nssver = 0x2 as libc::c_int as PRUint16;
            return CURLE_OK;
        }
        3 => return CURLE_NOT_BUILT_IN,
        4 => {
            *nssver = 0x301 as libc::c_int as PRUint16;
            return CURLE_OK;
        }
        5 => {
            match () {
                #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
                _ => {
                    *nssver = 0x302 as libc::c_int as PRUint16;
                    return CURLE_OK;
                }
                #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_1))]
                _ => {
                    return CURLE_SSL_CONNECT_ERROR;
                }
            }
            // #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
            // *nssver = 0x302 as libc::c_int as PRUint16;
            // #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
            // return CURLE_OK;
            // #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_1))]
            // return CURLE_SSL_CONNECT_ERROR;
        }
        6 => {
            match () {
                #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
                _ => {
                    *nssver = 0x303 as libc::c_int as PRUint16;
                    return CURLE_OK;
                }
                #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_2))]
                _ => {
                    return CURLE_SSL_CONNECT_ERROR;
                }
            }
            // #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
            // *nssver = 0x303 as libc::c_int as PRUint16;
            // #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
            // return CURLE_OK;
            // #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_2))]
            // return CURLE_SSL_CONNECT_ERROR;
        }
        7 => {
            match () {
                #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
                _ => {
                    *nssver = 0x304 as libc::c_int as PRUint16;
                    return CURLE_OK;
                }
                #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_3))]
                _ => {
                    return CURLE_SSL_CONNECT_ERROR;
                }
            }
            // #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
            // *nssver = 0x304 as libc::c_int as PRUint16;
            // #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
            // return CURLE_OK;
            // #[cfg(not(SSL_LIBRARY_VERSION_TLS_1_3))]
            // return CURLE_SSL_CONNECT_ERROR;
        }
        _ => return CURLE_SSL_CONNECT_ERROR,
    };
}
unsafe extern "C" fn nss_init_sslver(
    mut sslver: *mut SSLVersionRange,
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let min: libc::c_long = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
        == (*conn).http_proxy.proxytype as libc::c_uint
        && ssl_connection_complete as libc::c_int as libc::c_uint
            != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize] == -(1 as libc::c_int)
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
    let min: libc::c_long = (*conn).ssl_config.version;
    #[cfg(not(CURL_DISABLE_PROXY))]
    let max: libc::c_long = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
        == (*conn).http_proxy.proxytype as libc::c_uint
        && ssl_connection_complete as libc::c_int as libc::c_uint
            != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize] == -(1 as libc::c_int)
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
    let max: libc::c_long = (*conn).ssl_config.version_max;
    let mut vrange: SSLVersionRange = SSLVersionRange { min: 0, max: 0 };
    match min {
        1 | 0 => {
            if SSL_VersionRangeGetDefault(ssl_variant_stream, &mut vrange) as libc::c_int
                != SECSuccess as libc::c_int
            {
                return CURLE_SSL_CONNECT_ERROR;
            }
            if ((*sslver).min as libc::c_int) < vrange.min as libc::c_int {
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
            result = nss_sslver_from_curl(&mut (*sslver).max, max >> 16 as libc::c_int);
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
unsafe extern "C" fn nss_fail_connect(
    mut connssl: *mut ssl_connect_data,
    mut data: *mut Curl_easy,
    mut curlerr: CURLcode,
) -> CURLcode {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    if is_nss_error(curlerr) {
        let mut err: PRErrorCode = PR_GetError();
        if is_cc_error(err) {
            curlerr = CURLE_SSL_CERTPROBLEM;
        }
        Curl_infof(
            data,
            b"NSS error %d (%s)\0" as *const u8 as *const libc::c_char,
            err,
            nss_error_to_name(err),
        );
        nss_print_error_message(data, err as PRUint32);
    }
    Curl_llist_destroy(&mut (*backend).obj_list, 0 as *mut libc::c_void);
    return curlerr;
}
unsafe extern "C" fn nss_set_blocking(
    mut connssl: *mut ssl_connect_data,
    mut data: *mut Curl_easy,
    mut blocking: bool,
) -> CURLcode {
    let mut sock_opt: PRSocketOptionData = PRSocketOptionData {
        option: PR_SockOpt_Nonblocking,
        value: nss_C2RustUnnamed_5 { ip_ttl: 0 },
    };
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    sock_opt.option = PR_SockOpt_Nonblocking;
    sock_opt.value.non_blocking = !blocking as libc::c_int;
    if PR_SetSocketOption((*backend).nss_handle, &mut sock_opt) as libc::c_int
        != PR_SUCCESS as libc::c_int
    {
        return nss_fail_connect(connssl, data, CURLE_SSL_CONNECT_ERROR);
    }
    return CURLE_OK;
}
// unsafe extern "C" fn nss_setup_connect(
//     mut data: *mut Curl_easy,
//     mut conn: *mut connectdata,
//     mut sockindex: libc::c_int,
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
//     let mut second_layer: bool = 0 as libc::c_int != 0;
//     let mut sslver_supported: SSLVersionRange = SSLVersionRange { min: 0, max: 0 };
//     let mut sslver: SSLVersionRange = {
//         let mut init = SSLVersionRangeStr {
//             min: 0x301 as libc::c_int as PRUint16,
//             max: 0x304 as libc::c_int as PRUint16,
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
//         if result as libc::c_uint == CURLE_FAILED_INIT as libc::c_int as libc::c_uint {
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
//                     if !(SSL_OptionSet(model, 1 as libc::c_int, 1 as libc::c_int) as libc::c_int
//                         != SECSuccess as libc::c_int)
//                     {
//                         if !(SSL_OptionSet(model, 6 as libc::c_int, 0 as libc::c_int)
//                             as libc::c_int
//                             != SECSuccess as libc::c_int)
//                         {
//                             if !(SSL_OptionSet(model, 5 as libc::c_int, 1 as libc::c_int)
//                                 as libc::c_int
//                                 != SECSuccess as libc::c_int)
//                             {
//                                 ssl_no_cache = if (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                     == (*conn).http_proxy.proxytype as libc::c_uint
//                                     && ssl_connection_complete as libc::c_int as libc::c_uint
//                                         != (*conn).proxy_ssl[(if (*conn).sock
//                                             [1 as libc::c_int as usize]
//                                             == -(1 as libc::c_int)
//                                         {
//                                             0 as libc::c_int
//                                         } else {
//                                             1 as libc::c_int
//                                         })
//                                             as usize]
//                                             .state
//                                             as libc::c_uint
//                                 {
//                                     ((*data).set.proxy_ssl.primary).sessionid() as libc::c_int
//                                 } else {
//                                     ((*data).set.ssl.primary).sessionid() as libc::c_int
//                                 }) != 0
//                                     && (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                         == (*conn).http_proxy.proxytype as libc::c_uint
//                                         && ssl_connection_complete as libc::c_int as libc::c_uint
//                                             != (*conn).proxy_ssl[(if (*conn).sock
//                                                 [1 as libc::c_int as usize]
//                                                 == -(1 as libc::c_int)
//                                             {
//                                                 0 as libc::c_int
//                                             } else {
//                                                 1 as libc::c_int
//                                             })
//                                                 as usize]
//                                                 .state
//                                                 as libc::c_uint
//                                     {
//                                         ((*conn).proxy_ssl_config).verifypeer() as libc::c_int
//                                     } else {
//                                         ((*conn).ssl_config).verifypeer() as libc::c_int
//                                     }) != 0
//                                 {
//                                     0 as libc::c_int
//                                 } else {
//                                     1 as libc::c_int
//                                 };
//                                 if !(SSL_OptionSet(model, 9 as libc::c_int, ssl_no_cache)
//                                     as libc::c_int
//                                     != SECSuccess as libc::c_int)
//                                 {
//                                     if !(nss_init_sslver(&mut sslver, data, conn) as libc::c_uint
//                                         != CURLE_OK as libc::c_int as libc::c_uint)
//                                     {
//                                         if !(SSL_VersionRangeGetSupported(
//                                             ssl_variant_stream,
//                                             &mut sslver_supported,
//                                         )
//                                             as libc::c_int
//                                             != SECSuccess as libc::c_int)
//                                         {
//                                             if (sslver_supported.max as libc::c_int)
//                                                 < sslver.max as libc::c_int
//                                                 && sslver_supported.max as libc::c_int
//                                                     >= sslver.min as libc::c_int
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
//                                                 as libc::c_int
//                                                 != SECSuccess as libc::c_int)
//                                             {
//                                                 ssl_cbc_random_iv = (if CURLPROXY_HTTPS
//                                                     as libc::c_int
//                                                     as libc::c_uint
//                                                     == (*conn).http_proxy.proxytype as libc::c_uint
//                                                     && ssl_connection_complete as libc::c_int
//                                                         as libc::c_uint
//                                                         != (*conn).proxy_ssl[(if (*conn).sock
//                                                             [1 as libc::c_int as usize]
//                                                             == -(1 as libc::c_int)
//                                                         {
//                                                             0 as libc::c_int
//                                                         } else {
//                                                             1 as libc::c_int
//                                                         })
//                                                             as usize]
//                                                             .state
//                                                             as libc::c_uint
//                                                 {
//                                                     ((*data).set.proxy_ssl).enable_beast()
//                                                         as libc::c_int
//                                                 } else {
//                                                     ((*data).set.ssl).enable_beast() as libc::c_int
//                                                 } == 0)
//                                                     as libc::c_int;
//                                                 if SSL_OptionSet(
//                                                     model,
//                                                     23 as libc::c_int,
//                                                     ssl_cbc_random_iv,
//                                                 )
//                                                     as libc::c_int
//                                                     != SECSuccess as libc::c_int
//                                                 {
//                                                     Curl_infof(
//                                                         data,
//                                                         b"warning: failed to set SSL_CBC_RANDOM_IV = %d\0"
//                                                             as *const u8 as *const libc::c_char,
//                                                         ssl_cbc_random_iv,
//                                                     );
//                                                 }
//                                                 if !if CURLPROXY_HTTPS as libc::c_int
//                                                     as libc::c_uint
//                                                     == (*conn).http_proxy.proxytype as libc::c_uint
//                                                     && ssl_connection_complete as libc::c_int
//                                                         as libc::c_uint
//                                                         != (*conn).proxy_ssl[(if (*conn).sock
//                                                             [1 as libc::c_int as usize]
//                                                             == -(1 as libc::c_int)
//                                                         {
//                                                             0 as libc::c_int
//                                                         } else {
//                                                             1 as libc::c_int
//                                                         })
//                                                             as usize]
//                                                             .state
//                                                             as libc::c_uint
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
//                                                         (if CURLPROXY_HTTPS as libc::c_int
//                                                             as libc::c_uint
//                                                             == (*conn).http_proxy.proxytype
//                                                                 as libc::c_uint
//                                                             && ssl_connection_complete
//                                                                 as libc::c_int
//                                                                 as libc::c_uint
//                                                                 != (*conn).proxy_ssl[(if (*conn)
//                                                                     .sock
//                                                                     [1 as libc::c_int as usize]
//                                                                     == -(1 as libc::c_int)
//                                                                 {
//                                                                     0 as libc::c_int
//                                                                 } else {
//                                                                     1 as libc::c_int
//                                                                 })
//                                                                     as usize]
//                                                                     .state
//                                                                     as libc::c_uint
//                                                         {
//                                                             (*conn).proxy_ssl_config.cipher_list
//                                                         } else {
//                                                             (*conn).ssl_config.cipher_list
//                                                         }),
//                                                     )
//                                                         as libc::c_int
//                                                         != SECSuccess as libc::c_int
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
//                                                         if (if CURLPROXY_HTTPS as libc::c_int
//                                                             as libc::c_uint
//                                                             == (*conn).http_proxy.proxytype
//                                                                 as libc::c_uint
//                                                             && ssl_connection_complete
//                                                                 as libc::c_int
//                                                                 as libc::c_uint
//                                                                 != (*conn).proxy_ssl[(if (*conn)
//                                                                     .sock
//                                                                     [1 as libc::c_int as usize]
//                                                                     == -(1 as libc::c_int)
//                                                                 {
//                                                                     0 as libc::c_int
//                                                                 } else {
//                                                                     1 as libc::c_int
//                                                                 })
//                                                                     as usize]
//                                                                     .state
//                                                                     as libc::c_uint
//                                                         {
//                                                             ((*conn).proxy_ssl_config).verifypeer()
//                                                                 as libc::c_int
//                                                         } else {
//                                                             ((*conn).ssl_config).verifypeer()
//                                                                 as libc::c_int
//                                                         }) == 0
//                                                             && (if CURLPROXY_HTTPS as libc::c_int
//                                                                 as libc::c_uint
//                                                                 == (*conn).http_proxy.proxytype
//                                                                     as libc::c_uint
//                                                                 && ssl_connection_complete
//                                                                     as libc::c_int
//                                                                     as libc::c_uint
//                                                                     != (*conn).proxy_ssl[(if (*conn)
//                                                                         .sock
//                                                                         [1 as libc::c_int as usize]
//                                                                         == -(1 as libc::c_int)
//                                                                     {
//                                                                         0 as libc::c_int
//                                                                     } else {
//                                                                         1 as libc::c_int
//                                                                     })
//                                                                         as usize]
//                                                                         .state
//                                                                         as libc::c_uint
//                                                             {
//                                                                 ((*conn).proxy_ssl_config)
//                                                                     .verifyhost()
//                                                                     as libc::c_int
//                                                             } else {
//                                                                 ((*conn).ssl_config).verifyhost()
//                                                                     as libc::c_int
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
//                                                         ) as libc::c_int != SECSuccess as libc::c_int)
//                                                         {
//                                                             *if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                 == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                 && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                     != (*conn)
//                                                                         .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                             == -(1 as libc::c_int)
//                                                                         {
//                                                                             0 as libc::c_int
//                                                                         } else {
//                                                                             1 as libc::c_int
//                                                                         }) as usize]
//                                                                         .state as libc::c_uint
//                                                             {
//                                                                 &mut (*data).set.proxy_ssl.certverifyresult
//                                                             } else {
//                                                                 &mut (*data).set.ssl.certverifyresult
//                                                             } = 0 as libc::c_int as libc::c_long;
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
//                                                             ) as libc::c_int != SECSuccess as libc::c_int)
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
//                                                                 ) as libc::c_int != SECSuccess as libc::c_int)
//                                                                 {
//                                                                     let rv: CURLcode = nss_load_ca_certificates(
//                                                                         data,
//                                                                         conn,
//                                                                         sockindex,
//                                                                     );
//                                                                     if rv as libc::c_uint
//                                                                         == CURLE_SSL_CACERT_BADFILE as libc::c_int as libc::c_uint
//                                                                         && (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                             == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                             && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                 != (*conn)
//                                                                                     .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                         == -(1 as libc::c_int)
//                                                                                     {
//                                                                                         0 as libc::c_int
//                                                                                     } else {
//                                                                                         1 as libc::c_int
//                                                                                     }) as usize]
//                                                                                     .state as libc::c_uint
//                                                                         {
//                                                                             ((*conn).proxy_ssl_config).verifypeer() as libc::c_int
//                                                                         } else {
//                                                                             ((*conn).ssl_config).verifypeer() as libc::c_int
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
//                                                                             if !if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                 == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                 && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                     != (*conn)
//                                                                                         .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                             == -(1 as libc::c_int)
//                                                                                         {
//                                                                                             0 as libc::c_int
//                                                                                         } else {
//                                                                                             1 as libc::c_int
//                                                                                         }) as usize]
//                                                                                         .state as libc::c_uint
//                                                                             {
//                                                                                 (*data).set.proxy_ssl.CRLfile
//                                                                             } else {
//                                                                                 (*data).set.ssl.CRLfile
//                                                                             }
//                                                                                 .is_null()
//                                                                             {
//                                                                                 let rv_0: CURLcode = nss_load_crl(
//                                                                                     if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                         == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                         && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                             != (*conn)
//                                                                                                 .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                     == -(1 as libc::c_int)
//                                                                                                 {
//                                                                                                     0 as libc::c_int
//                                                                                                 } else {
//                                                                                                     1 as libc::c_int
//                                                                                                 }) as usize]
//                                                                                                 .state as libc::c_uint
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
//                                                                                         if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                             == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                             && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                 != (*conn)
//                                                                                                     .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                         == -(1 as libc::c_int)
//                                                                                                     {
//                                                                                                         0 as libc::c_int
//                                                                                                     } else {
//                                                                                                         1 as libc::c_int
//                                                                                                     }) as usize]
//                                                                                                     .state as libc::c_uint
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
//                                                                                     if !if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                         == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                         && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                             != (*conn)
//                                                                                                 .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                     == -(1 as libc::c_int)
//                                                                                                 {
//                                                                                                     0 as libc::c_int
//                                                                                                 } else {
//                                                                                                     1 as libc::c_int
//                                                                                                 }) as usize]
//                                                                                                 .state as libc::c_uint
//                                                                                     {
//                                                                                         (*data).set.proxy_ssl.primary.clientcert
//                                                                                     } else {
//                                                                                         (*data).set.ssl.primary.clientcert
//                                                                                     }
//                                                                                         .is_null()
//                                                                                     {
//                                                                                         let mut nickname: *mut libc::c_char = dup_nickname(
//                                                                                             data,
//                                                                                             if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                                 == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                                 && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                     != (*conn)
//                                                                                                         .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                             == -(1 as libc::c_int)
//                                                                                                         {
//                                                                                                             0 as libc::c_int
//                                                                                                         } else {
//                                                                                                             1 as libc::c_int
//                                                                                                         }) as usize]
//                                                                                                         .state as libc::c_uint
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
//                                                                                                 if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                                     == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                                     && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                         != (*conn)
//                                                                                                             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                                 == -(1 as libc::c_int)
//                                                                                                             {
//                                                                                                                 0 as libc::c_int
//                                                                                                             } else {
//                                                                                                                 1 as libc::c_int
//                                                                                                             }) as usize]
//                                                                                                             .state as libc::c_uint
//                                                                                                 {
//                                                                                                     (*data).set.proxy_ssl.primary.clientcert
//                                                                                                 } else {
//                                                                                                     (*data).set.ssl.primary.clientcert
//                                                                                                 },
//                                                                                                 if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                                     == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                                     && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                         != (*conn)
//                                                                                                             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                                 == -(1 as libc::c_int)
//                                                                                                             {
//                                                                                                                 0 as libc::c_int
//                                                                                                             } else {
//                                                                                                                 1 as libc::c_int
//                                                                                                             }) as usize]
//                                                                                                             .state as libc::c_uint
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
//                                                                                             ) as libc::c_int != SECSuccess as libc::c_int
//                                                                                             {
//                                                                                                 result = CURLE_SSL_CERTPROBLEM;
//                                                                                             } else {
//                                                                                                 if ((*conn).proxy_ssl[sockindex as usize]).use_0() != 0 {
//                                                                                                     nspr_io = (*(*conn).proxy_ssl[sockindex as usize].backend)
//                                                                                                          handle;
//                                                                                                     second_layer = 1 as libc::c_int != 0;
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
//                                                                                                                 -(2 as libc::c_int),
//                                                                                                                 nspr_io_stub,
//                                                                                                             ) as libc::c_int != PR_SUCCESS as libc::c_int
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
//                                                                                                                     if !if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                                                         == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                                                         && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                                             != (*conn)
//                                                                                                                                 .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                                                     == -(1 as libc::c_int)
//                                                                                                                                 {
//                                                                                                                                     0 as libc::c_int
//                                                                                                                                 } else {
//                                                                                                                                     1 as libc::c_int
//                                                                                                                                 }) as usize]
//                                                                                                                                 .state as libc::c_uint
//                                                                                                                     {
//                                                                                                                         (*data).set.proxy_ssl.key_passwd
//                                                                                                                     } else {
//                                                                                                                         (*data).set.ssl.key_passwd
//                                                                                                                     }
//                                                                                                                         .is_null()
//                                                                                                                     {
//                                                                                                                         SSL_SetPKCS11PinArg(
//                                                                                                                             (*backend).handle,
//                                                                                                                             (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                                                                 == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                                                                 && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                                                     != (*conn)
//                                                                                                                                         .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                                                             == -(1 as libc::c_int)
//                                                                                                                                         {
//                                                                                                                                             0 as libc::c_int
//                                                                                                                                         } else {
//                                                                                                                                             1 as libc::c_int
//                                                                                                                                         }) as usize]
//                                                                                                                                         .state as libc::c_uint
//                                                                                                                             {
//                                                                                                                                 (*data).set.proxy_ssl.key_passwd
//                                                                                                                             } else {
//                                                                                                                                 (*data).set.ssl.key_passwd
//                                                                                                                             }) as *mut libc::c_void,
//                                                                                                                         );
//                                                                                                                     }
//                                                                                                                     if if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                                                         == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                                                         && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                                             != (*conn)
//                                                                                                                                 .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                                                     == -(1 as libc::c_int)
//                                                                                                                                 {
//                                                                                                                                     0 as libc::c_int
//                                                                                                                                 } else {
//                                                                                                                                     1 as libc::c_int
//                                                                                                                                 }) as usize]
//                                                                                                                                 .state as libc::c_uint
//                                                                                                                     {
//                                                                                                                         ((*conn).proxy_ssl_config).verifystatus() as libc::c_int
//                                                                                                                     } else {
//                                                                                                                         ((*conn).ssl_config).verifystatus() as libc::c_int
//                                                                                                                     } != 0
//                                                                                                                     {
//                                                                                                                         if SSL_OptionSet(
//                                                                                                                             (*backend).handle,
//                                                                                                                             24 as libc::c_int,
//                                                                                                                             1 as libc::c_int,
//                                                                                                                         ) as libc::c_int != SECSuccess as libc::c_int
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
//                                                                                                                                 25 as libc::c_int,
//                                                                                                                                 (if ((*conn).bits).tls_enable_npn() as libc::c_int != 0 {
//                                                                                                                                     1 as libc::c_int
//                                                                                                                                 } else {
//                                                                                                                                     0 as libc::c_int
//                                                                                                                                 }),
//                                                                                                                             ) as libc::c_int != SECSuccess as libc::c_int)
//                                                                                                                             {
//                                                                                                                                 if !(SSL_OptionSet(
//                                                                                                                                     (*backend).handle,
//                                                                                                                                     26 as libc::c_int,
//                                                                                                                                     (if ((*conn).bits).tls_enable_alpn() as libc::c_int != 0 {
//                                                                                                                                         1 as libc::c_int
//                                                                                                                                     } else {
//                                                                                                                                         0 as libc::c_int
//                                                                                                                                     }),
//                                                                                                                                 ) as libc::c_int != SECSuccess as libc::c_int)
//                                                                                                                                 {
//                                                                                                                                     if ((*data).set.ssl).falsestart() != 0 {
//                                                                                                                                         if SSL_OptionSet(
//                                                                                                                                             (*backend).handle,
//                                                                                                                                             22 as libc::c_int,
//                                                                                                                                             1 as libc::c_int,
//                                                                                                                                         ) as libc::c_int != SECSuccess as libc::c_int
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
//                                                                                                                                             ) as libc::c_int != SECSuccess as libc::c_int
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
//                                                                                                                                             if ((*conn).bits).tls_enable_npn() as libc::c_int != 0
//                                                                                                                                                 || ((*conn).bits).tls_enable_alpn() as libc::c_int != 0
//                                                                                                                                             {
//                                                                                                                                                 let mut cur: libc::c_int = 0 as libc::c_int;
//                                                                                                                                                 let mut protocols: [libc::c_uchar; 128] = [0; 128];
//                                                                                                                                                 if (*data).state.httpwant as libc::c_int
//                                                                                                                                                     >= CURL_HTTP_VERSION_2_0 as libc::c_int
//                                                                                                                                                     && (!(CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                                                                                         == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                                                                                         && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                                                                             != (*conn)
//                                                                                                                                                                 .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                                                                                     == -(1 as libc::c_int)
//                                                                                                                                                                 {
//                                                                                                                                                                     0 as libc::c_int
//                                                                                                                                                                 } else {
//                                                                                                                                                                     1 as libc::c_int
//                                                                                                                                                                 }) as usize]
//                                                                                                                                                                 .state as libc::c_uint)
//                                                                                                                                                         || ((*conn).bits).tunnel_proxy() == 0)
//                                                                                                                                                 {
//                                                                                                                                                     let fresh23 = cur;
//                                                                                                                                                     cur = cur + 1;
//                                                                                                                                                     protocols[fresh23
//                                                                                                                                                         as usize] = 2 as libc::c_int as libc::c_uchar;
//                                                                                                                                                     memcpy(
//                                                                                                                                                         &mut *protocols.as_mut_ptr().offset(cur as isize)
//                                                                                                                                                             as *mut libc::c_uchar as *mut libc::c_void,
//                                                                                                                                                         b"h2\0" as *const u8 as *const libc::c_char
//                                                                                                                                                             as *const libc::c_void,
//                                                                                                                                                         2 as libc::c_int as libc::c_ulong,
//                                                                                                                                                     );
//                                                                                                                                                     cur += 2 as libc::c_int;
//                                                                                                                                                 }
//                                                                                                                                                 let fresh24 = cur;
//                                                                                                                                                 cur = cur + 1;
//                                                                                                                                                 protocols[fresh24
//                                                                                                                                                     as usize] = 8 as libc::c_int as libc::c_uchar;
//                                                                                                                                                 memcpy(
//                                                                                                                                                     &mut *protocols.as_mut_ptr().offset(cur as isize)
//                                                                                                                                                         as *mut libc::c_uchar as *mut libc::c_void,
//                                                                                                                                                     b"http/1.1\0" as *const u8 as *const libc::c_char
//                                                                                                                                                         as *const libc::c_void,
//                                                                                                                                                     8 as libc::c_int as libc::c_ulong,
//                                                                                                                                                 );
//                                                                                                                                                 cur += 8 as libc::c_int;
//                                                                                                                                                 if SSL_SetNextProtoNego(
//                                                                                                                                                     (*backend).handle,
//                                                                                                                                                     protocols.as_mut_ptr(),
//                                                                                                                                                     cur as libc::c_uint,
//                                                                                                                                                 ) as libc::c_int != SECSuccess as libc::c_int
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
//                                                                                                                                                     if !(SSL_ResetHandshake((*backend).handle, 0 as libc::c_int)
//                                                                                                                                                         as libc::c_int != SECSuccess as libc::c_int)
//                                                                                                                                                     {
//                                                                                                                                                         if !(SSL_SetURL(
//                                                                                                                                                             (*backend).handle,
//                                                                                                                                                             (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                                                                                                 == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                                                                                                 && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                                                                                     != (*conn)
//                                                                                                                                                                         .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                                                                                             == -(1 as libc::c_int)
//                                                                                                                                                                         {
//                                                                                                                                                                             0 as libc::c_int
//                                                                                                                                                                         } else {
//                                                                                                                                                                             1 as libc::c_int
//                                                                                                                                                                         }) as usize]
//                                                                                                                                                                         .state as libc::c_uint
//                                                                                                                                                             {
//                                                                                                                                                                 (*conn).http_proxy.host.name
//                                                                                                                                                             } else {
//                                                                                                                                                                 (*conn).host.name
//                                                                                                                                                             }),
//                                                                                                                                                         ) as libc::c_int != SECSuccess as libc::c_int)
//                                                                                                                                                         {
//                                                                                                                                                             if !(SSL_SetSockPeerID(
//                                                                                                                                                                 (*backend).handle,
//                                                                                                                                                                 (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                                                                                                                                                     == (*conn).http_proxy.proxytype as libc::c_uint
//                                                                                                                                                                     && ssl_connection_complete as libc::c_int as libc::c_uint
//                                                                                                                                                                         != (*conn)
//                                                                                                                                                                             .proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                                                                                                                                                                 == -(1 as libc::c_int)
//                                                                                                                                                                             {
//                                                                                                                                                                                 0 as libc::c_int
//                                                                                                                                                                             } else {
//                                                                                                                                                                                 1 as libc::c_int
//                                                                                                                                                                             }) as usize]
//                                                                                                                                                                             .state as libc::c_uint
//                                                                                                                                                                 {
//                                                                                                                                                                     (*conn).http_proxy.host.name
//                                                                                                                                                                 } else {
//                                                                                                                                                                     (*conn).host.name
//                                                                                                                                                                 }),
//                                                                                                                                                             ) as libc::c_int != SECSuccess as libc::c_int)
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
unsafe extern "C" fn nss_setup_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
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
    let mut second_layer: bool = 0 as libc::c_int != 0;
    let mut sslver_supported: SSLVersionRange = SSLVersionRange { min: 0, max: 0 };
    let mut sslver: SSLVersionRange = {
        #[cfg(SSL_LIBRARY_VERSION_TLS_1_3)]
        let mut init = SSLVersionRangeStr {
            min: 0x301 as libc::c_int as PRUint16,
            max: 0x304 as libc::c_int as PRUint16,
        };
        #[cfg(SSL_LIBRARY_VERSION_TLS_1_2)]
        let mut init = SSLVersionRangeStr {
            min: 0x301 as libc::c_int as PRUint16,
            max: 0x303 as libc::c_int as PRUint16,
        };
        #[cfg(SSL_LIBRARY_VERSION_TLS_1_1)]
        let mut init = SSLVersionRangeStr {
            min: 0x301 as libc::c_int as PRUint16,
            max: 0x302 as libc::c_int as PRUint16,
        };
        #[cfg(all(not(SSL_LIBRARY_VERSION_TLS_1_3), not(SSL_LIBRARY_VERSION_TLS_1_2), not(SSL_LIBRARY_VERSION_TLS_1_1)))]
        let mut init = SSLVersionRangeStr {
            min: 0x301 as libc::c_int as PRUint16,
            max: 0x301 as libc::c_int as PRUint16,
        };
        init
    };
    let ref mut fresh17 = (*backend).data;
    *fresh17 = data;
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
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        PK11_SetPasswordFunc(Some(
            nss_get_password
                as unsafe extern "C" fn(
                    *mut PK11SlotInfo,
                    PRBool,
                    *mut libc::c_void,
                ) -> *mut libc::c_char,
        ));
        result = nss_load_module(
            &mut pem_module,
            pem_library,
            b"PEM\0" as *const u8 as *const libc::c_char,
        );
        PR_Unlock(nss_initlock);
        if result as libc::c_uint == CURLE_FAILED_INIT as libc::c_int as libc::c_uint {
            Curl_infof(
            data,
            b"WARNING: failed to load NSS PEM library %s. Using OpenSSL PEM certificates will not work.\0"
                as *const u8 as *const libc::c_char,
            pem_library,
        );
        } else if result as u64 != 0 {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        result = CURLE_SSL_CONNECT_ERROR;
        model = PR_NewTCPSocket();
        if model.is_null() {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        model = SSL_ImportFD(0 as *mut PRFileDesc, model);
        if SSL_OptionSet(model, 1 as libc::c_int, 1 as libc::c_int) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if SSL_OptionSet(model, 6 as libc::c_int, 0 as libc::c_int) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if SSL_OptionSet(model, 5 as libc::c_int, 1 as libc::c_int) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let ssl_no_cache_value = if (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                    == (*conn).http_proxy.proxytype as libc::c_uint
                                    && ssl_connection_complete as libc::c_int as libc::c_uint
                                        != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
                                }) != 0
                                    && (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                        == (*conn).http_proxy.proxytype as libc::c_uint
                                        && ssl_connection_complete as libc::c_int as libc::c_uint
                                            != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
                                {
                                    0 as libc::c_int
                                } else {
                                    1 as libc::c_int
                                };
        #[cfg(CURL_DISABLE_PROXY)]
        let ssl_no_cache_value = if ((*data).set.ssl.primary).sessionid()
                                    as libc::c_int != 0
                                    && ((*conn).ssl_config).verifypeer() as libc::c_int != 0
                                {
                                    0 as libc::c_int
                                } else {
                                    1 as libc::c_int
                                };

        ssl_no_cache = ssl_no_cache_value;
        if SSL_OptionSet(model, 9 as libc::c_int, ssl_no_cache) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if nss_init_sslver(&mut sslver, data, conn) as libc::c_uint
            != CURLE_OK as libc::c_int as libc::c_uint
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if SSL_VersionRangeGetSupported(ssl_variant_stream, &mut sslver_supported) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if (sslver_supported.max as libc::c_int) < sslver.max as libc::c_int
            && sslver_supported.max as libc::c_int >= sslver.min as libc::c_int
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
            Curl_cfree.expect("non-null function pointer")(sslver_req_str as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")(sslver_supp_str as *mut libc::c_void);
            sslver.max = sslver_supported.max;
        }
        if SSL_VersionRangeSet(model, &mut sslver) as libc::c_int != SECSuccess as libc::c_int {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let ssl_cbc_random_iv_value = (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                        == (*conn).http_proxy.proxytype as libc::c_uint
                                        && ssl_connection_complete as libc::c_int as libc::c_uint
                                            != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                == -(1 as libc::c_int)
                                            {
                                                0 as libc::c_int
                                            } else {
                                                1 as libc::c_int
                                            }) as usize]
                                                .state as libc::c_uint
                                    {
                                        ((*data).set.proxy_ssl).enable_beast() as libc::c_int
                                    } else {
                                        ((*data).set.ssl).enable_beast() as libc::c_int
                                    } == 0) as libc::c_int;
        #[cfg(CURL_DISABLE_PROXY)]
        let ssl_cbc_random_iv_value = (((*data).set.ssl).enable_beast() == 0)
                                            as libc::c_int;
        ssl_cbc_random_iv = ssl_cbc_random_iv_value;
        #[cfg(SSL_CBC_RANDOM_IV)]
        if SSL_OptionSet(model, 23 as libc::c_int, ssl_cbc_random_iv) as libc::c_int
            != SECSuccess as libc::c_int
        {
            Curl_infof(
                data,
                b"warning: failed to set SSL_CBC_RANDOM_IV = %d\0" as *const u8
                    as *const libc::c_char,
                ssl_cbc_random_iv,
            );
        }

        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_CONN_CONFIG_cipher_list = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                            == (*conn).http_proxy.proxytype as libc::c_uint
                                            && ssl_connection_complete as libc::c_int as libc::c_uint
                                                != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
        if !SSL_CONN_CONFIG_cipher_list.is_null()
        {
            if set_ciphers(
                data,
                model,
                SSL_CONN_CONFIG_cipher_list,
            ) as libc::c_int
                != SECSuccess as libc::c_int
            {
                result = CURLE_SSL_CIPHER;
                // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
                break 'error;
            }
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_CONN_CONFIG_verifypeer = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                            == (*conn).http_proxy.proxytype as libc::c_uint
                                            && ssl_connection_complete as libc::c_int as libc::c_uint
                                                != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
                                        };
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_CONN_CONFIG_verifypeer = ((*conn).ssl_config).verifypeer();
        
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_CONN_CONFIG_verifyhost = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                            == (*conn).http_proxy.proxytype as libc::c_uint
                                            && ssl_connection_complete as libc::c_int as libc::c_uint
                                                != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
        ) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        if true {
            *if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                == (*conn).http_proxy.proxytype as libc::c_uint
                && ssl_connection_complete as libc::c_int as libc::c_uint
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
            } = 0 as libc::c_int as libc::c_long;
        }
        #[cfg(CURL_DISABLE_PROXY)]
        if true {
             (*data)
                .set
                .ssl
                .certverifyresult = 0 as libc::c_int as libc::c_long;
        }
        if SSL_BadCertHook(
            model,
            Some(
                BadCertHandler
                    as unsafe extern "C" fn(*mut libc::c_void, *mut PRFileDesc) -> SECStatus,
            ),
            data as *mut libc::c_void,
        ) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if SSL_HandshakeCallback(
            model,
            Some(
                HandshakeCallback as unsafe extern "C" fn(*mut PRFileDesc, *mut libc::c_void) -> (),
            ),
            data as *mut libc::c_void,
        ) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        let rv: CURLcode = nss_load_ca_certificates(data, conn, sockindex);
        if rv as libc::c_uint == CURLE_SSL_CACERT_BADFILE as libc::c_int as libc::c_uint
            && (SSL_CONN_CONFIG_verifypeer) == 0
        {
            Curl_infof(
                data,
                b"warning: CA certificates failed to load\0" as *const u8 as *const libc::c_char,
            );
        } else if rv as u64 != 0 {
            result = rv;
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_SET_OPTION_CRLfile = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                        == (*conn).http_proxy.proxytype as libc::c_uint
                                        && ssl_connection_complete as libc::c_int as libc::c_uint
                                            != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                == -(1 as libc::c_int)
                                            {
                                                0 as libc::c_int
                                            } else {
                                                1 as libc::c_int
                                            }) as usize]
                                                .state as libc::c_uint
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
                // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
                break 'error;
            }
            Curl_infof(
                data,
                b"  CRLfile: %s\0" as *const u8 as *const libc::c_char,
                SSL_SET_OPTION_CRLfile,
            );
        }

        #[cfg(not(CURL_DISABLE_PROXY))]
        let  SSL_SET_OPTION_primary_clientcert = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                                    == (*conn).http_proxy.proxytype as libc::c_uint
                                                    && ssl_connection_complete as libc::c_int as libc::c_uint
                                                        != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                            == -(1 as libc::c_int)
                                                        {
                                                            0 as libc::c_int
                                                        } else {
                                                            1 as libc::c_int
                                                        }) as usize]
                                                            .state as libc::c_uint
                                                {
                                                    (*data).set.proxy_ssl.primary.clientcert
                                                } else {
                                                    (*data).set.ssl.primary.clientcert
                                                };
        #[cfg(CURL_DISABLE_PROXY)]
        let  SSL_SET_OPTION_primary_clientcert = (*data).set.ssl.primary.clientcert;
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_SET_OPTION_key = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                        == (*conn).http_proxy.proxytype as libc::c_uint
                                        && ssl_connection_complete as libc::c_int as libc::c_uint
                                            != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
                let ref mut fresh18 = (*backend).obj_clicert;
                *fresh18 = 0 as *mut PK11GenericObject;
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
                    // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
                    break 'error;
                }
            }
            let ref mut fresh19 = (*backend).client_nickname;
            *fresh19 = nickname;
        } else {
            let ref mut fresh20 = (*backend).client_nickname;
            *fresh20 = 0 as *mut libc::c_char;
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
        ) as libc::c_int
            != SECSuccess as libc::c_int
        {
            result = CURLE_SSL_CERTPROBLEM;
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }

        #[cfg(not(CURL_DISABLE_PROXY))]
        if ((*conn).proxy_ssl[sockindex as usize]).use_0() != 0 {
            nspr_io = (*(*conn).proxy_ssl[sockindex as usize].backend).nss_handle;
            second_layer = 1 as libc::c_int != 0;
        } else {
            nspr_io = PR_ImportTCPSocket(sockfd);
            if nspr_io.is_null() {
                // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
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
        ) as libc::c_int
            != SECSuccess as libc::c_int
        {
            result = CURLE_SSL_CERTPROBLEM;
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }else {
            nspr_io = PR_ImportTCPSocket(sockfd);
            if nspr_io.is_null() {
                // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
                break 'error;
            }
        }


        nspr_io_stub = PR_CreateIOLayerStub(nspr_io_identity, &mut nspr_io_methods);
        if nspr_io_stub.is_null() {
            if !second_layer {
                PR_Close(nspr_io);
            }
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        let ref mut fresh21 = (*nspr_io_stub).secret;
        *fresh21 = connssl as *mut libc::c_void as *mut PRFilePrivate;
        if PR_PushIOLayer(nspr_io, -(2 as libc::c_int), nspr_io_stub) as libc::c_int
            != PR_SUCCESS as libc::c_int
        {
            if !second_layer {
                PR_Close(nspr_io);
            }
            PR_Close(nspr_io_stub);
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        let ref mut fresh22 = (*backend).nss_handle;
        *fresh22 = SSL_ImportFD(model, nspr_io);
        if ((*backend).nss_handle).is_null() {
            if !second_layer {
                PR_Close(nspr_io);
            }
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        PR_Close(model);
        model = 0 as *mut PRFileDesc;
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_SET_OPTION_key_passwd = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                            == (*conn).http_proxy.proxytype as libc::c_uint
                                            && ssl_connection_complete as libc::c_int as libc::c_uint
                                                != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
        let SSL_CONN_CONFIG_verifystatus = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                                == (*conn).http_proxy.proxytype as libc::c_uint
                                                && ssl_connection_complete as libc::c_int as libc::c_uint
                                                    != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
                                            };
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_CONN_CONFIG_verifystatus = ((*conn).ssl_config).verifystatus();
        #[cfg(SSL_ENABLE_OCSP_STAPLING)]
        if SSL_CONN_CONFIG_verifystatus != 0
        {
            if SSL_OptionSet((*backend).nss_handle, 24 as libc::c_int, 1 as libc::c_int) as libc::c_int
                != SECSuccess as libc::c_int
            {
                // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
                break 'error;
            }
        }
        #[cfg(SSL_ENABLE_NPN)]
        if SSL_OptionSet(
            (*backend).nss_handle,
            25 as libc::c_int,
            (if ((*conn).bits).tls_enable_npn() as libc::c_int != 0 {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }),
        ) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        #[cfg(SSL_ENABLE_ALPN)]
        if SSL_OptionSet(
            (*backend).nss_handle,
            26 as libc::c_int,
            (if ((*conn).bits).tls_enable_alpn() as libc::c_int != 0 {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }),
        ) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if ((*data).set.ssl).falsestart() != 0 {
            if SSL_OptionSet((*backend).nss_handle, 22 as libc::c_int, 1 as libc::c_int) as libc::c_int
                != SECSuccess as libc::c_int
            {
                // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
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
            ) as libc::c_int
                != SECSuccess as libc::c_int
            {
                // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
                break 'error;
            }
        }
        #[cfg(any(SSL_ENABLE_NPN, SSL_ENABLE_ALPN))]
        if ((*conn).bits).tls_enable_npn() as libc::c_int != 0
            || ((*conn).bits).tls_enable_alpn() as libc::c_int != 0
        {
            let mut cur: libc::c_int = 0 as libc::c_int;
            let mut protocols: [libc::c_uchar; 128] = [0; 128];
            #[cfg(USE_HTTP2)]
            if true{
                #[cfg(not(CURL_DISABLE_PROXY))]
                let CURL_DISABLE_PROXY_1 = (!(CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                            == (*conn).http_proxy.proxytype as libc::c_uint
                                            && ssl_connection_complete as libc::c_int as libc::c_uint
                                                != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
                                                    == -(1 as libc::c_int)
                                                {
                                                    0 as libc::c_int
                                                } else {
                                                    1 as libc::c_int
                                                }) as usize]
                                                    .state as libc::c_uint)
                                            || ((*conn).bits).tunnel_proxy() == 0);
                #[cfg(CURL_DISABLE_PROXY)]
                let CURL_DISABLE_PROXY_1 = true;                 
                if (*data).state.httpwant as libc::c_int >= CURL_HTTP_VERSION_2_0 as libc::c_int
                    && CURL_DISABLE_PROXY_1
                {
                    let fresh23 = cur;
                    cur = cur + 1;
                    protocols[fresh23 as usize] = 2 as libc::c_int as libc::c_uchar;
                    memcpy(
                        &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut libc::c_uchar
                            as *mut libc::c_void,
                        b"h2\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                        2 as libc::c_int as libc::c_ulong,
                    );
                    cur += 2 as libc::c_int;
                }
            }
            let fresh24 = cur;
            cur = cur + 1;
            protocols[fresh24 as usize] = 8 as libc::c_int as libc::c_uchar;
            memcpy(
                &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut libc::c_uchar
                    as *mut libc::c_void,
                b"http/1.1\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                8 as libc::c_int as libc::c_ulong,
            );
            cur += 8 as libc::c_int;
            if SSL_SetNextProtoNego(
                (*backend).nss_handle,
                protocols.as_mut_ptr(),
                cur as libc::c_uint,
            ) as libc::c_int
                != SECSuccess as libc::c_int
            {
                // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
                break 'error;
            }
        }
        if SSL_ResetHandshake((*backend).nss_handle, 0 as libc::c_int) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_HOST_NAME_void = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                    == (*conn).http_proxy.proxytype as libc::c_uint
                                    && ssl_connection_complete as libc::c_int as libc::c_uint
                                        != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
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
        let SSL_HOST_NAME_void = (*conn).host.name;
        if SSL_SetURL(
            (*backend).nss_handle,
            SSL_HOST_NAME_void,
        ) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        if SSL_SetSockPeerID(
            (*backend).nss_handle,
            SSL_HOST_NAME_void,
        ) as libc::c_int
            != SECSuccess as libc::c_int
        {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
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

// unsafe extern "C" fn nss_do_connect(
//     mut data: *mut Curl_easy,
//     mut conn: *mut connectdata,
//     mut sockindex: libc::c_int,
// ) -> CURLcode {
//     let mut current_block: u64;
//     let mut connssl: *mut ssl_connect_data =
//         &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
//     let mut backend: *mut ssl_backend_data = (*connssl).backend;
//     let mut result: CURLcode = CURLE_SSL_CONNECT_ERROR;
//     let mut timeout: PRUint32 = 0;
//     let time_left: timediff_t = Curl_timeleft(data, 0 as *mut curltime, 1 as libc::c_int != 0);
//     if time_left < 0 as libc::c_int as libc::c_long {
//         Curl_failf(
//             data,
//             b"timed out before SSL handshake\0" as *const u8 as *const libc::c_char,
//         );
//         result = CURLE_OPERATION_TIMEDOUT;
//     } else {
//         timeout = PR_MillisecondsToInterval(time_left as PRUint32);
//         if SSL_ForceHandshakeWithTimeout((*backend).handle, timeout) as libc::c_int
//             != SECSuccess as libc::c_int
//         {
//             if PR_GetError() as libc::c_long == -(5998 as libc::c_long) {
//                 return CURLE_AGAIN;
//             } else {
//                 if (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                     == (*conn).http_proxy.proxytype as libc::c_uint
//                     && ssl_connection_complete as libc::c_int as libc::c_uint
//                         != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                             == -(1 as libc::c_int)
//                         {
//                             0 as libc::c_int
//                         } else {
//                             1 as libc::c_int
//                         }) as usize]
//                             .state as libc::c_uint
//                 {
//                     (*data).set.proxy_ssl.certverifyresult
//                 } else {
//                     (*data).set.ssl.certverifyresult
//                 }) == SSL_ERROR_BAD_CERT_DOMAIN as libc::c_int as libc::c_long
//                 {
//                     result = CURLE_PEER_FAILED_VERIFICATION;
//                 } else if (if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                     == (*conn).http_proxy.proxytype as libc::c_uint
//                     && ssl_connection_complete as libc::c_int as libc::c_uint
//                         != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                             == -(1 as libc::c_int)
//                         {
//                             0 as libc::c_int
//                         } else {
//                             1 as libc::c_int
//                         }) as usize]
//                             .state as libc::c_uint
//                 {
//                     (*data).set.proxy_ssl.certverifyresult
//                 } else {
//                     (*data).set.ssl.certverifyresult
//                 }) != 0 as libc::c_int as libc::c_long
//                 {
//                     result = CURLE_PEER_FAILED_VERIFICATION;
//                 }
//             }
//         } else {
//             result = display_conn_info(data, (*backend).handle);
//             if !(result as u64 != 0) {
//                 if !if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                     == (*conn).http_proxy.proxytype as libc::c_uint
//                     && ssl_connection_complete as libc::c_int as libc::c_uint
//                         != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                             == -(1 as libc::c_int)
//                         {
//                             0 as libc::c_int
//                         } else {
//                             1 as libc::c_int
//                         }) as usize]
//                             .state as libc::c_uint
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
//                         if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                             == (*conn).http_proxy.proxytype as libc::c_uint
//                             && ssl_connection_complete as libc::c_int as libc::c_uint
//                                 != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                     == -(1 as libc::c_int)
//                                 {
//                                     0 as libc::c_int
//                                 } else {
//                                     1 as libc::c_int
//                                 }) as usize]
//                                     .state as libc::c_uint
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
//                     if SECFailure as libc::c_int == ret as libc::c_int {
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
//                             if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
//                                 == (*conn).http_proxy.proxytype as libc::c_uint
//                                 && ssl_connection_complete as libc::c_int as libc::c_uint
//                                     != (*conn).proxy_ssl[(if (*conn).sock[1 as libc::c_int as usize]
//                                         == -(1 as libc::c_int)
//                                     {
//                                         0 as libc::c_int
//                                     } else {
//                                         1 as libc::c_int
//                                     })
//                                         as usize]
//                                         .state
//                                         as libc::c_uint
//                             {
//                                 (*data).set.str_0
//                                     [STRING_SSL_PINNEDPUBLICKEY_PROXY as libc::c_int as usize]
//                             } else {
//                                 (*data).set.str_0
//                                     [STRING_SSL_PINNEDPUBLICKEY as libc::c_int as usize]
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
unsafe extern "C" fn nss_do_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data = &mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut result: CURLcode = CURLE_SSL_CONNECT_ERROR;
    let mut timeout: PRUint32 = 0;
    let time_left: timediff_t = Curl_timeleft(
        data,
        0 as *mut curltime,
        1 as libc::c_int != 0,
    );
    'error: loop {
        if time_left < 0 as libc::c_int as libc::c_long {
            Curl_failf(
                data,
                b"timed out before SSL handshake\0" as *const u8 as *const libc::c_char,
            );
            result = CURLE_OPERATION_TIMEDOUT;
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        timeout = PR_MillisecondsToInterval(time_left as PRUint32);
        #[cfg(not(CURL_DISABLE_PROXY))]
        let SSL_SET_OPTION_certverifyresult = if CURLPROXY_HTTPS as libc::c_int as libc::c_uint
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
                                                (*data).set.proxy_ssl.certverifyresult
                                            } else {
                                                (*data).set.ssl.certverifyresult
                                            };
        #[cfg(CURL_DISABLE_PROXY)]
        let SSL_SET_OPTION_certverifyresult = (*data).set.ssl.certverifyresult;
        if SSL_ForceHandshakeWithTimeout((*backend).nss_handle, timeout) as libc::c_int
            != SECSuccess as libc::c_int
        {
            if PR_GetError() as libc::c_long == -(5998 as libc::c_long) {
                return CURLE_AGAIN
            } else {
                if SSL_SET_OPTION_certverifyresult == SSL_ERROR_BAD_CERT_DOMAIN as libc::c_int as libc::c_long
                {
                    result = CURLE_PEER_FAILED_VERIFICATION;
                } else if SSL_SET_OPTION_certverifyresult != 0 as libc::c_int as libc::c_long
                    {
                    result = CURLE_PEER_FAILED_VERIFICATION;
                }
            }
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        result = display_conn_info(data, (*backend).nss_handle);
        if result as u64 != 0 {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }

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
            if SECFailure as libc::c_int == ret as libc::c_int {
                Curl_infof(
                    data,
                    b"SSL certificate issuer check failed\0" as *const u8
                        as *const libc::c_char,
                );
                result = CURLE_SSL_ISSUER_ERROR;
                // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
                break 'error;
            } else {
                Curl_infof(
                    data,
                    b"SSL certificate issuer check ok\0" as *const u8 as *const libc::c_char,
                );
            }
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
        let SSL_PINNED_PUB_KEY_void = (*data)
                                        .set
                                        .str_0[STRING_SSL_PINNEDPUBLICKEY as libc::c_int as usize];
        result = cmp_peer_pubkey(
            connssl,
            SSL_PINNED_PUB_KEY_void,
        );
        if result as u64 != 0 {
            // curl_mprintf(b"error\0" as *const u8 as *const libc::c_char);
            break 'error;
        }
        return CURLE_OK;
    }
    return nss_fail_connect(connssl, data, result);
}
unsafe extern "C" fn nss_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
    let blocking: bool = done.is_null();
    let mut result: CURLcode = CURLE_OK;
    if (*connssl).state as libc::c_uint == ssl_connection_complete as libc::c_int as libc::c_uint {
        if !blocking {
            *done = 1 as libc::c_int != 0;
        }
        return CURLE_OK;
    }
    if (*connssl).connecting_state as libc::c_uint == ssl_connect_1 as libc::c_int as libc::c_uint {
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
        match result as libc::c_uint {
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
        result = nss_set_blocking(connssl, data, 0 as libc::c_int != 0);
        if result as u64 != 0 {
            return result;
        }
    } else {
        *done = 1 as libc::c_int != 0;
    }
    (*connssl).state = ssl_connection_complete;
    let ref mut fresh25 = (*conn).recv[sockindex as usize];
    *fresh25 = Some(nss_recv as Curl_recv);
    let ref mut fresh26 = (*conn).send[sockindex as usize];
    *fresh26 = Some(nss_send as Curl_send);
    (*connssl).connecting_state = ssl_connect_1;
    return CURLE_OK;
}
unsafe extern "C" fn nss_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
) -> CURLcode {
    return nss_connect_common(data, conn, sockindex, 0 as *mut bool);
}
unsafe extern "C" fn nss_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: libc::c_int,
    mut done: *mut bool,
) -> CURLcode {
    return nss_connect_common(data, conn, sockindex, done);
}

unsafe extern "C" fn nss_send(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut rc: ssize_t = 0;
    let ref mut fresh27 = (*backend).data;
    *fresh27 = data;
    rc = PR_Send(
        (*backend).nss_handle,
        mem,
        len as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_ulong as PRIntervalTime,
    ) as ssize_t;
    if rc < 0 as libc::c_int as libc::c_long {
        let mut err: PRInt32 = PR_GetError();
        if err as libc::c_long == -(5998 as libc::c_long) {
            *curlcode = CURLE_AGAIN;
        } else {
            let mut err_name: *const libc::c_char = nss_error_to_name(err);
            Curl_infof(
                data,
                b"SSL write: error %d (%s)\0" as *const u8 as *const libc::c_char,
                err,
                err_name,
            );
            nss_print_error_message(data, err as PRUint32);
            *curlcode = (if is_cc_error(err) as libc::c_int != 0 {
                CURLE_SSL_CERTPROBLEM as libc::c_int
            } else {
                CURLE_SEND_ERROR as libc::c_int
            }) as CURLcode;
        }
        return -(1 as libc::c_int) as ssize_t;
    }
    return rc;
}
unsafe extern "C" fn nss_recv(
    mut data: *mut Curl_easy,
    mut sockindex: libc::c_int,
    mut buf: *mut libc::c_char,
    mut buffersize: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut conn: *mut connectdata = (*data).conn;
    let mut connssl: *mut ssl_connect_data =
        &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    let mut nread: ssize_t = 0;
    let ref mut fresh28 = (*backend).data;
    *fresh28 = data;
    nread = PR_Recv(
        (*backend).nss_handle,
        buf as *mut libc::c_void,
        buffersize as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_ulong as PRIntervalTime,
    ) as ssize_t;
    if nread < 0 as libc::c_int as libc::c_long {
        let mut err: PRInt32 = PR_GetError();
        if err as libc::c_long == -(5998 as libc::c_long) {
            *curlcode = CURLE_AGAIN;
        } else {
            let mut err_name: *const libc::c_char = nss_error_to_name(err);
            Curl_infof(
                data,
                b"SSL read: errno %d (%s)\0" as *const u8 as *const libc::c_char,
                err,
                err_name,
            );
            nss_print_error_message(data, err as PRUint32);
            *curlcode = (if is_cc_error(err) as libc::c_int != 0 {
                CURLE_SSL_CERTPROBLEM as libc::c_int
            } else {
                CURLE_RECV_ERROR as libc::c_int
            }) as CURLcode;
        }
        return -(1 as libc::c_int) as ssize_t;
    }
    return nread;
}
unsafe extern "C" fn nss_version(mut buffer: *mut libc::c_char, mut size: size_t) -> size_t {
    return curl_msnprintf(
        buffer,
        size,
        b"NSS/%s\0" as *const u8 as *const libc::c_char,
        NSS_GetVersion(),
    ) as size_t;
}
unsafe extern "C" fn Curl_nss_seed(mut data: *mut Curl_easy) -> libc::c_int {
    return (Curl_nss_force_init(data) as u64 != 0) as libc::c_int;
}
unsafe extern "C" fn nss_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut libc::c_uchar,
    mut length: size_t,
) -> CURLcode {
    Curl_nss_seed(data);
    if SECSuccess as libc::c_int
        != PK11_GenerateRandom(entropy, curlx_uztosi(length)) as libc::c_int
    {
        return CURLE_FAILED_INIT;
    }
    return CURLE_OK;
}
unsafe extern "C" fn nss_sha256sum(
    mut tmp: *const libc::c_uchar,
    mut tmplen: size_t,
    mut sha256sum: *mut libc::c_uchar,
    mut sha256len: size_t,
) -> CURLcode {
    let mut SHA256pw: *mut PK11Context = PK11_CreateDigestContext(SEC_OID_SHA256);
    let mut SHA256out: libc::c_uint = 0;
    if SHA256pw.is_null() {
        return CURLE_NOT_BUILT_IN;
    }
    PK11_DigestOp(SHA256pw, tmp, curlx_uztoui(tmplen));
    PK11_DigestFinal(SHA256pw, sha256sum, &mut SHA256out, curlx_uztoui(sha256len));
    PK11_DestroyContext(SHA256pw, 1 as libc::c_int);
    return CURLE_OK;
}
unsafe extern "C" fn nss_cert_status_request() -> bool {
    #[cfg(SSL_ENABLE_OCSP_STAPLING)]
    return 1 as libc::c_int != 0;
    #[cfg(not(SSL_ENABLE_OCSP_STAPLING))]
    return 0 as libc::c_int != 0;
}
unsafe extern "C" fn nss_false_start() -> bool {
    // #[cfg(NSSVERNUM >= 0x030f04)]
    return 1 as libc::c_int != 0;
}
unsafe extern "C" fn nss_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    let mut backend: *mut ssl_backend_data = (*connssl).backend;
    return (*backend).nss_handle as *mut libc::c_void;
}
#[no_mangle]
pub static mut Curl_ssl_nss: Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_NSS,
                    name: b"nss\0" as *const u8 as *const libc::c_char,
                };
                init
            },
            supports: ((1 as libc::c_int) << 0 as libc::c_int
                | (1 as libc::c_int) << 1 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int
                | (1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint,
            sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>() as libc::c_ulong,
            init: Some(nss_init as unsafe extern "C" fn() -> libc::c_int),
            cleanup: Some(nss_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(nss_version as unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t),
            check_cxn: Some(nss_check_cxn as unsafe extern "C" fn(*mut connectdata) -> libc::c_int),
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
                nss_random
                    as unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_uchar, size_t) -> CURLcode,
            ),
            cert_status_request: Some(nss_cert_status_request as unsafe extern "C" fn() -> bool),
            connect_blocking: Some(
                nss_connect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                    ) -> CURLcode,
            ),
            connect_nonblocking: Some(
                nss_connect_nonblocking
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        libc::c_int,
                        *mut bool,
                    ) -> CURLcode,
            ),
            getsock: Some(
                Curl_ssl_getsock
                    as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> libc::c_int,
            ),
            get_internals: Some(
                nss_get_internals
                    as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
            ),
            close_one: Some(
                nss_close
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, libc::c_int) -> (),
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
                        *const libc::c_uchar,
                        size_t,
                        *mut libc::c_uchar,
                        size_t,
                    ) -> CURLcode,
            ),
            associate_connection: None,
            disassociate_connection: None,
        };
        init
    }
};
