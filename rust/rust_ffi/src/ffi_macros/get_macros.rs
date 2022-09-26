extern "C" {
    // http2


    // http_proxy
    fn get_CURL_DISABLE_PROXY() -> i32;
    // http_ntlm

    // http_negotiate

    // http_digest

    // http_chunks

    // http_aws_sigv4

    // http

    // ftplistparser

    // ftp

    // bearssl

    // gskit

    // gtls

    // keylog

    // mbedtls

    // mbedtls_threadlock

    // nss

    // mesalink

    // openssl

    // rustls

    // vtls

    // wolfssl
}
pub fn get_all_cfg() {
    // http2


    // http_proxy
    get_CURL_DISABLE_PROXY_add_cfg();
    // http_ntlm

    // http_negotiate

    // http_digest

    // http_chunks

    // http_aws_sigv4

    // http

    // ftplistparser

    // ftp

    // bearssl

    // gskit

    // gtls

    // keylog

    // mbedtls

    // mbedtls_threadlock

    // nss

    // mesalink

    // openssl

    // rustls

    // vtls

    // wolfssl
}

// http2


// http_proxy
fn get_CURL_DISABLE_PROXY_add_cfg() {
    if unsafe { get_CURL_DISABLE_PROXY() } == 1 {
        println!("cargo:rustc-cfg=CURL_DISABLE_PROXY");
    }
}
// http_ntlm

// http_negotiate

// http_digest

// http_chunks

// http_aws_sigv4

// http

// ftplistparser

// ftp

// bearssl

// gskit

// gtls

// keylog

// mbedtls

// mbedtls_threadlock

// nss

// mesalink

// openssl

// rustls

// vtls

// wolfssl