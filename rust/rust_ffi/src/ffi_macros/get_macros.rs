extern "C" {
    fn get_CURL_DISABLE_PROXY() -> libc::c_int;
}
pub fn get_all_cfg() {
    get_CURL_DISABLE_PROXY_add_cfg();
}

fn get_CURL_DISABLE_PROXY_add_cfg() {
    if unsafe { get_CURL_DISABLE_PROXY() } == 1 as libc::c_int {
        println!("cargo:rustc-cfg=CURL_DISABLE_PROXY");
    }
}
