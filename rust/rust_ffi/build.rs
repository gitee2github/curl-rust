use rust_macro::src::get_macros::get_all_cfg;
fn main() {
    let mut rust_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    rust_path.pop();
    rust_path.pop();
    rust_path.push("lib");
    rust_path.push(".libs");
    let libcurl_path: String = String::from(rust_path.to_string_lossy());
    println!("cargo:rustc-link-lib=static=curl");
    println!("cargo:rustc-link-search=native={}", libcurl_path);
    get_all_cfg();
}
