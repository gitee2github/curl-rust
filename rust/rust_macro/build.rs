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
 * Description: build script for Rust project, get macros from C side for conditional compilation
 ******************************************************************************/
fn main() {
    let mut rust_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    rust_path.pop();
    rust_path.pop();
    rust_path.push("lib");
    rust_path.push(".libs");
    let libcurl_path: String = String::from(rust_path.to_string_lossy());
    println!("cargo:rustc-link-lib=static=curl");
    println!("cargo:rustc-link-search=native={}", libcurl_path);
}
