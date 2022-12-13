#!/bin/bash

set +e

cd ../
aclocal
automake

# LIBS=-ldl ./configure --without-ssl --disable-shared --without-ngtcp2
cd lib
make

cd ../rust/

# 开始检查
cargo fmt --all -- --check -v
cargo clean

# cargo clippy --all-targets --all-features --tests --benches -- -D warnings
cargo clippy --all-targets --all-features --tests --benches -- -v
cargo clean

cargo check
cargo clean

# cargo rustc -- -D warnings
# bin=$(sed -n '/[[bin]]/ {n;p}' Cargo.toml | sed 's/\"//g' | sed 's/name = //g')
# for bin_name in $bin
# do
# echo $bin_name
# cargo rustc --bin $bin_name -- -D warnings -v
# done

cargo build --release -v

# RUST_BACKTRACE=1 cargo test --all -v -- --nocapture --test-threads=1
# RUST_BACKTRACE=1 cargo test --all -- --nocapture

# cargo doc --all --no-deps

# libcurl.a
cd ../lib/.libs/
mkdir temp
mv libcurl.a temp/
cp ../../rust/target/release/librust_project.a temp/
cd temp
ar x libcurl.a
ar x librust_project.a
rm libcurl.a librust_project.a
ar r libcurl.a *.o
cp libcurl.a ../
cd ..
rm -r temp/

# libcurlu.a 开启debug选项时使用
# mkdir temp
# mv libcurlu.a temp/
# cp ../../rust/target/release/librust_project.a temp/
# cd temp
# ar x libcurlu.a
# ar x librust_project.a
# rm libcurlu.a librust_project.a
# ar r libcurlu.a *.o
# cp libcurlu.a ../
# cd ..
# rm -r temp/

cd ../../
make

# LDFLAGS="-L`pwd`/rust/target/release" LIBS="-lrust_project -ldl" ./configure --without-ssl --disable-shared

# make