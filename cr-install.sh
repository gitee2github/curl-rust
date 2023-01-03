#!/bin/bash

set +e

make clean
aclocal
automake

# 可根据需要更改选项
LIBS=-ldl ./configure --with-openssl --disable-shared --without-ngtcp2
cd lib
make

cd ../rust/

cargo clean
RUSTFLAGS="-Clink-arg=-Wl,--allow-multiple-definition" cargo build --release -v

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