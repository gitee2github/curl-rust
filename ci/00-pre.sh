#!/bin/bash
sudo yum clean all
sudo yum install -y gcc openssl-libs automake make cmake

# nghttp2
git clone https://github.com/tatsuhiro-t/nghttp2.git
cd nghttp2 && autoreconf -i && automake && autoconf
./configure && make && sudo make install

#git加速并安装rust工具链
git config --global url."https://github.91chi.fun/https://github.com/".insteadOf "https://github.com/"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustlang.sh
sh rustlang.sh -y

source ~/.bashrc

rustup install nightly
rustup default nightly

source ~/.bashrc

