# curl-rust

## 介绍

cURL 提供了curl（命令行工具）和 libcurl（C语言的API库），两者功能均是基于网络协议，对指定 URL 进行网络传输。cURL 使用C语言实现，libcurl 历史安全漏洞较多，其中内存类占比51%。本项目通过使用 Rust 重写 cURL 的高危模块，利用 Rust 语言的内存安全优势，以增加 libcurl 的安全性和可靠性。

## 项目实施方案

对 cURL 的改写，分为以下步骤进行：

- 构建 Rust 项目结构，确定重写的部分的组织方式
- 使用 c2rust 工具自动改写 C 代码
- 手动将数据结构定义和函数声明移动到公共模块中
- 构造条件编译宏传递模块
- 改写 Rust 中的宏定义
- 与 C 代码混合编译并通过测试

## 从源码编译

### 前置条件

需准备前置条件，以便 curl-rust 能正确地编译，需要的前置条件有：

- make
-  rustup
-  cargo
-  nightly 版的 rustc
-  gcc
-  openssl-libs
-  automake 等。

可以使用如下命令完成完成安装：

```
sudo yum install -y gcc openssl-libs automake make cmake
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustlang.sh
sh rustlang.sh -y
rustup install nightly
rustup default nightly
```

准备好前置条件后，可以使用我们提供的编译脚本完成编译：

1.  进入项目根目录
2.  在项目根目录下，执行`. ./cr-install.sh`，等待编译完成即可完成编译
3.  若要定制 curl-rust，修改`./configure`那一行命令，根据自己的需要选择某些选项
4.  还可以执行`make test`进行测试

