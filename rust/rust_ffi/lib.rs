#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(
    c_variadic,
    extern_types,
    label_break_value,
    register_tool
)]
#![register_tool(c2rust)]

#[macro_use]
extern crate libc;
extern crate c2rust_bitfields;

pub mod src {
    pub mod ffi_alias;
    pub mod ffi_fun;
    pub mod ffi_struct;
}