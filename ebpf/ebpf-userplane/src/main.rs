#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]

mod headers;
mod utils;
#[macro_use]
mod counters;
mod downlink_tc_program;
mod globals;
mod uplink_tc_program;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
