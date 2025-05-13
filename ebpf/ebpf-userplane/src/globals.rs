use aya_ebpf::{bindings::BPF_F_INGRESS, helpers::r#gen::bpf_redirect};

/// GTPU_LOCAL_IPV4 - must be set by the loader to the IPv4 GTP-U address of F1-U.  
/// This is used to match uplink GTP packets and to set as the source address of downlink GTP packets.
#[no_mangle]
static GTPU_LOCAL_IPV4: [u8; 4] = [0u8; 4];

#[inline(always)]
pub unsafe fn read_local_ipv4() -> [u8; 4] {
    core::ptr::read_volatile(&GTPU_LOCAL_IPV4)
}

/// TUN_IF_INDEX - must be set by the loader to the Linux if_index of the tunnel interface.
/// The tunnel interface is used both to receive downlink packets and inject all transmitted packets.  
#[no_mangle]
static TUN_IF_INDEX: u32 = 0u32;

#[inline(always)]
pub unsafe fn redirect_to_linux_routing() -> i32 {
    let tun_if_index = core::ptr::read_volatile(&TUN_IF_INDEX);
    bpf_redirect(tun_if_index, BPF_F_INGRESS as u64) as i32
}
