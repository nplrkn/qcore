use aes::Aes128;
use cmac::{Cmac, Mac};

// TS33.401, B.2.3
pub fn calculate_nia2_mac(
    integrity_key: &[u8; 16],
    count: [u8; 4],
    bearer_identity_5bit: u8,
    direction_1bit: u8,
    message: &[u8],
) -> [u8; 4] {
    /*
    The input to CMAC mode is a bit string M of length Mlen (see [17, clause 5.5]). M is constructed as follows:
    M0 .. M31 = COUNT[0] .. COUNT[31]
    M32 .. M36 = BEARER[0] .. BEARER[4]
    M37 = DIRECTION
    M38 .. M63 = 026  (i.e. 26 zero bits)
    M64 .. MBLENGTH+63 = MESSAGE[0]  .. MESSAGE[BLENGTH-1]
    and so Mlen = BLENGTH + 64.

    AES in CMAC mode is used with these inputs to produce a Message Authentication Code T (MACT) of length Tlen = 32.
    T is used directly as the 128-EIA2 output MACT[0]  .. MACT[31], with MACT[0] being the most significant bit of T.
    */
    let mut mac = Cmac::<Aes128>::new_from_slice(integrity_key).unwrap();
    // println!(
    //     "input start {:x?}{:x?}{:x?}",
    //     count,
    //     [bearer_identity_5bit << 3 | direction_1bit << 2],
    //     [0u8; 3]
    // );
    mac.update(&count);
    mac.update(&[(bearer_identity_5bit << 3) | (direction_1bit << 2)]);
    mac.update(&[0u8; 3]);
    mac.update(message);
    let output = mac.finalize().into_bytes();
    //println!("output {:x?}", output);
    output.as_slice()[0..4].try_into().unwrap()
}

// unsafe {
//     // TODO there is a possibly more efficient way to do this by reusing the context
//     // See aes_128_cbc_cmac.c in openairinterface5g.c
//     let ctx = openssl_sys::CMAC_CTX_new();
//     CMAC_Init(
//         ctx,
//         integrity_key.as_ptr() as *const c_void,
//         integrity_key.len(),
//         EVP_aes_128_cbc(),
//         ptr::null_mut(),
//     );
//     CMAC_Update(ctx, first_part.as_ptr() as *const c_void, 8);
//     CMAC_Update(ctx, message.as_ptr() as *const c_void, message.len());
//     CMAC_Final(ctx, result.as_mut_ptr() as *mut u8, &mut len as *mut size_t);
// }
// println!("output {:x?}", result);

#[cfg(test)]
use hex_literal::hex;

#[test]
fn test_nia2_mac_test_set_2() {
    let count = hex!("398a59b4");
    //let bearer = 0x1a;
    let bearer = 0b11010;
    let direction = 0b1;
    // so bearer, direction is 0b11010100
    let ik = hex!("d3 c5 d5 92 32 7f b1 1c 40 35 c6 68 0a f8 c6 d1");
    let message = hex!("48 45 83 d5 af e0 82 ae");
    let expected_cmac = hex!("b93787e6");
    let cmac = calculate_nia2_mac(&ik, count, bearer, direction, &message);
    assert_eq!(cmac, expected_cmac);
}
