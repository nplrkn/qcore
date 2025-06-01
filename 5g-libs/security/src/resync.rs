use milenage::Milenage;

// See TS33.102, 6.3.5
// Returns the new SQN.
pub fn resync_sqn(
    auts: &[u8; 14],
    k: &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
) -> Option<[u8; 6]> {
    // Run f5*K(RAND)
    let mut m = Milenage::new_with_opc(*k, *opc);
    let ak = m.f5star(rand);

    // "The HE/AuC retrieves SQNMS from Conc(SQNMS) by computing Conc(SQNMS) xor f5*K(RAND)."
    let concealed_sqn_ms = &auts[0..6];
    let sqn_ms = [
        concealed_sqn_ms[0] ^ ak[0],
        concealed_sqn_ms[1] ^ ak[1],
        concealed_sqn_ms[2] ^ ak[2],
        concealed_sqn_ms[3] ^ ak[3],
        concealed_sqn_ms[4] ^ ak[4],
        concealed_sqn_ms[5] ^ ak[5],
    ];

    // "The HE/AuC checks if SQNHE is in the correct range, i.e. if the next sequence number generated SQNHE
    // using would be accepted by the USIM."  We assume it isn't.

    // "The HE/AuC verifies AUTS (cf. subsection 6.3.3).""
    let expected_mac_s = m.f1star(rand, &sqn_ms, &[0, 0]);
    //println!("Expected {:?}", expected_mac_s);
    if expected_mac_s == auts[6..] {
        Some(sqn_ms)
    } else {
        None
    }
}

#[cfg(test)]
use hex_literal::hex;

#[test]
fn test_resync_sqn() {
    // Sanity check milenage f5star using test set 1 from TS35.208.
    let k = hex!("465b5ce8b199b49faa5f0a2ee238a6bc");
    let rand = hex!("23553cbe9637a89d218ae64dae47bf35");
    let opc = hex!("cd63cb71954a9f4e48a5994e37a02baf");
    let mut m = Milenage::new_with_opc(k, opc);
    let ak = m.f5star(&rand);
    assert_eq!(ak, hex!("451e8beca43b"));

    // Regression test a couple of runs of the AUTS algorithm.
    let k = hex!("5122250214c33e723a5dd523fc145fc0");
    let opc = hex!("981d464c7c52eb6e5036234984ad0bcf");

    let rand = hex!("7e2e5787b935df2f691b9a126a980fe7");
    let auts = hex!("b9aeb8d6e769e319d499597695c6");
    let sqn_ms = resync_sqn(&auts, &k, &opc, &rand).unwrap();
    assert_eq!(sqn_ms, hex!("0000000027E0"));

    let rand = hex!("7e2e5787b935df2f691b9a126a980fe7");
    let auts = hex!("b9aeb8d6e769e319d499597695c6");
    let sqn_ms = resync_sqn(&auts, &k, &opc, &rand).unwrap();
    assert_eq!(sqn_ms, hex!("0000000027E0"));
}

#[test]
fn test_resync_sqn_bad_macs() {
    let k = hex!("5122250214c33e723a5dd523fc145fc0");
    let opc = hex!("981d464c7c52eb6e5036234984ad0bcf");
    let rand = hex!("7e2e5787b935df2f691b9a126a980fe7");
    let auts = hex!("0000000000000000000000000000");
    let sqn_ms = resync_sqn(&auts, &k, &opc, &rand);
    assert!(sqn_ms.is_none());
}
