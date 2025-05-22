// Returns the new SQN.
pub fn resync_sqn(auts: &[u8; 14], ak: &[u8; 6]) -> Result<[u8; 6], ()> {
    let concealed_sqn_ms = &auts[0..6];
    let _mac_s = &auts[6..];

    // "The HE/AuC retrieves SQNMS from Conc(SQNMS) by computing Conc(SQNMS) xor f5*K(RAND)."
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
    // TODO

    // "If the verification is successful the HE/AuC resets the value of the counter SQNHE to SQNMS."
    Ok(sqn_ms)
}
