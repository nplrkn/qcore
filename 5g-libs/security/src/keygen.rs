use hmac::{Hmac, Mac};
use milenage::Milenage;
use rand_core::RngCore;
use sha2::Sha256;

use crate::NAS_ABBA;

pub struct Challenge {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub xres_star: [u8; 16],
    pub kseaf: [u8; 32],
}
type HmacSha256 = Hmac<Sha256>;

pub fn generate_challenge(
    k: &[u8; 16],
    opc: &[u8; 16],
    serving_network_name: &[u8],
    sqn: &mut [u8; 6],
) -> Challenge {
    // TS33.501, section 6.1.3.2.0
    // Generate an AV with AMF set to 1 as defined in 33.102.
    // Generating a fresh sequence number SQN and an unpredictable challenge RAND

    // TODO: Resynchronization
    // TODO: Increment SQN.

    // RAND
    let mut rand = [0u8; 16];
    rand::rng().fill_bytes(&mut rand);

    // Serving network name length as a two byte KDF input parameter.
    let serving_network_name_len_for_kdf = (serving_network_name.len() as u16).to_be_bytes();

    // MAC, XRES, CK, IK, AK
    let mut m = Milenage::new_with_opc(*k, *opc);
    let mac = m.f1(&rand, sqn, &AMF);
    let (xres, ck, ik, ak) = m.f2345(&rand);

    // AMF (authentication and key management field)
    const AMF: [u8; 2] = [0x80, 0x00];

    // AUTN = SQN ^ AK || AMF || MAC
    let mut autn = [0u8; 16];
    autn[0] = sqn[0] ^ ak[0];
    autn[1] = sqn[1] ^ ak[1];
    autn[2] = sqn[2] ^ ak[2];
    autn[3] = sqn[3] ^ ak[3];
    autn[4] = sqn[4] ^ ak[4];
    autn[5] = sqn[5] ^ ak[5];

    autn[6..8].copy_from_slice(&AMF);
    autn[8..16].copy_from_slice(&mac);

    // Derive KAUSF (as per Annex A.2) and calculate XRES* (as per Annex A.4).

    // KAUSF* - TS33.501, Annex A.2, using key definition function from TS33.220, B.2.0.
    let mut kausf = HmacSha256::new_from_slice(&[ck, ik].concat()).expect("Can't fail");
    kausf.update(&[0x6A]); // FC
    kausf.update(serving_network_name); // P0 = serving network name
    kausf.update(&serving_network_name_len_for_kdf); // L0
    kausf.update(&autn[0..6]); // P1 = SQN ^ AK
    kausf.update(&[0x00, 0x06]); // L1
    let kausf: [u8; 32] = kausf.finalize().into_bytes().into();

    // KSEAF - TS33.501, Annex A.6, using key definition function from TS33.220, B.2.0.
    let mut kseaf = HmacSha256::new_from_slice(&kausf).expect("Can't fail");
    kseaf.update(&[0x6C]);
    kseaf.update(serving_network_name); // P0 = serving network name
    kseaf.update(&serving_network_name_len_for_kdf); // L0
    let kseaf: [u8; 32] = kseaf.finalize().into_bytes().into();

    // XRES* - TS33.501, Annex A.4, using key definition function from TS33.220, B.2.0.
    let mut xres_star = HmacSha256::new_from_slice(&[ck, ik].concat()).expect("Can't fail");
    xres_star.update(&[0x6B]); // FC
    xres_star.update(serving_network_name); // P0 = serving network name
    xres_star.update(&serving_network_name_len_for_kdf); // L0
    xres_star.update(&rand); // P1 = RAND
    xres_star.update(&[0x00, 0x10]); // L1
    xres_star.update(&xres); // P2 = XRES
    xres_star.update(&[0x00, 0x08]); // L2
    let xres_star: [u8; 16] = xres_star.finalize().into_bytes()[16..]
        .try_into()
        .expect("Can't fail");

    Challenge {
        rand,
        autn,
        xres_star,
        kseaf,
    }
}

pub fn derive_kamf(kseaf: &[u8; 32], imsi: &[u8]) -> [u8; 32] {
    // KAMF* - TS33.501, Annex A.7.0, using key definition function from TS33.220, B.2.0.
    let mut kamf = HmacSha256::new_from_slice(kseaf).expect("Can't fail");
    kamf.update(&[0x6D]); // FC
    kamf.update(imsi); // P0 = IMSI
    kamf.update(&(imsi.len() as u16).to_be_bytes()); // L0 = length of IMSI
    kamf.update(&NAS_ABBA); // P1 = ABBA
    kamf.update(&[0x00, 0x02]); // L1 = length of ABBA 
    kamf.finalize().into_bytes().into()
}

pub fn derive_kgnb(kamf: &[u8; 32], uplink_nas_count: u32) -> [u8; 32] {
    // TS33.501, A.9
    let mut kgnb = HmacSha256::new_from_slice(kamf).expect("Can't fail");
    kgnb.update(&[0x6E]); // FC
    kgnb.update(&uplink_nas_count.to_be_bytes()); // P0 = uplink NAS count
    kgnb.update(&[0x00, 0x04]); // L0 = length of uplink NAS COUNT
    kgnb.update(&[0x01]); // P1 = Access type distinguisher = 3GPP = 0x01 (table A.9-1)
    kgnb.update(&[0x00, 0x01]); // L1 = length of Access type distiguisher
    kgnb.finalize().into_bytes().into()
}

// See TS33.501, A.8
pub fn derive_krrcint(kgnb: &[u8; 32]) -> [u8; 16] {
    derive_algorithm_key(kgnb, 0x04, 0x02)
}

pub fn derive_knasint(kamf: &[u8; 32]) -> [u8; 16] {
    derive_algorithm_key(kamf, 0x02, 0x02)
}

fn derive_algorithm_key(
    input_key: &[u8; 32],
    algorithm_type_distinguisher: u8,
    algorithm_identity: u8,
) -> [u8; 16] {
    let mut k = HmacSha256::new_from_slice(input_key).expect("Can't fail");
    k.update(&[0x69]); // FC
    k.update(&[algorithm_type_distinguisher]); // P0 = algorithm type distinguisher = 0x04 as above
    k.update(&[0x00, 0x01]); // L0 = length of algorithm type distinguisher = 0x00 0x01
    k.update(&[algorithm_identity]); // P1 = algorithm identity
    k.update(&[0x00, 0x01]); // L1 = length of algorithm identity

    // TS33.220, B.2.0: "For an algorithm key of length n bits, where n is less or equal to 256, the n least significant bits
    // of the 256 bits of the KDF output shall be used as the algorithm key."
    k.finalize().into_bytes()[16..32]
        .try_into()
        .expect("Can't fail")
}
