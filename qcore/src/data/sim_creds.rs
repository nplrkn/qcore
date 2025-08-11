use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct SimCreds {
    #[serde(with = "hex")]
    pub ki: [u8; 16],
    #[serde(with = "hex")]
    pub opc: [u8; 16],
}
