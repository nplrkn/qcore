use qcore::SimCreds;
use std::collections::HashMap;

fn main() {
    let filename = "./load_test_sims.toml";
    let contents = std::fs::read_to_string(filename).unwrap();
    let table: HashMap<String, SimCreds> = toml::from_str(&contents).unwrap();
    for (imsi, sub) in table.iter() {
        let imsi = imsi.strip_prefix("imsi-").unwrap();
        println!(
            "./open5gs-dbctl add {imsi} {} {}",
            hex::encode(sub.ki),
            hex::encode(sub.opc)
        );
    }
}
