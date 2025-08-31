# Comparative load testing against Open5GS

## Install Open5GS
-  Follow the instructions at https://open5gs.org/open5gs/docs/guide/01-quickstart/ to install MongoDB and Open5GS.
-  In /etc/open5gs/nrf.yaml, set mcc to 001 and mnc to 01 
-  In /etc/open5gs/amf.yaml, set mcc and mnc as above in multiple places, plus set the NGAP address to 127.0.0.1. 
-  Confine Open5GS to a CPU of your choice - in this example, CPU 8.
   - @@@@ 
-  Restart all Open5GS services.

#### Open5GS debugging if needed
Best place to start is the AMF logs:
```sh
tail -f /var/log/open5gs/amf.log
```

## Setup
```sh
# Build QCore in release mode
cd qcore
cargo build --release

# Get Open5GS's dbctl script from github
wget https://raw.githubusercontent.com/open5gs/open5gs/refs/heads/main/misc/db/open5gs-dbctl
chmod +x open5gs-dbctl

# Generate 200 test SIMs in PLMN 001/01.
./target/release/generate-load-test-sims > load_test_sims.toml

# Create and run a script for configuring Open5GS with these SIMs.
./target/release/provision-open5gs > ./provision-open5gs
sh provision-open5gs  # takes a while

