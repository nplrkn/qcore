# Comparative load testing against Open5GS

## Install Open5GS and confine it to a single CPU
-  Follow the instructions at https://open5gs.org/open5gs/docs/guide/01-quickstart/ to install MongoDB and Open5GS.
-  In /etc/open5gs/nrf.yaml, set mcc to 001 and mnc to 01 
-  In /etc/open5gs/amf.yaml, set mcc and mnc as above (multiple places), and set the NGAP address to 127.0.0.1. 
-  Confine Open5GS to a CPU of your choice
   - sudo vi system/multi-user.target.wants/open5gs-*.service
     -  for each udr,pcf,scp,amf,udm,smf,ausf,bsf,upf,
     -  add AllowedCPUs=<x> to the [Service] section, where x is the CPU to confine Open5GS to.
   - same for system/multi-user.target.wants/mongod.service 
   - sudo systemctl daemon-reload
   - sudo systemctl restart all of the above services
   - in top, enter f then use the cursor keys select P, <space>, <esc>

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

# Generate 200 test SIMs in PLMN 00101.
./target/release/generate-load-test-sims > load_test_sims.toml

# Create and run a script for configuring Open5GS with these SIMs.
./target/release/provision-open5gs > provision-open5gs
sh provision-open5gs  # takes a while

