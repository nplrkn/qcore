# Comparative load testing against Open5GS

## Results

The QCore control plane is >30x faster than Open5GS and has ~50x smaller memory footprint.

This is based on measurements from the QCore load test, where
-  Open5GS's time to execute the test message sequence was ~34ms, using ~85% CPU, using 740MB resident memory
-  QCore's time to execute the test message sequence was ~1ms using around ~70% CPU, using 15MB resident memory
...when confined to a single logical CPU (hyperhread).

The message rates observed in the test were 
-  Open5GS: ~800 messages/sec
-  QCore: ~30k message/sec.

The main time in Open5GS was spent in open5gs-scpd (27%), mongod (15%), open5gs-amfd (13%), 
open5gs-udmd (8%), and open5gs-smfd (8%).  The main memory usage was in mongod (185MB) and open5gs-smfd (148MB).

This is based on an out-of-the-box Ubuntu install of Open5GS compared to a standard release build of QCore.  Open5GS was not tuned 
in any way.

## Methodology

-  The test message sequence is a 27-message sequence of: registration, configuration update, session establishment, context release, service request, session release, deregistration.  
   - A message means an N2 NGAP message in either direction.  In many cases it contains a transported N1 NAS message. 

-  The load test tool acts as a single gNB and loops repeatedly through 200 UEs running through the test message sequence for each UE serially.  To get a quick sense of it, 

-  The results above were measured on a single hyperthread of a 12th Gen Intel(R) Core(TM) i7-1260P.  The method used for confining the cores to a single hyperthread is given below.

-  The measurements quoted above are averaged over several runs.

-  The CPU measurements and memory use are approximate and taken from `top` (%CPU and RES).  In the case of Open5GS, mongod usage was
   included in the quoted number but systemd-journal and rsyslogd were not.

## Instructions

### Install Open5GS and confine it to a single CPU
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
### Setup SIMs
```sh
# Build QCore in release mode
cd qcore
cargo build --release

# Get Open5GS's dbctl script from github
wget https://raw.githubusercontent.com/open5gs/open5gs/refs/heads/main/misc/db/open5gs-dbctl
chmod +x open5gs-dbctl

# Generate 200 test SIMs in PLMN 00101.
./target/release/generate-load-test-sims > load_test_sims.toml

# Create a script for configuring Open5GS with these SIMs.
./target/release/provision-open5gs > provision-open5gs

# Run it - this takes a few 10s of seconds
sh provision-open5gs
```

### Run top
Run `top`, enter `f` then use the cursor keys select `P` to show the CPU that the process are running on.

### Run load test against Open5GS and qcore 
```sh
# Run the load test against Open5GS
./target/release/load-test

# Stop Open5GS
sudo systemctl stop open5gs-amfd

# (Separate terminal) Run QCore
cd qcore
taskset --cpu-list 7 sudo ./target/release/qcore --mcc 001 --mnc 01 --local-ip 127.0.0.1 --ran-interface-name lo --sim-cred-file load_test_sims.toml > qcore.log 2>&1

# Run the load test against QCore
./target/release/load-test
```

### Open5GS debugging if needed
Best place to start is the AMF logs:
```sh
sudo tail -f /var/log/open5gs/amf.log
```

