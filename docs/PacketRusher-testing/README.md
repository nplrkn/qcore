# PacketRusher Testing

Thanks to the authors of [PacketRusher](https://github.com/HewlettPackard/PacketRusher)!


## Simple UE session establishment and teardown with PacketRusher + QCore
### Terminal 1 - QCore
```sh
cd ~/qcore && RUST_LOG=debug cargo run -- --mcc 208 --mnc 93 --local-ip 127.0.0.1 --ran-interface-name lo --sim-cred-file docs/PacketRusher-testing/sims.toml
```

### Terminal 2 - PacketRusher
```sh
cd $PACKETRUSHER && sudo ./packetrusher --config ~/qcore/docs/PacketRusher-testing/config.yml ue
``` 

### tcpdump if needed for debugging
```sh
sudo tcpdump -w qcore.pcap -i any sctp
``` 

## Comparative perf testing between Open5GS and QCore

### Switching between QCore and Open5GS

In these instructions we are going to run Open5GS AMF and QCore on the same NGAP port
in the default namespace.  Since AMF runs as a service, you need to stop it to switch to 
QCore.

```
# Stop Open5GS AMF to free up the NGAP port
sudo systemctl stop open5gs-amfd
# Start it again
sudo systemctl start open5gs-amfd
```

### Methodology 
#### Multi-CPU test
-  We run Open5GS and QCore on bare metal, on the same machine.
-  We use PacketRusher to generate a fixed amount of control plane load with no media load.
-  We measure the test duration and CPU consumption (perf top) during the test.

#### Single CPU test
In this case we confine the product under test to a single CPU, find the load at which it becomes  CPU bound.  This gives the overload threshold of each product.


### PacketRusher perf measurement of Open5GS
#### Open5GS setup
-  Follow the instructions at https://open5gs.org/open5gs/docs/guide/01-quickstart/ to install MongoDB and Open5GS.
-  In /etc/open5gs/nrf.yaml, set mcc to 208 and mnc to 93 
-  In /etc/open5gs/amf.yaml, as above, plus set the NGAP address to 127.0.0.1.  
-  Restart these services as per the instructions in the quickstart.
-  Add the sub to the Open5GS UDR:

```sh
# Get the open5gs-dbctl tool from the Open5GS github repo
wget https://raw.githubusercontent.com/open5gs/open5gs/refs/heads/main/misc/db/open5gs-dbctl
chmod +x open5gs-dbctl

# Add the sub that will be used by PacketRusher
./open5gs-dbctl add 208930000000120 00112233445566778899AABBCCDDEEFF 00112233445566778899AABBCCDDEEFF
``` 

#### Run PacketRusher
As above.

#### Open5GS debugging if needed
Best place to start is the AMF logs:
```sh
tail -f /var/log/open5gs/amf.log
```