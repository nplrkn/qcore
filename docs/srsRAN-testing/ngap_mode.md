# NGAP mode testing with srsRAN

[Simulated UE / srsRAN gNB](#Simulated-UE--srsRAN-gNB)
[Simulated UE / srsRAN DU / srsRAN CU](#Simulated-UE--srsRAN-DU--srsRAN-CU)

## Common setup

```sh
~/qcore/setup-routing
sudo ip netns add ue1
``` 

## Simulated UE / srsRAN gNB
### Copy across config files

```sh
cp ~/qcore/docs/srsRAN-testing/gnb-zmq.yml ~/srsRAN_Project/build/apps/gnb
cp ~/qcore/docs/srsRAN-testing/ue.conf ~/srsRAN_4G/build/srsue/src
```

### Terminal 1 - tcpdump

```sh
    cd && sudo tcpdump -w srsran_test.pcap -i any sctp or port 2152 or host 10.255.0.1
```

### Terminal 2 - QCore

```sh
cd ~/qcore
RUST_LOG=debug cargo run -- --mcc 001 --mnc 01 --local-ip 127.0.0.1  --ran-interface-name lo --sim-cred-file docs/srsRAN-testing/srs-sim.toml --ngap-mode
```

### Terminal 3 - gNB

```sh
cd ~/srsRAN_Project/build/apps/gnb && sudo ./gnb -c gnb-zmq.yml
```

### Terminal 4 - UE

```sh
cd ~/srsRAN_4G/build/srsue/src/ && sudo ./srsue ue.conf
```

### Terminal 5 - check connectivity from UE

```sh
sudo ip netns exec ue1 bash
# We are now running as root in netns ue1
ip route add default dev tun_srsue
ping 8.8.8.8
curl parrot.live
```

## Simulated UE / srsRAN DU / srsRAN CU
### Copy across config files

```sh
cp ~/qcore/docs/srsRAN-testing/cu.yml ~/srsRAN_Project/build/apps/cu
cp ~/qcore/docs/srsRAN-testing/du-zmq.yml ~/srsRAN_Project/build/apps/du
cp ~/qcore/docs/srsRAN-testing/ue.conf ~/srsRAN_4G/build/srsue/src
```

### Terminal 1 - tcpdump

```sh
cd && sudo tcpdump -w srsran_test_ngap_cu_du.pcap -i any sctp or port 2152 or host 10.255.0.1
```

### Terminal 2 - QCore

```sh
cd ~/qcore
RUST_LOG=debug cargo run -- --mcc 001 --mnc 01 --local-ip 127.0.0.3  --ran-interface-name lo --sim-cred-file docs/srsRAN-testing/srs-sim.toml --ngap-mode
```

### Terminal 3 - CU

```sh
cd ~/srsRAN_Project/build/apps/cu && sudo ./srscu -c cu.yml
```

### Terminal 4 - DU

```sh
cd ~/srsRAN_Project/build/apps/du && sudo ./srsdu -c du-zmq.yml
```

### Terminal 5 - UE

```sh
cd ~/srsRAN_4G/build/srsue/src/ && sudo ./srsue ue.conf
```

### Terminal 6 - check connectivity from UE

```sh
sudo ip netns exec ue1 bash
# We are now running as root in netns ue1
ip route add default dev tun_srsue
ping 8.8.8.8
curl parrot.live
```

