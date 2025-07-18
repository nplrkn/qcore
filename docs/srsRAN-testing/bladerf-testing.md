# Live UE + BladeRF testing

This uses https://github.com/hypermagik/srsRAN-5G/commit/9081cfc2b0.

It also requires the BladeRF .deb packages from https://github.com/pvnis/5g-config-files/tree/main/bladerf-deb-jammy (private repository) to be installed (`su dkbgdpkg -i *.deb`), before calling `cmake ../`.

It assumes a sims.toml file in $HOME.

## Common setup
### Copy across config files

```sh
cp ~/qcore/docs/srsRAN-testing/gnb-bladerf.yml ~/srsRAN-5G/build/apps/gnb
cp ~/qcore/docs/srsRAN-testing/cu.yml ~/srsRAN-5G/build/apps/cu
cp ~/qcore/docs/srsRAN-testing/du-bladerf.yml ~/srsRAN-5G/build/apps/du
```

### WSL - attach USB device 
In a Windows Cmd prompt
```
usbipd list
usbipd attach --wsl --busid 3-1
```
where the busid is set to match that of the bladeRF 2.0 in the device list.

### Check device present
`lsusb` to check the device has attached correctly - should output a line for the bladeRF device.

## NGAP mode / single gNB

### Terminal 1 - tcpdump

```sh
cd && sudo tcpdump -w srsran_test.pcap -i any sctp or port 2152 or host 10.255.0.2
```

### Terminal 2 - QCore

The setup-routing command assumes the external interface is called enp113s0.
The QCore invocation assumes the MCC/MNC of the SIMs are 001/06.  The SRS config files also use this value.

```sh
cd ~/qcore
./setup-routing enp113s0 # one off after reboot
RUST_LOG=debug cargo run -- --mcc 001 --mnc 06 --local-ip 127.0.0.1 --ran-interface-name lo --sim-cred-file ~/sims.toml --ngap-mode
```

### Terminal 3 - gNB

```sh
cd ~/srsRAN-5G/build/apps/gnb && sudo ./gnb -c gnb-bladerf.yml
```

Type `t ue`on the console to check radio strength.

## NGAP mode / SRS CU / SRS DU

### Terminal 1 - tcpdump

```sh
cd && sudo tcpdump -w srsran_test.pcap -i any sctp or port 2152 or host 10.255.0.2
```

### Terminal 2 - QCore

```sh
cd ~/qcore
RUST_LOG=debug cargo run -- --mcc 001 --mnc 06 --local-ip 127.0.0.3 --ran-interface-name lo --sim-cred-file ~/sims.toml --ngap-mode
```

### Terminal 3 - CU

```sh
cd ~/srsRAN-5G/build/apps/cu && sudo ./srscu -c cu.yml
```

### Terminal 4 - DU

```sh
cd ~/srsRAN-5G/build/apps/du && sudo ./srsdu -c du-bladerf.yml
```

## F1AP mode / SRS DU

### Terminal 1 - tcpdump

```sh
cd && sudo tcpdump -w srsran_test.pcap -i any sctp or port 2152 or host 10.255.0.2
```

### Terminal 2 - QCore

```sh
cd ~/qcore
RUST_LOG=debug cargo run -- --mcc 001 --mnc 06 --local-ip 127.0.0.1 --ran-interface-name lo --sim-cred-file ~/sims.toml
```

### Terminal 3 - DU

```sh
cd ~/srsRAN-5G/build/apps/du && sudo ./srsdu -c du-bladerf.yml
```
