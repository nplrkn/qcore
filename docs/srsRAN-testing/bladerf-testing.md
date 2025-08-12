# Live UE + BladeRF testing

This uses https://github.com/hypermagik/srsRAN-5G/commit/9081cfc2b0 with the BladeRF .deb packages from https://github.com/pvnis/5g-config-files/tree/main/bladerf-deb-jammy (private repository) installed (`su dkbgdpkg -i *.deb`), before calling SRS `cmake ../`.  There are probably other ways to get srsRAN working with bladeRF that just use publically available packages.

To date, I have not managed to get this setup working in WSL - the USB passthrough (usbipid) seems to be too laggy for the SDR board to function properly.

The instructions assume there is a sims.toml file in $HOME.

## Common setup
### Copy across config files

```sh
cp ~/qcore/docs/srsRAN-testing/gnb-bladerf.yml ~/srsRAN-5G/build/apps/gnb
cp ~/qcore/docs/srsRAN-testing/cu.yml ~/srsRAN-5G/build/apps/cu
cp ~/qcore/docs/srsRAN-testing/du-bladerf.yml ~/srsRAN-5G/build/apps/du
```

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

