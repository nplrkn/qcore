# OpenAirInterface demo

In this demo, we are going to ping a public IPv4 address from a simulated UE, running through the OAI DU, and QCore.  Below is a complete walkthrough.

Thank you to the team at the OpenAirInterface 5G RAN project group for their project!

QCore has been tested against [OpenAirInterface](https://openairinterface.org/oai-5g-ran-project/) on a fresh install of Ubuntu 22.04, running under WSL (Windows Subsystem for Linux).  The specific commit of OAI used was acb982d0bd96b01dee84aea730f01dfff73875d0.

## Install, build, test with OAI
### Install / Build
```sh
# get and build OAI - from https://gitlab.eurecom.fr/oai/openairinterface5g/-/blob/develop/doc/BUILD.md
git clone https://gitlab.eurecom.fr/oai/openairinterface5g.git
cd openairinterface5g/cmake_targets
./build_oai -I              # install OAI package dependencies into your Ubuntu distro
./build_oai --nrUE --gNB    # build the 5G UE and gNB

```

### Set up 
This assumes QCore is cloned to ~/qcore.

```sh
~/qcore/setup-routing
sudo ip netns add ue1

# make a shortcut to the OAI config file from the home dir
cd && ln -s qcore/docs/OpenAirInterface-testing/qcore-interop-gnb-du.sa.band78.106prb.rfsim.conf oai.conf
```

The first two commands need to be re-run following a reboot.

### Running the test
#### Terminal 1 - tcpdump
```sh
cd
sudo tcpdump -w oai_test.pcap -i any sctp or port 2152 or host 10.255.0.2
```

#### Terminal 2 - QCore

```sh
cd ~/qcore
RUST_LOG=debug cargo run -- --mcc 208 --mnc 99 --local-ip 127.0.0.1 --ran-interface-name lo --sim-cred-file docs/OpenAirInterface-testing/oai-sim.toml
```

#### Terminal 3 - OAI DU

```sh
cd ~/openairinterface5g/cmake_targets/ran_build/build && sudo ./nr-softmodem -O ~/oai.conf --rfsim
```

This uses the symlink oai.conf that we made earlier.

#### Terminal 4 - OAI UE

```sh
cd ~/openairinterface5g/cmake_targets/ran_build/build && sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --ssb 516 --rfsim
```
Note that the arguments to nr-uesoftmodem obey the startup log from nr-softmodem in terminal 3 "Command line parameters for OAI UE...".  

After not too long, the UE will establish a PDU session, which you can spot from the QCore INFO log in terminal 2.

#### Terminal 5 - check connectivity from UE

```sh
sudo ip link set oaitun_ue1 netns ue1  # move OAI's UE tunnel interface into the ue1 network namespace
sudo ip netns exec ue1 bash            # get an interactive shell session in the ue1 network namespace

# We are now 'inside' the simulated UE from a networking point of view, running as root

ip link set lo up                      # enable loopback interface
ip link set oaitun_ue1 up              # enable tunnel interface
ip addr add 10.255.0.2 dev oaitun_ue1  # configure the UE's IP address
ip route add default dev oaitun_ue1    # give it a route out
ping 8.8.8.8                           # ping outside world
curl parrot.live                       # test TCP + HTTP access to outside world
```

If you get a ping / curl response, congratulations.  On the one hand, this must be one of the most convoluted ways imaginable to access the internet from your machine :-), but on the other, you have just proven out the mainline end-to-end 5G service flow!

### Looking at the packet capture

Stop the test by hitting Ctrl-C in all of the terminals.

View the pcap in Wireshark.  (If using WSL, you can run `explorer.exe .` in terminal 1 to get at the PCAP file from Windows.)  The start of it should look something like `oai_test.pcap`, in the same folder as these instructions.

## Remarks on the configuration

Overall, the OAI configuration is chosen to be as close as possible to its existing GNB DU rfsim config file in OAI `ci-scripts/conf_files/gnb-du.sa.band78.106prb.rfsim.conf`, the only differences being that F1 addresses are set to 127.* addresses, and the GTP-U port is set to 2152 rather than 2513.

The SIM creds in `oai-sim.toml` match the default OAI test SIM in OAI `ci-scripts/conf_files/nrue.uicc.conf`.

The QCore MCC and MNC command line arguments are set to match the MCC/MNC in the above two OAI config files.


