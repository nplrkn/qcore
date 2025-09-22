# Packet loss debugging

## pwru
```
sudo ./pwru 'host 10.255.0.2'
```

Useful commands are
- 'port 2152' - debug lost GTP
- 'host 10.255.0.2' - debug N6 drops seen in test framework
- 'host 8.8.8.8' - debug N6 drops seen in live ping test

Look for kfree_skb_reason().

## Malformed packets from eBPF program
```
tcpdump -i tun
```

## Kernel source code
-  Code read is typically needed if `pwru` isn't self-explanatory (via the SKB drop reason or call stack). 

-  Browse source: https://elixir.bootlin.com/linux/v6.6.87/source.  Particularly https://elixir.bootlin.com/linux/v6.6.87/source/net/core/filter.c.

- `dmesg` to check if warnings / BUG_ON were hit.


## sysctls
There are sysctls that make Linux routing much more permissive.  Many of these are set in `setup-routing`.
Sometimes the sysctl needs to be set at the 'all' level in addition to the per interface level.
Other times it just needs to be set at the per interface level.

## Netfilter 
If pwru shows SKB_DROP_REASON_NETFILTER_DROP, work out which chain we are in from the call stack (prerouting? forward?).

e.g. for forward...
```
sudo nft add chain ip filter trace_chain { type filter hook forward priority -1\; }
sudo nft add rule ip filter trace_chain meta nftrace set 1
sudo nft monitor trace
``` 
(https://wiki.nftables.org/wiki-nftables/index.php/Ruleset_debug/tracing)

Then repro.  There is probably a line like this indicating that there has been no ACCEPT rule: "trace id 66159cf2 ip filter FORWARD policy drop"

## SRS DU dropping downlink packet
```
tail -f /tmp/gnb.log | grep [E]
```

- DU may be looking at NR RAN sequence numbers.
- If Linux might be dropping it, pwru 'dest host 10.255.0.2'

## UE dropping downlink packet 
- Run tcpdump in UE namespace.
- If Wireshark says that TCP checksum is 'partial', we introduced veth pair into downlink path to avoid this.  See ethtool -K
  incantation in setup-routing. 
- pwru 'dest host 10.255.0.2'

## A few reasons seen for lost packets during QCore development

-  bad IPv4 internet header length - code bug 
-  bad IP checksum - code bug
-  no socket - code bug, happens when eBPF redirect out lo rather than tun
-  loopback source address - needs sysctl to tolerate this
-  loopback dest address - needs sysctl to tolerate this
-  dropped by RP filter - needs sysctl to tolerate this
-  dropped by netfilter - missing accept rule on tun or eth0
-  transmitted but dropped by DU
   -  wrong sequence number
   -  wrong PDU length
- wrong TCP checksum cause by TCP checksum offload

# BPF issues

- https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it/
- Inserting an info!() after an is_long_enough() check and before the packet access can mess up the registers and break verification.

# L2 testing


```
# Set up bridge and veths in the default namespace
sudo ip link add veth_ue_1_a type veth peer veth_ue_1_b
sudo ip link add veth_ue_2_a type veth peer veth_ue_2_b
sudo ip link add qcore_br0 type bridge
sudo ip link set veth_ue_1_b master qcore_br0
sudo ip link set veth_ue_2_b master qcore_br0
sudo ip link set veth_ue_1_b up
sudo ip link set veth_ue_2_b up
sudo ip link set qcore_br0 up

# Create a UE 1 namespace, give it a veth, and assign IP 10.10.10.1.
sudo ip netns add ue1
sudo ip link set veth_ue_1_a netns ue1
sudo ip netns exec ue1 bash
ip addr add 10.10.10.1/24 dev veth_ue_1_a
ip link set veth_ue_1_a up

# Create a UE 2 namespace, give it a veth, and assign IP 10.10.10.2.
sudo ip netns add ue2
sudo ip link set veth_ue_2_a netns ue2
sudo ip netns exec ue2 bash
ip addr add 10.10.10.2/24 dev veth_ue_2_a
ip link set veth_ue_2_a up

# ARPPING UE 1 from UE 2 over the bridge
arping 10.10.10.1

# One way to see this in tcpdump
sudo tcpdump -i qcore_br0 -w bridge.pcap

# To put them back in the default namespace - needs to be run from the
# appropriate netns exec
ip link set veth_ue_1_a netns 1
ip link set veth_ue_2_a netns 1

```
