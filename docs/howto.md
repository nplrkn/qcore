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

## Kernel code read
ip_route_input_slow() + fib_validate_source() drop packets with non specific SKB reasons.  Need to 
read the Linux source code here.

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
