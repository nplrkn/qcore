# Clustering
## Implementation plan
-  Simultaneous operation of two nodes on same network without allocating clashing IP addresseses

-  SUPI registration on first node followed by TMSI reregistration on second node
-  Activity on second node takes over PDU session IP from first node 
-  Failure of first node causes UE to be pageable from second node
   -  e.g. ping to UE IP address is 'uninterrupted'
-  Database instance is fate-sharing with QCore.
-  Use of probe / witness to avoid split brain
-  Aging out + refresh of UE contexts in DB
-  Static MAC addresses for UEs and/or UE driven DHCP

Later
-  Paging of UE following simultaneous reboot of both nodes.
-  SQN replication
-  database replication encryption
-  database storage encryption
-  three+ node cluster
-  Ethernet
-  F1

## Prototyping notes
### PROXY ARP method for putting UE on the external LAN
This is the initial method we will use.  It doesn't create any MAC addresses.

```
 sudo ip link add veth0 type veth peer veth1
 sudo ip link set veth0 up
 
 sudo sysctl -w net.ipv4.ip_forward=1
 sudo sysctl -w net.ipv4.conf.enp113s0.proxy_arp=1

 # on machine where the external link is 192.168.1.14/24
 sudo ip route add 192.168.1.100/32 dev veth0
 
 # to simulate a UE that can talk respond to pings / talk to the world - in netns 1
 sudo ip netns add ns1
 sudo ip link set veth1 netns ns1
 sudo ip netns exec ns1 bash
 ip addr add 192.168.1.100/24 dev veth1
 ip link set veth1 up
 ip route add default dev veth1
```

### Bridge method for putting UEs on the external LAN

This is a proabbly viable alternative method.  It involves a new MAC address for each UE.  
In the absence of VLANs, it involves moving eth0 onto a bridge - which seems fragile because it temporarily disconnects the host.

-  create bridge
-  bring it up
-  move eth0 onto it
-  give the bridge an address
-  add a default route via the bridge
-  create veth0/veth1 and master veth0 on the bridge
-  put veth1 in a namespace
-  now it can get an address via DHCP

### IPVLAN/MACVLAN method for putting UEs on the external LAN
This option not chosen because of the first bullet below.

-  Host processes cannot send/receive packets over MACVLAN / IPVLAN links.  Only remote links or other links can.
-  Addresses appear immediately on the network if the MACVLAN/IPVLAN link is in the same namespace as the external link.  But if they are in a separate namespace, they only appear on the network if the link is up.

MACVLAN1:
   sudo ip link add macvlan1 link enp113s0 type macvlan mode bridge
   sudo ip link set macvlan1 up
   sudo dhclient -4 macvlan1

IPVLAN:
   sudo ip link add name ipvlan0 link enp113s0 type ipvlan mode l2
   sudo ip addr add 192.168.1.20/24 dev ipvlan0
   sudo ip link set ipvlan0 up

### ARP announcements
Not sent automatically.  
-  Maybe an /etc/network/if-up.d script?  (see https://askubuntu.com/a/23005).  But ARP announce here is superfluous on initial bring-up.
-  To quickly move addresses, need to send arp announcement.  (Because of ARP caching.)

arping -PU 192.168.1.10
arping -A 192.168.1.10

### DHCP clients
-  Built in network manager DHCP.
-  DHCLIENT: `sudo dhclient macvlan1 macvlan2` runs DHCP client for specific intefaces
-  DHCPCD: `sudo dhcpcd` runs dhcpcd on all interfaces as you can see from ps -eaf afterwards
-  Neither of them seem to react when you set the interface down or up.

...but QCore needs to be fully in control of DHCP so it can sequence it with session creation / deletion / failover.
So we need a programmatic DHCP client that doesn't interfere with whatever the Linux host is doing.

Linux also has a DHCP relay which is often used in conjunction with Proxy ARP.

