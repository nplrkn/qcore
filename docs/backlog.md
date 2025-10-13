# Backlog

## In progress
-  Interop testing bugs
   -  Received an ngReset (when we Ctrl-C the gNB) - unhandled
   -  Log DHCP server IP
   -  6 debug logs with "unknown TMSI" when we look in both the outer and inner message
   -  If a phone disconnects and reconnects (toggle mobile radio power), we get errors 
      -  "Lease already existed for" and "Carry on after netlink error..."
         -  It is setting up a new session and DHCP is giving it the same address.
      -  We did not clean up the session on UE Deregistration
   -  UE is still using its TMSI after deregistration to reregister
   -  "WARN Identity peek not implemented for message type on Service Request"
   -  "WARN Unsupported PduSessionType 011" log - actuallly this is IpV4V6
      -  meanwhile IPv6 case should say "UE asked for IPv6 - please change it to IPv4"

-  Clustering
   -  Get two_qcores test working, review new warnings + todos
   -  Test connection with catchup, disconnection and reconnection, session deletion, deregistration

## Persistence
- Paging continuity
- SQN

## Bugs / tech debt
- "slog-async: logger dropped messages due to channel overflow" - for example, when hitting Ctrl-C at end of PacketRusher test - check out tracing-appender
- OAI test broken - simulated UE doesn't send Configuration Update Complete

## Performance
- Do not put XDP programs in SKB mode.  (But this causes 15s interruption to NIC - avoid having QCore attach/detach and do separately?)
- iperf framework
- push to 1000 UEs
- Reduce memcpy?

## Usability

## Function gaps
- Implement and test NAS procedure interaction table
- Registration timeout and refresh (+ update parallelization table)
- DHCP gaps
  -  retries
  -  PDU session should be terminated by network on lease expiry, or lease renewal reject, or change of address on lease renewal (TS29.561)
  -  case where the subnet is not a /24 and the DHCP could allocate addresses with the same low byte
  -  pass through of DNS server name (+ MTU?) from DHCP in NAS extended PCOs 
- Ethernet paging
- Sessions / IP addresses should not persist forever.  Timeout; flush on TMSI register/service request without session reactivation; flush on IMSI registration? 
- Large SCTP messages - e.g. unfiltered UE Capability Information
- UE static IP
- Time out during procedures - e.g. Authentication procedure uses T3560
- UE AMBR
- NAS uplink integrity validation
- Transport key for SIM creds
- SUCI
- NEA2 ciphering for NAS
- TODOs
- Negative testing of rejections and protocol errors
- >1 PDU session per UE
- >1 DU

# CU specific function gaps / bugs
  - Paging
  - Poor download speed in F1ap mode possibly caused by out of order seq nos 
  - PDU session release command should flow on SRB 2, not SRB 1  
  - Unhandled RrcReestablishmentRequest
  - RRC uplink integrity validation
  - RRC ciphering
  - PDCP Rx reordering
  - Obey DL DATA DELIVERY STATUS backpressure (desired buffer size)
  - PDCP retransmission for RLC Am
  - Processing of UE measurements - detect when UE changes cell
  - Handling of PDCP control packets
  - Handling of uplink PDCP sequence number out or order / gaps
  - RRC Inactive
  - Update / Remove a DU's served cells on Du configuration update, F1 Remove, disconnection

## Error handling
- Session setup with existing PDU session ID should not leave up old session.  Seen with OnePlus phone which repeated 
  its session setup request (with no intervening delete) after not liking the response.

## Code cleanliness + refactoring
-  Is this a better design model for test UEs?: https://docs.rs/rtnetlink/latest/rtnetlink/struct.RouteMessageBuilder.html
- switch to tokio or smol
- commonize downlink xdp and tc, or reimplement downlink tc logic in a new xdp program
- review Arc / clone usage
- struct Config should be split into information that is used on startup (which doesn't need to be visible to procedures), and information that is used by procedures (which does need to be cloned) 
- uplink information transfer in separate module for F1AP?
- tests are slow to link
- use different forwarding tables for NGAP vs F1AP 

## Regression tests
- should check there are no further messages when a mock is dropped
- userplane testing of 18 bit PDCP sequence number
- using real AUTS calculation (to catch SQN handling changes).
- downlink packet checking of fields e.g. GTP payload length
- dl delivery status packet with / without payload
- tcp out through NAT masquerade
- stats (add new QCore pub method)

## XXAP + autogen
- retire use of async_trait?
- simplify Stack / transport provider?
- todo()s
