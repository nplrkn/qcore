# Backlog

## In progress
- Ethernet PDU sessions
  - get test framework passing
    -  offset (-5) >= skb_headlen() (43)
       [32754.734376] WARNING: CPU: 2 PID: 235294 at net/core/dev.c:3353 skb_checksum_help+0x1b5/0x210
       if (unlikely(offset >= skb_headlen(skb))) {
		DO_ONCE_LITE(skb_dump, KERN_ERR, skb, false);
		WARN_ONCE(true, "offset (%d) >= skb_headlen() (%u)\n",
			  offset, skb_headlen(skb));
		goto out;
	}
  
  offset = skb_checksum_start_offset(skb);
         = skb->csum_start - skb_headroom(skb);
         = skb->csum_start - (skb->data - skb->head)
         = -5

  If there is no headroom.
  Presumably checksum must be in the packet.
  We have increased the headroom (a lot) by shrinking the uplink packet.
  Therefore the checksum is somewhere different relative to the packet data.
  So csum_start needs to be changed by the XDP code.
  Or by the TC helper?? 


                                ---------------
                               | sk_buff       |
                                ---------------
   ,---------------------------  + head
  /          ,-----------------  + data
 /          /      ,-----------  + tail
|          |      |            , + end
|          |      |           |
v          v      v           v
 -----------------------------------------------
| headroom | data |  tailroom | skb_shared_info |
 -----------------------------------------------
                               + [page frag]
                               + [page frag]
                               + [page frag]
                               + [page frag]       ---------
                               + frag_list    --> | sk_buff |
                                                   ---------


  - test case where there are more ethernet sessions than available veth devices
  - commonize downlink to use XDP in both cases
  - try again redirecting to loopback from XDP program by installing dummy XDP programs? (https://ants-gitlab.inf.um.es/jorgegm/xdp-tutorial/-/tree/ae0ad18e1d7cba35cb5afbc8c4dfee2efa72fc38/packet03-redirecting)
  - prove unicast and broadcast between two UEs in test framework 
  -  with the XDP downlink program we can see the rewritten packet flowing (on veth_ue_1_a or veth_ue_2_a) but not being forwarded to lo 
     -  so try chaining onto TC program - safest first step?
        - (using [metadata ](https://docs.ebpf.io/linux/program-context/__sk_buff/#data_meta)) - e.g. do everything in XDP apart from the redirect?  - this avoids the memmove.
        -  first without metadata, just the slow way 
  - ensure stats give visibility into each arm of ethernet XDP/TC code
  - have the setup-ethernet script take a param which is number of veths to set up
  - "The bpf_redirect helper actually shouldn’t be used in production as it is slow" 
  - write up design notes if not clear from code
  - decide what to do about downlink buffering - issue warning for now?
  - how do we age out learnt MACs - e.g. 23.501 "The UPF reports the removal of a UE MAC address based on the detection of absence of traffic during an inactivity time. The inactivity time value is provided by the SMF to the UPF." (5.8.2.12)
  - can we use bpf_skb_change_type() "The major use case is to change incoming _skb_s to PACKET_HOST in a programmatic way instead of having to recirculate via redirect(..., BPF_F_INGRESS), for example."

## Bugs / tech debt
- "slog-async: logger dropped messages due to channel overflow" - for example, when hitting Ctrl-C at end of PacketRusher test - check out tracing-appender
-  On shutdown, delete rather than deactivate userplane sessions 
- OAI test broken - simulated UE doesn't send Configuration Update Complete

## Performance
- iperf framework
- push to 1000 UEs
- Reduce memcpy?

## Persistence
- Paging continuity
- SQN

## Usability
- Reduce number of mandatory command line arguments (e.g. derive IP address from interface, derive MNC/MCC from sims.toml)

## Function gaps
- Implement and test NAS procedure interaction table
- Registration timeout and refresh (+ update parallelization table)
- Proper handling of deregistration from UE, including sending of Deregistration accept (+ update parallelization table)
- Idle / paging
- Sessions / IP addresses should not persist forever.  Timeout; flush on TMSI register/service request without session reactivation; flush on IMSI registration? 
- Large SCTP messages - e.g. unfiltered UE Capability Information
- UE static IP
- Time out during procedures - e.g. Authentication procedure uses T3560
- UE AMBR
- Transport key for SIM creds
- SUCI
- NEA2 ciphering for NAS
- NAS uplink integrity validation for NAS
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

## Tidying + refactoring
- switch to tokio or smol
- review Arc / clone usage
- uplink information transfer in separate module for F1AP?
- tests are slow to link
- use different forwarding tables for NGAP vs F1AP 
- test scripts - move to builder pattern (new_with_base() etc)?
- struct Config should be split into information that is used on startup (which doesn't need to be cloned), and information that is used by procedures (which does need to be cloned) 

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
