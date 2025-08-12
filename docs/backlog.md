# Backlog

## In progress
- Live testing with multiple phones, update readme documenting interop status.
- "NG setup with GNB name" info log - trace of bitvec global gnb ID is ugly 


## Interop
- Rejection of Registration Request from Security Mode Command if slice asked for is eMBB / SST 1 with "no network slices available"
  -  causes OnePlus phone to reregister with MIoT SST 3 / SD 0.
-  Unhandled RrcReestablishmentRequest

## Bugs
- Poor download speed in F1ap mode possibly caused by out of order seq nos 
- PDU session release command should flow on SRB 2, not SRB 1  
- OAI test broken - simulated UE doesn't send Configuration Update Complete

## Performance
- iperf framework
- Release build perf profiling + tuning
- Reduce memcpy

## Persistence
- Paging continuity
- SQN

## Function gaps
- Deregistration accept
- Update / Remove a DU's served cells on Du configuration update, F1 Remove, disconnection
- Sessions / IP addresses should not persist forever.  Timeout; flush on TMSI register/service request without session reactivation; flush on IMSI registration? 
- Large SCTP messages - e.g. unfiltered UE Capability Information
- Idle / paging
- UE static IP
- Registration timeout and refresh
- PDCP Rx reordering
- Obey DL DATA DELIVERY STATUS backpressure (desired buffer size)
- PDCP retransmission for RLC Am
- Time out during procedures - e.g. Authentication procedure uses T3560
- UE AMBR
- Transport key for SIM creds
- SUCI
- NEA2 ciphering
- Processing of UE measurements - detect when UE changes cell
- Uplink integrity validation for RRC / NAS
- TODOs
- Handling of PDCP control packets
- Handling of uplink PDCP sequence number out or order / gaps
- Negative testing of rejections and protocol errors
- RRC Inactive
- >1 PDU session per UE
- >1 DU

## Error handling
- Session setup with existing PDU session ID should not leave up old session.  Seen with OnePlus phone which repeated 
  its session setup request (with no intervening delete) after not liking the response.

## Tidying + refactoring
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
