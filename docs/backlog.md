# Backlog

## In progress
- Live testing with multiple phones, update readme documenting interop status.

## Interop
- OnePlus: Rejection of Registration Request from Security Mode Command if slice asked for is eMBB / SST 1 with "no network slices available" -  causes OnePlus phone to reregister with MIoT SST 3 / SD 0.
- Unhandled RrcReestablishmentRequest

## Bugs
- Release cause propagation from RAN release request - tests should validate
- Poor download speed in F1ap mode possibly caused by out of order seq nos 
- PDU session release command should flow on SRB 2, not SRB 1  
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
- Proper handling of deregistration from UE, including sending of Deregistration accept
- Idle / paging
- Registration timeout and refresh
- Sessions / IP addresses should not persist forever.  Timeout; flush on TMSI register/service request without session reactivation; flush on IMSI registration? 
- Large SCTP messages - e.g. unfiltered UE Capability Information
- UE static IP
- CU specific function
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
