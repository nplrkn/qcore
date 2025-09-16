# Backlog

## In progress
- Live testing with multiple phones, update readme documenting interop status.

## Interop
-  Service request missing container from Samsung.  It asked for a UE context but no sessions.  So probably no need for non-cleartext inner message.  We dropped it on the floor.

-  OnePlus Nord CE 3 lite - interoperated fine.  Saw this. [Also seen with Samsung on adding APN] See oneplus_qcore.pcap.

Sep 05 13:17:20.600 DEBG >> Ngap UeContextReleaseRequest, ue_id: 3269710643
Sep 05 13:17:20.600 INFO gNB initiated context release, cause RadioNetwork(Unspecified), ue_id: 3269710643
Sep 05 13:17:20.600 DEBG << Ngap UeContextReleaseCommand, ue_id: 3269710643
Sep 05 13:17:20.637 DEBG >> Ngap UeContextReleaseComplete, ue_id: 3269710643
Sep 05 13:17:20.637 DEBG Store core context for TMSI tmsi-0093a658, ue_id: 3269710643
Sep 05 13:17:20.637 DEBG Deleted UE channel, ue_id: 3269710643
Sep 05 13:17:50.205 DEBG >> Ngap InitialUeMessage, ue_id: 2452092877
Sep 05 13:17:50.205 INFO New UE RAN connection, ue_id: 2452092877
Sep 05 13:17:50.205 DEBG >> Nas DeregistrationRequestFromUe, ue_id: 2452092877
Sep 05 13:17:50.205 INFO UE deregistration, ue_id: 2452092877
Sep 05 13:17:50.205 DEBG << Nas DeregistrationAcceptFromUe, ue_id: 2452092877
Sep 05 13:17:50.205 WARN No TMSI to delete, ue_id: 2452092877
Sep 05 13:17:50.205 DEBG << Ngap UeContextReleaseCommand, ue_id: 2452092877
Sep 05 13:17:50.341 DEBG >> Ngap UeContextReleaseComplete, ue_id: 2452092877
Sep 05 13:17:50.341 DEBG Deleted UE channel, ue_id: 2452092877

-  Oppo - oppo_qcore.pcap.  Issue below.  But ICMP ping + NAT didn't work.

Sep 05 13:31:44.070 INFO gNB initiated context release, cause RadioNetwork(Unspecified), ue_id: 3083365241
Sep 05 13:31:44.070 DEBG << Ngap UeContextReleaseCommand, ue_id: 3083365241
Sep 05 13:31:44.106 DEBG >> Ngap UeContextReleaseComplete, ue_id: 3083365241
Sep 05 13:31:44.106 DEBG Store core context for TMSI tmsi-ec7d573c, ue_id: 3083365241
Sep 05 13:31:44.107 DEBG Deleted UE channel, ue_id: 3083365241
Sep 05 13:32:36.215 DEBG >> Ngap InitialUeMessage, ue_id: 10338731
Sep 05 13:32:36.215 INFO New UE RAN connection, ue_id: 10338731
Sep 05 13:32:36.215 DEBG Using TMSI from outer message for NAS admit, ue_id: 10338731
Sep 05 13:32:36.215 DEBG >> Nas ServiceRequest, ue_id: 10338731
Sep 05 13:32:36.215 WARN Procedure failure: service request: Service request missing message container, ue_id: 10338731
Sep 05 13:32:39.315 DEBG >> Ngap InitialUeMessage, ue_id: 2711482715
Sep 05 13:32:39.315 INFO New UE RAN connection, ue_id: 2711482715
Sep 05 13:32:39.315 DEBG Unknown TMSI, ue_id: 2711482715
Sep 05 13:32:39.315 DEBG GUTI/TMSI with unknown AMF IDs or TMSI, ue_id: 2711482715
Sep 05 13:32:39.315 DEBG Unknown TMSI in outer message, ue_id: 2711482715
Sep 05 13:32:39.315 DEBG >> Nas ServiceRequest, ue_id: 2711482715
Sep 05 13:32:39.315 WARN Rejecting Nas Service Request - unknown TMSI, ue_id: 2711482715
Sep 05 13:32:39.315 DEBG << Nas ServiceReject, ue_id: 2711482715
Sep 05 13:32:42.315 DEBG >> Ngap UeContextReleaseRequest, ue_id: 2711482715
Sep 05 13:32:42.315 INFO gNB initiated context release, cause RadioNetwork(Unspecified), ue_id: 2711482715
Sep 05 13:32:42.315 DEBG << Ngap UeContextReleaseCommand, ue_id: 2711482715
Sep 05 13:32:42.351 DEBG >> Ngap UeContextReleaseComplete, ue_id: 2711482715
Sep 05 13:32:42.351 DEBG Deleted UE channel, ue_id: 2711482715
Sep 05 13:32:42.473 DEBG >> Ngap InitialUeMessage, ue_id: 1060125697
Sep 05 13:32:42.473 INFO New UE RAN connection, ue_id: 1060125697
Sep 05 13:32:42.473 DEBG >> Nas RegistrationRequest, ue_id: 1060125697
Sep 05 13:32:42.473 INFO Registering imsi-001060123456743, ue_id: 1060125697
Sep 05 13:32:42.473 DEBG SQN for challenge: Sqn([00, 00, 00, 00, 4b, e6]), ue_id: 1060125697
Sep 05 13:32:42.473 DEBG << NasAuthenticationRequest, ue_id: 1060125697

-  Bad trace line: WARN Wrong AMF IDs in GUTI/STMSI - theirs Some(2), [0, 64] ours 010080,

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
