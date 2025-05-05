In progress
- Squash commit
- check the history, license, readme all look good on github
- Publish

Next up
- demo with SRS RAN DU and SRS UE

High priority function gaps
- Deregistration accept
- Userplane stats
- Idle / paging
- SQN

Performance
- XDP userplane
- Release build perf profiling + tuning
- Check scaling to multiple threads
- Reduce memcpy

Persistence
- Paging continuity

Other function gaps
- Session deletion
- UE static IP
- Registration timeout and refresh
- Time out during procedures
- UE AMBR
- Transport key for SIM creds
- SUCI
- NEA2 ciphering
- Processing of UE measurements - detect when UE changes cell
- Uplink integrity validation for RRC / NAS
- Handling of PDCP control packets
- Handling of uplink PDCP sequence number out or order / gaps
- Negative testing of rejections and protocol errors
- RRC Inactive
- >1 PDU session per UE
- >1 DU

Tidying + refactoring
- message logs in both test framework and QCORE debug should use consistent F1 / RRC / NAS prefix
- merge nas_context.rs and security_context.rs
- simplify xxap 
