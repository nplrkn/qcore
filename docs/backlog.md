Up next
- Userplane stats

Performance
- XDP userplane
- Release build perf profiling + tuning
- Check scaling to multiple threads
- Reduce memcpy

Persistence
- Paging continuity

Function gaps
- Deregistration accept
- Idle / paging
- SQN
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

Regression testing gaps
- Uplink UP packet with delivery status extension header.

Tidying + refactoring
- message logs in both test framework and QCORE debug should use consistent F1 / RRC / NAS prefix
- merge nas_context.rs and security_context.rs
- simplify xxap 
