# Persistence 
## Paging continuity
The most tangible consequences of not persisting 5G core state are: loss of contact with idle UEs and reregistration avalanches.

-  Loss of contact with idle UEs occur if the 5G core loses the necessary state + security keys to receive downlink data and page UEs.  If the UEs spend most their time waiting to be notified, this can be a very significant loss of service.  

-  Re-registration avalanche occurs if all UEs need to reregister following update / restart of the 5G core in order to regain data connectivity.  This can stress the system and take a while.  If there are large numbers of UEs that need responsive data connectivity, this can be a very significant loss of service.

We define the feature 'Paging continuity' to mean that it is possible to terminate/restart 5G core components without triggering these scenarios.  Put simply, this means you could update or reconfigure the software via a stop/start with only a minor interruption to the 5G service.

A more advanced form of persistence is 'Session continuity', whereby active data transmission to/from UEs continues with minimal userplane packet loss (<5 seconds) following a single point of failure.

Without any form of persistence, there is 'Cold restore'.  This means that a fresh instance of the system is brought up following the failure, using the same configuration as before.

Typical cloud native 5G cores achieve paging and session continuity by having multiple concurrent replicas of all components and a separate replicated database tier, spread across multiple servers. 

## Requirements statement

Compared to a normal 5G core, QCore is more likely to be running on a single system with no hardware redundancy, and in some use cases there may be a lower expectation of service availability than a traditional 5G core.  However, we do not want to design out the possibility of hardware redundancy. 

Compared to a normal 5G core, QCore puts a far higher emphasis on reduced power consumption and machine / battery weight. 

Here is the working requirements statement:
-  A single machine system must support paging continuity across system reboot.
-  A two machine redundant deployment must support cold restore - particularly the case where one machine is a powered-down spare.
-  A two machine redundant deployment should ideally support paging continuity, but this is not a day 1 requirement.  (More below.)
-  It is not a requirement for QCore to support session continuity.

Two machine paging continuity is complex to implement, requiring replication and a far-reaching design choice about active-active vs active-standby.  Given that QCore is targeted at power-constrained use cases, the extra power demands of having two replicas running and in constant communication might outweigh the advantages of paging continuity.  Since machine failure is an order of magnitude rarer than machine reboot / process restart (e.g. for security update), the downsides of loss of paging continuity occur more rarely.

## Design considerations

Features associated with persistence include:
-  Storing running state (securely?) on the filesystem.
-  Implement TTL or some other technique to avoid stale data building up across failures and restarts.

With a 2nd replica:
-  Managing a (mTLS?) replication connection.
-  Ongoing streaming replication - the mainline case where events such as registration and session establishment need to be notified to the other system.
-  Catch-up replication - for the case where a blank 2nd instance starts up.
-  Audit - for the case where the data stores get out of sync.

The two main design options are: 
- running a separate datastore process (say, Redis), with a network API
- building data storage (and replication if needed) into the QCore process, with a function-calling API.  

Our monolithic guiding principle seems to suggest the latter.   


