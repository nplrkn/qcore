# UE serialization
It is possible that two operations could be initiated in parallel on different async tasks for the same UE.  
How is the UE context synchronized in this case?  How are NAS and PDCP counters handled?

One option might be to lock the UE context, and have whichever task came along second wait till the first task
releases the lock.  

Instead, we take the approach of having a single-instance UE task that gets all UE related messages delivered to it over
a channel.  This task initiates UE procedures (see the procedures/ue_procedures folder) and, while a procedure is running, allows it to wait for the next UE message.  It becomes the problem of the procedure logic to decide what to do if the message it gets is not the one it is expecting.

The consequence is that the UE Context struct is not cloneable and not locked.  In the style of the actor model, it is always owned by a UE task that has sole, serial access to it.

When a new UE F1AP ID is created (by an F1 Initial Context Setup request), we spawn the UE task and its channel.  This leads to the map of F1AP ID->sender channel found in the QCore struct.  (In due course, the channel will also need to be also retrievable by other UE IDs - e.g. IMSI, TMSI, IP address.)

