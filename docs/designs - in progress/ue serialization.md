# UE operation processing 

## The problem

It is possible that two operations could be initiated in parallel on different async tasks for the same UE.  
How is the UE context synchronized in this case?  How are NAS and PDCP counters handled?

This can get hard to reason about.  If any two procedures can run in parallel, and there are N different places in the code that do read--update--write operations on a UE context, then there are N-squared permutations of how procedures can interact with each other.  

The approach of forcing only one operation to happen at a time on a UE doesn't fly.  If the core and the UE simultaneously send NAS requests, and if both are implemented to wait on the response before doing anything else, then a deadly embrace occurs.  An example is where the core sends a Configuration Update Request as a follow on to its registration processing, and simultaneously the UE sends a PDU session establishment request.  In this case, if each side queues the other side's request until it gets the response it is waiting for, they will wait forever (or until timeout).

## Solution approach

Our guiding principle is to make procedure implementations read like simple 'straight-line code' - send this request, get the response, send that... - with no awareness of any other procedures going on in parallel.  This means each parallel procedure on a UE must be a separate Rust async task.  

There is a single-instance UE task ("UE message handler") that gets all UE related messages delivered to it over a Rust channel.  This task initiates UE procedures and, while a procedure is running, allows it to wait for the next UE message.

The difficulty comes when the next UE message actually needs to start a new procedure.  Ultimately this leads to having parallel tasks that are capable of reading / writing to the UE context, each of which is interested in a subset of the messages that could come in, and each of which runs a response timeout whenever it waits.  

UE context modificaiton could be done by locking, but another possibility to investigate is that they could be instantiated with a read-only copy of the UE context and send changes back over a channel to be applied serially by the UE message handler to its single mutable UE context.  

## Short term position

The current position is that only one procedure can be run at a time, with a special case for configuration update.  

In the case of configuration update, rather than leaving the registration procedure or the service procedures running,
we end them before they have received the configuration update response.  This means that the configuration update response
will in fact be processed by the dispatch() function. 

## NAS procedure interaction table

In this section, we study what procedures actually ought to be able to run in parallel.  This just considers the NAS layer, and just the subset of procedures that are implemented in QCore.

The rows are core-initiated transactions, the columns are UE initiated transactions, and the cells indicate what happens on receipt of the UE request:
 R = Reject
 I = Ignore
 P = Parallelize (further notes later)
 A = Abort: abort the core procedure and immediately action the UE request
 
|         | Reg   | SessEsb | SessRel | Dereg | Remark |
| ------- | ----- | ------- | ------- | ----- | ------ |
| Ident   | R     | R       | I       | I     | (1)    |
| Auth    | R     | R       | I       | I     | (1)    |
| SecMod  | R     | R       | I       | I     | (1)    |
| Conf    | R     | P (2)   | P (2)   | A (3) |        |
| SessRel | R (4) | R (5)   | I       | A (3) |        |

(1) During a registration, the core will trigger Authentication, Security Mode and possibly
Identity procedures.  During this time, the UE should not be doing anything else with the 
possible exception of trying to deregister.  The difference between the "R" and "I" actions 
depend on whether the NAS message is a true request (i.e. register, session establish) or a 
'kick' to the core to make it send a request (i.e. session release, deregister)

(2) A UE may update its session state immediately after sending Registration Complete.  During this
time, QCore is sending a configuration update to inform the UE of the timezone and/or updated GUTI.  

(3) The UE wants to deregister.  It may not be interested in replying to the configuration update / 
session release request from QCore.  Even if it does, we can safely drop these responses when
they arrive.  So, rather than parallelize the deregistration process, we just drop the current transaction.

(4) We are trying to release a session and the UE is trying to do an initial register.  This will need to 
change when we support reregistration.

(5) We only support 1 session and the UE is trying to establish it at the point we are trying to release it.  This
will change when we support >1 session, where operations on different sessions should be parallelized.



