---- MODULE LeaseLifecycle ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Identities, LeaseIdsSet, Versions, MaxTTL, MaxTime, Grace
VARIABLES now, issued, leases, revoked, revokedAt, uses, useLog, rotating

Active(l) == l \in issued /\ ~(l \in revoked) /\ leases[l].exp > now /\ uses[l] < leases[l].maxUses
Min(a,b) == IF a <= b THEN a ELSE b

TypeOK ==
  /\ now \in 0..MaxTime
  /\ issued \subseteq LeaseIdsSet
  /\ revoked \subseteq issued
  /\ leases \in [LeaseIdsSet -> [owner: Identities, exp: 0..(MaxTime + MaxTTL), maxUses: 1..2, ver: Versions]]
  /\ revokedAt \in [LeaseIdsSet -> 0..(MaxTime + 1)]
  /\ uses \in [LeaseIdsSet -> 0..2]
  /\ useLog \subseteq (LeaseIdsSet \X Identities \X (0..MaxTime))
  /\ rotating \in BOOLEAN

Init ==
  /\ now = 0
  /\ issued = {}
  /\ revoked = {}
  /\ leases = [l \in LeaseIdsSet |-> [owner |-> CHOOSE i \in Identities: TRUE, exp |-> 0, maxUses |-> 1, ver |-> 1]]
  /\ revokedAt = [l \in LeaseIdsSet |-> MaxTime + 1]
  /\ uses = [l \in LeaseIdsSet |-> 0]
  /\ useLog = {}
  /\ rotating = FALSE

Issue(l, id, ttl, ver) ==
  /\ l \in LeaseIdsSet \ issued
  /\ id \in Identities
  /\ ttl \in 1..MaxTTL
  /\ now + ttl <= MaxTime + MaxTTL
  /\ ver \in Versions
  /\ issued' = issued \cup {l}
  /\ leases' = [leases EXCEPT ![l] = [owner |-> id, exp |-> now + ttl, maxUses |-> 2, ver |-> ver]]
  /\ uses' = [uses EXCEPT ![l] = 0]
  /\ UNCHANGED <<now, revoked, revokedAt, useLog, rotating>>

Use(l, id) ==
  /\ l \in issued
  /\ id \in Identities
  /\ Active(l)
  /\ leases[l].owner = id
  /\ uses' = [uses EXCEPT ![l] = @ + 1]
  /\ useLog' = useLog \cup {<<l, id, now>>}
  /\ UNCHANGED <<now, issued, leases, revoked, revokedAt, rotating>>

Renew(l, ttl) ==
  /\ l \in issued
  /\ Active(l)
  /\ ttl \in 1..MaxTTL
  /\ now + ttl <= MaxTime + MaxTTL
  /\ leases' = [leases EXCEPT ![l].exp = now + ttl]
  /\ UNCHANGED <<now, issued, revoked, revokedAt, uses, useLog, rotating>>

Revoke(l) ==
  /\ l \in issued
  /\ ~(l \in revoked)
  /\ revoked' = revoked \cup {l}
  /\ revokedAt' = [revokedAt EXCEPT ![l] = now]
  /\ UNCHANGED <<now, issued, leases, uses, useLog, rotating>>

Tick ==
  /\ now < MaxTime
  /\ now' = now + 1
  /\ UNCHANGED <<issued, leases, revoked, revokedAt, uses, useLog, rotating>>

Rotate ==
  /\ \E l \in issued: Active(l)
  /\ rotating' = TRUE
  /\ leases' = [l \in LeaseIdsSet |->
        IF Active(l) THEN [leases[l] EXCEPT !.exp = Min(leases[l].exp, now + Grace)] ELSE leases[l]]
  /\ UNCHANGED <<now, issued, revoked, revokedAt, uses, useLog>>

Next ==
  \/ \E l \in LeaseIdsSet, id \in Identities, ttl \in 1..MaxTTL, ver \in Versions: Issue(l, id, ttl, ver)
  \/ \E l \in LeaseIdsSet, id \in Identities: Use(l, id)
  \/ \E l \in LeaseIdsSet, ttl \in 1..MaxTTL: Renew(l, ttl)
  \/ \E l \in LeaseIdsSet: Revoke(l)
  \/ Tick
  \/ Rotate

NoUseAfterExpiryOrRevocation ==
  \A e \in useLog:
    LET l == e[1] IN
      /\ e[3] < leases[l].exp
      /\ e[3] <= revokedAt[l]

OnlyBoundIdentityCanUse ==
  \A e \in useLog: leases[e[1]].owner = e[2]

AtMostTwoValidVersions ==
  Cardinality({leases[l].ver : l \in {x \in LeaseIdsSet : Active(x)}}) <= 2

Spec == Init /\ [][Next]_<<now, issued, leases, revoked, revokedAt, uses, useLog, rotating>>
====


