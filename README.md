Track past changes in your AD accounts (users & computers), even if no event logs exist - e.g. past retension/overwritten, wiped (e.g. during an Incident Response) etc. 
Uses Replication metadata history parsing.

No special permissions needed (no admin required).

Supports offline mode as well, using a consistent copy of the NTDS.dit file.

Note1:Offline operations do not show attribute value, yet all other information is there (LastChangeTime, NumberOfChanges, DaysSinceLastChange etc., including Enabled/Disabled status, AdminCount etc.).

Note2: The ActiveDirectory module is required Only for ONLINE operations (live DCs), and not needed for Offline operations.
