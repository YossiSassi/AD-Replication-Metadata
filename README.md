Track previous changes on specific AD accounts (users, computers) and Groups (online DC), even if event logs were wiped/not collected (e.g. during an Incident Response). Uses Replication metadata history parsing. Online and offline operations supported.

No special permissions required (any authenticated AD user is ok).

Supports offline mode as well, using a consistent copy of the NTDS.dit file.

Note 1: Offline operations do not show attribute value, yet all other information is there (LastChangeTime, NumberOfChanges, DaysSinceLastChange etc., including Enabled/Disabled status, AdminCount etc.). Also, group history parsing is currently available only for Online mode query, against a live Domain Controller.

Note 2: The ActiveDirectory module is required Only for ONLINE operations (live DCs), and not needed for Offline operations.
<br><BR>

### Example code on how to create a custom accountnames.txt file to query changes for a specific set of accounts
Creating an accounts file that will query changes for all administrative users (flagged as adminCount=1)

1st, query the account names and save to text file:

$a = ([adsisearcher]'(&(ObjectCategory=Person)(ObjectClass=User)(admincount=1)(!(samaccountname=krbtgt)))').FindAll();
$a.Properties.samaccountname | sort | Out-File .\accountnames.txt 

2nd, Run the script, from the same directory as the accountnames.txt file.

3rd, Identify the output csv file, e.g. ad-repl*, and import it to memory:

$res = import-csv .\AD-Replication-Metadata-History_11001510002023.csv -Delimiter ";"

4th - group it by objects:
$grouped = $res | group Object

5th - ensure you have the object you want to query/examine:

$grouped | where Name -like "cn=administrator,*"

6th, Can also get specific data, e.g. Total logons for this account (from all DCs, summed up):

$grouped | where Name -like "cn=administrator,*" | select -ExpandProperty group | where AttributeName -eq "LogonCount" | Measure-Object -Property attributevalue -Sum | select -ExpandProperty Sum

<br><br>
### Regarding Well-Known SIDs
Dynamic groups and/or Foreign security principals, as well as some built-in groups with unicode names - might need to be queried using their SID (Security Identifier).

e.g. 'Authenticated Users' - which is sid S-1-5-11, should be inputted as S-1-5-11, and NOT as authenticated users. otherwise the query will Not find the account in Active Directory.

Here is a list of well-known SIDs that should generate replication metadata output without error (as Foreign Security Principals and/or dynamic groups|built-in):

SID	    <b>Account Name</b>	  Description

S-1-5-4	<b>Interactive</b> - Represents users who are logged in interactively.

S-1-5-9	<b>Enterprise Domain Controllers</b> - Represents all domain controllers in an enterprise (forest).

S-1-5-11	<b>Authenticated Users</b> - Represents all users who have authenticated successfully, regardless of the authentication method or domain.

S-1-5-17	<b>This Organization</b> - Represents all users from the same organization in a federated trust scenario.

S-1-5-32-544	<b>Administrators</b> - Represents the local Administrators group.

S-1-5-32-545	<b>Users</b> - Represents the local Users group, which includes all authenticated users by default.

S-1-5-32-546	<b>Guests</b> - Represents the local Guests group.

S-1-5-32-551	<b>Backup Operators</b> - Represents the Backup Operators group, which has permissions to back up and restore files regardless of permissions.


<br>Other well-Known SIDs that might generate some replication metadata output, yet with errors:

S-1-5-7	Anonymous Logon	- Represents users who are not authenticated, including unauthenticated guest users.

S-1-5-32-573	Terminal Server Users	- Represents users who have logged on to a terminal server.

S-1-5-32-547	Power Users	- Represents the Power Users group, which historically had elevated privileges but is now deprecated in modern Windows versions.

S-1-5-14	Remote Interactive Logon	- Represents users who log on interactively through a remote desktop session.


<br>Additional well-Known SIDs that shouldn't generate replication metadata, and are locally used:

S-1-5-18	SYSTEM	- Represents the Local System account, used by Windows for system-level services.

S-1-5-19	Local Service	- Represents the Local Service account, a built-in service account with limited privileges.

S-1-5-20	Network Service	- Represents the Network Service account, used for services requiring network access with minimal privileges.

S-1-5-6	Service	- Represents all service accounts.

S-1-5-2	Network	- Represents users who log on through a network connection (e.g., accessing a shared folder).

S-1-5-8	Proxy	- Represents a proxy service account.

S-1-5-12	Restricted Code	- Represents processes running with restricted tokens.

S-1-5-3	Batch	- Represents accounts that log on using batch processing, such as scheduled tasks.


<br>As for known groups which may contain Unicode characters in the group name - you can query them by their SID instead -> 

Enterprise Domain Controllers	S-1-5-9

Administrators			S-1-5-32-544

Account Operators		S-1-5-32-548

Server Operators		S-1-5-32-549

Print Operators			S-1-5-32-550

Backup Operators		S-1-5-32-551

Replicators			S-1-5-32-552

Event Log Readers		S-1-5-32-573

Access Control Assistance Operators	S-1-5-32-579

Certificate Service DCOM Access		S-1-5-32-574

Distributed COM Users			S-1-5-32-562

Hyper-V Administrators			S-1-5-32-578

Remote Management Users			S-1-5-32-580

Incoming Forest Trust Builders		S-1-5-32-557

Cryptographic Operators			S-1-5-32-569
<br><br>
### Change Log (versions & revisions)
- v1.3 - Added support for well-known NT AUTHORITY SIDs (Security Identifiers) in the domain, e.g. 'Authenticated Users', for Online mode ONLY * (See Comment on Well-Known SIDs)
- v1.2 - Added support for group objects, for Online mode ONLY
- v1.1a - Added practical examples on how to use this script in the field, by creating custom accountnames.txt file(s)
- v1.1 - BadPasswordTime updated in LastOriginatingChangeTime + fixed out-gridview display bug in offline operations for attributevalue
- v1.0.9 - minor update to LastChangeTime for LastLogon
- v1.0.8 - added non-replicated attributes to OFFLINE operations (LogonCount, Lastlogon, BadPasswordCount & BadpasswordTime)
- v1.0.7 - added non-replicated attributes to LIVE Domain query - LogonCount, Lastlogon, BadPasswordCount & BadpasswordTime
- v1.0.6 - added csv output + better display of LAPS password expiration & serviceprincipalname
- v1.0.5 - added capability to read samaccountname list from text file (instead of typing one by one into the prompt)
- v1.0.4 - Minor improvements in sorting countable properties & dates
- v1.0.3 - Added better parsing for the AccountExpires attribute
- v1.0.2 - Added multi-Domain support, and check for AD module for live domain query.
- v1.0.1 - Added offline DB support (Updated for OSDFCon 2021 "I know what your AD did last summer!.." talk)


