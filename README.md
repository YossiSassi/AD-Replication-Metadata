Track past changes in your AD accounts (users & computers), even if no event logs exist - e.g. not collected, no retention/overwritten, wiped (e.g. during an Incident Response) etc. 
Uses Replication metadata history parsing.

No special permissions required (non-admin AD user is ok).

Supports offline mode as well, using a consistent copy of the NTDS.dit file.

Note 1: Offline operations do not show attribute value, yet all other information is there (LastChangeTime, NumberOfChanges, DaysSinceLastChange etc., including Enabled/Disabled status, AdminCount etc.).

Note 2: The ActiveDirectory module is required Only for ONLINE operations (live DCs), and not needed for Offline operations.
<br><BR>

### Example code on how to create a custom accountnames.txt file to query changes for a specific set of users
Create an accounts file that will query changes for all administrative users (adminCount=1)

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
