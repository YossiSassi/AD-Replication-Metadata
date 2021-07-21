# Track past changes on your AD objects, even if event logs were wiped (e.g. during an Incident Response), using Replication metadata history. No special permissions needed (no admin required).
# comments to yossis@protonmail.com

#$Objects = "administrator", "yossis", "DC01$"
$Objects = @();

while ($x=1)
{
    $ObjectToAdd = Read-Host -Prompt "Enter SamAccountName (hit ENTER to finish and view object changes)"
    if ($ObjectToAdd -eq "") {break} else {$Objects += $ObjectToAdd}
}

if ($Objects.count -eq 0) {break}

$DCs = Get-ADDomainController -Filter * | Select -ExpandProperty name

$ReplMetadata = @();

$Objects | foreach {
    $user = $_; 
    $ReplMetadata += $DCs | foreach { 
        Get-ADReplicationAttributeMetadata -Object $((Get-ADObject -Filter {samaccountname -eq $user} -IncludeDeletedObjects).distinguishedname) -ShowAllLinkedValues -Server $_ 
        }
    }

$ReplMetadata | sort object, LastOriginatingChangeTime -Descending |  
    select LastOriginatingChangeTime, attributeName, AttributeValue, Object, Server | 
        Out-GridView -Title "Replication Attribute Metadata history for $($Objects.toupper())"