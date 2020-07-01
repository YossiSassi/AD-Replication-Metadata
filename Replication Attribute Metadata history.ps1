# comments to yossis@protonmail.com

#$Objects = "administrator", "yossis"
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
        Get-ADReplicationAttributeMetadata -Object $((Get-ADUser $user).distinguishedname) -ShowAllLinkedValues -Server $_ 
        }
    }

$ReplMetadata | sort object, LastOriginatingChangeTime -Descending |  
    select LastOriginatingChangeTime, attributeName, AttributeValue, Object, Server | 
        Out-GridView -Title "Replication Attribute Metadata history for $($Objects.toupper())"
