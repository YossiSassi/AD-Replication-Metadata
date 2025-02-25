# Track previous changes on specific AD accounts (users, computers - online & offline DB backup) and Groups (online DC only), even if event logs were wiped/not collected (e.g. during an Incident Response), using Replication metadata history. No special permissions needed for Live AD query (no admin required). When using Offline DB, local admin needed for port bind to LDAP queries of loaded DB in memory.
# Requires ActiveDirectory Module *ONLY* when querying a live Domain Controller <in order to get attribute value(!)>
# IMPORTANT NOTE: If a text file named .\accountnames.txt exists in the same directory with the script, it will read the samaccountname list from that file. if not, you will be prompted to type the name(s) of users, computers, groups or well-known SIDs.
#
# comments to: yossis@protonmail.com (1nTh35h311)
#
# Version: 1.3
<# Change Log:
- v1.3 - Added support for well-known NT AUTHORITY SIDs (Security Identifiers) in the domain, e.g. 'Authenticated Users', for Online mode ONLY * (Read comment on Well-Known SIDs -->)
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
#>

<#
## Example code on how to create a custom accountnames.txt file to query changes for a specific set of accounts
# Creating an accounts file that will query changes for all administrative users (flagged as adminCount=1)
# 1st, query the account names and save to text file
$a = ([adsisearcher]'(&(ObjectCategory=Person)(ObjectClass=User)(admincount=1)(!(samaccountname=krbtgt)))').FindAll();
$a.Properties.samaccountname | sort | Out-File .\accountnames.txt 

# 2nd, Run the script, from the same directory as the accountnames.txt file

# 3rd, Identify the output csv file, e.g. ad-repl*, and import it to memory
# import csv
$res = import-csv .\AD-Replication-Metadata-History_11001510002023.csv -Delimiter ";"

# 4th - group it by objects
$grouped = $res | group Object

# 5th - ensure you have the object you want to query/examine
$grouped | where Name -like "cn=administrator,*"

# 6th, Can also get specific data, e.g. Total logons for this account (from all DCs, summed up)
$grouped | where Name -like "cn=administrator,*" | select -ExpandProperty group | where AttributeName -eq "LogonCount" | Measure-Object -Property attributevalue -Sum | select -ExpandProperty Sum
#>

<#
COMMENT ON WELL-KNOWN SIDs -->
Dynamic groups and/or Foreign security principals, as well as some built-in groups with unicode names - might need to be queried using their SID (Security Identifier).
e.g. 'Authenticated Users' - which is sid S-1-5-11, should be inputted as S-1-5-11, and NOT as authenticated users. otherwise the query will Not find the account in Active Directory.

Here is a list of well-known SIDs that should generate replication metadata output without error (as Foreign Security Principals and/or dynamic groups|built-in):
SID	Account Name	Description
S-1-5-4	Interactive	Represents users who are logged in interactively.
S-1-5-9	Enterprise Domain Controllers	Represents all domain controllers in an enterprise (forest).
S-1-5-11	Authenticated Users	Represents all users who have authenticated successfully, regardless of the authentication method or domain.
S-1-5-17	This Organization	Represents all users from the same organization in a federated trust scenario.
S-1-5-32-544	Administrators	Represents the local Administrators group.
S-1-5-32-545	Users	Represents the local Users group, which includes all authenticated users by default.
S-1-5-32-546	Guests	Represents the local Guests group.
S-1-5-32-551	Backup Operators	Represents the Backup Operators group, which has permissions to back up and restore files regardless of permissions.

Other well-Known SIDs that might generate some replication metadata output, yet with errors:
SID	Account Name	Description
S-1-5-7	Anonymous Logon	Represents users who are not authenticated, including unauthenticated guest users.
S-1-5-32-573	Terminal Server Users	Represents users who have logged on to a terminal server.
S-1-5-32-547	Power Users	Represents the Power Users group, which historically had elevated privileges but is now deprecated in modern Windows versions.
S-1-5-14	Remote Interactive Logon	Represents users who log on interactively through a remote desktop session.

Additional well-Known SIDs that shouldn't generate replication metadata, and are locally used:
S-1-5-18	SYSTEM	Represents the Local System account, used by Windows for system-level services.
S-1-5-19	Local Service	Represents the Local Service account, a built-in service account with limited privileges.
S-1-5-20	Network Service	Represents the Network Service account, used for services requiring network access with minimal privileges.
S-1-5-6	Service	Represents all service accounts.
S-1-5-2	Network	Represents users who log on through a network connection (e.g., accessing a shared folder).
S-1-5-8	Proxy	Represents a proxy service account.
S-1-5-12	Restricted Code	Represents processes running with restricted tokens.
S-1-5-3	Batch	Represents accounts that log on using batch processing, such as scheduled tasks.

As for known groups which may contain Unicode characters in the group name - you can query them by their SID instead -> 
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
#>

# Initialize empty array for object(s)
$Objects = @();

# Check if text file with account names exist, and if true - read it and use it
$AccountnamesFilePath = $(Get-Location).Path + "\accountnames.txt"
if (Test-Path $AccountnamesFilePath) {
    $Objects += Get-Content $AccountnamesFilePath | foreach {$_.Trim()} 
    Write-Host "[*] Found $($Objects | Measure-Object | select -ExpandProperty count) account(s) from file $AccountnamesFilePath." -ForegroundColor Green
}
else {  # accountnames.txt file Not found
Write-Warning "File $AccountnamesFilePath was not found. To automatically query multiple accounts, please create it.";
Write-Host "Type the SamAccountName of one or more accounts (or group), one after the other." -NoNewline -ForegroundColor Cyan; Write-Host "`nNote: Computer accounts should be followed by a $ sign (e.g. PC90210$)" -NoNewline -ForegroundColor Yellow; Write-Host "`nWhen finished, hit ENTER to continue." -foregroundcolor Cyan;

while ($x=1)
{
    $ObjectToAdd = Read-Host -Prompt "[!] Type SamAccountName, OR hit ENTER to finish and continue to view object changes"
    if ($ObjectToAdd -eq "") {break} else {$Objects += $ObjectToAdd}
}
}

if ($Objects.count -eq 0) {break}

$ReplMetadata = @();

### Function to query an account's replication metadata 'living off the land' (no dependencies) ###
Function Get-ReplMetadata {
    param (
        [Parameter(Mandatory = $True)]
        [string]$Account,

        [Parameter(Mandatory = $True)]
        [System.DirectoryServices.DirectoryEntry]$DomainObj
    )

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $DomainObj
        $ObjSearcher.PageSize = 256; 
        $objSearcher.SizeLimit = 100000;
        $objSearcher.Tombstone = $true # for deleted objects
        $ObjSearcher.Filter = "(samaccountname=$Account)"
        $objSearcher.PropertiesToLoad.Addrange(('msds-replattributemetadata','Name','DistinguishedName','useraccountcontrol','AdminCount','samaccountname','logoncount','lastlogon','badpwdcount','badpasswordtime'))
        #$objSearcher.PropertiesToLoad.AddRange(("msds-replattributemetadata","AdminCount","CanonicalName", "DistinguishedName", "Description", "GroupType","samaccountname", "SidHistory", "ManagedBy", "msDS-ReplValueMetaData", "ObjectSID", "WhenCreated", "WhenChanged"))
        $AccountObj = $ObjSearcher.FindOne();

        $Results = @();

        If ($AccountObj)
        {    
            $ReplMetadata = $AccountObj.Properties.'msds-replattributemetadata';

            # Get member account's SamAccountName, AdminCount, Enabled/Disabled..
            $SamAccountName = $AccountObj.Properties.samaccountname -join ',';
            $AdminCount = $AccountObj.Properties.admincount -join ',';
            #$Enabled = if ($ObjMember.Properties.useraccountcontrol -eq 514 -or $ObjMember.Properties.useraccountcontrol -eq 66050) {"False"} else {"True"}
	        $Enabled = if ($($AccountObj.Properties.useraccountcontrol) -band "0x2") {"False"} else {"True"}
            $DN = $AccountObj.Properties.distinguishedname -join ',';

            # get values of non-replicated attributes per this DC offlinebackup
            [int]$LogonCount = $AccountObj.Properties.logoncount -join ',';
            $LastLogon = [datetime]::FromFileTime($($AccountObj.Properties.lastlogon -join ',';));
            if ($LastLogon -eq "Monday, January 1, 1601 02:00:00") {$LastLogon = $null} # in case value was 1/1/1601 02:00:00
            [int]$BadPwdCount = $AccountObj.Properties.badpwdcount -join ',';;
            $BadPwdTime = [datetime]::FromFileTime($($AccountObj.Properties.badpasswordtime -join ',';));
            if ($BadPwdTime -eq "Monday, January 1, 1601 02:00:00") {$BadPwdTime = $null} # in case value was 1/1/1601 02:00:00

            # handle logonCount
            $NonReplicatedDataObj = New-Object psobject;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "DN" -Value $DN -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "SamAccountName" -Value $SamAccountName -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "Enabled" -Value $Enabled -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "AdminCount" -Value $AdminCount -Force;    
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name LastChangeTime -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name DaysSinceLastChange -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name NumberOfChanges -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeName -Value "LogonCount" -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeValue -Value $LogonCount -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name OriginatingDC -Value "Current DC Backup" -Force;
            $Results += $NonReplicatedDataObj | Write-Output;
            Clear-Variable NonReplicatedDataObj;

            # handle lastLogon
            if ($LastLogon -ne $null) {$LastChangeTimeForLastLogon = $LastLogon} else {$LastChangeTimeForLastLogon = 'N/A (Non-Replicated attribute)'}
            $NonReplicatedDataObj = New-Object psobject;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "DN" -Value $DN -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "SamAccountName" -Value $SamAccountName -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "Enabled" -Value $Enabled -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "AdminCount" -Value $AdminCount -Force;    
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name LastChangeTime -Value $(If ($LastLogon -eq $null) {$LastChangeTimeForLastLogon} else {$LastLogon}) -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name DaysSinceLastChange -Value $(If ($LastLogon -eq $null) {'N/A (Non-Replicated attribute)'} else {$(New-TimeSpan -Start $LastLogon -End $(Get-date)).Days}) -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name NumberOfChanges -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeName -Value "LastLogon" -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeValue -Value $LastLogon -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name OriginatingDC -Value "Current DC Backup" -Force;
            $Results += $NonReplicatedDataObj | Write-Output;
            Clear-Variable NonReplicatedDataObj;

            # handle BadpwdCount
            $NonReplicatedDataObj = New-Object psobject;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "DN" -Value $DN -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "SamAccountName" -Value $SamAccountName -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "Enabled" -Value $Enabled -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "AdminCount" -Value $AdminCount -Force;    
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name LastChangeTime -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name DaysSinceLastChange -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name NumberOfChanges -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeName -Value "BadPasswordCount" -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeValue -Value $BadPwdCount -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name OriginatingDC -Value "Current DC Backup" -Force;
            $Results += $NonReplicatedDataObj | Write-Output;
            Clear-Variable NonReplicatedDataObj;

            # handle BadpwdTime
            if ($BadPwdTime -ne $null -or $BadPwdTime -eq 0) {$LastChangeTimeForBadPwdTime = $BadPwdTime} else {$LastChangeTimeForBadPwdTime = 'N/A (Non-Replicated attribute)'}
            $NonReplicatedDataObj = New-Object psobject;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "DN" -Value $DN -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "SamAccountName" -Value $SamAccountName -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "Enabled" -Value $Enabled -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name "AdminCount" -Value $AdminCount -Force;    
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name LastChangeTime -Value $(If ($BadPwdTime -eq $null) {$LastChangeTimeForBadPwdTime} else {$BadPwdTime}) -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name DaysSinceLastChange -Value $(If ($BadPwdTime -eq $null) {'N/A (Non-Replicated attribute)'} else {$(New-TimeSpan -Start $BadPwdTime -End $(Get-date)).Days}) -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name NumberOfChanges -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeName -Value "BadPasswordTime" -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeValue -Value $BadPwdTime -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name OriginatingDC -Value "Current DC Backup" -Force;
            $Results += $NonReplicatedDataObj | Write-Output;
            Clear-Variable NonReplicatedDataObj, LastLogon, LogonCount, BadPwdCount, BadPwdTime, LastChangeTimeForLastLogon, LastChangeTimeForBadPwdTime -ErrorAction SilentlyContinue;
            
            if ($ReplMetaData) {

            Write-Verbose "[X] Parsing replication metadata for account $(($AccountObj.Properties.samaccountname |Out-String).ToUpper())";

            # Parse replmetadata for attributes
            $ReplMetaData | foreach {
                [xml]$ReplValue = ""
                $ReplValue.LoadXml($_.Replace("\x00", "").Replace("&","&amp;"))
    
                $LastActionDate = $ReplValue.DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange;
                [int]$DaysSinceLastAction = ($(get-date) - [datetime]$ReplValue.DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange).Days;
    
                $ChangeObj = New-Object PSObject;

                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "DN" -Value $DN -Force;
                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "SamAccountName" -Value $SamAccountName -Force;
                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "Enabled" -Value $Enabled -Force;
                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "LastChangeTime" -Value $([datetime]$LastActionDate) -Force;
                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "AdminCount" -Value $AdminCount -Force;
                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "DaysSinceLastChange" -Value $([int]$DaysSinceLastAction) -Force;
                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "NumberOfChanges" -Value $([int]$ReplValue.DS_REPL_ATTR_META_DATA.dwVersion) -Force;
                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "AttributeName" -Value $ReplValue.DS_REPL_ATTR_META_DATA.pszAttributeName -Force;
                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "OriginatingDC" -Value $ReplValue.DS_REPL_ATTR_META_DATA.pszLastOriginatingDsaDN -Force;
                Add-Member -InputObject $ChangeObj -MemberType NoteProperty -Name "AttributeValue" -Value 'N/A (non available in offline backups)';

                $Results += $ChangeObj
                Clear-Variable ChangeObj
            }
        } # end of ReplMetadata handling
        
        else # no replication metadata found for this object
        {
            Write-Verbose "[X] No replication metadata found for account $(($AccountObj.Properties.samaccountname |Out-String).ToUpper()) (no activity history to parse)"
        }

    }

    $ObjSearcher.dispose();
    Return $Results;
} # End of Get-ReplMetadata function

# Check if Offline DB query is required
[string]$OfflineDBPath = Read-Host "To query a LIVE DOMAIN - Press <ENTER>.`nTo query an OFFLINE DB BACKUP, please enter the FULL PATH of an ntds.dit file, e.g. c:\temp\ntds.dit`n";

### Offline DB Query ###
if ($OfflineDBPath -ne "")
    {
        # Check if running elevated
        if (!(New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
                {
	                Write-Warning "[X] Must be elevated to run Offline DB operations.`nPlease open an administrative shell and try again. Quiting.";
                    Exit;
                }
    
        # Set variables 
        [int]$BackupInstanceLDAPPort = 50005;
        [System.String]$DSAMainFilePath = "$ENV:windir\system32\dsamain.exe";
        
        # Check DB Path
        if ($(Test-Path $OfflineDBPath))
            {
                Write-Host "[*] a DBPath to an NTDS.dit file was specified.`nAn offline DB will be used." -ForegroundColor Cyan;
            }
        else
            {
                Write-Warning "[X] Unable to find path $OfflineDBPath. Quiting.";
                Exit;
            }

            # Check if Windows 10 AND AD LDS not Installed - opt user to choose to install required binaries
            [string]$OS = (Get-WmiObject -ClassName win32_Operatingsystem | select caption).Caption

            # if dsamain is not present, and OS is Windows 10, and the AD LDS feature is not installed and Enabled - offer to install it
            if (!(Test-Path $DSAMainFilePath) -and $OS -like "*Windows 10*" -and $(Get-WindowsOptionalFeature -Online -FeatureName DirectoryServices-ADAM-Client).State -ne "Enabled")
                {
                    # Display a choice menu to approve running with local administrator & LAPS passwords using NTLM
                    $Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes - Install AD LDS feature & dsamain required file(s)"
                    $No = New-Object System.Management.Automation.Host.ChoiceDescription "&No","No - and Continue without installing AD LDS"
                    $Cancel = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel","Exit Script"
                    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No, $Cancel)
                    $Title = "Installing AD Lightweight Directory Services (dsamain.exe)" 
                    $Message = "`nBy default, the dsamain.exe pre-requisite for loading an Offline DB instance is Not present on Windows 10.`nDo you want to install this Feature?`nNOTE: You can Remove the 'AD LDS' feature at a later time.`n`n"
                    $ResultChoiceADLDS = $Host.ui.PromptForChoice($Title, $Message, $Options, 2)
            
                    switch ($ResultChoiceADLDS) {
                        0 {
                            Enable-WindowsOptionalFeature -Online -FeatureName DirectoryServices-ADAM-Client
                        }
                        1 {
                            # do nothing - Try to continue without installing AD LDS..
                        }
                        2 {
                            Write-Warning "[X] Cannot find dsamain.exe. Loading of Backup Instance cannot continue.`nMake sure you have relevant files installed (e.g. AD RSAT or AD LDS / AD Role).";
                            break
                        }       
                    }       
                }
        
        # Check if port is available (default is 50005) 
        if ((New-Object System.Net.Sockets.TcpClient).ConnectAsync('localhost',$BackupInstanceLDAPPort).Wait(1000)) 
	        {
	            # if port in use, try a different random port
                Write-Host "[*] Specified Port <$BackupInstanceLDAPPort> is in use, trying a different random port." -ForegroundColor Yellow;
		        $BackupInstanceLDAPPort = Get-Random -Minimum 49152 -Maximum 65535;
	        }

        # Activate instance
        $DSAMainArguments = "/dbpath """ + $OfflineDBPath + """ /ldapport $BackupInstanceLDAPPort /allowNonAdminAccess";
        $DsaMainProc = Start-Process -FilePath $DSAMainFilePath -ArgumentList $DSAMainArguments -PassThru -RedirectStandardError $true -WindowStyle Hidden;

        # Check if process was launched successfully
        Sleep -Seconds 4;
        if (!(Get-Process -Id $DsaMainProc.Id -ErrorAction SilentlyContinue))
            {
                Write-Warning "[X] Process was Not loaded successfully. Make sure NTDS.dit file is not corrupted.`nLoading of the NTDS Instance Failed";
		        break
            }

        Write-Host "[*] NTDS instance Loaded on Port <$BackupInstanceLDAPPort>" -ForegroundColor Cyan
    
        # make sure instance loaded fine
        Sleep -seconds 3;
        [ADSI]"LDAP://localhost:$BackupInstanceLDAPPort";
        if (!$?)
	        {
    	        #$Error[0].ErrorRecord.Exception	
                Write-Warning "[X] Loading of the NTDS Instance Failed"
		        break
	        }		
        else
	        {
		        Write-Host "[*] AD Backup Instance Loaded Successfully" -ForegroundColor Green;
                $OfflineDBDateTime = (Get-ChildItem $OfflineDBPath).LastWriteTimeUtc;
                Write-Host "[*] AD Backup Instance Date Last Modified at $OfflineDBDateTime" -ForegroundColor Yellow
	        }

        # Get the domain Distinguished name
        $DN = ([adsi]"LDAP://localhost:$BackupInstanceLDAPPort").distinguishedName;
        $DomainObj = New-Object System.DirectoryServices.DirectoryEntry("LDAP://localhost:$BackupInstanceLDAPPort/$DN");
    
        $DomainFQDN = $DN.substring(3); 
        $DomainFQDN = $DomainFQDN.replace("DC=",".").replace(",","");

        ## Query metadata
        $Objects | foreach {
            $account = $_; 
            $ReplMetadata += Get-ReplMetadata -Account $account -DomainObj $DomainObj;            
        } # end of objects/accounts enum for replMetadata collection

        if ($ReplMetadata)
            {
                # Prepare and sort data
                $Data = $ReplMetadata | select LastChangeTime,DaysSinceLastChange,AttributeName,AttributeValue,NumberOfChanges,SamAccountName,DN,Enabled,AdminCount,OriginatingDC;
                # save to csv 
                [string]$CSVfile = $(Get-Location).Path + "\AD-Replication-Metadata-History_$(Get-Date -Format HHmmssddmmyyyy).csv";
                $Data | Export-Csv -Delimiter ";" $CSVfile -Encoding UTF8 -NoTypeInformation;
                if ($?)
                    {
                        Write-Host '[x] Results saved to semicolon-delimited (";") CSV file -> ' -NoNewline -ForegroundColor Green; Write-Host $CSVfile -ForegroundColor Cyan;
                    }
                else
                    {
                         Write-Warning "An error occured while saving to CSV file -> $CSVfile";
                    }

                # show grid
                $Data | Select-Object LastChangeTime,DaysSinceLastChange,AttributeName,@{n='AttributeValue';e={$_.attributevalue}},NumberOfChanges,SamAccountName,DN,Enabled,AdminCount,OriginatingDC | Sort-Object SamAccountName, LastChangeTime -Descending | Out-GridView -Title "Replication Attribute Metadata history from BACKUP dated $OfflineDBDateTime for $($Objects.toupper())";
            }

        # Terminate offline DB instance listener
        $DsaMainProc | Stop-Process -Force;
            
        # Remove temp file opened by dsamain.exe (not cleaned by default and 'in use' during operation)
        $FileOpenTrue = Get-ChildItem "$((Get-Location).Path)\True" | Where-Object {$_.PSIsContainer -eq $false} -ErrorAction SilentlyContinue;
        if ($FileOpenTrue) {
                Remove-Item $FileOpenTrue.FullName -ErrorAction SilentlyContinue;
                if (!$?) # Deletion of open handle file failed - likely due to multiple dsamain instances running
                    {
                        Write-Host "[X] Unable to remove the open handle file:`n$(($Error[0]).exception.Message)" -ForegroundColor DarkYellow
                        Write-Host "[X] Make sure you don't have other dsamain instances running from multiple runs of the command.`ne.g. Type " -ForegroundColor Yellow -NoNewline;
                        Write-Host -NoNewline "Get-Process dsamain" -ForegroundColor Cyan; Write-Host ", and see results. Can remove them with " -NoNewline -ForegroundColor Yellow;
                        Write-Host -NoNewline "Get-Process dsamain | Stop-Process -Force`n" -ForegroundColor Cyan;
                    }
            }
        Write-Host "`n[*] Offline DB instance terminated successfully.`n" -ForegroundColor Green -NoNewline;

    }

else

    {
    ### Domain query ###

    # Check for ActiveDirectory module
    if (Get-Module -ListAvailable ActiveDirectory) {
        #Write-Host "[*] Active Directory Module Found" -ForegroundColor Green;
        }
    else
        {
            Write-Host "[!] Active Directory Module Not Found (Required for live domain query & attribute value data)." -ForegroundColor Yellow;
            Write-Host '[*] To Install it, run from an elevated powershell console:';
            Write-Host '$x = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS*"; Add-WindowsCapability -Name $x.Name -Online;';
            Write-Host 'Quiting.' -ForegroundColor Cyan;
            break;
        }

    # Enter Domain FQDN to query (Multi-domain support)
    [string]$DomainDNS = $env:USERDNSDOMAIN;
    Write-Host -NoNewline "Type Domain FQDN/DNS name (Or, hit ENTER to use "; Write-Host $($DomainDNS.ToUpper()) -NoNewline -ForegroundColor Cyan; Write-Host ")";
    $Domain = Read-Host;
    if ($Domain -eq "") {$Domain = $DomainDNS};

    $DCs = Get-ADDomainController -Server $Domain -Filter * | Select -ExpandProperty hostname;
    $RespondingDCs = $DCs | Foreach {if ($(New-Object System.Net.Sockets.TcpClient).ConnectAsync($_,9389).Wait(1000)) {$_}};
    write-host "[x] Found $($RespondingDCs.count) DCs responding to ADWS/9389 (out of $($DCs.count))." -foregroundcolor yellow;
    write-host "[!] Collecting metadata history information from all DCs. this might take a while..." -foregroundcolor cyan;

    $DateTimeAttribs = "lastlogonTimestamp", "pwdLastSet", "ms-Mcs-AdmPwdExpirationTime";

    $ReplMetadata = @();

    $Objects | foreach {
        $account = $_; 
        $ReplMetadata += $RespondingDCs | foreach { 
            $DC = $_;
            # check if NT AUTHORITY SID was inputted, or other domain account
            if ($account.StartsWith("S-1-5-")) {
                $ReplOutput = Get-ADReplicationAttributeMetadata -ErrorAction SilentlyContinue -Object $((Get-ADObject -Server $Domain -Filter {objectSID -eq $account} -IncludeDeletedObjects).distinguishedname) -ShowAllLinkedValues -Server $DC;
            }
            else # non-SID account
                {
                $ReplOutput = Get-ADReplicationAttributeMetadata -Object $((Get-ADObject -Server $Domain -Filter {samaccountname -eq $account} -IncludeDeletedObjects).distinguishedname) -ShowAllLinkedValues -Server $DC;
            }

            $ReplOutput | Write-Output;

            # get other properties, from Non-Replicated attributes
            $ObjCategory = $ReplOutput | Where-Object attributename -eq "ObjectCategory" | select -ExpandProperty attributevalue;

            switch ($ObjCategory) {
            {$_.StartsWith("CN=Computer")} {$Obj = Get-ADComputer $account -Properties logoncount,lastlogon,badpwdcount,badpasswordtime -Server $DC; [boolean]$IsGroup = $false}
            {$_.StartsWith("CN=Person")} {$Obj = Get-ADUser $account -Properties logoncount,lastlogon,badpwdcount,badpasswordtime -Server $DC; [boolean]$IsGroup = $false}
            {$_.StartsWith("CN=Group")} {$Obj = Get-ADGroup $account -Server $DC -ErrorAction SilentlyContinue; [boolean]$IsGroup = $true}
            {$_.StartsWith("CN=Foreign-Security-Principal")} {$obj = Get-ADObject -Filter {objectsid -eq $account} -Server $DC -Properties * -ErrorAction SilentlyContinue; [boolean]$IsGroup = $true}
            }

            $DN = $Obj.distinguishedname;

            # Add well-known account name for SIDs + Lay the 'foundation' to add more relevant properties for well-known SID accounts in the future, if needed
            if ($account.StartsWith("S-1-5-")) {
                $SidObj = New-Object System.Security.Principal.SecurityIdentifier($account);
                $WellKnownAccountName = $SidObj.Translate([System.Security.Principal.NTAccount]).Value;
                
                $SidAccountProperties = New-Object psobject;
                Add-Member -InputObject $SidAccountProperties -MemberType NoteProperty -Name LastOriginatingChangeTime -Value 'N/A (Well-Known SID)' -Force;
                Add-Member -InputObject $SidAccountProperties -MemberType NoteProperty -Name AttributeName -Value "Well-Known-AccountName" -Force;
                Add-Member -InputObject $SidAccountProperties -MemberType NoteProperty -Name AttributeValue -Value $WellKnownAccountName -Force;
                Add-Member -InputObject $SidAccountProperties -MemberType NoteProperty -Name version -Value 'N/A' -Force;
                Add-Member -InputObject $SidAccountProperties -MemberType NoteProperty -Name Object -Value $DN -Force;
                Add-Member -InputObject $SidAccountProperties -MemberType NoteProperty -Name Server -Value $DC -Force;

                $SidAccountProperties | Write-Output;
                Clear-Variable SidAccountProperties                
            }

            # get values of non-replicated attributes per this DC
            if (!$IsGroup) {
            [int]$LogonCount = $Obj.logoncount;
            $LastLogon = [datetime]::FromFileTime($($Obj.lastlogon));
            if ($LastLogon -eq "Monday, January 1, 1601 02:00:00") {$LastLogon = $null} # in case value was 1/1/1601 02:00:00
            [int]$BadPwdCount = $Obj.badpwdcount;
            $BadPwdTime = [datetime]::FromFileTime($($Obj.badpasswordtime));
            if ($BadPwdTime -eq "Monday, January 1, 1601 02:00:00") {$BadPwdTime = $null} # in case value was 1/1/1601 02:00:00
            
            # handle logonCount
            $NonReplicatedDataObj = New-Object psobject;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name LastOriginatingChangeTime -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeName -Value "LogonCount" -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeValue -Value $LogonCount -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name version -Value 'N/A' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name Object -Value $DN -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name Server -Value $DC -Force;
            $NonReplicatedDataObj | Write-Output;
            Clear-Variable NonReplicatedDataObj;

            # handle lastLogon
            $NonReplicatedDataObj = New-Object psobject;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name LastOriginatingChangeTime -Value $LastLogon -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeName -Value "LastLogon" -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeValue -Value $LastLogon -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name version -Value 'N/A' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name Object -Value $DN -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name Server -Value $DC -Force;
            $NonReplicatedDataObj | Write-Output;
            Clear-Variable NonReplicatedDataObj;

            # handle BadpwdCount
            $NonReplicatedDataObj = New-Object psobject;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name LastOriginatingChangeTime -Value 'N/A (Non-Replicated attribute)' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeName -Value "BadPasswordCount" -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeValue -Value $BadPwdCount -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name version -Value 'N/A' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name Object -Value $DN -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name Server -Value $DC -Force;
            $NonReplicatedDataObj | Write-Output;
            Clear-Variable NonReplicatedDataObj;

            # handle BadpwdTime
            $NonReplicatedDataObj = New-Object psobject;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name LastOriginatingChangeTime -Value $(If ($BadPwdTime -eq $null) {$LastChangeTimeForBadPwdTime} else {$BadPwdTime}) -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeName -Value "BadPasswordTime" -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name AttributeValue -Value $BadPwdTime -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name version -Value 'N/A' -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name Object -Value $DN -Force;
            Add-Member -InputObject $NonReplicatedDataObj -MemberType NoteProperty -Name Server -Value $DC -Force;
            $NonReplicatedDataObj | Write-Output;
            Clear-Variable NonReplicatedDataObj, LastLogon, LogonCount, BadPwdCount, BadPwdTime -ErrorAction SilentlyContinue;
            } # end of non-replicated attributes (Person/Computer only)
          } # end of current DC data collection
        } # end of current object/account data collection

    # prepare data
    $Data = $ReplMetadata | select LastOriginatingChangeTime, AttributeName, 
        @{n='AttributeValue';e={if ($_.attributeName -in $DateTimeAttribs){[datetime]::FromFileTime($_.AttributeValue)}
        elseif ($_.attributename -eq "AccountExpires") {if ($_.attributevalue -eq '9223372036854775807') {"Never Expires"} 
        else {[datetime]::FromFileTime($_.AttributeValue)}} elseif ($_.attributename -eq "servicePrincipalName") {"$($_.attributevalue)"} else {$_.AttributeValue}}},
         @{n='NumberOfChanges';e={[int]$_.version}}, Object, Server;
    
    # save to csv 
    [string]$CSVfile = $(Get-Location).Path + "\AD-Replication-Metadata-History_$(Get-Date -Format HHmmssddmmyyyy).csv";
    $Data | Export-Csv -Delimiter ";" $CSVfile -Encoding UTF8 -NoTypeInformation;
    
    if ($?)
        {
             Write-Host '[x] Results saved to semicolon-delimited (";") CSV file -> ' -NoNewline -ForegroundColor Green; Write-Host $CSVfile -ForegroundColor Cyan;
        }
    else
        {
             Write-Warning "An error occured while saving to CSV file -> $CSVfile";
        }

    # show grid
    $Data | sort object, LastOriginatingChangeTime -Descending | 
        Out-GridView -Title "Replication Attribute Metadata history for $($Objects.toupper())"
    }