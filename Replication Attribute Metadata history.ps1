# Get past changes on specific AD accounts (users & computers), even if event logs were wiped (e.g. during an Incident Response), using Replication metadata history. No special permissions needed for Live AD query (no admin required), unless when using Offline DB (needed to port bind for LDAP queries of loaded DB in memory).
# Requires ActiveDirectory Module *ONLY* when querying a live Domain Controller <in order to get attribute value(!)>
#
# comments to: yossis@protonmail.com (1nTh35h311)
# Version: 1.0.4
# Change Log: 
# v1.0.3 - Minor improvements in sorting countable properties & dates
# v1.0.3 - Added better parsing for the AccountExpires attribute
# v1.0.2 - Added multi-Domain support, and check for AD module for live domain query.
# v1.0.1 - Added offline DB support (Updated for OSDFCon 2021 "I know what your AD did last summer!.." talk)

#$Objects = "administrator", "yossis", "DC01$"
$Objects = @();

Write-Host "Enter SamAccountName of one or more accounts, one after the other.`nNote: Computer accounts should be followed by a $ sign (e.g. PC90210$)`nWhen finished, hit ENTER to continue." -foregroundcolor Cyan;

while ($x=1)
{
    $ObjectToAdd = Read-Host -Prompt "Enter SamAccountName (hit ENTER to finish and continue to view object changes)"
    if ($ObjectToAdd -eq "") {break} else {$Objects += $ObjectToAdd}
}

if ($Objects.count -eq 0) {break}

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
        $objSearcher.PropertiesToLoad.Addrange(('msds-replattributemetadata','Name','DistinguishedName','useraccountcontrol','AdminCount','samaccountname'))
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

            if ($ReplMetaData) {

            Write-Verbose "[X] Parsing replication metadata for account $(($AccountObj.Properties.samaccountname |Out-String).ToUpper())";

            # Parse attributes
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
        $ReplMetadata = @();

        $Objects | foreach {
            $account = $_; 
            $ReplMetadata += Get-ReplMetadata -Account $account -DomainObj $DomainObj;
        }

        if ($ReplMetadata)
            {
                $ReplMetadata | sort SamAccountName, LastChangeTime -Descending |  
                    select LastChangeTime,DaysSinceLastChange,AttributeName,NumberOfChanges,SamAccountName,DN,Enabled,AdminCount,OriginatingDC |
                        Out-GridView -Title "Replication Attribute Metadata history from BACKUP DATED $OfflineDBDateTime for $($Objects.toupper())"
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
    $Domain = Read-Host -Prompt "Enter Domain FQDN/DNS name (Or, hit ENTER to use $($DomainDNS.ToUpper()))";
    if ($Domain -eq "") {$Domain = $DomainDNS};

    $DCs = Get-ADDomainController -Server $Domain -Filter * | Select -ExpandProperty hostname;
    $RespondingDCs = $DCs | Foreach {if ($(New-Object System.Net.Sockets.TcpClient).ConnectAsync($_,9389).Wait(1000)) {$_}};
    write-host "Found $($RespondingDCs.count) DCs responding to ADWS/9389 (out of $($DCs.count))." -foregroundcolor yellow;
    write-host "Collecting metadata history information from all DCs. this might take a while..." -foregroundcolor cyan;

    $DateTimeAttribs = "lastlogon", "lastlogonTimestamp", "pwdLastSet";

    $ReplMetadata = @();

    $Objects | foreach {
        $account = $_; 
        $ReplMetadata += $RespondingDCs | foreach { 
            Get-ADReplicationAttributeMetadata -Object $((Get-ADObject -Server $Domain -Filter {samaccountname -eq $account} -IncludeDeletedObjects).distinguishedname) -ShowAllLinkedValues -Server $_
            }
        }


    $ReplMetadata | sort object, LastOriginatingChangeTime -Descending |  
        select LastOriginatingChangeTime, attributeName, @{n='AttributeValue';e={if ($_.attributeName -in $DateTimeAttribs){[datetime]::FromFileTime($_.AttributeValue)}elseif ($_.attributename -eq "AccountExpires") {if ($_.attributevalue -eq '9223372036854775807') {"Never Expires"} else {[datetime]::FromFileTime($_.AttributeValue)}} else {$_.AttributeValue}}}, @{n='NumberOfChanges';e={[int]$_.version}}, Object, Server | 
            Out-GridView -Title "Replication Attribute Metadata history for $($Objects.toupper())"
    }