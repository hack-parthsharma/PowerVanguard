#PowerVanguard

$ErrorActionPreference = 'SilentlyContinue'
function Set-ConsoleColor ($bc, $fc) {
    $Host.UI.RawUI.BackgroundColor = $bc
    $Host.UI.RawUI.ForegroundColor = $fc
    Clear-Host
}
Start-Sleep -Seconds '1'
Mode 300
Start-Sleep -Seconds '1'
Set-ConsoleColor 'black' 'white'
Start-Sleep -Seconds '1'

Function Legend{

Write-Host 'CRITICAL' -BackgroundColor 'Red'
Write-Host 'IMPORTANT' -ForegroundColor 'Red'
Write-Host 'Medium' -ForegroundColor 'Magenta'
Write-Host 'Information' -ForegroundColor 'Green'
Write-Host 'Contextual' -ForegroundColor 'Cyan'


}
Function CheckEncryption{
    Start-Sleep -Seconds '5'
    $ProtectionStatus = Get-BitLockerVolume -MountPoint C:
        Write-Host 'Checking Encryption status' -ForegroundColor 'Yellow'
            Write-Host ""
            if ($ProtectionStatus.ProtectionStatus -eq 'On' -and $ProtectionStatus.VolumeStatus -eq 'FullyEncrypted'){Write-Host 'Device is encrypted' -ForegroundColor 'Green'}
            if ($ProtectionStatus.ProtectionStatus -eq 'Off' -and $ProtectionStatus.VolumeStatus -eq 'FullyEncrypted'){Write-Host 'Encryption is partial as keys are NOT protected' -ForegroundColor 'Red'}
            if ($ProtectionStatus.ProtectionStatus -eq 'off' -and $ProtectionStatus.VolumeStatus -eq 'EncryptionInProgress'){Write-Host 'Device is currently encrypting' -ForegroundColor 'Yellow'}
            if ($ProtectionStatus.ProtectionStatus -eq 'off' -and $ProtectionStatus.VolumeStatus -eq 'FullyDecrypted'){Write-Host '[!] DEVICE IS NOT ENCRYPTED' -BackgroundColor 'Red'}
            Else{Write-Host 'Unable to determine Encryption status.' -ForegroundColor 'Red'}
}

Function SMBChecks{
    Function CheckSMBv1{
        $SMBv1OptionalFeature = Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
            if ($SMBv1OptionalFeature.State -eq 'Enabled'){Write-Host 'SMBv1 is ENABLED' -BackgroundColor 'Red'}}
    
    Function CheckSMBShareSigningAndEncryption{
        function Format-Color([hashtable] $Colors = @{}, [switch] $SimpleMatch) {
            $lines = ($input | Out-String) -replace "`r", "" -split "`n"
            foreach($line in $lines) {
                $color = ''
                foreach($pattern in $Colors.Keys){
                    if(!$SimpleMatch -and $line -match $pattern) { $color = $Colors[$pattern] }
                    elseif ($SimpleMatch -and $line -like $pattern) { $color = $Colors[$pattern] }
                }
                if($color) {
                    Write-Host -ForegroundColor $color $line
                } else {
                    Write-Host $line
                }
            }
        }
        Write-Host ""
        Write-Host 'Are SMB shares signed?' -ForegroundColor 'Yellow'
        Get-SMBConnection | Select-Object ServerName,ShareName,Signed | Format-Color @{'False' = 'Red' ; 'True' = 'Green'}
        Write-Host 'Is SMB traffic encrypted in transit?' -ForegroundColor 'Yellow'
        Get-SMBConnection | Select-Object ServerName,ShareName,Encrypted | Format-Color @{'False' = 'Red' ; 'True' = 'Green'}
    }

    Function CheckSystemDriveSMBACL{
        Write-Host "Checking System Drive ACL's" -ForegroundColor 'Yellow'
        Get-SmbShareAccess -Name 'C$' | Select-Object AccountName,AccessControlType,AccessRight

    }
    # Function Logic
    CheckSMBv1
    CheckSMBShareSigningAndEncryption
    #CheckSystemDriveSMBACL
}

Function CheckPasswordPolicy{
    Write-Host ""
    Write-Host 'Password Policy' -ForegroundColor 'Yellow'
    Powershell -Command "Start-Process" 'cmd' -Verb RunAs -ArgumentList '/c net accounts'
}

Function CheckLaps{
    Write-Host 'Checking if LAPS is installed' -ForegroundColor 'Yellow'
    Write-Host ""
        $CheckLAPS = Test-Path -path "c:\program files\LAPS\CSE\Admpwd.dll"
        If ($CheckLAPS -eq $False){Write-Host '[!] LAPS IS NOT iNSTALLED' -BackgroundColor 'Red'}Else{
            Write-Host '[+] LAPS is installed' -ForegroundColor 'Green'}
}
Function CheckRunAs{
    function Format-Color([hashtable] $Colors = @{}, [switch] $SimpleMatch) {
        $lines = ($input | Out-String) -replace "`r", "" -split "`n"
        foreach($line in $lines) {
            $color = ''
            foreach($pattern in $Colors.Keys){
                if(!$SimpleMatch -and $line -match $pattern) { $color = $Colors[$pattern] }
                elseif ($SimpleMatch -and $line -like $pattern) { $color = $Colors[$pattern] }
            }
            if($color) {
                Write-Host -ForegroundColor $color $line
            } else {
                Write-Host $line
            }
        }
    }


Write-Host 'Checking if any privileged account credentials are stored' -ForegroundColor 'Yellow'
Write-Host 'If privileged credentials are found these can be used with "runas.exe" to execute commands in the context of the stored credentials' -ForegroundColor 'Cyan'

cmdkey /list | Format-Color @{'Admin' = 'Red' ; 'Administrator' = 'Red'}
}

Function CheckUserPrivileges{
    function Format-Color([hashtable] $Colors = @{}, [switch] $SimpleMatch) {
           $lines = ($input | Out-String) -replace "`r", "" -split "`n"
           foreach($line in $lines) {
               $color = ''
               foreach($pattern in $Colors.Keys){
                   if(!$SimpleMatch -and $line -match $pattern) { $color = $Colors[$pattern] }
                   elseif ($SimpleMatch -and $line -like $pattern) { $color = $Colors[$pattern] }
               }
               if($color) {
                   Write-Host -ForegroundColor $color $line
               } else {
                   Write-Host $line
               }
           }
       }
   
       Write-Host 'Checking if current user has potentially dangerous permissions' -ForegroundColor 'Yellow'
       whoami /priv | Format-Color @{
       'SeAssignPrimaryToken' = 'Red'
       'SeBackup' = 'Red'
       'SeCreateToken' = 'Red'
       'SeDebug' = 'Red'
       'SeRestore' = 'Red'
       'SeTakeOwnership' = 'Red'
       'SeTcb' = 'Red'
       'SeImpersonate' = 'Red'}
   }

   Function CheckWindowsVersion{

    $WindowsVersion = [System.Environment]::OSVersion.Version    
    Write-Host 'Checking current version of Windows' -ForegroundColor 'Yellow'
    ""
        If ($WindowsVersion -eq "10.0.19043.0")
        {Write-Host '[+] Windows version is latest' -ForegroundColor 'Green'}
        Else
        {Write-Host '[!] WINDOWS VERSION IS NOT LATEST ' -ForegroundColor 'Red'}
}
Function CheckAutoPlay{
    Write-Host 'Checking if AutoPlay is enabled for current user' -ForegroundColor 'Yellow'
    ""
        $CheckAutoPlay = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" | Select-Object -ExpandProperty 'DisableAutoplay'
            If ($CheckAutoPlay -match '1'){Write-Host '[+] AutoPlay is disabled for current user' -ForegroundColor 'Green'}
            If ($CheckAutoPlay -match '0'){Write-Host '[!] AutoPlay is enabled' -ForegroundColor 'Red'}
}
Function CheckAutoRun {
    Write-Host 'Checking if AutoRun is enabled for current user' -ForegroundColor 'Yellow'
    ""
    $CheckAutoRun = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Select-Object -ExpandProperty 'NoDriveTypeAutoRun'
           If ($CheckAutoRun -ne '0'){Write-Host '[!] AutoRun is enabled' -ForegroundColor 'Red'}Else
           {Write-Host '[+] AutoRun is disabled' -ForegroundColor 'Green'}
}
Function CheckIPV6{

$IPV6Description = '
By Default Windows is prone to IPV6 mitm attacks in which an attacker can masquerade as a DHCPv6 server. As Windows prefers IPV6 over IPv4 this means
an attacker can capture credentials. It is Recommended to disable IPV6 on the network unless a DHCPv6 server is actively in use.'
    
    
    Write-Host 'Checking if IPV6 adapters are enabled' -ForegroundColor 'Yellow'
    Write-Host ""
            $CheckIPV6 = Get-NetAdapterBinding -ComponentID ms_tcpip6
                If ($CheckIPV6.ComponentID -eq 'ms_tcpip6'){Write-Host '[!] Active IPV6 adapters have been found' -ForegroundColor 'Red' ; $CheckIPV6; Write-Host $IPV6Description -ForegroundColor 'Cyan'}Else
                    {Write-Host '[+] No IPV6 adapters have been found' -ForegroundColor 'Green'}  
}
Function SensitiveInformationSearch{

    Write-Host 'Searching user profiles for potentially sensitive information' -ForegroundColor 'Yellow'
    
    $Keywords = @(
    "pass*"
    "secret*"
    "key*"
    "cred*"
    "confidential"
    "Private"
    "money"
    "invoices"
    "bank"
    )
    
    $UserDirectories = Get-ChildItem -Path C:\Users -Recurse -Directory -Depth '20'
    foreach ($keyword in $Keywords)
        {Get-ChildItem -Path $UserDirectories.FullName $Keyword -Recurse -Verbose -ErrorAction 'SilentlyContinue' -Depth '0' | Select-Object 'Name', 'Directory'}
    }


    
# Execution Logic
CheckEncryption
""
CheckLaps
""
SMBChecks
""
CheckRunAs
""
CheckUserPrivileges
""
CheckWindowsVersion
""
CheckAutoPlay
""
CheckAutoRun
""
CheckIPV6
""
SensitiveInformationSearch
""

# References
#SMB protocol checks: https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3#how-to-detect-status-enable-and-disable-smb-protocols-on-the-smb-client



