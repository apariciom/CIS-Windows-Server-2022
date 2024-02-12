# CIS Azure Compute Microsoft Windows Server 2022 Benchmark 
# Script copied from Evan Greene at https://github.com/eneerge/CIS-Windows-Server-2022

##########################################################################################################
$LogonLegalNoticeMessageTitle = ""
$LogonLegalNoticeMessage = ""

# Set the max size of log files
$WindowsFirewallLogSize = 4*1024*1024 # Default for script is 4GB
$EventLogMaxFileSize = 4*1024*1024 # Default 4GB (for each log)
$WindowsDefenderLogSize = 1024MB

$AdminAccountPrefix = "DisabledUser" # Built-in admin account prefix. Numbers will be added to the end so that the built in admin account will be different on each server (account will be disabled after renaming)
$GuestAccountPrefix = "DisabledUser" # Build-in guest account prefix. Numbers will be added to the end so that the built in admin account will be different on each server (account will be disabled after renaming)
$NewLocalAdmin = "User" # Active admin account username (Local admin account that will be used to manage the server. Account will be active after script is run. This is not a prefix. It's the full account username)

#########################################################
# Compatibility Assurance 
# Set to true to ensure implemented policy supports functionality of a particular software
# Setting these to true will override any configurations you set in the "Policy Configuration" section below.
#########################################################
$AllowRDPFromLocalAccount = $true;            # CIS 2.2.26 - Set to true to oppose CIS recommendation and allow RDP from local account. This must be true or you will not be able to remote in using a local account. Enabling this removes local accounts from "Deny log on through Remote Desktop Services". If set to true, CIS Audit will report this as not being implemented, but you will be able to RDP using a local account which is a common requirement in most environments. (DenyRemoteDesktopServiceLogon)
$AllowRDPClipboard = $true;                   # CIS 18.9.65.3.3.3 - Set to true to oppose CIS recommendation and allow drive redirection so that copy/paste works to RDP sessions. This enables "Drive Redirection" feature so copy and paste in an RDP is allowed. A CIS audit will report this as not being implemented, but you will be able to copy/paste into an RDP session. (TerminalServicesfDisableCdm)
$AllowDefenderMAPS = $true;                   # CIS 18.9.47.4.2 - Set to true to oppose CIS recommendation and enable MAPS. CIS recommends disabling MAPs, but this reduces security by limiting cloud protection. Setting this true enables MAPs against the CIS recommendation. A CIS audit will report this as not being implemented, but you will receive better AV protection by going against the CIS recommendation. (SpynetReporting)
$AllowStoringPasswordsForTasks = $true        # CIS 2.3.10.4 - Set to true to oppose CIS recommendation and allow storing of passwords. CIS recommends disabling storage of passwords. However, this also prevents storing passwords required to run local batch jobs in the task scheduler. Setting this to true will disable this config. A CIS audit will report this as not being implemented, but saving passwords will be possible. (DisableDomainCreds)
$AllowAccessToSMBWithDifferentSPN = $true     # CIS 2.3.9.5 - Set to true to oppose CIS recommendation and allow SMB over unknown SPN. CIS recommends setting SPN validation to "Accept if provided by client." This can cause issues if you attempt to access a share using a different DNS name than the server currently recognizes. IE: If you have a non-domain joined computer and you access it using a DNS name that the server doesn't realize points to it, then the server will reject the connection. EG: Say you connect to "myserver.company.com", but the server's local name is just "myserver" and the server has no knowledge that it is also called "myserver.company.com" then the connection will be denied. (LanManServerSmbServerNameHardeningLevel)
$DontSetEnableLUAForVeeamBackup = $false       # CIS 2.3.17.6 - Set to true to oppose CIS recommendation and don't run all admins in Admin Approval Mode. CIS recommends setting this registry value to 1 so that all Admin users including the built in account must run in Admin Approval Mode (UAC popup always when running admin). However, this breaks Veeam Backup. See: https://www.veeam.com/kb4185
$DontSetTokenFilterPolicyForPSExec = $false    # CIS 18.3.1 - Set to true to oppose CIS recommendation and don't set require UAC for admins logging in over a network. Highly recommended to leave this $false unless you are legitimately using PSExec for any reason on the server. In addition, EnableLUA should also be disabled. See https://www.brandonmartinez.com/2013/04/24/resolve-access-is-denied-using-psexec-with-a-local-admin-account/

#########################################################
# Attack Surface Reduction Exclusions (Recommended)
# ASR will likely fire on legitimate software. To ensure server software runs properly, add exclusions to the executables or folders here.
#########################################################
$AttackSurfaceReductionExclusions = @(
    # Folder Example
    "C:\Program Files\RMM"
    
    # File Example
    "C:\some\folder\some.exe"
)

#########################################################
# Increase User Hardening (Optional)
# Add additional users that should not have a specific right to increase the hardening of this script.
#########################################################
$AdditionalUsersToDenyNetworkAccess = @(      #CIS 2.2.21 - This adds additional users to the "Deny access to this computer from the network" to add more than guest and built-in admin
  "batchuser"
)
$AdditionalUsersToDenyRemoteDesktopServiceLogon = @(  #CIS 2.2.26 - This adds additional users to the "Deny log on through Remote Desktop Services" if you want to exclude more than just the guest user
  "batchuser"
  ,"batchadmin"
)
$AdditionalUsersToDenyLocalLogon = @(         #CIS 2.2.24 - This adds additional users to the "Deny log on locally" if you want to exclude more than just the "guest" user.
  "batchuser"
  ,"batchadmin"
)


##########################################################################################################
# DO NOT CHANGE CODE BELLOW THIS LINE IF YOU ARE NOT 100% SURE ABOUT WHAT YOU ARE DOING!
##########################################################################################################

# Ensure the additional users specified for settings exist to prevent issues with applying policy
$existingUsers = (Get-LocalUser).Name
foreach ($u in $AdditionalUsersToDenyLocalLogon) {
  if (!$existingUsers.Contains($u)) {
    $AdditionalUsersToDenyLocalLogon = $AdditionalUsersToDenyLocalLogon | Where-Object { $_ -ne $u }
  }
}
foreach ($u in $AdditionalUsersToDenyRemoteDesktopServiceLogon) {
  if (!$existingUsers.Contains($u)) {
    $AdditionalUsersToDenyRemoteDesktopServiceLogon = $AdditionalUsersToDenyRemoteDesktopServiceLogon | Where-Object { $_ -ne $u }
  }
}
foreach ($u in $AdditionalUsersToDenyNetworkAccess) {
  if (!$existingUsers.Contains($u)) {
    $AdditionalUsersToDenyNetworkAccess = $AdditionalUsersToDenyNetworkAccess | Where-Object { $_ -ne $u }
  }
}

#WINDOWS SID CONSTANTS
#https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers

$SID_NOONE = "`"`""
$SID_ADMINISTRATORS = "*S-1-5-32-544"
$SID_GUESTS = "*S-1-5-32-546"
$SID_SERVICE = "*S-1-5-6"
$SID_NETWORK_SERVICE = "*S-1-5-20"
$SID_LOCAL_SERVICE = "*S-1-5-19"
$SID_LOCAL_ACCOUNT = "*S-1-5-113"
$SID_WINDOW_MANAGER_GROUP = "*S-1-5-90-0"
$SID_REMOTE_DESKTOP_USERS = "*S-1-5-32-555"
$SID_VIRTUAL_MACHINE = "*S-1-5-83-0"
$SID_AUTHENTICATED_USERS = "*S-1-5-11"
$SID_WDI_SYSTEM_SERVICE = "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
$SID_BACKUP_OPERATORS = "S-1-5-32-551"
$SID_IIS_IUSR = "S-1-5-17"
##########################################################################################################

#Registry Key Types

$REG_SZ = "String"
$REG_EXPAND_SZ = "ExpandString"
$REG_BINARY = "Binary"
$REG_DWORD = "DWord"
$REG_MULTI_SZ = "MultiString"
$REG_QWORD = "Qword"

##########################################################################################################


$global:valueChanges = @()

$fc = $host.UI.RawUI.ForegroundColor
$host.UI.RawUI.ForegroundColor = "White"

function Write-Info($text) {
    Write-Host $text -ForegroundColor Yellow
}

function Write-Before($text) {
    Write-Host $text -ForegroundColor Cyan
}

function Write-After($text) {
    Write-Host $text -ForegroundColor Green
}

function Write-Red($text) {
    Write-Host $text -ForegroundColor Red
}

function CheckError([bool] $result, [string] $message) {
  # Checks the specified result value and terminates the
  # the script after printing the specified error message 
  # if the specified result is false.
    if ($result -eq $false) {
        Write-Host $message -ForegroundColor Red
        throw $message
    }
}

function RegKeyExists([string] $path) {
  # Checks whether the specified registry key exists
  $result = Get-Item $path -ErrorAction SilentlyContinue
  $?
}

function SetRegistry([string] $path, [string] $key, [string] $value, [string] $keytype) {
  # Sets the specified registry value at the specified registry path to the specified value.
  # First the original value is read and print to the console.
  # If the original value does not exist, it is additionally checked
  # whether the according registry key is missing too.
  # If it is missing, the key is also created otherwise the 
  # Set-ItemProperty call would fail.
  #
  # The original implementation used try-catch to handle the errors
  # of Get-ItemProperty for missing values. However, Set-ItemProperty
  # is not throwing any exceptions. The error handling has to be done
  # by overwriting the -ErrorAction of the CmdLet and check the
  # $? variable afterwards.
  #
  # See: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters?view=powershell-7
  # See: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables?view=powershell-7

  $before = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
  
  if ($?) {
    Write-Before "Was: $($before.$key)"
  }
  else {
    Write-Before "Was: Not Defined!"
    $keyExists = RegKeyExists $path
    
    if ($keyExists -eq $false) {
      Write-Info "Creating registry key '$($path)'."
      New-Item $path -Force -ErrorAction SilentlyContinue
      CheckError $? "Creating registry key '$($path)' failed."
    }
  }

    Set-ItemProperty -Path $path -Name $key -Value $value -Type $keytype -ErrorAction SilentlyContinue

    CheckError $? "Creating registry value '$($path):$($value)' failed."
    
    $after = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
    Write-After "Now: $($after.$key)"

    if ($before.$key -ne $after.$key) {
        Write-Red "Value changed."
        $global:valueChanges += "$path => $($before.$key) to $($after.$key)"
    }
}

function DeleteRegistryValue([string] $path, [string] $key) {
  $before = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
  if ($?) {
    Write-Before "Was: $($before.$key)"
  }
  else {
    Write-Before "Was: Not Defined!"
  }

  Remove-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue

  $after = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue

  if ($?) {
    Write-After "Now: $($after.$key)"
  }
  else {
    Write-After "Now: Not Defined!"
  }

  if ($before.$key -ne $after.$key) {
    Write-Red "Value changed."
    $global:valueChanges += "$path => $($before.$key) to $($after.$key)"
  }
}

# Resets the security policy
function ResetSec {
  secedit /configure /cfg C:\windows\inf\defltbase.inf /db C:\windows\system32\defltbase.sdb /verbose
}

function SetSecEdit([string]$role, [string[]] $values, $area, $enforceCreation) {
    $valueSet = $false

    if($null -eq $values) {
        Write-Error "SetSecEdit: At least one value must be provided to set the role:$($role)"
        return
    }
    
    if($null -eq $enforceCreation){
        $enforceCreation = $true
    }

    secedit /export /cfg ${env:appdata}\secpol.cfg /areas $area
    CheckError $? "Exporting '$($area)' to $(${env:appdata})\secpol.cfg' failed."
  
    $lines = Get-Content ${env:appdata}\secpol.cfg

    $config = "$($role) = "
    for($r =0; $r -lt $values.Length; $r++){
        # If null, skip
        if ($values[$r] -eq $null -or $values[$r].trim() -eq "") {
            continue
        }
        # last iteration
        if($r -eq $values.Length -1) {
            if ($values[$r].trim() -ne "") {
                $config = "$($config)$($values[$r])"
            }
        } 
        # not last (include a comma)
        else {
           $global:val += $values[$r]
            if ($values[$r].trim() -ne "") {
              $config = "$($config)$($values[$r]),"
            }
        }
    }
    if ($role -notlike "*LogonLegalNotice*") {
        $config = $config.Trim(",")
    }
    
    for($i =0; $i -lt $lines.Length; $i++) {
        if($lines[$i].Contains($role)) {
            $before = $($lines[$i])
            Write-Before "Was: $before"
            
            $lines[$i] = $config
            $valueSet = $true
            Write-After "Now: $config"
            
            if ($config.Replace(" ","").Trim(",") -ne $before.Replace(" ","").Trim(",")) {
                Write-Red "Value changed."
                $global:valueChanges += "$before => $config"
            }

            break;
        }
    }

    if($enforceCreation -eq $true){
        if($valueSet -eq $false) {
            Write-Before "Was: Not Defined"

            # If a configuration option does not exist and comes before the [version] tag, it will not be applied, but if we add it before the [version] tag, it gets applied
            $lines = $lines | Where-Object {$_ -notin ("[Version]",'signature="$CHICAGO$"',"Revision=1")}
            $lines += $config

            $after = $($lines[$lines.Length -1])
            Write-After "Now: $($after)"

            if ($after -ne "$($role) = `"`"") {
                    Write-Red "Value changed."
                    $global:valueChanges += "Not defined => $after"
            }

            # Rewrite the version tag
            $lines += "[Version]"
            $lines += 'signature="$CHICAGO$"'
            $lines += "Revision=1"
        }
    }

    $lines | out-file ${env:appdata}\secpol.cfg

    secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas $area
    CheckError $? "Configuring '$($area)' via $(${env:appdata})\secpol.cfg' failed."
  
    Remove-Item -force ${env:appdata}\secpol.cfg -confirm:$false
}

function SetUserRight([string]$role, [string[]] $values, $enforceCreation=$true) {
    SetSecEdit $role $values "User_Rights" $enforceCreation
}

function SetSecurityPolicy([string]$role, [string[]] $values, $enforceCreation=$true) {
    SetSecEdit $role $values "SecurityPolicy" $enforceCreation 
}

function CreateASRExclusions {
    Write-Info "Creating Attack Surface Reduction Exclusions"

    #Clear current exclusions
    $currentExclusions = (Get-MpPreference).AttackSurfaceReductionOnlyExclusions
    foreach ($e in $currentExclusions) {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $e
    }

    # Create the ASR exclusions
    foreach ($e in $AttackSurfaceReductionExclusions) {
      if (Test-Path $e) {
        Write-Host "Excluding: " $e
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions $e
      }
    }
}

function SetWindowsDefenderLogSize {
    $log = Get-LogProperties "Microsoft-Windows-Windows Defender/Operational"
    $log.MaxLogSize = $WindowsDefenderLogSize
    Set-LogProperties -LogDetails $log
}

function CreateUserAccount([string] $username, [securestring] $password, [bool] $isAdmin=$false) {
    $NewLocalAdminExists = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if ($NewLocalAdminExists) {
        Write-Red "Skipping creating new Administrator account"
        Write-Red "- New Administrator account already exists: $($username)"
    }
    else {
        New-LocalUser -Name $username -Password $password -Description "" -AccountNeverExpires -PasswordNeverExpires
        Write-Info "New Administrator account created: $($username)."
        if($isAdmin -eq $true) {
            Add-LocalGroupMember -Group "Administrators" -Member $username
            Write-Info "Administrator account $($username) is now member of the local Administrators group."
        }

        $global:rebootRequired = $true
    }
}

function CreateNewLocalAdminAccount {
    CreateUserAccount $NewLocalAdmin $NewLocalAdminPassword $true
}

function EnforcePasswordHistory
{
    #1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Scored)
    Write-Info "1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Scored)"
    Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Length of password history maintained' )
    Write-After ("After hardening: *******                   ")
    net accounts /uniquepw:24
}


function MaximumPasswordAge
{
    #1.1.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Maximum password age
    #1.1.2 (L1) Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'
    Write-Info "1.1.2 (L1) Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"
    Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Maximum password age' )
    Write-After ("After hardening: *******                   ")
    net accounts /maxpwage:365
}


function MinimumPasswordAge
{
    #1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)' (Scored)
    Write-Info "1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)' (Scored)"
    Write-Before ("Before hardening: *******               ")
    Write-Output (net accounts | Select-String -SimpleMatch 'Minimum password age' )
    Write-After ("After hardening: *******                   ")
    net accounts /minpwage:1
}


function MinimumPasswordLength
{

    #1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)' (Scored)
    Write-Info "1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)' (Scored)"
    Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Minimum password length')
    Write-After ("After hardening: *******                   ")
    net accounts /MINPWLEN:14
}

function WindowsPasswordComplexityPolicyMustBeEnabled
{
    #1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Scored)
    Write-Info "1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Scored)"
    secedit /export /cfg ${env:appdata}\secpol.cfg
    (Get-Content ${env:appdata}\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Out-File ${env:appdata}\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -force ${env:appdata}\secpol.cfg -confirm:$false
}

function DisablePasswordReversibleEncryption {

    #1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (Scored)
    Write-Info "1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (Scored)"
    secedit /export /cfg ${env:appdata}\secpol.cfg
    (Get-Content ${env:appdata}\secpol.cfg).replace("ClearTextPassword = 1", "ClearTextPassword = 0") | Out-File ${env:appdata}\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -force ${env:appdata}\secpol.cfg -confirm:$false
}


function NoOneTrustCallerACM {
    #2.2.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access Credential Manager as a trusted caller
    Write-Info "2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' (Scored)"
    SetUserRight "SeTrustedCredManAccessPrivilege" @($SID_NOONE)
}

function AccessComputerFromNetwork {
    #2.2.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access this computer from the network
    Write-Info "2.2.3 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users"
    SetUserRight "SeNetworkLogonRight" ($SID_ADMINISTRATORS, $SID_AUTHENTICATED_USERS)
}

function NoOneActAsPartOfOperatingSystem {
    #2.2.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Act as part of the operating system
    Write-Info "2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One' (Scored)"
    SetUserRight "SeTcbPrivilege" @($SID_NOONE)
}

function AdjustMemoryQuotasForProcess {
    #2.2.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Adjust memory quotas for a process
    Write-Info "2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
    SetUserRight "SeIncreaseQuotaPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE, $SID_ADMINISTRATORS)
}

function AllowLogonLocallyToAdministrators {
    #2.2.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on locally
    Write-Info "2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'"
    SetUserRight "SeInteractiveLogonRight" (,$SID_ADMINISTRATORS)
}

function LogonThroughRemoteDesktopServices {
    #2.2.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on through Remote Desktop Services
    Write-Info "2.2.9 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
    SetUserRight "SeRemoteInteractiveLogonRight" ($SID_ADMINISTRATORS, $SID_REMOTE_DESKTOP_USERS)
}


function BackupFilesAndDirectories {
    #2.2.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Back up files and directories
    Write-Info "2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'"
    SetUserRight "SeBackupPrivilege" (,$SID_ADMINISTRATORS)
}

function ChangeSystemTime {
    #2.2.11 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the system time
    Write-Info "2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
    SetUserRight "SeSystemtimePrivilege" ($SID_LOCAL_SERVICE,$SID_ADMINISTRATORS)
}

function ChangeTimeZone {
    #2.2.12 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the time zone
    Write-Info "2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
    SetUserRight "SeTimeZonePrivilege" ($SID_LOCAL_SERVICE,$SID_ADMINISTRATORS)
}

function CreatePagefile {
    #2.2.13 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a pagefile
    Write-Info "2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'"
    SetUserRight "SeCreatePagefilePrivilege" (,$SID_ADMINISTRATORS)
}

function NoOneCreateTokenObject {
    #2.2.14 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a token object
    Write-Info "2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'"
    SetUserRight "SeCreateTokenPrivilege" @($SID_NOONE)
}

function CreateGlobalObjects {
    #2.2.15 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create global objects
    Write-Info "2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
    SetUserRight "SeCreateGlobalPrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE,$SID_ADMINISTRATORS,$SID_SERVICE)
}


function NoOneCreatesSharedObjects {
    #2.2.16 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create permanent shared objects
    Write-Info "2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'"
    SetUserRight "SeCreatePermanentPrivilege" @($SID_NOONE)
}

function CreateSymbolicLinks {
    #2.2.18 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create symbolic links
    #Check if Hyper-V is installed before deploying the setting, so no unrecognized SID will be added when Hyper-V is not installed
    if ((Get-WindowsFeature -Name Hyper-V).Installed -eq $false)
    {
        Write-Info "2.2.18 (L1) Ensure 'Create symbolic links' is set to 'Administrators'"
        SetUserRight "SeCreateSymbolicLinkPrivilege" (,$SID_ADMINISTRATORS)
    }
    else {
        Write-Info "2.2.18 (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'"
        SetUserRight "SeCreateSymbolicLinkPrivilege" ($SID_ADMINISTRATORS,$SID_VIRTUAL_MACHINE)
    }
}

function DebugPrograms {
    #2.2.19 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Debug programs
    Write-Info "2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'"
    SetUserRight "SeDebugPrivilege" (,$SID_ADMINISTRATORS)
}



function DenyNetworkAccess {
    #2.2.20 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny access to this computer from the network
    Write-Info "2.2.20 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account, and member of Administrators group'"

    $addlDenyUsers = ""
    if ($AdditionalUsersToDenyNetworkAccess.Count -gt 0) {
      $addlDenyUsers = $AdditionalUsersToDenyNetworkAccess -join ","
    }

    if ($AllowRDPFromLocalAccount -eq $true) {
        SetUserRight "SeDenyNetworkLogonRight" ($($global:AdminNewAccountName),$addlDenyUsers,$($SID_GUESTS))
    }
    else {
        SetUserRight "SeDenyNetworkLogonRight" ($($global:AdminNewAccountName),$addlDenyUsers,$SID_LOCAL_ACCOUNT,$($SID_GUESTS))
    }
}

function DenyGuestBatchLogon {
    #2.2.21 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a batch job
    Write-Info "2.2.21 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
    SetUserRight "SeDenyBatchLogonRight" (,$SID_GUESTS)
}

function DenyGuestServiceLogon {
    #2.2.22 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a service
    Write-Info "2.2.22 (L1) Ensure 'Deny log on as a service' to include 'Guests'"
    SetUserRight "SeDenyServiceLogonRight" (,$SID_GUESTS)
}

function DenyGuestLocalLogon {
    #2.2.23 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on locally
    Write-Info "2.2.23 (L1) Ensure 'Deny log on locally' to include 'Guests'"

    $addlDenyUsers = ""
    if ($AdditionalUsersToDenyLocalLogon.Count -gt 0) {
      $addlDenyUsers = $AdditionalUsersToDenyLocalLogon -join ","
    }

    SetUserRight "SeDenyInteractiveLogonRight" ($addlDenyUsers,$SID_GUESTS)
}

function DenyRemoteDesktopServiceLogon {
    #2.2.24 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Remote Desktop Services
    Write-Info "2.2.24 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'"

    $addlDenyUsers = ""
    if ($AdditionalUsersToDenyRemoteDesktopServiceLogon.Count -gt 0) {
      $addlDenyUsers = $AdditionalUsersToDenyRemoteDesktopServiceLogon -join ","
    }


    if ($AllowRDPFromLocalAccount -eq $true) {
      SetUserRight "SeDenyRemoteInteractiveLogonRight" ($SID_GUESTS,$addlDenyUsers)
    }
    else {
      SetUserRight "SeDenyRemoteInteractiveLogonRight" ($SID_GUESTS,$addlDenyUsers,$SID_LOCAL_ACCOUNT)
    }
}









function NoOneTrustedForDelegation {
    #2.2.26 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Enable computer and user accounts to be trusted for delegation
    Write-Info "2.2.26 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
    SetUserRight "SeDelegateSessionUserImpersonatePrivilege" @($SID_NOONE)
}

function ForceShutdownFromRemoteSystem {
    #2.2.27 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Force shutdown from a remote system
    Write-Info "2.2.27 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
    SetUserRight "SeRemoteShutdownPrivilege" (,$SID_ADMINISTRATORS)
}

function GenerateSecurityAudits {
    #2.2.28 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Generate security audits
    Write-Info "2.2.28 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE' (Scored)"
    SetUserRight "SeAuditPrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE)
}

# TODO : ADD IIS_IUSRS
function ImpersonateClientAfterAuthentication {
    #2.2.30 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Impersonate a client after authentication
    Write-Info "2.2.30 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS'"
    SetUserRight "SeImpersonatePrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE,$SID_ADMINISTRATORS,$SID_SERVICE)
}

function IncreaseSchedulingPriority {
    #2.2.31 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Increase scheduling priority
    Write-Info "2.2.31 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
    SetUserRight "SeIncreaseBasePriorityPrivilege" ($SID_ADMINISTRATORS,$SID_WINDOW_MANAGER_GROUP)
}

function LoadUnloadDeviceDrivers {
    #2.2.32 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Load and unload device drivers
    Write-Info "2.2.32 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
    SetUserRight "SeLoadDriverPrivilege" (,$SID_ADMINISTRATORS)
}

function NoOneLockPagesInMemory {
    #2.2.33 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Lock pages in memory
    Write-Info "2.2.33 (L1) Ensure 'Lock pages in memory' is set to 'No One'"
    SetUserRight "SeLockMemoryPrivilege" @($SID_NOONE)
}

function ManageAuditingAndSecurity {
    #2.2.35 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Manage auditing and security log
    Write-Info "2.2.35 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'"
    SetUserRight "SeSecurityPrivilege" @($SID_ADMINISTRATORS)
}

function NoOneModifiesObjectLabel {
    #2.2.36 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Modify an object label
    Write-Info "2.2.36 (L1) Ensure 'Modify an object label' is set to 'No One'"
    SetUserRight "SeRelabelPrivilege" @($SID_NOONE)
}

function FirmwareEnvValues {
    #2.2.37 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Modify firmware environment values
    Write-Info "2.2.37 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
    SetUserRight "SeSystemEnvironmentPrivilege" (,$SID_ADMINISTRATORS)
}

function VolumeMaintenance {
    #2.2.38 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Perform volume maintenance tasks
    Write-Info "2.2.38 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
    SetUserRight "SeManageVolumePrivilege" (,$SID_ADMINISTRATORS)

}

function ProfileSingleProcess {
    #2.2.39 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Profile single process
    Write-Info "2.2.39 (L1) Ensure 'Profile single process' is set to 'Administrators'"
    SetUserRight "SeProfileSingleProcessPrivilege" (,$SID_ADMINISTRATORS)
}

function ProfileSystemPerformance {
    #2.2.40 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Profile system performance
    Write-Info "2.2.40 (L1) Ensure 'Profile system performance' is set to 'Administrators,NT SERVICE\WdiServiceHost'"
    SetUserRight "SeSystemProfilePrivilege" ($SID_ADMINISTRATORS,$SID_WDI_SYSTEM_SERVICE)
}

function ReplaceProcessLevelToken {
    #2.2.41 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Replace a process level token
    Write-Info "2.2.41 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
    SetUserRight "SeAssignPrimaryTokenPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE)
}

function RestoreFilesDirectories {
    #2.2.42 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Restore files and directories
    Write-Info "2.2.42 (L1) Ensure 'Restore files and directories' is set to 'Administrators'"
    SetUserRight "SeRestorePrivilege" (,$SID_ADMINISTRATORS)
}

function SystemShutDown {
    #2.2.43 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Shut down the system
    Write-Info "2.2.43 (L1) Ensure 'Shut down the system' is set to 'Administrators, Backup Operators'"
    SetUserRight "SeShutdownPrivilege" (,$SID_ADMINISTRATORS,$SID_BACKUP_OPERATORS)
}

function TakeOwnershipFiles {
    #2.2.45 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Take ownership of files or other objects
    Write-Info "2.2.45 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
    SetUserRight "SeTakeOwnershipPrivilege" (,$SID_ADMINISTRATORS)
}

function DisableAdministratorAccount {
    #2.3.1.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Administrator account status
    Write-Info "2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
    SetSecurityPolicy "EnableAdminAccount" (,"0")
}

function DisableMicrosoftAccounts {
    #2.3.1.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Block Microsoft accounts
    Write-Info "2.3.1.1 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser" (,"4,3")
}

function DisableGuestAccount {
    #2.3.1.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Guest account status
    Write-Info "2.3.1.2 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'"
    SetSecurityPolicy "EnableGuestAccount" (,"0")
}


function LimitBlankPasswordConsole {
    #2.3.1.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Limit local account use of blank passwords to console logon only
    Write-Info "2.3.1.3 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" (,"4,1")
}


# TODO : Need to Test
function RenameAdministratorAccount {
    #2.3.1.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename administrator account
    $CurrentAdminUser = (Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE and SID like 'S-1-5-%-500'").Name
    $CurrentAdminPrefix = $CurrentAdminUser.substring(0,($CurrentAdminUser.Length-4)) # Remove the random seed from the end

    # If the current admin user prefix matches the configured admin user prefix, we should skip this section.
    if ($CurrentAdminUser.Length -eq ($AdminAccountPrefix.Length + 4) -and 
        $CurrentAdminPrefix -eq $AdminAccountPrefix
    ) {
        Write-Red "Skipping 2.3.1.4 (L1) Configure 'Accounts: Rename administrator account'"
        Write-Red "- Administrator account already renamed: $($CurrentAdminUser)."

        return
    }

    # Prefix doesn't match, continue renaming...
    $seed = Get-Random -Minimum 1000 -Maximum 9999   #Randomize the new admin and guest accounts on each system. 4-digit random number.
    $global:AdminNewAccountName = "$($AdminAccountPrefix)$($seed)"
    
    Write-Info "2.3.1.4 (L1) Configure 'Accounts: Rename administrator account'"
    Write-Info "- Renamed to $($global:AdminNewAccountName)"
    SetSecurityPolicy "NewAdministratorName" (,"`"$($global:AdminNewAccountName)`"")
    Set-LocalUser -Name $global:AdminNewAccountName -Description ""
}


# TODO : Need to test
function RenameGuestAccount {
    #2.3.1.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename guest account
    $CurrentGuestUser = (Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE and SID like 'S-1-5-%-501'").Name
    $CurrentGuestPrefix = $CurrentGuestUser.substring(0,($CurrentGuestUser.Length-4)) # Remove the random seed from the end

    # If the current guest user prefix matches the configured guest user prefix, we should skip this section.
    if ($CurrentGuestUser.Length -eq ($CurrentGuestPrefix.Length + 4) -and 
        $CurrentGuestPrefix -eq $GuestAccountPrefix
    ) {
        Write-Red "Skipping 2.3.1.5 (L1) Configure 'Accounts: Rename guest account'"
        Write-Red "- Guest account already renamed: $($CurrentGuestUser)"

        return
    }

    # Prefix doesn't match, continue renaming...
    $seed = Get-Random -Minimum 1000 -Maximum 9999   #Randomize the new admin and guest accounts on each system. 4-digit random number.
    $GuestNewAccountName = "$($GuestAccountPrefix)$($seed)"
    
    Write-Info "2.3.1.5 (L1) Configure 'Accounts: Rename guest account'"
    Write-Info "- Renamed to $($GuestNewAccountName)"
    SetSecurityPolicy "NewGuestName" (,"`"$($GuestNewAccountName)`"")
    Set-LocalUser -Name $GuestNewAccountName -Description ""
}



function AuditForceSubCategoryPolicy {
    #2.3.2.1 =>Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings
    Write-Info "2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings to override audit policy category settings' is set to 'Enabled' "
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy" (,"4,1")
}

function AuditForceShutdown {
    #2.3.2.2 Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Audit: Shut down system immediately if unable to log security audits
    Write-Info "2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail" (,"4,0")
}


function DevicesAdminAllowedFormatEject {
    #2.3.4.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Devices: Allowed to format and eject removable media
    Write-Info "2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD" (,"1,`"0`"")
}

function PreventPrinterInstallation {
    #2.3.4.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Devices: Prevent users from installing printer drivers
    Write-Info "2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers'is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers" (,"4,1")
}

function SignEncryptAllChannelData {
    #2.3.6.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally encrypt or sign secure channel data (always)
    Write-Info "2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal" (,"4,1")
}

function SecureChannelWhenPossible {
    #2.3.6.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally encrypt secure channel data (when possible)
    Write-Info "2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel" (,"4,1")
}

function DigitallySignChannelWhenPossible {
    #2.3.6.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally sign secure channel data (when possible)
    Write-Info "2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel" (,"4,1")
}

function EnableAccountPasswordChanges {
    #2.3.6.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Disable machine account password changes
    Write-Info "2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange" (,"4,0")
}


function MaximumAccountPasswordAge {
    #2.3.6.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Maximum machine account password age
    Write-Info "2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge" (,"4,30")
}


function MachineInactivityLimit {
    #2.3.7.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Machine inactivity limit
    Write-Info "2.3.7.1 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0' "
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs" (,"4,900")
}

function LogonLegalNotice {
    #2.3.7.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message text for users attempting to log on
    Write-Info "2.3.7.2 (L1) Configure 'Interactive logon: Message text for users attempting to log on'"
    if ($LogonLegalNoticeMessage.Length -gt 0) {
        SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText" ("7",$LogonLegalNoticeMessage)
    }
    else {
        SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText" ("7,")
    }
}

function LogonLegalNoticeTitle {
    #2.3.7.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message title for users attempting to log on
    Write-Info "2.3.7.3 (L1) Configure 'Interactive logon: Message title for users attempting to log on'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption" (,"1,`"$($LogonLegalNoticeMessageTitle)`"")
}

function PromptUserPassExpiration {
    #2.3.7.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Prompt user to change password before expiration
    Write-Info "2.3.7.4 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning" (,"4,5")
}