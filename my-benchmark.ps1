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

function NetworkClientSignCommunications {
    #2.3.8.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Digitally sign communications (always)
    Write-Info "2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature" (,"4,1")
}


function EnableSecuritySignature {
    #2.3.8.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Digitally sign communications (if server agrees)
    Write-Info "2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' "
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" "1" $REG_DWORD
}

function DisableSmbUnencryptedPassword {
    #2.3.8.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Send unencrypted password to third-party SMB servers
    Write-Info "2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword" (,"4,0")
}

function IdleTimeSuspendingSession {
    #2.3.9.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Amount of idle time required before suspending session
    Write-Info "2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect" (,"4,15")
}

function NetworkServerAlwaysDigitallySign {
    #2.3.9.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Digitally sign communications (always)
    Write-Info "2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature" (,"4,1")
}

function LanManSrvEnableSecuritySignature{
    #2.3.9.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Digitally sign communications (if client agrees)
    Write-Info "2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "EnableSecuritySignature" "1" $REG_DWORD
}

function LanManServerEnableForcedLogOff {
    #2.3.9.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Disconnect clients when logon hours expire
    Write-Info "2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff" (,"4,1")
}

function LanManServerSmbServerNameHardeningLevel {
    #2.3.9.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Server SPN target name validation level
    if ($AllowAccessToSMBWithDifferentSPN -eq $false) {
        Write-Info "2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
        SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel" (,"4,1")
    }
    else {
        Write-Red "Opposing 2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
        Write-Red "- You enabled $AllowAccessToSMBWithDifferentSPN. This CIS configuration has been altered so that SMB shares can be accessed by SPNs unknown to the server."
        SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel" (,"4,0")
    }
}

function LSAAnonymousNameDisabled {
    #2.3.10.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Allow anonymous SID/Name translation
    Write-Info "2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
    SetSecurityPolicy "LSAAnonymousNameLookup" (,"0")
    SetRegistry "HKLM:\System\CurrentControlSet\Control\Lsa" "TurnOffAnonymousBlock" "1" $REG_DWORD
}

function RestrictAnonymousSAM {
    #2.3.10.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow anonymous enumeration of SAM accounts
    Write-Info "2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM" (,"4,1")
}

function RestrictAnonymous {
    #2.3.10.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow anonymous enumeration of SAM accounts and shares
    Write-Info "2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous" (,"4,1")
}

function EveryoneIncludesAnonymous {
    #2.3.10.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Let Everyone permissions apply to anonymous users
    Write-Info "2.3.10.4 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous" (,"4,0")
}

function NullSessionPipes {
    #2.3.10.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Named Pipes that can be accessed anonymously
    Write-Info "2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes" ("7,", " ")
}

function AllowedExactPaths {
    #2.3.10.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths
    Write-Info "2.3.10.7 (L1) Configure 'Network access: Remotely accessible registry paths'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine" (
        "7",
        "System\CurrentControlSet\Control\ProductOptions",
        "System\CurrentControlSet\Control\Server Applications",
        "Software\Microsoft\Windows NT\CurrentVersion")
}

function AllowedPaths {
    #2.3.10.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths and sub-paths
    Write-Info "2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine" (
        "7",
        "System\CurrentControlSet\Control\Print\Printers",
        "System\CurrentControlSet\Services\Eventlog",
        "Software\Microsoft\OLAP Server",
        "Software\Microsoft\Windows NT\CurrentVersion\Print",
        "Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "System\CurrentControlSet\Control\ContentIndex",
        "System\CurrentControlSet\Control\Terminal Server",
        "System\CurrentControlSet\Control\Terminal Server\UserConfig",
        "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
        "Software\Microsoft\Windows NT\CurrentVersion\Perflib",
        "System\CurrentControlSet\Services\SysmonLog")
}

function RestrictNullSessAccess {
    #2.3.10.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Restrict anonymous access to Named Pipes and Shares
    Write-Info "2.3.10.9 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess" (,"4,1")
}

function RestrictRemoteSAM {
    #2.3.10.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Restrict clients allowed to make remote calls to SAM
    Write-Info "2.3.10.10 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM" (,'1,"O:BAG:BAD:(A;;RC;;;BA)"')
}

function NullSessionShares {
    #2.3.10.11 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Shares that can be accessed anonymously
    Write-Info "2.3.10.11 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares" (,"7,")
}

function LsaForceGuest {
    #2.3.10.12 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Sharing and security model for local accounts
    Write-Info "2.3.10.12 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest" (,"4,0")
}

function LsaUseMachineId {
    #2.3.11.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Allow Local System to use computer identity for NTLM
    Write-Info "2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId" (,"4,1")
}

function AllowNullSessionFallback {
    #2.3.11.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Allow LocalSystem NULL session fallback
    Write-Info "2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback" (,"4,0")
}

function AllowOnlineID {
    #2.3.11.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network Security: Allow PKU2U authentication requests to this computer to use online identities
    Write-Info "2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID" (,"4,0")
}

function SupportedEncryptionTypes {
    #2.3.11.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Configure encryption types allowed for Kerberos
    Write-Info "2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes" (,"4,2147483640")
}

function NoLMHash {
    #2.3.11.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Do not store LAN Manager hash value on next password change 
    Write-Info "2.3.11.5 Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash" (,"4,1")
}

function LmCompatibilityLevel {
    #2.3.11.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LAN Manager authentication level
    Write-Info "2.3.11.6 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel" (,"4,5")
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" "5" $REG_DWORD
}

function LDAPClientIntegrity {
    #2.3.11.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LDAP client signing requirements
    Write-Info "2.3.11.7 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity" (,"4,1")
}

function NTLMMinClientSec {
    #2.3.11.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
    Write-Info "2.3.11.8 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec" (,"4,537395200")
}

function NTLMMinServerSec {
    #2.3.11.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
    Write-Info "2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec" (,"4,537395200")
}

function ShutdownWithoutLogon {
    #2.3.13.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Shutdown: Allow system to be shut down without having to log on
    Write-Info "2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon" (,"4,0")
}

function ObCaseInsensitive {
    #2.3.15.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\System objects: Require case insensitivity for non Windows subsystems
    Write-Info "2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for nonWindows subsystems' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive" (, "4,1")
}

function SessionManagerProtectionMode {
    #2.3.15.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
    Write-Info "2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode" (,"4,1")
}

function FilterAdministratorToken {
    #2.3.17.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Admin Approval Mode for the Built-in Administrator account
    Write-Info "2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken" (,"4,1")
}

function ConsentPromptBehaviorAdmin {
    #2.3.17.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
    Write-Info "2.3.17.2 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" (,"4,2")
}


function ConsentPromptBehaviorUser {
    #2.3.17.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for standard users
    Write-Info "2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser" (,"4,0")
}

function EnableInstallerDetection {
    #2.3.17.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Detect application installations and prompt for elevation
    Write-Info "2.3.17.4 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection" (,"4,1")
}

function EnableSecureUIAPaths {
    #2.3.17.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Only elevate UIAccess applications that are installed in secure location
    Write-Info "2.3.17.5 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths" (, "4,1")
}

function EnableLUA {
    #2.3.17.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Run all administrators in Admin Approval Mode    
    if ($DontSetEnableLUAForVeeamBackup -eq $false) {
        Write-Info "2.3.17.6 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
        SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" (, "4,1")
    }
    else {
        Write-Red "Opposing 2.3.17.6 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
        Write-Red "- You enabled $DontSetEnableLUAForVeeamBackup. This setting has been opposed and set to 0 against CIS recommendations, but Veeam Backup will be able to perform backup operations."
        SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" (, "4,0")
    }
}

function PromptOnSecureDesktop {
    #2.3.17.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Switch to the secure desktop when prompting for elevation
    Write-Info "2.3.17.7 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop" (, "4,1")
}


function EnableVirtualization {
    #2.3.17.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Virtualize file and registry write failures to per-user locations
    Write-Info "2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization" (, "4,1")
}


function DisableSpooler {
    #5.2 => Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Print Spooler
    Write-Info "5.2 (L2) Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only)"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" "Start" "4" $REG_DWORD
}

function DomainEnableFirewall {
    #9.1.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Firewall state
    Write-Info "9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall" "1" $REG_DWORD
}

function DomainDefaultInboundAction {
    #9.1.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Inbound connection 
    Write-Info "9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultInboundAction" "1" $REG_DWORD
}

function DomainDefaultOutboundAction {
    #9.1.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Outbound connections 
    Write-Info "9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultOutboundAction" "0" $REG_DWORD
}

function DomainLogFilePath {
    #9.1.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Name
    Write-Info "9.1.4 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\domainfw.log" $REG_SZ
}

function DomainLogFileSize {
    #9.1.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Size limit (KB) 
    Write-Info "9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFileSize" $WindowsFirewallLogSize $REG_DWORD
}

function DomainLogDroppedPackets {
    #9.1.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Log dropped packets
    Write-Info "9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogDroppedPackets" "1" $REG_DWORD
}

function DomainLogSuccessfulConnections {
    #9.1.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Logging Customize\Log successful connections 
    Write-Info "9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogSuccessfulConnections" "1" $REG_DWORD
}


function PrivateEnableFirewall {
    #9.2.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Firewall state
    Write-Info "9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall" "1" $REG_DWORD
}

function PrivateDefaultInboundAction {
    #9.2.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Inbound connection 
    Write-Info "9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultInboundAction" "1" $REG_DWORD
}

function PrivateDefaultOutboundAction {
    #9.2.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Outbound connections 
    Write-Info "9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultOutboundAction" "0" $REG_DWORD
}

function PrivateLogFilePath {
    #9.2.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Name
    Write-Info "9.2.4 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\privatefw.log" $REG_SZ
}

function PrivateLogFileSize {
    #9.2.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Size limit (KB) 
    Write-Info "9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize" $WindowsFirewallLogSize $REG_DWORD
}

function PrivateLogDroppedPackets {
    #9.2.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Log dropped packets
    Write-Info "9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets" "1" $REG_DWORD
}

function PrivateLogSuccessfulConnections {
    #9.2.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Private Profile\Logging Customize\Log successful connections 
    Write-Info "9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" "1" $REG_DWORD
}

function PublicEnableFirewall {
    #9.3.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Firewall state
    Write-Info "9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "EnableFirewall" "1" $REG_DWORD
}

function PublicDefaultInboundAction {
    #9.3.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Inbound connection 
    Write-Info "9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultInboundAction" "1" $REG_DWORD
}


function PublicDefaultOutboundAction {
    #9.3.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Outbound connections 
    Write-Info "9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultOutboundAction" "0" $REG_DWORD
}


function PublicLogFilePath {
    #9.3.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Name
    Write-Info "9.3.4 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\publicfw.log" $REG_SZ
}

function PublicLogFileSize {
    #9.3.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Size limit (KB) 
    Write-Info "9.3.5 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFileSize" $WindowsFirewallLogSize $REG_DWORD
}

function PublicLogDroppedPackets {
    #9.3.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Log dropped packets
    Write-Info "9.3.6 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogDroppedPackets" "1" $REG_DWORD
}

function PublicLogSuccessfulConnections {
    #9.3.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Public Profile\Logging Customize\Log successful connections 
    Write-Info "9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogSuccessfulConnections" "1" $REG_DWORD
}

function AuditCredentialValidation {
    #17.1.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Logon\Audit Credential Validation
    Write-Info "17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
}

function AuditComputerAccountManagement {
    #17.2.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit Application Group Management
    Write-Info "17.2.4 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
}

function AuditUserAccountManagement {
    #17.2.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit User Account Management 
    Write-Info "17.2.5 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
}

function AuditPNPActivity {
    #17.3.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Detailed Tracking\Audit PNP Activity
    Write-Info "17.3.1 (L1) Ensure 'Audit PNP Activity' is set to include 'Success'"
    Auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable
}

function AuditProcessCreation {
    #17.3.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Detailed Tracking\Audit Process Creation
    Write-Info "17.3.2 (L1) Ensure 'Audit Process Creation' is set to include 'Success'"
    Auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
}

function AuditAccountLockout {
    #17.5.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Account Lockout
    Write-Info "17.5.1 (L1) Ensure 'Audit Account Lockout' is set to include 'Failure'"
    Auditpol /set /subcategory:"Account Lockout" /success:disable /failure:enable
}

function AuditGroupMembership  {
    #17.5.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Group Membership
    Write-Info "17.5.2 (L1) Ensure 'Audit Group Membership' is set to include 'Success'"
    Auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable
}

function AuditLogoff {
    #17.5.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Logoff
    Write-Info "17.5.3 (L1) Ensure 'Audit Logoff' is set to include 'Success'"
    Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
}

function AuditLogon {
    #17.5.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Logon 
    Write-Info "17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
} 

function AuditOtherLogonLogoffEvents {
    #17.5.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Other Logon/Logoff Events
    Write-Info "17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
}

function AuditSpecialLogon {
    #17.5.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff\Audit Special Logon
    Write-Info "17.5.6 (L1) Ensure 'Audit Special Logon' is set to include 'Success'"
    Auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
}

function AuditOtherObjectAccessEvents {
    #17.6.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit Other Object Access Events 
    Write-Info "17.6.1 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
}

function AuditRemovableStorage {
    #17.6.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit Removable Storage 
    Write-Info "17.6.2 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
}

function AuditPolicyChange {
    #17.7.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Audit Policy Change
    Write-Info "17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to include 'Success'"
    Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:disable
}

function AuditAuthenticationPolicyChange {
    #17.7.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authentication Policy Change 
    Write-Info "17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
    Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:disable
}

function AuditMPSSVCRuleLevelPolicyChange {
    #17.7.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit MPSSVC RuleLevel Policy Change
    Write-Info "17.7.3 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
}

function AuditSpecialLogon {
    #17.8.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Privilege Use\Audit Sensitive Privilege Use 
    Write-Info "17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
}

function AuditSecurityStateChange {
    #17.9.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit Security State Change 
    Write-Info "17.9.1 (L1) Ensure 'Audit Security State Change' is set to include 'Success'"
    Auditpol /set /subcategory:"Security State Change" /success:enable /failure:disable
}

function AuditSecuritySystemExtension {
    #17.9.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit Security System Extension 
    Write-Info "17.9.2 (L1) Ensure 'Audit Security System Extension' is set to include 'Success'"
    Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:disable
}

function AuditSystemIntegrity {
    #17.9.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit System Integrity
    Write-Info "17.9.3 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
}

function DisallowUsersToEnableOnlineSpeechRecognitionServices {
    #18.1.2.2 => Computer Configuration\Policies\Administrative Templates\Control Panel\Regional and Language Options\Allow users to enable online speech recognition services
    Write-Info "18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" "0" $REG_DWORD
}

function ConfigureSMBv1ClientDriver  {
    #18.3.1 => Computer Configuration\Policies\Administrative Templates\MS Security Guide\Configure SMB v1 client driver 
    Write-Info "18.3.1 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" "4" $REG_DWORD
}

function ConfigureSMBv1server {
    #18.3.2 => Computer Configuration\Policies\Administrative Templates\MS Security Guide\Configure SMB v1 server
    Write-Info "18.3.3 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" "0" $REG_DWORD
}

function DisableExceptionChainValidation {
    #18.3.3 => Computer Configuration\Policies\Administrative Templates\MS Security Guide\Enable Structured Exception Handling Overwrite Protection (SEHOP)
    Write-Info "18.3.3 (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" "0" $REG_DWORD
}

function NetBIOSNodeType {
    #18.3.4 => Navigate to the Registry path articulated in the Remediation section and confirm it is set as prescribed. 
    Write-Info "18.3.4 (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType" "2" $REG_DWORD
}

function WDigestUseLogonCredential   {
    #18.3.5 => Computer Configuration\Policies\Administrative Templates\MS Security Guide\WDigest Authentication (disabling may require KB2871997)
    Write-Info "18.3.5 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" "0" $REG_DWORD
}

# MSS Group Policies are not supported by GPEDIT anymore. the values must be ckecked directly on the registry

function WinlogonAutoAdminLogon {
    #18.4.1 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)
    Write-Info "18.4.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0" $REG_DWORD
}

function EnableICMPRedirect {
    #18.4.3 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
    Write-Info "18.4.3 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" "0"  $REG_DWORD
}

function NoNameReleaseOnDemand {
    #18.4.4 => Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
    Write-Info "18.4.4 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NoNameReleaseOnDemand" "1" $REG_DWORD
}

function EnableMulticast {
    #18.5.4.1 => Computer Configuration\Policies\Administrative Templates\Network\DNS Client\Turn off multicast name resolution 
    Write-Info "18.5.4.1 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" "0" $REG_DWORD
}

function AllowInsecureGuestAuth {
    #18.5.8.1 => Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Enable insecure guest logons 
    Write-Info "18.5.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth" "0" $REG_DWORD
}

function DisableNetworkBridges {
    #18.5.11.2 => Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Prohibit installation and configuration of Network Bridge on your DNS domain network 
    Write-Info "18.5.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NLA" "0"  $REG_DWORD
}

function ProhibitInternetConnectionSharing {
    #18.5.11.3 => Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Prohibit use of Internet Connection Sharing on your DNS domain network
    Write-Info "18.5.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI" "0"  $REG_DWORD
}

function HardenedPaths {
    #18.5.14.1 => Computer Configuration\Policies\Administrative Templates\Network\Network Provider\Hardened UNC Paths
    Write-Info "18.5.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication' and 'Require Integrity' set for all NETLOGON and SYSVOL shares"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON" "RequireMutualAuthentication=1, RequireIntegrity=1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\SYSVOL" "RequireMutualAuthentication=1, RequireIntegrity=1" $REG_SZ
}

function fMinimizeConnections {
    #18.5.21.1 => Computer Configuration\Policies\Administrative Templates\Network\Windows Connection Manager\Minimize the number of simultaneous connections to the Internet or a Windows Domain 
    Write-Info "18.5.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections" "3" $REG_DWORD
}


function ProcessCreationIncludeCmdLine {
    #18.8.3.1 => Computer Configuration\Policies\Administrative Templates\System\Audit Process Creation\Include command line in process creation events
    Write-Info "18.8.3.1 (L1) Ensure 'Include command line in process creation events' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" "1" $REG_DWORD
}

function EncryptionOracleRemediation {
    #18.8.4.1 => Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Encryption Oracle Remediation
    Write-Info "18.8.4.1 (L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" "0" $REG_DWORD
}

function AllowProtectedCreds {
    #18.8.4.2 => Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Remote host allows delegation of non-exportable credentials
    Write-Info "18.8.4.2 (L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" "1" $REG_DWORD
}

function EnableVirtualizationBasedSecurity {
    #18.8.5.1 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security
    Write-Info "18.8.5.1 (NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity" "1" $REG_DWORD
}

function RequirePlatformSecurityFeatures {
    #18.8.5.2 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Select Platform Security Level
    Write-Info "18.8.5.2 (NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures" "3" $REG_DWORD
}

function HypervisorEnforcedCodeIntegrity {
    #18.8.5.3 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity 
    Write-Info "18.8.5.3 (NG) Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'" ""
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity" "1" $REG_DWORD
}

function HVCIMATRequired {
    #18.8.5.4 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Require UEFI Memory Attributes Table
    Write-Info "18.8.5.4 (NG) Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired" "1" $REG_DWORD
}

function LsaCfgFlags {
    #18.8.5.5 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Credential Guard Configuration
    Write-Info "18.8.5.5 (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags" "1" $REG_DWORD
}

function ConfigureSystemGuardLaunch {
    #18.8.6.7 => Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security: Secure Launch Configuration
    Write-Info "18.8.5.7 (NG) Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "ConfigureSystemGuardLaunch" "1" $REG_DWORD
}

function DriverLoadPolicy {
    #18.8.14.1 => Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware\Boot-Start Driver Initialization Policy
    Write-Info "18.8.14.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" "3" $REG_DWORD
}


function NoBackgroundPolicy {
    #18.8.21.2 => Computer Configuration\Policies\Administrative Templates\System\Group Policy\Configure registry policy processing
    Write-Info "18.8.21.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" "0" $REG_DWORD
}


function NoGPOListChanges {
    #18.8.21.3 => Computer Configuration\Policies\Administrative Templates\System\Group Policy\Configure registry policy processing
    Write-Info "18.8.21.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" "0" $REG_DWORD
}

function EnableCdp {
    #18.8.21.4 => Computer Configuration\Policies\Administrative Templates\System\Group Policy\Continue experiences on this device
    Write-Info "18.8.21.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp" "0" $REG_DWORD
}

function DisableBkGndGroupPolicy {
    #18.8.21.5 => Computer Configuration\Policies\Administrative Templates\System\Group Policy\Turn off background refresh of Group Policy 
    Write-Info "18.8.21.5 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled' "
    DeleteRegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableBkGndGroupPolicy"
}


function DisableWebPnPDownload {
    #18.8.22.1.1 => Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off downloading of print drivers over HTTP
    Write-Info "18.8.22.1.1 (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" "1" $REG_DWORD
}

function BlockUserFromShowingAccountDetailsOnSignin {
    #18.8.28.1 => Computer Configuration\Policies\Administrative Templates\System\Logon\Block user from showing account details on sign-in
    Write-Info "18.8.28.1 (L1) Ensure 'Block user from showing account details on signin' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin" "1" $REG_DWORD
}

function fAllowUnsolicited {
    #18.8.36.1 => Computer Configuration\Policies\Administrative Templates\System\Remote Assistance\Configure Offer Remote Assistance
    Write-Info "18.8.36.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited" "0" $REG_DWORD
}

function fAllowToGetHelp {
    #18.8.36.2 => Computer Configuration\Policies\Administrative Templates\System\Remote Assistance\Configure Solicited Remote Assistance
    Write-Info "18.8.36.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" "0" $REG_DWORD
}

function EnableAuthEpResolution {
    #18.8.37.1 => Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Enable RPC Endpoint Mapper Client Authentication 
    Write-Info "18.8.37.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution" "1" $REG_DWORD
}


function MSAOptional {
    #18.9.6.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\App runtime\Allow Microsoft accounts to be optional 
    Write-Info "18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional" "1" $REG_DWORD
}

function DisableConsumerAccountStateContent {
    #18.9.14.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off cloud consumer account state content
    Write-Info "18.9.14.1 (L1) Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent" "1" $REG_DWORD
}

function DisableWindowsConsumerFeatures {
    #18.9.14.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off Microsoft consumer experiences
    Write-Info "18.9.14.2 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "1" $REG_DWORD
}


function DisablePasswordReveal {
    #18.9.16.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Do not display the password reveal button
    Write-Info "18.9.16.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal" "1" $REG_DWORD
}

function DisableEnumerateAdministrators {
    #18.9.16.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Enumerate administrator accounts on elevation
    Write-Info "18.9.16.2 (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators" "0" $REG_DWORD
}

function DisallowTelemetry {
    #18.9.17.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Telemetry 
    Write-Info "18.9.17.1 (L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "0" $REG_DWORD
}

function EventLogRetention  {
    #18.9.27.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application\Control Event Log behavior when the log file reaches its maximum size
    Write-Info "18.9.27.1.1 (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "Retention" "0" $REG_DWORD
}

function EventLogMaxSize {
    #18.9.27.1.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application\Specify the maximum log file size (KB)
    Write-Info "18.9.27.1.2 (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize" $EventLogMaxFileSize $REG_DWORD
}

function EventLogSecurityRetention {
    #18.9.27.2.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security\Control Event Log behavior when the log file reaches its maximum size
    Write-Info "18.9.27.2.1 (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention" "0" $REG_DWORD
}

function EventLogSecurityMaxSize {
    #18.9.27.2.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security\Specify the maximum log file size (KB)
    Write-Info "18.9.27.2.2 (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize" $EventLogMaxFileSize $REG_DWORD
}

function EventLogSetupRetention {
    #18.9.27.3.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup\Control Event Log behavior when the log file reaches its maximum size
    Write-Info "18.9.27.3.1 (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "Retention" "0" $REG_DWORD
}

function EventLogSetupMaxSize {
    #18.9.27.3.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup\Specify the maximum log file size (KB)
    Write-Info "18.9.27.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize" $EventLogMaxFileSize $REG_DWORD
}

function EventLogSystemRetention {
    #18.9.27.4.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System\Control Event Log behavior when the log file reaches its maximum size
    Write-Info "18.9.27.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "Retention" "0" $REG_DWORD
}

function EventLogSystemMaxSize {
    #18.9.27.4.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System\Specify the maximum log file size (KB)
    Write-Info "18.9.27.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize" $EventLogMaxFileSize $REG_DWORD
}

function NoDataExecutionPrevention {
    #18.9.31.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off Data Execution Prevention for Explorer 
    Write-Info "18.9.31.2 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" "0" $REG_DWORD
}

function NoHeapTerminationOnCorruption {
    #18.9.31.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off heap termination on corruption 
    Write-Info "18.9.31.3 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" "0" $REG_DWORD
}

function PreXPSP2ShellProtocolBehavior {
    #18.9.31.4 => Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Turn off shell protocol protected mode
    Write-Info "18.9.31.4 (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" "0" $REG_DWORD
}

function MicrosoftAccountDisableUserAuth {
    #18.9.46.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft accounts\Block all consumer Microsoft account user authentication
    Write-Info "18.9.46.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth" "1" $REG_DWORD
}


function LocalSettingOverrideSpynetReporting {
    #18.9.47.4.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS\Configure local setting override for reporting to Microsoft MAPS
    Write-Info "18.9.47.4.1 (L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "LocalSettingOverrideSpynetReporting" "0" $REG_DWORD
}


function ExploitGuard_ASR_Rules {
    #18.9.47.5.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction\Configure Attack Surface Reduction rules
    Write-Info "18.9.47.5.1.1 (L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules" "1" $REG_DWORD
}

# TODO : missing 18.9.47.5.1.2
function ConfigureASRrules {
    #18.9.47.5.1.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction\Configure Attack Surface Reduction rules: Set the state for each ASR rule
    Write-Info "18.9.47.5.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"    
}
function ConfigureASRRuleBlockOfficeCommsChildProcess {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block Office communication application from creating child processes"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "26190899-1602-49e8-8b27-eb1d0a1ce869" "1" $REG_SZ
}

function ConfigureASRRuleBlockOfficeCreateExeContent {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block Office applications from creating executable content"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "3b576869-a4ec-4529-8536-b80a7769e899" "1" $REG_SZ
}

function ConfigureASRRuleBlockObfuscatedScripts {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block execution of potentially obfuscated scripts"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "5beb7efe-fd9a-4556-801d-275e5ffc04cc" "1" $REG_SZ
}

function ConfigureASRRuleBlockOfficeInjectionIntoOtherProcess {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block Office applications from injecting code into other processes"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" "1" $REG_SZ
}

function ConfigureASRRuleBlockAdobeReaderChildProcess {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block Adobe Reader from creating child processes"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" "1" $REG_SZ
}

function ConfigureASRRuleBlockWin32ApiFromOfficeMacro {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block Win32 API calls from Office macro"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" "1" $REG_SZ
}

function ConfigureASRRuleBlockCredStealingFromLsass {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" "1" $REG_SZ
}

function ConfigureASRRuleBlockUntrustedUnsignedProcessesUSB {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block untrusted and unsigned processes that run from USB"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" "1" $REG_SZ
}

function ConfigureASRRuleBlockExeutablesFromEmails {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block executable content from email client and webmail"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" "1" $REG_SZ
}

function ConfigureASRRuleBlockJSVBSLaunchingExeContent {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block JavaScript or VBScript from launching downloaded executable content"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d3e037e1-3eb8-44c8-a917-57927947596d" "1" $REG_SZ
}

function ConfigureASRRuleBlockOfficeChildProcess {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block Office applications from creating child processes"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d4f940ab-401b-4efc-aadc-ad5f3c50688a" "1" $REG_SZ
}

function ConfigureASRRuleBlockPersistenceThroughWMI {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block persistence through WMI event subscription"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "e6db77e5-3df2-4cf1-b95a-636979351e5b" "1" $REG_SZ
}

function ConfigureASRRuleBlockExploitedSignedDrivers {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block abuse of exploited vulnerable signed drivers (Not currently in CIS)"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "56a863a9-875e-4185-98a7-b882c64b5ce5" "1" $REG_SZ
}

function ConfigureASRRuleBlockExeUnlessMeetPrevalence {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block executable files from running unless they meet a prevalence, age, or trusted list criterion (Not currently in CIS)"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "01443614-cd74-433a-b99e-2ecdc07bfc25" "1" $REG_SZ
}

function ConfigureASRRuleUseAdvancedRansomwareProtection {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Use advanced protection against ransomware (Not currently in CIS)"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "c1db55ab-c21a-4637-bb3f-a12568109d35" "1" $REG_SZ
}

function ConfigureASRRuleBlockProcessesFromPSExecandWmi {
    Write-Info "18.9.47.5.1.2 (L1) ASR Rule: Block process creations originating from PSExec and WMI commands (Not currently in CIS)"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d1e49aac-8f56-4280-b9ba-993a6d77406c" "1" $REG_SZ
}

function EnableNetworkProtection {
    #18.9.47.5.3.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Network Protection\Prevent users and apps from accessing dangerous websites
    Write-Info "18.9.47.5.3.1 (L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection" "1" $REG_DWORD
}

function DisableIOAVProtection {
    #18.9.47.9.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Real-Time Protection\Scan all downloaded files and attachments
    Write-Info "18.9.47.9.1 (L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection" "0" $REG_DWORD
}


function DisableRealtimeMonitoring {
    #18.9.47.9.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Real-Time Protection\Scan all downloaded files and attachments
    Write-Info "18.9.47.9.2 (L1) Ensure 'Turn off real-time protection' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" "0" $REG_DWORD
}

function DisableBehaviorMonitoring {
    #18.9.47.9.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Real-Time Protection\Turn on behavior monitoring 
    Write-Info "18.9.47.9.3 (L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
    SetRegistry "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring" "0" $REG_DWORD
}

function DisableScriptScanning {
    #18.9.47.9.4 => Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Real-Time Protection\Turn on script scanning
    Write-Info "18.9.47.9.4 (L1) Ensure 'Turn on script scanning' is set to 'Enabled'"
    SetRegistry "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableScriptScanning" "0" $REG_DWORD
}

function DisableEmailScanning {
    #18.9.47.12.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan\Turn on e-mail scanning
    Write-Info "18.9.47.12.2 (L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableEmailScanning" "0" $REG_DWORD
}

function PUAProtection  {
    #18.9.47.15 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Configure detection for potentially unwanted applications
    Write-Info "18.9.47.15 (L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection" "1" $REG_DWORD
}

function DisableAntiSpyware {
    #18.9.47.16 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Turn off Windows Defender AntiVirus
    Write-Info "18.9.47.16 (L1) Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" "0" $REG_DWORD
}

function TerminalServicesDisablePasswordSaving {
    #18.9.65.2.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Connection Client\Do not allow passwords to be saved
    Write-Info "18.9.65.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving" "1" $REG_DWORD
}

function TerminalServicesfDisableCdm {
    #18.9.65.3.3.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow drive redirection
    # This prevents copying and pasting into RDP. Set to 0 to allow pasting into the RDP session.
    if ($AllowRDPClipboard -eq $false) {
      Write-Info "18.9.65.3.3.1 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
      SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm" "1" $REG_DWORD
    }
    else {
      Write-Red "Opposing 18.9.65.3.3.1 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
      Write-Red '- You enabled $AllowRDPClipboard. This CIS configuration has been skipped so that the clipboard can be used.'
      SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm" "0" $REG_DWORD
    }
}

function TerminalServicesfPromptForPassword {
    #18.9.65.3.9.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Always prompt for password upon connection
    Write-Info "18.9.65.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword" "1" $REG_DWORD
}



function TerminalServicesfEncryptRPCTraffic {
    #18.9.65.3.9.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Require secure RPC communication
    Write-Info "18.9.65.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic" "1" $REG_DWORD
}

function TerminalServicesMinEncryptionLevel {
    #18.9.65.3.9.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Set client connection encryption level
    Write-Info "18.9.65.3.9.3 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel" "3" $REG_DWORD
}

function TerminalServicesDeleteTempDirsOnExit {
    #18.9.59.3.11.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Temporary Folders\Do not delete temp folders upon exit
    Write-Info "18.9.59.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit" "1" $REG_DWORD
}

function TerminalServicesPerSessionTempDir {
    #18.9.65.3.11.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Temporary Folders\Do not use temporary folders per session
    Write-Info "18.9.65.3.11.2 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "PerSessionTempDir" "1" $REG_DWORD
}


function DisableEnclosureDownload {
    #18.9.66.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\RSS Feeds\Prevent downloading of enclosures
    Write-Info "18.9.66.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" "1" $REG_DWORD
}


function AllowIndexingEncryptedStoresOrItems {
    #18.9.67.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow indexing of encrypted files
    Write-Info "18.9.67.2 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" "0" $REG_DWORD
}

function DefenderSmartScreen {
    #18.9.85.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender SmartScreen\Explorer\Configure Windows Defender SmartScreen
    Write-Info "18.9.85.1.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" "1" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "Block" $REG_SZ
}

function InstallerEnableUserControl {
    #18.9.90.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Allow user control over installs
    Write-Info "18.9.90.1 (L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl" "0" $REG_DWORD
}

function InstallerAlwaysInstallElevated {
    #18.9.90.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Always install with elevated privileges
    Write-Info "18.9.90.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "0" $REG_DWORD
}

function DisableAutomaticRestartSignOn {
    #18.9.91.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\Sign-in last interactive user automatically after a system-initiated restart 
    Write-Info "18.9.91.1 (L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" "1" $REG_DWORD
}

function EnableScriptBlockLogging {
    #18.9.100.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Script Block Logging
    Write-Info "18.9.100.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" "1" $REG_DWORD
}

function EnableTranscripting {
    #18.9.100.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Transcription 
    Write-Info "18.9.100.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" "0" $REG_DWORD
}

function WinRMClientAllowBasic  {
    #18.9.102.1.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Allow Basic authentication
    Write-Info "18.9.102.1.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic" "0" $REG_DWORD
}

function WinRMClientAllowUnencryptedTraffic {
    #18.9.102.1.2 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Allow unencrypted traffic
    Write-Info "18.9.102.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic" "0" $REG_DWORD
}

function WinRMClientAllowDigest {
    #18.9.102.1.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Disallow Digest authentication
    Write-Info "18.9.102.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest" "0" $REG_DWORD
}


function WinRMServiceAllowBasic {
    #18.9.102.2.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow Basic authentication 
    Write-Info "18.9.102.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic" "0" $REG_DWORD
}

function WinRMServiceAllowAutoConfig {
    #18.9.102.2.2 => Computer Configuration\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow remote server management through WinRM
    Write-Info "18.9.102.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig" "0" $REG_DWORD
}

function WinRMServiceDisableRunAs {
    #18.9.102.2.3 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Disallow WinRM from storing RunAs credentials
    Write-Info "18.9.102.2.3 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs" "1" $REG_DWORD
}

function DisallowExploitProtectionOverride {
    #18.9.105.2.1 => Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Security\App and browser protection\Prevent users from modifying settings 
    Write-Info "18.9.105.2.1 (L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" "DisallowExploitProtectionOverride" "1" $REG_DWORD
}


Write-Info "CIS Azure Compute Microsoft Windows Server 2022 Benchmark"
Write-Info "Script by Michael Aparicio"
Write-Info "Credit to Evan Greene and Vinicius Miguel for original scripts"

# Enable Windows Defender settings on Windows Server
Set-MpPreference -AllowNetworkProtectionOnWinServer 1
Set-MpPreference -AllowNetworkProtectionDownLevel 1
Set-MpPreference -AllowDatagramProcessingOnWinServer 1


$location = Get-Location
    
secedit /export /cfg "$location\secedit_original.cfg"  | out-null
    
Start-Transcript -Path "$location\PolicyResults.txt"
$ExecutionList | ForEach-Object { ( Invoke-Expression $_) } | Out-File $location\CommandsReport.txt
Stop-Transcript
    
"The following policies were defined in the ExecutionList: " | Out-File $location\PoliciesApplied.txt
$ExecutionList | Out-File $location\PoliciesApplied.txt -Append

Write-Host ""

Start-Transcript -Path "$location\PolicyChangesMade.txt"
Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Write-After "Changes Made"
Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Write-Red ($global:valueChanges -join "`n")
Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Stop-Transcript 

secedit /export /cfg $location\secedit_final.cfg | out-null

Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Write-After "Completed. Logs written to: $location"
    

$host.UI.RawUI.ForegroundColor = $fc