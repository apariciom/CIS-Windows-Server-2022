
$localizedData = ConvertFrom-StringData @'
    Section       = Section: {0}
    Value         = ValueName: {0}
    Option        = Options: {0}
    RawValue      = Raw current value: {0}
    TestingPolicy = Testing AccountPolicy: {0}
    SetFailed     = Failed to update Account Policy {0}. Refer to %windir%\\security\\logs\\scesrv.log for details.
    SetSuccess    = Successfully update Account Policy
    PoliciesBeingCompared = Current policy: {0} Desired policy: {1}
    RetrievingValue = Retrieving value for {0}
'@

function Build-Infs() {
     # SECURITYPOLICY - Includes Account Policies, Audit Policies, Event Log Settings and Security Options.
    secedit.exe /export /areas SECURITYPOLICY /cfg "SECURITYPOLICY.inf" | Out-Null

    # GROUP_MGMT - Includes Restricted Group settings
    secedit.exe /export /areas GROUP_MGMT /cfg "GROUP_MGMT.inf" | Out-Null

    # USER_RIGHTS - Includes User Rights Assignment
    secedit.exe /export /areas USER_RIGHTS /cfg "USER_RIGHTS.inf" | Out-Null

    # REGKEYS - Includes Registry Permissions
    secedit.exe /export /areas REGKEYS /cfg "REGKEYS.inf" | Out-Null

    # FILESTORE - Includes File System permissions
    secedit.exe /export /areas FILESTORE /cfg "FILESTORE.inf" | Out-Null

    # SERVICES - Includes System Service settings
    secedit.exe /export /areas SERVICES /cfg "SERVICES.inf" | Out-Null
}


<#
    .SYNOPSIS
        Wrapper around secedit.exe used to make changes
    .PARAMETER InfPath
        Path to an INF file with desired user rights assignment policy configuration
    .PARAMETER SeceditOutput
        Path to secedit log file output
    .EXAMPLE
        Invoke-Secedit -InfPath C:\secedit.inf -SeceditOutput C:\seceditLog.txt
#>
function Invoke-Secedit
{
    [OutputType([void])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $InfPath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SeceditOutput,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $OverWrite
    )

    $tempDB = "$env:TEMP\DscSecedit.sdb"
    $arguments = "/configure /db $tempDB /cfg $InfPath"

    if ($OverWrite)
    {
        $arguments = $arguments + " /overwrite /quiet"
    }

    Write-Verbose "secedit arguments: $arguments"
    Start-Process -FilePath secedit.exe -ArgumentList $arguments -RedirectStandardOutput $seceditOutput `
        -NoNewWindow -Wait
}

<#
    .SYNOPSIS
        Returns security policies configuration settings

    .PARAMETER Area
        Specifies the security areas to be returned

    .NOTES
    General notes
#>
function Get-Policy
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("SECURITYPOLICY", "GROUP_MGMT", "USER_RIGHTS", "REGKEYS", "FILESTORE", "SERVICES")]
        [System.String]
        $Area
    )

    $currentSecurityPolicyFilePath = "$($Area).inf"
    
    $policyConfiguration = @{}
    switch -regex -file $currentSecurityPolicyFilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $policyConfiguration[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $commentCount = $commentCount + 1
            $name = "Comment" + $commentCount
            $policyConfiguration[$section][$name] = $value
        }
        "(.+?)\s*=(.*)" # Key
        {
            $name, $value = $matches[1..2] -replace "\*"
            $policyConfiguration[$section][$name] = $value
        }
    }

    switch ($Area)
    {
        "USER_RIGHTS"
        {
            $returnValue = @{}
            $privilegeRights = $policyConfiguration.'Privilege Rights'
            foreach ($key in $privilegeRights.keys )
            {
                $policyName = Get-UserRightConstant -Policy $key -Inverse
                $identity = ConvertTo-LocalFriendlyName -Identity $($privilegeRights[$key] -split ",").Trim() `
                    -Policy $policyName -Verbose:$VerbosePreference
                $returnValue.Add( $key, $identity )
            }

            continue
        }

        default
        {
            $returnValue = $policyConfiguration
        }
    }

    return $returnValue
}
 


function Get-AccountPolicyData() {
    return @{
        "Enforce_password_history" = @{
            Value   = 'PasswordHistorySize'
            Section = 'System Access'
            Option  = @{
                String = ''
            }
        }
    
        "Maximum_Password_Age" = @{
            Value   = 'MaximumPasswordAge'
            Section = 'System Access'
            Option  = @{
                String = ''
            }
        }
    
        "Minimum_Password_Age" = @{
            Value   = 'MinimumPasswordAge'
            Section = 'System Access'
            Option  = @{
                String = ''
            }
        }
    
        "Minimum_Password_Length" = @{
            Value   = 'MinimumPasswordLength'
            Section = 'System Access'
            Option  = @{
                String = ''
            }
        }
    
        "Password_must_meet_complexity_requirements" = @{
            Value   = 'PasswordComplexity'
            Section = 'System Access'
            Option  = @{
                Enabled  = '1'
                Disabled = '0'
            }
        }
    
        "Store_passwords_using_reversible_encryption" = @{
            Value   = 'ClearTextPassword'
            Section = 'System Access'
            Option  = @{
                Enabled = '1'
                Disabled = '0'
            }
        }
    
        "Account_lockout_duration" = @{
            Value   = 'LockoutDuration'
            Section = 'System Access'
            Option  = @{
                String = ''
            }
        }
    
        "Account_lockout_threshold" = @{
            Value   = 'LockoutBadCount'
            Section = 'System Access'
            Option  = @{
                String = ''
            }
        }
    
        "Reset_account_lockout_counter_after" = @{
            Value   = 'ResetLockoutCount'
            Section = 'System Access'
            Option  = @{
                String = ''
            }
        }
    
        "Enforce_user_logon_restrictions" = @{
            Value   = 'TicketValidateClient'
            Section = 'Kerberos Policy'
            Option  = @{
                Enabled = '1'
                Disabled = '0'
            }
        }
    
        "Maximum_lifetime_for_service_ticket" = @{
            Value   = 'MaxServiceAge'
            Section = 'Kerberos Policy'
            Option  = @{
                String = ''
            }
        }
    
        "Maximum_lifetime_for_user_ticket" = @{
            Value   = 'MaxTicketAge'
            Section = 'Kerberos Policy'
            Option  = @{
                String = ''
            }
        }
    
        "Maximum_lifetime_for_user_ticket_renewal" = @{
            Value   = 'MaxRenewAge'
            Section = 'Kerberos Policy'
            Option  = @{
                String = ''
            }
        }
    
        "Maximum_tolerance_for_computer_clock_synchronization" = @{
            Value   = 'MaxClockSkew'
            Section = 'Kerberos Policy'
            Option  = @{
                String = ''
            }
        }
    }
}


function Get-AccountPolicy() {
    $accountPolicyData = Get-AccountPolicyData
    
    $currentSecurityPolicy = Get-Policy -Area SECURITYPOLICY

    $returnValue = @{ }

    foreach ($accountPolicy in $accountPolicyData.Keys)
    {
        Write-Verbose -Message $accountPolicy
        $section = $accountPolicyData[$accountPolicy].Section
        Write-Verbose -Message ($script:localizedData.Section -f $section)
        $valueName = $accountPolicyData[$accountPolicy].Value
        Write-Verbose -Message ($script:localizedData.Value -f $valueName)
        $options = $accountPolicyData[$accountPolicy].Option
        Write-Verbose -Message ($script:localizedData.Option -f $($options -join ','))
        $currentValue = $currentSecurityPolicy.$section.$valueName
        Write-Verbose -Message ($script:localizedData.RawValue -f $($currentValue -join ','))

        if ($options.keys -eq 'String')
        {
            $stringValue = ($currentValue -split ',')[-1]
            $resultValue = ($stringValue -replace '"').Trim()

            if ($resultValue -eq -1 -and $accountPolicy -in 'Maximum_Password_Age','Account_Lockout_Duration')
            {
                $resultValue = 0
            }
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.RetrievingValue -f $valueName)
            if ($currentSecurityPolicy.$section.keys -contains $valueName)
            {
                $resultValue = ($accountPolicyData.$accountPolicy.Option.GetEnumerator() |
                    Where-Object -Property Value -eq $currentValue.Trim()).Name
            }
            else
            {
                $resultValue = $null
            }
        }
        $returnValue.Add($accountPolicy, $resultValue)
    }

    return $returnValue
}

<#
    .SYNOPSIS
        Creates the INF file content that contains the security option configurations

    .PARAMETER SystemAccessPolicies
        Specifies the security options that pertain to [System Access] policies

    .PARAMETER RegistryPolicies
        Specifies the security opions that are managed via [Registry Values]
#>
function Add-PolicyOption
{
    [OutputType([System.Object[]])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [Collections.ArrayList]
        $SystemAccessPolicies,

        [Parameter()]
        [Collections.ArrayList]
        $RegistryPolicies,

        [Parameter()]
        [Collections.ArrayList]
        $KerberosPolicies
    )

    # insert the appropriate INI section
    if ([string]::IsNullOrWhiteSpace($RegistryPolicies) -eq $false)
    {
        $RegistryPolicies.Insert(0, '[Registry Values]')
    }

    if ([string]::IsNullOrWhiteSpace($SystemAccessPolicies) -eq $false)
    {
        $SystemAccessPolicies.Insert(0, '[System Access]')
    }

    if ([string]::IsNullOrWhiteSpace( $KerberosPolicies ) -eq $false)
    {
        $KerberosPolicies.Insert(0, '[Kerberos Policy]')
    }

    $iniTemplate = @(
        "[Unicode]"
        "Unicode=yes"
        $systemAccessPolicies
        "[Version]"
        'signature="$CHICAGO$"'
        "Revision=1"
        $KerberosPolicies
        $registryPolicies
    )

    return $iniTemplate
}

<#
    .SYNOPSIS
        Sets the specified account policy
#>
function Set-AccountPolicy
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingUserNameAndPassWordParams", "")]
    [CmdletBinding()]
    param
    (

        [Parameter()]
        [ValidateRange(0, 24)]
        [System.UInt32]
        $Enforce_password_history,

        [Parameter()]
        [ValidateRange(0, 999)]
        [System.UInt32]
        $Maximum_Password_Age,

        [Parameter()]
        [ValidateRange(0, 998)]
        [System.UInt32]
        $Minimum_Password_Age,

        [Parameter()]
        [ValidateRange(0, 14)]
        [System.UInt32]
        $Minimum_Password_Length,

        [Parameter()]
        [ValidateSet("Enabled", "Disabled")]
        [System.String]
        $Password_must_meet_complexity_requirements,

        [Parameter()]
        [ValidateSet("Enabled", "Disabled")]
        [System.String]
        $Store_passwords_using_reversible_encryption,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Account_lockout_duration,

        [Parameter()]
        [ValidateRange(0, 999)]
        [System.UInt32]
        $Account_lockout_threshold,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Reset_account_lockout_counter_after,

        [Parameter()]
        [ValidateSet("Enabled", "Disabled")]
        [System.String]
        $Enforce_user_logon_restrictions,

        [Parameter()]
        [ValidateRange(10, 99999)]
        [System.UInt32]
        $Maximum_lifetime_for_service_ticket,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Maximum_lifetime_for_user_ticket,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Maximum_lifetime_for_user_ticket_renewal,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Maximum_tolerance_for_computer_clock_synchronization
    )

    $kerberosPolicies = @()
    $systemAccessPolicies = @()
    $nonComplaintPolicies = @()
    
    $accountPolicyData = Get-AccountPolicyData
    # $seceditOutput = "$env:TEMP\Secedit-OutPut.txt"
    # $accountPolicyToAddInf = "$env:TEMP\accountPolicyToAdd.inf"
    $accountPolicyToAddInf = "accountPolicyToAdd.inf"

    $desiredPolicies = $PSBoundParameters.GetEnumerator() | Where-Object -FilterScript {$PSItem.key -in $accountPolicyData.Keys}

    foreach ($policy in $desiredPolicies)
    {
        $testParameters = @{            
            $policy.Key = $policy.Value
            Verbose     = $false
        }

        <#
            Define what policies are not in a desired state so we only add those policies
            that need to be changed to the INF.
         #>
        $isInDesiredState = Test-AccountPolicy @testParameters
        if (-not ($isInDesiredState))
        {
            $policyKey = $policy.Key
            $policyData = $accountPolicyData.$policyKey
            $nonComplaintPolicies += $policyKey

            if ($policyData.Option.GetEnumerator().Name -eq 'String')
            {
                if ([String]::IsNullOrWhiteSpace($policyData.Option.String))
                {
                    if ($policy.Key -in 'Maximum_Password_Age','Account_Lockout_Duration' -and $policy.Value -eq 0)
                    {
                        <#
                            This addresses the scenario when the desired value of Maximum_Password_Age or
                            Account_Lockout_Duration is 0. The INF file consumed by secedit.exe requires the value to
                            be -1.
                        #>
                        $newValue = -1
                    }
                    else
                    {
                        $newValue = $policy.value
                    }
                }
                else
                {
                    $newValue = "$($policyData.Option.String)" + "$($policy.Value)"
                }
            }
            else
            {
                $newValue = $($policyData.Option[$policy.value])
            }

            if ($policyData.Section -eq 'System Access')
            {
                $systemAccessPolicies += "$($policyData.Value)=$newValue"
            }
            else
            {
                $kerberosPolicies += "$($policyData.Value)=$newValue"
            }
        }
    }

    $infTemplate = Add-PolicyOption -SystemAccessPolicies $systemAccessPolicies -KerberosPolicies $kerberosPolicies

    Out-File -InputObject $infTemplate -FilePath $accountPolicyToAddInf -Encoding unicode -Force

    # Invoke-Secedit -InfPath $accountPolicyToAddInf -SecEditOutput $seceditOutput
    Remove-Item -Path $accountPolicyToAddInf

    $successResult = Test-AccountPolicy @PSBoundParameters

    if ($successResult -eq $false)
    {
        $nonComplaintPolicies = $nonComplaintPolicies | Sort-Object
        throw ($script:localizedData.SetFailed -f ($nonComplaintPolicies -join ','))
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.SetSuccess)
    }
}


<#
    .SYNOPSIS
        Tests the desired account policy configuration against the current configuration
#>
function Test-AccountPolicy
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingUserNameAndPassWordParams", "")]
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (

        [Parameter()]
        [ValidateRange(0, 24)]
        [System.UInt32]
        $Enforce_password_history,

        [Parameter()]
        [ValidateRange(0, 999)]
        [System.UInt32]
        $Maximum_Password_Age,

        [Parameter()]
        [ValidateRange(0, 998)]
        [System.UInt32]
        $Minimum_Password_Age,

        [Parameter()]
        [ValidateRange(0, 14)]
        [System.UInt32]
        $Minimum_Password_Length,

        [Parameter()]
        [ValidateSet("Enabled", "Disabled")]
        [System.String]
        $Password_must_meet_complexity_requirements,

        [Parameter()]
        [ValidateSet("Enabled", "Disabled")]
        [System.String]
        $Store_passwords_using_reversible_encryption,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Account_lockout_duration,

        [Parameter()]
        [ValidateRange(0, 999)]
        [System.UInt32]
        $Account_lockout_threshold,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Reset_account_lockout_counter_after,

        [Parameter()]
        [ValidateSet("Enabled", "Disabled")]
        [System.String]
        $Enforce_user_logon_restrictions,

        [Parameter()]
        [ValidateRange(10, 99999)]
        [System.UInt32]
        $Maximum_lifetime_for_service_ticket,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Maximum_lifetime_for_user_ticket,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Maximum_lifetime_for_user_ticket_renewal,

        [Parameter()]
        [ValidateRange(0, 99999)]
        [System.UInt32]
        $Maximum_tolerance_for_computer_clock_synchronization
    )

    $currentAccountPolicies = Get-AccountPolicy

    $desiredAccountPolicies = $PSBoundParameters


    foreach ($policy in $desiredAccountPolicies.Keys)
    {
        if ($currentAccountPolicies.ContainsKey($policy))
        {
            Write-Verbose -Message ($script:localizedData.TestingPolicy -f $policy)
            Write-Verbose -Message ($script:localizedData.PoliciesBeingCompared -f $($currentAccountPolicies[$policy] -join ','), $($desiredAccountPolicies[$policy] -join ','))

            if ($currentAccountPolicies[$policy] -ne $desiredAccountPolicies[$policy])
            {
                return $false
            }
        }
    }

    # if the code made it this far we must be in a desired state
    return $true
}


