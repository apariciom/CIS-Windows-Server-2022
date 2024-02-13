# CIS Azure Compute Microsoft Windows Server 2022 Benchmark 
# Script copied from Evan Greene at https://github.com/eneerge/CIS-Windows-Server-2022

##########################################################################################################
$LogonLegalNoticeMessageTitle = ">> WARNING <<"
$LogonLegalNoticeMessage = "You are accessing a Power Settlements Consulting & Software, LLC (""Company"") information system, which includes this computer, this computer network, all computers connected to this network, and all devices and storage media attached to this network or to a computer on this network. This information system is provided for Company authorized use only. Unauthorized or improper use of this system may result in disciplinary action, as well as civil and criminal penalties. By using this information system, you understand and consent to the following: you have no reasonable expectation of privacy regarding communications or data transiting or stored on this information system; at any time, and for any lawful Company purpose, the Company may monitor, intercept, search, and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Company purpose."

# Set the max size of log files
$WindowsFirewallLogSize = 4*1024*1024 # Default for script is 4GB
$EventLogMaxFileSize = 4*1024*1024 # Default 4GB (for each log)
$WindowsDefenderLogSize = 1024MB

$IncludeIisUsr = $false
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


#########################################################
# Policy Configuration
# Comment out any policy you do not wish to implement.
# Note that the "Compatibility Assurance" section you configured above above may override your wishes to ensure software your software works.
#########################################################
$ExecutionList = @(
    "CreateASRExclusions"                                               # This deletes and readds the attack surface reduction exclusions configured in the script.
    "SetWindowsDefenderLogSize"                                         # Sets the defender log size as configured in the top of this script
    #KEEP THESE IN THE BEGINING
    "CreateNewLocalAdminAccount",                                       #Mandatory otherwise the system access is lost
    "RenameAdministratorAccount",                                       #2.3.1.5 
    "RenameGuestAccount",                                               #2.3.1.6
    ###########################
    #"ResetSec",                                                        # Uncomment to reset the "Local Security Policy" (this doesn't touch the registry settings that are not in the Local Security Policy)

    #### 1. Account Policy / 1.1 Password Policy
    "EnforcePasswordHistory",                                           #1.1.1
    "MaximumPasswordAge",                                               #1.1.2
    "MinimumPasswordAge",                                               #1.1.3
    "MinimumPasswordLength",                                            #1.1.4
    "WindowsPasswordComplexityPolicyMustBeEnabled",                     #1.1.5    
    "DisablePasswordReversibleEncryption",                              #1.1.6


    "NoOneTrustCallerACM",                                              #2.2.1
    #2.2.2 Not Applicable to Member Server
    "AccessComputerFromNetwork",                                        #2.2.3
    "NoOneActAsPartOfOperatingSystem",                                  #2.2.4
    #2.2.5 Not Applicable to Member Server
    "AdjustMemoryQuotasForProcess",                                     #2.2.6
    "AllowLogonLocallyToAdministrators",                                #2.2.7
    #2.2.8 Not Applicable to Member Server
    "LogonThroughRemoteDesktopServices",                                #2.2.9
    "BackupFilesAndDirectories",                                        #2.2.10
    "ChangeSystemTime",                                                 #2.2.11
    "ChangeTimeZone",                                                   #2.2.12
    "CreatePagefile",                                                   #2.2.13
    "NoOneCreateTokenObject",                                           #2.2.14
    "CreateGlobalObjects",                                              #2.2.15
    "NoOneCreatesSharedObjects",                                        #2.2.16
    #2.2.17 Not Applicable to Member Server
    "CreateSymbolicLinks",                                              #2.2.18
    "DebugPrograms",                                                    #2.2.19
    #2.2.20 Not Applicable to Member Server
    "DenyNetworkAccess",                                                #2.2.21
    "DenyGuestBatchLogon",                                              #2.2.22
    "DenyGuestServiceLogon",                                            #2.2.23
    "DenyGuestLocalLogon",                                              #2.2.24
    #2.2.25 Not Applicable to Member Server
    "DenyRemoteDesktopServiceLogon",                                    #2.2.26
    #2.2.27 Not Applicable to Member Server
    "NoOneTrustedForDelegation",                                        #2.2.28
    "ForceShutdownFromRemoteSystem",                                    #2.2.29
    "GenerateSecurityAudits",                                           #2.2.30
    #2.2.31 Not Applicable to Member Server
    "ImpersonateClientAfterAuthentication",                             #2.2.32
    "IncreaseSchedulingPriority",                                       #2.2.33
    "LoadUnloadDeviceDrivers",                                          #2.2.34
    "NoOneLockPagesInMemory",                                           #2.2.35
    #2.2.36 Not Applicable to Member Server
    #2.2.37 Not Applicable to Member Server
    "ManageAuditingAndSecurity",                                        #2.2.38
    "NoOneModifiesObjectLabel",                                         #2.2.39
    "FirmwareEnvValues",                                                #2.2.40
    "VolumeMaintenance",                                                #2.2.41
    "ProfileSingleProcess",                                             #2.2.42
    "ProfileSystemPerformance",                                         #2.2.43
    "ReplaceProcessLevelToken",                                         #2.2.44
    "RestoreFilesDirectories",                                          #2.2.45
    "SystemShutDown",                                                   #2.2.46
    #2.2.47 Not Applicable to Member Server
    "TakeOwnershipFiles",                                               #2.2.48
    #"DisableAdministratorAccount",                                      #2.3.1.1
    "DisableMicrosoftAccounts",                                         #2.3.1.2
    "DisableGuestAccount",                                              #2.3.1.3
    "LimitBlankPasswordConsole",                                        #2.3.1.4
    "AuditForceSubCategoryPolicy",                                      #2.3.2.1
    "AuditForceShutdown",                                               #2.3.2.2
    "DevicesAdminAllowedFormatEject",                                   #2.3.4.1
    "PreventPrinterInstallation",                                       #2.3.4.2
    #2.3.5.1 Not Applicable to Member Server
    #2.3.5.2 Not Applicable to Member Server
    #2.3.5.3 Not Applicable to Member Server
    #2.3.5.4 Not Applicable to Member Server (2023.01.27)
    #2.3.5.5 Not Applicable to Member Server (2023.01.27)
    "SignEncryptAllChannelData",                                        #2.3.6.1
    "SecureChannelWhenPossible",                                        #2.3.6.2
    "DigitallySignChannelWhenPossible",                                 #2.3.6.3
    "EnableAccountPasswordChanges",                                     #2.3.6.4
    "MaximumAccountPasswordAge",                                        #2.3.6.5
    #"RequireStrongSessionKey",                                          #2.3.6.6
    #"RequireCtlAltDel",                                                 #2.3.7.1
    #"DontDisplayLastSigned",                                            #2.3.7.2
    "MachineInactivityLimit",                                           #2.3.7.3
    "LogonLegalNotice",                                                 #2.3.7.4
    "LogonLegalNoticeTitle",                                            #2.3.7.5
    #"PreviousLogonCache",                                               #2.3.7.6
    "PromptUserPassExpiration",                                         #2.3.7.7
    #"RequireDomainControllerAuth",                                      #2.3.7.8
    #"SmartCardRemovalBehaviour",                                        #2.3.7.9
    "NetworkClientSignCommunications",                                  #2.3.8.1
    "EnableSecuritySignature",                                          #2.3.8.2
    "DisableSmbUnencryptedPassword",                                    #2.3.8.3
    "IdleTimeSuspendingSession",                                        #2.3.9.1
    "NetworkServerAlwaysDigitallySign",                                 #2.3.9.2
    "LanManSrvEnableSecuritySignature",                                 #2.3.9.3
    "LanManServerEnableForcedLogOff",                                   #2.3.9.4
    "LanManServerSmbServerNameHardeningLevel",                          #2.3.9.5
    "LSAAnonymousNameDisabled",                                         #2.3.10.1
    "RestrictAnonymousSAM",                                             #2.3.10.2
    "RestrictAnonymous",                                                #2.3.10.3
    #"DisableDomainCreds",                                               #2.3.10.4
    "EveryoneIncludesAnonymous",                                        #2.3.10.5
    #2.3.10.6 Not Applicable to Member Server
    "NullSessionPipes",                                                 #2.3.10.7
    "AllowedExactPaths",                                                #2.3.10.8
    "AllowedPaths",                                                     #2.3.10.9
    "RestrictNullSessAccess",                                           #2.3.10.10
    "RestrictRemoteSAM",                                                #2.3.10.11
    "NullSessionShares",                                                #2.3.10.12
    "LsaForceGuest",                                                    #2.3.10.13
    "LsaUseMachineId",                                                  #2.3.11.1
    "AllowNullSessionFallback",                                         #2.3.11.2
    "AllowOnlineID",                                                    #2.3.11.3
    "SupportedEncryptionTypes",                                         #2.3.11.4
    "NoLMHash",                                                         #2.3.11.5
    #"ForceLogoff",                                                      #2.3.11.6
    "LmCompatibilityLevel",                                             #2.3.11.7
    "LDAPClientIntegrity",                                              #2.3.11.8
    "NTLMMinClientSec",                                                 #2.3.11.9
    "NTLMMinServerSec",                                                 #2.3.11.10
    "ShutdownWithoutLogon",                                             #2.3.13.1
    "ObCaseInsensitive",                                                #2.3.15.1
    "SessionManagerProtectionMode",                                     #2.3.15.2
    "FilterAdministratorToken",                                         #2.3.17.1
    "ConsentPromptBehaviorAdmin",                                       #2.3.17.2
    "ConsentPromptBehaviorUser",                                        #2.3.17.3
    "EnableInstallerDetection",                                         #2.3.17.4
    "EnableSecureUIAPaths",                                             #2.3.17.5
    "EnableLUA",                                                        #2.3.17.6
    "PromptOnSecureDesktop",                                            #2.3.17.7
    "EnableVirtualization",                                             #2.3.17.8
    #5.1 Not Applicable to Member Server (2023.01.27)
    "DisableSpooler",                                                   #5.2 (2023.01.27)
    "DomainEnableFirewall",                                             #9.1.1
    "DomainDefaultInboundAction",                                       #9.1.2
    "DomainDefaultOutboundAction",                                      #9.1.3
    #"DomainDisableNotifications",                                       #9.1.4
    "DomainLogFilePath",                                                #9.1.5
    "DomainLogFileSize",                                                #9.1.6
    "DomainLogDroppedPackets",                                          #9.1.7
    "DomainLogSuccessfulConnections",                                   #9.1.8
    "PrivateEnableFirewall",                                            #9.2.1
    "PrivateDefaultInboundAction",                                      #9.2.2
    "PrivateDefaultOutboundAction",                                     #9.2.3
    #"PrivateDisableNotifications",                                      #9.2.4
    "PrivateLogFilePath",                                               #9.2.5
    "PrivateLogFileSize",                                               #9.2.6
    "PrivateLogDroppedPackets",                                         #9.2.7
    "PrivateLogSuccessfulConnections",                                  #9.2.8
    "PublicEnableFirewall",                                             #9.3.1
    "PublicDefaultInboundAction",                                       #9.3.2
    "PublicDefaultOutboundAction",                                      #9.3.3
    #"PublicDisableNotifications",                                       #9.3.4
    #"PublicAllowLocalPolicyMerge",                                      #9.3.5
    #"PublicAllowLocalIPsecPolicyMerge",                                 #9.3.6
    "PublicLogFilePath",                                                #9.3.7
    "PublicLogFileSize",                                                #9.3.8
    "PublicLogDroppedPackets",                                          #9.3.9
    "PublicLogSuccessfulConnections",                                   #9.3.10
    "AuditCredentialValidation",                                        #17.1.1
    #17.1.2 Not Applicable to Member Server (2023.01.27)
    #17.1.3 Not Applicable to Member Server (2023.01.27)
    "AuditComputerAccountManagement",                                   #17.2.1
    #17.2.2 Not Applicable to Member Server
    #17.2.3 Not Applicable to Member Server
    #17.2.4 Not Applicable to Member Server
    #"AuditSecurityGroupManagement",                                     #17.2.5
    "AuditUserAccountManagement",                                       #17.2.6
    "AuditPNPActivity",                                                 #17.3.1
    "AuditProcessCreation",                                             #17.3.2
    #17.4.1 Not Applicable to Member Server
    #17.4.2 Not Applicable to Member Server
    "AuditAccountLockout",                                              #17.5.1
    "AuditGroupMembership",                                             #17.5.2
    "AuditLogoff",                                                      #17.5.3
    "AuditLogon",                                                       #17.5.4
    "AuditOtherLogonLogoffEvents",                                      #17.5.5
    "AuditSpecialLogon",                                                #17.5.6
    #"AuditDetailedFileShare",                                           #17.6.1
    #"AuditFileShare",                                                   #17.6.2
    "AuditOtherObjectAccessEvents",                                     #17.6.3
    "AuditRemovableStorage",                                            #17.6.4
    "AuditPolicyChange",                                                #17.7.1
    "AuditAuthenticationPolicyChange",                                  #17.7.2
    #"AuditAuthorizationPolicyChange",                                   #17.7.3
    "AuditMPSSVCRuleLevelPolicyChange",                                 #17.7.4
    #"AuditOtherPolicyChangeEvents",                                     #17.7.5
    "AuditSpecialLogon",                                                #17.8.1
    #"AuditIPsecDriver",                                                 #17.9.1
    #"AuditOtherSystemEvents",                                           #17.9.2
    "AuditSecurityStateChange",                                         #17.9.3
    "AuditSecuritySystemExtension",                                     #17.9.4
    "AuditSystemIntegrity",                                             #17.9.5
    #"PreventEnablingLockScreenCamera",                                  #18.1.1.1
    #"PreventEnablingLockScreenSlideShow",                               #18.1.1.2
    "DisallowUsersToEnableOnlineSpeechRecognitionServices",             #18.1.2.2 (2023.01.27 - updated from 18.1.2.1)
    #"DisallowOnlineTips",                                               #18.1.3
    #18.2.1 to 18.2.6 is LAP Implementation. This script will not enable LAPs.
    # In lieu of Microsoft's LAPs, you can use: https://github.com/eneerge/NAble-LAPS-LocalAdmin-Password-Rotation
    #"LocalAccountTokenFilterPolicy",                                    #18.3.1
    "ConfigureSMBv1ClientDriver",                                       #18.3.2
    "ConfigureSMBv1server",                                             #18.3.3
    "DisableExceptionChainValidation",                                  #18.3.4
    #"RestrictDriverInstallationToAdministrators",                       #18.3.5 (2023.01.27 - added support)
    "NetBIOSNodeType",                                                  #18.3.6 (2023.01.27 - updated from 18.5.4.1)
    "WDigestUseLogonCredential",                                        #18.3.7 (2023.01.27 - updated from 18.3.6)
    "WinlogonAutoAdminLogon",                                           #18.4.1
    #"DisableIPv6SourceRouting",                                         #18.4.2
    #"DisableIPv4SourceRouting",                                         #18.4.3
    "EnableICMPRedirect",                                               #18.4.4
    #"TcpIpKeepAliveTime",                                               #18.4.5
    "NoNameReleaseOnDemand",                                            #18.4.6
    #"PerformRouterDiscovery",                                           #18.4.7
    #"SafeDllSearchMode",                                                #18.4.8
    #"ScreenSaverGracePeriod",                                           #18.4.9
    #"TcpMaxDataRetransmissionsV6",                                      #18.4.10
    #"TcpMaxDataRetransmissions",                                        #18.4.11
    #"SecurityWarningLevel",                                             #18.4.12
    #"EnableDNSOverDoH",                                                 #18.5.4.1 (2023.01.27 - added support)
    "EnableMulticast",                                                  #18.5.4.2
    #"EnableFontProviders",                                              #18.5.5.1
    "AllowInsecureGuestAuth",                                           #18.5.8.1
    #"LLTDIODisabled",                                                   #18.5.9.1
    #"RSPNDRDisabled",                                                   #18.5.9.2
    #"PeernetDisabled",                                                  #18.5.10.2
    "DisableNetworkBridges",                                            #18.5.11.2
    "ProhibitInternetConnectionSharing",                                #18.5.11.3
    #"StdDomainUserSetLocation",                                         #18.5.11.4
    "HardenedPaths",                                                    #18.5.14.1
    #"DisableIPv6DisabledComponents",                                    #18.5.19.2.1
    #"DisableConfigurationWirelessSettings",                             #18.5.20.1
    #"ProhibitaccessWCNwizards",                                         #18.5.20.2
    "fMinimizeConnections",                                             #18.5.21.1
    #"fBlockNonDomain",                                                  #18.5.21.2
    #"RegisterSpoolerRemoteRpcEndPoint",                                 #18.6.1 (2023.01.27 - added support)
    #"PrinterNoWarningNoElevationOnInstall",                             #18.6.2 (2023.01.27 - added support)
    #"PrinterUpdatePromptSettings",                                      #18.6.3 (2023.01.27 - added support)
    #"NoCloudApplicationNotification",                                   #18.7.1.1
    "ProcessCreationIncludeCmdLine",                                    #18.8.3.1
    "EncryptionOracleRemediation",                                      #18.8.4.1
    "AllowProtectedCreds",                                              #18.8.4.2
    "EnableVirtualizationBasedSecurity",                                #18.8.5.1
    "RequirePlatformSecurityFeatures",                                  #18.8.5.2
    "HypervisorEnforcedCodeIntegrity",                                  #18.8.5.3
    "HVCIMATRequired",                                                  #18.8.5.4
    "LsaCfgFlags",                                                      #18.8.5.5
    #18.8.5.6 Not Applicable to Member Server (2023.01.27)
    "ConfigureSystemGuardLaunch",                                       #18.8.5.7 (2023.01.27 - renamed from 18.8.6.7)
    #"PreventDeviceMetadataFromNetwork",                                 #18.8.7.2 (2023.01.27 - added support)
    "DriverLoadPolicy",                                                 #18.8.14.1
    "NoBackgroundPolicy",                                               #18.8.21.2
    "NoGPOListChanges",                                                 #18.8.21.3
    "EnableCdp",                                                        #18.8.21.4
    "DisableBkGndGroupPolicy",                                          #18.8.21.5
    "DisableWebPnPDownload",                                            #18.8.22.1.1
    #"PreventHandwritingDataSharing",                                    #18.8.22.1.2
    #"PreventHandwritingErrorReports",                                   #18.8.22.1.3
    #"ExitOnMSICW",                                                      #18.8.22.1.4
    #"NoWebServices",                                                    #18.8.22.1.5
    #"DisableHTTPPrinting",                                              #18.8.22.1.6
    #"NoRegistration",                                                   #18.8.22.1.7
    #"DisableContentFileUpdates",                                        #18.8.22.1.8
    #"NoOnlinePrintsWizard",                                             #18.8.22.1.9
    #"NoPublishingWizard",                                               #18.8.22.1.10
    #"CEIP",                                                             #18.8.22.1.11
    #"CEIPEnable",                                                       #18.8.22.1.2
    #"TurnoffWindowsErrorReporting",                                     #18.8.22.1.13
    #"SupportDeviceAuthenticationUsingCertificate",                      #18.8.25.1
    #"DeviceEnumerationPolicy",                                          #18.8.26.1
    #"BlockUserInputMethodsForSignIn",                                   #18.8.27.1
    #"BlockUserFromShowingAccountDetailsOnSignin",                       #18.8.28.1
    #"DontDisplayNetworkSelectionUI",                                    #18.8.28.2
    #"DontEnumerateConnectedUsers",                                      #18.8.28.3
    #"EnumerateLocalUsers",                                              #18.8.28.4
    #"DisableLockScreenAppNotifications",                                #18.8.28.5
    #"BlockDomainPicturePassword",                                       #18.8.28.6
    #"AllowDomainPINLogon",                                              #18.8.28.7
    #"AllowCrossDeviceClipboard",                                        #18.8.31.1
    #"UploadUserActivities",                                             #18.8.31.2
    #"AllowNetworkBatteryStandby",                                       #18.8.34.6.1
    #"AllowNetworkACStandby",                                            #18.8.34.6.2
    #"RequirePasswordWakes",                                             #18.8.34.6.3
    #"RequirePasswordWakesAC",                                           #18.8.34.6.4
    "fAllowUnsolicited",                                                #18.8.36.1
    "fAllowToGetHelp",                                                  #18.8.36.2
    "EnableAuthEpResolution",                                           #18.8.37.1 (2023.01.27 - mapping added)
    #"RestrictRemoteClients",                                            #18.8.37.2 (2023.01.27 - added)
    #18.8.40.1 Not Applicable to Member Server (2023.01.27)
    #"DisableQueryRemoteServer",                                         #18.8.48.5.1 (2023.01.27 - added to default configuration in script)
    #"ScenarioExecutionEnabled",                                         #18.8.48.11.1 (2023.01.27 - added to default configuration in script)
    #"DisabledAdvertisingInfo",                                          #18.8.50.1 (2023.01.27 - added to default configuration in script)
    #"NtpClientEnabled",                                                 #18.8.53.1.1 (2023.01.27 - added to default configuration in script)
    #"DisableWindowsNTPServer",                                          #18.8.53.1.2 (2023.01.27 - added to default configuration in script)
    #"AllowSharedLocalAppData",                                          #18.9.4.1 (2023.01.27 - added to default configuration in script)
    "MSAOptional",                                                      #18.9.6.1 (2023.01.27 - added to default configuration in script)
    #"NoAutoplayfornonVolume",                                           #18.9.8.1 (2023.01.27 - added to default configuration in script)
    #"NoAutorun",                                                        #18.9.8.2 (2023.01.27 - added to default configuration in script)
    #"NoDriveTypeAutoRun",                                               #18.9.8.3 (2023.01.27 - added to default configuration in script)
    #"EnhancedAntiSpoofing",                                             #18.9.10.1.1 (2023.01.27 - added to default configuration in script)
    #"DisallowCamera",                                                   #18.9.12.1 (2023.01.27 - added to default configuration in script)
    "DisableConsumerAccountStateContent",                               #18.9.14.1 (2023.01.27 - added support)
    "DisableWindowsConsumerFeatures",                                   #18.9.14.2 (2023.01.27 - added to default configuration in script, renamed from 18.9.13.1)
    #"RequirePinForPairing",                                             #18.9.15.1 (2023.01.27 - added to default configuration in script)
    "DisablePasswordReveal",                                            #18.9.16.1 (2023.01.27 - added to default configuration in script, renamed from 18.9.15.1)
    "DisableEnumerateAdministrators",                                   #18.9.16.2 (2023.01.27 - added to default configuration in script, renamed from 18.9.15.2)
    "DisallowTelemetry",                                                #18.9.17.1 (2023.01.27 - added to default configuration in script)
    #"DisableEnterpriseAuthProxy",                                       #18.9.17.2 (2023.01.27 - added to default configuration in script)
    #"DisableOneSettingsDownloads",                                      #18.9.17.3 (2023.01.27 - added support)
    #"DoNotShowFeedbackNotifications",                                   #18.9.17.4 (2023.01.27 - added support)
    #"EnableOneSettingsAuditing",                                        #18.9.17.5 (2023.01.27 - added support)
    #"LimitDiagnosticLogCollection",                                     #18.9.17.6 (2023.01.27 - added support)
    #"LimitDumpCollection",                                              #18.9.17.7 (2023.01.27 - added support)
    #"AllowBuildPreview",                                                #18.9.17.8 (2023.01.27 - added to default configuration in script)
    "EventLogRetention",                                                #18.9.27.1.1 (2023.01.27 - added to default configuration in script and renamed)
    "EventLogMaxSize",                                                  #18.9.27.1.2 (2023.01.27 - added to default configuration in script and renamed)
    "EventLogSecurityRetention",                                        #18.9.27.2.1 (2023.01.27 - added to default configuration in script and renamed)
    "EventLogSecurityMaxSize",                                          #18.9.27.2.2 (2023.01.27 - added to default configuration in script and renamed)
    "EventLogSetupRetention",                                           #18.9.27.3.1 (2023.01.27 - added to default configuration in script and renamed)
    "EventLogSetupMaxSize",                                             #18.9.27.3.2 (2023.01.27 - added to default configuration in script and renamed)    
    "EventLogSystemRetention",                                          #18.9.27.4.1 (2023.01.27 - added to default configuration in script and renamed)    
    "EventLogSystemMaxSize",                                            #18.9.27.4.2 (2023.01.27 - added to default configuration in script and renamed)
    "NoDataExecutionPrevention",                                        #18.9.31.2 (2023.01.27 - added to default configuration in script and renamed)
    "NoHeapTerminationOnCorruption",                                    #18.9.31.3 (2023.01.27 - added to default configuration in script and renamed)
    "PreXPSP2ShellProtocolBehavior",                                    #18.9.31.4 (2023.01.27 - added to default configuration in script and renamed)
    #"LocationAndSensorsDisableLocation",                                #18.9.41.1 (2023.01.27 - added to default configuration in script and renamed)
    #"MessagingAllowMessageSync",                                        #18.9.45.1 (2023.01.27 - added to default configuration in script and renamed)
    "MicrosoftAccountDisableUserAuth",                                  #18.9.46.1 (2023.01.27 - added to default configuration in script and renamed)
    
    "LocalSettingOverrideSpynetReporting",                              #18.9.47.4.1 (2023.01.27 - added to default configuration in script and renamed)
    #"SpynetReporting",                                                  #18.9.47.4.2 (2023.01.27 - added to default configuration in script and renamed)

    "ExploitGuard_ASR_Rules",                                           #18.9.47.5.1.1 (2023.01.27 - added to default configuration in script and renamed)
    # 18.9.47.5.1.2 - ASR Rules have been separated into different functions
    "ConfigureASRrules",                                                #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockOfficeCommsChildProcess",                     #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockOfficeCreateExeContent",                      #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockObfuscatedScripts",                           #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockOfficeInjectionIntoOtherProcess",             #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockAdobeReaderChildProcess",                     #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockWin32ApiFromOfficeMacro",                     #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockCredStealingFromLsass",                       #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockUntrustedUnsignedProcessesUSB",               #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockExeutablesFromEmails",                        #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockJSVBSLaunchingExeContent",                    #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockOfficeChildProcess",                          #18.9.47.5.1.2 (2023.01.27 - added to default configuration in script)
    "ConfigureASRRuleBlockPersistenceThroughWMI",                       #18.9.47.5.1.2 (2023.01.27 - added support)

    # Not in CIS, but recommended
    "ConfigureASRRuleBlockExploitedSignedDrivers",                      #18.9.47.5.1.2 (2023.01.30 - added support)
    "ConfigureASRRuleBlockExeUnlessMeetPrevalence",                     #18.9.47.5.1.2 (2023.01.30 - added support)
    "ConfigureASRRuleUseAdvancedRansomwareProtection",                  #18.9.47.5.1.2 (2023.01.30 - added support)
    "ConfigureASRRuleBlockProcessesFromPSExecandWmi",                   #18.9.47.5.1.2 (2023.01.30 - added support)

    "EnableNetworkProtection",                                          #18.9.47.5.3.1 (2023.01.27 - added to default configuration in script)
    #"EnableFileHashComputationFeature",                                 #18.9.47.6.1 (2023.01.27 - added support)
    "DisableIOAVProtection",                                            #18.9.47.9.1 (2023.01.27 - added support)
    "DisableRealtimeMonitoring",                                        #18.9.47.9.2 (2023.01.27 - added support)
    "DisableBehaviorMonitoring",                                        #18.9.47.9.3 (2023.01.27 - added support)
    "DisableScriptScanning",                                            #18.9.47.9.4 (2023.01.27 - added support)
    #"DisableGenericRePorts",                                            #18.9.47.11.1 (2023.01.27 - added support)
    #"DisableRemovableDriveScanning",                                    #18.9.47.12.1 (2023.01.27 - added support)
    "DisableEmailScanning",                                             #18.9.47.12.2 (2023.01.27 - added support)

    "PUAProtection",                                                    #18.9.47.15 (2023.02.01 - added to default configuration in script)
    "DisableAntiSpyware",                                               #18.9.47.16 (2023.02.01 - added to default configuration in script)



    #"OneDriveDisableFileSyncNGSC",                                      #18.9.58.1 (2023.01.27 - added to default configuration)
    #"DisablePushToInstall",                                             #18.9.64.1 (2023.01.27 - added support)
    "TerminalServicesDisablePasswordSaving",                            #18.9.65.2.2 (2023.01.27 - added to default configuration)

    #"fSingleSessionPerUser",                                            #18.9.65.3.2.1 (2023.01.27 - added to default configuration)
    #"EnableUiaRedirection",                                             #18.9.65.3.3.1 (2023.01.27 - added support)
    #"TerminalServicesfDisableCcm",                                      #18.9.65.3.3.2 (2023.01.27 - added to default configuration)
    "TerminalServicesfDisableCdm",                                      #18.9.65.3.3.3 (2023.01.27 - added to default configuration)
    #"fDisableLocationRedir",                                            #18.9.65.3.3.4 (2023.01.27 - added support)
    #"TerminalServicesfDisableLPT",                                      #18.9.65.3.3.5 (2023.01.27 - added to default configuration)
    #"TerminalServicesfDisablePNPRedir",                                 #18.9.65.3.3.6 (2023.01.27 - added to default configuration)
    "TerminalServicesfPromptForPassword",                               #18.9.65.3.9.1 (2023.01.27 - added to default configuration)
    "TerminalServicesfEncryptRPCTraffic",                               #18.9.65.3.9.2 (2023.01.27 - added to default configuration)
    #"TerminalServicesSecurityLayer",                                    #18.9.65.3.9.3 (2023.02.01 - added to default configuration)
    #"TerminalServicesUserAuthentication",                               #18.9.65.3.9.4 (2023.01.27 - added to default configuration)
    "TerminalServicesMinEncryptionLevel",                               #18.9.65.3.9.5 (2023.01.27 - added to default configuration, corrected min level value)
    #"TerminalServicesMaxIdleTime",                                      #18.9.65.3.10.1 (2023.01.27 - added to default configuration)
    #"TerminalServicesMaxDisconnectionTime",                             #18.9.65.3.10.2 (2023.01.27 - added to default configuration)
    "TerminalServicesDeleteTempDirsOnExit",                             #18.9.65.3.11.1 (2023.01.27 - added to default configuration, corrected reg value)
    "TerminalServicesPerSessionTempDir",                                #18.9.65.3.11.2 (2023.01.27 - added to default configuration, corrected reg value)
    "DisableEnclosureDownload",                                         #18.9.66.1 (2023.01.27 - added to default configuration)
    #"WindowsSearchAllowCloudSearch",                                    #18.9.67.2 (2023.01.27 - added to default configuration)
    "AllowIndexingEncryptedStoresOrItems",                              #18.9.67.3 (2023.01.27 - added to default configuration)
    #"NoGenTicket",                                                      #18.9.72.1 (2023.01.27 - added to default configuration)
    "DefenderSmartScreen",                                              #18.9.85.1.1 (2023.01.27 - added to default configuration, corrected reg value)
    #"AllowSuggestedAppsInWindowsInkWorkspace",                          #18.9.89.1 (2023.01.27 - added to default configuration)
    #"AllowWindowsInkWorkspace",                                         #18.9.89.2 (2023.01.27 - added to default configuration, corrected reg value)
    "InstallerEnableUserControl",                                       #18.9.90.1 (2023.01.27 - added to default configuration)
    "InstallerAlwaysInstallElevated",                                   #18.9.90.2 (2023.01.27 - added to default configuration)
    #"InstallerSafeForScripting",                                        #18.9.90.3 (2023.01.27 - added to default configuration)
    "DisableAutomaticRestartSignOn",                                    #18.9.91.1 (2023.01.27 - added to default configuration, corrected reg value)
    "EnableScriptBlockLogging",                                         #18.9.100.1 (2023.01.27 - added to default configuration, corrected reg value)
    "EnableTranscripting",                                              #18.9.100.2 (2023.01.27 - added to default configuration)
    "WinRMClientAllowBasic",                                            #18.9.102.1.1 (2023.01.27 - added to default configuration)
    "WinRMClientAllowUnencryptedTraffic",                               #18.9.102.1.2 (2023.01.30 - added support)
    "WinRMClientAllowDigest",                                           #18.9.102.1.3 (2023.01.27 - added to default configuration, corrected reg value)
    "WinRMServiceAllowBasic",                                           #18.9.102.2.1 (2023.01.27 - added to default configuration)
    "WinRMServiceAllowAutoConfig",                                      #18.9.102.2.2 (2023.01.27 - added to default configuration)
    #"WinRMServiceAllowUnencryptedTraffic",                              #18.9.102.2.3 (2023.01.27 - added to default configuration)
    "WinRMServiceDisableRunAs",                                         #18.9.102.2.4 (2023.01.27 - added to default configuration)
    #"WinRSAllowRemoteShellAccess",                                      #18.9.103.1 (2023.01.27 - added to default configuration)
    "DisallowExploitProtectionOverride"                                #18.9.105.2.1 (2023.01.27 - added to default configuration)
    #"NoAutoRebootWithLoggedOnUsers",                                    #18.9.108.1.1 (2023.01.27 - added to default configuration)
    #"ConfigureAutomaticUpdates",                                        #18.9.108.2.1 (2023.01.27 - added to default configuration)
    #"Scheduledinstallday",                                              #18.9.108.2.2 (2023.01.27 - added to default configuration)
    #"Managepreviewbuilds",                                              #18.9.108.4.1 (2023.01.27 - added to default configuration, corrected reg value)
    #"WindowsUpdateFeature",                                             #18.9.108.4.2 (2023.01.27 - added to default configuration)
    #"#WindowsUpdateQuality"                                              #18.9.108.4.3 (2023.01.27 - added to default configuration)
    
    # These configurations references a user SID and are not automated in this script. (2023.01.27)
    #19.1.3.1
    #19.1.3.1
    #19.1.3.2
    #19.1.3.3
    #19.5.1.1
    #19.6.6.1.1
    #19.7.4.1
    #19.7.4.2
    #19.7.8.1
    #19.7.8.2
    #19.7.8.3
    #19.7.8.4
    #19.7.8.5
    #19.7.28.1
    #19.7.43.1
    #19.7.47.2.1

)


# End configuration
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
$SID_BACKUP_OPERATORS = "*S-1-5-32-551"
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

function PrintControl([string]$code, [string]$description, [string]$level = "1") {    
    Write-Host "$($code) (L$($level)) $($description)" -ForegroundColor Yellow
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

function ValidatePasswords([string] $pass1, [string] $pass2) {
    if($pass1 -ne $pass2) { return $False }
    if($pass1 -notmatch "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$#^!%*?&])[A-Za-z\d@$#^!%*?&]{15,}$") { return $False }
    return $True;
}

function CreateNewLocalAdminAccount {
    CreateUserAccount $NewLocalAdmin $NewLocalAdminPassword $true
}


function EnforcePasswordHistory
{    
    PrintControl -code "1.1.1" -level "1" -description "Ensure 'Enforce password history' is set to '24 or more password(s)'" 
    Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Length of password history maintained' )
    Write-After ("After hardening: *******                   ")
    net accounts /uniquepw:24
}


function MaximumPasswordAge
{    
    PrintControl -code "1.1.2" -level "1" -description "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"     
    Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Maximum password age' )
    Write-After ("After hardening: *******                   ")
    net accounts /maxpwage:365
}


function MinimumPasswordAge
{    
    PrintControl -code "1.1.3" -level "1" -description "Ensure 'Minimum password age' is set to '1 or more day(s)'"         
    Write-Before ("Before hardening: *******               ")
    Write-Output (net accounts | Select-String -SimpleMatch 'Minimum password age' )
    Write-After ("After hardening: *******                   ")
    net accounts /minpwage:1
}


function MinimumPasswordLength
{    
    PrintControl -code "1.1.4" -level "1" -description "Ensure 'Minimum password length' is set to '14 or more character(s)'"     
    Write-Before ("Before hardening: *******               ")
    Write-Output ( net accounts | Select-String -SimpleMatch 'Minimum password length')
    Write-After ("After hardening: *******                   ")
    net accounts /MINPWLEN:14
}

function WindowsPasswordComplexityPolicyMustBeEnabled
{
    PrintControl -code "1.1.5" -level "1" -description "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"     
    secedit /export /cfg ${env:appdata}\secpol.cfg
    (Get-Content ${env:appdata}\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Out-File ${env:appdata}\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -force ${env:appdata}\secpol.cfg -confirm:$false
}

function DisablePasswordReversibleEncryption {
    PrintControl -code "1.1.6" -level "1" -description "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
    secedit /export /cfg ${env:appdata}\secpol.cfg
    (Get-Content ${env:appdata}\secpol.cfg).replace("ClearTextPassword = 1", "ClearTextPassword = 0") | Out-File ${env:appdata}\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -force ${env:appdata}\secpol.cfg -confirm:$false
}


function NoOneTrustCallerACM {    
    PrintControl -code "2.2.1" -level "1" -description "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"    
    SetUserRight "SeTrustedCredManAccessPrivilege" @($SID_NOONE)
}

function AccessComputerFromNetwork {    
    PrintControl -code "2.2.3" -level "1" -description "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'"    
    SetUserRight "SeNetworkLogonRight" ($SID_ADMINISTRATORS, $SID_AUTHENTICATED_USERS)
}

function NoOneActAsPartOfOperatingSystem {    
    PrintControl -code "2.2.4" -level "1" -description "Ensure 'Act as part of the operating system' is set to 'No One'"
    SetUserRight "SeTcbPrivilege" @($SID_NOONE)
}

function AdjustMemoryQuotasForProcess {
    PrintControl -code "2.2.6" -level "1" -description "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
    SetUserRight "SeIncreaseQuotaPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE, $SID_ADMINISTRATORS)
}

function AllowLogonLocallyToAdministrators {
    PrintControl -code "2.2.7" -level "1" -description "Ensure 'Allow log on locally' is set to 'Administrators'"    
    SetUserRight "SeInteractiveLogonRight" (,$SID_ADMINISTRATORS)
}

function LogonThroughRemoteDesktopServices {
    PrintControl -code "2.2.9" -level "1" -description "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"    
    SetUserRight "SeRemoteInteractiveLogonRight" ($SID_ADMINISTRATORS, $SID_REMOTE_DESKTOP_USERS)
}


function BackupFilesAndDirectories {
    PrintControl -code "2.2.10" -level "1" -description "Ensure 'Back up files and directories' is set to 'Administrators'"    
    SetUserRight "SeBackupPrivilege" (,$SID_ADMINISTRATORS)
}

function ChangeSystemTime {
    PrintControl -code "2.2.11" -level "1" -description "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"    
    SetUserRight "SeSystemtimePrivilege" ($SID_LOCAL_SERVICE,$SID_ADMINISTRATORS)
}

function ChangeTimeZone {
    PrintControl -code "2.2.12" -level "1" -description "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"    
    SetUserRight "SeTimeZonePrivilege" ($SID_LOCAL_SERVICE,$SID_ADMINISTRATORS)
}

function CreatePagefile {
    PrintControl -code "2.2.13" -level "1" -description "Ensure 'Create a pagefile' is set to 'Administrators'"
    SetUserRight "SeCreatePagefilePrivilege" (,$SID_ADMINISTRATORS)
}

function NoOneCreateTokenObject {
    PrintControl -code "2.2.14" -level "1" -description "Ensure 'Create a token object' is set to 'No One'"    
    SetUserRight "SeCreateTokenPrivilege" @($SID_NOONE)
}

function CreateGlobalObjects {
    PrintControl -code "2.2.15" -level "1" -description "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"    
    SetUserRight "SeCreateGlobalPrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE,$SID_ADMINISTRATORS,$SID_SERVICE)
}


function NoOneCreatesSharedObjects {
    #2.2.16 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create permanent shared objects
    Write-Info "2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'"
    SetUserRight "SeCreatePermanentPrivilege" @($SID_NOONE)
}

function CreateSymbolicLinks {
    
    #Check if Hyper-V is installed before deploying the setting, so no unrecognized SID will be added when Hyper-V is not installed
    if ((Get-WindowsFeature -Name Hyper-V).Installed -eq $false)
    {
        PrintControl -code "2.2.18" -level "1" -description "Ensure 'Create symbolic links' is set to 'Administrators'"        
        SetUserRight "SeCreateSymbolicLinkPrivilege" (,$SID_ADMINISTRATORS)
    }
    else {
        PrintControl -code "2.2.18" -level "1" -description "Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'"        
        SetUserRight "SeCreateSymbolicLinkPrivilege" ($SID_ADMINISTRATORS,$SID_VIRTUAL_MACHINE)
    }
}

function DebugPrograms {
    PrintControl -code "2.2.19" -level "1" -description "Ensure 'Debug programs' is set to 'Administrators'"    
    SetUserRight "SeDebugPrivilege" (,$SID_ADMINISTRATORS)
}

function DenyNetworkAccess {        
    PrintControl -code "2.2.20" -level "1" -description "Ensure 'Deny access to this computer from the network' to include 'Guests, Local account, and member of Administrators group'"

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
    PrintControl -code "2.2.21" -level "1" -description "Ensure 'Deny log on as a batch job' to include 'Guests'"    
    SetUserRight "SeDenyBatchLogonRight" (,$SID_GUESTS)
}

function DenyGuestServiceLogon {
    PrintControl -code "2.2.22" -level "1" -description "Ensure 'Deny log on as a service' to include 'Guests'"    
    SetUserRight "SeDenyServiceLogonRight" (,$SID_GUESTS)
}

function DenyGuestLocalLogon {
    PrintControl -code "2.2.23" -level "1" -description "Ensure 'Deny log on locally' to include 'Guests'"

    $addlDenyUsers = ""
    if ($AdditionalUsersToDenyLocalLogon.Count -gt 0) {
      $addlDenyUsers = $AdditionalUsersToDenyLocalLogon -join ","
    }

    SetUserRight "SeDenyInteractiveLogonRight" ($addlDenyUsers,$SID_GUESTS)
}

function DenyRemoteDesktopServiceLogon {
    PrintControl -code "2.2.24" -level "1" -description "Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'"    

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
    PrintControl -code "2.2.26" -level "1" -description "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"   
    SetUserRight "SeDelegateSessionUserImpersonatePrivilege" @($SID_NOONE)
}

function ForceShutdownFromRemoteSystem {
    PrintControl -code "2.2.27" -level "1" -description "Ensure 'Force shutdown from a remote system' is set to 'Administrators'"    
    SetUserRight "SeRemoteShutdownPrivilege" (,$SID_ADMINISTRATORS)
}

function GenerateSecurityAudits {
    PrintControl -code "2.2.28" -level "1" -description "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"    
    SetUserRight "SeAuditPrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE)
}

function ImpersonateClientAfterAuthentication {
    PrintControl -code "2.2.30" -level "1" -description "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS'"    

    if ($true -eq $IncludeIisUsr) {
        SetUserRight "SeImpersonatePrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE,$SID_ADMINISTRATORS,$SID_SERVICE,$SID_IIS_IUSR)
    } else {
        SetUserRight "SeImpersonatePrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE,$SID_ADMINISTRATORS,$SID_SERVICE)
    }
}

function IncreaseSchedulingPriority {
    PrintControl -code "2.2.31" -level "1" -description "Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
    SetUserRight "SeIncreaseBasePriorityPrivilege" ($SID_ADMINISTRATORS,$SID_WINDOW_MANAGER_GROUP)
}

function LoadUnloadDeviceDrivers {
    PrintControl -code "2.2.32" -level "1" -description "Ensure 'Load and unload device drivers' is set to 'Administrators'"    
    SetUserRight "SeLoadDriverPrivilege" (,$SID_ADMINISTRATORS)
}

function NoOneLockPagesInMemory {
    PrintControl -code "2.2.33" -level "1" -description "Ensure 'Lock pages in memory' is set to 'No One'"    
    SetUserRight "SeLockMemoryPrivilege" @($SID_NOONE)
}

function ManageAuditingAndSecurity {
    PrintControl -code "2.2.35" -level "1" -description "Ensure 'Manage auditing and security log' is set to 'Administrators'"    
    SetUserRight "SeSecurityPrivilege" @($SID_ADMINISTRATORS)
}

function NoOneModifiesObjectLabel {
    PrintControl -code "2.2.36" -level "1" -description "Ensure 'Modify an object label' is set to 'No One'"    
    SetUserRight "SeRelabelPrivilege" @($SID_NOONE)
}

function FirmwareEnvValues {
    PrintControl -code "2.2.37" -level "1" -description "Ensure 'Modify firmware environment values' is set to 'Administrators'"    
    SetUserRight "SeSystemEnvironmentPrivilege" (,$SID_ADMINISTRATORS)
}

function VolumeMaintenance {
    PrintControl -code "2.2.38" -level "1" -description "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"    
    SetUserRight "SeManageVolumePrivilege" (,$SID_ADMINISTRATORS)

}

function ProfileSingleProcess {
    PrintControl -code "2.2.39" -level "1" -description "Ensure 'Profile single process' is set to 'Administrators'"    
    SetUserRight "SeProfileSingleProcessPrivilege" (,$SID_ADMINISTRATORS)
}

function ProfileSystemPerformance {
    PrintControl -code "2.2.40" -level "1" -description "Ensure 'Profile system performance' is set to 'Administrators,NT SERVICE\WdiServiceHost'"
    SetUserRight "SeSystemProfilePrivilege" ($SID_ADMINISTRATORS,$SID_WDI_SYSTEM_SERVICE)
}

function ReplaceProcessLevelToken {
    PrintControl -code "2.2.41" -level "1" -description "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"    
    SetUserRight "SeAssignPrimaryTokenPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE)
}

function RestoreFilesDirectories {
    PrintControl -code "2.2.42" -level "1" -description "Ensure 'Restore files and directories' is set to 'Administrators'"
    SetUserRight "SeRestorePrivilege" (,$SID_ADMINISTRATORS)
}

function SystemShutDown {
    PrintControl -code "2.2.43" -level "1" -description "Ensure 'Shut down the system' is set to 'Administrators, Backup Operators'"    
    SetUserRight "SeShutdownPrivilege" (,$SID_ADMINISTRATORS,$SID_BACKUP_OPERATORS)
}

function TakeOwnershipFiles {
    PrintControl -code "2.2.45" -level "1" -description "Ensure 'Take ownership of files or other objects' is set to 'Administrators'"    
    SetUserRight "SeTakeOwnershipPrivilege" (,$SID_ADMINISTRATORS)
}

function DisableMicrosoftAccounts {
    PrintControl -code "2.3.1.1" -level "1" -description "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"        
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser" (,"4,3")
}

function DisableGuestAccount {
    PrintControl -code "2.3.1.2" -level "1" -description "Ensure 'Accounts: Guest account status' is set to 'Disabled'"        
    SetSecurityPolicy "EnableGuestAccount" (,"0")
}


function LimitBlankPasswordConsole {
    PrintControl -code "2.3.1.3" -level "1" -description "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" (,"4,1")
}


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
    
    PrintControl -code "2.3.1.4" -level "1" -description "Configure 'Accounts: Rename administrator account'"    
    Write-Info "- Renamed to $($global:AdminNewAccountName)"
    SetSecurityPolicy "NewAdministratorName" (,"`"$($global:AdminNewAccountName)`"")
    Set-LocalUser -Name $global:AdminNewAccountName -Description ""
}


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
    
    PrintControl -code "2.3.1.5" -level "1" -description "Configure 'Accounts: Rename guest account'"    
    Write-Info "- Renamed to $($GuestNewAccountName)"
    SetSecurityPolicy "NewGuestName" (,"`"$($GuestNewAccountName)`"")
    Set-LocalUser -Name $GuestNewAccountName -Description ""
}



function AuditForceSubCategoryPolicy {
    PrintControl -code "2.3.2.1" -level "1" -description "Ensure 'Audit: Force audit policy subcategory settings to override audit policy category settings' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy" (,"4,1")
}

function AuditForceShutdown {
    PrintControl -code "2.3.2.2" -level "1" -description "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail" (,"4,0")
}


function DevicesAdminAllowedFormatEject {
    PrintControl -code "2.3.4.1" -level "1" -description "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"    
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD" (,"1,`"0`"")
}

function PreventPrinterInstallation {
    PrintControl -code "2.3.4.2" -level "1" -description "Ensure 'Devices: Prevent users from installing printer drivers'is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers" (,"4,1")
}

function SignEncryptAllChannelData {
    PrintControl -code "2.3.6.1" -level "1" -description "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal" (,"4,1")
}

function SecureChannelWhenPossible {
    PrintControl -code "2.3.6.2" -level "1" -description "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel" (,"4,1")
}

function DigitallySignChannelWhenPossible {
    PrintControl -code "2.3.6.3" -level "1" -description "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel" (,"4,1")
}

function EnableAccountPasswordChanges {
    PrintControl -code "2.3.6.4" -level "1" -description "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange" (,"4,0")
}


function MaximumAccountPasswordAge {
    PrintControl -code "2.3.6.5" -level "1" -description "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge" (,"4,30")
}


function MachineInactivityLimit {
    PrintControl -code "2.3.7.1" -level "1" -description "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"    
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs" (,"4,900")
}

function LogonLegalNotice {
    PrintControl -code "2.3.7.2" -level "1" -description "Configure 'Interactive logon: Message text for users attempting to log on'"
    if ($LogonLegalNoticeMessage.Length -gt 0) {
        SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText" ("7",$LogonLegalNoticeMessage)
    }
    else {
        SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText" ("7,")
    }
}

function LogonLegalNoticeTitle {
    PrintControl -code "2.3.7.3" -level "1" -description "Configure 'Interactive logon: Message title for users attempting to log on'"    
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption" (,"1,`"$($LogonLegalNoticeMessageTitle)`"")
}

function PromptUserPassExpiration {
    PrintControl -code "2.3.7.4" -level "1" -description "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"    
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning" (,"4,5")
}

function NetworkClientSignCommunications {
    PrintControl -code "2.3.8.1" -level "1" -description "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature" (,"4,1")
}

function EnableSecuritySignature {
    PrintControl -code "2.3.8.2" -level "1" -description "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"    
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" "1" $REG_DWORD
}

function DisableSmbUnencryptedPassword {
    PrintControl -code "2.3.8.3" -level "1" -description "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword" (,"4,0")
}

function IdleTimeSuspendingSession {
    PrintControl -code "2.3.9.1" -level "1" -description "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect" (,"4,15")
}

function NetworkServerAlwaysDigitallySign {
    PrintControl -code "2.3.9.2" -level "1" -description "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature" (,"4,1")
}

function LanManSrvEnableSecuritySignature{
    PrintControl -code "2.3.9.3" -level "1" -description "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"    
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "EnableSecuritySignature" "1" $REG_DWORD
}

function LanManServerEnableForcedLogOff {
    PrintControl -code "2.3.9.4" -level "1" -description "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff" (,"4,1")
}

function LanManServerSmbServerNameHardeningLevel {
    
    if ($AllowAccessToSMBWithDifferentSPN -eq $false) {
        PrintControl -code "2.3.9.5" -level "1" -description "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
        SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel" (,"4,1")
    }
    else {
        Write-Red "Opposing 2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
        Write-Red "- You enabled $AllowAccessToSMBWithDifferentSPN. This CIS configuration has been altered so that SMB shares can be accessed by SPNs unknown to the server."
        SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel" (,"4,0")
    }
}

function LSAAnonymousNameDisabled {
    PrintControl -code "2.3.10.1" -level "1" -description "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"    
    SetSecurityPolicy "LSAAnonymousNameLookup" (,"0")
    SetRegistry "HKLM:\System\CurrentControlSet\Control\Lsa" "TurnOffAnonymousBlock" "1" $REG_DWORD
}

function RestrictAnonymousSAM {
    PrintControl -code "2.3.10.2" -level "1" -description "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM" (,"4,1")
}

function RestrictAnonymous {
    PrintControl -code "2.3.10.3" -level "1" -description "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous" (,"4,1")
}

function EveryoneIncludesAnonymous {
    PrintControl -code "2.3.10.4" -level "1" -description "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous" (,"4,0")
}

function NullSessionPipes {
    PrintControl -code "2.3.10.6" -level "1" -description "Configure 'Network access: Named Pipes that can be accessed anonymously'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes" ("7,", " ")
}

function AllowedExactPaths {
    PrintControl -code "2.3.10.7" -level "1" -description "Configure 'Network access: Remotely accessible registry paths'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine" (
        "7",
        "System\CurrentControlSet\Control\ProductOptions",
        "System\CurrentControlSet\Control\Server Applications",
        "Software\Microsoft\Windows NT\CurrentVersion")
}

function AllowedPaths {
    PrintControl -code "2.3.10.8" -level "1" -description "Configure 'Network access: Remotely accessible registry paths and sub-paths'"    
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
    PrintControl -code "2.3.10.9" -level "1" -description "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess" (,"4,1")
}

function RestrictRemoteSAM {
    PrintControl -code "2.3.10.10" -level "1" -description "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM" (,'1,"O:BAG:BAD:(A;;RC;;;BA)"')
}

function NullSessionShares {
    PrintControl -code "2.3.10.11" -level "1" -description "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares" (,"7,")
}

function LsaForceGuest {
    PrintControl -code "2.3.10.12" -level "1" -description "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest" (,"4,0")
}

function LsaUseMachineId {
    PrintControl -code "2.3.11.1" -level "1" -description "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId" (,"4,1")
}

function AllowNullSessionFallback {
    PrintControl -code "2.3.11.2" -level "1" -description "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback" (,"4,0")
}

function AllowOnlineID {
    PrintControl -code "2.3.11.3" -level "1" -description "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID" (,"4,0")
}

function SupportedEncryptionTypes {
    PrintControl -code "2.3.11.4" -level "1" -description "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"    
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes" (,"4,2147483640")
}

function NoLMHash {
    PrintControl -code "2.3.11.5" -level "1" -description "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash" (,"4,1")
}

function LmCompatibilityLevel {
    PrintControl -code "2.3.11.6" -level "1" -description "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel" (,"4,5")
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" "5" $REG_DWORD
}

function LDAPClientIntegrity {
    PrintControl -code "2.3.11.7" -level "1" -description "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity" (,"4,1")
}

function NTLMMinClientSec {
    PrintControl -code "2.3.11.8" -level "1" -description "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec" (,"4,537395200")
}

function NTLMMinServerSec {
    PrintControl -code "2.3.11.9" -level "1" -description "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec" (,"4,537395200")
}

function ShutdownWithoutLogon {
    PrintControl -code "2.3.13.1" -level "1" -description "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon" (,"4,0")
}

function ObCaseInsensitive {
    PrintControl -code "2.3.15.1" -level "1" -description "Ensure 'System objects: Require case insensitivity for nonWindows subsystems' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive" (, "4,1")
}

function SessionManagerProtectionMode {
    PrintControl -code "2.3.15.2" -level "1" -description "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode" (,"4,1")
}

function FilterAdministratorToken {
    PrintControl -code "2.3.17.1" -level "1" -description "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken" (,"4,1")
}

function ConsentPromptBehaviorAdmin {
    PrintControl -code "2.3.17.2" -level "1" -description "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"    
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" (,"4,2")
}


function ConsentPromptBehaviorUser {
    PrintControl -code "2.3.17.3" -level "1" -description "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"    
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser" (,"4,0")
}

function EnableInstallerDetection {
    PrintControl -code "2.3.17.4" -level "1" -description "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection" (,"4,1")
}

function EnableSecureUIAPaths {
    PrintControl -code "2.3.17.5" -level "1" -description "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"    
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths" (, "4,1")
}

function EnableLUA {
    
    if ($DontSetEnableLUAForVeeamBackup -eq $false) {
        PrintControl -code "2.3.17.6" -level "1" -description "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"            
        SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" (, "4,1")
    }
    else {
        Write-Red "Opposing 2.3.17.6 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
        Write-Red "- You enabled $DontSetEnableLUAForVeeamBackup. This setting has been opposed and set to 0 against CIS recommendations, but Veeam Backup will be able to perform backup operations."
        SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" (, "4,0")
    }
}

function PromptOnSecureDesktop {
    PrintControl -code "2.3.17.7" -level "1" -description "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"        
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop" (, "4,1")
}


function EnableVirtualization {
    PrintControl -code "2.3.17.8" -level "1" -description "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
    SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization" (, "4,1")
}

function DisableSpooler {
    PrintControl -code "5.2" -level "1" -description "Ensure 'Print Spooler (Spooler)' is set to 'Disabled'"    
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" "Start" "4" $REG_DWORD
}

function DomainEnableFirewall {
    PrintControl -code "9.1.1" -level "1" -description "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall" "1" $REG_DWORD
}

function DomainDefaultInboundAction {
    PrintControl -code "9.1.2" -level "1" -description "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"     
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultInboundAction" "1" $REG_DWORD
}

function DomainDefaultOutboundAction {
    PrintControl -code "9.1.3" -level "1" -description "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultOutboundAction" "0" $REG_DWORD
}

function DomainLogFilePath {
    PrintControl -code "9.1.4" -level "1" -description "Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\domainfw.log" $REG_SZ
}

function DomainLogFileSize {
    PrintControl -code "9.1.5" -level "1" -description "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFileSize" $WindowsFirewallLogSize $REG_DWORD
}

function DomainLogDroppedPackets {
    PrintControl -code "9.1.6" -level "1" -description "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"        
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogDroppedPackets" "1" $REG_DWORD
}

function DomainLogSuccessfulConnections {
    PrintControl -code "9.1.7" -level "1" -description "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"  
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogSuccessfulConnections" "1" $REG_DWORD
}

function PrivateEnableFirewall {
    PrintControl -code "9.2.1" -level "1" -description "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"      
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall" "1" $REG_DWORD
}

function PrivateDefaultInboundAction {
    PrintControl -code "9.2.2" -level "1" -description "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"      
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultInboundAction" "1" $REG_DWORD
}

function PrivateDefaultOutboundAction {
    PrintControl -code "9.2.3" -level "1" -description "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"      
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultOutboundAction" "0" $REG_DWORD
}

function PrivateLogFilePath {
    PrintControl -code "9.2.4" -level "1" -description "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"  
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\privatefw.log" $REG_SZ
}

function PrivateLogFileSize {
    PrintControl -code "9.2.5" -level "1" -description "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"      
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize" $WindowsFirewallLogSize $REG_DWORD
}

function PrivateLogDroppedPackets {
    PrintControl -code "9.2.6" -level "1" -description "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"      
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets" "1" $REG_DWORD
}

function PrivateLogSuccessfulConnections {
    PrintControl -code "9.2.7" -level "1" -description "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"      
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" "1" $REG_DWORD
}

function PublicEnableFirewall {
    PrintControl -code "9.3.1" -level "1" -description "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "EnableFirewall" "1" $REG_DWORD
}

function PublicDefaultInboundAction {
    PrintControl -code "9.3.2" -level "1" -description "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultInboundAction" "1" $REG_DWORD
}


function PublicDefaultOutboundAction {
    PrintControl -code "9.3.3" -level "1" -description "Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultOutboundAction" "0" $REG_DWORD
}


function PublicLogFilePath {
    PrintControl -code "9.3.4" -level "1" -description "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\publicfw.log" $REG_SZ
}

function PublicLogFileSize {
    PrintControl -code "9.3.5" -level "1" -description "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFileSize" $WindowsFirewallLogSize $REG_DWORD
}

function PublicLogDroppedPackets {
    PrintControl -code "9.3.6" -level "1" -description "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogDroppedPackets" "1" $REG_DWORD
}

function PublicLogSuccessfulConnections {
    PrintControl -code "9.3.7" -level "1" -description "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogSuccessfulConnections" "1" $REG_DWORD
}

function AuditCredentialValidation {
    PrintControl -code "17.1.1" -level "1" -description "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"    
    Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
}

function AuditComputerAccountManagement {
    PrintControl -code "17.2.4" -level "1" -description "Ensure 'Audit Application Group Management' is set to 'Success and Failure'"    
    Auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
}

function AuditUserAccountManagement {
    PrintControl -code "17.2.5" -level "1" -description "Ensure 'Audit User Account Management' is set to 'Success and Failure'"    
    Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
}

function AuditPNPActivity {
    PrintControl -code "17.3.1" -level "1" -description "Ensure 'Audit PNP Activity' is set to include 'Success'" 
    Auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable
}

function AuditProcessCreation {
    PrintControl -code "17.3.2" -level "1" -description "Ensure 'Audit Process Creation' is set to include 'Success'"    
    Auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
}

function AuditAccountLockout {
    PrintControl -code "17.5.1" -level "1" -description "Ensure 'Audit Account Lockout' is set to include 'Failure'"    
    Auditpol /set /subcategory:"Account Lockout" /success:disable /failure:enable
}

function AuditGroupMembership  {
    PrintControl -code "17.5.2" -level "1" -description "Ensure 'Audit Group Membership' is set to include 'Success'"    
    Auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable
}

function AuditLogoff {
    PrintControl -code "17.5.3" -level "1" -description "Ensure 'Audit Logoff' is set to include 'Success'"    
    Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
}

function AuditLogon {
    PrintControl -code "17.5.4" -level "1" -description "Ensure 'Audit Logon' is set to 'Success and Failure'"        
    Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
} 

function AuditOtherLogonLogoffEvents {
    PrintControl -code "17.5.5" -level "1" -description "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
}

function AuditSpecialLogon {
    PrintControl -code "17.5.6" -level "1" -description "Ensure 'Audit Special Logon' is set to include 'Success'"    
    Auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
}

function AuditOtherObjectAccessEvents {
    PrintControl -code "17.6.1" -level "1" -description "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"    
    Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
}

function AuditRemovableStorage {
    PrintControl -code "17.6.2" -level "1" -description "Ensure 'Audit Removable Storage' is set to 'Success and Failure'"    
    Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
}

function AuditPolicyChange {
    PrintControl -code "17.7.1" -level "1" -description "Ensure 'Audit Audit Policy Change' is set to include 'Success'"    
    Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:disable
}

function AuditAuthenticationPolicyChange {
    PrintControl -code "17.7.2" -level "1" -description "Ensure 'Audit Authentication Policy Change' is set to include 'Success'"    
    Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:disable
}

function AuditMPSSVCRuleLevelPolicyChange {
    PrintControl -code "17.7.3" -level "1" -description "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
    Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
}

function AuditSpecialLogon {
    PrintControl -code "17.8.1" -level "1" -description "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"    
    Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
}

function AuditSecurityStateChange {
    PrintControl -code "17.9.1" -level "1" -description "Ensure 'Audit Security State Change' is set to include 'Success'"    
    Auditpol /set /subcategory:"Security State Change" /success:enable /failure:disable
}

function AuditSecuritySystemExtension {
    PrintControl -code "17.9.2" -level "1" -description "Ensure 'Audit Security System Extension' is set to include 'Success'"    
    Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:disable
}

function AuditSystemIntegrity {
    PrintControl -code "17.9.3" -level "1" -description "Ensure 'Audit System Integrity' is set to 'Success and Failure'"    
    Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
}

function DisallowUsersToEnableOnlineSpeechRecognitionServices {
    PrintControl -code "18.1.2.2" -level "1" -description "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"        
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" "0" $REG_DWORD
}

function ConfigureSMBv1ClientDriver  {
    PrintControl -code "18.3.1" -level "1" -description "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)"        
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" "4" $REG_DWORD
}

function ConfigureSMBv1server {
    PrintControl -code "18.3.2" -level "1" -description "Ensure 'Configure SMB v1 server' is set to 'Disabled'"        
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" "0" $REG_DWORD
}

function DisableExceptionChainValidation {
    PrintControl -code "18.3.3" -level "1" -description "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" "0" $REG_DWORD
}

function NetBIOSNodeType {
    PrintControl -code "18.3.4" -level "1" -description "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"    
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType" "2" $REG_DWORD
}

function WDigestUseLogonCredential   {
    PrintControl -code "18.3.5" -level "1" -description "Ensure 'WDigest Authentication' is set to 'Disabled'"    
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" "0" $REG_DWORD
}

# MSS Group Policies are not supported by GPEDIT anymore. the values must be ckecked directly on the registry

function WinlogonAutoAdminLogon {
    PrintControl -code "18.4.1" -level "1" -description "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0" $REG_DWORD
}

function EnableICMPRedirect {
    PrintControl -code "18.4.3" -level "1" -description "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"    
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" "0"  $REG_DWORD
}

function NoNameReleaseOnDemand {
    PrintControl -code "18.4.4" -level "1" -description "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"    
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NoNameReleaseOnDemand" "1" $REG_DWORD
}

function EnableMulticast {
    PrintControl -code "18.5.4.1" -level "1" -description "Ensure 'Turn off multicast name resolution' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" "0" $REG_DWORD
}

function AllowInsecureGuestAuth {
    PrintControl -code "18.5.8.1" -level "1" -description "Ensure 'Enable insecure guest logons' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth" "0" $REG_DWORD
}

function DisableNetworkBridges {
    PrintControl -code "18.5.11.2" -level "1" -description "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NLA" "0"  $REG_DWORD
}

function ProhibitInternetConnectionSharing {
    PrintControl -code "18.5.11.3" -level "1" -description "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI" "0"  $REG_DWORD
}

function HardenedPaths {
    PrintControl -code "18.5.14.1" -level "1" -description "Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication' and 'Require Integrity' set for all NETLOGON and SYSVOL shares"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON" "RequireMutualAuthentication=1, RequireIntegrity=1" $REG_SZ
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\SYSVOL" "RequireMutualAuthentication=1, RequireIntegrity=1" $REG_SZ
}

function fMinimizeConnections {
    PrintControl -code "18.5.21.1" -level "1" -description "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"        
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections" "3" $REG_DWORD
}


function ProcessCreationIncludeCmdLine {
    PrintControl -code "18.8.3.1" -level "1" -description "Ensure 'Include command line in process creation events' is set to 'Disabled'"        
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" "1" $REG_DWORD
}

function EncryptionOracleRemediation {
    PrintControl -code "18.8.4.1" -level "1" -description "Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'"        
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" "0" $REG_DWORD
}

function AllowProtectedCreds {
    PrintControl -code "18.8.4.2" -level "1" -description "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" "1" $REG_DWORD
}

function EnableVirtualizationBasedSecurity {
    PrintControl -code "18.8.5.1" -level "1" -description "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity" "1" $REG_DWORD
}

function RequirePlatformSecurityFeatures {
    PrintControl -code "18.8.5.2" -level "1" -description "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures" "3" $REG_DWORD
}

function HypervisorEnforcedCodeIntegrity {
    PrintControl -code "18.8.5.3" -level "1" -description "Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity" "1" $REG_DWORD
}

function HVCIMATRequired {
    PrintControl -code "18.8.5.4" -level "1" -description "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired" "1" $REG_DWORD
}

function LsaCfgFlags {
    PrintControl -code "18.8.5.5" -level "1" -description "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags" "1" $REG_DWORD
}

function ConfigureSystemGuardLaunch {
    PrintControl -code "18.8.5.7" -level "1" -description "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "ConfigureSystemGuardLaunch" "1" $REG_DWORD
}

function DriverLoadPolicy {
    PrintControl -code "18.8.14.1" -level "1" -description "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"    
    SetRegistry "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" "3" $REG_DWORD
}


function NoBackgroundPolicy {
    PrintControl -code "18.8.21.2" -level "1" -description "Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" "0" $REG_DWORD
}


function NoGPOListChanges {
    PrintControl -code "18.8.21.3" -level "1" -description "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" "0" $REG_DWORD
}

function EnableCdp {
    PrintControl -code "18.8.21.4" -level "1" -description "Ensure 'Continue experiences on this device' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp" "0" $REG_DWORD
}

function DisableBkGndGroupPolicy {
    PrintControl -code "18.8.21.5" -level "1" -description "Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"    
    DeleteRegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableBkGndGroupPolicy"
}


function DisableWebPnPDownload {
    PrintControl -code "18.8.22.1.1" -level "1" -description "Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" "1" $REG_DWORD
}

function BlockUserFromShowingAccountDetailsOnSignin {
    PrintControl -code "18.8.28.1" -level "1" -description "Ensure 'Block user from showing account details on signin' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin" "1" $REG_DWORD
}

function fAllowUnsolicited {
    PrintControl -code "18.8.36.1" -level "1" -description "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited" "0" $REG_DWORD
}

function fAllowToGetHelp {
    PrintControl -code "18.8.36.2" -level "1" -description "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" "0" $REG_DWORD
}

function EnableAuthEpResolution {
    PrintControl -code "18.8.37.1" -level "1" -description "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution" "1" $REG_DWORD
}

function MSAOptional {
    PrintControl -code "18.9.6.1" -level "1" -description "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"        
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional" "1" $REG_DWORD
}

function DisableConsumerAccountStateContent {
    PrintControl -code "18.9.14.1" -level "1" -description "Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'"        
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent" "1" $REG_DWORD
}

function DisableWindowsConsumerFeatures {
    PrintControl -code "18.9.14.2" -level "1" -description "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "1" $REG_DWORD
}


function DisablePasswordReveal {
    PrintControl -code "18.9.16.1" -level "1" -description "Ensure 'Do not display the password reveal button' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal" "1" $REG_DWORD
}

function DisableEnumerateAdministrators {
    PrintControl -code "18.9.16.2" -level "1" -description "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators" "0" $REG_DWORD
}

function DisallowTelemetry {
    PrintControl -code "18.9.17.1" -level "1" -description "Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "0" $REG_DWORD
}

function EventLogRetention  {
    PrintControl -code "18.9.27.1.1" -level "1" -description "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "Retention" "0" $REG_DWORD
}

function EventLogMaxSize {
    PrintControl -code "18.9.27.1.2" -level "1" -description "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize" $EventLogMaxFileSize $REG_DWORD
}

function EventLogSecurityRetention {
    PrintControl -code "18.9.27.2.1" -level "1" -description "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention" "0" $REG_DWORD
}

function EventLogSecurityMaxSize {
    PrintControl -code "18.9.27.2.2" -level "1" -description "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize" $EventLogMaxFileSize $REG_DWORD
}

function EventLogSetupRetention {
    PrintControl -code "18.9.27.3.1" -level "1" -description "Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "Retention" "0" $REG_DWORD
}

function EventLogSetupMaxSize {
    PrintControl -code "18.9.27.3.2" -level "1" -description "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize" $EventLogMaxFileSize $REG_DWORD
}

function EventLogSystemRetention {
    PrintControl -code "18.9.27.4.1" -level "1" -description "Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "Retention" "0" $REG_DWORD
}

function EventLogSystemMaxSize {
    PrintControl -code "18.9.27.4.2" -level "1" -description "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize" $EventLogMaxFileSize $REG_DWORD
}

function NoDataExecutionPrevention {
    PrintControl -code "18.9.31.2" -level "1" -description "Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" "0" $REG_DWORD
}

function NoHeapTerminationOnCorruption {
    PrintControl -code "18.9.31.3" -level "1" -description "Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" "0" $REG_DWORD
}

function PreXPSP2ShellProtocolBehavior {
    PrintControl -code "18.9.31.4" -level "1" -description "Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" "0" $REG_DWORD
}

function MicrosoftAccountDisableUserAuth {
    PrintControl -code "18.9.46.1" -level "1" -description "Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth" "1" $REG_DWORD
}


function LocalSettingOverrideSpynetReporting {
    PrintControl -code "18.9.47.4.1" -level "1" -description "Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "LocalSettingOverrideSpynetReporting" "0" $REG_DWORD
}


function ExploitGuard_ASR_Rules {
    PrintControl -code "18.9.47.5.1.1" -level "1" -description "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules" "1" $REG_DWORD
}


function ConfigureASRrules {
    PrintControl -code "18.9.47.5.1.2" -level "1" -description "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
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
    PrintControl -code "18.9.47.5.3.1" -level "1" -description "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection" "1" $REG_DWORD
}

function DisableIOAVProtection {
    PrintControl -code "18.9.47.9.1" -level "1" -description "Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection" "0" $REG_DWORD
}


function DisableRealtimeMonitoring {
    PrintControl -code "18.9.47.9.2" -level "1" -description "Ensure 'Turn off real-time protection' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" "0" $REG_DWORD
}

function DisableBehaviorMonitoring {
    PrintControl -code "18.9.47.9.3" -level "1" -description "Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
    SetRegistry "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring" "0" $REG_DWORD
}

function DisableScriptScanning {
    PrintControl -code "18.9.47.9.4" -level "1" -description "Ensure 'Turn on script scanning' is set to 'Enabled'"    
    SetRegistry "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableScriptScanning" "0" $REG_DWORD
}

function DisableEmailScanning {
    PrintControl -code "18.9.47.12.2" -level "1" -description "Ensure 'Turn on e-mail scanning' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableEmailScanning" "0" $REG_DWORD
}

function PUAProtection  {
    PrintControl -code "18.9.47.15" -level "1" -description "Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection" "1" $REG_DWORD
}

function DisableAntiSpyware {
    PrintControl -code "18.9.47.16" -level "1" -description "Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" "0" $REG_DWORD
}

function TerminalServicesDisablePasswordSaving {
    PrintControl -code "18.9.65.2.2" -level "1" -description "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving" "1" $REG_DWORD
}

function TerminalServicesfDisableCdm {
    # This prevents copying and pasting into RDP. Set to 0 to allow pasting into the RDP session.
    if ($AllowRDPClipboard -eq $false) {
      PrintControl -code "18.9.65.3.3.1" -level "1" -description "Ensure 'Do not allow drive redirection' is set to 'Enabled'"
      SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm" "1" $REG_DWORD
    }
    else {
      Write-Red "Opposing 18.9.65.3.3.1 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
      Write-Red '- You enabled $AllowRDPClipboard. This CIS configuration has been skipped so that the clipboard can be used.'
      SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm" "0" $REG_DWORD
    }
}

function TerminalServicesfPromptForPassword {
    PrintControl -code "18.9.65.3.9.1" -level "1" -description "Ensure 'Always prompt for password upon connection' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword" "1" $REG_DWORD
}



function TerminalServicesfEncryptRPCTraffic {
    PrintControl -code "18.9.65.3.9.2" -level "1" -description "Ensure 'Require secure RPC communication' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic" "1" $REG_DWORD
}

function TerminalServicesMinEncryptionLevel {
    PrintControl -code "18.9.65.3.9.3" -level "1" -description "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel" "3" $REG_DWORD
}

function TerminalServicesDeleteTempDirsOnExit {
    PrintControl -code "18.9.59.3.11.1" -level "1" -description "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit" "1" $REG_DWORD
}

function TerminalServicesPerSessionTempDir {
    PrintControl -code "18.9.65.3.11.2" -level "1" -description "Ensure 'Do not use temporary folders per session' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "PerSessionTempDir" "1" $REG_DWORD
}


function DisableEnclosureDownload {
    PrintControl -code "18.9.66.1" -level "1" -description "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" "1" $REG_DWORD
}


function AllowIndexingEncryptedStoresOrItems {
    PrintControl -code "18.9.67.2" -level "1" -description "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" "0" $REG_DWORD
}

function DefenderSmartScreen {
    PrintControl -code "18.9.85.1.1" -level "1" -description "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" "1" $REG_DWORD
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "Block" $REG_SZ
}

function InstallerEnableUserControl {
    PrintControl -code "18.9.90.1" -level "1" -description "Ensure 'Allow user control over installs' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl" "0" $REG_DWORD
}

function InstallerAlwaysInstallElevated {
    PrintControl -code "18.9.90.2" -level "1" -description "Ensure 'Always install with elevated privileges' is set to 'Disabled'" 
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "0" $REG_DWORD
}

function DisableAutomaticRestartSignOn {
    PrintControl -code "18.9.91.1" -level "1" -description "Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" "1" $REG_DWORD
}

function EnableScriptBlockLogging {
    PrintControl -code "18.9.100.1" -level "1" -description "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" "1" $REG_DWORD
}

function EnableTranscripting {
    PrintControl -code "18.9.100.2" -level "1" -description "Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" "0" $REG_DWORD
}

function WinRMClientAllowBasic  {
    PrintControl -code "18.9.102.1.1" -level "1" -description "Ensure 'Allow Basic authentication' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic" "0" $REG_DWORD
}

function WinRMClientAllowUnencryptedTraffic {
    PrintControl -code "18.9.102.1.2" -level "1" -description "Ensure 'Allow unencrypted traffic' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic" "0" $REG_DWORD
}

function WinRMClientAllowDigest {
    PrintControl -code "18.9.102.1.3" -level "1" -description "Ensure 'Disallow Digest authentication' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest" "0" $REG_DWORD
}


function WinRMServiceAllowBasic {
    PrintControl -code "18.9.102.2.1" -level "1" -description "Ensure 'Allow Basic authentication' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic" "0" $REG_DWORD
}

function WinRMServiceAllowAutoConfig {
    PrintControl -code "18.9.102.2.2" -level "1" -description "Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig" "0" $REG_DWORD
}

function WinRMServiceDisableRunAs {
    PrintControl -code "18.9.102.2.3" -level "1" -description "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs" "1" $REG_DWORD
}

function DisallowExploitProtectionOverride {
    PrintControl -code "18.9.105.2.1" -level "1" -description "Ensure 'Prevent users from modifying settings' is set to 'Enabled'"    
    SetRegistry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" "DisallowExploitProtectionOverride" "1" $REG_DWORD
}

if ([Environment]::Is64BitProcess -ne [Environment]::Is64BitOperatingSystem)
{
    Write-Error "You must execute this script on a x64 shell"
    Write-Error "Aborted."
    return 1;
}

if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator") -eq $false) {
    Write-Error "You must execute this script with administrator privileges!"
    Write-Error "Aborted."
    return 1;
}


Write-Info "CIS Azure Compute Microsoft Windows Server 2022 Benchmark"
Write-Info "Script by Michael Aparicio"
Write-Info "*******************************************************"
Write-Info "Credit to Evan Greene and Vinicius Miguel for original scripts"
Write-Info "*******************************************************"

# Enable Windows Defender settings on Windows Server
Set-MpPreference -AllowNetworkProtectionOnWinServer 1
Set-MpPreference -AllowNetworkProtectionDownLevel 1
Set-MpPreference -AllowDatagramProcessingOnWinServer 1


$temp_pass1 = ""
$temp_pass2 = ""
$invalid_pass = $true

# Get input password if the admin account does not already exist
$NewLocalAdminExists = Get-LocalUser -Name $NewLocalAdmin -ErrorAction SilentlyContinue
if ($NewLocalAdminExists.Count -eq 0) {
    do {
        Write-Info "I will create a new Administrator account, you need to specify the new account password."
        Write-Info "Your password must contain at least 15 characters, capital letters, numbers and symbols"
        
        Write-Info "Please enter the new password:"
        $temp_pass1 = Read-Host
        Write-Info "Please repeat the new password:"
        $temp_pass2 = Read-Host 
        
        $invalid_pass = ValidatePasswords $temp_pass1 $temp_pass2 
        if($invalid_pass -eq $false) {
            Write-Error "Your passwords do not match or do not follow the minimum complexity requirements, try again."
        } 
        else {
            $NewLocalAdminPassword = ConvertTo-SecureString $temp_pass1 -AsPlainText -Force 
        }
    } while($invalid_pass -eq $false)
}

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