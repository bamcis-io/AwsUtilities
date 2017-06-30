#
# Module manifest for module 'AwsUtilities'
#
# Generated by: Michael Haken
#
# Generated on: 5/2/2017
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'AwsUtilities.psm1'

# Version number of this module.
ModuleVersion = '1.0.1.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '10ba0882-dc17-438f-a6fb-7efaf690ca43'

# Author of this module
Author = 'Michael Haken'

# Company or vendor of this module
CompanyName = 'BAMCIS'

# Copyright statement for this module
Copyright = '(c) 2017 BAMCIS. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Supplemental AWS cmdlets to help automate common tasks.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @("AWSPowerShell")

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @("Get-S3ETagCalculation", "Get-EC2InstanceRegion", 
	"Get-EC2InstanceId", "New-EBSAutomatedSnapshot", "Get-AWSProductInformation", 
	"New-CloudFrontSignedUrl", "New-AWSSplat", "New-AWSUtilitiesSplat", "Copy-EBSVolume", 
	"Mount-EBSVolumes", "Get-EC2InstanceByNameOrId", "Invoke-AWSNetworkAdapterFixOnOfflineDisk", "Invoke-AWSNetworkAdapterFixOnRemoteInstance",
	"Update-EC2InstanceAmiId", "Set-EC2InstanceState", "Get-AWSAmiMappings", "Invoke-EnableCloudWatch", "Invoke-AWSKMSEncryptString", "Invoke-AWSKMSDecryptString",
	"Get-AWSFederationLogonUrl"
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @("AWSRegions")

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @("PSModule", "AWS")

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/bamcisnetworks/AwsUtilities/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/bamcisnetworks/AwsUtilities'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = '*1.0.1.0
Added Invoke-AWSNetworkAdapterFixOnOfflineDisk, Invoke-AWSNetworkAdapterFixOnRemoteInstance, Update-EC2InstanceAmiId, Set-EC2InstanceState, Get-AWSAmiMappings, Invoke-EnableCloudWatch, Invoke-AWSKMSEncryptString, Invoke-AWSKMSDecryptString, and Get-AWSFederationLogonUrl cmdlets.

*1.0.0.7
Fixed minor bugs on mounting volumes with Copy-EBSVolume.

*1.0.0.6
Added the New-AWSUtilitiesSplat cmdlet to be used with the cmdlets in the module and fixed a bug the previous version introduced with the splats.

*1.0.0.5
Added Mount-EBSVolumes and Get-EC2InstanceByNameOrId cmdlets to remove code duplication throughout.
		
*1.0.0.4
Updated Get-AWSProductInformation so the output is more useable.
		
*1.0.0.3
Fixed a bug with Get-AWSProductInformation.
		
*1.0.0.2
Updated exported variable AWSRegions.
		
*1.0.0.1
Updated manifest file and minor updates to fix issues found in PSScriptAnalyzer.

*1.0.0.0
Initial Release.
'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

