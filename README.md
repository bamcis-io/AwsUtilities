# Aws Utilities

## Revision History

### 1.0.3.0
Added the Get-AWSCloudTrailLogs cmdlet.

### 1.0.2.0
Added the Get-AWSPublicIPRanges cmdlet.

### 1.0.1.1
Updated the Invoke-AWSNetworkAdapterFixOnOfflineDisk and Invoke-AWSNetworkAdapterFixOnRemoteInstance cmdlets.

### 1.0.1.0
Added Invoke-AWSNetworkAdapterFixOnOfflineDisk, Invoke-AWSNetworkAdapterFixOnRemoteInstance, Update-EC2InstanceAmiId, Set-EC2InstanceState, Get-AWSAmiMappings, Invoke-EnableCloudWatch, Invoke-AWSKMSEncryptString, Invoke-AWSKMSDecryptString, and Get-AWSFederationLogonUrl cmdlets.

### 1.0.0.7
Fixed minor bugs on mounting volumes with Copy-EBSVolume.

### 1.0.0.6
Added the New-AWSUtilitiesSplat cmdlet to be used with the cmdlets in the module and fixed a bug the previous version introduced with the splats.

### 1.0.0.5
Added Mount-EBSVolumes and Get-EC2InstanceByNameOrId cmdlets to remove code duplication throughout.

### 1.0.0.4
Updated Get-AWSProductInformation so the output is more useable.

### 1.0.0.3
Fixed a bug with Get-AWSProductInformation.

### 1.0.0.2
Updated exported variable AWSRegions.

### 1.0.0.1
Updated manifest file and minor updates to fix issues found in PSScriptAnalyzer.

### 1.0.0.0
Initial Release.