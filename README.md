# Aws Utilities

## Revision History

### 1.0.3.5
Fixed typo bug in mounting copied volumes.

### 1.0.3.4
Removed the default parameter set from Copy-EBSVolume and allowed you to make encrypted EBS volume copies in the same AZ and region as the source. Added parameters to specify volume type and size and to copy tags from source to destination.

### 1.0.3.3
Fixed minor bugs in the Get-AWSCloudTrailLogs cmdlet that didn't correctly convert the DateTime for an S3 CloudTrail log file to the actual UTC time.

### 1.0.3.2
Fixed typos in examples.

### 1.0.3.1
Updated the manifest file to include the HostUtilities module. Fixed setting AWS credentials in Get-AWSCloudTrailLogs if no credential information provided. Added a Filter parameter to the Get-AWSCloudTrailLogs cmdlet.

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