#
# This is a PowerShell Unit Test file.
# You need a unit test framework such as Pester to run PowerShell Unit tests. 
# You can download Pester from http://go.microsoft.com/fwlink/?LinkID=534084
#

Describe "Get-Function" {
	Context "Function Exists" {
		It "Should Return" {
		
		}
	}
}

Function Test-UpdateImageIdMapping {

	$Subnet = ""
	$Profile = ""
	$SG = ""
	$Key = ""

	$BDM = New-Object -TypeName Amazon.EC2.Model.BlockDeviceMapping
	$BDM.DeviceName = "/dev/sdf"
	$BD = New-Object -TypeName Amazon.EC2.Model.EbsBlockDevice
	$BD.VolumeSize = 10
	$BD.VolumeType = [Amazon.EC2.VolumeType]::Gp2
	$BDM.Ebs = $BD

	[Amazon.EC2.Model.InstanceNetworkInterfaceSpecification]$Net1 = New-Object -TypeName Amazon.EC2.Model.InstanceNetworkInterfaceSpecification
	$Net1.DeviceIndex = 0
	$Net1.DeleteOnTermination = $true
	$Net1.SubnetId = $Subnet
	$Net1.Groups = @($SG)

	[Amazon.EC2.Model.InstanceNetworkInterfaceSpecification]$Net2 = New-Object -TypeName Amazon.EC2.Model.InstanceNetworkInterfaceSpecification
	$Net2.DeviceIndex = 1
	$Net2.DeleteOnTermination = $true
	$Net2.SubnetId = $Subnet
	$Net2.Groups = @($SG)

	$Tags = New-Object -TypeName Amazon.EC2.Model.TagSpecification
	$Tags.ResourceType = [Amazon.EC2.ResourceType]::Instance
	$NameTag = New-Object -TypeName Amazon.EC2.Model.Tag
	$NameTag.Key = "Name"
	$NameTag.Value = "UpdateAmiTest"
	$Tags.Tags.Add($NameTag)

	$Res = New-EC2Instance -ImageId ami-035be7bafff33b6b6 -KeyName $Key -InstanceType t2.micro -Monitoring_Enabled $true `
		 -ProfileName $Profile -BlockDeviceMapping @($BDM) -NetworkInterface @($Net1, $Net2) -TagSpecification $Tags

	Update-EC2InstanceImageId -InstanceId $Res.Instances[0].InstanceId -NewImageId "ami-0ac019f4fcb7cb7e6" -Verbose -ProfileName $Profile
}