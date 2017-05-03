Import-Module -Name AWSPowerShell -ErrorAction Stop
Initialize-AWSDefaults

$script:CREATED_BY = "CreatedBy"
$script:CAN_BE_DELETED = "CanBeDeleted"
[System.Guid]$script:UNIQUE_ID = [System.Guid]::Parse("17701dbb-33ff-4f31-8914-6f48856fe755")

#Make the variable $AWSRegions available to all of the cmdlets
Set-Variable -Name AWSRegions -Value (@((Get-AWSRegion -GovCloudOnly | Select-Object -ExpandProperty Region), (Get-AWSRegion -IncludeChina | Select-Object -ExpandProperty Region)) | Select-Object -Unique)

Function Get-S3ETagCalculation {
	<#
		.SYNOPSIS
			Calculates the expected ETag value for an object uploaded to S3.

		.DESCRIPTION
			The cmdlet calculates the hash of the targetted file to generate its S3 ETag value that can be used to validate file integrity.

			This cmdlet will fail to work if FIPS Compliant algorithms are enforced because AWS uses an MD5 hash for the ETag.

		.PARAMETER FilePath
			The path to the file that is having its ETag value calculated.

		.PARAMETER BlockSize
			The size of each part uploaded to S3, defaults to 8MB.

		.PARAMETER MinimumSize
			The file must be larger than this size to use multipart upload, defaults to 64MB.

        .EXAMPLE
			Get-S3ETagCalculation -FilePath "c:\test.txt"

			Calculates the ETag value for c:\test.txt.

		.INPUTS
			System.String

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/27/2017
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Path -Path $_
        })]
		[Alias("Path")]
		[System.String]$FilePath,

		[Parameter(Position = 1)]
		[System.UInt64]$BlockSize = 8MB,

		[Parameter(Position = 2)]
		[System.UInt64]$MinimumSize = 64MB
	)

	Begin {
	}

	Process {
		#Track the number of parts that would need to be uploaded
		$Parts = 0

		#Track the hashes of each part in the array
		[System.Byte[]]$BinaryHashArray = @()

		#FIPS compliance enforcement must be turned off to use MD5
		[System.Security.Cryptography.MD5CryptoServiceProvider]$MD5 = [Security.Cryptography.HashAlgorithm]::Create([System.Security.Cryptography.MD5])

		[System.IO.FileStream]$FileReader = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)

		#If the file is larger than the size to use multipart
		if ($FileReader.Length -gt $MinimumSize) 
		{
            Write-Verbose -Message "The upload will use multipart"

			#Set the buffer object to the size of upload part
			[System.Byte[]]$Buffer = New-Object -TypeName System.Byte[]($BlockSize)

			#This reads the file and ensures we haven't reached the end of the file
			#FileReader reads from 0 up to the buffer length and places it in the byte array
			while (($LengthToRead = $FileReader.Read($Buffer,0,$Buffer.Length)) -ne 0)
            {
				#The number of parts in the upload is appended to the end of the ETag, so track that here
				$Parts++

				#Calculate the hash of the part and add it to a byte array
				#ComputeHash takes in a byte array and returns one
				#Only read in the amount of data that is left to be read
				[System.Byte[]]$Temp = $MD5.ComputeHash($Buffer,0,$LengthToRead)

                Write-Verbose -Message "Reading part $Parts : $([System.BitConverter]::ToString($Temp).Replace("-",[System.String]::Empty).ToLower())"

                $BinaryHashArray += $Temp
			}

            Write-Verbose -Message "There are $Parts total parts."

            #The MD5 hash is calculated by concatenating all of the MD5 hashes of the parts
            #and then doing an MD5 hash of the concatenation
			#Calculate the hash, ComputeHash() takes in a byte[]
            Write-Verbose -Message "Calculating hash of concatenated hashes."
			$BinaryHashArray = $MD5.ComputeHash($BinaryHashArray)
		}
		else #The file is not big enough to use multipart
		{
            Write-Verbose -Message "The upload is smaller than the minimum threshold and will not use multipart."

			$Parts = 1
            #Here ComputeHash takes in a Stream object
			$BinaryHashArray = $MD5.ComputeHash($FileReader)
		}

        Write-Verbose -Message "Closing the file stream."
		$FileReader.Close()

		#Convert the byte array to a string
		[System.String]$Hash = [System.BitConverter]::ToString($BinaryHashArray).Replace("-","").ToLower()

		#Append the number of parts to the ETag if there were multiple
		if ($Parts -gt 1) 
		{
			$Hash += "-$Parts"
		}

		Write-Output -InputObject $Hash
	}

	End {
	}
}

Function Get-EC2InstanceRegion {
	<#
		.SYNOPSIS
			Gets the current region of the EC2 instance from instance metadata.

		.DESCRIPTION
			The cmdlet uses the EC2 instance metadata of the local or remote computer to get the AWS Region it is running in.

		.PARAMETER ComputerName
			The computer to the get the region for, this defaults to the local machine. The computer must be an AWS EC2 instance.

		.PARAMETER Credential
			The credentials used to connect to a remote computer.

        .EXAMPLE
			$Region = Get-EC2InstanceRegion

			Gets the AWS Region of the current machine.

		.INPUTS
			System.String

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 5/3/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		$ComputerName,

		[Parameter()]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	Begin {
	}

	Process {		
		if ($PSBoundParameters.ContainsKey("ComputerName") -and $ComputerName -inotin @(".", "localhost", "", $env:COMPUTERNAME, "127.0.0.1"))
		{
			[System.String]$Region = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
				[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
				Write-Output -InputObject (ConvertFrom-Json -InputObject ($WebClient.DownloadString("http://169.254.169.254/latest/dynamic/instance-identity/document"))).Region
			} -Credential $Credential
		}
		else
		{
			[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
			[System.String]$Region = (ConvertFrom-Json -InputObject ($WebClient.DownloadString("http://169.254.169.254/latest/dynamic/instance-identity/document"))).Region
		}

		Write-Output -InputObject $Region
	}

	End {
	}
}

Function Get-EC2InstanceId {
	<#
		.SYNOPSIS
			Gets the current instance id of the EC2 instance from instance metadata.

		.DESCRIPTION
			The cmdlet uses the EC2 instance metadata of the local or remote computer to get the instance's id.

		.PARAMETER ComputerName
			The computer to the get the id for, this defaults to the local machine. The computer must be an AWS EC2 instance.

		.PARAMETER Credential
			The credentials used to connect to a remote computer.

        .EXAMPLE
			$Id = Get-EC2InstanceId

			Gets the instance id of the current machine.

		.INPUTS
			System.String

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 5/3/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ComputerName,

		[Parameter()]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	Begin {
	}

	Process {		
		if ($PSBoundParameters.ContainsKey("ComputerName") -and $ComputerName -inotin @(".", "localhost", "", $env:COMPUTERNAME, "127.0.0.1"))
		{
			[System.String]$Id = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
				[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
				Write-Output -InputObject $WebClient.DownloadString("http://169.254.169.254/latest/meta-data/instance-id")
			} -Credential $Credential
		}
		else
		{
			[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
			[System.String]$Id = $WebClient.DownloadString("http://169.254.169.254/latest/meta-data/instance-id")
		}

		Write-Output -InputObject $Id
	}

	End {
	}
}

Function New-EBSAutomatedSnapshot {
	<#
		.SYNOPSIS
			Creates EBS snapshots of the volumes attached to the EC2 instance the cmdlet is run from.

		.DESCRIPTION
			The EC2 instance queries its attached volumes and creates snapshots of them. Then it also checks existing
			snapshots and deletes ones older than the retention period. This cmdlet is designed to be run as a recurring scheduled task.

			Only snapshots that were created through this cmdlet will be reviewed for deletion by using a tag "CreatedBy" : "17701dbb-33ff-4f31-8914-6f48856fe755", a unique Id used by this cmdlet. 
			Snapshots can also be marked as non-deletable by specifying DoNotDelete or manually adding a tag to the snapshot "CanDelete" : "false".

			The cmdlet requires the EC2 instance to have an IAM Instance Profile (IAM Role) that allows it to list volumes, list snapshots, list instances, create snapshots, and delete snapshots, 
			similar to the following example:

			{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Sid": "Automated EBS Snapshot Management",
						"Effect": "Allow",
						"Action": [
							"ec2:CreateSnapshot",
							"ec2:DeleteSnapshot",
							"ec2:DescribeInstances",
							"ec2:DescribeSnapshots",
							"ec2:CreateTags",
							"ec2:DescribeTags",
							"ec2:DescribeVolumes"
						],
						"Resource": [
							"*"
						]
					}
				]
			}

		.PARAMETER RetentionPeriod
			A TimeSpan object specifying how long snapshots should be retained before being deleted. This value is used with the Snapshot's StartTime property to
			determine if it should be deleted. It does not record a deleted time as a tag on the Snapshot so that if the retention period is changed in the scheduled task, 
			existing snapshots will then use that new retention period the next time the cmdlet is run.

			This defaults to 30 days.

		.PARAMETER DoNotDelete
			Specifies that the snapshots that are created should not be automatically deleted. If this is specified, you cannot specify a retention period.

		.PARAMETER EnableLogging
			Enables writing a log file to %SYSTEMDRIVE%\AwsLogs\EBS\Backup.log with the transcript of the backup job. The log file is automatically rolled over when it exceeds 5MB.

		.EXAMPLE
			New-AutomatedEBSSnapshot -RetentionPeriod (New-TimeSpan -Days 45)

			Creates a new EBS snapshot of the current EC2 instance's volumes and then deletes any snapshots of the instance's volumes that are marked as deletable and are older than 45 days.

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 5/3/2017
	#>

	[CmdletBinding(DefaultParameterSetName = "Retention")]
	Param(
		[Parameter(ParameterSetName = "Retention")]
		[System.TimeSpan]$RetentionPeriod = (New-TimeSpan -Days 30),

		[Parameter(ParameterSetName = "DoNotDelete")]
		[switch]$DoNotDelete,

		[Parameter()]
		[switch]$EnableLogging
	)

	Begin {	
		Function Write-EBSLog {
			Param(
				[Parameter(Mandatory = $true)]
				[ValidateNotNullOrEmpty()]
				[System.String]$Message,

				[Parameter()]
				[ValidateSet("INFO", "WARNING", "ERROR")]
				[System.String]$Level = "INFO",

				[Parameter()]
				[System.String]$Path = "$env:SystemDrive\AwsLogs\EBS\Backup.log",

				[Parameter()]
				[switch]$NoTimeStamp
			)

			Begin {
			}

			Process {
				[System.IO.FileInfo]$Info = New-Object -TypeName System.IO.FileInfo($Path)

				if (-not [System.IO.Directory]::Exists($Info.Directory.FullName))
				{
					New-Item -ItemType Directory -Path $Info.Directory.FullName
				}

				if (Test-Path -Path $Path)
				{
					$Log = Get-Item -Path $LogFile

					if ($Log.Length -gt 5MB)
					{
						$LogDate = (Get-Date).ToString("dd-MMM-yyyy_HH-mm-ss")
						$Parts = $Log.Name.Split(".")
						$NewName = $Parts[0] + "_" + $LogDate + "." + $Parts[1]

						while ((Get-Item -Path "$($Info.Directory.FullName)\$NewName" -ErrorAction SilentlyContinue) -ne $null) 
						{
							$LogDate = (Get-Date).ToString("dd-MMM-yyyy_HH-mm-ss")
							$NewName = $Parts[0] + "_" + $LogDate + "." + $Parts[1]
						}

						Rename-Item -Path $LogFile -NewName $NewName

						$Path = "$($Info.Directory.FullName)\$NewName"
					}
				}

				if(-not $NoTimeStamp)
				{
					$Message = "$(Get-Date) [$Level] : $Message"
				}

				Add-Content -Path $Path -Value $Message
			}

			End {
			}
		}
	}

	Process {

		if ($EnableLogging) 
		{
			Write-EBSLog -Message "*******************************************************************************" -NoTimeStamp
			Write-EBSLog -Message "Beginning volume snapshot creation job."		
		}

		try
		{
			[System.String]$Region = Get-EC2InstanceRegion

			if ($EnableLogging) 
			{ 
				Write-EBSLog -Message "Setting default region to $Region"
			}

			Set-DefaultAWSRegion -Region $Region

			[System.String]$InstanceId = Get-EC2InstanceId

			if ($EnableLogging) 
			{ 
				Write-EBSLog -Message "Getting instances."
			}

			#This is actually a [Amazon.EC2.Model.Reservation], but if no instance is returned, it comes back as System.Object[]
            #so save the error output and don't strongly type it
            $Instances = Get-EC2Instance -InstanceId $SourceInstanceId -ErrorAction SilentlyContinue

            if ($Instances -ne $null)
            {
                [Amazon.EC2.Model.Instance]$Instance = $Instances.Instances | Select-Object -First 1
				
				if ($Instance -ne $null)
                {
					[System.String]$InstanceName = $Instance.Tags | Where-Object {$_.Key -eq "Name"} | Select-Object -ExpandProperty Value

					try
					{
						if ($EnableLogging) 
						{ 
							Write-EBSLog -Message "Retrieving EBS Volumes for instance."
						}

						$Date = (Get-Date).ToString("dd-MMM-yyyy_HH-mm-ss")
						[Amazon.EC2.Model.Volume[]]$Volumes = Get-EC2Volume -Filter (New-Object -TypeName Amazon.EC2.Model.Filter -Property @{Name = "attachment.instance-id"; Value = $InstanceId})

						foreach ($Volume in $Volumes)
						{
							[System.String]$VolumeName = $Volume.Tags | Where-Object {$_.Key -eq "Name"} | Select-Object -ExpandProperty Value

							if ([System.String]::IsNullOrEmpty($VolumeName)) 
							{
								$VolumeName = $Volume.VolumeId
							}

							try
							{
								if ($EnableLogging) 
								{ 
									Write-EBSLog -Message "Starting snapshot for Volume $VolumeName - $($Volume.VolumeId)"
								}

								[System.String]$VolumeSnapshotName = "$InstanceId`_$VolumeName`_$Date"

								[Amazon.EC2.Model.Snapshot]$Snapshot = New-EC2Snapshot -VolumeId $Volume.VolumeId -Description "Automated backup created for $InstanceId on $Date" -Force
						
								New-EC2Tag -Resources @($Snapshot.SnapshotId) -Tags @(@{Key = "Source"; Value = $InstanceId}, @{Key="Name"; Value=$VolumeSnapshotName}, @{Key=$script:CREATED_BY; Value=$script:UNIQUE_ID}, @{Key=$script:CAN_BE_DELETED; Value=(-not [System.Bool]$DoNotDelete)})

								if ($EnableLogging) 
								{
									Write-EBSLog -Message "Finished snapshot for Volume $VolumeName - $($Volume.VolumeId)"
								}

								if ($RetentionPeriod -gt 0)
								{
									if ($EnableLogging) 
									{ 
										Write-EBSLog -Message "Selected retention period: $RetentionPeriod" 
									}

									#Get snapshots that were created from the current volume, but are not the snapshot we just took
									[Amazon.EC2.Model.Snapshot[]]$OldSnapshots = Get-EC2Snapshot -Filter (New-Object -TypeName Amazon.EC2.Model.Filter -Property @{Name = "volume-id"; Values = $Volume.VolumeId}) | Where-Object {$_.SnapshotId -ne $Snapshot.SnapshotId}
            
									foreach ($OldSnapshot in $OldSnapshots)
									{
										[System.String]$CreatedBy = $OldSnapshot.Tags | Where-Object {$_.Key -eq $script:CREATED_BY} | Select-Object -ExpandProperty Value
										[System.Boolean]$CanDelete = $OldSnapshot.Tags | Where-Object {$_.Key -eq $script:CAN_BE_DELETED} | Select-Object -ExpandProperty Value
										[System.DateTime]$CreatedDate = $Re

										if (($CreatedBy -ne $null -and $CreatedBy -eq $script:UNIQUE_ID) -and `
											($CanDelete -ne $null -and $CanDelete -eq $true) -and `
											$OldSnapshot.StartTime.ToUniversalTime().Add($RetentionPeriod) -lt [System.DateTime]::UtcNow
										)
										{
											try   
											{
												[System.String]$SnapshotName = $OldSnapshot.Tags | Where-Object {$_.Key -eq "Name"} | Select-Object -ExpandProperty Value

												if ($EnableLogging) 
												{ 
													Write-EBSLog -Message "Old Snapshot identified for volume $VolumeName - $($Volume.VolumeId)"
													Write-EBSLog -Message "Old Snapshot start : $($OldSnapshot.StartTime.ToUniversalTime()) | Current Time : $([System.DateTime]::UtcNow)"
													Write-EBSLog -Message "Deleting snapshot $SnapshotName - $($OldSnapshot.SnapshotId)"
												}
                                        
												#Returns no output
												Remove-EC2Snapshot -SnapshotId $OldSnapshot.SnapshotId -Force
                                        
												if ($EnableLogging) 
												{ 
													Write-EBSLog -Message "Deletion completed"
												}
											}
											catch [Exception]
											{
												Write-Warning "Error deleting snapshot : $($_.Exception.Message)"

												if ($EnableLogging) 
												{ 
													Write-EBSLog -Message "Error deleting snapshot : $($_.Exception.Message)" -Level ERROR
												}
											} 
										}
										else
										{
											Write-Verbose -Message "Not processing snapshot $($OldSnapshot.SnapshotId)."

											if ($EnableLogging)
											{
												Write-EBSLog -Message "Not processing snapshot $($OldSnapshot.SnapshotId)."
											}
										}
									}
								}
							}
							catch [Exception]
							{
								Write-Warning "Error creating new snapshot for volume $VolumeName : $($_.Exception.Message)"

								if ($EnableLogging) 
								{ 
									Write-EBSLog -Message "Error creating new snapshot for volume $VolumeName : $($_.Exception.Message)" -Level ERROR
								}
							}
						}
					}
					catch [Exception]
					{
						Write-Warning "Error analyzing instance $InstanceName : $($_.Exception.Message)"

						if ($EnableLogging) 
						{ 
							Write-EBSLog -Message "Error analyzing instance $InstanceName : $($_.Exception.Message)" -Level ERROR
						}
					}
				}
				else
                {
					#This will get caught below
					throw "Could not find a matching EC2 instance."
                }
            }
            else
            {
				#This will get caught below
                throw "Nothing was returned by the get instance request."
            }
		}
		catch [Exception]
		{
			Write-Warning -Message "$($_.Exception.Message)"

			if ($EnableLogging) 
			{ 
				Write-EBSLog -Message "$($_.Exception.Message)" -Level ERROR
			}
		}

		if ($EnableLogging) 
		{ 
			Write-EBSLog -Message "Volume snapshot job completed."
			Write-EBSLog -Message "*******************************************************************************" -NoTimeStamp
		}
	}

	End {
	}
}

Function Get-AWSProductInformation {
	<#
		.SYNOPSIS
			This cmdlet evaluates the data in the AWS Price List API json and returns information about products that match the search criteria.

		.DESCRIPTION
			The cmdlet parses the json in a specified file on disk retrieved from the price list API or downloads it directly from the provided Url. It matches products
			against the specified attributes. This is useful to find say all of the different SKUs and Operation codes for db.m4.large instances in US East (N. Virginia).

		.PARAMETER Path
			The path to the downloaded price list API file.

		.PARAMETER Url
			The Url containing the price list information for the product you want.

		.PARAMETER Product
			The product you want to download price list information for.

		.PARAMETER Attributes
			The attributes used to match specific skus in the price list API. Attributes will look like: @{"location" = "US East (N. Virginia)"; "instanceType" = "db.m4.large"; "databaseEngine" = "PostgreSQL"}

		.EXAMPLE
			Get-AWSProductInformation -Product AmazonRDS -Attributes @{"location" = "US East (N. Virginia)"; "instanceType" = "db.m4.large"; "databaseEngine" = "PostgreSQL"}

			Gets matching RDS skus for the attributes specified

		.EXAMPLE
			Get-AWSProductInformation -Url https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/current/index.json -Attributes @{"location" = "US East (N. Virginia)"; "instanceType" = "db.m4.large"; "databaseEngine" = "PostgreSQL"}

			Gets matching RDS skus for the attributes specified

		.INPUTS
			System.String

		.OUTPUTS
			System.Management.Automation.PSCustomObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/27/2107

	#>
	[CmdletBinding(DefaultParameterSetName = "Path")]
	Param(
		[Parameter(Mandatory=$true, ParameterSetName = "Path", Position = 0, ValueFromPipeline = $true)]
		[ValidateScript({Test-Path $_})]
		[System.String]$Path,

		[Parameter(Mandatory=$true)]
		[System.Collections.Hashtable]$Attributes
	)

	DynamicParam {
		[System.Management.Automation.RuntimeDefinedParameterDictionary]$ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		[System.String]$OfferIndexUrl = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json"
        [System.String]$BaseUrl = "https://pricing.us-east-1.amazonaws.com"

		[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
		[System.String]$Response = $WebClient.DownloadString($OfferIndexUrl)

		$IndexFileContents = ConvertFrom-Json -InputObject $Response

		[System.String[]]$Results = @()

        $OfferIndex.offers | Get-Member -MemberType *Property | ForEach-Object {
			try 
			{
				$Results += "$BaseUrl$($IndexFileContents.offers | Select-Object -ExpandProperty $_.Name | Select-Object -ExpandProperty currentVersionUrl)"
			}
			catch {}
        }

        [System.Management.Automation.ParameterAttribute]$UrlAttributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
		$UrlAttributes.ValueFromPipeline = $true
        $UrlAttributes.Mandatory = $true
		$UrlAttributes.ParameterSetName = "Url"
		$UrlAttributes.Position = 0

		[System.Collections.ObjectModel.Collection[System.Attribute]]$UrlAttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
        $UrlAttributeCollection.Add($UrlAttributes)

		[System.Management.Automation.ValidateSetAttribute]$UrlValidateSet = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($Results)
        $UrlAttributeCollection.Add($UrlValidateSet)

        [System.Management.Automation.RuntimeDefinedParameter]$UrlParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("Url", [System.String], $UrlAttributeCollection)
        $ParamDictionary.Add("Url", $UrlParam)

		[System.Management.Automation.ParameterAttribute]$ProductAttributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
		$ProductAttributes.ValueFromPipeline = $true
        $ProductAttributes.Mandatory = $true
		$ProductAttributes.ParameterSetName = "Product"
		$ProductAttributes.Position = 0

		[System.Collections.ObjectModel.Collection[System.Attribute]]$ProductAttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
        $ProductAttributeCollection.Add($ProductAttributes)

		[System.Management.Automation.ValidateSetAttribute]$ProductValidateSet = New-Object -TypeName System.Management.Automation.ValidateSetAttribute($private:IndexFileContents.offers| Get-Member -MemberType *Property | Select-Object -ExpandProperty Name)
        $ProductAttributeCollection.Add($ProductValidateSet)

        [System.Management.Automation.RuntimeDefinedParameter]$ProductParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("Product", [System.String], $ProductAttributeCollection)
        $ParamDictionary.Add("Product", $ProductParam)

		Write-Output -InputObject $ParamDictionary
	}

	Begin {
	}

	Process
	{
		[System.String]$BaseUrl = "https://pricing.us-east-1.amazonaws.com"

		if ($PSCmdlet.ParameterSetName -eq "Url")
		{			
			[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
			[System.String]$Response = $WebClient.DownloadString($PSBoundParameters["Url"])
		}
		elseif ($PSCmdlet.ParameterSetName -eq "Product")
		{
			[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
			[System.String]$Response = $WebClient.DownloadString($OfferIndexUrl)

			$IndexFileContents = ConvertFrom-Json -InputObject $Response

			$Url = "$private:BaseUrl$($IndexFileContents.offers | Select-Object -ExpandProperty $PSBoundParameters["Product"] | Select-Object -ExpandProperty currentVersionUrl)"
            [System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
			[System.String]$Response = $WebClient.DownloadString($Url)
		}
		else
		{
			$Response = Get-Content -Path $Path -Raw
		}

		$Obj = ConvertFrom-Json -InputObject $Response

		$Results = @()

		#Expanding the products property gets us a single object with member like
		#RBW79EQZWRSDB85D : @{sku=RBW79EQZWRSDB85D; productFamily=Database Instance; attributes=}
		#W3PUKFKG7RDK3KA5 : @{sku=W3PUKFKG7RDK3KA5; productFamily=Data Transfer; attributes=}
		
		#We want to expand the property of the products object for each sku to access the hash table that has the data
		#The only way to do this is to use an extra foreach
		$Products = $Obj | Select-Object -ExpandProperty products 

		#Getting the members of Products will get us all of the sku properties, we want to iterate each
		#one and select it, expanded from the products object, which will provide the hash table of data
		#which includes sku, productFamily, and attributes
		Get-Member -InputObject $Products -MemberType NoteProperty | ForEach-Object {
			#The Get-Member results will have a name property, that is the sku data for each product
			$Val = $Products | Select-Object -ExpandProperty $_.Name

			#Assume the product matches the filters, and prove it false
			$Matches = $true

			#Now that we have product object, we can filter based on the key value pairs provided
			foreach ($Key in $Attributes.Keys)
			{
				#Make sure the product has the attribute
				if ($Key -in (Get-Member -InputObject $Val.attributes -MemberType NoteProperty | Select-Object -ExpandProperty Name))
				{
					#Access the property through Select-Object since the name is dynamic and we can't use a "dot" propertyname technique
					#If the property value doesn't match the filter, set Matches to $false
					if (($Val.attributes | Select-Object -ExpandProperty $Key) -notlike $Attributes[$Key])
					{
						$Matches = $false
						break
					}
				}
				else
				{
					$Matches = $false
					break
				}
			}

			if ($Matches -eq $true)
			{
				$Results += $Val
			}
		}

		Write-Output -InputObject $Results
	}

	End {		
	}
}

Function New-CloudFrontSignedUrl {
	<#
		.SYNOPSIS
			Creates a signed cloudfront url. 
	
		.DESCRIPTION
			This cmdlet is mostly for educational purposes, AWS provides a cmdlet that does exactly this, but it is
			written in C# as part of the AWS PowerShell module. It uses the same approach of using BouncyCastle to
			translate the PEM content into a usable RSA key.

		.PARAMETER PemFileLocation
			The location on disk of the private key to use. This should be a base64 pem file.

		.PARAMETER PEM
			This is the base64 encoded private key including the header and footer data, such as -----BEGIN RSA PRIVATE KEY-----. The PEM content must include this to be recognized.

		.PARAMETER CloudfrontUrl
			The url to sign.

		.PARAMETER PolicyResource
			The resource in the policy document to apply the policy to. This defaults to the CloudfrontUrl, but could be a url with a wildcard. This parameter typically does not need to be
			used. Defining a resource other than the url is really only useful if the policy was in a template file so you could reuse that template for several different CF urls.

		.PARAMETER StartTime
			The time the Url starts to be valid. This defaults to the MinValue for .NET DateTime object.

		.PARAMETER SourceIp
			If you want to restrict access to the Cloudfront distribution to a certain IP or IP range, specify an IPv4 CIDR block (use a /32 for a specific IP address).

		.PARAMETER Expiration
			The time the signed url expires, this value must be later than the start time and the current time.

		.PARAMETER KeyPairId
			This is the Cloudfront KeyPair Id generated in the AWS management console using root credentials specifically for signing Cloudfront urls.

		.EXAMPLE
			New-CloudFrontSignedUrl -PemFileLocation c:\cert.pem -CloudfrontUrl http://d111111abcdef8.cloudfront.net/images/image.jpg -Expiration ([System.DateTime]::Now.AddHours(1))

			Creates a signed url for the image.jpg object that expires in 1 hour from now.

		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/27/2107
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "File")]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$PemFileLocation,

		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Pem")]
		[ValidateNotNullOrEmpty()]
		[System.String]$PEM,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$CloudfrontUrl,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$PolicyResource= $CloudfrontUrl,

		[Parameter()]
		[System.DateTime]$StartTime = [System.DateTime]::MinValue,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$SourceIp,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            $_ -gt [System.DateTime]::Now
        })]
        [System.DateTime]$Expiration,

        [Parameter(Mandatory = $true)]
        [System.String]$KeyPairId
	)

	Begin {

		Function Get-RsaKeysFromPem {
            [CmdletBinding()]
			Param(
				[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
				[System.String]$PEM
			)

			Begin {
				$Ret = Add-Type -Path "$(Split-Path -Path $script:MyInvocation.MyCommand.Path)\BouncyCastle.Crypto.dll" -ErrorAction SilentlyContinue
			}

			Process {
				[System.IO.MemoryStream]$Stream = New-Object System.IO.MemoryStream
				[System.IO.StreamWriter]$Writer = New-Object System.IO.StreamWriter($Stream)

				$Writer.Write($PEM)
				$Writer.Flush()
				$Stream.Position = 0

				[System.IO.StreamReader]$Reader = New-Object System.IO.StreamReader($Stream)

				try
				{
					[Org.BouncyCastle.OpenSsl.PemReader]$PemReader = New-Object -TypeName Org.BouncyCastle.OpenSsl.PemReader($Reader)

					if ($PEM.StartsWith("-----BEGIN RSA PRIVATE KEY-----") -or $PEM.StartsWith("-----BEGIN PRIVATE KEY-----"))
					{   
						#This read object could already be a [Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters] object, in which case, 
						#you don't need to tranform the Private property, just the whole object

						[Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters]$KeyParams = $null

						[System.Object]$Temp = $PemReader.ReadObject()

                        try
						{
							$KeyParams = [Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters]$Temp
						}
						catch [Exception]
						{
							[Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair]$KeyPair = [Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair]$Temp
							$KeyParams = [Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters]$KeyPair.Private
						}

						[System.Security.Cryptography.RSAParameters]$RsaParams = New-Object -TypeName System.Security.Cryptography.RSAParameters
						$RsaParams.Modulus = $KeyParams.Modulus.ToByteArrayUnsigned()
						$RsaParams.Exponent = $KeyParams.PublicExponent.ToByteArrayUnsigned()
						$RsaParams.D = $KeyParams.Exponent.ToByteArrayUnsigned()
						$RsaParams.P = $KeyParams.P.ToByteArrayUnsigned()
						$RsaParams.Q = $KeyParams.Q.ToByteArrayUnsigned()
						$RsaParams.DP = $KeyParams.DP.ToByteArrayUnsigned()
						$RsaParams.DQ = $KeyParams.DQ.ToByteArrayUnsigned()
						$RsaParams.InverseQ = $KeyParams.QInv.ToByteArrayUnsigned()
					}
					elseif ($PEM.StartsWith("-----BEGIN PUBLIC KEY-----"))
					{
						[Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters]$KeyParams = [Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters]$PemReader.ReadObject()
						[System.Security.Cryptography.RSAParameters]$RsaParams = New-Object -TypeName System.Security.Cryptography.RSAParameters
						$RsaParams.Modulus = $KeyParams.Modulus.ToByteArrayUnsigned()

						if ($KeyParams.IsPrivate)
						{
							$RsaParams.D = $KeyParams.Exponent.ToByteArrayUnsigned()
						}
						else
						{
							$RsaParams.Exponent = $KeyParams.Exponent.ToByteArrayUnsigned()
						}
					}
					else
					{
						throw New-Object -TypeName System.Security.Cryptography.CryptographicException("Unsupported PEM format.")
					}

					[System.Security.Cryptography.RSA]$Key = [System.Security.Cryptography.RSA]::Create()
					$Key.ImportParameters($RsaParams)
                    
					Write-Output -InputObject $Key
				}
				finally
				{
					$Reader.Dispose()
					$Stream.Dispose()
					$Writer.Dispose()
				}
			}

			End {
			}
		}

		Function ConvertRsaTo-Xml {
            [CmdletBinding()]
			Param(
				[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
				[System.Security.Cryptography.RSA]$RSA,

				[Parameter()]
				[switch]$IncludePrivateParameters
			)

			Begin {
			}

			Process {
				[System.Security.Cryptography.RSAParameters]$RsaParams = $RSA.ExportParameters(($IncludePrivateParameters -eq $true))

				$Xml = @"
<RSAKeyValue>
  <Modulus>$([System.Convert]::ToBase64String($RsaParams.Modulus))</Modulus>
  <Exponent>$([System.Convert]::ToBase64String($RsaParams.Exponent))</Exponent>
  <P>$([System.Convert]::ToBase64String($RsaParams.P))</P>
  <Q>$([System.Convert]::ToBase64String($RsaParams.Q))</Q>
  <DP>$([System.Convert]::ToBase64String($RsaParams.DP))</DP>
  <DQ>$([System.Convert]::ToBase64String($RsaParams.DQ))</DQ>
  <InverseQ>$([System.Convert]::ToBase64String($RsaParams.InverseQ))</InverseQ>
  <D>$([System.Convert]::ToBase64String($RsaParams.D))</D>
</RSAKeyValue>
"@
				Write-Output -InputObject $Xml
			}

			End {
			}
		}
	} 

	Process {
        $StartTime = $StartTime.ToUniversalTime()
        $Expiration = $Expiration.ToUniversalTime()

        [System.DateTime]$Epoch = New-Object System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)

        [System.Int32]$Seconds = $Expiration.Subtract($Epoch).TotalSeconds
		[System.Int32]$Start = 0

		if ($StartTime -gt $Epoch)
		{
            $Start = $StartTime.Subtract($Epoch).TotalSeconds
		}

		if ([System.String]::IsNullOrEmpty($SourceIp))
		{
			$SourceIp = "0.0.0.0/0"
		}

        $PolicyStatement = @"
{
  "Statement": [
    {
      "Resource" : "$PolicyResource",
      "Condition" : {
        "DateLessThan" : {		 
          "AWS:EpochTime" : $Seconds
        },
        "DateGreaterThan" : {
	      "AWS:EpochTime": $Start
		},
		"IpAddress" : {
		  "AWS:SourceIp" : "$SourceIp"
		}
      }
    }
  ]
}
"@
		#AWS requires that all white space be removed from the policy statement
		$PolicyStatement = $PolicyStatement -replace "\s",""

		[System.Byte[]]$PolicyStatementBytes = [System.Text.Encoding]::ASCII.GetBytes($PolicyStatement)

        [System.Security.Cryptography.SHA1CryptoServiceProvider]$SHA1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
        [System.Byte[]]$PolicyHash = $SHA1.ComputeHash($PolicyStatementBytes)

		#Replace hashed characters with URL safe characters, these are defined by AWS in their instructions
		[System.String]$Base64Policy = [System.Convert]::ToBase64String($PolicyStatementBytes).Replace("+", "-").Replace("=", "_").Replace("/", "~")

		#Otherwise, the PEM content was included as a parameter
		if ($PSCmdlet.ParameterSetName -eq "File")
		{
			$PEM = Get-Content -Path $PemFileLocation -Raw
		}
        
		[System.String]$Xml = Get-RsaKeysFromPem -PEM $PEM | ConvertRsaTo-Xml -IncludePrivateParameters

		[System.Security.Cryptography.RSACryptoServiceProvider]$RSA = New-Object -TypeName System.Security.Cryptography.RSACryptoServiceProvider
		$RSA.FromXmlString($Xml)

		[System.Security.Cryptography.RSAPKCS1SignatureFormatter]$RSAFormatter = New-Object -TypeName System.Security.Cryptography.RSAPKCS1SignatureFormatter($RSA)
		$RSAFormatter.SetHashAlgorithm("SHA1")

		[System.Byte[]]$SignedPolicyHash = $RSAFormatter.CreateSignature($PolicyHash)

		[System.String]$Signature = [System.Convert]::ToBase64String($SignedPolicyHash).Replace("+", "-").Replace("=", "_").Replace("/", "~")
		
		[System.Uri]$Url = New-Object -TypeName System.Uri($CloudfrontUrl)

		#Remove the leading ? in the query statement because we're going to add one explicitly as we need to add query string parameters
		#even if a query wasn't provided in the Url parameter
		[System.String]$Query = $Url.Query.Replace("?", "")

		#If the submitted url does have a query, add an ampersand because we'll append our query parameters after the user provided query
		if (-not [System.String]::IsNullOrEmpty($Query))
		{
			$Query += "&"
		}

		[System.String]$PrivateUrl = "$($Url.Scheme)://$($Url.DnsSafeHost)$($Url.AbsolutePath)?$Query`Policy=$Base64Policy&Signature=$Signature&Key-Pair-Id=$KeyPairId"

		Write-Output -InputObject $PrivateUrl 
	}

	End {
	}
}

Function New-AWSSplat {
	<#
		.SYNOPSIS
			Builds a hashtable that can be used as a splat for default AWS parameters.

		.DESCRIPTION
			Creates a hashtable that contains the common AWS Parameters for authentication and location. This collection can then be used as a splat against AWS PowerShell cmdlets.

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked. For example, us-east-1, eu-west-1 etc. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

		.PARAMETER AccessKey
			The AWS access key for the user account. This can be a temporary access key if the corresponding session token is supplied to the -SessionToken parameter.

		.PARAMETER SecretKey
			The AWS secret key for the user account. This can be a temporary secret key if the corresponding session token is supplied to the -SessionToken parameter.

		.PARAMETER SessionToken
			The session token if the access and secret keys are temporary session-based credentials.

		.PARAMETER Credential
			An AWSCredentials object instance containing access and secret key information, and optionally a token for session-based credentials.

		.PARAMETER ProfileLocation 
			Used to specify the name and location of the ini-format credential file (shared with the AWS CLI and other AWS SDKs)
			
			If this optional parameter is omitted this cmdlet will search the encrypted credential file used by the AWS SDK for .NET and AWS Toolkit for Visual Studio first. If the profile is not found then the cmdlet will search in the ini-format credential file at the default location: (user's home directory)\.aws\credentials. Note that the encrypted credential file is not supported on all platforms. It will be skipped when searching for profiles on Windows Nano Server, Mac, and Linux platforms.
			
			If this parameter is specified then this cmdlet will only search the ini-format credential file at the location given.
			
			As the current folder can vary in a shell or during script execution it is advised that you use specify a fully qualified path instead of a relative path.

		.PARAMETER ProfileName
			The user-defined name of an AWS credentials or SAML-based role profile containing credential information. The profile is expected to be found in the secure credential file shared with the AWS SDK for .NET and AWS Toolkit for Visual Studio. You can also specify the name of a profile stored in the .ini-format credential file used with the AWS CLI and other AWS SDKs.

		.PARAMETER DefaultRegion
			The default region to use if one hasn't been set and can be retrieved through Get-AWSDefaultRegion. This defaults to us-east-1.

				.EXAMPLE
			Copy-EBSVolume -SourceInstanceName server1 -DestinationInstanceName server2 -DeleteSnapshots -ProfileName mycredprofile -Verbose -Region ([Amazon.RegionEndpoint]::USWest2) -DestinationRegion ([Amazon.RegionEndpoint]::USEast2)
			
			Copies the EBS volume(s) from server1 in us-west-2 and attaches them to server2 in us-east-2. 

		.EXAMPLE
			New-AWSSplat -Region ([Amazon.RegionEndpoint]::USEast1) -ProfileName myprodaccount

			Creates a splat for us-east-1 using credentials stored in the myprodaccount profile.

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/15/2107
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
        [Amazon.RegionEndpoint]$Region,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]$ProfileName,

        [Parameter()]
		[ValidateNotNull()]
        [System.String]$AccessKey,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]$SecretKey,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]$SessionToken,

        [Parameter()]
        [Amazon.Runtime.AWSCredentials]$Credential,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]$ProfileLocation,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]$DefaultRegion = "us-east-1"
	)

	Begin {
	}

	Process {
		#Map the common AWS parameters
        $CommonSplat = @{}

        if ($PSBoundParameters.ContainsKey("Region") -and $Region -ne $null)
        {
            $CommonSplat.Region = $Region.SystemName
        }
		else
		{
            [System.String]$RegionTemp = Get-DefaultAWSRegion | Select-Object -ExpandProperty Region

            if (-not [System.String]::IsNullOrEmpty($RegionTemp))
            {
			    #Get-DefaultAWSRegions returns a Amazon.Powershell.Common.AWSRegion object
 			    $CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($RegionTemp) | Select-Object -ExpandProperty SystemName
            }
            else
            {
                #No default region set
                $CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($DefaultRegion) | Select-Object -ExpandProperty SystemName
            }
		}

        if ($PSBoundParameters.ContainsKey("SecretKey"))
        {
            $CommonSplat.SecretKey = $SecretKey
        }

        if ($PSBoundParameters.ContainsKey("AccessKey"))
        {
            $CommonSplat.AccessKey = $AccessKey
        }

        if ($PSBoundParameters.ContainsKey("SessionToken"))
        {
            $CommonSplat.SessionToken = $SessionToken
        }

        if ($PSBoundParameters.ContainsKey("ProfileName"))
        {
            $CommonSplat.ProfileName = $ProfileName
        }

        if ($PSBoundParameters.ContainsKey("ProfileLocation"))
        {
            $CommonSplat.ProfileLocation = $ProfileLocation
        }

        if ($PSBoundParameters.ContainsKey("Credential") -and $Credential -ne $null)
        {
            $CommonSplat.Credential = $Credential
        }

		Write-Output -InputObject $CommonSplat
	}

	End {
	}
}

Function Copy-EBSVolume {
    <#
        .SYNOPSIS
			Copies EBS volumes from a source to a destination.

		.DESCRIPTION
			This cmdlet creates EBS Volume snaphshots of a specified EBS volume, or volumes attached to an instance and then creates new EBS volumes
			from those snapshots.

			If a destination EC2 instance is not specified either by Id or name, the volumes are created in the destination region, but are not
			attached to anything and the cmdlet will return details about the volumes.

			The volume are attached to the first available device on the EC2 instance starting at xvdb and will attach until xvdp.

		.PARAMETER SourceInstanceId
			The Id of the source EC2 instance to copy EBS volumes from.

		.PARAMETER SourceEBSVolumeId
			The Id of the source EBS volume to copy.

		.PARAMETER SourceInstanceName
			The name of the source EC2 instance to copy EBS volumes from. This matches against the Name tag value.

		.PARAMETER DestinationInstanceId
			The Id of the EC2 instance to attach the new volumes to.

		.PARAMETER DestinationInstanceName
			The name of the destination EC2 instance to attach the new volumes to. This matches against the Name tag value.

		.PARAMETER OnlyRootDevice
			Only copies the root/boot volume from the source EC2 instance.

		.PARAMETER DeleteSnapshots
			The intermediary snapshots will be deleted. If this is not specified, they will be left.

		.PARAMETER DestinationRegion
			The region the new volumes should be created in. This must be specified if the destination instance
			is in a different region. This parameter defaults to the source region.

		.PARAMETER AvailabilityZone
			The AZ in which the new volume(s) should be created. If this is not specified, the AZ is determined by the AZ the source volume
			is in if the new volume is being created in the same region. If the volume is being created in a different region, the AZ of 
			the indicated destination EC2 instance is used. If a destination EC2 instance isn't specified, then the first available AZ of the
			region will be used.

		.PARAMETER Timeout
			The amount of time in seconds to wait for each snapshot and volume to be created. This defaults to 900 seconds (15 minutes).

		.PARAMETER KmsKeyId
			If you specify this, the resulting EBS volumes will be encrypted using this KMS key. You don't need to specify the EncryptNewVolumes parameter if you provide this one.

		.PARAMETER EncryptNewVolumes
			This will encrypt the resulting volumes using the default AWS KMS key.	

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked. For example, us-east-1, eu-west-1 etc. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

		.PARAMETER AccessKey
			The AWS access key for the user account. This can be a temporary access key if the corresponding session token is supplied to the -SessionToken parameter.

		.PARAMETER SecretKey
			The AWS secret key for the user account. This can be a temporary secret key if the corresponding session token is supplied to the -SessionToken parameter.

		.PARAMETER SessionToken
			The session token if the access and secret keys are temporary session-based credentials.

		.PARAMETER Credential
			An AWSCredentials object instance containing access and secret key information, and optionally a token for session-based credentials.

		.PARAMETER ProfileLocation 
			Used to specify the name and location of the ini-format credential file (shared with the AWS CLI and other AWS SDKs)
			
			If this optional parameter is omitted this cmdlet will search the encrypted credential file used by the AWS SDK for .NET and AWS Toolkit for Visual Studio first. If the profile is not found then the cmdlet will search in the ini-format credential file at the default location: (user's home directory)\.aws\credentials. Note that the encrypted credential file is not supported on all platforms. It will be skipped when searching for profiles on Windows Nano Server, Mac, and Linux platforms.
			
			If this parameter is specified then this cmdlet will only search the ini-format credential file at the location given.
			
			As the current folder can vary in a shell or during script execution it is advised that you use specify a fully qualified path instead of a relative path.

		.PARAMETER ProfileName
			The user-defined name of an AWS credentials or SAML-based role profile containing credential information. The profile is expected to be found in the secure credential file shared with the AWS SDK for .NET and AWS Toolkit for Visual Studio. You can also specify the name of a profile stored in the .ini-format credential file used with the AWS CLI and other AWS SDKs.

		.EXAMPLE
			[Amazon.EC2.Model.Volume[]]$NewVolumes = Copy-EBSVolume -SourceInstanceName server1 -DeleteSnapshots -ProfileName mycredprofile -Verbose -DestinationRegion ([Amazon.RegionEndpoint]::USEast2)
			
			Copies the EBS volumes from server1 in the region specified in the mycredprofile AWS credential profile as the default region to us-east-2. 

		.EXAMPLE
			[Amazon.EC2.Model.Volume[]]$NewVolumes = Copy-EBSVolume -SourceInstanceName server1 -DestinationInstanceName server2 -DeleteSnapshots -ProfileName mycredprofile -Verbose -Region ([Amazon.RegionEndpoint]::USWest2) -DestinationRegion ([Amazon.RegionEndpoint]::USEast2)
			
			Copies the EBS volume(s) from server1 in us-west-2 and attaches them to server2 in us-east-2. 

		.INPUTS
			None

		.OUTPUTS
			Amazon.EC2.Model.Volume[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/15/2107
    #>

    [CmdletBinding(DefaultParameterSetName = "DestinationByIdSourceByInstanceId")]
    Param(
		[Parameter(ParameterSetName = "SourceByInstanceId", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByIdSourceByInstanceId", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByNameSourceByInstanceId", Mandatory = $true)]
        [System.String]$SourceInstanceId,

		[Parameter(ParameterSetName = "SourceByVolumeId", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByNameSourceByVolumeId", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByIdSourceByVolumeId", Mandatory = $true)]
        [System.String]$SourceEBSVolumeId,

		[Parameter(ParameterSetName = "SourceByInstanceName", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByNameSourceByInstanceName", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByIdSourceByInstanceName", Mandatory = $true)]
        [System.String]$SourceInstanceName,

        [Parameter(ParameterSetName = "DestinationByIdSourceByInstanceId", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByIdSourceByVolumeId", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByIdSourceByInstanceName", Mandatory = $true)]
        [System.String]$DestinationInstaceId,

        [Parameter(ParameterSetName = "DestinationByNameSourceByInstanceId", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByNameSourceByVolumeId", Mandatory = $true)]
        [Parameter(ParameterSetName = "DestinationByNameSourceByInstanceName", Mandatory = $true)]
        [System.String]$DestinationInstanceName,

        [Parameter()]
        [switch]$OnlyRootDevice,

        [Parameter()]
        [switch]$DeleteSnapshots,

        [Parameter()]
		[ValidateNotNull()]
        [Amazon.RegionEndpoint]$Region,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]$ProfileName = [System.String]::Empty,

        [Parameter()]
		[ValidateNotNull()]
        [System.String]$AccessKey = [System.String]::Empty,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]$SecretKey = [System.String]::Empty,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]$SessionToken = [System.String]::Empty,

        [Parameter()]
        [ValidateNotNull()]
        [Amazon.Runtime.AWSCredentials]$Credential,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]$ProfileLocation = [System.String]::Empty,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$AvailabilityZone = [System.String]::Empty,

		[Parameter()]
		[ValidateNotNull()]
		[Amazon.RegionEndpoint]$DestinationRegion,

		[Parameter()]
		[System.UInt32]$Timeout = 900,

		[Parameter()]
		[switch]$EncryptNewVolumes,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$KmsKeyId = [System.String]::Empty
    )

    Begin {
    }

    Process {
		#Map the common AWS parameters
		[System.Collections.Hashtable]$SourceSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		
		if (-not $PSBoundParameters.ContainsKey("Region"))
		{
			$Region = [Amazon.RegionEndpoint]::GetBySystemName($SourceSplat.Region)
		}
		
		#Map the common parameters, but with the destination Region
		[System.Collections.Hashtable]$DestinationSplat = New-AWSSplat -Region $DestinationRegion -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation
		
		#If the user did not specify a destination region, use the source region
		#which could be specified, or be the default
		if (-not $PSBoundParameters.ContainsKey("DestinationRegion"))
		{
			$DestinationSplat.Region = $SourceSplat.Region
			$DestinationRegion = [Amazon.RegionEndpoint]::GetBySystemName($DestinationSplat.Region)
		}

		#The first step is to get the volume Ids attached to the instance we are trying to copy data from
        [System.String[]]$EBSVolumeIds = @()

        switch -Wildcard ($PSCmdlet.ParameterSetName) {
            "*SourceByInstanceName" {

                [Amazon.EC2.Model.Filter]$Filter = New-Object -TypeName Amazon.EC2.Model.Filter

				#Filtering on tag values uses the "tag:" preface for the key name
                $Filter.Name = "tag:Name"
                $Filter.Value = $SourceInstanceName
                
                #This is actually a [Amazon.EC2.Model.Reservation], but if no instance is returned, it comes back as System.Object[]
                #so save the error output and don't strongly type it
                $Instances = Get-EC2Instance -Filter @($Filter) @SourceSplat -ErrorAction SilentlyContinue

                if ($Instances -ne $null)
                {
                    [Amazon.EC2.Model.Instance]$Instance = $Instances.Instances | Select-Object -First 1

                    if ($Instance -ne $null)
                    {
						#Only update the AZ if a specific one wasn't specified and we're not moving cross region
						if (-not $PSBoundParameters.ContainsKey("AvailabilityZone") -and $Region.SystemName -eq $DestinationRegion.SystemName)
						{
							$AvailabilityZone = $Instance.Placement.AvailabilityZone
							Write-Verbose -Message "An AZ wasn't explicitly specified, so we'll use the AZ of the source volume: $AvailabilityZone"
						}

                        if ($OnlyRootDevice)
                        {
                            $EBSVolumeIds = $Instance.BlockDeviceMappings | Where-Object {$_.DeviceName -eq $Instance.RootDeviceName} | Select-Object -First 1 -ExpandProperty Ebs | Select-Object -ExpandProperty VolumeId
                        }
                        else
                        {
                            $EBSVolumeIds = $Instance.BlockDeviceMappings | Select-Object -ExpandProperty Ebs | Select-Object -ExpandProperty VolumeId
                        }                        
                    }
                    else
                    {
                        throw "[ERROR] Could not find a matching EC2 instance."
                    }
                }
                else
                {
                    throw "[ERROR] Nothing was returned by the get instance request."
                }
                
                break
            }
            "*SourceByInstanceId" {
                
                #This is actually a [Amazon.EC2.Model.Reservation], but if no instance is returned, it comes back as System.Object[]
                #so save the error output and don't strongly type it
                $Instances = Get-EC2Instance -InstanceId $SourceInstanceId @SourceSplat -ErrorAction SilentlyContinue

                if ($Instances -ne $null)
                {
                    [Amazon.EC2.Model.Instance]$Instance = $Instances.Instances | Select-Object -First 1

                    if ($Instance -ne $null)
                    {
						#Only update the AZ if a specific one wasn't specified and we're not moving cross region
						if (-not $PSBoundParameters.ContainsKey("AvailabilityZone") -and $Region.SystemName -eq $DestinationRegion.SystemName)
						{
							$AvailabilityZone = $Instance.Placement.AvailabilityZone
							Write-Verbose -Message "An AZ wasn't explicitly specified, so we'll use the AZ of the source volume: $AvailabilityZone"
						}

                        if ($OnlyRootDevice)
                        {
                            $EBSVolumeIds = $Instance.BlockDeviceMappings | `
												Where-Object {$_.DeviceName -eq $Instance.RootDeviceName} | `
												Select-Object -ExpandProperty Ebs | `
												Select-Object -First 1 -ExpandProperty VolumeId
                        }
                        else
                        {
                            $EBSVolumeIds = $Instance.BlockDeviceMappings | Select-Object -ExpandProperty Ebs | Select-Object -ExpandProperty VolumeId
                        }                       
                    }
                    else
                    {
                        throw -Message "[ERROR] Could not find a matching EC2 instance."
                    }
                }
                else
                {
                    throw -Message "[ERROR] Nothing was returned by the get instance request."
                }

                break
            }
            "*SourceByVolumeId" {
				#This check just ensures the EC2 EBS volume exists

                [Amazon.EC2.Model.Volume]$Volume = Get-EC2Volume -VolumeId $SourceEBSVolumeId @SourceSplat
                
                if ($Volume -ne $null)
                {
                    $EBSVolumeIds = @(($Volume | Select-Object -ExpandProperty VolumeId))

				    #Only update the AZ if a specific one wasn't specified and we're not moving cross region
					if (-not $PSBoundParameters.ContainsKey("AvailabilityZone") -and $Region.SystemName -eq $DestinationRegion.SystemName)
				    {
					    $AvailabilityZone = $Volume.AvailabilityZone
						Write-Verbose -Message "An AZ wasn't explicitly specified, so we'll use the AZ of the source volume: $AvailabilityZone"
				    }
                }
                else
                {
                    throw "[ERROR] Could not find a volume matching $SourceEBSVolumeId"
                }

                break
            }
            default {
                throw "Could not determine parameter set name"
            }
        }

		#Retrieve the destination EC2 instance
		#This needs to come after the instance retrieval because it may
		#update the destination AZ
        [Amazon.EC2.Model.Instance]$Destination = $null

        switch -Wildcard ($PSCmdlet.ParameterSetName)
        {
            "DestinationByName*" {
                [Amazon.EC2.Model.Filter]$Filter = New-Object -TypeName Amazon.EC2.Model.Filter
                $Filter.Name = "tag:Name"
                $Filter.Value = $DestinationInstanceName
                
                $Destination = Get-EC2Instance -Filter @($Filter) @DestinationSplat | Select-Object -ExpandProperty Instances | Select-Object -First 1
				$AvailabilityZone = $Destination.Placement.AvailabilityZone

                break
            }
            "DestinationById*" {
                $Destination = Get-EC2Instance -InstanceId $DestinationInstaceId @DestinationSplat | Select-Object -ExpandProperty Instances | Select-Object -First 1
				$AvailabilityZone = $Destination.Placement.AvailabilityZone

                break
            }
            default {
                Write-Verbose -Message "A destination is not provided, so just creating the snapshots and volumes"

				#If the AZ hasn't been specified previously because this is a cross region
				#move, select a default one for the destination region
                if ([System.String]::IsNullOrEmpty($AvailabilityZone))
                {
                    $AvailabilityZone = Get-EC2AvailabilityZone -Region $DestinationRegion.SystemName | Where-Object {$_.State -eq [Amazon.EC2.AvailabilityZoneState]::Available} | Select-Object -First 1 -ExpandProperty ZoneName
                    Write-Verbose -Message "Using a default AZ in the destination region since a destination instance and AZ were not specified: $AvailabilityZone"
                }
            }
        }

		#This will be used in the snapshot description
		[System.String]$Purpose = [System.String]::Empty

		if ($Destination -ne $null)
		{
			$Purpose = $Destination.InstanceId
		}
		else
		{
			$Purpose = $DestinationRegion.SystemName
		}

		#Create the snapshots at the source
        [Amazon.EC2.Model.Snapshot[]]$Snapshots = $EBSVolumeIds | New-EC2Snapshot @SourceSplat -Description "TEMPORARY for $Purpose"

		#Using a try here so the finally step will always delete the snapshots if specified
		try
		{
			#Reset the counter for the next loop
			$Counter = 0

			#While all of the snapshots have not completed, wait
			while (($Snapshots | Where-Object {$_.State -ne [Amazon.EC2.SnapshotState]::Completed}) -ne $null -and $Counter -lt $Timeout)
			{
				$Completed = (($Snapshots | Where-Object {$_.State -eq [Amazon.EC2.SnapshotState]::Completed}).Length / $Snapshots.Length) * 100
				Write-Progress -Activity "Creating snapshots" -Status "$Completed% Complete:" -PercentComplete $Completed

				#Update their statuses
				for ($i = 0; $i -lt $Snapshots.Length; $i++)
				{
					if ($Snapshots[$i].State -ne [Amazon.EC2.SnapshotState]::Completed)
					{
						Write-Verbose -Message "Waiting on snapshot $($Snapshots[$i].SnapshotId) to complete, currently at $($Snapshots[$i].Progress) in state $($Snapshots[$i].State)"
						$Snapshots[$i] = Get-EC2Snapshot -SnapshotId $Snapshots[$i].SnapshotId @SourceSplat
					}
				}

				Start-Sleep -Seconds 1
				$Counter++
			}

			if ($Counter -ge $Timeout)
			{
				throw "Timeout waiting for snapshots to be created."
			}
			else
			{
				Write-Verbose -Message "All of the snapshots have completed."
			}

			[Amazon.EC2.Model.Snapshot[]]$SnapshotsToCreate = @()

			#Reset the counter for the next loop
			$Counter = 0

			#If this is a cross region move, copy the snapshots over
			if ($DestinationRegion.SystemName -ne $Region.SystemName)
			{
				Write-Verbose -Message "Copying snapshots from $($SourceSplat.Region) to $($DestinationSplat.Region)"

				[System.String[]]$NewIds = $Snapshots | Select-Object -ExpandProperty SnapshotId | Copy-EC2Snapshot -SourceRegion $SourceSplat.Region -Description "TEMPORARY for $Purpose" @DestinationSplat
				$SnapshotsToCreate = $NewIds | Get-EC2Snapshot @DestinationSplat

				#While all of the snapshots have not completed, wait
				while (($SnapshotsToCreate | Where-Object {$_.State -ne [Amazon.EC2.SnapshotState]::Completed}) -ne $null -and $Counter -lt $Timeout)
				{
					$Completed = (($SnapshotsToCreate | Where-Object {$_.State -eq [Amazon.EC2.SnapshotState]::Completed}).Length / $SnapshotsToCreate.Length) * 100
					Write-Progress -Activity "Creating snapshots" -Status "$Completed% Complete:" -PercentComplete $Completed

					#Update their statuses
					for ($i = 0; $i -lt $SnapshotsToCreate.Length; $i++)
					{
						if ($SnapshotsToCreate[$i].State -ne [Amazon.EC2.SnapshotState]::Completed)
						{
							Write-Verbose -Message "Waiting on snapshot $($SnapshotsToCreate[$i].SnapshotId) copy to complete, currently at $($SnapshotsToCreate[$i].Progress) in state $($SnapshotsToCreate[$i].State)"
							$SnapshotsToCreate[$i] = Get-EC2Snapshot -SnapshotId $SnapshotsToCreate[$i].SnapshotId @DestinationSplat
						}
					}

					Start-Sleep -Seconds 1
					$Counter++
				}

				if ($Counter -ge $Timeout)
				{
					throw "Timeout waiting for snapshots to be copied to new region."
				}
				else
				{
					Write-Verbose -Message "All of the copied snapshots have completed."
				}
			}
			else
			{
				#Not a cross region move, so assign the current snapshots to the variable
				#that we will evaluate to create the volumes from

				$SnapshotsToCreate = $Snapshots

				#Empty the original array to be able to identify what needs
				#to be deleted later
				$Snapshots = @()
			}

			#If the cmdlet is told to encrypt the volumes or provides a specific KMS key, build the splat
			#to send the encryption parameters
			[System.Collections.HashTable]$NewVolumeSplat = @{}

			if (($EncryptNewVolumes -eq $true) -or (-not [System.String]::IsNullOrEmpty($KmsKeyId)))
			{
				$NewVolumeSplat.Encrypted = $true
			}

			if (-not [System.String]::IsNullOrEmpty($KmsKeyId))
			{
				$NewVolumeSplat.KmsKeyId = $KmsKeyId
			}

			[Amazon.EC2.Model.Volume[]]$NewVolumes = $SnapshotsToCreate | New-EC2Volume -AvailabilityZone $AvailabilityZone @DestinationSplat @NewVolumeSplat

			#Reset the counter for the next loop
			$Counter = 0

			#Wait for the new volumes to become available before we try to attach them
			while (($NewVolumes | Where-Object {$_.State -ne [Amazon.EC2.VolumeState]::Available}) -ne $null -and $Counter -lt $Timeout)
			{
				$Completed = (($NewVolumes | Where-Object {$_.State -eq [Amazon.EC2.VolumeState]::Available}).Length / $NewVolumes.Length) * 100
				Write-Progress -Activity "Creating volumes" -Status "$Completed% Complete:" -PercentComplete $Completed
			
				for ($i = 0; $i -lt $NewVolumes.Length; $i++)
				{
					if ($NewVolumes[$i].State -ne [Amazon.EC2.VolumeState]::Available)
					{
						Write-Verbose -Message "Waiting on volume $($NewVolumes[$i].VolumeId) to become available, currently $($NewVolumes[$i].State)"
						$NewVolumes[$i] = Get-EC2Volume -VolumeId $NewVolumes[$i].VolumeId @DestinationSplat
					}
				}

				Start-Sleep -Seconds 1
				$Counter++
			}

			if ($Counter -ge $Timeout)
			{
				throw "Timeout waiting for volumes to be created."
			}
			else
			{
				Write-Verbose -Message "All of the new volumes are available."
			}

			#Check if a destination instance was specified
			if ($Destination -ne $null)
			{
				[System.String]$DeviceBase = "xvd"

				#If you map an EBS volume with the name xvda, Windows does not recognize the volume.
				[System.Int32]$CurrentLetter = [System.Int32][System.Char]'b'

				[System.String[]]$Devices = $Destination.BlockDeviceMappings | Select-Object -ExpandProperty DeviceName

				#Iterate all of the new volumes and attach them
				foreach ($Item in $NewVolumes)
				{
					try
					{
						#Try to find an available device
						while ($Devices.Contains($DeviceBase + [System.Char]$CurrentLetter) -and [System.Char]$CurrentLetter -ne 'p')
						{
							$CurrentLetter++
						}

						#The last usable letter is p
						if ([System.Char]$CurrentLetter -ne 'q')
						{
							Write-Verbose -Message "Attaching $($Item.VolumeId) to $($Destination.InstanceId) at device $DeviceBase$([System.Char]$CurrentLetter)"
                        
							#The cmdlet will create the volume as the same size as the snapshot
							[Amazon.EC2.Model.VolumeAttachment]$Attachment = Add-EC2Volume -InstanceId $Destination.InstanceId -VolumeId $Item.VolumeId -Device ($DeviceBase + [System.String][System.Char]$CurrentLetter) @DestinationSplat
							Write-Verbose -Message "Attached at $($Attachment.AttachTime)"
                    
							#Increment the letter so the next check doesn't try to use the same device
							$CurrentLetter++
						}
						else
						{
							#Break out of the iteration because we can't mount any more drives
							Write-Warning -Message "No available devices left to mount the device"
							break
						}
					}
					catch [Exception]
					{
						Write-Warning -Message "[ERROR] Could not attach volume $($Item.VolumeId) with error $($_.Exception.Message)"
					}
				}
			}
			elseif ($PSCmdlet.ParameterSetName -like ("DestinationBy*"))
			{
				#This means a destination instance was specified, but we didn't
				#find it in the Get-EC2Instance cmdlet
				Write-Warning -Message "[ERROR] Could not find the destination instance"
			}

            Write-Output -InputObject $NewVolumes					
		}
		finally
		{		
			if ($DeleteSnapshots)
			{
				#Delete the original source Region snapshots if there are any
				if ($Snapshots -ne $null -and $Snapshots.Length -gt 0)
				{
					Write-Verbose -Message "Deleting snapshots $([System.String]::Join(",", ($Snapshots | Select-Object -ExpandProperty SnapshotId)))"
					$Snapshots | Remove-EC2Snapshot @SourceSplat -Confirm:$false
				}

				if ($SnapshotsToCreate -ne $null -and $SnapshotsToCreate.Length -gt 0)
				{
					Write-Verbose -Message "Deleting snapshots $([System.String]::Join(",", ($SnapshotsToCreate | Select-Object -ExpandProperty SnapshotId)))"
					$SnapshotsToCreate | Remove-EC2Snapshot @DestinationSplat -Confirm:$false
				}
			}
		}
    }

    End {
    }
}