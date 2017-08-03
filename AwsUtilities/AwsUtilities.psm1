Import-Module -Name AWSPowerShell -ErrorAction Stop
Initialize-AWSDefaults

$script:CREATED_BY = "CreatedBy"
$script:CAN_BE_DELETED = "CanBeDeleted"
[System.Guid]$script:UNIQUE_ID = [System.Guid]::Parse("17701dbb-33ff-4f31-8914-6f48856fe755")
$script:INTEL_DRIVER = "Intel82599VF"
$script:ENA = "ENA"
$script:FederationUrl = "https://signin.aws.amazon.com/federation"
$script:IPRangeUrl = "https://ip-ranges.amazonaws.com/ip-ranges.json"

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
			Enables writing a log file to c:\AwsLogs\EBS\Backup.log with the transcript of the backup job. The log file is automatically rolled over when it exceeds 5MB.

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

        $IndexFileContents.offers | Get-Member -MemberType *Property | ForEach-Object {
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
		[System.String]$private:BaseUrl = "https://pricing.us-east-1.amazonaws.com"

		if ($PSCmdlet.ParameterSetName -eq "Url")
		{			
			[System.Net.WebClient]$private:WebClient = New-Object -TypeName System.Net.WebClient
			[System.String]$private:Response = $private:WebClient.DownloadString($PSBoundParameters["Url"])
		}
		elseif ($PSCmdlet.ParameterSetName -eq "Product")
		{
			[System.Net.WebClient]$private:WebClient = New-Object -TypeName System.Net.WebClient
			[System.String]$private:Response = $private:WebClient.DownloadString($OfferIndexUrl)

			$private:IndexFileContents = ConvertFrom-Json -InputObject $private:Response

			$private:Url = "$private:BaseUrl$($private:IndexFileContents.offers | Select-Object -ExpandProperty $PSBoundParameters["Product"] | Select-Object -ExpandProperty currentVersionUrl)"
            [System.Net.WebClient]$private:WebClient = New-Object -TypeName System.Net.WebClient
			
			Write-Verbose -Message $private:Url
			[System.String]$private:Response = $WebClient.DownloadString($private:Url)
		}
		else
		{
			$private:Response = Get-Content -Path $Path -Raw
		}

		<#
			The converted Obj object will look like the following:

			formatVersion   : v1.0
			disclaimer      : This pricing list is for informational purposes only. All prices are subject to the additional terms included in the pricing pages on http://aws.amazon.com. All Free Tier 
							  prices are also subject to the terms included at https://aws.amazon.com/free/
			offerCode       : AmazonElastiCache
			version         : 20170419194925
			publicationDate : 2017-04-19T19:49:25Z
			products        : @{HBRQZSXXSY2DXJ77=; 3Y8QARGM5NXC9EBW=; ... }
			terms           : @{OnDemand=; Reserved=}
		#>
		$private:ConvertedResponse = ConvertFrom-Json -InputObject $private:Response

		[PSCustomObject[]]$private:Results = @()

		#Expanding the products property gets us a single object with members like
		#RBW79EQZWRSDB85D : @{sku=RBW79EQZWRSDB85D; productFamily=Database Instance; attributes=}
		#W3PUKFKG7RDK3KA5 : @{sku=W3PUKFKG7RDK3KA5; productFamily=Data Transfer; attributes=}
		
		#We want to expand the property of the products object for each sku to access the hash table that has the data
		<#
			Products will look like
			8W42JWEZE64YAUET : @{sku=8W42JWEZE64YAUET; productFamily=Cache Instance; attributes=}
			T64VHYZ5FZP9JDEC : @{sku=T64VHYZ5FZP9JDEC; productFamily=Cache Instance; attributes=}
		#>
		[PSCustomObject]$private:Products = $private:ConvertedResponse | Select-Object -ExpandProperty products 

		#Getting the members of Products will get us all of the sku properties, we want to iterate each
		#one and select it, expanded from the products object, which will provide the hash table of data
		#which includes sku, productFamily, and attributes
		Get-Member -InputObject $private:Products -MemberType *Property | ForEach-Object {
			
            #The Get-Member results will have a name property, that is the sku data for each product
			#By expanding the name property, we get the values of the sku index, which are the properties
			#like attributes and productfamily
			[PSCustomObject]$private:ProductData = $private:Products | Select-Object -ExpandProperty $_.Name

            [System.Collections.Hashtable]$private:TempHashTable = @{}
            
            #Convert the PSCustomObject to a hash table
            $private:ProductData.attributes.psobject.Properties | ForEach-Object  {
                $private:TempHashTable[$_.Name] = $_.Value
            }

			#Assume the product matches the filters, and prove it false
			$private:Matches = $true

			#Now that we have product object, we can filter based on the key value pairs provided
			foreach ($Key in $Attributes.Keys)
			{
                #If the hash table doesn't contain the key and the values are not alike, it doesn't match
                #Otherwise, keep going
                if (-not ($private:TempHashTable.ContainsKey($Key) -and $private:TempHashTable[$Key] -like $Attributes[$Key]))
                {                    
                    $private:Matches = $false
                    break                    
                }
			}

			if ($private:Matches -eq $true)
			{
                $private:Results += [PSCustomObject]@{"Sku" = $private:ProductData.sku; "ProductFamily" = $private:ProductData.productFamily; "Attributes" = $TempHashTable}
			}
		}

		Write-Output -InputObject $private:Results
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

        if ($PSBoundParameters.ContainsKey("SecretKey") -and -not [System.String]::IsNullOrEmpty($SecretKey))
        {
            $CommonSplat.SecretKey = $SecretKey
        }

        if ($PSBoundParameters.ContainsKey("AccessKey") -and -not [System.String]::IsNullOrEmpty($AccessKey))
        {
            $CommonSplat.AccessKey = $AccessKey
        }

        if ($PSBoundParameters.ContainsKey("SessionToken") -and -not [System.String]::IsNullOrEmpty($SessionToken))
        {
            $CommonSplat.SessionToken = $SessionToken
        }

        if ($PSBoundParameters.ContainsKey("ProfileName") -and -not [System.String]::IsNullOrEmpty($ProfileName))
        {
            $CommonSplat.ProfileName = $ProfileName
        }

        if ($PSBoundParameters.ContainsKey("ProfileLocation") -and -not [System.String]::IsNullOrEmpty($ProfileLocation))
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

Function New-AWSUtilitiesSplat {
	<#
		.SYNOPSIS
			Builds a hashtable that can be used as a splat for default AWS parameters.

		.DESCRIPTION
			Creates a hashtable that contains the common AWS Parameters for authentication and location. This collection can then be used as a splat against AWS Utilities PowerShell cmdlets.

			The major difference is that AWS PowerShell cmdlets take a string for the region parameter, and these cmdlets use the Amazon.RegionEndpoint object for the region parameter.

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
			New-AWSUtilitiesSplat -Region ([Amazon.RegionEndpoint]::USEast1) -ProfileName myprodaccount

			Creates a splat for us-east-1 using credentials stored in the myprodaccount profile.

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/15/2107
	#>
	[CmdletBinding(DefaultParameterSetName="Specify")]
	Param(
		[Parameter(ParameterSetName="Specify")]
		[ValidateNotNull()]
        [Amazon.RegionEndpoint]$Region,

        [Parameter(ParameterSetName="Specify")]
        [ValidateNotNull()]
        [System.String]$ProfileName,

        [Parameter(ParameterSetName="Specify")]
		[ValidateNotNull()]
        [System.String]$AccessKey,

        [Parameter(ParameterSetName="Specify")]
        [ValidateNotNull()]
        [System.String]$SecretKey,

        [Parameter(ParameterSetName="Specify")]
        [ValidateNotNull()]
        [System.String]$SessionToken,

        [Parameter(ParameterSetName="Specify")]
		[ValidateNotNull()]
        [Amazon.Runtime.AWSCredentials]$Credential,

        [Parameter(ParameterSetName="Specify")]
        [ValidateNotNull()]
        [System.String]$ProfileLocation,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]$DefaultRegion = "us-east-1",

		[Parameter(ParameterSetName = "Splat")]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$AWSSplat
	)

	Begin {
	}

	Process {
		#Map the common AWS parameters
        [System.Collections.Hashtable]$CommonSplat = @{}

		if ($PSCmdlet.ParameterSetName -eq "Specify")
		{
			if ($PSBoundParameters.ContainsKey("Region") -or $Region -ne $null)
			{
				[Amazon.RegionEndpoint]$CommonSplat.Region = $Region
			}
			else
			{
				[System.String]$RegionTemp = Get-DefaultAWSRegion | Select-Object -ExpandProperty Region

				if (-not [System.String]::IsNullOrEmpty($RegionTemp))
				{
					#Get-DefaultAWSRegions returns a Amazon.Powershell.Common.AWSRegion object
 					[Amazon.RegionEndpoint]$CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($RegionTemp)
				}
				else
				{
					#No default region set
					[Amazon.RegionEndpoint]$CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($DefaultRegion)
				}
			}

			if ($PSBoundParameters.ContainsKey("SecretKey") -and -not [System.String]::IsNullOrEmpty($SecretKey))
			{
				$CommonSplat.SecretKey = $SecretKey
			}

			if ($PSBoundParameters.ContainsKey("AccessKey") -and -not [System.String]::IsNullOrEmpty($AccessKey))
			{
				$CommonSplat.AccessKey = $AccessKey
			}

			if ($PSBoundParameters.ContainsKey("SessionToken") -and -not [System.String]::IsNullOrEmpty($SessionToken))
			{
				$CommonSplat.SessionToken = $SessionToken
			}

			if ($PSBoundParameters.ContainsKey("ProfileName") -and -not [System.String]::IsNullOrEmpty($ProfileName))
			{
				$CommonSplat.ProfileName = $ProfileName
			}

			if ($PSBoundParameters.ContainsKey("ProfileLocation") -and -not [System.String]::IsNullOrEmpty($ProfileLocation))
			{
				$CommonSplat.ProfileLocation = $ProfileLocation
			}

			if ($PSBoundParameters.ContainsKey("Credential") -and $Credential -ne $null)
			{
				$CommonSplat.Credential = $Credential
			}
		}
		else
		{
			foreach ($Key in $AWSSplat.GetEnumerator())
			{
				if ($Key.Name -eq "Region" -and -not [System.String]::IsNullOrEmpty($Key.Value))
				{
					$CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($Key.Value)
				}
				else
				{
					if ($Key.Value -ne $null)
					{
						Write-Verbose -Message "Adding key $($Key.Name) $($Key.Value)"
						$CommonSplat."$($Key.Name)" = $Key.Value
					}
				}
			}
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

			The volume are attached to the first available device on the EC2 instance starting at xvdf and will attach until xvdp.

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
			LAST UPDATE: 4/15/2017
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
		[System.Collections.Hashtable]$SourceAWSUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $SourceSplat

		if (-not $PSBoundParameters.ContainsKey("Region"))
		{
			$Region = [Amazon.RegionEndpoint]::GetBySystemName($SourceSplat.Region)
		}
		
		#Map the common parameters, but with the destination Region
		[System.Collections.Hashtable]$DestinationSplat = New-AWSSplat -Region $DestinationRegion -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation
		[System.Collections.Hashtable]$DestinationAWSUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $DestinationSplat

		#If the user did not specify a destination region, use the source region
		#which could be specified, or be the default
		if (-not $PSBoundParameters.ContainsKey("DestinationRegion"))
		{
			$DestinationSplat.Region = $SourceSplat.Region
			$DestinationAWSUtilitiesSplat.Region = $SourceAWSUtilitiesSplat.Region
			$DestinationRegion = [Amazon.RegionEndpoint]::GetBySystemName($DestinationSplat.Region)
		}

		#The first step is to get the volume Ids attached to the instance we are trying to copy data from
        [System.String[]]$EBSVolumeIds = @()

        switch -Wildcard ($PSCmdlet.ParameterSetName) {
            "*SourceByInstanceName" {

				[Amazon.EC2.Model.Instance]$Instance = Get-EC2InstanceByNameOrId -Name $SourceInstanceName @SourceAWSUtilitiesSplat

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

                break
            }
            "*SourceByInstanceId" {
                
                #This is actually a [Amazon.EC2.Model.Reservation], but if no instance is returned, it comes back as System.Object[]
                #so save the error output and don't strongly type it
                [Amazon.EC2.Model.Instance]$Instance  = Get-EC2InstanceByNameOrId -InstanceId $SourceInstanceId @SourceAWSUtilitiesSplat

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
				$Destination = Get-EC2InstanceByNameOrId -Name $DestinationInstanceName @DestinationAWSUtilitiesSplat
				$AvailabilityZone = $Destination.Placement.AvailabilityZone

                break
            }
            "DestinationById*" {
                $Destination = Get-EC2InstanceByNameOrId -InstanceId $DestinationInstaceId @DestinationAWSUtilitiesSplat
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

			Write-Progress -Completed -Activity "Creating snapshots"

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

				Write-Progress -Completed -Activity "Creating snapshots"

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

			Write-Progress -Completed -Activity "Creating volumes"

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
				Write-Verbose -Message "Mounting volumes."
				Mount-EBSVolumes -VolumeIds ($NewVolumes | Select-Object -ExpandProperty VolumeId) -NextAvailableDevice -Instance $Destination @DestinationAWSUtilitiesSplat
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

Function Mount-EBSVolumes {
	<#
		.SYNOPSIS
			Mounts a set of available EBS volumes to an instance.

		.DESCRIPTION
			The cmdlet can mount one to many available EBS volumes to an EC2 instance. The destination instance
			can be provided as an EC2 object or by instance id. The mount point device can be specified directly
			or the next available device is used. If the device is specified directly and is in use, or if multiple
			volumes are specified, the provided device is used as a starting point to find the next available device.

		.PARAMETER VolumeIds
			The Ids of the volumes to attach. The must be in an available status.

		.PARAMETER NextAvailableDevice
			Specifies that the cmdlet will find the next available device between xvdf and xvdp.

		.PARAMETER Device
			Specify the device that the volume will be attached at. If multiple volumes are specified, this is the starting
			point to find the next available device for each.

		.PARAMETER InstanceId
			The id of the instance to attach the volumes to.

		.PARAMETER Instance
			The Amazon.EC2.Model.Instance object to attach the volumes to.

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
			Mount-EBSVolumes -VolumeIds vol-04d16ab9a1b07449g -InstanceId i-057bd4fe22eced7bb -Region ([Amazon.RegionEndpoint]::USWest1)

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/5/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "IdAndNextAvailable")]
		[Parameter(Mandatory = $true, ParameterSetName = "InputObjectAndNextAvailable")]
		[ValidateNotNull()]
		[System.String[]]$VolumeIds,

		[Parameter(ParameterSetName = "InputObjectAndNextAvailable", Mandatory = $true)]
		[Parameter(ParameterSetName = "IdAndNextAvailable", Mandatory = $true)]
		[switch]$NextAvailableDevice,

		[Parameter(ParameterSetName = "InputObjectAndDevice", Mandatory = $true)]
		[Parameter(ParameterSetName = "IdAndDevice", Mandatory = $true)]
		[ValidateSet("xvdf", "xvdg", "xvdh", "xvdi", "xvdj",
			"xvdk", "xvdl", "xvdm", "xvdn", "xvdo", "xvdp")]
		[System.String]$Device,

		[Parameter(Mandatory = $true, ParameterSetName = "IdAndDevice")]
		[Parameter(Mandatory = $true, ParameterSetName = "IdAndNextAvailable")]
		[ValidateNotNullOrEmpty()]
		[System.String]$InstanceId,

		[Parameter(Mandatory = $true, ParameterSetName = "InputObjectAndDevice")]
		[Parameter(Mandatory = $true, ParameterSetName = "InputObjectAndNextAvailable")]
		[Amazon.EC2.Model.Instance]$Instance,

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
        [System.String]$ProfileLocation = [System.String]::Empty
	)		

	Begin {
	}

	Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

		if ($PSCmdlet.ParameterSetName.StartsWith("Id"))
		{
			$Destination = Get-EC2Instance -InstanceId $InstanceId @Splat | Select-Object -ExpandProperty Instances | Select-Object -First 1
		}

		[System.String]$DeviceBase = "xvd"
		[System.Int32]$CurrentLetter = 0

		if ($NextAvailableDevice)
		{
			#If you map an EBS volume with the name xvda, Windows does not recognize the volume.
			$CurrentLetter = [System.Int32][System.Char]'f'
		}
		else
		{
			$CurrentLetter = [System.Int32][System.Char]$Device.Substring($Device.Length - 1)
		}

		#Iterate all of the new volumes and attach them
		foreach ($Item in $VolumeIds)
		{
			try
			{
				$Destination = Get-EC2Instance -InstanceId $Destination.InstanceId @Splat | Select-Object -ExpandProperty Instances | Select-Object -First 1
				[System.String[]]$Devices = $Destination.BlockDeviceMappings | Select-Object -ExpandProperty DeviceName

				#Try to find an available device
				while ($Devices.Contains($DeviceBase + [System.Char]$CurrentLetter) -and [System.Char]$CurrentLetter -ne 'q')
				{
					$CurrentLetter++
				}

				#The last usable letter is p
				if ([System.Char]$CurrentLetter -ne 'q')
				{
					Write-Verbose -Message "Attaching $Item to $($Destination.InstanceId) at device $DeviceBase$([System.Char]$CurrentLetter)"
                        
					#The cmdlet will create the volume as the same size as the snapshot
					[Amazon.EC2.Model.VolumeAttachment]$Attachment = Add-EC2Volume -InstanceId $Destination.InstanceId -VolumeId $Item -Device ($DeviceBase + [System.String][System.Char]$CurrentLetter) @Splat
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

	End {
	}
}

Function Get-EC2InstanceByNameOrId {
	<#
		.SYNOPSIS
			Gets an EC2 instance object by supplying its name or instance id.

		.DESCRIPTION
			The cmdlet gets a single Amazon.EC2.Model.Instance object from an instance name tag value or instance id. If multiple instances are
			matched from a name tag, the cmdlet throws an exception, as it also does if it doesn't find an instance based on id.

		.PARAMETER InstanceId
			The id of the instance to get.

		.PARAMETER InstanceName
			The value of the name tag of the instance to get. The name tags in the account being accessed must be unique for this to work.

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
			Get-EC2InstanceByNameOrId -Name server1 -ProfileName myprodacct

		.INPUTS
			None

		.OUTPUTS
			Amazon.EC2.Model.Instance

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/5/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Id")]
		[System.String]$InstanceId,

		[Parameter(Mandatory = $true, ParameterSetName = "Name")]
		[Alias("Name")]
		[System.String]$InstanceName,

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
        [System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

		[Amazon.EC2.Model.Instance]$EC2 = $null

		if ($PSCmdlet.ParameterSetName -eq "Id")
		{
			Write-Verbose -Message "Getting instance by Id $InstanceId."
			$Instances = Get-EC2Instance -InstanceId $InstanceId -ErrorAction SilentlyContinue @Splat
		}
		else
		{
			Write-Verbose -Message "Getting instance by Name $InstanceName."
			[Amazon.EC2.Model.Filter]$Filter = New-Object -TypeName Amazon.EC2.Model.Filter

			#Filtering on tag values uses the "tag:" preface for the key name
			$Filter.Name = "tag:Name"
			$Filter.Value = $InstanceName
                
			#This is actually a [Amazon.EC2.Model.Reservation], but if no instance is returned, it comes back as System.Object[]
			#so save the error output and don't strongly type it
			$Instances = Get-EC2Instance -Filter @($Filter) -ErrorAction SilentlyContinue @Splat
		}

		if ($Instances -ne $null)
		{
			if ($Instances.Instances.Count -gt 0)
			{
				if ($Instances.Instances.Count -eq 1)
				{
					$EC2 = $Instances.Instances | Select-Object -First 1

					if ($EC2 -eq $null)
					{
						throw "No matching instances found."
					}
				}
				else
				{
					throw "Ambiguous match, more than 1 EC2 instance with the name $InstanceName found. Try instance id instead."
				}
			}
			else
			{
				throw "No matching instances found."
			}
		}
		else
		{
			throw "Nothing was returned by the get instance request."
		}

		Write-Output -InputObject $EC2
	}

	End {
	}
}

Function Invoke-AWSNetworkAdapterFixOnOfflineDisk {
	<#
		.SYNOPSIS
			This cmdlet attempts to fix broken network adapters on an instance through modifying the instance's offline root volume.

		.DESCRIPTION
			The cmdlet assumes the offline root volume of the instance to be fixed is already mounted to the server the cmdlet is being run on, indicated by the provided drive letter.
			
			The cmdlet then copies over the AWS PV Drivers or Citrix Xen drivers from a source specified, and optionally enhanced networking drivers, if specified.

			At this point, the SYSTEM and SOFTWARE registry hives from the target drive are mounted and several updates to the registry are made, most importantly an auto logon using the credentials specified, which will be deleted at the next logon. 
			The auto logon triggers run once tasks to install the drivers, and then reboots. If enhanced networking drivers are specified, the instance is updated to support srIovSupport or ENA as applicable.

		.PARAMETER DriveLetter
			The drive letter where the offline root volume is mounted.

		.PARAMETER AWSPVDriverPath
			The path to the AWS PV Drivers msi installer or Citrix Xen drivers exe installer to copy to the offline system.

		.PARAMETER EnhancedNetworkingDriverPath
			The path to the enhanced networking drivers applicable for the instance type being fixed. 
	
			For Intel 82599 VF drivers, the directory should target the extracted output of the PROWinx64.exe file. For example if c:\IntelDrivers is specified, that folder should contain

			c:\IntelDrivers\PROXGB
			c:\InterDrivers\PRO40GB
			etc...

			For Elastic Network Adapter, if c:\ENA is specified, the directory should contain folders in this structure:
			
			c:\ENA\1.0.8.0\2012
			c:\ENA\1.0.8.0\2012R2
			c:\ENA\1.0.9.0\2008R2

			Each of these folders should contain 3 files, ena.cat, ena.inf, ena.sys. These files and folder structure are included with the module.

		.PARAMETER EnhancedNetworkingType
			The type of enhanced networking drivers to setup, this is either Intel82599VF or ENA and is required if the EnhancedNetworkingDriverPath is specified to successfully setup the drivers. If the EC2 instance doesn't support enhanced networking, this can be an empty string or null or not specified.

		.PARAMETER TempSystemKey
			The key used to mount the offline SYSTEM registry hive in HKLM of the local machine. This defaults to AWSTempSystem.

		.PARAMETER TempSoftwareKey
			The key used to mount the offline SOFTWARE registry hive in HKLM of the local machine. This defaults to AWSTempSoftware.

		.PARAMETER Credential
			The credentials to use for the auto logon. The user name can be specified as domain\user, user@domain.com (UPN format), or just the username. If only a username
			is specified, provide the domain parameter, otherwise it will default to the offline machine computer name as specified in the computer's registry.

			If the user is a domain user, a cached logon must be present to use it, as this cmdlet assumes the offline instance has no network connectivity.

			The user must have local admin rights on the offline machine.

		.PARAMETER Domain
			The domain name to use for the auto logon if the supplied credentials/user name is an Active Directory account. Otherwise, do not specify this parameter, as the local machine name will be used for a local account logon. 

			Also, if the Credential or UserName parameter is specified with a domain name included, you do not need to specify this parameter.
		
		.PARAMETER RemoteLogPath
			The path to a file on the target server logs are written to during the RunOnce script. Defaults to $env:SystemDrive\NetworkAdapterFix.log.

		.PARAMETER OperatingSystem
			If you specify a ref, this variable will be populated with the Windows Operating System version as a decimal value (i.e. 6.1, 6.2, 6.3, 10.0, etc) is returned so it can be used to evaluate other decisions

		.EXAMPLE
			Invoke-AWSNetworkAdapterFixOnOfflineDisk -DriveLetter 'e' -EnhancedNetworkingDriverPath c:\ENA -EnhancedNetworkingType ENA -UserName "contoso\john.smith" -Password (ConvertTo-SecureString -String "MyS3cureP@$$word" -AsPlainText -Force)

			The cmdlet is executed against a mounted EBS root volume at "e:\" and is from an instance type that uses the Elastic Network Adapter.

		.EXAMPLE
			Invoke-AWSNetworkAdapterFixOnOfflineDisk -DriveLetter 'e' -EnhancedNetworkingDriverPath c:\IntelDrivers -EnhancedNetworkingType Intel82599VF -Credential (Get-Credential)

			The cmdlet is executed against a mounted EBS root volume at "e:\" and is from an instance type that uses the SR IOV support. The credentials to execute the AutoLogon and RunOnce script are prompted.

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 7/13/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[System.Char]$DriveLetter,

		[Parameter(ParameterSetName = "PV", Mandatory = $true)]
		[Parameter(ParameterSetName = "ENA")]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$AWSPVDriverPath = [System.String]::Empty,

		[Parameter(ParameterSetName = "ENA", Mandatory = $true)]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$EnhancedNetworkingDriverPath,

		[Parameter(ParameterSetName = "ENA", Mandatory = $true)]
		[ValidateSet("Intel82599VF", "ENA")]
		[System.String]$EnhancedNetworkingType,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$TempSystemKey = "AWSTempSystem",

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$TempSoftwareKey = "AWSTempSoftware",

		[Parameter()]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Domain = [System.String]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$RemoteLogPath = "`$env:SystemDrive\NetworkAdapterFix.log",

		[Parameter()]
		[ValidateNotNull()]
		[ValidateScript({
			$_.Value.GetType() -eq [System.Decimal]
		})]
		[ref]$OperatingSystem
	)

	Begin {
		if (-not (New-Object -TypeName System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltinRole]::Administrator))
		{
			throw "Script must be run with administrative privileges."
		}
	}

	Process {
		
		# PART 1 - Fixes a broken NIC that has been disabled by the Plug and Play Cleanup Feature
		Write-Verbose -Message "Configuring existing PV driver registry settings"
		try
		{   
			$SysDrive = "$DriveLetter`:\Windows\System32\config\SYSTEM"
			Write-Verbose -Message "Mounting offline registry at $SysDrive."
			$Temp = & reg load "HKLM\$TempSystemKey" "$SysDrive"
    
			Write-Verbose -Message "Creating new PSDrive"
			$Temp = New-PSDrive -Name $TempSystemKey -PSProvider Registry -Root "HKLM\$TempSystemKey" -ErrorAction Stop

			# http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/pvdrivers-troubleshooting.html#plug-n-play-script

			[System.String[]]$FilterPaths = @(
				"$TempSystemKey`:\ControlSet001\Control\Class\4d36e97d-e325-11ce-bfc1-08002be10318",
				"$TempSystemKey`:\ControlSet001\Control\Class\4d36e96a-e325-11ce-bfc1-08002be10318"
			)

			[System.String[]]$OverrideKeys = @(
				"xenvbd",
				"xenfilt",
				"xenbus",
				"xeniface",
				"xenvif"
			)

			foreach ($Item in $FilterPaths)
			{
				if (-not (Test-Path -Path $Item))
				{
					Write-Verbose -Message "Creating registry key $Item"
					$Temp = New-Item -Path $Item
				}

				Write-Verbose -Message "Creating UpperFilters value XENFILT at $Item"
				$Temp = Set-ItemProperty -Path $Item -Name UpperFilters -Value XENFILT -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Force
			}

			foreach ($Item in $OverrideKeys)
			{
				if (Test-Path -Path "$TempSystemKey`:\ControlSet001\Services\$Item\StartOverride")
				{
					try
					{
						Write-Verbose -Message "Removing registry key $TempSystemKey`:\ControlSet001\Services\$Item\StartOverride"
						Remove-Item -Path "$TempSystemKey`:\ControlSet001\Services\$Item\StartOverride" -Force
					}
					catch [Exception]
					{
						Write-Warning -Message "[ERROR] Error removing $Item : $($_.Exception.Message)"
					}
				}
			}

			[System.String]$XENBUSPath = "$TempSystemKey`:\ControlSet001\Services\XENBUS"

			if (Test-Path -Path $XENBUSPath)
			{
				Write-Verbose -Message "Creating active device key."
				$Temp = Set-ItemProperty -Path "$XENBUSPath\Parameters" -Name "ActiveDevice" -Value "PCI\VEN_5853&DEV_0001&SUBSYS_00015853&REV_01" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Force
				$Temp = Set-ItemProperty -Path $XENBUSPath -Name "Count" -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Force	    
			}
			
			[System.String]$ProductTypePath = "$TempSystemKey`:\ControlSet001\Control\ProductOptions"
			[System.String]$ComputerNamePath = "$TempSystemKey`:\ControlSet001\Control\ComputerName\ComputerName"

			#This will be used later to determine if the server is a domain controller
			[System.String]$ProductType = Get-ItemProperty -Path $ProductTypePath -Name ProductType | Select-Object -ExpandProperty ProductType
			[System.String]$ComputerName = Get-ItemProperty -Path $ComputerNamePath -Name ComputerName | Select-Object -ExpandProperty ComputerName

			Write-Verbose -Message "Server to be fixed: $ComputerName and is a $ProductType."
		}
		finally
		{
			Write-Verbose -Message "Cleaning up loaded registry hive."
			$Temp = Remove-PSDrive -Name $TempSystemKey

			# Remove unused references in hive
			[System.GC]::Collect()

			$Temp = & reg unload "HKLM\$TempSystemKey"
		}

		# PART 2 - Setup the driver installation for the PV drivers and Enhanced networking drivers
		
		# https://aws.amazon.com/premiumsupport/knowledge-center/corrupt-missing-drivers-windows/

		Write-Verbose -Message "Setting up driver installation on next boot."

		try
		{
			$SoftDrive = "$DriveLetter`:\Windows\System32\config\SOFTWARE"
			Write-Verbose -Message "Mounting offline registry SOFTWARE have at $SoftDrive."

			$Temp = & reg load "HKLM\$TempSoftwareKey" "$SoftDrive"

			$Temp = New-PSDrive -Name $TempSoftwareKey -PSProvider Registry -Root "HKLM\$TempSoftwareKey" -ErrorAction Stop

			# Used to disable the shutdown event tracker
			$PoliciesWinNTPath = "$TempSoftwareKey`:\Policies\Microsoft\Windows NT"
			$PoliciesReliabilityPath = "$PoliciesWinNTPath\Reliability"

			$WinNTPath = "$TempSoftwareKey`:\Microsoft\Windows NT"

			# Used to find the operating system version
			$WinNTCurrentVersionPath = "$WinNTPath\CurrentVersion"

			# Used to set the auto logon parameters
			$WinLogonPath = "$WinNTCurrentVersionPath\Winlogon"

			# Used to set the run once scripts
			$RunOncePath = "$TempSoftwareKey`:\Microsoft\Windows\CurrentVersion\RunOnce"

			# Used to disable the domain controller check if the server is a DC
			$AWSPVRegPath = "$TempSoftwareKey`:\Wow6432Node\Amazon\AWSPVDriverSetup"

			# Handle the username being provided as domain\username, domain.com\username, and UPN as username@domain.com
			$UserName = $Credential.UserName

			if ($UserName.Contains("\"))
			{
				[System.String[]]$Parts = $UserName.Split("\")
				$UserName = $Parts[1]
				$Domain = $Parts[0].Split(".")[0]
			}
			elseif ($UserName.Contains("@"))
			{
				[System.String[]]$Parts = $UserName.Split("@")
				$UserName = $Parts[0]
				$Domain = $Parts[1].Split(".")[0]
			}
			else
			{
				$UserName = $Credential.UserName
				$Domain = $ComputerName
			}

			[System.IntPtr]$UnmanagedString = [System.IntPtr]::Zero
			[System.String]$PlainPassword = [System.String]::Empty

			try
			{	
				$UnmanagedString = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Credential.Password)
				$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($UnmanagedString)
			}
			finally
			{
				[System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($UnmanagedString)
			}

			# Test for the version of windows to determine the enhanced networking driver to use
			[System.Int32]$CurrentMajor = Get-ItemProperty -Path $WinNTCurrentVersionPath -Name "CurrentMajorVersionNumber" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CurrentMajorVersionNumber
			[System.Int32]$CurrentMinor = Get-ItemProperty -Path $WinNTCurrentVersionPath -Name "CurrentMinorVersionNumber" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CurrentMinorVersionNumber
			[System.String]$CurrentVersion = Get-ItemProperty -Path $WinNTCurrentVersionPath -Name "CurrentVersion" | Select-Object -ExpandProperty CurrentVersion
			[System.String]$PnPCommand = [System.String]::Empty
			[System.String]$OSVersion = [System.String]::Empty

			# This happens if the major and minor registry keys aren't present on servers below 2016
			if ("$CurrentMajor$CurrentMinor" -eq "00")
			{
				$OSVersion = $CurrentVersion.Replace(".", "")
			}
			else
			{
				$OSVersion = "$CurrentMajor$CurrentMinor"
			}


			# Populate the OS version if specified
			if ($PSBoundParameters.ContainsKey("OperatingSystem"))
			{
				if (-not [System.String]::IsNullOrEmpty($OSVersion))
				{
					[System.Decimal]$Version = 0
					if ([System.Decimal]::TryParse($OSVersion.Insert( $(if ($OSVersion.Length -gt 1) { $OSVersion.Length - 1 } else { 1 }), "."), [ref]$Version))
					{
						$OperatingSystem.Value = $Version
					}
					else
					{
						$OperatingSystem.Value = 0
					}
				}
				else
				{
					$OperatingSystem.Value = 0
				}
			}

			$Keys = @(@{Key = "AutoAdminLogon"; Value = 1}, @{Key = "DefaultDomainName"; Value = $Domain }, @{Key = "DefaultPassword"; Value = $PlainPassword}, @{Key = "DefaultUserName"; Value = $UserName})

			[System.String]$FixItScriptName = "FixItScript_$([Guid]::NewGuid()).ps1"
			# Used if we want to execute a bat file from the runonce script that contains a call to the PowerShell
			# [System.String]$FixItScriptName = "FixItScript_$([Guid]::NewGuid()).bat"

			# Set up the run once script for the remote machine
			[System.String]$RunOnceScript = "[System.Guid]`$PathGuid = [System.Guid]::NewGuid()`r`n"
			$RunOnceScript += "`$ErrorActionPreference = `"Stop`"`r`n"
			$RunOnceScript += "[System.IO.FileInfo]`$LogInfo = New-Object -TypeName System.IO.FileInfo(`"$RemoteLogPath`")`r`n"
			$RunOnceScript += "[System.String]`$LogPath = `"`$(`$LogInfo.DirectoryName)\`$(`$LogInfo.BaseName)_`$(`$PathGuid.ToString())`$(`$LogInfo.Extension)`"`r`n"
			$RunOnceScript += "Start-Transcript -Path `"`$env:SystemDrive\Transcript.txt`"`r`n"
			$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Starting runonce script, id `$(`$PathGuid.ToString()).`"`r`n"			
			$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Current user context: `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`"`r`n"
			$RunOnceScript += "try {`r`n"

			# Add the RunOnce task for the enhanced networking driver
			if ($PSCmdlet.ParameterSetName -eq "ENA")
			{
				# Copy over drivers
				# Use xcopy instead of Copy-Item because the cmdlet sometimes does not recognize the mounted drive if it was called
				# from another command, thus the procedure fails
				[System.String]$ENADriversPath = "$DriveLetter`:\EnhancedNetworking"
				Write-Verbose -Message "Copying enhanced networking drivers to $ENADriversPath"
				& xcopy $EnhancedNetworkingDriverPath "$ENADriversPath\*" /Y /E | Out-Null

				switch ($EnhancedNetworkingType)
				{
					"Intel82599VF" {
						Write-Verbose -Message "Setting up pnputil for INTEL drivers."
						$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Running pnputil for INTEL drivers.`"`r`n"
						
						switch ($OSVersion)
						{
							# Server 2016
							"100" {
								$Version = "65"
								$RunOnceScript += "& pnputil -i -a `$env:SystemDrive\EnhancedNetworking\PROXGB\Winx64\NDIS$Version\vxn$Version`x64.inf`r`n"
								break
							}
							# Server 2012 R2
							"63" {
								$Version = "64"
								$RunOnceScript += "& pnputil -i -a `$env:SystemDrive\EnhancedNetworking\PROXGB\Winx64\NDIS$Version\vxn$Version`x64.inf`r`n"
								break
							}
							# Server 2012
							"62" {
								$Version = "63"
								$RunOnceScript += "& pnputil -i -a `$env:SystemDrive\EnhancedNetworking\PROXGB\Winx64\NDIS$Version\vxn$Version`x64.inf`r`n"
								break
							}
							# Server 2008 R2
							"61" {
								$Version = "62"
								$RunOnceScript += "& pnputil -a `$env:SystemDrive\EnhancedNetworking\PROXGB\Winx64\NDIS$Version\vxn$Version`x64.inf`r`n"
								break
							}
							default {
								Write-Warning -Message "Not a compatible version of Windows $($_) to use enhanced networking."
								break
							}
						}

						break
					}
					"ENA" {
						Write-Verbose -Message "Setting up pnputil for ENA drivers."

						$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Running pnputil for ENA drivers.`"`r`n"

						switch ($OSVersion)
						{
							# Server 2016
							"100" {
								$RunOnceScript += "& pnputil -i -a `$env:SystemDrive\EnhancedNetworking\1.0.8.0\2012R2\ena.inf`r`n"
								break
							}
							# Server 2012 R2
							"63" {
								$RunOnceScript += "& pnputil -i -a `$env:SystemDrive\EnhancedNetworking\1.0.8.0\2012R2\ena.inf`r`n"
								break
							}
							# Server 2012
							"62" {
								$RunOnceScript += "& pnputil -i -a `$env:SystemDrive\EnhancedNetworking\1.0.8.0\2012R2\ena.inf`r`n"
								break
							}
							# Server 2008 R2
							"61" {
								$RunOnceScript += "& pnputil -i -a `$env:SystemDrive\EnhancedNetworking\1.0.9.0\2008R2\ena.inf`r`n"
								break
							}
							default {
								Write-Warning -Message "Not a compatible version of Windows $($_) to use enhanced networking."
								break
							}
						}
						break
					}
					default {
						Write-Warning -Message "The enhanced networking type wasn't recognized: $EnhancedNetworkingType."
						break
					}
				}
			}
					
			if ($PSCmdlet.ParameterSetName -eq "PV" -or $PSBoundParameters.ContainsKey("AWSPVDriverPath"))
			{
				# Copy over drivers
				# Use xcopy instead of Copy-Item because the cmdlet sometimes does not recognize the mounted drive if it was called
				# from another command, thus the procedure fails
				Write-Verbose -Message "Copying PV Drivers"
				& xcopy $AWSPVDriverPath "$DriveLetter`:\" /Y | Out-Null
			
				# Add the runonce task to run the PV driver installer

				[System.IO.FileInfo]$DriverInfo = New-Object -TypeName System.IO.FileInfo($AWSPVDriverPath)

				[System.String]$DriverInstallCommand = [System.String]::Empty

				switch ($DriverInfo.Extension.ToLower())
				{
					".msi" {
						$DriverInstallCommand += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Killing all msiexec processes before running driver installation.`"`r`n"
						$DriverInstallCommand += "Get-Process -Name msiexec -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue`r`n"
						# We know we copied the installer to the root of the c:\ drive
						$DriverInstallCommand += "Start-Process -FilePath `"msiexec.exe`" -ArgumentList @(`"/i ```"`$env:SystemDrive\$($DriverInfo.Name)```"`", `"/qn`", `"/norestart`", `"/L*V `$env:SystemDrive\AWSPVDriverInstall.log`") -Wait -ErrorAction Stop`r`n"
						break
					}
					".exe" {
						$DriverInstallCommand += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Killing all $($DriverInfo.BaseName) processes before running driver installation.`"`r`n"
						$DriverInstallCommand += "`$Processes = Get-Process -Name `"*$($DriverInfo.BaseName)*`" -ErrorAction SilentlyContinue`r`n"
						$DriverInstallCommand += "if (`$Processes -ne `$null -and `$Processes.Count -gt 0) {`r`n"
						$DriverInstallCommand += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : There are `$(`$Processes.Count) existing processes.`"`r`n"
						$DriverInstallCommand += "`$Processes | ForEach-Object { Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : `$(`$_.Name) : `$(`$_.Id)`" }`r`n"
						$DriverInstallCommand += "`$Processes | Stop-Process -Force -ErrorAction Stop`r`n"
						$DriverInstallCommand += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Processes have been killed, launching the installer.`"`r`n"
						$DriverInstallCommand += "}`r`n"
						# We know we copied the installer to the root of the c:\ drive
						
						<# This probably isn't needed, the citrix install doesn't provide any command line output
						$DriverInstallCommand += "[System.Diagnostics.Process]`$Process = New-Object -TypeName System.Diagnostics.Process`r`n"
						$DriverInstallCommand += "`$Process.StartInfo.RedirectStandardOutput = `$true`r`n"
						$DriverInstallCommand += "`$Process.StartInfo.RedirectStandardError = `$true`r`n"
						$DriverInstallCommand += "`$Process.StartInfo.FileName = `"`$env:SystemDrive\$($DriverInfo.Name)`"`r`n"
						$DriverInstallCommand += "`$Process.StartInfo.Arguments = @(`"/S`", `"/norestart`")`r`n"
						$DriverInstallCommand += "`$Process.StartInfo.UseShellExecute = `$false`r`n"
						$DriverInstallCommand += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Starting installer now.`"`r`n"
						$DriverInstallCommand += "`$Process.Start() | Out-Null`r`n"
						$DriverInstallCommand += "while (!`$Process.HasExited) {`r`n"
						$DriverInstallCommand += "while (![System.String]::IsNullOrEmpty((`$Line = `$Process.StandardOutput.ReadLine()))) {`r`n"
						$DriverInstallCommand += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : `$Line`"`r`n"
						$DriverInstallCommand += "}`r`n"
						$DriverInstallCommand += "Start-Sleep -Milliseconds 10`r`n"
						$DriverInstallCommand += "}`r`n"
						$DriverInstallCommand += "if (`$Process.ExitCode -ne 0) {`r`n"
						$DriverInstallCommand += "`$Line = `$Process.StandardError.ReadToEnd()`r`n"
						$DriverInstallCommand += "if (![System.String]::IsNullOrEmpty(`$Line)) {`r`n"
						$DriverInstallCommand += "Add-Content -Path `$LogPath -Value `"[ERROR] `$(Get-Date) : `$Line`"`r`n"
						$DriverInstallCommand += "}`r`n"
						$DriverInstallCommand += "}`r`n"
						$DriverInstallCommand += "else {`r`n"
						$DriverInstallCommand += "`$Line = `$Process.StandardOutput.ReadToEnd()`r`n"
						$DriverInstallCommand += "if (![System.String]::IsNullOrEmpty(`$Line)) {`r`n"
						$DriverInstallCommand += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : `$Line`"`r`n"
						$DriverInstallCommand += "}`r`n"
						$DriverInstallCommand += "}`r`n"
						#>

						$DriverInstallCommand += "Start-Process -FilePath `"`$env:SystemDrive\$($DriverInfo.Name)`" -ArgumentList @(`"/S`",`"/norestart`") -Wait -ErrorAction Stop`r`n"
						$DriverInstallCommand += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Completed installer.`"`r`n"
						break
					}
					default {
						Write-Warning -Message "[WARNING] Unknown file extension $($DriverInfo.Extension) for driver installer."
						break
					}
				}

				# WinNT = Workstation
				# LanmanNT = Domain Controller
				# ServerNT = Member Server

				if (-not [System.String]::IsNullOrEmpty($DriverInstallCommand))
				{
					Write-Verbose -Message "The attached drive is from server type: $ProductType"

					if ($ProductType -eq "LanmanNT")
					{
						# http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/Upgrading_PV_drivers.html#aws-pv-upgrade-dc
						Write-Verbose -Message "The server is a domain controller, updating boot options and installation parameters for the PV Drivers"

						$Temp = Set-ItemProperty -Path $AWSPVRegPath -Type ([Microsoft.Win32.RegistryValueKind]::String) -Name "DisableDCCheck" -Value "true" -Force

						$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Adding bcd entry for a domain controller.`"`r`n"
					
						# This will get run at next boot so that when the PV drivers install and force a reboot, it will boot fine
						$RunOnceScript += "& bcdedit /set {default} safeboot dsrepair`r`n"
					
						# Build a second runonce script to execute after all the fixes have been made, so the first runonce script
						# will modify the BCD so after the reboot it goes into dsrepair mode to complete the driver install as a domain
						# controller won't boot if the NTDS.dit file is missing, which it could be if it is on a non-root volume, and the driver
						# install will only make the root volume available until the install completes.
						#
						# The second runonce script deletes the dsrepair boot mode entry, removes the auto logon, and reboots the server again, so
						# in this scenario, two reboots are executed

						[System.String]$SecondFixItScriptName = "FixItScript_$([Guid]::NewGuid()).ps1"

						$SecondRunOnceScript = "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Executing second runonce script for domain controllers.`"`r`n"
						$SecondRunOnceScript += "try {`r`n"
						$SecondRunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Deleting safeboot bcd entry.`"`r`n"
						$SecondRunOnceScript += "& bcdedit /deletevalue safeboot`r`n"

						foreach ($Item in $Keys)
						{
							# This will ensure the auto login keys are removed on the next reboot, 
							$SecondRunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Removing $($Item.Key) from Winlogon.`"`r`n"
							$SecondRunOnceScript += "Remove-ItemProperty -Name `"$($Item.Key)`" -Path `"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" -Force -ErrorAction Continue`r`n" 
						}

						$SecondRunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Rebooting.`"`r`n"
						$SecondRunOnceScript += "Remove-Item -Path `"`$env:SystemDrive\$SecondFixItScriptName`" -Force`r`n"
						$SecondRunOnceScript += "Restart-Computer -Force`r`n"
						$SecondRunOnceScript += "}`r`ncatch [Exception] {`r`nAdd-Content -Path `$LogPath -Value `"[ERROR] `$(Get-Date) : `$(`$_.Exception.Message)`"`r`n}"

						Write-Verbose -Message "Saving second run once script:`r`n$SecondRunOnceScript"
						Set-Content -Path "$DriveLetter`:\$SecondFixItScriptName" -Value $SecondRunOnceScript -Force

						# This will add a new RunOnce item at the next boot to remove the bcd entry after the following reboot
						$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Creating runonce registry entry with a script to delete BCD entry on next boot.`"`r`n"				
						$RunOnceScript += "Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -Name `"!*DeleteBCDEntry`" -Value `"c:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NoLogo -NonInteractive -WindowStyle Hidden -ExecutionPolicy Unrestricted -File ```"c:\$SecondFixItScriptName```"`"`r`n"
					}
					else
					{
						# Otherwise, we can remove the auto login keys after the first reboot since no further logins will be needed to execute scripts

						$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Removing auto logon registry entries.`"`r`n"
					
						foreach ($Item in $Keys)
						{
							# This will ensure the auto login keys are removed on the next reboot, we only want to do this if the server is not a
							# domain controller, because if it is, we want one more auto login to run the runonce commands to delete the bcd entry
							$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Removing $($Item.Key) from Winlogon.`"`r`n"
							$RunOnceScript += "Remove-ItemProperty -Name `"$($Item.Key)`" -Path `"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" -Force -ErrorAction Continue`r`n" 
						}
					}

					# Adds a RunOnce command to install the PV driver, do it last since we need to reboot afterwards
					$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Running driver install.`"`r`n"
					$RunOnceScript += $DriverInstallCommand
				}
				else
				{
					Write-Verbose -Message "No NIC driver installation setup, which means the installer file wasn't an msi or exe."
				}
			}

			# Disable Shutdown Event Tracker so that it doesn't interfere with runonce script
			Write-Verbose -Message "Disabling the Shutdown Event Tracker so it doesn't stall logon."

			if (-not (Test-Path -Path $PoliciesReliabilityPath))
			{
				Write-Verbose -Message "Creating Reliability key at $PoliciesWinNTPath."
				New-Item -Path $PoliciesWinNTPath -Name "Reliability" -Force | Out-Null
				Write-Verbose -Message "Successfully created key: $(Test-Path -Path $PoliciesReliabilityPath)"
			}

			Set-ItemProperty -Path $PoliciesReliabilityPath -Name "ShutdownReasonUI" -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
			Set-ItemProperty -Path $PoliciesReliabilityPath -Name "ShutdownReasonOn" -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)

			# Finish the run once script content

			$RunOnceScript += "Add-Content -Path `$LogPath -Value `"[INFO] `$(Get-Date) : Completed driver install, rebooting.`"`r`n"
			# $RunOnceScript += "Remove-Item -Path `"`$env:SystemDrive\$FixItScriptName`" -Force -ErrorAction Stop`r`n"				
			$RunOnceScript += "Restart-Computer -Force`r`n"
			$RunOnceScript += "}`r`ncatch [Exception] {`r`nAdd-Content -Path `$LogPath -Value `"[ERROR] `$(Get-Date) : `$(`$_.Exception.Message)`"`r`n}"

			Write-Verbose -Message "Setting up auto logon."

			# Add the winlogon autologon keys
			foreach ($Item in $Keys)
			{
				$Temp = Set-ItemProperty -Path $WinLogonPath -Name $Item.Key -Value $Item.Value -Type ([Microsoft.Win32.RegistryValueKind]::String) -Force
			}

			Write-Verbose -Message "Completed setting up auto logon."

			Write-Verbose -Message "The run once script to be executed:`r`n$RunOnceScript"

			# This is for running as a BAT
			# Set-Content -Path "$DriveLetter`:\$FixItScriptName" -Value "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NoLogo -NonInteractive -WindowStyle Hidden -ExecutionPolicy Unrestricted -EncodedCommand $EncodedCommand" -Force
			# $Temp = Set-ItemProperty -Path $RunOncePath -Type ([Microsoft.Win32.RegistryValueKind]::String) -Name "!*BootScript" -Value "c:\$FixItScriptName"

			# * will make the script run even in safe mode
			# ! will make sure the script runs successfully before it is deleted
			# This will run as FILE
			Set-Content -Path "$DriveLetter`:\$FixItScriptName" -Value $RunOnceScript -Force
			$Temp = Set-ItemProperty -Path $RunOncePath -Type ([Microsoft.Win32.RegistryValueKind]::String) -Name "!*BootScript" -Value "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NoLogo -NonInteractive -WindowStyle Hidden -ExecutionPolicy Unrestricted -File `"c:\$FixItScriptName`"" -ErrorAction Stop
			$Content = Get-ItemProperty -Path $RunOncePath -Name "!*BootScript" | Select-Object -ExpandProperty "!*BootScript"

			Write-Verbose -Message "The value of $RunOncePath property `"!*BootScript`": $Content"
		}
		finally 
		{
			$Temp = Remove-PSDrive -Name $TempSoftwareKey

			# Remove unused references in hive
			[System.GC]::Collect()

			$Temp = & reg unload "HKLM\$TempSoftwareKey"
		}
	}

	End {
	}
}

Function Invoke-AWSNetworkAdapterFixOnRemoteInstance {
	<#
		.SYNOPSIS
			Executes the Invoke-AWSNetworkAdapterFixOnOfflineDisk cmdlet on a volume that is mounted to the current EC2 instance this cmdlet is being run on from another EC2 instance.		

		.DESCRIPTION
			The cmdlet targets another EC2 instance that is in health status 1/2 and is not reachable over the network. The instance is stopped and the root volume is detached and re-attached to the first
			available device on the current EC2 instance. The user is prompted for the drive letter the new volume is given and then executes the Invoke-AWSNetworkAdapterFixOnOfflineDisk cmdlet using the source
			instance type to determine the type of enhanced networking drivers required. Once the cmdlet is run, the volume is dismounted, re-attached to the source instance, and the instance is started.

			The cmdlet initiates an EBS snapshot of the root volume of the source instance before it is modified. In testing this cmdlet, there have been occasions when an I/O error occured and the 
			source EC2 instance could not boot after the root volume was modified because c:\windows\system32\winload.exe could not be found. The FixBCD parameter is designed to help correct that, but it
			is not guaranteed to work. The safest option is to allow the snapshot to be taken in order to be able to revert to the original disk.

			Additionally, the EC2 instance executing this cmdlet should not have any additional EBS volumes mounted when the cmdlet is run. It is also advisable to have rebooted this instance just before
			executing the cmdlet and that there were no previous issues with mounting or dismounting EBS volumes. While these are not requirements to run the cmdlet, they provide the best chance of success.

			While this cmdlet can be executed with explicit credentials, since it is designed to be run on an EC2 instance in the same region as the instance to be fixed, using an IAM Instance Profile (IAM Role) is preferred.

		.PARAMETER InstanceId
			The instance Id of the EC2 instance to fix.

		.PARAMETER InstanceName
			The instance name of the EC2 instance to fix. The name tag value must be unique to use this parameter.

		.PARAMETER DestinationCredential
			The credentials to use for the auto logon. The user name can be specified as domain\user, user@domain.com (UPN format), or just the username. If only a username
			is specified, provide the domain parameter, otherwise it will default to the offline machine computer name as specified in the computer's registry.

			If the user is a domain user, a cached logon must be present to use it, as this cmdlet assumes the offline instance has no network connectivity.

			The user must have local admin rights on the offline machine.

		.PARAMETER Domain
			The domain name to use for the auto logon if the supplied credentials/user name is an Active Directory account. Otherwise, do not specify this parameter, as the local machine name will be used for a local account logon. 

			Also, if the Credential or UserName parameter is specified with a domain name included, you do not need to specify this parameter.

		.PARAMETER IntelDriversPath
			The path to the intel drivers used for the Intel 82599 VF enhanced networking driver.

			For Intel 82599 VF drivers, the directory should target the extracted output of the PROWinx64.exe file. For example if c:\IntelDrivers is specified, that folder should contain

			c:\IntelDrivers\PROXGB
			c:\InterDrivers\PRO40GB
			etc...

			This defaults to "$env:SystemDrive\Intel82599VF".

		.PARAMETER ENADriversPath
			The path to the Elastic Network Adapter (ENA) drivers.

			For Elastic Network Adapter, if c:\ENA is specified, the directory should contain folders in this structure:
			
			c:\ENA\1.0.8.0\2012
			c:\ENA\1.0.8.0\2012R2
			c:\ENA\1.0.9.0\2008R2

			Each of these folders should contain 3 files, ena.cat, ena.inf, ena.sys. These files and folder structure are included with the module.

		.PARAMETER AWSPVDriverPath
			The path to the AWS PV drivers setup file, usually AWSPVDriver.msi or Citrix_xensetup.exe. 

			This is optional. Use the AWSPVDriver.msi for Server 2008 R2 and above and Citrix_xensetup.exe for Server 2008 and below. 

		.PARAMETER Timeout
			The timeout in seconds to use when waiting for AWS operations to complete like stopping an instance, dismounting an EBS volume, etc. This defaults to 600.

		.PARAMETER DontTakeBackupSnapshot
			Specify this parameter if you don't want a backup snapshot of the source EBS volume to be made.

		.PARAMETER FixBCD
			Ensures the BCD is up to date with the correct device settings and runs a chkdsk on all volumes.

		.PARAMETER Force
			Enables unattended mode to automatically select the disk and partitions if multiple new disks are found or if the disk has multiple partitions. The first of each is selected automatically.

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

		.INPUTS
			None.

		.OUTPUTS
			None.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 7/13/2017			
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Id")]
		[System.String]$InstanceId,

		[Parameter(Mandatory = $true, ParameterSetName = "Name")]
		[Alias("Name")]
		[System.String]$InstanceName,

		[Parameter(Mandatory = $true)]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$DestinationCredential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Domain = [System.String]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$IntelDriversPath = "$env:SystemDrive\Intel82599VF",

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$ENADriversPath = "$env:SystemDrive\ENA",

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$AWSPVDriverPath,

		[Parameter()]
		[System.UInt32]$Timeout = 600,

		[Parameter()]
		[Switch]$DontTakeBackupSnapshot,

		[Parameter()]
		[Switch]$FixBCD,

		[Parameter()]
		[Switch]$Force,

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
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
		if (-not (New-Object -TypeName System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltinRole]::Administrator))
		{
			throw "Script must be run with administrative privileges."
		}
	}

	Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		
		$TempSplat = $Splat

		# Remove the source region so that the destination instance could be in a different region
		if ($TempSplat.ContainsKey("Region"))
		{
			$TempSplat.Remove("Region")
		}

		$TempSplat.Region = Get-EC2InstanceRegion
		
		[System.Collections.Hashtable]$AwsUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $TempSplat

		[Amazon.EC2.Model.Instance]$EC2 = $null

		Write-Verbose -Message "Getting target EC2 instance."

		if ($PSCmdlet.ParameterSetName -eq "Id")
		{
			$EC2 = Get-EC2InstanceByNameOrId -InstanceId $InstanceId @AwsUtilitiesSplat
		}
		else
		{
			$EC2 = Get-EC2InstanceByNameOrId -Name $InstanceName @AwsUtilitiesSplat
		}

		if ($EC2 -ne $null)
		{
			Write-Verbose -Message "Identified EC2 instance $($EC2.InstanceId)"

			Set-EC2InstanceState -InstanceId $EC2.InstanceId -State STOP -Wait -Timeout $Timeout @AwsUtilitiesSplat

			[System.String]$RootVolume = $EC2.BlockDeviceMappings | Where-Object {$_.DeviceName -eq $EC2.RootDeviceName} | Select-Object -ExpandProperty Ebs | Select-Object -First 1 -ExpandProperty VolumeId

			if (-not [System.String]::IsNullOrEmpty($RootVolume))
			{
				Write-Verbose -Message "Getting info about volume $RootVolume."

				[Amazon.EC2.Model.Volume]$EBS = Get-EC2Volume -VolumeId $RootVolume @Splat -ErrorAction Stop

				if (-not $DontTakeBackupSnapshot)
				{
					Write-Verbose -Message "Taking a backup EBS snapshot of the root volume."
					[Amazon.EC2.Model.Snapshot]$Backup = New-EC2Snapshot -VolumeId $EBS.VolumeId -Description "BACKUP for $($EC2.InstanceId)" @Splat

					$Counter = 0

					while ($Backup.State -ne [Amazon.EC2.SnapshotState]::Completed -and $Counter -lt $Timeout)
					{
						[System.String]$Percent = "0"

						if ($Backup.Progress -ne $null)
						{
							$Percent = $Backup.Progress.Replace("%", "")
						}

						Write-Progress -Activity "Creating backup snapshot" -Status "$Percent% Complete:" -PercentComplete $Percent

						Write-Verbose -Message "Waiting on snapshot $($Backup.SnapshotId) to complete, currently at $Percent% in state $($Backup.State)"
						$Backup = Get-EC2Snapshot -SnapshotId $Backup.SnapshotId @Splat

						Start-Sleep -Seconds 1
						$Counter++
					}

					Write-Progress -Completed -Activity "Creating backup snapshot"

					if ($Counter -ge $Timeout)
					{
						throw "Timeout waiting for the backup EBS snapshot to complete."
					}

					Write-Host -Object "Backup snapshot id $($Backup.SnapshotId)."
				}

				Write-Verbose -Message "Dismounting volumes"
				$Dismount = Dismount-EC2Volume -VolumeId $RootVolume -InstanceId $EC2.InstanceId @Splat -ErrorAction Stop

				$Counter = 0

				while ($EBS.State -ne [Amazon.EC2.VolumeState]::Available -and $Counter -le $Timeout)
				{
					Write-Verbose -Message "Waiting for EBS volume to become available."
					Start-Sleep -Seconds 5
					$EBS = Get-EC2Volume -VolumeId $RootVolume @Splat
					$Counter += 5
				}

				if ($Counter -gt $Timeout)
				{
					throw "[ERROR] Timeout waiting for EBS volume $RootVolume to become available."
				}

				Write-Verbose -Message "EBS Volume $RootVolume is now available."

				[System.String]$DestinationInstanceId = Get-EC2InstanceId
				[Amazon.EC2.Model.Instance]$Destination = Get-EC2InstanceByNameOrId -InstanceId $DestinationInstanceId @AwsUtilitiesSplat

				$OriginalDiskSerialNumbers = Get-Disk | Select-Object -ExpandProperty "SerialNumber"

				Write-Verbose -Message "Mounting volume $RootVolume to $($Destination.InstanceId)."
				Mount-EBSVolumes -VolumeIds $RootVolume -Instance $Destination -NextAvailableDevice @AwsUtilitiesSplat

				Write-Verbose -Message "Sleeping to give the OS time to recognize the newly mounted disk."
				Start-Sleep -Seconds 5

				Write-Verbose -Message "Onlining disks and clearing readonly."

				[Microsoft.Management.Infrastructure.CimInstance[]]$NewDisks = Get-Disk | Where-Object {$OriginalDiskSerialNumbers -notcontains $_.SerialNumber}

				$NewDisks | Set-Disk -IsOffline $false
				$NewDisks | Set-Disk -IsReadOnly $false

				[System.Char]$OSPartition = $null
				[System.Char]$BootPartition = $null

				[System.UInt32]$DiskIndex = 0

				if ($NewDisks.Length -eq 1 -or ($NewDisks.Length -gt 1 -and $Force))
				{
					$DiskIndex = $NewDisks[0].Number
				}
				elseif ($NewDisks.Count -gt 1)
				{
					while ($DiskIndex -lt 1)
					{
						$DiskIndex = Read-Host -Prompt "Enter the disk index for the EBS volume that you want to modify, multiple new disks were identified"
					}
				}
				else
				{
					throw "No new disks were identified, ensure the attached EBS volumes are attached to the EC2 instance."
				}

				[Microsoft.Management.Infrastructure.CimInstance[]]$Partitions = Get-CimInstance -ClassName Win32_DiskPartition -Filter ("DiskIndex = $DiskIndex") 

				if ($Partitions.Count -gt 1)
				{
					[Microsoft.Management.Infrastructure.CimInstance[]]$BootablePartitions = $Partitions | Where-Object { $_.BootPartition -eq $true } 
					[Microsoft.Management.Infrastructure.CimInstance[]]$NonBootablePartitions = $Partitions | Where-Object { $_.BootPartition -eq $false } 

					if ($BootablePartitions -ne $null -and $BootablePartitions.Count -ge 1)
					{
						if ($BootablePartitions.Count -eq 1 -or $Force)
						{
							# The CIM instance index is 0 based, the partition numbering is 1 based
							$BootPartition = Get-Partition -DiskNumber $BootablePartitions[0].DiskIndex -PartitionNumber ($BootablePartitions[0].Index + 1) | Select-Object -ExpandProperty DriveLetter
						}
						else
						{
							do {
								$BootPartition = Read-Host -Prompt "Multiple boot volumes discovered, enter the drive letter where the BCD is located (typically System Reserved partition) for the disk you want to fix"
							} while ($BootPartition -eq $null -or [System.Char]::ToLower($BootPartition) -lt 'd' -or [System.Char]::ToLower($BootPartition) -gt 'z')
						}
					
						if ($NonBootablePartitions.Count -eq 1)
						{
							$OSPartition = Get-Partition -DiskNumber $NonBootablePartitions[0].DiskIndex -PartitionNumber ($NonBootablePartitions[0].Index + 1) | Select-Object -ExpandProperty DriveLetter
						}
						elseif ($NonBootablePartitions.Count -eq 0)
						{
							if ($BootPartition -ne $null)
							{
								# There were multiple bootable partitions, and no non-bootable, use the selected bootable
								$OSPartition = $BootPartition
							}
						}
						else
						{
							# There are multiple non-bootable partitions, prompt the user for which to select
							do {
								$OSPartition = Read-Host -Prompt "Multiple data volumes discovered, enter the drive letter of the operating system volume"
							} while ($OSPartition -eq $null -or [System.Char]::ToLower($OSPartition) -lt 'd' -or [System.Char]::ToLower($OSPartition) -gt 'z')
						}
					}
					else
					{
						throw "No bootable volumes found from attached EBS volume, this wasn't a root device."
					}
				}
				else
				{
					$BootPartition = Get-Partition -DiskNumber $Partitions[0].DiskIndex -PartitionNumber ($Partitions[0].Index + 1) | Select-Object -ExpandProperty DriveLetter
					$OSPartition = $BootPartition
				}

				Write-Verbose -Message "The boot drive is $BootPartition`:\ and the OS drive is $OSPartition`:\."
			
				[System.Collections.Hashtable]$ScriptSplat = @{}

				$ScriptSplat.Credential = $DestinationCredential

				if (-not [System.String]::IsNullOrEmpty($Domain))
				{
					$ScriptSplat.Domain = $Domain
				}

				$IntelNetworkingTypes = @("c3", "c4", "d2", "i2", "r3", "m4")
				$ENANetworkingTypes = @("f1", "i3", "p2", "r4", "x1")

				Write-Verbose -Message "Instance type is $($EC2.InstanceType.Value)."

				$TypePrefix = $EC2.InstanceType.Value.Substring(0, 2)

				$DriversPath = [System.String]::Empty

				if ($TypePrefix -iin $IntelNetworkingTypes -and $EC2.InstanceType.Value -ine "m4.16xlarge")
				{
					Write-Verbose -Message "Using Intel enhanced networking drivers."
					$ScriptSplat.EnhancedNetworkingType = $script:INTEL_DRIVER
					$ScriptSplat.EnhancedNetworkingDriverPath = $IntelDriversPath
				}
				elseif ($TypePrefix -iin $ENANetworkingTypes -or $EC2.InstanceType.Value -ieq "m4.16xlarge")
				{
					Write-Verbose -Message "Use ENA enhanced networking drivers."
					$ScriptSplat.EnhancedNetworkingType = $script:ENA
					$ScriptSplat.EnhancedNetworkingDriverPath = $ENADriversPath
				}
				else
				{
					Write-Warning -Message "The instance type $($EC2.InstanceType.Value) does not support enhanced networking."
				}

				if (-not [System.String]::IsNullOrEmpty($AWSPVDriverPath))
				{
					$ScriptSplat.AWSPVDriverPath = $AWSPVDriverPath
				}

				Write-Verbose -Message "Running Invoke-AWSNetworkAdapterFixOnOfflineDisk."
			
				[System.Decimal]$OSVersion = 0

				try
				{
					Invoke-AWSNetworkAdapterFixOnOfflineDisk -DriveLetter ($OSPartition) -OperatingSystem ([ref]$OSVersion) @ScriptSplat
				}
				catch [Exception]
				{
					Write-Warning -Message "Could not modify the offline disk: $($_.Exception.Message)."
				}

				if ($FixBCD)
				{
					Write-Verbose -Message "Running a chkdsk on the mounted drive."
					& chkdsk.exe "$OSPartition`:" /F

					Write-Verbose -Message "Running a chkdsk on recovery partition."
					& chkdsk.exe "$BootPartition`:" /F

					Write-Verbose -Message "Checking BCD."
					$BCDPath = "$BootPartition`:\Boot\BCD"
					& bcdedit.exe /store "$BCDPath"

					Write-Verbose -Message "Fixing up BCD."

					& bcdedit.exe /store "$BCDPath" /set "{bootmgr}" device boot
					& bcdedit.exe /store "$BCDPath" /set "{default}" device partition=c:
					& bcdedit.exe /store "$BCDPath" /set "{default}" osdevice partition=c:
					& bcdedit.exe /store "$BCDPath"
				}

				Write-Verbose -Message "Offlining disks."
				$NewDisks | Set-Disk -IsOffline $true

				Write-Verbose -Message "Removing mounted volume."
				$Dismount = Dismount-EC2Volume -InstanceId $Destination.InstanceId -VolumeId $RootVolume @Splat

				$EBS = Get-EC2Volume -VolumeId $RootVolume @Splat

				$Counter = 0

				while ($EBS.State -ne [Amazon.EC2.VolumeState]::Available -and $Counter -le $Timeout)
				{
					Write-Verbose -Message "Waiting for EBS volume to become available."
					Start-Sleep -Seconds 5
					$EBS = Get-EC2Volume -VolumeId $RootVolume @Splat
					$Counter += 5
				}

				if ($Counter -gt $Timeout)
				{
					throw "[ERROR] Timeout waiting for EBS volume $RootVolume to become available."
				}

				Write-Verbose -Message "Attaching volume back to original instance."
				[Amazon.EC2.Model.VolumeAttachment]$Attachment = Add-EC2Volume -Device "/dev/sda1" -InstanceId $EC2.InstanceId -VolumeId $RootVolume @Splat

				# Enable enhanced networking if the script splat had the parameters set because the EC2 instance type matched
				# a compatible type and the operating system version supports enhanced networking, which is Server 2008 R2 and above (6.1)
				if ($OSVersion -ge 6.1 -and
					$ScriptSplat.ContainsKey("EnhancedNetworkingType") -and 
					(-not [System.String]::IsNullOrEmpty($ScriptSplat.EnhancedNetworkingType))
				)
				{
					if ($ScriptSplat.EnhancedNetworkingType -eq $script:INTEL_DRIVER)
					{
						Write-Verbose -Message "Enabling srIov support on $($EC2.InstanceId)."
						Edit-EC2InstanceAttribute -InstanceId $EC2.InstanceId -SriovNetSupport "simple" 
					}
					elseif ($ScriptSplat.EnhancedNetworkingType -eq $script:ENA)
					{
						Write-Verbose -Message "Enabling ENA support on $($EC2.InstanceId)."
						Edit-EC2InstanceAttribute -InstanceId $EC2.InstanceId -EnaSupport $true
					}
					else
					{
						Write-Warning -Message "The enhanced networking type specified was not recognized: $($ScriptSplat.EnhancedNetworkingType)."
					}
				}
				else
				{
					Write-Verbose -Message "Skipping modifying instance attributes to support enhanced networking."
				}

				$Result = Set-EC2InstanceState -InstanceId $EC2.InstanceId -State START @AwsUtilitiesSplat
			}
			else
			{
				Write-Warning -Message "EC2 Instance $($EC2.InstanceId) has no root volume attached."
			}
		}
		else
		{
			Write-Warning -Message "Could not find EC2 instance"
		}
	}

	End {
	}
}

Function Set-EC2InstanceState {
	<#
		.SYNOPSIS
			Changes the EC2 instance state to either START, STOP, TERMINATE, or RESTART the instance.

		.DESCRIPTION
			The cmdlet changes the state of the instance to achieve the desired end state if required. The cmdlet is idempotent, multiple calls to start an EC2 instance, for exampple, will succeed, but no action will be performed if the instance is already in the running state. If PassThru is specified, null will be returned if no action is taken.

		.PARAMETER InstanceId
			The id of the instance to get.

		.PARAMETER InstanceName
			The value of the name tag of the instance to get. The name tags in the account being accessed must be unique for this to work.

		.PARAMETER State
			The action to perform on the EC2 instance, this is either STOP, START, RESTART, or TERMINATE. If RESTART is specified, then the Wait parameter has no effect.

		.PARAMETER Timeout
			The amount of time in seconds to wait for the EC2 to reach the desired state if the Wait parameter is specified. This defaults to 600.

		.PARAMETER Wait
			Specify to wait for the EC2 instance to reach the desired state.

		.PARAMETER PassThru
			Returns back the InstanceStateChange result or InstanceId if RESTART is specified.

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
			Set-EC2InstanceState -InstanceId $EC2.InstanceId -State START -Wait 

			Starts the specified EC2 instance and waits for it to reach the Running state.

		.INPUTS
			None

		.OUTPUTS
			None or Amazon.EC2.Model.InstanceStateChange or System.String

			A string is returned if RESTART is specified, otherwise an InstanceStateChange object is returned if PassThru is specified.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/30/2017
	#>
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Name")]
		[Alias("Name")]
		[ValidateNotNullOrEmpty()]
		[System.String]$InstanceName,

		[Parameter(Mandatory = $true, ParameterSetName = "Id")]
		[ValidateNotNullOrEmpty()]
		[System.String]$InstanceId,

		[Parameter(Mandatory = $true)]
		[ValidateSet("STOP", "START", "TERMINATE", "RESTART")]
		[System.String]$State,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Wait,

		[Parameter()]
		[System.Int32]$Timeout = 600,

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
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		[System.Collections.Hashtable]$AwsUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $Splat
		[System.Collections.Hashtable]$InstanceSplat = @{}

		if ($PSCmdlet.ParameterSetName.Equals("Id"))
		{
			$InstanceSplat.InstanceId = $InstanceId
		}
		else
		{
			$InstanceSplat.InstanceName = $InstanceName
		}

		[Amazon.EC2.Model.Instance]$Instance = Get-EC2InstanceByNameOrId @InstanceSplat @AwsUtilitiesSplat
		[Amazon.EC2.InstanceStateName]$DesiredState = $null
		[Amazon.EC2.Model.InstanceStateChange]$Result = $null

		Write-Verbose -Message "Current instance state: $($Instance.State.Name)."

		switch ($State)
		{
			"STOP" {
				if ($Instance.State.Name -ne [Amazon.EC2.InstanceStateName]::Stopped -and $Instance.State.Name -ne [Amazon.EC2.InstanceStateName]::Stopping -and $Instance.State.Name -ne [Amazon.EC2.InstanceStateName]::ShuttingDown)
				{
					$Result = Stop-EC2Instance -InstanceId $Instance.InstanceId @Splat
				}
				else
				{
					Write-Verbose -Message "Instance $($Instance.InstanceId) already $($Instance.State.Name)."
				}

				$DesiredState = [Amazon.EC2.InstanceStateName]::Stopped
				
				break
			}
			"START" {
				if ($Instance.State.Name -ne [Amazon.EC2.InstanceStateName]::Running -and $Instance.State.Name -ne [Amazon.EC2.InstanceStateName]::Pending)
				{
					$Result = Start-EC2Instance -InstanceId $Instance.InstanceId @Splat
				}
				else
				{
					Write-Verbose -Message "Instance $($Instance.InstanceId) already $($Instance.State.Name)."
				}

				$DesiredState = [Amazon.EC2.InstanceStateName]::Running

				break
			}
			"RESTART" {
				$Result = Restart-EC2Instance -InstanceId $Instance.InstanceId -PassThru @Splat

				$DesiredState = [Amazon.EC2.InstanceStateName]::Running

				break
			}
			"TERMINATE" {
				if ($Instance.State.Name -ne [Amazon.EC2.InstanceStateName]::Terminated)
				{
					$Result = Remove-EC2Instance -InstanceId $Instance.InstanceId -Force @Splat
				}
				else
				{
					Write-Verbose -Message "Instance $($Instance.InstanceId) already $($Instance.State.Name)."
				}

				$DesiredState = [Amazon.EC2.InstanceStateName]::Terminated

				break
			}
			default {
				throw "Unexpected instance state provided: $State."
			}
		}

		if ($Wait -and $State -ne "RESTART")
		{
			Write-Host -Object "Waiting for EC2 instance $($Instance.InstanceId) to $State..."

			[System.Int32]$Increment = 5
			[System.Int32]$Counter = 0

			while ($Instance.State.Name -ne $DesiredState -and $Counter -lt $Timeout)
			{
				Write-Verbose -Message "Waiting for $($Instance.InstanceId) to $State."

				Start-Sleep -Seconds $Increment
				$Counter += $Increment

				$Instance = Get-EC2InstanceByNameOrId -InstanceId $Instance.InstanceId @AwsUtilitiesSplat
			}

			if ($Counter -ge $Timeout)
			{
				throw "Timeout waiting for instance to $State."
			}

			Write-Verbose -Message "Successfully completed waiting for state change."
		}

		if ($PassThru)
		{
			Write-Output -InputObject $Result
		}
	}

	End {
	}
}

Function Update-EC2InstanceAmiId {
	<#
		.SYNOPSIS
			Changes the AMI id of a currently launched instance.

		.DESCRIPTION
			The cmdlet stops the source EC2 instance, detaches its EBS volumes and ENIs (except eth0), terminates the instance, launches a new EC2 instance with the specified AMI id and any configuration items like sriovsupport enabled, stops it, deletes its EBS volumes, attaches the source volumes and ENIs, and restarts the new EC2 instance.

		.PARAMETER InstanceId
			The id of the instance to get.

		.PARAMETER InstanceName
			The value of the name tag of the instance to get. The name tags in the account being accessed must be unique for this to work.

		.PARAMETER NewAmiId
			The new AMI id to launch the EC2 instance with.

		.PARAMETER Timeout
			The amount of time in seconds to wait for each action to succeed. This defaults to 600.

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
			Update-EC2InstanceAmiId

			Changes the AMI id being used for the specified instance

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/30/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$NewAmiId,

		[Parameter(Mandatory = $true, ParameterSetName = "Name")]
		[Alias("Name")]
		[ValidateNotNullOrEmpty()]
		[System.String]$InstanceName,

		[Parameter(Mandatory = $true, ParameterSetName = "Id")]
		[ValidateNotNullOrEmpty()]
		[System.String]$InstanceId,

		[Parameter()]
		[System.Int32]$Timeout = 600,

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
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		[System.Collections.Hashtable]$AwsUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $Splat

		$InstanceSplat = @{}

		if ($PSCmdlet.ParameterSetName -eq "Id")
		{
			Write-Verbose -Message "Using instance id $InstanceId."
			$InstanceSplat.InstanceId = $InstanceId
		}
		else
		{
			Write-Verbose -Message "Using instance name $InstanceName."
			$InstanceSplat.InstanceName = $InstanceName
		}

		# Get the source EC2 instance
		[Amazon.EC2.Model.Instance]$Instance = Get-EC2InstanceByNameOrId @InstanceSplat @AwsUtilitiesSplat
	
		# Stop the source EC2 instance
		Set-EC2InstanceState -InstanceId $Instance.InstanceId -State STOP -Wait -Timeout $Timeout @AwsUtilitiesSplat

		[PSCustomObject[]]$BlockDevices = @()

		# Detach all EBS volumes from the source machine
		
		foreach ($BlockDevice in $Instance.BlockDeviceMappings)
		{
			$BlockDevices += [PSCustomObject]@{Volume = Get-EC2Volume -VolumeId $BlockDevice.Ebs.VolumeId @Splat; DeviceName = $BlockDevice.DeviceName}

			Dismount-EC2Volume -InstanceId $Instance.InstanceId -VolumeId $BlockDevice.Ebs.VolumeId @Splat | Out-Null
		}

		while (($BlockDevices | Select-Object -ExpandProperty Volume | Where-Object {$_.State -eq [Amazon.EC2.VolumeState]::Available}).Count -ne $BlockDevices.Count)
		{
			Write-Verbose -Message "Waiting for volumes to detach."

			for ($i = 0; $i -lt $BlockDevices.Length; $i++)
			{
				$BlockDevices[$i].Volume = Get-EC2Volume -VolumeId $BlockDevices[$i].Volume.VolumeId @Splat
			}

			Start-Sleep -Seconds 5
		}

		# Detach all the additional network interfaces

		[PSCustomObject[]]$Interfaces = @()

		foreach ($Interface in ($Instance.NetworkInterfaces | Where-Object {$_.Attachment.DeviceIndex -ne 0}))
		{
			$Interfaces += [PSCustomObject]@{ DeviceIndex = $Interface.Attachment.DeviceIndex; Interface = $Interface}

			Write-Verbose -Message "Dismounting interface $($Interface.NetworkInterfaceId) at index $($Interface.Attachment.DeviceIndex) from the source instance."				
			Dismount-EC2NetworkInterface -AttachmentId $Interface.Attachment.AttachmentId @Splat | Out-Null
		}

		if ($Interfaces.Count -gt 0)
		{
			# While the count of interfaces whose status is available is not equal to the count of interfaces
			# keep waiting until they are all available
			# Use a minus 1 on Interfaces count since we are not detaching the interface at index 0
			while ((($Interfaces | Select-Object -ExpandProperty Interface | Select-Object -ExpandProperty Status) | Where-Object {$_ -eq [Amazon.EC2.NetworkInterfaceStatus]::Available }).Count -ne $Interfaces.Count - 1)
			{
				Write-Verbose -Message "Waiting for all network interfaces to detach."

				# Start at 1 since index 0 isn't being detached
				for ($i = 1; $i -lt $Interfaces.Length; $i++)
				{
					$Interfaces[$i].Interface = Get-EC2NetworkInterface -NetworkInterfaceId $Interfaces[$i].NetworkInterfaceId @Splat
				}

				Start-Sleep -Seconds 5
			}
		}

		Write-Verbose -Message "Deleting the original instance."
		Write-Host -Object "Original instance AMI id: $($Instance.ImageId)"

		Set-EC2InstanceState -InstanceId $Instance.InstanceId -State TERMINATE -Wait -Timeout $Timeout @AwsUtilitiesSplat

		# Build some optional parameters for New-EC2Instance
		[System.Collections.Hashtable]$NewInstanceSplat = @{}

		if ($Instance.InstanceLifecycle -ne $null)
		{
			$NewInstanceSplat.InstanceLifecycle = $Instance.InstanceLifecycle
		}

		# Windows instances won't have a kernel id
		if (-not [System.String]::IsNullOrEmpty($Instance.KernelId))
		{
			$NewInstanceSplat.KernelId = $Instance.KernelId
		}

		# Copy all of the tags from the source insance
		if ($Instance.Tags.Count -gt 0)
		{
			[Amazon.EC2.Model.TagSpecification]$Tags = New-Object -TypeName Amazon.EC2.Model.TagSpecification

			$Tags.ResourceType = [Amazon.EC2.ResourceType]::Instance

			$Tags.Tags = $Instance.Tags

			$NewInstanceSplat.TagSpecification = $Tags
		}

		# Copy placement info for affinity, placement group, and host id
		if (-not [System.String]::IsNullOrEmpty($Instance.Placement.Affinity))
		{
			$NewInstanceSplat.Affinity = $Instance.Placement.Affinity
		}

		if (-not [System.String]::IsNullOrEmpty($Instance.Placement.GroupName))
		{
			$NewInstanceSplat.PlacementGroup = $Instance.Placement.GroupName
		}

		if (-not [System.String]::IsNullOrEmpty($Instance.Placement.HostId))
		{
			$NewInstanceSplat.HostId = $Instance.Placement.HostId
		}

		# This specifies if detailed monitoring is enabled

		if ($Instance.Monitoring.State -eq [Amazon.EC2.MonitoringState]::Enabled -or $Instance.Monitoring.State -eq [Amazon.EC2.MonitoringState]::Pending)
		{
			$NewInstanceSplat.Monitoring_Enabled = $true
		}

		if ($Instance.EbsOptimized -eq $true)
		{
			$NewInstanceSplat.EbsOptimized = $true
		}
		
		Write-Verbose -Message @"
Launching new instance:
	Type:              $($Instance.InstanceType)
	Subnet:            $($Instance.SubnetId)
	Security Groups:   $([System.String]::Join(",", ($Instance.SecurityGroups | Select-Object -ExpandProperty GroupId)))
	AZ:                $($Instance.Placement.AvailabilityZone)
	IAM Profile:       $($Instance.IamInstanceProfile.Arn)
	Private IP:        $($Instance.PrivateIPAddress)
	Tenancy:           $($Instance.Placement.Tenancy)
"@

		[Amazon.EC2.Model.Instance]$NewInstance = $null

		$Temp = New-EC2Instance -ImageId $NewAmiId `
						-AssociatePublicIp (-not [System.String]::IsNullOrEmpty($Instance.PublicIpAddress)) `
						-KeyName $Instance.KeyName `
						-SecurityGroupId ($Instance.SecurityGroups | Select-Object -ExpandProperty GroupId) `
						-SubnetId $Instance.SubnetId `
						-InstanceType $Instance.InstanceType `
						-AvailabilityZone $Instance.Placement.AvailabilityZone `
						-Tenancy $Instance.Placement.Tenancy `
						-InstanceProfile_Arn $Instance.IamInstanceProfile.Arn `
						-PrivateIpAddress $Instance.PrivateIpAddress `
						@NewInstanceSplat @Splat

		if ($Temp -eq $null)
		{
			throw "Could not create the new instance."
		}

		$NewInstance = Get-EC2InstanceByNameOrId -InstanceId $Temp.Instances[0].InstanceId @AwsUtilitiesSplat

		Set-EC2InstanceState -InstanceId $NewInstance.InstanceId -State START -Wait -Timeout $Timeout @AwsUtilitiesSplat

		Write-Verbose -Message "Stopping new instance."

		Set-EC2InstanceState -InstanceId $NewInstance.InstanceId -State STOP -Wait -Timeout $Timeout @AwsUtilitiesSplat

		if (-not [System.String]::IsNullOrEmpty($Instance.SriovNetSupport))
		{
			Write-Verbose -Message "Enabling SrIovNetSupport"
			Edit-EC2InstanceAttribute -InstanceId $NewInstance.InstanceId -SriovNetSupport $Instance.SriovNetSupport @Splat | Out-Null
		}

		if ($Instance.EnaSupport -eq $true)
		{
			Write-Verbose -Message "Enabling ENA"
			Edit-EC2InstanceAttribute -InstanceId $NewInstance.InstanceId -EnaSupport $true @Splat | Out-Null
		}

		# Update the interface at index 0 because we can't specify New-EC2Instance with both a set of security groups for the instance
		# in addition to security groups for the ENI as well as a specific subnet for the instance and ENI

		[Amazon.EC2.Model.InstanceNetworkInterface]$RootNetDevice = $NewInstance.NetworkInterfaces | Where-Object {$_.Attachment.DeviceIndex -eq 0} | Select-Object -First 1
		[Amazon.EC2.Model.InstanceNetworkInterface]$SourceRootInterface = $Interfaces | Where-Object {$_.DeviceIndex -eq 0} | Select-Object -First 1 -ExpandProperty Interface

		[System.Collections.Hashtable]$InterfaceSplat = @{}

		if ($SourceRootInterface.SourceDestCheck -ne $null)
		{
			$InterfaceSplat.SourceDestCheck = $SourceRootInterface.SourceDestCheck
		}

		if (-not [System.String]::IsNullOrEmpty($SourceRootInterface.Description))
		{
			$InterfaceSplat.Description = $SourceRootInterface.Description
		}

		if ($SourceRootInterface.Groups.Count -gt 0)
		{
			$InterfaceSplat.Groups = ($SourceRootInterface.Groups | Select-Object -ExpandProperty GroupId) 
		}

		if ($InterfaceSplat.Count -gt 0)
		{
			Write-Verbose -Message "Updated primary network interface attributes."
			Edit-EC2NetworkInterfaceAttribute -NetworkInterfaceId $RootNetDevice.NetworkInterfaceId `
											@InterfaceSplat `
											@Splat | Out-Null
		}

		# If the source machine had multiple IPs on the root ENI, add those IPs back
		if ($SourceRootInterface.PrivateIpAddresses.Count -gt 1)
		{
			Write-Verbose -Message "Adding secondary IP addresses to root network interface."
			Register-EC2PrivateIpAddress -NetworkInterfaceId $RootNetDevice.NetworkInterfaceId -PrivateIpAddress ($SourceRootInterface.PrivateIpAddresses | Where-Object {$_.Primary -eq $false} | Select-Object -ExpandProperty PrivateIpAddress) @Splat | Out-Null
		}
								
		[Amazon.EC2.Model.NetworkInterface[]]$InterfacesToDelete = @()

		foreach ($Interface in ($NewInstance.NetworkInterfaces | Where-Object {$_.Attachment.DeviceIndex -ne 0 }))
		{
			$InterfacesToDelete += Get-EC2NetworkInterface -NetworkInterfaceId $Interface.NetworkInterfaceId @Splat
			Write-Verbose -Message "Dismounting network interface $($Interface.NetworkInterfaceId) from new instance."
			Dismount-EC2NetworkInterface -AttachmentId $Interface.Attachment.AttachmentId @Splat | Out-Null
		}

		if ($InterfacesToDelete.Count -gt 0)
		{
			while ((($InterfacesToDelete | Select-Object -ExpandProperty Status) | Where-Object {$_ -eq [Amazon.EC2.NetworkInterfaceStatus]::Available }).Count -ne $InterfacesToDelete.Count)
			{
				Write-Verbose -Message "Waiting for all network interfaces to detach."

				for ($i = 0; $i -lt $InterfacesToDelete.Length; $i++)
				{
					$InterfacesToDelete[$i] = Get-EC2NetworkInterface -NetworkInterfaceId $InterfacesToDelete[$i].NetworkInterfaceId @Splat
				}

				Start-Sleep -Seconds 5
			}

			foreach ($Interface in $InterfacesToDelete)
			{
				Write-Verbose -Message "Deleting interface $($Interface.NetworkInterfaceId)."
				Remove-EC2NetworkInterface -NetworkInterfaceId $Interface.NetworkInterfaceId -Force @Splat | Out-Null
			}
		}

		# Update the value we have after all the interfaces have been updated, removed, and/or deleted
		$NewInstance = Get-EC2InstanceByNameOrId -InstanceId $NewInstance.InstanceId @AwsUtilitiesSplat

		if ($Interfaces.Count -gt 0)
		{
			Write-Verbose -Message "Adding network interfaces to the new instance."

			foreach ($Interface in $Interfaces)
			{
				Write-Verbose -Message "Adding $($Interface.Interface.NetworkInterfaceId) at index $($Interface.DeviceIndex)."
				Add-EC2NetworkInterface -InstanceId $NewInstance.InstanceId -NetworkInterfaceId $Interface.Interface.NetworkInterfaceId -DeviceIndex $Interface.DeviceIndex @Splat | Out-Null
			}

			while ((($Interfaces | Select-Object -ExpandProperty Interface | Select-Object -ExpandProperty Status) | Where-Object {$_ -eq [Amazon.EC2.NetworkInterfaceStatus]::InUse }).Count -ne $Interfaces.Count)
			{
				Write-Verbose -Message "Waiting for all network interfaces to be in use."

				for ($i = 0; $i -lt $Interfaces.Count; $i++)
				{
					$Interfaces[$i].Interface = Get-EC2NetworkInterface -NetworkInterfaceId $Interfaces[$i].Interface.NetworkInterfaceId @Splat
				}

				Start-Sleep -Seconds 5
			}
		}

		# Update again after new interfaces have been added
		$NewInstance = Get-EC2InstanceByNameOrId -InstanceId $NewInstance.InstanceId @AwsUtilitiesSplat

		Write-Verbose -Message "Removing EBS volumes from the new instance."

		[Amazon.EC2.Model.Volume[]]$VolumesToDelete = @()

		foreach ($BlockDevice in $NewInstance.BlockDeviceMappings)
		{
			Write-Verbose -Message "Dismounting device $($BlockDevice.Ebs.VolumeId) at $($BlockDevice.DeviceName)."
			Dismount-EC2Volume -InstanceId $NewInstance.InstanceId -VolumeId $BlockDevice.Ebs.VolumeId @Splat | Out-Null

			$VolumesToDelete += Get-EC2Volume -VolumeId $BlockDevice.Ebs.VolumeId @Splat
		}

		if ($VolumesToDelete.Count -gt 0)
		{
			while (($VolumesToDelete | Where-Object {$_.State -eq [Amazon.EC2.VolumeState]::Available}).Count -ne $VolumesToDelete.Length)
			{
				Write-Verbose -Message "Waiting for volumes to become available."

				for ($i = 0; $i -lt $VolumesToDelete.Length; $i++)
				{
					$VolumesToDelete[$i] = Get-EC2Volume -VolumeId $VolumesToDelete[$i].VolumeId @Splat
				}

				Start-Sleep -Seconds 5
			}

			foreach ($Volume in $VolumesToDelete)
			{
				Write-Verbose -Message "Deleting new instance volume $($Volume.VolumeId)." 
				Remove-EC2Volume -VolumeId $Volume.VolumeId -Force @Splat
			}
		}

		# Update again after all volumes have been removed
		$NewInstance = Get-EC2InstanceByNameOrId -InstanceId $NewInstance.InstanceId @AwsUtilitiesSplat

		Write-Verbose -Message "Adding original EBS volumes to new instance."

		foreach ($BlockDevice in $BlockDevices)
		{
			Write-Verbose -Message "Adding $($BlockDevice.Volume.VolumeId) to device $($BlockDevice.DeviceName)."
			Add-EC2Volume -InstanceId $NewInstance.InstanceId -Device $BlockDevice.DeviceName -VolumeId $BlockDevice.Volume.VolumeId @Splat | Out-Null
		}

		$Counter = 0

		while (($BlockDevices | Select-Object -ExpandProperty Volume | Where-Object {$_.State -eq [Amazon.EC2.VolumeState]::InUse}).Count -ne $BlockDevices.Count -and $Counter -lt $Timeout)
		{
			Write-Verbose -Message "Waiting for volumes to be attached."

			for ($i = 0; $i -lt $BlockDevices.Length; $i++)
			{
				$BlockDevices[$i].Volume = Get-EC2Volume -VolumeId $BlockDevices[$i].Volume.VolumeId @Splat
			}

			Start-Sleep -Seconds 5
			$Counter += 5
		}

		if ($Counter -ge $Timeout)
		{
			throw "Timout waiting for volumes to be attached to the new instance."
		}

		Write-Verbose -Message "Starting instance."

		Set-EC2InstanceState -InstanceId $NewInstance.InstanceId -State START @AwsUtilitiesSplat 
	}

	End {

	}
}

Function Invoke-EnableCloudWatch {
	<#
		.SYNOPSIS
			Enables CloudWatch Logs and custom metrics on the local EC2 instance.

		.DESCRIPTION
			The cmdlet uses SSM or EC2Config to enable CloudWatch Logs and custom metrics. If a bucket and key are specified, the json config file is downloaded and used to configure the service. If the SSMDocument is specified, it is used with a state manager association.

			If null or empty values are provided to bucket or key, the cmdlet creates an empty configuration file and enables EC2Config to send logs and metrics, but does not configure any.

		.PARAMETER Key
			The key of the object in S3 that is the config document for CloudWatch, this should be AWS.EC2.Windows.CloudWatch.json with any additional prefixes.

		.PARAMETER Bucket
			The bucket containing the configuration document.

		.PARAMETER SSMDocument
			The SSM Document to associate with the EC2 instance to enable CloudWatch.

		.PARAMETER RestartServices
			If specified, initiates a restart of either the SSMAgent or EC2Config service so that the new settings take effect. The service restart is executed as a scheduled task run by the SYSTEM account to ensure it succeeds and to prevent terminating being denied terminating the service because it is currently executing a script with this cmdlet.

		.EXAMPLE
			Invoke-EnableCloudWatch -Key AWS.EC2.Windows.CloudWatch.json -Bucket ec2configs -RestartServices
			
			Downloads the file from S3 with pre-existing CloudWatch configurations and restarts the appropriate service depending on the version of Windows (either SSM Agent or EC2Config).

		.INPUTS
			None

		.OUTPUTS 
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/30/2017
			
	#>
	[CmdletBinding(DefaultParameterSetName = "LocalConfig")]
	Param(
		[Parameter(ParameterSetName = "LocalConfig")]
		[ValidateNotNullOrEmpty()]
		[System.String]$Key,

		[Parameter(ParameterSetName = "LocalConfig")]
		[ValidateNotNullOrEmpty()]
		[System.String]$Bucket,

		[Parameter(Mandatory = $true, ParameterSetName = "SSM")]
		[ValidateNotNullOrEmpty()]
		[System.String]$SSMDocument,

		[Parameter()]
		[switch]$RestartServices
	)

	Begin {
	}

	Process {
		try
		{
			[System.String]$CloudWatchLogConfigDestination = "$env:ProgramFiles\Amazon\Ec2ConfigService\Settings\AWS.EC2.Windows.CloudWatch.json"
			[System.String]$EC2SettingsFile="$env:ProgramFiles\Amazon\Ec2ConfigService\Settings\Config.xml"

			Write-Log -Message "Enabling CloudWatch Logs."

			$AWSSoftware = Get-AWSSoftware
			$SSMSoftware = $AWSSoftware | Where-Object -FilterScript {$_.DisplayName -eq "Amazon SSM Agent"} | Select-Object -First 1
			$EC2ConfigSW = $AWSSoftware | Where-Object -FilterScript {$_.DisplayName -eq "EC2ConfigService"} | Select-Object -First 1

			if ($SSMSoftware -ne $null -and -not [System.String]::IsNullOrEmpty($SSMDocument))
			{
				Write-Log -Message "Using SSM to configure CloudWatch."
					
				$ServiceName = "AmazonSSMAgent"

				$InstanceId = Get-EC2InstanceId

				try
				{
					Write-Log -Message "Updating SSM agent to latest."
					New-SSMAssociation -InstanceId $InstanceId -Name "AWS-UpdateSSMAgent" -Force
				}
				catch [Amazon.SimpleSystemsManagement.Model.AssociationAlreadyExistsException]
				{
					Write-Log -Message "The AWS-UpdateSSMAgent association already exists."
				}

				try
				{
					Write-Log -Message "Associating CloudWatch SSM Document $SSMDocument."
					New-SSMAssociation -Target  @{Key="instanceids"; Values=@($InstanceId)} -Name $SSMDocument -Parameter @{"status" = "Enabled"} -Force
				}
					catch [Amazon.SimpleSystemsManagement.Model.AssociationAlreadyExistsException]
					{
						Write-Log -Message "The $CloudWatchSSMDocument association already exists."
					}
				}
				elseif ($EC2ConfigSW -ne $null)
				{
					$ServiceName = "EC2Config"

					Write-Log -Message "EC2Config Service Version $($EC2ConfigSW.DisplayVersion)"

					if (-not [System.String]::IsNullOrEmpty($Bucket) -and -not [System.String]::IsNullOrEmpty($Key))
					{
						Write-Log -Message "Downloading CloudWatch configuration file."
			
						Copy-S3Object -BucketName $Bucket -Key $Key -LocalFile $CloudWatchLogConfigDestination -Force
					}

					if (-not (Test-Path -Path $CloudWatchLogConfigDestination))
					{
						$Val = @"
{
  "IsEnabled": true,
  "EngineConfiguration": {
    "PollInterval": "00:00:05",
    "Components": [
	],
    "Flows": {
      "Flows": [
      ]
    }
  }
}
"@
						Set-Content -Path $CloudWatchLogConfigDestination -Value $Val -Force
					}


					# Version is 0xMMmmBBB
					[System.String]$Hex = $EC2ConfigSW.Version.ToString("X")

					# The major and minor values are stored little endian, so they need to be flipped
					# The build number is stored big endian
					$Hex = $Hex.Substring(1, 1) + $Hex.Substring(0, 1)
					$Major = [System.Int32]::Parse($Hex.Substring(0, 2), [System.Globalization.NumberStyles]::HexNumber)

					# For EC2Config less than version 4, enabling CloudWatch has to be done in the XML config
					if ($Major -lt 4)
					{
						Write-Log -Message "Ensuring the IsEnabled property isn't present in the config file."

						[PSCustomObject]$Obj = ConvertFrom-Json -InputObject (Get-Content -Path $CloudWatchLogConfigDestination -Raw)
					
						if ($Obj.Properties.Name -icontains "IsEnabled")
						{
							$Obj.Properties.Remove("IsEnabled")
							Set-Content -Path $CloudWatchLogConfigDestination -Value (ConvertTo-Json -InputObject $Obj) -Force
						}

						Write-Log -Message "Retrieving EC2Config settings file."
			
						[System.Xml.XmlDocument]$Xml = Get-Content -Path $EC2SettingsFile
						$Xml.Get_DocumentElement().Plugins.ChildNodes | Where-Object {$_.Name -eq "AWS.EC2.Windows.CloudWatch.PlugIn"} | ForEach-Object { $_.State = "Enabled"}
			
						Write-Log -Message "Saving updated settings file."
						$Xml.Save($EC2SettingsFile)
					}
					# Othwerwise it is done in the CloudWatch json file and SSM uses it to deliver logs and metrics
					else
					{
						Write-Log -Message "Ensuring the IsEnabled property is present and set to true in the config file."

						[PSCustomObject]$Obj = ConvertFrom-Json -InputObject (Get-Content -Path $CloudWatchLogConfigDestination -Raw)
					
						$Obj.IsEnabled = $true
						Set-Content -Path $CloudWatchLogConfigDestination -Value (ConvertTo-Json -InputObject $Obj) -Force

						$ServiceName = "AmazonSSMAgent"
					}

					if (-not $Reboot)
					{
						try 
						{
							$RestartServiceTaskName = "Restart$ServiceName`Task"
  
							Write-Log -Message "Creating scheduled task to restart $ServiceName service."

							if ((Get-ScheduledTask -TaskName $RestartServiceTaskName -ErrorAction SilentlyContinue) -ne $null) 
							{
								Unregister-ScheduledTask -TaskName $RestartServiceTaskName -Confirm:$false
							}

							$Command = @"
try {					
	Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Executing scheduled task $RestartServiceTaskName, waiting 30 seconds for other actions to complete."
	Start-Sleep -Seconds 30
	Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Removing script file at $PSCommandPath."
	Remove-Item -Path "$PSCommandPath" -Force
	Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Restarting $ServiceName service."
	Restart-Service -Name $ServiceName -Force
	Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Unregistering scheduled task."
	Unregister-ScheduledTask -TaskName $RestartServiceTaskName -Confirm:`$false
	Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Successfully unregistered scheduled task, task complete."
} 
catch [Exception] {
	Add-Content -Path "$script:LogPath" -Value "[ERROR] `$(Get-Date) : `$(`$_.Exception.Message)"
	Add-Content -Path "$script:LogPath" -Value "[ERROR] `$(Get-Date) : `$(`$_.Exception.StackTrace)"
}
"@

							$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
							$EncodedCommand = [Convert]::ToBase64String($Bytes)
        
							$STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
							$STSource =  "$env:SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe"
							$STAction = New-ScheduledTaskAction -Execute $STSource -Argument $STParams
							$STPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
							$STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew
                               
							$ScheduledTask = Register-ScheduledTask -TaskName $RestartServiceTaskName -Action $STAction -Principal $STPrincipal -Settings $STSettings -ErrorAction Stop 
							Start-ScheduledTask -TaskName $RestartServiceTaskName
						}
						catch [Exception] {
							Write-Log -Message "Error running scheduled task to restart $ServiceName service." -ErrorRecord $_ -Level ERROR
						}
					}					
				}
				else
				{
					Write-Log -Message "The SSM Agent and the EC2Config service are both not installed, cannot configure CloudWatch." -Level WARNING
				}
			}
			catch [Exception]
			{
				Write-Log -Message "Error configuring CloudWatch." -ErrorRecord $_ -Level ERROR
			}
		}

		End {
		}
	}

Function Get-AWSAmiMappings {
	<#
		.SYNOPSIS 
			Gets the most current AMI image id for Windows and Amazon Linux instances in each region.

		.DESCRIPTION
			The cmdlet retrieves the most current AMI image id for Windows Server 2008 through Windows Server 2016 and Amazon Linux. The output is a	
			json formatted string that is targetted for usage in a Mappings section in an AWS Cloudformation script.

		.EXAMPLE
			Get-AWSAmiMappings

			Retrieves the AMI mappings for Windows Server and Amazon Linux.
		
		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/21/2017		
	#>
    [CmdletBinding()]
    Param()

    Begin {
        $OperatingSystems = @{
            WindowsServer2016 = "Windows_Server-2016-English-Full-Base-*"
            WindowsServer2012R2 = "Windows_Server-2012-R2_RTM-English-64Bit-Base-*"
            WindowsServer2012 = "Windows_Server-2012-RTM-English-64Bit-Base-*"
            WindowsServer2008R2 = "Windows_Server-2008-R2_SP1-English-64Bit-Base-*"
            WindowsServer2008 = "Windows_Server-2008-SP2-English-64Bit-Base-*"
            AmazonLinux = "amzn-ami-hvm-*-gp2"
        }
    }

    Process {
        $Regions = Get-AWSRegion

        [System.Collections.Hashtable]$Results = @{}

        foreach ($Region in $Regions)
        {
            Write-Verbose -Message "Processing region $($Region.Region)."
            [PSCustomObject]$RegionResults = [PSCustomObject]@{Name = $Region.Name}

            $OperatingSystems.GetEnumerator() | Sort-Object -Property Key -Descending | ForEach-Object {
                Write-Verbose -Message "Processing OS $($_.Key)."

                [Amazon.EC2.Model.Filter]$Filter = New-Object -TypeName Amazon.EC2.Model.Filter
                $Filter.Name = "name"
                $Filter.Value = $_.Value
            
                $Id = [System.String]::Empty
                $Id = Get-EC2Image -Filter @($Filter) -Region $Region.Region -ErrorAction SilentlyContinue | Sort-Object -Property CreationDate -Descending | Select-Object -ExpandProperty ImageId -First 1

                if (-not [System.String]::IsNullOrEmpty($Id))
                {
                    $RegionResults | Add-Member -MemberType NoteProperty -Name $_.Key -Value $Id
                }
            }

           $Results.Add($Region.Region, $RegionResults)
        }

        ConvertTo-Json -InputObject ($Results | Sort-Object -Property Key)
    }

	End {
	}
}

Function Invoke-AWSKMSEncryptString {
	<#
		.SYNOPSIS
			Encrypts a plain text string with an AWS KMS key.

		.DESCRIPTION
			The cmdlet takes a plain text string and encrypts it with an AWS KMS key and returns back a Base 64 encoded string of the encrypted plain text.

			Optionally, an Encryption Context hash table can be provided to include with the encrypted string.

		.PARAMETER InputObject
			The string to encrypt.

		.PARAMETER Key
			The Key Id (a string version of a GUID) or the Key alias.

		.PARAMETER EncryptionContext
			Name-value pair in a Hashtable that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the Decrypt API or decryption will fail.

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
			Invoke-AWSEncryptString "MySecurePassword" -Key "c267f345-ef7a-40ff-95a0-a1b4dbeaac75" -EncryptionContext @{"UserName" = "john.smith"} 

			Encrypts the password with the supplied encryption context and returns a base 64 string of the encrypted value.

		.INPUTS
			System.String

		.OUTPUTS
			System.Sting

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/21/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNull()]
		[System.String]$InputObject,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Key,

		[Parameter()]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$EncryptionContext,

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
        [System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

		try
		{
			[System.Byte[]]$Bytes = [System.Text.Encoding]::UTF8.GetBytes($InputObject)

			[System.Collections.Hashtable]$ContextSplat = @{}

			if ($EncryptionContext -ne $null -and $EncryptionContext.Count -gt 0)
			{
				$ContextSplat.EncryptionContext = $EncryptionContext
			}

			[System.IO.MemoryStream]$MStream = New-Object -TypeName System.IO.MemoryStream($Bytes, 0, $Bytes.Length)
			[Amazon.KeyManagementService.Model.EncryptResponse]$Response = Invoke-KMSEncrypt -Plaintext $MStream -KeyId $Key @ContextSplat @Splat
			
			Write-Output -InputObject ([System.Convert]::ToBase64String($Response.CiphertextBlob.ToArray()))
		}
		finally
		{
			$MStream.Dispose()
		}		
	}

	End {
	}
}

Function Invoke-AWSKMSDecryptString {
	<#
		.SYNOPSIS
			Decrypts a base 64 encoded string back to the original string.

		.DESCRIPTION
			The cmdlet takes a base 64 encoded, encrypted string and decrypts it back to plain text.

			Optionally, an Encryption Context hash table can be provided to include with the encrypted string if it was provided during encryption.

		.PARAMETER InputObject
			The base 64 encoded string to decrypt.

		.PARAMETER EncryptionContext
			Name-value pair in a Hashtable that specifies the encryption context to be used for authenticated encryption. The same value must be supplied to the Decrypt API as was supplied to the Encrypt API or decryption will fail.

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
			$EncryptedString = "AQICAHirjhAS1dnk3AqaAX8ebvOi+2yKjwR2lcRsjqKC0zRl/AFALrR6jZfasOcnKLdT+Y26AAAAbjBsBgkqhkiG9w0BBwagXzBdAgEAMFgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMJnfWdFgGqptS23pfAgEQgCtqQ6FoKrjSlZDUIPTVzdDNJ/BfbbnPtlux0o8b2ya0DxUVZ5hFHroXUyFF"
			Invoke-AWSKMSDecryptString $EncryptedString -EncryptionContext @{"UserName" = "john.smith"} 

			Decrypts the string with the supplied encryption context and returns the plain text string from the encrypted value.

		.INPUTS
			System.String

		.OUTPUTS
			System.Sting

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/21/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNull()]
		[System.String]$InputObject,

		[Parameter()]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$EncryptionContext,

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
        [System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

		try
		{
			[System.Byte[]]$Bytes = [System.Convert]::FromBase64String($InputObject)

			[System.Collections.Hashtable]$ContextSplat = @{}

			if ($EncryptionContext -ne $null -and $EncryptionContext.Count -gt 0)
			{
				$ContextSplat.EncryptionContext = $EncryptionContext
			}

			[System.IO.MemoryStream]$MStream = New-Object -TypeName System.IO.MemoryStream($Bytes, 0, $Bytes.Length)
			[Amazon.KeyManagementService.Model.DecryptResponse]$Response = Invoke-KMSDecrypt -CipherTextBlob $MStream @ContextSplat @Splat
			
			Write-Output -InputObject ([System.Text.Encoding]::UTF8.GetString($Response.PlainText.ToArray()))
		}
		finally
		{
			$MStream.Dispose()
		}		
	}

	End {
	}
}

Function Get-AWSFederationLogonUrl {
	<#
		.SYNOPSIS
			Generates a temporary url that allows a logon to the AWS Management Console with an assumed role.

		.DESCRIPTION
			The cmdlet builds a url that can be used to logon to the AWS Management Console. First, the provided role is assumed using the specified credentials (or uses the default credentials).
			Then, the cmdlet retrieves a federation signin token and then creates the login url. The provided credentials do not need to exist in the same account as the specified role, they just 
			need permissions to be able to perform the sts:AssumeRole action for the provide role ARN.

		.PARAMETER RoleArn
			The role in the account you want to assume and log into. This role must be assumed using long-term AWS credentials (not temporary credentials).

		.PARAMETER Duration
			How long the assumed role credentials are good for between 900 and 3600 seconds. Regardless of what value is specified, the resulting Url is always valid for 15 minutes.

		.PARAMETER Issuer
			The url of your custom authentication system. This will default to https://<AWS Account Id>.signin.aws.amazon.com.

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
			Get-AWSFederationLogonUrl -RoleArn "arn:aws:iam::123456789012:role/AdministratorRole" -ProfileName mycredentialprofile
			
			Gets the AWS management console signin url for the AdministratorRole in the 123456789012 account.

		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 6/30/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[System.String]$RoleArn,

		[Parameter()]
		[ValidateRange(900, 3600)]
		[System.Int32]$Duration = 3600,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Issuer = [System.String]::Empty,

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
        [System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
		$Destination = [System.Net.WebUtility]::UrlEncode("https://console.aws.amazon.com")
	}

	Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

		# Get caller identity
		[Amazon.SecurityToken.Model.GetCallerIdentityResponse]$Identity = Get-STSCallerIdentity @Splat

		# Create the session name from the identity
		$SessionName = "$($Identity.Account)-$($Identity.UserId)-$($Identity.Arn.Split("/")[-1])"
		$SessionName = $SessionName.Substring(0, [System.Math]::Min(64, $SessionName.Length)) -replace "[^\\w +=,.@-]*",""
		
		# Assume the role in the remote account
		[Amazon.SecurityToken.Model.AssumeRoleResponse]$Role = Use-STSRole -DurationInSeconds $Duration -RoleSessionName $SessionName -RoleArn $RoleArn @Splat

		# Form the url to to get the signin token
		$Url = "$script:FederationUrl`?Action=getSigninToken&SessionType=json&Session={`"sessionId`":`"$([System.Net.WebUtility]::UrlEncode($Role.Credentials.AccessKeyId))`",`"sessionKey`":`"$([System.Net.WebUtility]::UrlEncode($Role.Credentials.SecretAccessKey))`",`"sessionToken`":`"$([System.Net.WebUtility]::UrlEncode($Role.Credentials.SessionToken))`"}"

		<# Get the token, it's in the form of
		{
			"SiginToken" : "UniqueStringHere"
		}
		#>
		[System.Net.WebClient]$Client = New-Object -TypeName System.Net.WebClient

		$Response = ConvertFrom-Json -InputObject $Client.DownloadString($Url)

		# Set the issuer if it wasn't provided by the user
		if ([System.String]::IsNullOrEmpty($Issuer))
		{
			$Issuer = "https://$($Identity.Account).signin.aws.amazon.com"
		}

		$Issuer = [System.Net.WebUtility]::UrlEncode($Issuer)		
		$Token = [System.Net.WebUtility]::UrlEncode($Response.SigninToken)
		$Action = "login"

		# Create the signin url, it's valid for 15 minutes regardless of the duration of the assumed role
		[System.String]$Signin = "$script:FederationUrl`?Action=$Action&Issuer=$Issuer&Destination=$Destination&SigninToken=$Token"

		Write-Output -InputObject $Signin
	}

	End {
	}
}

Function Get-AWSPublicIPRanges {
	<#
		.SYNOPSIS
			Gets the public IP ranges AWS uses.

		.DESCRIPTION
			The cmdlet queries the ip-ranges.json file AWS provides and filters the results based on the selected services and/or regions. If no filter
			values are provided, all of the results are returned. The results contain the IP prefix, the region, and the service.

		.PARAMETER Services
			The list of AWS services to filter the results on.

		.PARAMETER Regions
			The list of AWS regions to filter the results on.

		.EXAMPLE
			Get-AWSPublicIPRanges
			
			Gets all of the public IP prefixes AWS has.

		.EXAMPLE
			Get-AWSPublicIPRanges -Services @("EC2", "S3")

			Gets the public IP ranges used by EC2 and S3.

		.EXAMPLE
			Get-AWSPublicIPRanges -Services EC2 -Regions @([Amazon.RegionEndpoint]::USEast1, [Amazon.RegionEndpoint]::USEast2)

			Gets the public IP ranges used by EC2 in us-east-1 and us-east-2.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/3/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[ValidateSet("AMAZON", "ROUTE53_HEALTHCHECKS", "S3", "EC2", "ROUTE53", "CLOUDFRONT")]
		[System.String[]]$Services = @(),

		[Parameter()]
		[ValidateNotNull()]
        [Amazon.RegionEndpoint[]]$Regions = @()
	)

	Begin {
	}

	Process {
		[System.Net.WebClient]$Client = New-Object -TypeName System.Net.WebClient
		$Json = $Client.DownloadString($script:IPRangeUrl)
		$Content = ConvertFrom-Json -InputObject $Json | Select-Object -ExpandProperty prefixes
		
		if ($Regions.Length -gt 0)
		{
			$Content = $Content | Where-Object {$_.region -in ($Regions | Select-Object -ExpandProperty SystemName) }
		}

		if ($Services.Length -gt 0)
		{
			$Content = $Content | Where-Object {$_.service -in $Services}
		}

		Write-Output -InputObject ($Content | Sort-Object -Property service,region)
	}

	End {
	}
}