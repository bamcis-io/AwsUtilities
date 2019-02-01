Import-Module -Name AWSPowerShell -ErrorAction Stop -Verbose:$false

$script:CREATED_BY = "CreatedBy"
$script:CAN_BE_DELETED = "CanBeDeleted"
[System.Guid]$script:UNIQUE_ID = [System.Guid]::Parse("17701dbb-33ff-4f31-8914-6f48856fe755")
$script:INTEL_DRIVER = "Intel82599VF"
$script:ENA = "ENA"
$script:FederationUrl = "https://signin.aws.amazon.com/federation"
$script:IPRangeUrl = "https://ip-ranges.amazonaws.com/ip-ranges.json"
$script:MaxEC2Tags = 50

#Make the variable $AWSRegions available to all of the cmdlets
Set-Variable -Name AWSRegions -Value (Get-AWSRegion -IncludeChina -IncludeGovCloud | Select-Object -ExpandProperty Region)
Set-Variable -Name AWSPublicRegions -Value @(Get-AWSRegion | Select-Object -ExpandProperty Region)

#region S3 Functions

Function Get-S3ETagCalculation {
	<#
		.SYNOPSIS
			Calculates the expected ETag value for an object uploaded to S3.

		.DESCRIPTION
			The cmdlet calculates the hash of the targetted file to generate its S3 ETag value that can be used to validate file integrity.

			This cmdlet will fail to work if FIPS Compliant algorithms are enforced because AWS uses an MD5 hash for the ETag. (Microsoft no longer recommends FIPS mode https://blogs.technet.microsoft.com/secguide/2014/04/07/why-were-not-recommending-fips-mode-anymore/)

		.PARAMETER FilePath
			The path to the file that is having its ETag value calculated.

		.PARAMETER ChunkSize
			The size of each part uploaded to S3, defaults to 8MB. Minimum size is 5MB, maximum size is 5GB (all files larger than 5GB are chunked).

			https://docs.aws.amazon.com/cli/latest/topic/s3-config.html#multipart-chunksize

		.PARAMETER MultipartThreshold
			The file must be larger than this size to use multipart upload, defaults to 64MB. Minimum value is 2 Bytes.

			https://docs.aws.amazon.com/cli/latest/topic/s3-config.html#multipart-threshold

        .EXAMPLE
			Get-S3ETagCalculation -FilePath "c:\test.txt"

			Calculates the ETag value for c:\test.txt.

		.INPUTS
			System.String

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/14/2019
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	Param (
		[Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Path -Path $_
        })]
		[Alias("Path")]
		[System.String]$FilePath,

		[Parameter(Position = 1)]
		[ValidateRange(5MB, 5GB)]
		[System.UInt64]$ChunkSize = 8MB,

		[Parameter(Position = 2)]
		[ValidateRange(2, [System.UInt64]::MaxValue)]
		[System.UInt64]$MultipartThreshold = 64MB
	)

	Begin 
	{
		if ($env:OS -like "Windows*" -and (Test-Path -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy))
		{
			$FIPS = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy -Name Enabled -ErrorAction SilentlyContinue
    
			if ($?) # Will be true if previous command didn't error, which means the item property exists
			{
				if ((($FIPS | Get-Member -MemberType NoteProperty -Name "Enabled") -ne $null) -and $FIPS.Enabled -eq 1)
				{
					throw "FIPS Mode is currently enforced, and this cmdlet uses MD5 hash algorithms which are not allowed by FIPS enforced mode. Set DWORD `"Enabled`" in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy to 0."
				}
				else
				{
					Write-Verbose -Message "FIPS enforced mode disabled."
				}						
			}			
		}
	}

	Process 
	{
		# Track the number of parts that would need to be uploaded
		$Parts = 0

		# Track the hashes of each part in the array
		[System.Byte[]]$BinaryHashArray = @()

		# FIPS compliance enforcement must be turned off to use MD5
		[System.Security.Cryptography.MD5CryptoServiceProvider]$MD5 = [Security.Cryptography.HashAlgorithm]::Create([System.Security.Cryptography.MD5])

		[System.IO.FileStream]$FileReader = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)

		try
		{
            Write-Verbose -Message "File at $FilePath is $($FileReader.Length) bytes long."

			# If the file is larger than the size to use multipart
			if ($FileReader.Length -gt $MultipartThreshold) 
			{
				Write-Verbose -Message "The upload will use multipart"

				# Set the buffer object to the size of upload part
				[System.Byte[]]$Buffer = New-Object -TypeName System.Byte[]($ChunkSize)

				# This reads the file and ensures we haven't reached the end of the file
				# FileReader reads from 0 up to the buffer length and places it in the byte array
				while (($LengthToRead = $FileReader.Read($Buffer, 0, $Buffer.Length)) -ne 0)
				{
					# The number of parts in the upload is appended to the end of the ETag, so track that here
					$Parts++

					# Calculate the hash of the part and add it to a byte array
					# ComputeHash takes in a byte array and returns one
					# Only read in the amount of data that is left to be read
					[System.Byte[]]$Temp = $MD5.ComputeHash($Buffer, 0, $LengthToRead)

					Write-Verbose -Message "Reading part $Parts : $([System.BitConverter]::ToString($Temp).Replace("-", [System.String]::Empty).ToLower())"

					$BinaryHashArray += $Temp
				}

				Write-Verbose -Message "There are $Parts total parts."

				# The MD5 hash is calculated by concatenating all of the MD5 hashes of the parts
				# and then doing an MD5 hash of the concatenation
				# Calculate the hash, ComputeHash() takes in a byte[]
				Write-Verbose -Message "Calculating hash of concatenated hashes."
				$BinaryHashArray = $MD5.ComputeHash($BinaryHashArray)
			}
			else # The file is not big enough to use multipart
			{
				Write-Verbose -Message "The upload is smaller than the minimum threshold and will not use multipart."

				$Parts = 1
				# Here ComputeHash takes in a Stream object
				$BinaryHashArray = $MD5.ComputeHash($FileReader)
			}

			Write-Verbose -Message "Closing the file stream."
			$FileReader.Close()

			# Convert the byte array to a string
			[System.String]$Hash = [System.BitConverter]::ToString($BinaryHashArray).Replace("-","").ToLower()

			# Append the number of parts to the ETag if there were multiple
			if ($Parts -gt 1) 
			{
				$Hash += "-$Parts"
			}

			Write-Output -InputObject $Hash
		}
		finally
		{
			Write-Verbose -Message "Disposing MD5 Crypto Service Provider"
			$MD5.Dispose()

			Write-Verbose -Message "Disposing file reader"
			$FileReader.Dispose()
		}
	}

	End {
	}
}

#endregion

#region EC2 Instance Metadata

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
			LAST UPDATE: 1/14/2019
	#>
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		$ComputerName,

		[Parameter()]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	Begin {
        $HostIPs = @(".", "localhost", "", $env:COMPUTERNAME, "127.0.0.1")

        if ((Get-Command -Name "Get-NetIPAddress") -ne $null)
        {
            $HostIPs += (Get-NetIPAddress | Select-Object -ExpandProperty IPAddress)
        }
	}

	Process {	
        $Splat = @{}

        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
        {
            $Splat.Add("Credential", $Credential)
        }

        if ($PSBoundParameters.ContainsKey("ComputerName") -and $ComputerName -inotin $HostIPs)
        {
            $Splat.Add("ComputerName", $ComputerName)
        }
	
		Invoke-Command -ScriptBlock {
			[Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri http://169.254.169.254/latest/dynamic/instance-identity/document
            ConvertFrom-Json -InputObject $Response.Content | Select-Object -ExpandProperty Region | Write-Output
		} @Splat | Write-Output
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
			LAST UPDATE: 1/14/2019
	#>
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		$ComputerName,

		[Parameter()]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	Begin {
        $HostIPs = @(".", "localhost", "", $env:COMPUTERNAME, "127.0.0.1")

        if ((Get-Command -Name "Get-NetIPAddress") -ne $null)
        {
            $HostIPs += (Get-NetIPAddress | Select-Object -ExpandProperty IPAddress)
        }
	}

	Process {	
        $Splat = @{}

        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
        {
            $Splat.Add("Credential", $Credential)
        }

        if ($PSBoundParameters.ContainsKey("ComputerName") -and $ComputerName -inotin $HostIPs)
        {
            $Splat.Add("ComputerName", $ComputerName)
        }
	
		Invoke-Command -ScriptBlock {
			[Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/instance-id
            $Response.Content | Write-Output
		} @Splat | Write-Output
	}

	End {
	}
}

#endregion

#region EC2 Functions

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
			LAST UPDATE: 1/16/2019
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

			# Filtering on tag values uses the "tag:" preface for the key name
			$Filter.Name = "tag:Name"
			$Filter.Value = $InstanceName
                
			# This is actually a [Amazon.EC2.Model.Reservation], but if no instance is returned, it comes back as System.Object[]
			# so save the error output and don't strongly type it
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
					else
					{
						Write-Output -InputObject $EC2
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
			Specify to wait for the EC2 instance to reach the desired state. Also specify this parameter to wait for in instance in 'Pending' to reach 'Running' to change state to 'Stopped'.

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
			LAST UPDATE: 1/27/2019
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
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
		[Switch]$Force,

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
			$InstanceSplat.Add("InstanceId", $InstanceId)
		}
		else
		{
			$InstanceSplat.Add("InstanceName", $InstanceName)
		}

		[Amazon.EC2.Model.Instance]$Instance = Get-EC2InstanceByNameOrId @InstanceSplat @AwsUtilitiesSplat
		[Amazon.EC2.InstanceStateName]$DesiredState = $null
		[Amazon.EC2.Model.InstanceStateChange]$Result = $null

		Write-Verbose -Message "Current instance state: $($Instance.State.Name)."

		$ConfirmMessage = "Are you sure you want to $State instance $($Instance.InstanceId)?"

		$WhatIfDescription = "$State $($Instance.InstanceId)."
		$ConfirmCaption = "Change Instance State"

		if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
		{
			switch ($State)
			{
				"STOP" {
					# Stop can only be called when the instance has reached the running state
					switch ($Instance.State.Name)
					{
						([Amazon.EC2.InstanceStateName]::Pending) 
						{
							if ($Wait)
							{
								while ($Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::Pending)
								{
									Start-Sleep -Seconds 5
									$Instance = Get-EC2InstanceByNameOrId -InstanceId $Instance.InstanceId @AwsUtilitiesSplat
								}

								if ($Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::Running)
								{
									$Result = Stop-EC2Instance -InstanceId $Instance.InstanceId @Splat
								}
								else
								{
									throw "The instance did not enter a running state after pending and could not be stopped directly. The current state is $($Instance.State.Name)."
								}
							}
							else
							{
								throw "The instance has not reached the 'running' state and cannot be stopped. Specify 'Wait' to wait for the instance to enter the running state from pending."
							}

							break
						}
						([Amazon.EC2.InstanceStateName]::Running) {
							$Result = Stop-EC2Instance -InstanceId $Instance.InstanceId @Splat
							break
						}
						{ $_ -in @([Amazon.EC2.InstanceStateName]::Stopping, [Amazon.EC2.InstanceStateName]::ShuttingDown, [Amazon.EC2.InstanceStateName]::Stopped) } {
							Write-Verbose -Message "Instance is already in or entering the desired state."
							break
						}
						([Amazon.EC2.InstanceStateName]::Terminated) {
							throw "The specified instance $($Instance.InstanceId) has been terminated and cannot be stopped."
							break
						}
						default {
							throw "Unknown state $($Instance.State.Name) for instance $($Instance.InstanceId)."
						}
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
						Write-Verbose -Message "Instance $($Instance.InstanceId) already in state: $($Instance.State.Name)."
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
						Write-Verbose -Message "Instance $($Instance.InstanceId) already in state: $($Instance.State.Name)."
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
				$CursorStartPosition = $Host.UI.RawUI.CursorPosition
				$CursorStartPosition.Y += 1
				$Scroll = "/-\|"

				[System.Int32]$Increment = 5
				[System.Diagnostics.Stopwatch]$SW = [System.Diagnostics.Stopwatch]::StartNew()
				$Counter = 0

				while ($Instance.State.Name -ne $DesiredState -and $SW.Elapsed.TotalSeconds -le $Timeout)
				{
					$Host.UI.RawUI.CursorPosition = $CursorStartPosition
					$Text = "`rWaiting for $($Instance.InstanceId) to $State $($Scroll[$Counter++])"

					if ($Counter -eq $Scroll.Length)
					{
						$Counter = 0
					}

					Write-Host $Text -NoNewline

					Start-Sleep -Seconds $Increment

					$Instance = Get-EC2InstanceByNameOrId -InstanceId $Instance.InstanceId @AwsUtilitiesSplat
				}

				$Host.UI.RawUI.CursorPosition = $CursorStartPosition

				if ($SW.Elapsed.TotalSeconds -ge $Timeout)
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
	}

	End {
	}
}

Function Get-EC2CurrentImageIds {
	<#
		.SYNOPSIS 
			Gets the most current AMI image id for Windows and Amazon Linux, Debian, CentOS, Ubuntu, and SLES instances in each region.

		.DESCRIPTION
			The cmdlet retrieves the most current AMI image id for Windows Server 2012 through Windows Server 2019, Amazon Linux, Amazon Linux 2, Ubuntu 18.04, SLES 15, CentOS 7 and Debian 9. 

            Mappings for ARM and x86 processors are provided as well as Linux images with .NET Core 2.1 pre-installed. 

            The output is a	json formatted string that is targetted for usage in the Mappings section in an AWS Cloudformation script. This gives you an easy way to reference the most recent AMI id for an OS in CloudFormation as well as easily update that mapping element over time.

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked. For example, us-east-1, eu-west-1 etc. 

            If this parameter is specified, the AMI mappings are only returned for that region, otherwise mappings are returned for every region.

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
			Get-EC2CurrentImageIds

			Retrieves the AMI mappings for all included Operating Systems in every public region.

		.EXAMPLE
			Get-EC2CurrentImageIds -Region ([Amazon.RegionEndpoint]::UsEast1) -ProfileName myprodprofile

			Gets the AMI mappings for all included Operating Systems in the us-east-1 region using the credentials in the "myprodprofile" profile.
		
		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/17/2019		
	#>
    [CmdletBinding()]
    Param(
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
        $OperatingSystems = @{
			WindowsServer2019 = "Windows_Server-2019-English-Full-Base-*";
            WindowsServer2016 = "Windows_Server-2016-English-Full-Base-*";
            WindowsServer2012R2 = "Windows_Server-2012-R2_RTM-English-64Bit-Base-*";
            WindowsServer2012 = "Windows_Server-2012-RTM-English-64Bit-Base-*";
            AmazonLinux_x86_64 = "amzn-ami-hvm-*-x86_64-gp2";
			AmazonLinux2_x86_64 = "amzn2-ami-hvm-*-x86_64-gp2";
			AmazonLinux2_arm64 = "amzn2-ami-hvm-*-arm64-gp2";
			AmazonLinux2_netcore21_x86_64 = "amzn2-ami-hvm-*-x86_64-gp2-dotnetcore-*";
			Ubuntu1804_x86_64 = "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20??????";
			Ubuntu1804_arm64 = "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-arm64-server-20??????";
			Ubuntu1804_netcore21_x86_64 = "ubuntu-bionic-18.04-amd64-server-*-dotnetcore-*"
			SUSE15_x86_64 = "suse-sles-15-*-hvm-ssd-x86_64";
			CentOS7_x86_64 = "CentOS Linux 7 x86_64 HVM EBS ENA*";
			Debian9_x86_64 = "debian-stretch-hvm-x86_64-gp2*";
        }
    }

    Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
        $Splat.Remove("Region")		 

        if ($PSBoundParameters.ContainsKey("Region"))
        {
            [Amazon.PowerShell.Common.AWSRegion[]]$Regions = Get-AWSRegion -SystemName $Region.SystemName 
        }
        else
        {
            [Amazon.PowerShell.Common.AWSRegion[]]$Regions = Get-AWSRegion
        }

        [PSCustomObject]$Results = [PSCustomObject]@{}

        $Jobs = @()
        
        foreach ($Item in $Regions)
        {
            Write-Verbose -Message "Starting background job for region $($Item.Region)."

            $Job = Start-Job -Name $Item.Name -ScriptBlock {
                Import-Module AWSPowerShell
                $Region = $using:Item
                $Splat = $using:Splat
                $OS = $using:OperatingSystems
                
                [PSCustomObject]$RegionResults = [PSCustomObject]@{Name = $Region.Name; Region = $Region.Region}

                $OS.GetEnumerator() | Sort-Object -Property Key | ForEach-Object {
                    try
                    {
                        $Key = $_.Key
                        [Amazon.EC2.Model.Filter]$Filter = New-Object -TypeName Amazon.EC2.Model.Filter
                        $Filter.Name = "name"
                        $Filter.Value = $_.Value
            
                        $Id = [System.String]::Empty
                        $Id = Get-EC2Image -Filter @($Filter) -Region $Region.Region -ErrorAction SilentlyContinue @Splat | Sort-Object -Property CreationDate -Descending | Select-Object -ExpandProperty ImageId -First 1

                        if (-not [System.String]::IsNullOrEmpty($Id))
                        {
                            $RegionResults | Add-Member -MemberType NoteProperty -Name $_.Key -Value $Id
                        }
                    }
                    catch [Exception]
                    {
                        Write-Warning -Message "Error processing $Key in $($Region.Region): $($_.Exception.Message)"
                    }
                }
                
                Write-Output -InputObject $RegionResults
            }

            $Jobs += $Job
        }
        
        Write-Verbose -Message "Waiting on jobs to complete"

        [PSCustomObject[]]$JobResults = $Jobs | Receive-Job -AutoRemoveJob -Wait | Select-Object -Property * -ExcludeProperty PSComputerName,RunspaceId,PSSourceJobInstanceId,PSShowComputerName
        
        foreach ($Item in ($JobResults | Sort-Object -Property Region))
        {
            $Results | Add-Member -Name $Item.Region -Value ($Item | Select-Object -Property * -ExcludeProperty Region) -MemberType NoteProperty
        }

        Write-Output -InputObject ($Results | ConvertTo-Json)
    }

	End {
	}
}

Function Move-EC2Instance {
	<#
		.SYNOPSIS
			Moves an EC2 instance from a source region to a different target region.

		.DESCRIPTION
			This cmdlet moves 1 or more EC2 instances from a source region to a different target region by creating a new AMI of the source in the
			target region. The user will then need to manually deploy the EC2 instance into the desired VPC from the AMI. The cmdlet will also optionally
			cleanup the source region region by deleting the source EC2 instance(s) and source AMI(s).

			Each specified instance will be stopped before having an AMI created from it to ensure consistency of all EBS volumes.

		.PARAMETER InstanceIds
			The source EC2 instances to move.

		.PARAMETER DestinationRegion
			The region the new AMIs will be created in.

		.PARAMETER Encrypt
			Specifies that the destination AMIs will use encrypted EBS volumes that use the default KMS key for that region.

        .PARAMETER KmsKeyId
			If you specify this, the resulting AMIs will be encrypted using this KMS key. You don't need to specify the Encrypt parameter if you provide this one.

		.PARAMETER Cleanup
			If specified, the source EC2 instances and source AMIs that are created will all be deleted once the destination AMIs have been successfully created.

        .PARAMETER Wait
            If specified, the cmdlet will wait for the final AMIs to be created before returning.

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked and that the source EC2 instances are in. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

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
			$AMIs = Move-EC2Instance -InstanceIds @("i-033b1455fc5c3b386") -DestinationRegion ([Amazon.RegionEndpoint]::UsEast1) -Region ([Amazon.RegionEndpoint]::UsEast2) -CleanupSource -ProfileName "mylab"
		
			This example moves the instance i-033b1455fc5c3b386 to us-east-1 from us-east-2 and deletes the source instance and its intermediate AMI. The resulting AMI id is returned to the pipeline.

		.INPUTS
			System.String[]

		.OUTPUTS
			Amazon.EC2.Model.Image[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/23/2019

	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([System.String[]])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[System.String[]]$InstanceIds,

		[Parameter(Mandatory = $true)]
		[Amazon.RegionEndpoint]$DestinationRegion,

		[Parameter(ParameterSetName = "KMS")]
		[Switch]$Encrypted,

        [Parameter(ParameterSetName = "CustomKMS")]
		[ValidateNotNull()]
		[System.String]$KmsKeyId = [System.String]::Empty,

		[Parameter()]
		[Switch]$CleanupSource,

		[Parameter()]
		[Switch]$Force,

        [Parameter()]
        [Switch]$Wait,

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
		[Amazon.Runtime.AWSCredentials]$Credential = $null,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {

	}

	Process {
        [System.Collections.Hashtable]$SourceSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		[System.Collections.Hashtable]$DestinationSplat = New-AWSSplat -Region $DestinationRegion -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		[System.Collections.Hashtable]$UtilSplat = New-AWSUtilitiesSplat -AWSSplat $SourceSplat
        [System.Collections.Hashtable]$SourceImageIdToInstanceIdMap = @{}
        [System.String[]]$SourceInstanceIdsToDelete = @()

		$ConfirmMessage = "Are you sure you want to stop and copy $($InstanceIds.Length) EC2 instance$(if ($Instances.Length -gt 1){"s"}) from $Region to $DestinationRegion`?"

		$WhatIfDescription = "Stopped and moved $($InstanceIds.Length) EC2 instance$(if ($Instances.Length -gt 1){"s"}) from $Region to $DestinationRegion."
		$ConfirmCaption = "Move Instances"

		if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
		{
            [System.Collections.Generic.Queue[Amazon.EC2.Model.Instance]]$WaitingToStop = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.Instance]
            [System.Collections.Generic.Queue[Amazon.EC2.Model.Image]]$SourceAMIs = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.Image]
            [Amazon.EC2.Model.Image[]]$FinalAMIs = @()

			foreach ($Id in $InstanceIds)
			{
				Write-Verbose -Message "Stopping instance $Id."
				Set-EC2InstanceState -InstanceId $Id -State STOP -Force @UtilSplat 
				$WaitingToStop.Enqueue((Get-EC2InstanceByNameOrId -InstanceId $Id @UtilSplat))
			}

            while ($WaitingToStop.Count -gt 0)
			{
				Write-Verbose -Message "Waiting for all instances to stop."

                [Amazon.EC2.Model.Instance]$Instance = $WaitingToStop.Dequeue()

                switch ($Instance.State.Name)
                {
                    ([Amazon.EC2.InstanceStateName]::Stopped) {
                        Write-Verbose -Message "Instance $($Instance.InstanceId) is stopped."

                        try
				        {
							Write-Verbose -Message "Creating new AMI for $($Instance.InstanceId)."
							$Desc = Get-EC2Image -ImageId $Instance.ImageId @SourceSplat | Select-Object -ExpandProperty Name

							$Name = $Instance.InstanceId

							if (($Instance.Tags | Where-Object {$_.Key -ieq "Name"}).Length -gt 0)
							{
								$Name = $Instance.Tags | Where-Object {$_.Key -ieq "Name"} | Select-Object -First 1 -ExpandProperty Value
							}

							$ImageId = New-EC2Image -InstanceId $Instance.InstanceId -Name $Name -Description $Desc @SourceSplat
							Write-Verbose -Message "New AMI is $ImageId."
							$SourceAMIs.Enqueue((Get-EC2Image -ImageId $ImageId @SourceSplat))
                            $SourceImageIdToInstanceIdMap.Add($ImageId, $Instance.InstanceId)
						}
						catch [Exception] 
						{
							Write-Warning -Message "Could not create a new image for $($Instance.InstanceId):`r`n$(ConvertTo-Json -InputObject $_.Exception)"
						}

                        break
                    }
                    ([Amazon.EC2.InstanceStateName]::Terminated) {
                        throw "Instance $($Instance.InstanceId) has been terminated and cannot be moved."
                    }
                    default {
                        $WaitingToStop.Enqueue($Instance)
                    }
                }

                if ($WaitingToStop.Count -gt 0 -and ($WaitingToStop | Where-Object { $_.State.Name -eq [Amazon.EC2.InstanceStateName]::Stopped }).Count -ne $WaitingToStop.Count)
                {
                    Write-Verbose -Message "All remaining instances have not stopped, sleeping to allow them to finish stopping."
                    Start-Sleep -Seconds 10
                    $Arr = $WaitingToStop.ToArray()

                    $WaitingToStop = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.Instance]

                    for ($i = 0; $i -lt $Arr.Length; $i++)
                    {
                        $WaitingToStop.Enqueue((Get-EC2InstanceByNameOrId -InstanceId $Arr[$i].InstanceId @UtilSplat))
                    }
                }
            }

            [System.String[]]$SourceImageIdsToDeleteAtCleanup = @()

			while ($SourceAMIs.Count -gt 0)
			{
				[Amazon.EC2.Model.Image]$Image = $SourceAMIs.Dequeue()

                switch ($Image.State)
                {
                    ([Amazon.EC2.ImageState]::Available) {
                        Write-Verbose -Message "Copying AMI $($Image.ImageId) from $Region to $DestinationRegion."
						
                        [System.Collections.Hashtable]$EncryptSplat = @{}

                        if ($Encrypted)
                        {
                            $EncryptSplat.Add("Encrypted", $true)
                        }
                        elseif (-not [System.String]::IsNullOrEmpty($KmsKeyId))
                        {
                            $EncryptSplat.Add("KmsKeyId", $KmsKeyId)
                        }

						$NewAmiId = Copy-EC2Image -SourceImageId $Image.ImageId -Description $Image.Description -Name $Image.Name -SourceRegion $SourceSplat.Region @DestinationSplat @EncryptSplat
                        $FinalAMIs += (Get-EC2Image -ImageId $NewAmiId @DestinationSplat)
                        $SourceImageIdsToDeleteAtCleanup += $Image.ImageId
                        
                        $SourceInstanceIdsToDelete += $SourceImageIdToInstanceIdMap[$Image.ImageId]
                        
                        break
                    }
                    {$_ -in @([Amazon.EC2.ImageState]::Failed, [Amazon.EC2.ImageState]::Deregistered, [Amazon.EC2.ImageState]::Error, [Amazon.EC2.ImageState]::Invalid)} {
                        throw "The EC2 image $($Image.ImageId) is in state $($Image.State) and cannot be copied."
                    }
                    default {
                        $SourceAMIs.Enqueue($Image)
                    }
                }					

                if ($SourceAMIs.Count -gt 0 -and ($SourceAMIs | Where-Object { $_.State -ne [Amazon.EC2.ImageState]::Available }).Count -eq $SourceAMIs.Count)
                {
                    Write-Verbose -Message "All remaining images have not become available yet, sleeping to allow them to finish creating."
                    Start-Sleep -Seconds 10
                    $Arr = $SourceAMIs.ToArray()

                    $SourceAMIs = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.Image]

                    for ($i = 0; $i -lt $Arr.Length; $i++)
                    {
                        $SourceAMIs.Enqueue((Get-EC2Image -ImageId $Arr[$i].ImageId @SourceSplat))
                    }
                }
			}

            if ($Wait)
            {
                while (($FinalAMIs | Where-Object {$_.ImageState -eq [Amazon.EC2.ImageState]::Available}).Count -ne $FinalAMIs.Count)
                {
                    Write-Verbose -Message "Waiting for final AMIs to finish creation"
                    Start-Sleep -Seconds 10

                    for ($i = 0; $i -lt $FinalAMIs.Count; $i++)
                    {
                        if ($FinalAMIs[$i].ImageState -ne [Amazon.EC2.ImageState]::Available)
                        {
                            $FinalAMIs[$i] = Get-EC2Image -ImageId $FinalAMIs[$i].ImageId @DestinationSplat
                        }
                    }

                    $BadAMIs = $FinalAMIs | Where-Object {$_.ImageState -in @([Amazon.EC2.ImageState]::Deregistered, [Amazon.EC2.ImageState]::Error, [Amazon.EC2.ImageState]::Failed, [Amazon.EC2.ImageState]::Invalid)}

                    if ($BadAMIs -ne $null -and $BadAMIs.Count -gt 0)
                    {
                        throw "There was an error creating new AMIs for the following Ids: $([System.String]::Join(",", ($BadAMIs | Select-Object -ExpandProperty ImageId)))"
                    }
                }
            }

			if ($CleanupSource)
			{
				Write-Verbose -Message "Deleting source EC2 instances."
				
                foreach ($Id in $SourceInstanceIdsToDelete)
				{
					Write-Verbose -Message "Deleting instance $Id."
					Set-EC2InstanceState -InstanceId $Id -State TERMINATE -Force @UtilSplat
				}

				Write-Verbose -Message "Deleting source AMIs."

				foreach ($Id in $SourceImageIdsToDeleteAtCleanup)
				{
					Write-Verbose -Message "Deleting AMI $Id."
					Unregister-EC2Image -ImageId $Id @SourceSplat
				}
			}

			Write-Output -InputObject $FinalAMIs
		}
	}

	End {
	}
}

Function Copy-EC2InstanceLaunchParameters {
    <#
        .SYNOPSIS
            Evaluates the characteristics of a currently running EC2 instance and creates a hashtable that can be used as a Splat for the New-EC2Instance cmdlet to create a clone of the source instance.

        .DESCRIPTION
            Evaluates the characteristics of a currently running EC2 instance and creates a hashtable that can be used as a Splat for the New-EC2Instance cmdlet to create a clone of the source instance. Because a number of things are duplicated, like IP addresses, you would need to terminate the source instance before using this to launch another instance.

            The image id is only included when you specify the parameter because the image Ids regularly change as the AMIs are updated.

            EIPs are not included as part of the launch data.

			Source/Destination Checking is not included as part of the Network Interface configuration, it cannot be set in a InstanceNetworkInterfaceSpecification object.

			The tag specification aggregates the tags for attached volumes and network interfaces. The resulting tag specification includes all tag keys

            The following attributes are included:
                - Affinity
                - PlacementGroup
                - HostId
				- Tenancy
				- AvailabilityZone
				- BlockDeviceMappings
                - CpuCredit
                - CpuOption
                - DisableApiTermination
                - EbsOptimized
                - ElasticGpuSpecification
	            - ImageId
                - InstanceInitiatedShutdownBehavior
				- InstanceMarketOption
                - InstanceProfile_Arn
				- InstanceType
                - KernelId
				- KeyName
                - Monitoring_Enabled
                - RamdiskId
                - TagSpecification
                - UserData
                - InstanceMarketOption
                - NetworkInterface

        .PARAMETER Instance
            The instance to get details about. The cmdlet may retrieve additional attributes about the specified instance.

        .PARAMETER IncludeImageId
            Includes the image id as part of the results.

		.PARAMETER MatchVolumeTagKey
			If this is specified, only Volume tags keys that are common (case-sensitive) across all volumes are included in the tag specification. The first tag value will be used as the value for all volume tags with that key.

		.PARAMETER MatchVolumeTagKeyAndValue
			When this is specified, only Volume tags where both the key and value (case-sensitive) match for all attached volumes are included in the tag specification. The setting overrides the MatchVolumeTagKey parameter.

		.PARAMETER MatchInterfaceTagKey
			If this is specified, only Interface tags keys that are common (case-sensitive) across all interfaces are included in the tag specification. The first tag value will be used as the value for all interface tags with that key.

		.PARAMETER MatchInterfaceTagKeyAndValue
			When this is specified, only Interface tags where both the key and value (case-sensitive) match for all attached interfaces are included in the tag specification. The setting overrides the MatchInterfaceTagKey parameter.

		.PARAMETER NoVolumeTags
			When specified, no volume tags are copied.

		.PARAMETER OnlyRootVolumeTags
			When specified, only the root volume tags are included in the tag specification.

		.PARAMETER NoInterfaceTags
			When specified, no interface tags are copied.

		.PARAMETER OnlyRootInterfaceTags
			When specified, only the root interface (eth0) tags are included in the tag specification.

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
			$Params = Copy-EC2InstanceLaunchParameters -Instance (Get-EC2Instance i-123456789012)

			Gets the parameters of the specified instance that can be used to launch a "clone" of that instance.

		.INPUTS
			Amazon.EC2.Model.Instance

		.OUTPUTS
			System.Collections.Hashtable

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/27/2019
    #>    
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = "Instance")]
        [ValidateNotNull()]
        [Amazon.EC2.Model.Instance]$Instance,

		[Parameter(Mandatory = $true, Position = 0, ParameterSetName ="InstanceId")]
		[ValidateNotNullOrEmpty()]
		[System.String]$InstanceId,

        [Parameter()]
        [Switch]$IncludeImageId,

		[Parameter()]
		[Switch]$MatchVolumeTagKey,

		[Parameter()]
		[Switch]$MatchVolumeTagKeyAndValue,

		[Parameter()]
		[Switch]$MatchInterfaceTagKey,

		[Parameter()]
		[Switch]$MatchInterfaceTagKeyAndValue,

		[Parameter()]
		[Switch]$NoVolumeTags,

		[Parameter()]
		[Switch]$OnlyRootVolumeTags,

		[Parameter()]
		[Switch]$NoInterfaceTags,

		[Parameter()]
		[Switch]$OnlyRootInterfaceTags,

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

		if ($PSCmdlet.ParameterSetName -eq "InstanceId")
		{
			$Instance = Get-EC2InstanceByNameOrId -InstanceId $InstanceId @AwsUtilitiesSplat

			if ($Instance -eq $null)
			{
				throw "Could not find an instance with id $InstanceId. Make sure you have specified the correct region and credentials."
			}
		}

        # Build the optional parameters for New-EC2Instance
		[System.Collections.Hashtable]$NewInstanceSplat = @{}

		# Copy placement info for affinity, placement group, and host id
		if (-not [System.String]::IsNullOrEmpty($Instance.Placement.Affinity))
		{
			$NewInstanceSplat.Add("Affinity", $Instance.Placement.Affinity)
		}

		if (-not [System.String]::IsNullOrEmpty($Instance.Placement.GroupName))
		{
			$NewInstanceSplat.Add("PlacementGroup", $Instance.Placement.GroupName)
		}

		if (-not [System.String]::IsNullOrEmpty($Instance.Placement.HostId))
		{
			$NewInstanceSplat.Add("HostId", $Instance.Placement.HostId)
		}

		# Tenancy
		$NewInstanceSplat.Add("Tenancy", $Instance.Placement.Tenancy)

		# AZ
		$NewInstanceSplat.Add("AvailabilityZone", $Instance.Placement.AvailabilityZone)

        # This checks for the cpu credit specification for T3 instances
        if ($Instance.InstanceType.Value -ilike "t2*" -or $Instance.InstanceType.Value -ilike "t3*")
        {
            [Amazon.EC2.Model.InstanceCreditSpecification]$CreditSpec = Get-EC2CreditSpecification -InstanceId $Instance.InstanceId @Splat

            $NewInstanceSplat.Add("CpuCredit", $CreditSpec.CpuCredits)
        }

        # This checks to see if a specific CPU configuration was specified
        if ($Instance.CpuOptions -ne $null -and $Instance.InstanceType.Value -inotlike "t2*" -and $Instance.InstanceType.Value -inotlike "t3*")
        {
            [Amazon.EC2.Model.CpuOptionsRequest]$CpuOptionsRequest = New-Object -TypeName Amazon.EC2.Model.CpuOptionsRequest
            $CpuOptionsRequest.CoreCount = $Instance.CpuOptions.CoreCount
            $CpuOptionsRequest.ThreadsPerCore = $Instance.CpuOptions.ThreadsPerCore

            $NewInstanceSplat.Add("CpuOption", $CpuOptionsRequest)
        }

        # Checks for Disabling API Termination
        [Amazon.EC2.Model.InstanceAttribute]$DisableApiTerminationAttr = Get-EC2InstanceAttribute -InstanceId $Instance.InstanceId -Attribute disableApiTermination @Splat

        if ($DisableApiTerminationAttr.DisableApiTermination -eq $true)
        {
            $NewInstanceSplat.Add("DisableApiTermination", $true)
        }

        # Checks for EBS optimization
		if ($Instance.EbsOptimized -eq $true)
		{
			$NewInstanceSplat.Add("EbsOptimized", $true)
		}

        # Elastic GPUs
        if ($Instance.ElasticGpuAssociations -ne $null -and $Instance.ElasticGpuAssociations.Count -gt 0)
        {
            [Amazon.EC2.Model.ElasticGpuSpecification[]]$Specifications = @()

            foreach ($Association in $Instance.ElasticGpuAssociations)
            {
                [Amazon.EC2.Model.ElasticGpuAssociation]$Association = ""
                [Amazon.EC2.Model.ElasticGpuSpecification]$Spec = New-Object -TypeName Amazon.EC2.Model.ElasticGpuSpecification
                [Amazon.EC2.Model.ElasticGpus]$Gpu = Get-EC2ElasticGpu -ElasticGpuId $Association.ElasticGpuId @Splat
                $Spec.Type = $Gpu.ElasticGpuType
                $Specifications += $Spec
            }

            $NewInstanceSplat.Add("ElasticGpuSpecification", $Specifications)
        }

        # If specified, include the image id
        if ($IncludeImageId)
        {
            $NewInstanceSplat.Add("ImageId", $Instance.ImageId)
        }

        # Checks for shutdown behavior, can be "", stop, or terminate
        [Amazon.EC2.Model.InstanceAttribute]$ShutdownBehaviorAttr = Get-EC2InstanceAttribute -InstanceId $Instance.InstanceId -Attribute instanceInitiatedShutdownBehavior @Splat

        if (-not [System.String]::IsNullOrEmpty($ShutdownBehaviorAttr.InstanceInitiatedShutdownBehavior))
        {
            $NewInstanceSplat.Add("InstanceInitiatedShutdownBehavior", $ShutdownBehaviorAttr.InstanceInitiatedShutdownBehavior)
        }

        # Specifies the same IAM instance profile, if present
        if ($Instance.IamInstanceProfile -ne $null -and -not [System.String]::IsNullOrEmpty($Instance.IamInstanceProfile.Arn))
        {
            $NewInstanceSplat.Add("InstanceProfile_Arn", $Instance.IamInstanceProfile.Arn)
        }

		$NewInstanceSplat.Add("InstanceType", $Instance.InstanceType)

        # Checks KernelId
        if (-not [System.String]::IsNullOrEmpty($Instance.KernelId))
        {
            $NewInstanceSplat.Add("KernelId", $Instance.KernelId)
        }

		# Get KeyName
		if (-not [System.String]::IsNullOrEmpty($Instance.KeyName))
		{
			$NewInstanceSplat.Add("KeyName", $Instance.KeyName)
		}

        # This specifies if detailed monitoring is enabled
		if ($Instance.Monitoring.State -eq [Amazon.EC2.MonitoringState]::Enabled -or $Instance.Monitoring.State -eq [Amazon.EC2.MonitoringState]::Pending)
		{
			$NewInstanceSplat.Add("Monitoring_Enabled", $true)
		}

        # Checks for the Ram disk id
        if (-not [System.String]::IsNullOrEmpty($Instance.RamdiskId))
        {
            $NewInstanceSplat.Add("RamdiskId", $Instance.RamdiskId)
        }

        # Check for presence of userdata
        [Amazon.EC2.Model.InstanceAttribute]$UserDataAttr = Get-EC2InstanceAttribute -InstanceId $Instance.InstanceId -Attribute userData @Splat

        if (-not [System.String]::IsNullOrEmpty($UserDataAttr.UserData))
        {
            $NewInstanceSplat.Add("UserData", $UserDataAttr.UserData)
        }

        # Use this to help determine how to request the instance
        if ($Instance.InstanceLifecycle -ne $null -and -not [System.String]::IsNullOrEmpty($Instance.InstanceLifecycle.Value))
		{
			switch ($Instance.InstanceLifecycle) {
                ([Amazon.EC2.InstanceLifecycleType]::Scheduled) {
                    # Probably do nothing since the launch template would need to be updated, not the actual instance
                    Write-Warning -Message "This is a scheduled instance, you should update the launch template instead of the instance."
                    break
                }
                ([Amazon.EC2.InstanceLifecycleType]::Spot) {
                    [Amazon.EC2.Model.InstanceMarketOptionsRequest]$MarketRequest = New-Object -TypeName Amazon.EC2.Model.InstanceMarketOptionsRequest
                    $MarketRequest.MarketType = [Amazon.EC2.MarketType]::Spot
                    $MarketRequest.SpotOptions = New-Object -TypeName Amazon.EC2.Model.SpotMarketOptions

					[Amazon.EC2.Model.SpotInstanceRequest]$SpotRequest = Get-EC2SpotInstanceRequest -SpotInstanceRequestId $Instance.SpotInstanceRequestId @Splat

					if ($SpotRequest.BlockDurationMinutes -gt 0)
					{
						$MarketRequest.SpotOptions.BlockDurationMinutes = $SpotRequest.BlockDurationMinutes
					}

					$MarketRequest.SpotOptions.InstanceInterruptionBehavior = $SpotRequest.InstanceInterruptionBehavior
					$MarketRequest.SpotOptions.MaxPrice = $SpotRequest.SpotPrice
					$MarketRequest.SpotOptions.SpotInstanceType = $SpotRequest.Type

					if ($SpotRequest.ValidUntil -gt [System.DateTime]::MinValue)
					{
						$MarketRequest.SpotOptions.ValidUntilUtc = $SpotRequest.ValidUntil.ToUniversalTime()
					}

                    $NewInstanceSplat.Add("InstanceMarketOption", $MarketRequest)

                    break
                }
                default {
                    # Do nothing
                    break
                }
            }
		} 

		##### Do all network interface stuff here

		[Amazon.EC2.Model.InstanceNetworkInterfaceSpecification[]]$NetworkInterfaceSpecifications = @()

		# Track interfaces for use later in tagging
		[Amazon.EC2.Model.NetworkInterface[]]$Interfaces = @()

		foreach ($InstanceInterface in $Instance.NetworkInterfaces)
		{
			[Amazon.EC2.Model.InstanceNetworkInterface]$InstanceInterface= $InstanceInterface
			[Amazon.EC2.Model.NetworkInterface]$Interface = Get-EC2NetworkInterface -NetworkInterfaceId $InstanceInterface.NetworkInterfaceId @Splat

			$Interfaces += $Interface

			[Amazon.EC2.Model.InstanceNetworkInterfaceSpecification]$Spec = New-Object -TypeName Amazon.EC2.Model.InstanceNetworkInterfaceSpecification
			
			if ($Interface.Association -ne $null)
			{
				$Spec.AssociatePublicIpAddress = $true
			}

			$Spec.DeleteOnTermination = $Interface.Attachment.DeleteOnTermination

			if (-not [System.String]::IsNullOrEmpty($Interface.Description))
			{
				$Spec.Description = $Interface.Description
			}

			$Spec.DeviceIndex = $Interface.Attachment.DeviceIndex

			$Spec.Groups = $Interface.Groups | Select-Object -ExpandProperty GroupId

			if ($Interface.Ipv6Addresses -ne $null -and $Interface.Ipv6Addresses.Count -gt 0)
			{
				[Amazon.EC2.Model.InstanceIpv6Address[]]$Addresses = @()
				foreach ($IPv6 in $Interface.Ipv6Addresses)
				{
					[Amazon.EC2.Model.InstanceIpv6Address]$Address = New-Object -TypeName Amazon.EC2.Model.InstanceIpv6Address
					$Address.Ipv6Address = $IPv6
					$Addresses += $Address
				}

				$Spec.Ipv6Addresses = $Addresses
			}

			[Amazon.EC2.Model.PrivateIpAddressSpecification[]]$PrivateIPs = @()

			foreach ($IP in $Interface.PrivateIpAddresses)
			{
				[Amazon.EC2.Model.NetworkInterfacePrivateIpAddress]$IP = $IP
				[Amazon.EC2.Model.PrivateIpAddressSpecification]$PrivateIp = New-Object -TypeName Amazon.EC2.Model.PrivateIpAddressSpecification
				$PrivateIp.Primary = $IP.Primary
				$PrivateIp.PrivateIpAddress = $IP.PrivateIpAddress

				$PrivateIPs += $PrivateIp
			}

			$Spec.PrivateIpAddresses = $PrivateIPs

			$Spec.SubnetId = $Interface.SubnetId

			$NetworkInterfaceSpecifications += $Spec
		}

		$NewInstanceSplat.Add("NetworkInterface", $NetworkInterfaceSpecifications)

		#### Do all block device stuff here

		[Amazon.EC2.Model.BlockDeviceMapping[]]$BlockDevices = @()

		# Track volumes for use later in tagging
		[Amazon.EC2.Model.Volume[]]$Volumes = @()

		foreach ($Device in $Instance.BlockDeviceMappings)
		{
			[Amazon.EC2.Model.InstanceBlockDeviceMapping]$Device = $Device
			[Amazon.EC2.Model.EbsInstanceBlockDevice]$Ebs = $Device.Ebs

			if ($Ebs -ne $null)
			{
				[Amazon.EC2.Model.BlockDeviceMapping]$BDM = New-Object -TypeName Amazon.EC2.Model.BlockDeviceMapping
				$BDM.Ebs = New-Object -TypeName Amazon.EC2.Model.EbsBlockDevice

				$BDM.DeviceName = $Device.DeviceName

				[Amazon.EC2.Model.Volume]$Volume = Get-EC2Volume -VolumeId $Ebs.VolumeId @Splat
				$Volumes += $Volume

				$BDM.Ebs.DeleteOnTermination = $Ebs.DeleteOnTermination
				$BDM.Ebs.Encrypted = $Volume.Encrypted
				$BDM.Ebs.VolumeType = $Volume.VolumeType

				if ($Volume.VolumeType -eq [Amazon.EC2.VolumeType]::Io1)
				{
					$BDM.Ebs.Iops = $Volume.Iops
				}

				if (-not [System.String]::IsNullOrEmpty($Volume.KmsKeyId))
				{
					$BDM.Ebs.KmsKeyId = $Volume.KmsKeyId
				}
				
				$BDM.Ebs.VolumeSize = $Volume.Size

				if (-not [System.String]::IsNullOrEmpty($Volume.SnapshotId))
				{
					$BDM.Ebs.SnapshotId = $Volume.SnapshotId
				}

				$BlockDevices += $BDM	
			}		
		}

		if ($BlockDevices.Count -gt 0)
		{
			$NewInstanceSplat.Add("BlockDeviceMapping", $BlockDevices)
		}

		##### TAGGING

		[Amazon.EC2.Model.TagSpecification[]]$TagSpecification = @()

		# Instance Tags
		if ($Instance.Tags.Count -gt 0)
		{
			# Instance Tags
			[Amazon.EC2.Model.TagSpecification]$InstanceTags = New-Object -TypeName Amazon.EC2.Model.TagSpecification

			$InstanceTags.ResourceType = [Amazon.EC2.ResourceType]::Instance

			$InstanceTags.Tags = $Instance.Tags

			$TagSpecification += $InstanceTags
		}

		# Volume Tags
		if ($Volumes.Count -gt 0 -and -not $NoVolumeTags)
		{
			[Amazon.EC2.Model.TagSpecification]$VolumeTags = New-Object -TypeName Amazon.EC2.Model.TagSpecification

			$VolumeTags.ResourceType = [Amazon.EC2.ResourceType]::Volume

			[System.Collections.Generic.Dictionary[System.String, Amazon.EC2.Model.Tag]]$VolumeTagDictionary = New-Object -TypeName "System.Collections.Generic.Dictionary[System.String, Amazon.EC2.Model.Tag]"

			# If there's only 1 volume, then it's easy
			if ($OnlyRootVolumeTags)
			{
				$VolumeTags.Tags = $Volumes | Where-Object {$_.Attachments[0].Device -eq $Instance.RootDeviceName } | Select-Object -ExpandProperty Tags
			}
			elseif ($Volumes.Count -eq 1)
			{
				$VolumeTags.Tags = $Volumes[0].Tags			
			}
			else
			{
				if ($MatchVolumeTagKeyAndValue)
				{
					foreach ($Tag in $Volumes[0].Tags)
					{
						$Counter = 1

						for ($i = 1; $i -lt $Volumes.Count; $i++)
						{
							foreach ($SubTag in $Volumes[$i].Tags)
							{
								# Make sure to use case-sensitive comparison
								if ($SubTag.Key -eq $Tag.Key -and $SubTag.Value -eq $Tag.Value)
								{
									$Counter++
									break
								}
							}
						}

						if ($Counter -eq $Volumes.Count)
						{
							$VolumeTagDictionary.Add($Tag.Key, $Tag)
						}
					}
				}
				elseif($MatchVolumeTagKey)
				{
					foreach ($Tag in $Volumes[0].Tags)
					{
						$AllHaveTag = $true

						for ($i = 1; $i -lt $Volumes.Count; $i++)
						{
							# Make sure to use case-sensitive comparison
							if (($Volumes[$i].Tags | Select-Object -ExpandProperty Key) -notcontains $Tag.Key)
							{
								$AllHaveTag = $false
								break
							}
						}

						if ($AllHaveTag)
						{
							$VolumeTagDictionary.Add($Tag.Key, $Tag)
						}
					}
				}
				else
				{
					foreach ($Volume in $Volumes)
					{
						foreach ($Tag in $Volume.Tags)
						{
							if (-not $VolumeTagDictionary.ContainsKey($Tag.Key))
							{
								$VolumeTagDictionary.Add($Tag.Key, $Tag)
							}
						}
					}
				}

				if ($VolumeTagDictionary.Count -gt 0)
				{
					$VolumeTags.Tags = $VolumeTagDictionary.Values
					$TagSpecification += $VolumeTags
				}
			}
		}
		
		# Network Interface Tags
		if ($Interfaces.Count -gt 0 -and -not $NoInterfaceTags)
		{
			[Amazon.EC2.Model.TagSpecification]$InterfaceTags = New-Object -TypeName Amazon.EC2.Model.TagSpecification

			$InterfaceTags.ResourceType = [Amazon.EC2.ResourceType]::NetworkInterface

			[System.Collections.Generic.Dictionary[System.String, Amazon.EC2.Model.Tag]]$InterfaceTagDictionary = New-Object -TypeName "System.Collections.Generic.Dictionary[System.String, Amazon.EC2.Model.Tag]"

			# If there's only 1 interface, then it's easy
			if ($OnlyRootInterfaceTags)
			{
				$InterfaceTags.Tags = $Interfaces | Where-Object {$_.Attachment.DeviceIndex -eq 0} | Select-Object -First 1 | Select-Object -ExpandProperty TagSet
			}
			elseif ($Interfaces.Count -eq 1)
			{
				$InterfaceTags.Tags = $Interfaces[0].TagSet
			}
			else
			{
				# Otherwise, there's more than 1 and we need to perform additional checks
				if ($MatchInterfaceTagKeyAndValue)
				{
					foreach ($Tag in $Interfaces[0].TagSet)
					{
						$Counter = 1

						for ($i = 1; $i -lt $Interfaces.Count; $i++)
						{
							foreach ($SubTag in $Interfaces[$i].TagSet)
							{
								# Make sure to use case-sensitive comparison
								if ($SubTag.Key -eq $Tag.Key -and $SubTag.Value -eq $Tag.Value)
								{
									$Counter++
									break
								}
							}
						}

						if ($Counter -eq $Interfaces.Count)
						{
							$InterfaceTagDictionary.Add($Tag.Key, $Tag)
						}
					}
				}
				elseif($MatchInterfaceTagKey)
				{
					foreach ($Tag in $Interfaces[0].TagSet)
					{
						$AllHaveTag = $true

						for ($i = 1; $i -lt $Interfaces.Count; $i++)
						{
							# Make sure to use case-sensitive comparison
							if (($Interfaces[$i].TagSet | Select-Object -ExpandProperty Key) -notcontains $Tag.Key)
							{
								$AllHaveTag = $false
								break
							}
						}

						if ($AllHaveTag)
						{
							$InterfaceTagDictionary.Add($Tag.Key, $Tag)
						}
					}
				}
				else
				{
					foreach ($Interface in $Interfaces)
					{
						foreach ($Tag in $Interface.TagSet)
						{
							if (-not $InterfaceTagDictionary.ContainsKey($Tag.Key))
							{
								$InterfaceTagDictionary.Add($Tag.Key, $Tag)
							}
						}
					}		
				}

				if ($InterfaceTagDictionary.Count -gt 0)
				{
					$InterfaceTags.Tags = $InterfaceTagDictionary.Values

					$TagSpecification += $InterfaceTags
				}
			}	
		}

		if ($TagSpecification.Count -gt 0)
		{
			$NewInstanceSplat.Add("TagSpecification", $TagSpecification)
		}

		#### Write Output to Pipeline

        Write-Output -InputObject $NewInstanceSplat      
    }

    End {
    }
}

Function Dismount-EC2InstanceNetworkInterfaces {
	<#
		.SYNOPSIS
			Dismounts either specific or all network interfaces (except eth0) from a single EC2 instance.

		.DESCRIPTION
			The cmdlet dismounts network interfaces from an EC2 instance. If you specify specific network interface Ids, just these will be dismounted from the instance, otherwise all network interfaces, except eth0, will attempt to be dismounted. 

		.PARAMETER InstanceId
			The Id of the instance to dismount network interfaces from.  

		.PARAMETER Instance
			The instance object to dismount network interfaces from.

		.PARAMETER NetworkInterfaceId
			The Ids of the network interfaces to dismount from the specified instance. If this parameter is not specified, all network interfaces, except eth0, are dismounted.

		.PARAMETER Wait
			This will wait for the network interfaces to finish being dismounted and enter the available state.

        .PARAMETER ForceDismount
            Forces the dismount of the interface.

		.PARAMETER Delete
			The network interfaces will be deleted after they are dismounted. If you specify this parameter, the Wait parameter is automatically specified.

		.PARAMETER Timeout
			The amount of time to wait in seconds for the operation to complete before it is considered unsuccessful. Defaults to 600.

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
			$Instance = Get-EC2Instance -InstanceId i-09740780dc39bde98 | Select-Object -ExpandProperty Instances -First 1
			Dismount-EC2InstanceNetworkInterfaces -Instance $Instance -Wait

			All network interfaces, except eth0, are dismounted from the instance. The cmdlet waits for the itnerfaces to enter the available state indicating the dismount operation succeeded.

		.EXAMPLE
			$Instance = Get-EC2Instance -InstanceId i-09740780dc39bde98 | Select-Object -ExpandProperty Instances -First 1
			Dismount-EC2InstanceNetworkInterfaces -InstanceId $Instance.InstanceId -NetworkInterfaceId @("eni-0aa65525bf363acfe") -Wait

			The specified ENI is dismounted from the indicated instance. The cmdlet waits for the interface to become available before returning.

		.EXAMPLE
			$Instance = Get-EC2Instance -InstanceId i-09740780dc39bde98 | Select-Object -ExpandProperty Instances -First 1
			Dismount-EC2InstanceNetworkInterfaces -Instance $Instance -Delete

			All network interfaces, except eth0, are dismounted from the instance. Once the interfaces enter an available state, they are deleted. The cmdlet does not wait for the delete operation to complete.

		.INPUTS
			None or Amazon.EC2.Model.Instance

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

			The output contains the network interface id and the device index the interface was attached to on the instance. For example:

			@(
				[PSCustomObject]@{ "NetworkInterfaceId" = "eni-0aa65525bf363acfe"; "DeviceIndex" = "1" },
				[PSCustomObject]@{ "NetworkInterfaceId" = "eni-03eaea54d02ec33dc"; "DeviceIndex" = "2" }
			)

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/30/2019
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = [System.Management.Automation.ConfirmImpact]::Medium)]
	[OutputType([PSCustomObject[]])]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "InstanceId")]
        [ValidateNotNullOrEmpty()]
        [System.String]$InstanceId,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = "Instance")]
        [ValidateNotNull()]
        [Amazon.EC2.Model.Instance]$Instance,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String[]]$NetworkInterfaceId = @(),

        [Parameter()]
        [Switch]$Wait,

		[Parameter()]
		[Switch]$Delete,

        [Parameter()]
        [Switch]$ForceDismount,

		[Parameter()]
		[Switch]$Force,

        [Parameter()]
        [ValidateRange(1, [System.Int32]::MaxValue)]
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
		[System.Boolean]$YesToAll = $false
		[System.Boolean]$NoToAll = $false
    }

    Process {
        [System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		[System.Collections.Hashtable]$AwsUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $Splat

        [System.Collections.Generic.Queue[Amazon.EC2.Model.NetworkInterface]]$InterfacesToDetach = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.NetworkInterface]
        [System.Collections.Generic.Dictionary[System.String, System.String]]$TrackedInterfaces = New-Object -TypeName "System.Collections.Generic.Dictionary[System.String, System.String]"
        [PSCustomObject[]]$DetachedInterfaces = @()

        if ($PSCmdlet.ParameterSetName -eq "InstanceId")
        {
            $Instance = Get-EC2InstanceByNameOrId -InstanceId $InstanceId @AwsUtilitiesSplat

            if ($Instance -eq $null)
            {
                throw "Could not find an instance with id $InstanceId."
            }
        }

		# The instance is terminated or in the process of termination 
        if ($Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::Terminated -or $Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::ShuttingDown)
        {
            throw "This cmdlet cannot be used on an instance that is terminating or terminated."
        }

		# This will make sure the block device mappings are populated for a pending instance before tracking the volumes
		if($Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::Pending -and $Instance.NetworkInterfaces -eq $null -or $Instance.NetworkInterfaces.Count -eq 0)
		{
			Write-Verbose -Message "Waiting for instance to populate network interfaces during pending state."
			Start-Sleep -Seconds 5
            $Instance = Get-EC2InstanceByNameOrId -InstanceId $Instance.InstanceId @AwsUtilitiesSplat
		}

		[Amazon.EC2.Model.InstanceNetworkInterface[]]$Interfaces = $Instance.NetworkInterfaces | Where-Object { $_.Attachment.DeviceIndex -ne 0 }

        # Do this first so that we don't lose any data
        # Check to see if the user passed network interface Ids, and if they didn't make sure the instance has actual network interfaces
        # It's possible the user passes in a stopped instance that already has all block devices removed
        if ($NetworkInterfaceId -eq $null -or $NetworkInterfaceId.Count -eq 0 -and $Interfaces -ne $null -and $Interfaces.Count -gt 0)
        {
            $NetworkInterfaceId = $Interfaces | Select-Object -ExpandProperty NetworkInterfaceId
            
            foreach ($Interface in $Interfaces)
            { 
                $TrackedInterfaces.Add($Interface.NetworkInterfaceId, $Interface.Attachment.DeviceIndex)
            } 
        }
		else
		{
			# Make sure the user provided volume Ids are attached to the specified instance

			[System.String[]]$AttachedInterfaceIds = $Interfaces | Select-Object -ExpandProperty NetworkInterfaceId
			
			foreach ($Interface in $NetworkInterfaceId)
			{
				if ($Interface -inotin $AttachedInterfaceIds)	
				{
					throw "A provided interface, $Interface, is not one of the attached interfaces for instance $($Instance.InstanceId): $([System.String]::Join(",", $AttachedInterfaceIds))."
				}
			}
		}

		# Cannot remove volumes from a pending instance, make sure the instance leaves pending
		while ($Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::Pending)
		{
			Write-Verbose -Message "Waiting for instance to reaching a running state."
			Start-Sleep -Seconds 5
            $Instance = Get-EC2InstanceByNameOrId -InstanceId $Instance.InstanceId @AwsUtilitiesSplat
		}

        # It's possible the instance description was not returned with the interface data if the instance
        # was recently launched, wait to get that data, there will always be at least 1 interface
        while ($Instance -ne $null -and 
            $Instance.State.Name -notin @([Amazon.EC2.InstanceStateName]::ShuttingDown,[Amazon.EC2.InstanceStateName]::Terminated) -and 
            $Instance.NetworkInterfaces -eq $null -or $Instance.NetworkInterfaces.Count -eq 0)
        {
            Write-Verbose -Message "Waiting for network interface data in the instance object to be returned, instance $($Instance.InstanceId) is currently $($Instance.State.Name)."
            Start-Sleep -Seconds 5
            $Instance = Get-EC2InstanceByNameOrId -InstanceId $Instance.InstanceId @AwsUtilitiesSplat
        }

        if ($NetworkInterfaceId -ne $null -and $NetworkInterfaceId.Count -gt 0)
        {
		    $VerboseDescription = "Dismount network interfaces $([System.String]::Join(",", $NetworkInterfaceId)) from instance $($Instance.InstanceId)"
		    $VerboseWarning = "Are you sure you want dismount network interfaces $([System.String]::Join(",", $NetworkInterfaceId)) from $($Instance.InstanceId)?"
		    $Caption = "Dismount Network Interfaces"

		    if ($PSCmdlet.ShouldProcess($VerboseDescription, $VerboseWarning, $Caption))
		    {
                [System.Collections.Hashtable]$IntSplat = @{}
                if ($ForceDismount)
                {
                    $IntSplat.Add("ForceDismount", $true)
                }

			    foreach ($Id in $NetworkInterfaceId)
			    {
				    $Query = "Dismount network interface $Id from instance $($Instance.InstanceId)?"
				    $Caption = "Dismount Network Interface"

				    if ($Force -or $PSCmdlet.ShouldContinue($Query, $Caption, [ref]$YesToAll, [ref]$NoToAll))
				    {
					    [Amazon.EC2.Model.NetworkInterface]$Interface = Get-EC2NetworkInterface -NetworkInterfaceId $Id @Splat

                        # If the interface is attached, then proceed with dismounting it
                        if ($Interface.Attachment -ne $null -and -not [System.String]::IsNullOrEmpty($Interface.Attachment.AttachmentId))
                        {
					        $InterfacesToDetach.Enqueue($Interface)

					        Write-Verbose -Message "Dismounting interface $($Interface.NetworkInterfaceId) at device index $($Interface.Attachment.DeviceIndex) from the instance."				
					        Dismount-EC2NetworkInterface -AttachmentId $Interface.Attachment.AttachmentId @Splat @IntSplat | Out-Null	

                            # May have already been added previously, but if not, then add it, we know it has attachment data
                            if (-not $TrackedInterfaces.ContainsKey($Interface.NetworkInterfaceId))
                            {
					            $TrackedInterfaces.Add($Interface.NetworkInterfaceId, $Interface.Attachment.DeviceIndex)
                            }		
                        }
                        else
                        {
                            Write-Verbose -Message "It appears that interface $Id became dismounted during the cmdlet operation, the DescribeNetworkInterfaces API did not return Attachment data, its device index may not be tracked."
                            
                            # If it's not attached, and we haven't already added it, write a verbose message and add it with a -1 index
                            if (-not $TrackedInterfaces.ContainsKey($Interface.NetworkInterfaceId))
                            {
                                $TrackedInterfaces.Add($Interface.NetworkInterfaceId, -1)
                            }
                        }
				    }
			    }

			    $YesToAll = $false
			    $NoToAll = $false

			    if ($Wait -or $Delete)
			    {
				    [System.Diagnostics.Stopwatch]$SW = [System.Diagnostics.Stopwatch]::StartNew()

				    while ($InterfacesToDetach.Count -gt 0 -and $SW.Elapsed.TotalSeconds -le $Timeout)
				    {
					    [Amazon.EC2.Model.NetworkInterface]$Interface = $InterfacesToDetach.Dequeue()

					    switch ($Interface.Status)
					    {
						    ([Amazon.EC2.NetworkInterfaceStatus]::Available) {
							    Write-Verbose -Message "Successfully detached interface $($Interface.NetworkInterfaceId) from $($Instance.InstanceId)."     
                        
							    if ($Delete)
							    {
								    Write-Verbose -Message "Deleting interface $($Interface.NetworkInterfaceId)"

								    $Query = "Permanently delete Network Interface $($Interface.NetworkInterfaceId)?"
								    $Caption = "Delete Network Interface"

								    if ($Force -or $PSCmdlet.ShouldContinue($Query, $Caption, [ref]$YesToAll, [ref]$NoToAll))
								    {
									    Remove-EC2NetworkInterface -NetworkInterfaceId $Interface.NetworkInterfaceId -Force @Splat | Out-Null
								    }
							    }
                                     
							    break
						    }
						    {$_ -in @([Amazon.EC2.NetworkInterfaceStatus]::InUse, [Amazon.EC2.NetworkInterfaceStatus]::Detaching) } {
							    # Keep waiting
							    $InterfacesToDetach.Enqueue($Interface)
							    break
						    }
						    {$_ -in @([Amazon.EC2.NetworkInterfaceStatus]::Associated, [Amazon.EC2.NetworkInterfaceStatus]::Attaching) } {
							    throw "Invalid state for interface $($Interface.NetworkInterfaceId): $($Interface.Status)."
						    }
						    default {
							    throw "Unknown interface state $($Interface.Status) for interface $($Interface.NetworkInterfaceId)."
						    }
					    }

					    # Only update the interface list if all of them are not available
					    if ($InterfacesToDetach.Count -gt 0 -and ($InterfacesToDetach | Where-Object { $_.Status -ne [Amazon.EC2.NetworkInterfaceStatus]::Available}).Count -eq $InterfacesToDetach.Count)
					    {
						    Write-Verbose -Message "Waiting for interfaces to finish detaching."
						    Start-Sleep -Seconds 10

						    $Arr = $InterfacesToDetach.ToArray()

						    $InterfacesToDetach = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.NetworkInterface]

						    for ($i = 0; $i -lt $Arr.Length; $i++)
						    {
							    $InterfacesToDetach.Enqueue((Get-EC2NetworkInterface -NetworkInterfaceId $Interface.NetworkInterfaceId @Splat))
						    }
					    }
				    }

				    $SW.Stop()

				    if ($SW.Elapsed.TotalSeconds -gt $Timeout -and $InterfacesToDetach.Count -gt 0)
				    {
					    throw "Timeout occured waiting for interfaces to finish being dismounted. Did not finish dismounting interfaces $([System.String]::Join(",", ($InterfacesToDetach | Select-Object -ExpandProperty NetworkInterfaceId)))."
				    }
			    }

                foreach ($Key in $TrackedInterfaces.Keys)
                {
                    $DetachedInterfaces += [PSCustomObject]@{"NetworkInterfaceId" = $Key; "DeviceIndex" = $TrackedInterfaces[$Key]}
                }

			    Write-Output -InputObject $DetachedInterfaces
		    }
        }
        else
        {
            Write-Verbose -Message "No interfaces to detach."
            Write-Output -InputObject $DetachedInterfaces
        }
    }

    End {
    }
}

Function Invoke-EC2NetworkInterfaceAttachmentWait {
    <#
        .SYNOPSIS 
            Waits for a specified set of volumes to reach an attached state.

        .DESCRIPTION
            The cmdlet waits for a specified set of volumes to be in-use and attached to an EC2 instance.

        .PARAMETER NetworkInterface
            The network interface(s) to wait to become attached.

        .PARAMETER NetworkInterfaceId
            The network interface Id(s) to wait to become attached.

        .PARAMETER Timeout
            The amount of time in seconds to wait before the cmdlet fails. Defaults to 600.

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
            Invoke-EC2NetworkInterfaceAttachmentWait -NetworkInterfaceId @("eni-0f8d10b5ca8259a17", "eni-03fa72bf6ed7c2ed3")

            This waits for the two specified network interfaces to be in use and attached to an instance.

        .INPUTS
            Amazon.EC2.Model.NetworkInterface[]

        .OUTPUTS
            None

        .NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/30/2019
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "NetworkInterfaceId")]
        [ValidateNotNullOrEmpty()]
        [System.String[]]$NetworkInterfaceId,

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = "NetworkInterface")]
        [ValidateNotNullOrEmpty()]
        [Amazon.EC2.Model.NetworkInterface[]]$NetworkInterface,

        [Parameter()]
        [ValidateRange(1, [System.Int32]::MaxValue)]
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
		if ($PSCmdlet.ParameterSetName -eq "NetworkInterface")
        {
            $NetworkInterfaceId = $NetworkInterface | Select-Object -ExpandProperty NetworkInterfaceId
        }
    }

    Process {
        [System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		[System.Collections.Hashtable]$AwsUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $Splat

        # Use "," trick to preven the array from being unrolled
        [System.Collections.Generic.Queue[System.String]]$ENIQueue = New-Object -TypeName System.Collections.Generic.Queue[System.String] -ArgumentList (,$NetworkInterfaceId)

        [System.Diagnostics.Stopwatch]$SW = [System.Diagnostics.Stopwatch]::StartNew()

        # Track the source volumes that are now attached to the new instance to make sure they finish attaching
        while ($ENIQueue.Count -gt 0 -and $SW.Elapsed.TotalSeconds -le $Timeout)
        {
            [System.String]$Id = $ENIQueue.Dequeue()
            [Amazon.EC2.Model.NetworkInterface]$Interface = Get-EC2NetworkInterface -NetworkInterfaceId $Id @Splat

            switch ($Interface.Status)
            {
                ([Amazon.EC2.NetworkInterfaceStatus]::InUse) {
                    Write-Verbose -Message "ENI $($Interface.NetworkInterfaceId) is attached to $($Interface.Attachment.InstanceId)."
                    break
                }
                { $_ -in @([Amazon.EC2.NetworkInterfaceStatus]::Attaching, [Amazon.EC2.NetworkInterfaceStatus]::Available) } {                  
                    $ENIQueue.Enqueue($Id)
                    break
                }
                {$_ -in @([Amazon.EC2.NetworkInterfaceStatus]::Associated, [Amazon.EC2.NetworkInterfaceStatus]::Detaching) } {
                    throw "The interface $($Interface.NetworkInterfaceId) is not in an expected state to be waited on for attachment."
                }
                default {
                    throw "Unknown interface state $($Interface.Status) for interface $($Interface.NetworkInterfaceId)."
                }
            }

            if (($ENIQueue | Where-Object { $_.Status -ne [Amazon.EC2.NetworkInterfaceStatus]::InUse }).Count -gt 0)
            {
                Write-Verbose -Message "Waiting for interfaces to finish attaching."
                Start-Sleep -Seconds 10
            }
        }

        $SW.Stop()

        if ($SW.Elapsed.TotalSeconds -gt $Timeout)
        {
            throw "Timeout waiting for all interfaces to finish attaching."
        }
    }

    End {
    }
}

Function Update-EC2InstanceImageId {
	<#
		.SYNOPSIS
			Changes the AMI id of a currently launched instance.

		.DESCRIPTION
			The cmdlet stops the source EC2 instance, detaches its EBS volumes and ENIs (except eth0), terminates the instance, launches a new EC2 instance with the specified AMI id and any configuration items like sriovsupport enabled, stops it, deletes its EBS volumes, attaches the source volumes and ENIs, and restarts the new EC2 instance.

		.PARAMETER InstanceId
			The id of the instance to update. 

		.PARAMETER InstanceName
			The value of the name tag of the instance to get. The name tags in the account being accessed must be unique to target an instance this way.

		.PARAMETER NewImageId
			The new AMI id to launch the EC2 instance with.

		.PARAMETER Timeout
			The amount of time in seconds to wait for each action to succeed. There are multiple actions, each with their own timeout. This defaults to 600.

        .PARAMETER PassThru
            If specified, the new instance object will be returned to the pipeline.

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
			Update-EC2InstanceAmiId -InstanceId i-123456789012 -NewImageId "ami-123456789012"

			Changes the AMI id being used for the specified instance. You will be prompted to confirm certain actions.

        .EXAMPLE
			Update-EC2InstanceAmiId -InstanceId i-123456789012 -NewImageId "ami-123456789012" -Force

			Changes the AMI id being used for the specified instance. The Force parameter will bypass the confirmation prompts.

		.INPUTS
			None

		.OUTPUTS
			None or Amazon.EC2.Model.Instance

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/30/2019
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$NewImageId,

		[Parameter(Mandatory = $true, ParameterSetName = "Name")]
		[Alias("Name")]
		[ValidateNotNullOrEmpty()]
		[System.String]$InstanceName,

		[Parameter(Mandatory = $true, ParameterSetName = "Id")]
		[ValidateNotNullOrEmpty()]
		[System.String]$InstanceId,

		[Parameter()]
        [ValidateSet(1, [System.Int32]::MaxValue)]
		[System.Int32]$Timeout = 600,

        [Parameter()]
        [Switch]$PassThru,

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
			Write-Verbose -Message "Using instance id $InstanceId to update the image id."
			$InstanceSplat.Add("InstanceId", $InstanceId)
		}
		else
		{
			Write-Verbose -Message "Using instance name $InstanceName to update the image id."
			$InstanceSplat.Add("InstanceName", $InstanceName)
		}

		# Get the source EC2 instance
		[Amazon.EC2.Model.Instance]$Instance = Get-EC2InstanceByNameOrId @InstanceSplat @AwsUtilitiesSplat

        $Activity = "Updating the Image Id for instance $($Instance.InstanceId) to $NewImageId."
        $TotalSteps = 14
        $CurrentStep = 0
        
        Write-Progress -Activity $Activity -Status "Stopping source instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++	

		# Stop the source EC2 instance
        Write-Verbose -Message "Stopping the source instance."
		Set-EC2InstanceState -InstanceId $Instance.InstanceId -State STOP -Wait -Timeout $Timeout -Force @AwsUtilitiesSplat

        Write-Progress -Activity $Activity -Status "Detaching source instance network interfaces" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        ##### DETACH EBS VOLUMES AND NETWORK INTERFACES FROM SOURCE
        # This must all be done first so we can terminate the old instance and launch the new instance with the same private IP

        Write-Verbose -Message "Detaching source instance network interfaces."
        # Objects have NetworkInterfaceId and DeviceIndex properties
        [PSCustomObject[]]$InterfacesToAdd = Dismount-EC2InstanceNetworkInterfaces -Instance $Instance -Wait -Timeout $Timeout @AwsUtilitiesSplat

        Write-Verbose -Message "All source interfaces have been detached from source instance."
        Write-Host "***** Source interfaces that will be attached *****"

        foreach ($Interface in $InterfacesToAdd)
        {
            Write-Host "$($Interface.DeviceIndex) : $($Interface.NetworkInterfaceId)"
        }

        Write-Host ""

        Write-Progress -Activity $Activity -Status "Detaching source instance EBS volumes" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        Write-Verbose -Message "Detaching source instance EBS volumes."
        
        # Objects have VolumeId and Device properties
        [PSCustomObject[]]$VolumesToAdd = Dismount-EBSVolumes -Instance $Instance -Wait -Timeout $Timeout -IncludeRootVolume @AwsUtilitiesSplat
		
        Write-Verbose -Message "All source volumes have been detached from source instance."
        Write-Host "***** Source volumes that will be attached *****"

        foreach ($Volume in $VolumesToAdd)
        {
            Write-Host "$($Volume.Device) : $($Volume.VolumeId)"
        }

        Write-Host ""

        ##### GET LAUNCH PARAMETERS FROM THE SOURCE EC2 INSTANCE #####      

        Write-Progress -Activity $Activity -Status "Copying source instance launch parameters" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        # Build some optional parameters for New-EC2Instance
		[System.Collections.Hashtable]$NewInstanceSplat = Copy-EC2InstanceLaunchParameters -Instance $Instance @AwsUtilitiesSplat
        
        # Remove all NetworkInterface items except the root device, they will be dismounted from
        # source and attached to new

        [System.Boolean]$PrimaryInterfaceHasMultipleIps = $false

        if ($NewInstanceSplat.ContainsKey("NetworkInterface"))
        {
            [Amazon.EC2.Model.InstanceNetworkInterfaceSpecification[]]$RootInterface = $NewInstanceSplat["NetworkInterface"] | Where-Object {$_.DeviceIndex -eq 0 } | Select-Object -First 1
            
            # If we try to an IP (or multiple IPs) to a InstanceNetworkInterfaceSpecification, it results in an error: The parameter PrivateIpAddressesSet is not recognized
            $NewInstanceSplat.Remove("NetworkInterface")
            $NewInstanceSplat.Add("PrivateIpAddress", $RootInterface.PrivateIpAddress)
            $NewInstanceSplat.Add("SecurityGroupId", $RootInterface.Groups)
        }

        # Remove all BlockDeviceMapping items, all block devices will be directly dismounted
        # from source and attached to new
        if ($NewInstanceSplat.ContainsKey("BlockDeviceMapping"))
        {
            $NewInstanceSplat.Remove("BlockDeviceMapping")
        }
		
        # 1) Public IP & Public DNS & Association w/ Account Number Owner - EIP assigned to primary private IP
        # 2) Public DNS & No Public IP & No Association - EIP assigned to one or more secondary IPs on eth0
        # 3) Public IP & Public DNS & Association w/ Amazon Owner - Amazon assigned public IP

        [Amazon.EC2.Model.Address[]]$EIPs = @()

        # This will get the the association for the eth0 interface
            [Amazon.EC2.Model.InstanceNetworkInterfaceAssociation]$Association = $Instance.NetworkInterfaces | 
                Where-Object {$_.Attachment.DeviceIndex -eq 0 } | 
                Select-Object -First 1 -ExpandProperty Association

        if (($Association -ne $null -and $Association.IpOwnerId -ine "amazon") -or
            -not [System.String]::IsNullOrEmpty($Instance.PublicIpAddress) -or 
            -not [System.String]::IsNullOrEmpty($Instance.PublicDnsName))
        {
            # EIP on eth0
            [Amazon.EC2.Model.InstanceNetworkInterface]$Eth0 = $Instance.NetworkInterfaces | Where-Object {$_.Attachment.DeviceIndex -eq 0 } | Select-Object -First 1
            $EIPs = Get-EC2Address -Filter @{Name = "instance-id"; Value = $Instance.InstanceId}, @{Name = "network-interface-id"; Value = $Eth0.NetworkInterfaceId} @Splat
        }

        ##### TERMINATE THE SOURCE INSTANCE

        Write-Progress -Activity $Activity -Status "Terminating source instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        Write-Host "Terminating source instance."
        Set-EC2InstanceState -InstanceId $Instance.InstanceId -State TERMINATE -Wait -Force -Timeout $Timeout @AwsUtilitiesSplat

        ##### LAUNCH NEW INSTANCE

        Write-Progress -Activity $Activity -Status "Launching new instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        Write-Host "Launching new instance."
	
		Write-Verbose -Message @"
Launching new instance:
	Type:              $($Instance.InstanceType)
    Image Id:          $NewImageId
    Old Image Id:      $($Instance.ImageId)
	Subnet:            $($Instance.SubnetId)
	Security Groups:   $([System.String]::Join(",", ($Instance.SecurityGroups | Select-Object -ExpandProperty GroupId)))
	AZ:                $($Instance.Placement.AvailabilityZone)
	IAM Profile:       $($Instance.IamInstanceProfile.Arn)
	Private IP:        $($Instance.PrivateIPAddress)
	Tenancy:           $($Instance.Placement.Tenancy)
"@

		[Amazon.EC2.Model.Instance]$NewInstance = $null

        [System.String]$Token = [System.Guid]::NewGuid().ToString()

		$Temp = New-EC2Instance -ClientToken $Token `
                        -ImageId $NewImageId `
						@NewInstanceSplat @Splat

		if ($Temp -eq $null)
		{
			throw "Could not create the new instance."
		}

		[Amazon.EC2.Model.Instance]$NewInstance = Get-EC2InstanceByNameOrId -InstanceId $Temp.Instances[0].InstanceId @AwsUtilitiesSplat

        Write-Progress -Activity $Activity -Status "Stopping new instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++
        
		Write-Verbose -Message "Stopping new instance."

		Set-EC2InstanceState -InstanceId $NewInstance.InstanceId -State STOP -Wait -Timeout $Timeout -Force @AwsUtilitiesSplat

        Write-Progress -Activity $Activity -Status "Updating instance attributes" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        # Update the srIovNetSupport and ENA attributes for the instance

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

        Write-Progress -Activity $Activity -Status "Removing EBS volumes from the new instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        # Remove existing EBS volume(s) from the new instance

        Write-Verbose -Message "Removing EBS volumes from the new instance."
        Dismount-EBSVolumes -Instance $NewInstance -Wait -Delete -Force -Timeout $Timeout -IncludeRootVolume @AwsUtilitiesSplat | Out-Null

        # Attach source EBS Volumes to the new instance        

        Write-Progress -Activity $Activity -Status "Attaching source volumes to new instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        foreach ($Item in $VolumesToAdd)
        {
            Write-Verbose -Message "Adding volume $($Item.VolumeId) to device $($Item.Device)."
            Add-EC2Volume -InstanceId $NewInstance.InstanceId -Device $Item.Device -VolumeId $Item.VolumeId -Force @Splat | Out-Null         
        }

        Write-Verbose -Message "Waiting for all EBS volumes to finish attaching."
        Invoke-EBSVolumeAttachmentWait -VolumeId ($VolumesToAdd | Select-Object -ExpandProperty ($VolumesToAdd | Get-Member -MemberType NoteProperty -Name VolumeId)[0].Name) -Timeout $Timeout @AwsUtilitiesSplat

        # Remove existing Network Interface(s) from the new instance
        
        Write-Progress -Activity $Activity -Status "Removing network interfaces from the new instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        Write-Verbose -Message "Removing Network Interfaces from the new instance."
        Dismount-EC2InstanceNetworkInterfaces -Instance $NewInstance -Wait -Delete -Force -Timeout $Timeout @AwsUtilitiesSplat | Out-Null

        # Attach source network interfaces to the new instance

        Write-Progress -Activity $Activity -Status "Attaching source network interfaces to the new instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        foreach ($Item in $InterfacesToAdd)
        {
            Write-Verbose -Message "Adding interface $($Item.NetworkInterfaceId) to device index $($Item.DeviceIndex)."
            Add-EC2NetworkInterface -DeviceIndex $Item.DeviceIndex -InstanceId $NewInstance.InstanceId -NetworkInterfaceId $Item.NetworkInterfaceId -Force @Splat | Out-Null
        }

        Write-Verbose -Message "Waiting for all network interfaces to finish attaching."
        Invoke-EC2NetworkInterfaceAttachmentWait -NetworkInterfaceId ($InterfacesToAdd | Select-Object -ExpandProperty ($InterfacesToAdd | Get-Member -MemberType NoteProperty -Name NetworkInterfaceId)[0].Name) -Timeout $Timeout @AwsUtilitiesSplat       
                    
		# Update again after all old volumes have been removed and new volumes have been attached
		$NewInstance = Get-EC2InstanceByNameOrId -InstanceId $NewInstance.InstanceId @AwsUtilitiesSplat

        Write-Progress -Activity $Activity -Status "Updating eth0 on the new instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
        $CurrentStep++

        # Get the new instance's eth0 device
        [Amazon.EC2.Model.InstanceNetworkInterface]$RootNetDevice = $NewInstance.NetworkInterfaces | Where-Object {$_.Attachment.DeviceIndex -eq 0} | Select-Object -First 1

        # Get the source instance's eth0 device
        [Amazon.EC2.Model.InstanceNetworkInterface]$SourceRootInterface = $Instance.NetworkInterfaces | Where-Object {$_.Attachment.DeviceIndex -eq 0} | Select-Object -First 1

		[System.Collections.Hashtable]$InterfaceSplat = @{}

        # This is the only attribute we can't specify when creating an ENI during EC2 creation
		if ($SourceRootInterface.SourceDestCheck -ne $null)
		{
			$InterfaceSplat.Add("SourceDestCheck", $SourceRootInterface.SourceDestCheck)
		}

		if ($InterfaceSplat.Count -gt 0)
		{
            Write-Verbose -Message "Updating primary network interface attributes."

            foreach ($Item in $InterfaceSplat.GetEnumerator())
            {
                $TempSplat = @{}
                $TempSplat.Add($Item.Key, $Item.Value)
                Edit-EC2NetworkInterfaceAttribute -NetworkInterfaceId $RootNetDevice.NetworkInterfaceId `
											@TempSplat `
											@Splat | Out-Null
            }
		}

		# If the source machine had multiple IPs on the root ENI, add those IPs back
		if ($SourceRootInterface.PrivateIpAddresses.Count -gt 1)
		{
			Write-Verbose -Message "Adding secondary IP addresses to root network interface."
			Register-EC2PrivateIpAddress -NetworkInterfaceId $RootNetDevice.NetworkInterfaceId -PrivateIpAddress ($SourceRootInterface.PrivateIpAddresses | Where-Object {$_.Primary -eq $false} | Select-Object -ExpandProperty PrivateIpAddress) @Splat | Out-Null
		}
					
		# Update again after new interfaces and IPs have been added
		$NewInstance = Get-EC2InstanceByNameOrId -InstanceId $NewInstance.InstanceId @AwsUtilitiesSplat

        ### NOW THAT INTERFACES AND PRIVATE IPs HAVE BEEN MOVED, ASSOCIATE EIPs

        # EIPs was set earlier before the new instance was launched
        if ($EIPs -ne $null -and $EIPs.Count -gt 0)
        {
            Write-Progress -Activity $Activity -Status "Updating EIPs on the new instance" -PercentComplete (($CurrentStep / $TotalSteps) * 100)
            $CurrentStep++

            foreach ($EIP in $EIPs)
            {
                $SourcePrivateIP = $EIP.PrivateIpAddress

                Write-Verbose -Message "Removing EIP $($EIP.AssociationId) from $($Instance.InstanceId)."
                Unregister-EC2Address -AssociationId $EIP.AssociationId -Force @Splat

                [System.Diagnostics.Stopwatch]$SW = [System.Diagnostics.Stopwatch]::StartNew()

                while ($SW.Elapsed.TotalSeconds -le $Timeout)
                {
                    $EIP = Get-EC2Address -AllocationId $EIP.AllocationId @Splat

                    if ([System.String]::IsNullOrEmpty($EIP.AssociationId))
                    {
                        Write-Verbose -Message "Registering EIP $($EIP.AllocationId) with $($NewInstance.InstanceId)."

                        [System.Collections.Hashtable]$RegSplat = @{}

                        # This will register the EIP on eth0 for the new instance using the same private IP
                        if ($EIP.PrivateIpAddress -eq $Instance.PrivateIpAddress)
                        {
                            $RegSplat.Add("PrivateIpAddress", $NewInstance.PrivateIpAddress)
                        }
                        else
                        {
                            $RegSplat.Add("PrivateIpAddress", $SourcePrivateIP)
                        }

                        Register-EC2Address -AllocationId $EIP.AllocationId -NetworkInterfaceId $RootNetDevice.NetworkInterfaceId @RegSplat @Splat | Out-Null

                        [System.Diagnostics.Stopwatch]$SW2 = [System.Diagnostics.Stopwatch]::StartNew()

                        while ($SW2.Elapsed.TotalSeconds -le $Timeout)
                        {
                            $EIP = Get-EC2Address -AllocationId $EIP.AllocationId @Splat

                            if ([System.String]::IsNullOrEmpty($EIP.AssociationId))
                            {
                                Write-Verbose -Message "Waiting EIP to associate to new instance."
                                Start-Sleep -Seconds 5
                                $Counter += 5
                            }
                            else
                            {
                                break
                            }
                        }

                        $SW2.Stop()

                        if ($SW2.Elapsed.TotalSeconds -gt $Timeout)
                        {
                            throw "Timeout waiting for EIP $($EIP.AllocationId) to register to $($NewInstance.InstanceId)."
                        }

                        break
                    }
                    else
                    {
                        Write-Verbose -Message "Waiting for EIP to become available"
                        Start-Sleep -Seconds 5
                    }
                }

                if ($SW.Elapsed.TotalSeconds -gt $Timeout)
                {
                    throw "Timeout waiting for EIP $($EIP.AllocationId) to deregister from $($Instance.InstanceId)."
                }
            }
        }


		Write-Verbose -Message "Starting new instance."

		Set-EC2InstanceState -InstanceId $NewInstance.InstanceId -State START -Force @AwsUtilitiesSplat 

        Write-Progress -Activity $Activity -Completed

        if ($PassThru)
        {
            $NewInstance = Get-EC2InstanceByNameOrId -InstanceId $NewInstance.InstanceId @AwsUtilitiesSplat
            Write-Output -InputObject $NewInstance
        }
	}

	End {
	}
}

#endregion

#region IAM Functions

Function Get-AWSAccountId {
	<#
		.SYNOPSIS
			Gets the AWS account Id associated with the current or specified credentials.

		.DESCRIPTION
			The cmdlet gets the caller identity from STS and returns the AWS Account Id.

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
			$Id = Get-AWSAccountId

			Gets the account id of the current credentials.

		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/14/2019
	#>
	[CmdletBinding()]
	Param(
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

        [Amazon.SecurityToken.Model.GetCallerIdentityResponse]$Response = Get-STSCallerIdentity @Splat 
        Write-Output -InputObject $Response.Account
	}

	End {
	}
}

Function Get-AWSIAMPrincipalId {
	<#
		.SYNOPSIS
			Gets the AWS IAM principal Id associated with the current or specified credentials.

		.DESCRIPTION
			The cmdlet gets the caller identity from STS and returns the IAM principal id.

            PRINCIPAL             -   aws:userid
            AWS Account           -   Account ID
            IAM User              -   Unique ID
            Federated User        -   account:caller-specified-name
            Web Federated User    -   role-id:caller-specified-role-name
            SAML Federated User   -   role-id:caller-specified-role-name
            Assumed Role          -   role-id:caller-specified-role-name
            EC2 Instance Profilee -   role-id:ec2-instance-id

            The "role-id" is a unique identifier assigned to each role at creation.

            The "caller-specified-name" and "caller-specified-role-name" are names passed by the calling process when it makes a call to get temporary credentials.

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
			$Id = Get-AWSIAMPrincipalId

			Gets the user id of the current credentials.

		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/14/2019
	#>
	[CmdletBinding()]
	Param(
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

        [Amazon.SecurityToken.Model.GetCallerIdentityResponse]$Response = Get-STSCallerIdentity @Splat 
        Write-Output -InputObject $Response.UserId
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

			The url can then be provided to a user to be able to access the management console with the credentials of the supplied role in the RoleArn parameter.

		.PARAMETER RoleArn
			The role in the account you want to assume and log into. This role must be assumed using long-term AWS credentials (not temporary credentials). This is the role and permissions the user will have when accessing the management console. The user calling this cmdlet must have permisions to assume that role in order for the call to succeed.

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
			Get-AWSFederationLogonUrl -RoleArn "arn:aws:iam::123456789012:role/AdministratorRole" -ProfileName mydev
			
			Gets the AWS management console signin url for the AdministratorRole in the 123456789012 account. The credentials stored in the mydev profile are used to call AssumeRole on the provided role and generate the federated logon url.

		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/17/2019
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
		[PSCustomObject]$Response = Invoke-WebRequest -Uri $Url -Method Get | Select-Object -ExpandProperty Content | ConvertFrom-Json

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

Function Get-AWSIAMRoleSummary {
	<#
		.SYNOPSIS
			Retrieves a summary about the specified role(s) or all roles in an account.

		.DESCRIPTION
			This cmdlet retrieves details about specified roles or all roles in an account. The details include all inline and managed policy documents,
			the assume role policy document, name, arn, created date, path, etc. If a specified role is not found, the cmdlet produces a warning, but
			can throw an exception if the -ErrorAction parameter is set to stop.

		.PARAMETER RoleNames
			The name of a role or multiple roles to retrieve a summary of. If this parameter is not specified, all roles in the account are retrieved.

		.PARAMETER PathPrefix
			The path prefix for filtering the IAM roles processed. For example, the prefix /application_abc/component_xyz/ gets all roles whose path starts with /application_abc/component_xyz/.

			If it is not included, it defaults to a slash (/), listing all roles.

        .PARAMETER AsJson
            Returns the results as a JSON string instead of a PSCustomObject array.

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

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
			$IAMRoles = Get-AWSIAMRoleSummary -ProfileName "my-lab"

			Gets a summary of all the IAM roles and their policies in the account specified by the my-lab credentials profile.

		.EXAMPLE
			Get-AWSIAMRoleSummary -PathPrefix /caa-roles/ -ProfileName "my-lab"

			Gets a summary of the IAM roles and their policies in the /caa-roles/ path inside the account specified by the my-lab credentials profile.

		.EXAMPLE 
			Get-AWSIAMRoleSummary -RoleNames "PowerUserRole","AdministratorRole" -ProfileName "my-lab"

			Gets a summary of the PowerUserRole and AdministratorRole IAM roles and their policies inside the account specified by the my-lab credentials profile.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCustomObject[], System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/18/2019
	#>
	[CmdletBinding(DefaultParameterSetName = "Name")]
	[OutputType([System.Management.Automation.PSCustomObject[]], [System.String])]
	Param(
		[Parameter(ParameterSetName = "Name")]
		[ValidateNotNullOrEmpty()]
		[System.String[]]$RoleNames,

		[Parameter(ParameterSetName = "Prefix")]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern("(?:^\/$|(?:\/\S+\/)+)")]
		[System.String]$PathPrefix = "/",

        [Parameter()]
        [Switch]$AsJson,

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
		[Amazon.Runtime.AWSCredentials]$Credential = $null,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		[System.Collections.Hashtable]$SourceSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		
		[Amazon.SecurityToken.Model.GetCallerIdentityResponse]$Identity = Get-STSCallerIdentity @SourceSplat
		$AccountId = $Identity.Account

		[PSCustomObject[]]$AccountRoles = @()

        [Amazon.IdentityManagement.Model.Role[]]$Roles

		if (-not $PSBoundParameters.ContainsKey("RoleNames") -or $RoleNames.Length -eq 0)
		{
			# Path prefix defaults to "/", which lists all roles
			$Roles = Get-IAMRoleList -PathPrefix $PathPrefix @SourceSplat
		}
        else
        {
            foreach ($Name in $RoleNames)
            {
                [Amazon.IdentityManagement.Model.Role]$Role = Get-IAMRole -RoleName $Name @SourceSplat
                $Roles += $Role
            }
        }
		
		$i = 0

		foreach ($IAMRole in $Roles)
		{
			$i++
			$Percent = [System.Math]::Round(($i / $Roles.Length) * 100, 2)
			Write-Progress -Activity "Processing Roles" -Status "Processing $i of $($Roles.Length) IAM Roles, $Percent% Complete" -PercentComplete $Percent

            [System.Collections.Hashtable]$Inline = [System.Collections.Hashtable]@{}
            [System.Collections.Hashtable]$Attached = [System.Collections.Hashtable]@{}

			try
			{
				[System.String[]]$InlinePolicies = Get-IAMRolePolicyList -RoleName $IAMRole.RoleName @SourceSplat

				foreach ($InlinePolicy in $InlinePolicies)
				{
					[Amazon.IdentityManagement.Model.GetRolePolicyResponse]$GetPolicyResult = Get-IAMRolePolicy -PolicyName $InlinePolicy -RoleName $IAMRole.RoleName @SourceSplat
                    $Inline.Add($GetPolicyResult.PolicyName, (ConvertFrom-Json -InputObject ([System.Net.WebUtility]::UrlDecode($GetPolicyResult.PolicyDocument))))
				}

				[Amazon.IdentityManagement.Model.AttachedPolicyType[]]$AttachedPolicies = Get-IAMAttachedRolePolicyList -RoleName $IAMRole.RoleName @SourceSplat

				foreach ($AttachedPolicy in $AttachedPolicies)
				{
					[Amazon.IdentityManagement.Model.ManagedPolicy]$ManagedPolicy = Get-IAMPolicy -PolicyArn $AttachedPolicy.PolicyArn @SourceSplat
					[Amazon.IdentityManagement.Model.PolicyVersion]$GetManagedPolicyResult = Get-IAMPolicyVersion -PolicyArn $ManagedPolicy.Arn -VersionId $ManagedPolicy.DefaultVersionId @SourceSplat

					$Attached.Add($ManagedPolicy.Arn, (ConvertFrom-Json -InputObject ([System.Net.WebUtility]::UrlDecode($GetManagedPolicyResult.Document))))
				}

				$AccountRoles += [PSCustomObject]@{
					RoleId = $IAMRole.RoleId;
					RoleName = $IAMRole.RoleName;
					Arn = $IAMRole.Arn;
					AccountId = $AccountId;
					CreateDate = $IAMRole.CreateDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
					Path = $IAMRole.Path;
					AssumeRolePolicyDocument = ConvertFrom-Json -InputObject ([System.Net.WebUtility]::UrlDecode($IAMRole.AssumeRolePolicyDocument))
					InlinePolicies = $Inline;
                    AttachedPolicies = $Attached;
				}
			}
			catch [System.InvalidOperationException]
			{
				if ($_.Exception.InnerException -ne $null -and $_.Exception.InnerException -is [Amazon.IdentityManagement.Model.NoSuchEntityException])
				{
					if ($ErrorActionPreference -ne [System.Management.Automation.ActionPreference]::Stop)
					{
						Write-Warning -Message "$($_.Exception.InnerException.Message)"
					}
					else
					{
						throw $_.Exception
					}
				}
				else
				{
					throw $_.Exception
				}
			}
		}

		Write-Progress -Activity "Processing Roles" -Completed

        if ($AsJson)
        {
            ConvertTo-Json -InputObject $AccountRoles -Depth 5
        }
        else
        {
		    Write-Output -InputObject $AccountRoles
        }
	}

	End {
	}
}

#endregion

#region EBS Functions

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
		[Switch]$DoNotDelete,

		[Parameter()]
		[Switch]$EnableLogging,

		[Parameter()]
		[Switch]$PropogateTags,

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
		Function Write-EBSLog {
			<#
				.SYNOPSIS
					Writes to a log file about the EBS snapshot activity.

				.DESCRIPTION
					Writes to a log file about the EBS snapshot activity. When a log file is rolled after passing 5MB, the current datetime stamp is appended to the file.

				.PARAMETER Message
					The message to write.

				.PARAMETER Level
					The log level, INFO, WARNING, or ERROR.

				.PARAMETER Path
					The path to the log file. This defaults to $env:ProgramData\aws\ebs\backup.log

				.PARAMETER NoTimeStamp
					Specifies that the log entry is written without a timestamp.

				.EXAMPLE
					Write-EBSLog -Message "Beginning volume snapshot creation job."	

					Writes the message to the default log file.

				.INPUTS
					None

				.OUTPUTS
					None

				.NOTES
					AUTHOR: Michael Haken
					LAST UPDATE: 1/14/2019
			#>
			Param(
				[Parameter(Mandatory = $true)]
				[ValidateNotNullOrEmpty()]
				[System.String]$Message,

				[Parameter()]
				[ValidateSet("INFO", "WARNING", "ERROR")]
				[System.String]$Level = "INFO",

				[Parameter()]
				[System.String]$Path = "$env:ProgramData\aws\ebs\backup.log",

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

				if ($Info.Exists)
				{
					# Rollover the log file
					if ($Info.Length -gt 5MB)
					{
						$Name = [System.IO.Path]::GetFileNameWithoutExtension($Info.FullName) 

						do
						{
							$LogDate = (Get-Date).ToString("dd-MMM-yyyy_HH-mm-ss")
							$NewName = $Name + "_" + $LogDate + $Info.Extension

						} while (Test-Path -Path "$($Info.Directory.FullName)\$NewName")

						Rename-Item -Path $Info.FullName -NewName $NewName
					}
				}

				if(-not $NoTimeStamp)
				{
					$Message = "$(Get-Date) [$Level] : $Message"
				}

				Add-Content -Path $Info.FullName -Value $Message
			}

			End {
			}
		}
	}

	Process {
		[System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation
		[System.Collections.Hashtable]$AWSUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $Splat

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

			# This is actually a [Amazon.EC2.Model.Reservation], but if no instance is returned, it comes back as System.Object[]
            # so save the error output and don't strongly type it
            $Instances = Get-EC2Instance -InstanceId $SourceInstanceId -ErrorAction SilentlyContinue @Splat

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

						# Get the volumes attached to this instance, when MaxResults is not specified, all results are returned
						[Amazon.EC2.Model.Volume[]]$Volumes = Get-EC2Volume -Filter (New-Object -TypeName Amazon.EC2.Model.Filter -Property @{Name = "attachment.instance-id"; Value = $InstanceId}) @Splat

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
								[Amazon.EC2.Model.TagSpecification]$Tags = New-Object -TypeName Amazon.EC2.Model.TagSpecification
								$Tags.ResourceType = [Amazon.EC2.ResourceType]::Snapshot

								if ($PropogateTags)
								{
									$Tags.Tags.AddRange($Volume.Tags)
								}

								$Tags.Tags.Add((New-Object -TypeName Amazon.EC2.Model.Tag("InstanceId", $InstanceId)))
								$Tags.Tags.Add((New-Object -TypeName Amazon.EC2.Model.Tag("VolumeId", $Volume.VolumeId)))
								$Tags.Tags.Add((New-Object -TypeName Amazon.EC2.Model.Tag("Name", $VolumeSnapshotName)))
								$Tags.Tags.Add((New-Object -TypeName Amazon.EC2.Model.Tag($script:CREATED_BY, $script:UNIQUE_ID)))
								$Tags.Tags.Add((New-Object -TypeName Amazon.EC2.Model.Tag($script:CAN_BE_DELETED, (-not [System.Boolean]$DoNotDelete))))

								if (-not $DoNotDelete)
								{
									$Tags.Tags.Add((New-Object -TypeName Amazon.EC2.Model.Tag("DeleteAfter", [System.DateTime]::UtcNow.Add($RetentionPeriod).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))))
								}

								if ($Tags.Tags.Count -gt $script:MaxEC2Tags)
								{
									throw "The snapshot creation for $($Volume.VolumeId) cannot succeed because the number of tags is greater than $($script:MaxEC2Tags)."
								}

								[Amazon.EC2.Model.Snapshot]$Snapshot = New-EC2Snapshot -VolumeId $Volume.VolumeId -Description "Automated backup created for $InstanceId on $Date" -Force -TagSpecification $Tags @Splat
				
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

									# Get snapshots that were created from the current volume, but are not the snapshot we just took, use pagination in case there are a lot
									[Amazon.EC2.Model.Snapshot[]]$OldSnapshots = @()
									$NextToken = $null
									$AccountId = Get-AWSAccountId @AWSUtilitiesSplat
									
									do
									{
										$OldSnapshots += Get-EC2Snapshot `
											-OwnerId $AccountId `
											-Filter (New-Object -TypeName Amazon.EC2.Model.Filter -Property @{Name = "volume-id"; Values = $Volume.VolumeId}) `
											-MaxResult 1000 `
											-NextToken $NextToken `
											@Splat | Where-Object {$_.SnapshotId -ne $Snapshot.SnapshotId}

										[Amazon.EC2.Model.DescribeSnapshotsResponse]$Response =  $AWSHistory | Select-Object -ExpandProperty LastServiceResponse
										$NextToken = $Response.NextToken
            
									} while (-not [System.String]::IsNullOrEmpty($NextToken))

									foreach ($OldSnapshot in $OldSnapshots)
									{
										[System.String]$CreatedBy = $OldSnapshot.Tags | Where-Object {$_.Key -eq $script:CREATED_BY} | Select-Object -ExpandProperty Value
										[System.Boolean]$CanDelete = $OldSnapshot.Tags | Where-Object {$_.Key -eq $script:CAN_BE_DELETED} | Select-Object -ExpandProperty Value
										
										if (($OldSnapshot.Tags | Select-Object -ExpandProperty Key) -icontains "DeleteAfter")
										{
											try
											{
												[System.DateTime]$DeleteAfter = $OldSnapshot.Tags | Where-Object {$_.Key -eq "DeleteAfter"} | Select-Object -ExpandProperty Value
											}
											catch [Exception]
											{
												Write-EBSLog -Message "Could not parse DeleteAfter tag value: $($_.Exception.Message)"
												[System.DateTime]$DeleteAfter = [System.DateTime]::MaxValue
											}
										}
										else
										{
											[System.DateTime]$DeleteAfter = [System.DateTime]::MaxValue
										}

										if (($CreatedBy -ne $null -and $CreatedBy -eq $script:UNIQUE_ID) -and `
											($CanDelete -ne $null -and $CanDelete -eq $true) -and `
											[System.DateTime]::UtcNow -ge $DeleteAfter										
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
												Remove-EC2Snapshot -SnapshotId $OldSnapshot.SnapshotId -Force @Splat
                                        
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
				# This will get caught below
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

Function Copy-EBSVolume {
    <#
        .SYNOPSIS
			Copies EBS volumes from a source to a destination.

		.DESCRIPTION
			This cmdlet creates EBS Volume snaphshots of a specified EBS volume, or volumes attached to an instance and then creates new EBS volumes from those snapshots.

			If a destination EC2 instance is not specified either by Id or name, the volumes are created in the destination region, but are not attached to anything and the cmdlet will return details about the volumes.

			The volumes are attached to the first available device on the EC2 instance starting at xvdf and will attach until xvdp for Windows or /dev/sdf through /dev/sdp for Linux.

            If the source EBS volume(s) are encrypted, the snapshots and resulting new volumes will also be encrypted. If the destination is a different region, the default KMS key will be used, unless one is specified. If the destination is the same region, the same KMS key will be used, unless a different one is specified.

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
			The region the new volumes should be created in. This must be specified if the destination instance is in a different region. This parameter defaults to the source region.

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
			This will encrypt the resulting volumes using the default AWS KMS key. You do not need to specify this if the source volume(s) are already encrypted. The resulting copies will also be encrypted.	

		.PARAMETER VolumeType
			You can specify a single volume type for all newly created volumes. If this parameter is not specified, the source volume attributes are used to create the new volume, including the number of provisioned IOPS.

		.PARAMETER Iops
			Only valid for Provisioned IOPS SSD volumes when you specify Io1 for the VolumeType parameter. The number of I/O operations per second (IOPS) to provision for the volume, with a maximum ratio of 50 IOPS/GiB. Constraint: Range is 100 to 20000 for Provisioned IOPS SSD volumes.

		.PARAMETER VolumeSize
			If the source is an EBS Volume Id, or the OnlyRootDevice parameter is specified, a new Volume size can be specified for the resulting volume in GiBs. The size must be greater than or equal to the source.

			Constraints: 1-16384 for gp2, 4-16384 for io1, 500-16384 for st1, 500-16384 for sc1, and 1-1024 for standard.

		.PARAMETER CopyTags 
			Specify this to copy the current tag values from the source volume(s) to the destination volume(s) and intermediate EBS snapshots.

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

		.EXAMPLE
			[Amazon.EC2.Model.Volume[]]$NewVolumes = Copy-EBSVolume -SourceInstanceName server1 -DeleteSnapshots -ProfileName mycredprofile -Verbose -Region ([Amazon.RegionEndpoint]::USWest2) -DestinationRegion ([Amazon.RegionEndpoint]::USEast2)
			
			Copies the EBS volume(s) from server1 in us-west-2 to us-east-2. The new volumes are unattached.

		.INPUTS
			None

		.OUTPUTS
			Amazon.EC2.Model.Volume[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/23/2019
    #>
    [CmdletBinding()]
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
        [Switch]$OnlyRootDevice,

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
		[Switch]$EncryptNewVolumes,

		[Parameter()]
		[Amazon.EC2.VolumeType]$VolumeType,

		[Parameter()]
		[ValidateRange(100, 20000)]
		[System.Int32]$Iops,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$KmsKeyId = [System.String]::Empty,

		[Parameter()]
		[Switch]$CopyTags
    )

	DynamicParam 
	{
		[System.Management.Automation.RuntimeDefinedParameterDictionary]$ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		# If we're only targetting a single EBS volume, we can specify a new size
		if ($PSBoundParameters.ContainsKey("SourceEBSVolumeId") -or $PSBoundParameters.ContainsKey("OnlyRootDevice"))
		{
			New-DynamicParameter -Name "VolumeSize" -Type ([System.Int32]) -ValidateRange @(1, 16384) -RuntimeParameterDictionary $ParamDictionary | Out-Null
		}

		Write-Output -InputObject $ParamDictionary
	}

    Begin {
    }

    Process {
		if ($VolumeType -eq [Amazon.EC2.VolumeType]::Io1 -and -not $PSBoundParameters.ContainsKey("Iops"))
		{
			throw "You must specify a number of IOPS if the destination volumes are of type Io1."			
		}

		# Map the common AWS parameters
		[System.Collections.Hashtable]$SourceSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		[System.Collections.Hashtable]$SourceAWSUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $SourceSplat

		if (-not $PSBoundParameters.ContainsKey("Region"))
		{
			$Region = [Amazon.RegionEndpoint]::GetBySystemName($SourceSplat.Region)
		}
		
		# Map the common parameters, but with the destination Region
		[System.Collections.Hashtable]$DestinationSplat = New-AWSSplat -Region $DestinationRegion -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation
		[System.Collections.Hashtable]$DestinationAWSUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $DestinationSplat

		# If the user did not specify a destination region, use the source region
		# which could be specified, or be the default
		if (-not $PSBoundParameters.ContainsKey("DestinationRegion"))
		{
			$DestinationSplat.Region = $SourceSplat.Region
			$DestinationAWSUtilitiesSplat.Region = $SourceAWSUtilitiesSplat.Region
			$DestinationRegion = [Amazon.RegionEndpoint]::GetBySystemName($DestinationSplat.Region)
		}

		# The first step is to get the volume Ids attached to the instance we are trying to copy data from
        [Amazon.EC2.Model.Volume[]]$EBSVolumes = @()

        switch -Wildcard ($PSCmdlet.ParameterSetName) {
            "*SourceByInstanceName" {

				[Amazon.EC2.Model.Instance]$Instance = Get-EC2InstanceByNameOrId -Name $SourceInstanceName @SourceAWSUtilitiesSplat

				if ($Instance -ne $null)
				{
					# Only update the AZ if a specific one wasn't specified and we're not moving cross region
					if (-not $PSBoundParameters.ContainsKey("AvailabilityZone") -and $Region.SystemName -eq $DestinationRegion.SystemName)
					{
						$AvailabilityZone = $Instance.Placement.AvailabilityZone
						Write-Verbose -Message "An AZ wasn't explicitly specified, so we'll use the AZ of the source volume: $AvailabilityZone"
					}

					if ($OnlyRootDevice)
					{
						$EBSVolumes = $Instance.BlockDeviceMappings | `
                            Where-Object {$_.DeviceName -eq $Instance.RootDeviceName} | `
                            Select-Object -First 1 -ExpandProperty Ebs | `
                            Select-Object -ExpandProperty VolumeId	| `
                            Get-EC2Volume @SourceSplat
					}
					else
					{
						$EBSVolumes = $Instance.BlockDeviceMappings | Select-Object -ExpandProperty Ebs | Select-Object -ExpandProperty VolumeId | Get-EC2Volume @SourceSplat
					}                        
				}

                break
            }
            "*SourceByInstanceId" {
                
                # This is actually a [Amazon.EC2.Model.Reservation], but if no instance is returned, it comes back as System.Object[]
                # so save the error output and don't strongly type it
                [Amazon.EC2.Model.Instance]$Instance  = Get-EC2InstanceByNameOrId -InstanceId $SourceInstanceId @SourceAWSUtilitiesSplat

                if ($Instance -ne $null)
                {
					# Only update the AZ if a specific one wasn't specified and we're not moving cross region
					if (-not $PSBoundParameters.ContainsKey("AvailabilityZone") -and $Region.SystemName -eq $DestinationRegion.SystemName)
					{
						$AvailabilityZone = $Instance.Placement.AvailabilityZone
						Write-Verbose -Message "An AZ wasn't explicitly specified, so we'll use the AZ of the source volume: $AvailabilityZone"
					}

                    if ($OnlyRootDevice)
                    {
						$EBSVolumes = $Instance.BlockDeviceMappings | `
							Where-Object {$_.DeviceName -eq $Instance.RootDeviceName} | `
							Select-Object -ExpandProperty Ebs | `
							Select-Object -First 1 -ExpandProperty VolumeId	| `
							Get-EC2Volume @SourceSplat
                    }
                    else
                    {
                        $EBSVolumes = $Instance.BlockDeviceMappings | Select-Object -ExpandProperty Ebs | Select-Object -ExpandProperty VolumeId | Get-EC2Volume @SourceSplat
                    }                       
                }

                break
            }
            "*SourceByVolumeId" {
				# This check just ensures the EC2 EBS volume exists

                [Amazon.EC2.Model.Volume]$Volume = Get-EC2Volume -VolumeId $SourceEBSVolumeId @SourceSplat
                
                if ($Volume -ne $null)
                {
                    $EBSVolumes = @($Volume)

				    # Only update the AZ if a specific one wasn't specified and we're not moving cross region
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

		# Test this here so we can throw early and not go through creating snapshots before we find this out
		# The dynamic param VolumeSize should only be added if there is 1 source volume, but
		# but let's make sure
		# Constraints: 1-16384 for gp2, 4-16384 for io1, 500-16384 for st1, 500-16384 for sc1, and 1-1024 for standard.
		if ($PSBoundParameters.ContainsKey("VolumeSize") -and $EBSVolumes.Length -eq 1)
		{
			[System.Int32]$Size = $PSBoundParameters["VolumeSize"]

			foreach ($Vol in $EBSVolumes)
			{
				if ($Size -lt $Vol.Size)
				{
					throw "The specified new volume size, $Size GiB, is not greater than or equal to the current volume size of $($Vol.Size) GiB for $($Vol.VolumeId)."
				}

				# We don't need to check the other types since they all use the same upper limit, which was checked by the 
				# parameter validation, and the value can't be less than the minimum since the existing volumes must comply
				# with that minimum
				if ($Vol.VolumeType -eq [Amazon.EC2.VolumeType]::Standard -and $Size -gt 1024)
				{
					throw "The specified size, $Size GiB, is greater than 1024, the maximum size for the Standard volume type."				
				}
			}
		}

		# Retrieve the destination EC2 instance
		# This needs to come after the instance retrieval because it may
		# update the destination AZ
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

				# If the AZ hasn't been specified previously because this is a cross region
				# move, select a default one for the destination region
                if ([System.String]::IsNullOrEmpty($AvailabilityZone))
                {
                    $AvailabilityZone = Get-EC2AvailabilityZone @DestinationSplat | Where-Object {$_.State -eq [Amazon.EC2.AvailabilityZoneState]::Available} | Select-Object -First 1 -ExpandProperty ZoneName
                    Write-Verbose -Message "Using a default AZ in the destination region since a destination instance and AZ were not specified: $AvailabilityZone"
                }
            }
        }

		# This will be used in the snapshot description
		[System.String]$Purpose = [System.String]::Empty

		if ($Destination -ne $null)
		{
			$Purpose = $Destination.InstanceId
		}
		else
		{
			$Purpose = $DestinationRegion.SystemName
		}

		# Create the snapshots at the source

        [Amazon.EC2.Model.Snapshot[]]$SourceSnapshots = @()

        # Using a try here so the finally step will always delete the snapshots if specified
		try
		{
            [System.Collections.Generic.Queue[Amazon.EC2.Model.Volume]]$EBSVolQueue = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.Volume] 

            foreach ($Item in $EBSVolumes)
            {
                $EBSVolQueue.Enqueue($Item)
            }

            # Make sure the volume is available or in-use before attempting the snapshot
            while ($EBSVolQueue.Count -gt 0)
            {
                [Amazon.EC2.Model.Volume]$Vol = $EBSVolQueue.Dequeue()

                switch ($Vol.State)
                {
                    {$_ -in @([Amazon.EC2.VolumeState]::Available, [Amazon.EC2.VolumeState]::InUse)} {
                    
                        $SnapSplat = @{}

                        if ($CopyTags)
                        {
                            [Amazon.EC2.Model.TagSpecification]$Tags = New-Object -TypeName Amazon.EC2.Model.TagSpecification

			                $Tags.ResourceType = [Amazon.EC2.ResourceType]::Snapshot

			                $Tags.Tags = $Vol.Tags

                            $SnapSplat.Add("TagSpecification", $Tags)
                        }       			

                        [Amazon.EC2.Model.Snapshot]$Snap = New-EC2Snapshot -VolumeId $Vol.VolumeId @SourceSplat -Description "TEMPORARY for $Purpose" @SnapSplat
                        $SourceSnapshots += $Snap

                        break
                    }
                    ([Amazon.EC2.VolumeState]::Creating) {
                        Write-Verbose -Message "The volume $($Vol.VolumeId) is being created, cannot snapshot yet."
                        $EBSVolQueue.Enqueue($Vol)
                        break
                    }
                    {$_ -in @([Amazon.EC2.VolumeState]::Deleted, [Amazon.EC2.VolumeState]::Deleting, [Amazon.EC2.VolumeState]::Error)} {
                        $DeleteSnapshots = $true
                        throw "The volume $($Vol.VolumeId) is not in a state than can be snapshotted: $($Vol.State)."
                        break
                    }
                }
            
                # If all of the volumes are creating, wait
                if ($EBSVolQueue.Count -gt 0 -and ($EBSVolQueue | Where-Object { $_.State -eq  [Amazon.EC2.VolumeState]::Creating }).Count -eq $EBSVolQueue.Count)
                {
                    Write-Verbose -Message "All remaining volumes are in the Creating state, sleeping to allow them to finish."
                    Start-Sleep -Seconds 15

                    $Arr = $EBSVolQueue.ToArray()

                    $EBSVolQueue = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.Volume]
                
                    for ($i = 0; $i -lt $Arr.Length; $i++)
                    {
                        $EBSVolQueue.Enqueue((Get-EC2Volume -VolumeId $Arr[$i].VolumeId @SourceSplat))
                    }              
                }
            }

			# Reset the counter for the next loop
			$Counter = 0

			# While all of the snapshots have not completed, wait
			while (($SourceSnapshots | Where-Object {$_.State -ne [Amazon.EC2.SnapshotState]::Completed}) -ne $null -and $Counter -lt $Timeout)
			{
				$Completed = (($SourceSnapshots | Where-Object {$_.State -eq [Amazon.EC2.SnapshotState]::Completed}).Length / $SourceSnapshots.Length) * 100
				Write-Progress -Activity "Creating snapshots" -Status "$Completed% Complete:" -PercentComplete $Completed

				# Update their statuses
				for ($i = 0; $i -lt $SourceSnapshots.Length; $i++)
				{
					if ($SourceSnapshots[$i].State -ne [Amazon.EC2.SnapshotState]::Completed)
					{
						Write-Verbose -Message "Waiting on snapshot $($SourceSnapshots[$i].SnapshotId) to complete, currently at $($SourceSnapshots[$i].Progress) in state $($SourceSnapshots[$i].State)"
						$SourceSnapshots[$i] = Get-EC2Snapshot -SnapshotId $SourceSnapshots[$i].SnapshotId @SourceSplat
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

			# Reset the counter for the next loop
			$Counter = 0

			# If this is a cross region move, copy the snapshots over, or if we are going to encrypt the new volumes, create copies
			if (($DestinationRegion.SystemName -ne $Region.SystemName) -or $EncryptNewVolumes -or -not [System.String]::IsNullOrEmpty($KmsKeyId))
			{
				Write-Verbose -Message "Copying snapshots from $($SourceSplat.Region) to $($DestinationSplat.Region) using encryption: $($EncryptNewVolumes -or -not [System.String]::IsNullOrEmpty($KmsKeyId))"

				# Create the encryption splat
				[System.Collections.Hashtable]$EncryptionSplat = @{}

				if ($EncryptNewVolumes)
				{
					$EncryptionSplat.Add("Encrypted", $true)
				}
										  
				if (-not [System.String]::IsNullOrEmpty($KmsKeyId))
				{
					$EncryptionSplat.Add("KmsKeyId", $KmsKeyId)
				}

				# Copy the Snapshots and get the new copied snapshot objects back
				$SnapshotsToCreate = $SourceSnapshots | ForEach-Object {
					[System.String]$Id = Copy-EC2Snapshot -SourceSnapshotId $_.SnapshotId -SourceRegion $SourceSplat.Region -Description "COPY OF TEMPORARY for $Purpose" @DestinationSplat @EncryptionSplat
					[Amazon.EC2.Model.Snapshot]$Snap = Get-EC2Snapshot -SnapshotId $Id @DestinationSplat
					
                    # The "SnapshotsToCreate" array of objects have the original EBS volume id used to create the snapshot. This, the volume id produced by the Copy-EC2Snapshot
                    # API action is arbitrary, so we assign the original here to ensure it is carried over
                    $Snap.VolumeId = $_.VolumeId

					if ($CopyTags)
					{
                        
						New-EC2Tag -Resource $Id -Tag $_.Tags @DestinationSplat
					}

					Write-Output -InputObject $Snap
				}

				# While all of the snapshots have not completed, wait
				while (($SnapshotsToCreate | Where-Object {$_.State -ne [Amazon.EC2.SnapshotState]::Completed}) -ne $null -and $Counter -lt $Timeout)
				{
					$Completed = (($SnapshotsToCreate | Where-Object {$_.State -eq [Amazon.EC2.SnapshotState]::Completed}).Length / $SnapshotsToCreate.Length) * 100
					Write-Progress -Activity "Creating snapshot copies" -Status "$Completed% Complete:" -PercentComplete $Completed

					# Update their statuses
					for ($i = 0; $i -lt $SnapshotsToCreate.Length; $i++)
					{
						if ($SnapshotsToCreate[$i].State -ne [Amazon.EC2.SnapshotState]::Completed)
						{
							# This will ensure we have a VolumeId later that we can check on
							# to compare the copied snapshot with the original volume, since we assigned it originally
                            # above, it will be overwritten on the next Get-EC2Snapshot API call, so re-assign it in
                            # order to keep track of it locally in the cmdlet
							$TempVolId = $SnapshotsToCreate[$i].VolumeId
							Write-Verbose -Message "Waiting on snapshot $($SnapshotsToCreate[$i].SnapshotId) copy to complete, currently at $($SnapshotsToCreate[$i].Progress) in state $($SnapshotsToCreate[$i].State)"
							$SnapshotsToCreate[$i] = Get-EC2Snapshot -SnapshotId $SnapshotsToCreate[$i].SnapshotId @DestinationSplat
							$SnapshotsToCreate[$i].VolumeId = $TempVolId
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
				# Not a cross region move and/or not encrypting the new , so assign the current snapshots to the variable
				# that we will evaluate to create the volumes from

				$SourceSnapshots.CopyTo($SnapshotsToCreate, 0)

				# Empty the original array to be able to identify what needs
				# to be deleted later, otherwise the finally block will try to delete the 
				# same snapshots twice
				$SourceSnapshots = @()
			}

			# Create the new volumes from the newly created snapshots
			# The destination splat will either have the new region if it was specified or will be the same as the source region
			# The AZ was determined from the source instance if the source and destination region were the same, otherwise
			# the AZ was selected from the Destination instance, if one was provided, if it wasn't, then a default AZ for the new region
			# was selected
			[Amazon.EC2.Model.Volume[]]$NewVolumes = $SnapshotsToCreate | ForEach-Object {
				[System.Collections.Hashtable]$NewVolumeSplat = @{}

				# Make sure we use the right volume type for the destination
				if ($PSBoundParameters.ContainsKey("VolumeType"))
				{
					$NewVolumeSplat.Add("VolumeType", $VolumeType)

					if ($VolumeType -eq [Amazon.EC2.VolumeType]::Io1)
					{
						# Make sure the maximum of 50 IOPS to GiB isn't exceeded
						if ($Iops -le ($_.VolumeSize * 50))
						{
							$NewVolumeSplat.Add("Iops", $Iops)
						}
						else
						{
							Write-Warning -Message "The desired IOPS for the snapshot from $($_.VolumeId) exceed the maximum ratio of 50 IOPS / GiB. This has been throttled to $([System.Math]::Floor($_.VolumeSize) * 50)"
							$NewVolumeSplat.Add("Iops", [System.Math]::Floor($_.VolumeSize) * 50)
						}
					}
				}
				else
				{
					Write-Verbose -Message "Retrieving source volume attributes for volume $($_.VolumeId)."
					[Amazon.EC2.Model.Volume]$SourceVolume = $EBSVolumes | Where-Object {$_.VolumeId -eq $_.VolumeId} | Select-Object -First 1
					$NewVolumeSplat.Add("VolumeType", $SourceVolume.VolumeType)

					if ($SourceVolume.VolumeType -eq [Amazon.EC2.VolumeType]::Io1)
					{
						$NewVolumeSplat.Add("Iops", $SourceVolume.Iops)
					}
				}

				# The dynamic param VolumeSize should only be added if there is 1 source, but
				# but let's make sure. We also validated earlier than if there was 1 source and this
				# parameter was specified, that it wasn't smaller than the current volume size
				if ($PSBoundParameters.ContainsKey("VolumeSize") -and $SnapshotsToCreate.Length -eq 1)
				{
					[System.Int32]$Size = $PSBoundParameters["VolumeSize"]

					# This check is probably unnecessary here since we checked earlier, but can't hurt
					if ($Size -ge $_.VolumeSize)
					{
						$NewVolumeSplat.Add("Size", $Size)
					}
					else
					{
						throw "The specified new volume size, $Size GiB, is not greater than or equal to the current volume size of $($_.VolumeSize) GiB."
					}
				}

                if ($CopyTags)
                {
                    [Amazon.EC2.Model.TagSpecification]$Tags = New-Object -TypeName Amazon.EC2.Model.TagSpecification

			        $Tags.ResourceType = [Amazon.EC2.ResourceType]::Volume

			        $Tags.Tags = $_.Tags

                    $NewVolumeSplat.Add("TagSpecification", $Tags)
                } 

				[Amazon.EC2.Model.Volume]$NewVol = New-EC2Volume -SnapshotId $_.SnapshotId -AvailabilityZone $AvailabilityZone @DestinationSplat @NewVolumeSplat 

				Write-Output -InputObject $NewVol
			}

			# Reset the counter for the next loop
			$Counter = 0

			# Wait for the new volumes to become available before we try to attach them
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

			# Check if a destination instance was specified
			if ($Destination -ne $null)
			{
				Write-Verbose -Message "Mounting volumes."
				Mount-EBSVolumes -VolumeIds ($NewVolumes | Select-Object -ExpandProperty VolumeId) -NextAvailableDevice -Instance $Destination @DestinationAWSUtilitiesSplat
			}
			elseif ($PSCmdlet.ParameterSetName -like ("DestinationBy*"))
			{
				# This means a destination instance was specified, but we didn't
				# find it in the Get-EC2Instance cmdlet
				Write-Warning -Message "[ERROR] Could not find the destination instance"
			}

            Write-Output -InputObject $NewVolumes					
		}
		finally
		{		
			if ($DeleteSnapshots)
			{
				# Delete the original source Region snapshots if there are any
				if ($SourceSnapshots -ne $null -and $SourceSnapshots.Length -gt 0)
				{
					Write-Verbose -Message "Deleting snapshots $([System.String]::Join(",", ($SourceSnapshots | Select-Object -ExpandProperty SnapshotId)))"
					$SourceSnapshots | Remove-EC2Snapshot @SourceSplat -Confirm:$false
				}

                # Delete the snapshots used to create the new volumes, there should always be something to delete here
                # unless the cmdlet threw an exception
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
			LAST UPDATE: 1/23/2019
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "IdAndNextAvailable")]
		[Parameter(Mandatory = $true, ParameterSetName = "InputObjectAndNextAvailable")]
		[ValidateNotNullOrEmpty()]
		[System.String[]]$VolumeIds,

		[Parameter(ParameterSetName = "InputObjectAndNextAvailable", Mandatory = $true)]
		[Parameter(ParameterSetName = "IdAndNextAvailable", Mandatory = $true)]
		[Switch]$NextAvailableDevice,

		[Parameter(ParameterSetName = "InputObjectAndDevice", Mandatory = $true)]
		[Parameter(ParameterSetName = "IdAndDevice", Mandatory = $true)]
		[ValidateSet("xvdf", "xvdg", "xvdh", "xvdi", "xvdj",
			"xvdk", "xvdl", "xvdm", "xvdn", "xvdo", "xvdp",
			"/dev/sdf", "/dev/sdg", "/dev/sdh", "/dev/sdi", "/dev/sdj",
			"/dev/sdk", "/dev/sdl", "/dev/sdm", "/dev/sdn", "/dev/sdo", "/dev/sdp")]
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
			$Instance = Get-EC2Instance -InstanceId $InstanceId @Splat | Select-Object -ExpandProperty Instances | Select-Object -First 1
		}

		if ($Instance.Platform -ieq "windows")
		{
			[System.String]$DeviceBase = "xvd"
		}
		else
		{
			[System.String]$DeviceBase = "/dev/sd"
		}

		[System.Int32]$CurrentLetter = 0

		if ($NextAvailableDevice)
		{
			# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html
			# https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/device_naming.html
			# Both docs start recommended device naming at "f" for EBS volumes
			$CurrentLetter = [System.Int32][System.Char]'f'
		}
		else
		{
			$CurrentLetter = [System.Int32][System.Char]$Device.Substring($Device.Length - 1)
		}

		# Iterate all of the new volumes and attach them
		foreach ($Item in $VolumeIds)
		{
			try
			{
				# Update the instance object so we get updated block device mappings
				$Instance = Get-EC2Instance -InstanceId $Instance.InstanceId @Splat | Select-Object -ExpandProperty Instances | Select-Object -First 1
				[System.String[]]$Devices = $Instance.BlockDeviceMappings | Select-Object -ExpandProperty DeviceName

				# Try to find an available device
				while ($Devices.Contains($DeviceBase + [System.Char]$CurrentLetter) -and [System.Char]$CurrentLetter -ne 'q')
				{
					$CurrentLetter++
				}

				# The last usable letter is p, so if we get to q, there aren't any available device mounts left
				if ([System.Char]$CurrentLetter -ne 'q')
				{
					Write-Verbose -Message "Attaching $Item to $($Instance.InstanceId) at device $DeviceBase$([System.Char]$CurrentLetter)"
                        
					# The cmdlet will create the volume as the same size as the snapshot
					[Amazon.EC2.Model.VolumeAttachment]$Attachment = Add-EC2Volume -InstanceId $Instance.InstanceId -VolumeId $Item -Device ($DeviceBase + [System.String][System.Char]$CurrentLetter) @Splat
					Write-Verbose -Message "Attached at $($Attachment.AttachTime)"
                    
					# Increment the letter so the next check doesn't try to use the same device
					$CurrentLetter++
				}
				else
				{
					# Break out of the iteration because we can't mount any more drives
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

Function Dismount-EBSVolumes {
	<#
		.SYNOPSIS
			Dismounts either specific or all EBS volumes from a single EC2 instance.

		.DESCRIPTION
			The cmdlet dismounts volumes from an EC2 instance. If you specify specific volume Ids, just these will be dismounted from the instance, otherwise all volumes will attempt to be dismounted. 

			If the instance is not stopped (i.e. running or stopping), and you try to remove the root volume, this cmdlet will fail. You may optionally indicate that you want to stop the instance before attempting to dismount the volumes.
			
		.PARAMETER InstanceId
			The Id of the instance to dismount volumes from. It should ideally be stopped for the best results. 

		.PARAMETER Instance
			The instance object to dismount volumes from. It should ideally be stopped for the best results.

		.PARAMETER VolumeId
			The Ids of the volumes to dismount from the specified instance. If this parameter is not specified, all volumes, except the root volume, are dismounted.

		.PARAMETER IncludeRootVolume
			When this option is specified, the root instance volume is included with all the volumes to detach from the specified instance. The instance must be stopped, or you must specify the StopInstance parameter for the cmdlet to succeed.

			The VolumeId parameter is not available if this is specified, this adds the root volume to the list of all other volumes on the instance, by default the root volume is not included when the VolumeId parameter is not specified.
			
		.PARAMETER StopInstance
			If the instance is not already stopped, this initiates a Stop and waits for the instance to enter the stopped state.

		.PARAMETER Wait
			This will wait for the volumes to finish being dismounted and enter the available state.

		.PARAMETER Delete
			The volumes will be deleted after they are dismounted. If you specify this parameter, the Wait parameter is automatically specified.

		.PARAMETER ForceDismount
			The volumes with be force dismounted, this could cause data loss or corruption.

		.PARAMETER Timeout
			The amount of time to wait in seconds for the operation to complete before it is considered unsuccessful. Defaults to 600.

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
			$Instance = Get-EC2Instance -InstanceId i-09740780dc39bde98 | Select-Object -ExpandProperty Instances -First 1
			Dismount-EBSVolumes -Instance $Instance -StopInstance -IncludeRootVolume -Wait

			The specified instance will be stopped, then all of its volumes, including the root volume will be dismounted. The cmdlet waits for the volumes to enter the available state indicating the dismount operation succeeded.

		.EXAMPLE
			$Instance = Get-EC2Instance -InstanceId i-09740780dc39bde98 | Select-Object -ExpandProperty Instances -First 1
			Dismount-EBSVolumes -InstanceId $Instance.InstanceId -VolumeId @("vol-0aa65525bf363acfe") -Wait

			The specified volume is dismounted from the indicated instance. In this case, the specified volume is not the root volume and can be dismounted while the instance is still running. The cmdlet waits for the volume to become available before returning.

		.EXAMPLE
			$Instance = Get-EC2Instance -InstanceId i-09740780dc39bde98 | Select-Object -ExpandProperty Instances -First 1
			Dismount-EBSVolumes -Instance $Instance -StopInstance -IncludeRootVolume -Delete

			All volumes, including the root volume are dismounted from the instance after it is stopped. Once the volumes enter an available state, they are deleted. The cmdlet does not wait for the delete operation to complete.

		.EXAMPLE
			$Instance = Get-EC2Instance -InstanceId i-09740780dc39bde98 | Select-Object -ExpandProperty Instances -First 1
			Dismount-EBSVolumes -Instance $Instance -Wait

			All volumes except the root volume are dismounted from the running instance. The cmdlet waits for the volumes to enter the available state.

		.INPUTS
			None or Amazon.EC2.Model.Instance

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

			The output contains the VolumeId and the Device the volume was attached to on the instance. For example:

			@(
				[PSCustomObject]@{ "VolumeId" = "vol-0aa65525bf363acfe"; "Device" = "/dev/xvda" },
				[PSCustomObject]@{ "VolumeId" = "vol-03eaea54d02ec33dc"; "Device" = "/dev/sda1" }
			)

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/30/2019
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = [System.Management.Automation.ConfirmImpact]::Medium)]
	[OutputType([PSCustomObject[]])]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "InstanceIdWithVolumes")]
		[Parameter(Mandatory = $true, ParameterSetName = "InstanceIdNoVolumes")]
        [ValidateNotNullOrEmpty()]
        [System.String]$InstanceId,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = "InstanceWithVolumes")]
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = "InstanceNoVolumes")]
        [ValidateNotNull()]
        [Amazon.EC2.Model.Instance]$Instance,

        [Parameter(ParameterSetName = "InstanceIdWithVolumes", Mandatory = $true)]
		[Parameter(ParameterSetName = "InstanceWithVolumes", Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]$VolumeId = @(),

		[Parameter(ParameterSetName = "InstanceIdNoVolumes")]
		[Parameter(ParameterSetName = "InstanceNoVolumes")]
		[Switch]$IncludeRootVolume,

		[Parameter()]
		[Switch]$StopInstance,

        [Parameter()]
        [Switch]$Wait,

		[Parameter()]
		[Switch]$Delete,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[Switch]$ForceDismount,

        [Parameter()]
        [ValidateRange(1, [System.Int32]::MaxValue)]
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
		[System.Boolean]$YesToAll = $false
		[System.Boolean]$NoToAll = $false
    }

    Process {
        [System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		[System.Collections.Hashtable]$AwsUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $Splat

        [System.Collections.Generic.Queue[Amazon.EC2.Model.Volume]]$VolumesToDetach = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.Volume]
		[System.Collections.Generic.Dictionary[System.String, System.String]]$TrackedVolumes = New-Object -TypeName "System.Collections.Generic.Dictionary[System.String, System.String]"
        [PSCustomObject[]]$DetachedVolumes = @()

        if ($PSCmdlet.ParameterSetName -like "InstanceId*")
        {
            $Instance = Get-EC2InstanceByNameOrId -InstanceId $InstanceId @AwsUtilitiesSplat

            if ($Instance -eq $null)
            {
                throw "Could not find an instance with id $InstanceId."
            }
        }

		# The instance is terminated or in the process of termination
        if ($Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::Terminated -or $Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::ShuttingDown)
        {
            throw "This cmdlet cannot be used on an instance that is terminating or terminated."
        }

		# This will make sure the block device mappings are populated for a pending instance before tracking the volumes
		if($Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::Pending -and $Instance.BlockDeviceMappings -eq $null -or $Instance.BlockDeviceMappings.Count -eq 0)
		{
			Write-Verbose -Message "Waiting for instance to populate block device mappings during pending state."
			Start-Sleep -Seconds 5
            $Instance = Get-EC2InstanceByNameOrId -InstanceId $Instance.InstanceId @AwsUtilitiesSplat
		}

		[Amazon.EC2.Model.EbsInstanceBlockDevice[]]$EbsVolumes = $Instance.BlockDeviceMappings | Select-Object -ExpandProperty Ebs
		[Amazon.EC2.Model.Volume[]]$SourceVolumes = @()

		# Check to see if the user passed Volume Ids, and if they didn't make sure the instance has actual block device mappings
        # It's possible the user passes in a stopped instance that already has all block devices removed
        if ($VolumeId -eq $null -or $VolumeId.Count -eq 0 -and $Instance.BlockDeviceMappings -ne $null -and $Instance.BlockDeviceMappings.Count -gt 0)
        {
			$SourceVolumes = $Instance.BlockDeviceMappings | Select-Object -ExpandProperty Ebs | ForEach-Object {
				Write-Output -InputObject (Get-EC2Volume -VolumeId $_.VolumeId @Splat)
			}
			$VolumeId = $EbsVolumes | Select-Object -ExpandProperty VolumeId

			if (-not $IncludeRootVolume)
			{	
				$SourceVolumes = $SourceVolumes | Where-Object { $_.Attachments[0].Device -ne $Instance.RootDeviceName}

				if ($SourceVolumes -ne $null -and $SourceVolumes.Count -gt 0)
				{
					$VolumeId =  $SourceVolumes | Select-Object -ExpandProperty VolumeId
				}
			}
        }
		else
		{
			# Make sure the user provided volume Ids are attached to the specified instance			
			[System.String[]]$AttachedVolumeIds = $EbsVolumes | Select-Object -ExpandProperty VolumeId
			
			foreach ($Volume in $VolumeId)
			{
				if ($Volume -inotin $AttachedVolumeIds)	
				{
					throw "A provided volume, $Volume, is not one of the attached volumes for instance $($Instance.InstanceId): $([System.String]::Join(",", $AttachedVolumeIds))."
				}
			}

			$SourceVolumes = $VolumeId | ForEach-Object {
				Write-Output -InputObject (Get-EC2Volume -VolumeId $_ @Splat)
			}
		}

		foreach ($Volume in $SourceVolumes)
		{ 
			$TrackedVolumes.Add($Volume.VolumeId, $Volume.Attachments[0].Device)
		} 

		# Cannot remove volumes from a pending instance, make sure the instance leaves pending
		while ($Instance.State.Name -eq [Amazon.EC2.InstanceStateName]::Pending)
		{
			Write-Verbose -Message "Waiting for instance to reaching a running state."
			Start-Sleep -Seconds 5
            $Instance = Get-EC2InstanceByNameOrId -InstanceId $Instance.InstanceId @AwsUtilitiesSplat
		}

		# If the instance isn't stopped, see if the user specified to stop it, or prompt them to confirm
		if ($Instance.State.Name -ne [Amazon.EC2.InstanceStateName]::Stopped )
		{
			if ($StopInstance)
			{
                $StopSplat = @{}

                if ($Force)
                {
                    $StopSplat.Add("Force", $true)
                }

				Set-EC2InstanceState -InstanceId $Instance.InstanceId -State STOP -Wait @StopSplat @AwsUtilitiesSplat | Out-Null
			}
			else
			{
				$RootVolumeId = $Instance.BlockDeviceMappings | Where-Object { $_.DeviceName -eq $Instance.RootDeviceName } | Select-Object -ExpandProperty Ebs | Select-Object -ExpandProperty VolumeId
				
				if ($VolumeId -contains $RootVolumeId)
				{
					throw "You are trying to remove the root volume $RootVolumeId from a non-stopped instance. This will never succeed."
				}

				Write-Warning -Message "The EC2 instance $($Instance.InstanceId) is not stopped, it is currently $($Instance.State)."

				$Query = "Are you sure you want to dismount volumes from an instance that is not stopped? This could cause data corruption or fail to detach the volume(s)."
				$Caption = "Dismount Volumes"

				if (-not $Force -or -not $PSCmdlet.ShouldContinue($Query, $Caption))
				{
					Exit
				}
			}
		}

		if ($SourceVolumes -ne $null -and $SourceVolumes.Count -gt 0)
		{			
			$VerboseDescription = "Dismount volumes $([System.String]::Join(",", $VolumeId)) from instance $($Instance.InstanceId)"
			$VerboseWarning = "Are you sure you want dismount volumes $([System.String]::Join(",", $VolumeId)) from $($Instance.InstanceId)?"
			$Caption = "Dismount Volumes"

			if ($PSCmdlet.ShouldProcess($VerboseDescription, $VerboseWarning, $Caption))
			{
				[System.Collections.Hashtable]$VolumeSplat = @{}

				if ($ForceDismount)
				{
					$VolumeSplat.Add("ForceDismount", $true)
				}

				foreach ($Volume in $SourceVolumes)
				{
					$Query = "Dismount volume $($Volume.VolumeId) from instance $($Instance.InstanceId)?"
					$Caption = "Dismount Volume"

					if ($Force -or $PSCmdlet.ShouldContinue($Query, $Caption, [ref]$YesToAll, [ref]$NoToAll))
					{
						if ($Volume.Attachments -ne $null -and $Volume.Attachments.Count -gt 0)
						{
							$VolumesToDetach.Enqueue($Volume)

							Write-Verbose -Message "Dismounting volume $($Volume.VolumeId) at device $($Volume.Attachments[0].Device) from the instance."				
							Dismount-EC2Volume -VolumeId $Volume.VolumeId -InstanceId $Instance.InstanceId @Splat @VolumeSplat | Out-Null		
						}
						else
                        {
                            Write-Verbose -Message "It appears that volume $Id became dismounted during the cmdlet operation, the DescribeVolumes API did not return Attachment data, its device name may not be tracked."
                        }
					}
				}

				$YesToAll = $false
				$NoToAll = $false

				if ($Wait -or $Delete)
				{
					[System.Diagnostics.Stopwatch]$SW = [System.Diagnostics.Stopwatch]::StartNew()

					while ($VolumesToDetach.Count -gt 0 -and $SW.Elapsed.TotalSeconds -le $Timeout)
					{
						[Amazon.EC2.Model.Volume]$Volume = $VolumesToDetach.Dequeue()

						switch ($Volume.State)
						{
							([Amazon.EC2.VolumeState]::Available) {
								Write-Verbose -Message "Successfully detached volume $($Volume.VolumeId) from $($Instance.InstanceId)."     
                        
								if ($Delete)
								{
									Write-Verbose -Message "Deleting volume $($Volume.VolumeId)"

									$Query = "Permanently delete EBS volume $($Volume.VolumeId)?"
									$Caption = "Delete Volume"

									if ($Force -or $PSCmdlet.ShouldContinue($Query, $Caption, [ref]$YesToAll, [ref]$NoToAll))
									{
										Remove-EC2Volume -VolumeId $Volume.VolumeId -Force @Splat | Out-Null
									}
								}
                                     
								break
							}
							([Amazon.EC2.VolumeState]::InUse) {
								# Keep waiting
								$VolumesToDetach.Enqueue($Volume)
								break
							}
							{$_ -in @([Amazon.EC2.VolumeState]::Creating, [Amazon.EC2.VolumeState]::Deleted, [Amazon.EC2.VolumeState]::Deleting, [Amazon.EC2.VolumeState]::Error) } {
								throw "Invalid state for volume $($Volume.VolumeId): $($Volume.State)."
							}
							default {
								throw "Unknown volume state $($Volume.State) for volume $($Volume.VolumeId)."
							}
						}

						# Only update the volume list if all of them are not available
						if ($VolumesToDetach.Count -gt 0 -and ($VolumesToDetach | Where-Object { $_.Status -ne [Amazon.EC2.VolumeState]::Available}).Count -eq $VolumesToDetach.Count)
						{
							Write-Verbose -Message "Waiting for volumes to finish detaching."
							Start-Sleep -Seconds 10

							$Arr = $VolumesToDetach.ToArray()

							$VolumesToDetach = New-Object -TypeName System.Collections.Generic.Queue[Amazon.EC2.Model.Volume]

							for ($i = 0; $i -lt $Arr.Length; $i++)
							{
								$VolumesToDetach.Enqueue((Get-EC2Volume -VolumeId $Volume.VolumeId @Splat))
							}
						}
					}

					$SW.Stop()

					if ($SW.Elapsed.TotalSeconds -gt $Timeout -and $VolumesToDetach.Count -gt 0)
					{
						throw "Timeout occured waiting for volumes to finish being dismounted. Did not finish dismounting volumes $([System.String]::Join(",", ($VolumesToDetach | Select-Object -ExpandProperty VolumeId)))."
					}
				}
			}

			foreach ($Key in $TrackedVolumes.Keys)
            {
				$DetachedVolumes += [PSCustomObject]@{"VolumeId" = $Key; "Device" = $TrackedVolumes[$Key]}
            }

			Write-Output -InputObject $DetachedVolumes
		}
		else 
		{
			Write-Verbose -Message "No volumes to dismount."
			Write-Output -InputObject $DetachedVolumes
		}
    }

    End {
    }
}

Function Invoke-EBSVolumeAttachmentWait {
    <#
        .SYNOPSIS 
            Waits for a specified set of volumes to reach an attached state.

        .DESCRIPTION
            The cmdlet waits for a specified set of volumes to be in-use and attached to an EC2 instance.

        .PARAMETER Volume
            The volume(s) to wait to become attached.

        .PARAMETER VolumeId
            The volume Id(s) to wait to become attached.

        .PARAMETER Timeout
            The amount of time to wait in seconds before the cmdlet fails. Defaults to 600.

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
            Invoke-EBSVolumeAttachmentWait -VolumeId @("vol-0f8d10b5ca8259a17", "vol-03fa72bf6ed7c2ed3")

            This waits for the two specified volumes to be in use and attached to an instance.

        .INPUTS
            Amazon.EC2.Model.Volume[]

        .OUTPUTS
            None

        .NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/30/2019
    #>    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = "Volume")]
        [ValidateNotNullOrEmpty()]
        [Amazon.EC2.Model.Volume[]]$Volume,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "VolumeId")]
        [ValidateNotNullOrEmpty()]
        [System.String[]]$VolumeId,

        [Parameter()]
        [ValidateRange(1, [System.Int32]::MaxValue)]
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
		if ($PSCmdlet.ParameterSetName -eq "Volume")
        {
            $VolumeId = $Volume | Select-Object -ExpandProperty VolumeId
        }
    }

    Process {
        [System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		[System.Collections.Hashtable]$AwsUtilitiesSplat = New-AWSUtilitiesSplat -AWSSplat $Splat
        
        # Use "," trick to preven the array from being unrolled
        [System.Collections.Generic.Queue[System.String]]$VolumeQueue = New-Object -TypeName System.Collections.Generic.Queue[System.String] -ArgumentList (,$VolumeId)

        [System.Diagnostics.Stopwatch]$SW = [System.Diagnostics.Stopwatch]::StartNew()

        # Track the source volumes that are now attached to the new instance to make sure they finish attaching
        while ($VolumeQueue.Count -gt 0 -and $SW.Elapsed.TotalSeconds -le $Timeout)
        {
            [System.String]$Id = $VolumeQueue.Dequeue()
            [Amazon.EC2.Model.Volume]$Volume = Get-EC2Volume -VolumeId $Id @Splat

            switch ($Volume.State)
            {
                ([Amazon.EC2.VolumeState]::InUse) {
                    
                    switch ($Volume.Attachments[0].State)
                    {
                        ([Amazon.EC2.AttachmentStatus]::Attached) {
                            Write-Verbose -Message "Volume $($Volume.VolumeId) is attached to $($Volume.Attachments[0].InstanceId)."
                            break
                        }
                        ([Amazon.EC2.AttachmentStatus]::Attaching) {
                            $VolumeQueue.Enqueue($Id)
                            break
                        }
                        {$_ -in @([Amazon.EC2.AttachmentStatus]::Detached, [Amazon.EC2.AttachmentStatus]::Detaching)} {
                            throw "The volume $($Volume.VolumeId) is in attachment state $($Volume.Attachments[0].State), which is not attaching or attached."
                        }
                        default {
                            throw "Unknown attachment state $($Volume.Attachments[0].State) for volume $($Volume.VolumeId)."
                        }
                    }

                    break
                }
                ([Amazon.EC2.VolumeState]::Available) {                  
                    $VolumeQueue.Enqueue($Id)
                    break
                }
                {$_ -in @([Amazon.EC2.VolumeState]::Deleted, [Amazon.EC2.VolumeState]::Deleting, [Amazon.EC2.VolumeState]::Error, [Amazon.EC2.VolumeState]::Creating) } {
                    throw "The volume $($Volume.VolumeId) is not in an expected state to be waited on for attachment."
                }
                default {
                    throw "Unknown volume state $($Volume.State) for volume $($Volume.VolumeId)."
                }
            }

            if (($DevcesToAttach | Where-Object { $_.Attachments -eq $null -or 
                $_.Attachments.Count -eq 0 -or
                $_.Attachments[0].State -ne [Amazon.EC2.AttachmentStatus]::Attached}).Count -gt 0)
            {
                Write-Verbose -Message "Waiting for volumes to finish attaching."
                Start-Sleep -Seconds 10
            }
        }

        $SW.Stop()

        if ($SW.Elapsed.TotalSeconds -gt $Timeout)
        {
            throw "Timeout waiting for all volumes to finish attaching."
        }
    }

    End {
    }
}

#endregion

#region Splat Functions

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
		# Map the common AWS parameters
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
			    # Get-DefaultAWSRegions returns a Amazon.Powershell.Common.AWSRegion object
 			    $CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($RegionTemp) | Select-Object -ExpandProperty SystemName
            }
            else
            {
                # No default region set
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
			Builds a hashtable that can be used as a splat for default AWS parameters in the AWS Utilities PowerShell module.

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
			System.Collections.Hashtable

		.OUTPUTS
			System.Collections.Hashtable

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/16/2019
	#>
	[CmdletBinding(DefaultParameterSetName = "Specify")]
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

		[Parameter(ParameterSetName = "Splat", ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$AWSSplat
	)

	Begin {
	}

	Process {
		# Map the common AWS parameters
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
					# Get-DefaultAWSRegions returns a Amazon.Powershell.Common.AWSRegion object
 					[Amazon.RegionEndpoint]$CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($RegionTemp)
				}
				else
				{
					# No default region set
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

#endregion

#region KMS Functions

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

		.PARAMETER Encoding
			The encoding to use to convert the text to bytes. This defaults to UTF-8.

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
			LAST UPDATE: 1/17/2019
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
		[System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,

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
			[System.Byte[]]$Bytes = $Encoding.GetBytes($InputObject)

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

		.PARAMETER Encoding
			The encoding to use to convert the bytes back to text. This defaults to UTF-8.

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
			LAST UPDATE: 1/17/2019
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
		[System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,

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
			
			Write-Output -InputObject ($Encoding.GetString($Response.PlainText.ToArray()))
		}
		finally
		{
			$MStream.Dispose()
		}		
	}

	End {
	}
}

#endregion

#region Networking Functions

Function Get-AWSVPCEndpointsByLocation {
	<#
		.SYNOPSIS
			Gets the available VPC endpoints for AWS services per location, which can be region or availability zone.

		.DESCRIPTION
			This cmdlets iterates all regions and gets the AWS VPC service endpoints for that region. If the cmdlet specifies ByAvailabilityZone, then it adds each AZ in that region with the available services there, otherwise, it adds the region and the available services there. If a service is available in a region, it is not necessarily available in each AZ in that region.

            The cmdlet can also be run using both region and AZ as object level keys for the output object.

			The output from this cmdlet is intended to be used as a Mapping resource in CloudFormation so that it provides an easy way to check whether a PrivateLink endpoint service is available.

		.PARAMETER CopyToClipboard
			Copies the output to the clipboard as a JSON string.

		.PARAMETER AsJson
			Outputs as a JSON string instead of a PSCustomObject. Use this JSON as a Mapping element in CloudFormation to see if an endpoint service is available in a specific region or AZ.

		.PARAMETER ByAvailabilityZone
			This specifies which endpoints are available by AZ instead of by region. The AZ names are the top level keys in the output. This can be used as a mapping resource in CloudFormation.

        .PARAMETER ByRegionAndAZ
            This specifies which endpoints are available by AZ instead of by region. The region names are the top level keys in the output, with the AZs being underneath them. This output cannot be used as a mapping resource in CloudFormation as it goes 1 level too deep.

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
			$Json = Get-AWSVPCEndpointsByLocation -ProfileName dev -AsJson

			Gets the VPC endpoint mapping aligned to regions and returns the data as a JSON string.

		.EXAMPLE
			$AZMapping = Get-AWSVPCEndpointsByLocation -ProfileName dev -ByAvailabilityZone

			Gets the VPC endpoint mapping per AZ.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCustomObject, System.Sting

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/17/2019
	#>
    [CmdletBinding(DefaultParameterSetName="ByRegion")]
    Param(
        [Parameter()]
        [Switch]$CopyToClipboard,

        [Parameter()]
        [Switch]$AsJson,

        [Parameter(ParameterSetName = "ByAZ")]
        [Switch]$ByAvailabilityZone,

        [Parameter(ParameterSetName = "ByRegionAndAZ")]
        [Switch]$ByRegionAndAZ,

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
		[System.Collections.Hashtable]$Splat = New-AWSSplat -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		$Splat.Remove("Region")

        $Mapping = [PSCustomObject]@{}
        $AllServices = New-Object -TypeName System.Collections.Generic.Hashset[System.String]

        [System.String[]]$Regions =  Get-AWSRegion | Select-Object -ExpandProperty Region | Sort-Object
		[System.Int32]$i = 0

		$Regions | ForEach-Object {
            $Region = $_

			Write-Progress -Activity "Processing regions" -Status "Processing $Region" -PercentComplete ([System.Math]::Round(($i / $Regions.Length) * 100, 2)) 
			$i++
                    
            [System.String[]]$RegionAZs = Get-EC2AvailabilityZone -Region $Region @Splat | Select-Object -ExpandProperty ZoneName | Sort-Object

            Write-Verbose -Message "Processing region: $Region"
        
            switch ($PSCmdlet.ParameterSetName)
            {
                "ByRegion" {
                    $Mapping | Add-Member -Name $Region -MemberType NoteProperty -Value ([PSCustomObject]@{})
                    break
                }
                "ByAZ" {
                    $RegionAZs | ForEach-Object {
                        $Mapping | Add-Member -Name $_ -MemberType NoteProperty -Value ([PSCustomObject]@{})
                    }
                    break
                }
                "ByRegionAndAZ" {
                    $Mapping | Add-Member -Name $Region -MemberType NoteProperty -Value ([PSCustomObject]@{})

                    $RegionAZs | ForEach-Object {
                        $Mapping.$Region | Add-Member -Name $_ -MemberType NoteProperty -Value ([PSCustomObject]@{})
                    }

                    break
                }
                default {
                    throw "Parameter set name $($PSCmdlet.ParameterSetName) could not be resolved."
                }
            }

            Get-EC2VpcEndpointService -Region $Region @Splat | Select-Object -ExpandProperty ServiceDetails | ForEach-Object {
                [Amazon.EC2.Model.ServiceDetail]$Detail = $_

                $Name = $Detail.ServiceName.Substring($Detail.ServiceName.IndexOf($Region) + $Region.Length).Replace(".", "").Replace("-", "")

                $AllServices.Add($Name) | Out-Null

                switch ($PSCmdlet.ParameterSetName)
                {
                    "ByRegion" {
                        $Mapping.$Region | Add-Member -Name $Name -MemberType NoteProperty -Value $true
                        break
                    }
                    "ByAZ" {
                        $RegionAZs | ForEach-Object {                  
                            $Mapping.$_ | Add-Member -Name $Name -MemberType NoteProperty -Value ($Detail.AvailabilityZones -icontains $_)
                        }
                        break
                    }
                    "ByRegionAndAZ" {
                        $RegionAZs | ForEach-Object {
                            $Mapping.$Region.$_ | Add-Member -Name $Name -MemberType NoteProperty -Value ($Detail.AvailabilityZones -icontains $_)
                        }

                        break
                    }
                    default {
                        throw "Parameter set name $($PSCmdlet.ParameterSetName) could not be resolved."
                    }
                } 
            }                 
        }

        # Review each region or AZ and check to see if a service was not available in the region that was available in another region,
        # this will make sure that each AZ or region has the same list of services as all others
        switch ($PSCmdlet.ParameterSetName)
        {
            {$_ -iin @("ByRegion", "ByAZ")} {

                $Mapping | Get-Member -MemberType NoteProperty | ForEach-Object {
                    $Location = $_.Name
                    $Temp = [PSCustomObject]@{}
                    
                    $Names = $Mapping.$Location | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

                    foreach ($Service in $AllServices)
                    {
                        if ($Service -inotin $Names)
                        {
                            Write-Verbose -Message "Adding missing service $Service to $Location"

                            $Mapping.$Location | Add-Member -Name $Service -MemberType NoteProperty -Value $false
                        }
                    }

                    $Mapping.$Location | Get-Member -MemberType NoteProperty | Sort-Object -Property Name | Select-Object -ExpandProperty Name | ForEach-Object {
                        $Temp | Add-Member -Name $_ -MemberType NoteProperty -Value $Mapping.$Location.$_
                    }

                    $Mapping.$Location = $Temp
                }
                    
                break
            }
            "ByRegionAndAZ" {
                $Mapping | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name | ForEach-Object {
                    $Region = $_
                    $Mapping.$Region | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name | ForEach-Object {
                        $AZ = $_
                        $Names = $Mapping.$Region.$AZ | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

                        $Temp = [PSCustomObject]@{}

                        foreach ($Service in $AllServices)
                        {
                            if ($Service -inotin $Names)
                            {
                                Write-Verbose -Message "Adding missing service $Service to $Location"
                                $Mapping.$Region.$AZ | Add-Member -Name $Service -Value $false -MemberType NoteProperty
                            }
                        }

                        $Mapping.$Region.$AZ | Get-Member -MemberType NoteProperty | Sort-Object -Property Name | Select-Object -ExpandProperty Name | ForEach-Object {
                            $Temp | Add-Member -Name $_ -MemberType NoteProperty -Value $Mapping.$Region.$AZ.$_
                        }

                        $Mapping.$Region.$AZ = $Temp
                    }
                }

                break
            }
            default {
                throw "Parameter set name $($PSCmdlet.ParameterSetName) could not be resolved."
            }
        } 
        
        if ($AsJson)
        {
            $Json = $Mapping | ConvertTo-Json
            Write-Output -InputObject $Json          

            if ($CopyToClipboard)
            {
                $Json | Set-Clipboard
            }
        }
        else
        {
            Write-Output -InputObject $Mapping

            if ($CopyToClipboard)
            {
                $Json = $Mapping | ConvertTo-Json
                $Json | Set-Clipboard
            }
        }
    }

    End {
    }
}

#endregion


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

			Set-EC2InstanceState -InstanceId $EC2.InstanceId -State STOP -Wait -Timeout $Timeout -Force @AwsUtilitiesSplat

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

				$Result = Set-EC2InstanceState -InstanceId $EC2.InstanceId -State START -Force @AwsUtilitiesSplat
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


Function Get-AWSCloudTrailLogs {
	<#
		.SYNOPSIS
			Gets CloudTrail log files from an S3 bucket.

		.DESCRIPTION
			The cmdlet retrieves CloudTrail log data from S3 for the specified region. It expects the S3 keys for the files to be in the AWS created syntax:

			AWSLogs/AccountId/CloudTrail/Region/Year/Month/Day/filename.json.gz

			The contents of the log files are returned uncompressed. Additionally, the returned records can be filtered by eventName, aka API action, like DescribeInstances.

		.PARAMETER Bucket
			The name of the bucket containing the log files.

		.PARAMETER AccountId
			Specify the account Id in the S3 object key, this may not be the same as the account in which the S3 bucket exists if cross account CloudTrail log delivery is enabled.

			This parameter defaults to the account associated with the credentials of the calling user.

		.PARAMETER Start
			Specifies the date to retrieve log files after (inclusive). The date is represented in UTC time.

		.PARAMETER End
			Specifies the date to retrieve log files before (inclusive). The date is represented in UTC time.

		.PARAMETER APIs
			Specifies the eventName attribute of the CloudTrail log object to match against when retrieving log records. If this is not specified, all records are returned.

		.PARAMETER Filter
			You can specify a hash table of key values that correspond to properties of the CloudTrail log. You can specify sub-properties as the key like:

			@{"userIdentity.arn" : "arn:aws:iam::*:instance-profile/*" }

			The value can contain wildcards to match against the CloudTrail log attributes.

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked and the region for which to get CloudTrail log records from S3. For example, us-east-1, eu-west-1 etc. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

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
			$End = [System.DateTime]::Parse("7/1/2017 11:59:59 PM")

			$Results = Get-AWSCloudTrailLogs -Bucket "myaccount-logging" -ProfileName myaccount -Start ([System.DateTime]::Parse("7/1/2017")) -End $End -APIs @("DescribeInstances", "DescribeVolumes")
			ConvertTo-Json -InputObject $Results

			This gets the CloudTrail log files from 7/1/2017 in us-east-1, the default region, for DescribeInstances and DescribeVolumes API calls. The results are then serialized into JSON.

		.EXAMPLE
			$End = [System.DateTime]::Parse("7/31/2017 11:59:59 PM")

			$Results = Get-AWSCloudTrailLogs -Bucket "myaccount-logging" -Region ([Amazon.RegionEndpoint]::USEast2) -ProfileName myaccount -Start ([System.DateTime]::Parse("7/1/2017")) -End $End

			This gets the CloudTrail log files from 7/1/2017 to 7/31/2017 in the us-east-2 region and includes all API calls.

		.EXAMPLE
			$End = [System.DateTime]::Parse("7/31/2017 11:59:59 PM")

			$Results = Get-AWSCloudTrailLogs -Filter @{ "eventName" = "CreateTag" } -Bucket "myaccount-logging" -Region ([Amazon.RegionEndpoint]::USEast2) -ProfileName myaccount -Start ([System.DateTime]::Parse("7/1/2017")) -End $End

			This gets the CloudTrail log files from 7/1/2017 to 7/31/2017 in the us-east-2 region and includes CreateTag API calls (this example is identitical to providing the parameter -APIs @("CreateTag") ).

		.EXAMPLE
			$End = [System.DateTime]::Parse("7/31/2017 11:59:59 PM")

			$Results = Get-AWSCloudTrailLogs -Filter @{"eventSource" = "opsworks.amazonaws.com"; "eventName" = "TagResource"} -Bucket "myaccount-logging" -Region ([Amazon.RegionEndpoint]::USEast1) -ProfileName myaccount -Start ([System.DateTime]::Parse("7/1/2017")) -End $End

			This gets the CloudTrail log files from 7/1/2017 to 7/31/2017 in the us-east-1 region and includes TagResource events generated from OpsWorks.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/7/2017
	#>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$Bucket,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.Length -eq 12})]
        [System.String]$AccountId = [System.String]::Empty,

        [Parameter()]
        [System.DateTime]$Start = [System.DateTime]::MinValue,

        [Parameter()]
        [ValidateScript({
            $_ -ge $Start
        })]
        [System.DateTime]$End = [System.DateTime]::MaxValue,

        [Parameter(ParameterSetName = "API")]
        [ValidateNotNull()]
        [System.String[]]$APIs = @(),

		[Parameter(ParameterSetName = "Filter")]
		[System.Collections.Hashtable]$Filter = @{},

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
		[Amazon.Runtime.AWSCredentials]$Credential = $null,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$ProfileLocation = [System.String]::Empty
    )

    Begin {       
		$S3TimeRegex = "^([0-9]{4})(0[0-9]|1[0-2])(0[0-9]|[1-2][0-9]|3[0-1])T(0[0-9]|1[0-9]|2[0-3])([0-5][0-9])Z$"
    }

    Process {
        Initialize-AWSDefaults

        if ($Region -eq $null) 
		{
            $Region = [Amazon.RegionEndpoint]::GetBySystemName((Get-DefaultAWSRegion))
        }

        [System.Collections.Hashtable]$Splat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

        [Amazon.SecurityToken.Model.GetCallerIdentityResponse]$Identity = Get-STSCallerIdentity @Splat

        if ([System.String]::IsNullOrEmpty($AccountId))
        {
            $AccountId = $Identity.Account
        }

		# We can only set the credentials if 
		if (($Splat.ContainsKey("AccessKey") -and $Splat.ContainsKey("SecretKey")) -or $Splat.ContainsKey("ProfileName"))
		{
			$Temp = $Splat
			$Temp.Remove("Region")

			Set-AWSCredentials @Temp
		}

        if ($Credential -eq $null)
        {
			# This shouldn't return $null since we initialized defaults
            $Credential = Get-AWSCredentials
        }

        [Amazon.S3.IAmazonS3]$S3Client = New-Object -TypeName Amazon.S3.AmazonS3Client($Credential)

        [Amazon.S3.Model.S3Bucket]$S3Bucket = Get-S3Bucket -BucketName $Bucket @Splat

        if ($S3Bucket -ne $null)
        {
            $Prefix = "AWSLogs/$AccountId/CloudTrail/$($Region.SystemName)/"

            [Amazon.S3.Model.ListObjectsV2Response]$Response = $null
            [Amazon.S3.Model.ListObjectsV2Request]$Request = New-Object -TypeName Amazon.S3.Model.ListObjectsV2Request
            $Request.BucketName = $Bucket
            $Request.Prefix = $Prefix

            # If a start is defined, find the first key on or after that day
            if ($Start -gt [System.DateTime]::MinValue) 
			{
                [Amazon.S3.Model.S3Object]$FirstObject = $null

				# DateTime is a struct/value type, so this creates a copy
                [System.DateTime]$TempStart = $Start

                while ($FirstObject -eq $null) 
				{
                    if ($TempStart -gt $End -or $TempStart -gt [System.DateTime]::UtcNow) {
                        throw "No files could be found between the provided start and end times."
                    }

                    [System.String]$StartPrefix = "$Prefix$($TempStart.Year)/$($TempStart.Month.ToString("d2"))/$($TempStart.Day.ToString("d2"))/"
                    
					Write-Verbose -Message "Testing start prefix $StartPrefix"
                    
					$FirstObject = Get-S3Object -BucketName $Bucket -KeyPrefix $StartPrefix -MaxKey 1 @Splat
                    $TempStart = $TempStart.AddDays(1)
                }

                Write-Verbose -Message "First key $($FirstObject.Key)"

                # S3 will ignore this parameter after the first request if the ContinuationToken is set
				# This will at least get us close to the right place to start, it will get the first log from that day (in UTC), although
				# our start time may be minutes to hours after 00:00 AM on the specified day
                $Request.StartAfter = $FirstObject.Key
            }

            [System.String[]]$Files = @()

            do {
                if (-not [System.String]::IsNullOrEmpty($Request.ContinuationToken)) 
                {
                    Write-Progress -Activity "Listing objects" -Status "Making continuation request with marker $($Request.ContinuationToken) for 1000 objects"
                }

                $Response = $S3Client.ListObjectsV2($Request)

                foreach ($Object in $Response.S3Objects)
                {
					# Remove the known prefix from the key, and then split into the parts of the key path
					# The filename is in this format: 415720405880_CloudTrail_us-east-1_20170825T0300Z_gFC6PugTVDycrQIy.json.gz
					# Use the time here to create the $Time variable
					# After removing the prefix we get 2017/08/25/415720405880_CloudTrail_us-east-1_20170825T0300Z_gFC6PugTVDycrQIy.json.gz
                    $Parts = $Object.Key.Remove(0, $Prefix.Length).Split("/")
					
					# Get the last part of the remainder
					$FileName = $Parts[-1]

					# We need to use the time string in the file name because just parsing the DateTime with the year, month, day results in a time of 00:00 AM,
					# which would be less than a time specified by the user like 06:00 AM, even if the log was actually posted at 07:00 AM
					$FileNameParts = $FileName.Split("_")
					$TimeString = $FileNameParts[3]

					Write-Verbose -Message "Time from prefix $TimeString"
					
					if ($TimeString -match $S3TimeRegex)
					{
						[System.DateTime]$Time = [System.DateTime]::ParseExact($TimeString, "yyyyMMddTHHmmZ", [CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()

						# Check start to make sure the start marker or items after it weren't before the specified start hour/minute for the day
						# The start marker is the first object for the specified day, but may not be after the specified time since the parsed date time
						# for the start defaults to midnight 00:00 AM
						if ($Time -ge $Start) {
							if ($Time -le $End) {
								$Files += $Object.Key
								Write-Verbose -Message "Adding key $($Object.Key)"
							}
							else 
							{
								# Otherwise we've gotten into objects that are past the end time
								# Go ahead and end the do/while loop and break from this foreach loop
								Write-Verbose -Message "Passed end time with $Time."
								$Response.IsTruncated = $false
								break
							}
						}
					}
					else 
					{
						Write-Verbose -Message "$TimeString did not match the expected pattern for the timestamp in an S3 log."
					}
                }

                $Request.ContinuationToken = $Response.NextContinuationToken

            } while ($Response.IsTruncated)

            [Amazon.S3.Transfer.TransferUtility]$TransferUtility = New-Object -TypeName Amazon.S3.Transfer.TransferUtility($S3Client)
            [Amazon.S3.Transfer.TransferUtilityOpenStreamRequest]$StreamRequest = New-Object -TypeName Amazon.S3.Transfer.TransferUtilityOpenStreamRequest
            $StreamRequest.BucketName = $Bucket

			if ($Files.Length -gt 0)
			{
				[PSCustomObject[]]$Results = ForEach-ObjectParallel -WaitTime 500 -InputObject $Files -Verbose -Parameters @{"Bucket" = $Bucket; "S3Client" = $S3Client; "APIs" = $APIs; "Filter" = $Filter } -ScriptBlock {
					Param(
						[System.String]$File,
						[System.String]$Bucket,
						[Amazon.S3.IAmazonS3]$S3Client,
						[System.String[]]$APIs,
						[System.Collections.Hashtable]$Filter
					)

					try {
						[Amazon.S3.Transfer.TransferUtility]$TransferUtility = New-Object -TypeName Amazon.S3.Transfer.TransferUtility($S3Client)
						[Amazon.S3.Transfer.TransferUtilityOpenStreamRequest]$StreamRequest = New-Object -TypeName Amazon.S3.Transfer.TransferUtilityOpenStreamRequest
						$StreamRequest.BucketName = $Bucket

						$StreamRequest.Key = $File
						[System.IO.Stream]$Stream = $TransferUtility.OpenStream($StreamRequest)
						[System.IO.Compression.GZipStream]$GZipStream = New-Object -TypeName System.IO.Compression.GZipStream($Stream, [System.IO.Compression.CompressionMode]::Decompress)

						[System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($GZipStream)

						$Content = $Reader.ReadToEnd()

						$Temp = ConvertFrom-Json -InputObject $Content

						[PSCustomObject[]]$Records = $null

						if ($APIs.Length -gt 0)
						{
							$Temp.Records = $Temp.Records | Where-Object {$_.eventName -iin $APIs}
						}
					
						if ($Filter.Count -gt 0)
						{
							foreach ($Item in $Filter.GetEnumerator())
							{
								$Parts = $Item.Key.Split(".")

								$Temp.Records = $Temp.Records | Where-Object {
									$TempVal = $_
								
									# This will expand the sub properties if the key is "dotted" like user.id
									foreach ($Part in $Parts) {
										$TempVal = $TempVal | Select-Object -ExpandProperty $Part
									}
        
									$TempVal -ilike $Item.Value
								}    
							}
						}
                    
						$Records = $Temp.Records

						if ($Records -ne $null -and $Records.Length -gt 0) {                    
							Write-Output -InputObject $Records
						}
					}
					finally 
					{
						if ($Reader -ne $null) 
						{
							$Reader.Dispose()
						}

						if ($GZipStream -ne $null) 
						{
							$GZipStream.Dispose()
						}

						if ($Stream -ne $null) 
						{
							$Stream.Dispose()       
						}     
					}
				}

				Write-Output -InputObject $Results
			}
			else {
				throw "No CloudTrail Log Files discovered between $Start and $End in $Bucket using prefix $Prefix."
			}
        }
        else {
            throw "The bucket $Bucket could not be found in account $($Identity.Account)."
        }
    }

    End {
    }
}

Function Invoke-AWSTemporaryLogin {
	<#
		.SYNOPSIS
			Provides a wrapper around Get-STSSessionToken to include providing MFA credentials.

		.DESCRIPTION
			This cmdlet executes a Get-STSSessionToken while also optionally including a session token from a virtual or physical
			MFA device. This temporary credential can then be used for additional cmdlets or cross account access commands to prevent
			the need to re-enter MFA credentials each time.

		.PARAMETER UseVirtualMFA
			Specifies that an AWS virtual MFA is being used.

		.PARAMETER TokenSerialNumber
			The serial number of the physical MFA token.

		.PARAMETER TokenCode
			The current MFA token code, if this is not specified, but either UseVirtualMFA or TokenSerialNumber are specified, you will be prompted
			to enter the token code.

		.PARAMETER DurationInSeconds
			The length of time the temporary credentials are good for between 900 and 129600 seconds. This defaults to 43200, which is 12 hours.

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

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
			$Creds = Invoke-AWSTemporaryLogin -ProfileName my-jump-account -Verbose -UseVirtualMFA -TokenCode 527268
			Invoke-AWSCrossAccountCommand -Credential $Creds -ScriptBlock { Get-IAMRoleList } -AccountId 123456789012 -Role PowerUserRole

			This example gets temporary credentials in the account specified in the profile "my-jump-account" that utilizes a virtual MFA. This account may
			or may not require MFA. Once those credentials are acquired, they are used to access the remote AWS account, 123456789012, via cross account access.
			This remote account does require MFA for the cross account assume role to the PowerUserRole. The cmdlet, Get-IAMRoleList is executed in the remote account
			and then the credentials are reset to the state before the cross account command was executed.

		.INPUTS 
			None

		.OUTPUTS
			Amazon.SecurityToken.Model.Credentials

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/18/2017
	#>
	[CmdletBinding(DefaultParameterSetName = "NoMFA")]
	[OutputType([Amazon.SecurityToken.Model.Credentials])]
	Param(
		[Parameter(ParameterSetName = "Virtual", Mandatory = $true)]
		[Switch]$UseVirtualMFA,

		[Parameter(ParameterSetName = "Physical", Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$TokenSerialNumber,

		[Parameter(ParameterSetName = "Virtual")]
        [Parameter(ParameterSetName = "Physical")]
		[ValidateNotNullOrEmpty()]
		[System.String]$TokenCode,

        [Parameter()]
        [ValidateRange(900, 129600)]
        [System.Int32]$DurationInSeconds = 43200,

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
		[Amazon.Runtime.AWSCredentials]$Credential = $null,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		Initialize-AWSDefaults

        if ($Region -eq $null) {
            $Region = [Amazon.RegionEndpoint]::GetBySystemName((Get-DefaultAWSRegion))
        }

        [System.Collections.Hashtable]$SourceSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

		if ($UseVirtualMFA)
		{
			[Amazon.SecurityToken.Model.GetCallerIdentityResponse]$Identity = Get-STSCallerIdentity @SourceSplat
			$Regex = "^(arn:aws(?:-us-gov|-cn)?:iam::[0-9]{12}:)user(\/.*)$"

            $TokenSerialNumber = $Identity.Arn -replace $Regex, '$1mfa$2'			
		}

        [System.Collections.Hashtable]$TokenSplat = @{}

        if ($PSCmdlet.ParameterSetName -eq "Virtual" -or $PSCmdlet.ParameterSetName -eq "Physical" )
        {
            if (-not $PSBoundParameters.ContainsKey("TokenCode"))
            {
                $TokenCode = Read-Host -Prompt "Enter MFA token code"
            }

            $TokenSplat.Add("SerialNumber", $TokenSerialNumber)
            $TokenSplat.Add("TokenCode", $TokenCode)
        }

        Write-Output -InputObject (Get-STSSessionToken -DurationInSeconds $DurationInSeconds @SourceSplat @TokenSplat)
	}

	End {

	}
}

Function Invoke-AWSCrossAccountCommand {
	<#
		.SYNOPSIS
			Executes an assume role into another account with the provided credentials and executes a scriptblock.

		.DESCRIPTION
			This cmdlet executes a Use-STSRole in the account number specified with the supplied credentials. The role specified is assumed, 
			the default credentials are updated, the scriptblock is run, and the temporary credentials are then removed. The cmdlet effectively
			lets you run entire scripts in remote account accounts via cross account access.

		.PARAMETER AccountId
			The 12 digit account id to run the scriptblock in.

		.PARAMETER Role
			The role name to assume in the remote account.

		.PARAMETER ExternalId
			The external id provided by the central jump account for this remote account.

		.PARAMETER ScriptBlock
			The block of script to execute in the remote account.

		.PARAMETER FilePath
			The path to the script to execute against the remote account.

		.PARAMETER UseVirtualMFA
			Specifies that an AWS virtual MFA is being used.

		.PARAMETER TokenSerialNumber
			The serial number of the physical MFA token.

		.PARAMETER TokenCode
			The current MFA token code, if this is not specified, but either UseVirtualMFA or TokenSerialNumber are specified, you will be prompted
			to enter the token code.

		.PARAMETER DurationInSeconds
			The length of time the temporary credentials are good for between 900 and 3600 seconds. This defaults to 3600, which is 1 hour.

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

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
			$Creds = Invoke-AWSTemporaryLogin -ProfileName my-jump-account -Verbose -UseVirtualMFA -TokenCode 527268
			Invoke-AWSCrossAccountCommand -Credential $Creds -ScriptBlock { Get-IAMRoleList } -AccountId 123456789012 -Role PowerUserRole

			This example gets temporary credentials in the account specified in the profile "my-jump-account" that utilizes a virtual MFA. This account may
			or may not require MFA. Once those credentials are acquired, they are used to access the remote AWS account, 123456789012, via cross account access.
			This remote account does require MFA for the cross account assume role to the PowerUserRole. The cmdlet, Get-IAMRoleList is executed in the remote account
			and then the credentials are reset to the state before the cross account command was executed.

		.INPUTS 
			None

		.OUTPUTS
			Ouput of the invoked command.

			The output type is the value of the ScriptBlock parameter or the FilePath parameter.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/18/2017
	#>
	[CmdletBinding(DefaultParameterSetName = "NoMFA-SB")]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern("^[0-9]{12}$")]
		[System.String]$AccountId,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Role,

		[Parameter()]
        [ValidateRange(900, 3600)]
        [System.Int32]$DurationInSeconds = 3600,

		[Parameter(ParameterSetName = "Virtual-SB", Mandatory = $true)]
		[Parameter(ParameterSetName = "Virtual-File", Mandatory = $true)]
		[Switch]$UseVirtualMFA,

		[Parameter(ParameterSetName = "Physical-SB", Mandatory = $true)]
		[Parameter(ParameterSetName = "Physical-File", Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$TokenSerialNumber,

		[Parameter(ParameterSetName = "Virtual-SB")]
		[Parameter(ParameterSetName = "Virtual-File")]
		[Parameter(ParameterSetName = "Physical-SB")]
		[Parameter(ParameterSetName = "Physical-File")]
		[ValidateNotNullOrEmpty()]
		[System.String]$TokenCode,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern("^[-a-zA-Z0-9=,.@:\/]+$")]
		[System.String]$ExternalId,

		[Parameter(ParameterSetName = "Virtual-SB", Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[Parameter(ParameterSetName = "Physcial-SB", Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[Parameter(ParameterSetName = "NoMFA-SB", Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNull()]
		[ScriptBlock]$ScriptBlock,

		[Parameter(ParameterSetName = "Virtual-File", Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[Parameter(ParameterSetName = "Physical-File", Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[Parameter(ParameterSetName = "NoMFA-File", Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$FilePath,
		
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
		[Amazon.Runtime.AWSCredentials]$Credential = $null,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		Initialize-AWSDefaults

        if ($Region -eq $null) {
            $Region = [Amazon.RegionEndpoint]::GetBySystemName((Get-DefaultAWSRegion))
        }

        [System.Collections.Hashtable]$SourceSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

		[Amazon.SecurityToken.Model.GetCallerIdentityResponse]$Identity = Get-STSCallerIdentity @SourceSplat

		$Regex = "^(arn:aws(?:-us-gov|-cn)?:iam::)[0-9]{12}:.*$"
		$Arn = ($Identity.Arn -replace $Regex, '$1') + "$AccountId`:role/$Role"

		$RoleSessionName = "$($Identity.Arn.Substring($Identity.Arn.LastIndexOf("/") + 1))_$AccountId"

		[System.Collections.Hashtable]$RoleSplat = @{}

		if ($PSBoundParameters.ContainsKey("ExternalId"))
		{
			$RoleSplat.Add("ExternalId", $ExternalId)
		}

		if ($UseVirtualMFA)
		{
			[Amazon.SecurityToken.Model.GetCallerIdentityResponse]$Identity = Get-STSCallerIdentity @SourceSplat
			$Regex = "^(arn:aws(?:-us-gov|-cn)?:iam::[0-9]{12}:)user(\/.*)$"

            $TokenSerialNumber = $Identity.Arn -replace $Regex, '$1mfa$2'			
		}

        [System.Collections.Hashtable]$TokenSplat = @{}

        if ($PSCmdlet.ParameterSetName -ilike "Virtual*" -or $PSCmdlet.ParameterSetName -ilike "Physical*" )
        {
            if (-not $PSBoundParameters.ContainsKey("TokenCode"))
            {
                $TokenCode = Read-Host -Prompt "Enter MFA token code"
            }

            $TokenSplat.Add("SerialNumber", $TokenSerialNumber)
            $TokenSplat.Add("TokenCode", $TokenCode)
        }

		Write-Verbose -Message "Assuming role $Arn with session name $RoleSessionName."

		[Amazon.SecurityToken.Model.AssumeRoleResponse]$RemoteCredentials = Use-STSRole -RoleArn $Arn -RoleSessionName $RoleSessionName -DurationInSeconds $DurationInSeconds @RoleSplat @SourceSplat @TokenSplat

		try
		{
			if ($PSCmdlet.ParameterSetName -ilike "*-SB")
			{
				# Add the set-awscredential to the script block since the executed script block doesn't respect the credentials set in this ps host
				Write-Verbose -Message "Running scriptblock."
				$ScriptBlock = [System.Management.Automation.ScriptBlock]::Create("Set-AWSCredential -AccessKey $($RemoteCredentials.Credentials.AccessKeyId) -SecretKey $($RemoteCredentials.Credentials.SecretAccessKey) -SessionToken $($RemoteCredentials.Credentials.SessionToken)`n$ScriptBlock")
				
				& $ScriptBlock
			}
			else
			{
				Set-AWSCredential -Credential $RemoteCredentials.Credentials
				Write-Verbose -Message "Running script path."

				& $FilePath
			}
		}
		finally 
		{
			Clear-AWSCredential
		}
	}

	End {
	}
}

Function Get-AWSSupportCaseList {
	<#
		.SYNOPSIS
			Retrieves a list AWS support cases that can be easily converted to CSV or JSON

		.DESCRIPTION
			The cmdlet retrieves a list of AWS support cases and flattens the complex objects (communication and attachments) into 
			strings to make conversion into CSV or JSON straight forward.

		.PARAMETER BatchSize
			The number of cases to retrieve at one time. This is also used as the batch size for the amount of client communication entries to 
			retrieve.

		.PARAMETER AfterTime
			The time after which to retrieve support cases based on their start date.

		.PARAMETER BeforeTime
			The time before which to retrieve support cases based on their start date. Support cases are only available for the past 12 months.

		.PARAMETER IncludeResolvedCases
			Cases that have been resolved will be included in the results.

		.PARAMETER IncludeAllCommunication
			In the case that the support case has more than 5 client communication entries, specifying this will include all client communication
			for that case, otherwise, only up to 5 entries are included.

		.PARAMETER CaseIdList
			Supply up to 100 case Ids to retrieve details on instead of retrieving all cases.

		.PARAMETER Language
			Filter the cases based on the specified language, like 'en-us'.

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

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
			$Cases = Get-AWSSupportCaseList -IncludeResolvedCases -IncludeAllCommunication
			$Cases | Export-Csv -NoTypeInformation -Path C:\users\administrator\Desktop\cases.csv

			This example retrieves a list of all AWS support cases and includes all client communication. The $Cases variable is a list of PSCustomObjects. The
			retrieved cases are piped to Export-Csv where they are saved in a CSV report.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/18/2017
	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject[]])]
	Param(
		[Parameter()]
		[ValidateRange(1, [System.Int32]::MaxValue)]
		[System.Int32]$BatchSize = 20,

		[Parameter()]
		[ValidateNotNull()]
		[System.DateTime]$AfterTime,

		[Parameter()]
		[ValidateNotNull()]
		[System.DateTime]$BeforeTime,

		[Parameter()]
		[Switch]$IncludeResolvedCases,

		[Parameter()]
		[Switch]$IncludeAllCommunication,

		[Parameter()]
		[ValidateLength(1, 100)]
		[System.String[]]$CaseIdList = @(),

		[Parameter()]
		[System.String]$Language,

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
		[Amazon.Runtime.AWSCredentials]$Credential = $null,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	
	Begin {
	}

	Process {
        [System.Collections.Hashtable]$SourceSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

		[System.Collections.Hashtable]$CaseSplat = @{}

		if ($PSBoundParameters.ContainsKey("AfterTime"))
		{
			$CaseSplat.Add("AfterTime", $AfterTime.ToString("yyyy-MM-ddTHH:mmZ"))
		}

		if ($PSBoundParameters.ContainsKey("BeforeTime"))
		{
			$CaseSplat.Add("BeforeTime", $BeforeTime.ToString("yyyy-MM-ddTHH:mmZ"))
		}

		if ($PSBoundParameters.ContainsKey("CaseIdList"))
		{
			$CaseSplat.Add("CaseIdList", $CaseIdList)
		}

		if ($PSBoundParameters.ContainsKey("Language"))
		{
			$CaseSplat.Add("Language", $Language)
		}

		$NextToken = $null
		[PSCustomObject[]]$Results = @()
		do {
			[Amazon.AWSSupport.Model.CaseDetails[]]$Cases = Get-ASACase -NextToken $NextToken -MaxResult $BatchSize -IncludeResolvedCase ($IncludeResolvedCases -eq $true) @SourceSplat @CaseSplat

			foreach ($Case in $Cases) 
			{
				# Make sure to do this first so the last service response isn't overwritten by getting additional communication items
				$NextToken = $AWSHistory.LastServiceResponse.NextToken

				# The five most recent communications associated with the case.
                [System.String[]]$Comms = $Case.RecentCommunications.Communications | 
                    Where-Object {$_ -ne $null -and $_.Length -gt 0} |
					ForEach-Object {
						$Comm = "Timestamp: $($_.TimeCreated)`r`nAttachments: "

						if ($_.AttachmentSet.Length -gt 0)
						{
							$Comm += [System.String]::Join(",", ($_.AttachmentSet | Select-Object -Property @{Name = "Att"; Expression = { "{Id : $($_.AttachmentId); FileName : $($_.FileName)}" }} | Select-Object -ExpandProperty Att))
						}

						$Comm += "`r`nBody:`r`n`r`n$($_.Body)"

						Write-Output -InputObject $Comm
					}

				# No recent communications
                if ($Comms -eq $null -or $Comms.Length -eq 0)
                {
                    $Comms = @("No Case History")
                }
				# If we want to get all communication in the past 12 months, and there are more communication items
				elseif ($IncludeAllCommunication -and -not [System.String]::IsNullOrEmpty($Case.RecentCommunications.NextToken))
				{
					$CommNextToken = $Case.RecentCommunications.NextToken

					[System.Collections.Hashtable]$CommSplat = @{}

					if ($PSBoundParameters.ContainsKey("AfterTime"))
					{
						$CommSplat.Add("AfterTime", $AfterTime.ToString("yyyy-MM-ddTHH:mmZ"))
					}

					if ($PSBoundParameters.ContainsKey("BeforeTime"))
					{
						$CommSplat.Add("BeforeTime", $BeforeTime.ToString("yyyy-MM-ddTHH:mmZ"))
					}

					do {
						Write-Verbose -Message "Retrieving additional communications for $($Case.CaseId)."

						[Amazon.AWSSupport.Model.Communication[]]$CommResults = Get-ASACommunication -CaseId $Case.CaseId -MaxResult $BatchSize -NextToken $CommNextToken @SourceSplat @CommSplat
						$Comms += $CommResults |
							Where-Object {$_ -ne $null -and $_.Length -gt 0} |
							ForEach-Object {
								$Comm = "Timestamp: $($_.TimeCreated)`r`nAttachments: "

								if ($_.AttachmentSet.Length -gt 0)
								{
									$Comm += [System.String]::Join(",", ($_.AttachmentSet | Select-Object -Property @{Name = "Att"; Expression = { "{Id : $($_.AttachmentId); FileName : $($_.FileName)}" }} | Select-Object -ExpandProperty Att))
								}

								$Comm += "`r`nBody:`r`n`r`n$($_.Body)"

								Write-Output -InputObject $Comm
							}
						
						$CommNextToken = $AWSHistory.LastServiceResponse.NextToken

					} while ($CommNextToken -ne $null)
				}

				# CaseId               : case-490416305747-muen-2017-5dc8d9fa34a8e740
				# CategoryCode         : instance-issue
				# CcEmailAddresses     : {john@contoso.com, jeff@contoso.com}
				# DisplayId            : 4306238771
				# Language             : en
				# RecentCommunications : Amazon.AWSSupport.Model.RecentCaseCommunications
				# ServiceCode          : amazon-elastic-compute-cloud-linux
				# SeverityCode         : low
				# Status               : resolved
				# Subject              : Chat: High utilization traffic on Singapore location
				# SubmittedBy          : aws-dl-490416305747-admin@blackboard.com
				# TimeCreated          : 2017-08-22T14:41:48.000Z

                $Results += ([PSCustomObject]@{
                    CaseId = $Case.CaseId
					CategoryCode = $Case.CategoryCode
					CcEmailAddresses = [System.String]::Join(",", $Case.CcEmailAddresses)
					DisplayId = $Case.DisplayId
					Language = $Case.Language
					RecentCommunications = [System.String]::Join("`r`n`r`n", $Comms)
					ServiceCode = $Case.ServiceCode
					SeverityCode = $Case.SeverityCode
					Status = $Case.Status
					Subject = $Case.Subject
					SubmittedBy = $Case.SubmittedBy
					TimeCreated = $Case.TimeCreated
                })
			}
		} while ($NextToken -ne $null)

		Write-Output -InputObject $Results
	}

	End {
	}
}

Function Get-AWSVpcPeeringSummary {
	<#
		.SYNOPSIS
			Retrieves a summary of VPCs and their peering status in an AWS account.

		.DESCRIPTION
			The cmdlet retrieves the VPC peering status for each VPC in each specified region in an AWS account. If specific regions are not provided,
			then every region is queried for its VPCs and peering connections.

		.PARAMETER GovCloud
			This specifies the provided credentials and regions (if any) are part of GovCloud. If the Regions parameter is not specified, all GovCloud
			regions are used.

		.PARAMETER China
			This specifies the provided credentials and regions (if any) are part of China. If the Regions parameter is not specified, all China
			regions are used.

		.PARAMETER Regions
			The regions to retrieve VPC information from. If this is not specified, all regions are used.

		.PARAMETER OnlyIncludePeeredVpcs
			Specifies that only VPCs with an active peering connection are included in the output.

		.PARAMETER Region
			The system name of the AWS region in which the operation should be invoked. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

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

			Get-AWSVpcPeeringSummary -OnlyIncludePeeredVpcs -Regions @("us-west-1")
			
			Retrieves only the peered VPCs in the us-west-1 region.

		.EXAMPLE

			$VPCs = Get-AWSVpcPeeringSummary -ProfileName "my-aws-account"
			$VPCs | Export-Csv -Path c:\vpcpeering.csv -NoTypeInformation

			Retrieves information in all VPCs in all regions accessible to the credentials in the "my-aws-account" profile and writes out the details
			to a CSV file.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/18/2017
	#>
	[CmdletBinding(DefaultParameterSetName = "Public")]
	[OutputType([System.Management.Automation.PSCustomObject[]])]
	Param(
		[Parameter(ParameterSetName = "GovCloud")]
		[Switch]$GovCloud,

		[Parameter(ParameterSetName = "China")]
		[Switch]$China,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String[]]$Regions,

		[Parameter()]
		[Switch]$OnlyIncludePeeredVpcs,

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
		[Amazon.Runtime.AWSCredentials]$Credential = $null,

		[Parameter()]
		[ValidateNotNull()]
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {

	}

	Process {
		if (-not $PSBoundParameters.ContainsKey("Regions") -or $Regions.Length -eq 0)
		{
			switch ($PSCmdlet.ParameterSetName)
			{
				"Public" {
					$Regions = $AWSPublicRegions
					break
				}
				"China" {
					$Regions = Get-AWSRegion -IncludeChina | Select-Object -ExpandProperty Region | Where-Object {$_ -ilike "cn-*"}
					break
				}
				"GovCloud" {
					$Regions = Get-AWSRegion -GovCloudOnly | Select-Object -ExpandProperty Region
					break
				}
			}			
		}

		[System.Collections.Hashtable]$SourceSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 
		
		[Amazon.SecurityToken.Model.GetCallerIdentityResponse]$Identity = Get-STSCallerIdentity @SourceSplat
		$AccountId = $Identity.Account

		[PSCustomObject[]]$Results = @()

		# Remove the region parameter since we want to use the source splat across multiple regions
		$SourceSplat.Remove("Region")

		$i = 0

		foreach ($IncludedRegion in $Regions)
		{
			$i++
			$Percent = [System.Math]::Round(($i / $Regions.Length) * 100, 2)
			Write-Progress -Activity "Processing Regions" -Id 1 -Status "Processing $i of $($Regions.Length) AWS Regions ($IncludedRegion), $Percent% Complete" -PercentComplete $Percent

			try
			{
				[Amazon.EC2.Model.Vpc[]]$Vpcs = Get-EC2Vpc -Region $IncludedRegion @SourceSplat
				[Amazon.EC2.Model.VpcPeeringConnection[]]$Peering = Get-EC2VpcPeeringConnections -Region $IncludedRegion @SourceSplat
			
				Write-Verbose -Message "Found $($Vpcs.Length) VPCs and $($Peering.Length) peering connections in $IncludedRegion for account $AccountId."

				$j = 0

				if ($Peering -ne $null -and $Peering.Length -gt 0)
				{
					foreach ($Vpc in $Vpcs)
					{
						$j++
						$Percent2 = [System.Math]::Round(($j / $Vpcs.Length) * 100, 2)
						Write-Progress -Activity "Processing VPCs" -Id 2 -ParentId 1 -Status "Processing $j of $($Vpcs.Length) VPCs in $IncludedRegion, $Percent2% Complete" -PercentComplete $Percent2

						# Get the VPC Ids of peered VPCs where this VPC was the accepter
						[System.String[]]$AccepterConnections = $Peering | 
							Where-Object { ($_.AccepterVpcInfo | Select-Object -ExpandProperty VpcId).Contains($Vpc.VpcId) } | 
							Select-Object -ExpandProperty RequesterVpcInfo | Select-Object -ExpandProperty VpcId
					
						# Get the VPC Ids of peered VPCs where this VPC was the requestor
						[System.String[]]$RequesterConnections = $Peering | 
							Where-Object { ($_.RequesterVpcInfo | Select-Object -ExpandProperty VpcId).Contains($Vpc.VpcId) } | 
							Select-Object -ExpandProperty AccepterVpcInfo | Select-Object -ExpandProperty VpcId

						$Peered = $AccepterConnections.Length -gt 0 -or $RequesterConnections.Length -gt 0

						if (-not $OnlyIncludePeeredVpcs -or ($OnlyIncludePeeredVpcs -and $Peered))
						{
							$Results += [PSCustomObject]@{
									VpcId = $Vpc.VpcId; 
									CidrBlock = $Vpc.CidrBlock;
									AccountId = $AccountId;
									Region = $IncludedRegion;
									Peered = $Peered;
									RequesterVpc = if ($RequesterConnections.Length -gt 0) { [System.String]::Join("`r`n", $RequesterConnections) } else { "" };
									AccepterVpc = if ($AccepterConnections.Length -gt 0) { [System.String]::Join("`r`n", $AccepterConnections) } else { "" };
								}
						}
					}

					Write-Progress -Activity "Processing VPCs" -ParentId 1 -Id 2 -Completed
				}
				elseif (-not $OnlyIncludePeeredVpcs)
				{				
					Write-Progress -Activity "Processing VPCs" -Status "Processing VPCs in $IncludedRegion" -ParentId 1 -Id 2

					$Results += ($Vpcs | Select-Object -Property VpcId, 
						CidrBlock, 
						@{Name = "AccountId"; Expression = { $AccountId }}, 
						@{Name = "Region"; Expression = { $IncludedRegion }}, 
						@{Name = "Peered"; Expression = { $false }},
						@{Name = "RequesterVpc"; Expression = { "" }},
						@{Name = "AccepterVpc"; Expression = { "" }})

					Write-Progress -Activity "Processing VPCs" -ParentId 1 -Id 2 -Completed
				}
			}
			catch [System.InvalidOperationException]
			{
				if ($_.Exception.InnerException -ne $null -and 
					$_.Exception.InnerException.InnerException -ne $null -and
					$_.Exception.InnerException.InnerException -is [System.Net.WebException])
				{
					if ($ErrorActionPreference -ne [System.Management.Automation.ActionPreference]::Stop)
					{
						# If you can't contact a specific region, this doesn't need to terminate
						Write-Warning -Message "$IncludedRegion`: $($_.Exception.InnerException.Message)"
					}
					else
					{
						throw $_.Exception
					}
				}
				else
				{
					throw $_.Exception
				}
			}
		}

		Write-Progress -Activity "Processing Regions" -Completed

		Write-Output -InputObject $Results
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

			Write-Host -Message "Enabling CloudWatch Logs."

			$AWSSoftware = Get-AWSSoftware
			$SSMSoftware = $AWSSoftware | Where-Object -FilterScript {$_.DisplayName -eq "Amazon SSM Agent"} | Select-Object -First 1
			$EC2ConfigSW = $AWSSoftware | Where-Object -FilterScript {$_.DisplayName -eq "EC2ConfigService"} | Select-Object -First 1

			if ($SSMSoftware -ne $null -and -not [System.String]::IsNullOrEmpty($SSMDocument))
			{
				Write-Host -Message "Using SSM to configure CloudWatch."
					
				$ServiceName = "AmazonSSMAgent"

				$InstanceId = Get-EC2InstanceId

				try
				{
					Write-Host -Message "Updating SSM agent to latest."
					New-SSMAssociation -InstanceId $InstanceId -Name "AWS-UpdateSSMAgent" -Force
				}
				catch [Amazon.SimpleSystemsManagement.Model.AssociationAlreadyExistsException]
				{
					Write-Host -Message "The AWS-UpdateSSMAgent association already exists."
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