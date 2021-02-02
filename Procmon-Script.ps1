<#
.Synopsis
    Functions for working with Process monitor
.Link
    https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
#>
#Requires -Version 3.0
New-Module -Name Procmon -Scriptblock {

    Add-Type -Assembly System.IO.Compression.Filesystem

    $columns = @{
        "Date & Time"       = 116,156
        "Process Name"      = 117,156
        "PID"               = 118,156
        "Operation"         = 119,156
        "Result"            = 120,156
        "Detail"            = 121,156
        "Sequence"          = 122,156
        "Company"           = 128,156
        "Description"       = 129,156
        "Command Line"      = 130,156
        "User"              = 131,156
        "Image Path"        = 132,156        
        "Session"           = 133,156
        "Path"              = 135,156
        "TID"               = 136,156
        "Relative Time"     = 140,156
        "Duration"          = 141,156
        "Time Of Day"       = 142,156
        "Version"           = 145,156
        "Event Class"       = 146,156
        "Authentication ID" = 147,156
        "Virtualized"       = 148,156
        "Integrity"         = 149,156
        "Category"          = 150,156
        "Parent PID"        = 151,156
        "Architecture"      = 152,156        
        "Completion Time"   = 228,156        	
    }

    $relations = @{ 
        "is"          = 0
        "is not"      = 1
        "less than"   = 2
        "more than"   = 3
        "begins with" = 4
        "ends with"   = 5       
        "contains"    = 6
        "excludes"    = 7
    }

    $actions = @{
        "Include" = 1
        "Exclude" = 0
    }
      
    function ConvertTo-Bytes([int]$Int) {
        # 16 bit only
        ([BitConverter]::GetBytes($Int))[0..1]
    }

    function Is-Admin {
        $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        if( -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "You must be an Administrator to run this function"
        }	
    }

    function New-RuntimeDefinedParameter {
        Param(
            [string]$Name,
            [int]$Position,
            [string[]]$ValidateSet
        )

        $ParameterName = $Name
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = $Position

        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $AttributeCollection.Add($ParameterAttribute)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)
        $AttributeCollection.Add($ValidateSetAttribute)

        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)

        return $RuntimeParameter
    }

    function Get-ColumnBinaryValue {
        [CmdletBinding()]
        Param()

        DynamicParam {       
            $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $Column = New-RuntimeDefinedParameter -Name 'Column' -Position 0 -ValidateSet $columns.Keys  
            $RuntimeParameterDictionary.Add('Column', $Column)
            return $RuntimeParameterDictionary
        }

        Process {
            return $columns[$PSBoundParameters['Column']]      
        }
    }

    function Get-RelationBinaryValue {
        [CmdletBinding()]
        Param()

        DynamicParam {       
            $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $Relation = New-RuntimeDefinedParameter -Name 'Relation' -Position 0 -ValidateSet $relations.Keys  
            $RuntimeParameterDictionary.Add('Relation', $Relation)
            return $RuntimeParameterDictionary
        }

        Process {
            return $relations[$PSBoundParameters['Relation']]      
        }
    }

    function Get-ActionBinaryValue {
        [CmdletBinding()]
        Param()

        DynamicParam {       
            $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $Action = New-RuntimeDefinedParameter -Name 'Action' -Position 0 -ValidateSet $actions.Keys  
            $RuntimeParameterDictionary.Add('Action', $Action)
            return $RuntimeParameterDictionary
        }

        Process {
            return $actions[$PSBoundParameters['Action']]      
        }
    }

    <#
    .Synopsis
        Creates a new Process monitor filter
    .Description
        Creates a new Process monitor filter that can be applied to the
        registry to filter events in Process monitor
    DYNAMIC PARAMETERS
    -Column <String>
            the Column name to apply the filter to.
            Required?                    true
            Position?                    1
            Default value                
            Accept pipeline input?       false
            Accept wildcard characters?  false
    -Relation <String>
            the Relation condition to apply
            Required?                    true
            Position?                    2
            Default value                
            Accept pipeline input?       false
            Accept wildcard characters?  false
    -Action <String>
            whether to include or exclude events that match
            Required?                    true
            Position?                    4
            Default value                
            Accept pipeline input?       false
            Accept wildcard characters?  false
    .Example
        New-ProcmonFilter -Column 'Process Name' -Relation is -Value Procmon.exe -Action Exclude;
    .Parameter Value
        the Value of the condition
    #>
    function New-ProcmonFilter {
        [CmdletBinding()]
        Param (
            [Parameter(Position=2, Mandatory=$true, ValueFromPipeline = $true)]
            [string]
            [ValidateNotNullOrEmpty()]
            [ValidateLength(1,65535)]
            $Value
        )

        DynamicParam {       
            $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
 
            $Column = New-RuntimeDefinedParameter -Name 'Column' -Position 0 -ValidateSet $columns.Keys
            $Relation = New-RuntimeDefinedParameter -Name 'Relation' -Position 1 -ValidateSet $relations.Keys
            $Action = New-RuntimeDefinedParameter -Name 'Action' -Position 3 -ValidateSet $actions.Keys
     
            $RuntimeParameterDictionary.Add('Column', $Column)
            $RuntimeParameterDictionary.Add('Relation', $Relation)
            $RuntimeParameterDictionary.Add('Action', $Action)
   
            return $RuntimeParameterDictionary
        }

        Process {
            return [PSCustomObject]@{
                PSTypeName = "ProcmonFilter"
                Column = $PSBoundParameters['Column']
                Relation = $PSBoundParameters['Relation']
                Value = $Value
                Action = $PSBoundParameters['Action']
            }
        }
    }

    <#
    .Synopsis
        Gets the default Process monitor filters
    .Description
        Gets the default Process monitor filters. Useful to add to any other specific
        filters that may be defined
    .Example
        Get-DefaultProcmonFilters
    #>
    function Get-DefaultProcmonFilters {
        $filters = @()

        $filters += @('Procmon.exe', 'Procexp.exe', 'Autoruns.exe', 
            'Procmon64.exe', 'Procexp64.exe', 'System') |
             New-ProcmonFilter -Column 'Process Name' -Relation is -Action Exclude 

        $filters += New-ProcmonFilter -Column Operation -Relation 'begins with' -Value IRP_MJ_ -Action Exclude
        $filters += New-ProcmonFilter -Column Operation -Relation 'begins with' -Value FASTIO_ -Action Exclude
        $filters += New-ProcmonFilter -Column Result -Relation 'begins with' -Value 'FAST IO' -Action Exclude

        $filters += @('pagefile.sys', '$Mft', '$MftMirr', '$LogFile', '$Volume', '$AttrDef',
            '$Root', '$Bitmap', '$Boot', '$BadClus', '$Secure', '$UpCase') |
            New-ProcmonFilter -Column Path -Relation 'ends with' -Action Exclude

        $filters += New-ProcmonFilter -Column Path -Relation contains -Value '$Extend' -Action Exclude
        $filters += New-ProcmonFilter -Column 'Event Class' -Relation is -Value Profiling -Action Exclude

        return $filters
    }

    <#
    .Synopsis
        Gets the bytes for a collection of Process monitor filters
    .Description
        Gets the bytes for a collection of Process monitor filters that
        can be persisted in the registry, to apply the filters to
        Process monitor on start up
    .Example
        Get-ProcmonFiltersBytes -Filters @(New-ProcmonFilter -Column 'Process Name' -Relation is -Value Procmon.exe -Action Include)
    .Parameter Filters
        The Process monitor filters to get the bytes for. Each filter
        must be a PSCustomObject with PsTypeName of 'ProcmonFilter' and
        have the following valid properties: Column, Relation, Value, Action.
        The best way to create a new filter is with New-ProcmonFilter
    #>
    function Get-ProcmonFiltersBytes {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
            [ValidateCount(0, 65535)]
            [PSTypeName("ProcmonFilter")]
            [PSCustomObject[]]
            $Filters
        )

        Begin {
            $collectedFilters = @()
        }

        Process {
            $collectedFilters += $Filters
        }

        End {
	        [Byte[]]$bytes = 1
	        $bytes += ConvertTo-Bytes $collectedFilters.Length
	        $bytes += 0,0
        
            $index = 0
            $collectedFilters | ForEach-Object {
                $bytes += Get-ColumnBinaryValue $_.Column
                $bytes += 0,0

                $bytes += Get-RelationBinaryValue $_.Relation
                $bytes += 0,0,0

                $bytes += Get-ActionBinaryValue $_.Action

                $value = $_.Value

                if ($value.Length -gt 65535) {
                    Write-Warning "Procmon filter Value at index $index is larger than 65535. Value will be truncated"
                    $value = $value.Substring(0, 65535)
                }
           
	            $bytes += ConvertTo-Bytes (($value.Length + 1) *  2)
	            $bytes += 0,0
	    
                $bytes += [System.Text.Encoding]::Unicode.GetBytes($value)
                $bytes += 0,0,0,0,0,0,0,0,0,0
                
                $index += 1
	        }                      

            return $bytes
        }
    }

    <#
    .Synopsis
        Writes the Process monitor filters to the registry
    .Description
        Writes the Process monitor filters to the registry, 
        to apply the filters to Process monitor on start up
    .Example
        @(New-ProcmonFilter -Column 'Process Name' -Relation is -Value Procmon.exe -Action Include) `
        | Write-ProcmonFiltersToRegistry
    .Parameter Filters
        The Process monitor filters. Use New-ProcmonFilter to create new filters,
        and Get-DefaultProcmonFilters to get the default filters
    #>
    function Write-ProcmonFiltersToRegistry {
        [CmdletBinding()]
        Param (        
            [PSTypeName("ProcmonFilter")]
            [PSCustomObject[]]
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            $Filters
        )

        Begin {
            Is-Admin
            $collectedFilters = @()
        }
       
        Process {
            $collectedFilters += $Filters
        }

        End {
            $collectedFilters | Get-ProcmonFiltersBytes | Write-ProcmonFiltersBytesToRegistry         
        }
    }

    <#
    .Synopsis
        Writes the Process monitor filter bytes to the registry
    .Description
        Writes the Process monitor filter bytes to the registry, 
        to apply the filters to Process monitor on start up
    .Example
        @(New-ProcmonFilter -Column 'Process Name' -Relation is -Value Procmon.exe -Action Include) `
        | Get-ProcmonFiltersBytes `
        | Write-ProcmonFiltersBytesToRegistry
    .Parameter FilterBytes
        The bytes of the Process monitor filters. Use Get-ProcmonFiltersBytes
        to get the bytes for a collection of Process monitor filters
    #>
    function Write-ProcmonFiltersBytesToRegistry {
        [CmdletBinding()]
        Param (        
            [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
            [Byte[]]$FilterBytes
        )

        Begin {
            Is-Admin
            $bytes = @()
        }
       
        Process {
            $bytes += $FilterBytes
        }

        End {
            New-ItemProperty "HKCU:\Software\Sysinternals\Process Monitor" "FilterRules" `
                -Value $bytes -PropertyType Binary -Force -ErrorVariable regError | Out-Null

            if ($regError) {
                throw "Writing Procmon filter rules to registry failed. $regError"
            }           
        }
    }

    <#
    .Synopsis
        Clears the Process monitor filter bytes in the registry
    .Description
        Clears the Process monitor filter bytes in the registry
    .Example
        Clear-ProcmonFiltersRegistry
    #>
    function Clear-ProcmonFiltersRegistry {
        Is-Admin
        1,0,0,0,0 | Write-ProcmonFiltersBytesToRegistry
    }

    <#
    .Synopsis
        Downloads Process monitor zip to the destination file
    .Description
        Downloads Process monitor zip to the destination file
    .Example
        Download-Procmon
    #>
    function Download-Procmon {
        Param(
            [string]$Destination = "$env:TEMP\ProcessMonitor.zip"
        )

        if (-not (Test-Path $Destination)) {
            (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", $Destination)
        }
    }

    <#
    .Synopsis
        Unzips Process monitor zip file to the destination directory
    .Description
        Unzips Process monitor zip file to the destination directory
    .Example
        Unzip-Procmon -ZipSource "C:\ProcessMonitor.zip -Destination C:\ProcessMonitor
    .Parameter ZipSource
        The Process monitor zip file
    .Parameter Destination
        The destination directory
    #>
    function Unzip-Procmon {
        Param(
            [string]$ZipSource = "$env:TEMP\ProcessMonitor.zip",
            [string]$Destination = "$env:TEMP\ProcessMonitor"
        )

        if (-not (Test-Path $Destination) -and -not (Test-Path "$Destination\Procmon.exe")) {
            New-Item $Destination -Type Directory -ErrorAction Ignore | Out-Null
            [IO.Compression.ZipFile]::ExtractToDirectory($ZipSource, $Destination)
        }
    }

    <#
    .Synopsis
        Waits for Process monitor processes to finish running
    .Description
        Waits for Process monitor processes to finish running
    .Example
        Wait-Procmon
    .Example
        Wait-Procmon -Wait 10
    .Parameter Wait
        The maximum amount of seconds to wait. If the processes
        are still running after this time, an error will be written
        to Standard error
    #>
    function Wait-Procmon {
        Param(
            [Parameter(Mandatory = $false)]
            [ValidateRange(0, 3600)]
            [int]            
            $Wait
        )

        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            $processes = Get-Process Procmon,Procmon64 -ErrorAction Ignore      
            if ($processes -eq $null) {
                break
            }

            if ($Wait -and $Wait -gt 0 -and $stopWatch.Elapsed.TotalSeconds -gt $Wait) {
                Write-Error "Procmon processes still running after waiting $Wait"
                break
            }
        }
    }
    
    <#
    .Synopsis
        Invokes Process monitor with given arguments
    .Description
        Invokes Process monitor with given arguments.
        Looks for Procmon.exe in the passed directory. If the 
        directory does not exist, Process monitor is downloaded
        to the given directory.
    .Example
        Invoke-Procmon -ProcmonDir C:\ -ExeArgs "/BackingFile C:\events.pml /Quiet /AcceptEula /Minimized"
    .Example
        Invoke-Procmon -ExeArgs "/Quiet /AcceptEula /Minimized"
    .Example
        Invoke-Procmon
    .Parameter ProcmonDir
        The directory in which to locate Procmon.exe. If the directory
        does not exist or does not contain Procmon.exe, will be downloaded
    .Parameter ExeArgs
        The arguments for the Procmon.exe executable
    #>
    function Invoke-Procmon {
        [CmdletBinding()] 
        Param(
            [Parameter()]
            [string]
            $ProcmonDir = "$env:TEMP\ProcessMonitor", 
            
            [Parameter()]
            [string[]]
            $ExeArgs = @()
        )
        
        Is-Admin
        Download-Procmon -Destination "$($ProcmonDir).zip"
        Unzip-Procmon -Destination $ProcmonDir

        if ($ExeArgs) {
            Write-Verbose "Executing '$ProcmonDir\Procmon.exe $ExeArgs'"
            Start-Process -FilePath "$ProcmonDir\Procmon.exe" -ArgumentList $ExeArgs -PassThru
        }
        else {
            Write-Verbose "Executing '$ProcmonDir\Procmon.exe'"
            Start-Process -FilePath "$ProcmonDir\Procmon.exe" -PassThru
        }
    }

    <#
    .Synopsis
        Starts Process monitor with given filters applied,
        writing events to backing file
    .Description
        Starts Process monitor with given filters applied,
        writing events to backing file.
        If filters are supplied, these are written to the registry,
        to be applied to Process monitor on startup.
    .Example
        Start-Procmon
    .Example
        $(@(New-ProcmonFilter -Column 'Process Name' -Relation is -Value chrome.exe -Action Include) + 
        (Get-DefaultProcmonFilters)) | Start-Procmon
    .Parameter ProcmonDir
        The directory in which to locate Procmon.exe. If the directory
        does not exist or does not contain Procmon.exe, it will be downloaded
        to the directory
    .Parameter Filters
        The collection of filters to apply to Process Monitor. Use
        New-ProcmonFilter to construct new filters, and Get-DefaultProcmonFilters
        to get the default filters
    .Parameter EventFile
        The file in which to persist Process monitor events
    .Parameter Runtime
        Specify a number of seconds that Process monitor should run for
        before terminating
    .Parameter DefaultFilters
        Whether to apply the default Process monitor filters to the 
        collection of filters
    #>
    function Start-Procmon { 
        [CmdletBinding()] 
        Param (
            [Parameter()]
            [string]
            $ProcmonDir = "$env:TEMP\ProcessMonitor",

            [PSTypeName("ProcmonFilter")]
            [PSCustomObject[]]
            [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
            $Filters = @(),

            [Parameter()]
            [string]
            $EventFile = "$env:TEMP\ProcessMonitor\events.pml",

            [Parameter()]
            [int]
            $Runtime,

            [Parameter()]
            [switch]
            $DefaultFilters
        )

        Begin {
            $collectedFilters = @()
        }

        Process {
            $collectedFilters += $Filters
        }

        End {
            if ($DefaultFilters) {
                $collectedFilters += Get-DefaultProcmonFilters
            }

            if ($collectedFilters) {
                $collectedFilters | Sort-Object -Property Column,Relation,Value,Action -Unique | Write-ProcmonFiltersToRegistry
            }

            $runtimeSeconds = ""

            if ($Runtime -and $Runtime -gt 0) {
                $runtimeSeconds = "/Runtime $Runtime"
            }
    
            Invoke-Procmon -ProcmonDir "$ProcmonDir" -ExeArgs "/BackingFile `"$EventFile`" $runtimeSeconds /Quiet /AcceptEula /Minimized" | Out-Null
        }
    }

    <#
    .Synopsis
        Stops Process monitor
    .Description
        Stops Process monitor, optionally waiting a timeout
    .Example
        Stop-Procmon
    .Example
        Stop-Procmon -Timeout (New-TimeSpan -Seconds 10)
    .Parameter ProcmonDir
        The directory in which to locate Procmon.exe. If the directory
        does not exist or does not contain Procmon.exe, will be downloaded
    .Parameter Wait
        The maximum amount of time in seconds to wait for the Process monitor processes
        to finish. Will wait indefinitely for processes to finish
    #>
    function Stop-Procmon {
        [CmdletBinding()]
        Param(
            [Parameter()]
            $ProcmonDir = "$env:TEMP\ProcessMonitor",

            [Parameter(Mandatory = $false)]
            [int]
            $Wait
        )

        Invoke-Procmon -ProcmonDir "$ProcmonDir" -ExeArgs "/Terminate" | Out-Null
        Wait-Procmon $Wait
    }

    <#
    .Synopsis
        Converts a Process monitor event file to CSV file
    .Description
        Converts a Process monitor event file to CSV file
    .Example
        Stop-Procmon
    .Example
        Stop-Procmon -Timeout (New-TimeSpan -Seconds 10)
    .Parameter ProcmonDir
        The directory in which to locate Procmon.exe. If the directory
        does not exist or does not contain Procmon.exe, will be downloaded
    .Parameter EventFile
        The source file in which Process monitor events are persisted
    .Parameter CsvFile
        The desintation file to write Process monitor events in CSV format 
    .Parameter Wait
        The maximum amount of time in seconds to wait for the Process monitor processes
        to finish. Will wait indefinitely for processes to finish
    .Parameter ApplySavedFilter
        Whether to apply the saved event filter to the conversion 
    #>
    function ConvertTo-ProcmonCsv {
        [CmdletBinding()]
        Param(
            [Parameter()]
            [string]
            $ProcmonDir = "$env:TEMP\ProcessMonitor",

            [Parameter()]
            [string]
            $EventFile = "$env:TEMP\ProcessMonitor\events.pml",

            [Parameter()]
            [string]
            $CsvFile = "$env:TEMP\ProcessMonitor\events.csv",

            [Parameter(Mandatory = $false)]
            [int]
            $Wait,

            [switch]
            $ApplySavedFilter = $true
        )

        $saveApplyFilter = ""
        if ($ApplySavedFilter) {
            $saveApplyFilter = "/SaveApplyFilter"
        }

        Invoke-Procmon -ProcmonDir "$ProcmonDir" -ExeArgs "/Openlog `"$EventFile`" /SaveAs `"$CsvFile`" $saveApplyFilter /AcceptEula" | Out-Null
        Wait-Procmon $Wait
    }

    Export-ModuleMember -Function Download-Procmon,Unzip-Procmon,Invoke-Procmon, `
        Start-Procmon,Stop-Procmon,New-ProcmonFilter,Get-DefaultProcmonFilters, `
        Get-ProcmonFiltersBytes,Write-ProcmonFiltersToRegistry, `
        Write-ProcmonFiltersBytesToRegistry,Clear-ProcmonFiltersRegistry,ConvertTo-ProcmonCsv
}