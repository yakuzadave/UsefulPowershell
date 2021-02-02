
    # Initializing parameters (modify the Output folder by changing the $TargetDirectory define in the first line)

    $TargetDirectory = "C:\temp\DriversINFTest\"
    $hostname = $ENV:COMPUTERNAME
    
    # Get Third Party drivers used, that are not provided by Microsoft and presumably included in the OS
    
    $drivers = Get-WmiObject Win32_PNPSignedDriver | where {$_.DriverProviderName -ne "Microsoft"}
    
    # Initialize the list of detected driver packages as an array
    
    $DriverFolders = @()
    foreach ($d in $drivers) {
        
        # We initialize the list of driver files for each driver
        
        $DriverFiles = @()
        # For each driver instance from WMI class Win32_PNPSignedDriver, we compose the related WMI object name from the other WMI driver class, Win32_PNPSignedDriverCIMDataFile
        
        $ModifiedDeviceID = $d.DeviceID -replace "\\", "\\"
        $Antecedent = "\\" + $hostname + "\ROOT\cimv2:Win32_PNPSignedDriver.DeviceID=""$ModifiedDeviceID"""
        
        # Get all related driver files for each driver listed in WMI class Win32_PNPSignedDriver
        
        $DriverFiles += Get-WmiObject Win32_PNPSignedDriverCIMDataFile | where {$_.Antecedent -eq $Antecedent}
        if ($null -ne $DriverFiles) {
            
            foreach ($i in $DriverFiles) {
                # We elliminate double backslashes from the file paths
                $path = $i.Dependent.Split("=")[1] -replace '\\\\', '\'
                # We elliminate the trailing and ending quotes from the file paths
                $path2 = $path.Substring(1,$path.Length-2)
                # On the first pass, we only process the INF files as there is a very low chance of existing more than one driver package on the same machine, with the same INF file legth
                if ($path2.Split("\\")[$path2.Split("\\").Length-1].split(".")[1] -eq "inf") {
                    # We get the file attributes for each INF file
                    $CurrentDeviceID = $d.DeviceID
                    Write-Host "Current Device ID is $CurrentDeviceID"
                    $filedetails = $i.Dependent
                    Write-Host "Current inf file is $filedetails"
                    $where = $filedetails.split("=")[1]
                    $query = "select * from CIM_DataFile where Name=$where"
                    $InstallDate = Get-WmiObject -Namespace "ROOT\CIMV2" -Query $query
                    $ReadableDate = $InstallDate.ConvertToDateTime($InstallDate.InstallDate)
                    Write-Host "Installation date is:"
                    $ReadableDate
                    } # End of if ($path2.Split("\\")[$path2.Split("\\").Length-1].split(".")[1] -eq "inf")
                } # End of foreach ($i in $DriverFiles)
            } # End of if ($DriverFiles -ne $null)
        } # End of foreach ($d in $drivers)
