$diskdrive = Get-WmiObject win32_diskdrive
foreach($drive in $diskdrive)
  {
  out-host -InputObject "`nDevice: $($drive.deviceid.substring(4))`n  Model: $($drive.model)"
  # partition
  $partitions = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($drive.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"
  foreach($part in $partitions)
    {
    Out-Host -InputObject "  Partition: $($part.name)"
    $vols = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($part.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"
    foreach($vol in $vols)
      {
      out-host -InputObject "  Volume: $($vol.name)"
      $serial = Get-WmiObject -Class Win32_Volume | where { $_.Name -eq "$($vol.name)\" } | select SerialNumber
      out-host -InputObject "  Serial Number: $($serial.serialnumber)"
      }
    }
  }