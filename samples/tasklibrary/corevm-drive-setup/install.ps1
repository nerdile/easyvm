# Expand C Drive
$cdrive = (Get-Volume C | Get-Partition)
$cmax = ($cdrive | Get-PartitionSupportedSize).SizeMax
$cdrive | Resize-Partition -Size $cmax

# Initialize E Drive
$edisk = Get-Disk 1
if ($edisk.PartitionStyle -eq "RAW") {
  $edisk | Initialize-Disk -PartitionStyle GPT
  $edrive = ($edisk | New-Partition -UseMaximumSize -DriveLetter E)
  $edrive | Format-Volume -FileSystem NTFS -Confirm:$false
}
