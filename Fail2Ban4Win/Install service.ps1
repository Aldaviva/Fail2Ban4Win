$binaryPathName = Resolve-Path(join-path $PSScriptRoot "Fail2Ban4Win.exe")

New-Service -Name "Fail2Ban4Win" -DisplayName "Fail2Ban4Win" -Description "After enough incorrect passwords from a remote client, block them using Windows Firewall." -BinaryPathName $binaryPathName.Path -DependsOn mpssvc
sc.exe failure Fail2Ban4Win actions= restart/0/restart/0/restart/0 reset= 3600