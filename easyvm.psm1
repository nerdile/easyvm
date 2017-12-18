<#
.SYNOPSIS
  Deploys a simple VM.  Requires elevation.

.DESCRIPTION
  Deploys a VM based on standard templates.

  * This script requires elevation. *
  
  The first time this script is run, it will prompt you for configuration
  settings.  If these need to be changed later, you will have to tweak them
  directly in the registry.  (See: HKLM\Software\Awesome\EasyVM)

.PARAMETER Name
  The name of the VM to be created.  This is the name that will be
  shown in Hyper-V Manager.

.PARAMETER Template
  The standard template to use.
  
.PARAMETER Hostname
  The hostname of the machine on the network.  If this is not
  specified, the Name will be used.  If the name is five characters or less,
  the default hostname will be your alias followed by the Name.
  (example: w1 becomes billg-w1)

.PARAMETER NoBoot
  When done, don't boot the VM.  This lets you customize the VHD or the
  VM configuration before you boot it and it runs all the prep.
  
.PARAMETER NoDomainJoin
  Don't join the VM to the domain.  Note that some templates may require domain
  access.
  
.PARAMETER Resume
  If the VHD didn't mount properly, -Resume will take the VHD that was already
  created and try mounting and staging the files again.
  
.PARAMETER AdminCreds
  PSCredential object (See Get-Credential) with the password that should be
  used for the local Administrator account.  Note: The username is ignored,
  the local Administrator account will keep its default name.
  
.PARAMETER DomainCreds
  PSCredential object (See Get-Credential) with the domain, user, and password
  to use for domain joining the VM.
  
.EXAMPLE
  Make a new server VM.  The following two commands are equivalent.
  
  Deploy-EasyVM srv1 server
  Deploy-EasyVM -Name srv1 -Template server -Hostname billg-srv1
  
.EXAMPLE
  Make a new web server VM.

  Deploy-EasyVM billg-w1 web
#>
Function Deploy-EasyVM {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$True,Position=0)]
    [string] $Name,
    [Parameter(Mandatory=$True,Position=1)]
    [string] $Template,
    [Parameter(Mandatory=$False,Position=2)]
    [string] $Hostname,
    [switch] $NoBoot,
    [switch] $NoDomainJoin,
    [switch] $Resume,
    [Parameter()]
    [PSCredential] $AdminCreds,
    [Parameter()]
    [PSCredential] $DomainCreds,
    [Parameter()]
    [string] $ProductKey
  )
  
  $myeap = $ErrorActionPreference;
  $ErrorActionPreference = "Stop";
  
  if (!$Hostname) {
    if (!$Name.Contains("-") -and $Name.Length -lt 6) {
      $Hostname = ("$($Env:Username)-$Name");
    } else {
      $Hostname = $Name;
    }
  }

  # Check global setup
  if (!(_Check-EasyVMPrereqs)) { throw "Prerequisites not met."; };
  $config = _Get-EasyVMConfig;

  # Validate parameters
  if (Get-VM $Name -ea 0) { throw "VM already exists: $Name"; }

  $vmdir = "$($config.vmdir)\$Name";
  if ((Test-Path "$vmdir") -and !$Resume) {
    throw "Folder already exists: $vmdir.  Use -Resume to jump right to staging.";
  }
  [void](mkdir "$vmdir" -ea 0);

  $TeamDir = $config.teamdir;
  $T = "$TeamDir\Template\$Template";
  $templateData = [xml](gc "$T\template.xml");
  $uxml = $null;

  # Get the interactive prompts out of the way before we start copying vhd's around
  if ($templateData.template.image.prep -ne "none")
  {
    $xml = gi "$T\unattend.xml" -ea 0
    if (!$xml) { $xml = gi "$T\..\unattend.xml" }

    $uxml = [xml](gc $xml);
    $AdminCreds = _Get-AdminCreds $AdminCreds;
    if ($templateData.template.requiresDomainJoin -and $NoDomainJoin) {
      throw "This template cannot be used with -NoDomainJoin.";
    }
    
    $DomainCreds = _Get-DomainCreds $DomainCreds;
    
    # Get User Credentials
    if (!($NoDomainJoin)) {
      if (!$domaincreds) { throw "To skip domain join, use -NoDomainJoin." };
    }
  }

  Write-Host "Creating system volume..."
  $srcvhd = _Get-MaybeVhdx "$($config.TeamDir)\vhd\$($templateData.template.image.file)"
  if (!$srcvhd) { throw "VHD/VHDX not found: $templateData.template.image.file"; }
  $ext = $srcvhd.Extension.Substring(1);

  $vhd = "$vmdir\$Name-system.$ext";
  if (!($Resume -and (Test-Path $vhd))) {
    [void](_New-EasyVMSystemVolume $config $templateData.template.image.file $ext $vhd);
  }

  Write-Host "Staging deployment files..."
  $vm = _New-AutoVMState $Name $Hostname $vhd $uxml

  # Prepare the VHD if necessary
  if ($templateData.template.image.prep -ne "none")
  {
    _Set-UnattendHostname $vm.uxml $hostname;
    _Set-UnattendAdminPass $vm.uxml $admincreds;
    _Set-UnattendRegistration $vm.uxml $config.Owner $config.Org;
    if (!$NoDomainJoin) {
      _Set-UnattendDomainJoin $vm.uxml $config.CorpDomain $domaincreds;
      _Add-UnattendDomainAccount $vm.uxml $domaincreds.userinfo.domain $domaincreds.userinfo.name "Administrators"
    }
    if (![String]::IsNullOrEmpty($ProductKey)) {
      _Set-UnattendProductKey $vm.uxml $ProductKey
    } elseif (![String]::IsNullOrEmpty($templateData.template.image.productkey)) {
      _Set-UnattendProductKey $vm.uxml $templateData.template.image.productkey
    } elseif ($templateData.template.image.SkipProductKey -ne $true) {
      throw "Product key required";
    }
    _Stage-AutoVM $vm;
    
    try {
      echo "$((date).ToString()): Staged from $T" > "$($vm.Staging)\DeploymentLog.txt"
      [void]($vm.Uxml.Save("$($vm.Staging)\unattend.xml"));
      [void](mkdir "$($vm.Staging)\Windows\Setup\Scripts" -Force -ea 0);
      [void](mkdir "$($vm.Staging)\deploy.temp" -Force -ea 0);
      [void](mkdir "$($vm.Staging)\deploy.temp\_easyvm_" -Force -ea 0);
      copy "$($config.teamdir)\Support\SetupComplete.cmd" "$($vm.Staging)\Windows\Setup\Scripts\."
      copy "$($config.teamdir)\Support\RunDeploymentTasks.ps1" "$($vm.Staging)\Windows\Setup\Scripts\."
      xcopy /S/Y/Q "$($config.teamdir)\Support\Tools\*" "$($vm.Staging)\deploy.temp\_easyvm_\"
      
      _Mount-AutoVM $vm;
      $postinstall = "$($vm.Drive):\Windows\Setup\Scripts\SetupComplete.cmd";
      $postinstall2 = "$($vm.Drive):\Windows\Setup\Scripts\SetupComplete_easyvm.cmd";
      if (Test-Path $postinstall) {
        if (!(Test-Path $postinstall2)) {
          ren $postinstall $postinstall2;
        }
      }
      $client_tasks = [xml]("<tasks/>")
      xcopy /S/Y/Q "$($vm.Staging)\*" "$($vm.Drive):\"
      if (Test-Path "$T\Staging") {
        Write-Host "  Staging template: $template"
        xcopy /S/Y/Q "$T\Staging\*" "$($vm.Drive):\"
      }
      foreach ($task in $templateData.template.tasks.task) {
        $tid = $task.id;
        Write-Host "  Staging task: $tid"
        xcopy /S/Y/Q "$($config.teamdir)\TaskLibrary\$tid\*" "$($vm.Drive):\deploy.temp\$tid\"
        $client_tasks.SelectSingleNode("tasks").InnerXml += "<task id='$tid'/>";
      }
      $client_tasks.Save("$($vm.Drive):\deploy.temp\tasks.xml");
      [void](Dismount-VHD $vm.Vhd);
      $vm.Drive = $null;
    
      Write-Host "Staging complete."
    } finally {
      if ($vm.Staging) {
        [void](del -Force -Recurse $vm.Staging);
        $vm.Staging = $null;
      }
    }
  }

  # Deploy VM
  Write-Host "Creating VM in Hyper-V..."
  _New-BaseVM $vm.id $config.vswitch $vm.vhd $config.VSwitchVLAN;
  
  if ($templateData.template.datavol.type -ne "none")
  {
    $datavhd = "$vmdir\$Name-data.vhdx";
    [void](New-Vhd $datavhd -SizeBytes 250GB -Dynamic);
    [void](Add-VMHardDiskDrive $vm.id -Path $datavhd);
  }

  Write-Host "All done!"
  vmconnect localhost $name
  if (!$NoBoot) {
    Start-VM $vm.id
  }
  $ErrorActionPreference = $myeap;
}


<#
.SYNOPSIS
  Creates a simple VM based on VHD's that already exist.  Requires elevation.

.DESCRIPTION
  Deploys a VM based on VHD's that already exist.

  * This script requires elevation. *
  
  The first time this script is run, it will prompt you for configuration
  settings.  If these need to be changed later, you will have to tweak them
  directly in the registry.  (See: HKLM\Software\Awesome\EasyVM)

.PARAMETER Name
  The name of the VM to be created.  This is the name that will be
  shown in Hyper-V Manager.

.PARAMETER NoBoot
  When done, don't boot the VM.  This lets you customize the VHD or the
  VM configuration before you boot it and it runs all the prep.

.EXAMPLE
  Revive a server VM from VHD's that exist in $vmdir\srv1.
  
  Revive-EasyVM srv1
  
#>
Function Revive-EasyVM {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$True,Position=0)]
    [string] $Name,
    [switch] $NoBoot
  )
  
  $myeap = $ErrorActionPreference;
  $ErrorActionPreference = "Stop";
  
  # Check global setup
  if (!(_Check-EasyVMPrereqs)) { throw "Prerequisites not met."; };
  $config = _Get-EasyVMConfig;

  # Validate parameters
  if (Get-VM $Name -ea 0) { throw "VM already exists: $Name"; }

  $vmdir = "$($config.vmdir)\$Name";
  if (!(Test-Path "$vmdir")) {
    throw ("Folder does not exist: " + $vmdir);
  }

  $osvhd = _Get-MaybeVhdx "$vmdir\$Name-system";
  if (!$osvhd) { throw "VHD not found. Clean up $vmdir and use Deploy-EasyVM instead"; }
  $datavhd = "$vmdir\$Name-data.vhdx";

  # Deploy VM
  Write-Host "Creating VM in Hyper-V..."
  _New-BaseVM $Name $config.vswitch $osvhd.FullName $config.VSwitchVLAN;
  if ((gi $datavhd -ea 0) -ne $null) {
    [void](Add-VMHardDiskDrive $Name -Path $datavhd);
  }
  
  Write-Host "All done!"
  vmconnect localhost $Name
  if (!$NoBoot) {
    Start-VM $Name
  }
  $ErrorActionPreference = $myeap;
}

# ----------------------------------------------------------------------------
#  EasyVM helpers
# ----------------------------------------------------------------------------
Function _New-BaseVM($id, $vswitch, $osvhd, $vlan) {
  if ((gi $osvhd).Extension.ToLower() -eq ".vhdx") {
    #Gen2
    [void](New-VM $id -Generation 2 -MemoryStartupBytes 1GB -VHDPath $osvhd -SwitchName $vswitch);
    [void](Set-VMFirmware $id -EnableSecureBoot Off)
  } else {
    #Gen1
    [void](New-VM $id -MemoryStartupBytes 1GB -VHDPath $osvhd -SwitchName $vswitch);
    [void](Set-VMBios $id -EnableNumLock);
  }
  if ((gcm Set-VM).parameters.keys -contains "CheckpointType") { Set-VM $id -CheckpointType Standard }
  [void](Set-VMMemory $id -DynamicMemoryEnabled $true -MaximumBytes 2GB -MinimumBytes 256MB -StartupBytes 1GB);
  [void](Set-VMProcessor $id -Count 4);
  [void](Set-VMComPort $id -number 1 -path "\\.\pipe\vm$($id)");
  if ($vlan -ne 0) {
    [void](Set-VMNetworkAdapterVlan -VMName $id -Access -VlanId $vlan);
  }
}

Function _Get-MaybeVhdx($file)
{
  if (Test-Path "$file.vhdx") {
    return gi "$file.vhdx";
  } elseif (Test-Path "$file.vhd") {
    return gi "$file.vhd";
  }
}

Function _Check-EasyVMPrereqs {
  $prereqs = $true;
  if (!(gcm Get-Disk -ea 0)) { ipmo Storage };
  if (!(gcm Get-VM -ea 0)) { Write-Host "Hyper-V PowerShell is not installed!"; $prereqs = $false; }
  else {
    try {
      [void](Get-VM);
      if ((Get-VMSwitch).length -eq 0) { Write-Host "There are no Hyper-V virtual switches!"; $prereqs = $false; };
    } catch [System.Exception] { Write-Host "Hyper-V Core is not installed!"; $prereqs = $false; };
  }
  if (!(_Is-Admin)) { Write-Host "EasyVM requires Administrator privileges!"; $prereqs = $false; };
  return $prereqs;
}

Function _Get-EasyVMConfig {
  $vmlan = _Get-Config "vmlan";
  if (!($vmlan)) {
    $switches = (Get-VMSwitch);
    if ($switches -eq $null -or $switches.length -eq 0) { throw "You need at least one vswitch."; }
    Write-Host "Which vswitch do you want to use?"
    $switches | ft Name | Out-Host;
    $vmlan = (_Get-ConfigOrPrompt "vmlan" $switches[0].Name "If none of the above, hit Ctrl-C and go create a corpnet vswitch.");
  }
  
  $homedir = (_Get-ConfigOrPrompt "HomeDir" "\\daniel.ntdev.corp.microsoft.com\shared\easyvm" "Please enter the path where the EasyVM templates are stored.");
  $basedir = (_Get-ConfigOrPrompt "vmdir" "G:\vm" "Where should we store the VM's you create?");
  if (!(Test-Path $Basedir)) { [void](mkdir $Basedir -ea 0); };
  if (!(Test-Path $Basedir)) { throw "Not found: $Basedir"; };
  $cachedir = _Get-ConfigOrPrompt "pristine" "$Basedir\pristine" "Where should we store the base VHD images?";
  if (!(Test-Path $Cachedir)) { [void](mkdir $Cachedir -ea 0); };
  if (!(Test-Path $Cachedir)) { throw "Not found: $Cachedir"; };
  echo "EasyVM will cache standard OS images in this folder. You can delete them to reclaim space.  EasyVM will automatically download them if they are needed in the future." > "$cachedir\README.txt";
  $joindomain = (_Get-ConfigOrPrompt "joindomain" "$Env:USERDNSDOMAIN" "Please enter the domain for your VM to join.")

  $channel = (_Get-ConfigOrDefault "channel" ".")
  $homedir = "$homedir\$channel";

  $vlan = (_Get-ConfigOrDefault "vlan" "0")
  $owner = (_Get-ConfigOrDefault "owner" (gp "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").RegisteredOwner)
  $org = (_Get-ConfigOrDefault "org" (gp "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").RegisteredOrganization)

  return New-Object PSObject -Property @{ VSwitch = $vmlan; VmDir = $basedir; TeamDir = $homedir; VhdCache = $cachedir; CorpDomain = $joindomain; VSwitchVLAN = $vlan; Owner=$owner; Org=$org; };
}

function _New-EasyVMSystemVolume ($config, $basevhd, $ext, $vhd) {
  [void](xcopy /Y/D "$($config.TeamDir)\vhd\$($basevhd).$ext" "$($config.VhdCache)\.")
  New-VHD $vhd -ParentPath "$($config.VhdCache)\$($basevhd).$ext" -Differencing -SizeBytes 200GB;
  return $vhd;
}


# ----------------------------------------------------------------------------
#  From HELPERS.PS1
# ----------------------------------------------------------------------------
Function _Is-Admin {
  return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator");
}

Function _Get-Config ($key) {
  $cfgkey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Awesome\EasyVM";
  $value = Get-ItemProperty -Path $cfgkey -Name $key -ea 0;
  if ($value) {
    return ($value | Select-Object -ExpandProperty $key);
  } else {
    return $null;
  }
}

Function _Set-Config ($key, $value) {
  $cfgkey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Awesome\EasyVM";
  if (!(Get-Item $cfgkey -ea 0)) {
    [void](New-Item $cfgkey -Force);
  }
  [void](New-ItemProperty $cfgkey -Name $key -PropertyType String -Value $value -Force);
}

Function _Get-ConfigOrDefault ($key, $default) {
  $value = _Get-Config $key;
  if (!$value) {
    $value = $default;
    _Set-Config $key $value;
  }
  $value;
}

Function _Get-ConfigOrPrompt ($key, $default, $prompt) {
  $value = _Get-Config $key;
  if (!$value) {
    [void](Write-Host $prompt);
    [void](Write-Host "Default: $default");
    $value = Read-Host "Value: ";
    if (!$value) { $value = $default; }
    _Set-Config $key $value;
  }
  $value;
}

# ----------------------------------------------------------------------------
#  From AUTOVM.PS1
# ----------------------------------------------------------------------------
  Function _Get-DomainCreds ($creds) {
    if (!$creds) {
      $creds = Get-Credential "$Env:USERDOMAIN\$Env:USERNAME" -Message "Enter your domain credentials, for domain join. Format: DOMAIN\UserName";
    }
    if ($creds -and $creds.UserName -and $creds.UserName.Contains("\")) {
      if ($creds.userinfo -eq $null) {
        $creds | Add-Member userinfo @{
          domain = $creds.UserName.Substring(0, $creds.Username.IndexOf("\"));
          name = $creds.UserName.Substring($creds.Username.IndexOf("\") + 1);
        };
      }
    }
    return $creds;
  }
  
  function _Get-AdminCreds ($creds) {
    if (!$creds) {
      $creds = Get-Credential Administrator -Message "Create the local Administrator password";
    }
    return $creds;
  }
  
  Function _New-AutoVMState ($id, $name, $vhd, $uxml) {
    New-Object PSObject -Property @{Id = $id; Name = $Name; Vhd = $vhd; Drive = $null; Staging = $null; Uxml = $uxml;};
  }

  Function _Stage-AutoVM ($vm) {
    $stagingDir = [System.IO.Path]::GetTempFileName();
    [void](del -Force $stagingDir);
    [void](mkdir $stagingDir);
    $vm.Staging = $stagingDir;
  }
  
  Function _Mount-AutoVM ($vm) {
    $done = $false;
    [void](Dismount-VHD $vm.vhd -ea 0);
    $vm.Drive = (Mount-VHD -Path $vm.vhd -PassThru | Get-Disk | Get-Partition | Get-Volume)[0].DriveLetter;
    Sleep 1
  }
  

# ----------------------------------------------------------------------------
#  From XML.PS1
# ----------------------------------------------------------------------------
$g_XmlNsmgr = New-Object System.Xml.XmlNamespaceManager (New-Object System.Xml.NameTable);
$g_XmlNs = @{ `
  "appx" = "http://schemas.microsoft.com/appx/2010/manifest"; `
  "asm" = "urn:schemas-microsoft-com:asm.v3"; `
  "xsd" = "http://www.w3.org/2001/XMLSchema"; `
  "xsi" = "http://www.w3.org/2001/XMLSchema-instance"; `
  "store" = "Microsoft-Windows-Store-Unattend-Settings-Schema"; `
  "task" = "http://schemas.microsoft.com/windows/2004/02/mit/task"; `
  "ux" = "urn:schemas-microsoft-com:unattend"; `
  "wcm" = "http://schemas.microsoft.com/WMIConfig/2002/State"; `
};
$g_XmlNs.GetEnumerator() | %{ $g_XmlNsmgr.AddNamespace($_.Name, $_.Value); };

Function _Add-XmlNode ($parent, $newnode, $ns) {
  if ($ns) {
    $parent.AppendChild($parent.SelectSingleNode("/").CreateElement($newnode, $ns));
  } else {
    $parent.AppendChild($parent.SelectSingleNode("/").CreateElement($newnode));
  }
}

#==============================================================================
# From UXML.PS1
#==============================================================================
$g_XmlNsmgr.AddNamespace("", "urn:schemas-microsoft-com:unattend");

#==============================================================================
# Unattend.Xml Handling
#==============================================================================
Function _Get-UxChildNode ($parent, $childname) {
  $node = $parent.SelectSingleNode("ux:$childname", $g_XmlNsmgr);
  if (!$node) {
    $node = _Add-XmlNode $parent "$childname" $g_XmlNs["ux"];
  }
  return $node;
}

Function _Set-UxTextElement ($parent, $tag, $value) {
  $node = _Get-UxChildNode $parent $tag;
  $node.InnerText = $value;
}

Function _Get-UnattendPassNode($uxml, $pass) {
  $parent = $uxml.SelectSingleNode("/ux:unattend", $g_XmlNsmgr);
  $node = $parent.SelectSingleNode("ux:settings[@pass='$pass']", $g_XmlNsmgr);
  if (!$node) {
    $node = _Add-XmlNode $parent "settings" $g_XmlNs["ux"];
    [void]($node.SetAttribute("pass", $pass));
  }
  return $node;
}

Function _Get-UnattendCompNode($uxml, $pass, $comp) {
  $parent = _Get-UnattendPassNode $uxml $pass;
  $node = $parent.SelectSingleNode("ux:component[@name='$comp']", $g_XmlNsmgr);
  if (!$node) {
    $node = _Add-XmlNode $parent "component" $g_XmlNs["ux"];
    @{ `
      name = $comp; `
      processorArchitecture = "amd64"; `
      publicKeyToken = "31bf3856ad364e35"; `
      language = "neutral"; `
      versionScope = "nonSxS" `
    }.GetEnumerator() | %{ [void]($node.SetAttribute($_.name,$_.value)); };
  }
  return $node;
}

Function _Set-UnattendHostname ($uxml, $hostname) {
  _Set-UxTextElement (_Get-UnattendCompNode $uxml "specialize" "Microsoft-Windows-Shell-Setup") "ComputerName" $hostname;
  _Set-UxTextElement (_Get-UxChildNode (_Get-UnattendCompNode $uxml "oobeSystem" "Microsoft-Windows-Shell-Setup") "AutoLogon") "Domain" $hostname;
}

Function _Set-UnattendDomainJoin ($uxml, $machinedomain, $creds) {
  $id = _Get-UxChildNode (_Get-UnattendCompNode $uxml "specialize" "Microsoft-Windows-UnattendedJoin") "Identification";
  _Set-UxTextElement $id "JoinDomain" $machinedomain;

  $cred = _Get-UxChildNode $id "Credentials";
  _Set-UxTextElement $cred "Domain" $creds.GetNetworkCredential().Domain;
  _Set-UxTextElement $cred "Username" $creds.GetNetworkCredential().UserName;
  _Set-UxTextElement $cred "Password" $creds.GetNetworkCredential().Password;
}

Function _Set-UnattendAdminPass ($uxml, $creds) {
  $oobe = _Get-UnattendCompNode $uxml "oobeSystem" "Microsoft-Windows-Shell-Setup";
  _Set-UxTextElement $oobe.AutoLogon.Password "Value" $creds.GetNetworkCredential().password;
  _Set-UxTextElement $oobe.UserAccounts.AdministratorPassword "Value" $creds.GetNetworkCredential().password;
}

Function _Add-UnattendDomainAccount ($uxml, $udomain, $uname, $lgroup) {
  $oobe = _Get-UnattendCompNode $uxml "oobeSystem" "Microsoft-Windows-Shell-Setup";
  $daccts = _Get-UxChildNode $oobe.UserAccounts "DomainAccounts";
  $dacctlist = _Get-UxChildNode $daccts "DomainAccountList";
  [void]($dacctlist.SetAttribute("action", $g_XmlNs["wcm"], "add"));
  _Set-UxTextElement $dacctlist "Domain" $udomain;
  $unode = _Add-XmlNode $dacctlist "DomainAccount" $g_XmlNs["ux"];
  [void]($unode.SetAttribute("action", $g_XmlNs["wcm"], "add"));
  _Set-UxTextElement $unode "Name" $uname;
  _Set-UxTextElement $unode "Group" $lgroup;
}

Function _Set-UnattendRegistration {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$True,Position=0)]
    [System.Xml.XmlDocument]$Uxml,
    [Parameter(Mandatory=$True,Position=1)]
    [string]$Name,
    [Parameter(Position=2)]
    [string]$Organization
  )

  $setup1 = _Get-UnattendCompNode $uxml "windowsPE" "Microsoft-Windows-Setup";
  $setup2 = _Get-UnattendCompNode $uxml "specialize" "Microsoft-Windows-Shell-Setup";
  $setup3 = _Get-UnattendCompNode $uxml "oobeSetup" "Microsoft-Windows-Shell-Setup";
  $setup4 = _Get-UnattendCompNode $uxml "oobeSetup" "Microsoft-Windows-Shell-Setup";

  _Set-UxTextElement $setup1.UserData "FullName" $Name;
  _Set-UxTextElement $setup2 "RegisteredOwner" $Name;
  _Set-UxTextElement $setup3 "RegisteredOwner" $Name;
  _Set-UxTextElement $setup4 "RegisteredOwner" $Name;

  if (![String]::IsNullOrEmpty($Organization)) {
    _Set-UxTextElement $setup1.UserData "Organization" $Organization;
    _Set-UxTextElement $setup2 "RegisteredOrganization" $Organization;
    _Set-UxTextElement $setup3 "RegisteredOrganization" $Organization;
    _Set-UxTextElement $setup4 "RegisteredOrganization" $Organization;
  }
}

Function _Set-UnattendProductKey {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$True,Position=0)]
    [System.Xml.XmlDocument]$Uxml,
    [Parameter(Mandatory=$True,Position=1)]
    [string]$ProductKey
  )

  $setup1 = _Get-UnattendCompNode $uxml "windowsPE" "Microsoft-Windows-Setup";
  _Set-UxTextElement $setup1.UserData.ProductKey "Key" $ProductKey;

  $setup2 = _Get-UnattendCompNode $uxml "specialize" "Microsoft-Windows-Shell-Setup";
  _Set-UxTextElement $setup2 "ProductKey" $ProductKey;
}

Export-ModuleMember -Function Deploy-EasyVM
Export-ModuleMember -Function Revive-EasyVM
