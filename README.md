# easyvm
Simple Hyper-V template system.  Some assembly required (for licensing reasons).

EasyVM is a PowerShell module designed to make it easy to deploy templated VM's
in a domain environment.
NOTE: You need to provide your own propery licensed Windows ISO's or VHD's in order
to use this tool.

# Quick Start (single machine)
- Clone the easyvm repo into a local folder, like G:\easyvm.
- Install Hyper-V.
- Create a folder where you want to store your VHD's in, like G:\vm.
- Obtain a Windows client ISO, from Windows Insider, MSDN, or VLSC.
- Download Convert-WindowsImage.ps1 from TechNet ScriptCenter.
- In PowerShell, Convert your ISO into a VHDX.  Example:
````
    .\Convert-WindowsImage.ps1 -SourcePath "$pwd\en_windows_10_multi-edition_version_1709_updated_nov_2017_x64_dvd_100290211.iso" -Edition Professional -VHDFormat VHDX -VhdPartitionStyle GPT -VHDPath G:\easyvm\samples\vhd\16299.client.professional.vhdx -SizeBytes 200GB -Feature NetFx3
````
- Open PowerShell and run the following:
    import-module G:\easyvm\easyvm.psm1
    Deploy-EasyVM -Name mytestvm1 -Template client-pro -NoDomainJoin
- Provide the appropriate responses when prompted.  For example:
  - Which vswitch do you want to use?
    - MySwitch
  - Please enter the path where the EasyVM templates are stored.
    - G:\easyvm\samples
  - Where should we store the VM's you create?
    - G:\vm
- EasyVM will create and prepare the VM.

# Advanced Setup
EasyVM requires the following setup:
- EasyVM Library: This can be a file share, or just a local folder.
  You can start with the samples/ and add your own templates.
- Hyper-V Server: One or more Windows machines with Hyper-V installed
  where you plan to deploy the templated VM's.
The templates can be centrally maintained on the EasyVM library share,
and then a whole team can use these templates on their own PC's.

## Setting up your Template Server
The template share has 4 folders.  You can start with the samples/ folder in this repo.
- support/ - The support files needed by EasyVM. (Get these from samples/support)
- template/ - Template definitions.  The templates that you create here can be
  used when calling Deploy-EasyVM.  A template consists of:
   - template.xml: A name, VHD name, product key, and list of tasks to be installed.
   - unattend.xml (optional): a Windows setup answer file.  If this does not
     exist, the default unattend.xml file in the template library is used.
- tasklibrary/ - Task definitions.  A task consists of:
   - task.xml: Descriptive name of the task
   - install.cmd,bat,ps1,exe: A setup command to be run for the task.
   - Any other contents of the task folder will be copied directly to the VM.
- vhd/ - The VHD's referenced in the templates.  You need to provide these
    yourself, as they are not redistributed as part of this Git repo.

## Creating Windows VHD's for use with EasyVM
- You can obtain Windows client ISO's from Windows Insider, MSDN, or VLSC.
- You can use Convert-WindowsImage.ps1 to convert ISO's to VHD or VHDX.
- You can download Convert-WindowsImage.ps1 from TechNet ScriptCenter.
- Examples:
````
.\Convert-WindowsImage.ps1 -SourcePath "$pwd\en_windows_server_2016_x64_dvd_9327751.iso" -Edition ServerDataCenter -VHDFormat VHD -VhdPartitionStyle MBR -VHDPath .\14393.server.datacenter.vhd -SizeBytes 200GB -Feature NetFx3
.\Convert-WindowsImage.ps1 -SourcePath "$pwd\en_windows_server_2016_x64_dvd_9327751.iso" -Edition ServerDataCenter -VHDFormat VHDX -VhdPartitionStyle GPT -VHDPath .\14393.server.datacenter.vhdx -SizeBytes 200GB -Feature NetFx3
.\Convert-WindowsImage.ps1 -SourcePath "$pwd\en_windows_10_multi-edition_version_1709_updated_nov_2017_x64_dvd_100290211.iso" -Edition Professional -VHDFormat VHDX -VhdPartitionStyle GPT -VHDPath .\16299.client.professional.vhdx -SizeBytes 200GB -Feature NetFx3
````

## Setting up your Hyper-V server(s)
- Install the Hyper-V role, including the platform and the PowerShell management tools.
- Clone the easyvm repo into a local folder, like G:\easyvm.
- Create a folder where you want to store your VHD's in, like G:\vm.
- Open PowerShell and run the following:
    import-module G:\easyvm\easyvm.psm1
    Deploy-EasyVM -Name mytestvm1 -Template client-pro -NoDomainJoin
- Provide the appropriate responses when prompted.  For example:
  - Which vswitch do you want to use?
    - MySwitch
  - Please enter the path where the EasyVM templates are stored.
    - G:\easyvm\samples
  - Where should we store the VM's you create?
    - G:\vm
- EasyVM will create and prepare the VM.

## Creating your own Tasks
- Stage all the required files into tasklibrary/[taskname]/
- Create a task.xml file that provides a friendly name for the task.
- Create a install file: install.[ps1|bat|cmd|exe] that contains the necessary
  instructions to install the content.

## Using VLAN's
If your vswitch is attached to Trunk, you can configure the default VLAN to use:
- HKLM\Software\Awesome\EasyVM - vlan as REG_SZ

## Product Keys
- The product keys in the Samples are default (non-activating) or AVMA product keys.
- You can specify a product key in your template using <image productkey="">.
- You can pass an explicit product key to Deploy-EasyVM -ProductKey ...

