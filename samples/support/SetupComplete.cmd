del /q /f %SystemDrive%\unattend.xml
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v RunDeploymentTasks_EasyVM -t REG_SZ /d "powershell -ExecutionPolicy Bypass -File %SystemRoot%\Setup\Scripts\RunDeploymentTasks.ps1"
if exist %SystemRoot%\Setup\Scripts\SetupComplete_easyvm.cmd start /wait %SystemRoot%\Setup\Scripts\SetupComplete_easyvm.cmd
shutdown /r /t 10
