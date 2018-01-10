# =============================================================================
#  EasyVM System Prep
# =============================================================================
#  This script should be run by local admin after Setup is done

Start-Transcript

$runKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
$runValue = "RunDeploymentTasks_EasyVM";
$logonKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon";
$logonValue = "AutoAdminLogon"
$logFile = "$Env:SystemDrive\DeploymentLog.txt"
$deploy = "$Env:SystemDrive\deploy.temp"
$taskxml = [xml](gc $deploy\tasks.xml);

function log ($msg) {
  echo "$((date).ToString()): $msg" >> $logFile;
}

$done = $false;

$tasks = $taskxml.SelectNodes("/tasks/task");
if ($tasks -eq $null -or $tasks.Count -eq 0) {
  log " -> No more tasks"
  $done = $true;
  Remove-ItemProperty $runKey $runValue;
  del $deploy -Recurse -Force
  # Remove admin auto-logon
  Remove-ItemProperty $logonKey $logonValue;
} else {
  while (!$done) {
    log "Checking for deployment tasks"
    $tasks = $taskxml.SelectNodes("/tasks/task");
    if ($tasks -eq $null -or $tasks.Count -eq 0) {
      log " -> No more tasks"
      $done = $true;
    } else {
      log " -> Loading next task"
      
      # Pop next entry from list
      #   Note: $tasks[0] does not work on Win7 - can't index into an XPathNodeList
      $task = $taskxml.SelectSingleNode("/tasks/task");
      $t = $task.id;
      log " ->   Name: $t"

      cd $deploy\$t
      if (Test-Path $deploy\$t\task.xml) {
        $taskdata = ([xml](gc "$deploy\$t\task.xml")).task;
        $displayName = $taskdata.name;
        $reboot = [bool]($taskdata.reboot)
      }
      if ($displayName -eq $null) { $displayName = $t; }
      log " ->   Reboot: $reboot"
      cmd /c start $deploy\_easyvm_\ShowDeployState.exe "$displayName"

      $taskxml.SelectSingleNode("/tasks").RemoveChild($task);
      $taskxml.Save("$deploy\tasks.xml");
      
      # Run it
      log " -> Begin Task"
      if (Test-Path install.reg) {
        log " ->   Processing install.reg"
        regedit /s install.reg
      }
      if (Test-Path install.bat) {
        log " ->   Processing install.bat"
        cmd /c install.bat >> $logFile
      }
      if (Test-Path install.cmd) {
        log " ->   Processing install.cmd"
        cmd /c install.cmd >> $logFile
      }
      if (Test-Path install.ps1) {
        log " ->   Processing install.ps1"
        cmd /c powershell -ExecutionPolicy Bypass -File install.ps1 >> $logFile
      }
      if (Test-Path desktop\.) {
        log " ->   Processing desktop icons"
        xcopy /d /s /q /y desktop\* $Env:SystemDrive\Users\Public\Desktop\
      }

      log " -> End Task"
      
      if ($reboot) {
        $done = $true;
      }
    }
  }
}

log " -> Rebooting"
shutdown /r /t 15
Stop-Transcript
