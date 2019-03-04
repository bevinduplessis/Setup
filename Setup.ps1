[CmdletBinding()]
Param(
  [switch]
  [Parameter()]
  $CurrentUser,
  [switch]
  [Parameter()]
  $MinimalSoftware,
  [switch]
  [Parameter()]
  $NoWallpaper,
  [switch]
  [Parameter()]
  $NoLockScreen
)
Function Show-Progress # TODO: Update this to support standalone mode and task sequences
{
  param(
    [Parameter(Mandatory = $true)]
    [string] $Message,
    [string] $Source
  )

  Process {

    $Script:CurrentStep++
    $MaxStep = 100

    if(!$CurrentUser.IsPresent)	
    {
      # Not running in Task sequence
      $Id = 1
      $Activity = 'Applying Configuration...'
      $StatusText = '"Step $($CurrentStep.ToString().PadLeft($MaxStep.Count.ToString().Length)) of $MaxStep"'
      $StatusBlock = [ScriptBlock]::Create($StatusText)
      Write-Progress -Id $Id -Activity $Activity -Status (& $StatusBlock) -CurrentOperation $Message -PercentComplete ($Script:CurrentStep / $MaxStep * 100)
    }
  }
}

Function Invoke-DisableBackgroundServices
{
  Show-Progress -Message '"Disable background access of default apps'
	
  $BackgroundServicesRegisterKeys = @()

  foreach ($key in (Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications')) 
  {
    $BackgroundServicesRegisterKeys += @(
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' + $key.PSChildName
        Name        = 'Disabled'
        Value       = 1
        Description = "Disable background access of apps [$($key.PSChildName)]"
      }
    )
  }
  Set-RegistryValues -registerKeys $BackgroundServicesRegisterKeys
}

Function Invoke-UpdateGroupPolicy
{
  [CmdletBinding()]
  Param (
    [ValidateNotNullorEmpty()]
    [bool]$ContinueOnError = $true
  )
	
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process {
    [string[]]$GPUpdateCmds = '/C echo N | gpupdate.exe /Target:Computer /Force', '/C echo N | gpupdate.exe /Target:User /Force'
    [int]$InstallCount = 0
    ForEach ($GPUpdateCmd in $GPUpdateCmds) 
    {
      Try 
      {
        If ($InstallCount -eq 0) 
        {
          [string]$InstallMsg = 'Update Group Policies for the Machine'
          Write-Log -Message "$($InstallMsg)..." -Source $CmdletName
        }
        Else 
        {
          [string]$InstallMsg = 'Update Group Policies for the User'
          Write-Log -Message "$($InstallMsg)..." -Source $CmdletName
        }
        [psobject]$ExecuteResult = Execute-Process -Path "$env:windir\system32\cmd.exe" -Parameters $GPUpdateCmd -WindowStyle 'Hidden' -PassThru
				
        If ($ExecuteResult.ExitCode -ne 0) 
        {
          If ($ExecuteResult.ExitCode -eq 60002) 
          {
            Throw "Execute-Process function failed with exit code [$($ExecuteResult.ExitCode)]."
          }
          Else 
          {
            Throw "gpupdate.exe failed with exit code [$($ExecuteResult.ExitCode)]."
          }
        }
        $InstallCount++
      }
      Catch 
      {
        Write-Log -EntryType Error -Message "Failed to $($InstallMsg). `n$(Resolve-Error)"  -Source $CmdletName
        If (-not $ContinueOnError) 
        {
          Throw "Failed to $($InstallMsg): $($_.Exception.Message)"
        }
        Continue
      }
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}


Function Invoke-SetupOffice2016
{
  [CmdletBinding()]
  Param (
  )
	
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process 
  {
    Write-Log -EntryType Information -Message 'Installing Office 2016' -Source $CmdletName

    Try 
    {
      #$OSDOffice2016Setup = Join-Path -Path $(Get-TSValue -Name 'OSDOffice201601') -ChildPath 'setup.exe'
    }
    Catch 
    {
      #Write-Log -EntryType Error -Message "Unable to create path from TS environment variable for office 2016 `n$(Resolve-Error)" -Source $CmdletName
    }

    Try	
    {
      #Start-Process -FilePath "$OSDOffice2016Setup" -ArgumentList '/adminfile', "$env:SystemDrive\_SMSTaskSequence\Packages\DC000075\updates\_Hitachi.MSP" -Wait
    }
    Catch 
    {
      #Write-Log -EntryType Error -Message "Unable to start office 2016 setup process `n$(Resolve-Error)" -Source $CmdletName
    }
	
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetupRunOnce
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process 
  {
    if(Test-IsAdmin) 
    {
      New-Item -Path "$env:systemroot\OSDDeployment\" -ItemType Directory -Force -Confirm:$false
      Copy-Item -Path "$PSScriptRoot\*" -Destination "$env:systemroot\OSDDeployment\" -Recurse -Force -Confirm:$false
		
      Show-Progress -Message 'Adding registry key for RunOnceEx' -Source $CmdletName

      $RunOnceRegisterKeys = @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
          Name        = 'Title'
          Value       = 'OSD RunOnce'
          Description = 'Setup RunOnce'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
          Name  = 'Flags'
          Value = 30
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001'
          Name  = 'ProfileSetup'
          Value = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy ByPass -WindowStyle Hidden -Nologo -Command "&{ C:\Windows\OSDDeployment\Setup.ps1 -CurrentUser }"'
        }
      )
      Set-RegistryValues -registerKeys $RunOnceRegisterKeys
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }
	
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Set-RegistryValues 
{
  [CmdletBinding()]
  Param
  (
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user')]
    $registerKeys
  )
	
  Begin {
    ## Get the name of this function and write header
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process {
    Foreach ($registerKey in $registerKeys)
    {
      If(
        !([string]::IsNullOrEmpty($($registerKey.Key))) -and
        !([string]::IsNullOrEmpty($($registerKey.Name))) 
      )
      {
        $key = Convert-RegistryPath -Key $registerKey.Key
        $Name = $registerKey.Name
        $Value = $registerKey.Value
					
        If([string]::IsNullOrEmpty($($registerKey.Description))) 
        { 
          Write-Log -EntryType Information -Message "Applying registry modification: $($registerKey.Description)" -Source $CmdletName
          Show-Progress -Message "Applying registry modification: $($registerKey.Description)" -Source $CmdletName
        }
						
        Try 
        {
          if (!(Test-Path -LiteralPath $key))
          {
            Write-Log -EntryType Information -Message "Creating registry $key" -Source $CmdletName
            $null = New-Item -Path $key -ItemType RegistryKey -Force
          }
          Write-Log -EntryType Information -Message "Path $key Name $Name Value $Value" -Source $CmdletName
         
          if(!([string]::IsNullOrEmpty($Value))) 
          {
            Set-ItemProperty -LiteralPath $key -Name $Name -Value $Value -Force
          } 
          else 
          {
            Set-ItemProperty -LiteralPath $key -Name $Name -Value "$null" -Force
          }
        }
        Catch 
        {
          $Message = "Unable to add registry item [$key] [$Name] [$Value]"
          Write-Log -EntryType Warning -Message "$Message. `n$(Resolve-Error)" -Source $CmdletName
          Continue
        }
					
        if(Test-Path -Path "$key" -PathType Container) 
        {
          Write-Log -EntryType Warning -Message "Testing if registry value name exists: $(Test-RegistryValue -Key "$key" -Value "$Name")" -Source $CmdletName
        }
        else 
        {
          Write-Log -EntryType Warning -Message 'Registry key does not exist' -Source $CmdletName
        }
      }
    }
  }
		
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Get-VirtualPrinter
{
  Param
  (
    [Parameter(Mandatory = $true)]
    [string]$PrinterName
  )

  
  Function Test-PrinterName
  {
    Process
    {
      if ($_.Name -eq $PrinterName)
      {
        $_
      }
    }
  }

  (Get-Printer | Test-PrinterName)
}

Function Remove-VirtualPrinter
{
  Param
  (
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user')]
    [string]$PrinterName
  )
  Function Test-PrinterName
  {
    Process
    {
      if ($_.Name -eq $PrinterName)
      {
        $_
      }
    }
  }

  (Get-Printer | Test-PrinterName) | Remove-Printer
}

Function Invoke-SetupShortcutsAsAdmin
{
  [CmdletBinding()]
  Param  
  ()

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
	
    if(Test-IsAdmin) 
    {
      $PowerShellPath = "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\"
      $CommandPrompt = "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\"

      $ShortcutPaths = Get-ChildItem -Path $PowerShellPath -Recurse -Include *.lnk
      $ShortcutPaths += Get-ChildItem -Path $CommandPrompt -Recurse -Include 'Command Prompt.lnk'

      Foreach ($ShortcutPath in $ShortcutPaths) 
      {
        Show-Progress -Message "Setting '$ShortcutPath' to run as administrator" -Source $CmdletName
			
        Try 
        {
          $bytes = [IO.File]::ReadAllBytes("$ShortcutPath")
          $bytes[0x15] = $bytes[0x15] -bor 0x20
          [IO.File]::WriteAllBytes("$ShortcutPath", $bytes)
        } 
        Catch 
        {
          Write-Log -EntryType Warning -Message "Unable to set [$ShortcutPath] to always run as administrator"
        }
      }
    }
    else 	
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-DisableServices
{
  [CmdletBinding()]
  Param
  (
    $services = @(
      'diagnosticshub.standardcollector.service' # Microsoft (R) Diagnostics Hub Standard Collector Service
      'DiagTrack'                                # Diagnostics Tracking Service
      'dmwappushservice'                         # WAP Push Message Routing Service
      'HomeGroupListener'                        # HomeGroup Listener
      'HomeGroupProvider'                        # HomeGroup Provider
      'lfsvc'                                    # Geolocation Service
      'MapsBroker'                               # Downloaded Maps Manager
      'SharedAccess'                             # Internet Connection Sharing (ICS)
      'WbioSrvc'                                 # Windows Biometric Service
      'WMPNetworkSvc'                            # Windows Media Player Network Sharing Service
      'XblAuthManager'                           # Xbox Live Auth Manager
      'XblGameSave'                              # Xbox Live Game Save Service
      'XboxNetApiSvc'                            # Xbox Live Networking Service
      'TrkWks'                                   # Distributed Link Tracking Client. Description: Maintains links between NTFS files within a computer or across computers in a network.
      'beep'                                     # Windows Beep Service, stops annoying beeps in powershell console
    )
  )
	
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
    if(Test-IsAdmin) 
    {
      Foreach ($service in $services)
      {
        Show-Progress -Message "Stopping Service and disabling [$service]" -Source $CmdletName
			
        Try 
        {
          $null = Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
        }
        Catch 
        {
          Write-Log -EntryType Warning -Message "Unable to set [$service] to disabled"
        }
				
        Try 
        {
          $null = Stop-Service -InputObject $service -ErrorAction Stop
        }
        Catch 
        {
          Write-Log -EntryType Warning -Message "Unable to stop [$service]"
        }
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetIEDefaultSearchProvider
{
  [CmdletBinding()]
  Param()

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
		
    $SearchScopes  = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\SearchScopes'
    $null = New-ItemProperty -Path "$SearchScopes" -Name 'DefaultScope' -PropertyType 'String' -Value '{A3C1E120-0692-4CFE-8F3E-FC214C255495}' -Force

    Write-Log -EntryType Information -Message 'Setting default search provider for IE to Google' -Source $CmdletName
 
    $Guid = '{A3C1E120-0692-4CFE-8F3E-FC214C255495}'
    #{0633EE93-D776-472f-A0FF-E1416B8B2E3A} - Remove Bing
    $null = New-Item -Path $SearchScopes -Name "$Guid" -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'DisplayName' -PropertyType 'String' -Value 'Google' -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'FaviconURL' -PropertyType 'String' -Value 'http://www.google.com/favicon.ico' -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'FaviconURLFallback' -PropertyType 'String' -Value 'http://www.google.com/favicon.ico' -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'OSDFileURL' -PropertyType 'String' -Value 'http://www.iegallery.com/en-us/AddOns/DownloadAddOn?resourceId=813' -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'ShowSearchSuggestions' -PropertyType 'DWord' -Value '1' -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'SuggestionsURL' -PropertyType 'String' -Value 'http://clients5.google.com/complete/search?q={searchTerms}&client=ie8&mw={ie:maxWidth}&sh={ie:sectionHeight}&rh={ie:rowHeight}&inputencoding={inputEncoding}&outputencoding={outputEncoding}' -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'SuggestionsURLFallback' -PropertyType 'String' -Value 'http://clients5.google.com/complete/search?hl={language}&q={searchTerms}&client=ie8&inputencoding={inputEncoding}&outputencoding={outputEncoding}' -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'TopResultURLFallback' -PropertyType 'String' -Value "$null" -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'URL' -PropertyType 'String' -Value 'http://www.google.com/search?q={searchTerms}&sourceid=ie7&rls=com.microsoft:{language}:{referrer:source}&ie={inputEncoding?}&oe={outputEncoding?}' -Force
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'DefaultScope' -PropertyType 'String' -Value "$guid" -Force 

    Write-Log -EntryType Information -Message 'Adding Google Search' -Source $CmdletName

  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-DisableScheduledTasks
{
  [CmdletBinding()]
  Param
  (
    $tasks = @(
      'Microsoft\Windows\AppID\SmartScreenSpecific'
      'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser'
      'Microsoft\Windows\Application Experience\ProgramDataUpdater'
      'Microsoft\Windows\Application Experience\StartupAppTask'
      'Microsoft\Windows\Autochk\Proxy'
      'Microsoft\Windows\CloudExperienceHost\CreateObjectTask'
      'Microsoft\Windows\Customer Experience Improvement Program\Consolidator'
      'Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask'
      'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip'
      'Microsoft\Windows\Customer Experience Improvement Program\Uploader'
      'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
      'Microsoft\Windows\DiskFootprint\Diagnostics'
      'Microsoft\Windows\FileHistory\File History (maintenance mode)'
      'Microsoft\Windows\Maintenance\WinSAT'
      'Microsoft\Windows\NetTrace\GatherNetworkInfo'
      'Microsoft\Windows\PI\Sqm-Tasks'
      'Microsoft\Windows\Windows Error Reporting\QueueReporting'
      'Microsoft\Windows\WindowsUpdate\Automatic App Update'
      'Microsoft\Office\Office 15 Subscription Heartbeat'
      'Microsoft\Office\OfficeTelemetryAgentFallBack'
      'Microsoft\Office\OfficeTelemetryAgentLogOn'
      'Microsoft\Windows\Feedback\Siuf\DmClient'
      'Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser'
      '\NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}' # Nvidia Telemetry
      '\NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8' # Nvidia Telemetry
      '\NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}' # Nvidia Telemetry
    )
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    Foreach ($task in $tasks)
    {
      Show-Progress -Message "Removing scheduled task $task" -Source $CmdletName
      try 
      {
        Disable-ScheduledTask -TaskName $task -ErrorAction Stop
      }
      catch 
      {
        Write-Log -EntryType Warning -Message "Unable to remove scheduled task [$task]"
      }
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetPowerPlan
{
  [CmdletBinding()]
  Param(
    [bool]$HighPerformance,
    [bool]$Balanced
  )
  
  if($HighPerformance) {
  
    $Filter = 'High performance'
  
  } else {
    $Filter = 'Balanced'
  }

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
	
    If(Test-IsAdmin) 
    {
      Function Select-Plan
      {
        Process
        {
          if($_.contains($Filter)) 
          {
            $_.split()[3]
          }
        }
      }

      Try 
      {
        Show-Progress -Message 'Activating [High Performance] power plan' -Source $CmdletName
        $HighPerf = & "$env:windir\system32\powercfg.exe" -l | Select-Plan
        $CurrPlan = $(& "$env:windir\system32\powercfg.exe" -getactivescheme).split()[3]
        if ($CurrPlan -ne $HighPerf) 
        {
          & "$env:windir\system32\powercfg.exe" -setactive $HighPerf
        }
      }
      Catch 
      {
        Write-Log -EntryType Warning -Message 'Unable to set power plan to [High Performance]' -Source $CmdletName
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}


Function Invoke-InstallSoftware
{
  [CmdletBinding()]
  Param
  (
    [string[]]$SoftwareList = @(
      'winscp'
      'ussf'
      'ffmpeg'
      'sudo'
      'googlechrome'
      'directx'
      'origin'
      'uplay'
      '7zip.install'
      'autohotkey.install'
      'ccenhancer' # https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini download to C:\Program Files\CCleaner alternative
      'ccleaner'
      'chocolatey'
      'chocolatey-core.extension'
      'chocolatey-uninstall.extension'
      'chocolatey-visualstudio.extension'
      'chocolatey-windowsupdate.extension'
      'cpu-z.install'
      'discord'
      'DotNet4.6.1'
      'ffmpeg'
      'geforce-game-ready-driver-win10'
      'git.install'
      'gpu-z'
      'grepwin'
      'irfanviewplugins'
      'irfanview'
      'jdk8'
      'k-litecodecpackfull'
      'kodi'
      'nircmd'
      'nodejs.install'
      'notepadplusplus.install'
      'Office365ProPlus'
      'PSWindowsUpdate'
      'putty.install'
      'PyCharm-community'
      'python2'
      'qbittorrent'
      'ipfilter-updater'
      'rsat'
      'Shotcut'
      'streamlink'
      'streamlink-twitch-gui'
      'sysinternals'
      'vcredist2005'
      'vcredist2008'
      'vcredist2010'
      'vcredist2012'
      'vcredist2013'
      'vcredist2015'
      'visualstudio2017-installer'
      'visualstudio2017community'
      'WhatsApp'
      'youtube-dl'
      'nuget.commandline'
    )
  )
	
	
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
	
    if(Test-IsAdmin) 
    {
      if(!(Test-Path -Path "$env:AllUsersProfile\chocolatey\choco.exe")) 
      {
        Write-Log -EntryType Warning -Message 'Chocolatey is not installed skipping software installation' -Source $CmdletName
        return
        # TODO: Attempt to install chocolatey
      }
  
      Foreach ($Software in $SoftwareList)
      {
        Show-Progress -Message 'Installing software Software' -Source $CmdletName
        Run-ProcessWithOutput -FileName "$env:AllUsersProfile\chocolatey\choco.exe" -Arguments 'install Software -y'
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-RemoveBuiltinApps
{
  [CmdletBinding()]
  Param
  (
    $apps = @(
      'Microsoft.Windows.CloudExperienceHost'
      'Microsoft.Windows.ShellExperienceHost'
      'Microsoft.AAD.BrokerPlugin'
      'Microsoft.Windows.Cortana'
      'Microsoft.Appconnector'
      'Microsoft.Messaging'
      'Microsoft.Windows.Apprep.ChxApp'
      'Microsoft.Windows.AssignedAccessLockApp'
      'Microsoft.Windows.ContentDeliveryManager'
      'Microsoft.Windows.ParentalControls'
      'Microsoft.Windows.SecondaryTileExperience'
      'Microsoft.Windows.SecureAssessmentBrowser'
      'Microsoft.AccountsControl'
      'Microsoft.LockApp'
      'Microsoft.MicrosoftEdge'
      'Microsoft.PPIProjection'
      'Windows.PrintDialog'
      'Microsoft.StorePurchaseApp'
      'Microsoft.NET.Native.Runtime.1.3'
      'Microsoft.NET.Native.Runtime.1.1'
      'Microsoft.NET.Native.Framework.1.3' 
      'Microsoft.NET.Native.Runtime.1.4' 
      'Microsoft.VCLibs.140.00' 
      'Microsoft.VCLibs.120.00' 
      'Microsoft.BingTranslator' 
      'Microsoft.DesktopAppInstaller'
      'Microsoft.MicrosoftStickyNotes'
      'Microsoft.BingWeather'
      'Microsoft.WindowsMaps'
      'Microsoft.WindowsSoundRecorder'
      'Microsoft.Windows.Photos'
      'Microsoft.WindowsStore'
      'Microsoft.WindowsAlarms'
      'microsoft.WindowsCommunicationsApps'
      'Microsoft.WindowsCalculator'
    )
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    if(Test-IsAdmin) 
    {
      Function Test-AppDisplayName
      {
        Process
        {
          if (
            $_.DisplayName -like $app.Name
          )
          {
            $_
          }
        }
      }

      $AppArrayList = Get-AppxPackage -PackageTypeFilter Bundle |
      Select-Object -Property Name, PackageFullName |
      Sort-Object -Property Name

      # Loop through the list of apps
      Foreach ($app in $AppArrayList) 
      {
        If (($app.Name -in $apps)) # Exclude essential Windows apps
        {
          Show-Progress -Message "Skipping essential Windows app: $($app.Name)" -Source $CmdletName
        }
        Else # Remove AppxPackage and AppxProvisioningPackage
        {
          # Gather package names
          $AppPackageFullName = Get-AppxPackage -Name $app.Name | Select-Object -ExpandProperty PackageFullName
          $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online |
          Test-AppDisplayName |
          Select-Object -ExpandProperty PackageName

          # Attempt to remove AppxPackage
          Try 
          {
            Show-Progress -Message "Removing AppxPackage: $($AppPackageFullName)" -Source $CmdletName
            Remove-AppxPackage -Package $AppPackageFullName -ErrorAction Stop
          }
          Catch  
          {
            Write-Log -EntryType Warning -Message "$_.Exception.Message" -Source $CmdletName
          }

          Try 
          {
            Show-Progress -Message "Removing AppxProvisioningPackage: $($AppProvisioningPackageName)" -Source $CmdletName
            Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -ErrorAction Stop
          }
          Catch  
          {
            Write-Log -EntryType Warning -Message "$_.Exception.Message" -Source $CmdletName
          }
        }
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-AddWindowsFeatures
{
  [CmdletBinding()]
  param
  (
    $features = @(
      'NetFx3'
    )
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process 
  {
    if(Test-IsAdmin) 
    {
      Foreach ($feature in $features) 
      {
        if((Get-WindowsOptionalFeature -Online -FeatureName $feature).State -eq 'Disabled') 
        {
          Show-Progress -Message "Adding Windows feature [$feature]" -Source $CmdletName
          Try 
          {
            Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart -Source "$PSScriptRoot\Sources\sxs" -ErrorAction Stop
          }
          Catch 
          {
            Write-Log -EntryType Warning -Message "Unable to add windows feature [$feature]"
          }
        }
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Copy-BackgroundImage 
{
  [CmdletBinding()]
  param()


  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
		
    if(Test-IsAdmin) 
    {
      $Destination = "$env:systemroot\WEB\Wallpaper\Windows"
      $File = 'img0.jpg'
      $Source = Join-Path -Path "$PSScriptRoot\Wallpaper" -ChildPath $File

      Write-Log -EntryType Information -Message "Taking ownership of $Destination" -Source $CmdletName
      $acl = Get-Acl -Path $Destination
      $Group = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList ('Builtin', 'Administrators')
      $acl.SetOwner($Group)
      Set-Acl -Path $Destination -AclObject $acl
	
      Write-Log -EntryType Information -Message "Changing permissions on $Destination folder" -Source $CmdletName
      $Permission = $Group, 'FullControl', 'Allow'
      $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
      $acl.SetAccessRule($AccessRule)
      Set-Acl -Path $Destination -AclObject $acl
	
      Write-Log -EntryType Information -Message "Enabling permission inheritance on $Destination folder" -Source $CmdletName
      $New = $Group, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
      $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $New
      $acl.SetAccessRule($AccessRule)
      Set-Acl -Path $Destination -AclObject $acl
      $Files = (Get-ChildItem -Path $Destination)
	
      Foreach ($File in $Files)
      {
        $Permission = $Group, 'FullControl', 'Allow'
        $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
        $acl.SetAccessRule($AccessRule)
        $ACLFile = (Join-Path -Path $Destination -ChildPath $File)
        Write-Log -EntryType Information -Message "Changing permissions on $ACLFile" -Source $CmdletName
        Set-Acl -Path $ACLFile -AclObject $acl
      }
      Copy-File -Path $Source -Destination $Destination
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Copy-LockScreenImage 
{
  [CmdletBinding()]
  Param()

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    if(Test-IsAdmin) 
    {
      $File = 'img105.jpg'
      $Destination = "$env:systemroot\WEB\Screen"
      $Source = Join-Path -Path "$PSScriptRoot\LockScreen" -ChildPath $File

      Write-Log -EntryType Information -Message "Taking ownership of $Destination" -Source $CmdletName
      $acl = Get-Acl -Path $Destination
      $Group = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList ('Builtin', 'Administrators')
      $acl.SetOwner($Group)
      Set-Acl -Path $Destination -AclObject $acl
	
      Write-Log -EntryType Information -Message "Changing permissions on $Destination folder" -Source $CmdletName 
      $Permission = $Group, 'FullControl', 'Allow'
      $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
      $acl.SetAccessRule($AccessRule)
      Set-Acl -Path $Destination -AclObject $acl
	
      Write-Log -EntryType Information -Message "Enabling permission inheritance on $Destination folder" -Source $CmdletName
      $New = $Group, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
      $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $New
      $acl.SetAccessRule($AccessRule)

      Set-Acl -Path $Destination -AclObject $acl
      $Files = (Get-ChildItem -Path $Destination)
	
      Foreach ($File in $Files)
      {
        $Permission = $Group, 'FullControl', 'Allow'
        $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
        $acl.SetAccessRule($AccessRule)
        $ACLFile = (Join-Path -Path $Destination -ChildPath $File)
        Write-Log -EntryType Information -Message "Changing permissions on $ACLFile" -Source $CmdletName
        Set-Acl -Path $ACLFile -AclObject $acl
      }
		
      Copy-File -Path $Source -Destination $Destination
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetupFileAssociations 
{
  [CmdletBinding()]
  Param()

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process {
    if(Test-IsAdmin) 
    {
      Show-Progress -Message "Copying [$PSScriptRoot\FileAssociations\AppAssoc.xml] to [$env:ProgramData\Microsoft\Windows]" -Source $CmdletName
		
      Copy-File -Path "$PSScriptRoot\FileAssociations\AppAssoc.xml" -Destination "$env:ProgramData\Microsoft\Windows\AppAssoc.xml"
		
      Try 
      {
        & "$env:windir\system32\dism.exe" /online /Import-DefaultAppAssociations:"$env:ProgramData\Microsoft\Windows\AppAssoc.xml"
      }
      Catch 
      {
        Write-Log -EntryType Warning -Message 'Unable to execute DISM to setup file ssociations'
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }
	
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-DisableWindowsThemeSounds
{
  #-----------------------
  # Context: Current User
  #-----------------------
  [CmdletBinding()]
  Param()

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process {

    Show-Progress -Message 'Disable all windows sounds' -Source $CmdletName
    $ThemeSounds = Get-ChildItem -Path 'Registry::HKEY_CURRENT_USER\AppEvents\Schemes\Apps' -Recurse | Get-ItemProperty
    foreach ($RegKey in $ThemeSounds)
    {
      $strVal = [string]$RegKey.'(default)'
      if($strVal.EndsWith('.wav'))
      {
        Set-ItemProperty -Path $RegKey.PSPath -Name '(default)' -Value ''
      }
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-RemoveBuiltInPrinters
{
  [CmdletBinding()]
  Param()

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
    if(Test-IsAdmin) 
    {
      $PrintersToRemove = 'Microsoft XPS Document Writer', 'Send to OneNote 2016', 'Fax'
      foreach ($Printer in $PrintersToRemove)
      {
        $PrinterToFind = (Get-VirtualPrinter -PrinterName $Printer)
        if (!($PrinterToFind -eq $null))
        {
          Write-Log -EntryType Information -Message "Removing $Printer" -Source $CmdletName
          Try 
          {
            Remove-VirtualPrinter -PrinterName $Printer
          } 
          Catch 
          {
            $Message = "Unable to remove [$Printer]"
            Write-Log -EntryType Warning -Message "$Message. `n$(Resolve-Error)" -Source $CmdletName
            Continue
          }
        }
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetWindowsSearchWebResults
{
  [CmdletBinding()]
  Param(
	
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
    Show-Progress -Message 'Disable windows search web results' -Source $CmdletName
    Try 
    {
      Set-WindowsSearchSetting -EnableWebResultsSetting $false
    }
    Catch 
    {
      $Message = 'Unable to disable windows search web results the service may already be disabled'
      Write-Log -EntryType Warning -Message "$Message. `n$(Resolve-Error)" -Source $CmdletName
      Continue
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetupTaskBarItemsCurrentUser
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
	
    $taskbarlayoutxml = @'
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
  <CustomTaskbarLayoutCollection>
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk"/>
        <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk"/>
        <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Google Chrome.lnk"/>
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
'@
    $Destination = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\"
    if (!(Test-Path -Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")) 
    {
      Show-Progress -Message "Creating Path [$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar]" -Source $CmdletName
      New-Item -Force -Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    }
		
    Show-Progress -Message "Copying shortcuts to [$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar]" -Source $CmdletName
    Copy-File -Path "$PSScriptRoot\CurrentUserPinTaskBar\*.lnk" -Destination $Destination

    Try 
    {
      Add-Content -Path "$env:TEMP\taskbarlayout.xml" -Value $taskbarlayoutxml
    }
    Catch 
    {
      Write-Log -EntryType Warning  -Message "Unable to create temp file [$env:TEMP\taskbarlayout.xml] for clean start menu layout for new users"
    }

    Try 
    {
      Import-StartLayout -LayoutPath "$env:TEMP\taskbarlayout.xml" -MountPath $env:SystemDrive
    }
    Catch 
    {
      Write-Log -EntryType Warning  -Message "Unable to import file [$env:TEMP\taskbarlayout.xml] for clean start menu layout for new users"
    }
		
    Try 
    {
      Remove-Item -Path "$env:TEMP\taskbarlayout.xml"
    }
    Catch 
    {
      Write-Log -EntryType Warning  -Message "Unable to remove temp file [$env:TEMP\taskbarlayout.xml] for clean start menu layout for new users"
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetupTaskBarItemsDefaultUsers
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
    if(Test-IsAdmin) 
    {
      $Destination = "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\"
      if (!(Test-Path -Path "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")) 
      {
        Show-Progress -Message "Creating Path $env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" -Source $CmdletName
        New-Item -Force -Path "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
      }
    
      Copy-File -Path "$PSScriptRoot\DefaultUserPinTaskBar\*.lnk" -Destination $Destination
      Show-Progress -Message "Importing Registry File for Taskbar $PSScriptRoot\DefaultUserPinTaskBar\Taskbar.reg" -Source $CmdletName
		
      Try 
      {
        Run-ProcessWithOutput -FileName "$env:windir\system32\reg.exe" -Arguments "load HKEY_LOCAL_MACHINE\defuser $env:SystemDrive\Users\Default\NTUSER.DAT"
        Run-ProcessWithOutput -FileName "$env:windir\system32\reg.exe" -Arguments "import $PSScriptRoot\DefaultUserPinTaskBar\Taskbar.reg"
        Run-ProcessWithOutput -FileName "$env:windir\system32\reg.exe" -Arguments 'unload HKEY_LOCAL_MACHINE\defuser'
      }
      Catch 
      {
        $Message = 'Unable to import taskbar registry items'
        Write-Log -EntryType Warning -Message "$Message. `n$(Resolve-Error)" -Source $CmdletName
        Continue
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetupStartmenuDefaultUsers
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process {
    If(Test-IsAdmin) 
    {
      Show-Progress -Message 'Copying Start Menu Shortcuts to Default User' -Source $CmdletName
		
      Copy-Item -Path "$PSScriptRoot\StartMenuShortcuts\Control Panel.lnk" -Destination "$env:AllUsersProfile\Microsoft\Windows\Start Menu\Programs\System Tools\"
      Copy-Item -Path "$PSScriptRoot\StartMenuShortcuts\File Explorer.lnk" -Destination "$env:AllUsersProfile\Microsoft\Windows\Start Menu\Programs\System Tools\"
      Copy-Item -Path "$PSScriptRoot\StartMenuShortcuts\Internet Explorer.lnk" -Destination "$env:AllUsersProfile\Microsoft\Windows\Start Menu\Programs\Accessories\"

      Show-Progress -Message 'Applying clean start menu layout for new user profiles'
		
      $startlayoutstr = @'
<LayoutModificationTemplate Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
  <LayoutOptions StartTileGroupCellWidth="6" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout">
        <start:Group Name="" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Snipping Tool.lnk" />
        </start:Group>
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
</LayoutModificationTemplate>
'@

      Try 
      {
        Add-Content -Path "$env:TEMP\startlayout.xml" -Value $startlayoutstr
      }
      Catch 
      {
        Write-Log -EntryType Warning  -Message "Unable to create temp file [$env:TEMP\startlayout.xml] for clean start menu layout for new users"
      }

      Try 
      {
        Import-StartLayout -LayoutPath "$env:TEMP\startlayout.xml" -MountPath $env:SystemDrive
      }
      Catch 
      {
        Write-Log -EntryType Warning  -Message "Unable to import file [$env:TEMP\startlayout.xml] for clean start menu layout for new users"
      }
		
      Try 
      {
        Remove-Item -Path "$env:TEMP\startlayout.xml"
      }
      Catch 
      {
        Write-Log -EntryType Warning  -Message "Unable to remove temp file [$env:TEMP\startlayout.xml] for clean start menu layout for new users"
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }
	
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetupStartmenuCurrentUser
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process {

    Show-Progress -Message 'Setting up start menu shortcuts for user' -Source $CmdletName
		
    $startlayoutstruser = @'
<LayoutModificationTemplate Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout">
  <LayoutOptions StartTileGroupCellWidth="6" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout">
        <start:Group Name="" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\System Tools\Control Panel.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="2" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Snipping Tool.lnk" />
          <start:Tile Size="2x2" Column="4" Row="2" AppUserModelID="windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" />
          <start:Tile Size="2x2" Column="4" Row="0" AppUserModelID="Microsoft.WindowsAlarms_8wekyb3d8bbwe!App" />
          <start:Tile Size="2x2" Column="2" Row="2" AppUserModelID="Microsoft.WindowsCalculator_8wekyb3d8bbwe!App" />
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="4" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Microsoft System Center\Configuration Manager\Software Center.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="4" Row="4" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Word 2016.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="6" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Skype for Business 2016.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="6" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\OneDrive for Business.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="4" Row="6" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Outlook 2016.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="4" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Excel 2016.lnk" />
        </start:Group>
        <start:Group Name="" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk" />
        </start:Group>
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
    <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk"/>
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
'@

    Try 
    {
      Add-Content -Path "$env:TEMP\startlayoutuser.xml" -Value $startlayoutstr
    }
    Catch 
    {
      Write-Log -EntryType Warning  -Message "Unable to create temp file [$env:TEMP\startlayoutuser.xml] for clean start menu layout for new users"
    }

    Try 
    {
      Import-StartLayout -LayoutPath "$env:TEMP\startlayoutuser.xml" -MountPath $env:SystemDrive
    }
    Catch 
    {
      Write-Log -EntryType Warning  -Message "Unable to import file [$env:TEMP\startlayoutuser.xml] for clean start menu layout for new users"
    }
		
    Try 
    {
      Remove-Item -Path "$env:TEMP\startlayoutuser.xml"
    }
    Catch 
    {
      Write-Log -EntryType Warning  -Message "Unable to remove temp file [$env:TEMP\startlayoutuser.xml] for clean start menu layout for new users"
    }
  }
	
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetLanguage
{
  [CmdletBinding()]
  param (
    [int]$Id = 1
  )

  switch ($Id)
  {
    1            
    { 
      # English 
      if(!($CurrentUser.IsPresent)) 
      {
        if(Test-IsAdmin) 
        {
          Set-WinSystemLocale -SystemLocale en-za
        }
      }
      else 
      {
        Set-Culture -CultureInfo en-za
        Set-WinUserLanguageList -LanguageList en-za -Force
        Set-WinUILanguageOverride -Language en-za
      }
    }
    2            
    {
      # Portugese
      if(!($CurrentUser.IsPresent)) 
      {
        if(Test-IsAdmin) 
        {
          Set-WinSystemLocale -SystemLocale pt-pt
        }
      }
      else 
      {
        Set-Culture -CultureInfo pt-pt
        Set-WinUserLanguageList -LanguageList pt-pt -Force
        Set-WinUILanguageOverride -Language pt-pt
      }
    }
    3   
    {
      # Japanese
      if(!($CurrentUser.IsPresent)) 
      {
        if(Test-IsAdmin) 
        {
          Set-WinSystemLocale -SystemLocale ja-jp
        }
      }
      else 
      {
        Set-Culture -CultureInfo ja-jp
        Set-WinUserLanguageList -LanguageList ja-jp -Force
        Set-WinUILanguageOverride -Language ja-jp
      }
    }

    default      
    {
      # English 
      if(!($CurrentUser.IsPresent)) 
      {
        if(Test-IsAdmin) 
        {
          Set-WinSystemLocale -SystemLocale en-za
        }
      }
      else 
      {
        Set-Culture -CultureInfo en-za
        Set-WinUserLanguageList -LanguageList en-za -Force
        Set-WinUILanguageOverride -Language en-za
      }
    }
  }
}

Function Invoke-SetHomeLocation
{
  [CmdletBinding()]
  param (
    [int]$Id = 1
  )
  switch ($Id)
  {
    1            
    { 
      # South Africa
      Set-WinHomeLocation -GeoId 209
    }
    2            
    {
      # Zambia
      Set-WinHomeLocation -GeoId 263
    }
    3   
    {
      # Mozambique
      Set-WinHomeLocation -GeoId 168
    }
    default      
    {
      # South Africa
      Set-WinHomeLocation -GeoId 209
    }
  }
}

Function Add-PowerShellContextMenu
{
  [CmdletBinding()]
  param(
    [Parameter(Position = 0)]
    [ValidateSet('openPowerShellHere','editWithPowerShellISE')]
    $contextType,
    $platform = 'x64',
    [switch]$noProfile,
    [switch]$asAdmin
  )
	
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process {
    if(Test-IsAdmin) 
    {
      $versionToOpen = 'PowerShell (x64)'
      $powerShellExe = 'powershell.exe'
      if ($contextType -eq 'editWithPowerShellISE') 
      { 
        $powerShellExe = 'PowerShell_ISE.exe' 
        $versionToOpen = 'PowerShell ISE (x64)'
      }
      $PowerShellPath = "$env:windir\sysWOW64\WindowsPowerShell\v1.0\$powerShellExe"
      if ($platform -eq 'x86')
      { 
        $PowerShellPath = "$env:windir\sysWOW64\WindowsPowerShell\v1.0\$powerShellExe" 
        $versionToOpen = $versionToOpen -replace 'x64', 'x86'
      }
      if ($contextType -eq 'openPowerShellHere')
      {
        $menu = "Open Windows $versionToOpen here"
        $command = "$PowerShellPath -NoExit -Command ""Set-Location '%V'"""
        if ($noProfile.IsPresent)
        {
          $command = $command -replace 'NoExit', 'NoExit -noProfile'
        }
        if ($asAdmin.IsPresent)
        {
          $menu += ' as Administrator'
          'directory', 'directory\background', 'drive' | ForEach-Object -Process {
            New-Item -Path "Registry::HKEY_CLASSES_ROOT\$_\shell" -Name runas\command -Force |
            Set-ItemProperty -Name '(default)' -Value $command -PassThru |
            Set-ItemProperty -Path {
              $_.PSParentPath
            } -Name '(default)' -Value $menu -PassThru |
            Set-ItemProperty -Name HasLUAShield -Value ''
          }
        }
        else
        {
          'directory', 'directory\background', 'drive' | ForEach-Object -Process {
            $null = New-Item -Path "Registry::HKEY_CLASSES_ROOT\$_\shell" -Name $menu -Value $menu -Force
            $null = New-Item -Path "Registry::HKEY_CLASSES_ROOT\$_\shell\$menu\command" -Value $command
          }
        }
      }
      elseif($contextType -eq 'editWithPowerShellISE')
      {
        $menu = "Edit with $versionToOpen"
        $command = $PowerShellPath
        if ($noProfile.IsPresent)
        {
          $command += ' -noProfile'
        }
        if($asAdmin.IsPresent)
        {
          $menu += ' as Administrator'
          Get-ChildItem -Path 'Registry::HKEY_CLASSES_ROOT' |
          Where-Object -Property [ PSChildName -Like -Value 'Microsoft.PowerShell*' |
          ForEach-Object -Process {
            if (!(Test-Path -Path "Registry::$($_.Name)\shell"))
            {
              $null = New-Item -Path "Registry::$($_.Name)\shell"
            }
            New-Item -Path "Registry::$($_.Name)\shell\" -Name runas\command -Force |
            Set-ItemProperty -Name '(default)' -Value "$command ""%1""" -PassThru |
            Set-ItemProperty -Path {
              $_.PSParentPath
            } -Name '(default)' -Value $menu -PassThru |
            Set-ItemProperty -Name HasLUAShield -Value ''
          }
        }
        else
        {
          Get-ChildItem -Path 'Registry::HKEY_CLASSES_ROOT' |
          Where-Object -Property PSChildName -Like -Value 'Microsoft.PowerShell*' |
          ForEach-Object -Process {
            if (!(Test-Path -Path "Registry::$($_.Name)\shell"))
            {
              $null = New-Item -Path "Registry::$($_.Name)\shell"
            }
            $null = New-Item -Path "Registry::$($_.Name)\shell\$menu\command" -Value "$command ""%1""" -Force  
          }
        }
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }
	
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-ApplyRegistrySettingsCurrentUser 
{
  [CmdletBinding()]
  param()
	
			
  #------------------------------------------------------
  #  User specific settings for run once
  #------------------------------------------------------
	
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
      Name        = 'SensorPermissionState'
      Value       = 0
      Description = 'Disable app access to location'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
      Name  = 'Value'
      Value = 'DENY'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}'
      Name  = 'Value'
      Value = 'DENY'
    }
  )
				
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to text messages'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}'
      Name  = 'Value'
      Value = 'DENY'
    }
  )
				
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to camera'
    }

    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to Calendar'
    }

    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to Contacts'
    }

    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to Notifications'
    }

    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to Microphone'
    }

    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to Account Info'
    }

    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to Call history'
    }

    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to email'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable app access to radios'
    }
  )
			
  # Mouse Settings
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Mouse'
      Name        = 'MouseSpeed'
      Value       = 0
      Description = 'Disable Mouse Acceleration'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Mouse'
      Name        = 'MouseSensitivity'
      Value       = 10
      Description = 'Disable Mouse Acceleration MouseSensitivity'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Mouse'
      Name        = 'MouseThreshold1'
      Value       = 0
      Description = 'Disable Mouse Acceleration MouseThreshold1'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Mouse'
      Name        = 'MouseThreshold2'
      Value       = 0
      Description = 'Disable Mouse Acceleration MouseThreshold2'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Mouse'
      Name        = 'SmoothMouseYCurve'
      Value       = ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))
      Description = 'Disable Mouse Acceleration SmoothMouseYCurve'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Mouse'
      Name        = 'SmoothMouseXCurve'
      Value       = ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
      Description = 'Disable Mouse Acceleration SmoothMouseXCurve'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
      Name        = 'UserPreferencesMask'
      Value       = ([byte[]](0x9e, 0x1e, 0x06, 0x80, 0x12, 0x00, 0x00, 0x00))
      Description = 'Disable mouse pointer hiding'
    }
  )

  # Accessibility Settings
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys'
      Name        = 'Flags'
      Value       = '506'
      Description = 'Disable sticky keys'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response'
      Name  = 'Flags'
      Value = '122'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys'
      Name  = 'Flags'
      Value = '58'
    }
  )
	
	
	
  # Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and full window dragging enabled
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
      Name        = 'DragFullWindows'
      Value       = '1'
      Description = 'Enable Drag Full Windows'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
      Name        = 'MenuShowDelay'
      Value       = '0'
      Description = 'Disable show menu delay'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Control Panel\Desktop'
      Name  = 'UserPreferencesMask'
      Value = ([byte[]](0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00))
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics'
      Name        = 'MinAnimate'
      Value       = '0'
      Description = 'Disable minimize and maximize animations'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Control Panel\Desktop\Keyboard'
      Name  = 'KeyboardDelay'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name  = 'ListviewAlphaSelect'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name  = 'ListviewShadow'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name  = 'TaskbarAnimations'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
      Name  = 'VisualFXSetting'
      Value = 3
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM'
      Name  = 'EnableAeroPeek'
      Value = 1
    }
  )
	
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager'
      Name        = 'EnthusiastMode'
      Value       = 1
      Description = 'Show file operations details'
    }
  )
			
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
      Name        = 'LogPixels'
      Value       = 96
      Description = 'Set Display DPI to 100%'
    }
  )
					
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\International\User Profile'
      Name        = 'HttpAcceptLanguageOptOut'
      Value       = 1
      Description = 'Disable websites providing local content by accessing language list'
    }
  )
			
  # Color and theme settings
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Colors'
      Name        = 'Background'
      Value       = '0 0 0'
      Description = 'Set desktop default Background color to black'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
      Name        = 'WallPaper'
      Value       = "$env:SystemDrive\Windows\Web\Wallpaper\Windows\img0.jpg"
      Description = 'Set desktop default wallpaper'
    }
  )
			
  # Explorer Settings
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'DisableThumbnailCache'
      Value       = 1
      Description = 'Disable creation of Thumbs.db thumbnail cache files'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'HideFileExt'
      Value       = 0
      Description = 'Hide file extensions'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'Hidden'
      Value       = 1
      Description = 'Show hidden files'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'ShowSuperHidden'
      Value       = 0
      Description = 'Show hidden operating system files'
    }
				
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'HideDrivesWithNoMedia'
      Value       = 0
      Description = 'Hide drives with no media'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'NavPaneExpandToCurrentFolder'
      Value       = 1
      Description = 'Expand to current folder in the left panel in Explorer'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'LaunchTo'
      Value       = 1
      Description = 'Change default Explorer view to This PC'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'ShowSyncProviderNotifications'
      Value       = 0
      Description = 'Disable showing sync provider notifications'
    }
  )

  # File Associations
  $registerKeys += @(
    # Microsoft.3DBuilder file associations
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg'
      Name        = 'NoOpenWith'
      Value       = "$null"
      Description = 'Remove 3DBuilder file associations'
    }

    # Microsoft Edge file associations
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9'
      Name        = 'NoOpenWith'
      Value       = "$null"
      Description = 'Remove Microsoft Edge file associations'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723'
      Name  = 'NoOpenWith'
      Value = "$null"
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs'
      Name  = 'NoOpenWith'
      Value = "$null"
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t'
      Name  = 'NoOpenWith'
      Value = "$null"
    }

    # Microsoft Photos file associations
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt'
      Name        = 'NoOpenWith'
      Value       = "$null"
      Description = 'Remove Microsoft Photos file associations'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc'
      Name  = 'NoOpenWith'
      Value = "$null"
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h'
      Name  = 'NoOpenWith'
      Value = "$null"
    }

    # Zune Music file associations
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs'
      Name        = 'NoOpenWith'
      Value       = "$null"
      Description = 'Remove Zune Music file associations'
    }

    # Zune Video file associations
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Classes\AppX6eg8h5sxqq90pv53845wmnbewywdqq5h'
      Name        = 'NoOpenWith'
      Value       = "$null"
      Description = 'Remove Zune Video file associations'
    }
  )
			
  # Game DVR
  $registerKeys += @(
    @{
      Key   = 'HKEY_CURRENT_USER\System\GameConfigStore'
      Name  = 'GameDVR_Enabled'
      Value = 0
    }
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR'
      Name        = 'AppCaptureEnabled'
      Value       = 0
      Description = 'Disable GameDVR'
    }
  )
			
  # Disable Start Menu suggestions
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      Name        = 'SystemPaneSuggestionsEnabled'
      Value       = 0
      Description = 'Disable Start Menu suggestions'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      Name        = 'SilentInstalledAppsEnabled'
      Value       = 0
      Description = 'Disable microsoft shoehorning apps quietly into your profile'
    }
  )
				
  # Lockscreen suggestions, rotating pictures and pre-installed apps
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SoftLandingEnabled'
      Name        = 'SoftLandingEnabled'
      Value       = 0
      Description = 'Disable Lockscreen suggestions'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      Name        = 'RotatingLockScreenEnable'
      Value       = 0
      Description = 'Disable Lockscreen rotating pictures'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      Name        = 'PreInstalledAppsEnabled'
      Value       = 0
      Description = 'Disable preinstalled apps, Minecraft and Twitter etc'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      Name  = 'OEMPreInstalledAppsEnabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
      Name  = 'ContentDeliveryAllowed'
      Value = 0
    }
  )
		
  # Disable SmartScreen Filter
  $edge = (Get-AppxPackage -AllUsers -Name 'Microsoft.MicrosoftEdge').PackageFamilyName
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'
      Name        = 'EnableWebContentEvaluation'
      Value       = 0
      Description = 'Disable SmartScreen Filter'
    }
    @{
      Key   = "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter"
      Name  = 'EnabledV9'
      Value = 0
    }
    @{
      Key   = "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter"
      Name  = 'PreventOverride'
      Value = 0
    }
  )

  # Device Access
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled'
      Name        = 'Value'
      Value       = 'DENY'
      Description = 'Disable apps sharing and syncing with non-explicitly paired wireless devices over uPnP'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled'
      Name  = 'Type'
      Value = 'LooselyCoupled'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled'
      Name  = 'InitialAppValue'
      Value = 'Unspecified'
    }
  )
			
  foreach ($key in (Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global')) 
  {
    if ($key.PSChildName -EQ 'LooselyCoupled') 
    {
      continue
    }
	
    $registerKeys += @(
      @{
        Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\' + $key.PSChildName
        Name  = 'Type'
        Value = 'InterfaceClass'
      }
      @{
        Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\' + $key.PSChildName
        Name  = 'Value'
        Value = 'Deny'
      }
      @{
        Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\' + $key.PSChildName
        Name  = 'InitialAppValue'
        Value = 'Unspecified'
      }
    )
  }
		
  # Don't ask for feedback
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules'
      Name        = 'NumberOfSIUFInPeriod'
      Value       = 0
      Description = 'Disable windows feedback submission'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules'
      Name  = 'PeriodInNanoSeconds'
      Value = 0
    }
  )
				
  # Stopping Cortana / Microsoft from getting to know you
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings'
      Name        = 'AcceptedPrivacyPolicy'
      Value       = 0
      Description = 'Stopping Cortana/Microsoft from getting to know you'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization'
      Name  = 'RestrictImplicitTextCollection'
      Value = 1
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization'
      Name  = 'RestrictImplicitInkCollection'
      Value = 1
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore'
      Name  = 'HarvestContacts'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Input\TIPC'
      Name  = 'Enabled'
      Value = 0
    }
  )
				
  # Disabling Cortana and Bing search user settings
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
      Name        = 'CortanaEnabled'
      Value       = 0
      Description = 'Disabling Cortana and Bing search user settings'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
      Name  = 'SearchboxTaskbarMode'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
      Name  = 'BingSearchEnabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
      Name  = 'DeviceHistoryEnabled'
      Value = 0
    }
  )
				
  # Stop Cortana from remembering history
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
      Name        = 'HistoryViewEnabled'
      Value       = 0
      Description = 'Stop Cortana from remembering history'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Printers\Defaults'
      Name        = 'NetID'
      Value       = '{00000000-0000-0000-0000-000000000000}'
      Description = 'Disable location aware printing'
    }
  )

  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync'
      Name        = 'BackupPolicy'
      Value       = 0x3c
      Description = 'Disable synchronization of settings current user'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync'
      Name  = 'DeviceMetadataUploaded'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync'
      Name  = 'PriorLogons'
      Value = 1
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility'
      Name  = 'Enabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync'
      Name  = 'Enabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings'
      Name  = 'Enabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials'
      Name  = 'Enabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme'
      Name  = 'Enabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language'
      Name  = 'Enabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState'
      Name  = 'Enabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization'
      Name  = 'Enabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout'
      Name  = 'Enabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows'
      Name  = 'Enabled'
      Value = 0
    }
  )

  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Console'
      Name        = 'QuickEdit'
      Value       = 1
      Description = 'Quick Edit Command Prompt'
    }
  )

  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
      Name        = 'AppsUseLightTheme'
      Value       = 0
      Description = 'Enable Dark Theme for XAML apps'
    }
  )

  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows Defender'
      Name        = 'UIFirstRun'
      Value       = 0
      Description = 'Disable Windows Defender First Run UI'
    }
  )
			
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main'
      Name        = 'DoNotTrack' 
      Value       = 1
      Description = 'Microsoft Edge settings'
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes'
      Name  = 'ShowSearchSuggestionsGlobal'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead'
      Name  = 'FPEnabled'
      Value = 0
    }
    @{
      Key   = 'HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter'
      Name  = 'EnabledV9'
      Value = 0
    }
  )
 
  # Taskbar settings
  $registerKeys += @(
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'TaskbarSmallIcons'
      Value       = 1
      Description = 'Set taskbar icons to small'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
      Name        = 'ShowTaskViewButton'
      Value       = 0
      Description = 'Hide Task View button'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
      Name        = 'SearchboxTaskbarMode'
      Value       = 0
      Description = 'Show Taskbar Search button / box'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
      Name        = 'PeopleBand'
      Value       = 0
      Description = 'Hide Taskbar People icon'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
      Name        = 'SearchboxTaskbarMode'
      Value       = 0
      Description = 'Remove Cortana from taskbar'
    }
    @{
      Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer'
      Name        = 'EnableAutoTray'
      Value       = 0
      Description = 'Show all tray icons'
    }
  )
}

Function Invoke-ApplyRegistrySettingsLocalMachine
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process {
	
    $registerKeys = @()

    #------------------------------------------------------
    #  Computer settings (Admin Rights Required)
    #------------------------------------------------------
    if(Test-IsAdmin)
    {
      # System Tweaks
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
          Name        = 'NoPreviousVersionsPage'
          Value       = 1
          Description = 'Disable previous versions tab'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
          Name        = 'Status'
          Value       = 0
          Description = 'Disable Location Tracking'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
          Name        = 'SensorPermissionState'
          Value       = 0
          Description = 'Disable Location Tracking'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\Maps'
          Name        = 'AutoUpdateEnabled'
          Value       = 0
          Description = 'Disabling automatic Maps updates'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
          Name        = 'EnablePrefetcher'
          Value       = 0
          Description = 'Disable Prefetch'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
          Name        = 'EnableSuperfetch'
          Value       = 0
          Description = 'Disable Superfetch'
        }
      )
			
      # Stop Edge Browser from Hijacking PDF & HTML OpenWith (Windows 10 1607+)
			
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723'
          Name        = 'NoOpenWith'
          Value       = $null
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723'
          Name        = 'NoStaticDefaultVerb'
          Value       = $null
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9'
          Name        = 'NoOpenWith'
          Value       = $null
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9'
          Name        = 'NoStaticDefaultVerb'
          Value       = $null
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9'
          Name        = 'NoOpenWith'
          Value       = $null
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9'
          Name        = 'NoStaticDefaultVerb'
          Value       = $null
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723'
          Name        = 'NoOpenWith'
          Value       = $null
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723'
          Name        = 'NoStaticDefaultVerb'
          Value       = $null
          Description = ''
        }
      )
			
      # Smart Screen Settings
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
          Name        = 'SmartScreenEnabled'
          Value       = 'Off'
          Description = 'Disabling SmartScreen Filter...'
        }
      )

				
      # GameDVR
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR'
          Name        = 'value'
          Value       = 0
          Description = 'Disable Game DVR and Game Bar'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
          Name  = 'AllowgameDVR'
          Value = 0
        }
      )

      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
          Name        = 'NoTileApplicationNotification'
          Value       = 0
          Description = 'Disabling tile push notification'
        }
      )
			
      # Windows Photo viewer file associations
      $registerKeys += @(	
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations'
          Name        = '.tif'
          Value       = 'PhotoViewer.FileAssoc.Tiff'
          Description = 'Photoviewer file associations'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations'
          Name  = '.tiff'
          Value = 'PhotoViewer.FileAssoc.Tiff'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations'
          Name  = '.jpg'
          Value = 'PhotoViewer.FileAssoc.Tiff'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations'
          Name  = '.jpeg'
          Value = 'PhotoViewer.FileAssoc.Tiff'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations'
          Name  = '.png'
          Value = 'PhotoViewer.FileAssoc.Tiff'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations'
          Name  = '.gif'
          Value = 'PhotoViewer.FileAssoc.Tiff'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations'
          Name  = '.bmp'
          Value = 'PhotoViewer.FileAssoc.Tiff'
        }
      )
   
      $registerKeys += @(
        @{
          Key         = 'HKEY_CLASSES_ROOT\*\shell\runas'
          Name        = '(Default)'
          Value       = 'Take Ownership'
          Description = 'Add take ownership to context menus'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\*\shell\runas'
          Name  = 'HasLUAShield'
          Value = ''
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\*\shell\runas'
          Name  = 'NoWorkingDirectory'
          Value = ''
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\*\shell\runas\command'
          Name  = '(Default)'
          Value = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F /c /l && pause'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\*\shell\runas\command'
          Name  = 'IsolatedCommand'
          Value = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F /c /l && pause'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Directory\shell\runas'
          Name  = '(Default)'
          Value = 'Take Ownership'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Directory\shell\runas'
          Name  = 'HasLUAShield'
          Value = ''
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Directory\shell\runas\command'
          Name  = 'NoWorkingDirectory'
          Value = ''
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Directory\shell\runas'
          Name  = '(Default)'
          Value = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t /c /l /q && pause'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Directory\shell\runas'
          Name  = 'IsolatedCommand'
          Value = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t /c /l /q && pause'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\dllfile\shell\runas'
          Name  = '(Default)'
          Value = 'Take Ownership'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\dllfile\shell\runas'
          Name  = 'HasLUAShield'
          Value = ''
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\dllfile\shell\runas'
          Name  = 'NoWorkingDirectory'
          Value = ''
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\dllfile\shell\runas\command'
          Name  = '(Default)'
          Value = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F /c /l && pause'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\dllfile\shell\runas\command'
          Name  = 'IsolatedCommand'
          Value = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F /c /l && pause'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Drive\shell\runas'
          Name  = '(Default)'
          Value = 'Take Ownership'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Drive\shell\runas'
          Name  = 'HasLUAShield'
          Value = ''
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Drive\shell\runas'
          Name  = 'NoWorkingDirectory'
          Value = ''
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Drive\shell\runas\command'
          Name  = '(Default)'
          Value = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t /c /l /q && pause'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\Drive\shell\runas\command'
          Name  = 'IsolatedCommand'
          Value = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t /c /l /q && pause'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\exefile\shell\runas'
          Name  = 'HasLUAShield'
          Value = ''
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\exefile\shell\runas\command'
          Name  = '(Default)'
          Value = '"%1" %*'
        }
        @{
          Key   = 'HKEY_CLASSES_ROOT\exefile\shell\runas\command'
          Name  = 'IsolatedCommand'
          Value = '"%1" %*'
        }
      )
  
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
          Name        = 'AllowTelemetry'
          Value       = 0
          Description = 'Disabling telemetry'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
          Name  = 'AllowTelemetry'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
          Name  = 'AllowTelemetry'
          Value = 0
        }
      )
			
      # Disable Wi-Fi Sense
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting'
          Name        = 'Value'
          Value       = 0
          Description = 'Disable Auto Connect To WiFiSense Hotspots'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots'
          Name        = 'Value'
          Value       = 0
          Description = 'Disable Auto Connect To WiFiSense Hotspots'
        }
      )

      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC'
          Name        = 'EnableMtcUvc'
          Value       = 0
          Description = 'Enable old volume slider'
        }
      )
  

      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          Name        = 'NoDriveTypeAutoRun'
          Value       = 255
          Description = 'Disable AutoRun'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'
          Name        = 'DisableAutoplay'
          Value       = 0
          Description = 'Disable Autoplay'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance'
          Name        = 'fAllowToGetHelp'
          Value       = 0
          Description = 'Disable Remote Assistance'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server'
          Name        = 'fDenyTSConnections'
          Value       = 0
          Description = 'Enable Remote Desktop'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
          Name        = 'UserAuthentication'
          Value       = 0
          Description = 'Disabling network level authentication requirement for remote desktop'
        }
      )

      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          Name        = 'EnableLUA'
          Value       = 1
          Description = 'Set Never Notify UAC settings'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          Name  = 'ConsentPromptBehaviorAdmin'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          Name  = 'ConsentPromptBehaviorUser'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          Name  = 'PromptOnSecureDesktop'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          Name  = 'FilterAdministratorToken'
          Value = 1
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI'
          Name  = '(Default)'
          Value = '0x00000001(1)'
        }
      )
  
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability'
          Name        = 'ShutdownReasonOn'
          Value       = 0
          Description = 'Disable Shutdown Tracker'
        }
      )
  
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power'
          Name        = 'HiberFileSizePercent'
          Value       = 0
          Description = 'Disable Hibernation'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power'
          Name  = 'HibernateEnabled'
          Value = 0
        }
      )

      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          Name        = 'VerboseStatus'
          Value       = 1
          Description = 'Enable verbose status messages when you sign in/out of Windows'
        }
      )
  
      If (Test-IsDesktop)
      {
        $registerKeys += @(
          @{
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583'
            Name        = 'Attributes'
            Value       = 0
            Description = 'Processor performance core parking min cores'
          }
          @{
            Key         = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583'
            Name        = 'ValueMax'
            Value       = 0
            Description = 'Disable CPU core parking desktops only'
          }
        )
      }
				
      $registerKeys += @(
        @{
          Key         = 'SOFTWARE\Policies\Microsoft\WindowsStore'
          Name        = 'AutoDownload'
          Value       = 2
          Description = 'Turn off Automatic download/install of app updates'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
          Name        = 'Enabled'
          Value       = 0
          Description = 'Disabling advertising info collection for this machine'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
          Name        = 'Disabled'
          Value       = 1
          Description = 'Disable Error reporting'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata'
          Name        = 'PreventDeviceMetadataFromNetwork'
          Value       = 1
          Description = 'Disabling device metadata collection for this machine'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass'
          Name        = 'UserAuthPolicy'
          Value       = 0
          Description = 'Prevent apps on other devices from opening apps on this one'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
          Name        = 'ARSOUserConsent'
          Value       = 2
          Description = 'Prevent using sign-in info to automatically finish setting up after an update'
        }
      )
					
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
          Name        = 'DODownloadMode'
          Value       = 0
          Description = 'Disable seeding of updates to other computers on LAN via Group Policies'
        }
      )
			
      # Disable offering of drivers through Windows Update
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching'
          Name        = 'SearchOrderConfig'
          Value       = 0
          Description = 'Disabling automatic driver update'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          Name        = 'ExcludeWUDriversInQualityUpdate'
          Value       = 1
          Description = 'Disabling automatic driver update'
        }
				
      )
				
      Takeown-Registry -key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet'
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet'
          Name        = 'SpyNetReporting'
          Value       = 0
          Description = 'Windows Defender Spynet'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet'
          Name        = 'SubmitSamplesConsent'
          Value       = 0
          Description = 'Windows Defender Sample Submission'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
          Name        = 'DODownloadMode'
          Value       = 1
          Description = 'Restrict Windows Update Peer to Peer only to local network'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization'
          Name        = 'SystemSettingsDownloadMode'
          Value       = 3
          Description = 'Restrict Windows Update Peer to Peer only to local network'
        }
      )
				
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features'
          Name        = 'WiFiSenseCredShared'
          Value       = 0
          Description = 'WifiSense Credential Share'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features'
          Name        = 'WiFiSenseOpen'
          Value       = 0
          Description = 'WifiSense Open-ness'
        }
      )
				
      # Local GP settings
				
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessAccountInfo'
          Value       = 2
          Description = 'App Privacy	Account Info'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessCalendar'
          Value       = 2
          Description = 'App Privacy	Calendar'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessCallHistory'
          Value       = 2
          Description = 'App Privacy	Call History'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessCamera'
          Value       = 2
          Description = 'App Privacy	Camera'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessContacts'
          Value       = 2
          Description = 'App Privacy	Contacts'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessEmail'
          Value       = 2
          Description = 'App Privacy	Email'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessLocation'
          Value       = 2
          Description = 'App Privacy	Location'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessMessaging'
          Value       = 2
          Description = 'App Privacy	Messaging'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessMicrophone'
          Value       = 2
          Description = 'App Privacy	Microphone'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessMotion'
          Value       = 2
          Description = 'App Privacy	Motion'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessNotifications'
          Value       = 2
          Description = 'App Privacy	Notifications'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessPhone'
          Value       = 2
          Description = 'App Privacy	Make Phone Calls'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessRadios'
          Value       = 2
          Description = 'App Privacy	Radios'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsAccessTrustedDevices'
          Value       = 2
          Description = 'App Privacy	Access trusted devices'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
          Name        = 'LetAppsSyncWithDevices'
          Value       = 2
          Description = 'App Privacy	Sync with devices'
        }
	
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
          Name        = 'AITEnable'
          Value       = 0
          Description = 'Application compatibility turn off Application Telemetry'
        }
	
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
          Name        = 'DisableInventory'
          Value       = 1
          Description = 'Application compatibility turn off inventory collector'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
          Name        = 'DisableUAR'
          Value       = 1
          Description = 'Application compatibility turn off steps recorder'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
          Name        = 'DisableSoftLanding'
          Value       = 1
          Description = 'Cloud Content do not show windows tips'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
          Name        = 'DisableWindowsConsumerFeatures'
          Value       = 1
          Description = 'Cloud Content turn off Consumer Experiences Prevents Suggested Applications returning'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'
          Name        = 'EnableConfigFlighting'
          Value       = 0
          Description = 'Data Collection disable pre-release features and settings'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
          Name        = 'DoNotShowFeedbackNotifications'
          Value       = 1
          Description = 'Data Collection Do not show feedback notifications'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
          Name        = 'DisableLocation'
          Value       = 1
          Description = 'Location and Sensors turn off location'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
          Name        = 'DisableSensors'
          Value       = 1
          Description = 'Location and Sensors Turn off Sensors'
        }

        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main'
          Name        = 'DoNotTrack'
          Value       = 1
          Description = 'Microsoft Edge Always send do not track'
        }
      )
					
					
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
          Name        = 'AllowCortana'
          Value       = 0
          Description = 'Search Disallow Cortana'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
          Name        = 'AllowCortanaAboveLock'
          Value       = 0
          Description = 'Search Disallow Cortana on lock screen'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
          Name        = 'DisableWebSearch'
          Value       = 1
          Description = 'Search Disallow web search from desktop search'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
          Name        = 'ConnectedSearchUseWeb'
          Value       = 0
          Description = 'Search Dont search the web or dispaly web results in search'
        }
      )
					
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
          Name        = 'EnableFeaturedSoftware'
          Value       = 0
          Description = 'Windows Update Turn off featured software notifications through WU (basically ads)'
        }
      )
					
			
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
          Name        = 'DisableSettingSync'
          Value       = 2
          Description = 'Sync your settings Do not sync (anything)'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
          Name        = 'DisableSettingSyncUserOverride'
          Value       = 1
          Description = 'Sync your settings Do not sync (anything)'
        }
      )
				
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
          Name        = 'CEIPEnable'
          Value       = 0
          Description = 'Disable Malicious Software Removal Tool through WU, and CEIP.  Left MRT enabled by default.'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack'
          Name  = 'Disabled'
          Value = 1
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack'
          Name  = 'DisableAutomaticTelemetryKeywordReporting'
          Value = 1
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack'
          Name  = 'TelemetryServiceDisabled'
          Value = 1
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TestHooks'
          Name  = 'DisableAsimovUpload'
          Value = 1
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\PerfTrack'
          Name  = 'Disabled'
          Value = 1
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener'
          Name  = 'Start'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener\{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}'
          Name  = 'Enabled'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener\{331C3B3A-2005-44C2-AC5E-77220C37D6B4}'
          Name  = 'Enabled'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener\{44345799-E748-4607-9ACF-35306808422C}'
          Name  = 'Enabled'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener\{96F4A050-7E31-453C-88BE-9634F4E02139}'
          Name  = 'Enabled'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener\{DBE9B383-7CF3-4331-91CC-A3CB16A3B538}'
          Name  = 'Enabled'
          Value = 0
        }
      )

			
      if(!($NoLockScreen.IsPresent)) 
      {
        $registerKeys += @(
          @{
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            Name        = 'LockScreenImage'
            Value       = "$env:systemroot\Web\Screen\img105.jpg"
            Description = 'Set LockScreen Image'
          }
          @{
            Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
            Name        = 'LockScreenOverlaysDisabled'
            Value       = 1
            Description = 'Disable Lockscreen advertisements'
          }
          @{
            Key   = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
            Name  = 'PersonalColors_Background'
            Value = '#000000'
          }
          @{
            Key   = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
            Name  = 'PersonalColors_Accent'
            Value = '#00bbff'
          }
          @{
            Key   = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
            Name  = 'DisableLockScreenAppNotifications'
            Value = 1
          }
        )
      }

      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag'
          Name        = 'ThisPCPolicy'
          Value       = 'Hide'
          Description = 'Remove Music, Pictures & Videos icon from explorer'
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag'
          Name        = 'ThisPCPolicy'
          Value       = 'Hide'
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag'
          Name        = 'ThisPCPolicy'
          Value       = 'Hide'
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag'
          Name        = 'ThisPCPolicy'
          Value       = 'Hide'
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag'
          Name        = 'ThisPCPolicy'
          Value       = 'Hide'
          Description = ''
        }
        @{
          Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag'
          Name        = 'ThisPCPolicy'
          Value       = 'Hide'
          Description = ''
        }
      )
			
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
          Name        = 'fDenyTSConnection'
          Value       = 0
          Description = 'Enable remote desktop'
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
          Name  = 'fNoRemoteDesktopWallpaper'
          Value = 1
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
          Name  = 'fAllowDesktopCompositionOnServer'
          Value = 0
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
          Name  = 'fNoFontSmoothing'
          Value = 1
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
          Name  = 'VisualExperiencePolicy'
          Value = 2
        }
        @{
          Key   = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
          Name  = 'MaxCompressionLevel'
          Value = 3
        }
      )
			

      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
          Name        = 'EnableSmartScreen'
          Value       = 0
          Description = 'Disable Smartscreen'
        }
      )
      $registerKeys += @(
        @{
          Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HomeGroup'
          Name        = 'DisableHomeGroup'
          Value       = 1
          Description = 'Disable Homegroup'
        }
      )
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Invoke-SetBackgroundLockScreen 
{
  [CmdletBinding()]
  param()
	
  Show-Progress -Message 'Applying lockscreen' -Source $CmdletName
  Copy-LockScreenImage
	
  Show-Progress -Message 'Applying background' -Source $CmdletName
  Copy-BackgroundImage
}

Function Set-PageFile 
{
  [cmdletbinding(SupportsShouldProcess,DefaultParameterSetName = 'SetPageFileSize')]
  Param
  (
    [Parameter(Mandatory,ParameterSetName = 'SetPageFileSize')]
    [Alias('is')]
    [int]$InitialSize,
 
    [Parameter(Mandatory,ParameterSetName = 'SetPageFileSize')]
    [Alias('ms')]
    [int]$MaximumSize,
 
    [Parameter(Mandatory)]
    [Alias('dl')]
    [ValidatePattern('^[A-Z]$')]
    [String[]]$DriveLetter,
 
    [Parameter(Mandatory,ParameterSetName = 'None')]
    [Switch]$None,
 
    [Parameter(Mandatory,ParameterSetName = 'SystemManagedSize')]
    [Switch]$SystemManagedSize,
 
    [Parameter()]
    [Switch]$Reboot,
 
    [Parameter(Mandatory,ParameterSetName = 'AutoConfigure')]
    [Alias('auto')]
    [Switch]$AutoConfigure
  )
  Begin {}
  Process {
    If($PSCmdlet.ShouldProcess('Setting the virtual memory page file size')) 
    {
      $DriveLetter | ForEach-Object -Process {
        $DL = $_
        $PageFile = $Vol = $null
        try 
        {
          $Vol = Get-CimInstance -ClassName CIM_StorageVolume -Filter "Name='$($DL):\\'" -ErrorAction Stop
        }
        catch 
        {
          Write-Warning -Message "Failed to find the DriveLetter $DL specified"
          return
        }
        if ($Vol.DriveType -ne 3) 
        {
          Write-Warning -Message 'The selected drive should be a fixed local volume'
          return
        }
        Switch ($PSCmdlet.ParameterSetName) {
          None 
          {
            try 
            {
              $PageFile = Get-CimInstance -Query "Select * From Win32_PageFileSetting Where Name='$($DL):\\pagefile.sys'" -ErrorAction Stop
            }
            catch 
            {
              Write-Warning -Message "Failed to query the Win32_PageFileSetting class because $($_.Exception.Message)"
            }
            If($PageFile) 
            {
              try 
              {
                $PageFile | Remove-CimInstance -ErrorAction Stop
              }
              catch 
              {
                Write-Warning -Message "Failed to delete pagefile the Win32_PageFileSetting class because $($_.Exception.Message)"
              }
            }
            Else 
            {
              Write-Warning -Message "$DL is already set None!"
            }
            break
          }
          SystemManagedSize 
          {
            Set-PageFileSize -DL $DL -InitialSize 0 -MaximumSize 0
            break
          }
          AutoConfigure 
          {         
            $TotalPhysicalMemorySize = @()
            #Getting total physical memory size
            try 
            {
              Get-CimInstance -ClassName Win32_PhysicalMemory  -ErrorAction Stop |
              Where-Object -Property DeviceLocator -NE -Value 'SYSTEM ROM' |
              ForEach-Object -Process {
                $TotalPhysicalMemorySize += [Double]($_.Capacity)/1GB
              }
            }
            catch 
            {
              Write-Warning -Message "Failed to query the Win32_PhysicalMemory class because $($_.Exception.Message)"
            }       
            $InitialSize = (Get-CimInstance -ClassName Win32_PageFileUsage).AllocatedBaseSize
            $sum = $null
            (Get-Counter -Counter '\Process(*)\Page File Bytes Peak' -SampleInterval 15 -ErrorAction SilentlyContinue).CounterSamples.CookedValue | ForEach-Object -Process {
              $sum += $_
            }
            $MaximumSize = ($sum*70/100)/1MB
            if ($Vol.FreeSpace -gt $MaximumSize) 
            {
              Set-PageFileSize -DL $DL -InitialSize $InitialSize -MaximumSize $MaximumSize
            }
            else 
            {
              Write-Warning -Message 'Maximum size of page file being set exceeds the freespace available on the drive'
            }
            break
          }
          Default 
          {
            if ($Vol.FreeSpace -gt $MaximumSize) 
            {
              Set-PageFileSize -DL $DL -InitialSize $InitialSize -MaximumSize $MaximumSize
            }
            else 
            {
              Write-Warning -Message 'Maximum size of page file being set exceeds the freespace available on the drive'
            }
          }
        }
      }
 
      # Get current page file size information
      try 
      {
        Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction Stop |
        Select-Object -Property Name, 
        @{
          Name       = 'InitialSize(MB)'
          Expression = {
            if($_.InitialSize -eq 0)
            {
              'System Managed'
            }
            else
            {
              $_.InitialSize
            }
          }
        }, 
        @{
          Name       = 'MaximumSize(MB)'
          Expression = {
            if($_.MaximumSize -eq 0)
            {
              'System Managed'
            }
            else
            {
              $_.MaximumSize
            }
          }
        }| 
        Format-Table -AutoSize
      }
      catch 
      {
        Write-Warning -Message "Failed to query Win32_PageFileSetting class because $($_.Exception.Message)"
      }
      If($Reboot) 
      {
        Restart-Computer -ComputerName $Env:COMPUTERNAME -Force
      }
    }
  }
  End {}
}
 
Function Set-PageFileSize 
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory)]
    [Alias('dl')]
    [ValidatePattern('^[A-Z]$')]
    [String]$DriveLetter,
 
    [Parameter(Mandatory)]
    [ValidateRange(0,[int]::MaxValue)]
    [int]$InitialSize,
 
    [Parameter(Mandatory)]
    [ValidateRange(0,[int]::MaxValue)]
    [int]$MaximumSize
  )
  Begin {}
  Process {
    try 
    {
      $Sys = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    }
    catch 
    {

    }
 
    If($Sys.AutomaticManagedPagefile) 
    {
      try 
      {
        $Sys | Set-CimInstance -Property @{
          AutomaticManagedPageFile = $false
        } -ErrorAction Stop
        Write-Verbose -Message 'Set the AutomaticManagedPageFile to false'
      }
      catch 
      {
        Write-Warning -Message "Failed to set the AutomaticManagedPageFile property to false in  Win32_ComputerSystem class because $($_.Exception.Message)"
      }
    }
     
    # Configuring the page file size
    try 
    {
      $PageFile = Get-CimInstance -ClassName Win32_PageFileSetting -Filter "SettingID='pagefile.sys @ $($DriveLetter):'" -ErrorAction Stop
    }
    catch 
    {
      Write-Warning -Message "Failed to query Win32_PageFileSetting class because $($_.Exception.Message)"
    }
 
    If($PageFile)
    {
      try 
      {
        $PageFile | Remove-CimInstance -ErrorAction Stop
      }
      catch 
      {
        Write-Warning -Message "Failed to delete pagefile the Win32_PageFileSetting class because $($_.Exception.Message)"
      }
    }
    try 
    {
      New-CimInstance -ClassName Win32_PageFileSetting -Property  @{
        Name = "$($DriveLetter):\pagefile.sys"
      } -ErrorAction Stop | Out-Null
      
      # http://msdn.microsoft.com/en-us/library/windows/desktop/aa394245%28v=vs.85%29.aspx            
      Get-CimInstance -ClassName Win32_PageFileSetting -Filter "SettingID='pagefile.sys @ $($DriveLetter):'" -ErrorAction Stop | Set-CimInstance -Property @{
        InitialSize = $InitialSize
        MaximumSize = $MaximumSize
      } -ErrorAction Stop
         
      Write-Verbose -Message "Successfully configured the pagefile on drive letter $DriveLetter"
    }
    catch 
    {
      Write-Warning -Message "Pagefile configuration changed on computer '$Env:COMPUTERNAME'. The computer must be restarted for the changes to take effect."
    }
  }
  End {}
}



Function Disable-OptionalWindowsFeatures 
{
  [CmdletBinding()]
  param()
	
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process {
    Show-Progress -Message 'Uninstalling Windows Media Player...' -Source $CmdletName
    Disable-WindowsOptionalFeature -Online -FeatureName 'WindowsMediaPlayer' -NoRestart -WarningAction SilentlyContinue | Out-Null
		
    Show-Progress -Message 'Uninstalling Work Folders Client...' -Source $CmdletName
    Disable-WindowsOptionalFeature -Online -FeatureName 'WorkFolders-Client' -NoRestart -WarningAction SilentlyContinue | Out-Null
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}


Function Enable-F8BootMenu 
{
  # Enable F8 boot menu options
  & "$env:windir\system32\bcdedit.exe" /set `{current`} bootmenupolicy Legacy | Out-Null
}

Function Set-DEPOptOut 
{
  # Set Data Execution Prevention (DEP) policy to OptOut
  & "$env:windir\system32\bcdedit.exe" /set `{current`} nx OptOut | Out-Null
}



Function Disable-SMBv1
  {
    Try 
    {
      [string]$OperatingSystemVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
      switch -Regex ($OperatingSystemVersion) {
        '(^10\.0.*|^6\.3.*)'
        {
          # Windows 8.1 / Server 2012 R2 / Windows 10 / Server 2016
          # SMB1 Server Settings
          if ((Get-SmbServerConfiguration).EnableSMB1Protocol) 
          {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
          }
          # SMB1 Client Settings
          if (((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State) -match 'Enable(d|Pending)') 
          {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
          }
        }
        '^6\.2.*'
        {
          # Windows 8 / Server 2012
          # SMB1 Server Settings
          if ((Get-SmbServerConfiguration).EnableSMB1Protocol) 
          {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
          }
          # SMB1 Client Settings
          if ((& "$env:windir\system32\sc.exe" qc lanmanworkstation) -match 'MRxSmb10') 
          {
            Start-Process -FilePath "$env:windir\System32\sc.exe" -ArgumentList 'config lanmanworkstation depend= bowser/mrxsmb20/nsi' -WindowStyle Hidden
            Start-Process -FilePath "$env:windir\System32\sc.exe" -ArgumentList 'config mrxsmb10 start= disabled' -WindowStyle Hidden
          }
        }
        '^6\.(0|1).*'
        {
          # Windows Vista / Server 2008 / Windows 7 / Server 2008R2
          # SMB1 Server Settings
          if (((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'-Name SMB1 -ErrorAction SilentlyContinue).SMB1) -ne '0') 
          {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue
          }
          # SMB1 Client Settings
          if ((& "$env:windir\system32\sc.exe" qc lanmanworkstation) -match 'MRxSmb10') 
          {
            Start-Process -FilePath "$env:windir\System32\sc.exe" -ArgumentList 'config lanmanworkstation depend= bowser/mrxsmb20/nsi' -WindowStyle Hidden
            Start-Process -FilePath "$env:windir\System32\sc.exe" -ArgumentList 'config mrxsmb10 start= disabled' -WindowStyle Hidden
          }
        }
        default
        {
          Throw 'Unsupported Operating System'
        }
      }
    }
    Catch 
    {
      $LastError = $Error | Select-Object -First 1 -ExpandProperty Exception | Select-Object -ExpandProperty Message
        Write-Warning -Message $LastError
    }
  }


Function Disable-AutoLogger 
{
  # Remove AutoLogger file and restrict directory
  $autoLoggerDir = "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger"
  If (Test-Path -Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") 
  {
    Remove-Item -Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
  }
  & "$env:windir\system32\icacls.exe" $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
}

Function Invoke-Setup
{
  [CmdletBinding()]
  param()

		
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process {

    #------------------------------------------------------
    #  User specific functions for run once
    #------------------------------------------------------
    if($CurrentUser.IsPresent) 
    {
      Show-Progress -Message 'Disable windows theme sounds' -Source $CmdletName
      Invoke-DisableWindowsThemeSounds
			
      Show-Progress -Message 'Setting IE default search provider' -Source $CmdletName
      Invoke-SetIEDefaultSearchProvider
			
      Show-Progress -Message 'Disabling desktop web search results' -Source $CmdletName
      Invoke-SetWindowsSearchWebResults
			
      Show-Progress -Message 'Disabling updating group policies' -Source $CmdletName
      Invoke-UpdateGroupPolicy
			
      Show-Progress -Message 'Disabling unneeded background services' -Source $CmdletName
      Invoke-DisableBackgroundServices
			
      #Show-Progress -Message 'Applying start menu settings' -Source $CmdletName
      #Invoke-SetupStartmenuCurrentUser
			
      #Show-Progress -Message 'Applying taskbar settings' -Source $CmdletName
      #Invoke-SetupTaskBarItemsCurrentUser
			
      Show-Progress -Message 'Applying user registry settings' -Source $CmdletName
      Invoke-ApplyRegistrySettingsCurrentUser
    }
		
    if(-Not ($CurrentUser.IsPresent))
    {
      #------------------------------------------------------
      #  Computer settings functions (Requires Admin Rights)
      #------------------------------------------------------
      Show-Progress -Message 'Applying power settings' -Source $CmdletName
      Invoke-SetPowerPlan
    
      Show-Progress -Message 'Set admin shortcuts to always run as administrator' -Source $CmdletName
      Invoke-SetupShortcutsAsAdmin

      Show-Progress -Message 'Stopping and disable unneeded services' -Source $CmdletName
      Invoke-DisableServices

      Show-Progress -Message 'Removing unneeded Windows apps' -Source $CmdletName
      Invoke-RemoveBuiltinApps
    
      Show-Progress -Message 'Removing built in printers' -Source $CmdletName
      Invoke-RemoveBuiltInPrinters

      #Show-Progress -Message 'Setting up background and lockscreen' -Source $CmdletName
      #Invoke-SetBackgroundLockScreen
   
      #Show-Progress -Message 'Applying start menu' -Source $CmdletName
      #Invoke-SetupStartmenuDefaultUsers

      #Show-Progress -Message 'Applying taskbar layout' -Source $CmdletName
      #Invoke-SetupTaskBarItemsDefaultUsers
    
      Show-Progress -Message 'Adding RunOnceEx for all users' -Source $CmdletName
      Invoke-SetupRunOnce

      Show-Progress -Message 'Updating group policies' -Source $CmdletName
      Invoke-UpdateGroupPolicy

      #TODO: Replace this with built-in function and zip package
      Invoke-WebRequest -Uri https://chocolatey.org/install.ps1 -UseBasicParsing | Invoke-Expression

      #Show-Progress -Message 'Getting site location details for package management' -Source $CmdletName
      #. "$PSScriptRoot\Set-ServerAddress.ps1"

      Show-Progress -Message 'Setting chocolatey source' -Source $CmdletName
      Invoke-SetChocolateySource -Source Internet

      Show-Progress -Message 'Installing software' -Source $CmdletName
      Invoke-InstallSoftware

      Show-Progress -Message 'Disabling un-needed scheduled tasks' -Source $CmdletName 
      Invoke-DisableScheduledTasks

      Show-Progress -Message 'Adding powershell to right click context menu' -Source $CmdletName
      Add-PowerShellContextMenu -contextType editWithPowerShellISE -platform x64 -asAdmin -noProfile
      Add-PowerShellContextMenu -contextType openPowerShellHere -platform x64 -asAdmin -noProfile
				
      Show-Progress -Message 'Adding Windows Features' -Source $CmdletName
      Invoke-AddWindowsFeatures
				
      #Show-Progress -Message 'Setting Windows File Associations' -Source $CmdletName
      #Invoke-SetupFileAssociations
			
      Show-Progress -Message 'Applying system registry settings' -Source $CmdletName
      Invoke-ApplyRegistrySettingsLocalMachine
			
      Show-Progress -Message 'Applying page file settings' -Source $CmdletName
      Set-PageFile -AutoConfigure -DriveLetter $($env:SystemDrive.Replace(':',''))
			
      Show-Progress -Message 'Setting Data Execution Prevention (DEP) policy to OptOut...' -Source $CmdletName
      Set-DEPOptOut
			
      Show-Progress -Message 'Enabling F8 boot menu options' -Source $CmdletName
      Enable-F8BootMenu
			
      Show-Progress -Message 'Removing AutoLogger file and restricting directory...' -Source $CmdletName
      Disable-AutoLogger
			
      Show-Progress -Message 'Disabling insecure SMB 1.0 protocol' -Source $CmdletName
      Disable-SMB1
    }
	
    Show-Progress -Message 'Set language settings'
    Invoke-SetLanguage
    Invoke-SetHomeLocation
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}
Function Invoke-SetChocolateySource
{
  [CmdletBinding()]
  Param(
    [ValidateSet('Local', 'Internet')]
    [Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true)]
    [string]$Source
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process 
  {
    if(Test-IsAdmin) 
    {
      $ChocolateyInstallLocation = "$env:AllUsersProfile\chocolatey\" 
      $ChocoExe = (Join-Path -Path $ChocolateyInstallLocation -ChildPath 'bin\choco.exe')
	
      Show-Progress -Message 'Running chocolatey to create initial config file' -Source $CmdletName
      Try
      {
        if(Test-Path -Path "$ChocoExe")
        {
          Start-Process -FilePath $ChocoExe -ArgumentList 'feature', 'enable', '-n', 'allowEmptyChecksums' -Wait -WindowStyle Hidden
          Start-Process -FilePath $ChocoExe -ArgumentList 'feature', 'enable', '-n', 'allowGlobalConfirmation' -Wait -WindowStyle Hidden
        }
      }
      Catch
      {
        Write-Log -EntryType Warning -Message "Unable to run choco.exe `n$(Resolve-Error)" -Source $CmdletName
        return
      }
		
      Show-Progress -Message 'Getting chocolatey config file' -Source $CmdletName
      Try 
      {
        $ChocolateyConfig = (Join-Path -Path "$ChocolateyInstallLocation" -ChildPath 'config\chocolatey.config')
      }
      catch 
      {
        Write-Log -EntryType Error -Message "Unable to load config file $ChocolateyConfig `n$(Resolve-Error)" -Source $CmdletName
        return
      }
		
      Show-Progress -Message 'Setting Chocolatey Source' -Source $CmdletName
		
      if(Test-Path -Path $ChocolateyConfig)
      {
        [xml]$ChocolateXmlDocument = New-Object -TypeName System.Xml.XmlDocument
        
        try 
        {
          $ChocolateXmlDocument.Load($ChocolateyConfig)
        } 
        catch 
        {
          Write-Log -EntryType Warning -Message "Unable to load config file $ChocolateyConfig `n$(Resolve-Error)" -Source $CmdletName
        }
			
        Switch ($Source) 
        { 
          'Local' 
          {
            Show-Progress -Message 'Setting Local Source'
            $ChocolateXmlDocument.chocolatey.sources.source.value = "$env:NuGetServer/nuget"
            $ChocolateXmlDocument.chocolatey.sources.source.id = 'custom'
          }
          'Internet' 
          {
            Show-Progress -Message 'Setting Internet Source'
            $ChocolateXmlDocument.chocolatey.sources.source.value = 'https://chocolatey.org/api/v2/'
            $ChocolateXmlDocument.chocolatey.sources.source.id = 'chocolatey'
          }
          default 
          {
            Show-Progress -Message 'Setting Local Source'
            $ChocolateXmlDocument.chocolatey.sources.source.value = 'https://chocolatey.org/api/v2/'
            $ChocolateXmlDocument.chocolatey.sources.source.id = 'chocolatey'
          }
        }

        Show-Progress -Message "Saving config file: $ChocolateyConfig" -Source $CmdletName
        try 
        {
          $ChocolateXmlDocument.Save("$ChocolateyConfig")
        }
        catch 
        {
          Write-Log -EntryType Warning -Message "Unable to save config file $ChocolateyConfig" -Source $CmdletName
        }
      }
      else 
      {
        Write-Log -EntryType Warning -Message 'Chocolatey has not been initialized run choco.exe atleast once to generate config file'
      }
    }
    else 
    {
      Write-Log -EntryType Warning  -Message "User is not administrator skipping [$CmdletName]"
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

do 
{

}
until (Invoke-ElevatePrivileges -Privilege SeTakeOwnershipPrivilege)

[string]$Script:ScriptName = $PSCmdlet.MyInvocation.MyCommand.Name
[string]$Script:ComputerName = $Env:COMPUTERNAME
[string]$Script:OSLanguage = (Get-Culture).Name
[string]$Script:ProcessorArch = $env:PROCESSOR_ARCHITECTURE
[string]$Script:ScriptVersion = '0.0.3'
[int]$Script:CurrentStep = 0

Initialize-Logging

Write-Log -EntryType Information -Message "ScriptVersion: $ScriptVersion" -Source $ScriptName
Write-Log -EntryType Information -Message "ScriptDir: $PSScriptRoot" -Source $ScriptName
Write-Log -EntryType Information -Message "ScriptName: $ScriptName" -Source $ScriptName
Write-Log -EntryType Information -Message "OS Architecture: $ProcessorArch" -Source $ScriptName
Write-Log -EntryType Information -Message "Current Culture: $OSLanguage" -Source $ScriptName
Write-Log -EntryType Information -Message "Computer Name: $ComputerName" -Source $ScriptName

if($(Get-OSVersion) -eq 'Windows 10')
{
  Show-Progress -Message 'Begining Setup - Applying Custom Settings for Windows 10'
  Show-BalloonTip -Title 'Begining Setup' -MessageType Info -Message 'Applying Custom Settings for Windows 10' -Duration 5000
	
  Invoke-Setup

  Show-Progress -Message 'Completed Setup - Rebooting in 60 seconds'
  Show-BalloonTip -Title 'Completed Setup' -MessageType Info -Message 'Rebooting in 60 seconds' -Duration 5000
	
  #shutdown /t 60
}
else 
{
  Write-Log -EntryType Warning -Message 'Unsupported operating system exiting setup...'
  Show-BalloonTip -Title 'Unsupported Operating System' -MessageType Info -Message 'Exiting setup...' -Duration 5000
}

Complete-Logging 
