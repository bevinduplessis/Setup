[CmdletBinding()]
Param (
  [Parameter(Mandatory = $false)]
  [ValidateSet('Install','Uninstall')]
  [string]$DeploymentType = 'Install',
  [Parameter(Mandatory = $false)]
  [ValidateSet('Interactive','Silent','NonInteractive')]
  [string]$DeployMode = 'Interactive',
  [Parameter(Mandatory = $false)]
  [switch]$AllowRebootPassThru = $false,
  [Parameter(Mandatory = $false)]
  [switch]$TerminalServerMode = $false,
  [Parameter(Mandatory = $false)]
  [switch]$DisableLogging = $false
)

Try 
{
  ## Set the script execution policy for this process
  Try 
  {
    Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop'
  }
  Catch 
  {

  }
	
  ##*===============================================
  ##* VARIABLE DECLARATION
  ##*===============================================
  ## Variables: Application
  [string]$appVendor = 'Setup'
  [string]$appName = 'Utility'
  [string]$appVersion = '1.0.0'
  [string]$appArch = 'x64'
  [string]$appLang = 'EN'
  [string]$appRevision = '01'
  [string]$appScriptVersion = '1.0.0'
  [string]$appScriptDate = '07/03/2019'
  [string]$appScriptAuthor = 'Bevin Du Plessis'
  ##*===============================================
  ## Variables: Install Titles (Only set here to override defaults set by the toolkit)
  [string]$installName = ''
  [string]$installTitle = ''
	
  ##* Do not modify section below
  #region DoNotModify
	
  ## Variables: Exit Code
  [int32]$mainExitCode = 0
	
  ## Variables: Script
  [string]$deployAppScriptFriendlyName = 'Deploy Application'
  [version]$deployAppScriptVersion = [version]'3.7.0'
  [string]$deployAppScriptDate = '02/13/2018'
  [hashtable]$deployAppScriptParameters = $psBoundParameters
	
  ## Variables: Environment
  If (Test-Path -LiteralPath 'variable:HostInvocation') 
  {
    $InvocationInfo = $HostInvocation
  }
  Else 
  {
    $InvocationInfo = $MyInvocation
  }
  [string]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent
	
  ## Dot source the required App Deploy Toolkit Functions
  Try 
  {
    [string]$moduleAppDeployToolkitMain = "$scriptDirectory\AppDeployToolkit\AppDeployToolkitMain.ps1"
    If (-not (Test-Path -LiteralPath $moduleAppDeployToolkitMain -PathType 'Leaf')) 
    {
      Throw "Module does not exist at the specified location [$moduleAppDeployToolkitMain]."
    }
    If ($DisableLogging) 
    {
      . $moduleAppDeployToolkitMain -DisableLogging
    }
    Else 
    {
      . $moduleAppDeployToolkitMain
    }
  }
  Catch 
  {
    If ($mainExitCode -eq 0)
    {
      [int32]$mainExitCode = 60008
    }
    Write-Error -Message "Module [$moduleAppDeployToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
    ## Exit the script, returning the exit code to SCCM
    If (Test-Path -LiteralPath 'variable:HostInvocation') 
    {
      $script:ExitCode = $mainExitCode
      Exit
    }
    Else 
    {
      Exit $mainExitCode
    }
  }
	
  #endregion
  ##* Do not modify section above
  ##*===============================================
  ##* END VARIABLE DECLARATION
  ##*===============================================
		
  If ($DeploymentType -ine 'Uninstall') 
  {
    ##*===============================================
    ##* PRE-INSTALLATION
    ##*===============================================
    [string]$installPhase = 'Pre-Installation'

    
    do 
    {

    }
    until (Invoke-ElevatePrivileges -Privilege SeTakeOwnershipPrivilege)
    
    
    Show-InstallationWelcome -Silent
   
   #region InstallSoftware
    ##*===============================================
    ##*  
    ##* Install Software
    ##*
    ##*===============================================

    <#
        Show-InstallationProgress -StatusMessage 'Installing Chocolatey Packages'
        Install-ChocolateyPackage -Package @(
        'vcredist-all'
        'winscp'
        'ussf'
        'ffmpeg'
        'sudo'
        'googlechrome'
        'directx'
        '7zip.install'
        'ccleaner'
        'chocolatey-core.extension'
        'chocolatey-uninstall.extension'
        'chocolatey-visualstudio.extension'
        'chocolatey-windowsupdate.extension'
        'cpu-z.install'
        'discord'
        'ffmpeg'
        #'geforce-game-ready-driver-win10'
        'git.install'
        'gpu-z'
        'grepwin'
        'irfanviewplugins'
        'irfanview'
        'k-litecodecpackfull'
        #'kodi'
        'nircmd'
        'notepadplusplus.install'
        #'Office365ProPlus'
        #'PSWindowsUpdate'
        'putty.install'
        'pycharm-community'
        'python2'
        #'qbittorrent'
        #'ipfilter-updater'
        #'rsat'
        #'Shotcut'
        #'sysinternals'
        #'WhatsApp'
        #'youtube-dl'
        )

    #>

    
    Install-CCEnhancer

    Install-ISLC
    
    Invoke-InstallCMTrace
#endregion
    
#region QualityofLifeTweaks
    ##*===============================================
    ##*  
    ##* Quality of Life Tweaks and Settings
    ##*
    ##*===============================================
    
    [string]$installPhase = 'Installation'

    Set-PowershellRunAsAdminContextMenu

    Disable-WindowsThemeSounds

    Clean-DesktopIcons
        
    Set-TerminalShortcutsAsAdmin
    
    Unpin-App  -Name 'Microsoft Edge'
    Unpin-App  -Name 'Mail' 
    Unpin-App  -Name 'Microsoft Store'

    #Set-PinnedApplication -Action 'PintoStartMenu' -FilePath "$envProgramFilesX86\IBM\Lotus\Notes\notes.exe"


    $NetworkConnection = @{
      Name             = 'Network Connections.lnk'
      TargetPath       = 'explorer.exe'
      Arguments        = '::{7007ACC7-3202-11D1-AAD2-00805FC1270E}'
      IconLocation     = 'shell32.dll, 88'
      Description      = 'Network Connections'
      WorkingDirectory = $null
      Destination      = Join-Path -Path  $env:USERPROFILE -ChildPath 'Desktop'
    }

    New-Shortcut @NetworkConnection

    
    $ControlPanel = @{
      Name             = 'Control Panel.lnk'
      TargetPath       = 'RunDll32.exe '
      Arguments        = 'shell32.dll,Control_RunDLL'
      IconLocation     = 'shell32.dll, 207'
      Description      = 'Control Panel'
      WorkingDirectory = $null
      Destination      = Join-Path -Path  $env:USERPROFILE -ChildPath 'Desktop'
    }
    New-Shortcut @ControlPanel
    
    
    Invoke-AddWindowsFeatures -feature @(
      'NetFx3'
    )

    # Disable other windows annoyances
    $registerKeys += @(
      @{
        Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
        Name        = 'SaveZoneInformation'
        Value       = 1
        Description = 'Disable saving zone information to files eg: Unblock file in file properties'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Associations'
        Name        = 'LowRiskFileTypes '
        Value       = '.zip;.rar;.nfo;.txt;.exe;.bat;.vbs;.com;.cmd;.reg;.msi;.htm;.html;.gif;.bmp;.jpg;.avi;.mpg;.mpeg;.mov;.mp3;.m3u;.wav;'
        Description = 'Disable this publisher could not be verified message when running an executable'
      }
     
      @{
        Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
        Name        = 'WindowArrangementActive'
        Value       = 0
        Description = 'Disable windows snapping to the edge of the screen (Multi-monitor)'
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
        Key         = 'HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys'
        Name        = 'Flags'
        Value       = '58'
        Description = 'Disable toggle keys'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop\Keyboard'
        Name        = 'KeyboardDelay'
        Value       = 0
        Description = 'Set keyboard repeat delay'
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
      @{
        Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags\1\Desktop'
        Name        = 'IconSize'
        Value       = 16
        Description = 'Set small desktop icon size'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags\1\Desktop'
        Name        = 'FFLAGS'
        Value       = 1075839524 
        Description = 'Auto arrange desktop icons'
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
        Value       = 0
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
        Description = 'Disabling Ads in File Explorer'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        Name        = 'SubscribedContent-310093Enabled'
        Value       = 0
        Description = 'Disabling showing the Windows welcome experience after updates and occasionally after logging in'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        Name        = 'SubscribedContent-338389Enabled'
        Value       = 0
        Description = 'Get tips, tricks, suggestions as you use Windows'
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
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'SubscribedContent-314559Enabled'
        Value       = 0
        Description = 'Disable show suggestions occasionally'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'SubscribedContent-338387Enabled'
        Value       = 0
        Description = 'Disable show suggestions occasionally'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'SubscribedContent-338388Enabled'
        Value       = 0
        Description = 'Disable show suggestions occasionally'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'SubscribedContent-353698Enabled'
        Value       = 0
        Description = 'Disable show suggestions in timeline'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'SubscribedContent-338393Enabled'
        Value       = 0
        Description = 'Disable show suggested content in settings app'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'SubscribedContent-353694Enabled'
        Value       = 0
        Description = 'Disable show suggested content in settings'
      }
    )
				
    # Lockscreen suggestions, rotating pictures and pre-installed apps
    $registerKeys += @(
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'SoftLandingEnabled'
        Value       = 0
        Description = 'Disable Lockscreen suggestions'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'RotatingLockScreenEnabled'
        Value       = 0
        Description = 'Disable Lockscreen rotating pictures'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'RotatingLockScreenOverlayEnabled'
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
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'FeatureManagementEnabled'
        Value       = 0
        Description = 'Disable preinstalled apps, Minecraft and Twitter etc'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name        = 'PreInstalledAppsEverEnabled'
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
      @{
        Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name  = 'SubscribedContentEnabled'
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

    # Dark Theme
    $registerKeys += @(
      @{
        Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
        Name        = 'AppsUseLightTheme'
        Value       = 0
        Description = 'Enable Dark Theme for XAML apps'
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

      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel'
        Name        = 'StartupPage'
        Value       = 1
        Description = 'Show all tray icons'
      }

      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel'
        Name        = 'AllItemsIconView'
        Value       = 1
        Description = 'Show all tray icons'
      }

    )
    
    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Name        = 'NoUseStoreOpenWith'
        Value       = 1
        Description = 'Enabling Classic Control Panel Icons.'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Name        = 'NoNewAppAlert'
        Value       = 1
        Description = 'Enabling Classic Control Panel Icons.'
      }
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

#endregion


#region PrivacySecurity

    ##*===============================================
    ##*
    ##* Privacy & Security
    ##*
    ##*===============================================
    Disable-SMBv1
        
    Disable-SharingWifiNetworks
       
    Set-WindowsSearchWebResults
        
    Add-PhotoViewerOpenWith
    
    Set-Hide3DObjectsFromThisPC
        
    Set-Hide3DObjectsFromExplorer

    $Edge = (Get-AppxPackage -AllUsers -Name 'Microsoft.MicrosoftEdge') | Select-Object -Property PackageFamilyName -ExpandProperty PackageFamilyName -First 1

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

    					
    $registerKeys += @(
      @{
        Key         = 'HKEY_CURRENT_USER\Control Panel\International\User Profile'
        Name        = 'HttpAcceptLanguageOptOut'
        Value       = 1
        Description = 'Disable websites providing local content by accessing language list'
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
  
    # Privacy Settings
    $registerKeys += @(
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy'
        Name        = 'TailoredExperiencesWithDiagnosticDataEnabled'
        Value       = 0
        Description = 'Disable windows feedback submission'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP'
        Name        = 'RomeSdkChannelUserAuthzPolicy'
        Value       = 0
        Description = 'Let apps on other devices open messages and apps on this device - Shared Experiences settings'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP'
        Name        = 'CdpSessionUserAuthzPolicy'
        Value       = 0
        Description = 'Let apps on other devices open messages and apps on this device - Shared Experiences settings'
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
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
        Name        = 'CanCortanaBeEnabled'
        Value       = 0
        Description = 'Disabling Cortana and Bing search user settings'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
        Name        = 'DeviceHistoryEnabled'
        Value       = 0
        Description = 'Disabling Cortana and Bing search user settings'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
        Name        = 'CortanaConsent'
        Value       = 0
        Description = 'Disabling Cortana and Bing search user settings'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
        Name        = 'CortanaInAmbientMode'
        Value       = 0
        Description = 'Disabling Cortana and Bing search user settings'
      }
      @{
        Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
        Name  = 'SearchboxTaskbarMode'
        Value = 0
      }
      @{
        Key   = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Speech_OneCore\Preferences'
        Name  = 'VoiceActivationEnableAboveLockscreen'
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
        Key         = "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$Edge\MicrosoftEdge\Main"
        Name        = 'DoNotTrack' 
        Value       = 1
        Description = 'Microsoft Edge settings'
      }
      @{
        Key   = "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$Edge\MicrosoftEdge\User\Default\SearchScopes"
        Name  = 'ShowSearchSuggestionsGlobal'
        Value = 0
      }
      @{
        Key   = "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$Edge\MicrosoftEdge\FlipAhead"
        Name  = 'FPEnabled'
        Value = 0
      }
      @{
        Key   = "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$Edge\MicrosoftEdge\PhishingFilter"
        Name  = 'EnabledV9'
        Value = 0
      }
    )

    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
        Name        = 'Status'
        Value       = 0
        Description = 'Disable location tracking'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
        Name        = 'SensorPermissionState'
        Value       = 0
        Description = 'Disable location tracking'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
        Name        = 'Value'
        Value       = 0
        Description = 'Disable location tracking'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}'
        Name        = 'Value'
        Value       = 0
        Description = 'Disable location tracking'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        Name        = 'Value'
        Value       = 'Deny'
        Description = 'Disable location tracking'
      }
    )

    
    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
        Name        = 'NoTileApplicationNotification'
        Value       = 0
        Description = 'Disabling live tile push notification'
      }
    )

    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
        Name        = 'AllowTelemetry'
        Value       = 0
        Description = 'Disable telemetry'
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
        
    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore'
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
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
        Name        = 'DisabledByGroupPolicy'
        Value       = 1
        Description = 'Disabling advertising info collection for this machine'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
        Name        = 'Disabled'
        Value       = 1
        Description = 'Disable windows error reporting'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
        Name        = 'Disabled'
        Value       = 1
        Description = 'Disable windows error reporting'
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
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey'
        Name        = 'EnableEventTranscript'
        Value       = 1
        Description = 'Enable diagnostic data viewer'
      }
    )
    
    # Disable Wi-Fi Sense	
    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features'
        Name        = 'WiFiSenseCredShared'
        Value       = 0
        Description = 'Disable WifiSense Credential Share'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features'
        Name        = 'WiFiSenseOpen'
        Value       = 0
        Description = 'Disable WifiSense Open-ness'
      }
    )

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
				
    # Local GP settings
    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessAccountInfo'
        Value       = 2
        Description = 'App Privacy Account Info'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessCalendar'
        Value       = 2
        Description = 'App Privacy Calendar'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessCallHistory'
        Value       = 2
        Description = 'App Privacy Call History'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessCamera'
        Value       = 2
        Description = 'App Privacy Camera'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessContacts'
        Value       = 2
        Description = 'App Privacy Contacts'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessEmail'
        Value       = 2
        Description = 'App Privacy Email'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessLocation'
        Value       = 2
        Description = 'App Privacy Location'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessMessaging'
        Value       = 2
        Description = 'App Privacy Messaging'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessMotion'
        Value       = 2
        Description = 'App Privacy Motion'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessNotifications'
        Value       = 2
        Description = 'App Privacy Notifications'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessPhone'
        Value       = 2
        Description = 'App Privacy Make Phone Calls'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessRadios'
        Value       = 2
        Description = 'App Privacy Radios'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name        = 'LetAppsAccessTrustedDevices'
        Value       = 2
        Description = 'App Privacy Access trusted devices'
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
        Name        = 'DisableTailoredExperiencesWithDiagnosticData'
        Value       = 1
        Description = 'Disable Tailored Experiences With Diagnostic Data'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name        = 'DisableSoftLanding'
        Value       = 1
        Description = 'Cloud Content do not show windows tips'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name        = 'DisableWindowsSpotlightFeatures'
        Value       = 1
        Description = 'Disable Windows Spotlight Features'
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
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Name        = 'ShowRunasDifferentuserinStart'
        Value       = 1
        Description = 'Add Run as different user to context menu'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Name        = 'DisableNotificationCenter'
        Value       = 1
        Description = 'Disable Notification Center'
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
        Description = 'Disable Cortana'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
        Name        = '{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}'
        Value       = 'BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|'
        Description = 'Disable Cortana'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name        = 'AllowCortanaAboveLock'
        Value       = 0
        Description = 'Disable Cortana on lock screen'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name        = 'DisableWebSearch'
        Value       = 1
        Description = 'Disable web search from desktop search'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name        = 'ConnectedSearchUseWeb'
        Value       = 0
        Description = 'Disable search the web or display web results in windows search'
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
        Description = 'Disable Malicious Software Removal Tool through WU, and CEIP. Left MRT enabled by default.'
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

#endregion


#region PerformanceOptimization
    ##*===============================================
    #
    # Performance and Optimization
    #
    ##*===============================================

    
    Set-WindowsPowerPlan -HighPerformance

   
    Disable-GameDVRXboxServices
    
    
    Disable-ApplicationsRunningInBackground


    Disable-8dot3FileNames


    Set-DEPOptOut

   
    Disable-WindowsDefender 

    
    Uninstall-OneDrive

    
    Remove-BuiltInPrinters
   
    Set-HomeLocation



#region  DisableWindowsServices

    <#
    Disable-WindowsService -Service @(
      'diagnosticshub.standardcollector.service' # Microsoft Diagnostics Hub Standard Collector Service
      'DiagTrack'                                # Diagnostics Tracking Service
      'dmwappushservice'                         # WAP Push Message Routing Service
      'HomeGroupListener'                        # HomeGroup Listener
      'HomeGroupProvider'                        # HomeGroup Provider
      'lfsvc'                                    # Geolocation Service
      'MapsBroker'                               # Downloaded Maps Manager
      'NetTcpPortSharing'                        # Net.Tcp Port Sharing Service
      'SharedAccess'                             # Internet Connection Sharing (ICS)
      'WbioSrvc'                                 # Windows Biometric Service
      'WMPNetworkSvc'                            # Windows Media Player Network Sharing Service
      'TrkWks'                                   # Distributed Link Tracking Client. Description: Maintains links between NTFS files within a computer or across computers in a network.
      'AdobeFlashPlayerUpdateSvc'                # Adobe flash player updater
      'RemoteAccess'                             # Routing and Remote Access
      'RemoteRegistry'                           # Remote Registry
      'WlanSvc'                                  # WLAN AutoConfig
      'wscsvc'                                   # Windows Security Center Service
      'WSearch'                                  # Windows Search
      'WerSvc'
      'OneSyncSvc'
      'MessagingService'
      'wercplsupport'
      'PcaSvc'
      'ClipSVC'                                  # Needed for Microsoft Store
      'wisvc'
      'RetailDemo'
      'diagsvc'
      'shpamsvc' 
      'TroubleshootingSvc'
    )
    #>


    #'wlidsvc' # Change to startup on demand windows live sign in assistant can break windows live games etc..
    Disable-BeepService

#endregion
      


#region RemoveBuiltinWindowsApplications

    Remove-BuiltinWindowsApplications -apps @(
    'Microsoft.FreshPaint'
    'Microsoft.MicrosoftStickyNotes'
    'Microsoft.OneConnect'
    'Microsoft.Windows.Photos'
    'Microsoft.WindowsCalculator'
    'Microsoft.WindowsStore'
    'Microsoft.MSPaint'
    # apps which other apps depend on
    'Microsoft.Advertising.Xaml'
    )


    $null = Get-WindowsPackage -Online | Where-Object PackageName -like *QuickAssist* -ErrorAction SilentlyContinue | Remove-WindowsPackage -Online -NoRestart -ErrorAction SilentlyContinue
    $null = Get-WindowsPackage -Online | Where-Object PackageName -like *Hello-Face* -ErrorAction SilentlyContinue | Remove-WindowsPackage -Online -NoRestart -ErrorAction SilentlyContinue
    $null = Get-WindowsPackage -Online | Where-Object PackageName -like *MediaPlayer* -ErrorAction SilentlyContinue | Remove-WindowsPackage -Online -NoRestart -ErrorAction SilentlyContinue
    $null = Get-WindowsPackage -Online | Where-Object PackageName -like *MathRecognizer* -ErrorAction SilentlyContinue | Remove-WindowsPackage -Online -NoRestart -ErrorAction SilentlyContinue
    $null = Get-WindowsPackage -Online | Where-Object PackageName -like *OneCoreUAP.OneSync* -ErrorAction SilentlyContinue | Remove-WindowsPackage -Online -NoRestart -ErrorAction SilentlyContinue
   

#endregion
#region DisableScheduledTasks
   
    Disable-ScheduledTasks -TaskName @(
      'Microsoft\Windows\AppID\SmartScreenSpecific'
      'Microsoft\Windows\NetTrace\GatherNetworkInfo'
      'Microsoft\Windows\Application Experience\AitAgent'
      'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' 
      'Microsoft\Windows\Application Experience\ProgramDataUpdater' 
      'Microsoft\Windows\Application Experience\StartupAppTask' 
      'Microsoft\Windows\Autochk\Proxy'
      'Microsoft\Windows\CloudExperienceHost\CreateObjectTask' 
      'Microsoft\Windows\Customer Experience Improvement Program\BthSQM' 
      'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' 
      'Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask' 
      'Microsoft\Windows\Customer Experience Improvement Program\Uploader' 
      'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' 
      'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' 
      'Microsoft\Windows\DiskFootprint\Diagnostics' 
      'Microsoft\Windows\FileHistory\File History (maintenance mode)' 
      'Microsoft\Windows\Maintenance\WinSAT' 
      'Microsoft\Windows\PI\Sqm-Tasks' 
      'Microsoft\Windows\Shell\FamilySafetyRefresh' 
      'Microsoft\Windows\Shell\FamilySafetyUpload' 
      'Microsoft\Windows\Windows Error Reporting\QueueReporting' 
      'Microsoft\Windows\WindowsUpdate\Automatic App Update' 
      'Microsoft\Windows\License Manager\TempSignedLicenseExchange' 
      'Microsoft\Windows\Clip\License Validation' 
      'Microsoft\Windows\ApplicationData\DsSvcCleanup' 
      'Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem' 
      'Microsoft\Windows\PushToInstall\LoginCheck' 
      'Microsoft\Windows\PushToInstall\Registration' 
      'Microsoft\Windows\Shell\FamilySafetyMonitor' 
      'Microsoft\Windows\Shell\FamilySafetyMonitorToastTask' 
      'Microsoft\Windows\Shell\FamilySafetyRefreshTask' 
      'Microsoft\Windows\Subscription\EnableLicenseAcquisition' 
      'Microsoft\Windows\Subscription\LicenseAcquisition' 
      'Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner' 
      'Microsoft\Windows\Diagnosis\Scheduled' 
      'Microsoft\Office\Office 15 Subscription Heartbeat'
      'Microsoft\Office\OfficeTelemetryAgentFallBack'
      'Microsoft\Office\OfficeTelemetryAgentLogOn'
      'Microsoft\Windows\Feedback\Siuf\DmClient'
      'Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser'
      '\NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}' # Nvidia Telemetry
      '\NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8' # Nvidia Telemetry
      '\NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}'# Nvidia Telemetry
      'NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}' # NVIDIA display driver daily update checks
      'Adobe Flash Player Updater' # Adobe Flash Player update task
      'Adobe Acrobat Update Task' # Adobe Reader update task
      'NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}' # GeForce Experience Self Update
      'Microsoft\Windows\WCM\WiFiTask'
      'Microsoft\Windows\Work Folders\Work Folders Logon Synchronization'
      'Microsoft\Windows\Work Folders\Work Folders Maintenance Work'
      'Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)'
      'Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives'
      'Microsoft\Windows\BitLocker\BitLocker MDM policy Refresh'
      '\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner'
      '\Microsoft\Windows\Bluetooth\UninstallDeviceTask'
      '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem'
      '\Microsoft\Windows\Shell\FamilySafetyMonitor'
      '\Microsoft\Windows\Shell\FamilySafetyRefreshTask'
      '\Microsoft\Windows\TPM\Tpm-HASCertRetr'
      '\Microsoft\Windows\TPM\Tpm-Maintenance'
      '\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask'
      '\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon'
      '\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork'
      '\Microsoft\Windows\NlaSvc\WiFiTask'
      '\Microsoft\Windows\Maps\MapsToastTask'
      '\Microsoft\Windows\HelloFace\FODCleanupTask'
    )
    

    Takeown-Folder -Path "$env:SystemDrive:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\"
    Remove-Item -Path "$env:SystemDrive:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue


#endregion

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
        Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
        Name        = 'LogPixels'
        Value       = 96
        Description = 'Set Display DPI to 100%'
      }
    )
   
    # System Tweaks
    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
        Name        = 'NoPreviousVersionsPage'
        Value       = 1
        Description = 'Disable previous versions tab'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
        Name        = 'DisableEdgeDesktopShortcutCreation'
        Value       = 1
        Description = 'Disable Edge desktop shortcut'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\Maps'
        Name        = 'AutoUpdateEnabled'
        Value       = 0
        Description = 'Disabling automatic map updates'
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
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
        Name        = 'EnableBoottrace'
        Value       = 0
        Description = 'Disable Boot trace'
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
    )

    $registerKeys += @(
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
      @{
        Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
        Name        = 'fNoRemoteDesktopWallpaper'
        Value       = 1
        Description = 'Applying other Remote Desktop settings and tweaks'
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
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power'
        Name        = 'HiberbootEnabled'
        Value       = 0
        Description = 'Disable fast startup'
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

    					
    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
        Name        = 'DODownloadMode'
        Value       = 0
        Description = 'Disable seeding of updates to other computers on LAN via Group Policies'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization'
        Name        = 'SystemSettingsDownloadMode'
        Value       = 3
        Description = 'Restrict Windows Update Peer to Peer only to local network'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
        Name        = 'DownloadMode'
        Value       = 1
        Description = 'Restrict Windows Update Peer to Peer only to local network'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
        Name        = 'DODownloadMode'
        Value       = 1
        Description = 'Restrict Windows Update Peer to Peer only to local network'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings'
        Name        = 'DownloadMode'
        Value       = 1
        Description = 'Restrict Windows Update Peer to Peer only to local network'
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
    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
        Name        = 'NoGenTicket '
        Value       = 1
        Description = 'Disable Windows license check on startup'
      }
    )
    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        Name        = 'FeatureSettingsOverride'
        Value       = 3
        Description = 'Disable Spectre and Meltdown mitigations'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        Name        = 'FeatureSettingsOverrideMask'
        Value       = 3
        Description = 'Disable Spectre and Meltdown mitigations'
      }
    )

    $registerKeys += @(
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe'
        Name        = 'Debugger'
        Value       = '%windir%\\system32\\taskkill.exe'
        Description = 'Disable compatibility telemetry'
      }

      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe'
        Name        = 'Debugger'
        Value       = '%windir%\\system32\\taskkill.exe'
        Description = 'Disable gathering information about your PC to target builds through Windows Update'
      }
    )
    
    Set-RegistryValues -registerKeys $registerKeys
    
#endregion

    ##*===============================================
    ##* POST-INSTALLATION
    ##*===============================================
    [string]$installPhase = 'Post-Installation'


    Update-Desktop

		# Congratulations! Your copy of Windows 10 is now Debotnetted!
    Show-InstallationRestartPrompt -CountdownSeconds 600
  }
  ElseIf ($DeploymentType -ieq 'Uninstall')
  {
    ##*===============================================
    ##* PRE-UNINSTALLATION
    ##*===============================================
    [string]$installPhase = 'Pre-Uninstallation'
		
    ## Show Welcome Message, close Internet Explorer with a 60 second countdown before automatically closing
    Show-InstallationWelcome
		
    ## Show Progress Message (with the default message)
    Show-InstallationProgress
		
    ## <Perform Pre-Uninstallation tasks here>
		
		
    ##*===============================================
    ##* UNINSTALLATION
    ##*===============================================
    [string]$installPhase = 'Uninstallation'


    ##*===============================================
    ##* POST-UNINSTALLATION
    ##*===============================================
    [string]$installPhase = 'Post-Uninstallation'
		
    ## <Perform Post-Uninstallation tasks here>
  }
	
  ##*===============================================
  ##* END SCRIPT BODY
  ##*===============================================
	
  ## Call the Exit-Script function to perform final cleanup operations
  Exit-Script -ExitCode $mainExitCode
}
Catch 
{
  [int32]$mainExitCode = 60001
  [string]$mainErrorMessage = "$(Resolve-Error)"
  Write-Log -Message $mainErrorMessage -Severity 3 -Source $deployAppScriptFriendlyName
  Show-DialogBox -Text $mainErrorMessage -Icon 'Stop'
  Exit-Script -ExitCode $mainExitCode
}
