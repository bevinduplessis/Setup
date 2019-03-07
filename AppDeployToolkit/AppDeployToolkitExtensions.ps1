<#
    .SYNOPSIS
    This script is a template that allows you to extend the toolkit with your own custom functions.
    # LICENSE #
    PowerShell App Deployment Toolkit - Provides a set of functions to perform common application deployment tasks on Windows. 
    Copyright (C) 2017 - Sean Lillis, Dan Cunningham, Muhammad Mashwani, Aman Motazedian.
    This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 
    You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
    .DESCRIPTION
    The script is automatically dot-sourced by the AppDeployToolkitMain.ps1 script.
    .NOTES
    Toolkit Exit Code Ranges:
    60000 - 68999: Reserved for built-in exit codes in Deploy-Application.ps1, Deploy-Application.exe, and AppDeployToolkitMain.ps1
    69000 - 69999: Recommended for user customized exit codes in Deploy-Application.ps1
    70000 - 79999: Recommended for user customized exit codes in AppDeployToolkitExtensions.ps1
    .LINK 
    http://psappdeploytoolkit.com
#>
[CmdletBinding()]
Param (
)

##*===============================================
##* VARIABLE DECLARATION
##*===============================================

# Variables: Script
[string]$appDeployToolkitExtName = 'PSAppDeployToolkitExt'
[string]$appDeployExtScriptFriendlyName = 'App Deploy Toolkit Extensions'
[version]$appDeployExtScriptVersion = [version]'1.5.0'
[string]$appDeployExtScriptDate = '02/12/2017'
[hashtable]$appDeployExtScriptParameters = $PSBoundParameters

##*===============================================
##* FUNCTION LISTINGS
##*===============================================

Function Invoke-ElevatePrivileges
{
  [CmdletBinding()]
  param($Privilege)
  $Definition = @'
    using System;
    using System.Runtime.InteropServices;
    public class AdjPriv {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
        [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public static bool EnablePrivilege(long processHandle, string privilege) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
'@
  $ProcessHandle = (Get-Process -Id $PID).Handle
  $Type = Add-Type -TypeDefinition $Definition -PassThru
  $Type[0]::EnablePrivilege($ProcessHandle, $Privilege)
}

Function Set-RegistryValues
{
  [CmdletBinding()]
  Param
  (
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user')]
    [string[]]$registerKeys
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
          Write-Log -Message "Applying registry modification: $($registerKey.Description)" -Source $CmdletName
          Show-InstallationProgress  -StatusMessage "Applying registry modification: $($registerKey.Description). `n Please wait..."
        }
						
        Try 
        {
          if (!(Test-Path -LiteralPath $key))
          {
            Write-Log -Message "Creating registry '$key'" -Source $CmdletName
            $null = New-Item -Path $key -ItemType RegistryKey -Force
          }
          Write-Log -Message "Path '$key' Name '$Name' Value '$Value'" -Source $CmdletName
         
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
          Write-Log -Severity 2 -Message "$Message. `n$(Resolve-Error)" -Source $CmdletName
          Continue
        }
					
        if(Test-Path -Path "$key" -PathType Container) 
        {
          Write-Log -Severity 2 -Message "Testing if registry value name exists '$(Test-RegistryValue -Key "$key" -Value "$Name")'" -Source $CmdletName
        }
        else 
        {
          Write-Log -Severity 2 -Message 'Registry key does not exist' -Source $CmdletName
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
  
  Begin {
    ## Get the name of this function and write header
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
  
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
  
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Remove-VirtualPrinter
{
  Param
  (
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user')]
    [string]$PrinterName
  )
  
  Begin {
    ## Get the name of this function and write header
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  
  
  Process {
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
  
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Test-IsAdmin
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process
  {
    Try
    {
      # Get the current ID and its security principal
      $windowsID = [Security.Principal.WindowsIdentity]::GetCurrent()
      $windowsPrincipal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($windowsID)
 
      # Get the Admin role security principal
      $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
 
      # Are we an admin role?
      if ($windowsPrincipal.IsInRole($adminRole))
      {
        $obj = $true
      }
      else
      {
        $obj = $false
      }
    }
    Catch 
    {
      Write-Log -Message "Unable to test for administrative rights `n$(Resolve-Error)" -Severity 3 -Source $CmdletName
    }
    Write-Output -InputObject $obj
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Set-DEPOptOut 
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process {
    # Set Data Execution Prevention (DEP) policy to OptOut
    $null = & "$env:windir\system32\bcdedit.exe" /set `{current`} nx OptOut
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
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
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
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
          Write-Log -Message "Failed to find the DriveLetter $DL specified" -Severity 2 -Source $CmdletName
          return
        }
        if ($Vol.DriveType -ne 3) 
        {
          Write-Log -Message 'The selected drive should be a fixed local volume' -Severity 2 -Source $CmdletName
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
              Write-Log -Message "Failed to query the Win32_PageFileSetting class because $($_.Exception.Message)" -Severity 2 -Source $CmdletName
            }
            If($PageFile) 
            {
              try 
              {
                $PageFile | Remove-CimInstance -ErrorAction Stop
              }
              catch 
              {
                Write-Log -Message "Failed to delete pagefile the Win32_PageFileSetting class because $($_.Exception.Message)" -Severity 2 -Source $CmdletName
              }
            }
            Else 
            {
              Write-Log -Message "$DL is already set None!" -Severity 2 -Source $CmdletName
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
              Write-Log -Message "Failed to query the Win32_PhysicalMemory class because $($_.Exception.Message)" -Severity 2 -Source $CmdletName
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
              Write-Log -Message 'Maximum size of page file being set exceeds the freespace available on the drive' -Severity 2 -Source $CmdletName
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
              Write-Log -Message 'Maximum size of page file being set exceeds the freespace available on the drive'  -Severity 2 -Source $CmdletName
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
        Write-Log -Message "Failed to query Win32_PageFileSetting class because $($_.Exception.Message)" -Severity 3 -Source $CmdletName
      }
      If($Reboot) 
      {
        Restart-Computer -ComputerName $Env:COMPUTERNAME -Force
      }
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
    [string[]]$feature
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process 
  {
    Foreach ($f in $feature) 
    {
      if((Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue).State -eq 'Disabled')
      {
        Write-Log -Message "Adding Windows feature '$f'" -Source $CmdletName
        Try 
        {
          Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart -Source "$PSScriptRoot\Sources\sxs" -ErrorAction Stop
        }
        Catch 
        {
          Write-Log -Message "Unable to add windows feature '$f'" -Severity 2 -Source $CmdletName
        }
      }
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}


Function Disable-ScheduledTasks
{
  [CmdletBinding()]
  Param
  (
    [string[]]$tasks
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    Foreach ($task in $tasks)
    {
      Write-Log -Message "Removing scheduled task '$task'" -Source $CmdletName
      try 
      {
        Disable-ScheduledTask -TaskName $task -ErrorAction Stop
      }
      catch 
      {
        Write-Log -Message "Unable to remove scheduled task '$task'" -Severity 2
      }
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Disable-WindowsService
{
  [CmdletBinding()]
  Param
  (
    [string[]]$Service
  )
	
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    Foreach ($s in $Service)
    {
      Write-Log -Message "Stopping Service and disabling '$s'" -Source $CmdletName
      Try 
      {
        $null = Set-Service -Name $s -StartupType Disabled -ErrorAction Stop
      }
      Catch 
      {
        Write-Log -Message "Unable to set '$s' to disabled `n$(Resolve-Error)" -Severity 3 -Source $CmdletName
      }
				
      Try 
      {
        $null = Stop-Service -InputObject $s -ErrorAction Stop
      }
      Catch 
      {
        Write-Log -Message "Unable to stop '$s' `n$(Resolve-Error)" -Severity 3 -Source $CmdletName
      }
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Set-ShortcutRunAsAdmin
{
  [CmdletBinding()]
  Param  
  ([string[]]$ShortcutPath
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
	
    Foreach ($Path in $ShortcutPath) 
    {
      $Path = Get-ChildItem -Path $Path

      Write-Log -Message "Setting '$Path' to always run as administrator" -Source $CmdletName
      Try 
      {
        $bytes = [IO.File]::ReadAllBytes("$ShortcutPath")
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [IO.File]::WriteAllBytes("$ShortcutPath", $bytes)
      } 
      Catch 
      {
        Write-Log -Message "Unable to set '$ShortcutPath' to always run as administrator `n$(Resolve-Error)" -Severity 3 -Source $CmdletName
      }
    }
    
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Set-WindowsPowerPlan
{
  [CmdletBinding()]
  Param(
    [bool]$HighPerformance,
    [bool]$Balanced
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
     
    if($HighPerformance) 
    {
      $Filter = 'High performance'
    }
    else 
    {
      $Filter = 'Balanced'
    }
  }

  Process {
	
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
      Write-Log -Message 'Activating [High Performance] power plan' -Source $CmdletName
      $Plan = & "$env:windir\system32\powercfg.exe" -l | Select-Plan
      $CurrPlan = $(& "$env:windir\system32\powercfg.exe" -getactivescheme).split()[3]
      if ($CurrPlan -ne $Plan) 
      {
        & "$env:windir\system32\powercfg.exe" -setactive $Plan
      }
    }
    Catch 
    {
      Write-Log -Message "Unable to set power plan to '$Filter'" -Severity 2 -Source $CmdletName
    }
    
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}



Function Install-ChocolateyPackage
{
  [CmdletBinding()]
  Param
  (
    [string[]]$Package
  )
	
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
	
    $chocoCmd = Get-Command -Name 'choco' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object -ExpandProperty Source
    
    if ($chocoCmd -eq $null) 
    { 
      Write-Log -Message 'Chocolatey is not installed skipping software installation' -Severity 2 -Source $CmdletName
      return
    }
  
    Foreach ($p in $Package)
    {
      Write-Log -Message "Installing $p" -Source $CmdletName
      Start-Process -FilePath $chocoCmd -ArgumentList "install $p -y" -NoNewWindow -Wait
    }
   
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Install-CCEnhancer 
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  
  Process {
  
    if(Test-Path -Path "$env:ProgramW6432\CCleaner") 
    {
      Try 
      {
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini' -OutFile "$env:ProgramW6432\CCleaner\Winapp2.ini"
      }
      catch 
      {
        Write-Log -Message "Unable to download CCEnhancer winapp2.ini file `n$(Resolve-Error)" -Severity 3 -Source $CmdletName
      }
    }
    else 
    {
      Write-Log -Message 'CCleaner is not installed' -Severity 2 -Source $CmdletName
    }
    

  } End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}



Function Remove-BuiltinWindowsApplications
{
  [CmdletBinding()]
  Param
  (
    [string[]]$apps
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

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
        Write-Log -Message "Skipping essential Windows app: $($app.Name)" -Source $CmdletName
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
          Write-Log -Message "Removing AppxPackage '$($AppPackageFullName)'" -Source $CmdletName
          Remove-AppxPackage -Package $AppPackageFullName -ErrorAction Stop
        }
        Catch  
        {
          Write-Log -Message "Unable to remove $($AppPackageFullName)" -Severity 2 -Source $CmdletName
        }

        Try 
        {
          Write-Log -Message "Removing AppxProvisioningPackage '$($AppProvisioningPackageName)'" -Source $CmdletName
          Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -ErrorAction Stop
        }
        Catch  
        {
          Write-Log -Message "Unable to remove '$($AppProvisioningPackageName)'" -Severity 2 -Source $CmdletName
        }
      }
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}


Function Disable-ApplicationsRunningINBackground
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  
  Process {

    Write-Log -Message 'Disable background access of default Windows 10 apps' -Source $CmdletName
	
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
  
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Disable-WindowsThemeSounds
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
    Write-Log -Message 'Disable all windows sounds' -Source $CmdletName
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

Function Remove-BuiltInPrinters
{
  [CmdletBinding()]
  Param()

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    $PrintersToRemove = 'Microsoft XPS Document Writer', 'Send to OneNote 2016', 'Fax'
    foreach ($Printer in $PrintersToRemove)
    {
      $PrinterToFind = (Get-VirtualPrinter -PrinterName $Printer)
      if (!($PrinterToFind -eq $null))
      {
        Write-Log -Message "Removing $Printer" -Source $CmdletName
        Try 
        {
          Remove-VirtualPrinter -PrinterName $Printer
        } 
        Catch 
        {
          $Message = "Unable to remove [$Printer]"
          Write-Log -Message "$Message. `n$(Resolve-Error)" -Severity 2 -Source $CmdletName
          Continue
        }
      }
    }
    
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
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


Function Set-IEDefaultSearchProvider
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

    Write-Log -Message 'Setting default search provider for IE to Google' -Source $CmdletName
 
    $Guid = '{A3C1E120-0692-4CFE-8F3E-FC214C255495}'
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
    $null = New-ItemProperty -Path "$SearchScopes\$Guid" -Name 'DefaultScope' -PropertyType 'String' -Value "$Guid" -Force 
    
    Write-Log -Message 'Adding Google Search' -Source $CmdletName
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Set-WindowsSearchWebResults
{
  [CmdletBinding()]
  Param()

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {
    Try 
    {
      Set-WindowsSearchSetting -EnableWebResultsSetting $false
    }
    Catch 
    {
      $Message = 'Unable to disable windows search web results the service may already be disabled'
      Write-Log -Message "$Message. `n$(Resolve-Error)" -Severity 3 -Source $CmdletName
      Continue
    }
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
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
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}


Function Test-IsDesktop
{
  Begin {
    [string]$CmdletName = $MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
		
  Process {
		
    $hardwaretype = Get-WmiObject -Class Win32_ComputerSystem -Property PCSystemType
    If ($hardwaretype -ne 2)
    {
      return $true
    }
    Else
    {
      return $false
    }
		
  }
		
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Test-NetworkConnection
{
  <#
      .SYNOPSIS
      Tests for an active local network connection, excluding wireless and virtual network adapters.
      .DESCRIPTION
      Tests for an active local network connection, excluding wireless and virtual network adapters, by querying the Win32_NetworkAdapter WMI class.
      .EXAMPLE
      Test-NetworkConnection
      .NOTES
      .LINK
	
  #>
  [CmdletBinding()]
  Param (
  )
	
  Begin {
    ## Get the name of this function and write header
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process {
    Write-Log -Message 'Check if system is using a wired network connection...' -Source ${CmdletName}
		
    [psobject[]]$networkConnected = Get-WmiObject -Class 'Win32_NetworkAdapter' | Where-Object -FilterScript {
      ($_.NetConnectionStatus -eq 2) -and ($_.NetConnectionID -match 'Local') -or ($_.NetConnectionID -match 'Ethernet') -and ($_.NetConnectionID -notmatch 'Wireless') -and ($_.Name -notmatch 'Virtual')
    } -ErrorAction 'SilentlyContinue'
    [boolean]$onNetwork = $false
    If ($networkConnected) 
    {
      Write-Log -Message 'Wired network connection found.' -Source ${CmdletName}
      [boolean]$onNetwork = $true
    }
    Else 
    {
      Write-Log -Message 'Wired network connection not found.' -Source ${CmdletName}
    }
		
    Write-Output -InputObject $onNetwork
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
  }
}

Function Invoke-TakeownRegistry 
{
  # TODO: does not work for all root keys yet

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)][string]$key
  )
  
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
    
  Process 
  {
    switch ($key.split('\')[0]) {
      'HKEY_CLASSES_ROOT' 
      {
        $reg = [Microsoft.Win32.Registry]::ClassesRoot
        $key = $key.substring(18)
      }
      'HKEY_CURRENT_USER' 
      {
        $reg = [Microsoft.Win32.Registry]::CurrentUser
        $key = $key.substring(18)
      }
      'HKEY_LOCAL_MACHINE' 
      {
        $reg = [Microsoft.Win32.Registry]::LocalMachine
        $key = $key.substring(19)
      }
    }

    # Get administrators Group
    $admins = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ('S-1-5-32-544')
    $admins = $admins.Translate([Security.Principal.NTAccount])

    # Set Owner
    $key = $reg.OpenSubKey($key, 'ReadWriteSubTree', 'TakeOwnership')
    $acl = $key.GetAccessControl()
    $acl.SetOwner($admins)
    $key.SetAccessControl($acl)

    # Set FullControl
    $acl = $key.GetAccessControl()
    $rule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList ($admins, 'FullControl', 'Allow')
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
  } 
  
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}





##*===============================================
##* END FUNCTION LISTINGS
##*===============================================

##*===============================================
##* SCRIPT BODY
##*===============================================

If ($scriptParentPath) 
{
  Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] dot-source invoked by [$(((Get-Variable -Name MyInvocation).Value).ScriptName)]" -Source $appDeployToolkitExtName
}
Else 
{
  Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] invoked directly" -Source $appDeployToolkitExtName
}

##*===============================================
##* END SCRIPT BODY
##*===============================================