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
Param ()

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

Function Get-Temp 
{
  <# 
      Workaround for temp running in system context 
      7-Zip fails to extract files when running as system in the $env:Temp directory
  #>
  if([Security.Principal.WindowsIdentity]::GetCurrent().Name -ieq 'NT Authority\System') 
  {
    $obj = Join-Path -Path $env:windir -ChildPath 'temp'
  }
  else 
  {
    if ($env:TEMP -eq $null) 
    {
      $env:TEMP = Join-Path -Path $env:windir -ChildPath 'temp'
    }
    $obj = $env:TEMP
  }
  Write-Output -InputObject $obj
}

Function Convert-RegistryPath
{
  <#
      .SYNOPSIS
      Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.
      .DESCRIPTION
      Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.
      Converts registry key hives to their full paths. Example: HKLM is converted to "Registry::HKEY_LOCAL_MACHINE".
      .PARAMETER Key
      Path to the registry key to convert (can be a registry hive or fully qualified path)
      .PARAMETER SID
      The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.
      Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.
      .EXAMPLE
      Convert-RegistryPath -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
      .EXAMPLE
      Convert-RegistryPath -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
      .NOTES
      .LINK
	
  #>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string]$Key,
    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$SID
  )
	
  Begin {
    ## Get the name of this function and write header
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process {
    ## Convert the registry key hive to the full path, only match if at the beginning of the line
    If ($Key -match '^HKLM:\\|^HKCU:\\|^HKCR:\\|^HKU:\\|^HKCC:\\|^HKPD:\\') 
    {
      #  Converts registry paths that start with, e.g.: HKLM:\
      $Key = $Key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
      $Key = $Key -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\'
      $Key = $Key -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
      $Key = $Key -replace '^HKU:\\', 'HKEY_USERS\'
      $Key = $Key -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\'
      $Key = $Key -replace '^HKPD:\\', 'HKEY_PERFORMANCE_DATA\'
    }
    ElseIf ($Key -match '^HKLM:|^HKCU:|^HKCR:|^HKU:|^HKCC:|^HKPD:') 
    {
      #  Converts registry paths that start with, e.g.: HKLM:
      $Key = $Key -replace '^HKLM:', 'HKEY_LOCAL_MACHINE\'
      $Key = $Key -replace '^HKCR:', 'HKEY_CLASSES_ROOT\'
      $Key = $Key -replace '^HKCU:', 'HKEY_CURRENT_USER\'
      $Key = $Key -replace '^HKU:', 'HKEY_USERS\'
      $Key = $Key -replace '^HKCC:', 'HKEY_CURRENT_CONFIG\'
      $Key = $Key -replace '^HKPD:', 'HKEY_PERFORMANCE_DATA\'
    }
    ElseIf ($Key -match '^HKLM\\|^HKCU\\|^HKCR\\|^HKU\\|^HKCC\\|^HKPD\\') 
    {
      #  Converts registry paths that start with, e.g.: HKLM\
      $Key = $Key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
      $Key = $Key -replace '^HKCR\\', 'HKEY_CLASSES_ROOT\'
      $Key = $Key -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
      $Key = $Key -replace '^HKU\\', 'HKEY_USERS\'
      $Key = $Key -replace '^HKCC\\', 'HKEY_CURRENT_CONFIG\'
      $Key = $Key -replace '^HKPD\\', 'HKEY_PERFORMANCE_DATA\'
    }
		
    If ($PSBoundParameters.ContainsKey('SID')) 
    {
      ## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID				
      If ($Key -match '^HKEY_CURRENT_USER\\') 
      {
        $Key = $Key -replace '^HKEY_CURRENT_USER\\', "HKEY_USERS\$SID\"
      }
    }
		
    ## Append the PowerShell drive to the registry key path
    If ($Key -notmatch '^Registry::') 
    {
      [string]$Key = "Registry::$Key"
    }
		
    If($Key -match '^Registry::HKEY_LOCAL_MACHINE|^Registry::HKEY_CLASSES_ROOT|^Registry::HKEY_CURRENT_USER|^Registry::HKEY_USERS|^Registry::HKEY_CURRENT_CONFIG|^Registry::HKEY_PERFORMANCE_DATA') 
    {
      ## Check for expected key string format
      #Write-Log -Message "Return fully qualified registry key path [$Key]." -Source $CmdletName
      Write-Output -InputObject $Key
    }
    Else
    {
      #  If key string is not properly formatted, throw an error
      Throw "Unable to detect target registry hive in string [$Key]."
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
    [Parameter(Mandatory = $true)]
    [Array]$registerKeys
  )
	
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process {
    Foreach ($registerKey in $registerKeys)
    {
      If(!([string]::IsNullOrEmpty($($registerKey.Key))) -and !([string]::IsNullOrEmpty($($registerKey.Name))))
      {
        $Key = Convert-RegistryPath -Key $registerKey.Key
        $Name = $registerKey.Name
        $Value = $registerKey.Value
        $Description = $registerKey.Description	
        If([string]::IsNullOrEmpty($($registerKey.Description))) 
        {
          Show-InstallationProgress -StatusMessage "Applying Registry Modification: $Description"
        }

        Try 
        {
          if (!(Test-Path -LiteralPath $Key))
          {
            $null = New-Item -Path $Key -ItemType RegistryKey -Force
          }
         
          if(!([string]::IsNullOrEmpty($Value))) 
          {
            Set-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -Force
          } 
          else 
          {
            Set-ItemProperty -LiteralPath $Key -Name $Name -Value "$null" -Force
          }
        }
        Catch 
        {
          $Message = "Unable to add registry item [$Key] [$Name] [$Value]"
          Write-Warning -Message "$Message. `n$(Resolve-Error)"
          Continue
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

Function Invoke-InstallCMTrace
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  
  Process {
    Show-InstallationProgress  -StatusMessage  'Installing CMTrace'

    if(-Not (Test-Path -Path "$env:windir\cmtrace.exe")) 
    {
      if(Test-Path -Path "$PSScriptRoot\Includes\CMTrace.exe") 
      {
        Copy-Item -Path "$PSScriptRoot\Includes\CMTrace.exe" -Destination $env:windir
      }
      else 
      {
        Write-Warning -Message "cmtrace.exe not found in $PSScriptRoot\Includes"
      }
    }

    New-Item -Path 'HKLM:\Software\Classes\.lo_' -ItemType Directory -Force -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\Software\Classes\.log' -ItemType Directory -Force -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\Software\Classes\.log.File' -ItemType Directory -Force -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\Software\Classes\.Log.File\shell' -ItemType Directory -Force -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\Software\Classes\Log.File\shell\Open' -ItemType Directory -Force -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\Software\Classes\Log.File\shell\Open\Command' -ItemType Directory -Force -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\Software\Microsoft\Trace32' -ItemType Directory -Force -ErrorAction SilentlyContinue

    # Create the properties to make CMtrace the default log viewer
    New-ItemProperty -LiteralPath 'HKLM:\Software\Classes\.lo_' -Name '(default)' -Value 'Log.File' -PropertyType String -Force -ErrorAction SilentlyContinue

    New-ItemProperty -LiteralPath 'HKLM:\Software\Classes\.log' -Name '(default)' -Value 'Log.File' -PropertyType String -Force -ErrorAction SilentlyContinue

    New-ItemProperty -LiteralPath 'HKLM:\Software\Classes\Log.File\shell\open\command' -Name '(default)' -Value "`"C:\Windows\CCM\CMTrace.exe`" `"%1`"" -PropertyType String -Force -ErrorAction SilentlyContinue


    # Create an ActiveSetup that will remove the initial question in CMtrace if it should be the default reader
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\CMtrace' -ItemType Directory
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\CMtrace' -Name 'Version' -Value 1 -PropertyType String -Force 
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\CMtrace' -Name 'StubPath' -Value 'reg.exe add HKCU\Software\Microsoft\Trace32 /v ""Register File Types"" /d 0 /f' -PropertyType ExpandString -Force
  } 
  
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Disable-GameDVR
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    Show-InstallationProgress -StatusMessage 'Disable GameDVR and Gamebar'

    if((Test-Path -LiteralPath 'HKCU:\Software\Microsoft\GameBar') -ne $true) 
    {
      New-Item -Path 'HKCU:\Software\Microsoft\GameBar' -Force -ErrorAction SilentlyContinue
    }
    if((Test-Path -LiteralPath 'HKCU:\System\GameConfigStore') -ne $true) 
    {
      New-Item -Path 'HKCU:\System\GameConfigStore' -Force -ErrorAction SilentlyContinue
    }
    New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\GameBar' -Name 'UseNexusForGameBarEnabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_FSEBehavior' -Value 2 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_FSEBehaviorMode' -Value 2 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_HonorUserFSEBehaviorMode' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_DXGIHonorFSEWindowsCompatible' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_EFSEFeatureFlags' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'Win32_AutoGameModeDefaultProfile' -Value ([byte[]](0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc4, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -PropertyType Binary -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'Win32_GameModeRelatedProcesses' -Value ([byte[]](0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0xc0, 0x00, 0xc6, 0x02, 0x50, 0x54, 0xc7, 0x02, 0x70, 0x00, 0x61, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x00, 0x00, 0x8c, 0x00, 0x4e, 0x8d, 0xe1, 0x74, 0xb8, 0xed, 0xd2, 0x02, 0x18, 0x4c, 0xc7, 0x02, 0x1e, 0x00, 0x00, 0x00, 0xb8, 0xed, 0xd2, 0x02, 0x1e, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x30, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -PropertyType Binary -Force -ea SilentlyContinue
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

    Show-InstallationProgress -StatusMessage 'Set Data Execution Prevention (DEP) policy to OptOut'

    $null = & "$env:windir\system32\bcdedit.exe" /set `{current`} nx OptOut
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Set-WindowsUpdateSettings 
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process {
    Show-InstallationProgress -StatusMessage 'Setting Windows Update to notify when updates are available, and you decide when to install them.'

    $WindowsUpdateSettingsRegistry = @(
      @{
        Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Name  = 'NoAutoUpdate'
        Value = 0
      }
      @{
        Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Name  = 'AUOptions'
        Value = 2
      }
      @{
        Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Name  = 'ScheduledInstallDay'
        Value = 0
      }
      @{
        Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Name  = 'ScheduledInstallTime'
        Value = 3
      }
    )

    Set-RegistryValues -registerKeys $WindowsUpdateSettingsRegistry

  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Disable-SystemRestore 
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    Show-InstallationProgress -StatusMessage 'Disable System Restore'

    Disable-ComputerRestore -Drive "$env:SystemDrive\"
    vssadmin.exe delete shadows /all /Quiet

    $DisableSystemRestoreRegistry = @(
      @{
        Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
        Name  = 'DisableConfig'
        Value = 1
      }
      @{
        Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
        Name  = 'DisableSR'
        Value = 1
      }
      @{
        Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        Name  = 'DisableConfig'
        Value = 1
      }
      @{
        Key   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        Name  = 'DisableSR'
        Value = 1
      }
    )

    Set-RegistryValues -registerKeys $DisableSystemRestoreRegistry
    Disable-ScheduledTasks -TaskName '\Microsoft\Windows\SystemRestore\SR'
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Disable-8dot3FileNames
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process {
    Show-InstallationProgress -StatusMessage 'Disable 8dot3 file name creation'
    $null = & "$env:windir\system32\fsutil.exe" behavior set Disable8dot3 1
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
          Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart -Source "$PSScriptRoot\Includes\Sources\sxs" -ErrorAction Stop
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
    [Parameter(Mandatory = $true)][string[]]$TaskName
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    Show-InstallationProgress  -StatusMessage  'Disabling Scheduled Tasks'

    Foreach ($Task in $TaskName)
    {
      Write-Log -Message "Removing scheduled task '$Task'" -Source $CmdletName
      try 
      {
        Disable-ScheduledTask -TaskName $Task -ErrorAction Stop
      }
      catch 
      {
        Write-Log -Message "Unable to remove scheduled task '$Task'" -Severity 2
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

    Show-InstallationProgress  -StatusMessage  'Disabling unneeded windows services'

    Foreach ($s in $Service)
    {
      Show-InstallationProgress -StatusMessage "Stopping Service and disabling '$s'"
      try 
      {
        $null = Set-Service -Name $s -StartupType Disabled -ErrorAction Stop
      }
      catch 
      {
        $Message = "Unable to disable service '$($s)'" 
        Write-Warning -Message "$Message. `n$(Resolve-Error)"
      }
      try 
      {
        $null = Stop-Service -InputObject $s -ErrorAction Stop
      }
      catch 
      {
        $Message = "Unable to stop service '$($s)'" 
        Write-Warning -Message "$Message. `n$(Resolve-Error)"
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
    Show-InstallationProgress  -StatusMessage  'Enable High Performance Power Plan'


    Foreach ($Path in $ShortcutPath) 
    {
      $Path = Get-ChildItem -Path $Path
      Show-InstallationProgress -StatusMessage "Setting '$Path' to always run as administrator"
      Try 
      {
        $bytes = [IO.File]::ReadAllBytes("$ShortcutPath")
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [IO.File]::WriteAllBytes("$ShortcutPath", $bytes)
      } 
      Catch 
      {
        Show-InstallationProgress -StatusMessage  "Unable to set '$ShortcutPath' to always run as administrator"
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
    [switch]$HighPerformance,
    [switch]$UltimatePerformance,
    [switch]$Balanced
  )

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
     
    if($UltimatePerformance.IsPresent) 
    {
      $Filter = 'Ultimate Performance'
    }
    elseif($HighPerformance.IsPresent) 
    {
      $Filter = 'High performance'
    }
    elseif($Balanced.IsPresent) 
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


    Show-InstallationProgress -StatusMessage "Activating '$Filter' power plan"
    $Plan = & "$env:windir\system32\powercfg.exe" -l | Select-Plan
    $CurrPlan = $(& "$env:windir\system32\powercfg.exe" -getactivescheme).split()[3]
    if ($CurrPlan -ne $Plan) 
    {
      & "$env:windir\system32\powercfg.exe" -setactive $Plan
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
  
    # Setup Logging
    $LogDir = "$PSScriptRoot\Logs"

    If (!(Test-Path -Path $LogDir))
    {
      New-Item -Path $LogDir -ItemType Directory
    }
    $LogFile = "$LogDir\chocolatey_log_$(Get-Date -UFormat '%Y-%m-%d')"
  
  
    # Attempt to upgrade chocolatey (and all installed packages) else (if the command fails) install it.
    try
    {
      choco.exe upgrade all -y -r --no-progress --log-file=$LogFile
    }
    catch 
    {
      Invoke-Expression -Command ((New-Object -TypeName System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
 
	
    $chocoCmd = Get-Command -Name 'choco' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object -ExpandProperty Source
    
    if ($chocoCmd -eq $null) 
    { 
      Show-InstallationProgress -StatusMessage 'Chocolatey is not installed skipping software installation'
      return
    }
  
    Foreach ($p in $Package)
    {
      Show-InstallationProgress -StatusMessage  "Installing $p"
      Start-Process -FilePath $chocoCmd -ArgumentList "install $p  -y -r --no-progress --log-file=$LogFile" -NoNewWindow -Wait
    }
    
    # Remove log files over 10 days old
    $limit = (Get-Date).AddDays(-10)

    Get-ChildItem -Path $LogDir |
    Where-Object -FilterScript {
      $_.CreationTime -lt $limit
    } |
    Remove-Item -Force
    
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

    Show-InstallationProgress  -StatusMessage  'Installing CCEnhancer'
  
    if(Test-Path -Path "$env:ProgramW6432\CCleaner") 
    {
      Try 
      {
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini' -OutFile "$env:ProgramW6432\CCleaner\Winapp2.ini"
      }
      catch 
      {
        Write-Error -Message "Unable to download CCEnhancer winapp2.ini file `n$(Resolve-Error)"
      }
    }
    else 
    {
      Write-Error -Message 'CCleaner is not installed'
    }
    

  } End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}
Function Install-ISLC
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  
  Process {

    Show-InstallationProgress -StatusMessage  'Installing Intelligent standby list cleaner'
  
    Try
    {
      Invoke-WebRequest -Uri 'https://www.wagnardsoft.com/ISLC/ISLC%20v1.0.1.1.exe' -OutFile "$(Get-Temp)\ISLC.exe"
    }
    catch 
    {
      Write-Error -Message "Unable to download ISLC `n$(Resolve-Error)"
    }

    Start-Process -FilePath "$(Get-Temp)\ISLC.exe" -ArgumentList "-y -o$([char]34)$($env:ProgramW6432)$([char]34)"
     
    if(Test-Path -Path "$($env:ProgramW6432)\ISLC v1.0.1.1\Intelligent standby list cleaner ISLC.exe")
    {
      Set-StartupEntry -Name 'ISLC' -Type HKLM -Operation Add -Path "$($env:ProgramW6432)\ISLC v1.0.1.1\Intelligent standby list cleaner ISLC.exe"
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
        Show-InstallationProgress -StatusMessage "Skipping essential Windows app: $($app.Name)"
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
          Show-InstallationProgress -StatusMessage "Removing AppxPackage '$($AppPackageFullName)'"
          Remove-AppxPackage -Package $AppPackageFullName -ErrorAction Stop
        }
        Catch  
        {
          $Message = "Unable to remove $($AppPackageFullName)" 
          Write-Warning -Message "$Message. `n$(Resolve-Error)"
        }

        Try 
        {
          Show-InstallationProgress -StatusMessage "Removing AppxProvisioningPackage '$($AppProvisioningPackageName)'" 
          Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -ErrorAction Stop
        }
        Catch  
        {
          $Message = "Unable to remove '$($AppProvisioningPackageName)'"
          Write-Warning -Message "$Message. `n$(Resolve-Error)"
        }
      }
    }
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Disable-WindowsDefender 
{
  [CmdletBinding()]
  Param
  ()
  
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process 
  {
    Show-InstallationProgress -StatusMessage 'Disable Windows Defender'


    $tasks = @(
      'Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance'
      'Microsoft\Windows\Windows Defender\Windows Defender Cleanup'
      'Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan'
      'Microsoft\Windows\Windows Defender\Windows Defender Verification'
    )

    Disable-ScheduledTasks -TaskName $tasks

    Takeown-Registry -key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet'
    Takeown-Registry -key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend'
    $DisableWindowsDefenderRegisteryKeys = @(
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
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
        Name        = 'DisableAntiSpyware'
        Value       = 1
        Description = 'Disable Windows Defender'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
        Name        = 'DisableRoutinelyTakingAction'
        Value       = 1
        Description = 'Disable Windows Defender Routinely Taking Action'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name        = 'DisableRealtimeMonitoring'
        Value       = 1
        Description = 'Disable Windows Defender Realtime Protection'
      }
      @{
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32'
        Name        = 'Default'
        Value       = ''
        Description = 'Removing Windows Defender context menu item'
      }
      @{
        Key         = 'HKEY_CURRENT_USER\Software\Microsoft\Windows Defender'
        Name        = 'UIFirstRun'
        Value       = 0
        Description = 'Disable Windows Defender First Run UI'
      }
    )

    Set-RegistryValues -registerKeys $DisableWindowsDefenderRegisteryKeys
    
    Disable-WindowsService -Service 'WinDefend'
    Disable-WindowsService -Service 'WdNisSvc'
    Disable-WindowsService -Service 'Sense'

    Show-InstallationProgress -StatusMessage 'Removing Windows Defender GUI / tray from autorun'
    Set-StartupEntry -Name 'WindowsDefender' -Type 'HKLM' -Operation Remove
  }
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}


Function Set-TerminalShortcutsAsAdmin
{
  [CmdletBinding()]
  Param  
  ()

  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process {

    Show-InstallationProgress -StatusMessage 'Set Powershell and Command Prompt to run as administrator'

    $PowerShellPath = "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\"
    $CommandPrompt = "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\"

    $ShortcutPaths = Get-ChildItem -Path $PowerShellPath -Recurse -Include *.lnk
    $ShortcutPaths += Get-ChildItem -Path $CommandPrompt -Recurse -Include 'Command Prompt.lnk'

    Foreach ($ShortcutPath in $ShortcutPaths) 
    {
      Show-InstallationProgress -StatusMessage "Setting '$ShortcutPath' to run as administrator"
			
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

  End {


    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Disable-SMBv1 
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }

  Process 
  {
    Show-InstallationProgress -StatusMessage 'Disabling SMBv1'

    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Disable-SharingWifiNetworks 
{
  Show-InstallationProgress  -StatusMessage  'Disabling sharing of Wi-Fi networks'

  $user = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList ($env:UserName)
  $SID = $user.Translate([System.Security.Principal.SecurityIdentifier]).value

  $DisableSharingWifiNetworksRegistryKeys = @(
    @{
      Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\$SID"
      Name        = 'FeatureStates'
      Value       = 0x33c
      Description = 'WifiSense Credential Share'
    }
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

  Set-RegistryValues -registerKeys $DisableSharingWifiNetworksRegistryKeys
}

Function Set-StartupEntry
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][ValidateSet('HKLM','HKCU')]
    [string]$Type,
    [Parameter(Mandatory = $true)][ValidateSet('Remove','Add')]
    [string]$Operation,
    [switch]$RunOnce,
    [string]$Path
  )

  # HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
  # HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
  # HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
  # HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce


  if($Type -imatch 'HKLM')
  {
    if($RunOnce.IsPresent) 
    {
      if($Operation -imatch 'Remove') 
      {
        Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name "$Name" -ErrorAction SilentlyContinue
      }
      else 
      {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name $Name -Value $Path -ErrorAction SilentlyContinue
      }
    }
    else 
    {
      if($Operation -imatch 'Remove') 
      {
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name "$Name" -ErrorAction SilentlyContinue
      }
      else 
      {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $Name -Value $Path -ErrorAction SilentlyContinue
      }
    }
  }

  if($Type -imatch 'HKCU')
  {
    if($RunOnce.IsPresent) 
    {
      if($Operation -imatch 'Remove') 
      {
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name "$Name" -ErrorAction SilentlyContinue
      }
      elseif ($Operation -imatch 'Add')  
      {
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name $Name -Value $Path -ErrorAction SilentlyContinue
      }
    }
    else 
    {
      if($Operation -imatch 'Remove') 
      {
        Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name "$Name" -ErrorAction SilentlyContinue
      }
      elseif ($Operation -imatch 'Add') 
      {
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $Name -Value $Path -ErrorAction SilentlyContinue
      }
    }
  }
}


Function New-Shortcut
{
  [CmdletBinding()]
  Param(
    [string]$Name,
    [string]$TargetPath,
    [string]$Arguments,
    [string]$WorkingDirectory,
    [string]$IconLocation,
    [string]$Description,
    [string]$Destination
  )
  
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  
  Process {

    if(Test-Path -Path "$env:USERPROFILE\Desktop\$Name") 
    {
      Remove-Item -Path "$env:USERPROFILE\Desktop\$Name" -Force
    }
  
    $ShortcutPath = Join-Path -Path $Destination -ChildPath $Name
  
    $Shell = New-Object -ComObject ('WScript.Shell')
    $ShortCut = $Shell.CreateShortcut($ShortcutPath)
    $ShortCut.TargetPath = $TargetPath
    $ShortCut.Arguments = $Arguments
    $ShortCut.WorkingDirectory = $WorkingDirectory
    $ShortCut.WindowStyle = 1
    $ShortCut.Hotkey = ''
    $ShortCut.IconLocation = $IconLocation
    $ShortCut.Description = $Description
    $ShortCut.Save()

  }
  
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

function Unpin-App 
{
  [CmdletBinding()]
  param
  (
    [string]
    $Name
  )

  try 
  {
    $exec = $false

    ((New-Object -ComObject Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() |
      Where-Object -FilterScript {
        $_.Name -eq $Name
    }).Verbs() |
    Where-Object -FilterScript {
      $_.Name.replace('&','') -match 'Unpin from taskbar'
    } |
    ForEach-Object -Process {
      $_.DoIt()
      $exec = $true
    }
    if ($exec) 
    {
      Show-InstallationProgress -StatusMessage "App '$Name' unpinned from Taskbar"
    }
    else 
    {
      Show-InstallationProgress -StatusMessage "'$Name' not found or 'Unpin from taskbar' not found on item"
    }
  }
  catch 
  {
    Write-Warning -Message "Error unpinning $Name from taskbar `n$(Resolve-Error)"
  }
}


# Set Photo Viewer association for bmp, gif, jpg, png and tif
function Set-PhotoViewerAssociation
{
  Show-InstallationProgress  -StatusMessage  'Setting Photo Viewer association for bmp, gif, jpg, png and tif...'

  If (!(Test-Path -Path 'HKCR:'))
  {
    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
  }
  ForEach ($Type in @('Paint.Picture', 'giffile', 'jpegfile', 'pngfile'))
  {
    $null = New-Item -Path $("HKCR:\$Type\shell\open") -Force
    $null = New-Item -Path $("HKCR:\$Type\shell\open\command")
    Set-ItemProperty -Path $("HKCR:\$Type\shell\open") -Name 'MuiVerb' -Type ExpandString -Value '@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043'
    Set-ItemProperty -Path $("HKCR:\$Type\shell\open\command") -Name '(Default)' -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
  }
}
# Add Photo Viewer to "Open with..."
function Add-PhotoViewerOpenWith
{
  Show-InstallationProgress -StatusMessage "Adding Photo Viewer to `"Open with...`""

  If (!(Test-Path -Path 'HKCR:'))
  {
    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
  }
  $null = New-Item -Path 'HKCR:\Applications\photoviewer.dll\shell\open\command' -Force
  $null = New-Item -Path 'HKCR:\Applications\photoviewer.dll\shell\open\DropTarget' -Force
  Set-ItemProperty -Path 'HKCR:\Applications\photoviewer.dll\shell\open' -Name 'MuiVerb' -Type String -Value '@photoviewer.dll,-3043'
  Set-ItemProperty -Path 'HKCR:\Applications\photoviewer.dll\shell\open\command' -Name '(Default)' -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
  Set-ItemProperty -Path 'HKCR:\Applications\photoviewer.dll\shell\open\DropTarget' -Name 'Clsid' -Type String -Value '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}'
}

# Hide Task View button
function Set-HideTaskView
{
  Show-InstallationProgress  -StatusMessage  'Hiding Task View button...'
  Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowTaskViewButton' -Type DWord -Value 0
}


# Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
function Set-Hide3DObjectsFromThisPC
{
  Show-InstallationProgress  -StatusMessage  'Hide 3D Objects From This PC'
  Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}' -Recurse -ErrorAction SilentlyContinue
}

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
function Set-Hide3DObjectsFromExplorer
{
  Show-InstallationProgress  -StatusMessage  'Hide 3D Objects From Explorer'

  If (!(Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag'))
  {
    $null = New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Force
  }
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Name 'ThisPCPolicy' -Type String -Value 'Hide'
  If (!(Test-Path -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag'))
  {
    $null = New-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Force
  }
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Name 'ThisPCPolicy' -Type String -Value 'Hide'
}

function Uninstall-OneDrive 
{
  Show-InstallationProgress -StatusMessage 'Uninstall OneDrive'

  taskkill.exe /F /IM 'OneDrive.exe'
  taskkill.exe /F /IM 'explorer.exe'
	
  if (Test-Path -Path "$env:systemroot\System32\OneDriveSetup.exe")
  {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
  }
  if (Test-Path -Path "$env:systemroot\SysWOW64\OneDriveSetup.exe")
  {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
  }
  Start-Process -FilePath 'explorer.exe'
}

Function Disable-ApplicationsRunningInBackground
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  
  Process {

    Show-InstallationProgress -StatusMessage 'Disable background access of default Windows 10 apps' 
	
    $BackgroundServicesRegisterKeys = @()

    foreach ($Key in (Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications')) 
    {
      $BackgroundServicesRegisterKeys += @(
        @{
          Key         = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' + $Key.PSChildName
          Name        = 'Disabled'
          Value       = 1
          Description = "Disable background access of apps '$($Key.PSChildName)'"
        }
      )
    }
    Set-RegistryValues -registerKeys $BackgroundServicesRegisterKeys
  }
  
  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}


Function  Clean-DesktopIcons 
{
  Begin {
    [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
	
  Process {
    Show-InstallationProgress -StatusMessage 'Clean up desktop icons.'

    $EdgeLnk = 'Microsoft Edge.lnk'
    Remove-Item -Path (Join-Path -Path "$env:USERPROFILE\Desktop" -ChildPath "$EdgeLnk") -Force -Confirm:$false -ErrorAction SilentlyContinue

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

    Show-InstallationProgress -StatusMessage 'Disable all windows theme sounds'
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

    Show-InstallationProgress -StatusMessage 'Remove Builtin Default Windows Printers'

    $PrintersToRemove = 'Microsoft XPS Document Writer', 'Send to OneNote 2016', 'Fax'
    foreach ($Printer in $PrintersToRemove)
    {
      $PrinterToFind = (Get-VirtualPrinter -PrinterName $Printer)
      if (!($PrinterToFind -eq $null))
      {
        Show-InstallationProgress -StatusMessage "Removing $Printer" 
        Try 
        {
          Remove-VirtualPrinter -PrinterName $Printer
        } 
        Catch 
        {
          $Message = "Unable to remove printer '$Printer'"
          Write-Warning -Message "$Message. `n$(Resolve-Error)"
          Continue
        }
      }
    }
    
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Set-HomeLocation
{
  [CmdletBinding()]
  param (
    [int]$Id = 1
  )

  Show-InstallationProgress -StatusMessage 'Set Location'

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

    Show-InstallationProgress -StatusMessage 'Setting default search provider for IE to Google' 
 
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
  }

  End {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

Function Enable-F8BootMenu 
{
  # Enable F8 boot menu options
  $null = & "$env:windir\system32\bcdedit.exe" /set `{current`} bootmenupolicy Legacy
}

Function Disable-StartupRecovery 
{
  Write-Verbose -Message 'Disable-StartupRecovery'
  $null = & "$env:windir\system32\bcdedit.exe" /set recoveryenabled No
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
    Show-InstallationProgress -StatusMessage 'Disabling Windows Search Web Results'


    Try 
    {
      Set-WindowsSearchSetting -EnableWebResultsSetting $false
    }
    Catch 
    {
      $Message = 'Unable to disable windows search web results the service may already be disabled'
      Write-Warning -Message "$Message. `n$(Resolve-Error)"
      Continue
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


Function Disable-BeepService
{
  Begin {
    [string]$CmdletName = $MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
  }
  Process 
  {

    Show-InstallationProgress -StatusMessage 'Windows Beep Service, stops annoying beeps in powershell console'
    Set-Service -Name beep -StartupType disabled
  }
  End 
  {
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
  }
}

function Takeown-Registry 
{
  # TODO does not work for all root keys yet
    
  [CmdletBinding()]
  param
  (
    $Key
  )
  switch ($Key.split('\')[0]) {
    'HKEY_CLASSES_ROOT' 
    {
      $reg = [Microsoft.Win32.Registry]::ClassesRoot
      $Key = $Key.substring(18)
    }
    'HKEY_CURRENT_USER' 
    {
      $reg = [Microsoft.Win32.Registry]::CurrentUser
      $Key = $Key.substring(18)
    }
    'HKEY_LOCAL_MACHINE' 
    {
      $reg = [Microsoft.Win32.Registry]::LocalMachine
      $Key = $Key.substring(19)
    }
  }

  # get administraor group
  $admins = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ('S-1-5-32-544')
  $admins = $admins.Translate([System.Security.Principal.NTAccount])

  # set owner
  $Key = $reg.OpenSubKey($Key, 'ReadWriteSubTree', 'TakeOwnership')
  $acl = $Key.GetAccessControl()
  $acl.SetOwner($admins)
  $Key.SetAccessControl($acl)

  # set FullControl
  $acl = $Key.GetAccessControl()
  $rule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList ($admins, 'FullControl', 'Allow')
  $acl.SetAccessRule($rule)
  $Key.SetAccessControl($acl)
}

function Takeown-File 
{
  [CmdletBinding()]
  param
  (
    $Path
  )
  takeown.exe /A /F $Path
  $acl = Get-Acl -Path $Path

  # get administraor group
  $admins = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ('S-1-5-32-544')
  $admins = $admins.Translate([System.Security.Principal.NTAccount])

  # add NT Authority\SYSTEM
  $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($admins, 'FullControl', 'None', 'None', 'Allow')
  $acl.AddAccessRule($rule)

  Set-Acl -Path $Path -AclObject $acl
}

function Takeown-Folder
{
  [CmdletBinding()]
  param
  (
    [string]$Path
  )
  Takeown-File -Path $Path
  foreach ($item in Get-ChildItem -Path $Path) 
  {
    if (Test-Path -Path $item -PathType Container) 
    {
      Takeown-Folder -path $item.FullName
    }
    else 
    {
      Takeown-File -Path $item.FullName
    }
  }
}

function Force-Mkdir 
{
  param
  (
    [Parameter(Mandatory = $true)]
    [string]$Path
  )
  
  # While `mkdir -force` works fine when dealing with regular folders, it behaves
  # strange when using it at registry level. If the target registry key is
  # already present, all values within that key are purged.

  if (-Not (Test-Path -Path $Path)) 
  {
    New-Item -ItemType Directory -Force -Path $Path
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