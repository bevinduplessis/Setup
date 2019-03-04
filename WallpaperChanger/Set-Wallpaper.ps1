$Market = "en-US"
$Resolution = "1920x1080"
$ImageFileName = "wallpaper.jpg"
$ImageFileNameWatermark = "wallpaper_wm.jpg"
$DownloadDirectory = "$env:USERPROFILE\Pictures\Wallpaper"
$BingImageFullPath = "$($DownloadDirectory)\$($ImageFileName)"
$BingImageFullPathWatermark = "$($DownloadDirectory)\$($ImageFileNameWatermark)"
$ProgramFiles = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles%")
$BGInfoLocation = $ProgramFiles + "\LogonScript\includes\bginfo\Bginfo.exe"
$BGInfoConfiguration = $ProgramFiles + "\LogonScript\includes\bginfo\background.bgi"

While (!(Test-Connection -ComputerName www.google.com -count 1 -Quiet -ErrorAction SilentlyContinue )) {
    Write-Host -ForegroundColor Red "Waiting for internet connection to continue..."
    Start-Sleep -Seconds 10
}

New-Item -ItemType directory -Force -Path $DownloadDirectory | Out-Null
 
[ xml ]$Bingxml = (New-Object System.Net.WebClient).DownloadString("http://www.bing.com/HPImageArchive.aspx?format=xml&idx=0&n=1&mkt=$($Market)");
$ImageUrl = "http://www.bing.com$($Bingxml.images.image.urlBase)_$($Resolution).jpg";
 
if ((Test-Path "$BingImageFullPath") -And ((Get-ChildItem "$BingImageFullPath").LastWriteTime.ToShortDateString() -eq (get-date).ToShortDatesTring())){
    Write-Host -ForegroundColor Green "You already have today's Bing image in: $DownloadDirectory"  
}
else {
    Invoke-WebRequest -UseBasicParsing -Uri $ImageUrl -OutFile "$BingImageFullPath";
    Write-Host -ForegroundColor Green "Today's Bing image downloaded to: $DownloadDirectory"
}
 
While (!(Test-Path "$BingImageFullPath")) {
    Write-Host -ForegroundColor Yellow "Waiting for Bing image to finish downloading..."
    Start-Sleep -Seconds 10
}


#Select a font and instantiate
		$font = new-object System.Drawing.Font("Helvetica",75,[Drawing.FontStyle]'Bold' )
		if([System.IO.File]::Exists($BingImageFullPath)){
					#Get the image
					Write-Host "processing " $_.Name
					$img = [System.Drawing.Image]::FromFile($BingImageFullPath)
					
					#Create a bitmap
					$bmp = new-object System.Drawing.Bitmap([int]($img.width)),([int]($img.height))
					
					#Intialize Graphics
					$gImg = [System.Drawing.Graphics]::FromImage($bmp)
					$gImg.SmoothingMode = "AntiAlias"
					
					#Set the color required for the watermark. You can change the color combination
					$color = [System.Drawing.Color]::FromArgb(75, 255, 255,255)
					
					#Set up the brush for drawing image/watermark string
					$myBrush = new-object Drawing.SolidBrush $color
					$rect = New-Object Drawing.Rectangle 0,0,$img.Width,$img.Height
					$gUnit = [Drawing.GraphicsUnit]::Pixel
					
					#at last, draw the water mark
					$gImg.DrawImage($img,$rect,0,0,$img.Width,$img.Height,$gUnit)
					$gImg.DrawString("HITACHI",$font,$myBrush,($img.Width/2-250),($img.Height/3+50))
					Write-Host ($img.Width/2)
					Write-Host ($img.Height/2)
					if (Test-Path $DownloadDirectory) {
						if (Get-Item $DownloadDirectory | % { $_.PSIsContainer }) {
							$newImagePath = "$DownloadDirectory" + "\" + $ImageFileNameWatermark
							Write-Host $BingImageFullPathWatermark
						}
						else {
							Write-Host "$DownloadDirectory isn't a folder. Defaulting to the source location. Watermarked images will be written with a WaterMarked- prefix"
							$newImagePath = $BingImageFullPathWatermark
						}
					}
					else {
						Write-Host "$DownloadDirectory does not exist. Defaulting to the source location. Watermarked images will be written with a WaterMarked- prefix"
						$newImagePath = $BingImageFullPathWatermark
					}
					$bmp.save($BingImageFullPathWatermark,[System.Drawing.Imaging.ImageFormat]::Jpeg)
					$bmp.Dispose()
					$img.Dispose()
				}
		
			else
			{
				Write-Host "$BingImageFullPath is not a valid file"
			}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
namespace Wallpaper
{
   public enum Style : int
   {
       Tile, Center, Stretch, NoChange
   }
   public class Setter {
      public const int SetDesktopWallpaper = 20;
      public const int UpdateIniFile = 0x01;
      public const int SendWinIniChange = 0x02;
      [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
      private static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
      public static void SetWallpaper ( string path, Wallpaper.Style style ) {
         SystemParametersInfo( SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange );
         RegistryKey key = Registry.CurrentUser.OpenSubKey("Control Panel\\Desktop", true);
         switch( style )
         {
            case Style.Stretch :
               key.SetValue(@"WallpaperStyle", "2") ; 
               key.SetValue(@"TileWallpaper", "0") ;
               break;
            case Style.Center :
               key.SetValue(@"WallpaperStyle", "1") ; 
               key.SetValue(@"TileWallpaper", "0") ; 
               break;
            case Style.Tile :
               key.SetValue(@"WallpaperStyle", "1") ; 
               key.SetValue(@"TileWallpaper", "1") ;
               break;
            case Style.NoChange :
               break;
         }
         key.Close();
      }
   }
}
"@


[Wallpaper.Setter]::SetWallpaper( "$BingImageFullPathWatermark", 3 )
$args = '"' + $BGInfoConfiguration + '"'
$p = Start-Process $BGInfoLocation -ArgumentList $args, '/timer:0', '/silent', '/NOLICPROMPT' -wait -NoNewWindow -PassThru
$p.ExitCode