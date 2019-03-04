Dim objOS, colOSes, objOSVersion
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
Set colOSes = objWMIService.ExecQuery ("SELECT * FROM Win32_OperatingSystem")

For Each objOS In colOSes
    objOSVersion = Left(objOS.Version, 3)
Next

Select Case objOSVersion
    Case "10."
		Echo "Windows 10"
    Case "6.3"
		Echo "Windows 8.1"
	Case "6.2"
        Echo "Windows 8"
    Case "6.1"
        Echo "Windows 7"
    Case "6.0"
        Echo "Windows Vista"
    Case "5.2"
        Echo "Windows 2003"
    Case "5.1"
        Echo "Windows XP"
    Case Else
        Echo "Windows ME or older"
End Select