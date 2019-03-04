' Open handle to to Windows Security Center '
Set oWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\SecurityCenter2")
  
' Run Query for all AntiVirusProduct instances '
Set colItems = oWMI.ExecQuery("Select * from AntiVirusProduct")

' Check if we found any instances '
If colItems.count = 0 Then
    Echo "No Antivirus Products"
    Quit
End If

' Iterate over each of the instances found and dump useful display data '
For Each objItem in colItems
  With objItem
   Echo objItem.displayName
  End With
Next
