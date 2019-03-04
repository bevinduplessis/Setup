Set ObjShell = CreateObject("WScript.Shell")


'Get Last Logged On User From the registry
StrLastLoggedOnUser = ReadReg("HKLM\SOFTWARE\LogonScript\LastLoggedOnUser") 'Read last logged on user from Windows Vista/7/8


Echo StrLastLoggedOnUser

Function ReadReg(RegPath) ' Function used to read a registry value if it exists
    
    If RegistryItemExists(RegPath) Then
        ReadReg = ObjShell.RegRead(RegPath)
    End If
    
End Function

Function RegistryItemExists(RegistryItem) ' Function used to check if a registry value exists
    'If there isn't the item when we read it, it will return an error, so we need to resume
    On Error Resume Next
    
    'Find out if we are looking for a key or a value
    If (Right(RegistryItem, 1) = "\") Then
        ObjShell.RegRead RegistryItem
    Else
        ObjShell.RegRead RegistryItem
    End If
    
    'Catch the error
    If Err.Number <> 0 Then
        RegistryItemExists = False
    Else
        RegistryItemExists = True
    End If
    Err.Clear
    
    'Turn error reporting back on
    On Error GoTo 0
End Function