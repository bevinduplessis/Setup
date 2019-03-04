Dim IPConfigSet, IPConfig, h
Set IPConfigSet = GetObject("winmgmts:{impersonationLevel=impersonate}!root\cimv2").ExecQuery("select * from win32_networkadapterconfiguration WHERE IPEnabled='TRUE' " _
                  & "AND ServiceName<>'AsyncMac' " _
                  & "AND ServiceName<>'VMnetx' " _
                  & "AND ServiceName<>'VMnetadapter' " _
                  & "AND ServiceName<>'Rasl2tp' " _
                  & "AND ServiceName<>'msloop' " _
                  & "AND ServiceName<>'PptpMiniport' " _
                  & "AND ServiceName<>'Raspti' " _
                  & "AND ServiceName<>'NDISWan' " _
                  & "AND ServiceName<>'NdisWan4' " _
                  & "AND ServiceName<>'RasPppoe' " _
                  & "AND ServiceName<>'NdisIP' " _
                  & "AND ServiceName<>'' " _
                  & "AND Description<>'PPP Adapter.'", , 48)

For Each IPConfig in IPConfigSet
    If Not IsNull(IPConfig.IPAddress) Then
    	  
	   If Not IsNull(IPConfig.DefaultIPGateway) Then
        For h = LBound(IPConfig.DefaultIPGateway) To UBound(IPConfig.DefaultIPGateway)
            Echo IPConfig.DefaultIPGateway(h)
        Next
    End If
	
	  
    End If
	
   



	Next