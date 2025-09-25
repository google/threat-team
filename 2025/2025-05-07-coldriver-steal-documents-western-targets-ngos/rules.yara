rule LOSTKEYS__Strings {
  meta:
    author = "Google Threat Intelligence"
    description = "wscript that steals documents and becaons system information out to a hardcoded address"
    hash = "28a0596b9c62b7b7aca9cac2a07b067109f27d327581a60e8cb4fab92f8f4fa9"
  strings:
    $rep0 = "my_str = replace(my_str,a1,\"!\" )"
    $rep1 = "my_str = replace(my_str,b1 ,a1 )"
    $rep2 = "my_str = replace(my_str,\"!\" ,b1 )"

    $mid0 = "a1 = Mid(ch_a,ina+1,1)"
    $mid1 = "b1 = Mid(ch_b,ina+1,1)"

    $req0 = "ReqStr = base64encode( z & \";\" & ws.ExpandEnvironmentStrings(\"%COMPUTERNAME%\") & \";\" & ws.ExpandEnvironmentStrings(\"%USERNAME%\") & \";\" & fso.GetDrive(\"C:\\\").SerialNumber)"
    $req1 = "ReqStr = Chain(ReqStr,\"=+/\",\",-_\")"

    $cap0 = "CapIN \"systeminfo > \"\"\" & TmpF & \"\"\"\", 1, True"
    $cap1 = "CapIN \"ipconfig /all >>  \"\"\" & TmpF & \"\"\"\", 1, True"
    $cap2 = "CapIN \"net view >>  \"\"\" & TmpF & \"\"\"\", 1, True"
    $cap3 = "CapIN \"tasklist >>  \"\"\" & TmpF & \"\"\"\", 1, True"
  condition:
    all of ($rep*) or all of ($mid*) or all of ($req*) or all of ($cap*)
}
