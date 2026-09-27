Set WshShell = CreateObject("WScript.Shell")
' Run start_app.bat silently in the background (0 = hide window)
WshShell.Run chr(34) & Replace(WScript.ScriptFullName, WScript.ScriptName, "") & "start_app.bat" & chr(34), 0
Set WshShell = Nothing
