Set WshShell = CreateObject("WScript.Shell")

' === Paths ===
pythonPath = "C:\Users\Rohith\AppData\Local\Microsoft\WindowsApps\python.exe"
scriptPath = "C:\Users\Rohith\PycharmProjects\Antivirus\app.py"

' === Launch Flask server silently ===
command = "cmd /c start /min " & pythonPath & " " & Chr(34) & scriptPath & Chr(34)
WshShell.Run command, 0, False

' === Wait for server to start ===
url = "http://127.0.0.1:5000/"
Set http = CreateObject("MSXML2.XMLHTTP")

For i = 1 To 20  ' Try for 20 seconds
    On Error Resume Next
    http.Open "GET", url, False
    http.Send
    If http.Status = 200 Then
        On Error GoTo 0
        Exit For
    End If
    On Error GoTo 0
    WScript.Sleep 1000  ' wait 1 second
Next

' === Launch browser only after Flask is ready ===
WshShell.Run url
