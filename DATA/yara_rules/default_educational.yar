/*
    E-MAT Default Educational YARA Rules
    
    These rules are designed for EDUCATIONAL purposes only.
    They detect common patterns found in both legitimate and malicious software.
    
    Author: Naveed Gung
    Purpose: Educational malware analysis
*/

rule Suspicious_API_Calls
{
    meta:
        description = "Detects potentially suspicious Windows API calls"
        author = "E-MAT / Naveed Gung"
        severity = "medium"
        educational_note = "These APIs can be used for legitimate purposes but are also common in malware"
    
    strings:
        $api1 = "CreateRemoteThread" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "VirtualAllocEx" nocase
        $api4 = "SetWindowsHookEx" nocase
        $api5 = "GetAsyncKeyState" nocase
    
    condition:
        2 of ($api*)
}

rule UPX_Packer
{
    meta:
        description = "Detects UPX packer signatures"
        author = "E-MAT / Naveed Gung"
        severity = "low"
        educational_note = "UPX is a legitimate packer but also used to obfuscate malware"
    
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"
    
    condition:
        any of them
}

rule Network_Activity
{
    meta:
        description = "Detects network-related strings and APIs"
        author = "E-MAT / Naveed Gung"
        severity = "low"
        educational_note = "Network activity is normal but worth investigating"
    
    strings:
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $dll1 = "ws2_32.dll" nocase
        $dll2 = "wininet.dll" nocase
        $api1 = "InternetOpen" nocase
        $api2 = "URLDownloadToFile" nocase
    
    condition:
        2 of them
}

rule Registry_Modification
{
    meta:
        description = "Detects registry-related strings"
        author = "E-MAT / Naveed Gung"
        severity = "medium"
        educational_note = "Registry modifications can indicate persistence mechanisms"
    
    strings:
        $reg1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $api1 = "RegSetValueEx" nocase
        $api2 = "RegCreateKeyEx" nocase
    
    condition:
        any of them
}

rule Command_Execution
{
    meta:
        description = "Detects command execution strings"
        author = "E-MAT / Naveed Gung"
        severity = "medium"
        educational_note = "Command execution can be legitimate or malicious depending on context"
    
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell.exe" nocase
        $cmd3 = "wscript.exe" nocase
        $cmd4 = "cscript.exe" nocase
        $api1 = "WinExec" nocase
        $api2 = "ShellExecute" nocase
        $api3 = "CreateProcess" nocase
    
    condition:
        2 of them
}
