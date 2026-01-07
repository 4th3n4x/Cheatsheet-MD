# Ports - Enumeration

## Port Scanning

```bash
# Nmap - Quick scan
nmap {{machine_ip}}
nmap -p- {{machine_ip}}
nmap -p {{port}} {{machine_ip}}

# Nmap - Full scan
nmap -p- -sV -sC -A {{machine_ip}} -oN scan.txt
nmap -p- --min-rate=1000 -T4 {{machine_ip}}

# Nmap - UDP scan
nmap -sU --top-ports 20 {{machine_ip}}
nmap -sU -p {{port}} {{machine_ip}}

# Masscan
masscan -p1-65535 {{machine_ip}} --rate=1000
masscan -p80,443,8080 {{subnet}}/24 --rate=10000

# Rustscan
rustscan -a {{machine_ip}} -- -sV -sC
```

## FTP - 21

```bash
# Anonymous login
ftp {{machine_ip}}
# user: anonymous / pass: anonymous

# Nmap scripts
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 {{machine_ip}}

# Brute force
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt ftp://{{machine_ip}}

# Download all files
wget -r ftp://{{user}}:{{pass}}@{{machine_ip}}/
```

## SSH - 22

```bash
# Connect
ssh {{user}}@{{machine_ip}}
ssh -p {{port}} {{user}}@{{machine_ip}}

# SSH key
ssh -i {{key}} {{user}}@{{machine_ip}}
chmod 600 {{key}}

# Nmap scripts
nmap -p 22 --script ssh-auth-methods,ssh-hostkey,ssh-run {{machine_ip}}

# Brute force
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt ssh://{{machine_ip}}

# Crack SSH key
ssh2john {{key}} > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

## SMTP - 25

```bash
# Connect
nc {{machine_ip}} 25
telnet {{machine_ip}} 25

# VRFY user enum
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t {{machine_ip}}

# Nmap scripts
nmap -p 25 --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344 {{machine_ip}}

# Send email
swaks --to {{email}} --from {{sender}} --server {{machine_ip}} --body "{{message}}"
```

## DNS - 53

```bash
# Zone transfer
dig axfr @{{machine_ip}} {{domain}}
host -l {{domain}} {{machine_ip}}

# Enumerate
dnsrecon -d {{domain}} -t axfr
dnsenum {{domain}}

# Nmap scripts
nmap -p 53 --script dns-zone-transfer,dns-recursion,dns-cache-snoop {{machine_ip}}
```

## HTTP/HTTPS - 80/443

```bash
# Curl
curl http://{{machine_ip}}
curl -I http://{{machine_ip}}

# Nikto
nikto -h http://{{machine_ip}}

# Directory brute
gobuster dir -u http://{{machine_ip}} -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://{{machine_ip}}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Nmap scripts
nmap -p 80 --script http-enum,http-headers,http-methods,http-robots.txt,http-title {{machine_ip}}

# SSL
sslscan {{machine_ip}}:443
openssl s_client -connect {{machine_ip}}:443
```

## POP3 - 110

```bash
# Connect
nc {{machine_ip}} 110
telnet {{machine_ip}} 110

# Commands
USER {{user}}
PASS {{pass}}
LIST
RETR 1

# Brute force
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt pop3://{{machine_ip}}
```

## RPC - 111

```bash
# Enumerate
rpcinfo {{machine_ip}}
rpcdump {{machine_ip}}

# Nmap
nmap -p 111 --script rpcinfo,nfs-ls,nfs-showmount {{machine_ip}}
```

## NetBIOS - 139

```bash
# Enum4linux
enum4linux -a {{machine_ip}}

# NBTScan
nbtscan {{machine_ip}}

# Nmap
nmap -p 139 --script nbstat,smb-enum-shares,smb-enum-users {{machine_ip}}
```

## SMB - 445

```bash
# Enum shares
smbclient -L //{{machine_ip}} -N
smbmap -H {{machine_ip}}
crackmapexec smb {{machine_ip}} --shares

# Connect to share
smbclient //{{machine_ip}}/{{share}} -U {{user}}

# Mount share
mount -t cifs //{{machine_ip}}/{{share}} /mnt -o username={{user}},password={{pass}}

# Nmap scripts
nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-vuln* {{machine_ip}}

# EternalBlue check
nmap -p 445 --script smb-vuln-ms17-010 {{machine_ip}}

# Download all files
smbget -R smb://{{machine_ip}}/{{share}} -U {{user}}
```

## SNMP - 161

```bash
# Enumerate
snmpwalk -v2c -c public {{machine_ip}}
snmpwalk -v2c -c {{community}} {{machine_ip}}

# Brute force community
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {{machine_ip}}

# Nmap
nmap -p 161 -sU --script snmp-enum,snmp-info,snmp-processes,snmp-sysdescr {{machine_ip}}
```

## LDAP - 389

```bash
# Anonymous bind
ldapsearch -x -h {{machine_ip}} -s base
ldapsearch -x -h {{machine_ip}} -b "dc={{domain}},dc={{tld}}"

# Authenticated
ldapsearch -x -h {{machine_ip}} -D "cn={{user}},dc={{domain}},dc={{tld}}" -w {{pass}} -b "dc={{domain}},dc={{tld}}"

# Nmap
nmap -p 389 --script ldap-rootdse,ldap-search {{machine_ip}}
```

## HTTPS - 443

```bash
# Certificate info
openssl s_client -connect {{machine_ip}}:443 -showcerts
sslscan {{machine_ip}}:443

# Extract domains from cert
openssl s_client -connect {{machine_ip}}:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep DNS
```

## MySQL - 3306

```bash
# Connect
mysql -h {{machine_ip}} -u {{user}} -p
mysql -h {{machine_ip}} -u {{user}} -p{{pass}}

# Nmap
nmap -p 3306 --script mysql-enum,mysql-info,mysql-databases,mysql-users {{machine_ip}}

# Brute force
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt mysql://{{machine_ip}}
```

## RDP - 3389

```bash
# Connect
xfreerdp /u:{{user}} /p:{{pass}} /v:{{machine_ip}}
rdesktop {{machine_ip}} -u {{user}} -p {{pass}}

# Nmap
nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 {{machine_ip}}

# Brute force
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt rdp://{{machine_ip}}
crowbar -b rdp -s {{machine_ip}}/32 -u {{user}} -C /usr/share/wordlists/rockyou.txt
```

## PostgreSQL - 5432

```bash
# Connect
psql -h {{machine_ip}} -U {{user}} -d {{database}}

# Nmap
nmap -p 5432 --script pgsql-brute {{machine_ip}}

# Brute force
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt postgres://{{machine_ip}}
```

## VNC - 5900

```bash
# Connect
vncviewer {{machine_ip}}

# Nmap
nmap -p 5900 --script vnc-info,vnc-title {{machine_ip}}

# Brute force
hydra -P /usr/share/wordlists/rockyou.txt vnc://{{machine_ip}}
```

## WinRM - 5985/5986

```bash
# Connect
evil-winrm -i {{machine_ip}} -u {{user}} -p {{pass}}

# Nmap
nmap -p 5985 --script http-headers {{machine_ip}}

# Test access
crackmapexec winrm {{machine_ip}} -u {{user}} -p {{pass}}
```

## Redis - 6379

```bash
# Connect
redis-cli -h {{machine_ip}}

# Commands
INFO
CONFIG GET *
KEYS *

# Nmap
nmap -p 6379 --script redis-info {{machine_ip}}
```

## Kerberos - 88

```bash
# User enum
kerbrute userenum --dc {{machine_ip}} -d {{domain}} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# AS-REP Roasting
GetNPUsers.py {{domain}}/ -no-pass -usersfile users.txt -dc-ip {{machine_ip}}

# Nmap
nmap -p 88 --script krb5-enum-users {{machine_ip}}
```

## MSSQL - 1433

```bash
# Connect
impacket-mssqlclient {{user}}:{{pass}}@{{machine_ip}} -windows-auth

# Nmap
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell {{machine_ip}}

# Brute force
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt mssql://{{machine_ip}}
```

## NFS - 2049

```bash
# Show mounts
showmount -e {{machine_ip}}

# Mount
mount -t nfs {{machine_ip}}:/{{share}} /mnt

# Nmap
nmap -p 2049 --script nfs-ls,nfs-showmount,nfs-statfs {{machine_ip}}
```

## MongoDB - 27017

```bash
# Connect
mongo mongodb://{{machine_ip}}:27017

# Nmap
nmap -p 27017 --script mongodb-info,mongodb-databases {{machine_ip}}
```

## Common Ports Reference

```
20/21   - FTP
22      - SSH
23      - Telnet
25      - SMTP
53      - DNS
80      - HTTP
88      - Kerberos
110     - POP3
111     - RPC
135     - MSRPC
139     - NetBIOS
143     - IMAP
161     - SNMP
389     - LDAP
443     - HTTPS
445     - SMB
636     - LDAPS
873     - Rsync
1433    - MSSQL
1521    - Oracle
2049    - NFS
3306    - MySQL
3389    - RDP
5432    - PostgreSQL
5900    - VNC
5985    - WinRM HTTP
5986    - WinRM HTTPS
6379    - Redis
8080    - HTTP Alt
27017   - MongoDB
```