```TEXT
DAY-1 1/8/2022
PLATFORM: PROVING-GROUND
PLAY-FUNBOXROOKIE
TYPE:EASY
SMALL WRITEUP
```


# FunboxRookie


# IP OF THE MACHINE: 192.168.57.107

===================
# Enumeration
===================

# Nmap
====================

```bash
(kali?kali)-[~]
$ nmap 192.168.57.107
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-31 21:12 EDT
Nmap scan report for 192.168.57.107
Host is up (0.00029s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

Note: Now we can run service and version scan on the discovered port 

```bash
(kali?kali)-[~]
$ nmap -p 21,22,80 -sC -sV  192.168.57.107 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-31 21:15 EDT
Nmap scan report for 192.168.57.107
Host is up (0.00064s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
| -r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
| -rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
|_-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f9:46:7d:fe:0c:4d:a9:7e:2d:77:74:0f:a2:51:72:51 (RSA)
|   256 15:00:46:67:80:9b:40:12:3a:0c:66:07:db:1d:18:47 (ECDSA)
|_  256 75:ba:66:95:bb:0f:16:de:7e:7e:a1:7b:27:3b:b0:58 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/logs/
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.15 seconds

```

# Note : First Check the Port 80 (Website)

# Port 80 

VISITING THE WEBSITE
=====================

![default-apache-page](https://user-images.githubusercontent.com/98345027/182064150-1e95a223-4d20-4b5a-baf3-05c343f95c5e.png)



CHECKING FOR ROBOTS.TXT
========================

![robots-txt](https://user-images.githubusercontent.com/98345027/182064259-f9152743-b519-485c-8150-cc63b3b18d8f.png)



VISITING /LOGS/
================
![visiting-logs-file](https://user-images.githubusercontent.com/98345027/182064545-6e386414-72ba-4901-ab8e-dcd03b6edad8.png)


=============================================
RUNNING-GOBUSTER-TOCHECK-HIDDEN-DIRECTORIES
==============================================
```BASH
 ┌──(kali㉿kali)-[~/Desktop/Proving-ground/FunboxRookie]
└─$ gobuster dir -u 'http://192.168.57.107/' -w /home/kali/SecLists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.57.107/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/kali/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/1 07:16:03 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/index.html           (Status: 200) [Size: 10918]
/robots.txt           (Status: 200) [Size: 17]   
/server-status        (Status: 403) [Size: 280]  
                                                 
===============================================================
2022/08/1 07:17:22 Finished
===============================================================
```

# NOTE: Doesn't FIND ANY USEFUL INFORMATION ON PORT 80 , MOVING ON TO PORT 21-FTP

=================
PORT-21(FTP)
==========================

COMMING SOON
