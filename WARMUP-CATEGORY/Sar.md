# IP: 192.168.114.35

# 192.168.114.35


# Nmap

```javascript
┌──(dx㉿kali)-[~]
└─$ nmap 192.168.114.35                 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-01 01:38 EDT
Nmap scan report for 192.168.114.35
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 59.67 seconds
```

# NMAP-Advanced Section
```javascript
┌──(dx㉿kali)-[~]
└─$ nmap -p 22,80 -sC -sV 192.168.114.35
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-01 01:40 EDT
Nmap scan report for 192.168.114.35
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:40:be:13:cf:51:7d:d6:a5:9c:64:c8:13:e5:f2:9f (RSA)
|   256 8a:4e:ab:0b:de:e3:69:40:50:98:98:58:32:8f:71:9e (ECDSA)
|_  256 e6:2f:55:1c:db:d0:bb:46:92:80:dd:5f:8e:a3:0a:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.19 seconds
```

# Navigating to Port-80

![Sar-provingground-webpage](https://user-images.githubusercontent.com/98345027/187840124-10cea880-c77d-44e0-b77e-0da506295069.png)

# Robots.txt Webpage
![sar-robots-txt-provingground](https://user-images.githubusercontent.com/98345027/187840339-c9d282a8-f05b-4c2e-bef2-c8ea52bc0dd1.png)
```javascript
Note: In The Robots.txt page we got: sar2HTML
lets try to append in the url: http://192.168.114.35/sar2HTML/
```

![sartohtml-webpage-provingground](https://user-images.githubusercontent.com/98345027/187841032-e90bafbb-f40e-460a-8308-974c9be0f27d.png)

# Findingd from /sar2HTML
```javascript
1. From the webpage we found the Version of sar2html 
2. From the Source page we don't fnd anything relevant to the information
```

# Dirbuster: checking for directory
```javascript
┌──(dx㉿kali)-[~]
└─$ dirb http://192.168.114.35/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Sep  1 01:58:37 2022
URL_BASE: http://192.168.114.35/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.114.35/ ----
+ http://192.168.114.35/index.html (CODE:200|SIZE:10918)                                                                                        
+ http://192.168.114.35/phpinfo.php (CODE:200|SIZE:95499)                                                                                       
+ http://192.168.114.35/robots.txt (CODE:200|SIZE:9)                                                                                            
+ http://192.168.114.35/server-status (CODE:403|SIZE:279)                                                                                       
                                                                                                                                                 
-----------------
END_TIME: Thu Sep  1 02:13:04 2022
DOWNLOADED: 4612 - FOUND: 4
```

```javascript
```

```javascript
```

```javascript
```

```javascript
```
