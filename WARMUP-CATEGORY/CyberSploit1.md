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


```javascript
```



```javascript
```
```javascript
```
