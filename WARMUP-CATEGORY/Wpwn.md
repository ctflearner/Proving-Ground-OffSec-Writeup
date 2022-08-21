# IP: 192.168.68.123

# Enumeration

# Nmap

```python
┌──(dx㉿kali)-[~/Desktop/Proving-ground/Wpwn]
└─$ nmap 192.168.68.123
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-21 09:59 EDT
Nmap scan report for 192.168.68.123
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

```

# Nmap - Advanced

```python
                                                                                                                                                 
┌──(dx㉿kali)-[~]
└─$ nmap -p 22,80 -sC -sV 192.168.68.123
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-21 10:03 EDT
Nmap scan report for 192.168.68.123
Host is up (0.28s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 59:b7:db:e0:ba:63:76:af:d0:20:03:11:e1:3c:0e:34 (RSA)
|   256 2e:20:56:75:84:ca:35:ce:e3:6a:21:32:1f:e7:f5:9a (ECDSA)
|_  256 0d:02:83:8b:1a:1c:ec:0f:ae:74:cc:7b:da:12:89:9e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.62 seconds

```

# Finding- From Nmap
```python
port-80:  Apache httpd 2.4.38
port-22:  OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0
```

# Navigating Port-80
![htb-wpwn-page-visit](https://user-images.githubusercontent.com/98345027/185795050-57a2e29b-5424-4bb1-93c7-eac9e24e66fe.png)

# Robots.txt-Page
![htb-wpwn-page-robots](https://user-images.githubusercontent.com/98345027/185795334-24c168dd-82c1-4ae4-801c-763020a2e7b4.png)

# /secret

![htb-wpwn-page-secret](https://user-images.githubusercontent.com/98345027/185795447-e57800c9-4cb0-4683-ba88-d72b2fbf0b8e.png)

# Findings-webpage

```python
Webpage and source page doesn't reveal anything interesting/sensitive
```
