# IP:  192.168.103.128

## Enumeration

### Nmap
```javascript
┌──(dx㉿kali)-[~]
└─$ nmap -p- --min-rate 10000 192.168.103.128
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-09 06:28 EDT
Nmap scan report for 192.168.103.128
Host is up (0.16s latency).
Not shown: 65337 filtered tcp ports (no-response), 194 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
995/tcp open  pop3s

Nmap done: 1 IP address (1 host up) scanned in 33.52 seconds 

                                                                      
┌──(dx㉿kali)-[~]
└─$ nmap -p 22,80,110,995 -sCV 192.168.103.128 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-09 06:31 EDT
Nmap scan report for 192.168.103.128
Host is up (0.27s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 04:d0:6e:c4:ba:4a:31:5a:6f:b3:ee:b8:1b:ed:5a:b7 (RSA)
|   256 24:b3:df:01:0b:ca:c2:ab:2e:e9:49:b0:58:08:6a:fa (ECDSA)
|_  256 6a:c4:35:6a:7a:1e:7e:51:85:5b:81:5c:7c:74:49:84 (ED25519)
80/tcp  open  http     Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
110/tcp open  pop3     Courier pop3d
|_pop3-capabilities: UIDL TOP IMPLEMENTATION(Courier Mail Server) UTF8(USER) LOGIN-DELAY(10) USER PIPELINING STLS
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-09-17T16:28:06
|_Not valid after:  2021-09-17T16:28:06
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3 Courier pop3d
|_pop3-capabilities: UIDL TOP PIPELINING LOGIN-DELAY(10) USER UTF8(USER) IMPLEMENTATION(Courier Mail Server)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-09-17T16:28:06
|_Not valid after:  2021-09-17T16:28:06
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.91 seconds
                                                                      
```

#### SITE

#### TCP_80








