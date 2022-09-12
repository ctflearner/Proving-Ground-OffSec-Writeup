# IP : 	192.168.103.193


## Nmap

`` nmap shows 3 open port ``
```javascript
┌──(dx㉿kali)-[~]
└─$ nmap -p- --min-rate 10000 192.168.103.193
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-12 00:18 EDT
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 5.06% done; ETC: 00:19 (0:00:38 remaining)
Warning: 192.168.103.193 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.103.193
Host is up (0.18s latency).
Not shown: 63231 filtered tcp ports (no-response), 2301 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
111/tcp open  rpcbind

Nmap done: 1 IP address (1 host up) scanned in 120.01 seconds

┌──(dx㉿kali)-[~]
└─$ nmap -p 22,80,111 -sCV 192.168.103.193     
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-12 00:27 EDT
Nmap scan report for 192.168.103.193
Host is up (0.24s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 c4:d6:59:e6:77:4c:22:7a:96:16:60:67:8b:42:48:8f (DSA)
|   2048 11:82:fe:53:4e:dc:5b:32:7f:44:64:82:75:7d:d0:a0 (RSA)
|_  256 3d:aa:98:5c:87:af:ea:84:b8:23:68:8d:b9:05:5f:d8 (ECDSA)
80/tcp  open  http    Apache httpd 2.2.22 ((Debian))
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to Drupal Site | Drupal Site
|_http-server-header: Apache/2.2.22 (Debian)
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          50550/tcp6  status
|   100024  1          55270/udp   status
|   100024  1          55271/udp6  status
|_  100024  1          57092/tcp   status
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.83 seconds

```
## Drupal TCP-80

###### Site
![DC-1-site-proving-ground](https://user-images.githubusercontent.com/98345027/189575510-a0d486a6-bc72-4751-b654-8ec679725fb6.png)

###### Robots.txt
```javascript
#
# robots.txt
#
# This file is to prevent the crawling and indexing of certain parts
# of your site by web crawlers and spiders run by sites like Yahoo!
# and Google. By telling these "robots" where not to go on your site,
# you save bandwidth and server resources.
#
# This file will be ignored unless it is at the root of your host:
# Used:    http://example.com/robots.txt
# Ignored: http://example.com/site/robots.txt
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/wc/robots.html
#
# For syntax checking, see:
# http://www.sxw.org.uk/computing/robots/check.html

User-agent: *
Crawl-delay: 10
# Directories
Disallow: /includes/
Disallow: /misc/
Disallow: /modules/
Disallow: /profiles/
Disallow: /scripts/
Disallow: /themes/
# Files
Disallow: /CHANGELOG.txt
Disallow: /cron.php
Disallow: /INSTALL.mysql.txt
Disallow: /INSTALL.pgsql.txt
Disallow: /INSTALL.sqlite.txt
Disallow: /install.php
Disallow: /INSTALL.txt
Disallow: /LICENSE.txt
Disallow: /MAINTAINERS.txt
Disallow: /update.php
Disallow: /UPGRADE.txt
Disallow: /xmlrpc.php
# Paths (clean URLs)
Disallow: /admin/
Disallow: /comment/reply/
Disallow: /filter/tips/
Disallow: /node/add/
Disallow: /search/
Disallow: /user/register/
Disallow: /user/password/
Disallow: /user/login/
Disallow: /user/logout/
# Paths (no clean URLs)
Disallow: /?q=admin/
Disallow: /?q=comment/reply/
Disallow: /?q=filter/tips/
Disallow: /?q=node/add/
Disallow: /?q=search/
Disallow: /?q=user/password/
Disallow: /?q=user/register/
Disallow: /?q=user/login/
Disallow: /?q=user/logout/

```


`` Lets  Enumerate the drupal CMS using droopescan Because we don't have any credentials to login to the drupal website ``

```javascript
┌──(dx㉿kali)-[~/droopescan]
└─$ ./droopescan scan -u http://192.168.103.193/
[+] Site identified as drupal.
[+] Plugins found:
    ctools http://192.168.103.193/sites/all/modules/ctools/
        http://192.168.103.193/sites/all/modules/ctools/LICENSE.txt                                                           
        http://192.168.103.193/sites/all/modules/ctools/API.txt
    views http://192.168.103.193/sites/all/modules/views/
        http://192.168.103.193/sites/all/modules/views/README.txt                                                             
        http://192.168.103.193/sites/all/modules/views/LICENSE.txt                                                            
    profile http://192.168.103.193/modules/profile/
    php http://192.168.103.193/modules/php/
    image http://192.168.103.193/modules/image/

[+] Themes found:
    seven http://192.168.103.193/themes/seven/
    garland http://192.168.103.193/themes/garland/

[+] Possible version(s):
    7.22
    7.23
    7.24
    7.25
    7.26

[+] Possible interesting urls found:
    Default admin - http://192.168.103.193/user/login

```
`` WE can see from droopescan that there is possible version of drupal , we'll use Searchsploit to look for any publicly available exploits for Drupal 7.x
```javascript
┌──(dx㉿kali)-[~]
└─$ searchsploit drupal " < 7.31 "
--------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                 |  Path
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User)                                              | php/webapps/34992.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Admin Session)                                               | php/webapps/44355.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Admin Session)                                               | php/webapps/44355.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (1)                                    | php/webapps/34984.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (2)                                    | php/webapps/34993.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Remote Code Execution)                                       | php/webapps/35150.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Remote Code Execution)                                       | php/webapps/35150.php
Drupal < 7.34 - Denial of Service                                                                              | php/dos/35415.txt
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                       | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                    | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                            | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                        | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                               | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)          | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                                 | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                                                             | php/webapps/46459.py
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

`` Searchsploit output indicated that drupal Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 is vulnerable to Remote Code Execution, Another name for this vulnerability isDrupalgeddon2 
